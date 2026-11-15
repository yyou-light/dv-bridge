import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile
TEST_TEMP=Path.cwd()/'.work/test-dv-bridge'
TEST_TEMP.mkdir(parents=True,exist_ok=True)
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BASE/'etx'), str(BASE/'local')]
from session_protocol import Rejected, digest, request, canonical
from session_files import Files
from session_service import Dispatcher
from windows_read_files import read_files


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_TEMP)
        self.root = Path(self.temp.name)
        self.project = self.root/'project'; self.project.mkdir()
        self.output = self.root/'output'; self.output.mkdir()
        self.files = Files(self.root/'state', [self.project])
        self.dispatcher = Dispatcher(self.root/'rpc', self.files, '1'*32)
        self.calls = []
        outer = self
        class Adapter:
            def call(self, op, args, rid):
                outer.calls.append((op, rid))
                return outer.dispatcher.dispatch(request('1'*32, op, args, rid))
        self.client = Adapter()

    def tearDown(self):
        self.temp.cleanup()

    def spec(self, values, cached=False, task='2'*32):
        items = []
        for i, value in enumerate(values):
            p = self.project/('file'+str(i)); p.write_bytes(value)
            cache = self.root/('cache'+str(i))
            if cached: cache.write_bytes(value)
            items.append({'path': str(p), 'cached_file': str(cache) if cached else None,
                'cached_sha256': digest(value) if cached else None, 'output_name': 'file'+str(i)})
        return {'id': task, 'files': items, 'timeout_seconds': 60}

    def test_ten_text_files_are_one_rpc_and_repeat_is_same_snapshot(self):
        values = [('hello 汉字\r\n'+str(i)).encode() for i in range(10)]
        spec = self.spec(values)
        result = read_files(self.client, spec, self.output)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(result['downloaded_bytes'], sum(map(len, values)))
        for i, value in enumerate(values): self.assertEqual((self.output/('file'+str(i))).read_bytes(), value)
        (self.project/'file0').write_bytes(b'edited after snapshot')
        self.assertEqual(read_files(self.client, spec, self.output)['files'], result['files'])

    def test_unchanged_files_send_no_content(self):
        spec = self.spec([b'one', b'two'], cached=True)
        result = read_files(self.client, spec, self.output)
        self.assertEqual((result['cache_hits'], result['downloaded_bytes'], len(self.calls)), (2, 0, 1))

    def test_changed_cached_file_fetches_only_changed_bytes(self):
        spec = self.spec([b'one', b'two'], cached=True)
        (self.project/'file1').write_bytes('new 汉字'.encode())
        result = read_files(self.client, spec, self.output)
        self.assertEqual(result['cache_hits'], 1)
        self.assertEqual(result['downloaded_bytes'], len('new 汉字'.encode()))

    def test_inline_budget_and_large_file_continuation(self):
        spec = self.spec([b'a'*524288, b'b'*10])
        result = read_files(self.client, spec, self.output)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(result['downloaded_bytes'], 524298)

    def test_server_rejects_oversize_and_non_utf8(self):
        for value in (b'x'*524289, b'\xff'):
            with self.subTest(length=len(value)):
                spec = self.spec([value], task=('%032x' % len(value)))
                with self.assertRaises(Rejected): read_files(self.client, spec, self.output)

    def test_batch_limit_duplicate_paths_and_traversal(self):
        for mutate in (lambda s:s.update(files=s['files']*11),
                       lambda s:s.update(files=s['files']*2),
                       lambda s:s['files'][0].update(output_name='../escape')):
            spec = self.spec([b'a']); mutate(spec)
            with self.assertRaises(Rejected): read_files(self.client, spec, self.output)
        self.assertEqual(self.calls, [])

    def test_local_cache_change_rejected_before_network(self):
        spec = self.spec([b'a'], cached=True)
        Path(spec['files'][0]['cached_file']).write_bytes(b'b')
        with self.assertRaisesRegex(Rejected, 'LOCAL_CACHE_CHANGED'):
            read_files(self.client, spec, self.output)
        self.assertEqual(self.calls, [])

    def test_remote_path_scope_and_directory_rejected(self):
        for path in (str(self.root/'outside'), str(self.project)):
            spec = self.spec([b'a']);spec['files'][0]['path'] = path
            with self.assertRaises(Rejected): read_files(self.client, spec, self.output)

    def test_bad_chunk_hash_never_publishes_result(self):
        real = self.files.read_chunk
        def bad(args):
            r = real(args);r['sha256'] = '0'*64;return r
        self.files.read_chunk = bad
        with self.assertRaisesRegex(Rejected, 'CHUNK_HASH_MISMATCH'):
            read_files(self.client, self.spec([b'a']), self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink creation needs native ETX')
    def test_remote_symlink_rejected(self):
        spec = self.spec([b'a']);p = Path(spec['files'][0]['path'])
        p.unlink();p.symlink_to(self.root/'outside')
        with self.assertRaisesRegex(Rejected, 'SYMLINK_REJECTED'):
            read_files(self.client, spec, self.output)


if __name__ == '__main__':
    unittest.main()
