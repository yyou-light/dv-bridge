from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE/'etx'),str(BASE/'local'),str(BASE/'clients')]

from session_protocol import Rejected, digest, decode_bytes, MAX_CHUNK
from session_files import Files
from session_service import Dispatcher

ROOT=Path(__file__).resolve().parents[1]


class NativeLogTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'.test-tmp').mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'.test-tmp')
        self.root=Path(self.temp.name)
        self.allowed=self.root/'results'
        self.case=self.allowed/'demo_tb__demo_sim__demo_case__7_cov'
        self.case.mkdir(parents=True)
        self.log=self.case/'stdout.log'
        self.files=Files(self.root/'state',[self.allowed])
        self.dispatcher=Dispatcher(self.root/'rpc',self.files,'1'*32)

    def tearDown(self):self.temp.cleanup()

    def args(self,**changes):
        return dict({'path':str(self.log),'mode':'errors','offset':0,'limit':MAX_CHUNK,'identity':None},**changes)

    def test_large_log_first_error_context_and_footer(self):
        with self.log.open('wb') as stream:
            for _ in range(40000):stream.write(b'informational progress line\n')
            stream.write(b'%E-(checker.sv:10) synthetic first failure\n')
            for _ in range(40000):stream.write(b'following progress line\n')
            stream.write(b'FINAL: synthetic failure summary\n')
        value=self.dispatcher.native_log(self.args())
        self.assertTrue(value['match_found']);self.assertEqual(value['match_line'],40001)
        chunks={f['kind']:decode_bytes(f['data']) for f in value['fragments']}
        self.assertIn(b'synthetic first failure',chunks['first_error'])
        self.assertIn(b'FINAL:',chunks['tail'])
        self.assertLessEqual(value['bytes'],MAX_CHUNK)
        for fragment in value['fragments']:
            self.assertEqual(digest(decode_bytes(fragment['data'])),fragment['sha256'])

    def test_utf8_range_continuation_and_identity_change(self):
        data=b'x'*(MAX_CHUNK-1)+'汉字\n'.encode()
        self.log.write_bytes(data)
        first=self.dispatcher.native_log(self.args(mode='range'))
        self.assertEqual(first['scanned_to'],MAX_CHUNK-1)
        second=self.dispatcher.native_log(self.args(mode='range',offset=first['scanned_to'],identity=first['identity']))
        raw=b''.join(decode_bytes(f['data']) for f in first['fragments']+second['fragments'])
        self.assertEqual(raw,data)
        with self.log.open('ab') as stream:stream.write(b'append\n')
        with self.assertRaisesRegex(Rejected,'LOG_CHANGED'):
            self.dispatcher.native_log(self.args(mode='tail',identity=first['identity']))

    def test_invalid_target_and_zero_error_summary(self):
        self.log.write_bytes(b'UVM_ERROR : 0\nUVM_FATAL : 0\n$finish called\n')
        value=self.dispatcher.native_log(self.args())
        self.assertFalse(value['match_found']);self.assertTrue(value['scan_complete'])
        source=self.case/'other.log';source.write_bytes(b'%E- not an allowed log\n')
        with self.assertRaisesRegex(Rejected,'NATIVE_LOG_PATH_REJECTED'):
            self.dispatcher.native_log(self.args(path=str(source)))
        with self.assertRaises(Rejected):self.dispatcher.native_log(self.args(path=str(self.case)))

    def test_scan_timeout_is_explicit_and_binary_text_rejected(self):
        self.log.write_bytes(b'informational\n'*100)
        with patch('session_service.NATIVE_LOG_SCAN_SECONDS',-1):
            value=self.dispatcher.native_log(self.args())
        self.assertTrue(value['scan_timed_out']);self.assertFalse(value['scan_complete'])
        self.log.write_bytes(b'binary\x00data')
        with self.assertRaisesRegex(Rejected,'TEXT_ENCODING_REJECTED'):
            self.dispatcher.native_log(self.args())
