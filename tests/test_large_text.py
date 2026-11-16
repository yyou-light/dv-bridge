import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch
import uuid
import sys

BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE/'etx'),str(BASE/'local'),str(BASE/'clients')]

from session_protocol import Rejected, digest, request, MAX_CHUNK, MAX_TEXT_FILE, MAX_FILE
from session_files import Files, atomic_json
from session_service import Dispatcher
from windows_read_files import read_files, file_meta, stable_id
from etx_cli import Project, Failure, text_file_meta, save

ROOT=Path(__file__).resolve().parents[1]
TEST_ROOT=ROOT/'.test-tmp'
TEST_ROOT.mkdir(exist_ok=True)


class LargeTextTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root=Path(self.temp.name).resolve()
        self.assertTrue(self.root.is_relative_to(TEST_ROOT.resolve()))
        self.allowed=self.root/'project';self.allowed.mkdir()
        self.files=Files(self.root/'state',[self.allowed],True)
        self.dispatcher=Dispatcher(self.root/'rpc',self.files,'1'*32)
        self.output=self.root/'output';self.output.mkdir()
        self.serial=100
        self.calls=[]
        outer=self
        class Adapter:
            def call(self,op,args,rid):
                outer.calls.append((op,args))
                return outer.dispatcher.dispatch(request('1'*32,op,args,rid))
        self.adapter=Adapter()

    def tearDown(self): self.temp.cleanup()

    def spec(self,data=b'x',task='2'*32):
        source=self.allowed/'source.txt';source.write_bytes(data)
        return {'id':task,'files':[{'path':str(source),'cached_file':None,
            'cached_sha256':None,'output_name':'source.txt'}],'timeout_seconds':60}

    def upload(self,target,source,before='absent',transfer=None):
        transfer=transfer or uuid.uuid4().hex
        metadata=text_file_meta(source)
        self.files.upload_begin({'transfer_id':transfer,'path':str(target),
            'bytes':metadata['bytes'],'sha256':metadata['sha256'],
            'expected_before_sha256':before,'text_only':True})
        offset=0
        with source.open('rb') as stream:
            for part in iter(lambda:stream.read(MAX_CHUNK),b''):
                self.files.upload_chunk({'transfer_id':transfer,'offset':offset,
                    'data':base64.b64encode(part).decode(),'sha256':digest(part)})
                offset+=len(part)
        return transfer

    def test_multibyte_text_over_old_limit_and_binary_limit_unchanged(self):
        value=('汉字\r\n'*150000).encode()
        result=read_files(self.adapter,self.spec(value),self.output)
        self.assertEqual(result['files'][0]['bytes'],len(value))
        self.assertEqual((self.output/'source.txt').read_bytes(),value)
        self.assertFalse(list(self.output.glob('*.part')))
        oversize=self.allowed/'legacy.txt'
        with oversize.open('wb') as stream: stream.truncate(MAX_FILE+1)
        with self.assertRaises(Rejected):
            self.files.read_begin({'path':str(oversize),'transfer_id':'f'*32})

    def test_download_resumes_same_snapshot_and_rejects_changed_part(self):
        value=b'line\n'*300000;spec=self.spec(value)
        real=self.adapter.call;failed=[False]
        def fail(op,args,rid):
            if op=='read_chunk' and not failed[0]:
                failed[0]=True;raise Rejected('SYNTHETIC_INTERRUPTION')
            return real(op,args,rid)
        self.adapter.call=fail
        with self.assertRaisesRegex(Rejected,'SYNTHETIC_INTERRUPTION'):
            read_files(self.adapter,spec,self.output)
        source=Path(spec['files'][0]['path']);source.write_bytes(b'edited after snapshot')
        self.adapter.call=real
        result=read_files(self.adapter,spec,self.output)
        self.assertEqual(file_meta(self.output/'source.txt'),(len(value),digest(value)))
        self.assertLess(result['downloaded_bytes'],len(value))
        self.assertEqual(sorted(p.name for p in self.output.iterdir()),['source.txt'])

    def test_modified_partial_is_not_published(self):
        spec=self.spec(b'line\n'*300000)
        real=self.adapter.call
        def fail(op,args,rid):
            if op=='read_chunk': raise Rejected('SYNTHETIC_INTERRUPTION')
            return real(op,args,rid)
        self.adapter.call=fail
        with self.assertRaises(Rejected):read_files(self.adapter,spec,self.output)
        part=self.output/('.'+stable_id(spec['id'],'file-0')+'.part')
        with part.open('r+b') as stream:stream.write(b'X')
        self.adapter.call=real
        with self.assertRaisesRegex(Rejected,'LOCAL_PART_CHANGED'):
            read_files(self.adapter,spec,self.output)
        self.assertFalse((self.output/'source.txt').exists())

    def test_upload_over_16_mib_backup_restore_without_whole_file_reads(self):
        source=self.root/'large.txt'
        with source.open('wb') as stream:
            for _ in range(68):stream.write(b'textline\n'*32768)
        target=self.allowed/'installed.txt';target.write_bytes(b'original\n')
        before=digest(b'original\n');original_read=Path.read_bytes
        def guarded(path):
            if path.stat().st_size>524288:raise AssertionError('whole large file read')
            return original_read(path)
        with patch.object(Path,'read_bytes',guarded):
            transfer=self.upload(target,source,before)
            receipt=self.files.commit({'transaction_id':'3'*32,'transfer_ids':[transfer]})
            self.assertEqual(self.files.current_hash(target),text_file_meta(source)['sha256'])
            self.assertEqual(receipt['files'][0]['before_sha256'],before)
            self.files.restore({'transaction_id':'3'*32,'restoration_id':'4'*32})
        self.assertEqual(target.read_bytes(),b'original\n')

    def test_invalid_utf8_upload_rejected_before_install(self):
        target=self.allowed/'target.txt';target.write_bytes(b'original')
        raw=b'valid\n\xff'
        self.files.upload_begin({'transfer_id':'5'*32,'path':str(target),'bytes':len(raw),
            'sha256':digest(raw),'expected_before_sha256':digest(b'original'),'text_only':True})
        self.files.upload_chunk({'transfer_id':'5'*32,'offset':0,
            'data':base64.b64encode(raw).decode(),'sha256':digest(raw)})
        with self.assertRaisesRegex(Rejected,'TEXT_ENCODING_REJECTED'):
            self.files.commit({'transaction_id':'6'*32,'transfer_ids':['5'*32]})
        self.assertEqual(target.read_bytes(),b'original')

    def test_real_256_mib_snapshot_uses_bounded_python_memory(self):
        source=self.allowed/'max.txt';block=b'0123456789abcdef'*16384
        with source.open('wb') as stream:
            for _ in range(MAX_TEXT_FILE//len(block)):stream.write(block)
        tracemalloc.start()
        try:
            result=self.files.read_batch({'files':[{'path':str(source),
                'transfer_id':'7'*32,'known_sha256':None}]})
            _,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        meta=result['files'][0]['metadata']
        self.assertEqual(meta['bytes'],256*1024*1024)
        self.assertLess(peak,8*1024*1024)
        self.assertEqual(self.files.stream_file(source)[0].hexdigest(),meta['sha256'])

    def test_text_limit_plus_one_and_batch_sum_rejected(self):
        source=self.allowed/'over.txt'
        with source.open('wb') as stream:stream.truncate(MAX_TEXT_FILE+1)
        with self.assertRaises(Rejected):
            self.files.read_batch({'files':[{'path':str(source),'transfer_id':'8'*32,'known_sha256':None}]})
        with self.assertRaises(Rejected):
            self.files.upload_begin({'transfer_id':'9'*32,'path':str(self.allowed/'new'),
                'bytes':MAX_TEXT_FILE+1,'sha256':'0'*64,'expected_before_sha256':'absent','text_only':True})

    def test_cleanup_removes_only_verified_temporary_log(self):
        project=Project(self.root/'client','a'*32)
        log=project.result/'stdout.log';log.write_bytes(b'%E- synthetic\n')
        baseline=project.result/'source.sv';baseline.write_bytes(b'module m; endmodule\n')
        summary={'ok':True,'result':{'files':[
            {'path':'/srv/test/results/run/stdout.log','local':str(log),'bytes':log.stat().st_size,
                'sha256':digest(log.read_bytes()),'retention':'temporary_log'},
            {'path':'/srv/test/project/source.sv','local':str(baseline),'bytes':baseline.stat().st_size,
                'sha256':digest(baseline.read_bytes()),'retention':'baseline'}]}}
        save(project.result/'summary.json',summary)
        self.assertEqual(project.cleanup_logs()['removed_files'],1)
        self.assertFalse(log.exists());self.assertTrue(baseline.exists())
        self.assertEqual(project.cleanup_logs()['removed_files'],0)
        self.assertFalse(json.loads((project.result/'summary.json').read_text())['result']['files'][0]['retained'])

    def test_cleanup_changed_or_outside_file_is_rejected(self):
        project=Project(self.root/'client','b'*32)
        log=project.result/'stdout.log';log.write_bytes(b'changed')
        summary={'ok':True,'result':{'files':[{'path':'/srv/test/results/run/stdout.log','local':str(log),
            'bytes':3,'sha256':digest(b'old'),'retention':'temporary_log'}]}}
        save(project.result/'summary.json',summary)
        with self.assertRaisesRegex(Failure,'LOCAL_LOG_CHANGED'):project.cleanup_logs()
        self.assertTrue(log.exists())
        summary['result']['files'][0]['local']=str(self.allowed/'outside.log')
        save(project.result/'summary.json',summary)
        with self.assertRaisesRegex(Failure,'LOCAL_PATH_REJECTED'):project.cleanup_logs()
