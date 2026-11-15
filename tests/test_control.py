"""Execution profile contracts; --native-pool exercises a private five-slot queue."""
import argparse
import ast
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
TEST_TEMP=Path.cwd()/'.work/test-dv-bridge'
TEST_TEMP.mkdir(parents=True,exist_ok=True)
import threading
import time
import unittest
import uuid

BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE/'etx'),str(BASE/'worker-runtime')]
import site_config
from helpers import demo_site
from session_protocol import Rejected,request,digest,canonical
from session_files import Files
from session_service import Dispatcher
from session_control import ControlWorker
from session_jobs import job_argv
from session_agent import validate_execution_profile,validate_file_profile


def configuration():
    settings=demo_site(BASE);site_config._loaded=settings
    return {'profile':'execution-online-v1','transport_host':'test-node','persistent_endpoint':True,
        'enable_workers':True,'enable_writes':True,'allowed_roots':settings['permissions']['read_roots'],
        'write_roots':settings['permissions']['write_roots'],'state':str(BASE/'.private/state/control'),
        'worker_module':str(BASE/'worker-runtime/sim_control.py'),'worker_module_sha256':'1'*64,
        'executor_profiles':['work01','work02','work03','work04','work05'],
        'wave_enabled':False,'wave_root':'','wave_release':'','wave_fsdbs':[],
        'endpoint_id':'3'*32,'activation_task_id':'4'*32,
        'activation_file':str(BASE/'.private/state/activation.json'),
        'session_seconds':3600,'initial_handshake_timeout_seconds':0}


class ContractTests(unittest.TestCase):
    def test_execution_profile_is_explicit_and_bounded(self):
        cfg=configuration();validate_execution_profile(cfg,'test-node',BASE)
        for key,value in [('enable_workers',False),('allowed_roots',['/']),
            ('executor_profiles',['work06']),('activation_file','/tmp/other')]:
            with self.subTest(key=key):
                with self.assertRaises(Rejected):validate_execution_profile(dict(cfg,**{key:value}),'test-node',BASE)

    def test_file_profile_does_not_gain_execution(self):
        cfg=configuration();cfg.update(profile='files-online-v1',state=str(BASE/'.private/state/files'))
        with self.assertRaisesRegex(Rejected,'FILE_PROFILE_SCOPE_REJECTED'):
            validate_file_profile(cfg,'test-node',BASE)

    def test_command_is_a_pinned_fixed_job(self):
        argv=job_argv('/srv/test/dv-bridge','1'*64,'2'*64,
            'selftest','3'*32,'work04',{'hold_seconds':1})
        self.assertIn('JOB_MODULE_CHANGED',argv[3])
        self.assertEqual(argv[-3:],['/srv/test/dv-bridge/server-control-online.json','2'*64,
            canonical({'kind':'selftest','request_id':'3'*32,'profile':'work04','options':{'hold_seconds':1}}).decode()])
        for kind in ('shell','exec','python'):
            with self.assertRaisesRegex(RuntimeError,'JOB_KIND_REJECTED'):
                job_argv('/nfs/x','1'*64,'2'*64,kind,'3'*32,'work04',{})

    def test_activation_marker_required(self):
        worker=ControlWorker.__new__(ControlWorker);worker.config=configuration()
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            p=Path(tmp)/'activation.json';worker.config['activation_file']=str(p)
            with self.assertRaisesRegex(Rejected,'CONTROL_ACTIVATION_PENDING'):worker.require_active()
            p.write_text(json.dumps({'task_id':'4'*32,'endpoint_id':'3'*32,'commit':True}))
            worker.require_active()

    def test_status_batch_refreshes_and_rejects_duplicate_or_oversize(self):
        class Queue:
            state='queued'
            def snapshot(self,rid):return {'request_id':rid,'state':self.state}
        worker=ControlWorker.__new__(ControlWorker);worker.queue=Queue()
        worker.workers=lambda _: {'workers':[]}
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            root=Path(tmp);project=root/'project';project.mkdir()
            dispatcher=Dispatcher(root/'rpc',Files(root/'files',[project]),'1'*32,worker)
            spec=request('1'*32,'status_many',{'request_ids':['2'*32]},'3'*32)
            self.assertEqual(dispatcher.dispatch(spec)['jobs'][0]['state'],'queued')
            worker.queue.state='running'
            self.assertEqual(dispatcher.dispatch(spec)['jobs'][0]['state'],'running')
            for ids in ([],['2'*32]*2,['2'*32]*6,['invalid']):
                with self.assertRaises(Rejected):worker.status_many({'request_ids':ids})

    def test_file_only_dispatcher_rejects_new_task_operations(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            root=Path(tmp);project=root/'project';project.mkdir()
            dispatcher=Dispatcher(root/'rpc',Files(root/'files',[project]),'1'*32)
            for op in ('submit_task','task_result','status_many','release_selftests'):
                with self.assertRaisesRegex(Rejected,'WORKERS_DISABLED'):
                    dispatcher.dispatch(request('1'*32,op,{},uuid.uuid4().hex))


if __name__=='__main__':unittest.main()
