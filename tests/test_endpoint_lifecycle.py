"""File endpoint lifecycle tests; synthetic data, no native clipboard or EDA jobs."""
import base64
import argparse
import contextlib
import copy
import importlib.util
import json
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
TEST_TEMP=Path.cwd()/'.work/test-dv-bridge'
TEST_TEMP.mkdir(parents=True,exist_ok=True)
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'etx'))
sys.path.insert(0,str(BASE/'local'))
import session_agent as agent
from session_files import Files,private_directory,atomic_json
from session_service import Dispatcher
from session_protocol import Rejected,request,digest
from windows_session import Client
import site_config
from helpers import demo_site


def uid(n):return format(n,'032x')


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEST_TEMP)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.allowed=private_directory(self.root/'allowed')
        self.files=Files(private_directory(self.root/'state/files'),[self.allowed],
            write_enabled=True,write_roots=[self.allowed])

    def dispatcher(self,now=lambda:100):
        d=Dispatcher(self.root/'state/rpc',self.files,uid(1),now=now,session_seconds=2)
        d.endpoint_info={'persistent':True,'lease_number':1,'endpoint_id':uid(9)}
        return d

    def upload(self,data=b'synthetic text',suffix='.txt'):
        target=self.allowed/('file'+suffix)
        args={'transfer_id':uid(2),'path':str(target),'bytes':len(data),
            'sha256':digest(data),'expected_before_sha256':'absent'}
        self.files.upload_begin(args)
        if data:self.files.upload_chunk({'transfer_id':uid(2),'offset':0,
            'data':base64.b64encode(data).decode(),'sha256':digest(data)})
        return target

    def test_lease_renewal_keeps_committed_receipt_and_does_not_rewrite(self):
        clock=[100]
        d=self.dispatcher(now=lambda:clock[0]);target=self.upload()
        args={'transaction_id':uid(3),'transfer_ids':[uid(2)]}
        result=d.dispatch(request(uid(1),'commit',args,uid(4),now=100))
        identity=Files.identity(target.stat())
        clock[0]=103
        config={'persistent_endpoint':True,'session_seconds':2,'rg_path':None}
        fresh=agent.renew_file_lease(d,config,self.files,self.root/'state')
        self.assertIsNot(fresh,d)
        self.assertEqual(fresh.endpoint_info['lease_number'],2)
        self.assertEqual(fresh.dispatch(request(fresh.session,'commit',args,uid(4),now=103)),result)
        self.assertEqual(Files.identity(target.stat()),identity)

    def test_unexpired_lease_and_legacy_endpoint_are_not_rotated(self):
        d=self.dispatcher()
        self.assertIs(agent.renew_file_lease(d,{'persistent_endpoint':True},self.files,self.root/'state'),d)
        d.expires=0
        self.assertIs(agent.renew_file_lease(d,{},self.files,self.root/'state'),d)

    def test_running_receiver_survives_lease_expiry_and_can_still_close(self):
        from session_protocol import MAGIC,canonical
        clock=[100.0]
        def now():return clock[0]
        def sleep(value):clock[0]+=value
        def construct(*args,**kwargs):
            kwargs.setdefault('now',now)
            return Dispatcher(*args,**kwargs)
        class Wire:
            def open(self,value,**_):return json.loads(value[len(MAGIC):])
            def seal(self,value,**_):return MAGIC+canonical(value).decode()
        board=None
        class Board:
            value=None
            hello_result=None
            hello_sent=False
            close_sent=False
            def __init__(self,*_):
                nonlocal board
                board=self
            def read(self):
                if clock[0]>=104 and self.hello_result and not self.close_sent:
                    self.close_sent=True
                    self.value=MAGIC+canonical(request(self.hello_result['session'],
                        'close',{},uid(8),now=clock[0])).decode()
                elif clock[0]>=103 and not self.hello_sent:
                    self.hello_sent=True
                    self.value=MAGIC+canonical(request(uid(7),'hello',{},uid(7),now=clock[0])).decode()
                return self.value
            def write(self,text):
                self.value=text
                reply=json.loads(text[len(MAGIC):])
                if reply['id']==uid(7):self.hello_result=reply['result']
            def close(self):pass
        cfg={'profile':'files-online-v1','persistent_endpoint':True,'enable_workers':False,
            'state':str(self.root/'state'),'display':':19.0','allowed_roots':[str(self.allowed)],
            'write_roots':[str(self.allowed)],'enable_writes':True,
            'endpoint_id':uid(9),'session_seconds':2,'initial_handshake_timeout_seconds':0}
        with patch.object(agent,'Dispatcher',side_effect=construct),patch.object(agent,'Selection',Board),\
             patch.object(agent,'identity_files',return_value=Wire()),\
             patch.object(agent.time,'time',side_effect=now),\
             patch.object(agent.time,'monotonic',side_effect=now),\
             patch.object(agent.time,'sleep',side_effect=sleep),\
             patch('session_runner_pause.inventory',return_value=([],[])),\
             contextlib.redirect_stdout(io.StringIO()):
            # Fingerprinting is public metadata; fake it without touching keys.
            Wire.fingerprint=lambda self,_:uid(9)*2
            cfg['server_cert']='synthetic'
            self.assertEqual(agent.serve(cfg,None,False,generation=1),0)
        self.assertTrue(board.close_sent)
        self.assertGreater(board.hello_result['endpoint']['lease_number'],1)
        self.assertGreater(clock[0],cfg['session_seconds']+100)

    def test_unconfirmed_read_survives_a_lease_change(self):
        source=self.allowed/'source.txt';source.write_bytes(b'preserve pending download')
        meta=self.files.read_begin({'path':str(source),'transfer_id':uid(2)})
        d=self.dispatcher();d.expires=0
        fresh=agent.renew_file_lease(d,{'persistent_endpoint':True,'session_seconds':2},self.files,self.root/'state')
        value=fresh.dispatch(request(fresh.session,'read_chunk',{'transfer_id':uid(2),
            'offset':0,'limit':100},uid(6),now=100))
        self.assertEqual(base64.b64decode(value['data']),source.read_bytes())
        self.assertTrue((self.files.root/('read-'+uid(2))/'data').exists())








    def test_file_profile_cannot_enable_worker_or_broaden_roots(self):
        install=Path('/srv/test/install');host='test-node'
        settings=demo_site(install);site_config._loaded=settings
        config={'profile':'files-online-v1','transport_host':host,'persistent_endpoint':True,
            'enable_workers':False,'enable_writes':True,'allowed_roots':settings['permissions']['read_roots'],
            'write_roots':settings['permissions']['write_roots'],
            'state':str(install/'.private/state/files'),
            'session_seconds':3600,'initial_handshake_timeout_seconds':0,'endpoint_id':uid(9)}
        agent.validate_file_profile(config,host,install)
        for change in ({'enable_workers':True},{'allowed_roots':['/']},
                       {'write_roots':settings['permissions']['read_roots']},{'session_seconds':0},
                       {'state':'/tmp/other'},{'transport_host':'other-node'}):
            with self.assertRaises(Rejected):agent.validate_file_profile(dict(config,**change),host,install)

    def test_client_reconnects_expired_lease_without_changing_business_id(self):
        client=Client.__new__(Client);client.session=uid(1);client.session_expires=1000
        client.now=lambda:100
        seen=[]
        def exchange(message):
            seen.append(message)
            if len(seen)==1:raise Rejected('SESSION_EXPIRED')
            return {'recovered':True}
        client.exchange=exchange
        def hello():client.session=uid(2)
        client.hello=hello
        self.assertTrue(client.call('receipt',{'transaction_id':uid(3)},uid(4))['recovered'])
        self.assertEqual([m['id'] for m in seen],[uid(4),uid(4)])
        self.assertNotEqual(seen[0]['session'],seen[1]['session'])


class SupervisorTests(unittest.TestCase):
    def test_start_reuses_verified_live_processes_without_spawning(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            state=private_directory(Path(tmp)/'state')
            config={'profile':'files-online-v1','state':str(state),'endpoint_id':uid(9)}
            folder=agent.endpoint_status_directory(config)
            def process(pid):return {'pid':pid,'start':'unchanged','exe':'python','cwd':'owned'}
            atomic_json(folder/'supervisor.json',{'state':'running','pid':10,'child_pid':11,
                'generation':3,'process_identity':process(10)})
            atomic_json(folder/'receiver.json',{'state':'ready','pid':11,'generation':3,
                'endpoint_id':uid(9),'lease_seconds':3600,'process_identity':process(11)})
            with patch.object(agent.subprocess if hasattr(agent,'subprocess') else subprocess,'Popen') as spawn:
                result=agent.start_files(config,'unused',popen=spawn,inspect=process,sleep=lambda _:None)
            self.assertEqual(result['state'],'ready');spawn.assert_not_called()

    def test_stale_parent_pid_does_not_adopt_or_kill_an_orphan_receiver(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            state=private_directory(Path(tmp)/'state')
            config={'profile':'files-online-v1','state':str(state),'endpoint_id':uid(9)}
            folder=agent.endpoint_status_directory(config)
            def process(pid):return {'pid':pid,'start':'same','exe':'python','cwd':'owned'}
            atomic_json(folder/'supervisor.json',{'process_identity':dict(process(10),start='old')})
            atomic_json(folder/'receiver.json',{'process_identity':process(11)})
            spawn=unittest.mock.Mock()
            with self.assertRaisesRegex(Rejected,'ORPHAN_RECEIVER_REQUIRES_REVIEW'):
                agent.start_files(config,'unused',popen=spawn,inspect=process,sleep=lambda _:None)
            spawn.assert_not_called()

    def test_nonzero_child_restarts_and_normal_close_stays_closed(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            root=Path(tmp);state=private_directory(root/'state')
            config={'profile':'files-online-v1','enable_workers':False,
                'state':str(state),'endpoint_id':uid(9)}
            path=root/'config.json';path.write_text('{}')
            launches=[];codes=[1,1,0]
            class Child:
                pid=123
                def __init__(self,command,**kw):launches.append(command);self.code=codes.pop(0)
                def poll(self):return self.code
                def wait(self):return self.code
            with patch.object(agent,'load_config',return_value=config),patch('session_runner_pause.inventory',return_value=([],[])):
                self.assertEqual(agent.maintain_files(config,path,popen=Child,sleep=lambda _:None),0)
            self.assertEqual(len(launches),3)
            self.assertEqual([cmd[-1] for cmd in launches],['1','2','3'])
            self.assertTrue(all(cmd[4]==str(Path(agent.__file__).resolve()) for cmd in launches))
            status=Files.meta(state.with_name(state.name+'-status')/'supervisor.json')
            self.assertEqual(status['state'],'stopped')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--report')
    parser.add_argument('--native-posix',action='store_true')
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    if args.native_posix:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_session.FileTests.test_symlink_rejection'))
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    report={'tests':result.testsRun,'failures':len(result.failures),
        'errors':len(result.errors),'skips':len(result.skipped),'ok':result.wasSuccessful(),
        'business_simulations':0,'native_clipboard_access':False}
    if args.report:
        path=Path(args.report);private_directory(path.parent);atomic_json(path,report)
    print(json.dumps(report))
    raise SystemExit(not result.wasSuccessful())
