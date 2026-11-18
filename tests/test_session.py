import importlib.util
import contextlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
TEST_TEMP=Path.cwd()/'.work/test-etx-clipboard-bridge'
TEST_TEMP.mkdir(parents=True,exist_ok=True)
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'etx'))
sys.path.insert(0,str(BASE/'local'))
sys.path.insert(0,str(BASE/'clients'))
from session_protocol import *
from session_files import Files, private_directory, atomic_json
from session_service import Dispatcher
from windows_session import Client,clipboard_text
import windows_session as session_client
try:
    from etx_cli import Project
except ImportError:
    Project=None


def uid(n):
    return format(n,'032x')


def temporary_directory():
    root=TEST_TEMP
    root.mkdir(exist_ok=True)
    return tempfile.TemporaryDirectory(dir=root)


class ProtocolTests(unittest.TestCase):
    def test_windows_unicode_clipboard_padding_does_not_change_text(self):
        self.assertEqual(clipboard_text('汉字\nend\0'.encode('utf-16-le')+b'\xff\xff\xff'),
            '汉字\nend')
        for raw in (b'x',b'x\x00',b'\x00\xd8\x00\x00'):
            with self.assertRaisesRegex(Rejected,'CLIPBOARD_ENCODING_REJECTED'):
                clipboard_text(raw)

    def test_duplicate_keys_nonfinite_truncation_and_wrong_fields_rejected(self):
        for data in (b'{"a":1,"a":2}',b'{"n":NaN}',b'{"x":',b'[]',b'\xff'):
            with self.assertRaises(Rejected):
                strict_json(data)
        message=request(uid(1),'status',{'request_id':uid(9)},uid(2),now=100)
        for change in ({'session':uid(3)},{'expires':99},{'op':'exec'},
                       {'argv':['sh','-c','bad']},{'v':True}):
            with self.assertRaises(Rejected):
                validate_request(dict(message,**change),uid(1),now=100)

    def test_transport_renewal_keeps_business_identity(self):
        one=request(uid(1),'status',{'request_id':uid(9)},uid(2),now=100)
        two=request(uid(3),'status',{'request_id':uid(9)},uid(2),now=200)
        self.assertEqual(operation_digest(one),operation_digest(two))
        with self.assertRaises(Rejected):
            validate_request(one,uid(1),now=221)


class FileFixture:
    def setUp(self):
        self.temp=temporary_directory()
        self.root=Path(self.temp.name)
        self.allowed=self.root/'project'
        self.allowed.mkdir()
        self.files=Files(self.root/'state',[self.allowed],True)
        self.serial=20

    def tearDown(self):
        self.temp.cleanup()

    def upload(self,target,data,before='absent'):
        self.serial+=1
        transfer=uid(self.serial)
        self.files.upload_begin({'transfer_id':transfer,'path':str(target),
            'bytes':len(data),'sha256':digest(data),'expected_before_sha256':before})
        for offset in range(0,len(data),MAX_CHUNK):
            part=data[offset:offset+MAX_CHUNK]
            self.files.upload_chunk({'transfer_id':transfer,'offset':offset,
                'data':encode_bytes(part),'sha256':digest(part)})
        return transfer


class FileTests(FileFixture,unittest.TestCase):
    def test_restore_backs_up_current_version_and_removes_originally_absent_file(self):
        existing,new=self.allowed/'existing',self.allowed/'new'
        existing.write_bytes(b'before')
        transfers=[self.upload(existing,b'after',digest(b'before')),
            self.upload(new,b'created')]
        self.files.commit({'transaction_id':uid(10),'transfer_ids':transfers})
        args={'transaction_id':uid(10),'restoration_id':uid(11)}
        result=self.files.restore(args)
        self.assertEqual(result['state'],'committed')
        self.assertEqual(existing.read_bytes(),b'before')
        self.assertFalse(new.exists())
        backup=self.files.root/('restoration-'+uid(11))
        self.assertEqual((backup/'0.before').read_bytes(),b'after')
        self.assertEqual((backup/'1.before').read_bytes(),b'created')
        self.assertEqual(self.files.restore(args),result)

    def test_restore_conflict_leaves_all_targets_unchanged(self):
        existing=self.allowed/'existing'
        existing.write_bytes(b'before')
        transfer=self.upload(existing,b'after',digest(b'before'))
        self.files.commit({'transaction_id':uid(10),'transfer_ids':[transfer]})
        existing.write_bytes(b'user edit')
        with self.assertRaisesRegex(Rejected,'BASELINE_CONFLICT'):
            self.files.restore({'transaction_id':uid(10),'restoration_id':uid(11)})
        self.assertEqual(existing.read_bytes(),b'user edit')

    def test_read_roots_do_not_grant_write_permission(self):
        self.files.write_roots=[]
        path=self.allowed/'readonly'
        path.write_bytes(b'keep')
        self.files.read_begin({'path':str(path),'transfer_id':uid(1)})
        with self.assertRaisesRegex(Rejected,'PATH_NOT_AUTHORIZED'):
            self.upload(path,b'change',digest(b'keep'))

    def test_byte_exact_binary_and_unicode_download(self):
        data=bytes(range(256))*2048+'汉字\r\nend\n'.encode()
        source=self.allowed/'source.bin'
        source.write_bytes(data)
        meta=self.files.read_begin({'path':str(source),'transfer_id':uid(1)})
        source.write_bytes(b'user edited source after snapshot')
        chunks=[]
        for offset in range(0,meta['bytes'],MAX_CHUNK):
            part=self.files.read_chunk({'transfer_id':uid(1),'offset':offset,'limit':MAX_CHUNK})
            raw=decode_bytes(part['data'])
            self.assertEqual(digest(raw),part['sha256'])
            chunks.append(raw)
        self.assertEqual(b''.join(chunks),data)
        self.assertEqual(meta['sha256'],digest(data))

    def test_resume_duplicate_ack_and_changed_chunk(self):
        target=self.allowed/'x'
        data=b'abcdef'
        transfer=uid(2)
        args={'transfer_id':transfer,'path':str(target),'bytes':6,
            'sha256':digest(data),'expected_before_sha256':'absent'}
        self.files.upload_begin(args)
        chunk={'transfer_id':transfer,'offset':0,'data':encode_bytes(b'abc'),
            'sha256':digest(b'abc')}
        self.files.upload_chunk(chunk)
        self.files.upload_chunk(chunk)  # Lost acknowledgement: no duplicate bytes.
        self.assertEqual(self.files.upload_begin(args)['received'],3)
        with self.assertRaises(Rejected):
            self.files.upload_chunk(dict(chunk,data=encode_bytes(b'abX'),sha256=digest(b'abX')))
        with self.assertRaises(Rejected):
            self.files.upload_chunk(dict(chunk,offset=4))
        self.files.upload_chunk(dict(chunk,offset=3,data=encode_bytes(b'def'),sha256=digest(b'def')))
        result=self.files.commit({'transaction_id':uid(3),'transfer_ids':[transfer]})
        self.assertEqual(result['state'],'committed')
        self.assertEqual(target.read_bytes(),data)

    def test_concurrent_target_edit_is_not_overwritten(self):
        target=self.allowed/'existing'
        target.write_bytes(b'baseline')
        transfer=self.upload(target,b'new',digest(b'baseline'))
        target.write_bytes(b'user change')
        with self.assertRaisesRegex(Rejected,'BASELINE_CONFLICT'):
            self.files.commit({'transaction_id':uid(4),'transfer_ids':[transfer]})
        self.assertEqual(target.read_bytes(),b'user change')

    def test_batch_failure_rolls_back_prior_install_and_preserves_mode(self):
        first,second=self.allowed/'one',self.allowed/'two'
        first.write_bytes(b'old1')
        second.write_bytes(b'old2')
        first.chmod(0o640)
        transfers=[self.upload(first,b'new1',digest(b'old1')),
                   self.upload(second,b'new2',digest(b'old2'))]
        replace=self.files.replace
        def fail_second(path,data,mode):
            if path==second:
                raise OSError('injected disk failure')
            replace(path,data,mode)
        with patch.object(self.files,'replace',side_effect=fail_second):
            with self.assertRaises(OSError):
                self.files.commit({'transaction_id':uid(5),'transfer_ids':transfers})
        self.assertEqual(first.read_bytes(),b'old1')
        self.assertEqual(second.read_bytes(),b'old2')
        self.assertEqual(self.files.receipt({'transaction_id':uid(5)})['state'],'rolled_back')
        if os.name=='posix':
            self.assertEqual(first.stat().st_mode & 0o777,0o640)

    def test_crash_after_install_recovers_receipt_without_second_install(self):
        target=self.allowed/'crash'
        target.write_bytes(b'before')
        transfer=self.upload(target,b'after',digest(b'before'))
        args={'transaction_id':uid(6),'transfer_ids':[transfer]}
        replace=self.files.replace
        def crash(path,data,mode):
            replace(path,data,mode)
            raise KeyboardInterrupt('simulated process loss after rename')
        with patch.object(self.files,'replace',side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.files.commit(args)
        with patch.object(self.files,'replace',side_effect=AssertionError('must not reinstall')):
            result=self.files.commit(args)
        self.assertEqual(result['state'],'committed')
        self.assertEqual(target.read_bytes(),b'after')

    def test_path_boundary_rejection(self):
        for path in (self.root/'outside',self.allowed/'..'/'outside'):
            with self.assertRaises(Rejected):
                self.files.path(str(path),absent=True)

    def test_symlink_rejection(self):
        original=self.allowed/'real'
        original.write_bytes(b'a')
        link=self.allowed/'link'
        try:
            link.symlink_to(original)
        except (OSError,NotImplementedError):
            self.skipTest('Local symlink privilege unavailable; native POSIX check required')
        with self.assertRaisesRegex(Rejected,'SYMLINK_REJECTED'):
            self.files.path(str(link))

    def test_missing_baseline_and_incomplete_upload_rejected(self):
        with self.assertRaises(Rejected):
            self.files.upload_begin({'transfer_id':uid(8),'path':str(self.allowed/'x'),
                'bytes':1,'sha256':digest(b'x')})
        self.files.upload_begin({'transfer_id':uid(8),'path':str(self.allowed/'x'),
            'bytes':1,'sha256':digest(b'x'),'expected_before_sha256':'absent'})
        with self.assertRaisesRegex(Rejected,'TRANSFER_INCOMPLETE'):
            self.files.commit({'transaction_id':uid(9),'transfer_ids':[uid(8)]})


class FakeWorker:
    def __init__(self):
        self.executions=0
        self.jobs={}
    def submit_simmer(self,args):
        rid=args['request_id']
        if rid not in self.jobs:
            self.executions+=1
            self.jobs[rid]={'state':'running','request_id':rid}
        return dict(self.jobs[rid])
    def status(self,args):
        return dict(self.jobs[args['request_id']])


class DispatcherTests(FileFixture,unittest.TestCase):
    def test_close_is_idempotent_and_stops_further_file_operations(self):
        dispatcher=Dispatcher(self.root/'rpc',self.files,uid(1),now=lambda:100)
        message=request(uid(1),'close',{},uid(2),now=100)
        self.assertTrue(dispatcher.dispatch(message)['closing'])
        self.assertTrue(dispatcher.dispatch(message)['closing'])
        with self.assertRaisesRegex(Rejected,'SESSION_CLOSING'):
            dispatcher.dispatch(request(uid(1),'search',{'root':str(self.allowed),
                'pattern':'x'},uid(3),now=100))

    def test_log_append_is_allowed_but_replacement_or_truncation_rejected(self):
        path=self.allowed/'stdout.log'
        path.write_bytes(b'first\n')
        worker=FakeWorker()
        worker.log_path=lambda rid,stream:str(path)
        dispatcher=Dispatcher(self.root/'rpc',self.files,uid(1),worker,now=lambda:100)
        args={'request_id':uid(10),'stream':'stdout','offset':0,'limit':3,'identity':None}
        one=dispatcher.read_log(args)
        with path.open('ab') as stream:
            stream.write(b'second\n')
        two=dispatcher.read_log(dict(args,offset=3,identity=one['identity']))
        self.assertEqual(decode_bytes(two['data']),b'st\n')
        path.write_bytes(b'x')
        with self.assertRaisesRegex(Rejected,'LOG_TRUNCATED'):
            dispatcher.read_log(dict(args,offset=two['next_offset'],identity=one['identity']))
        replacement=self.allowed/'replacement'
        replacement.write_bytes(b'another file\n')
        os.replace(replacement,path)
        with self.assertRaisesRegex(Rejected,'LOG_REPLACED'):
            dispatcher.read_log(dict(args,identity=one['identity']))

    def test_submit_lost_receipt_recovery_and_replay_conflict(self):
        worker=FakeWorker()
        dispatcher=Dispatcher(self.root/'rpc',self.files,uid(1),worker,now=lambda:100)
        message=request(uid(1),'submit_simmer',{'request_id':uid(15)},uid(16),now=100)
        real_atomic=atomic_json
        def fail_final(path,value):
            if value.get('state')=='done':
                raise OSError('lost RPC receipt')
            real_atomic(path,value)
        with patch('session_service.atomic_json',side_effect=fail_final):
            with self.assertRaises(OSError):
                dispatcher.dispatch(message)
        reply=dispatcher.dispatch(message)
        self.assertEqual(reply['state'],'running')
        self.assertEqual(worker.executions,1)
        with self.assertRaisesRegex(Rejected,'REQUEST_ID_CONFLICT'):
            dispatcher.dispatch(dict(message,args={'request_id':uid(17)}))
        worker.jobs[uid(15)]['state']='exited'
        status=request(uid(1),'status',{'request_id':uid(15)},uid(18),now=100)
        self.assertEqual(dispatcher.dispatch(status)['state'],'exited')
        worker.jobs[uid(15)]['state']='needs_review'
        self.assertEqual(dispatcher.dispatch(status)['state'],'needs_review')


@unittest.skipIf(Project is None,'Project consumer is not part of this endpoint bundle')
class ProjectTransferTests(FileFixture,unittest.TestCase):
    def test_lost_chunk_and_commit_ack_resume_one_install_and_exact_download(self):
        client_root=self.root/'client'
        private=client_root/'.private/x11'
        private.mkdir(parents=True)
        source=private/'synthetic.txt'
        data=('synthetic UTF-8 text\n'*20000).encode('utf-8')  # Multiple chunks, below the text upload limit.
        source.write_bytes(data)
        target=self.allowed/'installed.txt'
        manifest=private/'upload.json'
        atomic_json(manifest,{'files':[{'source':str(source),'target':str(target),
            'expected_before_sha256':'absent'}]})
        dispatcher=Dispatcher(self.root/'rpc',self.files,uid(1),now=lambda:100)
        uploader=Project(client_root,uid(30))
        lost={'upload_chunk':True,'commit':True}
        def rpc(op,args,name=None):
            rid=uploader.sub_id(name) if name else uuid.uuid4().hex
            result=dispatcher.dispatch(request(uid(1),op,args,rid,now=100))
            if lost.get(op):
                lost[op]=False
                raise OSError('synthetic acknowledgement loss')
            return result
        uploader.rpc=rpc
        with self.assertRaises(OSError):
            uploader.upload(manifest)
        self.assertFalse(target.exists())
        with self.assertRaises(OSError):
            uploader.upload(manifest)
        self.assertEqual(target.read_bytes(),data)
        with patch.object(self.files,'replace',side_effect=AssertionError('must not reinstall')):
            self.assertEqual(uploader.upload(manifest)['state'],'committed')
        downloader=Project(client_root,uid(31))
        downloader.rpc=lambda op,args,name=None:dispatcher.dispatch(request(uid(1),op,args,
            downloader.sub_id(name) if name else None,now=100))
        def text_transport(command):
            from windows_read_files import read_files
            class Adapter:
                def call(self,op,args,rid):
                    return dispatcher.dispatch(request(uid(1),op,args,rid,now=100))
            spec=Files.meta(Path(command[command.index('-SessionRequest')+1]))
            value=read_files(Adapter(),spec,downloader.result)
            atomic_json(downloader.result/'summary.json',{'ok':True,'result':value})
            return subprocess.CompletedProcess(command,0,b'',b'')
        downloader.transport=text_transport
        output=downloader.read(str(target),'download.bin')
        self.assertEqual(Path(output['path']).read_bytes(),data)


class ExistingQueueTests(FileFixture,unittest.TestCase):
    def setUp(self):
        super().setUp()
        source=BASE/'worker-runtime/sim_control.py'
        spec=importlib.util.spec_from_file_location('existing_queue_under_test',source)
        self.module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.clock=1000
        self.queue=self.module.Queue(self.root/'queue',lambda:contextlib.nullcontext(),
            now=lambda:self.clock)
        self.queue.prepare()
        self.profiles={}
        for n in range(1,7):
            profile={'profile':'work{:02d}'.format(n),'cases':{'run':{}},
                'timeout_seconds':14400,'parallel':True,'command_certificate':'public'}
            self.profiles[n]=profile
            self.queue.heartbeat(uid(n),profile,False)

    def reserve(self,n,rid=None):
        return self.queue.reserve(rid or uid(100+n),'work{:02d}'.format(n),
            'run',1,uid(n),encode_bytes(b'opaque signed command'))

    def test_real_queue_claim_once_and_stable_reservation(self):
        original,created=self.reserve(1)
        again,recreated=self.reserve(1)
        self.assertTrue(created)
        self.assertFalse(recreated)
        self.assertEqual(original,again)
        self.assertEqual(self.queue.claim(uid(1),self.profiles[1]),original)
        self.assertIsNone(self.queue.claim(uid(1),self.profiles[1]))
        with self.assertRaisesRegex(self.module.Rejected,'WORKER_ALREADY_ASSIGNED'):
            self.reserve(1,uid(300))

    def test_five_slots_and_needs_review_reservation_remain_protected(self):
        for n in range(1,6):
            self.reserve(n)
        with self.assertRaisesRegex(self.module.Rejected,'SIMULATION_CAPACITY_REACHED'):
            self.reserve(6)
        self.queue.finish(self.queue.job(uid(101)),'needs_review')
        with self.assertRaisesRegex(self.module.Rejected,'SIMULATION_CAPACITY_REACHED'):
            self.reserve(6)
        self.queue.finish(self.queue.job(uid(101)),'exited',exit_code=0)
        self.assertTrue(self.reserve(6)[1])

    def test_expired_queued_request_is_not_executed_or_replaced(self):
        self.reserve(1)
        self.clock+=31
        self.assertIsNone(self.queue.claim(uid(1),self.profiles[1]))
        again,created=self.reserve(1)
        self.assertFalse(created)
        self.assertEqual(again['request_id'],uid(101))
        self.assertEqual(self.queue.snapshot(uid(101))['state'],'not_started')


class CryptoAndExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=temporary_directory()
        cls.root=Path(cls.temp.name)
        cls.openssl=shutil.which('openssl') or next((p for p in (
            'C:/Program Files/Git/mingw64/bin/openssl.exe',
            'C:/Program Files/Git/usr/bin/openssl.exe',
            'C:/Program Files/Git/usr/bin/openssl.exe') if Path(p).is_file()),None)
        if not cls.openssl:
            raise unittest.SkipTest('OpenSSL unavailable')
        for name in ('client','server','stranger'):
            subprocess.run([cls.openssl,'req','-new','-x509','-newkey','rsa:2048',
                '-nodes','-days','1','-subj','/CN='+name,'-keyout',str(cls.root/(name+'.key')),
                '-out',str(cls.root/(name+'.pem'))],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def crypt(self,name,peer):
        return Crypto(self.root/(name+'.pem'),self.root/(name+'.key'),
            self.root/(peer+'.pem'),self.root/(peer+'.pem'),self.openssl)

    def test_encrypted_roundtrip_tampering_wrong_peer_and_signed_command_rejection(self):
        client,server=self.crypt('client','server'),self.crypt('server','client')
        message=request(uid(1),'status',{'request_id':uid(2)},uid(3),now=100)
        wire=client.seal(message)
        self.assertNotIn('status',wire)
        self.assertEqual(server.open(wire),message)
        self.assertEqual(server.open(wire.replace(MAGIC,MAGIC_CRLF,1)),message)
        frame=strict_json(wire[len(MAGIC):].encode(),MAX_WIRE)
        frame['sha256']='0'*64
        with self.assertRaises(Rejected):
            server.open(MAGIC+canonical(frame).decode())
        with self.assertRaises(Rejected):
            self.crypt('server','stranger').open(wire)
        with self.assertRaisesRegex(Rejected,'ENCRYPTION_REQUIRED'):
            server.open(client.seal(message,encrypted=False),allow_signed_hello=True)

    def test_clipboard_collision_preserves_user_text(self):
        class Board:
            value='original'
            def read(self): return self.value
            def write(self,value,expected=None,compare=False):
                require(not compare or self.value==expected,'CLIPBOARD_USER_CHANGED')
                self.value='user copied new text' if value and value.startswith(MAGIC) else value
        config={'signer_cert':str(self.root/'client.pem'),'signer_key':str(self.root/'client.key'),
            'server_cert':str(self.root/'server.pem'),'openssl':self.openssl}
        board=Board()
        client=Client(config,board)
        with self.assertRaisesRegex(Rejected,'CLIPBOARD_USER_CHANGED'):
            client.exchange(request(uid(1),'status',{},now=time.time()))
        self.assertEqual(board.value,'user copied new text')

    def test_pair_lost_response_and_reconnect_use_same_operation(self):
        class Clock:
            value=1000
            def now(self): return self.value
            def sleep(self,seconds): self.value+=seconds
        class Peer:
            def __init__(peer,dispatcher,crypto):
                peer.value='original user text'
                peer.dispatcher=dispatcher
                peer.crypto=crypto
                peer.lose_submit_once=True
            def read(peer): return peer.value
            def write(peer,value,expected=None,compare=False):
                require(not compare or peer.value==expected,'CLIPBOARD_USER_CHANGED')
                peer.value=value
                if value and value.startswith(MAGIC):
                    incoming=peer.crypto.open(value,allow_signed_hello=True)
                    response={'v':1,'id':incoming['id'],'session':incoming['session'],
                        'request_sha256':digest(normalize_frame(value).encode('ascii')),
                        'expires':int(clock.now())+120}
                    try:
                        response.update(ok=True,result=peer.dispatcher.dispatch(incoming))
                    except Rejected as exc:
                        response.update(ok=False,error=exc.code)
                    if incoming['op']=='submit_simmer' and peer.lose_submit_once:
                        peer.lose_submit_once=False
                        return
                    peer.value=peer.crypto.seal(response,advertise_cert=incoming['op']=='hello').replace(MAGIC,MAGIC_CRLF,1)
        with temporary_directory() as temporary:
            root=Path(temporary)
            clock=Clock()
            files=Files(root/'files',[root])
            worker=FakeWorker()
            dispatcher=Dispatcher(root/'rpc',files,uid(1),worker,now=clock.now)
            peer=Peer(dispatcher,self.crypt('server','client'))
            pinned=root/'server.pem'
            config={'signer_cert':str(self.root/'client.pem'),
                'signer_key':str(self.root/'client.key'),'server_cert':str(pinned),
                'openssl':self.openssl,'connection_state':str(root/'connection.json')}
            client=Client(config,peer,now=clock.now,sleep=clock.sleep)
            client.hello(self.crypt('server','client').fingerprint(self.root/'server.pem'))
            self.assertEqual(peer.value,'original user text')
            self.assertEqual(client.session,uid(1))
            args={'request_id':uid(30)}
            with self.assertRaisesRegex(Rejected,'RPC_TIMEOUT_QUERY_SAME_ID'):
                client.call('submit_simmer',args,uid(31))
            self.assertEqual(worker.executions,1)
            reply=client.call('submit_simmer',args,uid(31))
            self.assertEqual(reply['state'],'running')
            self.assertEqual(worker.executions,1)
            self.assertGreaterEqual(clock.now(),1030)
            peer.dispatcher=Dispatcher(root/'rpc',files,uid(2),worker,now=clock.now)
            reconnected=Client(config,peer,now=clock.now,sleep=clock.sleep)
            self.assertEqual(reconnected.call('submit_simmer',args,uid(31)),reply)
            self.assertEqual(worker.executions,1)
            self.assertEqual(reconnected.session,uid(2))
            self.assertEqual(peer.value,'original user text')

    def test_stale_authenticated_hello_reply_retries_same_request_and_restores_clipboard(self):
        class Clock:
            value=1000
            def now(self): return self.value
            def sleep(self,seconds): self.value+=seconds
        clock=Clock()
        server=self.crypt('server','client')
        class Board:
            def __init__(board,value):
                board.value=value
                board.requests=[]
            def read(board): return board.value
            def write(board,value,expected=None,compare=False):
                require(not compare or board.value==expected,'CLIPBOARD_USER_CHANGED')
                board.value=value
                if value and value.startswith(MAGIC):
                    message=server.open(value,allow_signed_hello=True)
                    board.requests.append(message)
                    response={'v':1,'id':message['id'],'session':message['session'],
                        'request_sha256':digest(normalize_frame(value).encode('ascii')),
                        'expires':int(clock.now())+120,'ok':True,
                        'result':{'session':uid(40),'expires':int(clock.now())+3600}}
                    if len(board.requests)==1:
                        response.update(id=uid(90),session=uid(91),expires=999)
                    board.value=server.seal(response,advertise_cert=True).replace(MAGIC,MAGIC_CRLF,1)
            def sequence(board):return len(board.requests)
        old_reply=server.seal({'v':1,'id':uid(90),'session':uid(91),'expires':999,
            'ok':True,'result':{}},advertise_cert=True)
        for baseline in ('original user text',old_reply):
            clock.value=1000
            with self.subTest(protocol_residue=baseline==old_reply),temporary_directory() as temporary:
                root=Path(temporary)
                board=Board(baseline)
                client=Client({'signer_cert':str(self.root/'client.pem'),
                    'signer_key':str(self.root/'client.key'),'server_cert':str(root/'server.pem'),
                    'openssl':self.openssl},board,now=clock.now,sleep=clock.sleep)
                client.hello(server.fingerprint(self.root/'server.pem'))
                self.assertEqual(client.session,uid(40))
                self.assertEqual(len(board.requests),2)
                self.assertEqual(board.requests[0]['id'],board.requests[1]['id'])
                self.assertGreaterEqual(board.requests[1]['issued']-board.requests[0]['issued'],30)
                self.assertIsNone(board.value)
                self.assertTrue(client.clipboard_restored)
                self.assertTrue(client.protocol_baseline_recovered)

    def test_maximum_chunk_crypto_roundtrip(self):
        client,server=self.crypt('client','server'),self.crypt('server','client')
        data=os.urandom(MAX_CHUNK)
        message=request(uid(1),'upload_chunk',{'transfer_id':uid(2),'offset':0,
            'data':encode_bytes(data),'sha256':digest(data)},uid(3),now=100)
        wire=client.seal(message)
        self.assertLess(len(wire),MAX_WIRE)
        self.assertEqual(server.open(wire),message)


class InterruptionRetryTests(FileFixture,unittest.TestCase):
    """Virtual time and clipboard; real durable dispatcher, no native clipboard."""
    def setUp(self):
        super().setUp()

        class Clock:
            value=1000.0
            events=[]
            board=None
            def now(clock): return clock.value
            def sleep(clock,seconds):
                target=clock.value+seconds
                while clock.events and clock.events[0][0]<=target:
                    when,value=clock.events.pop(0)
                    clock.value=when
                    clock.board.user_copy(value)
                clock.value=target
        self.clock=Clock()
        self.clock.events=[]

        class Wire:
            def seal(wire,message,**_):return MAGIC+canonical(message).decode()
            def open(wire,value,**_):return strict_json(normalize_frame(value)[len(MAGIC):].encode())
        wire=Wire()
        self.worker=FakeWorker()
        self.dispatcher=Dispatcher(self.root/'rpc',self.files,uid(1),
            self.worker,now=self.clock.now)
        clock,dispatcher=self.clock,self.dispatcher

        class Board:
            value='original user text'
            generation=0
            image=object()
            unsupported=object()
            interrupt_attempts=set()
            copy_at_resume_snapshot=False
            copy_at_restore=False
            writes=[]
            read_times=[]
            def sequence(board):return board.generation
            def user_copy(board,value):
                board.value=value
                board.generation+=1
            def read(board):
                board.read_times.append(clock.now())
                require(board.value not in (board.image,board.unsupported),'CLIPBOARD_NOT_PLAIN_TEXT')
                board.last_read_sequence=board.generation
                return board.value
            def snapshot(board):
                if board.copy_at_resume_snapshot and board.writes and clock.now()>=1030:
                    board.copy_at_resume_snapshot=False
                    board.user_copy('copy at resume boundary')
                text=None if board.value is board.image else board.read()
                return {'text':text,'sequence':board.sequence(),'image':board.value is board.image}
            def write(board,value,expected=None,compare=False,expected_sequence=None):
                current=None if board.value is board.image and expected_sequence is not None else board.value
                require(not compare or current==expected,'CLIPBOARD_USER_CHANGED')
                require(expected_sequence is None or board.sequence()==expected_sequence,
                    'CLIPBOARD_USER_CHANGED')
                board.user_copy(value)
                board.last_write_sequence=board.generation
                if not is_frame(value):return
                incoming=wire.open(value)
                board.writes.append((clock.now(),incoming))
                response={'v':1,'id':incoming['id'],'session':incoming['session'],
                    'request_sha256':digest(normalize_frame(value).encode('ascii')),
                    'expires':int(clock.now())+120,'ok':True,
                    'result':dispatcher.dispatch(incoming)}
                attempt=len(board.writes)
                if attempt in board.interrupt_attempts:
                    board.user_copy('user copy '+str(attempt))
                else:
                    board.user_copy(wire.seal(response))
            def restore(board,saved,expected,expected_sequence=None):
                if board.copy_at_restore:
                    board.copy_at_restore=False
                    board.user_copy('copy while verifying reply')
                require(board.value==expected and (expected_sequence is None or
                    board.sequence()==expected_sequence),'CLIPBOARD_USER_CHANGED')
                board.user_copy(board.image if saved['image'] else saved['text'])
                board.last_write_sequence=board.generation
        self.board=Board()
        self.board.writes=[]
        self.board.read_times=[]
        self.board.interrupt_attempts=set()
        self.clock.board=self.board
        patched=patch.object(session_client,'Crypto',return_value=wire)
        patched.start()
        self.addCleanup(patched.stop)
        self.client=Client({'signer_cert':'unused','signer_key':'unused',
            'server_cert':'unused'},self.board,now=self.clock.now,
            sleep=self.clock.sleep,monotonic=self.clock.now)
        self.client.session=uid(1)
        self.client.session_expires=10000

    def submit(self):
        return self.client.call('submit_simmer',{'request_id':uid(500)},uid(501))

    def assert_same_operation(self):
        messages=[message for _,message in self.board.writes]
        self.assertEqual({message['id'] for message in messages},{uid(501)})
        self.assertEqual(len({operation_digest(message) for message in messages}),1)
        self.assertEqual(self.worker.executions,1)

    def test_uninterrupted_exchange_has_no_initial_wait(self):
        self.submit()
        self.assertEqual(self.clock.now(),1000)
        self.assertEqual(self.client.interruption_retries,0)
        self.assertEqual(self.board.value,'original user text')

    def test_interruption_waits_30_seconds_and_recovers_committed_result_once(self):
        self.board.interrupt_attempts={1}
        self.submit()
        self.assertAlmostEqual(self.board.writes[1][0],1030,places=6)
        self.assertEqual(self.board.value,'user copy 1')
        self.assertEqual(self.client.interruption_retries,1)
        self.assert_same_operation()

    def test_another_user_copy_restarts_the_30_second_wait(self):
        self.board.interrupt_attempts={1}
        self.clock.events=[(1015,'second user copy')]
        self.submit()
        self.assertAlmostEqual(self.board.writes[1][0],1045,places=6)
        self.assertEqual(self.board.value,'second user copy')
        self.assert_same_operation()

    def test_copy_between_wait_and_snapshot_does_not_get_overwritten(self):
        self.board.interrupt_attempts={1}
        self.board.copy_at_resume_snapshot=True
        self.submit()
        self.assertEqual(len(self.board.writes),2)
        self.assertAlmostEqual(self.board.writes[1][0],1060,places=6)
        self.assertEqual(self.board.value,'copy at resume boundary')
        self.assert_same_operation()

    def test_quiet_wait_observes_sequence_without_reading_user_contents(self):
        self.board.interrupt_attempts={1}
        self.clock.events=[(1015,'second user copy')]
        self.submit()
        self.assertFalse(any(1000<t<1045 for t in self.board.read_times))
        self.assertAlmostEqual(self.board.writes[1][0],1045,places=6)

    def test_copy_during_restore_also_yields_before_same_id_recovery(self):
        self.board.copy_at_restore=True
        self.submit()
        self.assertAlmostEqual(self.board.writes[1][0],1030,places=6)
        self.assertEqual(self.board.value,'copy while verifying reply')
        self.assert_same_operation()

    def test_continuous_copying_stops_at_wait_limit_without_forcing_a_write(self):
        self.board.interrupt_attempts={1}
        self.clock.events=[(1000+20*i,'user copy at '+str(i)) for i in range(1,16)]
        with self.assertRaisesRegex(Rejected,'CLIPBOARD_USER_BUSY'):
            self.submit()
        self.assertEqual(len(self.board.writes),1)
        self.assertEqual(self.board.value,'user copy at 15')
        self.assertTrue(self.client.interruption_wait_expired)

    def test_transport_expiry_is_renewed_without_changing_business_identity(self):
        self.board.interrupt_attempts={1,2,3,4,5}
        self.submit()
        self.assertAlmostEqual(self.board.writes[-1][0],1150,places=6)
        self.assertGreater(self.board.writes[-1][1]['issued'],
            self.board.writes[0][1]['expires'])
        self.assert_same_operation()

    def test_image_uses_same_quiet_window_and_request(self):
        self.board.interrupt_attempts={1}
        self.clock.events=[(1015,self.board.image)]
        self.submit()
        self.assertAlmostEqual(self.board.writes[-1][0],1045,places=6)
        self.assertIs(self.board.value,self.board.image)
        self.assert_same_operation()

    def test_unrestorable_clipboard_value_is_preserved(self):
        self.board.interrupt_attempts={1}
        self.clock.events=[(1000.1,self.board.unsupported)]
        with self.assertRaisesRegex(Rejected,'CLIPBOARD_NOT_PLAIN_TEXT'):
            self.submit()
        self.assertEqual(len(self.board.writes),1)
        self.assertIs(self.board.value,self.board.unsupported)
        self.assertGreaterEqual(self.clock.now(),1030)

    def test_wait_before_first_send_does_not_expire_the_request(self):
        self.client.user_priority.owned(self.board.sequence())
        self.board.user_copy(self.board.image)
        self.clock.events=[(1000+20*i,self.board.image) for i in range(1,7)]
        self.submit()
        timestamp,message=self.board.writes[0]
        self.assertGreaterEqual(timestamp,1150)
        self.assertLess(timestamp,1150.2)
        self.assertGreater(message['expires'],timestamp)
        self.assertIs(self.board.value,self.board.image)
        self.assert_same_operation()

    def test_interrupted_close_does_not_retry_an_endpoint_that_is_shutting_down(self):
        self.dispatcher.worker=None
        self.board.interrupt_attempts={1}
        with self.assertRaisesRegex(Rejected,'CLIPBOARD_USER_CHANGED'):
            self.client.call('close',{},uid(502))
        self.assertEqual(len(self.board.writes),1)
        self.assertEqual(self.clock.now(),1000)
        self.assertEqual(self.board.value,'user copy 1')





if __name__=='__main__':
    unittest.main()
