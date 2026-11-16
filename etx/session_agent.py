#!/usr/bin/env python3
"""User-enabled foreground ETX session endpoint. No network listening ports."""
import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import traceback
import unittest
import uuid
from pathlib import Path
from site_config import site, configure

from session_protocol import (Crypto, Rejected, require, canonical, strict_json,
    digest, MAX_SESSION, MAGIC,is_frame,normalize_frame,identifier)
from session_files import Files, private_directory, file_lock, atomic_json
from session_service import Dispatcher




def validate_file_profile(config,host,install):
    settings=site(required=True)
    require(config.get('profile')=='files-online-v1' and config.get('transport_host')==host,
        'FILE_PROFILE_HOST_REJECTED')
    require(config.get('persistent_endpoint') is True and config.get('enable_workers') is False and
        config.get('enable_writes') is bool(settings['permissions']['write_roots']) and
        config.get('allowed_roots')==settings['permissions']['read_roots'] and
        config.get('write_roots')==settings['permissions']['write_roots'],'FILE_PROFILE_SCOPE_REJECTED')
    require(config.get('state')==str(Path(install)/'.private/state/files'),'FILE_PROFILE_STATE_REJECTED')
    require(type(config.get('session_seconds')) is int and 1<=config['session_seconds']<=MAX_SESSION and
        config.get('initial_handshake_timeout_seconds')==0,'FILE_PROFILE_LEASE_REJECTED')
    identifier(config.get('endpoint_id'))


def validate_execution_profile(config,host,install):
    settings=site(required=True)
    require(config.get('profile')=='execution-online-v1' and config.get('transport_host')==host,
        'CONTROL_PROFILE_HOST_REJECTED')
    require(config.get('persistent_endpoint') is True and config.get('enable_workers') is True and
        config.get('enable_writes') is bool(settings['permissions']['write_roots']) and
        config.get('allowed_roots')==settings['permissions']['read_roots'] and
        config.get('write_roots')==settings['permissions']['write_roots'],'CONTROL_PROFILE_SCOPE_REJECTED')
    require(config.get('state')==str(Path(install)/'.private/state/control') and
        config.get('worker_module')==str(Path(install)/'worker-runtime/sim_control.py'),'CONTROL_PROFILE_STATE_REJECTED')
    require(config.get('executor_profiles')==['work01','work02','work03','work04','work05'],'CONTROL_EXECUTOR_PROFILE_REJECTED')
    require(config.get('wave_enabled') is settings['wave']['enabled'] and
        config.get('wave_root')==settings['wave']['root'] and
        config.get('wave_fsdbs')==settings['permissions']['wave_fsdbs'],'CONTROL_WAVE_SCOPE_REJECTED')
    require(isinstance(config.get('worker_module_sha256'),str) and
        re.fullmatch('[0-9a-f]{64}',config['worker_module_sha256']) is not None,'CONTROL_MODULE_HASH_REJECTED')
    if config['wave_enabled']:
        require(config.get('wave_release')==settings['wave']['release'],'CONTROL_WAVE_RELEASE_REJECTED')
    identifier(config.get('endpoint_id'));identifier(config.get('activation_task_id'))
    require(config.get('activation_file')==str(Path(install)/'.private/state/activation.json'),'CONTROL_ACTIVATION_PATH_REJECTED')
    require(type(config.get('session_seconds')) is int and 1<=config['session_seconds']<=MAX_SESSION and
        config.get('initial_handshake_timeout_seconds')==0,'CONTROL_PROFILE_LEASE_REJECTED')


def load_config(path):
    path=Path(path)
    require(not path.is_symlink(),'CONFIG_REJECTED')
    config=strict_json(path.read_bytes())
    require(config.get('version')==1,'BAD_CONFIG_VERSION')
    settings=configure(config['site_config'])
    import pwd
    require(pwd.getpwuid(os.geteuid()).pw_name==settings['remote']['user'],'CONFIGURED_USER_REQUIRED')
    host=socket.gethostname().split('.')[0]
    install=Path(__file__).resolve().parents[1]
    require(Path(settings['remote']['install_root']).resolve()==install,'INSTALL_ROOT_MISMATCH')
    if config.get('profile')=='files-online-v1':validate_file_profile(config,host,install)
    elif config.get('profile')=='execution-online-v1':validate_execution_profile(config,host,install)
    else:raise Rejected('PROFILE_NOT_SUPPORTED')
    require(path.stat().st_uid==os.geteuid() and stat.S_IMODE(path.stat().st_mode)==0o600,'CONFIG_PERMISSIONS_REJECTED')
    return config


def make_worker(config, path):
    if config.get('profile')=='execution-online-v1':
        from session_control import ControlWorker
        return ControlWorker(config,path)
    from session_worker import Worker
    return Worker(config['worker_module'],config['worker_module_sha256'],
        private_directory(Path(config['state'])/'workers'),
        coordinator_script=Path(__file__).resolve(),coordinator_config=path)


def identity_files(config):
    cert, key = Path(config['server_cert']), Path(config['server_key'])
    require(cert.exists() == key.exists(), 'PARTIAL_SERVER_IDENTITY')
    if not cert.exists():
        require(cert.parent == key.parent, 'IDENTITY_PATH_REJECTED')
        private_directory(cert.parent)
        temporary_cert = cert.with_name(cert.name+'.new')
        temporary_key = key.with_name(key.name+'.new')
        require(not temporary_cert.exists() and not temporary_key.exists(), 'IDENTITY_RECOVERY_REQUIRED')
        Crypto(cert,key,cert,cert,config.get('openssl','openssl')).run([
            'req','-new','-x509','-newkey','rsa:3072','-nodes','-days','365',
            '-subj','/CN=etx-clipboard-bridge-session','-keyout',str(temporary_key),
            '-out',str(temporary_cert)])
        os.chmod(temporary_key,0o600)
        os.chmod(temporary_cert,0o600)
        os.replace(temporary_key,key)
        os.replace(temporary_cert,cert)
    for path in (key,cert,Path(config['trusted_client_cert']),Path(config['client_recipient_cert'])):
        require(not path.is_symlink() and path.is_file() and
            path.stat().st_uid == os.geteuid(), 'IDENTITY_FILE_REJECTED')
    require(stat.S_IMODE(key.stat().st_mode) == 0o600, 'PRIVATE_KEY_PERMISSIONS_REJECTED')
    crypto=Crypto(cert,key,config['trusted_client_cert'],
        config['client_recipient_cert'],config.get('openssl','openssl'))
    require(crypto.fingerprint(config['trusted_client_cert'])==
        crypto.fingerprint(config['client_recipient_cert']),'CLIENT_IDENTITY_MISMATCH')
    return crypto


class Selection:
    def __init__(self, display, selection='PRIMARY'):
        import tkinter as tk
        require(selection=='PRIMARY' or re.fullmatch('ETX_SESSION_SELFTEST_[0-9a-f]{32}',selection),
            'SELECTION_REJECTED')
        self.tk = tk
        self.display = display
        self.selection = selection
        self.root = tk.Tk(screenName=display)
        self.root.withdraw()
        self.writer = None
        self.owned = None

    def read(self):
        self.root.update()
        try:
            return self.root.selection_get(selection=self.selection,type='STRING')
        except self.tk.TclError:
            return None

    def write(self, text):
        # STRING and explicit ownership are required by the measured ETX route.
        # A new owner forces ETX to fetch the new response. Keep one Tcl
        # interpreter and display connection instead of creating repeated Tk
        # interpreters in a common event queue. Ownership ends when replaced
        # or this bounded session closes, never on an in-flight reply timer.
        previous=self.writer
        self.writer=self.tk.Toplevel(self.root)
        self.writer.withdraw()
        self.owned = text
        self.writer.selection_handle(lambda offset,length:
            text[int(offset):int(offset)+int(length)], selection=self.selection,type='STRING')
        self.writer.selection_own(selection=self.selection)
        self.root.update()
        if previous is not None:
            previous.destroy()

    def close(self):
        try:
            self.root.destroy()
        except self.tk.TclError:
            pass


def selection_check(display):
    """Exercise real X11 owners without changing PRIMARY or the user clipboard."""
    selection=Selection(display,'ETX_SESSION_SELFTEST_'+uuid.uuid4().hex)
    initial=len(os.listdir('/proc/self/fd'))
    maximum=initial
    owners=set()
    try:
        for index in range(256):
            text='ETX synthetic private selection {}\n'.format(index)+'x'*16384
            selection.write(text)
            require(selection.read()==text,'SELECTION_SELFTEST_FAILED')
            owners.add(selection.writer.winfo_id())
            maximum=max(maximum,len(os.listdir('/proc/self/fd')))
            require(maximum-initial<=4,'SELECTION_RESOURCE_GROWTH')
        require(len(owners)==256,'SELECTION_OWNER_REUSED')
        return {'ok':True,'publications':256,'distinct_owners':len(owners),
            'fd_growth':maximum-initial,'primary_changed':False}
    finally:
        selection.close()


def source_locks(mode):
    import fcntl
    root = private_directory(Path(site()['remote']['lock_root']))
    @contextlib.contextmanager
    def acquire():
        turn = os.open(str(root/'turnstile.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        resource = os.open(str(root/'resource.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            for fd in (turn,resource):
                info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and
                    info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'LOCK_REJECTED')
            fcntl.flock(turn,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(resource,(fcntl.LOCK_EX if mode=='write' else fcntl.LOCK_SH)|fcntl.LOCK_NB)
            if mode=='read':
                fcntl.flock(turn,fcntl.LOCK_UN)
            yield
        except BlockingIOError:
            raise Rejected('SOURCE_RESOURCE_BUSY') from None
        finally:
            os.close(resource)
            os.close(turn)
    return acquire()


def renew_file_lease(dispatcher, config, files, state):
    if not config.get('persistent_endpoint') or dispatcher.now()<=dispatcher.expires:
        return dispatcher
    require(dispatcher.worker is None or config.get('profile')=='execution-online-v1','FILE_PROFILE_SCOPE_REJECTED')
    renewed=Dispatcher(private_directory(state/'rpc'),files,uuid.uuid4().hex,dispatcher.worker,
        now=dispatcher.now,search_program=config.get('rg_path'),
        session_seconds=config['session_seconds'])
    renewed.native_check=getattr(dispatcher,'native_check',None)
    renewed.endpoint_info=dict(dispatcher.endpoint_info,
        lease_number=dispatcher.endpoint_info['lease_number']+1)
    return renewed


def endpoint_status_directory(config):
    state=Path(config['state'])
    return private_directory(state.with_name(state.name+'-status'))


def start_files(config, config_path, popen=None, sleep=time.sleep, inspect=None):
    """Start this fixed maintainer detached from the terminal, at most once."""
    import subprocess
    from session_runner_pause import identity,same_process
    require(config.get('profile') in ('files-online-v1','execution-online-v1'),'FILE_PROFILE_SCOPE_REJECTED')
    popen=popen or subprocess.Popen
    inspect=inspect or identity
    folder=endpoint_status_directory(config)
    def snapshot():
        values={}
        for name in ('supervisor','receiver'):
            path=folder/(name+'.json')
            require(not path.is_symlink(),'STATE_SYMLINK_REJECTED')
            values[name]=Files.meta(path) if path.exists() else {}
        return values
    def alive(value):
        expected=value.get('process_identity')
        return bool(expected and same_process(expected,inspect(expected['pid'])))
    value=snapshot()
    if not alive(value['supervisor']):
        require(not alive(value['receiver']),'ORPHAN_RECEIVER_REQUIRES_REVIEW')
        command=[sys.executable,'-E','-s','-B',str(Path(__file__).resolve()),
            'maintain-files','--config',str(Path(config_path).absolute())]
        popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,start_new_session=True)
    for _ in range(80):
        value=snapshot();supervisor,receiver=value['supervisor'],value['receiver']
        if (alive(supervisor) and alive(receiver) and receiver.get('state')=='ready' and
                receiver.get('endpoint_id')==config['endpoint_id'] and
                supervisor.get('generation')==receiver.get('generation') and
                supervisor.get('child_pid')==receiver.get('pid')):
            return {'state':'ready','endpoint_id':config['endpoint_id'],
                'supervisor_pid':supervisor['pid'],'receiver_pid':receiver['pid'],
                'generation':receiver['generation'],'lease_seconds':receiver['lease_seconds']}
        if supervisor.get('state') in ('blocked','waiting_runner_idle'):
            return {'state':supervisor['state'],'last_error':supervisor.get('last_error')}
        sleep(0.25)
    return {'state':'starting_or_reconnecting','endpoint_id':config['endpoint_id']}


def maintain_files(config, config_path, popen=None, sleep=time.sleep):
    """Supervise only our fixed, file-only receiver; no remote session lifecycle."""
    import subprocess
    require((config.get('profile')=='files-online-v1' and config.get('enable_workers') is False) or
        (config.get('profile')=='execution-online-v1' and config.get('enable_workers') is True),
        'FILE_PROFILE_SCOPE_REJECTED')
    popen=popen or subprocess.Popen
    path=Path(config_path).absolute()
    baseline=digest(path.read_bytes())
    status_root=endpoint_status_directory(config)
    status_path=status_root/'supervisor.json'
    process_identity=None
    if os.name=='posix':
        from session_runner_pause import identity
        process_identity=identity(os.getpid())
    generation=0
    if status_path.exists():
        require(not status_path.is_symlink(),'STATE_SYMLINK_REJECTED')
        generation=Files.meta(status_path).get('generation',0)
        require(type(generation) is int and 0<=generation<2**31-1,'BAD_GENERATION')
    stopping=False
    child=None
    handlers={}
    def stop(*_):
        nonlocal stopping
        stopping=True
    for sig in (signal.SIGINT,signal.SIGTERM):
        handlers[sig]=signal.signal(sig,stop)
    delay=2
    previous_code=None
    last_error=None
    def report(mode):
        atomic_json(status_path,{'state':mode,'endpoint_id':config['endpoint_id'],
            'generation':generation,'pid':os.getpid(),
            'child_pid':child.pid if child else None,'updated_at':int(time.time()),
            'last_exit_code':previous_code,'last_error':last_error,
            'process_identity':process_identity})
    try:
        with file_lock(status_root/'supervisor.lock',timeout=1):
            while not stopping:
                require(digest(path.read_bytes())==baseline,'CONFIG_CHANGED_RESTART_REQUIRED')
                load_config(path)  # Recheck ownership, role and scope before every restart.
                from session_runner_pause import inventory
                listeners,jobs=inventory()
                if listeners or jobs:
                    report('waiting_runner_idle')
                    sleep(2)
                    continue
                generation+=1
                require(generation<2**31,'BAD_GENERATION')
                report('starting')
                command=[sys.executable,'-E','-s','-B',str(Path(__file__).resolve()),
                    'serve','--config',str(path),'--generation',str(generation)]
                child=popen(command,stdin=subprocess.DEVNULL)
                report('running')
                launched=time.monotonic()
                reported=launched
                while child.poll() is None and not stopping:
                    if time.monotonic()-reported>=5:
                        report('running')
                        reported=time.monotonic()
                    sleep(0.5)
                if stopping:
                    if child.poll() is None:
                        child.send_signal(signal.SIGINT)
                    report('stopping')
                    # Never force-kill a possibly active atomic file transaction.
                    child.wait()
                    break
                previous_code=child.wait()
                child=None
                if previous_code==0:
                    break  # Explicit close/Ctrl+C stays closed.
                report('restarting')
                if time.monotonic()-launched>=60:
                    delay=2
                for _ in range(delay*2):
                    if stopping:break
                    sleep(0.5)
                delay=min(60,delay*2)
            report('stopped')
    except Rejected as exc:
        last_error=exc.code
        report('blocked')
        raise
    finally:
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGINT)
            child.wait()
        for sig,handler in handlers.items():
            signal.signal(sig,handler)
    return 0


def serve(config, config_path, pause_requested, generation=0):
    config=dict(config)
    persistent=config.get('profile') in ('files-online-v1','execution-online-v1') and config.get('persistent_endpoint') is True
    require(not persistent or not pause_requested,'PERSISTENT_RUNNER_PAUSE_FORBIDDEN')
    require(type(generation) is int and 0<=generation<2**31,'BAD_GENERATION')
    config['display']=config.get('display') or os.environ.get('DISPLAY','')
    local_host='(?:'+re.escape(socket.gethostname().split('.')[0])+'|'+re.escape(socket.getfqdn())+')'
    require(re.fullmatch(r'(?:(?:localhost|'+local_host+r'))?:[0-9]{1,5}(?:\.[0-9])?',
        config['display']) is not None,'LOCAL_DISPLAY_REQUIRED')
    handshake=config.get('initial_handshake_timeout_seconds',0)
    require(type(handshake) is int and 0<=handshake<=600,'BAD_HANDSHAKE_TIMEOUT')
    state = private_directory(config['state'])
    crypto = identity_files(config)
    print('ETX_SESSION_FINGERPRINT='+crypto.fingerprint(config['server_cert']),flush=True)
    print('ETX_SESSION_DISPLAY='+config['display'],flush=True)
    pause = None
    if pause_requested:
        from session_runner_pause import RunnerPause
        pause = RunnerPause(state/('runner-pause-'+uuid.uuid4().hex+'.json'))
        pause.acquire()
    else:
        from session_runner_pause import inventory
        listeners, jobs = inventory()
        require(not listeners and not jobs,'RUNNER_ISOLATION_REQUIRED')
    selection = None
    worker = None
    try:
        worker = make_worker(config,config_path) if config.get('enable_workers') else None
        files = Files(private_directory(state/'files'),config['allowed_roots'],
            write_enabled=config.get('enable_writes',False),locks=source_locks,
            write_roots=config.get('write_roots',[]))
        session=uuid.uuid4().hex
        dispatcher=Dispatcher(private_directory(state/'rpc'),files,session,worker,
            search_program=config.get('rg_path'),
            session_seconds=config.get('session_seconds',MAX_SESSION))
        status_path=None
        if persistent:
            dispatcher.endpoint_info={'persistent':True,'endpoint_id':config['endpoint_id'],
                'generation':generation,'supervised':generation>0,'pid':os.getpid(),
                'display':config['display'],'lease_number':1,
                'lease_seconds':config['session_seconds'],'read_roots':config['allowed_roots'],
                'write_roots':config['write_roots'],'workers_enabled':worker is not None}
            if os.name=='posix':
                from session_runner_pause import identity
                dispatcher.endpoint_info['process_identity']=identity(os.getpid())
            status_path=endpoint_status_directory(config)/'receiver.json'
        native=state/'native-check.json'
        dispatcher.native_check=Files.meta(native) if native.exists() else None
        stop=False
        stop_signal=None
        def stopped(number,*_):
            nonlocal stop,stop_signal
            stop=True
            stop_signal=number
        signal.signal(signal.SIGINT,stopped)
        signal.signal(signal.SIGTERM,stopped)
        last_request=None
        last_response=None
        selection=Selection(config['display'])
        print('ETX_SESSION_READY session='+session,flush=True)
        last_mode_check=0
        closing_at=None
        handshake_deadline=time.monotonic()+handshake if handshake else None
        confirmed=False
        last_rejected=None
        last_heartbeat=0
        while not stop and (persistent or time.time() <= dispatcher.expires):
            if persistent and closing_at is None:
                dispatcher=renew_file_lease(dispatcher,config,files,state)
            if status_path and time.monotonic()-last_heartbeat>=5:
                atomic_json(status_path,dict(dispatcher.endpoint_info,state='ready',
                    session=dispatcher.session,expires=int(dispatcher.expires),
                    heartbeat_at=int(time.time())))
                last_heartbeat=time.monotonic()
            if handshake_deadline and not confirmed and time.monotonic()>=handshake_deadline:
                raise Rejected('HANDSHAKE_TIMEOUT')
            if closing_at is not None and time.monotonic()>=closing_at:
                break
            if time.monotonic()-last_mode_check>=2:
                if pause:
                    pause.check()
                else:
                    from session_runner_pause import inventory
                    listeners,jobs=inventory()
                    require(not listeners and not jobs,'RUNNER_MODE_CHANGED')
                last_mode_check=time.monotonic()
            text=selection.read()
            if text and text.startswith('ETX_SESSION_V1') and not is_frame(text):
                if last_rejected!='prefix':
                    print('ETX_SESSION_FRAME_ERROR=FRAME_PREFIX_REJECTED',flush=True)
                    last_rejected='prefix'
            if not is_frame(text):
                text=None  # Do not retain or log ordinary clipboard contents.
                time.sleep(1 if persistent else 0.1)
                continue
            text=normalize_frame(text)
            if text==last_response:
                time.sleep(0.1)
                continue
            wire_hash=digest(text.encode('utf-8'))
            if wire_hash==last_request and last_response:
                selection.write(last_response)
                time.sleep(0.1)
                continue
            try:
                message=crypto.open(text,allow_signed_hello=True)
            except Rejected as exc:
                if last_rejected!=wire_hash:
                    print('ETX_SESSION_FRAME_ERROR='+exc.code,flush=True)
                    last_rejected=wire_hash
                time.sleep(0.1)
                continue
            response={'v':1,'id':message.get('id'),'session':message.get('session'),
                'expires':int(time.time())+120}
            try:
                if pause:
                    pause.check()
                response.update(ok=True,result=dispatcher.dispatch(message))
                if message['op']!='hello':
                    confirmed=True
                if message['op']=='close' and closing_at is None:
                    # Serve the close acknowledgement before dropping PRIMARY.
                    # The ordinary RPC dispatcher rejects further work now.
                    closing_at=time.monotonic()+5
            except Rejected as exc:
                response.update(ok=False,error=exc.code)
            except Exception:
                response.update(ok=False,error='INTERNAL_ERROR')
            last_response=crypto.seal(response,advertise_cert=message.get('op')=='hello')
            last_request=wire_hash
            # A user may copy ordinary text while an operation is processing.
            # Keep the durable result for a same-ID retry; do not overwrite it.
            current=selection.read()
            published=False
            if is_frame(current) and normalize_frame(current)==text:
                selection.write(last_response)
                published=True
            current_kind='none' if current is None else 'protocol' if is_frame(current) else 'ordinary'
            print('ETX_SESSION_RESULT id={} ok={} published={} current={}'.format(
                response['id'],response['ok'],published,current_kind),flush=True)
    finally:
        if selection:
            selection.close()
        if persistent and 'status_path' in locals() and status_path:
            atomic_json(status_path,dict(dispatcher.endpoint_info,state='stopped',
                heartbeat_at=int(time.time())))
        # Accepted simulations own ETX-local lease processes. Keep Runner
        # isolation until their queue states are terminal, even after Ctrl+C.
        if worker:
            print('ETX_SESSION_DRAINING_ACCEPTED_JOBS',flush=True)
            while True:
                pending=[]
                worker.queue.reconcile_workers()
                for path in list(worker.state.glob('*.simulation.json'))+list(worker.state.glob('*.task.json')):
                    rid=path.name.split('.')[0]
                    status=worker.queue.snapshot(rid)
                    if status.get('state') not in worker.module.TERMINAL|{'unknown'}:
                        pending.append(rid)
                if not pending:
                    break
                time.sleep(2)
        if pause:
            pause.release()
    return 1 if persistent and stop_signal==signal.SIGTERM else 0





def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('serve','start-files','start-control','maintain-files','executor','initialize','coordinate'))
    parser.add_argument('--config',required=True)
    parser.add_argument('--request-id');parser.add_argument('--worker-profile')
    parser.add_argument('--generation',type=int,default=0)
    args=parser.parse_args()
    os.umask(0o077);sys.dont_write_bytecode=True
    try:
        config=load_config(args.config)
        if args.operation in ('start-files','start-control'):
            result=start_files(config,args.config)
            print(json.dumps(result),flush=True)
            return 0 if result['state']=='ready' else 2
        if args.operation=='maintain-files':return maintain_files(config,args.config)
        if args.operation=='initialize':
            crypto=identity_files(config)
            print('ETX_SESSION_FINGERPRINT='+crypto.fingerprint(config['server_cert']))
        elif args.operation=='executor':
            return make_worker(config,args.config).run_executor(args.worker_profile)
        elif args.operation=='coordinate':make_worker(config,args.config).coordinate(args.request_id)
        else:
            lock_root=private_directory(Path(__file__).resolve().parents[1]/'.private/state')
            with file_lock(lock_root/'foreground.lock',timeout=1):
                return serve(config,args.config,False,args.generation)
        return 0
    except (Rejected,ValueError) as exc:
        code=exc.code if isinstance(exc,Rejected) else str(exc)
        if re.fullmatch('[A-Z][A-Z0-9_]+',code) is None:code='INVALID_CONFIGURATION'
        print('ETX_SESSION_ERROR='+code,file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
