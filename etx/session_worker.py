"""Fixed-host adapter for the installed simulation queue, not a shell RPC.

The local project client constructs the same signed/encrypted command boxes used
by the existing Worker. The queue and Worker still verify their normal identity,
slot, command signature, process and waveform locks.
"""
import os
import re
import stat
import subprocess
import sys
import time
import types
from pathlib import Path
from site_config import site, native_output

from session_protocol import Rejected, require, keys, identifier, sha, digest, canonical
from session_files import private_directory, file_lock, atomic_json, Files


def process_birth(pid):
    require(type(pid) is int and pid>1,'COORDINATOR_NEEDS_REVIEW')
    try:
        raw=(Path('/proc')/str(pid)/'stat').read_text()
        return raw[raw.rfind(')')+2:].split()[19]
    except (OSError,IndexError):
        raise Rejected('COORDINATOR_NEEDS_REVIEW') from None


class Worker:
    def __init__(self, module_path, expected_sha256, state, queue_root=None,
                 coordinator_script=None, coordinator_config=None):
        module_path = Path(module_path)
        require(not module_path.is_symlink() and module_path.is_file(),
            'WORKER_MODULE_REJECTED')
        fd=os.open(str(module_path),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and
                info.st_size<=524288,'WORKER_MODULE_REJECTED')
            source=stream.read(524289)
        require(digest(source)==sha(expected_sha256),'WORKER_MODULE_HASH_MISMATCH')
        # Compile the verified bytes; do not reopen a module after its hash check.
        self.module=types.ModuleType('etx_session_installed_sim_control')
        self.module.__file__=str(module_path)
        exec(compile(source,str(module_path),'exec'),self.module.__dict__)
        require(self.module.ROOT == Path(site()['remote']['queue_root']), 'WRONG_WORKER_QUEUE')
        self.state = private_directory(state)
        self.lock_root = Path(site()['remote']['lock_root'])
        self.module.private_directory(self.lock_root, create=True)
        self.queue = self.module.Queue(Path(queue_root or self.module.ROOT),
            lambda:self.module.transaction(self.lock_root))
        self.coordinator_script = coordinator_script
        self.coordinator_config = coordinator_config

    def workers(self, args):
        keys(args, ())
        fields = ('id','profile','cases','busy','command_certificate','parallel','upload_independent')
        return {'workers':[{k:w[k] for k in fields if k in w}
            for w in self.queue.available_workers()]}

    def submit_simmer(self, args):
        keys(args, ('request_id','worker_id','profile','case','seed','waves',
            'command_box','launcher_sha256'))
        request_id = identifier(args['request_id'])
        worker_id = identifier(args['worker_id'])
        require(re.fullmatch(r'work0[1-5]', args['profile']) is not None,
            'BAD_WORKER_PROFILE')
        require(isinstance(args['case'],str) and re.fullmatch(
            r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}',args['case']) is not None,
            'BAD_CASE')
        require(type(args['seed']) is int and 0 <= args['seed'] <= 2147483647 and
            args['waves'] is True, 'BAD_SIMULATION_OPTIONS')
        argv = self.module.simmer_argv(args['case'],args['seed'],args['profile'])
        require(digest(canonical(argv)) == args['launcher_sha256'], 'LAUNCHER_MISMATCH')
        require(self.coordinator_script is not None, 'COORDINATOR_NOT_CONFIGURED')
        self.module.checked_box(args['command_box'])
        meta_path = self.state / (request_id + '.simulation.json')
        expected = {k:args[k] for k in ('request_id','worker_id','profile','case','seed','waves','launcher_sha256')}
        base = native_output(args['case'],args['seed'],args['profile'])
        with file_lock(self.state / 'submit.lock'):
            if meta_path.exists():
                old = Files.meta(meta_path)
                require(old['specification'] == expected, 'REQUEST_ID_CONFLICT')
            else:
                baseline={}
                for stream in ('stdout','stderr'):
                    path=Path(base+'/'+stream+'.log')
                    if path.exists():
                        info=path.lstat()
                        require(stat.S_ISREG(info.st_mode),'NATIVE_LOG_TYPE_REJECTED')
                        baseline[stream]=[info.st_dev,info.st_ino,info.st_size,
                            info.st_mtime_ns,info.st_ctime_ns]
                    else:
                        baseline[stream]=None
                atomic_json(meta_path, {'specification':expected,
                    'stdout':base+'/stdout.log','stderr':base+'/stderr.log',
                    'fsdb':base+'/'+site()['remote']['fsdb_name'],'previous_log_identity':baseline})
                owners_path=self.state/'native-log-owners.json'
                owners=Files.meta(owners_path) if owners_path.exists() else {}
                owners.update({base+'/stdout.log':request_id,base+'/stderr.log':request_id})
                # Publish the possible new owner before the queue becomes live.
                # If reservation is uncertain, old native logs fail closed.
                atomic_json(owners_path,owners)
            with self.module.simulation_access(self.lock_root) as locks:
                require(locks is not None, 'SIMULATION_RESOURCE_BUSY')
                try:
                    request, created = self.queue.reserve(request_id,args['profile'],
                        'run',1,worker_id,args['command_box'])
                except self.module.Rejected as exc:
                    raise Rejected(str(exc)) from None
                state = self.queue.snapshot(request_id)
                if created:
                    self.start_coordinator(request_id)
                elif state['state'] not in self.module.TERMINAL:
                    # A lost submit response must never create another request.
                    self.require_coordinator(request_id)
                return dict(self.queue.snapshot(request_id), **{
                    'created':created,'stdout':base+'/stdout.log' if created else Files.meta(meta_path)['stdout'],
                    'fsdb':base+'/'+site()['remote']['fsdb_name'] if created else Files.meta(meta_path)['fsdb']})

    def start_coordinator(self, request_id):
        output = self.state / (request_id+'.coordinator.log')
        with output.open('ab') as stream:
            process = subprocess.Popen([sys.executable, str(self.coordinator_script),
                'coordinate', '--config',str(self.coordinator_config),
                '--request-id',request_id], stdin=subprocess.DEVNULL,
                stdout=stream, stderr=stream, start_new_session=True, close_fds=True)
        deadline = time.monotonic() + 5
        ready = self.state / (request_id+'.coordinator.json')
        while time.monotonic() < deadline:
            if ready.exists():
                data = Files.meta(ready)
                if data.get('pid') == process.pid and data.get('ready') and \
                        data.get('birth')==process_birth(process.pid):
                    return
            require(process.poll() is None, 'COORDINATOR_START_FAILED')
            time.sleep(0.05)
        raise Rejected('COORDINATOR_START_TIMEOUT')

    def require_coordinator(self, request_id):
        path = self.state / (request_id+'.coordinator.json')
        require(path.exists(), 'COORDINATOR_NEEDS_REVIEW')
        info = Files.meta(path)
        require(info.get('ready') is True and info.get('request_id')==request_id and
            info.get('birth')==process_birth(info.get('pid')),'COORDINATOR_NEEDS_REVIEW')
        try:
            os.kill(info['pid'],0)
        except (OSError, KeyError, TypeError):
            raise Rejected('COORDINATOR_NEEDS_REVIEW') from None

    def coordinate(self, request_id):
        request_id = identifier(request_id)
        with file_lock(self.state/(request_id+'.coordinator.lock'),timeout=1):
            directory = self.queue.job(request_id)
            request = self.module.read_json(directory/'request.json')
            require(request is not None, 'REQUEST_NOT_FOUND')
            atomic_json(self.state/(request_id+'.coordinator.json'),
                {'pid':os.getpid(),'birth':process_birth(os.getpid()),
                    'ready':True,'request_id':request_id})
            # Queue.wait maintains the lease on ETX. It does not read a clipboard.
            try:
                result = self.queue.wait(request,lambda:False)
                if result.get('requires_review') and result['state'] not in self.module.TERMINAL:
                    with self.queue.transact():
                        current=self.queue.snapshot(request_id)
                        if current['state'] not in self.module.TERMINAL:
                            self.queue.finish(directory,'needs_review',
                                reason='coordinator_requires_review')
                    result=self.queue.snapshot(request_id)
                atomic_json(self.state/(request_id+'.terminal.json'),result)
            finally:
                self.queue.reconcile_workers()

    def status(self, args):
        keys(args, ('request_id',))
        return self.queue.snapshot(identifier(args['request_id']))

    def log_path(self, request_id, stream):
        require(stream in ('stdout','stderr'), 'LOG_STREAM_REJECTED')
        meta = Files.meta(self.state/(identifier(request_id)+'.simulation.json'))
        require(Files.meta(self.state/'native-log-owners.json').get(meta[stream])==request_id,
            'NATIVE_LOG_REUSED')
        state=self.queue.snapshot(request_id)['state']
        require(state in ('running','exited','needs_review'),'LOG_NOT_READY')
        path=Path(meta[stream])
        if not path.exists():
            raise Rejected('LOG_NOT_READY')
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode),'NATIVE_LOG_TYPE_REJECTED')
        identity=[info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
        require(identity!=meta['previous_log_identity'][stream],'LOG_NOT_READY')
        return str(path)
