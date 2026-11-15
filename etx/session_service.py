"""Restricted RPC dispatch with durable operation IDs and local lease owners."""
import os
import re
import stat
import subprocess
import time
from pathlib import Path

from session_protocol import (Rejected, require, keys, identifier, integer,
    canonical, digest, encode_bytes, validate_request, operation_digest,
    MAX_CHUNK, MAX_SESSION)
from session_files import Files, private_directory, file_lock, atomic_json


class Dispatcher:
    def __init__(self, state, files, session, worker=None, now=time.time,
                 search_program=None, session_seconds=MAX_SESSION):
        self.state = private_directory(state)
        self.files = files
        self.session = identifier(session)
        self.worker = worker
        self.now = now
        self.search_program = search_program
        self.expires = now() + integer(session_seconds, 1, MAX_SESSION)
        self.closing=False

    def dispatch(self, message):
        validate_request(message, self.session, self.now())
        require(self.now() <= self.expires, 'SESSION_EXPIRED')
        operation, arguments = message['op'], message['args']
        if operation=='close':
            keys(arguments,())
            if self.worker:
                for path in list(self.worker.state.glob('*.simulation.json'))+list(self.worker.state.glob('*.task.json')):
                    rid=path.name.split('.')[0]
                    require(self.worker.queue.snapshot(rid)['state'] in
                        self.worker.module.TERMINAL|{'unknown'},'SESSION_HAS_ACTIVE_TASKS')
            self.closing=True
            return {'closing':True,'session':self.session}
        require(not self.closing,'SESSION_CLOSING')
        if operation == 'hello':
            keys(arguments, ())
            return {'session':self.session, 'expires':int(self.expires),
                'version':1, 'chunk_bytes':MAX_CHUNK, 'files_enabled':True,
                'read_batch_enabled':True,
                'writes_enabled':self.files.write_enabled,
                'workers_enabled':self.worker is not None,
                'native_check':getattr(self,'native_check',None),
                'endpoint':getattr(self,'endpoint_info',None)}
        if operation in ('workers','status','status_many','task_result','receipt','read_log','read_chunk',
                         'upload_status','search'):
            # Observational queries must report current state, rather than a
            # cached "running" status or a previously empty log tail.
            return self.perform(operation,arguments)
        operation_id = identifier(message['id'])
        fingerprint = operation_digest(message)
        receipt_path = self.state / (operation_id + '.json')
        with file_lock(self.state / 'rpc.lock'):
            total=0
            count=0
            for parent,dirs,names in os.walk(str(self.state.parent),followlinks=False):
                require(not any(Path(parent,name).is_symlink() for name in dirs),
                    'STATE_SYMLINK_REJECTED')
                for name in names:
                    item=Path(parent,name)
                    require(not item.is_symlink(),'STATE_SYMLINK_REJECTED')
                    total+=item.stat().st_size
                    count+=1
                    require(count<=4096 and total<=200*1024*1024,'SESSION_QUOTA_LIMIT')
            if receipt_path.exists():
                old = Files.meta(receipt_path)
                require(old['operation_digest'] == fingerprint, 'REQUEST_ID_CONFLICT')
                if old['state'] == 'done':
                    return old['result']
                if old['state'] == 'failed':
                    raise Rejected(old['error'])
                # These operations have their own stable transaction/queue IDs;
                # they recover from a committed action with a lost RPC receipt.
                require(operation in ('commit','restore','submit_simmer','upload_begin',
                    'upload_chunk','read_begin','read_batch','submit_task','release_selftests'), 'OPERATION_NEEDS_REVIEW')
            atomic_json(receipt_path, {'operation_digest':fingerprint, 'state':'started'})
            try:
                result = self.perform(operation, arguments)
                require(len(canonical(result)) <= 450000, 'RESULT_SIZE_LIMIT')
                atomic_json(receipt_path, {'operation_digest':fingerprint,
                    'state':'done', 'result':result})
                return result
            except Rejected as exc:
                atomic_json(receipt_path, {'operation_digest':fingerprint,
                    'state':'failed', 'error':exc.code})
                raise

    def perform(self, operation, arguments):
        file_operations = {'read_batch':self.files.read_batch,
            'read_begin':self.files.read_begin,
            'read_chunk':self.files.read_chunk, 'upload_begin':self.files.upload_begin,
            'upload_chunk':self.files.upload_chunk, 'upload_status':self.files.upload_status,
            'commit':self.files.commit, 'restore':self.files.restore,
            'receipt':self.files.receipt}
        if operation in file_operations:
            return file_operations[operation](arguments)
        if operation in ('workers','submit_simmer','status','status_many','submit_task','task_result','release_selftests'):
            require(self.worker is not None, 'WORKERS_DISABLED')
            return getattr(self.worker, operation)(arguments)
        if operation == 'read_log':
            return self.read_log(arguments)
        if operation == 'search':
            return self.search(arguments)
        raise Rejected('BAD_OPERATION')

    def read_log(self, args):
        keys(args, ('request_id','stream','offset','limit','identity'))
        require(self.worker is not None, 'WORKERS_DISABLED')
        path = self.worker.log_path(identifier(args['request_id']), args['stream'])
        path = self.files.path(str(path))
        offset = integer(args['offset'], 0, 2**40)
        limit = integer(args['limit'], 1, MAX_CHUNK)
        fd = os.open(str(path), os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) |
            getattr(os,'O_NONBLOCK',0))
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            identity = [before.st_dev, before.st_ino]
            require(stat.S_ISREG(before.st_mode) and before.st_size <= 2**30,
                'LOG_FILE_REJECTED')
            require(args['identity'] is None or args['identity'] == identity,
                'LOG_REPLACED')
            require(offset <= before.st_size, 'LOG_TRUNCATED')
            stream.seek(offset)
            data = stream.read(min(limit, before.st_size - offset))
            after = os.fstat(stream.fileno())
            current = path.lstat()
            require([after.st_dev,after.st_ino] == identity == [current.st_dev,current.st_ino]
                and after.st_size >= before.st_size and current.st_size >= before.st_size,
                'LOG_CHANGED')
        return {'identity':identity, 'offset':offset, 'next_offset':offset+len(data),
            'bytes':len(data), 'sha256':digest(data), 'data':encode_bytes(data),
            'observed_file_bytes':before.st_size}

    def search(self, args):
        keys(args, ('root','pattern'))
        require(self.search_program is not None, 'SEARCH_DISABLED')
        root = Path(args['root'])
        require(root.is_absolute() and '..' not in root.parts and root.is_dir() and
            any(Files._inside(root, allowed) for allowed in self.files.roots),
            'PATH_NOT_AUTHORIZED')
        require(all(not p.is_symlink() for p in [root,*root.parents]), 'SYMLINK_REJECTED')
        require(isinstance(args['pattern'],str) and 0 < len(args['pattern']) <= 1024 and
            '\x00' not in args['pattern'], 'BAD_PATTERN')
        # Bounded pipe consumption prevents rg from accumulating unbounded output.
        import tempfile
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen([self.search_program, '--line-number',
                '--no-heading','--color','never','--max-count','20', '--max-filesize','2M',
                '--',args['pattern'],str(root)], stdout=output,
                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + 20
            try:
                while process.poll() is None:
                    require(time.monotonic() < deadline, 'SEARCH_TIMEOUT')
                    require(os.fstat(output.fileno()).st_size <= MAX_CHUNK,
                        'SEARCH_RESULT_SIZE_LIMIT')
                    time.sleep(0.02)
                require(process.returncode in (0,1), 'SEARCH_FAILED')
                output.seek(0)
                data = output.read(MAX_CHUNK + 1)
                require(len(data) <= MAX_CHUNK, 'SEARCH_RESULT_SIZE_LIMIT')
                return {'exit_code':process.returncode, 'bytes':len(data),
                    'sha256':digest(data), 'data':encode_bytes(data)}
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
