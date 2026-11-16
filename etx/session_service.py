"""Restricted RPC dispatch with durable operation IDs and local lease owners."""
import os
import re
import stat
import subprocess
import time
import codecs
from collections import deque
from pathlib import Path

from session_protocol import (Rejected, require, keys, identifier, integer,
    canonical, digest, encode_bytes, validate_request, operation_digest,
    MAX_CHUNK, MAX_SESSION, MAX_TEXT_FILE, MAX_SESSION_STORAGE)
from session_files import Files, private_directory, file_lock, atomic_json, parent_directory


NATIVE_LOG_MAX_BYTES = MAX_TEXT_FILE
NATIVE_LOG_MAX_LINE = 65536
NATIVE_LOG_SCAN_SECONDS = 15
NATIVE_LOG_ERRORS = (b'%E-', b'%F-', b'UVM_ERROR ', b'UVM_FATAL ',
    b'Error-[', b'Fatal-[', b'Segmentation fault', b'Timed out')


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
                'native_log_enabled':True,
                'max_text_file_bytes':MAX_TEXT_FILE,
                'max_text_batch_bytes':MAX_TEXT_FILE,
                'large_text_upload_enabled':True,
                'writes_enabled':self.files.write_enabled,
                'workers_enabled':self.worker is not None,
                'native_check':getattr(self,'native_check',None),
                'endpoint':getattr(self,'endpoint_info',None)}
        if operation in ('workers','status','status_many','task_result','receipt','read_log','native_log','read_chunk',
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
                    require(count<=4096 and total<=MAX_SESSION_STORAGE,'SESSION_QUOTA_LIMIT')
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
        if operation == 'native_log':
            return self.native_log(arguments)
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

    @staticmethod
    def native_text(data, final=True):
        require(b'\x00' not in data, 'TEXT_ENCODING_REJECTED')
        try:
            text = codecs.getincrementaldecoder('utf-8')().decode(data, final=final)
        except UnicodeError:
            raise Rejected('TEXT_ENCODING_REJECTED') from None
        return text.encode('utf-8')

    def native_log(self, args):
        """Bounded text excerpts from one exact, stable native regression log."""
        keys(args, ('path','mode','offset','limit','identity'))
        path = self.files.path(args['path'])
        log_root = path.parent.parent
        require(path.name in ('stdout.log','stderr.log') and log_root in self.files.roots
            and re.fullmatch(r'[A-Za-z0-9_]+__[A-Za-z0-9_]+__[A-Za-z0-9_]+__[0-9]+(?:_[A-Za-z0-9_]+)?',
                path.parent.name) is not None, 'NATIVE_LOG_PATH_REJECTED')
        mode = args['mode']
        require(mode in ('errors','range','tail'), 'NATIVE_LOG_MODE_REJECTED')
        offset = integer(args['offset'], 0, NATIVE_LOG_MAX_BYTES)
        limit = integer(args['limit'], 1, MAX_CHUNK)
        require(mode != 'errors' or limit >= 131072, 'NATIVE_LOG_LIMIT_TOO_SMALL')
        require(mode != 'tail' or offset == 0, 'NATIVE_LOG_OFFSET_REJECTED')
        if args['identity'] is not None:
            require(type(args['identity']) is list and len(args['identity']) == 4
                and all(type(v) is int and v >= 0 for v in args['identity']), 'BAD_LOG_IDENTITY')
        fragments = []
        meta = {'match_found':False, 'match_line':None, 'scan_complete':False,
            'scan_timed_out':False, 'context_truncated':False, 'scanned_from':offset}

        def fragment(kind, start, data, line=None):
            data = self.native_text(data)
            if data:
                fragments.append({'kind':kind, 'offset':start, 'bytes':len(data),
                    'line':line, 'sha256':digest(data), 'data':encode_bytes(data)})

        def tail(stream, size, budget):
            start = max(0, size - budget)
            stream.seek(start)
            data = stream.read(size - start)
            if start:
                boundary = data.find(b'\n')
                if boundary < 0:
                    meta['context_truncated'] = True
                    return
                start += boundary + 1
                data = data[boundary + 1:]
            lines = data.splitlines(keepends=True)
            selected = b''.join(lines[-50:])
            fragment('tail', start + len(data) - len(selected), selected)

        with self.files.scope('read'), parent_directory(path) as parent:
            fd = os.open(path.name if parent is not None else str(path),
                os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_NONBLOCK',0), dir_fd=parent)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                identity = self.files.identity(before)
                require(stat.S_ISREG(before.st_mode) and before.st_size <= NATIVE_LOG_MAX_BYTES,
                    'NATIVE_LOG_FILE_REJECTED')
                if os.name == 'posix':
                    require(before.st_uid == os.geteuid(), 'NATIVE_LOG_OWNER_REJECTED')
                require(args['identity'] is None or args['identity'] == identity, 'LOG_CHANGED')
                require(offset <= before.st_size, 'LOG_TRUNCATED')
                if mode == 'range':
                    stream.seek(offset)
                    raw = stream.read(min(limit, before.st_size - offset))
                    data = self.native_text(raw, final=offset + len(raw) == before.st_size)
                    require(not raw or data, 'NATIVE_LOG_LIMIT_TOO_SMALL_FOR_UTF8')
                    fragment('range', offset, data)
                    meta['scanned_to'] = offset + len(data)
                    meta['scan_complete'] = meta['scanned_to'] == before.st_size
                elif mode == 'tail':
                    tail(stream, before.st_size, limit)
                    meta.update(scanned_to=before.st_size, scan_complete=True)
                else:
                    context_budget = limit * 3 // 4
                    preceding = deque(maxlen=10)
                    line_number = 0 if offset == 0 else None
                    stream.seek(offset)
                    deadline = time.monotonic() + NATIVE_LOG_SCAN_SECONDS
                    while stream.tell() < before.st_size:
                        if time.monotonic() >= deadline:
                            meta['scan_timed_out'] = True
                            break
                        start = stream.tell()
                        line = stream.readline(NATIVE_LOG_MAX_LINE + 1)
                        require(len(line) <= NATIVE_LOG_MAX_LINE, 'NATIVE_LOG_LINE_SIZE_LIMIT')
                        self.native_text(line)
                        if line_number is not None:
                            line_number += 1
                        summary = re.fullmatch(rb'\s*UVM_(?:ERROR|FATAL)\s*:\s*\d+\s*',line)
                        if not summary and any(token in line for token in NATIVE_LOG_ERRORS):
                            meta.update(match_found=True, match_line=line_number)
                            selected = list(preceding) + [(start, line, line_number)]
                            data = b''.join(item[1] for item in selected)
                            for _ in range(20):
                                if stream.tell() == before.st_size:
                                    break
                                if time.monotonic() >= deadline:
                                    meta['scan_timed_out'] = True
                                    break
                                following = stream.readline(NATIVE_LOG_MAX_LINE + 1)
                                require(len(following) <= NATIVE_LOG_MAX_LINE, 'NATIVE_LOG_LINE_SIZE_LIMIT')
                                self.native_text(following)
                                if len(data) + len(following) > context_budget:
                                    meta['context_truncated'] = True
                                    break
                                data += following
                            fragment('first_error', selected[0][0], data, selected[0][2])
                            break
                        preceding.append((start, line, line_number))
                        while sum(len(item[1]) for item in preceding) > context_budget // 4:
                            preceding.popleft()
                    meta['scanned_to'] = stream.tell()
                    meta['scan_complete'] = stream.tell() == before.st_size
                    tail(stream, before.st_size, min(65536, limit - sum(f['bytes'] for f in fragments)))
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False) \
                    if parent is not None else path.lstat()
                require(identity == self.files.identity(os.fstat(stream.fileno()))
                    == self.files.identity(current), 'LOG_CHANGED')
        require(sum(f['bytes'] for f in fragments) <= limit, 'NATIVE_LOG_RESULT_SIZE_LIMIT')
        return dict(meta, path=str(path), mode=mode, identity=identity,
            observed_file_bytes=before.st_size, fragments=fragments,
            bytes=sum(f['bytes'] for f in fragments))

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
