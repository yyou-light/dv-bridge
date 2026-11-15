"""Ordinary-file snapshots and SHA-conditional, recoverable installations."""
import contextlib
import json
import os
import shutil
import stat
import tempfile
import time
import uuid
from pathlib import Path

from session_protocol import (Rejected, require, keys, identifier, integer, sha,
    canonical, strict_json, digest, encode_bytes, decode_bytes, MAX_FILE, MAX_CHUNK)


def atomic_json(path, value):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.state-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_directory(path):
    if os.name=='posix':
        fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextlib.contextmanager
def parent_directory(path):
    """Anchor POSIX operations to non-symlink directory descriptors."""
    path=Path(path)
    if os.name!='posix':
        yield None
        return
    fd=os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parent.parts[1:]:
            following=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd)
            fd=following
        yield fd
    finally:
        os.close(fd)


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for item in [path, *path.parents]:
        require(not item.is_symlink(), 'SYMLINK_REJECTED')
    if os.name == 'posix':
        info = path.stat()
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'PRIVATE_DIRECTORY_REJECTED')
    return path


@contextlib.contextmanager
def file_lock(path, timeout=5):
    path = Path(path)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'LOCK_REJECTED')
        if os.name=='posix':
            require(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600,
                'LOCK_REJECTED')
        deadline = time.monotonic() + timeout
        if os.name == 'nt':
            import msvcrt
            if info.st_size == 0:
                os.write(fd, b'0')
            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise Rejected('LOCK_BUSY') from None
                    time.sleep(0.05)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Rejected('LOCK_BUSY') from None
                    time.sleep(0.05)
        yield
    finally:
        os.close(fd)


class Files:
    def __init__(self, root, allowed_roots, write_enabled=False, locks=None,
                 write_roots=None):
        self.root = private_directory(root)
        self.roots = [Path(p).absolute() for p in allowed_roots]
        self.write_enabled = write_enabled
        self.write_roots=[Path(p).absolute() for p in (
            allowed_roots if write_roots is None else write_roots)]
        self.locks = locks

    def path(self, value, absent=False, writing=False):
        require(isinstance(value, str) and value and '\x00' not in value,
            'BAD_PATH')
        candidate = Path(value)
        require(candidate.is_absolute() and '..' not in candidate.parts,
            'BAD_PATH')
        roots=self.write_roots if writing else self.roots
        require(any(self._inside(candidate, root) for root in roots),
            'PATH_NOT_AUTHORIZED')
        for item in [*reversed(candidate.parents), candidate]:
            require(not item.is_symlink(), 'SYMLINK_REJECTED')
        require(candidate.parent.is_dir(), 'PARENT_NOT_FOUND')
        if candidate.exists():
            require(stat.S_ISREG(candidate.lstat().st_mode), 'NOT_REGULAR_FILE')
            if writing and os.name=='posix':
                require(candidate.lstat().st_uid==os.geteuid(),'TARGET_OWNER_REJECTED')
        else:
            require(absent, 'FILE_NOT_FOUND')
        return candidate

    @staticmethod
    def _inside(candidate, root):
        try:
            return os.path.commonpath((str(candidate), str(root))) == str(root)
        except ValueError:
            return False

    @staticmethod
    def identity(info):
        return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]

    def read(self, path, limit=MAX_FILE):
        path=Path(path)
        with parent_directory(path) as parent:
            fd = os.open(path.name if parent is not None else str(path),
                os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                getattr(os, 'O_NONBLOCK', 0),dir_fd=parent)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                    'FILE_SIZE_OR_TYPE_REJECTED')
                data = stream.read(limit + 1)
                current=os.stat(path.name,dir_fd=parent,follow_symlinks=False) \
                    if parent is not None else path.lstat()
                require(len(data) <= limit and self.identity(before) ==
                    self.identity(os.fstat(stream.fileno())) and self.identity(before) ==
                    self.identity(current), 'SOURCE_CHANGED')
        return data, before

    def scope(self, mode):
        return self.locks(mode) if self.locks else contextlib.nullcontext()

    def read_begin(self, args):
        return self._read_snapshot(args)

    def _read_snapshot(self, args, text_only=False):
        keys(args, ('path', 'transfer_id'))
        transfer = identifier(args['transfer_id'])
        path = self.path(args['path'])
        folder = private_directory(self.root / ('read-' + transfer))
        with file_lock(folder / 'lock'):
            meta_path = folder / 'meta.json'
            if meta_path.exists():
                meta = self.meta(meta_path)
                require(meta['path'] == str(path), 'TRANSFER_CONFLICT')
                if text_only:
                    require(meta['bytes'] <= 524288, 'TEXT_SIZE_LIMIT')
                    self._utf8((folder / 'data').read_bytes())
                return meta
            with self.scope('read'):
                data, info = self.read(path, 524288 if text_only else MAX_FILE)
                if text_only:
                    self._utf8(data)
            with (folder / 'data').open('xb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(folder / 'data', 0o600)
            meta = {'transfer_id': transfer, 'path': str(path), 'bytes': len(data),
                'sha256': digest(data), 'identity': self.identity(info),
                'chunk_bytes': MAX_CHUNK}
            atomic_json(meta_path, meta)
            return meta

    @staticmethod
    def _utf8(data):
        try:
            data.decode('utf-8')
        except UnicodeError:
            raise Rejected('TEXT_ENCODING_REJECTED') from None

    def read_batch(self, args):
        """Exact text paths only; bounded inline data, immutable continuation IDs."""
        keys(args, ('files',))
        items = args['files']
        require(type(items) is list and 1 <= len(items) <= 10, 'BATCH_SIZE_LIMIT')
        paths, transfers = set(), set()
        for item in items:
            keys(item, ('path', 'transfer_id', 'known_sha256'))
            path = self.path(item['path'])
            transfer = identifier(item['transfer_id'])
            if item['known_sha256'] is not None:
                sha(item['known_sha256'])
            require(str(path) not in paths and transfer not in transfers, 'BATCH_DUPLICATE')
            paths.add(str(path))
            transfers.add(transfer)
        remaining = 196608
        results = []
        for item in items:
            meta = self._read_snapshot({'path': item['path'],
                'transfer_id': item['transfer_id']}, text_only=True)
            unchanged = item['known_sha256'] == meta['sha256']
            chunk = None
            if not unchanged and remaining > 0:
                chunk = self.read_chunk({'transfer_id': item['transfer_id'],
                    'offset': 0, 'limit': max(1, remaining)})
                remaining -= chunk['bytes']
            results.append({'metadata': meta, 'unchanged': unchanged, 'chunk': chunk})
        return {'files': results}

    @staticmethod
    def meta(path):
        return strict_json(Path(path).read_bytes())

    def read_chunk(self, args):
        keys(args, ('transfer_id', 'offset', 'limit'))
        folder = self.root / ('read-' + identifier(args['transfer_id']))
        meta = self.meta(folder / 'meta.json')
        offset = integer(args['offset'], 0, meta['bytes'])
        limit = integer(args['limit'], 1, MAX_CHUNK)
        with (folder / 'data').open('rb') as stream:
            stream.seek(offset)
            data = stream.read(limit)
        return {'offset': offset, 'bytes': len(data), 'sha256': digest(data),
            'data': encode_bytes(data), 'complete': offset + len(data) == meta['bytes']}

    def upload_begin(self, args):
        keys(args, ('transfer_id', 'path', 'bytes', 'sha256', 'expected_before_sha256'))
        require(self.write_enabled, 'WRITES_DISABLED')
        transfer = identifier(args['transfer_id'])
        target = self.path(args['path'], absent=True,writing=True)
        size = integer(args['bytes'], 0, MAX_FILE)
        sha(args['sha256'])
        before = args['expected_before_sha256']
        require(before == 'absent' or (isinstance(before, str) and len(before) == 64),
            'BASELINE_REQUIRED')
        if before != 'absent':
            sha(before)
        specification = dict(args, path=str(target))
        folder = private_directory(self.root / ('upload-' + transfer))
        with file_lock(folder / 'lock'):
            if (folder / 'meta.json').exists():
                meta = self.meta(folder / 'meta.json')
                require(meta['specification'] == specification, 'TRANSFER_CONFLICT')
            else:
                with (folder / 'data').open('xb'):
                    pass
                os.chmod(folder / 'data', 0o600)
                atomic_json(folder / 'meta.json', {'specification': specification})
            return {'transfer_id': transfer, 'received': (folder / 'data').stat().st_size,
                'bytes': size}

    def upload_status(self, args):
        keys(args, ('transfer_id',))
        folder = self.root / ('upload-' + identifier(args['transfer_id']))
        meta = self.meta(folder / 'meta.json')['specification']
        data = (folder / 'data').read_bytes()
        require(len(data) <= meta['bytes'], 'TRANSFER_CORRUPTED')
        return {'transfer_id': args['transfer_id'], 'received': len(data),
            'prefix_sha256': digest(data), 'complete': len(data) == meta['bytes'] and
            digest(data) == meta['sha256']}

    def upload_chunk(self, args):
        keys(args, ('transfer_id', 'offset', 'data', 'sha256'))
        require(self.write_enabled, 'WRITES_DISABLED')
        folder = self.root / ('upload-' + identifier(args['transfer_id']))
        meta = self.meta(folder / 'meta.json')['specification']
        data = decode_bytes(args['data'])
        require(args['sha256'] == digest(data), 'CHUNK_HASH_MISMATCH')
        offset = integer(args['offset'], 0, meta['bytes'])
        require(data and offset + len(data) <= meta['bytes'], 'BAD_CHUNK_RANGE')
        with file_lock(folder / 'lock'):
            current = (folder / 'data').stat().st_size
            if offset < current:
                with (folder / 'data').open('rb') as stream:
                    stream.seek(offset)
                    require(stream.read(len(data)) == data and offset + len(data) <= current,
                        'DUPLICATE_CHUNK_CONFLICT')
            else:
                require(offset == current, 'CHUNK_OUT_OF_ORDER')
                with (folder / 'data').open('ab') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            return self.upload_status({'transfer_id': args['transfer_id']})

    def commit(self, args):
        keys(args, ('transaction_id', 'transfer_ids'))
        require(self.write_enabled, 'WRITES_DISABLED')
        transaction = identifier(args['transaction_id'])
        transfers = args['transfer_ids']
        require(isinstance(transfers, list) and 1 <= len(transfers) <= 10 and
            len(set(transfers)) == len(transfers), 'BAD_BATCH')
        folder = private_directory(self.root / ('transaction-' + transaction))
        with file_lock(self.root / 'install.lock'), self.scope('write'):
            manifest_path = folder / 'manifest.json'
            if manifest_path.exists():
                manifest = self.meta(manifest_path)
                require(manifest['transfer_ids'] == transfers, 'TRANSACTION_CONFLICT')
                if manifest['state'] == 'committed':
                    return manifest
                require(manifest['state'] == 'applying', 'TRANSACTION_NEEDS_REVIEW')
                if all(self.current_hash(Path(e['path'])) == e['after_sha256']
                       for e in manifest['files']):
                    self.verify_backups(manifest, folder)
                    manifest['state'] = 'committed'
                    atomic_json(manifest_path, manifest)
                    return manifest
                raise Rejected('TRANSACTION_NEEDS_REVIEW')
            entries = []
            for transfer in transfers:
                transfer = identifier(transfer)
                upload = self.root / ('upload-' + transfer)
                spec = self.meta(upload / 'meta.json')['specification']
                target = self.path(spec['path'], absent=True,writing=True)
                data = (upload / 'data').read_bytes()
                require(len(data) == spec['bytes'] and digest(data) == spec['sha256'],
                    'TRANSFER_INCOMPLETE')
                require(str(target) not in [e['path'] for e in entries], 'DUPLICATE_TARGET')
                require(sum(e['bytes'] for e in entries) + len(data) <= MAX_FILE,
                    'BATCH_SIZE_LIMIT')
                current = self.current_hash(target)
                require(current == spec['expected_before_sha256'], 'BASELINE_CONFLICT')
                before_mode = stat.S_IMODE(target.stat().st_mode) if current != 'absent' else 0o644
                backup = str(len(entries)) + '.before'
                if current != 'absent':
                    original, info = self.read(target)
                    require(digest(original) == current, 'BASELINE_CONFLICT')
                    if (folder/backup).exists():
                        require(digest((folder/backup).read_bytes())==current,
                            'BACKUP_HASH_MISMATCH')
                    else:
                        with (folder / backup).open('xb') as stream:
                            stream.write(original)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.chmod(folder / backup, 0o600)
                else:
                    info=None
                entries.append({'path':str(target), 'transfer_id':transfer,
                    'before_sha256':current, 'after_sha256':spec['sha256'],
                    'bytes':len(data), 'mode':before_mode, 'backup':backup,
                    'before_metadata':None if info is None else {
                        'uid':info.st_uid,'gid':info.st_gid,'bytes':info.st_size,
                        'mode':stat.S_IMODE(info.st_mode),'mtime_ns':info.st_mtime_ns}})
            manifest = {'transaction_id': transaction, 'transfer_ids': transfers,
                'state':'applying', 'files':entries}
            atomic_json(manifest_path, manifest)
            changed = []
            try:
                self.verify_backups(manifest, folder)
                for entry in entries:
                    target = self.path(entry['path'], absent=True,writing=True)
                    require(self.current_hash(target) == entry['before_sha256'], 'BASELINE_CONFLICT')
                    data = (self.root / ('upload-' + entry['transfer_id']) / 'data').read_bytes()
                    require(len(data)==entry['bytes'] and digest(data)==entry['after_sha256'],
                        'TRANSFER_CORRUPTED')
                    changed.append(entry)
                    self.replace(target, data, entry['mode'])
                    require(self.current_hash(target) == entry['after_sha256'], 'INSTALL_VERIFY_FAILED')
                manifest['state'] = 'committed'
                atomic_json(manifest_path, manifest)
                return manifest
            except Exception:
                rollback_ok = True
                for entry in reversed(changed):
                    try:
                        target = self.path(entry['path'], absent=True,writing=True)
                        current=self.current_hash(target)
                        if current==entry['before_sha256']:
                            continue
                        if current != entry['after_sha256']:
                            rollback_ok = False
                            continue
                        if entry['before_sha256'] == 'absent':
                            self.remove(target)
                        else:
                            require(digest((folder / entry['backup']).read_bytes())==
                                entry['before_sha256'],'BACKUP_HASH_MISMATCH')
                            self.replace(target, (folder / entry['backup']).read_bytes(), entry['mode'])
                        require(self.current_hash(target)==entry['before_sha256'],
                            'ROLLBACK_VERIFY_FAILED')
                    except Exception:
                        rollback_ok = False
                manifest['state'] = 'rolled_back' if rollback_ok else 'needs_review'
                atomic_json(manifest_path, manifest)
                raise

    def verify_backups(self, manifest, folder):
        for entry in manifest['files']:
            if entry['before_sha256'] != 'absent':
                require(digest((folder / entry['backup']).read_bytes()) == entry['before_sha256'],
                    'BACKUP_HASH_MISMATCH')

    def current_hash(self, path):
        if not path.exists():
            require(not path.is_symlink(), 'SYMLINK_REJECTED')
            return 'absent'
        require(not path.is_symlink(), 'SYMLINK_REJECTED')
        return digest(self.read(path)[0])

    @staticmethod
    def replace(target, data, mode):
        if os.name=='posix':
            with parent_directory(target) as parent:
                name='.etx-install-'+uuid.uuid4().hex
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                    0o600,dir_fd=parent)
                try:
                    with os.fdopen(fd,'wb') as stream:
                        stream.write(data)
                        stream.flush()
                        if target.exists():
                            info=os.stat(target.name,dir_fd=parent,follow_symlinks=False)
                            require(stat.S_ISREG(info.st_mode),'NOT_REGULAR_FILE')
                            os.fchown(stream.fileno(),-1,info.st_gid)
                        os.fchmod(stream.fileno(),mode)
                        os.fsync(stream.fileno())
                    os.replace(name,target.name,src_dir_fd=parent,dst_dir_fd=parent)
                    os.fsync(parent)
                finally:
                    try:
                        os.unlink(name,dir_fd=parent)
                    except FileNotFoundError:
                        pass
            return
        fd, temporary = tempfile.mkstemp(prefix='.etx-install-', dir=str(target.parent))
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, target)
            sync_directory(target.parent)
        finally:
            Path(temporary).unlink(missing_ok=True)

    @staticmethod
    def remove(target):
        with parent_directory(target) as parent:
            os.unlink(target.name if parent is not None else str(target),dir_fd=parent)
            if parent is not None:
                os.fsync(parent)

    def restore(self,args):
        keys(args,('transaction_id','restoration_id'))
        require(self.write_enabled,'WRITES_DISABLED')
        original=identifier(args['transaction_id'])
        restoration=identifier(args['restoration_id'])
        source=self.root/('transaction-'+original)
        folder=private_directory(self.root/('restoration-'+restoration))
        with file_lock(self.root/'install.lock'),self.scope('write'):
            manifest_path=folder/'manifest.json'
            if manifest_path.exists():
                saved=self.meta(manifest_path)
                require(saved['source_transaction_id']==original,'TRANSACTION_CONFLICT')
                if saved['state']=='committed':
                    return saved
                if saved['state']=='applying' and all(self.current_hash(
                        self.path(e['path'],absent=True,writing=True))==e['after_sha256']
                        for e in saved['files']):
                    self.verify_backups(saved,folder)
                    saved['state']='committed'
                    atomic_json(manifest_path,saved)
                    return saved
                raise Rejected('RESTORATION_NEEDS_REVIEW')
            installed=self.meta(source/'manifest.json')
            require(installed['state']=='committed','TRANSACTION_NEEDS_REVIEW')
            self.verify_backups(installed,source)
            entries=[]
            for index,entry in enumerate(installed['files']):
                target=self.path(entry['path'],writing=True)
                data,info=self.read(target)
                require(digest(data)==entry['after_sha256'],'BASELINE_CONFLICT')
                backup=str(index)+'.before'
                if (folder/backup).exists():
                    require(digest((folder/backup).read_bytes())==digest(data),
                        'BACKUP_HASH_MISMATCH')
                else:
                    with (folder/backup).open('xb') as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.chmod(folder/backup,0o600)
                entries.append({'path':str(target),'before_sha256':digest(data),
                    'after_sha256':entry['before_sha256'],'backup':backup,
                    'original_backup':entry['backup'],'mode':entry['mode'],
                    'before_mode':stat.S_IMODE(info.st_mode),
                    'before_metadata':{'uid':info.st_uid,'gid':info.st_gid,
                        'bytes':info.st_size,'mode':stat.S_IMODE(info.st_mode),
                        'mtime_ns':info.st_mtime_ns}})
            manifest={'transaction_id':restoration,'source_transaction_id':original,
                'state':'applying','files':entries}
            atomic_json(manifest_path,manifest)
            changed=[]
            try:
                for entry in entries:
                    target=self.path(entry['path'],writing=True)
                    require(self.current_hash(target)==entry['before_sha256'],'BASELINE_CONFLICT')
                    changed.append(entry)
                    if entry['after_sha256']=='absent':
                        self.remove(target)
                    else:
                        self.replace(target,(source/entry['original_backup']).read_bytes(),entry['mode'])
                    require(self.current_hash(target)==entry['after_sha256'],'INSTALL_VERIFY_FAILED')
                manifest['state']='committed'
                atomic_json(manifest_path,manifest)
                return manifest
            except Exception:
                rollback_ok=True
                for entry in reversed(changed):
                    try:
                        target=self.path(entry['path'],absent=True,writing=True)
                        current=self.current_hash(target)
                        if current==entry['before_sha256']:
                            continue
                        require(current==entry['after_sha256'],'BASELINE_CONFLICT')
                        data=(folder/entry['backup']).read_bytes()
                        require(digest(data)==entry['before_sha256'],'BACKUP_HASH_MISMATCH')
                        self.replace(target,data,entry['before_mode'])
                        require(self.current_hash(target)==entry['before_sha256'],'ROLLBACK_VERIFY_FAILED')
                    except Exception:
                        rollback_ok=False
                manifest['state']='rolled_back' if rollback_ok else 'needs_review'
                atomic_json(manifest_path,manifest)
                raise

    def receipt(self, args):
        keys(args, ('transaction_id',))
        folder = self.root / ('transaction-' + identifier(args['transaction_id']))
        require((folder / 'manifest.json').exists(), 'RECEIPT_NOT_FOUND')
        return self.meta(folder / 'manifest.json')
