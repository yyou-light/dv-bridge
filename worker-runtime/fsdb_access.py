"""Small per-FSDB read/write lock, embedded in the signed simulation launcher."""
import contextlib
import hashlib
import os
import json
import re
import stat
from pathlib import Path
from site_config import site


class FsdbInUse(RuntimeError):
    pass


def fsdb_slot(path):
    name = Path(path).parent.name.rsplit('_', 1)[-1]
    return name if re.fullmatch(r'work[0-9]{2}', name) else 'manual'


@contextlib.contextmanager
def fsdb_access(path, write=False):
    import fcntl

    identity = hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest()
    root = Path(site()['remote']['lock_root'])
    for directory in (root, root / 'fsdb'):
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise FsdbInUse('UNSAFE_FSDB_LOCK_DIRECTORY')
    fd = os.open(str(root / 'fsdb' / (identity + '.lock')), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise FsdbInUse('UNSAFE_FSDB_LOCK_FILE')
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise FsdbInUse('FSDB_FILE_IN_USE')
        if write:
            leases = Path(site()['remote']['queue_root'])/'readers' / fsdb_slot(path)
            if leases.is_dir():
                for entry in leases.glob('*.json'):
                    info = entry.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > 8192:
                        raise FsdbInUse('UNSAFE_FSDB_READER_RECORD')
                    lease = json.loads(entry.read_text(encoding='utf-8'))
                    if lease.get('fsdb') == str(Path(path).resolve()):
                        raise FsdbInUse('FSDB_READER_NOT_CLOSED')
        yield
    finally:
        os.close(fd)
