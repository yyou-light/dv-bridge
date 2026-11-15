"""One bounded text batch in one Windows client, with pinned local cache hashes."""
import os
import re
import stat
import tempfile
import time
from pathlib import Path

from session_protocol import (Rejected, require, keys, identifier, integer, sha,
    digest, decode_bytes, MAX_CHUNK)


def stable_id(task, suffix):
    return digest((task + '/' + suffix).encode('ascii'))[:32]


def ordinary(path):
    path = Path(path)
    for item in (path, *path.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not
            (getattr(info, 'st_file_attributes', 0) & 0x400), 'LOCAL_SYMLINK_REJECTED')
    require(stat.S_ISREG(path.stat().st_mode), 'LOCAL_NOT_REGULAR')
    return path


def local_bytes(path):
    path = ordinary(path)
    before = path.stat()
    require(before.st_size <= 524288, 'TEXT_SIZE_LIMIT')
    with path.open('rb') as stream:
        data = stream.read(524289)
    after = path.stat()
    require((before.st_ino, before.st_size, before.st_mtime_ns) ==
        (after.st_ino, after.st_size, after.st_mtime_ns), 'LOCAL_CACHE_CHANGED')
    require(len(data) <= 524288, 'TEXT_SIZE_LIMIT')
    utf8(data)
    return data


def utf8(data):
    try:
        data.decode('utf-8')
    except UnicodeError:
        raise Rejected('TEXT_ENCODING_REJECTED') from None


def read_files(client, spec, output_root):
    started = time.perf_counter()
    keys(spec, ('id', 'files', 'timeout_seconds'))
    task = identifier(spec['id'])
    deadline = time.monotonic() + integer(spec['timeout_seconds'], 1, 3600)
    require(type(spec['files']) is list and 1 <= len(spec['files']) <= 10,
        'BATCH_SIZE_LIMIT')
    prepared, arguments, names, paths = [], [], set(), set()
    for index, item in enumerate(spec['files']):
        keys(item, ('path', 'cached_file', 'cached_sha256', 'output_name'))
        path, name = item['path'], item['output_name']
        require(isinstance(path, str) and (path.startswith('/') or Path(path).is_absolute()) and '\x00' not in path
            and '..' not in Path(path).parts, 'BAD_PATH')
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,160}', name)
            is not None and name not in ('.', '..'), 'BAD_OUTPUT_NAME')
        require(name.casefold() not in names and path not in paths, 'BATCH_DUPLICATE')
        names.add(name.casefold()); paths.add(path)
        cached = None
        if item['cached_file'] is None:
            require(item['cached_sha256'] is None, 'BAD_CACHE_SPEC')
        else:
            sha(item['cached_sha256'])
            require(isinstance(item['cached_file'], str) and
                Path(item['cached_file']).is_absolute(), 'BAD_CACHE_SPEC')
            cached = local_bytes(item['cached_file'])
            require(digest(cached) == item['cached_sha256'], 'LOCAL_CACHE_CHANGED')
        transfer = stable_id(task, 'file-' + str(index))
        prepared.append((item, cached, transfer))
        arguments.append({'path': path, 'transfer_id': transfer,
            'known_sha256': item['cached_sha256']})
    cache_seconds = time.perf_counter() - started
    output_root = Path(output_root)
    require(output_root.is_absolute() and output_root.is_dir(), 'BAD_OUTPUT_ROOT')
    for parent in (output_root, *output_root.parents):
        info = parent.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not
            (getattr(info, 'st_file_attributes', 0) & 0x400), 'LOCAL_SYMLINK_REJECTED')

    def call(op, args, rid):
        require(time.monotonic() < deadline, 'READ_TASK_TIMEOUT_QUERY_SAME_ID')
        return client.call(op, args, rid)

    result = call('read_batch', {'files': arguments}, task)
    keys(result, ('files',))
    require(type(result['files']) is list and len(result['files']) == len(prepared),
        'BATCH_RESPONSE_MISMATCH')
    completed, inline_total, downloaded = [], 0, 0
    for (item, cached, transfer), received in zip(prepared, result['files']):
        keys(received, ('metadata', 'unchanged', 'chunk'))
        meta = received['metadata']
        keys(meta, ('transfer_id', 'path', 'bytes', 'sha256', 'identity', 'chunk_bytes'))
        require(meta['path'] == item['path'] and meta['transfer_id'] == transfer,
            'BATCH_RESPONSE_MISMATCH')
        integer(meta['bytes'], 0, 524288); sha(meta['sha256'])
        require(type(received['unchanged']) is bool and received['unchanged'] ==
            (item['cached_sha256'] == meta['sha256']), 'BATCH_RESPONSE_MISMATCH')
        if received['unchanged']:
            require(received['chunk'] is None and cached is not None, 'BATCH_RESPONSE_MISMATCH')
            data = cached
        else:
            data = bytearray()

            def append(part):
                keys(part, ('offset', 'bytes', 'sha256', 'data', 'complete'))
                raw = decode_bytes(part['data'])
                require(part['offset'] == len(data) and type(part['bytes']) is int and
                    part['bytes'] == len(raw) and digest(raw) == part['sha256'], 'CHUNK_HASH_MISMATCH')
                require(len(data) + len(raw) <= meta['bytes'] and
                    (len(raw) > 0 or meta['bytes'] == 0), 'CHUNK_SIZE_LIMIT')
                data.extend(raw)
                require(type(part['complete']) is bool and part['complete'] ==
                    (len(data) == meta['bytes']), 'CHUNK_COMPLETION_MISMATCH')
                return len(raw)

            if received['chunk'] is not None:
                size = append(received['chunk']); inline_total += size; downloaded += size
                require(inline_total <= 196608, 'BATCH_INLINE_LIMIT')
            while len(data) < meta['bytes']:
                offset = len(data)
                part = call('read_chunk', {'transfer_id': transfer, 'offset': offset,
                    'limit': MAX_CHUNK}, stable_id(task, 'chunk-' + str(len(completed)) + '-' + str(offset)))
                downloaded += append(part)
            data = bytes(data)
        require(len(data) == meta['bytes'] and digest(data) == meta['sha256'], 'FILE_HASH_MISMATCH')
        utf8(data)
        completed.append((item, meta, data, received['unchanged']))

    written = time.perf_counter()
    outputs = []
    for item, meta, data, unchanged in completed:
        target = output_root / item['output_name']
        if target.exists() or target.is_symlink():
            require(digest(local_bytes(target)) == meta['sha256'], 'LOCAL_OUTPUT_CONFLICT')
        else:
            fd, name = tempfile.mkstemp(prefix='.read-', dir=str(output_root))
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.replace(name, target)
            finally:
                Path(name).unlink(missing_ok=True)
        outputs.append({'path': item['path'], 'local': str(target), 'bytes': meta['bytes'],
            'sha256': meta['sha256'], 'identity': meta['identity'], 'cache_hit': unchanged})
    return {'files': outputs, 'downloaded_bytes': downloaded,
        'cache_hits': sum(x['cache_hit'] for x in outputs),
        'timings': {'cache_validation_seconds': round(cache_seconds, 6),
            'write_seconds': round(time.perf_counter() - written, 6),
            'total_seconds': round(time.perf_counter() - started, 6)}}
