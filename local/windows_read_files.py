"""Bounded-memory UTF-8 downloads with immutable snapshots and resumable parts."""
import os
import re
import stat
import time
from pathlib import Path

from session_protocol import (Rejected, require, keys, identifier, integer, sha,
    digest, decode_bytes, MAX_CHUNK, MAX_TEXT_FILE)
from session_files import Files, atomic_json


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


def file_meta(path):
    path = ordinary(path)
    hasher, info = Files.stream_file(path, text_only=True)
    return info.st_size, hasher.hexdigest()


def verify_part(part, checkpoint, meta):
    if not part.exists():
        require(not checkpoint.exists(), 'LOCAL_PART_MISSING')
        return []
    ordinary(part)
    require(checkpoint.exists(), 'LOCAL_CHECKPOINT_MISSING')
    saved = Files.meta(ordinary(checkpoint))
    require(set(saved) == {'metadata','chunks'} and saved['metadata'] == meta
        and type(saved['chunks']) is list, 'LOCAL_CHECKPOINT_CONFLICT')
    offset = 0
    with part.open('rb') as stream:
        for chunk in saved['chunks']:
            keys(chunk, ('offset','bytes','sha256'))
            require(type(chunk['offset']) is int and chunk['offset'] == offset, 'LOCAL_PART_CHANGED')
            size = integer(chunk['bytes'], 1, MAX_CHUNK)
            require(offset + size <= meta['bytes'], 'LOCAL_PART_CHANGED')
            raw = stream.read(size)
            require(len(raw) == size and digest(raw) == chunk['sha256'], 'LOCAL_PART_CHANGED')
            offset += size
        require(part.stat().st_size >= offset, 'LOCAL_PART_CHANGED')
    if part.stat().st_size != offset:
        # Discard only our own interrupted append beyond the durable checkpoint.
        with part.open('r+b') as stream:
            stream.truncate(offset)
            stream.flush()
            os.fsync(stream.fileno())
    return saved['chunks']


def read_files(client, spec, output_root):
    started = time.perf_counter()
    keys(spec, ('id','files','timeout_seconds'))
    task = identifier(spec['id'])
    deadline = time.monotonic() + integer(spec['timeout_seconds'], 1, 3600)
    require(type(spec['files']) is list and 1 <= len(spec['files']) <= 10, 'BATCH_SIZE_LIMIT')
    prepared, arguments, names, paths = [], [], set(), set()
    for index, item in enumerate(spec['files']):
        keys(item, ('path','cached_file','cached_sha256','output_name'))
        path, name = item['path'], item['output_name']
        require(isinstance(path,str) and (path.startswith('/') or Path(path).is_absolute())
            and '\x00' not in path and '..' not in Path(path).parts, 'BAD_PATH')
        require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,160}',name)
            is not None and name not in ('.','..'), 'BAD_OUTPUT_NAME')
        require(name.casefold() not in names and path not in paths, 'BATCH_DUPLICATE')
        names.add(name.casefold()); paths.add(path)
        cache = None
        if item['cached_file'] is None:
            require(item['cached_sha256'] is None, 'BAD_CACHE_SPEC')
        else:
            sha(item['cached_sha256'])
            require(isinstance(item['cached_file'],str) and Path(item['cached_file']).is_absolute(), 'BAD_CACHE_SPEC')
            cache = ordinary(item['cached_file'])
            require(file_meta(cache)[1] == item['cached_sha256'], 'LOCAL_CACHE_CHANGED')
        transfer = stable_id(task, 'file-' + str(index))
        prepared.append((item, cache, transfer))
        arguments.append({'path':path,'transfer_id':transfer,'known_sha256':item['cached_sha256']})
    cache_seconds = time.perf_counter() - started
    output_root = Path(output_root)
    require(output_root.is_absolute() and output_root.is_dir(), 'BAD_OUTPUT_ROOT')
    for parent in (output_root,*output_root.parents):
        info = parent.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not
            (getattr(info,'st_file_attributes',0) & 0x400), 'LOCAL_SYMLINK_REJECTED')

    def call(op, args, rid):
        require(time.monotonic() < deadline, 'READ_TASK_TIMEOUT_QUERY_SAME_ID')
        return client.call(op,args,rid)

    result = call('read_batch', {'files':arguments}, task)
    keys(result, ('files',))
    require(type(result['files']) is list and len(result['files']) == len(prepared), 'BATCH_RESPONSE_MISMATCH')
    outputs, inline_total, downloaded, total = [], 0, 0, 0
    written = time.perf_counter()
    for index, ((item,cache,transfer),received) in enumerate(zip(prepared,result['files'])):
        keys(received, ('metadata','unchanged','chunk'))
        meta = received['metadata']
        keys(meta, ('transfer_id','path','bytes','sha256','identity','chunk_bytes'))
        require(meta['path'] == item['path'] and meta['transfer_id'] == transfer, 'BATCH_RESPONSE_MISMATCH')
        integer(meta['bytes'],0,MAX_TEXT_FILE); sha(meta['sha256'])
        require(meta['chunk_bytes'] == MAX_CHUNK, 'BATCH_RESPONSE_MISMATCH')
        total += meta['bytes']
        require(total <= MAX_TEXT_FILE, 'BATCH_SIZE_LIMIT')
        require(type(received['unchanged']) is bool and received['unchanged'] ==
            (item['cached_sha256'] == meta['sha256']), 'BATCH_RESPONSE_MISMATCH')
        target = output_root / item['output_name']
        if target.exists() or target.is_symlink():
            require(file_meta(target) == (meta['bytes'],meta['sha256']), 'LOCAL_OUTPUT_CONFLICT')
        else:
            part = output_root / ('.' + transfer + '.part')
            checkpoint = output_root / ('.' + transfer + '.checkpoint.json')
            require(not part.is_symlink() and not checkpoint.is_symlink(), 'LOCAL_SYMLINK_REJECTED')
            chunks = verify_part(part,checkpoint,meta)
            offset = sum(chunk['bytes'] for chunk in chunks)

            def append(part_reply):
                nonlocal offset, downloaded
                keys(part_reply, ('offset','bytes','sha256','data','complete'))
                raw = decode_bytes(part_reply['data'])
                require(type(part_reply['offset']) is int and type(part_reply['bytes']) is int
                    and part_reply['bytes'] == len(raw) and digest(raw) == part_reply['sha256'], 'CHUNK_HASH_MISMATCH')
                require(part_reply['offset'] >= 0 and part_reply['offset'] + len(raw) <= meta['bytes']
                    and (raw or meta['bytes'] == 0), 'CHUNK_SIZE_LIMIT')
                require(type(part_reply['complete']) is bool and part_reply['complete'] ==
                    (part_reply['offset'] + len(raw) == meta['bytes']), 'CHUNK_COMPLETION_MISMATCH')
                if part_reply['offset'] < offset:
                    require(part_reply['offset'] + len(raw) <= offset, 'LOCAL_PART_CHANGED')
                    with part.open('rb') as stream:
                        stream.seek(part_reply['offset'])
                        require(stream.read(len(raw)) == raw, 'LOCAL_PART_CHANGED')
                    return
                require(part_reply['offset'] == offset, 'CHUNK_OFFSET_MISMATCH')
                if part.exists(): ordinary(part)
                with part.open('ab') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                if raw:
                    chunks.append({'offset':offset,'bytes':len(raw),'sha256':digest(raw)})
                offset += len(raw)
                downloaded += len(raw)
                atomic_json(checkpoint, {'metadata':meta,'chunks':chunks})

            if received['unchanged']:
                require(received['chunk'] is None and cache is not None, 'BATCH_RESPONSE_MISMATCH')
                require(not chunks and not part.exists(), 'LOCAL_CHECKPOINT_CONFLICT')
                with part.open('xb') as stream:
                    copied, info = Files.stream_file(cache,text_only=True,output=stream)
                    stream.flush(); os.fsync(stream.fileno())
                require((info.st_size,copied.hexdigest()) == (meta['bytes'],meta['sha256']), 'LOCAL_CACHE_CHANGED')
            else:
                if received['chunk'] is not None:
                    inline_total += received['chunk']['bytes']
                    require(inline_total <= 196608, 'BATCH_INLINE_LIMIT')
                    append(received['chunk'])
                while offset < meta['bytes']:
                    append(call('read_chunk', {'transfer_id':transfer,'offset':offset,'limit':MAX_CHUNK},
                        stable_id(task,'chunk-' + str(index) + '-' + str(offset))))
                if not part.exists(): part.touch(exist_ok=False)
            require(file_meta(part) == (meta['bytes'],meta['sha256']), 'FILE_HASH_MISMATCH')
            require(not target.exists() and not target.is_symlink(), 'LOCAL_OUTPUT_CONFLICT')
            os.replace(part,target)
            checkpoint.unlink(missing_ok=True)
        outputs.append({'path':meta['path'],'local':str(target),'bytes':meta['bytes'],
            'sha256':meta['sha256'],'identity':meta['identity'],'cache_hit':received['unchanged'],
            'retention':'temporary_log' if Path(meta['path']).name.endswith('.log') else 'baseline'})
    return {'files':outputs,'cache_hits':sum(item['cache_hit'] for item in outputs),
        'downloaded_bytes':downloaded,'timings':{'total_seconds':time.perf_counter()-started,
            'cache_validation_seconds':cache_seconds,'write_seconds':time.perf_counter()-written}}
