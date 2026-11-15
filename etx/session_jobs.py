"""Fixed signed self-test and read-only wave jobs; no user command execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import time
from site_config import site as deployment_site

MAX_RESULT = 196608
JOB_LOADER = '''import hashlib,os,sys
p,expected=sys.argv[1:3]
sys.path.insert(0,os.path.dirname(p))
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as f:
 d=f.read(524289)
assert len(d)<=524288 and hashlib.sha256(d).hexdigest()==expected,'JOB_MODULE_CHANGED'
sys.argv=[p]+sys.argv[3:]
exec(compile(d,p,'exec'),{'__name__':'__main__','__file__':p})
'''


def canonical(value):
    return json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,
        separators=(',',':')).encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check(value, code):
    if not value:
        raise RuntimeError(code)


def ordinary(path, limit=524288):
    path=Path(path)
    for p in (path,*path.parents):
        check(not p.is_symlink(),'JOB_SYMLINK_REJECTED')
    info=path.stat()
    check(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and
        info.st_size<=limit,'JOB_FILE_REJECTED')
    return path


def job_argv(root, job_sha256, config_sha256, kind, request_id, profile, options):
    check(kind in ('selftest','wave','wave_probe'),'JOB_KIND_REJECTED')
    check(re.fullmatch('[0-9a-f]{32}',request_id) is not None and
        re.fullmatch('work0[1-5]',profile) is not None,'JOB_ID_REJECTED')
    for value in (job_sha256,config_sha256):
        check(re.fullmatch('[0-9a-f]{64}',value) is not None,'JOB_HASH_REJECTED')
    spec={'kind':kind,'request_id':request_id,'profile':profile,'options':options}
    path=PurePosixPath(root)
    return [deployment_site()['remote']['python'],'-B','-c',JOB_LOADER,
        str(path/'etx/session_jobs.py'),job_sha256,
        str(path/'server-control-online.json'),config_sha256,canonical(spec).decode('utf-8')]


def compatible_backend_source(raw):
    if deployment_site()['wave']['compatibility_patch']=='none':return raw
    newline=b'\r\n' if b'\r\n' in raw else b'\n'
    old=b'                for value in times:'+newline+b'                    wave_time(value)'
    new=b'                for sample_time in times:'+newline+b'                    wave_time(sample_time)'
    check(raw.count(old)==1,'BACKEND_COMPATIBILITY_REVIEW_REQUIRED')
    return raw.replace(old,new,1)


def load_backend(config):
    """Verify the installed release; retain its existing NPI and LSF implementation."""
    check(config.get('wave_enabled') is True,'WAVE_NOT_CONFIGURED')
    root=Path(config['wave_root'])
    expected=config['wave_release']
    current=json.loads(ordinary(root/'current.json',65536).read_bytes())
    check(current.get('release')==expected,'XVERIF_RELEASE_CHANGED')
    names={'common.py','wire.py','worker.py','installer.py','fake_mcp.py','recipient.pem'}
    check(set(current.get('files',{}))==names,'XVERIF_RELEASE_MANIFEST_REJECTED')
    folder=root/'releases'/expected
    for name,want in current['files'].items():
        check(digest(ordinary(folder/name,2097152).read_bytes())==want,'XVERIF_FILE_CHANGED')
    sys.path.insert(0,str(folder))
    spec=importlib.util.spec_from_file_location('etx_x11_pinned_wave_backend',folder/'worker.py')
    backend=importlib.util.module_from_spec(spec)
    raw=ordinary(folder/'worker.py',2097152).read_bytes()
    check(digest(raw)==current['files']['worker.py'],'XVERIF_FILE_CHANGED')
    exec(compile(compatible_backend_source(raw),str(folder/'worker.py'),'exec'),backend.__dict__)
    return backend,root,current


def execution_environment(config):
    backend,root,_=load_backend(config)
    site=backend.site(root)
    tools,env=backend.lsf_tools(site,deployment_site()['remote']['eda_bin'])
    if any(not p for p in tools.values()):
        loaded=backend.load_lsf_module(site,env)
        check(loaded.get('ok'),'LSF_MODULE_LOAD_FAILED')
        env.update(loaded['environment']);tools=backend.resolved_lsf_tools(env)
    check(all(tools.values()),'LSF_TOOLS_MISSING')
    return env,{'tools_ready':sorted(tools),'site_python':site['python']}


def selftest(options, output, request_id, profile):
    check(set(options)=={'hold_seconds'} and type(options['hold_seconds']) is int
        and options['hold_seconds'] in (1,30,90),'SELFTEST_OPTIONS_REJECTED')
    import socket
    start=time.time();end=time.monotonic()+options['hold_seconds']
    while time.monotonic()<end and not (output/'selftest-release.json').exists():
        time.sleep(0.1)
    return {'result':'PASS','kind':'selftest','request_id':request_id,'profile':profile,
        'host':socket.gethostname(),'started_at':start,'finished_at':time.time(),
        'business_simulations':0}


def require_no_other_writer(queue, fsdb, request_id, slot):
    path=queue/'active.json'
    if not path.exists():return
    active=json.loads(ordinary(path,65536).read_bytes())
    ids=list(active.get('workers',{}).values()) if 'workers' in active else [active['request_id']]
    for writer in ids:
        if writer==request_id:continue  # This queue entry owns the read request.
        check(re.fullmatch('[0-9a-f]{32}',writer) is not None,'BAD_WRITER_RECORD')
        job=queue/'jobs'/writer
        state=json.loads(ordinary(job/'state.json',65536).read_bytes())
        if state['state'] in ('exited','not_started','launch_failed'):continue
        declaration=job/'output/fsdb-write.json'
        if declaration.exists():
            record=json.loads(ordinary(declaration,8192).read_bytes())
            check(record.get('request_id')==writer,'BAD_WRITER_RECORD')
            check(record.get('fsdb')!=str(fsdb.resolve()),'FSDB_ACTIVE_WRITER')
        else:
            record=json.loads(ordinary(job/'request.json',65536).read_bytes())
            check(record.get('profile')!=slot,'FSDB_LEGACY_WRITER_UNRESOLVED')


def wave(config, options, output, request_id, probe=False):
    backend,original,current=load_backend(config)
    if not probe:
        options=backend.validate_wave_request(options)
        fsdb=ordinary(options['fsdb'],2**63-1)
        check(fsdb.suffix.lower()=='.fsdb','FSDB_TYPE_REJECTED')
        info=fsdb.stat();before=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
        check(info.st_size>0,'FSDB_EMPTY')
        stdout=fsdb.parent/'stdout.log'
        ordinary(stdout,2**63-1)
        with stdout.open('rb') as stream:
            stream.seek(max(0,stdout.stat().st_size-262144));tail=stream.read(262144)
        check(any(marker in tail for marker in (b'V C S   S i m u l a t i o n',
            b'$finish called',b'$finish at simulation time')),'FSDB_NATIVE_END_NOT_FOUND')
    # State and NPI cleanup belong only to this request. Legacy unresolved
    # guards in the old Runner root are never deleted or reused.
    isolated=output/'wave-backend';isolated.mkdir(mode=0o700,exist_ok=True)
    state=isolated/'state';state.mkdir(mode=0o700,exist_ok=True)
    files={}
    for name,want in current['files'].items():
        data=ordinary(original/'releases'/current['release']/name,2097152).read_bytes()
        check(digest(data)==want,'XVERIF_FILE_CHANGED')
        files[name]=compatible_backend_source(data) if name=='worker.py' else data
    hashes={name:digest(data) for name,data in files.items()}
    owned_current=dict(current,files=hashes,release=digest(canonical(sorted(hashes.items()))))
    target=isolated/'releases'/owned_current['release'];target.mkdir(mode=0o700,parents=True,exist_ok=True)
    for name,data in files.items():
        (target/name).write_bytes(data);os.chmod(target/name,0o600)
    (isolated/'current.json').write_bytes(canonical(owned_current));os.chmod(isolated/'current.json',0o600)
    (isolated/'owner.json').write_bytes(ordinary(original/'owner.json',4096).read_bytes())
    os.chmod(isolated/'owner.json',0o600)
    (state/'site.json').write_bytes(ordinary(original/'state/site.json',65536).read_bytes())
    os.chmod(state/'site.json',0o600)
    # Load the verified copy so its LSF child entry point uses the same private root.
    spec=importlib.util.spec_from_file_location('etx_x11_owned_wave_backend',target/'worker.py')
    owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)
    if probe:
        result=owned.lsf_probe(isolated,request_id,deployment_site()['remote']['eda_bin'],task='wave_metadata')
        return {'kind':'wave_probe','request_id':request_id,
            'result':'PASS' if result.get('readiness',{}).get('mcp_connected') else 'FAIL',
            'wave':backend.public_wave_result(result)}
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from session_files import file_lock,atomic_json
    from fsdb_access import fsdb_access,fsdb_slot
    queue=Path(deployment_site()['remote']['queue_root'])
    readers=queue/'readers'/fsdb_slot(fsdb)
    readers.mkdir(mode=0o700,parents=True,exist_ok=True)
    lease=readers/(request_id+'.json')
    with backend.queue_transaction():
        require_no_other_writer(queue,fsdb,request_id,fsdb_slot(fsdb))
        check(not lease.exists(),'WAVE_READER_ALREADY_REGISTERED')
        atomic_json(lease,{'request_id':request_id,'fsdb':str(fsdb.resolve()),'kind':'x11-wave'})
    result=None;query_started=False
    try:
        with fsdb_access(fsdb,write=False):
            query_started=True
            # This adapter already owns the read lease and has excluded its own
            # queue entry. Reuse the backend's LSF/NPI execution without creating
            # a second, conflicting lease for this same request.
            result=owned.run_lsf_task(isolated,request_id,deployment_site()['remote']['eda_bin'],
                task='query',options=options)
        after=fsdb.stat()
        check(before==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'FSDB_CHANGED')
        released=result.get('lsf',{}).get('submitted') is False or result.get('resource_release',{}).get('confirmed') is True
        passed=released and result.get('query_ok') is True
        return {'kind':'wave','result':'PASS' if passed else 'FAIL','request_id':request_id,
            'wave':backend.public_wave_result(result)}
    finally:
        # Failed or uncertain NPI cleanup keeps this exact output reservation.
        if not query_started or (result is not None and (result.get('lsf',{}).get('submitted') is False or result.get('resource_release',{}).get('confirmed') is True)):
            lease.unlink(missing_ok=True)


def main():
    os.umask(0o077)
    config_path,expected,spec_text=sys.argv[1:]
    config_raw=ordinary(config_path).read_bytes()
    check(digest(config_raw)==expected,'JOB_CONFIGURATION_CHANGED')
    config=json.loads(config_raw);spec=json.loads(spec_text)
    check(set(spec)=={'kind','request_id','profile','options'},'JOB_FIELDS_REJECTED')
    check(os.environ.get('ETX_SIM_REQUEST_ID')==spec['request_id'],'JOB_OWNER_MISMATCH')
    output=Path(os.environ['ETX_SIM_OUTPUT_DIR'])
    check(output==Path(deployment_site()['remote']['queue_root'])/'jobs'/spec['request_id']/'output',
        'JOB_OUTPUT_REJECTED')
    output.mkdir(mode=0o700,exist_ok=True)
    result_path=output/'task-result.json'
    try:
        if spec['kind']=='selftest':
            result=selftest(spec['options'],output,spec['request_id'],spec['profile'])
        elif spec['kind']=='wave':
            sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'worker-runtime'))
            result=wave(config,spec['options'],output,spec['request_id'])
        elif spec['kind']=='wave_probe':
            result=wave(config,{},output,spec['request_id'],probe=True)
        else:
            raise RuntimeError('JOB_KIND_REJECTED')
        raw=canonical(result)
        check(len(raw)<=MAX_RESULT,'WAVE_RESULT_SIZE_LIMIT')
    except Exception as exc:
        # No stderr, environment or license strings cross the clipboard.
        error=str(exc) if re.fullmatch('[A-Z][A-Z0-9_]{1,100}',str(exc)) else type(exc).__name__
        result={'kind':spec['kind'],'request_id':spec['request_id'],'result':'FAIL','error':error}
        raw=canonical(result)
    temporary=result_path.with_suffix('.pending');temporary.write_bytes(raw);os.replace(temporary,result_path)
    print(json.dumps({'request_id':spec['request_id'],'result':result['result'],
        'bytes':len(raw),'sha256':digest(raw)}),flush=True)
    return 0 if result['result']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
