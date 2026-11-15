#!/usr/bin/env python3
"""One-time, per-user configuration. Private keys never enter a bootstrap bundle."""
import argparse
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import subprocess
import sys
import uuid
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'etx'))
from site_config import DEFAULT,validate,configure,release_files


def write(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.is_symlink():raise ValueError('SYMLINK_REJECTED')
    raw=value if isinstance(value,bytes) else json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2).encode()
    pending=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    try:
        fd=os.open(pending,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(pending,path)
    finally:pending.unlink(missing_ok=True)


def verify_release():
    for name,want in release_files().items():
        path=ROOT/name
        if '..' in Path(name).parts or path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=want:
            raise ValueError('RELEASE_FILE_CHANGED: '+name)


def crypto(tool,args):
    result=subprocess.run([tool,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,timeout=30)
    if result.returncode:raise RuntimeError('OPENSSL_OPERATION_FAILED')
    return result.stdout


def create_identity(folder,name,tool):
    folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    cert=folder/(name+'.pem');key=folder/(name+'-key.pem')
    if cert.exists()!=key.exists():raise ValueError('PARTIAL_IDENTITY_REQUIRES_REVIEW')
    if not cert.exists():
        crypto(tool,['req','-new','-x509','-newkey','rsa:3072','-nodes','-days','365',
            '-subj','/CN=dv-bridge-'+name,'-keyout',str(key),'-out',str(cert)])
    for p in (cert,key):
        if p.is_symlink():raise ValueError('IDENTITY_SYMLINK_REJECTED')
        os.chmod(p,0o600)
    return cert,key


def private_windows(folder):
    if os.name!='nt':return
    result=subprocess.run(['whoami.exe','/user','/fo','csv','/nh'],stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=10,check=True)
    match=re.search(rb'S-1-[0-9-]+',result.stdout)
    if not match:raise ValueError('WINDOWS_IDENTITY_UNAVAILABLE')
    sid=match.group().decode('ascii')
    result=subprocess.run(['icacls.exe',str(folder),'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F',
        '/grant:r','*S-1-5-18:(OI)(CI)F'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    if result.returncode:raise ValueError('PRIVATE_DIRECTORY_ACL_FAILED')


def prompt(value,label,default=None):
    if value is not None:return value
    suffix=' ['+default+']' if default else ''
    result=input(label+suffix+': ').strip()
    return result or default


def windows(args):
    if os.name!='nt':raise ValueError('WINDOWS_REQUIRED')
    private=ROOT/'.private';private.mkdir(mode=0o700,exist_ok=True);private_windows(private)
    site_path=private/'site.json'
    if (private/'x11/session/client.json').exists():
        raise ValueError('CONFIGURATION_EXISTS: use start.py for ordinary restarts')
    settings=copy.deepcopy(DEFAULT)
    if site_path.exists():settings=json.loads(site_path.read_bytes())
    elif args.site:settings=json.loads(Path(args.site).read_bytes())
    else:
        remote=settings['remote']
        remote['user']=prompt(args.user,'Linux account')
        remote['install_root']=prompt(args.install_root,'Linux installation path')
        remote['project_root']=prompt(args.project_root,'Linux project path')
        remote['regression_root']=prompt(args.regression_root,'Linux regression/log root')
        remote['python']=prompt(args.python,'Linux Python path','/usr/bin/python3')
        remote['queue_root']=str(PurePosixPath(remote['install_root'])/'.private/queue')
        remote['lock_root']=str(PurePosixPath(remote['install_root'])/'.private/locks')
        remote['environment_script']=prompt(args.environment_script,'Project environment script (empty to inherit)','')
        remote['lsf_module']=args.lsf_module or ''
        settings['permissions']['read_roots']=list(dict.fromkeys([remote['project_root'],remote['regression_root']]))
        settings['permissions']['write_roots']=[remote['project_root']]
    validate(settings);write(site_path,settings);configure(site_path)
    tool=args.openssl or shutil.which('openssl')
    if not tool:raise ValueError('OPENSSL_NOT_FOUND: supply --openssl')
    crypto(tool,['version'])
    cert,key=create_identity(private/'identity','signer',tool)
    session=private/'x11/session';session.mkdir(mode=0o700,parents=True,exist_ok=True)
    write(session/'client.json',{'version':1,'signer_cert':str(cert),'signer_key':str(key),
        'server_cert':str(session/'server-public.pem'),'connection_state':str(session/'connection.json'),
        'openssl':str(tool),'rpc_timeout_seconds':30})
    write(session/'xverif-transport.json',{'transport':'x11','project_root':str(ROOT),
        'install_root':settings['remote']['install_root']})
    bundle=private/'bootstrap/dv-bridge-setup.zip';bundle.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    # Only explicit public release files, public certificate and path settings.
    # No private directory traversal and no private key are ever included.
    with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as archive:
        for name in sorted([*release_files(),'config/release.json']):archive.write(ROOT/name,name)
        archive.writestr('bootstrap/site.json',json.dumps(settings,ensure_ascii=False,indent=2))
        archive.writestr('bootstrap/client-public.pem',cert.read_bytes())
    print(json.dumps({'state':'configured','bootstrap_bundle':str(bundle),
        'next':'Place this personal bootstrap bundle at the configured Linux installation path; run scripts/configure.py linux once.'}))


def linux(args):
    if os.name!='posix':raise ValueError('LINUX_REQUIRED')
    import pwd
    private=ROOT/'.private';private.mkdir(mode=0o700,exist_ok=True)
    site_path=private/'site.json'
    if (ROOT/'server-control-online.json').exists():
        raise ValueError('CONFIGURATION_EXISTS: use start.py endpoint; do not reinstall to restart')
    bootstrap=Path(args.bootstrap).absolute()
    settings=json.loads((bootstrap/'site.json').read_bytes());validate(settings)
    if settings['remote']['user']!=pwd.getpwuid(os.geteuid()).pw_name:raise ValueError('WRONG_LINUX_ACCOUNT')
    if Path(settings['remote']['install_root']).resolve()!=ROOT:raise ValueError('WRONG_INSTALLATION_DIRECTORY')
    write(site_path,settings);configure(site_path)
    public=(bootstrap/'client-public.pem').read_bytes()
    if len(public)>8192 or b'PRIVATE KEY' in public:raise ValueError('PUBLIC_CLIENT_CERTIFICATE_REQUIRED')
    queue=Path(settings['remote']['queue_root']);queue.mkdir(mode=0o700,parents=True,exist_ok=True)
    locks=Path(settings['remote']['lock_root']);locks.mkdir(mode=0o700,parents=True,exist_ok=True)
    if (queue/'command-signer.pem').exists() and (queue/'command-signer.pem').read_bytes()!=public:
        raise ValueError('QUEUE_BELONGS_TO_ANOTHER_IDENTITY')
    write(queue/'command-signer.pem',public)
    tool=shutil.which(settings['remote']['openssl'])
    if not tool:raise ValueError('OPENSSL_NOT_FOUND')
    crypto(tool,['x509','-in',str(queue/'command-signer.pem'),'-noout'])
    cert,key=create_identity(private/'identity','server',tool)
    state=private/'state';state.mkdir(mode=0o700,exist_ok=True)
    endpoint=uuid.uuid4().hex;activation=uuid.uuid4().hex
    permissions=settings['permissions'];wave=settings['wave']
    config={'version':1,'site_config':str(site_path),'transport_host':socket.gethostname().split('.')[0],
        'display':os.environ.get('DISPLAY',''),'state':str(state/'control'),
        'server_cert':str(cert),'server_key':str(key),'trusted_client_cert':str(queue/'command-signer.pem'),
        'client_recipient_cert':str(queue/'command-signer.pem'),
        'allowed_roots':permissions['read_roots'],'write_roots':permissions['write_roots'],
        'enable_writes':bool(permissions['write_roots']),'enable_workers':True,
        'session_seconds':3600,'initial_handshake_timeout_seconds':0,'rg_path':shutil.which('rg'),
        'openssl':tool,'profile':'execution-online-v1','persistent_endpoint':True,'endpoint_id':endpoint,
        'worker_module':str(ROOT/'worker-runtime/sim_control.py'),
        'worker_module_sha256':release_files()['worker-runtime/sim_control.py'],
        'executor_profiles':['work01','work02','work03','work04','work05'],
        'wave_enabled':wave['enabled'],'wave_root':wave['root'],'wave_release':wave['release'],
        'wave_fsdbs':permissions['wave_fsdbs'],'activation_task_id':activation,
        'activation_file':str(state/'activation.json')}
    write(state/'activation.json',{'task_id':activation,'endpoint_id':endpoint,'commit':True})
    write(ROOT/'server-control-online.json',config)
    fingerprint=hashlib.sha256(crypto(tool,['x509','-in',str(cert),'-outform','DER'])).hexdigest()
    print('SERVER_FINGERPRINT='+fingerprint)
    print('Configured. In this graphical ETX terminal run: python3 scripts/start.py endpoint')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='side',required=True)
    win=commands.add_parser('windows')
    for name in ('site','user','install-root','project-root','regression-root','python','openssl','environment-script','lsf-module'):
        win.add_argument('--'+name)
    lin=commands.add_parser('linux');lin.add_argument('--bootstrap',default=str(ROOT/'bootstrap'))
    args=parser.parse_args();os.umask(0o077);verify_release()
    windows(args) if args.side=='windows' else linux(args)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('CONFIGURATION_FAILED: '+str(error),file=sys.stderr)
        raise SystemExit(1)
