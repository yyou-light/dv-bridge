#!/usr/bin/env python3
"""Short restart entries for an existing graphical ETX and foreground Workers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'etx'),str(ROOT/'clients')]
from site_config import site,configure,release_identity
from configure import verify_release,write


def endpoint(reload=False):
    if os.name!='posix' or not os.environ.get('DISPLAY'):raise ValueError('USE_AN_EXISTING_GRAPHICAL_ETX_TERMINAL')
    from session_runner_pause import identity,same_process
    from session_files import Files,file_lock
    from session_agent import endpoint_status_directory
    path=ROOT/'server-control-online.json';before=path.read_bytes();config=json.loads(before)
    host=socket.gethostname().split('.')[0];display=os.environ['DISPLAY']
    status=endpoint_status_directory(config)
    with file_lock(ROOT/'.private/state/restart.lock',timeout=2):
        for name in ('supervisor','receiver'):
            report=status/(name+'.json')
            saved=Files.meta(report) if report.exists() else {}
            process=saved.get('process_identity') or {}
            stamp=saved.get('heartbeat_at',saved.get('updated_at',0))
            if process.get('host') not in (None,host) and 0<=time.time()-stamp<30:
                raise ValueError('ENDPOINT_ACTIVE_ON_OTHER_HOST')
        changed=config['display']!=display or config['transport_host']!=host
        if changed:
            for name,operation in (('supervisor','maintain-files'),('receiver','serve')):
                report=status/(name+'.json')
                saved=Files.meta(report).get('process_identity') if report.exists() else None
                if not saved:continue
                if saved.get('host')!=host:
                    stamp=Files.meta(report).get('heartbeat_at',Files.meta(report).get('updated_at',0))
                    if 0<=time.time()-stamp<30:raise ValueError('ENDPOINT_ACTIVE_ON_OTHER_HOST')
                    continue
                if not same_process(saved,identity(saved['pid'])):continue
                argv=(Path('/proc')/str(saved['pid'])/'cmdline').read_bytes().split(b'\0')
                if str(ROOT/'etx/session_agent.py').encode() not in argv or operation.encode() not in argv or str(path).encode() not in argv:
                    raise ValueError('ENDPOINT_PROCESS_CHANGED')
                try:os.kill(saved['pid'],signal.SIGTERM)
                except ProcessLookupError:pass
                deadline=time.monotonic()+45
                while same_process(saved,identity(saved['pid'])) and time.monotonic()<deadline:time.sleep(0.2)
                if same_process(saved,identity(saved['pid'])):raise ValueError('ENDPOINT_STILL_STOPPING')
            backup=ROOT/'.private/state/config-backups'/uuid.uuid4().hex/'server-control-online.json'
            write(backup,before)
            config.update(transport_host=host,display=display)
            if path.read_bytes()!=before:raise ValueError('CONFIGURATION_CHANGED')
            write(path,config)
            print(json.dumps({'backup':str(backup),'before_sha256':hashlib.sha256(before).hexdigest(),
                'after_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}),flush=True)
        command=[sys.executable,'-B',str(ROOT/'etx/session_agent.py'),
            'start-control','--config',str(path)]
        if reload:command.append('--reload')
        result=subprocess.run(command,timeout=45)
        return result.returncode


def worker(profile):
    if os.name!='posix':raise ValueError('LINUX_REQUIRED')
    settings=site(required=True)['remote']
    os.execv('/bin/bash',['bash',str(ROOT/'scripts/worker-env.sh'),settings['project_root'],
        settings['environment_script'],settings['lsf_module'],settings['python'],
        str(ROOT/'worker-runtime/sim_control.py'),profile])


def verify():
    from etx_cli import Project

    local_release = release_identity()
    result = Project(ROOT, uuid.uuid4().hex).rpc('hello', {}, 'verify-release')
    remote_release = (result.get('endpoint') or {}).get('release')
    matched = local_release == remote_release
    print(json.dumps({'state': 'verified' if matched else 'upgrade_incomplete',
        'windows_release': local_release, 'etx_release': remote_release}))
    return 0 if matched else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    start=commands.add_parser('endpoint')
    start.add_argument('--reload',action='store_true',help='reload an active receiver from an older release')
    run=commands.add_parser('worker');run.add_argument('profile',choices=['work01','work02','work03','work04','work05'])
    pair=commands.add_parser('pair');pair.add_argument('fingerprint')
    commands.add_parser('verify',help='compare the Windows release with the paired ETX receiver')
    args=parser.parse_args();os.umask(0o077);verify_release();configure()
    if args.command=='endpoint':return endpoint(args.reload)
    if args.command=='worker':return worker(args.profile)
    if args.command=='verify':return verify()
    from etx_cli import Project
    value=Project(ROOT,uuid.uuid4().hex).pair(args.fingerprint)
    print(json.dumps({'paired':True,'endpoint':value.get('endpoint')}))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print('START_FAILED: '+str(error),file=sys.stderr)
        raise SystemExit(1)
