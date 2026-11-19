"""Owner-controlled deployment settings; contains paths and public policy, not keys."""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

ROOT=Path(__file__).resolve().parents[1]
_loaded=None
_loaded_path=None

DEFAULT={
    'version':1,
    'remote':{'user':'','install_root':'/replace-me/etx-clipboard-bridge','project_root':'/replace-me/project',
        'regression_root':'/replace-me/results','queue_root':'/replace-me/state/queue',
        'lock_root':'/replace-me/state/locks','python':'/usr/bin/python3',
        'eda_bin':'','lsf_queue':'syn','target':'sys_tb','simulator':'vcs',
        'environment_script':'','lsf_module':'','fsdb_name':'waves.fsdb','openssl':'openssl'},
    'permissions':{'read_roots':[],'write_roots':[],'wave_fsdbs':[]},
    'wave':{'enabled':False,'root':'','release':'','compatibility_patch':'none'},
    'monitor_interval_seconds':300,
}


def path_setting(value):
    if not isinstance(value,str) or not PurePosixPath(value).is_absolute() or \
            '..' in PurePosixPath(value).parts or value=='/' or '\x00' in value:
        raise ValueError('INVALID_DEPLOYMENT_PATH')
    return value


def validate(value):
    if not isinstance(value,dict) or set(value)!=set(DEFAULT) or value['version']!=1:
        raise ValueError('INVALID_SITE_CONFIGURATION')
    remote=value['remote'];permissions=value['permissions'];wave=value['wave']
    if set(remote)!=set(DEFAULT['remote']) or set(permissions)!=set(DEFAULT['permissions']) or set(wave)!=set(DEFAULT['wave']):
        raise ValueError('INVALID_SITE_FIELDS')
    if not isinstance(remote['user'],str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}',remote['user']):
        raise ValueError('INVALID_REMOTE_USER')
    for key in ('install_root','project_root','regression_root','queue_root','lock_root','python'):
        path_setting(remote[key])
        if '/replace-me/' in remote[key]:raise ValueError('CONFIGURATION_REQUIRED')
    for key in ('environment_script','eda_bin'):
        if remote[key]:path_setting(remote[key])
    for key in ('lsf_queue','target','simulator'):
        if not re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}',remote[key]):
            raise ValueError('INVALID_SIMULATOR_SETTING')
    if not re.fullmatch('[A-Za-z0-9_.-]+',remote['fsdb_name']) or not remote['fsdb_name'].endswith('.fsdb'):
        raise ValueError('INVALID_FSDB_NAME')
    for key in ('read_roots','write_roots','wave_fsdbs'):
        entries=permissions[key]
        if not isinstance(entries,list) or len(entries)>64 or len(set(entries))!=len(entries):
            raise ValueError('INVALID_PERMISSION_LIST')
        for entry in entries:path_setting(entry)
    if not permissions['read_roots']:raise ValueError('READ_ROOTS_REQUIRED')
    if any(not any(PurePosixPath(p).is_relative_to(PurePosixPath(r)) for r in permissions['read_roots'])
           for p in permissions['write_roots']):
        raise ValueError('WRITE_ROOT_NOT_READABLE')
    for p in permissions['wave_fsdbs']:
        if not p.endswith('.fsdb') or not PurePosixPath(p).is_relative_to(PurePosixPath(remote['regression_root'])):
            raise ValueError('INVALID_WAVEFORM_SCOPE')
    if type(wave['enabled']) is not bool:raise ValueError('INVALID_WAVE_CONFIGURATION')
    if wave['enabled']:
        path_setting(wave['root'])
        if not re.fullmatch('[0-9a-f]{64}',wave['release']):raise ValueError('WAVE_RELEASE_REQUIRED')
    elif permissions['wave_fsdbs']:
        raise ValueError('WAVE_BACKEND_DISABLED')
    if wave['compatibility_patch'] not in ('none','time-loop-v1'):
        raise ValueError('UNKNOWN_WAVE_COMPATIBILITY')
    if type(value['monitor_interval_seconds']) is not int or value['monitor_interval_seconds']<30:
        raise ValueError('INVALID_MONITOR_INTERVAL')
    return value


def configure(path=None):
    global _loaded,_loaded_path
    path=Path(path or os.environ.get('ETX_X11_SITE',ROOT/'.private/site.json')).absolute()
    if any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('SITE_SYMLINK_REJECTED')
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size>65536:
        raise ValueError('INVALID_SITE_FILE')
    if os.name=='posix' and (info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600):
        raise ValueError('SITE_PERMISSIONS_REJECTED')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('DUPLICATE_SITE_KEY')
            result[key]=value
        return result
    value=json.loads(path.read_bytes(),object_pairs_hook=unique)
    _loaded=validate(value);_loaded_path=path
    os.environ['ETX_X11_SITE']=str(path)
    return _loaded


def site(required=False):
    if _loaded is not None:return _loaded
    candidate=Path(os.environ.get('ETX_X11_SITE',ROOT/'.private/site.json'))
    if candidate.is_file():return configure(candidate)
    if required:raise ValueError('CONFIGURATION_REQUIRED')
    # Import-only defaults cannot start a service or authorize any file root.
    return copy.deepcopy(DEFAULT)


def release_files():
    value=json.loads((ROOT/'config/release.json').read_bytes())
    if value.get('version')!=1 or not isinstance(value.get('files'),dict):
        raise ValueError('INVALID_RELEASE_MANIFEST')
    return value['files']


def release_identity():
    raw = (ROOT / 'config/release.json').read_bytes()
    version = json.loads(raw).get('release')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('INVALID_RELEASE_MANIFEST')
    return {'version': version, 'manifest_sha256': sha256(raw).hexdigest()}


def native_output(case,seed,profile):
    remote=site()['remote']
    name='{target}__{simulator}__{case}__{seed}_{profile}'.format(
        target=remote['target'],simulator=remote['simulator'],case=case,seed=seed,profile=profile)
    return str(PurePosixPath(remote['regression_root'])/name)
