"""Process identity and a read-only Runner/X11 interlock; no Runner administration."""
import os
from pathlib import Path
import socket


def identity(pid):
    root=Path('/proc')/str(pid)
    try:
        if root.stat().st_uid!=os.geteuid():return None
        raw=(root/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
        return {'pid':pid,'start':fields[19],'exe':os.readlink(root/'exe'),
            'cwd':os.readlink(root/'cwd'),'state':fields[0],
            'host':socket.gethostname().split('.')[0],
            'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    except (FileNotFoundError,ProcessLookupError):return None


def same_process(previous,current):
    return current is not None and all(previous.get(k)==current.get(k)
        for k in ('pid','start','exe','cwd','host','boot'))


def inventory():
    listeners=[];workers=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:
            if entry.stat().st_uid!=os.geteuid():continue
            name=(entry/'comm').read_text().strip()
            if name=='Runner.Worker':workers.append(int(entry.name))
            elif name=='Runner.Listener':listeners.append(identity(int(entry.name)))
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
    return [x for x in listeners if x is not None],workers


class RunnerPause:
    def __init__(self,*args,**kwargs):
        raise RuntimeError('RUNNER_ADMINISTRATION_NOT_INCLUDED')
