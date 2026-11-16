import copy
import sys
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'etx'))
from site_config import DEFAULT


def demo_site(install='/srv/test/etx-clipboard-bridge'):
    value=copy.deepcopy(DEFAULT)
    value['remote'].update(user='testuser',install_root=str(install),project_root='/srv/test/project',
        regression_root='/srv/test/results',queue_root='/srv/test/state/queue',lock_root='/srv/test/state/locks')
    value['permissions'].update(read_roots=['/srv/test/project','/srv/test/results'],write_roots=['/srv/test/project'])
    return value
