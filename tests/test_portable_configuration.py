"""New-account setup contracts. No ETX connection or EDA simulation."""
import argparse
import copy
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

BASE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(BASE/'etx'),str(BASE/'clients'),str(BASE/'scripts')]
import site_config
from helpers import demo_site
from etx_cli import Project,Failure
from configure import create_identity

TEST_TEMP=Path.cwd()/'.work/test-dv-bridge'
TEST_TEMP.mkdir(parents=True,exist_ok=True)


def openssl_path():
    return next((str(p) for p in [shutil.which('openssl'),
        'C:/Program Files/Git/mingw64/bin/openssl.exe','C:/Program Files/Git/usr/bin/openssl.exe']
        if p and Path(p).is_file()),None)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.old=site_config._loaded;self.old_path=site_config._loaded_path
        self.env=os.environ.get('ETX_X11_SITE')

    def tearDown(self):
        site_config._loaded=self.old;site_config._loaded_path=self.old_path
        if self.env is None:os.environ.pop('ETX_X11_SITE',None)
        else:os.environ['ETX_X11_SITE']=self.env

    def test_settings_require_an_explicit_user_and_scope(self):
        site_config.validate(demo_site())
        for change in ('user','root','scope','interval'):
            value=demo_site()
            if change=='user':value['remote']['user']=''
            elif change=='root':value['remote']['queue_root']='/'
            elif change=='scope':value['permissions']['write_roots']=['/outside']
            else:value['monitor_interval_seconds']=0
            with self.assertRaises(ValueError):site_config.validate(value)

    def test_default_monitoring_interval_is_five_minutes(self):
        self.assertEqual(demo_site()['monitor_interval_seconds'],300)

    def test_waveforms_are_exact_and_optional(self):
        value=demo_site();site_config.validate(value)
        value['permissions']['wave_fsdbs']=['/srv/test/results/demo/waves.fsdb']
        with self.assertRaisesRegex(ValueError,'WAVE_BACKEND_DISABLED'):site_config.validate(value)
        value['wave'].update(enabled=True,root='/srv/test/backend',release='a'*64)
        site_config.validate(value)
        value['permissions']['wave_fsdbs']=['/other/waves.fsdb']
        with self.assertRaisesRegex(ValueError,'INVALID_WAVEFORM_SCOPE'):site_config.validate(value)

    def test_configuration_is_owned_private_and_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            path=Path(tmp)/'site.json';path.write_text(json.dumps(demo_site()))
            os.chmod(path,0o600)
            self.assertEqual(site_config.configure(path)['remote']['user'],'testuser')
            path.write_text('{"version":1,"version":1}')
            with self.assertRaisesRegex(ValueError,'DUPLICATE_SITE_KEY'):site_config.configure(path)

    def test_fsdb_is_not_downloaded_through_file_interface(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            project=Project(tmp,'a'*32)
            project.rpc=lambda *args: self.fail('Unsupported file must be rejected before transport')
            with self.assertRaisesRegex(Failure,'UNSUPPORTED_FILE_TYPE'):
                project.read('/srv/test/results/demo/waves.fsdb','waves.fsdb')

    def test_text_size_is_checked_before_chunks(self):
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as tmp:
            project=Project(tmp,'a'*32)
            project.rpc=lambda *args:{'path':'/srv/test/project/demo.sv','bytes':524289,'sha256':'0'*64}
            with self.assertRaisesRegex(Failure,'BAD_DOWNLOAD_METADATA'):
                project.read('/srv/test/project/demo.sv','demo.sv')

    def test_output_paths_and_fixed_arguments_use_configuration(self):
        value=demo_site();value['remote'].update(target='demo_tb',simulator='demo_sim')
        site_config._loaded=value
        self.assertEqual(site_config.native_output('demo_case',7,'work02'),
            '/srv/test/results/demo_tb__demo_sim__demo_case__7_work02')
        spec=importlib.util.spec_from_file_location('portable_runtime',BASE/'worker-runtime/sim_control.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        argv=module.simmer_argv('demo_case',7,'work02')
        self.assertEqual(argv[0],value['remote']['python'])
        packet=json.dumps({'request_id':'1'*32,'worker_id':'2'*32,'profile':'work02','argv':argv},separators=(',',':')).encode()
        self.assertLessEqual(len(packet),module.MAX_COMMAND_BYTES)


class SetupSmokeTests(unittest.TestCase):
    def setUp(self):
        self.tool=openssl_path()
        if not self.tool:self.skipTest('OpenSSL is not installed')
        self.temp=tempfile.TemporaryDirectory(dir=TEST_TEMP)
        self.root=Path(self.temp.name)/'clone';self.root.mkdir()
        manifest=json.loads((BASE/'config/release.json').read_bytes())
        for name in [*manifest['files'],'config/release.json']:
            target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(BASE/name,target)

    def tearDown(self):
        if hasattr(self,'temp'):self.temp.cleanup()

    def test_fresh_windows_setup_exports_only_public_bootstrap_material(self):
        if os.name!='nt':self.skipTest('Windows setup')
        settings=demo_site()
        settings_path=Path(self.temp.name)/'settings.json';settings_path.write_text(json.dumps(settings))
        run=subprocess.run([sys.executable,str(self.root/'scripts/configure.py'),'windows',
            '--site',str(settings_path),'--openssl',self.tool],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace'))
        private=self.root/'.private'
        self.assertTrue((private/'identity/signer-key.pem').is_file())
        import zipfile
        with zipfile.ZipFile(private/'bootstrap/dv-bridge-setup.zip') as archive:
            names=set(archive.namelist())
            expected=set(json.loads((self.root/'config/release.json').read_bytes())['files'])
            self.assertEqual(names,expected|{'config/release.json','bootstrap/site.json','bootstrap/client-public.pem'})
            self.assertFalse(any(name.endswith('-key.pem') for name in names))
            self.assertNotIn(b'PRIVATE KEY',archive.read('bootstrap/client-public.pem'))

    def test_fresh_linux_setup_keeps_identity_scope_and_does_not_start_processes(self):
        if os.name!='posix':self.skipTest('Native Linux ownership/permission check')
        settings=demo_site(self.root)
        settings['remote'].update(user=getpass.getuser(),python=sys.executable,
            queue_root=str(self.root/'.private/queue'),lock_root=str(self.root/'.private/locks'),openssl=self.tool)
        bootstrap=self.root/'bootstrap';bootstrap.mkdir()
        (bootstrap/'site.json').write_text(json.dumps(settings))
        cert,key=create_identity(Path(self.temp.name)/'client','signer',self.tool)
        shutil.copyfile(cert,bootstrap/'client-public.pem')
        run=subprocess.run([sys.executable,str(self.root/'scripts/configure.py'),'linux'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
        self.assertEqual(run.returncode,0,run.stderr.decode(errors='replace'))
        config=json.loads((self.root/'server-control-online.json').read_bytes())
        self.assertEqual(config['allowed_roots'],settings['permissions']['read_roots'])
        self.assertEqual(config['wave_fsdbs'],[])
        self.assertEqual((self.root/'.private/identity/server-key.pem').stat().st_mode & 0o777,0o600)
        self.assertFalse((self.root/'.private/state/control-status/receiver.json').exists())
        self.assertIn('SERVER_FINGERPRINT=',run.stdout.decode())


if __name__=='__main__':unittest.main(verbosity=2)
