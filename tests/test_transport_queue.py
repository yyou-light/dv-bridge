"""Real Windows process contention with inert delegates and isolated mutex names."""
import json
import os
from pathlib import Path
import subprocess
import time
import unittest

import test_session_client as fixtures


@unittest.skipUnless(os.name == 'nt', 'Windows consumer queue')
class QueueTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.LauncherTests('test_five_children_reuse_one_powershell_process')
        self.f.setUp()
        self.addCleanup(self.f.tearDown)
        self.processes = []
        self.addCleanup(self.stop_processes)
        self.ps = fixtures.client.POWERSHELL
        self.core = self.f.flags/'local/windows_etx_packet.ps1'
        fake = r'''param($Mode,$SessionConfig,$SessionRequest,$OutputPath,$Fingerprint)
$folder=Split-Path $PSScriptRoot -Parent
$spec=if ($SessionRequest) {Get-Content -LiteralPath $SessionRequest -Raw | ConvertFrom-Json} else {@{id='pair'}}
if (Test-Path -LiteralPath (Join-Path $folder 'exit-without-receipt')) { exit 1 }
$busy=Join-Path $folder 'busy-once'
if (Test-Path -LiteralPath $busy) {
    Remove-Item -LiteralPath $busy
    [IO.File]::WriteAllText($OutputPath,'{"ok":false,"error":"CLIPBOARD_BUSY","phase":"packet_mutex"}')
    exit 1
}
$packet=[Threading.Mutex]::new($false,'PACKET_NAME')
if (-not $packet.WaitOne(0)) {
    [IO.File]::WriteAllText($OutputPath,'{"ok":false,"error":"CLIPBOARD_BUSY","phase":"packet_mutex"}')
    $packet.Dispose();exit 1
}
try {
    $log=Join-Path $folder 'invocations.jsonl'
    [IO.File]::AppendAllText($log,((@{id=$spec.id;event='start';pid=$PID}|ConvertTo-Json -Compress)+"`n"))
    Start-Sleep -Milliseconds 350
    $failed=Test-Path -LiteralPath (Join-Path $folder 'fail-after-start')
    $count=if (Test-Path -LiteralPath (Join-Path $folder 'interrupted')) {1} else {0}
    $reply=if ($failed) {@{ok=$false;error='CLIPBOARD_OPEN_BUSY';phase='exchange'}} else {
        @{ok=$true;result=@{state='exited'};interruption_count=$count}}
    [IO.File]::WriteAllText($OutputPath,($reply|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
    [IO.File]::AppendAllText($log,((@{id=$spec.id;event='end';pid=$PID}|ConvertTo-Json -Compress)+"`n"))
}
finally {$packet.ReleaseMutex();$packet.Dispose()}
if ($failed) {exit 1}
exit 0
'''
        self.core.write_text(fake.replace('PACKET_NAME', self.f.packet_name), encoding='utf-8')

    def stop_processes(self):
        for p in self.processes:
            if p.poll() is None:
                p.kill()
            p.communicate(timeout=10)

    def launch(self, request=None, mode='SessionRpc', output='result.json', timeout=12):
        cmd = [self.ps, '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', str(self.f.wrapper),
            '-Mode', mode, '-SessionConfig', str(self.f.config), '-SessionOutputName', self.f.group+'/'+output,
            '-QueueWaitTimeoutSeconds', str(timeout)]
        if mode == 'SessionPair':
            cmd += ['-Fingerprint', 'a'*64]
        else:
            cmd += ['-SessionRequest', str(request or self.f.batch)]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(p)
        return p

    def finish(self, p, expected=0):
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, expected, (out+err).decode(errors='replace'))
        return out.decode(errors='replace')

    def holder(self, mutex_name):
        assert mutex_name.startswith(('Local\\ETX_Queue_Test_', 'Local\\ETX_Packet_Test_'))
        n = str(len(self.processes))
        ready, release = self.f.root/('ready-'+n), self.f.root/('release-'+n)
        script = self.f.root/('holder-'+n+'.ps1')
        script.write_text(r'''param($Name,$Ready,$Release)
$m=[Threading.Mutex]::new($false,$Name)
$null=$m.WaitOne()
try {
    [IO.File]::WriteAllText($Ready,'ready')
    while (-not (Test-Path -LiteralPath $Release)) {Start-Sleep -Milliseconds 20}
}
finally {$m.ReleaseMutex();$m.Dispose()}
''', encoding='utf-8')
        p = subprocess.Popen([self.ps, '-NoProfile', '-File', str(script), '-Name', mutex_name,
            '-Ready', str(ready), '-Release', str(release)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(p)
        deadline = time.monotonic()+8
        while not ready.exists():
            if p.poll() is not None or time.monotonic() > deadline:
                self.fail('Synthetic holder did not become ready')
            time.sleep(.02)
        return p, release

    def wait_phase(self, name, phase):
        p = self.f.output/(name+'.queue.json')
        deadline = time.monotonic()+8
        while time.monotonic() < deadline:
            try:
                value=json.loads(p.read_bytes())
                if value['phase'] == phase:
                    return value
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(.03)
        self.fail('Queue phase did not appear: '+phase)

    def events(self):
        return self.f.invocations()

    def test_five_processes_serialize_without_busy(self):
        refs = self.f.manifest(5)
        jobs = [self.launch(Path(r['request_file']), output=r['id']+'.json') for r in refs]
        for p in jobs:
            self.finish(p)
        events = self.events()
        self.assertEqual([e['event'] for e in events], ['start','end']*5)
        self.assertEqual({e['id'] for e in events}, {r['id'] for r in refs})
        for r in refs:
            self.assertTrue(json.loads((self.f.output/(r['id']+'.json')).read_bytes())['ok'])

    def test_old_inflight_packet_is_allowed_to_finish(self):
        refs = self.f.manifest(1)
        old, release = self.holder(self.f.packet_name)
        p = self.launch(Path(refs[0]['request_file']))
        state = self.wait_phase('result.json', 'waiting_active_transfer')
        self.assertTrue(state['not_sent'])
        self.assertEqual(self.events(), [])
        release.touch();self.finish(old)
        self.finish(p)
        self.assertEqual(len(self.events()), 2)

    def test_queue_timeout_keeps_batch_not_started_and_same_id_can_resume(self):
        self.f.manifest(1, True)
        old, release = self.holder(self.f.packet_name)
        out = self.finish(self.launch(mode='SessionRpcBatch', output='aggregate.json', timeout=1), 2)
        self.assertIn('ETX_QUEUE_WAIT_TIMEOUT', out)
        aggregate = self.f.aggregate()
        self.assertEqual(aggregate['items'][0]['state'], 'not_started')
        self.assertEqual(self.events(), [])
        release.touch();self.finish(old)
        self.finish(self.launch(mode='SessionRpcBatch', output='aggregate.json'))
        self.assertEqual(self.f.aggregate()['items'][0]['state'], 'complete')
        self.assertEqual(len(self.events()), 2)

    def test_proven_presend_busy_retries_same_request_only(self):
        refs = self.f.manifest(1, True)
        (self.f.flags/'busy-once').touch()
        self.finish(self.launch(mode='SessionRpcBatch', output='aggregate.json'))
        self.assertEqual(self.f.aggregate()['items'][0]['state'], 'complete')
        self.assertEqual([e['id'] for e in self.events() if e['event']=='start'], [refs[0]['id']])
        state = json.loads((self.f.output/(refs[0]['id']+'.json.queue.json')).read_bytes())
        self.assertEqual(state['not_sent_retries'], 1)

    def test_postsend_error_stays_uncertain_without_automatic_redispatch(self):
        self.f.manifest(1, True)
        (self.f.flags/'fail-after-start').touch()
        self.finish(self.launch(mode='SessionRpcBatch', output='aggregate.json'), 2)
        self.assertEqual(self.f.aggregate()['items'][0]['state'], 'uncertain')
        self.finish(self.launch(mode='SessionRpcBatch', output='aggregate.json'), 2)
        self.assertEqual(len(self.events()), 2)

    def test_stale_presend_busy_receipt_never_proves_a_new_attempt_was_not_sent(self):
        self.f.manifest(1, True)
        rid = json.loads(self.f.batch.read_bytes())['requests'][0]['id']
        old = b'{"ok":false,"error":"CLIPBOARD_BUSY","phase":"packet_mutex"}'
        (self.f.output/(rid+'.json')).write_bytes(old)
        (self.f.flags/'exit-without-receipt').touch()
        self.finish(self.launch(mode='SessionRpcBatch', output='aggregate.json'), 2)
        self.assertEqual(self.f.aggregate()['items'][0]['state'], 'uncertain')
        state = json.loads((self.f.output/(rid+'.json.queue.json')).read_bytes())
        self.assertEqual(state['not_sent_retries'], 0)
        self.assertEqual((self.f.output/(rid+'.json')).read_bytes(), old)

