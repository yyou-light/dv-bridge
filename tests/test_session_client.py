"""Client/launcher regressions using an inert canonical delegate, never ETX."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
TEST_TEMP=Path.cwd()/'.work/test-etx-clipboard-bridge'
TEST_TEMP.mkdir(parents=True,exist_ok=True)
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('session_client_under_test',HERE.parent/'clients/etx_cli.py')
client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
TEST_TEMP=Path.cwd()/'.work'/'test-x11'
TEST_TEMP.mkdir(parents=True,exist_ok=True)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEST_TEMP)
        self.root=Path(self.temp.name)
        self.project=client.Project(self.root,'a'*32)

    def tearDown(self): self.temp.cleanup()

    def fake_transport(self,command,tamper=False):
        self.project.transport_samples.append({'outer_seconds':0.1})
        manifest=Path(command[command.index('-SessionRequest')+1])
        source=client.read_json(manifest);items=[]
        for entry in source['requests']:
            request=client.read_json(entry['request_file'])
            target=self.project.result/(entry['id']+'.json')
            raw=client.json_bytes({'ok':True,'result':{'state':'exited'}})
            target.write_bytes(raw)
            items.append({'id':entry['id'],'op':request['op'],'state':'complete',
                'output_name':entry['output_name'],'receipt_sha256':client.sha(raw)})
        aggregate=self.project.result/Path(command[command.index('-SessionOutputName')+1]).name
        client.save(aggregate,{'ok':True,'manifest_sha256':client.sha(manifest.read_bytes()),'items':items})
        if tamper: target.write_bytes(b'{}')
        return subprocess.CompletedProcess(command,0,b'',b'')

    def test_batch_stable_ids_and_immutable_requests(self):
        self.project.transport=self.fake_transport
        calls=[{'op':'workers','args':{}},{'op':'status','args':{'request_id':'b'*32}}]
        first=self.project.rpc_batch(calls)
        second=self.project.rpc_batch(calls)
        self.assertEqual([i['id'] for i in first['items']],[i['id'] for i in second['items']])
        with self.assertRaisesRegex(client.Failure,'LOCAL_REQUEST_CONFLICT'):
            self.project.rpc_batch([{'op':'status','args':{}},calls[1]])

    def test_bounds_and_non_worker_operations_rejected(self):
        for calls in ([],[{'op':'workers','args':{}}]*6,[{'op':'close','args':{}}]):
            with self.assertRaises(client.Failure): self.project.rpc_batch(calls)

    def test_duplicate_profiles_rejected_before_transport(self):
        calls=[{'op':'submit_simmer','args':{'profile':'work01'}}]*2
        with self.assertRaisesRegex(client.Failure,'BATCH_DUPLICATE_PROFILE'):
            self.project.rpc_batch(calls)

    def test_modified_receipt_rejected(self):
        self.project.transport=lambda command:self.fake_transport(command,tamper=True)
        with self.assertRaisesRegex(client.Failure,'BATCH_RECEIPT_HASH_MISMATCH'):
            self.project.rpc_batch([{'op':'workers','args':{}}])

    def test_existing_sealed_submission_is_reused(self):
        arguments={'request_id':'a'*32,'command_box':'sealed-once'}
        client.save(self.project.requests/'simulation.json',{'specification':{
            'case':'case','seed':1,'profile':'work01','worker_id':None},'arguments':arguments})
        self.assertEqual(self.project.prepare_submit('case',1,'work01'),arguments)
        with self.assertRaisesRegex(client.Failure,'LOCAL_REQUEST_CONFLICT'):
            self.project.prepare_submit('changed_case',1,'work01')

    def test_native_log_verifies_all_fragments_before_publishing(self):
        import base64
        remote='/srv/test/results/demo_tb__vcs__demo_case__1_cov/stdout.log'
        data=b'%E- synthetic failure\n'
        value={'path':remote,'mode':'errors','identity':[1,2,len(data),3],
            'observed_file_bytes':len(data),'bytes':len(data),'fragments':[{
                'kind':'first_error','offset':0,'bytes':len(data),'line':1,
                'sha256':client.sha(data),'data':base64.b64encode(data).decode()}]}
        self.project.rpc=lambda op,args,name=None:{'native_log_enabled':True} if op=='hello' else value
        value['fragments'][0]['sha256']='0'*64
        with self.assertRaisesRegex(client.Failure,'NATIVE_LOG_HASH_MISMATCH'):
            self.project.native_log(remote)
        self.assertEqual(list(self.project.result.iterdir()),[])
        value['fragments'][0]['sha256']=client.sha(data)
        result=self.project.native_log(remote)
        self.assertEqual(Path(result['fragments'][0]['local']).read_bytes(),data)
        self.assertTrue((self.project.result/'native-log.source.json').exists())
        value['identity']=[1,2,len(data),4]
        with self.assertRaisesRegex(client.Failure,'LOG_CHANGED'):self.project.native_log(remote)


    def test_old_endpoint_rejects_large_text_upgrade_before_any_upload(self):
        source=self.root/'.private/x11/source.txt';source.parent.mkdir(parents=True,exist_ok=True)
        source.write_bytes(b'x'*524289)
        manifest=source.parent/'upload.json'
        client.save(manifest,{'files':[{'source':str(source),'target':'/srv/test/project/target.txt',
            'expected_before_sha256':'absent'}]})
        calls=[]
        self.project.rpc=lambda op,args,name=None:calls.append(op) or {}
        with self.assertRaisesRegex(client.Failure,'LARGE_TEXT_ENDPOINT_UPGRADE_REQUIRED'):
            self.project.upload(manifest)
        self.assertEqual(calls,['hello'])

    def test_small_text_upload_stays_compatible_with_old_endpoint(self):
        source=self.root/'.private/x11/source.txt';source.parent.mkdir(parents=True,exist_ok=True)
        raw=b'ordinary text\n';source.write_bytes(raw)
        manifest=source.parent/'upload.json'
        client.save(manifest,{'files':[{'source':str(source),'target':'/srv/test/project/file.txt',
            'expected_before_sha256':'absent'}]})
        calls=[]
        def rpc(op,args,name=None):
            calls.append(op)
            if op=='hello':return {}
            if op=='upload_begin':
                self.assertNotIn('text_only',args)
                return {'received':0}
            if op=='upload_status':return {'received':0,'prefix_sha256':client.sha(b'')}
            if op=='upload_chunk':return {'received':len(raw),'prefix_sha256':client.sha(raw)}
            if op=='commit':return {'state':'committed','files':[]}
            self.fail(op)
        self.project.rpc=rpc
        self.assertEqual(self.project.upload(manifest)['state'],'committed')
        self.assertEqual(calls,['hello','upload_begin','upload_status','upload_chunk','commit'])


    def test_task_payload_hash_checked_before_returning_results(self):
        payload={'result':'PASS'};raw=client.json_bytes(payload)
        result={'ready':True,'payload':payload,'bytes':len(raw),'sha256':client.sha(raw)}
        self.project.rpc_batch=lambda *args:{'ok':True,'items':[{'ok':True,'result':result}]}
        self.assertTrue(self.project.results_many(['b'*32])['ok'])
        result['payload']={'result':'changed'}
        with self.assertRaisesRegex(client.Failure,'TASK_RESULT_HASH_MISMATCH'):
            self.project.results_many(['b'*32])

    def test_status_many_validates_ids_and_uses_existing_rpc(self):
        observed=[]
        self.project.rpc=lambda op,args:observed.append((op,args)) or {'jobs':[]}
        self.project.status_many(['b'*32,'c'*32])
        self.assertEqual(observed,[('status_many',{'request_ids':['b'*32,'c'*32]})])
        with self.assertRaises(client.Failure): self.project.status_many(['b'*32]*2)

    def test_submit_many_prepares_once_and_fixes_child_ids(self):
        jobs=[{'case':'case','seed':0,'profile':'work01'},
              {'case':'case','seed':1,'profile':'work02'}]
        snapshots=[];original=client.Project.prepare_submit
        def prepare(child,case,seed,profile,worker_id,workers):
            client.save(child.requests/'simulation.json',{})
            return {'request_id':child.operation_id,'profile':profile}
        self.project.rpc=lambda op,args:snapshots.append(op) or {'workers':[]}
        self.project.rpc_batch=lambda specs,name:{'ok':True,'items':[{'id':s['id']} for s in specs]}
        client.Project.prepare_submit=prepare
        try:
            first=self.project.submit_many(jobs)
            second=self.project.submit_many(jobs)
        finally: client.Project.prepare_submit=original
        self.assertEqual(first,second)
        self.assertEqual(snapshots,['workers'])
        self.assertEqual(len({i['request_id'] for i in first['items']}),2)


@unittest.skipUnless(os.name=='nt','Windows launcher regression')
class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEST_TEMP)
        self.root=Path(self.temp.name)
        self.group='a'*32
        self.private=self.root/'.private/x11/session'
        self.requests=self.private/'requests'/self.group
        self.requests.mkdir(parents=True)
        self.config=self.private/'client.json';self.config.write_text('{}')
        self.output=self.root/'.work/x11/session'/self.group
        self.output.mkdir(parents=True)
        tools=self.root/'tools';tools.mkdir()
        canonical=self.root/'canonical';(canonical/'local').mkdir(parents=True)
        self.log=canonical/'invocations.jsonl'
        self.flags=canonical
        fake=r'''param($Mode,$SessionConfig,$SessionRequest,$OutputPath,$Fingerprint)
$spec=Get-Content -LiteralPath $SessionRequest -Raw | ConvertFrom-Json
$folder=Split-Path $PSScriptRoot -Parent
[IO.File]::AppendAllText((Join-Path $folder 'invocations.jsonl'),
    ((@{id=$spec.id;pid=$PID} | ConvertTo-Json -Compress)+[Environment]::NewLine))
$flag=Join-Path $folder ('fail-'+$spec.id)
if (Test-Path -LiteralPath $flag) { Remove-Item -LiteralPath $flag; exit 1 }
$reply=@{ok=$true;result=@{delegate_pid=$PID;state='exited'}} | ConvertTo-Json -Depth 10 -Compress
[IO.File]::WriteAllText($OutputPath,$reply,[Text.UTF8Encoding]::new($false))
Write-Output '{"ok":true}'
exit 0
'''
        (canonical/'local/windows_etx_packet.ps1').write_text(fake,encoding='utf-8')
        wrapper=(HERE.parent/'clients/Invoke-EtxX11.ps1').read_text(encoding='utf-8')
        wrapper=wrapper.replace("$canonicalRoot = $projectRoot",
            "$canonicalRoot = '"+str(canonical).replace("'","''")+"'")
        self.wrapper=tools/'Invoke-EtxX11.ps1';self.wrapper.write_text(wrapper,encoding='utf-8')

    def tearDown(self): self.temp.cleanup()

    def manifest(self,count=3,mutating=False):
        references=[]
        for index in range(count):
            rid=f'{index+1:032x}'
            request={'id':rid,'op':'submit_simmer' if mutating else 'workers',
                'args':{'profile':'work0'+str(index+1),'request_id':rid} if mutating else {}}
            path=self.requests/(rid+'.json');raw=client.json_bytes(request);path.write_bytes(raw)
            references.append({'id':rid,'request_file':str(path),'request_sha256':client.sha(raw),
                'output_name':self.group+'/'+rid+'.json'})
        self.batch=self.requests/'batch.json'
        client.save(self.batch,{'version':1,'requests':references})
        return references

    def run_wrapper(self,mode='SessionRpcBatch',apartment='STA',request=None,no_profile=True):
        command=[client.POWERSHELL,*(['-NoProfile'] if no_profile else []),'-'+apartment,'-ExecutionPolicy','Bypass',
            '-File',str(self.wrapper),'-Mode',mode,'-SessionConfig',str(self.config),
            '-SessionRequest',str(request or self.batch),'-SessionOutputName',self.group+'/aggregate.json']
        return subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)

    def invocations(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def aggregate(self): return client.read_json(self.output/'aggregate.json')

    def test_five_children_reuse_one_powershell_process(self):
        self.manifest(5)
        result=self.run_wrapper()
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertEqual(len(self.invocations()),5)
        self.assertEqual(len({v['pid'] for v in self.invocations()}),1)
        self.assertTrue(self.aggregate()['ok'])

    def test_sta_direct_and_mta_compatibility_fallback(self):
        references=self.manifest(1)
        path=Path(references[0]['request_file'])
        for apartment,expected in [('STA','in_process'),('MTA','separate_process')]:
            result=self.run_wrapper('SessionRpc',apartment,path)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            text=result.stdout.decode(errors='replace')
            self.assertIn('"mode":"'+expected+'"',text)

    def test_command_host_uses_clean_fallback_process(self):
        references=self.manifest(1)
        quote=lambda value:"'"+str(value).replace("'","''")+"'"
        command='& '+quote(self.wrapper)+' -Mode SessionRpc -SessionConfig '+quote(self.config)+ \
            ' -SessionRequest '+quote(references[0]['request_file'])+ \
            ' -SessionOutputName '+quote(self.group+'/aggregate.json')
        result=subprocess.run([client.POWERSHELL,'-NoProfile','-STA','-ExecutionPolicy','Bypass',
            '-Command',command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertIn('"mode":"separate_process"',result.stdout.decode(errors='replace'))

    def test_all_paths_and_hashes_checked_before_any_dispatch(self):
        refs=self.manifest(2)
        Path(refs[1]['request_file']).write_text('{}')
        result=self.run_wrapper()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.invocations(),[])

    def test_outside_private_request_rejected(self):
        refs=self.manifest(1)
        outside=self.root/'outside.json';outside.write_bytes(Path(refs[0]['request_file']).read_bytes())
        refs[0]['request_file']=str(outside)
        client.save(self.batch,{'version':1,'requests':refs})
        self.assertNotEqual(self.run_wrapper().returncode,0)
        self.assertEqual(self.invocations(),[])

    def test_six_children_rejected(self):
        self.manifest(6)
        self.assertNotEqual(self.run_wrapper().returncode,0)
        self.assertEqual(self.invocations(),[])

    def test_completed_submissions_cached_with_hash_validation(self):
        refs=self.manifest(2,True)
        self.assertEqual(self.run_wrapper().returncode,0)
        self.assertEqual(self.run_wrapper().returncode,0)
        self.assertEqual(len(self.invocations()),2)
        (self.output/(refs[0]['id']+'.json')).write_text('{}')
        self.assertNotEqual(self.run_wrapper().returncode,0)
        self.assertEqual(len(self.invocations()),2)

    def test_uncertain_child_never_redispatched_and_other_slot_can_continue(self):
        refs=self.manifest(3,True)
        (self.flags/('fail-'+refs[1]['id'])).write_text('fail once')
        self.assertEqual(self.run_wrapper().returncode,2)
        self.assertEqual([v['state'] for v in self.aggregate()['items']],
            ['complete','uncertain','not_started'])
        self.assertEqual(self.run_wrapper().returncode,2)
        self.assertEqual([v['state'] for v in self.aggregate()['items']],
            ['complete','uncertain','complete'])
        self.assertEqual([v['id'] for v in self.invocations()],[r['id'] for r in refs])

    def test_observational_batch_refreshes_instead_of_returning_stale_cache(self):
        self.manifest(1)
        self.assertEqual(self.run_wrapper().returncode,0)
        self.assertEqual(self.run_wrapper().returncode,0)
        self.assertEqual(len(self.invocations()),2)


if __name__=='__main__': unittest.main(verbosity=2)
