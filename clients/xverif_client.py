"""xverif task adapter. Clipboard access is delegated to Invoke-EtxX11 only."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'etx'))
from site_config import site,configure,release_files
from common import BridgeError,encoded,decoded,regular,private_dir,atomic_write,digest,ID_RE


class X11Client:
    def __init__(self,config_path,waveforms):
        self.config=decoded(regular(config_path,65536,True).read_bytes())
        if set(self.config)!={'transport','project_root','install_root'} or self.config['transport']!='x11':
            raise BridgeError('BAD_X11_CONFIGURATION')
        self.root=Path(self.config['project_root']).absolute()
        self.session=self.root/'.private/x11/session/client.json'
        self.session_data=decoded(regular(self.session,65536,True).read_bytes())
        self.state=private_dir(Path(config_path).parent/'bridge-state-x11')
        self.records=private_dir(self.state/'requests')
        self.output=private_dir(self.root/'.work/x11/xverif')
        self.waveforms=set(waveforms)

    def rpc(self,group,op,args,rid=None):
        rid=rid or uuid.uuid4().hex
        requests=self.root/'.private/x11/session/requests'/group
        requests.mkdir(parents=True,exist_ok=True)
        output=self.root/'.work/x11/session'/group
        output.mkdir(parents=True,exist_ok=True)
        path=requests/(rid+'.json');spec=encoded({'id':rid,'op':op,'args':args})
        if path.exists() and path.read_bytes()!=spec:raise BridgeError('LOCAL_REQUEST_CONFLICT')
        if not path.exists():atomic_write(path,spec)
        destination=output/(rid+'.json')
        argv=['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-STA',
            '-ExecutionPolicy','Bypass','-File',str(self.root/'clients/Invoke-EtxX11.ps1'),
            '-Mode','SessionRpc','-SessionConfig',str(self.session),'-SessionRequest',str(path),
            '-SessionOutputName',group+'/'+rid+'.json','-TimeoutSeconds','3600']
        if not destination.exists():
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=3600,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            if not destination.exists():raise BridgeError('X11_RECEIPT_MISSING')
        reply=decoded(regular(destination,524288,False).read_bytes())
        if reply.get('ok') is not True:raise BridgeError(reply.get('error','X11_REQUEST_FAILED'))
        return reply['result']

    def status(self):
        pending=[]
        for path in self.record_files():
            item=decoded(regular(path,65536,True).read_bytes())
            if item.get('state')!='complete':pending.append({'request_id':item['request_id'],'status':item['state']})
        last=self.output/'last-wave.json'
        wave=decoded(regular(last,196608,True).read_bytes()) if last.exists() else None
        return {'transport':'x11','bootstrapped':True,'waveform_queries_enabled':bool(wave and wave.get('verified')),
            'last_wave':wave,'active_requests':pending,'runner_required':False}

    def record_files(self):
        paths=list(self.records.glob('*.json'))
        if len(paths)>4096:raise BridgeError('X11_LOCAL_RECORD_LIMIT')
        return paths

    def submit(self,operation,options=None):
        self.preparing_id=None
        try:
            return self._submit(operation,options)
        except Exception:
            if self.preparing_id:
                path=self.records/(self.preparing_id+'.json')
                item=decoded(regular(path,65536,True).read_bytes())
                if item['state']=='preparing':
                    item['state']='complete';item['error']='NOT_SUBMITTED';atomic_write(path,encoded(item))
            raise

    def _submit(self,operation,options=None):
        options=options or {}
        if operation=='query':
            if set(options) not in ({'fsdb','queries'},{'fsdb','queries','writer_stopped'}) or options['fsdb'] not in self.waveforms:
                raise BridgeError('FSDB_NOT_AUTHORIZED')
            if 'writer_stopped' in options and options['writer_stopped'] is not True:
                raise BridgeError('FSDB_WRITER_NOT_STOPPED')
            options={k:options[k] for k in ('fsdb','queries')}
            kind='wave'
        elif operation in ('probe','lsf_probe','wave_metadata'):
            kind='wave_probe';options={}
        else:raise BridgeError('X11_OPERATION_NOT_SUPPORTED')
        signature=digest(encoded({'operation':operation,'options':options}))
        for path in self.record_files():
            saved=decoded(regular(path,65536,True).read_bytes())
            if saved.get('signature')==signature and saved.get('state')!='complete':
                return {'request_id':saved['request_id'],'transport':'x11','status':saved['state'],'reused_request':True}
        rid=uuid.uuid4().hex
        record={'request_id':rid,'operation':operation,'kind':kind,'options':options,
            'signature':signature,'state':'preparing'}
        path=self.records/(rid+'.json');atomic_write(path,encoded(record))
        self.preparing_id=rid
        workers=self.rpc(rid,'workers',{})
        public=workers.get('control',{})
        if public.get('activation_pending'):raise BridgeError('CONTROL_ACTIVATION_PENDING')
        required=Path(options['fsdb']).parent.name.rsplit('_',1)[-1] if kind=='wave' else None
        choices=[w for w in workers['workers'] if not w['busy'] and w.get('command_certificate') and
            w.get('parallel') and (required not in ('work01','work02','work03','work04','work05') or w['profile']==required)]
        if not choices:raise BridgeError('NO_MATCHING_IDLE_WORKER')
        chosen=sorted(choices,key=lambda w:(w['profile'],w['id']))[0]
        sys.path.insert(0,str(self.root/'etx'))
        from session_jobs import job_argv
        argv=job_argv(self.config['install_root'],public['job_sha256'],public['config_sha256'],
            kind,rid,chosen['profile'],options)
        module_path=self.root/'worker-runtime/sim_control.py'
        if digest(module_path.read_bytes())!=release_files()['worker-runtime/sim_control.py']:
            raise BridgeError('LOCAL_WORKER_MODULE_CHANGED')
        spec=importlib.util.spec_from_file_location('xverif_signed_queue',module_path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        def crypto(args,data=None):
            result=subprocess.run([self.session_data['openssl'],*args],input=data,
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
            if result.returncode:raise BridgeError('COMMAND_CRYPTO_FAILED')
            return result.stdout
        module.openssl=crypto
        cert=base64.b64decode(chosen['command_certificate'],validate=True)
        if len(cert)>8192:raise BridgeError('BAD_WORKER_CERTIFICATE')
        certificate=self.root/'.private/x11/session/requests'/rid/'worker.pem';certificate.write_bytes(cert)
        box=module.seal_command(rid,chosen['id'],chosen['profile'],argv,
            self.session_data['signer_cert'],self.session_data['signer_key'],certificate)
        args={'request_id':rid,'worker_id':chosen['id'],'profile':chosen['profile'],'kind':kind,
            'options':options,'command_box':box,'launcher_sha256':digest(encoded(argv))}
        record.update(state='submitting',arguments=args);atomic_write(path,encoded(record))
        result=self.rpc(rid,'submit_task',args,uuid.uuid5(uuid.UUID(rid),'submit').hex)
        record.update(state='submitted',queue=result);atomic_write(path,encoded(record))
        return {'request_id':rid,'transport':'x11','status':result['state'],'worker_profile':chosen['profile']}

    def result(self,request_id):
        if not ID_RE.fullmatch(request_id):raise BridgeError('BAD_REQUEST_ID')
        path=self.records/(request_id+'.json');record=decoded(regular(path,65536,True).read_bytes())
        cached=self.output/(request_id+'.result.json')
        if cached.exists():
            raw=regular(cached,262144,True).read_bytes()
            if digest(raw)!=record.get('result_cache_sha256'):raise BridgeError('CACHED_RESULT_HASH_MISMATCH')
            return decoded(raw)
        result=self.rpc(request_id,'task_result',{'request_id':request_id})
        if not result.get('ready'):
            return dict(result,request_id=request_id,transport='x11',verified=False)
        payload=result['payload'];raw=encoded(payload)
        if len(raw)!=result['bytes'] or digest(raw)!=result['sha256']:
            raise BridgeError('X11_RESULT_HASH_MISMATCH')
        verified=result['state']=='exited' and result.get('exit_code')==0 and payload.get('result')=='PASS'
        if record['kind']=='wave':
            wave=payload.get('wave',{})
            verified=verified and wave.get('query_ok') is True and wave.get('resource_release',{}).get('confirmed') is True and wave.get('lsf',{}).get('terminal_confirmed') is True
        value={'request_id':request_id,'transport':'x11','status':result['state'],'verified':verified,
            'result':payload.get('wave',payload),'result_sha256':result['sha256']}
        if record['kind']=='wave':
            value['fsdb']=record['options']['fsdb']
            value['resource_release']=payload.get('wave',{}).get('resource_release',{})
        data=encoded(value);atomic_write(cached,data)
        record.update(state='complete',result_cache_sha256=digest(data));atomic_write(path,encoded(record))
        if record['kind']=='wave':
            fields=('request_id','transport','status','verified','fsdb','result_sha256','resource_release')
            atomic_write(self.output/'last-wave.json',encoded({k:value[k] for k in fields if k in value}))
        return value


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True,type=Path)
    parser.add_argument('operation',choices=('status','query','probe','result'))
    parser.add_argument('--options-file',type=Path)
    parser.add_argument('--request-id')
    args=parser.parse_args()
    configure()
    WAVEFORMS=site(required=True)['permissions']['wave_fsdbs']
    client=X11Client(args.config,WAVEFORMS)
    if args.operation=='status':value=client.status()
    elif args.operation=='result':value=client.result(args.request_id or '')
    elif args.operation=='query':
        if not args.options_file:raise BridgeError('OPTIONS_FILE_REQUIRED')
        value=client.submit('query',decoded(regular(args.options_file,65536,True).read_bytes()))
    else:value=client.submit('probe')
    print(encoded(value).decode(),flush=True)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(encoded({'ok':False,'error':str(error) if isinstance(error,BridgeError) else type(error).__name__}).decode(),file=sys.stderr)
        raise SystemExit(1)
