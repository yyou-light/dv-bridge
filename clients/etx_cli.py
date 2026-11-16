"""Project actions over the canonical X11 helper; no clipboard implementation.

Stable operation directories preserve upload offsets, command boxes and request
IDs. An uncertain dispatch is queried or retried with the same identity.
"""
import argparse
import base64
import codecs
import stat
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'etx'))
from site_config import site,configure,release_files

MAX_FILE=16777216
MAX_TEXT_FILE=256*1024*1024
CHUNK=262144
PINNED_SIM=None
POWERSHELL=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
BATCH_OPERATIONS={'workers','status','status_many','task_result','submit_simmer','submit_task'}
DOCUMENT_TYPES={'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx'}
TEXT_TYPES={'.sv','.svh','.v','.vh','.bzl','.py','.c','.cpp','.h','.txt','.md','.json','.yaml','.yml',
    '.log','.out','.ini','.tcl','.sh','.bash','.sdc','.f','.conf','.cfg','.xml','.csv','.html','.css','.js','.rst',''}


class Failure(Exception):
    pass


def check(value,code):
    if not value:
        raise Failure(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,
        separators=(',',':'),allow_nan=False).encode('utf-8')


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def save(path,value):
    path=Path(path)
    temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    try:
        with temporary.open('xb') as stream:
            stream.write(json_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


def under(path,root):
    path,root=Path(path).absolute(),Path(root).absolute()
    check(path.is_relative_to(root) and path!=root,'LOCAL_PATH_REJECTED')
    check(all(not p.is_symlink() for p in [path,*path.parents]),'LOCAL_SYMLINK_REJECTED')
    return path


def text_file_meta(path):
    path=Path(path)
    for parent in (path,*path.parents):
        info=parent.lstat()
        check(not stat.S_ISLNK(info.st_mode) and not
            (getattr(info,'st_file_attributes',0)&0x400),'LOCAL_SYMLINK_REJECTED')
    before=path.stat()
    check(stat.S_ISREG(before.st_mode) and before.st_size<=MAX_TEXT_FILE,'TEXT_SOURCE_REJECTED')
    hasher=hashlib.sha256();decoder=codecs.getincrementaldecoder('utf-8')();count=0
    try:
        with path.open('rb') as stream:
            for part in iter(lambda:stream.read(CHUNK),b''):
                count+=len(part)
                check(count<=MAX_TEXT_FILE and b'\x00' not in part,'TEXT_SOURCE_REJECTED')
                decoder.decode(part);hasher.update(part)
            decoder.decode(b'',final=True)
            after=os.fstat(stream.fileno())
    except UnicodeError:
        raise Failure('TEXT_ENCODING_REJECTED') from None
    identity=lambda info:[info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns]
    check(count==before.st_size and identity(before)==identity(after)==identity(path.stat()),
        'LOCAL_SOURCE_CHANGED')
    return {'bytes':count,'sha256':hasher.hexdigest(),'identity':identity(before)}


def save_bytes(path,data):
    path=Path(path);temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    try:
        with temporary.open('xb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


class Project:
    def __init__(self,root,operation_id):
        self.root=Path(root).absolute()
        check(re.fullmatch('[0-9a-f]{32}',operation_id),'BAD_OPERATION_ID')
        if (self.root/'.private/site.json').exists(): configure(self.root/'.private/site.json')
        self.operation_id=operation_id
        self.private=self.root/'.private/x11/session'
        self.result=self.root/'.work/x11/session'/operation_id
        self.requests=self.private/'requests'/operation_id
        self.config=self.private/'client.json'
        for folder in (self.result,self.requests):
            under(folder,self.root)
            folder.mkdir(parents=True,exist_ok=True)
        self.config_data=read_json(self.config) if self.config.exists() else {}
        self.transport_samples=[]

    def sub_id(self,name):
        return uuid.uuid5(uuid.UUID(self.operation_id),name).hex

    def transport(self,command):
        started=time.perf_counter()
        completed=subprocess.run(command,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3600,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        sample={'outer_seconds':round(time.perf_counter()-started,6)}
        for line in completed.stdout.decode('utf-8',errors='replace').splitlines():
            if line.startswith('ETX_CONSUMER_TIMINGS='):
                try: sample['consumer']=json.loads(line.split('=',1)[1])
                except ValueError: pass
        self.transport_samples.append(sample)
        return completed

    def rpc(self,op,args,name=None):
        request_id=self.sub_id(name) if name else uuid.uuid4().hex
        request_file=self.requests/(request_id+'.json')
        specification={'id':request_id,'op':op,'args':args}
        if request_file.exists():
            check(read_json(request_file)==specification,'LOCAL_REQUEST_CONFLICT')
        else:
            save(request_file,specification)
        output_name=self.operation_id+'/'+request_id+'.json'
        command=[POWERSHELL,'-NoProfile','-STA','-ExecutionPolicy','Bypass',
            '-File',str(self.root/'clients/Invoke-EtxX11.ps1'),'-Mode','SessionRpc',
            '-SessionConfig',str(self.config),'-SessionRequest',str(request_file),
            '-SessionOutputName',output_name]
        response=self.result/(request_id+'.json')
        # This small file is a transport receipt. It may be refreshed for status;
        # durable business IDs remain in the request and ETX receipt.
        completed=self.transport(command)
        check(response.is_file(),'TRANSPORT_RECEIPT_MISSING')
        reply=read_json(response)
        check(completed.returncode==0 and reply.get('ok'),reply.get('error','TRANSPORT_FAILED'))
        return reply['result']

    def rpc_batch(self,specifications,name='batch'):
        check(re.fullmatch(r'[A-Za-z0-9_-]{1,64}',name),'BAD_BATCH_NAME')
        check(type(specifications) is list and 1<=len(specifications)<=5,'BATCH_LIMIT')
        references=[]; ids=set(); profiles=set()
        for index,item in enumerate(specifications):
            check(type(item) is dict and set(item) in ({'op','args'},{'id','op','args'}),
                'BAD_BATCH_FIELDS')
            check(item['op'] in BATCH_OPERATIONS and type(item['args']) is dict,'BAD_BATCH_OPERATION')
            rid=item.get('id') or self.sub_id(name+'-'+str(index))
            check(type(rid) is str and re.fullmatch('[0-9a-f]{32}',rid) and rid not in ids,
                'BAD_BATCH_ID')
            ids.add(rid)
            if item['op'] in ('submit_simmer','submit_task'):
                profile=item['args'].get('profile')
                check(type(profile) is str and re.fullmatch('work0[1-5]',profile) and
                    profile not in profiles,'BATCH_DUPLICATE_PROFILE')
                profiles.add(profile)
            specification={'id':rid,'op':item['op'],'args':item['args']}
            raw=json_bytes(specification)
            check(len(raw)<=524288,'BATCH_REQUEST_LIMIT')
            path=self.requests/(rid+'.json')
            if path.exists(): check(path.read_bytes()==raw,'LOCAL_REQUEST_CONFLICT')
            else: save(path,specification)
            references.append({'id':rid,'request_file':str(path),
                'request_sha256':sha(raw),'output_name':self.operation_id+'/'+rid+'.json'})
        manifest={'version':1,'requests':references}
        path=self.requests/(name+'.batch.json')
        if path.exists(): check(read_json(path)==manifest,'LOCAL_BATCH_CONFLICT')
        else: save(path,manifest)
        aggregate=self.result/(name+'.batch.json')
        command=[POWERSHELL,'-NoProfile','-STA','-ExecutionPolicy','Bypass',
            '-File',str(self.root/'clients/Invoke-EtxX11.ps1'),'-Mode','SessionRpcBatch',
            '-SessionConfig',str(self.config),'-SessionRequest',str(path),
            '-SessionOutputName',self.operation_id+'/'+aggregate.name]
        completed=self.transport(command)
        check(completed.returncode in (0,2) and aggregate.is_file(),'BATCH_TRANSPORT_FAILED')
        reply=read_json(aggregate)
        self.transport_samples[-1]['consumer']=reply.get('timings',{})
        check(reply['manifest_sha256']==sha(path.read_bytes()) and
            len(reply['items'])==len(references),'BATCH_RECEIPT_MISMATCH')
        items=[]
        for expected,value,spec in zip(references,reply['items'],specifications):
            check(value['id']==expected['id'] and value['op']==spec['op'] and
                value['output_name']==expected['output_name'],'BATCH_RECEIPT_MISMATCH')
            item={'id':value['id'],'op':value['op'],'state':value['state'],
                'receipt':str(self.result/(value['id']+'.json'))}
            if value['state']=='complete':
                raw=Path(item['receipt']).read_bytes()
                check(sha(raw)==value['receipt_sha256'],'BATCH_RECEIPT_HASH_MISMATCH')
                child=json.loads(raw)
                check(child.get('ok') is True,'BATCH_CHILD_FAILED')
                item.update(ok=True,result=child['result'])
            else:
                item.update(ok=False,error=value.get('error') or value['state'])
                if spec['op'] in ('submit_simmer','submit_task'):
                    item['request_id']=spec['args'].get('request_id')
            items.append(item)
        return {'ok':all(item['ok'] for item in items),'items':items,
            'transport_timings':self.transport_samples[-1]}

    def pair(self,fingerprint):
        check(re.fullmatch('[0-9a-f]{64}',fingerprint),'BAD_FINGERPRINT')
        response=self.result/'pair.json'
        completed=self.transport([POWERSHELL,'-NoProfile','-STA','-ExecutionPolicy','Bypass',
            '-File',str(self.root/'clients/Invoke-EtxX11.ps1'),'-Mode','SessionPair',
            '-SessionConfig',str(self.config),'-Fingerprint',fingerprint,
            '-SessionOutputName',self.operation_id+'/pair.json'])
        check(response.exists(),'TRANSPORT_RECEIPT_MISSING')
        reply=read_json(response)
        check(completed.returncode==0 and reply.get('ok'),reply.get('error','PAIRING_FAILED'))
        return reply['result']

    def read_text(self,remote,name):
        check(re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',name) and name not in ('.','..'),'BAD_OUTPUT_NAME')
        request_file=self.requests/'files.json'
        specification={'id':self.operation_id,'files':[{'path':remote,'cached_file':None,
            'cached_sha256':None,'output_name':name}],'timeout_seconds':3600}
        if request_file.exists():check(read_json(request_file)==specification,'LOCAL_REQUEST_CONFLICT')
        else:save(request_file,specification)
        command=[POWERSHELL,'-NoProfile','-STA','-ExecutionPolicy','Bypass','-File',
            str(self.root/'clients/Invoke-EtxX11.ps1'),'-Mode','SessionReadFiles',
            '-SessionConfig',str(self.config),'-SessionRequest',str(request_file),
            '-SessionOutputName',self.operation_id+'/summary.json','-TimeoutSeconds','3600']
        completed=self.transport(command)
        response=self.result/'summary.json'
        check(response.is_file(),'TRANSPORT_RECEIPT_MISSING')
        reply=read_json(response)
        check(completed.returncode==0 and reply.get('ok'),reply.get('error','TRANSPORT_FAILED'))
        files=reply.get('result',{}).get('files')
        check(type(files) is list and len(files)==1,'BAD_DOWNLOAD_METADATA')
        meta=files[0]
        check(meta.get('path')==remote and type(meta.get('bytes')) is int and
            0<=meta['bytes']<=MAX_TEXT_FILE,'BAD_DOWNLOAD_METADATA')
        output=under(meta['local'],self.result)
        check(output==self.result/name,'BAD_DOWNLOAD_METADATA')
        local=text_file_meta(output)
        check((local['bytes'],local['sha256'])==(meta['bytes'],meta['sha256']),'DOWNLOAD_HASH_MISMATCH')
        return {'path':str(output),'bytes':meta['bytes'],'sha256':meta['sha256'],
            'retention':meta.get('retention','baseline')}

    def read(self,remote,name):
        extension=Path(remote).suffix.lower()
        check(extension in DOCUMENT_TYPES|TEXT_TYPES,'UNSUPPORTED_FILE_TYPE')
        if extension not in DOCUMENT_TYPES:return self.read_text(remote,name)
        limit=MAX_FILE
        check(re.fullmatch(r'[A-Za-z0-9_.-]{1,120}',name) and name not in ('.','..'),
            'BAD_OUTPUT_NAME')
        meta=self.rpc('read_begin',{'path':remote,'transfer_id':self.operation_id},'read-begin')
        check(meta['path']==remote and 0<=meta['bytes']<=limit,'BAD_DOWNLOAD_METADATA')
        check(re.fullmatch('[0-9a-f]{64}',meta['sha256']),'BAD_DOWNLOAD_METADATA')
        output=self.result/name
        if output.exists():
            check(output.is_file() and sha(output.read_bytes())==meta['sha256'],'LOCAL_OUTPUT_CONFLICT')
            return {'path':str(output),'bytes':meta['bytes'],'sha256':meta['sha256']}
        partial=self.result/(name+'.part')
        offset=partial.stat().st_size if partial.exists() else 0
        check(offset<=meta['bytes'],'PARTIAL_DOWNLOAD_CONFLICT')
        # Validate every retained chunk by re-reading its same immutable transfer.
        if offset:
            with partial.open('rb') as stream:
                for start in range(0,offset,CHUNK):
                    length=min(CHUNK,offset-start)
                    part=self.rpc('read_chunk',{'transfer_id':self.operation_id,
                        'offset':start,'limit':length})
                    check(sha(stream.read(length))==part['sha256'],'PARTIAL_DOWNLOAD_CONFLICT')
        while offset<meta['bytes']:
            chunk=self.rpc('read_chunk',{'transfer_id':self.operation_id,
                'offset':offset,'limit':CHUNK})
            data=base64.b64decode(chunk['data'],validate=True)
            check(chunk['offset']==offset and len(data)==chunk['bytes'] and
                0<len(data)<=CHUNK and sha(data)==chunk['sha256'],'DOWNLOAD_CHUNK_INVALID')
            check(offset+len(data)<=meta['bytes'],'DOWNLOAD_CHUNK_INVALID')
            with partial.open('ab') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            offset+=len(data)
        if not partial.exists():
            partial.write_bytes(b'')
        check(sha(partial.read_bytes())==meta['sha256'],'DOWNLOAD_HASH_MISMATCH')
        if extension not in DOCUMENT_TYPES:
            try: partial.read_bytes().decode('utf-8')
            except UnicodeDecodeError: raise Failure('UTF8_TEXT_REQUIRED') from None
        check(not output.exists(),'LOCAL_OUTPUT_CONFLICT')
        os.replace(partial,output)
        return {'path':str(output),'bytes':meta['bytes'],'sha256':meta['sha256']}

    def upload(self,manifest_path):
        manifest_path=under(manifest_path,self.root/'.private/x11')
        manifest=read_json(manifest_path)
        check(set(manifest)=={'files'} and 1<=len(manifest['files'])<=10,'BAD_UPLOAD_MANIFEST')
        prepared=[]
        total=0
        for index,item in enumerate(manifest['files']):
            check(set(item)=={'source','target','expected_before_sha256'},'BAD_UPLOAD_MANIFEST')
            source=under(item['source'],self.root/'.private/x11')
            metadata=text_file_meta(source)
            total+=metadata['bytes']
            check(total<=MAX_TEXT_FILE,'BATCH_SIZE_LIMIT')
            prepared.append(dict(item,bytes=metadata['bytes'],sha256=metadata['sha256'],
                source_identity=metadata['identity'],
                transfer_id=self.sub_id('upload-'+str(index))))
        capabilities=self.rpc('hello',{})
        text_mode=capabilities.get('large_text_upload_enabled') is True
        limit=capabilities.get('max_text_file_bytes',0) if text_mode else 524288
        check(max(p['bytes'] for p in prepared)<=limit and (text_mode or total<=MAX_FILE),
            'LARGE_TEXT_ENDPOINT_UPGRADE_REQUIRED')
        specification={'transaction_id':self.operation_id,'files':prepared}
        prepared_path=self.requests/'upload-specification.json'
        if prepared_path.exists():
            check(read_json(prepared_path)==specification,'LOCAL_UPLOAD_CONFLICT')
        else:
            save(prepared_path,specification)
        for index,item in enumerate(prepared):
            source=Path(item['source'])
            check(text_file_meta(source)=={'bytes':item['bytes'],'sha256':item['sha256'],
                'identity':item['source_identity']},'UPLOAD_SOURCE_CHANGED')
            transfer=item['transfer_id']
            self.rpc('upload_begin',{'transfer_id':transfer,'path':item['target'],
                'bytes':item['bytes'],'sha256':item['sha256'],
                'expected_before_sha256':item['expected_before_sha256'],**({'text_only':True} if text_mode else {})},'upload-begin-'+str(index))
            current=self.rpc('upload_status',{'transfer_id':transfer})
            offset=current['received']
            check(type(offset) is int and 0<=offset<=item['bytes'],'UPLOAD_PREFIX_MISMATCH')
            hasher=hashlib.sha256()
            with source.open('rb') as stream:
                remaining=offset
                while remaining:
                    part=stream.read(min(CHUNK,remaining))
                    check(bool(part),'UPLOAD_SOURCE_CHANGED')
                    hasher.update(part);remaining-=len(part)
                check(hasher.hexdigest()==current['prefix_sha256'],'UPLOAD_PREFIX_MISMATCH')
                while offset<item['bytes']:
                    part=stream.read(min(CHUNK,item['bytes']-offset))
                    check(bool(part),'UPLOAD_SOURCE_CHANGED')
                    hasher.update(part)
                    reply=self.rpc('upload_chunk',{'transfer_id':transfer,'offset':offset,
                        'data':base64.b64encode(part).decode('ascii'),'sha256':sha(part)},
                        'upload-chunk-{}-{}'.format(index,offset))
                    expected=offset+len(part)
                    check(reply['received']==expected and reply['prefix_sha256']==hasher.hexdigest(),
                        'UPLOAD_ACK_INVALID')
                    offset=expected
                check(not stream.read(1) and hasher.hexdigest()==item['sha256'],'UPLOAD_SOURCE_CHANGED')
            check(text_file_meta(source)['identity']==item['source_identity'],'UPLOAD_SOURCE_CHANGED')
        receipt=self.rpc('commit',{'transaction_id':self.operation_id,
            'transfer_ids':[p['transfer_id'] for p in prepared]},'commit')
        check(receipt['state']=='committed','INSTALL_NOT_COMMITTED')
        save(self.result/'install.json',receipt)
        return receipt

    def native_log(self,remote,mode='errors',offset=0,limit=CHUNK):
        check(mode in ('errors','range','tail') and type(offset) is int and offset>=0
            and type(limit) is int and 1<=limit<=CHUNK,'BAD_NATIVE_LOG_OPTIONS')
        capabilities=self.rpc('hello',{})
        check(capabilities.get('native_log_enabled') is True,'NATIVE_LOG_ENDPOINT_UPGRADE_REQUIRED')
        source_file=self.result/'native-log.source.json'
        source=read_json(source_file) if source_file.exists() else None
        check(source is None or source['path']==remote,'LOCAL_LOG_SOURCE_CONFLICT')
        name='native-log-{}-{}-{}'.format(mode,offset,limit)
        request_file=self.requests/(self.sub_id(name)+'.json')
        arguments={'path':remote,'mode':mode,'offset':offset,'limit':limit,
            'identity':source['identity'] if source else None}
        if request_file.exists():
            old=read_json(request_file)['args']
            check(all(old[key]==arguments[key] for key in ('path','mode','offset','limit')),
                'LOCAL_REQUEST_CONFLICT')
            arguments=old
        value=self.rpc('native_log',arguments,name)
        check(value['path']==remote and value['mode']==mode and type(value['fragments']) is list
            and len(value['fragments'])<=2,'NATIVE_LOG_REPLY_INVALID')
        check(source is None or value['identity']==source['identity'],'LOG_CHANGED')
        check(type(value.get('identity')) is list and len(value['identity'])==4 and
            all(type(v) is int and v>=0 for v in value['identity']) and
            type(value.get('observed_file_bytes')) is int and 0<=value['observed_file_bytes']<=MAX_TEXT_FILE,
            'NATIVE_LOG_REPLY_INVALID')
        total=0;outputs=[];kinds=set()
        for index,fragment in enumerate(value['fragments']):
            data=base64.b64decode(fragment['data'],validate=True)
            check(fragment['kind'] in ('range','tail','first_error') and fragment['kind'] not in kinds
                and fragment['bytes']==len(data)
                and sha(data)==fragment['sha256'],'NATIVE_LOG_HASH_MISMATCH')
            kinds.add(fragment['kind'])
            total+=len(data);check(total<=limit,'NATIVE_LOG_REPLY_INVALID')
            try: data.decode('utf-8')
            except UnicodeError: raise Failure('TEXT_ENCODING_REJECTED') from None
            check(type(fragment['offset']) is int and fragment['offset']>=0
                and fragment['offset']+len(data)<=value['observed_file_bytes'],'NATIVE_LOG_REPLY_INVALID')
            output=under(self.result/('native-log-'+fragment['kind']+'-'+str(offset)+'.txt'),self.result)
            outputs.append((output,data,{k:v for k,v in fragment.items() if k!='data'}))
        check(total==value['bytes'],'NATIVE_LOG_REPLY_INVALID')
        # Publish only after all fragment hashes and ranges have passed.
        for output,data,fragment in outputs: save_bytes(output,data)
        save(source_file,{'path':remote,'identity':value['identity'],'bytes':value['observed_file_bytes']})
        result={k:v for k,v in value.items() if k!='fragments'}
        result['fragments']=[dict(fragment,local=str(output)) for output,data,fragment in outputs]
        save(self.result/('native-log-'+mode+'-'+str(offset)+'.json'),result)
        return result


    def cleanup_logs(self,summary_name='summary.json'):
        check(re.fullmatch(r'[A-Za-z0-9_.-]+\.json',summary_name) is not None,'BAD_SUMMARY_NAME')
        summary_file=under(self.result/summary_name,self.result)
        summary=read_json(summary_file)
        check(summary.get('ok') is True and type(summary.get('result',{}).get('files')) is list,
            'BAD_LOG_SUMMARY')
        pending=[]
        for entry in summary['result']['files']:
            if not entry['path'].endswith('.log') or entry.get('retention')!='temporary_log':
                continue
            path=under(entry['local'],self.result)
            if entry.get('retained') is False:
                check(not path.exists(),'LOCAL_OUTPUT_CONFLICT')
                continue
            metadata=text_file_meta(path)
            check((metadata['bytes'],metadata['sha256'])==(entry['bytes'],entry['sha256']),
                'LOCAL_LOG_CHANGED')
            pending.append((path,entry))
        for path,entry in pending:
            metadata=text_file_meta(path)
            check((metadata['bytes'],metadata['sha256'])==(entry['bytes'],entry['sha256']),
                'LOCAL_LOG_CHANGED')
            path.unlink()
            entry['retained']=False
        save(summary_file,summary)
        return {'removed_files':len(pending),'removed_bytes':sum(entry['bytes'] for path,entry in pending),
            'summary':str(summary_file)}
        return {'transaction_id':self.operation_id,'receipt':str(self.result/'install.json'),
            'state':'committed','files':len(prepared)}


    def prepare_submit(self,case,seed,profile=None,worker_id=None,workers=None):
        path=self.requests/'simulation.json'
        specification={'case':case,'seed':seed,'profile':profile,'worker_id':worker_id}
        if path.exists():
            saved=read_json(path)
            check(saved['specification']==specification,'LOCAL_REQUEST_CONFLICT')
            arguments=saved['arguments']
        else:
            if workers is None: workers=self.rpc('workers',{})['workers']
            choices=[w for w in workers if not w['busy'] and w.get('parallel') and
                w.get('command_certificate') and 'run' in w['cases'] and
                re.fullmatch('work0[1-5]',w['profile']) and
                (profile is None or w['profile']==profile) and
                (worker_id is None or w['id']==worker_id)]
            check(bool(choices),'NO_MATCHING_IDLE_WORKER')
            selected=sorted(choices,key=lambda w:(w['profile'],w['id']))[0]
            module_path=self.root/'worker-runtime/sim_control.py'
            check(sha(module_path.read_bytes())==release_files()['worker-runtime/sim_control.py'],'LOCAL_WORKER_MODULE_CHANGED')
            spec=importlib.util.spec_from_file_location('etx_session_project_sim',module_path)
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            openssl=self.config_data['openssl']
            def crypto(args,data=None):
                result=subprocess.run([openssl,*args],input=data,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,timeout=30)
                check(result.returncode==0,'COMMAND_CRYPTO_FAILED')
                return result.stdout
            module.openssl=crypto
            certificate=base64.b64decode(selected['command_certificate'],validate=True)
            check(len(certificate)<=8192,'BAD_WORKER_CERTIFICATE')
            recipient=self.requests/'worker-public.pem'
            recipient.write_bytes(certificate)
            argv=module.simmer_argv(case,seed,selected['profile'])
            box=module.seal_command(self.operation_id,selected['id'],selected['profile'],argv,
                self.config_data['signer_cert'],self.config_data['signer_key'],recipient)
            arguments={'request_id':self.operation_id,'worker_id':selected['id'],
                'profile':selected['profile'],'case':case,'seed':seed,'waves':True,
                'launcher_sha256':sha(json_bytes(argv)),'command_box':box}
            save(path,{'specification':specification,'arguments':arguments})
        return arguments

    def submit(self,case,seed,profile=None,worker_id=None):
        return self.rpc('submit_simmer',self.prepare_submit(case,seed,profile,worker_id),'submit')

    def submit_many(self,jobs):
        check(type(jobs) is list and 1<=len(jobs)<=5,'BATCH_LIMIT')
        profiles=set()
        for job in jobs:
            check(type(job) is dict and set(job) in (
                {'case','seed','profile'},{'case','seed','profile','worker_id'}),'BAD_JOB_FIELDS')
            check(type(job['case']) is str and re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}',job['case']),
                'BAD_CASE')
            check(type(job['seed']) is int and 0<=job['seed']<=2147483647,'BAD_SEED')
            check(type(job['profile']) is str and re.fullmatch('work0[1-5]',job['profile']) and
                job['profile'] not in profiles,'BATCH_DUPLICATE_PROFILE')
            profiles.add(job['profile'])
            if 'worker_id' in job:
                check(type(job['worker_id']) is str and re.fullmatch('[0-9a-f]{32}',job['worker_id']),
                    'BAD_WORKER_ID')
        path=self.requests/'simulations.json'
        if path.exists(): check(read_json(path)==jobs,'LOCAL_BATCH_CONFLICT')
        else: save(path,jobs)
        children=[Project(self.root,self.sub_id('simulation-'+job['profile'])) for job in jobs]
        needed=any(not (child.requests/'simulation.json').exists() for child in children)
        workers=self.rpc('workers',{})['workers'] if needed else []
        specifications=[]
        for child,job in zip(children,jobs):
            arguments=child.prepare_submit(job['case'],job['seed'],job['profile'],job.get('worker_id'),workers)
            specifications.append({'id':child.sub_id('submit'),'op':'submit_simmer','args':arguments})
        result=self.rpc_batch(specifications,'simulations')
        for item,child in zip(result['items'],children): item['request_id']=child.operation_id
        return result

    def status_many(self,request_ids):
        self.check_request_ids(request_ids)
        return self.rpc('status_many',{'request_ids':request_ids})

    @staticmethod
    def check_request_ids(request_ids):
        check(type(request_ids) is list and 1<=len(request_ids)<=5 and
            all(type(rid) is str and re.fullmatch('[0-9a-f]{32}',rid) for rid in request_ids) and
            len(set(request_ids))==len(request_ids),'BAD_REQUEST_IDS')

    def results_many(self,request_ids):
        self.check_request_ids(request_ids)
        result=self.rpc_batch([{'op':'task_result','args':{'request_id':rid}}
            for rid in request_ids],'results')
        for item in result['items']:
            if item['ok'] and item['result'].get('ready'):
                value=item['result']; data=json_bytes(value['payload'])
                check(len(data)==value['bytes'] and sha(data)==value['sha256'],'TASK_RESULT_HASH_MISMATCH')
        return result

    def logs(self,request_id,stream):
        checkpoint=self.result/(stream+'.offset.json')
        log=self.result/(stream+'.log')
        state=read_json(checkpoint) if checkpoint.exists() else {
            'offset':0,'identity':None,'request_id':request_id,'stream':stream}
        check(state['request_id']==request_id and state['stream']==stream,'LOG_CHECKPOINT_CONFLICT')
        check((log.stat().st_size if log.exists() else 0)>=state['offset'],'LOCAL_LOG_TRUNCATED')
        chunk=self.rpc('read_log',{'request_id':request_id,'stream':stream,
            'offset':state['offset'],'identity':state['identity'],'limit':32768})
        data=base64.b64decode(chunk['data'],validate=True)
        check(len(data)==chunk['bytes'] and sha(data)==chunk['sha256'] and
            chunk['offset']==state['offset'] and
            chunk['next_offset']==state['offset']+len(data),'LOG_CHUNK_INVALID')
        with log.open('r+b' if log.exists() else 'w+b') as output:
            output.seek(state['offset'])
            output.write(data)
            output.truncate()
            output.flush()
            os.fsync(output.fileno())
        state.update(offset=chunk['next_offset'],identity=chunk['identity'])
        save(checkpoint,state)
        return {'path':str(log),'received':len(data),'next_offset':state['offset'],
            'observed_file_bytes':chunk['observed_file_bytes']}


def compact_batch(value):
    summary=dict(value)
    summary['items']=[]
    fields=('request_id','state','exit_code','ready','bytes','sha256','kind','created',
        'simmer_result','reason','error')
    for item in value['items']:
        row={k:v for k,v in item.items() if k!='result'}
        if 'result' in item:
            result=item['result']
            row['result']={k:result[k] for k in fields if k in result}
            payload=result.get('payload',{})
            if payload:
                row['result']['task_result']=payload.get('result')
                wave=payload.get('wave',{})
                if wave:
                    row['result']['query_ok']=wave.get('query_ok')
                    row['result']['resource_release']=wave.get('resource_release')
        summary['items'].append(row)
    return summary


def compact_status(value):
    result=dict(value)
    if 'workers' in result:
        result['workers']=[{k:w[k] for k in ('id','profile','busy','reservation',
            'output_reader_reservation','execution_host') if k in w} for w in result['workers']]
    if 'control' in result:
        result['control']={k:result['control'][k] for k in ('activation_pending','max_workers',
            'config_sha256','job_sha256') if k in result['control']}
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root',default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--operation-id',required=True)
    commands=parser.add_subparsers(dest='command',required=True)
    pair=commands.add_parser('pair'); pair.add_argument('--fingerprint',required=True)
    commands.add_parser('workers')
    many=commands.add_parser('submit-many')
    many.add_argument('--jobs-file',required=True)
    many.add_argument('--full',action='store_true')
    for operation in ('status-many','result-many'):
        command=commands.add_parser(operation)
        command.add_argument('--request-id',required=True,action='append')
        command.add_argument('--full',action='store_true')
    commands.add_parser('close')
    submit=commands.add_parser('submit')
    submit.add_argument('--case',required=True); submit.add_argument('--seed',type=int,default=0)
    submit.add_argument('--profile'); submit.add_argument('--worker-id')
    status=commands.add_parser('status'); status.add_argument('--request-id',required=True)
    read=commands.add_parser('read'); read.add_argument('--remote',required=True); read.add_argument('--name',required=True)
    upload=commands.add_parser('upload'); upload.add_argument('--manifest',required=True)
    receipt=commands.add_parser('receipt'); receipt.add_argument('--transaction-id',required=True)
    restore=commands.add_parser('restore'); restore.add_argument('--transaction-id',required=True)
    logs=commands.add_parser('logs'); logs.add_argument('--request-id',required=True)
    logs.add_argument('--stream',choices=('stdout','stderr'),default='stdout')
    search=commands.add_parser('search'); search.add_argument('--root',required=True); search.add_argument('--pattern',required=True)
    native=commands.add_parser('native-log'); native.add_argument('--remote',required=True)
    native.add_argument('--mode',choices=('errors','range','tail'),default='errors')
    native.add_argument('--offset',type=int,default=0); native.add_argument('--limit',type=int,default=CHUNK)
    cleanup=commands.add_parser('cleanup-logs'); cleanup.add_argument('--summary',default='summary.json')
    args=parser.parse_args()
    started=time.perf_counter()
    try:
        configure(Path(args.project_root)/'.private/site.json')
        project=Project(args.project_root,args.operation_id)
        if args.command=='pair': result=project.pair(args.fingerprint)
        elif args.command=='workers': result=project.rpc('workers',{})
        elif args.command=='close': result=project.rpc('close',{},'close')
        elif args.command=='submit': result=project.submit(args.case,args.seed,args.profile,args.worker_id)
        elif args.command=='submit-many':
            path=under(args.jobs_file,project.private)
            check(path.is_file() and path.stat().st_size<=65536,'BAD_JOBS_FILE')
            result=project.submit_many(read_json(path))
            if not args.full: result=compact_batch(result)
        elif args.command=='status-many':
            result=project.status_many(args.request_id)
            if not args.full: result=compact_status(result)
        elif args.command=='result-many':
            result=project.results_many(args.request_id)
            if not args.full: result=compact_batch(result)
        elif args.command=='status': result=project.rpc('status',{'request_id':args.request_id})
        elif args.command=='read': result=project.read(args.remote,args.name)
        elif args.command=='upload': result=project.upload(args.manifest)
        elif args.command=='receipt': result=project.rpc('receipt',{'transaction_id':args.transaction_id})
        elif args.command=='restore': result=project.rpc('restore',{
            'transaction_id':args.transaction_id,'restoration_id':args.operation_id},'restore')
        elif args.command=='logs': result=project.logs(args.request_id,args.stream)
        elif args.command=='native-log': result=project.native_log(args.remote,args.mode,args.offset,args.limit)
        elif args.command=='cleanup-logs': result=project.cleanup_logs(args.summary)
        else:
            value=project.rpc('search',{'root':args.root,'pattern':args.pattern})
            data=base64.b64decode(value.pop('data'),validate=True)
            check(sha(data)==value['sha256'],'SEARCH_HASH_MISMATCH')
            output=project.result/'search.txt'
            output.write_bytes(data)
            result=dict(value,path=str(output))
        ok=not (isinstance(result,dict) and 'items' in result and result.get('ok') is False)
        print(json.dumps({'ok':ok,'result':result,'timings':{
            'command_seconds':round(time.perf_counter()-started,6),
            'transport':project.transport_samples}},ensure_ascii=False))
        return 0 if ok else 2
    except Exception as exc:
        code=str(exc) if isinstance(exc,Failure) else 'LOCAL_OPERATION_FAILED'
        print(json.dumps({'ok':False,'error':code}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
