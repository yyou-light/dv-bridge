"""Fixed Worker queue capabilities for the execution-enabled X11 profile."""
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

from session_protocol import Rejected, require, keys, identifier, sha, digest, canonical
from session_files import Files, private_directory, file_lock, atomic_json
from session_worker import Worker
from session_jobs import job_argv


class ControlWorker(Worker):
    def __init__(self, config, config_path):
        self.config=dict(config)
        self.config_path=Path(config_path).absolute()
        self.install=Path(__file__).resolve().parents[1]
        self.config_sha=digest(self.config_path.read_bytes())
        self.job_sha=digest((self.install/'etx/session_jobs.py').read_bytes())
        super().__init__(config['worker_module'],config['worker_module_sha256'],
            private_directory(Path(config['state'])/'workers'),
            coordinator_script=self.install/'etx/session_agent.py',coordinator_config=self.config_path)
        self.result_files=Files(private_directory(self.state/'result-cache'),[self.queue.root])

    def active(self):
        path=Path(self.config['activation_file'])
        if not path.exists():return False
        return Files.meta(path)=={'task_id':self.config['activation_task_id'],
            'endpoint_id':self.config['endpoint_id'],'commit':True}

    def require_active(self):
        require(self.active(),'CONTROL_ACTIVATION_PENDING')

    def reservations(self):
        active=self.module.read_json(self.queue.active)
        if not active:return {}
        ids=list(active.get('workers',{}).values()) if 'workers' in active else [active.get('request_id')]
        reservations={}
        for rid in ids:
            if not rid:continue
            request=self.module.read_json(self.queue.job(rid)/'request.json')
            state=self.queue.snapshot(rid)
            if request and state['state'] not in self.module.SAFE_TERMINAL:
                reservations[request['profile']]={'request_id':rid,'state':state['state']}
        return reservations

    def workers(self,args):
        keys(args,())
        reserved=self.reservations();values=[]
        fields=('id','profile','cases','busy','command_certificate','parallel','upload_independent',
            'execution_host','process_identity')
        for worker in self.queue.available_workers():
            item={k:worker[k] for k in fields if k in worker}
            if item['profile'] in reserved:
                item.update(busy=True,reservation=reserved[item['profile']])
            readers=self.queue.root/'readers'/item['profile']
            if readers.is_dir() and any(readers.glob('*.json')):
                item.update(busy=True,output_reader_reservation=True)
            values.append(item)
        return {'workers':values,'control':{'activation_pending':not self.active(),
            'install_root':str(self.install),'job_sha256':self.job_sha,'config_sha256':self.config_sha,
            'wave_fsdbs':self.config['wave_fsdbs'],'max_workers':5}}

    def status_many(self,args):
        keys(args,('request_ids',));ids=args['request_ids']
        require(type(ids) is list and 1<=len(ids)<=5,'STATUS_BATCH_LIMIT')
        for rid in ids:identifier(rid)
        require(len(ids)==len(set(ids)),'STATUS_BATCH_DUPLICATE')
        return dict(self.workers({}),jobs=[self.queue.snapshot(rid) for rid in ids])

    def submit_simmer(self,args):
        self.require_active()
        return super().submit_simmer(args)

    def submit_task(self,args):
        self.require_active()
        keys(args,('request_id','worker_id','profile','kind','options','command_box','launcher_sha256'))
        rid=identifier(args['request_id']);identifier(args['worker_id'])
        require(re.fullmatch('work0[1-5]',args['profile']) is not None,'BAD_WORKER_PROFILE')
        require(args['kind'] in ('selftest','wave','wave_probe'),'JOB_KIND_REJECTED')
        options=args['options']
        if args['kind']=='selftest':
            keys(options,('hold_seconds',))
            require(type(options['hold_seconds']) is int and options['hold_seconds'] in (1,30,90),
                'SELFTEST_OPTIONS_REJECTED')
        elif args['kind']=='wave_probe':
            keys(options,())
            require(self.config.get('wave_enabled') is True,'WAVE_NOT_CONFIGURED')
        else:
            keys(options,('fsdb','queries'))
            require(options['fsdb'] in self.config['wave_fsdbs'],'FSDB_NOT_AUTHORIZED')
            require(type(options['queries']) is list and 1<=len(options['queries'])<=4,'WAVE_QUERY_LIMIT')
            for query in options['queries']:
                keys(query,('action','args'))
                require(query['action'] in ('scope.roots','scope.list','value.at','signal.changes')
                    and type(query['args']) is dict,'WAVE_QUERY_REJECTED')
            slot=Path(options['fsdb']).parent.name.rsplit('_',1)[-1]
            if re.fullmatch('work0[1-5]',slot):
                require(args['profile']==slot,'WAVE_EXECUTOR_SLOT_MISMATCH')
        argv=job_argv(str(self.install),self.job_sha,self.config_sha,args['kind'],rid,args['profile'],options)
        require(digest(canonical(argv))==sha(args['launcher_sha256']),'LAUNCHER_MISMATCH')
        self.module.checked_box(args['command_box'])
        meta=self.state/(rid+'.task.json')
        specification={k:args[k] for k in ('request_id','worker_id','profile','kind','options','launcher_sha256')}
        with file_lock(self.state/'submit.lock'):
            if meta.exists():
                require(Files.meta(meta)['specification']==specification,'REQUEST_ID_CONFLICT')
            else:
                atomic_json(meta,{'specification':specification,
                    'result':str(self.queue.job(rid)/'output/task-result.json')})
            with self.module.simulation_access(self.lock_root) as locks:
                require(locks is not None,'SIMULATION_RESOURCE_BUSY')
                try:
                    _,created=self.queue.reserve(rid,args['profile'],'run',1,args['worker_id'],args['command_box'])
                except self.module.Rejected as exc:
                    raise Rejected(str(exc)) from None
                state=self.queue.snapshot(rid)
                if created:self.start_coordinator(rid)
                elif state['state'] not in self.module.TERMINAL:self.require_coordinator(rid)
                return dict(self.queue.snapshot(rid),created=created,kind=args['kind'])

    def task_result(self,args):
        keys(args,('request_id',));rid=identifier(args['request_id'])
        path=self.state/(rid+'.task.json')
        require(path.exists(),'REQUEST_NOT_FOUND')
        meta=Files.meta(path);state=self.queue.snapshot(rid)
        if state['state'] not in self.module.TERMINAL:
            return dict(state,ready=False)
        result=Path(meta['result'])
        if not result.exists():return dict(state,ready=False,error='TASK_RESULT_NOT_PUBLISHED')
        data,_=self.result_files.read(result,196608)
        value=json.loads(data)
        require(value.get('request_id')==rid,'TASK_RESULT_IDENTITY_MISMATCH')
        return dict(state,ready=True,bytes=len(data),sha256=digest(data),payload=value)

    def release_selftests(self,args):
        self.require_active();keys(args,('request_ids',));ids=args['request_ids']
        require(type(ids) is list and 1<=len(ids)<=5,'STATUS_BATCH_LIMIT')
        for rid in ids:
            identifier(rid);meta=Files.meta(self.state/(rid+'.task.json'))
            require(meta['specification']['kind']=='selftest','NOT_A_SELFTEST')
            require(self.queue.snapshot(rid)['state'] in ('running','exited'),'SELFTEST_NOT_RUNNING')
        for rid in ids:
            output=self.queue.job(rid)/'output'
            require(output.is_dir() and not output.is_symlink(),'TASK_OUTPUT_REJECTED')
            atomic_json(output/'selftest-release.json',{'request_id':rid})
        return {'released':ids}

    def run_executor(self,profile):
        require(profile in self.config['executor_profiles'],'BAD_WORKER_PROFILE')
        self.require_active()
        require(not any(w['profile']==profile for w in self.queue.available_workers()),
            'WORKER_PROFILE_ALREADY_ONLINE')
        from session_runner_pause import identity
        queue=self.queue;original=queue.heartbeat
        def heartbeat(worker_id,definition,busy):
            original(worker_id,definition,busy)
            path=queue.workers/(worker_id+'.json');entry=self.module.read_json(path)
            entry.update(execution_host=self.config['transport_host'],process_identity=identity(os.getpid()))
            self.module.put_json(path,entry)
        queue.heartbeat=heartbeat
        stopping=[False]
        def stop(*_):stopping[0]=True
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,stop)
        self.module.command_worker(queue,profile,self.lock_root,
            lambda:self.module.simulation_access(self.lock_root),lambda:stopping[0])


