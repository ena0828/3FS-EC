#!/usr/bin/env python3
"""ACK2 real-service acceptance on a fresh, already running single-Storage GC bundle.

No service startup/shutdown, signal to services, automatic restoration, or benchmark.
The formal experiment Runner owns child lifetimes, signals, records and private paths.
"""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import sys
import time

import tomllib

PROFILE='native-gc-local-1-storage-12-targets'
HEADER=['Id','Type','Status','Hostname','Pid','Tags','LastHeartbeatTime','ConfigVersion','ReleaseVersion']
ROLES={'STORAGE':('storage',10001),'META':('meta',100)}

def require(value,message):
    if not value: raise RuntimeError(message)

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result

def integer(text):
    require(isinstance(text,str) and re.fullmatch(r'[1-9][0-9]*',text),'Expected positive decimal integer')
    value=int(text);require(value<=2**64-1,'Version outside uint64');return value

def server_update_version(description):
    # heartbeatImpl formats the strong typedef itself, not its underlying value.
    # Do not accept ConfigInfo::genUpdateDesc, arbitrary suffixes, or bare digits.
    if description == 'N/A':return None
    require(isinstance(description,str) and len(description)<=35,'Malformed server ConfigVersion description')
    match=re.fullmatch(r'ConfigVersion\(([1-9][0-9]{0,19})\)',description)
    require(match is not None,'Expected exact ConfigVersion(positive uint64) description')
    return integer(match[1])

def typed(value,depth=0):
    require(depth<64,'Excessively nested TOML')
    kind=type(value)
    if kind is dict:return ('table',tuple((k,typed(v,depth+1)) for k,v in sorted(value.items())))
    if kind is list:return ('array',tuple(typed(v,depth+1) for v in value))
    if kind is float:require(math.isfinite(value),'Nonfinite TOML value')
    require(kind in (str,int,float,bool,datetime.datetime,datetime.date,datetime.time),'Unsupported TOML value')
    return (kind.__name__,value)

def kv(text,keys,succeed=False):
    lines=text.splitlines()
    if succeed:
        require(lines and lines.pop(0)=='Succeed','set-config did not report Succeed')
    result={}
    for line in lines:
        require(line and not line.isspace(),'Unexpected empty output row')
        match=re.fullmatch(r'([A-Za-z][A-Za-z0-9]*) {2,}(.*)',line)
        require(match is not None,'Unexpected administrative output format')
        key,value=match.groups();require(key not in result,'Duplicate administrative output key')
        result[key]=value
    require(set(result)==set(keys),'Unexpected/missing administrative output keys')
    return result

def nodes(text):
    lines=text.splitlines();require(len(lines)>=2,'Empty list-nodes table')
    spans=list(re.finditer(r'\S+',lines[0]))
    require([m.group() for m in spans]==HEADER,'Unexpected list-nodes header')
    starts=[m.start() for m in spans];result={}
    for line in lines[1:]:
        # Printer.cc pads std::string byte lengths; non-ASCII hostnames must not shift columns.
        raw=line.encode('utf-8')
        cells=[raw[start:starts[i+1] if i+1<len(starts) else None].decode('utf-8').strip() for i,start in enumerate(starts)]
        require(len(cells)==9 and all(cells),'Incomplete node row')
        node=integer(cells[0]);require(node not in result,'Duplicate node row')
        version=re.fullmatch(r'(0|[1-9][0-9]*)(?:\((UPTODATE|DIRTY|FAILED)\))?',cells[7])
        require(version is not None,'Malformed reported ConfigVersion')
        result[node]=dict(zip(HEADER,cells))
        result[node].update(pid=integer(cells[4]),version=int(version[1]),config_status=version[2])
    return result

def update(text,node):
    result=kv(text,['NodeId','UpdateTime','Description','Result'])
    require(integer(result['NodeId'])==node,'Update record has wrong node')
    if result['Result']=='N/A':
        require(result['UpdateTime']==result['Description']=='N/A','Partial absent update record')
        result['code']=None
    else:
        match=re.fullmatch(r'([A-Za-z:]+)\(([0-9]+)\)(?: (.*))?',result['Result'])
        require(match is not None,'Malformed Status::describe output')
        result['code']=int(match[2]);result['status_name']=match[1]
        datetime.datetime.strptime(result['UpdateTime'],'%Y-%m-%d %H:%M:%S')
        require(server_update_version(result['Description']) is not None,'Present update lacks a server version')
    return result

def supervisor(root):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(5);client.connect(str(root/'state/control.sock'));client.sendall(b'status\n')
        data=bytearray()
        while part:=client.recv(4096):
            data.extend(part);require(len(data)<=65536,'Oversized supervisor response')
    result=json.loads(data)
    require(type(result.get('schema')) is int and result['schema']==1 and result.get('root')==str(root) and result.get('profile')==PROFILE,
            'Wrong supervisor/root/profile')
    require(result.get('stage')=='ready' and result.get('failure') is None,'Supervisor not ready')
    procs=result.get('processes',[])
    require(len(procs)==4 and {p['name'] for p in procs}=={'fdb','mgmtd','storage','meta'} and
            all(type(p.get('pid')) is int and p['pid']>0 and p.get('exit_code') is None for p in procs),
            'Expected four live supervised services')
    return result

def process_identity(root,process):
    pid=process['pid'];base=Path('/proc')/str(pid)
    raw=(base/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
    require(len(fields)>19 and fields[0] not in ('Z','X'),'Process is not alive')
    command=(base/'cmdline').read_bytes().split(b'\0');command=[x.decode() for x in command if x]
    executable=os.readlink(base/'exe')
    expected=root/'bin'/('fdbserver' if process['name']=='fdb' else process['name']+'_main')
    require(executable==str(expected),'Process executable path changed or deleted')
    uid=re.search(r'^Uid:\s+(\d+)\s+(\d+)',(base/'status').read_text(),re.M)
    require(uid is not None and int(uid[1])==int(uid[2])==os.geteuid(),'Process has unexpected ownership')
    if process['name']!='fdb':
        cfg=str(root/'config'/(process['name']+'_main.toml'))
        require('--cfg' in command and command[command.index('--cfg')+1]==cfg,
                'Service does not use the exact explicit local --cfg path')
    return {'name':process['name'],'pid':pid,'start_ticks':fields[19],'executable':executable,'argv':command}

def hash_file(w,path):
    path=w.canonical(path);info=path.stat()
    require(stat.S_ISREG(info.st_mode),'Expected regular locked file')
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda:stream.read(1048576),b''):digest.update(part)
    after=path.stat()
    require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'Locked file changed during hash')
    return digest.hexdigest()

def sync_parent(path):
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def command(runner,w,argv):
    require(not runner.stop_requested,'Stop requested; no new command')
    index=len(runner.commands)
    entry={'index':index,'argv':list(map(str,argv)),'process_started':False,'process_exited':False,
           'remote_release_proven_by_exit':False,'equivalent_bash':shlex.join(list(map(str,argv)))}
    runner.commands.append(entry);runner.event({'event':'command_planned',**entry})
    path=runner.report/f'command-{index:03d}.log'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as log:
        proc=subprocess.Popen(entry['argv'],cwd=runner.root,env=runner.env,stdin=subprocess.DEVNULL,
                              stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        runner.child=proc
        try:
            # Runner signal handlers only mark stop_requested. Logging failures cannot bypass join.
            entry.update(process_started=True,pid=proc.pid)
            runner.event({'event':'command_started',**entry})
            while proc.poll() is None:
                try:proc.wait(timeout=0.2)
                except subprocess.TimeoutExpired:pass
        finally:
            proc.wait();runner.child=None
            entry.update(process_exited=True,returncode=proc.returncode)
    runner.event({'event':'command_exited',**entry})
    require(not runner.stop_requested,'Owned command joined; interrupted, preserve all evidence')
    require(proc.returncode==0,f'Admin command failed; inspect {path}; no automatic retry or restoration')
    return w.regular_bytes(path,2*1024**2).decode('utf-8')

class Acceptance:
    def __init__(self,w,runner,launcher,generator,label,rounds):
        self.w=w;self.runner=runner;self.root=runner.root;self.launcher=launcher;self.generator=generator
        self.label=label;self.rounds=rounds;self.sequence=0;self.baselines={};self.phase_results=[]
        self.claims=[];self.pending_phase=None
        self.initial_status=supervisor(self.root)
        self.identities=[process_identity(self.root,p) for p in self.initial_status['processes']]
        files=list((self.root/'config').iterdir())+[self.root/'cluster.json',self.root/'state/initialized.json',
            self.root/'client/stripe-client.toml']
        files += [self.root/'bin'/name for name in ('admin_cli','storage_main','meta_main','mgmtd_main','fdbserver')]
        files += [self.root/'scripts'/name for name in ('experiment-runner.py','run-cluster.py','generate.py','native-v2.py')]
        self.locks={str(p.relative_to(self.root)):hash_file(w,p) for p in files}

    def save(self,name,value):
        path=self.runner.report/name
        self.w.write_exclusive(path,self.w.json_data(value));sync_parent(path)

    def guard(self):
        require(not any(self.runner.runs.iterdir()),'An EC workload journal appeared during ACK acceptance')
        observed=supervisor(self.root)
        require(observed['run']==self.initial_status['run'],'Supervisor run changed')
        identities=[process_identity(self.root,p) for p in observed['processes']]
        require(identities==self.identities,'PID/starttime/executable/argv changed')
        require({p:hash_file(self.w,self.root/p) for p in self.locks}==self.locks,'Local configuration or binary changed')
        return observed

    def admin(self,parts):
        return command(self.runner,self.w,[self.root/'bin/admin_cli','--cfg',self.root/'config/admin_cli.toml',
                                           '--',self.launcher.admin_command_line(parts)])

    def remote(self,kind,stem):
        path=self.runner.report/(stem+'-remote.toml');require(not path.exists(),'Output already exists')
        output=self.admin(['get-config','-t',kind,'-o',str(path)])
        fields=kv(output,['NodeType','ConfigVersion','ConfigDesc','OutputFile'])
        require(fields['NodeType']==kind and fields['OutputFile']==str(path),'Remote output tuple differs')
        return {'version':integer(fields['ConfigVersion']),'description':fields['ConfigDesc'],
                'sha256':hash_file(self.w,path),'file':str(path)}

    def snapshot(self,kind):
        stem=f'snapshot-{self.sequence:03d}-{kind.lower()}';self.sequence+=1
        role,node=ROLES[kind];self.guard()
        remote=self.remote(kind,stem)
        reported=nodes(self.admin(['list-nodes']))
        require(node in reported and reported[node]['Type']==kind,'Missing expected node')
        row=reported[node]
        identity=next(p for p in self.identities if p['name']==role)
        require(row['pid']==identity['pid'] and row['Status']=='HEARTBEAT_CONNECTED','Wrong/disconnected reported process')
        datetime.datetime.strptime(row['LastHeartbeatTime'],'%Y-%m-%d %H:%M:%S')
        attempt=update(self.admin(['get-last-config-update-record','-n',str(node)]),node)
        path=self.runner.report/(stem+'-live.toml');require(not path.exists(),'Output already exists')
        fields=kv(self.admin(['get-config','-n',str(node),'-o',str(path)]),['NodeId','OutputFile'])
        require(integer(fields['NodeId'])==node and fields['OutputFile']==str(path),'Live configuration tuple differs')
        raw=self.w.regular_bytes(path,4*1024**2);actual=tomllib.loads(raw.decode());shape=typed(actual)
        if kind=='STORAGE':
            pool=actual['server']['coroutines_pool_default']['coroutines_num']
            require(type(pool) is int and pool==128,'Live Storage pool is not 128; stop without restoration')
        if kind not in self.baselines:self.baselines[kind]={'shape':shape,'raw':raw,'file':str(path)}
        require(shape==self.baselines[kind]['shape'],'Full typed live TOML differs from baseline')
        after=self.remote(kind,stem+'-after')
        require(all(remote[k]==after[k] for k in ('version','description','sha256')),'Concurrent remote configuration change')
        guard=self.guard()
        result={'kind':kind,'remote':remote,'node':row,'update':attempt,'live_sha256':hash_file(self.w,path),
                'live_file':str(path),'supervisor_run':guard['run'],'full_live_toml_equals_baseline':True}
        self.save(stem+'.json',result)
        return result

    def pause(self):
        # At least three seconds between observations; a distinct real heartbeat is still required.
        end=time.monotonic()+3
        while time.monotonic()<end:
            require(not self.runner.stop_requested,'Stopped between observations; no further remote mutation')
            time.sleep(min(0.1,max(0,end-time.monotonic())))

    def stable(self,kind,phase,expected,accepted,rejected=False):
        previous=None;observations=[]
        for _ in range(self.rounds):
            self.pause();value=self.snapshot(kind);observations.append(value)
            require(all(value['remote'][k]==expected[k] for k in ('version','description','sha256')),
                    'Remote version/description/content no longer bound to this phase')
            node=value['node'];record=value['update']
            require(node['version']<=expected['version'],'Node reported a newer unexpected version')
            if rejected:require(node['version']==accepted,'Rejected version was acknowledged or baseline changed')
            wanted=53 if rejected else 0
            bound=server_update_version(record['Description'])==expected['version']
            if bound:require(record['code']==wanted,'Unexpected node result for this remote version')
            ready=node['version']==accepted and bound and record['code']==wanted
            if ready:
                require(record['status_name']==('CannotPushConfig' if rejected else 'OK'),'Status name/code mismatch')
                require(node['config_status'] in (None,'UPTODATE','DIRTY'),'Node configuration status FAILED')
                if previous is not None and node['LastHeartbeatTime']>previous['node']['LastHeartbeatTime']:
                    old=previous['update']
                    stable_record=(record['UpdateTime']>old['UpdateTime'] if rejected else record['UpdateTime']==old['UpdateTime'])
                    if stable_record:
                        result={'phase':phase,'kind':kind,'remote':expected,'accepted_version':accepted,
                                'expected_status_code':wanted,'two_distinct_heartbeats':True,
                                'record_time_semantics':'distinct rejection attempts' if rejected else 'unchanged successful attempt',
                                'dirtypresent':any(x['node']['config_status']=='DIRTY' for x in (previous,value)),
                                'last_two_observations':[previous,value],'observation_count':len(observations)}
                        self.phase_results.append(result);self.runner.checked.append(result)
                        self.save(phase+'-confirmed.json',result);return value
                previous=value
            else:previous=None
        raise RuntimeError('No two stable real reports for '+phase+'; preserve remote state and all observations')

    def publish(self,kind,phase,input_path,prior):
        self.pending_phase={'kind':kind,'phase':phase,'input':str(input_path),'sha256':hash_file(self.w,input_path),
                            'description':self.label+'-'+phase,'prior_remote':prior,
                            'dispatch_attempted':False,'outcome':'not-confirmed'}
        self.save(phase+'-intent.json',self.pending_phase)
        before=self.remote(kind,phase+'-preflight')
        require(all(before[k]==prior[k] for k in ('version','description','sha256')),'Another writer changed the remote baseline')
        self.guard()
        self.pending_phase['dispatch_attempted']=True
        output=self.admin(['set-config','-t',kind,'-f',str(input_path),'--desc',self.pending_phase['description']])
        version=integer(kv(output,['ConfigVersion'],succeed=True)['ConfigVersion'])
        require(version==prior['version']+1,'Unexpected version increment; do not retry set-config')
        expected={'version':version,'description':self.pending_phase['description'],'sha256':self.pending_phase['sha256']}
        remote=self.remote(kind,phase+'-committed')
        require(all(remote[k]==expected[k] for k in expected),'Remote readback does not bind exact uploaded content/description')
        self.claims.append({'kind':kind,'phase':phase,**expected});self.save(phase+'-publication.json',self.claims[-1])
        self.pending_phase=None
        return expected

    def execute(self):
        self.save('baseline-locks.json',{'files':self.locks,'processes':self.identities,'supervisor':self.initial_status})
        baseline={}
        for kind in ROLES:
            first=self.snapshot(kind);expected=first['remote']
            self.stable(kind,kind.lower()+'-baseline',expected,expected['version'])
            baseline[kind]=expected
        storage_raw=self.baselines['STORAGE']['raw'];different=tomllib.loads(storage_raw.decode())
        different['server']['coroutines_pool_default']['coroutines_num']=129
        different_bytes=self.generator.to_toml(different).encode()
        check=copy.deepcopy(different);check['server']['coroutines_pool_default']['coroutines_num']=128
        require(typed(check)==self.baselines['STORAGE']['shape'],'Negative input changes more than pool capacity')
        storage_same=self.runner.report/'storage-same.toml';storage_diff=self.runner.report/'storage-different.toml'
        meta_same=self.runner.report/'meta-same.toml'
        for path,data in ((storage_same,b'# Canonically equivalent pinned local values\n'+storage_raw),
                          (storage_diff,different_bytes),(meta_same,b'# Canonically equivalent pinned local values\n'+self.baselines['META']['raw'])):
            self.w.write_exclusive(path,data)
            sync_parent(path)
        same=self.publish('STORAGE','storage-same',storage_same,baseline['STORAGE'])
        self.stable('STORAGE','storage-same',same,same['version'])
        changed=self.publish('STORAGE','storage-different',storage_diff,same)
        self.stable('STORAGE','storage-different',changed,same['version'],rejected=True)
        restored=self.publish('STORAGE','storage-restored',storage_same,changed)
        self.stable('STORAGE','storage-restored',restored,restored['version'])
        meta=self.publish('META','meta-same',meta_same,baseline['META'])
        self.stable('META','meta-same',meta,meta['version'])
        self.guard()

def execute(args):
    require(sys.platform=='linux','Real execution requires Linux/Python 3.11')
    os.umask(0o077);root=Path(args.root).absolute()
    require(root==root.resolve() and root.name.startswith('3fs-ec-native-'),'Canonical native lab root required')
    expected=json.loads((Path(__file__).parent/'ack-expected-scripts.json').read_text())
    for name,digest in expected.items():
        require(hashlib.sha256((root/'scripts'/name).read_bytes()).hexdigest()==digest,
                'Bundled formal script differs from reviewed dependency: '+name)
    sys.path.insert(0,str(root/'scripts'))
    w=module(root/'scripts/experiment-runner.py','ack_formal_runner')
    launcher=module(root/'scripts/run-cluster.py','ack_formal_launcher')
    generator=module(root/'scripts/generate.py','ack_formal_generator')
    w.private_directory(root);require(w.LABEL.fullmatch(args.label),'Invalid label')
    require(4<=args.rounds<=30,'Observation rounds must be 4..30')
    manifest=w.load_json(root/'cluster.json');initial=w.load_json(root/'state/initialized.json');live=supervisor(root)
    require(manifest.get('profile')==PROFILE and type(manifest.get('storage_count')) is int and
            manifest['storage_count']==1 and manifest.get('root')==str(root),
            'Explicit one-Storage GC profile required')
    require(initial.get('run')==live['run'] and initial.get('cluster_id')==manifest.get('cluster_id'),
            'Requires first initialized supervisor run, not a resumed old lab')
    runs=root/'client/runs';require(not runs.exists() or not any(runs.iterdir()),'Run ACK acceptance before EC workload journals')
    admin=tomllib.loads(w.regular_bytes(root/'config/admin_cli.toml',4*1024**2).decode())
    require(admin.get('verbose') is False and admin.get('profile') is False,'Admin output must use the exact nonverbose table contract')
    claim=root/'state/ack-service-acceptance.claim.json'
    w.write_exclusive(claim,w.json_data({'label':args.label,'root':str(root),'supervisor_run':live['run'],
                                      'status':'claimed-not-complete','automatic_resume':False}))
    sync_parent(claim)
    report=root/'client'/('ack-'+args.label)
    runner=w.Runner(root,config=root/'config/admin_cli.toml',report=report)
    acceptance=None;state='failed';error=None
    with runner.signal_scope():
        try:
            acceptance=Acceptance(w,runner,launcher,generator,args.label,args.rounds)
            acceptance.execute();state='passed'
        except BaseException as exc:error=f'{type(exc).__name__}: {exc}'
        finally:
            require(runner.child is None,'Owned administrative child not joined')
            result={'schema':1,'state':state,'error':error,'label':args.label,'root':str(root),
                    'publications':acceptance.claims if acceptance else [],
                    'pending_or_unknown_publication':acceptance.pending_phase if acceptance else None,
                    'confirmed_phases':acceptance.phase_results if acceptance else [],
                    'services_started_stopped_or_signalled':False,'automatic_restoration_on_failure':False,
                    'comparison_policy':'full typed live TOML; see each confirmed phase','performance_validated':False,
                    'callback_and_persist_runtime_counts_measured':False}
            w.write_exclusive(report/'ack-result.json',w.json_data(result))
            sync_parent(report/'ack-result.json')
            runner.summary(state,error)
            sync_parent(report/'result.json')
    print(json.dumps({'state':state,'report':str(report)},ensure_ascii=False))
    return 0 if state=='passed' else 1

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,required=True);p.add_argument('--label',required=True)
    p.add_argument('--rounds',type=int,default=12)
    return execute(p.parse_args())

if __name__=='__main__':sys.exit(main())
