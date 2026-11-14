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
import uuid

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

def command(runner,w,argv,*,pass_fds=()):
    require(not runner.stop_requested,'Stop requested; no new command')
    local_export=False
    if pass_fds:
        if runner.transport_role=='file':
            local_export=validate_leased_file_command(runner,argv)
        else:
            require(runner.transport_role=='control' and len(argv)==5 and
                    list(map(str,argv[:4]))==[str(runner.root/'bin/admin_cli'),'--cfg',str(runner.config),'--'],
                    'An inherited collector lease requires the original control CLI and configuration')
    namespace_control=(runner.transport_role=='file' and argv and
                       argv[-1] in ('mode4-unlink','mode4-resume-unlink','mode4-inspect-unlink'))
    if namespace_control and not pass_fds:
        validate_leased_file_command(runner,argv)
    binding=runner.check_transport()
    if namespace_control:
        # This facade sends only the fixed Meta Remove request. A configured
        # RDMA profile must not turn namespace acknowledgement into data I/O.
        kind='local_namespace_inspect' if argv[-1]=='mode4-inspect-unlink' else 'namespace_control'
        return _owned_command(runner,w,argv,None,kind=kind,pass_fds=pass_fds)
    if local_export:
        # Read-only journal export still verifies the prepared profile. It does
        # not send data RPCs or create a transport sidecar for the journal.
        return _owned_command(runner,w,argv,None,kind='local_read_export',pass_fds=pass_fds)
    if binding is not None:
        # This shared child owner also runs the formal file acceptance driver.
        # Control-only admin calls have no data-transport claim.
        require(runner.transport_role=='file' and str(argv[0])==str(runner.root/'bin/ec_file_cli'),
                'Prepared file transport requires the original native executable path')
        configs=[str(arg) for arg in argv if str(arg).startswith('--cfg=')]
        modes=[str(arg) for arg in argv if str(arg).startswith('--config.storage_transport=')]
        runs=[str(arg).split('=',1)[1] for arg in argv if str(arg).startswith('--config.run_dir=')]
        require(configs==['--cfg='+str(runner.config)] and modes==['--config.storage_transport=rdma'] and len(runs)==1,
                'File command transport/config/run differs from prepared selection')
        w.bind_transport_run(runner.root,Path(runs[0]),binding,[str(argv[0])])
    return _owned_command(runner,w,argv,binding,pass_fds=pass_fds)


def validate_leased_file_command(runner,argv):
    """Narrow trace-lease handoff; never an arbitrary executable permission."""
    require(type(argv) is list and all(type(x) is str for x in argv) and len(argv)>=4,
            'Leased file command must be an explicit argument list')
    require(argv[:2]==[str(runner.root/'bin/ec_file_cli'),'--cfg='+str(runner.config)] and
            runner.config==runner.root/'client/file-client.toml', 'Leased file executable/config differs')
    common={'run_dir'}
    fields={
        'create':{'file_path','shard_bytes','permission','session_rights'},
        'resume-open':set(), 'close':set(),
        'unlink':{'session_run_dir','file_path'}, 'resume-unlink':set(), 'inspect-unlink':set(),
        'pwrite':{'session_run_dir','offset_decimal','input_file'}, 'resume':set(), 'query':set(),
        'read':{'session_run_dir','offset_decimal','length_decimal','output_file'},
        'resume-read':{'output_file'}, 'release-read':set(),
        'export-read-allocations':{'output_file'},
        'repair':{'session_run_dir','repair_stripe_decimal','repair_mask_decimal','repair_source_order',
                  'repair_mode','repair_window_decimal','repair_delivery'},
        'resume-repair':set(), 'query-repair':set(), 'close-repair-debt':set(),
        'truncate':{'session_run_dir','length_decimal'}, 'resume-truncate':set(),
        'query-truncate':set(), 'close-truncate-debt':set()}
    require(argv[-1].startswith('mode4-') and argv[-1][6:] in fields, 'Leased file operation is not supported')
    action=argv[-1][6:]; values={}
    for arg in argv[2:-1]:
        require(arg.startswith('--config.') and '=' in arg,'Unexpected leased file argument')
        key,value=arg[9:].split('=',1)
        require(key not in values and value!='','Duplicate/empty leased file argument')
        values[key]=value
    optional={'storage_transport','deadline_seconds','max_application_bytes'}
    if action=='repair':optional.add('repair_delivery')
    required=common|fields[action]
    if action=='repair':required=required-{'repair_delivery'}
    require(required<=values.keys() and values.keys()<=required|optional,'Leased file argument set differs')
    require(values.get('storage_transport','tcp') in ('tcp','rdma'),'Invalid leased transport')
    for key in ('run_dir','session_run_dir','input_file','output_file'):
        if key in values:
            path=Path(values[key])
            require(path.is_absolute() and path==path.resolve(),'Leased file paths must be canonical absolute paths')
    return action=='export-read-allocations'


def validate_collector_command(root,argv,*,expected_executable=None):
    """Read-only validation; an evidence reader can pin the original interpreter."""
    root=Path(root)
    executable=sys.executable if expected_executable is None else expected_executable
    require(type(executable) is str and bool(executable) and root.is_absolute() and root==root.resolve(),
            'Invalid fixed collector interpreter/root')
    require(type(argv) is list and all(type(x) is str for x in argv) and len(argv) in (8,10,14),
            'Invalid collector command shape')
    require(argv[:3]==[executable,'-B',str(root/'scripts/tree-gc-runner.py')] and
            argv[3] in ('start','resume') and argv[4:6]==['--root',str(root)] and argv[6]=='--run-dir',
            'Collector executable/root/operation differs')
    require((argv[3]=='start' and len(argv) in (10,14) and argv[8]=='--expected') or
            (argv[3]=='resume' and len(argv)==8),'Collector start/resume arguments differ')
    limits=None
    if argv[3]=='start':
        limits={'nodes':256,'commands':8192}
        if len(argv)==14:
            require(argv[10]=='--max-nodes' and argv[12]=='--max-commands','Collector limit fields differ')
            for field,raw,maximum in (('nodes',argv[11],4096),('commands',argv[13],16384)):
                require(re.fullmatch('[1-9][0-9]{0,4}',raw) is not None and int(raw)<=maximum,
                        'Collector limit out of bounds')
                limits[field]=int(raw)
    for raw in (argv[7],*([argv[9]] if len(argv)>=10 else [])):
        path=Path(raw)
        require(path.is_absolute() and path==path.resolve(),'Collector paths must be canonical absolute paths')
    return {'action':argv[3],'run_dir':argv[7], 'expected':argv[9] if len(argv)>=10 else None, 'limits':limits}


def collector_command(runner,w,argv,*,pass_fds):
    """Only the existing object collector may inherit a trace-level lease."""
    require(not runner.stop_requested and runner.transport_role=='control','Stopped or non-control collector owner')
    validate_collector_command(runner.root,argv)
    require(len(checked_pass_fds(pass_fds))==1,'Collector child requires the inherited trace lease')
    require(runner.check_transport() is None,'Collector unexpectedly claims data transport')
    return _owned_command(runner,w,argv,None,kind='tree_gc_collector',pass_fds=pass_fds)


def validate_supervisor_command(root,argv,*,expected_executable=None):
    """Read-only grammar; a receipt reader may pin the original owned interpreter."""
    executable=sys.executable if expected_executable is None else expected_executable
    require(type(executable) is str and bool(executable),'Missing expected supervisor interpreter')
    root=Path(root)
    script=root/'scripts/native-v2.py'
    require(root.is_absolute() and root==root.resolve() and script==script.resolve(),
            'Supervisor command requires the original canonical bundle paths')
    require(type(argv) is list and all(type(value) is str for value in argv) and len(argv)>=5,
            'Supervisor command requires an exact string argument list')
    operation=argv[2]
    require(operation in ('status','fault-storage','restart-storage','replace-placement','action-status') and
            argv[:2]==[executable,str(script)] and argv[3:5]==['--root',str(root)],
            'Supervisor executable/path/operation/root differs')
    if operation=='status':
        require(len(argv)==5,'Status does not accept action or launch arguments')
        return {'operation':operation}
    require(len(argv)==(9 if operation=='action-status' else 13) and
            argv[5]=='--run' and argv[7]=='--action-id', 'Supervisor action argument shape differs')
    run,action_id=argv[6],argv[8]
    require(bool(run) and len(run)<=128 and all(32<=ord(char)<127 for char in run),
            'Supervisor run identity is invalid')
    require(str(uuid.UUID(action_id))==action_id and uuid.UUID(action_id).int!=0,
            'Supervisor action requires the original nonzero canonical UUID')
    request={'operation':operation,'run':run,'action_id':action_id}
    if operation=='action-status':
        return request
    require(argv[11:]==['--wait-seconds','600'],'Supervisor action wait bound differs')
    key='replacements' if operation=='replace-placement' else 'nodes'
    require(argv[9]==('--replace' if key=='replacements' else '--nodes'), 'Supervisor selection flag differs')
    parts=argv[10].split(',')
    require(1<=len(parts)<=2,'Supervisor action needs one or two selections')
    if key=='nodes':
        require(all(re.fullmatch(r'[1-9][0-9]*',part) for part in parts),'Invalid exact Storage node')
        nodes=list(map(int,parts))
        require(len(set(nodes))==len(nodes) and all(10001<=node<=10014 for node in nodes),
                'Supervisor action node is outside the prepared spare topology')
        request[key]=nodes
    else:
        require(all(re.fullmatch(r'[1-9][0-9]*:[1-9][0-9]*',part) for part in parts),'Invalid exact replacement pair')
        pairs=[list(map(int,part.split(':'))) for part in parts]
        require(len({pair[0] for pair in pairs})==len(pairs) and len({pair[1] for pair in pairs})==len(pairs) and
                all(10001<=old<=10014 and new in (10013,10014) and old!=new for old,new in pairs),
                'Supervisor replacement is outside the prepared spare topology')
        request[key]=pairs
    return request


def supervisor_command(runner,w,argv,*,operation,run=None,action=None):
    require(not runner.stop_requested,'Stop requested; no new command')
    binding=runner.check_transport()
    actual=validate_supervisor_command(runner.root,argv)
    if operation=='status':
        require(run is None and action is None and actual=={'operation':'status'},'Status cannot change an action')
    else:
        require(type(action) is dict and type(run) is str and action.get('run')==run,
                'Supervisor action differs from the fixed live run')
        original=action.get('operation')
        require(original in ('fault-storage','restart-storage','replace-placement'), 'Unknown fixed action')
        key='replacements' if original=='replace-placement' else 'nodes'
        require(set(action)=={'operation','run','action_id',key},'Fixed action fields differ')
        expected=({'operation':'action-status','run':run,'action_id':action['action_id']}
                  if operation=='action-status' else action)
        require((operation=='action-status' or operation==original) and typed(actual)==typed(expected),
                'Supervisor command differs from the original action')
    return _owned_command(runner,w,argv,None,kind='supervisor_control' if binding is not None else None)


def checked_pass_fds(value):
    require(type(value) is tuple and len(value)<=1,'At most one explicit collector lease descriptor is supported')
    if value:
        require(sys.platform=='linux' and type(value[0]) is int and value[0]>2,
                'Collector lease inheritance requires a Linux descriptor above standard streams')
        info=os.fstat(value[0])
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and
                not info.st_mode&0o077 and info.st_nlink==1,
                'Collector lease must be a private single-link regular file owned by this user')
    return value


def _owned_command(runner,w,argv,binding,*,kind=None,pass_fds=()):
    inherited=checked_pass_fds(pass_fds)
    index=len(runner.commands)
    entry={'index':index,'argv':list(map(str,argv)),'process_started':False,'process_exited':False,
           'remote_release_proven_by_exit':False,'equivalent_bash':shlex.join(list(map(str,argv)))}
    if binding is not None:entry['transport']=binding
    if kind is not None:entry['kind']=kind
    if inherited:entry['inherited_collector_lease']=True
    runner.commands.append(entry);runner.event({'event':'command_planned',**entry})
    path=runner.report/f'command-{index:03d}.log'
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as log:
        # The caller owns the flock and only closes its descriptor after this
        # join. Inheritance also retains that lock if the caller is killed.
        # Reacquiring it is not a remote-drain or prior-manager-join receipt.
        inherited_options={'pass_fds':inherited} if inherited else {}
        proc=subprocess.Popen(entry['argv'],cwd=runner.root,env=runner.env,stdin=subprocess.DEVNULL,
                              stdout=log,stderr=subprocess.STDOUT,start_new_session=True,**inherited_options)
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
