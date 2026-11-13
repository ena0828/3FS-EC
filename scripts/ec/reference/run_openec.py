"""Actual OpenEC coordinator/12-agent functional acceptance; requires separately built candidates."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from runtime_common import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-record', type=Path, required=True)
    parser.add_argument('--redis-server', type=Path, required=True)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--loopback-octet', type=int, default=91)
    parser.add_argument('--code', choices=['RSPIPE','RSCONV'], default='RSPIPE')
    args = parser.parse_args()
    build, binaries = check_build(args.build_record, 'openec')
    root = args.run_root
    addresses, host = preflight(root,args.loopback_octet,args.redis_server)
    environment = os.environ.copy()
    environment.update(build['dependency_environment'])
    runner = Owned(root,environment)
    result = dict(schema=1, status='failed', project='openec', code=args.code, profile='posix-shared-namespace',
                  build_record_sha256=sha(args.build_record), host=host, checks=[], performance_measurement=False)
    try:
        objects = root/'objects'; objects.mkdir(mode=0o700)
        quarantined = root/'quarantine'; quarantined.mkdir(mode=0o700)
        roles = []
        for idx,address in enumerate(addresses):
            role = root/f'role-{idx:02d}'; role.mkdir(mode=0o700); roles.append(role)
            xml_config(role/'conf/sysSetting.xml', {
                'controller.addr':addresses[0], 'agents.addr':['/default/'+ip for ip in addresses[1:]],
                'oec.controller.thread.num':2, 'oec.agent.thread.num':4, 'oec.cmddist.thread.num':2,
                'ec.concurrent.num':1, 'local.addr':address, 'packet.size':PACKET,
                'dss.type':'LOCAL_POSIX', 'dss.parameter':str(objects)},
                {'ec.policy':[{'ecid':'rs_12_10','class':args.code,'n':12,'k':10,'w':1,'opt':-1}]})
        data,shards = data_and_shards()
        input_path = root/'input.bin'; input_path.write_bytes(data)
        result['input'] = verify(input_path,data)
        result['oracle'] = {'polynomial':'0x11d','matrix':'I10 + Vandermonde bases 1,2','order':'data0..9,parity0..1',
                            'packet_bytes':PACKET, 'packets_per_shard':PACKETS_PER_SHARD,
                            'seed':'3fs-ec-reference-runtime-v1-fixed-input'}
        runner.redis(args.redis_server,addresses)
        for idx in range(1,13):
            name = f'agent-{idx:02d}'
            runner.start(name,[binaries['OECAgent']],roles[idx])
            runner.wait_for(name+' ready',lambda n=name:log_contains(root,n,'OECAgent started'),30)
        runner.start('coordinator',[binaries['OECCoordinator']],roles[0])
        runner.wait_for('coordinator ready',lambda:log_contains(root,'coordinator','OECCoordinator started'),30)
        client = binaries['OECClient']; client_cwd = roles[1]
        def client_data_command(name,argv):
            # This marker is shared by four workers: activity is not a request-correlated
            # completion or distributed drain proof. Separate byte and repair checks follow.
            marker=b'OECWorker::doProcess\n'
            previous=(root/'agent-01.log').read_bytes().count(marker)
            runner.command(name,argv,client_cwd)
            runner.wait_for(name+' agent command-loop activity observed',
                            lambda:(root/'agent-01.log').read_bytes().count(marker)>previous,30)
        runner.require_empty_redis(addresses,'before-first-write')
        client_data_command('write',[client,'write',input_path,'/runtime_object','rs_12_10','online','10'])
        paths = [objects/f'runtime_object_oecobj_{i}' for i in range(12)]
        result['checks'].append({'stage':'all-original-objects','files':[verify(p,x) for p,x in zip(paths,shards)]})
        healthy = root/'healthy.bin'
        client_data_command('read-healthy',[client,'read','/runtime_object',healthy])
        result['checks'].append({'stage':'healthy-read',**verify(healthy,data)})
        runner.require_empty_redis(addresses,'before-file-fault')
        paths[0].rename(quarantined/paths[0].name)
        if paths[0].exists(): raise RuntimeError('fault injection did not remove the selected data object')
        runner.event('fault',kind='one-physical-file-renamed',path=str(paths[0]),storage_process_still_running=True)
        degraded = root/'degraded.bin'
        client_data_command('read-degraded',[client,'read','/runtime_object',degraded])
        result['checks'].append({'stage':'degraded-read',**verify(degraded,data)})
        if paths[0].exists(): raise RuntimeError('unexpected repair before explicit startRepair')
        runner.require_empty_redis(addresses,'before-unique-repair')
        offsets = {f'agent-{i:02d}':(root/f'agent-{i:02d}.log').stat().st_size for i in range(1,13)}
        coordinator_offset = (root/'coordinator.log').stat().st_size
        result['redis_before_repair'] = runner.stats(addresses)
        runner.command('start-repair',[client,'startRepair'],client_cwd)
        completion = 'Coordinator::repair for /runtime_object_oecobj_0 finishes'
        def repaired():
            return (paths[0].is_file() and paths[0].stat().st_size == SHARD and
                    log_contains(root,'coordinator',completion,coordinator_offset))
        runner.wait_for('physical object plus coordinator repair completion',repaired,180)
        result['checks'].append({'stage':'all-postrepair-objects','files':[verify(p,x) for p,x in zip(paths,shards)]})
        participants = []
        persistence = []
        for name,offset in offsets.items():
            with (root/(name+'.log')).open('rb') as stream:
                stream.seek(offset); text = stream.read().decode(errors='replace')
            if re.search(r'receive a request of type [37]\b',text): participants.append(name)
            if re.search(r'receive a request of type 5\b',text): persistence.append(name)
        if len(participants) < (2 if args.code == 'RSPIPE' else 1) or not persistence:
            raise RuntimeError('missing actual helper compute/persist dispatch evidence')
        result['helper_compute_participants'] = participants
        result['helper_persist_participants'] = persistence
        runner.require_empty_redis(addresses,'after-repair-ack-consumed')
        final = root/'after-repair.bin'
        client_data_command('read-after-repair',[client,'read','/runtime_object',final])
        result['checks'].append({'stage':'postrepair-read',**verify(final,data)})
        runner.require_empty_redis(addresses,'after-final-read')
        result['redis_after_repair'] = runner.stats(addresses)
        runner.alive()
        result['status'] = 'passed-functional-runtime'
    except BaseException as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        if runner.stop_requested and result['status']=='passed-functional-runtime':result['status']='interrupted'
        if not runner.stop(): result['status'] = 'failed-cleanup'
        result['cleanup_errors'] = runner.cleanup_errors
        result['stop_requested'] = runner.stop_requested
        result['stop_signal'] = runner.stop_signal
        result['events'] = runner.events
        result['logs'] = [{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(root.glob('*.log'))]
        new_json(root/'result.json',result)
    print(json.dumps({'status':result['status'],'result':str(root/'result.json')}))
    return 0 if result['status'] == 'passed-functional-runtime' else 1

if __name__ == '__main__':
    with reference_lease():sys.exit(main())
