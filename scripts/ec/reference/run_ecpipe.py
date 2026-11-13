"""Reference-only ECPipe basicSingle runtime. This is not an integrated 3FS module."""
import argparse
import json
import os
from pathlib import Path
import sys
from runtime_common import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-record',type=Path,required=True)
    parser.add_argument('--redis-server',type=Path,required=True)
    parser.add_argument('--run-root',type=Path,required=True)
    parser.add_argument('--loopback-octet',type=int,default=92)
    args = parser.parse_args()
    build,binaries = check_build(args.build_record,'ecpipe')
    root = args.run_root
    addresses,host = preflight(root,args.loopback_octet,args.redis_server)
    environment = os.environ.copy(); environment.update(build['dependency_environment'])
    runner = Owned(root,environment)
    result = dict(schema=1,status='failed',project='ecpipe',profile='standalone/basicSingle',
                  build_record_sha256=sha(args.build_record),host=host,checks=[],performance_measurement=False)
    try:
        _,data_first = data_and_shards()
        shards = data_first[10:]+data_first[:10]
        matrix = root/'rs-12-10.txt'
        row = []; v=1
        for _ in range(10): row.append(v); v=mul(v,2)
        matrix.write_text(' '.join(['1']*10)+'\n'+' '.join(map(str,row))+'\n')
        stripe = root/'stripes'; stripe.mkdir(mode=0o700)
        text = ':'.join(f'blk{i}_0' for i in range(12))+'\n'
        for i in range(12): (stripe/f'meta:blk{i}_0').write_text(text)
        roles=[]; paths=[]
        for idx,address in enumerate(addresses):
            role=root/f'role-{idx:02d}'; role.mkdir(mode=0o700);roles.append(role)
            blocks=role/'blocks';blocks.mkdir(mode=0o700)
            if idx:
                path=blocks/f'blk{idx-1}';path.write_bytes(shards[idx-1]);paths.append(path)
            xml_config(role/'conf/config.xml',{
                'erasure.code.k':10,'erasure.code.n':12,'rs.code.config.file':str(matrix),
                'packet.size':PACKET,'packet.count':PACKETS_PER_SHARD,'packet.skipsize':0,
                'helper.worker.thread.num':1,'degraded.read.policy':'ecpipe','ecpipe.policy':'basicSingle',
                'file.system.type':'standalone','stripe.store':str(stripe),'block.directory':str(blocks),
                'coordinator.address':addresses[0],'local.ip.address':address,
                'helpers.address':['default/'+ip for ip in addresses[1:]],
                'path.selection.enabled':'false','rack.aware.enable':'false',
                'rack.load.balance':'false','multi.stripe.scheduling':'false','push.pipeline.opt':'false'})
        result['checks'].append({'stage':'all-original-blocks','files':[verify(p,x) for p,x in zip(paths,shards)]})
        result['oracle']={'polynomial':'0x11d','order':'parity0,parity1,data0..9','packet_bytes':PACKET,
                          'packets_per_shard':PACKETS_PER_SHARD,'matrix_sha256':sha(matrix)}
        runner.redis(args.redis_server,addresses)
        runner.start('coordinator',[binaries['ECCoordinator']],roles[0])
        for idx in range(1,13): runner.start(f'helper-{idx:02d}',[binaries['ECHelper']],roles[idx])
        # Metadata initialization consumes actual reports of all 12 files before this request loop.
        # Removing a block before startup would leave the original metadata constructor waiting.
        runner.wait_for('metadata reports consumed and request loop entered',
                        lambda:log_contains(root,'coordinator','waiting for requests ...'),60)
        runner.require_empty_redis(addresses,'after-real-block-reports-before-fault')
        quarantine=root/'quarantine';quarantine.mkdir(mode=0o700)
        target=2  # data0 in ECPipe's parity-first matrix; requestor is its existing holder.
        paths[target].rename(quarantine/paths[target].name)
        offsets={f'helper-{i:02d}':(root/f'helper-{i:02d}.log').stat().st_size for i in range(1,13)}
        runner.event('fault',kind='one-block-renamed',path=str(paths[target]),helper_process_still_running=True)
        result['redis_before_repair']=runner.stats(addresses)
        runner.command('client-repair',[binaries['ECPipeClient'],f'blk{target}'],roles[target+1])
        output=roles[target+1]/'testfileOut'
        result['checks'].append({'stage':'decoded-client-file',**verify(output,shards[target])})
        if paths[target].exists(): raise RuntimeError('unexpected in-place repair; upstream client should write testfileOut')
        def completed_helpers():
            return [name for name,offset in offsets.items() if log_contains(root,name,'send key:',offset)]
        runner.wait_for('10 actual helper completions',lambda:len(completed_helpers())==10,30)
        participants=completed_helpers()
        result['actual_helper_completions']=participants
        runner.require_empty_redis(addresses,'after-unique-client-repair')
        result['checks'].append({'stage':'healthy-blocks-unchanged',
                                'files':[verify(p,x) for i,(p,x) in enumerate(zip(paths,shards)) if i != target]})
        result['redis_after_repair']=runner.stats(addresses)
        result['output_is_original_block_replacement']=False
        runner.alive()  # No persistent process may have exited before success.
        result['status']='passed-functional-runtime'
    except BaseException as exc:
        result['error']=f'{type(exc).__name__}: {exc}'
    finally:
        if runner.stop_requested and result['status']=='passed-functional-runtime':result['status']='interrupted'
        if not runner.stop(): result['status']='failed-cleanup'
        result['cleanup_errors']=runner.cleanup_errors;result['events']=runner.events
        result['stop_requested']=runner.stop_requested;result['stop_signal']=runner.stop_signal
        result['logs']=[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(root.glob('*.log'))]
        new_json(root/'result.json',result)
    print(json.dumps({'status':result['status'],'result':str(root/'result.json')}))
    return 0 if result['status']=='passed-functional-runtime' else 1

if __name__=='__main__':
    with reference_lease():sys.exit(main())
