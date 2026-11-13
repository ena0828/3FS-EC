"""Serial OpenEC-only private build; no concurrent build on this experiment host."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
from runtime_common import Owned, sha, new_json, reference_lease

def main():
    p=argparse.ArgumentParser();p.add_argument('--prepared-root',type=Path,required=True)
    p.add_argument('--dependency-prefix',type=Path,required=True)
    p.add_argument('--build-root',type=Path,required=True)
    a=p.parse_args()
    if sys.platform!='linux' or os.uname().machine!='x86_64': raise ValueError('Linux x86-64 required')
    for comm in Path('/proc').glob('[0-9]*/comm'):
        try: name=comm.read_text().strip()
        except OSError: continue
        if name in {'ninja','make','cmake','cc1plus','clang','clang++','rustc','cargo','ld','ld.lld'}:
            raise RuntimeError('another build is active; serial experiments require it to finish')
    if not a.build_root.is_absolute() or a.build_root.exists(): raise ValueError('new absolute build root required')
    source=(a.prepared_root/'source').resolve()
    info=json.loads((a.prepared_root/'prepared.json').read_text())
    if info['project'] != 'openec': raise ValueError('this adapter only builds OpenEC')
    source_entries=[]
    for item in info['sources']:
        path=source/item['relative']
        if sha(path)!=item['sha256']: raise ValueError('prepared source changed '+str(path))
        source_entries.append({'path':str(path),'sha256':item['sha256']})
    prefix=a.dependency_prefix.resolve();inc=prefix/'usr/include';lib=prefix/'usr/lib/x86_64-linux-gnu'
    for name in ('libhiredis.so','libgf_complete.so','libisal.so'):
        if not (lib/name).is_file(): raise ValueError('missing pre-existing private dependency '+name)
    dependency_env={'C_INCLUDE_PATH':str(inc),'CPLUS_INCLUDE_PATH':str(inc),
                    'LIBRARY_PATH':str(lib),'LD_LIBRARY_PATH':str(lib)}
    env=os.environ.copy();env.update(dependency_env)
    a.build_root.mkdir(mode=0o700)
    runner=Owned(a.build_root,env);runner.deadline=time.monotonic()+7200
    result={'schema':1,'project':info['project'],'status':'failed','sources':source_entries,
            'prepared_manifest_sha256':sha(a.prepared_root/'prepared.json'),'dependency_environment':dependency_env,
            'dependency_files':[{'path':str(x),'sha256':sha(x)} for x in sorted(prefix.rglob('*')) if x.is_file()]}
    try:
        runner.command('compiler-version',['/usr/bin/g++','--version'],a.build_root,30)
        runner.command('cmake-version',['/usr/bin/cmake','--version'],a.build_root,30)
        target=a.build_root/'build'
        runner.command('configure',['/usr/bin/cmake','-S',source,'-B',target,'-DFS_TYPE=LOCAL_POSIX','-DCMAKE_BUILD_TYPE=Release',
            '-DCMAKE_C_COMPILER=/usr/bin/gcc','-DCMAKE_CXX_COMPILER=/usr/bin/g++',
            '-DCMAKE_EXE_LINKER_FLAGS=-L'+str(lib)+' -Wl,-rpath,'+str(lib)],a.build_root,300)
        runner.command('build',['/usr/bin/cmake','--build',target,'--target','OECCoordinator','OECAgent','OECClient','-j1'],a.build_root,6500)
        binaries=[target/name for name in ('OECCoordinator','OECAgent','OECClient')]
        result['binaries']=[{'path':str(x),'sha256':sha(x)} for x in binaries]
        for idx,binary in enumerate(binaries):
            runner.command('linked-libraries-'+str(idx),['ldd',binary],a.build_root,30)
        result['build_logs']=[{'path':str(x),'sha256':sha(x)} for x in sorted(a.build_root.glob('*.log'))]
        result['status']='built'
    except BaseException as exc:
        result['error']=f'{type(exc).__name__}: {exc}'
    finally:
        if runner.stop_requested and result['status']=='built':result['status']='interrupted'
        if not runner.stop(): result['status']='failed-cleanup'
        result['events']=runner.events;result['cleanup_errors']=runner.cleanup_errors
        result['stop_requested']=runner.stop_requested;result['stop_signal']=runner.stop_signal
        new_json(a.build_root/'build-record.json',result)
    print(json.dumps({'status':result['status'],'error':result.get('error','')[:512],
                      'build_record_sha256':sha(a.build_root/'build-record.json')}))
    if result['status'] != 'built':
        for name in ('configure.log','build.log'):
            log=a.build_root/name
            if log.is_file():
                with log.open('rb') as stream:
                    stream.seek(max(0,log.stat().st_size-4096))
                    print(json.dumps({'diagnostic_log':name,'tail':stream.read(4096).decode(errors='replace')}))
    return 0 if result['status']=='built' else 1

if __name__=='__main__':
    with reference_lease():sys.exit(main())
