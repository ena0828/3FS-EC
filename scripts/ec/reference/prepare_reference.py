"""Extract fixed reference archives and apply isolated patches. Does not compile or start services."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

HERE=Path(__file__).resolve().parent

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def extract(archive, destination, prefix=''):
    destination.mkdir(mode=0o700)
    with tarfile.open(archive) as tar:
        members=tar.getmembers()
        if sum(m.size for m in members)>128*1024**2: raise ValueError('archive exceeds bounded extraction size')
        seen=set()
        for member in members:
            path=PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or '\\' in member.name or not(member.isdir() or member.isfile()):
                raise ValueError('unsupported archive member '+member.name)
            name=member.name
            if prefix:
                if name.rstrip('/')==prefix.rstrip('/'): continue
                if not name.startswith(prefix): raise ValueError('archive prefix mismatch')
                name=name[len(prefix):]
            if not name or name in seen: raise ValueError('duplicate/empty archive member')
            seen.add(name)
            target=destination/name
            if member.isdir(): target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as out: out.write(tar.extractfile(member).read())
                target.chmod(0o700 if member.mode&0o111 else 0o600)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--project',choices=['openec'],required=True)
    p.add_argument('--reference-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not a.output.is_absolute() or a.output.exists(): raise ValueError('exclusive new absolute output required')
    locks=json.loads((HERE/'inputs.json').read_text())
    cfg=locks[a.project]
    archive=a.reference_root/cfg['archive']
    if sha(archive)!=cfg['archive_sha256']: raise ValueError('fixed archive SHA mismatch')
    for item in cfg['patches']:
        if sha(HERE/item['path'])!=item['sha256']: raise ValueError('patch SHA mismatch')
    a.output.mkdir(mode=0o700)
    source=a.output/'source'
    extract(archive,source,cfg['prefix'])
    env=os.environ.copy()
    for key in list(env):
        if key.startswith('GIT_'): del env[key]
    commands=[]
    for item in cfg['patches']:
        patch=HERE/item['path']
        for check in (True,False):
            argv=['git','-c','core.autocrlf=false','apply']+(['--check'] if check else [])+[str(patch)]
            result=subprocess.run(argv,cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            commands.append({'argv':argv,'returncode':result.returncode,'output':result.stdout})
            if result.returncode: raise RuntimeError('patch rejected; preserve failed directory for inspection')
        for item2 in item['after']:
            if sha(source/item2['path'])!=item2['sha256']: raise ValueError('applied source byte mismatch')
    entries=[{'relative':str(x.relative_to(source)).replace('\\','/'),'sha256':sha(x)}
             for x in sorted(source.rglob('*')) if x.is_file()]
    with (a.output/'prepared.json').open('x') as f:
        json.dump({'schema':1,'status':'prepared-not-built','project':a.project,'original_commit':cfg['commit'],
                   'archive_sha256':cfg['archive_sha256'],'patches':cfg['patches'],'sources':entries,
                   'commands':commands},f,indent=2);f.write('\n')

if __name__=='__main__': main()
