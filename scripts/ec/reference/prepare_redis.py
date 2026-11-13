"""Download and safely unpack private Redis 7.2.11; no install/build/service action."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
from prepare_reference import extract

URL='https://download.redis.io/releases/redis-7.2.11.tar.gz'
SHA='2f9886eca68d30114ad6a01da65631f8007d802fd3e6c9fac711251e6390323d'

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--archive',type=Path,help='Reuse already downloaded exact archive without network')
    a=p.parse_args()
    if not a.output.is_absolute() or a.output.exists(): raise ValueError('exclusive new absolute output required')
    a.output.mkdir(mode=0o700)
    archive=a.output/'redis-7.2.11.tar.gz'
    source=a.archive.open('rb') if a.archive else urllib.request.urlopen(URL,timeout=60)
    with source,archive.open('xb') as out:
        total=0
        while True:
            chunk=source.read(1048576)
            if not chunk: break
            total+=len(chunk)
            if total>32*1024**2: raise ValueError('download exceeded 32 MiB')
            out.write(chunk)
    actual=hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual!=SHA: raise ValueError('official Redis archive hash mismatch; nothing extracted')
    extract(archive,a.output/'source','redis-7.2.11/')
    (a.output/'provenance.json').write_text(json.dumps({'version':'7.2.11','url':URL,'archive_sha256':actual,
        'hash_source':'https://raw.githubusercontent.com/redis/redis-hashes/master/README',
        'status':'downloaded-and-extracted-not-built','global_install':False},indent=2)+'\n')
    print('After all other builds and experiments stop:')
    print('make -C '+str(a.output/'source')+' -j1 MALLOC=libc BUILD_TLS=no redis-server')

if __name__=='__main__':main()
