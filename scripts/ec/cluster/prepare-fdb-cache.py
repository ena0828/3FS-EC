#!/usr/bin/env python3
"""Extract locked FDB cache copies; no download, package install or service start."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess


BASE = 'https://github.com/apple/foundationdb/releases/download/7.3.63/'
PACKAGES = (
    {'package': 'foundationdb-clients', 'version': '7.3.63', 'architecture': 'amd64',
     'url': BASE + 'foundationdb-clients_7.3.63-1_amd64.deb', 'size': 70823150,
     'sha256': '4241d43395d74f229b232e3dd2e71a693013db96d4924010cf403ee93119b423'},
    {'package': 'foundationdb-server', 'version': '7.3.63', 'architecture': 'amd64',
     'url': BASE + 'foundationdb-server_7.3.63-1_amd64.deb', 'size': 35342624,
     'sha256': '1591fc02047449db820c0e26131473b1060b0a43d3b73d227f53c478dac7b7e4'},
)


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical_directory(path):
    require(path.is_absolute() and path == path.resolve(strict=True),
            'Directory must be absolute and canonical')
    for part in (path, *path.parents):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and stat.S_ISDIR(info.st_mode),
                'Directory and ancestors must not be links')
    return path


def regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'Package must be a regular file with exactly one link')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def copy_package(cache, downloads, spec):
    # A sidecar is deliberately never opened. Only the reviewed source lock is
    # trusted, and every consumer below receives this exclusive work copy.
    canonical_directory(cache)
    canonical_directory(downloads)
    cached = cache / (spec['sha256'] + '.deb')
    before = cached.lstat()
    regular(before)
    require(before.st_size == spec['size'], 'Cached package size differs from source lock')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_BINARY', 0)
    fd = os.open(cached, flags)
    destination = downloads / (spec['package'] + '.deb')
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        regular(opened)
        require(identity(opened) == identity(before), 'Cached package changed while opening')
        with destination.open('xb') as out:
            total = 0
            while block := source.read(1024 * 1024):
                total += len(block)
                require(total <= spec['size'], 'Cached package grew during copy')
                out.write(block)
        require(identity(os.fstat(source.fileno())) == identity(opened)
                and identity(cached.lstat()) == identity(opened), 'Cached package changed during copy')
    copied = destination.lstat()
    regular(copied)
    actual_sha = digest(destination)
    require(copied.st_size == spec['size'] and total == spec['size']
            and actual_sha == spec['sha256'], 'Work copy differs from locked size/SHA256')
    return {'cache_path': str(cached), 'path': str(destination),
            'size': copied.st_size, 'sha256': actual_sha}


def prepare(source, work, cache):
    roots = [canonical_directory(path) for path in (source, work, cache)]
    for index, left in enumerate(roots):
        for right in roots[index + 1:]:
            require(left != right and left not in right.parents and right not in left.parents,
                    'Source, work and cache must be independent trees')
    bundle = work / 'fdb'
    bundle.mkdir(mode=0o700)  # Exclusive: failed or partial preparations are never resumed.
    for name in ('downloads', 'bin', 'lib', 'fdb-package'):
        (bundle / name).mkdir(mode=0o700)
    packages = []
    for spec in PACKAGES:
        copied = copy_package(cache, bundle / 'downloads', spec)
        output = subprocess.check_output(
            ['/usr/bin/dpkg-deb', '--field', copied['path'], 'Package', 'Version', 'Architecture'], text=True)
        lines = output.splitlines()
        require(len(lines) == 3 and all(': ' in line for line in lines), 'Invalid FDB package metadata')
        metadata = dict(line.split(': ', 1) for line in lines)
        require(metadata == {'Package': spec['package'], 'Version': spec['version'],
                             'Architecture': spec['architecture']}, 'FDB package metadata differs from lock')
        packages.append(dict(spec, **copied, metadata=metadata))
    # Both identities must be verified before either package is extracted.
    for package in packages:
        path = Path(package['path'])
        regular(path.lstat())
        require(path.stat().st_size == package['size'] and digest(path) == package['sha256'],
                'Verified FDB work copy changed before extraction')
        subprocess.run(['/usr/bin/dpkg-deb', '--extract', str(path), str(bundle / 'fdb-package')], check=True)
    record = {'schema': 1, 'status': 'private-packages-extracted-from-verified-cache',
              'source': str(source), 'work': str(work), 'cache_root': str(cache),
              'helper_sha256': digest(Path(__file__).resolve()), 'packages': packages,
              'network_fetch_performed': False, 'system_install_performed': False,
              'package_hooks_executed': False, 'build_executed': False, 'acceptance_executed': False,
              'scope': 'FDB packages only; other build dependencies may still require network access'}
    with (bundle / 'fdb-cache-provenance.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'work', 'cache', 'bundle'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and os.getuid() == os.geteuid() != 0, 'Use the ordinary Linux x86_64 container build user')
    require(args.bundle == args.work / 'fdb', 'FDB bundle must be the fresh build work/fdb')
    require(Path(__file__).resolve() == args.source / 'scripts/ec/cluster/prepare-fdb-cache.py',
            'Use the helper from the checked source')
    info = args.work.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'Build work must be owned and private')
    os.umask(0o077)
    print(json.dumps(prepare(args.source, args.work, args.cache)), flush=True)


if __name__ == '__main__':
    main()
