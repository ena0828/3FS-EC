#!/usr/bin/env python3
"""Prepare seven locked Arrow archives; no extraction, download or native build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat


ARROW_REVISION = 'b7d2f7ffca66c868bd2fce5b3749c6caa002a7f0'
VERSIONS_SHA256 = '2738d2dba6dfe4630ebec78f41e7f667f33c20a6f529f229da5cdebd6578f10a'
# Fail closed if this reviewed component/options closure changes.
PROJECT_CMAKE_SHA256 = '8602b71163982272a9a6d7daaad9846a1d32d5b8debc989ec547437d89bea94b'
MAX_ARCHIVE_BYTES = 1024 ** 3
ARCHIVES = (
    {'name': 'BOOST', 'version': '1.81.0', 'filename': 'boost-1.81.0.tar.gz', 'sha256': '9e0ffae35528c35f90468997bc8d99500bf179cbae355415a89a600c38e13574', 'extension': '.tar.gz'},
    {'name': 'JEMALLOC', 'version': '5.3.0', 'filename': 'jemalloc-5.3.0.tar.bz2', 'sha256': '2db82d1e7119df3e71b7640219b6dfe84789bc0537983c3b7ac4f7189aecfeaa', 'extension': '.tar.bz2'},
    {'name': 'LZ4', 'version': 'v1.9.4', 'filename': 'lz4-v1.9.4.tar.gz', 'sha256': '0b0e3aa07c8c063ddf40b082bdf7e37a1562bda40a0ff5272957f3e987e0e54b', 'extension': '.tar.gz'},
    {'name': 'THRIFT', 'version': '0.16.0', 'filename': 'thrift-0.16.0.tar.gz', 'sha256': 'f460b5c1ca30d8918ff95ea3eb6291b3951cf518553566088f3f2be8981f6209', 'extension': '.tar.gz'},
    {'name': 'XSIMD', 'version': '9.0.1', 'filename': 'xsimd-9.0.1.tar.gz', 'sha256': 'b1bb5f92167fd3a4f25749db0be7e61ed37e0a5d943490f3accdcd2cd2918cc0', 'extension': '.tar.gz'},
    {'name': 'ZLIB', 'version': '1.2.13', 'filename': 'zlib-1.2.13.tar.gz', 'sha256': 'b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30', 'extension': '.tar.gz'},
    {'name': 'ZSTD', 'version': '1.5.5', 'filename': 'zstd-1.5.5.tar.gz', 'sha256': '9c4396cc829cfae319a6e2615202e82aad41372073482fce286fac78646d3ee4', 'extension': '.tar.gz'},
)


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical_directory(path):
    require(path.is_absolute() and path == path.resolve(strict=True), 'Directory must be absolute and canonical')
    for parent in (path, *path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), 'Directory and ancestors must not be links')
    return path


def regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'Archive must be a regular file with exactly one link')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def roots(source, work, cache):
    values = [canonical_directory(path) for path in (source, work, cache)]
    for index, left in enumerate(values):
        for right in values[index + 1:]:
            require(left != right and left not in right.parents and right not in left.parents,
                    'Source, work and cache must be independent trees')
    canonical_directory(work / 'provenance')
    require(digest(source / 'cmake/ApacheArrow.cmake') == PROJECT_CMAKE_SHA256,
            'Arrow project options differ from the reviewed seven-archive closure')


def copy_archive(cache, output, spec):
    cached = cache / (spec['sha256'] + spec['extension'])
    before = cached.lstat()
    regular(before)
    require(0 < before.st_size <= MAX_ARCHIVE_BYTES, 'Archive size is outside the copy bound')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    destination = output / spec['filename']
    with os.fdopen(os.open(cached, flags), 'rb') as source:
        opened = os.fstat(source.fileno())
        regular(opened)
        require(identity(opened) == identity(before), 'Cached archive changed while opening')
        with destination.open('xb') as target:
            total = 0
            while block := source.read(1024 * 1024):
                total += len(block)
                require(total <= before.st_size, 'Cached archive grew during copy')
                target.write(block)
        require(identity(os.fstat(source.fileno())) == identity(opened)
                and identity(cached.lstat()) == identity(opened), 'Cached archive changed during copy')
    copied = destination.lstat()
    regular(copied)
    require(total == copied.st_size == before.st_size and digest(destination) == spec['sha256'],
            'Private archive copy differs from the fixed upstream SHA256')
    return dict(spec, cache_path=str(cached), path=str(destination), size=copied.st_size,
                url=destination.as_uri())


def url_bytes(work):
    return b''.join((work / 'arrow-cache' / spec['filename']).as_uri().encode('utf-8') + b'\0'
                    for spec in ARCHIVES)


def prepare(source, work, cache):
    roots(source, work, cache)
    output = work / 'arrow-cache'
    output.mkdir(mode=0o700)  # Exclusive; failed partial preparations are not reused.
    archives = [copy_archive(cache, output, spec) for spec in ARCHIVES]
    urls = output / 'urls.nul'
    with urls.open('xb') as stream:
        stream.write(url_bytes(work))
    record = {'schema': 1, 'status': 'selected-arrow-archives-prepared', 'source': str(source),
              'work': str(work), 'cache_root': str(cache), 'arrow_revision': ARROW_REVISION,
              'versions_sha256': VERSIONS_SHA256, 'project_cmake_sha256': PROJECT_CMAKE_SHA256,
              'helper_sha256': digest(Path(__file__).resolve()), 'archives': archives,
              'urls_sha256': digest(urls), 'network_fetch_performed': False,
              'extraction_performed': False, 'build_executed': False, 'acceptance_executed': False,
              'scope': 'Only seven archives for the fixed BUNDLED Arrow options; Git, Cargo and other inputs may use network'}
    # No success record before all seven private copies have passed their locks.
    with (work / 'provenance/arrow-cache.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    return record


def verify_preparation(source, work, cache, *, verify_upstream=False):
    roots(source, work, cache)
    output = canonical_directory(work / 'arrow-cache')
    proof = work / 'provenance/arrow-cache.json'
    regular(proof.lstat())
    record = json.loads(proof.read_text(encoding='utf-8'))
    expected = {'schema': 1, 'status': 'selected-arrow-archives-prepared', 'source': str(source),
                'work': str(work), 'cache_root': str(cache), 'arrow_revision': ARROW_REVISION,
                'versions_sha256': VERSIONS_SHA256, 'project_cmake_sha256': PROJECT_CMAKE_SHA256,
                'helper_sha256': digest(Path(__file__).resolve()), 'network_fetch_performed': False,
                'extraction_performed': False, 'build_executed': False, 'acceptance_executed': False}
    require(all(record.get(key) == value for key, value in expected.items()), 'Arrow preparation identity changed')
    rows = record.get('archives')
    require(isinstance(rows, list) and len(rows) == len(ARCHIVES), 'Arrow archive set is incomplete')
    for spec, item in zip(ARCHIVES, rows):
        path = output / spec['filename']
        regular(path.lstat())
        require(item == dict(spec, cache_path=str(cache / (spec['sha256'] + spec['extension'])),
                             path=str(path), size=path.stat().st_size, url=path.as_uri())
                and 0 < path.stat().st_size <= MAX_ARCHIVE_BYTES and digest(path) == spec['sha256'],
                'Prepared Arrow archive or recorded identity changed')
    urls = output / 'urls.nul'
    regular(urls.lstat())
    require(urls.read_bytes() == url_bytes(work) and record.get('urls_sha256') == digest(urls),
            'Arrow environment URL list changed')
    if verify_upstream:
        versions = work / 'build/src/apache-arrow-cpp/cpp/thirdparty/versions.txt'
        regular(versions.lstat())
        require(digest(versions) == VERSIONS_SHA256, 'Actual Arrow version/hash table differs from the fixed lock')
    return {'path': str(proof), 'sha256': digest(proof), 'arrow_revision': ARROW_REVISION,
            'versions_sha256': VERSIONS_SHA256, 'archive_count': len(rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'work', 'cache'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and os.getuid() == os.geteuid() != 0, 'Use the ordinary Linux x86_64 container build user')
    require(Path(__file__).resolve() == args.source / 'scripts/ec/ci/prepare-arrow-cache.py',
            'Use the helper from the checked source')
    info = args.work.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'Build work must be owned and private')
    os.umask(0o077)
    result = (verify_preparation(args.source, args.work, args.cache, verify_upstream=True)
              if args.verify else prepare(args.source, args.work, args.cache))
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
