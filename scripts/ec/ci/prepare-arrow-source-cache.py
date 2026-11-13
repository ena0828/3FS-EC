#!/usr/bin/env python3
"""Prepare a fixed Arrow shallow source snapshot from a complete tree/object pack."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess


REVISION = 'b7d2f7ffca66c868bd2fce5b3749c6caa002a7f0'
EXPECTED_TREE = '3788349ce2bb6e195cb979d5646a1a7e14731189'
VERSIONS_SHA256 = '2738d2dba6dfe4630ebec78f41e7f667f33c20a6f529f229da5cdebd6578f10a'
ORIGIN = 'https://github.com/apache/arrow.git'
GITLINKS = {'cpp/submodules/parquet-testing': 'b2e7cc755159196e3a068c8594f7acbaecfdaaac',
            'testing': '47f7b56b25683202c1fd957668e13f2abafc0f12'}
GIT = '/usr/bin/git'
_spec = importlib.util.spec_from_file_location('arrow_source_copy', Path(__file__).with_name('prepare-libfuse-cache.py'))
_copy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_copy)
require, digest, regular, canonical_directory = _copy.require, _copy.digest, _copy.regular, _copy.canonical_directory


def roots(source, work, pack):
    values = [canonical_directory(path) for path in (source, work, pack.parent)]
    for index, left in enumerate(values):
        require(not any(char in str(left) for char in (';', '\n', '\r')), 'CMake source path is not representable')
        for right in values[index + 1:]:
            require(left != right and left not in right.parents and right not in left.parents,
                    'Source, work and pack cache must be independent trees')
    canonical_directory(work / 'provenance')


def git_runner(checkout, audit, log=None):
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(audit / 'empty-git-config'),
                       GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', LC_ALL='C')

    def git(*arguments, stdin=None):
        argv = [GIT, '-c', 'protocol.allow=never', '-c', 'submodule.recurse=false',
                '-c', 'core.autocrlf=false', '-c', 'gc.auto=0',
                '-c', 'core.hooksPath=' + str(audit / 'empty-template'),
                '-c', 'core.attributesFile=' + str(audit / 'empty-git-config'),
                '-C', str(checkout), *arguments]
        result = subprocess.run(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment)
        if log is not None:
            row = {'argv': argv, 'exitcode': result.returncode,
                   'stdout_bytes': len(result.stdout), 'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                   'stderr_bytes': len(result.stderr), 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}
            log.write(json.dumps(row) + '\n')
            log.flush()
        require(result.returncode == 0, 'Arrow source Git step failed: ' + ' '.join(arguments))
        return result.stdout
    return git


def verify_objects(git, checkout, *, prepared):
    # This is intentionally a shallow snapshot, never a rewritten root commit or
    # a claim to have verified upstream history. Only the fixed boundary is allowed.
    canonical_directory(checkout / '.git')
    canonical_directory(checkout / '.git/objects')
    regular((checkout / '.git/shallow').lstat())
    require((checkout / '.git/shallow').read_bytes() == (REVISION + '\n').encode(),
            'Arrow shallow boundary changed')
    require(not os.path.lexists(checkout / '.git/objects/info/alternates'), 'Object alternates rejected')
    require(not git('for-each-ref', '--format=%(refname)', 'refs/replace/'), 'Replace objects rejected')
    require(git('rev-parse', '--is-shallow-repository').strip() == b'true', 'Expected explicit shallow snapshot')
    require(git('cat-file', '-t', REVISION).strip() == b'commit', 'Fixed Arrow object is not a commit')
    require(git('rev-parse', REVISION + '^{tree}').decode().strip() == EXPECTED_TREE, 'Arrow tree differs from lock')
    objects = {REVISION, EXPECTED_TREE}
    gitlinks = {}
    for entry in filter(None, git('ls-tree', '-r', '-t', '-z', REVISION).split(b'\0')):
        info, path = entry.split(b'\t', 1)
        mode, kind, oid = info.decode('ascii').split()
        if mode == '160000':
            gitlinks[path.decode('utf-8')] = oid
        else:
            require(mode in ('040000', '100644', '100755', '120000') and kind in ('tree', 'blob'),
                    'Unexpected Arrow tree entry')
            objects.add(oid)
    require(gitlinks == GITLINKS, 'Arrow gitlink set differs; submodules must remain uninitialized')
    actual = set(git('cat-file', '--batch-all-objects', '--batch-check=%(objectname)').decode().splitlines())
    require(actual == objects, 'Pack must contain exactly the fixed commit and complete current tree/blob closure')
    git('fsck', '--full', '--strict', '--no-reflogs', REVISION)
    if prepared:
        require(git('rev-parse', 'HEAD').decode().strip() == REVISION, 'Prepared Arrow HEAD changed')
        git('diff', '--exit-code', 'HEAD', '--ignore-submodules=none')
        for path in GITLINKS:
            child = checkout / path
            require(not child.exists() or (child.is_dir() and not any(child.iterdir())),
                    'Arrow test submodule was unexpectedly populated')
        versions = checkout / 'cpp/thirdparty/versions.txt'
        regular(versions.lstat())
        require(digest(versions) == VERSIONS_SHA256, 'Arrow version/hash table differs')
        require(git('remote', 'get-url', 'origin').decode().strip() == ORIGIN, 'Arrow original origin changed')
    return len(objects)


def prepare(source, work, pack, expected_sha256):
    roots(source, work, pack)
    audit = work / 'arrow-source-cache'
    build = work / 'build'
    require(not os.path.lexists(build), 'Prepared Arrow requires a fresh build directory')
    audit.mkdir(mode=0o700)  # Failed preparations remain exclusive; no adoption.
    copied = _copy.copy_bundle(pack, audit / 'input.pack', expected_sha256)
    (audit / 'empty-template').mkdir(mode=0o700)
    (audit / 'empty-git-config').touch(exist_ok=False)
    checkout = build / 'src/apache-arrow-cpp'
    checkout.mkdir(mode=0o700, parents=True)
    with (audit / 'commands.jsonl').open('x', encoding='utf-8') as log:
        git = git_runner(checkout, audit, log)
        git('init', '-q', '--template=' + str(audit / 'empty-template'))
        with (checkout / '.git/shallow').open('x', encoding='ascii', newline='\n') as stream:
            stream.write(REVISION + '\n')
        # No --fix-thin: every delta base must be contained in this input pack.
        with (audit / 'input.pack').open('rb') as stream:
            git('index-pack', '--stdin', '--strict', stdin=stream)
        object_count = verify_objects(git, checkout, prepared=False)
        git('checkout', '--detach', REVISION)
        git('remote', 'add', 'origin', ORIGIN)
        verify_objects(git, checkout, prepared=True)
        require(not git('status', '--porcelain=v1', '--untracked-files=all', '--ignored=matching'),
                'New Arrow source checkout is not clean')
    require(digest(audit / 'input.pack') == copied['actual_sha256'], 'Source pack copy changed during preparation')
    record = {'schema': 1, 'status': 'fixed-arrow-shallow-source-prepared', 'source': str(source),
              'work': str(work), 'checkout': str(checkout), 'original_remote': ORIGIN,
              'revision': REVISION, 'tree': EXPECTED_TREE, 'shallow_boundary': REVISION,
              'history_verified': False, 'gitlinks_uninitialized': GITLINKS,
              'versions_sha256': VERSIONS_SHA256, 'object_count': object_count, 'pack': copied,
              'git_config_sha256': digest(checkout / '.git/config'),
              'helper_sha256': digest(Path(__file__).resolve()),
              'copy_helper_sha256': digest(Path(_copy.__file__).resolve()),
              'network_fetch_performed': False, 'build_executed': False, 'acceptance_executed': False}
    with (work / 'provenance/arrow-source-cache.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    return record


def verify_preparation(source, work):
    audit = work / 'arrow-source-cache'
    proof = work / 'provenance/arrow-source-cache.json'
    regular(proof.lstat())
    record = json.loads(proof.read_text())
    roots(source, work, Path(record['pack']['cache_path']))
    checkout = canonical_directory(work / 'build/src/apache-arrow-cpp')
    expected = {'schema': 1, 'status': 'fixed-arrow-shallow-source-prepared', 'source': str(source),
                'work': str(work), 'checkout': str(checkout), 'original_remote': ORIGIN,
                'revision': REVISION, 'tree': EXPECTED_TREE, 'shallow_boundary': REVISION,
                'history_verified': False, 'gitlinks_uninitialized': GITLINKS,
                'versions_sha256': VERSIONS_SHA256, 'helper_sha256': digest(Path(__file__).resolve()),
                'copy_helper_sha256': digest(Path(_copy.__file__).resolve()),
                'network_fetch_performed': False, 'build_executed': False, 'acceptance_executed': False}
    require(all(record.get(key) == value for key, value in expected.items()), 'Arrow source preparation identity changed')
    copied = audit / 'input.pack'
    regular(copied.lstat())
    require(record['pack']['copy_path'] == str(copied) and copied.stat().st_size == record['pack']['size']
            and digest(copied) == record['pack']['actual_sha256'] == record['pack']['requested_sha256'],
            'Arrow source input copy changed')
    regular((checkout / '.git/config').lstat())
    require(digest(checkout / '.git/config') == record['git_config_sha256'], 'Arrow local Git configuration changed')
    count = verify_objects(git_runner(checkout, audit), checkout, prepared=True)
    require(count == record['object_count'], 'Arrow snapshot object count changed')
    return {'path': str(proof), 'sha256': digest(proof), 'revision': REVISION, 'tree': EXPECTED_TREE,
            'shallow_boundary': REVISION, 'history_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'work', 'pack'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--pack-sha256', required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and os.getuid() == os.geteuid() != 0, 'Use the ordinary Linux x86_64 container build user')
    require(Path(__file__).resolve() == args.source / 'scripts/ec/ci/prepare-arrow-source-cache.py',
            'Use the helper from the checked source')
    info = args.work.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'Build work must be owned and private')
    os.umask(0o077)
    print(json.dumps(prepare(args.source, args.work, args.pack, args.pack_sha256)), flush=True)


if __name__ == '__main__':
    main()
