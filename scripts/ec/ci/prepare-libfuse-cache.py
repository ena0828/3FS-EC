#!/usr/bin/env python3
"""Prepare the fixed libfuse source from a local bundle, without building it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess


REVISION = '7a92727d97c10290b3501d86a194738973edb61d'
EXPECTED_TREE = '6f3d4c9e41953c99dcb79d53aa11c524ce99517b'
ORIGIN = 'https://github.com/libfuse/libfuse.git'
GIT = '/usr/bin/git'


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical_directory(path):
    require(path.is_absolute() and path == path.resolve(strict=True), 'Directory must be absolute and canonical')
    for parent in (path, *path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), 'Directory and ancestors must not be links')
    return path


def regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'Bundle must be a regular file with exactly one link')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def copy_bundle(bundle, destination, expected_sha256):
    require(re.fullmatch(r'[a-f0-9]{64}', expected_sha256), 'Expected bundle SHA256 must be 64 lowercase hex digits')
    canonical_directory(bundle.parent)
    require(bundle.is_absolute() and bundle == bundle.resolve(strict=True), 'Bundle path must be canonical')
    before = bundle.lstat()
    regular(before)
    require(before.st_size > 0, 'Bundle is empty')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    with os.fdopen(os.open(bundle, flags), 'rb') as source:
        opened = os.fstat(source.fileno())
        regular(opened)
        require(identity(opened) == identity(before), 'Bundle changed while opening')
        with destination.open('xb') as target:
            total = 0
            while block := source.read(1024 * 1024):
                total += len(block)
                require(total <= before.st_size, 'Bundle grew during copy')
                target.write(block)
        require(identity(os.fstat(source.fileno())) == identity(opened)
                and identity(bundle.lstat()) == identity(opened), 'Bundle changed during copy')
    copied = destination.lstat()
    regular(copied)
    actual = digest(destination)
    require(total == copied.st_size == before.st_size and actual == expected_sha256,
            'Bundle work copy differs from requested transfer SHA256/size')
    return {'cache_path': str(bundle), 'copy_path': str(destination), 'size': copied.st_size,
            'requested_sha256': expected_sha256, 'actual_sha256': actual,
            'digest_scope': 'caller-supplied transfer integrity; not an official bundle release digest'}


def prepare(source, work, bundle, expected_sha256):
    require(re.fullmatch(r'[a-f0-9]{40}', REVISION) and re.fullmatch(r'[a-f0-9]{40}', EXPECTED_TREE),
            'Invalid fixed libfuse source identity')
    roots = [canonical_directory(path) for path in (source, work, bundle.parent)]
    for index, left in enumerate(roots):
        for right in roots[index + 1:]:
            require(left != right and left not in right.parents and right not in left.parents,
                    'Source, work and bundle cache must be independent trees')
    provenance = canonical_directory(work / 'provenance')
    audit, checkout = work / 'libfuse-cache', work / 'libfuse'
    require(not os.path.lexists(checkout), 'Existing libfuse checkout must not be adopted')
    audit.mkdir(mode=0o700)  # Failed preparations remain exclusive and cannot be resumed.
    copied = copy_bundle(bundle, audit / 'input.bundle', expected_sha256)
    template = audit / 'empty-template'
    template.mkdir(mode=0o700)
    config = audit / 'empty-git-config'
    config.touch(exist_ok=False)
    checkout.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(config),
                       GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', LC_ALL='C')
    commands = []
    with (audit / 'commands.jsonl').open('x', encoding='utf-8') as log:
        def git(*arguments):
            argv = [GIT, '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always',
                    '-c', 'submodule.recurse=false', '-c', 'core.autocrlf=false', '-c', 'gc.auto=0',
                    '-c', 'core.hooksPath=' + str(template), '-c', 'core.attributesFile=' + str(config),
                    '-C', str(checkout), *arguments]
            result = subprocess.run(argv, env=environment, text=True, encoding='utf-8', capture_output=True)
            row = {'argv': argv, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
            commands.append(row)
            log.write(json.dumps(row) + '\n')
            log.flush()
            require(result.returncode == 0, 'Local libfuse Git command failed: ' + ' '.join(arguments))
            return result.stdout

        git('init', '-q', '--template=' + str(template))
        # No objects or alternate object stores exist here: prerequisites cannot
        # be satisfied accidentally by a developer's pre-existing checkout.
        git('bundle', 'verify', copied['copy_path'])
        advertised = git('bundle', 'list-heads', copied['copy_path']).splitlines()
        refs = [line.split(' ', 1) for line in advertised]
        require(refs and all(len(row) == 2 for row in refs)
                and any(sha == REVISION for sha, _ in refs), 'Bundle does not advertise the fixed libfuse commit')
        git('fetch', '--no-tags', '--no-recurse-submodules', copied['copy_path'], REVISION)
        git('fsck', '--full', '--strict')
        require(git('rev-parse', '--is-shallow-repository').strip() == 'false', 'Shallow libfuse source rejected')
        require(git('cat-file', '-t', REVISION).strip() == 'commit', 'Fixed object is not a commit')
        tree = git('rev-parse', REVISION + '^{tree}').strip()
        require(tree == EXPECTED_TREE, 'Fixed libfuse tree differs from source lock')
        entries = git('ls-tree', '-r', '-z', REVISION).split('\0')
        for entry in filter(None, entries):
            info, path = entry.split('\t', 1)
            require(info.split()[0] != '160000' and '.gitmodules' not in path.split('/'),
                    'Unexpected libfuse submodule declaration or gitlink')
        git('checkout', '--detach', REVISION)
        require(git('rev-parse', 'HEAD').strip() == REVISION, 'Checked-out libfuse HEAD differs from source lock')
        require(not git('status', '--porcelain=v1', '--untracked-files=all', '--ignored=matching'),
                'Prepared libfuse checkout is not clean')
        git('remote', 'add', 'origin', ORIGIN)
        require(git('remote', 'get-url', 'origin').strip() == ORIGIN, 'Original libfuse remote was not retained')
    regular((audit / 'input.bundle').lstat())
    require(digest(audit / 'input.bundle') == copied['actual_sha256'], 'Bundle copy changed during preparation')
    record = {'schema': 1, 'status': 'fixed-libfuse-source-prepared', 'source': str(source),
              'work': str(work), 'checkout': str(checkout), 'original_remote': ORIGIN,
              'revision': REVISION, 'tree': tree, 'bundle': copied, 'bundle_refs': refs,
              'helper_sha256': digest(Path(__file__).resolve()), 'commands': commands,
              'network_fetch_performed': False, 'build_executed': False, 'acceptance_executed': False,
              'scope': 'Fixed libfuse source only; no Meson/Ninja build or mount performed here'}
    with (provenance / 'libfuse-cache.json').open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2)
        stream.write('\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'work', 'bundle'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--bundle-sha256', required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
            and os.getuid() == os.geteuid() != 0, 'Use the ordinary Linux x86_64 container build user')
    require(Path(__file__).resolve() == args.source / 'scripts/ec/ci/prepare-libfuse-cache.py',
            'Use the helper from the checked source')
    info = args.work.stat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'Build work must be owned and private')
    os.umask(0o077)
    print(json.dumps(prepare(args.source, args.work, args.bundle, args.bundle_sha256)), flush=True)


if __name__ == '__main__':
    main()
