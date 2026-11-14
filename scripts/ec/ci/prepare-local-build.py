#!/usr/bin/env python3
"""Validate a dedicated ordinary-user checkout; install nothing and build nothing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys


GIB = 1024 ** 3
CONTAMINANTS = (
    'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'LD_PRELOAD',
    'LD_LIBRARY_PATH', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC',
    'CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN',
    'RUSTUP_DIST_SERVER', 'RUSTUP_UPDATE_ROOT', 'CMAKE_PREFIX_PATH',
    'CMAKE_TOOLCHAIN_FILE', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR',
    'PKG_CONFIG_SYSROOT_DIR', 'BASH_ENV', 'ENV', 'PYTHONPATH', 'PYTHONHOME',
    'GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT',
    'GIT_DIR', 'GIT_WORK_TREE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
)


def require(value, message):
    if not value:
        raise ValueError(message)


def clean_environment(environment):
    bad = [key for key, value in environment.items() if value and
           (key in CONTAMINANTS or key.startswith(('CARGO_', 'RUSTUP_', 'RUSTC_',
                                                  'GIT_CONFIG_KEY_', 'GIT_CONFIG_VALUE_', 'BASH_FUNC_')))]
    require(not bad, 'Inherited build overrides must be unset: ' + ', '.join(sorted(bad)))


def canonical(path):
    require(path.is_absolute() and str(path) == str(path.resolve(strict=True)),
            'Existing path must be absolute and canonical (no symlinks or dot components)')
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)) is not None,
            'Build paths must use simple ASCII components (CMake/Rust nested build contract)')
    for part in (path, *path.parents):
        require(not stat.S_ISLNK(part.lstat().st_mode), 'Path ancestor is a symlink')
    return path


def fresh_paths(source, work, uid):
    canonical(source)
    parent = canonical(work.parent)
    require(work.is_absolute() and re.fullmatch(r'[A-Za-z0-9_-]+', work.name) is not None,
            'Work must be absolute with a simple new directory name')
    require(not work.exists() and not work.is_symlink(), 'Work already exists; preserve it and use a new checkout/work')
    require(source != work and source not in work.parents and work not in source.parents,
            'Source and work must be independent trees (neither may contain the other)')
    source_info, parent_info = source.stat(), parent.stat()
    require(stat.S_ISDIR(source_info.st_mode) and source_info.st_uid == uid
            and source_info.st_mode & 0o022 == 0, 'Source root must be owned and not group/world writable')
    require(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == uid
            and parent_info.st_mode & 0o077 == 0, 'Work parent must be owned and private (0700)')


def packages(script):
    text = script.read_text(encoding='utf-8').replace('\\\n', ' ')
    rows = [line for line in text.splitlines() if line.startswith('DEBIAN_FRONTEND=noninteractive apt-get install ')]
    require(len(rows) == 1, 'Unrecognized published dependency installer')
    result = rows[0].split('--no-install-recommends ', 1)[1].split()
    require(result and len(result) == len(set(result)) and
            all(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', item) for item in result), 'Invalid dependency package list')
    return result


def git_state(source, revision):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    require(re.fullmatch(r'[0-9a-f]{40}', revision) is not None, 'Revision must be a full lowercase Git commit')
    require(git('rev-parse', '--show-toplevel') == str(source) and git('rev-parse', 'HEAD') == revision,
            'Source root/HEAD differs from the requested revision')
    require(not git('status', '--porcelain=v1', '--untracked-files=all', '--ignored=matching'),
            'Use a dedicated clean checkout, including ignored build outputs')
    submodules = subprocess.check_output(['git', '-C', str(source), 'submodule', 'status', '--recursive'], text=True)
    require(submodules and all(row.startswith(' ') for row in submodules.splitlines()),
            'All recursive submodules must be initialized at their recorded gitlinks')
    subprocess.run(['git', '-C', str(source), 'submodule', 'foreach', '--quiet', '--recursive',
                    'test -z "$(git status --porcelain=v1 --untracked-files=all --ignored=matching)"'], check=True)
    # Reject global/local git URL remapping and external command hooks in this path.
    configured = subprocess.run(['git', '-C', str(source), 'config', '--get-regexp',
                                 r'^(url\..*\.insteadof|core\.sshcommand|filter\..*|include.*)$'],
                                text=True, capture_output=True)
    require(configured.returncode == 1, 'Git URL/filter/include overrides are not supported by this entry')
    return submodules


def cargo_ancestor_configs(source):
    for parent in (source, *source.parents):
        for name in ('config', 'config.toml'):
            require(not os.path.lexists(parent / '.cargo' / name),
                    'Inherited Cargo configuration is unsupported: ' + str(parent / '.cargo' / name))


def check_filesystem(kind, container_build_only):
    require(kind in (('ext4', 'xfs') if container_build_only else ('ext4',)),
            'Container build-only paths require ext4/xfs; ordinary local paths require ext4')


def managed_existing_paths(source, work, original):
    """Read-only ordinary-host refresh; does not adopt or rewrite a build epoch."""
    import resource
    require(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid(),
            'Managed resume requires unchanged ordinary real/effective UID/GID')
    require((original['uid'], original['gid']) == (os.getuid(), os.getgid()), 'Original build owner changed')
    for name, item in original['tools'].items():
        actual = shutil.which(name)
        require(actual is not None and Path(actual).samefile(item['path']),
                'Actual PATH tool differs from original provider: ' + name)
    for path in (source, work):
        canonical(path)
        info = path.stat()
        require(info.st_uid == os.getuid() and info.st_gid == os.getgid() and not info.st_mode & 0o022,
                'Managed source/work ownership or permissions changed')
        kind = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(path)], text=True).strip()
        check_filesystem(kind, False)
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    require(hard == resource.RLIM_INFINITY or hard >= 65536, 'Hard nofile limit must allow 65536')
    disk = os.statvfs(work)
    free = disk.f_bavail * disk.f_frsize
    require(free >= 8 * GIB and disk.f_favail >= 25000, 'Managed incremental free-space floor not met')
    return {'uid': os.getuid(), 'gid': os.getgid(), 'filesystem': 'ext4', 'disk_free_bytes': free,
            'free_inodes': disk.f_favail, 'nofile_hard': hard,
            'scope': 'incremental guard only; 8 GiB/25000 inodes do not guarantee peak storage use'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--backend', choices=('scalar', 'isal'), required=True)
    parser.add_argument('--container-build-only', action='store_true')
    args = parser.parse_args()
    require(sys.platform == 'linux' and platform.machine() == 'x86_64', 'Linux x86_64 required')
    require(sys.version_info >= (3, 11) and Path(sys.executable).resolve() == Path('/usr/bin/python3').resolve(),
            'The actual /usr/bin/python3 must be >= 3.11')
    require(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid(), 'Use one ordinary real/effective UID/GID')
    clean_environment(os.environ)
    os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                      if '=' in line and not line.startswith('#'))
    require(os_release.get('ID', '').strip('"') == 'ubuntu'
            and os_release.get('VERSION_ID', '').strip('"') == '24.04', 'This dependency profile requires Ubuntu 24.04')
    fresh_paths(args.source, args.work, os.geteuid())
    cargo_ancestor_configs(args.source)
    require(Path(__file__).resolve() == args.source / 'scripts/ec/ci/prepare-local-build.py',
            'Run the helper from the requested source checkout')
    submodules = git_state(args.source, args.revision)
    filesystems = []
    for path in (args.source, args.work.parent):
        kind = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(path)], text=True).strip()
        check_filesystem(kind, args.container_build_only)
        filesystems.append({'path': str(path), 'filesystem': kind})
    disk = os.statvfs(args.work.parent)
    require(disk.f_bavail * disk.f_frsize >= 80 * GIB and disk.f_favail >= 250000,
            'Need at least 80 GiB and 250000 free inodes before the cold build (not a peak-use guarantee)')
    # package-services deliberately prepends this existing system directory to
    # LD_LIBRARY_PATH. Refuse shadow providers instead of modifying the host.
    for name in ('libfdb_c.so', 'libfuse3.so.3') + (('libisal.so.2',) if args.backend == 'isal' else ()):
        require(not os.path.lexists(Path('/usr/local/lib') / name),
                'Existing /usr/local provider would shadow the private package closure: ' + name)
    installed = {}
    for package in packages(args.source / 'scripts/ec/install-build-deps.sh'):
        value = subprocess.check_output(['dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}', package], text=True)
        state, version = value.split('\t', 1)
        require(state == 'installed' and version, 'Missing system development package: ' + package)
        installed[package] = version
    tools = {}
    for tool in ('python3', 'clang-14', 'clang++-14', 'gcc-12', 'g++-12', 'ld.lld-14', 'cmake', 'ninja', 'meson',
                 'pkg-config', 'curl', 'git', 'rustup', 'cargo', 'rustc'):
        value = shutil.which(tool)
        require(value is not None, 'Missing prepared tool: ' + tool)
        path = Path(value).resolve(strict=True)
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        tools[tool] = {'path': str(path), 'sha256': digest}
    require(Path(shutil.which('python3')).samefile('/usr/bin/python3'),
            'PATH python3 must be the checked /usr/bin/python3, not a venv or another version')
    require(tools['clang-14']['path'] == '/usr/lib/llvm-14/bin/clang'
            and tools['clang++-14']['path'] == '/usr/lib/llvm-14/bin/clang', 'Unexpected Clang 14 provider')
    require(Path(shutil.which('gcc-12')).samefile('/usr/bin/gcc-12')
            and Path(shutil.which('g++-12')).samefile('/usr/bin/g++-12'), 'Unexpected GCC 12 provider')
    require(Path(tools['ld.lld-14']['path']).samefile('/usr/lib/llvm-14/bin/ld.lld'),
            'Unexpected Clang 14 companion linker')
    require(tools['cargo']['path'] == tools['rustup']['path'] == tools['rustc']['path']
            or (Path(shutil.which('cargo')).samefile(shutil.which('rustup'))
                and Path(shutil.which('rustc')).samefile(shutil.which('rustup'))),
            'Cargo and rustc must be the prepared rustup proxies, not a system toolchain')
    import resource
    nofile = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    require(nofile == resource.RLIM_INFINITY or nofile >= 65536, 'Hard nofile limit must allow 65536')
    print(json.dumps({'schema': 1, 'status': 'local-preflight-only-no-build', 'source': str(args.source),
                      'revision': args.revision, 'work': str(args.work), 'uid': os.geteuid(), 'gid': os.getegid(),
                      'backend': args.backend, 'container_build_only': args.container_build_only,
                      'acceptance_executed': False, 'filesystems': filesystems,
                      'python': sys.version, 'filesystem': filesystems[1]['filesystem'],
                      'disk_free_bytes': disk.f_bavail * disk.f_frsize,
                      'free_inodes': disk.f_favail, 'packages': installed, 'tools': tools,
                      'submodules': submodules, 'system_install_performed': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('local-build preflight: ' + str(error), file=sys.stderr)
        raise SystemExit(2)
