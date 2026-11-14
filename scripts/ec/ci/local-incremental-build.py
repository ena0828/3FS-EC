#!/usr/bin/env python3
"""Owned ordinary-Linux build attempts; reuse only a verified prepared epoch."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True

GIB = 1024 ** 3
JOBS = (1, 2, 4, 8, 12, 16)
HERE = Path(__file__).resolve().parent


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(Path(path).parent)


def replace_record(path, value):
    temporary = path.with_name(path.name + '.pending')
    write_new(temporary, value)
    os.replace(temporary, path)
    sync_dir(path.parent)


def read(path):
    require(path.is_file() and not path.is_symlink(), 'missing regular record: ' + str(path))
    return json.loads(path.read_text(encoding='utf-8'))


def load_preflight(source):
    spec = importlib.util.spec_from_file_location('local_build_preflight', source / 'scripts/ec/ci/prepare-local-build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args])


def source_identity(source, revision):
    require(re.fullmatch(r'[0-9a-f]{40}', revision) is not None, 'full revision required')
    require(git(source, 'rev-parse', 'HEAD').decode().strip() == revision, 'HEAD differs from requested revision')
    require(not git(source, 'diff', '--binary', 'HEAD', '--ignore-submodules=all'), 'tracked source is dirty')
    require(not git(source, 'ls-files', '--others', '--exclude-standard'), 'untracked source is not allowed')


def tree_files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            result[str(path.relative_to(root))] = {'symlink': os.readlink(path)}
        elif path.is_file():
            result[str(path.relative_to(root))] = {'sha256': sha(path)}
    return result


def compatible_source_inputs(source):
    files = git(source, 'ls-files', '-z').decode().split('\0')
    selected = [p for p in files if p and (p.startswith(('cmake/', 'patches/'))
                or Path(p).name in ('Cargo.lock', 'Cargo.toml', 'CMakeLists.txt', '.gitmodules')
                or p in ('scripts/ec/ci/build-native.sh', 'scripts/ec/ci/prepare-local-build.py',
                         'scripts/ec/ci/local-incremental-build.py', 'scripts/ec/install-build-deps.sh',
                         'scripts/ec/reference/downloads.json', 'scripts/ec/cluster/fetch-fdb.sh')
                or p.startswith('scripts/ec/ci/prepare-') or p == 'scripts/ec/cluster/prepare-fdb-cache.py')]
    return {p: sha(source / p) for p in selected}


def epoch_inputs(source, work):
    """Business src/tests may change; dependency/tool/provider inputs may not."""
    load_preflight(source).cargo_ancestor_configs(source)
    for name in ('config', 'config.toml'):
        require(not os.path.lexists(work / 'cargo-home' / name), 'Private Cargo configuration is unsupported')
    selected = compatible_source_inputs(source)
    modules = git(source, 'submodule', 'status', '--recursive').decode().splitlines()
    require(modules and all(line.startswith(' ') for line in modules), 'submodule revision changed/uninitialized')
    module_records = {}
    for line in modules:
        commit, relative = line.strip().split()[:2]
        path = source / relative
        require(not git(path, 'ls-files', '--others', '--exclude-standard'), 'untracked submodule input')
        module_records[relative] = {'commit': commit, 'tracked_diff_sha256': hashlib.sha256(
            git(path, 'diff', '--binary', 'HEAD')).hexdigest()}
    preflight = read(work / 'provenance/local-preflight.json')
    for item in preflight['tools'].values():
        require(sha(item['path']) == item['sha256'], 'prepared tool bytes changed')
    packages = {}
    for package in preflight['packages']:
        value = subprocess.check_output(['dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}', package], text=True)
        state, version = value.split('\t', 1)
        require(state == 'installed', 'prepared package is absent')
        packages[package] = version
    require(packages == preflight['packages'], 'prepared package versions changed')
    environment = dict(os.environ, RUSTUP_HOME=str(work / 'rustup-home'), RUSTUP_TOOLCHAIN='1.99.1')
    rustup = preflight['tools']['rustup']['path']
    rust_tools = {}
    for name in ('rustc', 'cargo'):
        actual = Path(subprocess.check_output([rustup, 'which', '--toolchain', '1.99.1', name],
                                             text=True, env=environment).strip()).resolve(strict=True)
        require(actual.is_relative_to(work / 'rustup-home'), 'Rust tool is outside the original private root')
        rust_tools[name] = {'path': str(actual), 'sha256': sha(actual)}
    sysroot = Path(subprocess.check_output([rust_tools['rustc']['path'], '--print', 'sysroot'],
                                          text=True, env=environment).strip()).resolve(strict=True)
    require(sysroot.is_relative_to(work / 'rustup-home'), 'Rust sysroot escaped private root')
    rust_tools['sysroot'] = {'path': str(sysroot), 'bin': tree_files(sysroot / 'bin'),
                            'lib': tree_files(sysroot / 'lib')}
    providers = {name: tree_files(work / name) for name in ('deps', 'isal-prefix')}
    for name in ('deps', 'cargo-home', 'cargo-target', 'rustup-home', 'gcc12'):
        require((work / name).is_dir() and not (work / name).is_symlink(), 'prepared directory absent/moved')
    require((source / 'target').is_symlink() and (source / 'target').resolve() == work / 'cargo-target',
            'Cargo target binding changed')
    subprocess.run(['sha256sum', '--check', str(work / 'provenance/private-libraries.sha256')],
                   check=True, stdout=subprocess.DEVNULL)
    return {'source_inputs': selected, 'submodules': module_records,
            'tools': preflight['tools'], 'packages': packages, 'providers': providers,
            'rust_toolchain': rust_tools, 'cargo_wrapper_sha256': sha(work / 'bin/cargo'),
            'local_preflight_sha256': sha(work / 'provenance/local-preflight.json'),
            'gcc_links': tree_files(work / 'gcc12')}


def resource_plan(jobs, memory, affinity, groups, previous=None):
    require(type(jobs) is int and jobs in JOBS, 'unsupported managed local concurrency')
    require(type(affinity) is int and affinity > 0, 'missing CPU affinity')
    available, total = memory['MemAvailable'], memory['MemTotal']
    require(0 <= available <= total, 'invalid memory observation')
    cpus, headroom = affinity, available
    for row in groups:
        if row['cpu_max'] is not None:
            quota, period = row['cpu_max'].split()
            if quota != 'max':
                cpus = min(cpus, int(quota) // int(period))
        if row['memory_max'] not in (None, 'max'):
            headroom = min(headroom, max(0, int(row['memory_max']) - row['memory_current']))
    per_job = 3 * GIB
    if previous and previous.get('max_compiler_rss_bytes', 0):
        per_job = max(per_job, math.ceil(previous['max_compiler_rss_bytes'] * 1.5))
    needed = 4 * GIB + per_job * jobs
    admitted = total >= 15 * GIB and headroom >= max(12 * GIB, needed) and cpus >= jobs
    return {'schema': 1, 'profile': 'ordinary-linux-managed-build',
            'status': 'admitted' if admitted else 'insufficient-local-resources',
            'requested_jobs': jobs, 'effective_jobs': jobs if admitted else None,
            'affinity_cpus': affinity, 'visible_cpu_budget_limit': cpus,
            'host_memory_bytes': memory, 'visible_memory_headroom_bytes': headroom,
            'required_headroom_bytes': needed, 'estimate_bytes_per_job': per_job,
            'reserve_bytes': 4 * GIB, 'cgroup_ancestors': groups,
            'pools': {'compile': jobs, 'link': 1},
            'nested_jobs': {'cmake_environment': 1, 'cargo': 1, 'make': 1, 'jemalloc': 1},
            'scope': 'current visible resources plus conservative estimate; sampled RSS is not an absolute peak guarantee'}


def context():
    attempt = Path(os.environ['EC_LOCAL_BUILD_ATTEMPT'])
    intent = read(attempt / 'intent.json')
    fd = int(os.environ['EC_LOCAL_BUILD_LOCK_FD'])
    lock = Path(intent['state_root']) / 'lock'
    a, b = os.fstat(fd), lock.lstat()
    require(stat.S_ISREG(a.st_mode) and a.st_uid == os.getuid() and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino),
            'managed build lock descriptor mismatch')
    require(Path(intent['source']) / 'scripts/ec/ci/local-incremental-build.py' == Path(__file__).resolve(),
            'use the source-bound managed producer')
    require(read(Path(intent['state_root']) / 'state.json')['attempt'] == str(attempt), 'attempt is no longer current')
    return attempt, intent


def verify_prepared(source, work, state):
    checkpoint = read(work / 'provenance/local-build-ready.json')
    require(checkpoint['source'] == str(source) and checkpoint['work'] == str(work), 'prepared paths differ')
    require(checkpoint['inputs'] == epoch_inputs(source, work), 'dependency epoch changed: use a fresh managed work')
    require(sha(work / 'build/CMakeCache.txt') == state['cmake_cache_sha256'], 'CMake cache changed outside owned attempt')
    return checkpoint


def checkpoint():
    attempt, intent = context()
    source, work = Path(intent['source']), Path(intent['work'])
    source_identity(source, intent['revision'])
    data = {'schema': 1, 'source': str(source), 'work': str(work), 'initial_revision': intent['revision'],
            'inputs': epoch_inputs(source, work)}
    path = work / 'provenance/local-build-ready.json'
    if path.exists():
        prior = read(path)
        require(prior['inputs'] == data['inputs'], 'dependency epoch drift after configure')
    else:
        write_new(path, data)
    write_new(attempt / 'configured.json', {'checkpoint_sha256': sha(path),
                                         'cmake_cache_sha256': sha(work / 'build/CMakeCache.txt')})


def sample_group(pgid):
    total, compiler, members = 0, 0, []
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) != pgid or fields[0] == 'Z':
                continue
            status = (path / 'status').read_text()
            match = re.search(r'^VmRSS:\s+(\d+) kB$', status, re.M)
            rss = int(match[1]) * 1024 if match else 0
            name = (path / 'comm').read_text().strip()
            total += rss
            if name.startswith(('clang', 'cc1', 'rustc')):
                compiler = max(compiler, rss)
            members.append(int(path.name))
        except (OSError, ValueError, IndexError):
            continue
    available = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                     if line.startswith('MemAvailable:'))
    return {'sampled_group_rss_bytes': total, 'max_compiler_rss_bytes': compiler,
            'mem_available_bytes': available, 'live_pids': members}


def publish(attempt, intent, monitor):
    work = Path(intent['work'])
    staged = attempt / 'staged'
    native = read(staged / 'native-build.json')
    require(native['revision'] == intent['revision'], 'staged revision differs')
    lab = read(staged / 'lab-build.json')
    require(lab['revision'] == intent['revision']
            and lab['native_build_receipt_sha256'] == sha(staged / 'native-build.json'),
            'staged native/lab generation binding differs')
    managed = {'schema': 1, 'attempt': str(attempt), 'mode': intent['mode'],
               'producer_sha256': sha(Path(__file__)), 'intent_sha256': sha(attempt / 'intent.json'),
               'prepared_sha256': sha(work / 'provenance/local-build-ready.json'),
               'monitor_sha256': sha(attempt / 'monitor.json'), 'direct_child_joined': True,
               'build_inputs_sha256': sha(work / 'provenance/build-inputs.sha256'),
               'source_head_sha256': sha(work / 'provenance/source-head.txt'),
               'owned_process_group_empty': True}
    native['managed_build'] = managed
    native_bytes = encoded(native)
    lab['managed_build'] = managed
    lab['native_build_receipt_sha256'] = hashlib.sha256(native_bytes).hexdigest()
    # Preserve both full generation records; publish the completion marker last.
    write_new(attempt / 'native-build.json', native)
    write_new(attempt / 'lab-build.json', lab)
    write_new(work / 'provenance/lab-build.json', lab)
    try:
        write_new(work / 'provenance/native-build.json', native)
    except BaseException:
        for name in ('native-build.json', 'lab-build.json'):
            path = work / 'provenance' / name
            if path.exists():
                path.unlink()
        sync_dir(work / 'provenance')
        raise


def archive_previous(attempt, work):
    archive = attempt / 'previous'
    archive.mkdir(mode=0o700)
    for name in ('native-build.json', 'lab-build.json', 'build-resources.json', 'build-command.json',
                 'source-head.txt', 'submodules.txt', 'build-inputs.sha256', 'cargo-locks.sha256'):
        path = work / 'provenance' / name
        if path.exists():
            require(path.is_file() and not path.is_symlink(), 'invalid old receipt')
            os.rename(path, archive / name)
    sync_dir(work / 'provenance')
    sync_dir(archive)


def run(args):
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid(),
            'ordinary Linux real/effective UID/GID required')
    import fcntl
    source, work = args.source, args.work
    require(source / 'scripts/ec/ci/local-incremental-build.py' == Path(__file__).resolve(), 'source-bound entry required')
    source_identity(source, args.revision)
    preflight = load_preflight(source)
    preflight.clean_environment(os.environ)
    preflight.canonical(source)
    preflight.canonical(work.parent)
    require(source / 'scripts/ec/ci/local-incremental-build.py' == Path(__file__).resolve(), 'source-bound entry required')
    require(work.is_absolute() and re.fullmatch(r'[A-Za-z0-9_-]+', work.name), 'invalid work name')
    require(source != work and source not in work.parents and work not in source.parents, 'overlapping source/work')
    require(work.parent.stat().st_uid == os.getuid() and not work.parent.stat().st_mode & 0o077, 'private owned work parent required')
    state_root = work.parent / ('.' + work.name + '-managed')
    if not state_root.exists():
        state_root.mkdir(mode=0o700)
        sync_dir(state_root.parent)
    preflight.canonical(state_root)
    require(state_root.stat().st_uid == os.getuid() and not state_root.stat().st_mode & 0o077, 'private state root required')
    lock = os.open(state_root / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_path = state_root / 'state.json'
        state = read(state_path) if state_path.exists() else None
        if state:
            require(state['status'] in ('failed', 'complete'), 'prior owner/attempt is unresolved; no PID adoption')
            require(state['source'] == str(source) and state['work'] == str(work), 'managed workspace identity changed')
        mode = 'resume' if work.exists() else 'fresh'
        if mode == 'resume':
            require(state is not None, 'existing work has no managed owner/checkpoint; cannot adopt')
            preflight.canonical(work)
            refreshed = preflight.managed_existing_paths(source, work, read(work / 'provenance/local-preflight.json'))
            verify_prepared(source, work, state)
        else:
            require(state is None, 'managed work disappeared')
        ordinal = 1 if state is None else state['generation'] + 1
        attempt = state_root / f'attempt-{ordinal:06d}'
        attempt.mkdir(mode=0o700)
        (attempt / 'staged').mkdir(mode=0o700)
        intent = {'schema': 1, 'source': str(source), 'work': str(work), 'revision': args.revision,
                  'jobs': args.build_jobs, 'mode': mode, 'generation': ordinal, 'state_root': str(state_root),
                  'previous_attempt': None if state is None else state['attempt']}
        write_new(attempt / 'intent.json', intent)
        if mode == 'resume':
            write_new(attempt / 'host-preflight.json', refreshed)
        current = dict(intent, attempt=str(attempt), status='running')
        replace_record(state_path, current)
        if mode == 'resume':
            archive_previous(attempt, work)
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', EC_LOCAL_BUILD_ATTEMPT=str(attempt), EC_LOCAL_BUILD_LOCK_FD=str(lock),
                           EC_LOCAL_BUILD_MODE=mode)
        argv = ['bash', str(source / 'scripts/ec/ci/build-native.sh'), '--backend', 'isal',
                '--build-jobs', str(args.build_jobs), '--with-lab-targets', '--with-ec-regression-targets',
                '--local-source', str(source), '--local-work', str(work), '--local-revision', args.revision]
        write_new(attempt / 'command.json', {'argv': argv})
        print(json.dumps({'status': 'running', 'attempt': str(attempt), 'mode': mode,
                          'build_stdout': str(attempt / 'build.stdout'),
                          'build_stderr': str(attempt / 'build.stderr')}), flush=True)
        monitor = {'samples': 0, 'sampled_group_rss_peak_bytes': 0, 'max_compiler_rss_bytes': 0,
                   'minimum_mem_available_bytes': None, 'scope': '1-second samples; shared RSS may be counted repeatedly'}
        with (attempt / 'build.stdout').open('xb') as stdout, (attempt / 'build.stderr').open('xb') as stderr:
            process = subprocess.Popen(argv, env=environment, stdout=stdout, stderr=stderr,
                                       pass_fds=(lock,), start_new_session=True)
            try:
                write_new(attempt / 'process.json', {'pid': process.pid, 'process_group': process.pid,
                                                   'scope': 'owned direct child; not a recovery/adoption credential'})
                while process.poll() is None:
                    sample = sample_group(process.pid)
                    monitor['samples'] += 1
                    monitor['sampled_group_rss_peak_bytes'] = max(monitor['sampled_group_rss_peak_bytes'], sample['sampled_group_rss_bytes'])
                    monitor['max_compiler_rss_bytes'] = max(monitor['max_compiler_rss_bytes'], sample['max_compiler_rss_bytes'])
                    old = monitor['minimum_mem_available_bytes']
                    monitor['minimum_mem_available_bytes'] = sample['mem_available_bytes'] if old is None else min(old, sample['mem_available_bytes'])
                    replace_record(attempt / 'monitor-live.json', monitor)
                    time.sleep(1)
            except BaseException:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise  # Unresolved owner state deliberately remains closed.
            code = process.wait()
        remaining = sample_group(process.pid)['live_pids']
        write_new(attempt / 'monitor.json', dict(monitor, remaining_group_pids=remaining))
        require(not remaining, 'builder returned with live group members; refuse resume/publication')
        source_identity(source, args.revision)
        if code == 0:
            ready = read(work / 'provenance/local-build-ready.json')
            require(ready['inputs'] == epoch_inputs(source, work), 'dependency epoch drifted during compilation')
            publish(attempt, intent, monitor)
        current.update(status='complete' if code == 0 else 'failed', exit_code=code,
                       cmake_cache_sha256=sha(work / 'build/CMakeCache.txt') if (work / 'build/CMakeCache.txt').is_file() else None)
        write_new(attempt / 'outcome.json', current)
        replace_record(state_path, current)
        print(json.dumps({'attempt': str(attempt), 'status': current['status'], 'exit_code': code}), flush=True)
        return code
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('run', 'child-check', 'checkpoint'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--revision')
    parser.add_argument('--build-jobs', type=int, choices=JOBS, default=8)
    args = parser.parse_args()
    if args.operation == 'run':
        require(all((args.source, args.work, args.revision)), 'source/work/revision required')
        return run(args)
    if args.operation == 'child-check':
        _, intent = context()
        require((str(args.source), str(args.work), args.revision, args.build_jobs) ==
                (intent['source'], intent['work'], intent['revision'], intent['jobs']),
                'child arguments differ from owned intent')
    else:
        checkpoint()
    return 0


if __name__ == '__main__':
    sys.exit(main())
