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
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
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


MANAGER = 'scripts/ec/ci/local-incremental-build.py'
PATCHES = {'third_party/folly': ('folly.patch',),
           'third_party/rocksdb': ('rocksdb.patch', 'rocksdb.patch.2')}
ARCHIVED_NAMES = ('native-build.json', 'lab-build.json', 'build-resources.json', 'build-command.json',
                  'source-head.txt', 'submodules.txt', 'build-inputs.sha256', 'cargo-locks.sha256')


def compatible_source_inputs(source, revision=None):
    files = git(source, *(['ls-tree', '-r', '--name-only', '-z', revision] if revision
                         else ['ls-files', '-z'])).decode().split('\0')
    selected = [p for p in files if p and (p.startswith(('cmake/', 'patches/'))
                or Path(p).name in ('Cargo.lock', 'Cargo.toml', 'CMakeLists.txt', '.gitmodules')
                or p in ('scripts/ec/ci/build-native.sh', 'scripts/ec/ci/prepare-local-build.py',
                         'scripts/ec/ci/local-incremental-build.py', 'scripts/ec/install-build-deps.sh',
                         'scripts/ec/reference/downloads.json', 'scripts/ec/cluster/fetch-fdb.sh')
                or p.startswith('scripts/ec/ci/prepare-') or p == 'scripts/ec/cluster/prepare-fdb-cache.py')]
    return {p: hashlib.sha256(git(source, 'show', revision + ':' + p)).hexdigest()
            if revision else sha(source / p) for p in selected}


def verified_submodule(path, commit, patches):
    """Reconstruct the expected patched index without changing the checkout/index/object store."""
    require(git(path, 'rev-parse', 'HEAD').decode().strip() == commit, 'submodule HEAD changed')
    require(not git(path, 'diff', '--cached', '--binary', 'HEAD'), 'staged submodule input is unsupported')
    untracked = set(filter(None, git(path, 'ls-files', '--others', '--exclude-standard', '-z').decode().split('\0')))
    objects = git(path, 'rev-parse', '--git-path', 'objects').decode().strip()
    objects = (path / objects).resolve()
    with tempfile.TemporaryDirectory(prefix='ec-patch-index-') as temporary:
        private = Path(temporary)
        (private / 'objects').mkdir()
        environment = dict(os.environ, GIT_INDEX_FILE=str(private / 'index'),
                           GIT_OBJECT_DIRECTORY=str(private / 'objects'),
                           GIT_ALTERNATE_OBJECT_DIRECTORIES=str(objects))
        def expected(*args):
            return subprocess.check_output(['git', '-c', 'core.autocrlf=false', '-C', str(path), *args],
                                           env=environment, stderr=subprocess.PIPE)
        expected('read-tree', commit)
        for patch in patches:
            expected('apply', '--cached', '--whitespace=nowarn', str(patch))
        added = set(filter(None, expected('diff', '--cached', '--name-only', '--diff-filter=A', '-z', commit).decode().split('\0')))
        require(untracked == added, 'untracked submodule input differs from exact patch additions')
        additions = {}
        for name in sorted(added):
            target = path / name
            info = target.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not target.is_symlink(),
                    'patch addition must be a regular single-link file')
            mode = expected('ls-files', '--stage', '--', name).decode().split()[0]
            require(mode in ('100644', '100755'), 'unsupported patch addition mode')
            if os.name == 'posix':
                require(bool(info.st_mode & 0o111) == (mode == '100755'), 'patch addition executable mode changed')
            wanted = expected('show', ':' + name)
            require(target.read_bytes() == wanted, 'patch addition bytes differ: ' + name)
            additions[name] = {'mode': mode, 'sha256': hashlib.sha256(wanted).hexdigest()}
        # --no-ext-diff and the private expected index check every tracked hunk,
        # including unrelated edits that reverse --check would not reject.
        require(not expected('diff', '--no-ext-diff', '--binary', '--ignore-submodules=all'),
                'submodule worktree differs from the complete expected patch')
        return {'commit': commit, 'expected_patch_diff_sha256': hashlib.sha256(
                    expected('diff', '--cached', '--binary', commit)).hexdigest(),
                'patches': {p.name: sha(p) for p in patches}, 'added_files': additions}


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
        module_records[relative] = verified_submodule(path, commit,
            [source / 'patches' / name for name in PATCHES.get(relative, ())])
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


def verify_source_snapshot(source, path, revision, expected_names):
    rows = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None and match[2] not in rows, 'invalid or duplicate source input snapshot')
        rows[match[2]] = match[1]
    require(set(rows) == set(expected_names), 'source input snapshot inventory differs')
    for name, digest in rows.items():
        require(hashlib.sha256(git(source, 'show', revision + ':' + name)).hexdigest() == digest,
                'original source input snapshot differs from its Git revision: ' + name)


def verify_configured_recovery(source, work, state):
    """Explicit recovery of the old post-configure patch-addition rejection only.

    There was no prepared epoch. Revalidate original recorded inputs/providers and
    snapshot the current private Rust/provider trees as a NEW epoch; never claim
    their full-tree hashes existed before the failed checkpoint.
    """
    require(state['status'] == 'failed' and type(state['exit_code']) is int and state['exit_code'] != 0,
            'configured recovery requires an owned failed attempt')
    previous = Path(state['attempt'])
    require(previous == Path(state['state_root']) / f"attempt-{state['generation']:06d}", 'previous attempt path differs')
    intent, outcome = read(previous / 'intent.json'), read(previous / 'outcome.json')
    require(outcome == state and all(outcome.get(k) == v for k, v in intent.items()), 'failed attempt identity differs')
    require(intent['source'] == str(source) and intent['work'] == str(work)
            and intent['mode'] == 'fresh', 'only the original fresh configured failure is recoverable')
    process, monitor = read(previous / 'process.json'), read(previous / 'monitor.json')
    require(type(process['pid']) is int and process['pid'] > 0 and process['process_group'] == process['pid']
            and monitor['remaining_group_pids'] == [], 'original owned process group was not joined')
    # A new lock alone is not proof that an abandoned builder exited.
    require(not sample_group(process['process_group'])['live_pids'], 'original process group is still live')
    expected_argv = ['bash', str(source / 'scripts/ec/ci/build-native.sh'), '--backend', 'isal',
                     '--build-jobs', str(intent['jobs']), '--with-lab-targets', '--with-ec-regression-targets',
                     '--local-source', str(source), '--local-work', str(work), '--local-revision', intent['revision']]
    require(read(previous / 'command.json') == {'argv': expected_argv}, 'original build invocation differs')
    error = (previous / 'build.stderr').read_bytes()
    require(error.endswith(b'ValueError: untracked submodule input\n') and b'in checkpoint\n' in error
            and b'in epoch_inputs\n' in error, 'not the known post-configure patch-addition failure')
    for path in (work / 'provenance/local-build-ready.json', previous / 'configured.json',
                 work / 'provenance/build-command.json', work / 'provenance/native-build.json',
                 work / 'provenance/lab-build.json'):
        require(not os.path.lexists(path), 'configured recovery must not replace a prepared/build/success record')
    cache = work / 'build/CMakeCache.txt'
    require(sha(cache) == state['cmake_cache_sha256'], 'original configured cache changed')
    old_revision = intent['revision']
    require(re.fullmatch(r'[0-9a-f]{40}', old_revision) is not None, 'invalid original revision')
    subprocess.run(['git', '-C', str(source), 'merge-base', '--is-ancestor', old_revision, 'HEAD'], check=True)
    before, after = compatible_source_inputs(source, old_revision), compatible_source_inputs(source)
    require(set(before) == set(after) and all(before[p] == after[p] for p in before if p != MANAGER),
            'configured recovery permits only the managed producer fix among dependency inputs')
    provenance = work / 'provenance'
    require((provenance / 'source-head.txt').read_text().strip() == old_revision, 'original source-head differs')
    original_preflight = read(provenance / 'local-preflight.json')
    require(original_preflight['revision'] == old_revision and original_preflight['source'] == str(source)
            and original_preflight['work'] == str(work) and original_preflight['backend'] == 'isal'
            and original_preflight['container_build_only'] is False, 'original preflight differs')
    modules = (provenance / 'submodules.txt').read_bytes()
    require(modules == original_preflight['submodules'].encode()
            and modules == git(source, 'submodule', 'status', '--recursive'), 'original gitlinks changed')
    builder = git(source, 'show', old_revision + ':scripts/ec/ci/build-native.sh').decode()
    block = builder.split('sha256sum scripts/ec/install-build-deps.sh', 1)[1].split('| tee "$work/provenance/build-inputs.sha256"', 1)[0]
    names = shlex.split('scripts/ec/install-build-deps.sh' + block.replace('\\\n', ' '))
    verify_source_snapshot(source, provenance / 'build-inputs.sha256', old_revision, names)
    verify_source_snapshot(source, provenance / 'cargo-locks.sha256', old_revision,
                           ('Cargo.lock', 'src/storage/ec/Cargo.lock'))
    isal = read(provenance / 'isal-prepare.json')
    require(isal['source_lock_sha256'] == after['scripts/ec/reference/downloads.json']
            and isal['helper_sha256'] == after['scripts/ec/ci/prepare-isal.py']
            and isal['prefix'] == str(work / 'isal-prefix'), 'original ISA-L source binding differs')
    require(Path(isal['provider']['path']).is_relative_to(work / 'isal-prefix')
            and sha(isal['provider']['path']) == isal['provider']['sha256'], 'original ISA-L provider changed')
    for package in isal['packages']:
        archive = work / 'isal-downloads' / (package['package'] + '.deb')
        require(archive.stat().st_size == package['size'] and sha(archive) == package['sha256'],
                'original ISA-L archive changed')
    fdb = read(provenance / 'fdb-link-probe.json')
    require(fdb['status'] == 'linked-and-loaded-fixed-client'
            and fdb['provider'] == str(work / 'deps/lib/libfdb_c.so')
            and sha(fdb['provider']) == fdb['provider_sha256'] == fdb['expected_package_library_sha256'],
            'original FDB provider changed')
    inputs = epoch_inputs(source, work)  # Exact patch tree, tools/packages, private paths/libraries, Rust and provider bytes.
    evidence = [previous / name for name in ('intent.json', 'outcome.json', 'command.json', 'process.json',
                                            'monitor.json', 'build.stdout', 'build.stderr')]
    evidence += [p for p in sorted(provenance.iterdir()) if p.is_file()]
    evidence.append(cache)
    return {'schema': 1, 'kind': 'verified-configured-failure-recovery', 'previous_attempt': str(previous),
            'original_revision': old_revision, 'original_evidence': {str(p): sha(p) for p in evidence},
            'original_source_inputs': before, 'inputs': inputs,
            'epoch_scope': 'new full-tree baseline after recorded-input/provider revalidation; no previous full-tree epoch existed',
            'reconfigure_required': True, 'build_success': False}


def checkpoint():
    attempt, intent = context()
    source, work = Path(intent['source']), Path(intent['work'])
    source_identity(source, intent['revision'])
    data = {'schema': 1, 'source': str(source), 'work': str(work), 'initial_revision': intent['revision'],
            'inputs': epoch_inputs(source, work)}
    if intent['mode'] == 'recover-configured':
        recovery = read(attempt / 'recovery.json')
        require(data['inputs'] == recovery['inputs'], 'recovery input drift during configure')
        data['recovery_sha256'] = sha(attempt / 'recovery.json')
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
    for name in ARCHIVED_NAMES:
        path = work / 'provenance' / name
        if path.exists():
            require(path.is_file() and not path.is_symlink(), 'invalid old receipt')
            os.rename(path, archive / name)
    cache = work / 'build/CMakeCache.txt'
    if cache.exists():
        require(cache.is_file() and not cache.is_symlink(), 'invalid previous CMake cache')
        with cache.open('rb') as source, (archive / 'CMakeCache.txt').open('xb') as target:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
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
            require(state['state_root'] == str(state_root), 'managed state root changed')
        recovery = None
        mode = 'recover-configured' if args.operation == 'recover-configured' else ('resume' if work.exists() else 'fresh')
        if mode != 'fresh':
            require(state is not None, 'existing work has no managed owner/checkpoint; cannot adopt')
            preflight.canonical(work)
            refreshed = preflight.managed_existing_paths(source, work, read(work / 'provenance/local-preflight.json'))
            if mode == 'recover-configured':
                recovery = verify_configured_recovery(source, work, state)
            else:
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
        if mode != 'fresh':
            write_new(attempt / 'host-preflight.json', refreshed)
        if recovery is not None:
            recovery['preserved_evidence'] = {
                str(attempt / 'previous' / Path(p).name)
                if (Path(p).parent == work / 'provenance' and Path(p).name in ARCHIVED_NAMES)
                or Path(p) == work / 'build/CMakeCache.txt' else p: digest
                for p, digest in recovery['original_evidence'].items()}
            write_new(attempt / 'recovery.json', recovery)
        current = dict(intent, attempt=str(attempt), status='running')
        replace_record(state_path, current)
        if mode != 'fresh':
            archive_previous(attempt, work)
        if recovery is not None:
            require(all(sha(p) == digest for p, digest in recovery['preserved_evidence'].items()),
                    'preserved original recovery evidence changed')
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', EC_LOCAL_BUILD_ATTEMPT=str(attempt), EC_LOCAL_BUILD_LOCK_FD=str(lock),
                           EC_LOCAL_BUILD_MODE='fresh' if mode == 'fresh' else 'resume')
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
    parser.add_argument('operation', choices=('run', 'recover-configured', 'child-check', 'checkpoint'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--revision')
    parser.add_argument('--build-jobs', type=int, choices=JOBS, default=8)
    args = parser.parse_args()
    if args.operation in ('run', 'recover-configured'):
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
