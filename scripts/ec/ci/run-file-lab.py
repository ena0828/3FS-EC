#!/usr/bin/env python3
"""Compose native-GC file CLI and two-mount acceptance on a fresh private tree.

The ordinary hosted runner packages one new tree, hands only that tree to UID
1000, then execs the ordinary-UID runtime. Explicit local mode keeps the actual
ordinary UID/GID and inherited resource limits without sudo or chown.
No RPC, FUSE ownership or recovery
protocol is implemented here. Private logs/keys remain on the disposable host.
Owner.command and final wait retain ownership without a local wall-clock cap;
the enclosing workflow cap may interrupt them and is not a clean-stop proof.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

TARGETS = ('storage_main', 'mgmtd_main', 'meta_main', 'admin_cli', 'ec_stripe_cli',
           'ec_file_cli', 'hf3fs_fuse_main', 'ec_mount_read_probe')
SERVICE_NAMES = {'fdb', 'mgmtd', 'storage', 'meta'}
PHASE = 'arguments'
PHASES = {'arguments', 'source', 'core', 'lab-build', 'prepare', 'package', 'copy-fdb',
          'inventory', 'handoff', 'uid-handoff', 'exec-uid1000', 'exec-same-user', 'runtime-preflight',
          'doctor', 'packaged-loader', 'bootstrap', 'cli-basic', 'cli-repair', 'dump-fuse-default.toml',
          'dump-launcher-default.toml', 'prepare-fuse', 'mode4-lifecycle', 'cleanup',
          'cleanup-unknown', 'receipt'}


class GateError(ValueError):
    """Only static messages written in this driver are safe for public logs."""


def phase(value):
    global PHASE
    if value not in PHASES:
        raise GateError('unexpected internal phase')
    PHASE = value


def diagnostic(error):
    result = {'phase': PHASE, 'error_type': type(error).__name__}
    if isinstance(error, GateError):
        result['detail'] = str(error)[:240]
    elif isinstance(error, OSError):
        result['errno'] = error.errno
    elif isinstance(error, subprocess.CalledProcessError):
        result['returncode'] = error.returncode
    return result


def require(ok, message):
    if not ok:
        raise GateError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 << 20,
            'invalid or oversized JSON input')
    value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    require(type(value) is dict, 'JSON object required')
    return value


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(path):
    require(path.is_absolute() and '..' not in path.parts, 'absolute canonical path required')
    require(path == path.resolve(strict=True), 'redirected path rejected')
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'symlink ancestor rejected')
    return path


def private(path, uid):
    canonical(path)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o077,
            'private owner directory required')


def write_new(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def copy_new(source, target, mode=0o600):
    canonical(source)
    before = sha(source)
    with source.open('rb') as incoming:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as outgoing:
            while block := incoming.read(1 << 20):
                outgoing.write(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    require(sha(target) == before and sha(source) == before, 'exclusive copy hash differs')
    return before


def tree_rows(root, uid, *, retain=False):
    """Open every entry by a held parent FD; never follow links during handoff.

    The only privileged mutations use these verified FDs after the full check.
    No recursive chown, path concatenation traversal or adopted tree is used.
    """
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds, rows = [root_fd], []
    device = os.fstat(root_fd).st_dev
    try:
        def visit(fd, relative, depth):
            require(depth <= 16 and len(rows) < 4096, 'handoff tree exceeds bounds')
            info = os.fstat(fd)
            directory = stat.S_ISDIR(info.st_mode)
            require(info.st_dev == device and info.st_uid == uid, 'foreign device or owner in handoff')
            require(directory or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                    'only unlinked-to-other-paths regular files and directories are allowed')
            mode = stat.S_IMODE(info.st_mode)
            require(not mode & 0o7000 and (not mode & 0o077 if directory else not mode & 0o022),
                    'unsafe handoff permissions')
            row = {'path': relative, 'kind': 'directory' if directory else 'file', 'mode': mode}
            if not directory:
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    row.update(size=info.st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
            rows.append(row)
            if directory:
                for name in sorted(os.listdir(fd)):
                    require(name not in ('.', '..') and '/' not in name, 'invalid directory entry')
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    fds.append(child)
                    visit(child, name if relative == '.' else relative + '/' + name, depth + 1)
        visit(root_fd, '.', 0)
        if retain:
            return rows, fds
        return rows
    finally:
        if not retain or sys.exc_info()[0] is not None:
            for fd in reversed(fds):
                os.close(fd)


def handoff_shape(parent, request, *, suffix=''):
    require(suffix == '' or re.fullmatch(r'-spare-(central|pipeline|helper)-[12]', suffix) is not None,
            'invalid fixed handoff suffix')
    if suffix:
        require(request.get('strategy') in ('central', 'pipeline', 'helper')
                and type(request.get('failures')) is int and request['failures'] in (1, 2)
                and suffix == '-spare-' + request['strategy'] + '-' + str(request['failures']),
                'handoff suffix differs from the requested fault case')
    require(re.fullmatch(r'ec-h-[1-9][0-9]*-[1-9][0-9]*' + re.escape(suffix), parent.name) is not None
            and parent.parent == Path('/tmp'), 'handoff path must be the fixed fresh CI root')
    require(type(request['schema']) is int and request['schema'] == 1 and request['parent'] == str(parent)
            and request['creator_uid'] == 1001 and request['target_uid'] == 1000,
            'handoff identity differs')
    require(parent.name == 'ec-h-' + request['run_id'] + '-' + request['run_attempt'] + suffix, 'run identity differs')
    paths = [row['path'] for row in request['inventory']]
    require(len(paths) == len(set(paths)) and '.' in paths, 'duplicate or missing inventory root')
    require(all(p == '.' or (not p.startswith('/') and all(part not in ('', '.', '..')
                for part in p.split('/'))) for p in paths), 'inventory path escapes root')


def privileged_handoff(parent, expected_sha, *, suffix='', driver_name='run-file-lab.py'):
    phase('uid-handoff')
    require(os.getuid() == os.geteuid() == 0, 'handoff requires the scoped sudo invocation')
    private(parent, 1001)
    request_path = parent / 'handoff-request.json'
    require(sha(request_path) == expected_sha, 'handoff request hash differs')
    request = read_json(request_path)
    require((not suffix and driver_name == 'run-file-lab.py')
            or (bool(suffix) and driver_name == 'run-spare-lab.py'), 'unexpected handoff driver')
    handoff_shape(parent, request, suffix=suffix)
    info = parent.stat()
    require([info.st_dev, info.st_ino] == request['parent_identity'], 'original directory was replaced')
    rows, fds = tree_rows(parent, 1001, retain=True)
    try:
        require([row for row in rows if row['path'] != 'handoff-request.json'] == request['inventory'],
                'fresh tree differs from the pre-handoff inventory')
        require(sha(parent / 'tools' / driver_name) == request['driver_sha256'], 'copied driver differs')
        if suffix:
            require(sha(parent / 'tools/run-file-lab.py') == request['shared_driver_sha256'],
                    'copied shared handoff driver differs')
        # Refuse to borrow an account that already owns unrelated live work.
        for path in Path('/proc').iterdir():
            if path.name.isdecimal():
                try:
                    fields = re.search(r'^Uid:\s+(.+)$', (path / 'status').read_text(), re.M)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                require(fields is not None and 1000 not in map(int, fields[1].split()),
                        'UID1000 already owns an active process')
        import grp
        import pwd
        try:
            grp.getgrgid(1000)
        except KeyError:
            subprocess.run(['/usr/sbin/groupadd', '--gid', '1000', 'ec-native-1000'], check=True)
        try:
            account = pwd.getpwuid(1000)
        except KeyError:
            subprocess.run(['/usr/sbin/useradd', '--uid', '1000', '--gid', '1000', '--no-create-home',
                            '--home-dir', str(parent / 'home'), '--shell', '/usr/sbin/nologin',
                            'ec-native-1000'], check=True)
            account = pwd.getpwuid(1000)
        require(account.pw_uid == 1000 and account.pw_gid == 1000, 'unexpected UID1000 primary group')
        # All checks complete before changing any FD; children before root.
        for fd in reversed(fds):
            require(os.fstat(fd).st_uid == 1001, 'owner changed during handoff')
            os.fchown(fd, 1000, 1000)
        marker = {'schema': 1, 'request_sha256': expected_sha, 'uid': 1000, 'gid': 1000,
                  'user': account.pw_name, 'parent_identity': request['parent_identity'],
                  'services_started': False}
        write_new(parent / 'handoff-complete.json', marker)
        os.chown(parent / 'handoff-complete.json', 1000, 1000, follow_symlinks=False)
        os.fsync(fds[0])
        print(json.dumps(marker, sort_keys=True))
    finally:
        for fd in reversed(fds):
            os.close(fd)


def core_gate(source, build, fdb, path):
    core = module(source / 'scripts/ec/ci/run-core-tests.py', 'lab_core_receipts')
    common = module(source / 'scripts/ec/test-native-fragments.py', 'lab_core_common')
    record = read_json(path)
    require(record['status'] == 'passed' and record['exitcode'] == 0 and record['passed_tests'] == 21
            and not record['failures'] and not record['signals'], 'real core21 acceptance is required')
    require(record['source'] == str(source) and record['build'] == str(build)
            and record['work'] == str(path.parent), 'core receipt path binding differs')
    require(record['runner_sha256'] == sha(source / 'scripts/ec/ci/run-core-tests.py'), 'core driver changed')
    for name, expected in record['helpers_sha256'].items():
        require(expected == sha(source / 'scripts/ec' / name), 'core helper changed')
    require(set(record['helpers_sha256']) == {'test-meta-catalog.py', 'test-native-fragments.py'}, 'core helper set differs')
    for name, expected in [('meta', core.META_CASES), ('fuse', core.FUSE_CASES)]:
        stage = record[name]
        folder = path.parent / name
        require(stage['status'] == 'passed' and stage['passed_tests'] == len(expected)
                and stage['skipped_tests'] == 0, 'incomplete core phase')
        core.check_xml(common.xml_tests(folder / 'tests.xml'), expected)
        core.check_listing(common.listed_tests(folder / ('test-list.log' if name == 'meta' else 'list.log')), expected)
        require(stage['xml_sha256'] == sha(folder / 'tests.xml'), 'core XML changed')
        require(stage['listing_sha256'] == sha(folder / ('test-list.log' if name == 'meta' else 'list.log')), 'core listing changed')
        require(stage['binary_sha256'] == sha(build / 'tests' / ('test_meta' if name == 'meta' else 'test_fuse_ec')),
                'accepted core binary changed')
    meta = read_json(path.parent / 'meta/results.json')
    require(record['meta']['receipt_sha256'] == sha(path.parent / 'meta/results.json'), 'Meta receipt changed')
    core.check_meta_receipt(meta, build / 'tests/test_meta', path.parent / 'meta')
    for name in ('fdbserver', 'fdbcli'):
        require(meta['binaries'][name]['sha256'] == sha(fdb / name), 'accepted FDB binary changed')
    core.command_ok(record['fuse']['listing'])
    core.command_ok(record['fuse']['execution'])
    return {'path': str(path), 'sha256': sha(path), 'passed_tests': 21,
            'binaries': {binary: record[stage]['binary_sha256']
                         for stage, binary in (('meta', 'test_meta'), ('fuse', 'test_fuse_ec'))}}


def build_gate(built, native, source, build, revision):
    """Require the same formal build producer and backend as the spare lab."""
    require(type(built.get('schema')) is int and built['schema'] == 1
            and tuple(built.get('targets', [])) == TARGETS
            and set(built.get('binaries', {})) == set(TARGETS), 'explicit eight-target lab build required')
    for item in (built, native):
        require(type(item.get('schema')) is int and item['schema'] == 1
                and item.get('source') == str(source) and item.get('build') == str(build)
                and item.get('revision') == revision and item.get('backend') in ('scalar', 'isal')
                and item.get('acceptance_executed') is False, 'same-source backend build identity differs')
    require(native.get('lab_targets_requested') is True
            and all(built.get(key) == native.get(key) for key in
                    ('backend', 'isal', 'build_script_sha256', 'cmake_cache_sha256'))
            and all(native.get('binaries', {}).get(name) == digest for name, digest in built['binaries'].items()),
            'native and lab build receipts differ')
    if built['backend'] == 'scalar':
        require(built.get('isal') is None, 'Scalar receipt unexpectedly selects ISA-L')
    else:
        provider = built.get('isal', {}).get('provider', {})
        require(provider.get('sha256') == '40ccd5e5abaff0451feff750d2b011370a546ac4706d1b06b9285ac26eda2c3c',
                'unexpected ISA-L provider digest')


def local_identity(request, uid, euid, gid, egid):
    require(type(uid) is int and uid > 0 and uid == euid and type(gid) is int and gid >= 0 and gid == egid,
            'local mode requires unchanged ordinary real/effective UID and GID')
    require(request.get('execution_mode') == 'local-same-user'
            and type(request.get('creator_uid')) is int and request['creator_uid'] == uid
            and type(request.get('target_uid')) is int and request['target_uid'] == uid
            and type(request.get('target_gid')) is int and request['target_gid'] == gid,
            'local OS identity differs from preparation')


def local_shape(parent, request):
    local_identity(request, os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    private(parent, os.geteuid())
    private(parent.parent, os.geteuid())
    require(type(request.get('schema')) is int and request['schema'] == 1
            and request.get('parent') == str(parent)
            and request.get('parent_identity') == [parent.stat().st_dev, parent.stat().st_ino],
            'local preparation identity differs')


def mount_host_gate():
    """Check prerequisites without mounting or changing host permissions."""
    import resource
    for which, minimum in ((resource.RLIMIT_NOFILE, 65536), (resource.RLIMIT_MEMLOCK, 3 << 30)):
        require(all(value == resource.RLIM_INFINITY or value >= minimum for value in resource.getrlimit(which)),
                'runtime resource limit insufficient')
    tool = shutil.which('fusermount3')
    require(tool is not None, 'system fusermount3 is required')
    unmount = Path(tool).resolve(strict=True)
    require(unmount.is_file() and os.access(unmount, os.X_OK), 'fusermount3 is not executable')
    fd = os.open('/dev/fuse', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode), '/dev/fuse is not a character device')
    finally:
        os.close(fd)
    return {'fusermount3': str(unmount), 'sha256': sha(unmount), 'device_opened': True,
            'mount_permission_proven': False}


def resolution_gate(backend, text, lab, *, fuse=False):
    require('not found' not in text, 'packaged runtime library unresolved')
    observed = {}
    for name in ('libisal.so.2', 'libfdb_c.so', 'libfuse3.so.3'):
        matches = re.findall(r'^\s*' + re.escape(name) + r'\s+=>\s+(\S+)\s+\(', text, re.M)
        if matches:
            require(matches == [str(lab / 'lib' / name)], 'loader resolved a provider outside the package')
            observed[name] = matches[0]
    require((backend == 'isal' and 'libisal.so.2' in observed)
            or (backend == 'scalar' and 'libisal' not in text), 'loader differs from the selected codec backend')
    require(not fuse or 'libfuse3.so.3' in observed, 'FUSE loader provider is missing')
    return observed


def require_cli_result(value):
    require(value.get('success') is True and value.get('failure') is None
            and value.get('all_owned_children_joined') is True and value.get('steps'), 'CLI phase incomplete')
    require(all(step.get('checks_complete') is True for step in value['steps']), 'CLI step lacks checks')


def require_shutdown(final, cleanup, ready_run, supervisor_code):
    codes = cleanup.get('exit_codes') if type(cleanup) is dict else None
    require(type(final) is dict and {'run', 'stage', 'failure'} <= set(final)
            and type(supervisor_code) is int and supervisor_code == 0
            and final.get('run') == ready_run and final.get('stage') == 'stopped'
            and final.get('failure') is None and type(cleanup) is dict and cleanup.get('clean') is True
            and type(codes) is dict and set(codes) == SERVICE_NAMES
            and all(type(code) is int and code in ({0, -15} if name == 'fdb' else {0})
                    for name, code in codes.items()), 'native shutdown not fully confirmed')


def package_backend_gate(built, package, lab):
    """Bind an explicitly selected codec provider; legacy receipts stay unlabelled."""
    if 'backend' not in built and 'isal' not in built:
        return {'backend': 'unrecorded', 'provider_verified': False}
    require(built.get('backend') in ('scalar', 'isal') and 'isal' in built, 'incomplete codec backend receipt')
    files = package.get('files', {})
    isal_files = {name for name in files if Path(name).name.startswith('libisal')}
    if built['backend'] == 'scalar':
        require(built['isal'] is None and not isal_files, 'Scalar package must not carry ISA-L')
        return {'backend': 'scalar', 'provider_verified': False}
    require(isal_files == {'lib/libisal.so.2'} and type(built['isal']) is dict, 'ISA-L package provider missing or ambiguous')
    provider = built['isal'].get('provider', {})
    require(type(provider.get('path')) is str and type(provider.get('sha256')) is str
            and re.fullmatch(r'[0-9a-f]{64}', provider['sha256']) is not None, 'invalid bound ISA-L provider')
    item = files['lib/libisal.so.2']
    expected = canonical(Path(provider['path']))
    actual = canonical(Path(item['source']))
    require(actual == expected and item.get('kind') == 'shared-library'
            and item.get('sha256') == provider['sha256']
            and sha(actual) == sha(canonical(lab / 'lib/libisal.so.2')) == provider['sha256'],
            'packaged ISA-L source or bytes differ from the selected build')
    return {'backend': 'isal', 'provider_verified': True, 'provider_source': str(expected),
            'packaged_provider': str(lab / 'lib/libisal.so.2'), 'provider_sha256': provider['sha256']}


def require_mount_result(value):
    cleanup = value.get('cleanup', {})
    require(value.get('schema') == 1 and value.get('status') == 'passed' and value.get('exitcode') == 0
            and value.get('services_started_or_stopped') is False, 'lifecycle phase failed')
    require(cleanup.get('all_fuse_joined') is True and cleanup.get('all_commands_joined') is True
            and cleanup.get('unmounted') is True and cleanup.get('normal_unmounts') == 2
            and cleanup.get('fuse_exitcodes') == [0, 0] and cleanup.get('unknown_owned_processes') == [],
            'lifecycle did not confirm both normal joins')
    probes = value.get('probes', [])
    expected = {(kind, phase, 'confirmed') for kind in ('posix', 'usrbio') for phase in ('prepare', 'verify')}
    require(len(probes) == 4 and {(p['kind'], p['phase'], p['state']) for p in probes} == expected,
            'lifecycle probe set differs')
    for kind in ('posix', 'usrbio'):
        before = next(p for p in probes if p['kind'] == kind and p['phase'] == 'prepare')
        after = next(p for p in probes if p['kind'] == kind and p['phase'] == 'verify')
        require(type(before['bytes']) is int and before['bytes'] > 0 and after['bytes'] == before['bytes']
                and re.fullmatch(r'[0-9a-f]{64}', before['sha256']) is not None
                and after['sha256'] == before['sha256'], 'lifecycle remount bytes differ')
        if kind == 'usrbio':
            require(type(before['inode']) is int and before['inode'] > 0 and after['inode'] == before['inode']
                    and before['actual_abi_reads'] == after['actual_abi_reads'] == 3, 'actual USRBIO identity/ABI differs')


def mount_cleanup_known(value):
    cleanup = value.get('cleanup', {})
    return (cleanup.get('all_fuse_joined') is True and cleanup.get('all_commands_joined') is True
            and cleanup.get('unmounted') is True and cleanup.get('unknown_owned_processes') == [])


def process_identity(pid):
    path = Path('/proc') / str(pid)
    text = (path / 'stat').read_text()
    fields = text[text.rfind(')') + 2:].split()
    require(len(fields) > 19 and fields[0] not in ('Z', 'X'), 'owned process is not live')
    return {'pid': pid, 'start_ticks': fields[19], 'executable': os.readlink(path / 'exe')}


def stop_signals(owner):
    return {sig: signal.signal(sig, owner.interrupted) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}


def runtime(parent):
    phase('runtime-preflight')
    private(parent, os.geteuid())
    request = read_json(parent / 'handoff-request.json')
    local = request.get('execution_mode') == 'local-same-user'
    if local:
        local_shape(parent, request)
    else:
        require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1000,
                'hosted runtime requires actual UID/GID1000')
        handoff_shape(parent, request)
    marker = read_json(parent / 'handoff-complete.json')
    require(marker.get('uid') == os.geteuid() and marker.get('gid') == os.getegid(), 'prepared owner differs')
    require(not local or marker.get('ownership_changed') is False, 'local mode cannot change ownership')
    require(marker['request_sha256'] == sha(parent / 'handoff-request.json')
            and marker['parent_identity'] == request['parent_identity']
            and request['parent_identity'] == [parent.stat().st_dev, parent.stat().st_ino]
            and sha(Path(__file__).resolve()) == request['driver_sha256'], 'handoff/source proof differs')
    require([row for row in tree_rows(parent, os.geteuid()) if row['path'] not in
             ('handoff-request.json', 'handoff-complete.json')] == request['inventory'], 'post-handoff inputs changed')
    lab = parent / '3fs-ec-native-file'
    sys.path.insert(0, str(lab / 'scripts'))
    helper = module(lab / 'scripts/fuse-read-acceptance.py', 'lab_owner')
    native = module(lab / 'scripts/native-v2.py', 'lab_native')
    output = parent / 'runtime'
    output.mkdir(mode=0o700)
    owner = helper.Owner(output)
    previous = stop_signals(owner)
    report = {'schema': 1, 'status': 'running', 'revision': request['revision'], 'uid': os.geteuid(),
              'gid': os.getegid(), 'execution_mode': request.get('execution_mode', 'hosted-handoff'),
              'preparation_sha256': sha(parent / 'handoff-request.json'),
              'native_build_sha256': request['native_build_sha256'], 'lab_build_sha256': request['lab_build_sha256'],
              'backend_validation': request['backend_validation'],
              'core': request['core'], 'receipts': [], 'services_started': False, 'exitcode': 1}
    supervisor = None
    failure = None
    lifecycle_started = False
    try:
        report['mount_host'] = mount_host_gate()
        manifest = read_json(lab / 'cluster.json')
        remote_user = manifest.get('authenticated_user', {'uid': 1000, 'gid': 1000})
        require(remote_user == {'uid': os.geteuid(), 'gid': os.getegid()},
                'fresh remote file identity differs from runtime UID/GID')
        report['authenticated_user'] = remote_user
        os.environ.pop('LD_PRELOAD', None)
        os.environ['LD_LIBRARY_PATH'] = str(lab / 'lib')
        def command(name, argv):
            phase(name)
            owner.checkpoint()
            result = owner.command(name, argv)
            owner.checkpoint()
            return result
        command('doctor', [sys.executable, '-B', lab / 'scripts/native-v2.py', 'doctor', '--root', lab])
        report['packaged_loader'] = {}
        for name in ('storage_main', 'hf3fs_fuse_main'):
            listing = command('packaged-loader', ['ldd', lab / 'bin' / name]).decode('utf-8')
            report['packaged_loader'][name] = resolution_gate(
                request['backend_validation']['backend'], listing, lab, fuse=name == 'hf3fs_fuse_main')
        phase('bootstrap')
        log = (output / 'supervisor.log').open('xb')
        try:
            supervisor = subprocess.Popen([sys.executable, '-B', str(lab / 'scripts/native-v2.py'),
                                           'start', '--root', str(lab), '--mode', 'initialize'],
                                          cwd=lab, stdout=log, stderr=subprocess.STDOUT)
            report.update(services_started=True, supervisor_pid=supervisor.pid)
            report['supervisor_identity'] = process_identity(supervisor.pid)
            write_new(output / 'supervisor-started.json', report)
            deadline = time.monotonic() + 900
            ready = None
            while time.monotonic() < deadline:
                owner.checkpoint()
                require(supervisor.poll() is None, 'native supervisor exited before readiness')
                try:
                    state = native.request_control(lab, 'status')
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(0.25)
                    continue
                if state['stage'] == 'ready':
                    ready = state
                    break
                time.sleep(0.25)
            require(ready is not None, 'native readiness timed out')
            ready_identities = {row['name']: process_identity(row['pid']) for row in ready['processes']}
            def healthy():
                owner.checkpoint()
                require(supervisor.poll() is None, 'owned supervisor exited')
                now = native.request_control(lab, 'status')
                require(now['stage'] == 'ready' and now['failure'] is None and now['run'] == ready['run']
                        and now['processes'] == ready['processes'] and now['root'] == str(lab)
                        and {row['name'] for row in now['processes']} == SERVICE_NAMES
                        and len(now['processes']) == 4
                        and all(row['exit_code'] is None for row in now['processes']), 'native identity/readiness changed')
                require({row['name']: process_identity(row['pid']) for row in now['processes']} == ready_identities,
                        'service process birth identity changed')
                disk = os.statvfs(lab)
                require(disk.f_bavail * disk.f_frsize >= 4 << 30, 'less than existing 4GiB lab disk reserve')
            healthy()
            report['ready'] = ready
            report['ready_process_identities'] = ready_identities
            for cli_phase in ('basic', 'repair'):
                healthy()
                command('cli-' + cli_phase, [sys.executable, '-B', lab / 'scripts/file-cli-acceptance.py',
                                            '--root', lab, '--label', 'hosted-' + cli_phase, cli_phase])
                receipt = lab / 'client/file-cli-acceptance' / ('hosted-' + cli_phase) / cli_phase / 'report/result.json'
                require_cli_result(read_json(receipt))
                report['receipts'].append({'phase': cli_phase, 'path': str(receipt), 'sha256': sha(receipt)})
            healthy()
            mountpoint = parent / 'mount'
            mountpoint.mkdir(mode=0o700)
            for flag, name in (('--dump_default_cfg', 'fuse-default.toml'),
                               ('--dump_default_launcher_cfg', 'launcher-default.toml')):
                data = command('dump-' + name, [lab / 'bin/hf3fs_fuse_main', flag])
                fd = os.open(parent / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            command('prepare-fuse', [sys.executable, '-B', lab / 'scripts/prepare-fuse-file.py', '--root', lab,
                    '--fuse-default', parent / 'fuse-default.toml', '--launcher-default', parent / 'launcher-default.toml',
                    '--output-dir', parent / 'fuse-config', '--mountpoint', mountpoint, '--create-new', '--shard-bytes', '65536'])
            healthy()
            lifecycle_started = True
            command('mode4-lifecycle', [sys.executable, '-B', lab / 'scripts/mode4-lifecycle-acceptance.py',
                    '--root', lab, '--preparation', parent / 'fuse-config/preparation.json', '--work', parent / 'mode4'])
            receipt = parent / 'mode4/result.json'
            lifecycle = read_json(receipt)
            require_mount_result(lifecycle)
            for probe in lifecycle['probes']:
                proof = canonical(Path(probe['receipt']))
                require(proof.is_relative_to(parent / 'mode4') and sha(proof) == probe['receipt_sha256'],
                        'lifecycle probe receipt hash differs')
            report['receipts'].append({'phase': 'mode4-lifecycle', 'path': str(receipt), 'sha256': sha(receipt)})
            healthy()
            report['business_passed'] = True
        except BaseException:
            report['failure_phase'] = PHASE
            raise
        finally:
            phase('cleanup')
            # Only this owned supervisor is signalled if its private control
            # endpoint is unavailable. No PID files or adopted descendants.
            if supervisor is not None:
                safe_to_stop = not lifecycle_started
                if lifecycle_started:
                    try:
                        lifecycle = read_json(parent / 'mode4/result.json')
                        safe_to_stop = mount_cleanup_known(lifecycle) and not helper.mounts_at(parent / 'mount')
                    except Exception:
                        safe_to_stop = False
                if not safe_to_stop and supervisor.poll() is None:
                    # The lifecycle driver still owns its unknown FUSE/probe
                    # descendants. Do not tear down their services or adopt them.
                    report['cleanup_blocked'] = True
                    phase('cleanup-unknown')
                    try:
                        write_new(output / 'cleanup-blocked.json', report)
                        print('file-lab: cleanup unconfirmed; retaining owned supervisor, no forced stop', flush=True)
                    finally:
                        supervisor.wait()  # External cancellation is not a cleanup-success receipt.
                try:
                    if supervisor.poll() is None:
                        try:
                            native.request_control(lab, 'stop')
                        except Exception:
                            supervisor.terminate()
                finally:
                    supervisor.wait()
                report['supervisor_exitcode'] = supervisor.returncode
                final_path = lab / 'state/last-supervisor.json'
                if final_path.is_file():
                    report['final_supervisor_observation'] = read_json(final_path)
            log.close()
        final = read_json(lab / 'state/last-supervisor.json')
        cleanup = read_json(lab / 'logs' / report['ready']['run'] / 'cleanup.json')
        require_shutdown(final, cleanup, report['ready']['run'], supervisor.returncode)
        require(not helper.mounts_at(parent / 'mount'), 'mount still present after lifecycle')
        report.update(status='passed', exitcode=0, cleanup=cleanup)
    except BaseException as error:
        failure = error
        report.update(status='failed', error_type=type(error).__name__, error=str(error), exitcode=1,
                      diagnostic=diagnostic(error))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        write_new(output / 'result.json', report)
    print(json.dumps({'status': report['status'], 'exitcode': report['exitcode'], 'revision': report['revision'],
                      'receipt_sha256': sha(output / 'result.json'), 'receipts': report['receipts'],
                      'services_started': report['services_started'], 'diagnostic': report.get('diagnostic'),
                      'failure_phase': report.get('failure_phase')},
                     sort_keys=True), flush=True)
    return report['exitcode']


def prepare(args):
    phase('source')
    local = args.local_work is not None
    source, build, fdb, core_path = map(canonical, (args.source, args.build, args.fdb_bin_dir, args.core_record))
    if local:
        require(os.getuid() == os.geteuid() and os.getuid() > 0 and os.getgid() == os.getegid(),
                'local mode requires unchanged ordinary real/effective UID and GID')
        work = canonical(build.parent)
        require(build.name == 'build' and fdb == work / 'fdb/bin', 'local build/FDB layout differs')
        private(args.local_work.parent, os.geteuid())
        require(args.local_work.is_absolute() and '..' not in args.local_work.parts
                and not os.path.lexists(args.local_work), 'fresh canonical local work required')
        require(all(not args.local_work.is_relative_to(path) and not path.is_relative_to(args.local_work)
                    for path in (source, work, core_path.parent)), 'local lab overlaps source/build/core work')
        require(len(os.fsencode(args.local_work / '3fs-ec-native-file/state/control.sock')) < 104,
                'local work path is too long for the control socket')
        mount_host_gate()
        run_id, attempt = None, None
    else:
        require(os.getuid() == os.geteuid() == 1001, 'preparation requires the observed ordinary hosted UID1001')
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'hosted Linux job required')
        run_id, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
        require(all(re.fullmatch(r'[1-9][0-9]*', x) for x in (run_id, attempt)), 'invalid hosted run identity')
        work = canonical(Path(os.environ['RUNNER_TEMP']) / 'ec-native')
        require(source == canonical(Path(os.environ['GITHUB_WORKSPACE'])) and build == work / 'build'
                and fdb == work / 'fdb/bin' and core_path == work / 'acceptance/results.json', 'unexpected source/build/core paths')
    require(Path(__file__).resolve() == source / 'scripts/ec/ci/run-file-lab.py', 'use the checked-out formal driver')
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    require(local or revision == os.environ['GITHUB_SHA'], 'source is not the triggering revision')
    subprocess.run(['git', '-C', str(source), 'diff', '--exit-code', 'HEAD', '--ignore-submodules=all'], check=True,
                   stdout=subprocess.DEVNULL)
    phase('core')
    core = core_gate(source, build, fdb, core_path)
    phase('lab-build')
    built = read_json(work / 'provenance/lab-build.json')
    native_path = work / 'provenance/native-build.json'
    native_build = read_json(native_path)
    build_gate(built, native_build, source, build, revision)
    require(all(native_build['binaries'].get(name) == digest for name, digest in core['binaries'].items()),
            'accepted core binaries differ from the same native build')
    require(built['build_script_sha256'] == sha(source / 'scripts/ec/ci/build-native.sh')
            and built.get('cmake_cache_sha256') == sha(build / 'CMakeCache.txt')
            and built.get('native_build_receipt_sha256') == sha(native_path), 'backend/native build input binding differs')
    require(all(built['binaries'][name] == sha(build / 'bin' / name) for name in TARGETS), 'lab binary changed')
    output = args.local_work.with_name(args.local_work.name + '-preparation') if local else work / 'lab-preparation'
    output.mkdir(mode=0o700)
    helper = module(source / 'scripts/ec/cluster/fuse-read-acceptance.py', 'lab_prepare_owner')
    owner = helper.Owner(output)
    previous = stop_signals(owner)
    parent = args.local_work if local else Path('/tmp') / ('ec-h-' + run_id + '-' + attempt)
    require(not os.path.lexists(parent) and (local or canonical(parent.parent) == Path('/tmp')),
            'fresh preparation root required')
    parent.mkdir(mode=0o700)
    lab = parent / '3fs-ec-native-file'
    try:
        def command(name, argv):
            phase(name)
            owner.checkpoint()
            data = owner.command(name, argv)
            owner.checkpoint()
            return data
        prepare_argv = [sys.executable, '-B', source / 'scripts/ec/cluster/native-v2.py', 'prepare',
                        '--root', lab, '--source', source, '--profile', 'gc', '--file-api', '--port-base', '13500']
        if local:
            prepare_argv.extend(['--user-uid', str(os.geteuid()), '--user-gid', str(os.getegid())])
        command('prepare', prepare_argv)
        command('package', [sys.executable, '-B', source / 'scripts/ec/package-services.py', '--build', build,
                           '--output', lab, '--native-gc', '--ec-file-mount'])
        manifests = list((lab / 'provenance').glob('services-*/manifest.json'))
        require(len(manifests) == 1, 'one new package manifest required')
        package = read_json(manifests[0])
        require(package['build_directory'] == str(build) and package['bundle_directory'] == str(lab), 'package path binding differs')
        for relative, item in package['files'].items():
            require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'invalid package relative path')
            require(sha(lab / relative) == item['sha256'], 'packaged contents differ')
            if item['kind'] == 'service':
                name = Path(relative).name
                require(item['source'] == str(build / 'bin' / name) and item['sha256'] == built['binaries'][name],
                        'packaged service differs from the current lab build')
        require({Path(p).name for p, item in package['files'].items() if item['kind'] == 'service'} == set(TARGETS),
                'package runtime target set differs')
        require('scripts/mode4-lifecycle-acceptance.py' in package['files'], 'lifecycle must be in formal package manifest')
        backend_validation = package_backend_gate(built, package, lab)
        phase('copy-fdb')
        for name in ('fdbserver', 'fdbcli'):
            copy_new(fdb / name, lab / 'bin' / name, 0o755)
        require(sha(lab / 'lib/libfdb_c.so') == sha(fdb.parent / 'lib/libfdb_c.so'), 'FDB shared library differs')
        for name in ('home', 'tmp', 'tools'):
            (parent / name).mkdir(mode=0o700)
        driver_sha = copy_new(Path(__file__).resolve(), parent / 'tools/run-file-lab.py')
        phase('inventory')
        request = {'schema': 1, 'parent': str(parent), 'parent_identity': [parent.stat().st_dev, parent.stat().st_ino],
                   'creator_uid': os.geteuid() if local else 1001, 'target_uid': os.geteuid() if local else 1000,
                   'target_gid': os.getegid() if local else 1000, 'run_id': run_id, 'run_attempt': attempt,
                   'execution_mode': 'local-same-user' if local else 'hosted-handoff',
                   'revision': revision, 'core': core, 'driver_sha256': driver_sha,
                   'backend_validation': backend_validation,
                   'package_manifest_sha256': sha(manifests[0]), 'lab_build_sha256': sha(work / 'provenance/lab-build.json'),
                   'native_build_sha256': sha(native_path),
                   'inventory': tree_rows(parent, os.geteuid())}
        write_new(parent / 'handoff-request.json', request)
        request_sha = sha(parent / 'handoff-request.json')
        if local:
            import pwd
            marker = {'schema': 1, 'request_sha256': request_sha, 'uid': os.geteuid(), 'gid': os.getegid(),
                      'user': pwd.getpwuid(os.geteuid()).pw_name, 'parent_identity': request['parent_identity'],
                      'services_started': False, 'ownership_changed': False}
            write_new(parent / 'handoff-complete.json', marker)
        else:
            marker = json.loads(command('handoff', ['sudo', '-n', '/usr/bin/python3', '-I', parent / 'tools/run-file-lab.py',
                                                   '--handoff', parent, '--request-sha256', request_sha]))
        require(marker['request_sha256'] == request_sha and marker['uid'] == (os.geteuid() if local else 1000),
                'handoff response differs')
        write_new(output / 'prepared.json', {'schema': 1, 'parent': str(parent), 'revision': revision,
                  'request_sha256': request_sha, 'handoff': marker, 'services_started': False})
        owner.checkpoint()
        phase('exec-same-user' if local else 'exec-uid1000')
        argv = ['/usr/bin/sudo', '-n', 'prlimit', '--memlock=3221225472:3221225472', '--nofile=65536:65536', '--',
                'setpriv', '--reuid=1000', '--regid=1000', '--clear-groups', 'env', '--chdir=' + str(parent),
                'HOME=' + str(parent / 'home'), 'USER=' + marker['user'], 'LOGNAME=' + marker['user'],
                'TMPDIR=' + str(parent / 'tmp'), 'LD_LIBRARY_PATH=' + str(lab / 'lib'),
                'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/bin/python3', '-I', parent / 'tools/run-file-lab.py',
                '--run-owned', parent]
        if local:
            argv = ['/usr/bin/env', '--chdir=' + str(parent), 'HOME=' + str(parent / 'home'),
                    'USER=' + marker['user'], 'LOGNAME=' + marker['user'], 'TMPDIR=' + str(parent / 'tmp'),
                    'LD_LIBRARY_PATH=' + str(lab / 'lib'), 'PATH=/usr/local/bin:/usr/bin:/bin',
                    '/usr/bin/python3', '-I', parent / 'tools/run-file-lab.py', '--run-owned', parent]
        # Replace this foreground command with its runtime. Hosted sudo forwards
        # signals/exit to UID1000; local exec keeps the same user and limits.
        # No cross-UID background Popen is discarded or adopted later.
        for sig in previous:
            signal.signal(sig, signal.SIG_DFL)
        os.execv(argv[0], list(map(str, argv)))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'fdb-bin-dir', 'core-record'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--local-work', type=Path, help='fresh private same-user work; no hosted environment or chown')
    internal = parser.add_mutually_exclusive_group()
    internal.add_argument('--handoff', type=Path, help=argparse.SUPPRESS)
    internal.add_argument('--run-owned', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--request-sha256', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.version_info >= (3, 11), 'Python 3.11 or newer required')
    require(sys.platform == 'linux', 'Linux only; no WSL/VM launcher is implemented')
    os.umask(0o077)
    sys.dont_write_bytecode = True
    os.environ.pop('LD_PRELOAD', None)
    if args.handoff:
        privileged_handoff(args.handoff, args.request_sha256)
        return 0
    if args.run_owned:
        return runtime(args.run_owned)
    require(all(getattr(args, name) is not None for name in ('source', 'build', 'fdb_bin_dir', 'core_record')),
            'source/build/fdb-bin-dir/core-record are required')
    prepare(args)
    return 1  # execv never returns on success.


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('file-lab: ' + json.dumps(diagnostic(error), sort_keys=True) + '; preserve private receipts', file=sys.stderr)
        raise SystemExit(2)
