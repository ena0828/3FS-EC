#!/usr/bin/env python3
"""Root-owned, trusted-host execution fencing; never a physical deletion proof.

This provider must enroll and launch a fresh dedicated storage identity before
Meta prepares its external retirement. It cannot adopt an existing lab process.
The host kernel/root and non-rollback provider disk are trusted. VM/disk clones,
host-root compromise and whole-host loss require an independent external provider.
"""
import argparse
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid

sys.dont_write_bytecode = True
DOMAIN = b'3FSEHF01'
MAX_JSON = 2 * 1024 * 1024
CGROUP_ROOT = Path('/sys/fs/cgroup/3fs-ec-fence')
PROVIDER_ROOT = Path('/var/lib/3fs-ec-fence/provider')


class ProviderError(ValueError):
    pass


class ProviderInterrupted(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise ProviderError(message)


def identifier(value):
    require(type(value) is str, 'UUID string required')
    parsed = uuid.UUID(value)
    require(parsed.int != 0 and str(parsed) == value, 'Canonical nonzero UUID required')
    return value


def integer(value, bits):
    require(type(value) is int and 0 < value < 2**bits, 'Positive bounded integer required')
    return value


def digest(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value) and value != '0' * 64,
            'Nonzero lowercase SHA256 required')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys.split()), 'Unexpected JSON fields')


def endpoint(value):
    exact(value, 'node chain target engine_uuid target_incarnation')
    for name, bits in [('node', 32), ('chain', 32), ('target', 64)]:
        integer(value[name], bits)
    identifier(value['engine_uuid'])
    identifier(value['target_incarnation'])
    return value


def validate_intent(value):
    exact(value, 'schema authority endpoint provider_id enrollment_id resource_generation '
          'retirement_id owner_namespace owner_uid request_id binding_digest')
    require(type(value['schema']) is int and value['schema'] == 1, 'Intent schema differs')
    for name in ('authority', 'provider_id', 'enrollment_id', 'resource_generation',
                 'retirement_id', 'owner_namespace', 'request_id'):
        identifier(value[name])
    require(type(value['owner_uid']) is int and value['owner_uid'] == 0, 'Root Meta owner required')
    endpoint(value['endpoint'])
    digest(value['binding_digest'])
    return value


def certificate_payload(intent, deny_digest, sequence=1):
    validate_intent(intent)
    digest(deny_digest)
    require(type(sequence) is int and sequence == 1, 'First irreversible retirement sequence required')
    ep = intent['endpoint']
    u = lambda name: uuid.UUID(intent[name]).bytes
    body = (DOMAIN + struct.pack('>HH', 1, 1) + u('authority') +
            struct.pack('>IIQ', ep['node'], ep['chain'], ep['target']) +
            uuid.UUID(ep['engine_uuid']).bytes + uuid.UUID(ep['target_incarnation']).bytes +
            u('provider_id') + u('enrollment_id') + u('resource_generation') +
            u('retirement_id') + u('owner_namespace') + struct.pack('>I', 0) + u('request_id') +
            bytes.fromhex(intent['binding_digest']) + bytes.fromhex(deny_digest) + struct.pack('>Q', sequence))
    require(len(body) == 248, 'Canonical certificate size differs')
    return body


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def read_json(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= MAX_JSON, 'JSON bound exceeded')
    return json.loads(raw, object_pairs_hook=no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def atomic_json(path, value):
    data = canonical(value) + b'\n'
    require(len(data) <= MAX_JSON, 'State bound exceeded')
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def safe_path(value):
    require(type(value) is str and '\x00' not in value, 'Invalid path')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts and str(path) == value, 'Canonical absolute path required')
    for part in [*reversed(path.parents), path]:
        require(not part.is_symlink(), 'Symlink refused')
    return path


def stat_identity(info):
    return [info.st_dev, info.st_ino]


def routing_row(text, node, pid, hostname):
    rows = [line.split() for line in text.splitlines() if re.match(r'^\s*' + str(node) + r'\s', line)]
    require(len(rows) == 1 and len(rows[0]) >= 5 and rows[0][:5] ==
            [str(node), 'STORAGE', 'HEARTBEAT_CONNECTED', hostname, str(pid)],
            'Actual Mgmtd routing must name this live enrolled Storage process')
    return rows[0][:5]


def discovery_identity(value, requested, now):
    exact(value, 'schema authority node chain target engine_uuid target_incarnation protocol '
          'observed_at_seconds verified_at_seconds verification')
    for name in ('schema', 'node', 'chain', 'target', 'protocol', 'observed_at_seconds', 'verified_at_seconds'):
        require(type(value[name]) is int, 'Discovery numeric type differs')
    require(value['schema'] == 1 and value['protocol'] == 2 and
            value['verification'] == 'control_mac_verified' and
            0 < value['observed_at_seconds'] <= value['verified_at_seconds'] <= now and
            now - value['observed_at_seconds'] <= 30, 'Fresh actual C-authenticated discovery required')
    actual = {'authority': value['authority'], 'endpoint': {key: value[key] for key in requested['endpoint']}}
    require(actual == requested, 'Actual Storage identity differs from requested enrollment')
    return actual


class Linux:
    """Privileged kernel adapter. Tests supply a separate fake; CLI never does."""
    def __init__(self):
        require(os.name == 'posix' and os.geteuid() == 0, 'Linux root provider required')

    def trusted(self, path, *, private=False, role_uid=None):
        path = safe_path(str(path))
        for part in reversed(path.parents):
            info = part.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Root-owned non-writable ancestry required')
        info = path.lstat()
        if role_uid is None:
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'Root-owned non-writable input required')
        else:
            require(type(role_uid) is int and role_uid >= 2000 and info.st_uid == role_uid and
                    stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o400,
                    'Only an explicitly enrolled private role key may be storage-UID owned, mode0400')
        require(not private or not info.st_mode & 0o077, 'Root-private path required')
        require(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                'Directory or singly linked regular file required')
        return info

    def account(self, uid, gid):
        import pwd
        import grp
        integer(uid, 32)
        integer(gid, 32)
        require(uid >= 2000 and gid >= 2000, 'Dedicated UID/GID >=2000 required; never ubuntu/root')
        user = pwd.getpwuid(uid)
        require(user.pw_gid == gid and user.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'),
                'Dedicated no-login account required')
        require(all(g.gr_gid == gid for g in grp.getgrall() if user.pw_name in g.gr_mem),
                'Supplementary groups are forbidden')
        require(set(grp.getgrgid(gid).gr_mem) <= {user.pw_name} and
                all(p.pw_uid == uid for p in pwd.getpwall() if p.pw_gid == gid), 'Group must be exclusive')
        check = subprocess.run(['/usr/bin/sudo', '-n', '-l', '-U', user.pw_name], capture_output=True)
        require(check.returncode == 1, 'Account must have no sudo permissions')

    def uid_processes(self, uid):
        found = []
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                lines = (entry / 'status').read_text().splitlines()
                row = next(line for line in lines if line.startswith('Uid:'))
                if uid in map(int, row.split()[1:]):
                    found.append(int(entry.name))
            except FileNotFoundError:
                continue
        return sorted(found)

    def cgroup(self, provider, enrollment, *, create=False):
        path = CGROUP_ROOT / identifier(provider) / identifier(enrollment)
        if create:
            require(not path.exists(), 'Execution cgroup already exists')
            path.mkdir(parents=True, mode=0o755)
        self.trusted(path)
        require((path / 'cgroup.kill').is_file() and (path / 'cgroup.events').is_file(),
                'cgroup v2 kill/events support required')
        return path

    def inputs(self, spec):
        exact(spec, 'schema provider_id enrollment_id resource_generation uid gid domain data logs argv env')
        require(type(spec['schema']) is int and spec['schema'] == 1, 'Enrollment schema differs')
        for key in ('provider_id', 'enrollment_id', 'resource_generation'):
            identifier(spec[key])
        self.account(spec['uid'], spec['gid'])
        domain = safe_path(spec['domain'])
        self.trusted(domain)
        require(domain.parent == PROVIDER_ROOT.parent / 'domains' and domain.name == spec['enrollment_id'],
                'Fresh domain must use its enrollment UUID under the independent provider domains root')
        data, logs = safe_path(spec['data']), safe_path(spec['logs'])
        require(data == domain / 'data' and logs == domain / 'logs', 'Fixed data/logs subdirectories required')
        resource = {}
        for name, path in [('data', data), ('logs', logs)]:
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == spec['uid'] and
                    info.st_gid == spec['gid'] and stat.S_IMODE(info.st_mode) == 0o700,
                    'Dedicated private writable directory required')
            require(not any(path.iterdir()), 'Enrollment requires fresh empty data/log directories')
            resource[name] = stat_identity(info)
        require(type(spec['argv']) is list and 1 <= len(spec['argv']) <= 32 and
                all(type(x) is str and x and '\x00' not in x for x in spec['argv']), 'Fixed bounded argv required')
        require(len(spec['argv']) == 7 and spec['argv'][1::2] == ['--app_cfg', '--launcher_cfg', '--cfg'],
                'Exact original storage_main configuration argv required')
        binary = safe_path(spec['argv'][0])
        require(binary == domain / 'bin/storage_main' and binary.is_file(), 'Root-packaged Storage binary required')
        exact(spec['env'], 'HOME USER LOGNAME PATH LD_LIBRARY_PATH')
        require(all(type(x) is str and '\x00' not in x for x in spec['env'].values()), 'Invalid fixed environment')
        require(spec['env']['HOME'] == spec['data'] and spec['env']['PATH'] == '/usr/bin:/bin' and
                spec['env']['LD_LIBRARY_PATH'] == str(domain / 'lib'), 'Domain-owned environment required')
        storage = tomllib.loads(Path(spec['argv'][6]).read_text())['server']['storage']
        roles = []
        for name in ('ec_capability_key_file', 'ec_scope_control_key_file', 'ec_helper_key_file',
                     'ec_gc_key_file', 'ec_rmw_key_file'):
            if not storage.get(name):
                continue
            key = safe_path(storage[name])
            require(key.parent == domain / 'secrets', 'Role-key exception is limited to the fixed domain secrets')
            roles.append(str(key))
        require(len(set(roles)) == len(roles), 'Signing roles cannot share an enrolled key path')
        files, directory_inputs = {}, {}
        for base, directories, names in os.walk(domain, followlinks=False):
            folder = Path(base)
            info = self.trusted(folder)
            directory_inputs[str(folder)] = {'identity': stat_identity(info), 'mode': stat.S_IMODE(info.st_mode)}
            require(len(directory_inputs) <= 512, 'Packaged directory bound exceeded')
            directories[:] = sorted(x for x in directories if folder / x not in (data, logs))
            for name in directories:
                self.trusted(folder / name)
            for name in sorted(names):
                path = folder / name
                info = self.trusted(path, role_uid=spec['uid'] if str(path) in roles else None)
                require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o6000,
                        'Packaged inputs must be regular without set-ID bits')
                files[str(path)] = {'identity': stat_identity(info), 'bytes': info.st_size,
                                    'mode': stat.S_IMODE(info.st_mode), 'sha256': sha(path.read_bytes())}
                require(len(files) <= 512, 'Packaged input inventory bound exceeded')
        require(str(binary) in files, 'Missing original binary')
        for name in spec['argv'][2::2]:
            require(safe_path(name).is_relative_to(domain / 'config') and name in files,
                    'All three Storage configuration inputs must be packaged in the domain')
        require(str(domain / 'bin/admin_cli') in files and str(domain / 'config/admin_cli.toml') in files,
                'Original root-owned Admin binary/config required for authenticated binding')
        return {'resources': resource, 'files': files, 'directories': directory_inputs, 'role_keys': sorted(roles)}

    def check_inputs(self, record):
        spec, inputs = record['spec'], record['inputs']
        self.trusted(safe_path(spec['domain']))
        for name in ('data', 'logs'):
            path = safe_path(spec[name])
            require(stat.S_ISDIR(path.lstat().st_mode) and
                    stat_identity(path.lstat()) == inputs['resources'][name], 'Original resource replaced')
        found = set()
        directories_found = {}
        for base, directories, names in os.walk(spec['domain'], followlinks=False):
            folder = Path(base)
            info = self.trusted(folder)
            directories_found[str(folder)] = {'identity': stat_identity(info), 'mode': stat.S_IMODE(info.st_mode)}
            directories[:] = sorted(x for x in directories if str(folder / x) not in (spec['data'], spec['logs']))
            for name in directories:
                self.trusted(folder / name)
            found.update(str(folder / name) for name in names)
            require(len(found) <= 512 and len(directories_found) <= 512, 'Packaged input bound exceeded')
        require(found == set(inputs['files']) and directories_found == inputs['directories'],
                'Packaged input membership changed')
        for name, expected in inputs['files'].items():
            path = safe_path(name)
            info = self.trusted(path, role_uid=spec['uid'] if name in inputs['role_keys'] else None)
            require({'identity': stat_identity(info), 'bytes': info.st_size,
                     'mode': stat.S_IMODE(info.st_mode), 'sha256': sha(path.read_bytes())} == expected,
                    'Enrolled immutable input changed')

    def live(self, record):
        launch = record['launch']
        require(launch is not None and launch['state'] == 'running', 'Original provider launch must be live')
        pid = launch['pid']
        status = Path('/proc', str(pid), 'stat').read_text()
        require(int(status[status.rindex(')') + 2:].split()[19]) == launch['start_ticks'], 'Original process changed')
        group = self.cgroup(record['spec']['provider_id'], record['spec']['enrollment_id'])
        require(pid in [int(x) for x in (group / 'cgroup.procs').read_text().split()], 'Original process escaped domain')
        require(sha(Path('/proc', str(pid), 'exe').read_bytes()) ==
                record['inputs']['files'][record['spec']['argv'][0]]['sha256'], 'Original executable differs')
        after = Path('/proc', str(pid), 'stat').read_text()
        require(int(after[after.rindex(')') + 2:].split()[19]) == launch['start_ticks'],
                'Original process changed during observation')

    def probe(self, record, identity, folder):
        spec, inputs = record['spec'], record['inputs']
        app = tomllib.loads(Path(spec['argv'][2]).read_text())
        config = tomllib.loads(Path(spec['argv'][6]).read_text())['server']
        node = identity['endpoint']['node']
        require(type(app['node_id']) is int and app['node_id'] == node and
                config['targets']['target_paths'] == [spec['data']] and
                config['targets']['ec_only'] is True and config['targets']['ec_staging_v2'] is True,
                'Actual original Storage node/data/V2 configuration differs')
        control = config['storage']
        key = str(safe_path(control['ec_scope_control_key_file']))
        require(control['enable_ec_scope_control'] is True and
                control['ec_scope_control_authority'] == identity['authority'] and
                key in inputs['files'], 'Original local C role differs or its key is not enrolled')
        target = safe_path(spec['data']) / str(identity['endpoint']['target'])
        marker, physical = target / 'target.toml', target / 'ec-target-v1.toml'
        for path in (marker, physical):
            safe_path(str(path))
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    info.st_uid == spec['uid'] and info.st_size <= 65536, 'Actual target metadata required')
        marker_bytes, physical_bytes = marker.read_bytes(), physical.read_bytes()
        require(marker_bytes == b'3FS_EC_TARGET_V1\n', 'Actual EC target marker differs')
        physical_value = tomllib.loads(physical_bytes.decode())
        require(physical_value['path'] == str(target) and
                type(physical_value['target_id']) is int and physical_value['target_id'] == identity['endpoint']['target'] and
                type(physical_value['chain_id']) is int and physical_value['chain_id'] == identity['endpoint']['chain'] and
                all(physical_value[name] is True for name in ('only_chunk_engine', 'ec_only', 'ec_staging_v2')),
                'Actual physical target path/chain/target/V2 differs')
        domain = Path(spec['domain'])
        def unique_local_node():
            # The provider supports a single trusted host, not a remote clone.
            # Refuse a second live local Storage with this node even if routing
            # would briefly select the expected PID before and after discovery.
            matches = []
            for proc in Path('/proc').iterdir():
                if not proc.name.isdigit():
                    continue
                try:
                    executable = os.readlink(proc / 'exe')
                    if Path(executable.removesuffix(' (deleted)')).name != 'storage_main':
                        continue
                    argv = (proc / 'cmdline').read_bytes().split(b'\0')
                    argv = [x.decode() for x in argv if x]
                    if '--app_cfg' in argv:
                        config_path = argv[argv.index('--app_cfg') + 1]
                    else:
                        configs = [x.split('=', 1)[1] for x in argv if x.startswith('--app_cfg=')]
                        require(len(configs) == 1, 'Cannot identify another local Storage configuration')
                        config_path = configs[0]
                    other = tomllib.loads(Path(config_path).read_text())
                    if other.get('node_id') == node:
                        matches.append(int(proc.name))
                except FileNotFoundError:
                    continue
            require(matches == [record['launch']['pid']], 'Another live local process owns this Storage node')
        def admin(name, parts):
            require(all(type(x) is str and x and not any(c in x for c in ';\r\n\x00') for x in parts),
                    'Unsafe Admin argument')
            argv = [str(domain / 'bin/admin_cli'), '--cfg', str(domain / 'config/admin_cli.toml'), '--', shlex.join(parts)]
            with (folder / (name + '.stdout')).open('xb') as out, (folder / (name + '.stderr')).open('xb') as err:
                os.fchmod(out.fileno(), 0o600)
                os.fchmod(err.fileno(), 0o600)
                process = subprocess.Popen(argv, env=spec['env'], cwd=domain, stdin=subprocess.DEVNULL,
                                           stdout=out, stderr=err, close_fds=True)
                try:
                    code = process.wait(timeout=30)
                except BaseException:
                    process.kill()
                    process.wait()
                    raise
                finally:
                    out.flush()
                    err.flush()
                    os.fsync(out.fileno())
                    os.fsync(err.fileno())
                    atomic_json(folder / (name + '.result.json'), {'argv': argv,
                                'returncode': process.returncode, 'joined': process.returncode is not None})
            require(code == 0, 'Actual readonly Admin probe failed; binding not created')
            return (folder / (name + '.stdout')).read_text()
        self.live(record)
        unique_local_node()
        before = routing_row(admin('routing-before', ['list-nodes']), node, record['launch']['pid'], socket.gethostname())
        exported = folder / 'discovery.json'
        # The original loader requires owner-only mode and owner=euid or root.
        # Storage reads its UID-owned0400 role key; this root Admin reads only a
        # root-private0600 exact copy. Never retain that secret among artifacts.
        key_copy = folder / '.probe-control.key'
        fd = os.open(key_copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            raw_key = Path(key).read_bytes()
            require(sha(raw_key) == inputs['files'][key]['sha256'], 'Original C key changed before probe')
            with os.fdopen(fd, 'wb') as stream:
                fd = None
                stream.write(raw_key)
                stream.flush()
                os.fsync(stream.fileno())
            admin('discovery', ['discover-ec-target', '--node-id', str(node),
                '--chain-id', str(identity['endpoint']['chain']), '--target-id', str(identity['endpoint']['target']),
                '--authority', identity['authority'], '--control-key-file', str(key_copy), '--output', str(exported)])
        finally:
            if fd is not None:
                os.close(fd)
            key_copy.unlink()  # Only this command's O_EXCL root-private temporary file.
        self.trusted(exported, private=True)
        actual = discovery_identity(read_json(exported), identity, int(time.time()))
        after = routing_row(admin('routing-after', ['list-nodes']), node, record['launch']['pid'], socket.gethostname())
        require(before == after, 'Routing changed during actual identity observation')
        self.live(record)
        unique_local_node()
        self.check_inputs(record)
        require(marker.read_bytes() == marker_bytes and physical.read_bytes() == physical_bytes,
                'Actual physical target changed during identity observation')
        artifacts = {str(path): {'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}
                     for path in sorted(folder.iterdir())}
        return {'identity': actual, 'routing': before, 'physical_path': str(physical),
                'physical_sha256': sha(physical_bytes), 'artifacts': artifacts}

    def kill_and_empty(self, record, timeout):
        group = self.cgroup(record['spec']['provider_id'], record['spec']['enrollment_id'])
        (group / 'cgroup.kill').write_text('1\n')
        deadline = time.monotonic() + timeout
        while True:
            events = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())
            if events.get('populated') == '0' and not self.uid_processes(record['spec']['uid']):
                return
            require(time.monotonic() < deadline, 'Execution domain has not drained; no certificate')
            time.sleep(0.02)

    def quarantine(self, record):
        # No deletion, rename or traversal of the old data. Its inode is retained.
        path = safe_path(record['spec']['data'])
        require(stat_identity(path.lstat()) == record['inputs']['resources']['data'], 'Original data replaced')
        os.chown(path, 0, 0, follow_symlinks=False)
        os.chmod(path, 0o700, follow_symlinks=False)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def fenced(self, record):
        group = self.cgroup(record['spec']['provider_id'], record['spec']['enrollment_id'])
        events = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines())
        info = safe_path(record['spec']['data']).lstat()
        require(events.get('populated') == '0' and not self.uid_processes(record['spec']['uid']) and
                info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700 and
                stat_identity(info) == record['inputs']['resources']['data'], 'Fenced execution/resource invariant lost')
        return {'path': record['spec']['data'], 'device_decimal': str(info.st_dev),
                'inode_decimal': str(info.st_ino), 'owner_uid': 0, 'owner_gid': 0, 'mode_octal': '0700'}


class Provider:
    def __init__(self, root, kernel=None):
        self.root = Path(root)
        self.kernel = Linux() if kernel is None else kernel
        if isinstance(self.kernel, Linux):
            require(self.root == PROVIDER_ROOT, 'One fixed host provider root; no second UID namespace')

    @contextlib.contextmanager
    def locked(self):
        import fcntl
        self.kernel.trusted(self.root, private=True)
        path = self.root / 'provider.lock'
        self.kernel.trusted(path, private=True)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def read(self, enrollment):
        path = self.root / 'enrollments' / (identifier(enrollment) + '.json')
        self.kernel.trusted(path, private=True)
        record = read_json(path)
        require(record['spec']['enrollment_id'] == enrollment, 'Enrollment record differs')
        return record

    def save(self, record):
        atomic_json(self.root / 'enrollments' / (record['spec']['enrollment_id'] + '.json'), record)

    def enroll(self, spec):
        with self.locked():
            config = read_json(self.root / 'provider.json')
            require(spec['provider_id'] == config['provider_id'], 'Provider authority differs')
            path = self.root / 'enrollments' / (identifier(spec['enrollment_id']) + '.json')
            require(not path.exists(), 'Enrollment cannot be reused or adopted')
            for old in (self.root / 'enrollments').glob('*.json'):
                previous = read_json(old)['spec']
                require(spec['uid'] != previous['uid'] and spec['gid'] != previous['gid'] and
                        spec['domain'] != previous['domain'] and
                        spec['resource_generation'] != previous['resource_generation'], 'Dedicated identity cannot be reused')
            inputs = self.kernel.inputs(spec)
            require(not self.kernel.uid_processes(spec['uid']), 'Dedicated UID already has a process')
            self.kernel.cgroup(spec['provider_id'], spec['enrollment_id'], create=True)
            record = {'schema': 1, 'spec': spec, 'inputs': inputs, 'bound': None,
                      'launch': None, 'deny': None, 'completion': None}
            self.save(record)
            return {'schema': 1, 'state': 'enrolled', 'enrollment_id': spec['enrollment_id']}

    def bind(self, enrollment, value):
        exact(value, 'authority endpoint')
        identifier(value['authority'])
        endpoint(value['endpoint'])
        with self.locked():
            record = self.read(enrollment)
            require(record['deny'] is None, 'Retirement permanently denies new binding')
            if record['bound'] is not None:
                require(record['bound']['identity'] == value, 'Target binding is immutable')
                return record['bound']
            self.kernel.check_inputs(record)
            self.kernel.live(record)
            folder = self.root / ('probe-' + uuid.uuid4().hex)
            folder.mkdir(mode=0o700)
            discovery = self.kernel.probe(record, value, folder)
            binding = {'policy': 'trusted_host_execution_v1', 'spec': record['spec'],
                       'inputs': record['inputs'], 'identity': value, 'discovery': discovery}
            record['bound'] = {'identity': value, 'binding_digest': sha(canonical(binding)),
                               'provider_id': record['spec']['provider_id'], 'enrollment_id': enrollment,
                               'resource_generation': record['spec']['resource_generation'], 'discovery': discovery}
            self.save(record)
            return record['bound']

    def validate(self, record, intent):
        validate_intent(intent)
        bound = record['bound']
        require(bound is not None, 'Real launched resource must be bound before Meta retirement')
        require(bound['binding_digest'] == sha(canonical({'policy': 'trusted_host_execution_v1',
                'spec': record['spec'], 'inputs': record['inputs'], 'identity': bound['identity'],
                'discovery': bound['discovery']})), 'Persisted resource/identity binding changed')
        for path, original in bound['discovery']['artifacts'].items():
            self.kernel.trusted(Path(path), private=True)
            raw = Path(path).read_bytes()
            require({'bytes': len(raw), 'sha256': sha(raw)} == original, 'Original binding probe evidence changed')
        for key in ('provider_id', 'enrollment_id', 'resource_generation', 'binding_digest'):
            require(intent[key] == bound[key], 'External Meta binding differs')
        require(intent['authority'] == bound['identity']['authority'] and
                intent['endpoint'] == bound['identity']['endpoint'], 'Original target identity differs')
        if record['deny'] is not None:
            require(record['deny']['intent'] == intent, 'Original permanent retirement intent cannot change')

    def sign(self, payload):
        key = self.root / 'provider-private.pem'
        self.kernel.trusted(key, private=True)
        with tempfile.TemporaryDirectory(prefix='.sign-', dir=self.root) as folder:
            source, target = Path(folder) / 'payload', Path(folder) / 'signature'
            source.write_bytes(payload)
            result = subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key),
                                     '-in', str(source), '-out', str(target)], capture_output=True)
            require(result.returncode == 0, 'Provider signature failed; original deny retained')
            signature = target.read_bytes()
            require(len(signature) == 64, 'Ed25519 signature size differs')
            return signature

    def fence(self, intent, *, timeout=15):
        require(type(timeout) is int and 1 <= timeout <= 120, 'Bounded fence timeout required')
        with self.locked():
            record = self.read(intent['enrollment_id'])
            self.validate(record, intent)
            self.kernel.check_inputs(record)
            if record['completion'] is not None:
                self.kernel.fenced(record)
                return self.completed(record)
            if record['deny'] is None:
                record['deny'] = {'intent': intent, 'sequence': 1}
                self.save(record)  # Irreversible durable denial MUST precede cgroup.kill.
            self.kernel.kill_and_empty(record, timeout)
            self.kernel.check_inputs(record)  # Key owners cannot race changed bytes into a signed completion.
            self.kernel.quarantine(record)
            quarantine = self.kernel.fenced(record)
            deny_digest = sha(b'3FSEHFD1' + canonical(record['deny']))
            payload = certificate_payload(intent, deny_digest)
            certificate = payload + self.sign(payload)
            record['completion'] = {'certificate_hex': certificate.hex(), 'deny_digest': deny_digest,
                                    'quarantine': quarantine}
            self.save(record)  # Complete bytes durable before they are returned to Meta.
            return self.completed(record)

    def completed(self, record):
        value = record['completion']
        require(value is not None, 'No completed host fence; Query never confirms or creates one')
        require(value['deny_digest'] == sha(b'3FSEHFD1' + canonical(record['deny'])),
                'Original permanent deny digest differs')
        payload = certificate_payload(record['deny']['intent'], value['deny_digest'])
        certificate = bytes.fromhex(value['certificate_hex'])
        require(len(certificate) == 312 and certificate[:248] == payload, 'Stored certificate differs')
        require(self.kernel.fenced(record) == value['quarantine'], 'Original quarantined resource differs')
        return {'schema': 1, 'state': 'HostExecutionFenced', 'certificate_hex': certificate.hex(),
                'certificate_sha256': sha(certificate), 'physical_reclamation_confirmed': False,
                'resource_disposition': {'state': 'RetiredInaccessible',
                    'enrollment_id': record['spec']['enrollment_id'],
                    'resource_generation': record['spec']['resource_generation'],
                    'binding_digest': record['bound']['binding_digest'],
                    'quarantine': value['quarantine'], 'capacity_retained': True,
                    'physical_capacity_returned': False, 'retained_physical_bytes': None},
                'scope': 'trusted_host_not_vm_clone_or_root_rollback'}

    def query(self, intent):
        with self.locked():
            record = self.read(intent['enrollment_id'])
            self.validate(record, intent)
            self.kernel.check_inputs(record)
            require(record['completion'] is not None, 'No completed host fence; no mutation performed')
            self.kernel.fenced(record)
            return self.completed(record)

    def run(self, enrollment):
        require(isinstance(self.kernel, Linux), 'Only the real privileged kernel adapter can launch')
        previous = signal.getsignal(signal.SIGTERM)
        def interrupted(signum, frame):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            raise ProviderInterrupted('Provider owner stopping')
        signal.signal(signal.SIGTERM, interrupted)
        try:
            return self._run_owned(enrollment)
        finally:
            signal.signal(signal.SIGTERM, previous)

    def _run_owned(self, enrollment):
        with self.locked():
            record = self.read(enrollment)
            require(record['deny'] is None, 'Permanently fenced enrollment cannot launch')
            require(record['launch'] is None or record['launch']['state'] == 'joined',
                    'Previous launch unknown; fence it instead of adopting a PID')
            self.kernel.check_inputs(record)
            require(not self.kernel.uid_processes(record['spec']['uid']), 'Dedicated UID is already running')
            launch_id = str(uuid.uuid4())
            record['launch'] = {'id': launch_id, 'state': 'launching', 'pid': None,
                                'start_ticks': None, 'exitcode': None}
            self.save(record)
            spec = record['spec']
            group = self.kernel.cgroup(spec['provider_id'], enrollment)
            require(not (group / 'cgroup.procs').read_text().split(), 'Execution cgroup is not empty')
            def child_setup():
                (group / 'cgroup.procs').write_text(str(os.getpid()) + '\n')
                libc = ctypes.CDLL(None, use_errno=True)
                require(libc.prctl(47, 4, 0, 0, 0) == 0, 'Clear ambient capabilities failed')
                os.setgroups([])
                os.setgid(spec['gid'])
                os.setuid(spec['uid'])
                require(libc.prctl(38, 1, 0, 0, 0) == 0, 'PR_SET_NO_NEW_PRIVS failed')
                status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                              if ':' in line)
                require(all(int(status[name].strip(), 16) == 0 for name in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
                        'Storage must have no inherited, permitted, effective or ambient capabilities')
                os.umask(0o077)
            process = subprocess.Popen(spec['argv'], env=spec['env'], cwd=spec['data'],
                                       preexec_fn=child_setup, close_fds=True)
            try:
                status = Path('/proc', str(process.pid), 'stat').read_text()
                record['launch'].update(state='running', pid=process.pid,
                    start_ticks=int(status[status.rindex(')') + 2:].split()[19]))
                self.save(record)
            except BaseException:
                (group / 'cgroup.kill').write_text('1\n')
                process.wait()
                self.kernel.kill_and_empty(record, 15)
                raise
        try:
            print(json.dumps({'schema': 1, 'state': 'running', 'enrollment_id': enrollment,
                              'pid': process.pid, 'start_ticks': record['launch']['start_ticks']}), flush=True)
            code = process.wait()
        except BaseException:
            (group / 'cgroup.kill').write_text('1\n')
            process.wait()
            self.kernel.kill_and_empty(record, 15)
            raise
        with self.locked():
            current = self.read(enrollment)
            require(current['launch']['id'] == launch_id, 'Launch identity changed')
            current['launch'].update(state='joined', exitcode=code)
            self.save(current)  # Preserve a concurrent fence; never overwrite it with the old record.
        return code


def initialize(root, provider):
    kernel = Linux()
    identifier(provider)
    root = safe_path(str(root))
    require(root == PROVIDER_ROOT, 'One fixed host provider root required')
    kernel.trusted(root.parent)
    require(not root.exists(), 'Fresh provider root required')
    root.mkdir(mode=0o700)
    (root / 'enrollments').mkdir(mode=0o700)
    fd = os.open(root / 'provider.lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    key = root / 'provider-private.pem'
    result = subprocess.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)],
                            capture_output=True)
    require(result.returncode == 0, 'Independent provider key generation failed')
    os.chmod(key, 0o600)
    public = subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                            capture_output=True)
    require(public.returncode == 0 and len(public.stdout) == 44 and
            public.stdout[:12] == bytes.fromhex('302a300506032b6570032100'), 'Ed25519 public key format differs')
    (root / 'provider-public.bin').write_bytes(public.stdout[12:])
    os.chmod(root / 'provider-public.bin', 0o644)
    for path in (key, root / 'provider-public.bin'):
        with path.open('rb') as stream:
            os.fsync(stream.fileno())
    atomic_json(root / 'provider.json', {'schema': 1, 'provider_id': provider,
                'public_key_sha256': sha(public.stdout[12:]), 'trust_scope': 'trusted_nonrollback_host_root'})
    directory = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {'schema': 1, 'provider_id': provider, 'public_key_file': str(root / 'provider-public.bin'),
            'public_key_sha256': sha(public.stdout[12:])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    sub = parser.add_subparsers(dest='operation', required=True)
    sub.add_parser('init').add_argument('--provider-id', required=True)
    sub.add_parser('enroll').add_argument('--spec', required=True, type=Path)
    bind = sub.add_parser('bind')
    bind.add_argument('--enrollment', required=True)
    bind.add_argument('--identity', required=True, type=Path)
    sub.add_parser('run').add_argument('--enrollment', required=True)
    for name in ('fence', 'query'):
        sub.add_parser(name).add_argument('--intent', required=True, type=Path)
    args = parser.parse_args()
    try:
        provider = Provider(args.root)
        for name in ('spec', 'identity', 'intent'):
            path = getattr(args, name, None)
            if path is not None:
                provider.kernel.trusted(path, private=True)
        if args.operation == 'init':
            result = initialize(args.root, args.provider_id)
        elif args.operation == 'enroll':
            result = provider.enroll(read_json(args.spec))
        elif args.operation == 'bind':
            result = provider.bind(args.enrollment, read_json(args.identity))
        elif args.operation == 'run':
            code = provider.run(args.enrollment)
            return code if code >= 0 else 128 - code
        else:
            result = getattr(provider, args.operation)(read_json(args.intent))
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        # Do not echo arbitrary OpenSSL/system/config text or secret contents.
        result = {'schema': 1, 'state': 'not_confirmed', 'error_type': type(error).__name__}
        if type(error) is ProviderError:
            result['reason'] = str(error)  # Only this module's fixed literal gate messages.
        print(json.dumps(result), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
