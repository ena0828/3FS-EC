"""Persistent admission for one explicitly enrolled, owned process.

This is a reusable managed-launch component, NOT an external fencing provider.
An honest exclusive operator, intact non-rolled-back control storage and use of
this entry point are prerequisites. No PID adoption, MAC, Meta/T2 or GC proof.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import uuid

try:
    import fcntl
except ImportError:  # Pure validation tests are portable; lifecycle is Linux.
    fcntl = None


KEY = 'managed_domain'
SCOPE = 'managed_launch_only_not_external_fence'
MAX_BYTES = 65536


def require(value, message):
    if not value:
        raise ValueError(message)


def identifier(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int,
            'Require a nonzero canonical UUID')
    return value


def encoded(value):
    data = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
    require(len(data) <= MAX_BYTES, 'Managed record exceeds fixed bound')
    return data


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def private_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'Noncanonical control directory')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            'Control directory must be private and owned')
    return path


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                not info.st_mode & 0o077 and info.st_size <= MAX_BYTES, 'Invalid private managed record')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, 'Oversized managed record')
        return json.loads(data)
    finally:
        os.close(fd)


def durable_replace(path, value, *, create=False):
    """No success until BOTH file data and containing directory are synced."""
    path = Path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = path.name + '.' + secrets.token_hex(12) + '.pending'
    try:
        if create:
            # Install a fixed marker before any side effect; failure may leave
            # an invalid marker, which future admission must refuse.
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        else:
            old = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(old.st_mode) and old.st_nlink == 1 and old.st_uid == os.geteuid(),
                    'Refuse to replace a redirected managed record')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(encoded(value))
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        if not create:
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def sync_private(path):
    """A visible record is not a durability acknowledgement until this succeeds."""
    read_private(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def enrollment_lock(root):
    """Stable lab-wide serialization before a locator selects its external lock."""
    path = private_directory(Path(root) / 'state') / 'managed-enrollment.lock'
    try:
        durable_replace(path, {'schema': 1, 'purpose': 'managed-enrollment'}, create=True)
    except FileExistsError:
        pass
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                not info.st_mode & 0o077, 'Invalid enrollment lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        sync_private(path)
        yield
    finally:
        os.close(fd)


def artifact_identity(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'Redirected managed input')
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'Managed input must be a single-link file')
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Managed input changed during read')
    return {'path': str(path), 'dev': before.st_dev, 'ino': before.st_ino, 'bytes': before.st_size, 'sha256': value}


def directory_identity(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'Redirected managed data directory')
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            'Managed data directory must be private and owned')
    return {'path': str(path), 'dev': info.st_dev, 'ino': info.st_ino}


def make_binding(root, manifest, endpoint, spec, generation):
    """Adapter supplies a fresh authenticated endpoint, never a user assertion."""
    root = Path(root)
    endpoint = dict(endpoint)
    require(set(endpoint) == {'node', 'chain', 'target', 'engine_uuid', 'target_incarnation'}, 'Incomplete instance')
    for name in ('engine_uuid', 'target_incarnation'):
        identifier(endpoint[name])
    require(all(type(endpoint[k]) is int and endpoint[k] > 0 for k in ('node', 'chain', 'target')),
            'Invalid fixed logical endpoint')
    require(spec['node'] == endpoint['node'] and spec['name'] == 'storage-' + str(endpoint['node']),
            'One process per target required')
    baseline = {k: v for k, v in manifest.items() if k != KEY}
    binary = artifact_identity(root / 'bin/storage_main')
    configs = [artifact_identity(root / 'config' / (spec['stem'] + suffix))
               for suffix in ('_app.toml', '_launcher.toml', '.toml')]
    argv = [binary['path']]
    for flag, row in zip(('--app_cfg', '--launcher_cfg', '--cfg'), configs):
        argv.extend((flag, row['path']))
    return {'schema': 1, 'root': str(root), 'authority': identifier(manifest['authority']),
            'endpoint': endpoint, 'service': spec['name'],
            'resource_generation': identifier(generation),
            'resource_generation_scope': 'caller_fixed_binding_not_authenticated_device_generation',
            'manifest_digest': digest(baseline),
            'data': directory_identity(Path(spec['data_path'])),
            'binary': binary, 'configs': configs, 'argv': argv,
            'config_scope': 'fixed_local_launch_inputs_not_all_effective_dynamic_configuration'}


def observe_owned_executable(proc, expected):
    """/proc is used ONLY for the already owned live Popen, never to adopt it."""
    require(proc.poll() is None, 'Owned process is not live')
    with Path('/proc', str(proc.pid), 'exe').open('rb') as stream:
        info = os.fstat(stream.fileno())
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    require((info.st_dev, info.st_ino, info.st_size, actual) ==
            (expected['dev'], expected['ino'], expected['bytes'], expected['sha256']),
            'Owned process is not executing the enrolled binary')
    value = Path('/proc', str(proc.pid), 'stat').read_text()
    ticks = int(value[value.rindex(')') + 2:].split()[19])
    require(proc.poll() is None, 'Owned process exited during executable observation')
    return {'pid': proc.pid, 'start_ticks': ticks, 'executable_sha256': actual}


class ManagedDomain:
    """An owned-process handle must never be reconstructed from persisted PID."""
    def __init__(self, root, locator, owner_run):
        require(fcntl is not None, 'Managed lifecycle requires Linux flock')
        self.root = private_directory(root)
        self.locator = locator
        self.control = private_directory(locator['control'])
        require(self.control != self.root and self.root not in self.control.parents and
                self.control not in self.root.parents, 'Control directory must be independent of the lab tree')
        require(set(locator) == {'schema', 'domain', 'enrollment', 'control', 'binding', 'binding_digest', 'initial_owner'} and
                type(locator['schema']) is int and locator['schema'] == 1, 'Invalid managed locator')
        identifier(locator['domain'])
        identifier(locator['enrollment'])
        initial = locator['initial_owner']
        require(set(initial) == {'run', 'launch_id', 'pid', 'start_ticks', 'executable_sha256'} and
                isinstance(initial['run'], str) and initial['run'] and
                type(initial['pid']) is int and initial['pid'] > 0 and
                type(initial['start_ticks']) is int and initial['start_ticks'] > 0 and
                initial['executable_sha256'] == locator['binding']['binary']['sha256'], 'Invalid initial owned launch')
        identifier(initial['launch_id'])
        require(digest(locator['binding']) == locator['binding_digest'] and locator['binding']['root'] == str(self.root),
                'Managed binding differs')
        self.owner_run = owner_run
        self.handle = None
        self.launch_id = None
        self.poisoned = False
        self.retry_deny = None
        self.mutex = threading.RLock()
        self.path = self.control / 'domain.json'
        self.lock_path = self.control / 'domain.lock'

    @classmethod
    def attach(cls, root, manifest, owner_run):
        if KEY not in manifest:
            return None
        result = cls(root, manifest[KEY], owner_run)
        with result.locked():
            result.read()
        return result

    @classmethod
    def enroll(cls, root, manifest, control, domain, enrollment, binding, owner_run, proc, launch_inputs):
        require(fcntl is not None, 'Managed enrollment requires Linux flock')
        private_directory(root)
        require(binding['root'] == str(root) and isinstance(owner_run, str) and owner_run,
                'Enrollment root/owner differs')
        with enrollment_lock(root):
            return cls._enroll_locked(root, manifest, control, domain, enrollment, binding, owner_run, proc, launch_inputs)

    @classmethod
    def _enroll_locked(cls, root, manifest, control, domain, enrollment, binding, owner_run, proc, launch_inputs):
        require(proc.poll() is None, 'Enrollment requires the original live owned process')
        require({key: launch_inputs[key] for key in ('argv', 'binary', 'configs')} ==
                {key: binding[key] for key in ('argv', 'binary', 'configs')},
                'Current inputs differ from captured actual launch inputs')
        observed = observe_owned_executable(proc, binding['binary'])
        require(observed == launch_inputs['owned'], 'Original owned launch changed')
        locator = {'schema': 1, 'domain': identifier(domain), 'enrollment': identifier(enrollment),
                   'control': str(Path(control)), 'binding': binding, 'binding_digest': digest(binding),
                   'initial_owner': dict(observed, run=owner_run, launch_id=identifier(launch_inputs['launch_id']))}
        private_directory(control)
        require(Path(control) != Path(root) and Path(root) not in Path(control).parents and
                Path(control) not in Path(root).parents, 'Control state must be outside the lab')
        current = read_private(Path(root) / 'cluster.json')
        require(digest({k: v for k, v in current.items() if k != KEY}) == binding['manifest_digest'] and
                {k: v for k, v in current.items() if k != KEY} == {k: v for k, v in manifest.items() if k != KEY},
                'Prepared manifest changed during enrollment')
        if KEY not in current:
            require(not any(Path(control).iterdir()), 'New control directory must be empty')
            # This locator is the irreversible opt-in. All later start paths
            # auto-attach it, even if enrollment never obtains an acknowledgement.
            marked = dict(current, **{KEY: locator})
            durable_replace(Path(root) / 'cluster.json', marked)
        else:
            require(current[KEY] == locator, 'Enrollment identity/binding/original owner cannot change')
        # Also re-sync a marker left visible by a prior failed directory fsync.
        sync_private(Path(root) / 'cluster.json')
        manifest[KEY] = locator
        result = cls(root, locator, owner_run)
        # Only the caller retaining THIS live Popen may finish partial enrollment.
        require(proc.poll() is None, 'Owned process exited during enrollment')
        if not result.lock_path.exists():
            durable_replace(result.lock_path, {'schema': 1, 'domain': domain}, create=True)
        with result.locked():
            if result.path.exists():
                record = result.read()
                require(record['runtime']['owner_run'] == owner_run and record['runtime']['pid'] == proc.pid and
                        record['runtime']['launch_id'] == locator['initial_owner']['launch_id'] and
                        record['runtime']['state'] == 'running' and record['deny'] is None,
                        'Cannot recover enrollment without its original owner')
            else:
                record = {'schema': 1, 'locator': locator, 'deny': None,
                          'runtime': {'state': 'running', 'owner_run': owner_run,
                                      'launch_id': locator['initial_owner']['launch_id'], 'pid': proc.pid, 'exitcode': None}}
                result.write(record, create=True)
            # Reconfirm durability on same-id retry; page-cache visibility alone
            # is never a successful persistence acknowledgement.
            result.sync_record()
            result.handle, result.launch_id = proc, record['runtime']['launch_id']
        return result

    @contextlib.contextmanager
    def locked(self):
        with self.mutex:
            fd = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                        not info.st_mode & 0o077, 'Invalid managed lock')
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def read(self):
        value = read_private(self.path)
        require(set(value) == {'schema', 'locator', 'deny', 'runtime'} and type(value['schema']) is int and value['schema'] == 1 and
                value['locator'] == self.locator, 'Managed record binding/schema mismatch')
        if value['deny'] is not None:
            identifier(value['deny'])
        runtime = value['runtime']
        require(set(runtime) == {'state', 'owner_run', 'launch_id', 'pid', 'exitcode'} and
                runtime['state'] in ('launching', 'running', 'joined') and
                isinstance(runtime['owner_run'], str) and runtime['owner_run'] and
                (runtime['pid'] is None or type(runtime['pid']) is int and runtime['pid'] > 0) and
                (runtime['exitcode'] is None or type(runtime['exitcode']) is int), 'Invalid managed runtime record')
        identifier(runtime['launch_id'])
        require((runtime['state'] == 'joined') == (runtime['exitcode'] is not None), 'Contradictory join state')
        return value

    def sync_record(self):
        try:
            sync_private(self.path)
        except BaseException:
            self.poisoned = True
            raise

    def write(self, value, *, create=False):
        try:
            durable_replace(self.path, value, create=create)
        except BaseException:
            self.poisoned = True
            raise

    def verify_inputs(self):
        current = read_private(self.root / 'cluster.json')
        require(current.get(KEY) == self.locator, 'Mandatory enrollment marker changed or vanished')
        binding = self.locator['binding']
        require(digest({k: v for k, v in current.items() if k != KEY}) == binding['manifest_digest'],
                'Prepared manifest changed after enrollment')
        require(directory_identity(binding['data']['path']) == binding['data'], 'Managed resource directory changed')
        require(artifact_identity(binding['binary']['path']) == binding['binary'], 'Managed executable changed')
        require([artifact_identity(row['path']) for row in binding['configs']] == binding['configs'],
                'Managed configuration changed')

    def assert_startable(self):
        with self.locked():
            require(not self.poisoned, 'Managed persistence is unconfirmed')
            value = self.read()
            require(value['deny'] is None, 'Managed instance is permanently launch-denied')
            require(value['runtime']['state'] == 'joined', 'Prior owned process outcome is unknown; no PID adoption')
            self.verify_inputs()
            self.sync_record()

    def launch(self, command, spawn):
        with self.locked():
            require(not self.poisoned, 'Managed persistence is unconfirmed')
            record = self.read()
            require(record['deny'] is None, 'Managed instance is permanently launch-denied')
            self.verify_inputs()
            expected = self.locator['binding']['argv']
            require(list(map(str, command)) == expected, 'Managed launch argv differs from enrollment')
            if record['runtime']['state'] != 'joined':
                self._joined(record)  # Only this instance's retained exact Popen can establish an exit.
            launch_id = str(uuid.uuid4())
            record['runtime'] = {'state': 'launching', 'owner_run': self.owner_run,
                                 'launch_id': launch_id, 'pid': None, 'exitcode': None}
            self.write(record)  # Must succeed before spawn, with this same lock held.
            self.handle = None
            self.launch_id = launch_id
            proc = spawn()  # Adapter registers its Popen before returning, even on subsequent errors.
            self.handle = proc
            observe_owned_executable(proc, self.locator['binding']['binary'])
            record['runtime'].update(state='running', pid=proc.pid)
            self.write(record)
            return proc

    def _joined(self, record):
        require(not self.poisoned, 'Unconfirmed persistence cannot be converted to a restartable joined state')
        require(self.handle is not None and record['runtime']['owner_run'] == self.owner_run and
                record['runtime']['launch_id'] == self.launch_id and record['runtime']['pid'] == self.handle.pid,
                'Lost original Popen ownership; refuse PID-based recovery')
        require(self.handle.poll() is not None, 'Owned process is still live')
        code = self.handle.wait()
        record['runtime'].update(state='joined', exitcode=code)
        self.write(record)

    def observe_join(self, proc):
        with self.locked():
            require(proc is self.handle, 'Join is not for the owned process')
            record = self.read()
            self._joined(record)

    def prepare_deny(self, retirement):
        retirement = identifier(retirement)
        with self.locked():
            require(not self.poisoned or self.retry_deny == retirement,
                    'Only the original owned deny intent may reconfirm unknown persistence')
            record = self.read()
            require(record['deny'] in (None, retirement), 'Retirement UUID cannot change')
            require(self.handle is not None and record['runtime']['owner_run'] == self.owner_run and
                    record['runtime']['launch_id'] == self.launch_id and record['runtime']['pid'] == self.handle.pid,
                    'Retirement requires exact current Popen ownership')
            record['deny'] = retirement
            self.retry_deny = retirement
            self.write(record)  # No terminate/kill may precede this durable write.
            self.sync_record()
            self.poisoned = False  # Exact deny, not general query/launch, was durably reconfirmed.
            return self.handle

    def query(self):
        with self.locked():
            record = self.read()
            # A new observer can confirm current bytes by a new sync; this does
            # not repair a poisoned active owner or invent a lost process join.
            if not self.poisoned:
                self.sync_record()
            owned = self.handle is not None and record['runtime']['owner_run'] == self.owner_run and \
                record['runtime']['launch_id'] == self.launch_id
            # False is not permission to launch: this query does not rehash
            # inputs. assert_startable/launch alone enforce those additional gates.
            return {'schema': 1, 'scope': SCOPE, 'domain': self.locator['domain'],
                    'enrollment': self.locator['enrollment'], 'binding_digest': self.locator['binding_digest'],
                    'service': self.locator['binding']['service'], 'retirement_id': record['deny'],
                    'launch_denied': record['deny'] is not None or self.poisoned or record['runtime']['state'] != 'joined',
                    'persistence_confirmed': not self.poisoned, 'runtime': record['runtime'],
                    'current_owner_handle': owned, 'external_fence': False, 'scope_T2': False,
                    'publication_authorized': False, 'physical_gc_confirmed': False}
