"""Private Linux reference-runtime utilities. No shell, global service, or PID-file control."""
import hashlib
import ipaddress
import json
import os
from contextlib import contextmanager
import fcntl
from pathlib import Path
import resource
import signal
import socket
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PACKET = 65536
PACKETS_PER_SHARD = 16
SHARD = PACKET * PACKETS_PER_SHARD
REDIS_VERSION = '7.2.11'

@contextmanager
def reference_lease():
    """One private, nonblocking per-UID lease for both projects and their reference builds.

    The lease remains held until the caller has joined every owned child. No PID from this
    file is ever used to terminate or adopt a process; flock is the sole ownership primitive.
    """
    directory=Path('/tmp')/('3fs-ec-reference-runtime-lock-'+str(os.geteuid()))
    try:directory.mkdir(mode=0o700)
    except FileExistsError:pass
    info=directory.lstat()
    if directory!=directory.resolve() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
        raise RuntimeError('shared reference lease directory is redirected or not private/owned')
    fd=os.open(directory/'lease',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077 or info.st_nlink!=1:
            raise RuntimeError('shared reference lease file is not a private single-link owned file')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('another reference build or runtime owns the common per-UID lease') from None
        yield
    finally:
        os.close(fd)

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()

def new_json(path, value):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.write('\n'); f.flush(); os.fsync(f.fileno())

def check_build(record, project):
    data = json.loads(Path(record).read_text())
    if data['project'] != project or data['status'] != 'built':
        raise ValueError('incorrect or incomplete build record')
    for entry in data['binaries']:
        if sha(entry['path']) != entry['sha256']:
            raise ValueError('binary changed: ' + entry['path'])
    for entry in data['sources']:
        if sha(entry['path']) != entry['sha256']:
            raise ValueError('build source changed: ' + entry['path'])
    for entry in data['dependency_files']:
        if sha(entry['path']) != entry['sha256']:
            raise ValueError('private dependency changed: ' + entry['path'])
    return data, {Path(e['path']).name: e['path'] for e in data['binaries']}

def preflight(root, octet, redis):
    if sys.platform != 'linux' or sys.byteorder != 'little':
        raise RuntimeError('candidate requires Linux little-endian x86-64')
    if os.uname().machine != 'x86_64':
        raise RuntimeError('upstream compiler flags require x86-64')
    if not root.is_absolute() or root.exists() or any(c in str(root) for c in '\r\n\0,'):
        raise ValueError('run root must be a new absolute path without comma/control characters')
    if not 1 <= octet <= 254:
        raise ValueError('loopback second octet must be 1..254')
    if not redis.is_absolute() or not redis.is_file() or not os.access(redis, os.X_OK):
        raise ValueError('explicit executable redis-server required')
    available = int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))) * 1024
    if available < 3 * 1024**3:
        raise RuntimeError('less than 3 GiB guest MemAvailable; stop builds/other experiments first')
    builders = []
    for path in Path('/proc').glob('[0-9]*/comm'):
        try:
            if path.read_text().strip() in {'ninja', 'make', 'cmake', 'cc1plus', 'clang', 'clang++', 'rustc', 'cargo', 'ld', 'ld.lld'}:
                builders.append(str(path.parent.name))
        except (OSError, UnicodeError):
            pass
    if builders:
        raise RuntimeError('build processes still present: ' + ','.join(builders))
    if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < 4096:
        raise RuntimeError('per-process nofile soft limit must be at least 4096')
    addresses = [f'127.{octet}.0.1'] + [f'127.{octet}.0.{i}' for i in range(11, 23)]
    for address in addresses:
        if not ipaddress.ip_address(address).is_loopback:
            raise ValueError('non-loopback address')
        with socket.socket() as s:
            s.bind((address, 6379))
    root.mkdir(mode=0o700, parents=False)
    return addresses, {'mem_available_before': available, 'nofile': resource.getrlimit(resource.RLIMIT_NOFILE),
                       'uname': list(os.uname()), 'redis_path': str(redis), 'redis_sha256': sha(redis),
                       'addresses': addresses, 'port': 6379, 'performance_measurement': False}

def redis_command(address, *args):
    payload = ('*' + str(len(args)) + '\r\n').encode()
    for arg in args:
        arg = str(arg).encode()
        payload += b'$' + str(len(arg)).encode() + b'\r\n' + arg + b'\r\n'
    with socket.create_connection((address, 6379), timeout=2) as sock:
        sock.sendall(payload)
        with sock.makefile('rb') as stream:
            line = stream.readline(1024)
            if line.startswith(b'+'):
                return line[1:-2].decode()
            if line.startswith(b':'):
                return int(line[1:-2])
            if not line.startswith(b'$'):
                raise RuntimeError('unexpected Redis response: ' + repr(line))
            size = int(line[1:-2])
            if size < 0 or size > 1048576:
                raise RuntimeError('invalid Redis bulk size')
            raw = stream.read(size)
            if len(raw) != size or stream.read(2) != b'\r\n':
                raise RuntimeError('truncated Redis response')
            return raw.decode()

def fields(info):
    return dict(line.split(':', 1) for line in info.splitlines() if ':' in line and not line.startswith('#'))

class Owned:
    def __init__(self, root, env=None):
        self.root = root
        self.env = env or os.environ.copy()
        self.children = []
        self.events = []
        self.cleanup_errors = []
        self.deadline = time.monotonic() + 900
        self.stop_requested = False
        self.stop_signal = None
        signals = [signal.SIGINT,signal.SIGTERM]
        if hasattr(signal,'SIGHUP'):signals.append(signal.SIGHUP)
        self.previous_signals = {sig: signal.getsignal(sig) for sig in signals}
        for sig in self.previous_signals: signal.signal(sig,self.interrupted)

    def interrupted(self, number, frame):
        # Never raise between Popen returning and recording ownership of its handle.
        self.stop_requested = True
        self.stop_signal = number

    def check_stop(self):
        if self.stop_requested:
            raise KeyboardInterrupt('stop requested by signal '+str(self.stop_signal))

    def event(self, event, **data):
        item = dict(event=event, monotonic=time.monotonic(), **data)
        self.events.append(item)
        with (self.root/'events.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(item, ensure_ascii=False)+'\n'); f.flush()

    def start(self, name, argv, cwd, persistent=True):
        self.check_stop()
        log = self.root/(name+'.log')
        with log.open('xb') as output:
            proc = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=self.env,
                                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                    start_new_session=True)
            # Register ownership before logging can fail; main finally always joins this handle.
            self.children.append((name, proc, persistent))
        self.check_stop()  # A signal during Popen is observed only after registration.
        self.event('started', name=name, argv=[str(x) for x in argv], cwd=str(cwd), pid=proc.pid, log=str(log))
        return proc

    def alive(self):
        self.check_stop()
        if time.monotonic() > self.deadline:
            raise TimeoutError('whole experiment exceeded 900 seconds')
        for name, proc, persistent in self.children:
            if persistent and proc.poll() is not None:
                raise RuntimeError(f'{name} exited early with {proc.returncode}')

    def wait_for(self, description, predicate, seconds=120):
        end = min(self.deadline, time.monotonic()+seconds)
        while time.monotonic() < end:
            self.alive()
            if predicate():
                self.event('observed', description=description)
                return
            time.sleep(0.1)
        raise TimeoutError(description)

    def command(self, name, argv, cwd, seconds=180):
        proc = self.start(name, argv, cwd, persistent=False)
        self.wait_for(name+' exit', lambda: proc.poll() is not None, seconds)
        if proc.returncode != 0:
            raise RuntimeError(f'{name} failed: {proc.returncode}')

    def stop(self):
        # Upstream daemons expose no graceful shutdown API. SIGTERM is controlled process teardown,
        # not proof of their internal queue drain or crash durability. Never signal borrowed PIDs.
        for sig in self.previous_signals: signal.signal(sig,signal.SIG_IGN)
        for name, proc, persistent in reversed(self.children):
            forced = False
            try:
                before_signal = proc.poll()
                if persistent and before_signal is not None:
                    self.cleanup_errors.append(f'{name}: persistent process exited before controlled teardown: {before_signal}')
                if before_signal is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    forced = True
                    os.killpg(proc.pid, signal.SIGKILL)
            except BaseException as exc:
                self.cleanup_errors.append(f'{name}: {type(exc).__name__}: {exc}')
            finally:
                # Even a signal race/error or uninterruptible kernel wait cannot detach this
                # handle or release the common lease while owned work remains outstanding.
                proc.wait()
            self.events.append(dict(event='stopped', name=name, pid=proc.pid, returncode=proc.returncode, forced_kill=forced))
        for sig,handler in self.previous_signals.items(): signal.signal(sig,handler)
        return not self.cleanup_errors

    def redis(self, binary, addresses):
        for idx, address in enumerate(addresses):
            directory = self.root/f'redis-{idx:02d}'
            directory.mkdir(mode=0o700)
            cfg = directory/'redis.conf'
            # Redis quotes paths using double quotes; reject embedded backslash/quotes here.
            if any(c in str(directory) for c in '\\"'):
                raise ValueError('Redis directory cannot contain backslash or double quote')
            cfg.write_text(f'bind {address}\nport 6379\nprotected-mode yes\ndaemonize no\nsave ""\nappendonly no\n'
                           f'dir "{directory}"\nmaxmemory 64mb\nmaxmemory-policy noeviction\nloglevel notice\n')
            with socket.socket() as reservation:
                reservation.bind((address,6379))
            proc = self.start(f'redis-{idx:02d}', [binary,cfg], directory)
            def ready():
                try:
                    info = fields(redis_command(address, 'INFO', 'server'))
                except (OSError, RuntimeError, ValueError):
                    return False
                if int(info.get('process_id','-1')) != proc.pid or info.get('redis_version') != REDIS_VERSION:
                    raise RuntimeError('Redis port is not the exact owned process/version')
                return True
            self.wait_for('owned Redis '+address, ready, 15)

    def stats(self, addresses):
        return {address: {section: fields(redis_command(address, 'INFO', section))
                          for section in ('server','stats','memory','commandstats')} for address in addresses}

    def require_empty_redis(self, addresses, phase):
        observed = {}
        def empty():
            observed.clear()
            for address in addresses:
                count = redis_command(address,'DBSIZE')
                if type(count) is not int or count < 0: raise RuntimeError('invalid DBSIZE response')
                observed[address] = count
            return all(count == 0 for count in observed.values())
        try:
            self.wait_for(phase+' all private Redis databases empty',empty,20)
        finally:
            self.event('redis_empty_boundary',phase=phase,dbsizes=observed.copy(),keys_deleted_by_driver=False)

def xml_config(path, values, nested=None):
    root = ET.Element('setting')
    for key, value in values.items():
        attr = ET.SubElement(root, 'attribute'); ET.SubElement(attr,'name').text = key
        for item in value if isinstance(value,list) else [value]:
            ET.SubElement(attr,'value').text = str(item)
    for key, entries in (nested or {}).items():
        attr = ET.SubElement(root,'attribute'); ET.SubElement(attr,'name').text = key
        for entry in entries:
            value = ET.SubElement(attr,'value')
            for key2,value2 in entry.items(): ET.SubElement(value,key2).text = str(value2)
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)

def mul(a,b):
    result = 0
    while b:
        if b & 1: result ^= a
        a <<= 1
        if a & 256: a ^= 0x11d
        b >>= 1
    return result

def data_and_shards():
    data = hashlib.shake_256(b'3fs-ec-reference-runtime-v1-fixed-input').digest(10*SHARD)
    shards = [b''.join(data[pos:pos+PACKET] for pos in range(i*PACKET,len(data),10*PACKET)) for i in range(10)]
    parity = []
    for row in range(2):
        # Little-endian Python big integers implement only bytewise XOR; multiplication is an
        # independent polynomial GF(2^8) table, not a call to either project's coding library.
        result = 0; coefficient = 1
        for shard in shards:
            table = bytes(mul(coefficient,x) for x in range(256))
            result ^= int.from_bytes(shard.translate(table),'little')
            coefficient = mul(coefficient,row+1)
        parity.append(result.to_bytes(SHARD,'little'))
    return data, shards+parity

def verify(path, expected):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != len(expected) or path.read_bytes() != expected:
        raise RuntimeError('exact byte comparison failed: '+str(path))
    return {'path':str(path), 'bytes':len(expected), 'sha256':sha(path), 'exact_equal':True}

def log_contains(root, name, text, offset=0):
    path = root/(name+'.log')
    if not path.exists(): return False
    with path.open('rb') as f:
        f.seek(offset)
        return text.encode() in f.read()
