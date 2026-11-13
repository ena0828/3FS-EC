#!/usr/bin/env python3
"""Prepare and supervise a private native EC lab with an explicit process topology."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import tomllib
import uuid

from native_fault_control import FaultController, initial_placement, validate_placement
from native_managed_domain import (KEY as MANAGED_KEY, ManagedDomain, artifact_identity,
                                   identifier as managed_id, make_binding, observe_owned_executable)
from native_v2_config import (PROFILES, SERVICES, SPARE_GC_PROFILE, target_count, file_api_enabled, required_services,
                              authenticated_user, validate_initialized_user, gc_inventory_from_observations, gc_settings, json_text,
                              key_roles, pool_from_observations, prepare, profile_config_problems,
                              replace_private, storage_process_count, storage_specs, topology_problems, to_toml, write_new)


def inherited_runner():
    spec = importlib.util.spec_from_file_location("ec_cluster_runner", Path(__file__).with_name("run-cluster.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Cluster


def load_manifest(root):
    if root.absolute() != root.resolve():
        raise RuntimeError("Refusing a symlink or non-canonical task root")
    info = root.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("Task root must belong to the supervisor UID with mode 0700")
    data = json.loads((root / "cluster.json").read_text(encoding="utf-8"))
    if type(data.get("schema")) is not int or data["schema"] != 1 or data.get("profile") not in PROFILES.values() or data.get("root") != str(root) or \
            topology_problems(data):
        raise RuntimeError("Not a matching explicitly prepared native process topology")
    gc_settings(data)
    file_api_enabled(data)
    authenticated_user(data)
    for directory in ("config", "secrets", "client", "state", "logs", "scripts", "data", "bin", "lib"):
        path = root / directory
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError(f"Missing or redirected task directory: {path}")
    if len(os.fsencode(root / "state/control.sock")) >= 104:
        raise RuntimeError("Task root is too long for the private Unix control socket")
    return data


def active_build_processes(proc_root=Path("/proc")):
    """Observe build tools; never signal or identify ownership from a PID file."""
    found = []
    pattern = re.compile(r"(?:cc1plus|cc1|g\+\+|c\+\+|clang(?:\+\+)?(?:-[0-9]+)?|rustc|cargo|ninja|cmake|ld(?:\.lld|\.gold)?|lto1)")
    for path in proc_root.iterdir():
        if not path.name.isdigit():
            continue
        try:
            name = (path / "comm").read_text().strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if pattern.fullmatch(name):
            found.append({"pid": int(path.name), "comm": name})
    return found


def doctor(root, check_ports=True):
    manifest = load_manifest(root)
    problems, observations = [], {}
    env = dict(os.environ, LD_LIBRARY_PATH=str(root / "lib"))
    env.pop("LD_PRELOAD", None)
    for name in (*required_services(manifest), "fdbserver", "fdbcli"):
        binary = root / "bin" / name
        if not binary.is_file() or not os.access(binary, os.X_OK):
            problems.append(f"missing executable {binary}")
            continue
        resolved = subprocess.run(["ldd", str(binary)], env=env, text=True, capture_output=True, timeout=15)
        if resolved.returncode or "not found" in resolved.stdout:
            problems.append(f"unresolved runtime libraries for {name}")
        if name in {"fdbserver", "fdbcli"}:
            version = subprocess.run([str(binary), "--version"], env=env, text=True, capture_output=True, timeout=10)
            if version.returncode or manifest["fdb_version"] not in version.stdout + version.stderr:
                problems.append(f"{name} version must be {manifest['fdb_version']}")
    if not (root / "lib/libfdb_c.so").is_file():
        problems.append("missing lib/libfdb_c.so")
    configs = {}
    for path in list((root / "config").glob("*.toml")) + list((root / "client").glob("*.toml")):
        configs[path.name] = tomllib.loads(path.read_text(encoding="utf-8"))
    problems.extend(profile_config_problems(manifest, configs))
    initialized = root / "state/initialized.json"
    if initialized.exists():
        if initialized.is_symlink():
            raise RuntimeError("Refusing redirected initialization record")
        validate_initialized_user(manifest, json.loads(initialized.read_text(encoding="utf-8")))
    # This flag exits before IB, FDB or server initialization. The three
    # launchers have fixed top-level objects. Do not treat the full default
    # dump as a schema: unset optional nested fields (e.g. network_type) are
    # omitted even though the native parser accepts them.
    observations["launcher_section_checks"] = []
    launcher_specs = [(kind, kind + "_main") for kind in ("mgmtd", "meta")]
    launcher_specs += [("storage", spec["stem"]) for spec in storage_specs(manifest)]
    for kind, stem in launcher_specs:
        binary = root / "bin" / f"{kind}_main"
        if not binary.is_file() or not os.access(binary, os.X_OK):
            continue
        path = root / "config" / f"{stem}_launcher.toml"
        argv = [str(binary), "--dump_default_launcher_cfg", "--app_cfg", str(root / "config" / f"{stem}_app.toml")]
        try:
            dumped = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=15)
            if dumped.returncode:
                problems.append(f"cannot inspect launcher sections for {path.name}: exit {dumped.returncode}")
                continue
            defaults = tomllib.loads(dumped.stdout)
            unknown = sorted(tomllib.loads(path.read_text(encoding="utf-8")).keys() - defaults.keys())
            observations["launcher_section_checks"].append({
                "config": path.name, "argv": argv, "unknown_keys": unknown,
                "default_toml_sha256": hashlib.sha256(dumped.stdout.encode()).hexdigest(),
                "scope": "top-level launcher keys only; nested/optional fields and values require native startup validation"})
            if unknown:
                problems.append(f"unknown native launcher keys in {path.name}: {', '.join(unknown)}")
        except (OSError, subprocess.TimeoutExpired, tomllib.TOMLDecodeError) as error:
            problems.append(f"cannot inspect launcher sections for {path.name}: {type(error).__name__}")
    inodes, key_material = set(), set()
    for role in key_roles(manifest):
        path = root / "secrets" / f"{role}.key"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size != 32:
            problems.append(f"invalid private 32-byte {role} key file")
        elif not any(path.read_bytes()):
            problems.append(f"zero-filled {role} key file")
        identity = (info.st_dev, info.st_ino)
        if identity in inodes:
            problems.append("different signing roles share a physical key file")
        inodes.add(identity)
        if gc_settings(manifest) and stat.S_ISREG(info.st_mode) and info.st_size == 32:
            value = path.read_bytes()
            if value in key_material:
                problems.append("GC profile signing roles must have independent key bytes")
            key_material.add(value)
    filesystem = subprocess.run(["findmnt", "-n", "-o", "FSTYPE", "-T", str(root)], text=True,
                                capture_output=True, timeout=10)
    observations["filesystem"] = filesystem.stdout.strip()
    if filesystem.returncode or observations["filesystem"] not in {"ext4", "xfs", "btrfs"}:
        problems.append("use a local ext4/xfs/btrfs task directory, not /mnt/c, /mnt/e, NFS or an existing image mount")
    memory = Path("/proc/meminfo").read_text()
    observations["memory_kib"] = {key: int(value) for key, value in re.findall(
        r"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)", memory, re.MULTILINE)}
    count = storage_process_count(manifest)
    required_gib = (7 if count == 14 else 6) if count > 1 else 3
    observations["required_available_memory_gib"] = required_gib
    if observations["memory_kib"].get("MemAvailable", 0) < required_gib * 1024**2:
        problems.append(f"less than {required_gib} GiB available; finish all builds/other experiments before startup")
    disk = os.statvfs(root)
    observations["free_bytes"] = disk.f_bavail * disk.f_frsize
    required_disk_gib = (10 if count == 14 else 8) if count > 1 else 4
    if observations["free_bytes"] < required_disk_gib * 1024**3:
        problems.append(f"less than {required_disk_gib} GiB free; no automatic cleanup or expansion")
    if count > 1:
        observations["active_build_processes"] = active_build_processes()
        if observations["active_build_processes"]:
            problems.append("finish all compiler/build-tool processes before multi-Storage startup; none are stopped automatically")
        observations["free_inodes"] = disk.f_favail
        observations["engine_data_files_lower_bound"] = count * 11 * 256
        observations["engine_open_fds_lower_bound"] = count * 11 * 256 * 2
        observations["buffer_pool_payload_bytes"] = count * (16 * 1024**2 + 4 * 4 * 1024**2)
        required_inodes = 60000 if count == 14 else 50000
        if disk.f_favail < required_inodes:
            problems.append(f"less than {required_inodes} free inodes for the prepared Engine trees and experiment records")
        file_nr = [int(part) for part in Path("/proc/sys/fs/file-nr").read_text().split()]
        observations["kernel_file_nr"] = file_nr
        observations["global_fd_headroom_required"] = count * 6000 + 8192
        if len(file_nr) != 3 or file_nr[2] - file_nr[0] < observations["global_fd_headroom_required"]:
            problems.append("insufficient global kernel file-table headroom; per-process nofile alone is insufficient")
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    observations["nofile_hard"] = hard
    if hard != resource.RLIM_INFINITY and hard < 16384:
        problems.append("nofile hard limit must be at least 16384 for the shared Rust Engine")
    if check_ports:
        for port in range(manifest["port_base"], manifest["port_base"] + 3 + storage_process_count(manifest)):
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError:
                    problems.append(f"TCP port {port} is occupied; existing listeners are not stopped")
    return {"profile": manifest["profile"], "status": "ready" if not problems else "needs_attention",
            "problems": problems, "observations": observations, "services_started": False,
            "validation": "configuration/resources only; native service behavior remains to be tested"}


class NativeCluster(inherited_runner()):
    def __init__(self, root, mode):
        super().__init__(root)
        self.mode = mode
        self.halt = threading.Event()
        self.socket_halt = threading.Event()
        self.control_thread = None
        self.control_socket = None
        self.control_path = root / "state/control.sock"
        self.run_id = self.run_dir.name
        self.status_lock = threading.Lock()
        self.failure = None
        self.storage_log_start = {}
        self.fault_control = FaultController(self)
        self.env.pop("LD_PRELOAD", None)
        self.managed = ManagedDomain.attach(root, self.manifest, self.run_id)
        self.managed_uncertain = False
        self.managed_launch_inputs = {}
        self.managed_lock = threading.Lock()
        self.managed_pending = None
        self.managed_actions = {}
        self.managed_enrollment_owner = None

    def status(self):
        with self.status_lock:
            return {"schema": 1, "run": self.run_id, "stage": self.stage, "root": str(self.root),
                    "profile": self.manifest["profile"],
                    "processes": [{"name": name, "pid": proc.pid, "exit_code": proc.poll()}
                                  for name, proc in self.processes],
                    "logical_targets": target_count(self.manifest), "storage_processes": storage_process_count(self.manifest),
                    "storage_process_failure_domains": storage_process_count(self.manifest),
                    "independent_storage_failure_domains": 1, "performance_validated": False,
                    "failure": self.failure, "maintenance": self.fault_control.snapshot()}

    def control(self):
        if self.control_path.exists():
            # Caller already owns the lifetime flock; a prior socket cannot
            # belong to a live supervisor for this root. Never remove a file.
            info = self.control_path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError("Unexpected control socket path; preserve for diagnosis")
            self.control_path.unlink()
        self.control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control_socket.bind(str(self.control_path))
        os.chmod(self.control_path, 0o600)
        self.control_socket.listen(4)
        self.control_socket.settimeout(0.5)

        def serve():
            while not self.socket_halt.is_set():
                try:
                    conn, _ = self.control_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    conn.settimeout(2)
                    try:
                        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        payload = bytearray()
                        while b"\n" not in payload:
                            part = conn.recv(1024)
                            if not part:
                                break
                            payload.extend(part)
                            if len(payload) > 4096:
                                raise ValueError("oversized supervisor request")
                        command = payload.decode("ascii").strip()
                        if uid != os.geteuid():
                            raise ValueError("invalid local supervisor UID")
                        if command in {"status", "stop"}:
                            if command == "stop":
                                self.halt.set()
                            response = self.status()
                        else:
                            request = json.loads(command)
                            if type(request) is not dict or not isinstance(request.get('operation'), str):
                                raise ValueError('Invalid control operation')
                            if request['operation'].startswith('managed-'):
                                response = self.managed_submit(request)
                            else:
                                with self.managed_lock:
                                    if self.managed_pending is not None or self.stage.startswith('managed_'):
                                        raise ValueError('Managed maintenance excludes fault maintenance')
                                    response = self.fault_control.submit(request)
                        conn.sendall(json_text(response).encode())
                    except (OSError, UnicodeError, ValueError, RuntimeError) as error:
                        try:
                            conn.sendall(json_text({"error": str(error), "accepted": False,
                                                    "outcome_unknown": True}).encode())
                        except OSError:
                            pass
        self.control_thread = threading.Thread(target=serve, name="native-v2-control", daemon=True)
        self.control_thread.start()

    def healthy(self):
        if self.halt.is_set():
            raise InterruptedError("Supervisor stop requested")
        self.fault_control.healthy()

    def admin(self, *args, **kwargs):
        self.healthy()
        return super().admin(*args, **kwargs)

    def preflight(self):
        # A registered domain is mandatory; no start flag can omit this gate.
        # Check before FDB/other services as well as immediately at Storage Popen.
        if self.managed is not None:
            self.managed.assert_startable()
        checks = doctor(self.root)
        if checks["problems"]:
            raise RuntimeError(json_text(checks))
        initialized = self.root / "state/initialized.json"
        fdb = self.root / "data/fdb"
        data_paths = [fdb] + [Path(spec["data_path"]) for spec in storage_specs(self.manifest)]
        if self.mode == "initialize":
            if initialized.exists() or any(path.exists() and any(path.iterdir()) for path in data_paths):
                raise RuntimeError("initialize requires empty task data directories; never reuse or clear an old database")
        elif not initialized.is_file():
            raise RuntimeError("resume requires successful initialization; partial bootstrap needs administrator diagnosis")
        else:
            validate_initialized_user(self.manifest, json.loads(initialized.read_text(encoding="utf-8")))
        for path in data_paths:
            if path.is_symlink():
                raise RuntimeError("Refusing redirected database directory")
            path.mkdir(mode=0o700, exist_ok=True)
        self.run_dir.mkdir(mode=0o700)
        write_new(self.run_dir / "doctor.json", json_text(checks))
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (16384, hard))
        self.disk_snapshot("before")
        self.start_sampler()

    def start(self, name, command):
        spec = next((row for row in storage_specs(self.manifest) if row['name'] == name), None)
        if spec is not None:
            if self.managed_uncertain:
                raise RuntimeError('Managed enrollment persistence is unknown; no Storage launch')
            if self.managed is not None and self.managed.locator['binding']['service'] == name:
                return self.managed.launch(command, lambda: self._start_owned(name, command))
        return self._start_owned(name, command)

    def _start_owned(self, name, command):
        spec = next((row for row in storage_specs(self.manifest) if row['name'] == name), None)
        launch_inputs = None
        if spec is not None and self.manifest['profile'] == SPARE_GC_PROFILE:
            launch_inputs = {'argv': list(map(str, command)), 'binary': artifact_identity(Path(command[0])),
                             'configs': [artifact_identity(Path(command[index])) for index in (2, 4, 6)],
                             'launch_id': str(uuid.uuid4())}
        generation = sum(child == name for child, _ in self.processes)
        if not generation and self.manifest["profile"] != SPARE_GC_PROFILE:
            super().start(name, command)
            proc = self.processes[-1][1]
            if launch_inputs is not None:
                launch_inputs['owned'] = observe_owned_executable(proc, launch_inputs['binary'])
                self.managed_launch_inputs[id(proc)] = launch_inputs
            return proc
        if generation:
            spec = next((v for v in storage_specs(self.manifest) if v["name"] == name), None)
            if name != "meta" and spec is None:
                raise RuntimeError("Only explicitly prepared Storage/Meta children support restart")
            port = spec["port"] if spec else self.manifest["port_base"] + 2
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", port))  # Refuse a borrowed listener; never signal it.
        suffix = f".restart-{generation}" if generation else ""
        log = (self.run_dir / f"{name}{suffix}.stdout.log").open("xb")
        self.logs.append(log)
        proc = subprocess.Popen(list(map(str, command)), cwd=self.root, env=self.env,
                                stdout=log, stderr=subprocess.STDOUT)
        try:
            self.processes.append((name, proc))
        except BaseException:
            # The local handle still owns this child even if registration fails.
            try:
                proc.terminate()
            finally:
                proc.wait()
            raise
        print(f"Started {name} pid={proc.pid} generation={generation}", flush=True)
        if launch_inputs is not None:
            launch_inputs['owned'] = observe_owned_executable(proc, launch_inputs['binary'])
            self.managed_launch_inputs[id(proc)] = launch_inputs
        return proc

    def managed_submit(self, request):
        """Socket thread only queues; the foreground owner performs all effects."""
        if self.manifest['profile'] != SPARE_GC_PROFILE or type(request) is not dict:
            raise ValueError('Managed adapter requires the explicit gc-14 profile')
        action = managed_id(request.get('action_id'))
        if request.get('run') != self.run_id:
            raise ValueError('Managed action belongs to another supervisor run')
        operation = request.get('operation')
        with self.managed_lock:
            if operation == 'managed-action-status':
                if set(request) != {'operation', 'action_id', 'run'}:
                    raise ValueError('Invalid managed status fields')
                return self.managed_actions.get(action, {'state': 'not_observed', 'action_id': action,
                                                          'scope': 'managed_launch_only_not_external_fence'})
            fields = {'operation', 'action_id', 'run', 'domain'}
            if operation == 'managed-enroll':
                fields |= {'node', 'control', 'resource_generation'}
                managed_id(request.get('resource_generation'))
                if type(request.get('node')) is not int or request['node'] not in {s['node'] for s in storage_specs(self.manifest)}:
                    raise ValueError('Require one exact prepared Storage node')
            elif operation != 'managed-retire':
                raise ValueError('Invalid managed operation')
            managed_id(request.get('domain'))
            if set(request) != fields:
                raise ValueError('Invalid managed request fields')
            prior = self.managed_actions.get(action)
            if prior is not None:
                if prior['request'] != request:
                    raise ValueError('Managed action UUID payload conflict')
                if prior['state'] != 'failed':
                    return prior
                if operation == 'managed-enroll' and self.managed_enrollment_owner is None:
                    return prior
            if self.halt.is_set() or self.managed_pending is not None or self.stage not in {'ready', 'managed_retired', 'managed_unknown'}:
                raise ValueError('Managed action requires an idle live supervisor')
            if prior is None and self.stage == 'managed_unknown':
                raise ValueError('Unknown state only accepts the original action identity')
            with self.fault_control.lock:
                if self.fault_control.pending or self.fault_control.running or self.fault_control.failed:
                    raise ValueError('Another maintenance action is outstanding')
            record = {'request': request, 'state': 'queued', 'action_id': action,
                      'scope': 'managed_launch_only_not_external_fence', 'external_fence': False, 'scope_T2': False}
            self.managed_actions[action] = record
            self.managed_pending = request
            self.stage = 'managed_queued'
            return record

    def managed_execute_one(self):
        with self.managed_lock:
            request = self.managed_pending
            if request is None:
                return
            self.managed_pending = None
            record = self.managed_actions[request['action_id']]
            record['state'] = 'running'
            record = dict(record)  # Status thread never serializes an actively mutated result.
            self.stage = 'managed_processing'
        try:
            with self.fault_control.lock:
                if self.fault_control.pending or self.fault_control.running or self.fault_control.failed:
                    raise RuntimeError('Concurrent maintenance is not accepted')
            if request['operation'] == 'managed-enroll':
                self.stage = 'managed_enrollment'
                self.managed_uncertain = True
                spec = next(s for s in storage_specs(self.manifest) if s['node'] == request['node'])
                proc = self.fault_control._owned(spec['name'])
                if self.managed_enrollment_owner is None:
                    self.managed_enrollment_owner = (dict(request), proc)
                elif self.managed_enrollment_owner != (request, proc):
                    raise RuntimeError('Partial enrollment can only retain its original live owner')
                inventory = json.loads((self.root / 'state/physical-pool.json').read_text(encoding='utf-8'))
                endpoint = next(row for row in inventory if row['node'] == request['node'])
                # This is a fresh authenticated RPC observation, not enrollment
                # of a caller-supplied engine/incarnation or an old PID file.
                self.fault_control._discover_one(endpoint, {'request': {'action_id': str(uuid.uuid4())}})
                self.manifest = load_manifest(self.root)  # Includes any persisted partial marker.
                binding = make_binding(self.root, self.manifest, endpoint, spec, request['resource_generation'])
                self.managed = ManagedDomain.enroll(self.root, self.manifest, Path(request['control']),
                    request['domain'], request['action_id'], binding, self.run_id, proc,
                    self.managed_launch_inputs[id(proc)])
                self.managed_uncertain = False
                self.stage = 'ready'
            else:
                if self.managed is None or self.managed.locator['domain'] != request['domain']:
                    raise RuntimeError('Managed domain is not enrolled by this owner')
                self.stage = 'managed_retiring'
                proc = self.managed.prepare_deny(request['action_id'])
                # The durable deny precedes the first signal. This expected exit
                # is deliberately NOT added to the restartable faulted-node set.
                with self.fault_control.lock:
                    self.fault_control.expected[id(proc)] = (proc, {
                        'name': self.managed.locator['binding']['service'], 'pid': proc.pid,
                        'reason': 'managed_launch_deny_then_owned_stop'})
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=45)
                self.managed.observe_join(proc)
                self.stage = 'managed_retired'
            record.update(state='completed', observation=self.managed.query())
        except BaseException as error:
            record.update(state='failed', error_type=type(error).__name__, outcome_unknown=True)
            self.stage = 'managed_unknown'
        finally:
            with self.managed_lock:
                self.managed_actions[request['action_id']] = record

    def start_service(self, name):
        spec = next((value for value in storage_specs(self.manifest) if value["name"] == name), None)
        kind, stem = ("storage", spec["stem"]) if spec else (name, name + "_main")
        if spec and storage_process_count(self.manifest) > 1:
            path = self.root / "logs" / (spec["name"] + ".log")
            if path.is_symlink():
                raise RuntimeError("Refusing redirected Storage log")
            old = path.stat() if path.exists() else None
            self.storage_log_start[name] = None if old is None else (old.st_dev, old.st_ino, old.st_size)
        self.start(name, [self.root / "bin" / f"{kind}_main",
            "--app_cfg", self.config / f"{stem}_app.toml",
            "--launcher_cfg", self.config / f"{stem}_launcher.toml",
            "--cfg", self.config / f"{stem}.toml"])

    def startup_memory_guard(self):
        if storage_process_count(self.manifest) == 1:
            return
        memory = Path("/proc/meminfo").read_text()
        available = re.search(r"^MemAvailable:\s+(\d+)", memory, re.MULTILINE)
        if not available or int(available[1]) < 2 * 1024**2:
            raise RuntimeError("Multi-process startup exhausted its 2 GiB guest reserve; stop owned services normally")

    def startup_resource_snapshot(self, node):
        if storage_process_count(self.manifest) == 1:
            return
        records = []
        for name, process in self.processes:
            row = {"name": name, "pid": process.pid, "exit_code": process.poll()}
            path = Path("/proc") / str(process.pid)
            try:
                text = (path / "status").read_text()
                row["status_values"] = dict(re.findall(r"^(VmRSS|VmSize|Threads):\s+([^\n]+)", text, re.MULTILINE))
                row["open_fds"] = len(list((path / "fd").iterdir()))
                # Sum PSS/USS, not summed RSS, when accounting shared ELF pages.
                smaps = (path / "smaps_rollup").read_text()
                row["smaps_kib"] = {k: int(v) for k, v in re.findall(
                    r"^(Pss|Private_Clean|Private_Dirty|Swap):\s+(\d+)", smaps, re.MULTILINE)}
            except (FileNotFoundError, PermissionError, ProcessLookupError) as error:
                row["observation_error"] = type(error).__name__
            records.append(row)
        write_new(self.run_dir / f"startup-resources-{node}.json", json_text({
            "scope": "point_in_time_startup_only_not_benchmark", "processes": records,
            "guest_meminfo": Path("/proc/meminfo").read_text(),
            "physical_machine_failure_domains": 1, "configured_storage_processes": storage_process_count(self.manifest)}))

    def record_pinned_config_observations(self):
        if storage_process_count(self.manifest) == 1:
            return
        self.admin(["get-config", "-t", "STORAGE", "-o", self.run_dir / "global-storage-config.toml"],
                   "global-storage-config-version.log")
        self.admin(["list-nodes"], "config-observation-nodes.log")
        records = []
        for spec in storage_specs(self.manifest):
            name, node = spec["name"], spec["node"]
            effective = self.run_dir / f"effective-{node}.toml"
            self.admin(["get-config", "-n", str(node), "-o", effective], f"effective-{node}.log")
            self.admin(["get-last-config-update-record", "-n", str(node)], f"config-attempt-{node}.log")
            local = self.config / (spec["stem"] + ".toml")
            row = {"node": node, "local_config": str(local),
                   "local_config_sha256": hashlib.sha256(local.read_bytes()).hexdigest(),
                   "effective_config": str(effective), "effective_config_sha256": hashlib.sha256(effective.read_bytes()).hexdigest(),
                   "config_version_source": "config-observation-nodes.log; actual Mgmtd heartbeat value",
                   "attempt_source": f"config-attempt-{node}.log"}
            log = self.root / "logs" / (name + ".log")
            if log.is_symlink() or not log.is_file():
                row["rejection_count_status"] = "unavailable_missing_or_redirected_log"
            else:
                with log.open("rb") as stream:
                    current = os.fstat(stream.fileno())
                    old = self.storage_log_start[name]
                    offset = old[2] if old else 0
                    if old and ((current.st_dev, current.st_ino) != old[:2] or current.st_size < offset):
                        row["rejection_count_status"] = "unavailable_rotation_or_truncation"
                    else:
                        stream.seek(offset)
                        text = stream.read(current.st_size - offset).decode("utf-8", errors="replace")
                        row.update(rejection_count_status="bounded_same_log_segment", from_byte=offset,
                                   to_byte=current.st_size,
                                   rejected_version_headers=text.count("Pinned local config rejected remote version."),
                                   equivalent_version_headers=text.count("Pinned local config already matches remote version;"))
            records.append(row)
        write_new(self.run_dir / "pinned-config-observations.json", json_text({
            "policy": "global_STORAGE_configuration_is_not_equivalent_to_all_per_node_local_configurations",
            "config_versions_not_fabricated": True, "network_repeated_payloads_remain": True,
            "counts_scope": "startup log segments only; not full lifetime or performance measurements", "nodes": records}))

    def node_ready(self, node, kind):
        text = self.admin(["list-nodes"], f"node-{node}.log")
        return bool(re.search(rf"^{node}\s+{kind}\s+HEARTBEAT_CONNECTED\b", text, re.MULTILINE))

    def add_user(self, uid, name, administrator=False, *, gid=None):
        args = (["user-add"] + (["--root", "--admin"] if administrator else [])
                + (["--gid", str(gid)] if gid is not None else []) + [str(uid), name])
        output = self.admin(args, f"{self.run_id}-create-user-{uid}.log", secret=True)
        found = re.findall(r"^Token\s+([A-Za-z0-9+/]{24})\(Expired", output, flags=re.MULTILINE)
        if len(found) != 1:
            raise RuntimeError("Could not extract one UserStore token; private output retained for diagnosis")
        return found[0]

    def launch(self):
        base = self.manifest["port_base"]
        self.stage = "foundationdb"
        self.start("fdb", [self.root / "bin/fdbserver", "-p", f"127.0.0.1:{base}", "-l", f"127.0.0.1:{base}",
            "-C", self.config / "fdb.cluster", "-d", self.root / "data/fdb", "-L", self.run_dir,
            "--memory", "1024MiB", "--cache-memory", "64MiB", "--logsize", "10MiB", "--maxlogssize", "100MiB"])
        self.wait("FoundationDB TCP", lambda: self.port_ready(base), timeout=30)
        fdbcli = [self.root / "bin/fdbcli", "-C", self.config / "fdb.cluster", "--exec"]
        if self.mode == "initialize":
            self.call(fdbcli + ["configure new single ssd logs=1 commit_proxies=1 grv_proxies=1 resolvers=1"], "fdb-configure.log")
        def fdb_ready():
            text = self.call(fdbcli + ["status minimal"], "fdb-status.log", timeout=10).lower()
            return "available" in text and "unavailable" not in text
        self.wait("FoundationDB available", fdb_ready)
        if self.mode == "initialize":
            self.stage = "user-and-namespace-bootstrap"
            admin = tomllib.loads((self.config / "admin_cli.toml").read_text())
            admin["user_info"]["token"] = self.add_user(0, "native-lab-admin", True)
            replace_private(self.config / "admin_cli.toml", to_toml(admin))
            user = authenticated_user(self.manifest)
            user_token = self.add_user(user["uid"], "native-lab-user", gid=user["gid"])
            write_new(self.root / "client/user.token", user_token + "\n")
            # This initializes only the metadata root and configuration records;
            # no ordinary replicated data target or FUSE process is created.
            self.admin(["init-cluster", "--mgmtd", self.config / "mgmtd_main.toml", "--meta", self.config / "meta_main.toml",
                "--storage", self.config / (storage_specs(self.manifest)[0]["stem"] + ".toml"), "1", "65536", "1"], "init-cluster.log")
        self.stage = "storage-bootstrap"
        self.start_service("mgmtd")
        self.wait("mgmtd routing", lambda: "MGMTD" in self.admin(["list-nodes"], "nodes-mgmtd.log"))
        if self.mode == "initialize":
            for spec in storage_specs(self.manifest):
                self.admin(["register-node", str(spec["node"]), "STORAGE"], f"register-{spec['name']}.log")
            self.admin(["register-node", "100", "META"], "register-meta.log")
        for spec in storage_specs(self.manifest):
            self.startup_memory_guard()
            self.start_service(spec["name"])
            self.wait(spec["name"], lambda node=spec["node"]: self.node_ready(node, "STORAGE"))
            self.startup_resource_snapshot(spec["node"])
            self.startup_memory_guard()
        if self.mode == "initialize":
            for endpoint in self.manifest["endpoints"]:
                self.admin(["create-ec-target", "--node-id", str(endpoint["node"]), "--disk-index", "0",
                    "--chain-id", str(endpoint["chain"]), "--target-id", str(endpoint["target"])],
                    f"create-target-{endpoint['target']}.log")
            self.admin(["upload-chains", self.config / "chains.csv", "--set-preferred-target-order"], "upload-chains.log")
            self.admin(["upload-chain-table", "1", self.config / "chain-table.csv", "--desc", "native-v2-colocated-test"],
                       "upload-chain-table.log")
        def chains_ready():
            lines = self.admin(["list-chains", "--table-id", "1"], "chains.log").splitlines()
            return all(any(re.match(rf"^{endpoint['chain']}\s", line) and line.count("(SERVING-UPTODATE)") == 1
                           for line in lines) for endpoint in self.manifest["endpoints"])
        self.wait("prepared single-member EC chains", chains_ready, timeout=240)
        self.stage = "authenticated-instance-discovery"
        observations = []
        for endpoint in self.manifest["endpoints"]:
            output = self.run_dir / f"instance-{endpoint['target']}.json"
            self.admin(["discover-ec-target", "--node-id", str(endpoint["node"]), "--chain-id", str(endpoint["chain"]),
                "--target-id", str(endpoint["target"]), "--authority", self.manifest["authority"],
                "--control-key-file", self.root / "secrets/control.key", "--output", output],
                f"discover-{endpoint['target']}.log")
            observations.append(json.loads(output.read_text()))
        pool = pool_from_observations(self.manifest, observations)
        stored = self.root / "state/physical-pool.json"
        if self.mode == "initialize":
            write_new(stored, json_text(pool))
        elif json.loads(stored.read_text()) != pool:
            raise RuntimeError("Persistent Engine/target identity changed; refusing to replace historical allocations or Meta pool")
        gc = gc_settings(self.manifest)
        if gc:
            self.stage = "authenticated-gc-capability-discovery"
            observed_gc = []
            for endpoint in self.manifest["endpoints"]:
                output = self.run_dir / f"gc-instance-{endpoint['target']}.json"
                self.admin(["discover-ec-gc-target", "--node-id", str(endpoint["node"]),
                    "--chain-id", str(endpoint["chain"]), "--target-id", str(endpoint["target"]),
                    "--authority", gc["authority"], "--gc-key-id", gc["key_id"],
                    "--gc-key-file", self.root / "secrets/gc.key", "--output", output],
                    f"discover-gc-{endpoint['target']}.log")
                observed_gc.append(json.loads(output.read_text(encoding="utf-8")))
            inventory = gc_inventory_from_observations(self.manifest, pool, observed_gc, int(time.time()))
            gc_stored = self.root / "state/gc-physical-pool.json"
            if self.mode == "initialize":
                write_new(gc_stored, json_text(inventory))
            elif json.loads(gc_stored.read_text(encoding="utf-8")) != inventory:
                raise RuntimeError("Persistent GC instance/format changed; historical inventory is not replaced")
        placement = pool
        if self.manifest["profile"] == SPARE_GC_PROFILE:
            placement_path = self.root / "state/placement.json"
            if self.mode == "initialize":
                placement = initial_placement(self.manifest, pool)
                write_new(placement_path, json_text({"schema": 1, "pool": placement, "action_id": None}))
            else:
                retained = json.loads(placement_path.read_text(encoding="utf-8"))
                if type(retained.get("schema")) is not int or retained["schema"] != 1:
                    raise RuntimeError("Invalid retained placement")
                placement = validate_placement(self.manifest, pool, retained["pool"])
        meta_path = self.config / "meta_main.toml"
        meta = tomllib.loads(meta_path.read_text())
        meta["server"]["meta"].update(enable_ec_v2=True, ec_targets=placement)
        if gc:
            meta["server"]["meta"].update(enable_ec_exact_gc=True, enable_ec_revision_retirement=True)
        if file_api_enabled(self.manifest):
            meta["server"]["meta"].update(enable_ec_rmw=True, enable_ec_file_ranges=True)
        replace_private(meta_path, to_toml(meta))
        self.admin(["set-config", "-t", "META", "-f", meta_path, "--desc", "verified native-v2 physical pool"],
                   "set-meta-v2-config.log")
        self.stage = "meta-startup"
        self.start_service("meta")
        self.wait("authenticated Meta V2 service", lambda: self.node_ready(100, "META"))
        self.record_pinned_config_observations()
        self.startup_resource_snapshot("all-ready")
        self.startup_memory_guard()
        if self.mode == "initialize":
            self.admin(["mkdir", "/ec-lab", "--perm", "0700"], "mkdir-user-workspace.log")
            user = authenticated_user(self.manifest)
            self.admin(["set-perm", "/ec-lab", "-u", str(user["uid"]), "-g", str(user["gid"]), "-p", "0700"],
                       "chown-user-workspace.log")
            write_new(self.root / "state/initialized.json", json_text({"schema": 1, "run": self.run_id,
                "cluster_id": self.manifest["cluster_id"], "physical_pool": pool, "authenticated_user": user}))
        self.stage = "ready"
        self.healthy()
        # Startup resource sampling is outside the experiment's timed region.
        # No one-second sampler runs through subsequent user measurements.
        self.sample_stop.set()
        if self.sampler is not None:
            self.sampler.join(timeout=3)
            if self.sampler.is_alive():
                raise RuntimeError("Startup sampler did not finish; refusing measurement-ready state")
        write_new(self.run_dir / "ready.json", json_text(self.status()))
        print(f"READY: {self.manifest['profile']}; {storage_process_count(self.manifest)} Storage processes, {target_count(self.manifest)} logical targets, twelve placement slots; "
              f"client config {self.root / 'client/stripe-client.toml'}", flush=True)
        print("Services are ready; write/read/repair experiments have not been run.", flush=True)

    def finish(self):
        clean = super().stop()
        if self.managed is not None and self.managed.handle is not None:
            try:
                self.managed.observe_join(self.managed.handle)
            except (OSError, ValueError):
                clean = False  # Never make a lost/unknown handle restartable.
        self.stage = "stopped" if clean else "cleanup_incomplete"
        replace_private(self.root / "state/last-supervisor.json", json_text(self.status()))
        self.socket_halt.set()
        if self.control_socket is not None:
            self.control_socket.close()
        if self.control_thread is not None:
            self.control_thread.join(timeout=3)
        if self.control_path.is_socket():
            self.control_path.unlink()
        return clean


def request_control(root, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(root / "state/control.sock"))
        client.sendall(((json.dumps(command, separators=(",", ":")) if isinstance(command, dict) else command) +
                        "\n").encode("ascii"))
        result = bytearray()
        while True:
            part = client.recv(4096)
            if not part:
                break
            result.extend(part)
            if len(result) > 65536:
                raise RuntimeError("oversized supervisor response")
        return json.loads(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "doctor", "start", "status", "stop", "fault-storage", "restart-storage", "replace-placement", "action-status",
                                           "managed-enroll", "managed-retire", "managed-query"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--port-base", type=int, default=13500)
    parser.add_argument("--profile", choices=tuple(PROFILES),
                        help="prepare only: v2/gc (one), v2-12/gc-12 (twelve), gc-14 (twelve plus two spares); fresh roots only")
    parser.add_argument("--mode", choices=["initialize", "resume"], default="resume")
    parser.add_argument("--file-api", action="store_true",
                        help="prepare only: enable EC file sessions and RMW on a fresh gc/gc-12/gc-14 profile")
    parser.add_argument("--user-uid", type=int, help="prepare only: authenticated ordinary UID; supply with --user-gid")
    parser.add_argument("--user-gid", type=int, help="prepare only: authenticated GID; both default to 1000")
    parser.add_argument("--run", help="fault action: exact live supervisor run from status")
    parser.add_argument("--action-id", help="fault action: caller-saved nonzero UUID; never regenerated on retry")
    parser.add_argument("--wait-seconds", type=int, default=600,
                        help="fault action observation limit; timeout never cancels or reissues the action")
    parser.add_argument("--nodes", help="fault/restart: one or two explicit node IDs, comma separated")
    parser.add_argument("--replace", help="placement: explicit old:new mappings, comma separated")
    parser.add_argument('--domain-id', help='managed operations: fixed nonzero domain UUID')
    parser.add_argument('--control-dir', type=Path, help='enroll: existing empty private directory outside this lab')
    parser.add_argument('--resource-generation', help='enroll: fixed resource binding UUID, not a device isolation proof')
    parser.add_argument('--node', type=int, help='enroll: one already-running gc14 Storage node')
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Use Python 3.11+ inside Linux/WSL; no Windows filesystem database support")
    os.umask(0o077)
    root = args.root.absolute()
    managed_args = (args.domain_id, args.control_dir, args.resource_generation, args.node)
    if not args.command.startswith('managed-') and any(v is not None for v in managed_args):
        parser.error('Managed arguments require a managed command')
    if args.command == "prepare":
        if args.run or args.action_id or args.nodes or args.replace:
            parser.error("Fault action arguments cannot be used with prepare")
        if (args.user_uid is None) != (args.user_gid is None):
            parser.error("--user-uid and --user-gid must be supplied together")
        user = authenticated_user({"authenticated_user": {"uid": 1000 if args.user_uid is None else args.user_uid,
                                                         "gid": 1000 if args.user_gid is None else args.user_gid}})
        prepare(root, args.source, args.port_base, args.profile or "v2", file_api=args.file_api,
                user_uid=user["uid"], user_gid=user["gid"])
        return 0
    if args.profile is not None or args.file_api or args.user_uid is not None or args.user_gid is not None:
        parser.error("--profile/--file-api/--user-uid/--user-gid are prepare-only; start/resume uses the immutable prepared profile")
    load_manifest(root)
    if args.command.startswith('managed-'):
        if args.nodes or args.replace or not args.domain_id:
            parser.error('Managed commands require --domain-id and no fault selection flags')
        managed_id(args.domain_id)
        if args.command == 'managed-query':
            if args.run or args.action_id or any(v is not None for v in (args.control_dir, args.resource_generation, args.node)):
                parser.error('managed-query takes only --root/--domain-id; it may re-sync persistence but never starts/stops processes')
            manifest = load_manifest(root)
            if MANAGED_KEY not in manifest or manifest[MANAGED_KEY]['domain'] != args.domain_id:
                parser.error('No matching mandatory managed-domain marker')
            try:
                gate = ManagedDomain.attach(root, manifest, 'offline-query-no-process-ownership')
                result = gate.query()
                print(json_text(result))
                return 0
            except (OSError, ValueError, KeyError, TypeError) as error:
                print(json_text({'scope': 'managed_launch_only_not_external_fence', 'state': 'unknown',
                                 'error_type': type(error).__name__, 'external_fence': False, 'scope_T2': False}))
                return 2
        if not args.run or not args.action_id or not 1 <= args.wait_seconds <= 1800:
            parser.error('Managed mutation requires fixed --run/--action-id and wait 1..1800')
        managed_id(args.action_id)
        request = {'operation': args.command, 'action_id': args.action_id, 'run': args.run, 'domain': args.domain_id}
        if args.command == 'managed-enroll':
            if args.control_dir is None or args.resource_generation is None or args.node is None:
                parser.error('Enrollment requires --control-dir/--resource-generation/--node')
            request.update(control=str(args.control_dir.absolute()), resource_generation=managed_id(args.resource_generation),
                           node=args.node)
        elif any(v is not None for v in (args.control_dir, args.resource_generation, args.node)):
            parser.error('Retirement uses the enrolled binding; no replacement paths/identity')
        result = request_control(root, request)
        print(json_text(result), flush=True)
        deadline = time.monotonic() + args.wait_seconds
        while 'error' not in result and result.get('state') in {'queued', 'running'}:
            if time.monotonic() >= deadline:
                return 2  # Never reissue, cancel or invent a new retirement ID.
            time.sleep(0.25)
            result = request_control(root, {'operation': 'managed-action-status', 'run': args.run,
                                            'action_id': args.action_id})
        print(json_text(result), flush=True)
        return 0 if result.get('state') == 'completed' else 1
    if args.command in {"fault-storage", "restart-storage", "replace-placement", "action-status"}:
        if not args.run or not args.action_id:
            parser.error("--run and --action-id are mandatory")
        request = {"operation": args.command, "run": args.run, "action_id": args.action_id}
        if args.command in {"fault-storage", "restart-storage"}:
            if not args.nodes or args.replace:
                parser.error("Require --nodes and no --replace")
            if not re.fullmatch(r"[1-9][0-9]*(?:,[1-9][0-9]*)?", args.nodes):
                parser.error("Invalid exact node integers")
            request["nodes"] = [int(n) for n in args.nodes.split(",")]
        elif args.command == "replace-placement":
            if (not args.replace or args.nodes or
                    not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*(?:,[1-9][0-9]*:[1-9][0-9]*)?", args.replace)):
                parser.error("Require explicit --replace old:new[,old:new]")
            request["replacements"] = [[int(n) for n in pair.split(":")] for pair in args.replace.split(",")]
        elif args.nodes or args.replace:
            parser.error("Status takes no node mutation fields")
        if not 1 <= args.wait_seconds <= 1800:
            parser.error("--wait-seconds must be 1..1800")
        result = request_control(root, request)
        print(json_text(result), flush=True)
        if args.command != "action-status":
            deadline = time.monotonic() + args.wait_seconds
            query = {"operation": "action-status", "run": args.run, "action_id": args.action_id}
            while "error" not in result and result.get("state") in {"queued", "running"}:
                if time.monotonic() >= deadline:
                    print("Action remains unconfirmed; query the same run and action UUID, never generate a retry identity",
                          file=sys.stderr)
                    return 2
                time.sleep(0.25)
                result = request_control(root, query)
            print(json_text(result), flush=True)
        return 0 if result.get("state") == "completed" else (1 if "error" in result or result.get("state") == "failed" else 2)
    if args.run or args.action_id or args.nodes or args.replace:
        parser.error("Fault action arguments require an explicit fault command")
    if args.command == "doctor":
        report = doctor(root)
        print(json_text(report))
        return bool(report["problems"])
    if args.command in {"status", "stop"}:
        try:
            snapshot = request_control(root, args.command)
        except (ConnectionRefusedError, FileNotFoundError):
            path = root / "state/last-supervisor.json"
            print(json_text({"live_supervisor": False, "last_observation": json.loads(path.read_text()) if path.exists() else None,
                             "note": "No PID is signalled; this does not prove orphan processes are absent."}))
            return 1
        print(json_text(snapshot))
        if args.command == "stop":
            shutdown_seconds = 240 if storage_process_count(load_manifest(root)) == 1 else 45 * (storage_process_count(load_manifest(root)) + 3) + 30
            deadline = time.monotonic() + shutdown_seconds
            while time.monotonic() < deadline:
                path = root / "state/last-supervisor.json"
                if path.exists():
                    final = json.loads(path.read_text())
                    if final.get("run") == snapshot["run"]:
                        print(json_text(final))
                        return final["stage"] != "stopped"
                time.sleep(0.5)
            raise RuntimeError(f"Supervisor cleanup exceeded {shutdown_seconds} seconds; inspect owned-process logs, no forced kill sent")
        return 0
    # The foreground supervisor alone holds child Popen handles and the lock.
    # Status/stop communicate over its private socket instead of using PID files.
    with (root / "state/supervisor.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cluster = NativeCluster(root, args.mode)
        signal.signal(signal.SIGTERM, lambda *_: cluster.halt.set())
        signal.signal(signal.SIGINT, lambda *_: cluster.halt.set())
        signal.signal(signal.SIGHUP, lambda *_: cluster.halt.set())
        try:
            cluster.control()
            cluster.preflight()
            cluster.launch()
            while not cluster.halt.wait(1):
                cluster.managed_execute_one()
                cluster.fault_control.execute_one()
                cluster.fault_control.healthy()
        except BaseException as error:
            cluster.failure = {"type": type(error).__name__, "message": str(error), "stage": cluster.stage}
            raise
        finally:
            if not cluster.finish():
                raise RuntimeError("Some owned processes did not stop cleanly; inspect state/last-supervisor.json")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
