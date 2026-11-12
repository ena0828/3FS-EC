#!/usr/bin/env python3
"""Prepare and supervise a private one- or twelve-Storage-process native EC lab."""
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

from native_v2_config import (PROFILES, SERVICES, file_api_enabled, required_services, gc_inventory_from_observations, gc_settings, json_text,
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
    required_gib = 6 if count == 12 else 3
    observations["required_available_memory_gib"] = required_gib
    if observations["memory_kib"].get("MemAvailable", 0) < required_gib * 1024**2:
        problems.append(f"less than {required_gib} GiB available; finish all builds/other experiments before startup")
    disk = os.statvfs(root)
    observations["free_bytes"] = disk.f_bavail * disk.f_frsize
    required_disk_gib = 8 if count == 12 else 4
    if observations["free_bytes"] < required_disk_gib * 1024**3:
        problems.append(f"less than {required_disk_gib} GiB free; no automatic cleanup or expansion")
    if count == 12:
        observations["active_build_processes"] = active_build_processes()
        if observations["active_build_processes"]:
            problems.append("finish all compiler/build-tool processes before twelve-Storage startup; none are stopped automatically")
        observations["free_inodes"] = disk.f_favail
        observations["engine_data_files_lower_bound"] = 12 * 11 * 256
        observations["engine_open_fds_lower_bound"] = 12 * 11 * 256 * 2
        observations["buffer_pool_payload_bytes"] = 12 * (16 * 1024**2 + 4 * 4 * 1024**2)
        if disk.f_favail < 50000:
            problems.append("less than 50000 free inodes for twelve Engine trees and experiment records")
        file_nr = [int(part) for part in Path("/proc/sys/fs/file-nr").read_text().split()]
        observations["kernel_file_nr"] = file_nr
        observations["global_fd_headroom_required"] = 12 * 6000 + 8192
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
        self.env.pop("LD_PRELOAD", None)

    def status(self):
        with self.status_lock:
            return {"schema": 1, "run": self.run_id, "stage": self.stage, "root": str(self.root),
                    "profile": self.manifest["profile"],
                    "processes": [{"name": name, "pid": proc.pid, "exit_code": proc.poll()}
                                  for name, proc in self.processes],
                    "logical_targets": 12, "storage_processes": storage_process_count(self.manifest),
                    "storage_process_failure_domains": storage_process_count(self.manifest),
                    "independent_storage_failure_domains": 1, "performance_validated": False,
                    "failure": self.failure}

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
                        command = conn.recv(64).decode("ascii").strip()
                        if uid != os.geteuid() or command not in {"status", "stop"}:
                            raise ValueError("invalid local supervisor request")
                        if command == "stop":
                            self.halt.set()
                        conn.sendall(json_text(self.status()).encode())
                    except (OSError, UnicodeError, ValueError):
                        continue
        self.control_thread = threading.Thread(target=serve, name="native-v2-control", daemon=True)
        self.control_thread.start()

    def healthy(self):
        if self.halt.is_set():
            raise InterruptedError("Supervisor stop requested")
        super().healthy()

    def admin(self, *args, **kwargs):
        self.healthy()
        return super().admin(*args, **kwargs)

    def preflight(self):
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

    def start_service(self, name):
        spec = next((value for value in storage_specs(self.manifest) if value["name"] == name), None)
        kind, stem = ("storage", spec["stem"]) if spec else (name, name + "_main")
        if spec and storage_process_count(self.manifest) == 12:
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
        if storage_process_count(self.manifest) != 12:
            return
        memory = Path("/proc/meminfo").read_text()
        available = re.search(r"^MemAvailable:\s+(\d+)", memory, re.MULTILINE)
        if not available or int(available[1]) < 2 * 1024**2:
            raise RuntimeError("Twelve-process startup exhausted its 2 GiB guest reserve; stop owned services normally")

    def startup_resource_snapshot(self, node):
        if storage_process_count(self.manifest) != 12:
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
            "physical_machine_failure_domains": 1, "configured_storage_processes": 12}))

    def record_pinned_config_observations(self):
        if storage_process_count(self.manifest) != 12:
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

    def add_user(self, uid, name, administrator=False):
        args = ["user-add"] + (["--root", "--admin"] if administrator else []) + [str(uid), name]
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
            user_token = self.add_user(1000, "native-lab-user")
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
        self.wait("twelve single-member EC chains", chains_ready, timeout=240)
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
        meta_path = self.config / "meta_main.toml"
        meta = tomllib.loads(meta_path.read_text())
        meta["server"]["meta"].update(enable_ec_v2=True, ec_targets=pool)
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
            self.admin(["set-perm", "/ec-lab", "-u", "1000", "-g", "1000", "-p", "0700"], "chown-user-workspace.log")
            write_new(self.root / "state/initialized.json", json_text({"schema": 1, "run": self.run_id,
                "cluster_id": self.manifest["cluster_id"], "physical_pool": pool}))
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
        print(f"READY: {self.manifest['profile']}; {storage_process_count(self.manifest)} Storage processes, 12 logical targets; "
              f"client config {self.root / 'client/stripe-client.toml'}", flush=True)
        print("Services are ready; write/read/repair experiments have not been run.", flush=True)

    def finish(self):
        clean = super().stop()
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
        client.sendall((command + "\n").encode("ascii"))
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
    parser.add_argument("command", choices=["prepare", "doctor", "start", "status", "stop"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--port-base", type=int, default=13500)
    parser.add_argument("--profile", choices=tuple(PROFILES),
                        help="prepare only: v2/gc (one process), v2-12/gc-12 (twelve); fresh roots only")
    parser.add_argument("--mode", choices=["initialize", "resume"], default="resume")
    parser.add_argument("--file-api", action="store_true",
                        help="prepare only: enable EC file sessions and RMW on a fresh gc/gc-12 profile")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Use Python 3.11+ inside Linux/WSL; no Windows filesystem database support")
    os.umask(0o077)
    root = args.root.absolute()
    if args.command == "prepare":
        prepare(root, args.source, args.port_base, args.profile or "v2", file_api=args.file_api)
        return 0
    if args.profile is not None or args.file_api:
        parser.error("--profile/--file-api are prepare-only; start/resume uses the immutable prepared profile")
    load_manifest(root)
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
            shutdown_seconds = 240 if storage_process_count(load_manifest(root)) == 1 else 45 * 15 + 30
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
        try:
            cluster.control()
            cluster.preflight()
            cluster.launch()
            while not cluster.halt.wait(1):
                cluster.healthy()
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
