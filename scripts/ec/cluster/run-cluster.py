#!/usr/bin/env python3
"""Supervise task-owned real 3FS processes inside the isolated Linux guest."""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import subprocess
import sys
import threading
import time
import tomllib


class Cluster:
    def __init__(self, root):
        self.root = root
        self.config = root / "config"
        self.manifest = json.loads((root / "cluster.json").read_text())
        self.processes = []
        self.logs = []
        self.mounted = False
        self.stage = "preflight"
        self.sample_stop = threading.Event()
        self.sampler = None
        self.env = dict(os.environ, LD_LIBRARY_PATH=str(root / "lib") + (":" + os.environ["LD_LIBRARY_PATH"] if os.environ.get("LD_LIBRARY_PATH") else ""))
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.run_dir = root / "logs" / f"run-{stamp}"

    def call(self, command, name, timeout=60, secret=False):
        path = self.root / "secrets" / name if secret else self.run_dir / name
        try:
            result = subprocess.run(list(map(str, command)), cwd=self.root, env=self.env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            if isinstance(output, str):
                output = output.encode()
            path.write_bytes(output + f"\nCommand timed out after {timeout} seconds.\n".encode())
            raise
        path.write_bytes(result.stdout)
        if result.returncode:
            raise RuntimeError(f"Command failed ({result.returncode}); inspect {path}")
        return result.stdout.decode(errors="replace")

    def admin(self, command, name="admin-command.log", secret=False):
        return self.call([self.root / "bin/admin_cli", "--cfg", self.config / "admin_cli.toml", "--", *command], name, secret=secret)

    def start(self, name, command):
        log = (self.run_dir / f"{name}.stdout.log").open("wb")
        self.logs.append(log)
        proc = subprocess.Popen(list(map(str, command)), cwd=self.root, env=self.env, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append((name, proc))
        print(f"Started {name} pid={proc.pid}", flush=True)

    def healthy(self):
        for name, proc in self.processes:
            if proc.poll() is not None:
                raise RuntimeError(f"{name} exited unexpectedly with {proc.returncode}; inspect {self.run_dir}")

    def disk_snapshot(self, label):
        paths = [self.root / "data"] + sorted((self.root / "data").glob("storage-*"))
        paths += [path / "engine" for path in paths[1:] if (path / "engine").is_dir()]
        self.call(["df", "-B1", self.root], f"disk-{label}-filesystem.log")
        # A single du invocation skips child operands already visited through
        # their parent. Inspect each path independently; these totals overlap.
        (self.run_dir / f"disk-{label}-paths.json").write_text(json.dumps(
            {str(index): str(path) for index, path in enumerate(paths)}, indent=2) + "\n")
        for index, path in enumerate(paths):
            self.call(["du", "-x", "-B1", "-s", path], f"disk-{label}-{index}-allocated.log")
            self.call(["du", "-x", "-B1", "--apparent-size", "-s", path], f"disk-{label}-{index}-apparent.log")

    def start_sampler(self):
        def sample():
            with (self.run_dir / "resources.jsonl").open("a", buffering=1) as out:
                while not self.sample_stop.is_set():
                    record = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                              "monotonic_seconds": time.monotonic(), "stage": self.stage, "processes": []}
                    try:
                        memory = Path("/proc/meminfo").read_text()
                        record["memory_kib"] = {key: int(value) for key, value in re.findall(
                            r"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)", memory, re.MULTILINE)}
                        for name, proc in list(self.processes):
                            item = {"name": name, "pid": proc.pid}
                            try:
                                status = Path(f"/proc/{proc.pid}/status").read_text()
                                item.update({key: int(value) for key, value in re.findall(
                                    r"^(VmRSS|VmHWM|Threads):\s+(\d+)", status, re.MULTILINE)})
                            except FileNotFoundError:
                                item["exited"] = True
                            record["processes"].append(item)
                    except OSError as error:
                        record["sample_error"] = str(error)
                    out.write(json.dumps(record) + "\n")
                    self.sample_stop.wait(1)
        self.sampler = threading.Thread(target=sample, name="cluster-resource-sampler", daemon=True)
        self.sampler.start()

    def wait(self, label, predicate, timeout=180):
        deadline = time.monotonic() + timeout
        last_error = ""
        while time.monotonic() < deadline:
            self.healthy()
            try:
                if predicate():
                    print(f"Ready: {label}", flush=True)
                    return
            except (subprocess.SubprocessError, OSError, RuntimeError) as error:
                last_error = str(error)
            time.sleep(1)
        raise TimeoutError(f"Timeout waiting for {label}: {last_error}")

    @staticmethod
    def port_ready(port):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True

    def preflight(self, mode):
        if os.geteuid() != 0 or socket.gethostname() != "3fs-ec-lab" or "microsoft" in os.uname().release.lower():
            raise RuntimeError("Run as root inside the isolated 3fs-ec-lab guest")
        if self.root != Path(self.manifest["guest_root"]).resolve() or not str(self.root).startswith("/home/ec/3fs-lab"):
            raise RuntimeError("Bundle must be located at its recorded task guest_root")
        memory = int(re.search(r"MemTotal:\s+(\d+)", Path("/proc/meminfo").read_text()).group(1))
        if memory < 3500 * 1024:
            raise RuntimeError("Full-cluster preflight requires the planned 4 GiB guest")
        for directory in ["logs", "secrets", "state", "mnt", "data/fdb"]:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir()
        os.chmod(self.root / "secrets", 0o700)
        if subprocess.run(["mountpoint", "-q", str(self.root / "mnt")]).returncode == 0:
            raise RuntimeError("Mountpoint is already mounted; refusing to take ownership")
        if mode == "init" and any((self.root / "data/fdb").iterdir()):
            raise RuntimeError("init requires an empty task FDB directory; data is preserved for diagnosis")
        if mode == "resume" and not (self.root / "state/initialized").exists():
            raise RuntimeError("resume requires a completed initialization marker")
        for path in self.config.glob("*.toml"):
            tomllib.loads(path.read_text())
        names = ["fdbserver", "fdbcli", "admin_cli", "mgmtd_main", "meta_main", "storage_main", "hf3fs_fuse_main", "monitor_collector_main"]
        for name in names:
            binary = self.root / "bin" / name
            if not os.access(binary, os.X_OK):
                raise RuntimeError(f"Missing executable: {binary}")
            result = self.call(["ldd", binary], f"ldd-{name}.log")
            if "not found" in result:
                raise RuntimeError(f"Unresolved runtime library: {binary}")
        for name in ["fdbserver", "fdbcli"]:
            if "7.3.63" not in self.call([self.root / "bin" / name, "--version"], f"{name}-version.log"):
                raise RuntimeError("FoundationDB binaries must be 7.3.63")
        if not (self.root / "lib/libfdb_c.so").is_file():
            raise RuntimeError("Missing bundled FoundationDB client library")
        for port in [12500, 12501, 12502, 12510, 12601, 12602] + list(range(12503, 12503 + self.manifest["storage_count"])) + list(range(12603, 12603 + self.manifest["storage_count"])):
            with socket.socket() as probe:
                # Completed connections may remain in TIME_WAIT after a clean
                # shutdown. Reuse permits those, but still rejects a listener.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    probe.bind(("0.0.0.0", port))
                except OSError as error:
                    raise RuntimeError(f"TCP port {port} is unavailable: {error}") from error
        subprocess.run(["modprobe", "rdma_rxe"], check=True)
        subprocess.run(["modprobe", "fuse"], check=True)
        addresses = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr"], text=True))
        matches = [a["ifname"] for a in addresses for address in a.get("addr_info", []) if address["local"] == self.manifest["guest_ip"]]
        if len(matches) != 1:
            raise RuntimeError("Configured guest IP does not match exactly one interface")
        existing = subprocess.run(["rdma", "link", "show", "rxe0/1"], capture_output=True, text=True)
        if existing.returncode or not existing.stdout.strip():
            subprocess.run(["rdma", "link", "add", "rxe0", "type", "rxe", "netdev", matches[0]], check=True)
        self.call(["ibv_devinfo", "-d", "rxe0"], "rdma-device.log")
        # These limits apply to this guest supervisor and its children only.
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (256 * 1024**2, 256 * 1024**2))
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65536, hard), hard))
        self.call(["free", "-m"], "memory-before.log")
        self.disk_snapshot("before")
        self.start_sampler()

    def launch(self, mode):
        self.stage = "foundationdb"
        fdb = [self.root / "bin/fdbserver", "-p", "127.0.0.1:12500", "-l", "127.0.0.1:12500",
               "-C", self.config / "fdb.cluster", "-d", self.root / "data/fdb", "-L", self.run_dir,
               "--memory", "1536MiB", "--cache-memory", "128MiB", "--logsize", "10MiB", "--maxlogssize", "100MiB"]
        self.start("fdb", fdb)
        self.wait("FoundationDB TCP", lambda: self.port_ready(12500), timeout=30)
        fdbcli = [self.root / "bin/fdbcli", "-C", self.config / "fdb.cluster", "--exec"]
        if mode == "init":
            self.call(fdbcli + ["configure new single ssd logs=1 commit_proxies=1 grv_proxies=1 resolvers=1"], "fdb-configure.log")
        self.wait("FoundationDB available", lambda: "available" in self.call(fdbcli + ["status minimal"], "fdb-status.log", timeout=10).lower()
                  and "unavailable" not in (self.run_dir / "fdb-status.log").read_text().lower())
        if mode == "init":
            self.stage = "cluster-initialization"
            token_output = self.admin(["user-add", "--root", "--admin", "0", "lab-admin"], "create-user.log", secret=True)
            found = re.findall(r"^Token\s+([A-Za-z0-9+/]{24})\(Expired", token_output, flags=re.MULTILINE)
            if len(found) != 1:
                raise RuntimeError("Could not extract exactly one generated admin token; see private create-user.log")
            (self.root / "secrets/token").write_text(found[0] + "\n")
            admin_path = self.config / "admin_cli.toml"
            text = admin_path.read_text()
            text, count = re.subn(r'(?m)^token = ""$', f'token = "{found[0]}"', text)
            if count != 1:
                raise RuntimeError("Expected one empty admin token field")
            admin_path.write_text(text)
            os.chmod(admin_path, 0o600)
            self.admin(["init-cluster", "--mgmtd", str(self.config / "mgmtd_main.toml"),
                        "--meta", str(self.config / "meta_main.toml"), "--storage", str(self.config / "storage_main.toml"),
                        "--fuse", str(self.config / "hf3fs_fuse_main.toml"), "1", "524288", "1"], "init-cluster.log")
        self.stage = "service-startup"
        self.start("monitor", [self.root / "bin/monitor_collector_main", "--cfg", self.config / "monitor_collector_main.toml"])
        for name in ["mgmtd", "meta"]:
            self.start(name, [self.root / "bin" / f"{name}_main", "--app_cfg", self.config / f"{name}_main_app.toml",
                             "--launcher_cfg", self.config / f"{name}_main_launcher.toml", "--cfg", self.config / f"{name}_main.toml"])
            if name == "mgmtd":
                self.wait("mgmtd routing", lambda: "MGMTD" in self.admin(["list-nodes"], "nodes-mgmtd.log"))
        node_ids = []
        for index in range(self.manifest["storage_count"]):
            node = 10001 + index
            node_ids.append(node)
            name = f"storage-{node}"
            (self.root / "data" / name).mkdir(exist_ok=True)
            self.start(name, [self.root / "bin/storage_main", "--app_cfg", self.config / f"{name}-app.toml",
                             "--launcher_cfg", self.config / f"{name}-launcher.toml", "--cfg", self.config / f"{name}.toml"])

        def nodes_ready():
            text = self.admin(["list-nodes"], "nodes-all.log")
            return all(re.search(rf"^{node}\s+{kind}\s+HEARTBEAT_CONNECTED\b", text, re.MULTILINE)
                       for node, kind in [(100, "META")] + [(node, "STORAGE") for node in node_ids])
        self.wait("meta and independent storage processes", nodes_ready)
        self.stage = "targets-and-chains"
        if mode == "init":
            for index, command in enumerate((self.config / "create-targets.txt").read_text().splitlines()):
                self.admin(command.split(), f"target-{index}.log")
            self.admin(["upload-chains", str(self.config / "chains.csv"), "--set-preferred-target-order"], "upload-chains.log")
            self.admin(["upload-chain-table", "1", str(self.config / "chain-table.csv"), "--desc", "local-replication"], "upload-chain-table.log")

        def chains_ready():
            text = self.admin(["list-chains", "--table-id", "1"], "chains.log")
            rows = [line for line in text.splitlines() if re.match(r"^90000[1-4]\s", line)]
            return len(rows) == 4 and all(line.count("(SERVING-UPTODATE)") == len(node_ids) for line in rows)
        self.wait("all replica targets SERVING-UPTODATE", chains_ready, timeout=240)
        self.disk_snapshot("targets-ready")
        self.stage = "fuse-mount"
        self.start("fuse", [self.root / "bin/hf3fs_fuse_main", "--launcher_cfg", self.config / "hf3fs_fuse_main_launcher.toml",
                            "--cfg", self.config / "hf3fs_fuse_main.toml"])

        def fuse_ready():
            mounted = subprocess.run(["mountpoint", "-q", str(self.root / "mnt")]).returncode == 0
            self.mounted = mounted
            return mounted
        self.wait("FUSE mount", fuse_ready)
        if mode == "init":
            (self.root / "state/initialized").write_text("All real services and replica targets became ready.\n")
        self.stage = "file-acceptance"
        self.call([sys.executable, self.root / "scripts/acceptance.py", "write" if mode == "init" else "verify", self.root], "acceptance.log", timeout=180)
        self.call(fdbcli + ["status json"], "fdb-status.json")
        self.call(["free", "-m"], "memory-after.log")
        self.call(["ps", "-o", "pid,ppid,rss,nlwp,args", "-p", ",".join(str(proc.pid) for _, proc in self.processes)], "processes.log")
        self.disk_snapshot("acceptance")
        self.healthy()
        (self.run_dir / "result.json").write_text(json.dumps({"mode": mode, "status": "passed", "storage_count": len(node_ids),
            "scope": "real FDB/RPC/disk targets/FUSE functional check", "performance_validated": False}, indent=2) + "\n")
        print(f"PASS {mode} full-service functional check; logs: {self.run_dir}", flush=True)

    def stop(self):
        self.stage = "shutdown"
        clean = True
        fuse_started = any(name == "fuse" for name, _ in self.processes)
        if fuse_started and subprocess.run(["mountpoint", "-q", str(self.root / "mnt")]).returncode == 0:
            try:
                unmount = subprocess.run(["fusermount3", "-u", str(self.root / "mnt")], capture_output=True, text=True, timeout=30)
                (self.run_dir / "unmount.log").write_text(unmount.stdout + unmount.stderr)
                if unmount.returncode:
                    clean = False
                    print("FUSE unmount failed; no lazy/forced unmount performed", file=sys.stderr)
            except subprocess.TimeoutExpired:
                clean = False
                print("FUSE unmount timed out; continuing to stop owned children", file=sys.stderr)
        # Children remain owned by Popen; no stale PID files or unrelated processes are used.
        for name, proc in reversed(self.processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    clean = False
                    print(f"{name} did not stop in 45 seconds; left running for diagnosis", file=sys.stderr)
            print(f"Stopped {name}: exit={proc.poll()}", flush=True)
        for log in self.logs:
            log.close()
        self.sample_stop.set()
        if self.sampler is not None:
            self.sampler.join(timeout=2)
            if self.sampler.is_alive():
                clean = False
                print("Resource sampler did not stop in 2 seconds", file=sys.stderr)
        if self.run_dir.exists():
            try:
                self.disk_snapshot("after-stop")
            except (subprocess.SubprocessError, OSError, RuntimeError) as error:
                clean = False
                (self.run_dir / "disk-after-stop-error.log").write_text(str(error) + "\n")
            (self.run_dir / "cleanup.json").write_text(json.dumps({"clean": clean,
                "exit_codes": {name: proc.poll() for name, proc in self.processes}}, indent=2) + "\n")
        return clean


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["init", "resume"])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--hold", action="store_true", help="Keep services running after acceptance until SIGINT/SIGTERM")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    lock = (root / "cluster-run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    cluster = Cluster(root)
    hold_stop = threading.Event()
    def interrupted(*_):
        if args.hold and cluster.stage == "holding":
            hold_stop.set()
            return
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        cluster.preflight(args.mode)
        cluster.launch(args.mode)
        if args.hold:
            cluster.stage = "holding"
        while args.hold and not hold_stop.wait(1):
            cluster.healthy()
    except BaseException as error:
        if cluster.run_dir.exists():
            (cluster.run_dir / "result.json").write_text(json.dumps({"mode": args.mode, "status": "failed",
                "stage": cluster.stage, "error_type": type(error).__name__, "error": str(error),
                "performance_validated": False}, indent=2) + "\n")
        raise
    finally:
        if not cluster.stop():
            if cluster.run_dir.exists():
                previous = cluster.run_dir / "result.json"
                acceptance_passed = previous.exists() and json.loads(previous.read_text()).get("status") == "passed"
                previous.write_text(json.dumps({"mode": args.mode, "status": "failed", "stage": "shutdown",
                    "error": "Some owned processes, mount, or diagnostics did not stop cleanly; inspect cleanup.json",
                    "acceptance_passed_before_cleanup": acceptance_passed, "performance_validated": False}, indent=2) + "\n")
            raise RuntimeError("Some owned processes or mount did not stop cleanly; inspect cleanup.json")


if __name__ == "__main__":
    main()
