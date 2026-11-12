#!/usr/bin/env python3
"""Own one FUSE process; verify a previously published EC file without deleting it.

Configuration and expected bytes are explicit. This is a functional acceptance
driver, not a storage throughput benchmark. SIGINT/SIGTERM requests orderly
unmount after the current owned operation. No subprocess is force-killed.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import tomllib


def require(value, message):
    if not value:
        raise ValueError(message)


def absolute(text, directory=False):
    path = Path(text)
    require(path.is_absolute() and str(path) == text and path == path.resolve(strict=True), "explicit canonical absolute path required")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "wrong path type")
    return path


def private(path):
    info = path.stat()
    require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "path must be private and owned by this UID")


def read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "invalid or excessive input")
        content = stream.read(limit + 1)
        require(len(content) == info.st_size, "file changed during read")
        return content


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            value.update(block)
    return value.hexdigest()


def write_new(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def mounts_at(path):
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)
    found = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields, tail = before.split(), after.split()
        if unescape(fields[4]) == str(path):
            found.append({"id": fields[0], "fs": tail[0], "source": unescape(tail[1]), "raw": line})
    return found


class Owner:
    def __init__(self, result):
        self.result, self.stop, self.sequence = result, False, 0

    def interrupted(self, _signum, _frame):
        self.stop = True

    def checkpoint(self):
        require(not self.stop, "interrupted; starting orderly unmount")

    def command(self, name, argv):
        self.sequence += 1
        base = self.result / f"{self.sequence:03}-{name}"
        started = time.monotonic_ns()
        with base.with_suffix(".stdout").open("xb") as output, base.with_suffix(".stderr").open("xb") as error:
            os.chmod(output.name, 0o600); os.chmod(error.name, 0o600)
            process = subprocess.Popen([str(x) for x in argv], stdout=output, stderr=error, start_new_session=True)
            try:
                write_new(base.with_suffix(".started.json"), json.dumps({"argv": [str(x) for x in argv], "pid": process.pid}).encode())
                code = process.wait()
            finally:
                # Includes disk-full failures immediately after Popen. No
                # discarded owned child and no timeout-induced process kill.
                process.wait()
        write_new(base.with_suffix(".finished.json"), json.dumps({"returncode": code,
                  "wall_ns": time.monotonic_ns() - started}).encode())
        require(code == 0, f"{name} failed; see preserved stdout/stderr")
        return read_file(base.with_suffix(".stdout"), 4 << 20)


def denied(action, accepted):
    try:
        value = action()
    except OSError as error:
        require(error.errno in accepted, f"unexpected refusal errno {error.errno}")
        return error.errno
    if isinstance(value, int) and value >= 0:
        os.close(value)
    raise ValueError("unsupported EC mutation unexpectedly succeeded")


def check_reads(mounted_file, expected, stripe, inode):
    fd = os.open(mounted_file, os.O_RDONLY | os.O_CLOEXEC)
    try:
        actual = os.fstat(fd)
        require(actual.st_ino == inode and actual.st_size == len(expected), "actual inode or EOF differs")
        cases = [(0, min(len(expected), 65536)), (stripe - 1, 2), (2 * stripe - 7, 19), (len(expected) - 1, 2), (len(expected), 17)]
        output = []
        for offset, length in cases:
            begin = time.monotonic_ns()
            data = os.pread(fd, length, offset)
            require(data == expected[offset:offset + length], "actual pread bytes or EOF clipping differs")
            output.append({"offset": offset, "requested": length, "returned": len(data),
                           "sha256": hashlib.sha256(data).hexdigest(), "wall_ns": time.monotonic_ns() - begin})
        rejected = {"fsync_errno": denied(lambda: os.fsync(fd), {errno.EOPNOTSUPP, errno.ENOSYS})}
    finally:
        os.close(fd)
    rejected["write_open_errno"] = denied(lambda: os.open(mounted_file, os.O_WRONLY), {errno.EOPNOTSUPP, errno.ENOSYS})
    rejected["truncate_errno"] = denied(lambda: os.truncate(mounted_file, 0), {errno.EOPNOTSUPP, errno.ENOSYS})
    return {"reads": output, "unsupported_operations": rejected, "timing_scope": "whole system call including control and cleanup"}


def execute(args):
    require(sys.platform == "linux", "actual FUSE acceptance requires Linux")
    paths = {name: absolute(getattr(args, name)) for name in
             ("fuse_binary", "launcher_cfg", "fuse_cfg", "spool_cli", "spool_cfg", "usrbio_probe", "expected", "fusermount")}
    mountpoint = absolute(args.mountpoint, True); private(mountpoint)
    require(not mounts_at(mountpoint) and not any(mountpoint.iterdir()), "mountpoint must be empty and currently unmounted")
    relative = Path(args.file)
    require(not relative.is_absolute() and relative.parts and all(p not in (".", "..") for p in relative.parts), "file must be a strict relative path")
    require(type(args.shard_bytes) is int and 1 <= args.shard_bytes <= 1 << 20 and args.inode > 0, "invalid fixed layout/identity")
    for key in ("launcher_cfg", "fuse_cfg", "spool_cfg"):
        private(paths[key])
    launcher, config, maintenance = [tomllib.loads(read_file(paths[k], 1 << 20).decode())
                                    for k in ("launcher_cfg", "fuse_cfg", "spool_cfg")]
    ec = config.get("ec_read", {})
    require(ec.get("enable") is True and ec.get("create_state") is False, "explicit enabled EC mount must reopen original spool")
    require(config.get("enable_writeback_cache") is False and config.get("meta", {}).get("network_type") == "TCP", "explicit TCP/direct-read configuration required")
    require(launcher.get("mountpoint") == str(mountpoint) and launcher.get("allow_other") is False, "launcher mountpoint/allow_other mismatch")
    require(launcher.get("cluster_id") == maintenance.get("cluster_id") and ec.get("state_directory") == maintenance.get("state_directory"), "maintenance must address same cluster/spool")
    require(maintenance.get("user_info", {}).get("uid") == os.geteuid(), "run as configured effective owner UID")
    spool = absolute(ec["state_directory"], True); private(spool)
    expected = read_file(paths["expected"], 32 << 20)
    require(len(expected) >= 20 * args.shard_bytes, "expected input must span at least two complete stripes")
    result = Path(args.result_dir)
    require(result.is_absolute() and result.parent == result.parent.resolve(strict=True) and not result.exists(), "new explicit result directory required")
    result.mkdir(mode=0o700)
    owner = Owner(result)
    old = {signum: signal.signal(signum, owner.interrupted) for signum in (signal.SIGINT, signal.SIGTERM)}
    process, acquired_mount, failure = None, None, None
    report = {"schema": 1, "status": "started", "inputs": {k: {"path": str(p), "sha256": digest(p)} for k, p in paths.items()},
              "mountpoint": str(mountpoint), "relative_file": str(relative), "inode": args.inode, "shard_bytes": args.shard_bytes,
              "auto_retire": ec.get("retire_completed", False), "kernel": os.uname().release,
              "uid": os.geteuid(), "no_storage_performance_claim": True}
    try:
        write_new(result / "inputs.json", json.dumps(report, indent=2).encode())
        before = owner.command("local-before", [paths["spool_cli"], "--cfg=" + str(paths["spool_cfg"]), "inspect"])
        write_new(result / "spool-before.json", before)
        owner.checkpoint()
        with (result / "fuse.stdout").open("xb") as output, (result / "fuse.stderr").open("xb") as error:
            os.chmod(output.name, 0o600); os.chmod(error.name, 0o600)
            process = subprocess.Popen([str(paths["fuse_binary"]), "--launcher_cfg", str(paths["launcher_cfg"]),
                                        "--cfg", str(paths["fuse_cfg"])], stdout=output, stderr=error, start_new_session=True)
            try:
                write_new(result / "fuse.started.json", json.dumps({"pid": process.pid}).encode())
                deadline = time.monotonic() + args.ready_timeout
                while time.monotonic() < deadline:
                    owner.checkpoint()
                    require(process.poll() is None, "FUSE exited before mount readiness")
                    mounted = mounts_at(mountpoint)
                    if mounted:
                        require(len(mounted) == 1 and mounted[0]["fs"] == "fuse.hf3fs" and
                                mounted[0]["source"] == "hf3fs." + launcher["cluster_id"], "unexpected mount identity")
                        acquired_mount = mounted[0]
                        break
                    time.sleep(0.05)
                require(acquired_mount is not None, "FUSE mount readiness deadline exceeded")
                write_new(result / "mount.json", json.dumps(acquired_mount).encode())
                report["posix_read"] = check_reads(mountpoint / relative, expected, 10 * args.shard_bytes, args.inode)
                owner.checkpoint()
                report["usrbio"] = json.loads(owner.command("usrbio", [paths["usrbio_probe"], mountpoint,
                    mountpoint / relative, paths["expected"], str(args.shard_bytes)]).decode())
                require(report["usrbio"] == {"actual_abi": True, "completed_reads": 3, "cross_stripe": True,
                                            "eof_clipped": True, "bytes_equal": True}, "USRBIO did not report complete actual ABI proof")
                owner.checkpoint()
            finally:
                current = mounts_at(mountpoint)
                if acquired_mount and len(current) == 1 and current[0]["id"] == acquired_mount["id"]:
                    try:
                        owner.command("unmount", [paths["fusermount"], "-u", mountpoint])
                    finally:
                        # Failure cannot drop ownership. In a failed/hung
                        # startup/unmount, preserve logs and wait for operator.
                        if process.poll() is None:
                            print("Waiting for owned FUSE exit; no forced kill. Preserve this result directory.", file=sys.stderr, flush=True)
                        process.wait()
                else:
                    if process.poll() is None:
                        print("No verified owned mount to unmount; waiting for owned FUSE exit. No forced kill.", file=sys.stderr, flush=True)
                    process.wait()
        require(process.returncode == 0 and not mounts_at(mountpoint), "FUSE did not exit cleanly and unmount")
        after = owner.command("local-after", [paths["spool_cli"], "--cfg=" + str(paths["spool_cfg"]), "inspect"])
        write_new(result / "spool-after.json", after)
        inventory = json.loads(after)
        require(inventory.get("local_evidence_only") is True and inventory.get("remote_revalidated") is False,
                "maintenance output must distinguish local observation")
        report["local_inventory"] = inventory
        report["remote_t2_revalidated_by_driver"] = False
        report["status"] = "passed"
    except BaseException as error:
        report["status"], failure = "failed", error
        report["error"] = str(error)
    finally:
        if process is not None:
            process.wait()
            report["fuse_returncode"] = process.returncode
        for signum, handler in old.items():
            signal.signal(signum, handler)
        write_new(result / "result.json", json.dumps(report, indent=2).encode())
    if failure is not None:
        raise failure
    print(result / "result.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fuse-binary", "launcher-cfg", "fuse-cfg", "spool-cli", "spool-cfg", "usrbio-probe", "expected",
                 "fusermount", "mountpoint", "file", "result-dir"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--shard-bytes", type=int, required=True)
    parser.add_argument("--inode", type=int, required=True)
    parser.add_argument("--ready-timeout", type=int, default=60)
    args = parser.parse_args()
    require(1 <= args.ready_timeout <= 600, "readiness timeout must be 1..600 seconds")
    execute(args)


if __name__ == "__main__":
    main()
