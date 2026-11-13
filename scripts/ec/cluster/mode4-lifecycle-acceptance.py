#!/usr/bin/env python3
"""Own two mode4 mounts around unchanged POSIX/USRBIO acceptance probes.

The native-v2 services must already be healthy. Their lifecycle is never changed.
Only normal fusermount3 -u is allowed; an unknown join is a failed experiment.
"""
import argparse
import errno
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
import uuid


def require(value, message):
    if not value:
        raise ValueError(message)


def same_user(user, client, preparation, uid, euid, gid, egid):
    """Use the prepared authenticated user; never remap FUSE request ownership."""
    require(type(uid) is int and uid > 0 and uid == euid and type(euid) is int
            and type(gid) is int and gid >= 0 and gid == egid and type(egid) is int,
            "mode4 requires the same ordinary real/effective UID and GID")
    require(type(user) is dict and set(user) == {"uid", "gid"}
            and type(user["uid"]) is int and user["uid"] == uid
            and type(user["gid"]) is int and user["gid"] == gid,
            "prepared authenticated user differs from the mount user")
    configured = client.get("user_info", {})
    require(type(configured.get("uid")) is int and configured["uid"] == uid
            and type(configured.get("gid")) is int and configured["gid"] == gid
            and type(preparation.get("uid")) is int and preparation["uid"] == uid,
            "authenticated client/preparation differs from the mount user")


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "preparation", "work"):
        result.add_argument("--" + name, required=True, type=Path)
    result.add_argument("--ready-timeout", type=int, default=120)
    result.add_argument("--command-timeout", type=int, default=1800)
    result.add_argument("--join-timeout", type=int, default=120)
    return result


def configured_timeout(text):
    match = re.fullmatch(r"([1-9][0-9]*)(s|min|h)", text or "")
    require(match is not None, "unsupported configured Mgmtd session timeout")
    return int(match[1]) * {"s": 1, "min": 60, "h": 3600}[match[2]]


def process_identity(pid, executable=None, allow_setuid_helper=False):
    """Observe a live PID; callers signal only their retained Popen handles."""
    folder = Path("/proc") / str(pid)
    fields = (folder / "stat").read_text().rsplit(")", 1)[1].split()
    require(len(fields) > 19 and fields[0] not in ("Z", "X"), "process is not alive")
    lines = (folder / "status").read_text().splitlines()
    uids = [line.split()[1:] for line in lines if line.startswith("Uid:")]
    require(len(uids) == 1 and int(uids[0][0]) == os.geteuid()
            and (all(int(value) == os.geteuid() for value in uids[0]) or
                 allow_setuid_helper and all(int(value) in (0, os.geteuid()) for value in uids[0])),
            "process UID differs")
    actual = os.readlink(folder / "exe")
    require(executable is None or actual == str(executable), "process executable differs")
    return {"pid": pid, "start_ticks": fields[19], "executable": actual}


def service_contract(snapshot, root, cluster, identities):
    require(snapshot.get("schema") == 1 and snapshot.get("stage") == "ready"
            and snapshot.get("root") == str(root) and snapshot.get("profile") == cluster["profile"]
            and snapshot.get("failure") is None and snapshot.get("logical_targets") == 12,
            "native-v2 services are not ready for this root")
    count = cluster["storage_count"]
    expected = {"fdb", "mgmtd", "meta"} | ({"storage"} if count == 1 else
                                          {"storage-" + str(10001 + i) for i in range(12)})
    rows = snapshot.get("processes", [])
    require(snapshot.get("storage_processes") == count and len(rows) == len(expected)
            and {row["name"] for row in rows} == expected
            and all(type(row.get("pid")) is int and row["pid"] > 0
                    and row.get("exit_code") is None for row in rows), "service process set differs")
    require(set(identities) == expected, "service process observations differ")
    require(type(snapshot.get("run")) is str and snapshot["run"].startswith("run-"), "missing native run")
    return {"run": snapshot["run"], "processes": identities}


def posix_receipt(rows, phase, file, expected_bytes, expected_sha):
    require(rows and all(type(row) is dict and row.get("schema") == 1
                        and row.get("sequence") == index for index, row in enumerate(rows)),
            "POSIX receipt sequence differs")
    require(rows[0].get("state") == "prepared" and rows[0].get("command") == phase
            and rows[0].get("file") == str(file), "POSIX receipt belongs to another invocation")
    pending = None
    for row in rows:
        state, operation = row.get("state"), row.get("operation")
        if state == "operation_entered":
            require(pending is None and type(operation) is str, "POSIX receipt contains unconfirmed work")
            pending = operation
        elif state in ("operation_confirmed", "operation_failed"):
            if state == "operation_failed":
                expected_errno = {"open_append": errno.EOPNOTSUPP, "create_append": errno.EOPNOTSUPP,
                                  "lstat": errno.ENOENT}.get(operation)
                require(pending == operation and row.get("expected_failure") is True
                        and row.get("failure_source") == "syscall" and expected_errno is not None
                        and type(row.get("errno")) is int and row["errno"] == expected_errno,
                        "POSIX receipt contains unconfirmed work")
            require(pending is None or pending == operation, "POSIX receipt contains unconfirmed work")
            pending = None
        else:
            require(pending is None and state in ("prepared", "confirmed"),
                    "POSIX receipt contains unconfirmed work")
    require(pending is None, "POSIX receipt contains unconfirmed work")
    require(rows[-1].get("operation") == "probe" and rows[-1].get("state") == "confirmed"
            and rows[-1].get("bytes") == expected_bytes and rows[-1].get("sha256") == expected_sha,
            "POSIX bytes or terminal receipt differ")
    if phase == "verify":
        require(not any(row.get("operation") in ("pwrite", "ftruncate", "fsync") for row in rows),
                "verify unexpectedly performed a data mutation")
    else:
        require(any(row.get("operation") == "fsync" and row.get("state") == "operation_confirmed"
                    and row.get("file_data_barrier") is True for row in rows),
                "prepare has no real file-data barrier")
    return {"bytes": expected_bytes, "sha256": expected_sha, "confirmed_events": len(rows)}


def run_sequence(lifecycle):
    """The small ordered protocol is independently testable without a mount."""
    lifecycle.services("before-first")
    for phase in ("prepare", "verify"):
        try:
            lifecycle.start(phase)
            lifecycle.probe("posix", phase)
            lifecycle.probe("usrbio", phase)
        finally:
            lifecycle.close(phase)
        require(lifecycle.clean_last(), "normal unmount and successful FUSE join are required before continuing")
        lifecycle.services("after-" + phase)
    lifecycle.finish()


def rapid_remount(first_start_ns, second_ready_ns, timeout_seconds):
    elapsed = second_ready_ns - first_start_ns
    require(0 < elapsed < timeout_seconds * 1_000_000_000,
            "first-start to remount-ready crossed the locked configured session timeout")
    return elapsed


class Commands:
    """Bounded complement to the existing Owner's stop flag and sequence."""
    def __init__(self, helper, owner, env):
        self.helper, self.owner, self.env = helper, owner, env
        self.children = []

    def terminate(self, process, row):
        if process.poll() is None:
            try:
                # Short commands can already be zombies, and setuid fusermount
                # can forbid /proc/exe reads. The retained, unreaped Popen child
                # is the signal authority; /proc is optional evidence here.
                row["signal_authority"] = "retained_popen_handle"
                process.terminate()  # This retained Popen only, never a PID from a file.
                row["termination_requested"] = "SIGTERM"
            except ProcessLookupError:
                pass
            except (OSError, ValueError) as error:
                row["termination_error"] = str(error)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            row["join_unknown"] = True
        row["exitcode"] = process.poll()
        row["joined"] = row["exitcode"] is not None

    def run(self, name, argv, timeout, cleanup=False, allow_setuid_helper=False):
        if not cleanup:
            self.owner.checkpoint()
        self.owner.sequence += 1
        base = self.owner.result / f"{self.owner.sequence:03}-{name}"
        row = {"name": name, "sequence": self.owner.sequence, "argv": list(map(str, argv)), "exitcode": None,
               "joined": False, "timeout_seconds": timeout, "timed_out": False,
               "cancelled": False, "started_monotonic_ns": time.monotonic_ns(),
               "allow_setuid_helper": allow_setuid_helper}
        process = None
        with base.with_suffix(".stdout").open("xb") as stdout, base.with_suffix(".stderr").open("xb") as stderr:
            try:
                process = subprocess.Popen(row["argv"], env=self.env, stdout=stdout, stderr=stderr,
                                           start_new_session=True)
                # Register before process observation or durable log writes can fail.
                self.children.append((process, row))
                row["pid"] = process.pid
                try:
                    row["identity"] = process_identity(process.pid, allow_setuid_helper=allow_setuid_helper)
                except (OSError, ValueError) as error:
                    row["identity_observation_unavailable"] = type(error).__name__
                self.helper.write_new(base.with_suffix(".started.json"), json.dumps(row).encode())
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if not cleanup and self.owner.stop:
                        row["cancelled"] = True
                        break
                    if time.monotonic() >= deadline:
                        row["timed_out"] = True
                        break
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                if process is not None:
                    if process.poll() is None:
                        self.terminate(process, row)
                    row["exitcode"] = process.poll()
                    row["joined"] = row["exitcode"] is not None
        row["finished_monotonic_ns"] = time.monotonic_ns()
        self.helper.write_new(base.with_suffix(".finished.json"), json.dumps(row).encode())
        require(row["exitcode"] == 0 and row["joined"] and not row["timed_out"] and not row["cancelled"],
                name + " failed, timed out or has an unknown join")
        return self.helper.read_file(base.with_suffix(".stdout"), 4 << 20)


class Lifecycle:
    def __init__(self, args, helper, usr, prep, config, root, scripts, work, mountpoint, state, binary, unmount, locks):
        self.args, self.h, self.usr = args, helper, usr
        self.prep, self.config, self.root, self.scripts = prep, config, root, scripts
        self.work, self.mountpoint, self.state, self.binary, self.unmount = work, mountpoint, state, binary, unmount
        self.locks = locks
        self.owner = helper.Owner(work)
        env = dict(os.environ)
        env.pop("LD_PRELOAD", None)
        env["LD_LIBRARY_PATH"] = str(root / "lib")
        self.commands = Commands(helper, self.owner, env)
        self.fuse_children = []
        self.active = None
        self.service_identity = None
        self.state_identity = None
        self.first_exit_ns = None
        label = "lifecycle-" + uuid.uuid4().hex
        self.posix_file = mountpoint / "ec-lab" / (label + "-posix.bin")
        self.usr_file = mountpoint / "ec-lab" / (label + "-usrbio.bin")
        self.report = {"schema": 1, "status": "started", "root": str(root), "work": str(work),
                       "preparation": str(args.preparation), "uid": os.geteuid(), "gid": os.getegid(),
                       "authenticated_user": config["authenticated_user"], "mounts": [], "probes": [],
                       "errors": [], "services": [], "services_started_or_stopped": False,
                       "performance_validated": False, "files": {"posix": str(self.posix_file), "usrbio": str(self.usr_file)},
                       "source_sha256": locks, "driver_argv": sys.argv}
        self.timeout = configured_timeout(config["mgmtd"]["server"]["service"]["client_session_timeout"])
        self.report["configured_mgmtd_client_session_timeout_seconds"] = self.timeout

    def save(self, name, value):
        self.h.write_new(self.work / name, (json.dumps(value, indent=2) + "\n").encode())

    def locked(self):
        self.owner.checkpoint()
        require(all(self.h.digest(Path(path)) == digest for path, digest in self.locks.items()),
                "a prepared input or executable changed")

    def services(self, label):
        self.owner.checkpoint()
        raw = self.commands.run("status-" + label,
                                [sys.executable, "-B", self.scripts / "native-v2.py", "status", "--root", self.root], 15)
        snapshot = json.loads(raw, object_pairs_hook=self.usr.unique)
        identities = {}
        for row in snapshot.get("processes", []):
            name = row["name"]
            executable = "fdbserver" if name == "fdb" else "storage_main" if name.startswith("storage") else name + "_main"
            identities[name] = process_identity(row["pid"], self.root / "bin" / executable)
        current = service_contract(snapshot, self.root, self.config["cluster"], identities)
        if self.service_identity is None:
            self.service_identity = current
        require(current == self.service_identity, "native supervisor run or service PID/start time changed")
        self.report["services"].append({"label": label, "snapshot": snapshot, "identity": current})

    def state_check(self):
        self.h.absolute(str(self.state), True)
        self.h.private(self.state)
        info = self.state.stat()
        values = {}
        for name in ("namespace", "index-version"):
            path = self.h.absolute(str(self.state / name))
            self.h.private(path)
            raw = self.h.read_file(path, 4096)
            if name == "index-version":
                require(raw == b"2\n", "state format must remain version 2")
            values[name] = hashlib.sha256(raw).hexdigest()
        current = {"device": info.st_dev, "inode": info.st_ino, "files_sha256": values}
        if self.state_identity is None:
            self.state_identity = current
            self.report["state_identity"] = current
        require(current == self.state_identity, "original namespace/index or state directory changed")

    def mounted_identity(self):
        require(self.active is not None and self.active["process"].poll() is None, "owned FUSE is not alive")
        current = self.usr.process_for(self.prep, self.binary)
        require(current["pid"] == self.active["process"].pid
                and current["argv"] == self.active["row"]["argv"], "mounted FUSE is not this owned invocation")
        mount = self.usr.mounted(self.h, self.mountpoint, self.config["cluster"]["cluster_id"])
        return current, mount

    def guard(self):
        self.owner.checkpoint()
        current, mount = self.mounted_identity()
        require(current == self.active["row"]["identity"] and mount == self.active["row"]["mount"],
                "owned mount or FUSE process changed")
        self.state_check()

    def start(self, phase):
        self.locked()
        self.services("before-" + phase)
        require(not self.h.mounts_at(self.mountpoint) and not any(self.mountpoint.iterdir()),
                "mountpoint must remain empty and unmounted")
        if phase == "prepare":
            require(not os.path.lexists(self.state), "first mount must create a new state; preserve old attempts")
        else:
            self.state_check()
            rapid_remount(self.report["mounts"][0]["started_monotonic_ns"], time.monotonic_ns(), self.timeout)
        argv = self.prep["first_mount_argv" if phase == "prepare" else "remount_argv"]
        row = {"phase": phase, "argv": argv, "exitcode": None, "joined": False, "ready": False,
               "normal_unmount": False, "started_monotonic_ns": time.monotonic_ns()}
        self.report["mounts"].append(row)
        with (self.work / (phase + "-fuse.stdout")).open("xb") as out, \
             (self.work / (phase + "-fuse.stderr")).open("xb") as err:
            process = subprocess.Popen(argv, env=self.commands.env, stdout=out, stderr=err, start_new_session=True)
            self.active = {"process": process, "row": row}
            self.fuse_children.append((process, row))
            row["pid"] = process.pid
            row["process_observation"] = process_identity(process.pid, self.binary)
            self.save(phase + "-fuse-started.json", row)
        deadline = time.monotonic() + self.args.ready_timeout
        while time.monotonic() < deadline:
            self.owner.checkpoint()
            require(process.poll() is None, "owned FUSE exited before mount readiness")
            if self.h.mounts_at(self.mountpoint):
                identity, mounted = self.mounted_identity()
                row.update(identity=identity, mount=mounted, ready=True, ready_monotonic_ns=time.monotonic_ns())
                break
            time.sleep(0.05)
        require(row["ready"], "mount readiness deadline exceeded; probes are forbidden")
        if phase == "verify":
            row["remount_gap_ns"] = row["ready_monotonic_ns"] - self.first_exit_ns
            row["first_ready_to_remount_ready_ns"] = row["ready_monotonic_ns"] - self.report["mounts"][0]["ready_monotonic_ns"]
            # The first session cannot have been created before this Popen.
            # Include startup age instead of assuming an observed heartbeat.
            row["first_start_to_remount_ready_ns"] = rapid_remount(
                self.report["mounts"][0]["started_monotonic_ns"], row["ready_monotonic_ns"], self.timeout)
        self.state_check()
        self.services("ready-" + phase)
        directory = self.h.absolute(str(self.mountpoint / "ec-lab"), True)
        require(directory.stat().st_dev == self.mountpoint.stat().st_dev, "ec-lab must belong to this mount")
        self.save(phase + "-mount-ready.json", row)

    def probe(self, kind, phase):
        self.guard()
        self.services("before-" + kind + "-" + phase)
        if kind == "posix":
            path = self.work / ("posix-" + phase + ".jsonl")
            self.commands.run("posix-" + phase, [sys.executable, "-B", self.scripts / "mode4-mount-acceptance.py",
                              phase, "--file", self.posix_file, "--report", path], self.args.command_timeout)
            rows = [json.loads(line, object_pairs_hook=self.usr.unique)
                    for line in self.h.read_file(path, 1 << 20).splitlines()]
            probe = module(self.scripts / "mode4-mount-acceptance.py", "mode4_posix_recipe")
            final = probe.expected()[1]
            details = posix_receipt(rows, phase, self.posix_file, len(final), hashlib.sha256(final).hexdigest())
            record = {"kind": kind, "phase": phase, "state": "confirmed", "receipt": str(path),
                      "receipt_sha256": self.h.digest(path), **details}
        else:
            output = self.work / ("usrbio-" + phase)
            argv = [sys.executable, "-B", self.scripts / "mode4-usrbio-acceptance.py", phase,
                    "--root", self.root, "--preparation", self.args.preparation,
                    "--helpers-dir", self.scripts, "--file", self.usr_file, "--output-dir", output]
            if phase == "verify":
                original = self.work / "usrbio-prepare/result.json"
                previous = next(row for row in self.report["probes"] if row["kind"] == "usrbio" and row["phase"] == "prepare")
                require(self.h.digest(original) == previous["receipt_sha256"], "original USRBIO receipt changed")
                argv += ["--prepared-record", original]
            self.commands.run("usrbio-" + phase, argv, self.args.command_timeout)
            path = output / "result.json"
            receipt = self.usr.load_json(self.h, path)
            wanted = {"actual_abi": True, "completed_reads": 3, "cross_stripe": True,
                      "eof_clipped": True, "bytes_equal": True}
            require(receipt.get("state") == "confirmed" and receipt.get("phase") == phase
                    and receipt.get("file") == str(self.usr_file)
                    and receipt.get("root") == str(self.root) and receipt.get("preparation") == str(self.args.preparation)
                    and receipt.get("usrbio") == wanted and receipt.get("posix_read", {}).get("bytes_equal") is True,
                    "USRBIO receipt did not confirm this file and the actual ABI")
            if phase == "verify":
                original = self.work / "usrbio-prepare/result.json"
                require(receipt.get("prepared_record") == {"path": str(original), "sha256": self.h.digest(original)},
                        "USRBIO verify did not consume the original receipt")
            record = {"kind": kind, "phase": phase, "state": "confirmed", "receipt": str(path),
                      "receipt_sha256": self.h.digest(path), "bytes": receipt["bytes"], "sha256": receipt["sha256"],
                      "inode": receipt["inode"], "actual_abi_reads": 3}
        self.guard()
        self.report["probes"].append(record)

    def close(self, phase):
        if self.active is None:
            return
        process, row = self.active["process"], self.active["row"]
        # Cleanup ignores cancellation, but never borrows another process/mount.
        try:
            mounted = self.h.mounts_at(self.mountpoint)
            if mounted:
                identity, actual = self.mounted_identity()
                if row.get("mount") is not None:
                    require(actual == row["mount"] and identity == row["identity"], "cannot unmount a changed mount")
                else:
                    row.update(identity=identity, mount=actual, late_mount_observed=True)
                self.commands.run("unmount-" + phase, [self.unmount, "-u", self.mountpoint], 30,
                                  cleanup=True, allow_setuid_helper=True)
                require(not self.h.mounts_at(self.mountpoint), "normal unmount did not remove the owned mount")
                row["normal_unmount"] = True
            else:
                row["unmounted_without_owned_command"] = True
            try:
                process.wait(timeout=self.args.join_timeout if row["normal_unmount"] else 1)
            except subprocess.TimeoutExpired:
                row["normal_join_timed_out"] = True
        except BaseException as error:
            row["cleanup_error"] = type(error).__name__ + ": " + str(error)
        finally:
            if process.poll() is None:
                try:
                    remaining = self.h.mounts_at(self.mountpoint)
                except (OSError, ValueError) as error:
                    remaining = None
                    row["mount_observation_error"] = type(error).__name__ + ": " + str(error)
                if remaining == []:
                    temporary = {}
                    self.commands.terminate(process, temporary)
                    row["termination"] = temporary
                else:
                    # Killing a still-mounted FUSE could abort its connection
                    # and bypass the required ordinary unmount boundary.
                    row["termination_withheld"] = "mount remains or mount state is unknown"
                    row["join_unknown"] = True
            row["exitcode"] = process.poll()
            row["joined"] = row["exitcode"] is not None
            row["finished_monotonic_ns"] = time.monotonic_ns()
            if not row["joined"]:
                row["join_unknown"] = True
            self.active = None
            if phase == "prepare" and self.clean_last():
                self.first_exit_ns = row["finished_monotonic_ns"]
            self.save(phase + "-fuse-finished.json", row)

    def clean_last(self):
        if not self.report["mounts"]:
            return False
        row = self.report["mounts"][-1]
        return (row["ready"] and row["normal_unmount"] and row["joined"] and row["exitcode"] == 0
                and not row.get("normal_join_timed_out") and not row.get("termination")
                and not row.get("cleanup_error") and not self.h.mounts_at(self.mountpoint))

    def finish(self):
        self.locked()
        self.state_check()
        require(len(self.report["probes"]) == 4, "four real probe phases are required")
        require(all(self.h.digest(Path(row["receipt"])) == row["receipt_sha256"] for row in self.report["probes"]),
                "a completed probe receipt changed")
        for kind in ("posix", "usrbio"):
            before, after = [row for row in self.report["probes"] if row["kind"] == kind]
            require(before["bytes"] == after["bytes"] and before["sha256"] == after["sha256"],
                    "file data changed across remount")
            if kind == "usrbio":
                require(before["inode"] == after["inode"], "USRBIO inode changed across remount")
        self.report["status"] = "passed"

    def cleanup_summary(self):
        unknown = []
        for process, row in self.commands.children:
            row["exitcode"] = process.poll()
            row["joined"] = row["exitcode"] is not None
            if not row["joined"]:
                unknown.append({"kind": "command", "name": row["name"], "pid": process.pid,
                                "descendant_joins": "unknown; retained child owns its nested probes"})
        mounts = self.report["mounts"]
        for process, row in self.fuse_children:
            row["exitcode"] = process.poll()
            row["joined"] = row["exitcode"] is not None
        unknown.extend({"kind": "fuse", "pid": row["pid"]} for row in mounts if not row["joined"] and "pid" in row)
        try:
            unmounted = not self.h.mounts_at(self.mountpoint)
        except (OSError, ValueError):
            unmounted = False
        return {"all_fuse_joined": all(row["joined"] for row in mounts),
                "all_commands_joined": all(row["joined"] for _, row in self.commands.children),
                "unmounted": unmounted,
                "normal_unmounts": sum(row["normal_unmount"] for row in mounts),
                "fuse_exitcodes": [row["exitcode"] for row in mounts], "unknown_owned_processes": unknown}


def preflight(args):
    import tomllib
    require(sys.platform == "linux" and os.getuid() == os.geteuid() and os.geteuid() > 0
            and os.getgid() == os.getegid(), "use one ordinary real/effective UID and GID")
    require(1 <= args.ready_timeout <= 600 and 1 <= args.command_timeout <= 3600
            and 1 <= args.join_timeout <= 600, "timeouts out of range")
    root = args.root
    scripts = root / "scripts"
    helper = module(scripts / "fuse-read-acceptance.py", "mode4_lifecycle_helpers")
    usr = module(scripts / "mode4-usrbio-acceptance.py", "mode4_lifecycle_usr")
    root = helper.absolute(str(root), True)
    helper.private(root)
    scripts = helper.absolute(str(scripts), True)
    prep_path = helper.absolute(str(args.preparation))
    helper.private(prep_path)
    prep = usr.load_json(helper, prep_path)
    require(type(prep.get("schema")) is int and prep["schema"] == 1 and prep.get("configuration_only") is True
            and type(prep.get("uid")) is int and prep["uid"] == os.geteuid()
            and prep.get("allow_other") is False, "wrong preparation contract")
    inputs = {}
    for name, record in prep["inputs"].items():
        path = helper.absolute(record["path"])
        require(helper.digest(path) == record["sha256"], "preparation input changed")
        inputs[name] = path
    require(inputs["manifest"] == root / "cluster.json", "preparation belongs to another root")
    cluster = usr.load_json(helper, inputs["manifest"])
    configs = {}
    for name in ("launcher.toml", "fuse-first.toml", "fuse-resume.toml"):
        path = helper.absolute(str(prep_path.parent / name))
        helper.private(path)
        require(helper.digest(path) == prep["outputs"][name], "prepared config changed")
        configs[name] = tomllib.loads(helper.read_file(path, 1 << 20).decode())
    launcher, first = configs["launcher.toml"], configs["fuse-first.toml"]
    mountpoint = helper.absolute(launcher["mountpoint"], True)
    helper.private(mountpoint)
    require(not helper.mounts_at(mountpoint) and not any(mountpoint.iterdir()), "fresh unmounted mountpoint required")
    state = Path(prep["state_not_created"])
    require(state == prep_path.parent / "mount-state" and first["ec_file"]["state_directory"] == str(state)
            and not os.path.lexists(state), "original new mount state must not yet exist")
    # Reuse the actual preparation transformation instead of a second relaxed
    # configuration validator. These imports only define the existing renderer.
    old_path = list(sys.path)
    try:
        sys.path.insert(0, str(scripts))
        preparation = module(scripts / "prepare-fuse-file.py", "mode4_lifecycle_preparation")
        from native_v2_config import authenticated_user, validate_initialized_user
        user = authenticated_user(cluster)
        client = tomllib.loads(helper.read_file(inputs["client_cfg"], 1 << 20).decode())
        same_user(user, client, prep, os.getuid(), os.geteuid(), os.getgid(), os.getegid())
        initialized_path = helper.absolute(str(root / "state/initialized.json"))
        helper.private(initialized_path)
        validate_initialized_user(cluster, usr.load_json(helper, initialized_path))
        ec = first["ec_file"]
        rendered = preparation.render(
            cluster, tomllib.loads(helper.read_file(inputs["fuse_default"], 1 << 20).decode()),
            tomllib.loads(helper.read_file(inputs["launcher_default"], 1 << 20).decode()),
            client,
            effective_uid=os.geteuid(), root=root, output=prep_path.parent, mountpoint=mountpoint,
            token=Path(launcher["token_file"]), create_new=True, shard_bytes=ec["shard_bytes"],
            maximum_operation_seconds=ec["maximum_operation_seconds"], retained_sessions=ec["retained_sessions"],
            maximum_input_bytes=ec["maximum_input_bytes"])
        require(rendered == configs, "configs differ from the original mode4 preparation contract")
    finally:
        sys.path[:] = old_path
    binary = helper.absolute(str(root / "bin/hf3fs_fuse_main"))
    require(os.access(binary, os.X_OK) and helper.digest(binary) == prep["binary_sha256"],
            "FUSE binary differs from preparation")
    for key, cfg in (("first_mount_argv", "fuse-first.toml"), ("remount_argv", "fuse-resume.toml")):
        require(prep[key] == [str(binary), "--use_local_cfg", "--launcher_cfg", str(prep_path.parent / "launcher.toml"),
                              "--cfg", str(prep_path.parent / cfg)], "prepared mount argv differs")
    require(prep["unmount_argv"] == ["fusermount3", "-u", str(mountpoint)], "normal fusermount3 -u only")
    tool = shutil.which("fusermount3")
    require(tool is not None, "fusermount3 is required")
    unmount = Path(tool).resolve(strict=True)
    require(unmount.is_file() and os.access(unmount, os.X_OK), "fusermount3 is not executable")
    work = args.work
    require(work.is_absolute() and work.name not in ("", ".", "..") and
            work.parent == work.parent.resolve(strict=True) and not os.path.lexists(work)
            and work != mountpoint and mountpoint not in work.parents and work not in mountpoint.parents,
            "new local WORK outside the mount required")
    helper.private(work.parent)
    config_path = helper.absolute(str(root / "config/mgmtd_main.toml"))
    config = {"cluster": cluster, "authenticated_user": user,
              "mgmtd": tomllib.loads(helper.read_file(config_path, 1 << 20).decode())}
    require(cluster.get("storage_count") in (1, 12), "unsupported native process count")
    configured_timeout(config["mgmtd"]["server"]["service"]["client_session_timeout"])
    paths = [Path(__file__).resolve(), prep_path, config_path, initialized_path, binary, unmount,
             helper.absolute(str(root / "bin/ec_mount_read_probe")), *inputs.values(),
             *(prep_path.parent / name for name in configs),
             *(scripts / name for name in ("fuse-read-acceptance.py", "mode4-mount-acceptance.py",
               "mode4-usrbio-acceptance.py", "prepare-fuse-file.py", "prepare-fuse-read.py",
               "native-v2.py", "native_v2_config.py", "generate.py", "run-cluster.py"))]
    locks = {str(helper.absolute(str(path))): helper.digest(path) for path in paths}
    work.mkdir(mode=0o700)
    return Lifecycle(args, helper, usr, prep, config, root, scripts, work, mountpoint, state, binary, unmount, locks)


def main(argv=None):
    args = parser().parse_args(argv)
    sys.dont_write_bytecode = True
    old_mask = os.umask(0o077)
    lifecycle = None
    signals = {}
    try:
        lifecycle = preflight(args)
        signals = {sig: signal.signal(sig, lifecycle.owner.interrupted)
                   for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        lifecycle.save("inputs.json", lifecycle.report)
        run_sequence(lifecycle)
    except BaseException as error:
        if lifecycle is None:
            print("mode4 lifecycle preflight failed: " + str(error), file=sys.stderr)
            return 2
        lifecycle.report["status"] = "failed"
        lifecycle.report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        if lifecycle is not None:
            # A failed start can still have created an owned process.
            if lifecycle.active is not None:
                lifecycle.close(lifecycle.active["row"]["phase"])
            cleanup = lifecycle.cleanup_summary()
            if (cleanup["unknown_owned_processes"] or not cleanup["unmounted"]
                    or not cleanup["all_fuse_joined"] or not cleanup["all_commands_joined"] or lifecycle.owner.stop):
                lifecycle.report["status"] = "failed"
            lifecycle.report["cleanup"] = cleanup
            lifecycle.report["commands"] = [row for _, row in lifecycle.commands.children]
            lifecycle.report["exitcode"] = 0 if lifecycle.report["status"] == "passed" else 1
            lifecycle.save("result.json", lifecycle.report)
            print(json.dumps({"status": lifecycle.report["status"], "exitcode": lifecycle.report["exitcode"],
                              "probes_confirmed": len(lifecycle.report["probes"]), "cleanup": cleanup,
                              "result": str(lifecycle.work / "result.json")}, sort_keys=True))
        for sig, previous in signals.items():
            signal.signal(sig, previous)
        os.umask(old_mask)
    return lifecycle.report["exitcode"]


if __name__ == "__main__":
    raise SystemExit(main())
