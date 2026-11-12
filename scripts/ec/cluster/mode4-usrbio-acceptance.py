#!/usr/bin/env python3
"""Prepare/verify a real mode4 mounted file and run the unchanged USRBIO probe.

Services and FUSE are externally supervised. No startup, unmount, retry, file
replacement, deletion or performance sampling is performed by this driver.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tomllib


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def load_json(helper, path):
    value = json.loads(helper.read_file(path, 1 << 20), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    require(type(value) is dict, "Expected a JSON object")
    return value


def module(path):
    # The imported file is the existing read-only supervisor, but only its pure
    # path/file/mount helpers and owned-command method are used, never execute().
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("mode4_usrbio_helpers", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def process_for(preparation, binary):
    allowed = (preparation["first_mount_argv"], preparation["remount_argv"])
    found = []
    for folder in Path("/proc").iterdir():
        if not folder.name.isdecimal():
            continue
        try:
            raw = (folder / "cmdline").read_bytes()
            argv = [item.decode("utf-8") for item in raw.rstrip(b"\0").split(b"\0")]
            if argv not in allowed:
                continue
            lines = (folder / "status").read_text().splitlines()
            uids = [line.split()[1:] for line in lines if line.startswith("Uid:")]
            require(len(uids) == 1 and all(int(x) == os.geteuid() for x in uids[0]),
                    "FUSE process is not the configured ordinary UID")
            require(os.readlink(folder / "exe") == str(binary), "Mounted process executable differs")
            raw_stat = (folder / "stat").read_text()
            fields = raw_stat[raw_stat.rfind(")") + 2:].split()
            require(len(fields) > 19 and fields[0] not in ("Z", "X"), "FUSE process is not alive")
            found.append({"pid": int(folder.name), "start_ticks": fields[19], "argv": argv,
                          "executable": str(binary)})
        except (FileNotFoundError, ProcessLookupError, PermissionError, UnicodeDecodeError):
            continue
    require(len(found) == 1, "Require exactly one live process with the prepared first/remount argv")
    return found[0]


def mounted(helper, mountpoint, cluster):
    values = helper.mounts_at(mountpoint)
    require(len(values) == 1 and values[0]["fs"] == "fuse.hf3fs" and
            values[0]["source"] == "hf3fs." + cluster, "Unexpected actual mount identity")
    return values[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify"))
    for name in ("root", "preparation", "helpers-dir", "file", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--prepared-record", type=Path, help="verify only: original successful prepare result.json")
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() != 0, "Run as the configured ordinary Linux UID, never root")
    require((args.phase == "verify") == (args.prepared_record is not None), "verify requires exactly the original prepare receipt")
    helpers_dir = args.helpers_dir
    require(helpers_dir.is_absolute() and helpers_dir == helpers_dir.resolve(strict=True), "Canonical helper directory required")
    helper_path = helpers_dir / "fuse-read-acceptance.py"
    helper = module(helper_path)
    root = helper.absolute(str(args.root), True)
    prep_path = helper.absolute(str(args.preparation))
    helper.private(prep_path)
    preparation = load_json(helper, prep_path)
    require(type(preparation.get("schema")) is int and preparation["schema"] == 1 and
            preparation.get("configuration_only") is True and preparation.get("allow_other") is False and
            type(preparation.get("uid")) is int and preparation["uid"] == os.geteuid(), "Wrong preparation/UID contract")
    cluster_path = helper.absolute(str(root / "cluster.json"))
    cluster = load_json(helper, cluster_path)
    require(cluster.get("root") == str(root) and cluster.get("file_api") is True, "Not the prepared file-api bundle")
    require(preparation["inputs"]["manifest"]["path"] == str(cluster_path) and
            preparation["inputs"]["manifest"]["sha256"] == helper.digest(cluster_path), "Preparation belongs to another bundle")
    config_paths = {name: helper.absolute(str(prep_path.parent / name))
                    for name in ("launcher.toml", "fuse-first.toml", "fuse-resume.toml")}
    configs = {}
    for name, path in config_paths.items():
        helper.private(path)
        require(helper.digest(path) == preparation["outputs"][name], "Prepared configuration changed")
        configs[name] = tomllib.loads(helper.read_file(path, 1 << 20).decode("utf-8"))
    launcher = configs["launcher.toml"]
    mountpoint = helper.absolute(launcher["mountpoint"], True)
    require(launcher.get("cluster_id") == cluster["cluster_id"] and launcher.get("allow_other") is False,
            "Launcher cluster/allow_other differs")
    first, resume = configs["fuse-first.toml"], configs["fuse-resume.toml"]
    ec = first.get("ec_file", {})
    shard = ec.get("shard_bytes")
    require(type(shard) is int and 1 <= shard <= 1 << 20 and 20 * shard + 17 <= 32 << 20,
            "Exact shard_bytes must produce at most 32 MiB of data")
    require(ec.get("enable") is True and ec.get("create_new") is True and ec.get("create_state") is True,
            "Explicit mode4 create profile required")
    require(first.get("ec_read", {}).get("enable") is False and first.get("enable_writeback_cache") is False and
            first.get("enable_read_cache") is False and first.get("meta", {}).get("network_type") == "TCP",
            "Expected explicit uncached mode4 TCP configuration")
    expected_resume = json.loads(json.dumps(first))
    expected_resume["ec_file"]["create_state"] = False
    require(resume == expected_resume, "Remount must change only create_state, retaining the original state and shard size")
    state = helper.absolute(ec["state_directory"], True)
    helper.private(state)
    require(str(state) == preparation["state_not_created"], "Mount state path differs from preparation")
    client_path = helper.absolute(preparation["inputs"]["client_cfg"]["path"])
    require(helper.digest(client_path) == preparation["inputs"]["client_cfg"]["sha256"], "Authenticated client configuration changed")
    client = tomllib.loads(helper.read_file(client_path, 1 << 20).decode("utf-8"))
    require(type(client.get("user_info", {}).get("uid")) is int and client["user_info"]["uid"] == os.geteuid(),
            "Authenticated client must be this ordinary UID")
    binary = helper.absolute(str(root / "bin/hf3fs_fuse_main"))
    probe = helper.absolute(str(root / "bin/ec_mount_read_probe"))
    require(helper.digest(binary) == preparation["binary_sha256"] and os.access(probe, os.X_OK),
            "Use the exact prepared FUSE binary and already built probe")
    for key, cfg in (("first_mount_argv", "fuse-first.toml"), ("remount_argv", "fuse-resume.toml")):
        require(preparation[key] == [str(binary), "--use_local_cfg", "--launcher_cfg", str(config_paths["launcher.toml"]),
                                     "--cfg", str(config_paths[cfg])], "Unexpected prepared FUSE command")
    mount = mounted(helper, mountpoint, cluster["cluster_id"])
    process = process_for(preparation, binary)
    file = args.file
    require(file.is_absolute() and file.name not in ("", ".", "..") and file.parent == file.parent.resolve(strict=True) and
            mountpoint in file.parents and not file.is_symlink(), "File must be a canonical descendant of this mount")
    require(file.parent.stat().st_dev == mountpoint.stat().st_dev, "File parent is in another filesystem")
    if args.phase == "prepare":
        require(not file.exists(), "Prepare requires a new exclusive file; never overwrite a prior attempt")
    else:
        helper.absolute(str(file))
    output = args.output_dir
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True) and not output.exists() and
            not output.is_symlink() and output != mountpoint and mountpoint not in output.parents,
            "Each phase requires a new local report directory outside the mount")
    helper.private(output.parent)
    output.mkdir(mode=0o700)
    owner = helper.Owner(output)
    # These handlers only set a stop flag, including the Popen/register window.
    signals = {sig: signal.signal(sig, owner.interrupted) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    paths = [Path(__file__).resolve(), helper_path, prep_path, cluster_path, client_path, probe, binary, *config_paths.values()]
    hashes = {str(path): helper.digest(path) for path in paths}
    recipe = "3fs-mode4-usrbio-functional-v1"
    expected = hashlib.shake_256(recipe.encode("ascii")).digest(20 * shard + 17)
    expected_sha = hashlib.sha256(expected).hexdigest()
    record = {"schema": 1, "phase": args.phase, "state": "started", "root": str(root), "driver_argv": sys.argv,
              "preparation": str(prep_path), "file": str(file), "mountpoint": str(mountpoint),
              "uid": os.geteuid(), "shard_bytes": shard, "bytes": len(expected), "sha256": expected_sha,
              "recipe": "SHAKE256(ASCII(3fs-mode4-usrbio-functional-v1),20*shard_bytes+17)",
              "synthetic": True, "mount": mount, "fuse_process": process, "source_sha256": hashes,
              "io": [], "services_started_or_stopped": False, "mount_started_or_stopped": False,
              "performance_validated": False, "remote_cleanup_revalidated_by_driver": False}
    old = None
    failure = None

    def save(name, value):
        helper.write_new(output / name, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    def guard():
        require(not owner.stop, "Interrupted; preserve original file and mount state; no unmount is performed")
        require(mounted(helper, mountpoint, cluster["cluster_id"]) == mount and process_for(preparation, binary) == process,
                "Mount or FUSE process changed during this phase")

    try:
        if args.phase == "prepare":
            expected_path = output / "expected.bin"
            helper.write_new(expected_path, expected)
        else:
            receipt = helper.absolute(str(args.prepared_record))
            old = load_json(helper, receipt)
            require(old.get("state") == "confirmed" and old.get("phase") == "prepare", "Require a successful original preparation receipt")
            for key in ("root", "preparation", "file", "mountpoint", "uid", "shard_bytes", "bytes", "sha256", "recipe"):
                require(type(old.get(key)) is type(record[key]) and old[key] == record[key], f"Original {key} differs")
            for path in (prep_path, probe, binary, *config_paths.values()):
                require(old["source_sha256"].get(str(path)) == hashes[str(path)], "Original preparation/binary contract changed")
            expected_path = helper.absolute(old["expected_file"])
            require(helper.read_file(expected_path, 32 << 20) == expected, "Original expected bytes/recipe changed")
            record["prepared_record"] = {"path": str(receipt), "sha256": helper.digest(receipt)}
        record["expected_file"] = str(expected_path)
        save("inputs.json", record)
        guard()
        if args.phase == "prepare":
            fd = os.open(file, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_dev == mountpoint.stat().st_dev,
                        "Created file is not in the actual mounted filesystem")
                for offset in range(0, len(expected), 1 << 20):
                    guard()
                    chunk = expected[offset:offset + (1 << 20)]
                    count = os.pwrite(fd, chunk, offset)
                    event = {"call": "pwrite", "offset": offset, "requested": len(chunk), "returned": count}
                    record["io"].append(event)
                    save(f"write-{offset:08d}.json", event)
                    require(count == len(chunk), "Short/unconfirmed pwrite; retain partial file, do not retry")
                guard()
                os.fsync(fd)  # Real FUSE fsync; local report fsync is a separate action.
                record["io"].append({"call": "fsync", "returned": 0, "actual_mounted_fd": True})
            finally:
                os.close(fd)
            record["write_fd_closed"] = True
        guard()
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_dev == mountpoint.stat().st_dev and
                    info.st_size == len(expected) and info.st_uid == os.geteuid(), "Actual file identity/length/UID differs")
            if old is not None:
                require(type(old.get("inode")) is int and info.st_ino == old["inode"], "Remount read selected another inode")
            record["inode"] = info.st_ino
            actual = os.pread(fd, len(expected) + 1, 0)
            record["posix_read"] = {"returned": len(actual), "sha256": hashlib.sha256(actual).hexdigest(),
                                    "bytes_equal": actual == expected}
            require(actual == expected, "Actual FUSE readback differs byte-for-byte")
            require(os.pread(fd, 17, len(expected)) == b"", "Actual FUSE EOF differs")
        finally:
            os.close(fd)
        guard()
        # Existing Owner.command owns Popen through finally wait, including log
        # failures. It retains raw stdout/stderr and exact argv/exit receipts.
        os.environ.pop("LD_PRELOAD", None)
        os.environ["LD_LIBRARY_PATH"] = str(root / "lib")
        raw = owner.command("usrbio", [probe, mountpoint, file, expected_path, str(shard)])
        result = json.loads(raw, object_pairs_hook=unique)
        wanted = {"actual_abi": True, "completed_reads": 3, "cross_stripe": True, "eof_clipped": True, "bytes_equal": True}
        require(type(result) is dict and set(result) == set(wanted) and
                all(type(result[k]) is type(v) and result[k] == v for k, v in wanted.items()),
                "Probe did not confirm the actual USRBIO ABI, all CQEs, boundaries and bytes")
        record["usrbio"] = result
        guard()
        require(helper.digest(expected_path) == expected_sha and
                all(helper.digest(Path(path)) == digest for path, digest in hashes.items()),
                "Locked input changed during the phase")
        record["state"] = "confirmed"
    except BaseException as error:
        failure = error
        record["state"] = "unconfirmed"
        record["error"] = f"{type(error).__name__}: {error}"
    finally:
        for sig, previous in signals.items():
            signal.signal(sig, previous)
        record["probe_receipts_sha256"] = {path.name: helper.digest(path) for path in output.glob("001-usrbio.*")}
        save("result.json", record)
    print(output / "result.json")
    if failure is not None:
        raise failure


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"USRBIO acceptance stopped: {error}; preserve original files and mount state", file=sys.stderr)
        sys.exit(1)
