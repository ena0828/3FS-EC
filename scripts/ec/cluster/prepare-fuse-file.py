#!/usr/bin/env python3
"""Prepare explicit mode4 first-mount/remount configs; never start any process.

The source defaults must be dumped by the packaged matching FUSE binary. Real
UID/token/address settings come from the bundle file client. No key, token,
database, mount state or user is created; mode2/3 roots are never upgraded.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tomllib

from generate import to_toml
from native_v2_config import client_transport_problems, file_api_enabled, transport_settings


def read_helpers():
    # Reuse the established private path/O_EXCL/fsync implementation rather
    # than adding a second mount supervisor or an independent token loader.
    spec = importlib.util.spec_from_file_location("ec_fuse_read_prepare", Path(__file__).with_name("prepare-fuse-read.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, f"invalid {label}")
    return value


def transport_evidence(manifest):
    """Record configuration intent, never device discovery or a verbs result."""
    transport = transport_settings(manifest)
    return {} if transport is None else {
        "data_transport_requested": transport, "transport_validation": "configuration_only"}


def render(manifest, fuse_default, launcher_default, client, *, effective_uid,
           root, output, mountpoint, token, create_new=False, shard_bytes=1 << 20,
           maximum_operation_seconds=300, retained_sessions=128, maximum_input_bytes=256 << 20):
    """Pure transformation used by configuration tests; no filesystem/network IO."""
    require(type(manifest.get("schema")) is int and manifest["schema"] == 1 and
            manifest.get("root") == str(root) and file_api_enabled(manifest),
            "bundle must already be explicitly prepared as gc/gc-12 --file-api")
    require(type(create_new) is bool, "create_new must be explicit boolean")
    uid = client.get("user_info", {}).get("uid")
    integer(uid, 1, (1 << 32) - 1, "ordinary authenticated UID")
    require(type(effective_uid) is int and uid == effective_uid,
            "prepare and mount must run as the configured ordinary effective UID")
    integer(client["user_info"].get("gid"), 0, (1 << 32) - 1, "authenticated GID")
    require(type(client.get("cluster_id")) is str and client["cluster_id"] == manifest.get("cluster_id"),
            "client cluster differs from prepared bundle")
    transport = transport_settings(manifest)
    require(not client_transport_problems(manifest, client, file_api=True),
            "file-client transport differs from the prepared profile")
    require((transport is not None or client.get("client", {}).get("force_use_tcp") is True) and
            client.get("mgmtd_client", {}).get("network_type") == "TCP" and
            client.get("meta_client", {}).get("network_type") == "TCP",
            "explicit real TCP control-client settings required")
    addresses = client["mgmtd_client"].get("mgmtd_server_addresses")
    require(type(addresses) is list and addresses and all(type(a) is str and a.startswith("TCP://") for a in addresses),
            "real TCP management addresses required")
    require(type(client.get("storage_client")) is dict and not client["user_info"].get("token"),
            "file client must use token_file, never an inline bearer")
    require(all(type(fuse_default.get(k)) is dict for k in
                ("common", "ec_read", "ec_file", "io_worker_coros", "io_jobq_sizes", "io_bufs")),
            "matching mode4 ENABLE_FUSE_APPLICATION defaults required")
    require(fuse_default["ec_read"].get("enable") is False and fuse_default["ec_file"].get("enable") is False,
            "use untouched defaults; do not mix an active ec_read/mode4 profile")
    require(transport is not None or fuse_default.get("ec_storage_transport", "tcp") == "tcp",
            "TCP preparation requires matching default Storage transport")
    require(type(launcher_default.get("ib_devices")) is dict, "matching FUSE launcher defaults required")
    integer(shard_bytes, 1, 1 << 20, "shard bytes")
    integer(maximum_operation_seconds, 1, 3600, "operation seconds")
    integer(retained_sessions, 1, 4096, "retained sessions")
    integer(maximum_input_bytes, 32 << 20, 1 << 40, "input reservation bytes")
    fuse, launcher = copy.deepcopy(fuse_default), copy.deepcopy(launcher_default)
    for target, source in (("client", "client"), ("mgmtd", "mgmtd_client"), ("meta", "meta_client"), ("storage", "storage_client")):
        fuse[target] = copy.deepcopy(client[source])
    fuse["mgmtd"].update(enable_auto_refresh=True, enable_auto_heartbeat=False, enable_auto_extend_client_session=True)
    fuse.update(enable_writeback_cache=False, enable_read_cache=False, batch_io_coros=4,
                io_jobq_size=8, notify_inval_threads=1, rdma_buf_pool_size=2)
    fuse["io_worker_coros"].update(hi=1, lo=1)
    fuse["io_jobq_sizes"].update(hi=8, lo=8)
    fuse["io_bufs"].update(max_buf_size="1MB", max_readahead="256KB")
    fuse["ec_read"]["enable"] = False
    fuse["ec_file"].update(enable=True, create_new=create_new, state_directory=str(output / "mount-state"),
                           create_state=True, retained_sessions=retained_sessions,
                           maximum_input_bytes=maximum_input_bytes,
                           maximum_operation_seconds=maximum_operation_seconds, shard_bytes=shard_bytes)
    handlers = fuse["common"].get("log", {}).get("handlers")
    require(type(handlers) is list and handlers and all(type(h) is dict for h in handlers), "actual default log handlers required")
    for index, handler in enumerate(handlers):
        if handler.get("writer_type") == "FILE":
            handler["file_path"] = str(output / "logs" / f"fuse-{index}.log")
    launcher.update(cluster_id=client["cluster_id"], mountpoint=str(mountpoint), allow_other=False, token_file=str(token))
    launcher["client"] = copy.deepcopy(client["client"])
    launcher["mgmtd_client"] = copy.deepcopy(client["mgmtd_client"])
    if transport is None:
        launcher["ib_devices"].update(allow_no_usable_devices=True, device_filter=[])
    else:
        fuse["ec_storage_transport"] = "rdma"
        launcher["ib_devices"] = copy.deepcopy(client["ib_devices"])
    resume = copy.deepcopy(fuse)
    resume["ec_file"]["create_state"] = False
    return {"fuse-first.toml": fuse, "fuse-resume.toml": resume, "launcher.toml": launcher}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "fuse-default", "launcher-default", "output-dir", "mountpoint"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--client-cfg", type=Path, help="Existing private file-client config; default ROOT/client/file-client.toml")
    parser.add_argument("--token-file", type=Path, help="Optional existing private copy of the SAME real user token; never creates a token")
    parser.add_argument("--create-new", action="store_true", help="Explicitly route ordinary regular-file create to mode4")
    parser.add_argument("--shard-bytes", type=int, default=1 << 20)
    parser.add_argument("--maximum-operation-seconds", type=int, default=300)
    parser.add_argument("--retained-sessions", type=int, default=128)
    parser.add_argument("--maximum-input-bytes", type=int, default=256 << 20)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("prepare requires actual Linux UID/permissions; it never starts a mount")
    helper = read_helpers()
    root = helper.canonical(args.root, True)
    inputs = {"manifest": helper.canonical(root / "cluster.json"),
              "fuse_default": helper.canonical(args.fuse_default),
              "launcher_default": helper.canonical(args.launcher_default),
              "client_cfg": helper.canonical(args.client_cfg or root / "client/file-client.toml")}
    raw = {}
    for key, path in inputs.items():
        with path.open("rb") as stream:
            raw[key] = stream.read((1 << 20) + 1)
    require(all(len(data) <= 1 << 20 for data in raw.values()), "configuration input exceeds 1 MiB")
    manifest = json.loads(raw["manifest"])
    fuse, launcher, client = [tomllib.loads(raw[k].decode("utf-8")) for k in ("fuse_default", "launcher_default", "client_cfg")]
    uid = os.geteuid()
    config_info = inputs["client_cfg"].stat()
    require(config_info.st_uid in (0, uid) and not config_info.st_mode & 0o077, "private authenticated client config required")
    token = helper.canonical(args.token_file or client["user_info"]["token_file"])
    info = token.stat()
    require(info.st_uid in (0, uid) and not info.st_mode & 0o077, "existing owner-only token required")
    mountpoint = helper.canonical(args.mountpoint, True)
    require(mountpoint.stat().st_uid == uid and not mountpoint.stat().st_mode & 0o077 and
            not os.path.ismount(mountpoint) and not any(mountpoint.iterdir()), "private empty unmounted mountpoint required")
    output = args.output_dir
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True) and
            output.name not in ("", ".", "..") and not output.exists() and not output.is_symlink(), "new private output directory required")
    parent_info = output.parent.stat()
    require(parent_info.st_uid == uid and not parent_info.st_mode & 0o077, "output parent must be private and owned by mount UID")
    require(output != mountpoint and output not in mountpoint.parents and mountpoint not in output.parents,
            "mountpoint and retained state must be disjoint")
    binary = helper.canonical(root / "bin/hf3fs_fuse_main")
    probe = helper.canonical(root / "bin/ec_mount_read_probe")
    require(os.access(binary, os.X_OK) and os.access(probe, os.X_OK), "package --ec-file-mount first; never build implicitly")
    configs = render(manifest, fuse, launcher, client, effective_uid=uid, root=root, output=output,
                     mountpoint=mountpoint, token=token, create_new=args.create_new, shard_bytes=args.shard_bytes,
                     maximum_operation_seconds=args.maximum_operation_seconds,
                     retained_sessions=args.retained_sessions, maximum_input_bytes=args.maximum_input_bytes)
    output.mkdir(mode=0o700)
    (output / "logs").mkdir(mode=0o700)
    hashes = {}
    for name, config in configs.items():
        data = to_toml(config).encode("utf-8")
        helper.new_file(output / name, data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    argv = lambda cfg: [str(binary), "--use_local_cfg", "--launcher_cfg", str(output / "launcher.toml"), "--cfg", str(output / cfg)]
    with binary.open("rb") as stream:
        binary_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    record = {"schema": 1, "configuration_only": True, "services_started": False, "mount_performed": False,
              "uid": uid, "allow_other": False, "state_not_created": str(output / "mount-state"),
              "inputs": {k: {"path": str(inputs[k]), "sha256": hashlib.sha256(v).hexdigest()} for k, v in raw.items()},
              "outputs": hashes, "binary_sha256": binary_digest,
              "first_mount_argv": argv("fuse-first.toml"), "remount_argv": argv("fuse-resume.toml"),
              "unmount_argv": ["fusermount3", "-u", str(mountpoint)],
              "live_file_api_verified": False, "rdma_note": "Empty device_filter permits found devices; it does not disable RDMA registration."}
    if transport_settings(manifest) is not None:
        record.update(transport_evidence(manifest))
        record["rdma_note"] = "Explicit device configuration only; no device, mount or verbs data path was validated."
    helper.new_file(output / "preparation.json", (json.dumps(record, indent=2) + "\n").encode("utf-8"))
    for directory in (output / "logs", output, output.parent):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print(output / "preparation.json")


if __name__ == "__main__":
    main()
