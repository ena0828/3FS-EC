#!/usr/bin/env python3
"""Prepare private FUSE read configs from the matching binaries' dumped defaults.

No service, mount, token creation or database operation is performed. The spool
is created explicitly by ec_read_spool_cli create-state after this command.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tomllib

from generate import to_toml


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value, directory=False):
    path = Path(value)
    require(path.is_absolute() and path == path.resolve(strict=True), "existing canonical absolute path required")
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "unexpected path type")
    return path


def new_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fuse-default", "launcher-default", "client-cfg", "output-dir", "mountpoint", "spool"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--archive")
    parser.add_argument("--retire-completed", action="store_true")
    args = parser.parse_args()
    inputs = {name: canonical(getattr(args, name)) for name in ("fuse_default", "launcher_default", "client_cfg")}
    raw = {name: path.read_bytes() for name, path in inputs.items()}
    fuse, launcher, client = [tomllib.loads(raw[name].decode()) for name in ("fuse_default", "launcher_default", "client_cfg")]
    require("ec_read" in fuse and "common" in fuse, "matching ENABLE_FUSE_APPLICATION binary defaults required")
    uid = client["user_info"]["uid"]
    require(type(uid) is int and uid == os.geteuid(), "run preparation and mount as the configured effective UID")
    token = canonical(client["user_info"]["token_file"])
    info = token.stat()
    require(info.st_uid in (0, uid) and not info.st_mode & 0o077, "explicit owner-only user token required")
    mountpoint = canonical(args.mountpoint, True)
    require(not any(mountpoint.iterdir()), "mountpoint must be empty")
    require(mountpoint.stat().st_uid == uid and not mountpoint.stat().st_mode & 0o077, "private owned mountpoint required")
    spool = Path(args.spool)
    require(spool.is_absolute() and spool.parent == spool.parent.resolve(strict=True) and
            spool.name not in ("", ".", "..") and not spool.exists(), "new explicit spool with existing parent required")
    archive = canonical(args.archive, True) if args.archive else None
    require(not args.retire_completed or archive is not None, "automatic retirement requires a separate private archive")
    if archive:
        require(archive != spool and spool not in archive.parents and archive.stat().st_uid == uid and
                not archive.stat().st_mode & 0o077, "archive must be private, owned and outside spool")
    output = Path(args.output_dir)
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True) and not output.exists(), "new explicit config directory required")
    require(client.get("cluster_id") and client["mgmtd_client"].get("network_type") == "TCP" and
            client["meta_client"].get("network_type") == "TCP", "existing authenticated TCP client configuration required")
    for target, source in (("client", "client"), ("mgmtd", "mgmtd_client"), ("meta", "meta_client"), ("storage", "storage_client")):
        fuse[target] = copy.deepcopy(client[source])
    fuse["mgmtd"].update(enable_auto_refresh=True, enable_auto_heartbeat=False, enable_auto_extend_client_session=True)
    fuse.update(enable_writeback_cache=False, enable_read_cache=False, batch_io_coros=4,
                io_jobq_size=8, notify_inval_threads=1, rdma_buf_pool_size=2)
    fuse["io_worker_coros"].update(hi=1, lo=1)
    fuse["io_jobq_sizes"].update(hi=8, lo=8)
    fuse["io_bufs"].update(max_buf_size="1MB", max_readahead="256KB")
    fuse["ec_read"].update(enable=True, state_directory=str(spool), create_state=False,
                           retire_completed=args.retire_completed, archive_directory=str(archive) if archive else "")
    launcher.update(cluster_id=client["cluster_id"], mountpoint=str(mountpoint), allow_other=False, token_file=str(token))
    launcher["client"] = copy.deepcopy(client["client"])
    launcher["mgmtd_client"] = copy.deepcopy(client["mgmtd_client"])
    launcher["ib_devices"].update(allow_no_usable_devices=True, device_filter=[])
    maintenance = {name: copy.deepcopy(client[name]) for name in
                   ("client", "mgmtd_client", "meta_client", "storage_client", "user_info", "cluster_id")}
    maintenance.update(state_directory=str(spool), retained_runs=fuse["ec_read"]["retained_runs"],
                       outstanding_runs=fuse["ec_read"]["outstanding_runs"], logical_spool_bytes=fuse["ec_read"]["logical_spool_bytes"])
    output.mkdir(mode=0o700)
    generated = {}
    for name, config in (("fuse.toml", fuse), ("launcher.toml", launcher), ("spool.toml", maintenance)):
        data = to_toml(config).encode()
        new_file(output / name, data)
        generated[name] = hashlib.sha256(data).hexdigest()
    manifest = {"schema": 1, "configuration_only": True, "services_started": False,
                "inputs": {name: {"path": str(inputs[name]), "sha256": hashlib.sha256(data).hexdigest()} for name, data in raw.items()},
                "outputs": generated, "spool_not_created": str(spool), "automatic_retirement": args.retire_completed,
                "rdma_note": "An empty device filter allows discovered devices; it does not disable registration."}
    new_file(output / "preparation.json", (json.dumps(manifest, indent=2) + "\n").encode())
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    print(output / "preparation.json")


if __name__ == "__main__":
    main()
