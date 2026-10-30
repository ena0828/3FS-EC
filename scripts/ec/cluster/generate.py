#!/usr/bin/env python3
"""Generate reviewed local-cluster files without starting services or creating tokens."""
import argparse
import hashlib
import ipaddress
import json
import secrets
from pathlib import Path, PurePosixPath
import shutil
import tomllib


def scalar(value):
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (str, int, float)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list) and not any(isinstance(v, dict) for v in value):
        return "[" + ", ".join(scalar(v) for v in value) + "]"
    raise TypeError(f"Unsupported TOML scalar: {type(value)}")


def to_toml(data):
    lines = []

    def emit(table, path, header=None):
        if header:
            lines.extend(["", header])
        for key, value in table.items():
            if not isinstance(value, dict) and not (isinstance(value, list) and value and isinstance(value[0], dict)):
                lines.append(f"{key} = {scalar(value)}")
        for key, value in table.items():
            name = ".".join(path + [key])
            if isinstance(value, dict):
                emit(value, path + [key], f"[{name}]")
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                for item in value:
                    emit(item, path + [key], f"[[{name}]]")

    emit(data, [])
    text = "\n".join(lines) + "\n"
    if tomllib.loads(text) != data:
        raise ValueError("TOML round-trip mismatch")
    return text


def put(data, path, value):
    keys = path.split(".")
    for key in keys[:-1]:
        data = data.setdefault(key, {})
    data[keys[-1]] = value


def tune(data, mgmtd_address, root):
    """Bound the existing upstream fields, preserving other protocol settings."""
    if isinstance(data, list):
        for value in data:
            tune(value, mgmtd_address, root)
        return
    if not isinstance(data, dict):
        return
    for key, value in list(data.items()):
        if key in {"num_bg_threads", "num_connect_threads", "threads_num", "bg_num_threads"}:
            data[key] = 1
        elif key in {"num_threads", "num_io_threads", "num_proc_threads", "rocksdb_threads_num"}:
            data[key] = 2
        elif key == "coroutines_num":
            data[key] = min(value, 8)
        elif key == "queue_size":
            data[key] = min(value, 128)
        elif key == "max_coroutines_num":
            data[key] = 32
        elif key == "max_processing_requests_num":
            data[key] = 128
        elif key == "max_concurrent_requests":
            data[key] = 8
        elif key == "max_concurrent_requests_per_server":
            data[key] = 4
        elif key == "max_concurrent_transmission":
            data[key] = 8
        elif key == "max_batch_bytes":
            data[key] = "1MB"
        elif key == "max_batch_size":
            data[key] = 2
        elif key == "mgmtd_server_addresses":
            data[key] = [mgmtd_address]
        elif key in {"auto_heartbeat_interval", "auto_refresh_interval", "auto_extend_client_session_interval"}:
            data[key] = "2s"
        elif key == "clusterFile":
            data[key] = f"{root}/config/fdb.cluster"
        elif key == "externalClientPath":
            data[key] = f"{root}/lib/libfdb_c.so"
        elif key == "multipleClientThreadNum":
            data[key] = 1
        elif key == "use_memkv":
            data[key] = False
        else:
            tune(value, mgmtd_address, root)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--guest-root", default="/home/ec/3fs-lab")
    parser.add_argument("--guest-ip", default="10.0.2.15")
    parser.add_argument("--storage-count", type=int, choices=[2, 3], default=2)
    args = parser.parse_args()
    root = str(PurePosixPath(args.guest_root))
    if not root.startswith("/home/ec/3fs-lab") or root in {"/home/ec", "/home", "/"} or ".." in PurePosixPath(root).parts:
        parser.error("Guest root must be a task-specific /home/ec/3fs-lab* directory")
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-" for c in root):
        parser.error("Guest root contains unsupported characters")
    ip = str(ipaddress.IPv4Address(args.guest_ip))
    output = args.output.resolve()
    config_dir = output / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    if any(config_dir.iterdir()):
        parser.error("Refusing to overwrite an existing configuration directory")
    mgmtd = f"RDMA://{ip}:12501"
    source = args.source.resolve()
    inputs = {}

    def load(name):
        path = source / "configs" / f"{name}.toml"
        inputs[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        tune(data, mgmtd, root)
        return data

    def save(name, data):
        (config_dir / f"{name}.toml").write_text(to_toml(data), encoding="utf-8")

    def common(data, name, monitor=True):
        data["common"]["log"] = {
            "categories": [{"categories": ["."], "handlers": ["normal"], "level": "INFO"}],
            "handlers": [{"name": "normal", "writer_type": "FILE", "file_path": f"{root}/logs/{name}.log",
                          "async": True, "rotate": True, "rotate_on_open": False,
                          "max_file_size": "16MB", "max_files": 3, "start_level": "NONE"}],
        }
        if monitor:
            data["common"]["monitor"] = {"collect_period": "10s", "num_collectors": 1,
                "reporters": [{"type": "monitor_collector", "monitor_collector": {"remote_ip": "127.0.0.1:12510"}}]}

    def listeners(data, rdma_port, tcp_port):
        groups = data["server"]["base"]["groups"]
        groups[0]["listener"]["listen_port"] = rdma_port
        groups[1]["listener"]["listen_port"] = tcp_port

    for kind, node_id in [("mgmtd", 1), ("meta", 100)]:
        data = load(f"{kind}_main")
        common(data, kind)
        listeners(data, 12501 if kind == "mgmtd" else 12502, 12601 if kind == "mgmtd" else 12602)
        if kind == "mgmtd":
            service = data["server"]["service"]
            service.update(bootstrapping_length="5s", new_chain_bootstrap_interval="2s",
                           check_status_interval="1s", heartbeat_fail_interval="30s",
                           extend_lease_interval="5s", lease_length="30s", suspicious_lease_interval="10s")
        else:
            put(data, "server.meta.event_trace_log.enabled", False)
            put(data, "server.meta.gc.gc_file_concurrent", 2)
            put(data, "server.meta.gc.gc_directory_concurrent", 1)
            put(data, "server.meta.gc.gc_directory_entry_concurrent", 1)
        save(f"{kind}_main", data)
        launcher = load(f"{kind}_main_launcher")
        launcher["cluster_id"] = "ec_local"
        launcher["ib_devices"]["device_filter"] = ["rxe0"]
        save(f"{kind}_main_launcher", launcher)
        save(f"{kind}_main_app", {"allow_empty_node_id": False, "node_id": node_id})

    for index in range(args.storage_count):
        node_id = 10001 + index
        name = f"storage-{node_id}"
        data = load("storage_main")
        common(data, name)
        listeners(data, 12503 + index, 12603 + index)
        server = data["server"]
        server["speed_up_quit"] = False
        server["buffer_pool"].update(rdmabuf_count=16, rdmabuf_size="1MB", big_rdmabuf_count=4, big_rdmabuf_size="4MB")
        server["aio_read_worker"].update(num_threads=1, queue_size=128, max_events=32, min_complete=1,
                                         inflight_control_offset=8, enable_io_uring=False, ioengine="libaio")
        server["allocate_worker"].update(min_remain_groups=0, max_remain_groups=0,
                                         min_remain_ultra_groups=0, max_remain_ultra_groups=0, max_reserved_chunks="64MB")
        server["storage"].update(max_concurrent_rdma_reads=8, max_concurrent_rdma_writes=8)
        server["storage"]["event_trace_log"]["enabled"] = False
        server["storage"]["write_worker"].update(num_threads=2, bg_num_threads=1, queue_size=128)
        server["sync_worker"].update(num_threads=2, num_channels=8, batch_size=4)
        server["sync_worker"]["batch_concurrency_limiter"]["max_concurrency"] = 2
        server["targets"].update(target_paths=[f"{root}/data/{name}"], allow_disk_without_uuid=True)
        target = server["targets"]["storage_target"]
        target["force_persist"] = True
        target["kv_store"].update(type="LevelDB", leveldb_block_cache_size="16MB", leveldb_write_buffer_size="4MB",
                                   rocksdb_block_cache_size="16MB", rocksdb_write_buffer_size="4MB", sync_when_write=True)
        target["meta_store"]["allocate_size"] = "64MB"
        save(name, data)
        if index == 0:
            save("storage_main", data)
        launcher = load("storage_main_launcher")
        launcher["cluster_id"] = "ec_local"
        launcher["ib_devices"]["device_filter"] = ["rxe0"]
        save(f"{name}-launcher", launcher)
        save(f"{name}-app", {"allow_empty_node_id": False, "node_id": node_id})

    fuse = load("hf3fs_fuse_main")
    common(fuse, "fuse")
    fuse.update(max_threads=4, max_idle_threads=1, notify_inval_threads=1, max_background=4,
                max_readahead="1MB", io_jobq_size=128, batch_io_coros=8, rdma_buf_pool_size=16,
                enable_read_cache=False, enable_writeback_cache=False, attr_timeout=0.0, entry_timeout=0.0,
                negative_timeout=0.0, fsync_length_hint=False)
    fuse["io_jobq_sizes"].update(hi=8, lo=128)
    fuse["io_worker_coros"].update(hi=2, lo=2)
    fuse["periodic_sync"].update(interval="2s", limit=16)
    save("hf3fs_fuse_main", fuse)
    launcher = load("hf3fs_fuse_main_launcher")
    launcher.update(cluster_id="ec_local", allow_other=False, mountpoint=f"{root}/mnt", token_file=f"{root}/secrets/token")
    launcher["ib_devices"]["device_filter"] = ["rxe0"]
    save("hf3fs_fuse_main_launcher", launcher)

    monitor = load("monitor_collector_main")
    common(monitor, "monitor", monitor=False)
    monitor["common"]["cluster_id"] = "ec_local"
    monitor["common"]["ib_devices"]["allow_no_usable_devices"] = True
    monitor["server"]["base"]["groups"][0]["listener"]["listen_port"] = 12510
    monitor["server"]["monitor_collector"].update(conn_threads=1, queue_capacity=2048, batch_commit_size=128,
                                                  reporter={"type": "log", "log": {"ignore": ""}})
    save("monitor_collector_main", monitor)

    admin = load("admin_cli")
    admin.update(cluster_id="ec_local", num_timeout_ms=5000, break_multi_line_command_on_failure=True,
                 log=f"INFO:normal; normal=file:path={root}/logs/admin.log,async=true,sync_level=ERR")
    admin["ib_devices"]["device_filter"] = ["rxe0"]
    admin["user_info"].update(uid=0, gid=0, token="")
    save("admin_cli", admin)
    (config_dir / "fdb.cluster").write_text(f"ec_local:{secrets.token_hex(8)}@127.0.0.1:12500\n", encoding="utf-8")
    chains = []
    targets = []
    for offset in range(4):
        chain = 900001 + offset
        replicas = [1000000 + index * 100 + offset + 1 for index in range(args.storage_count)]
        order = offset % args.storage_count
        chains.append([chain] + replicas[order:] + replicas[:order])
        for index, target in enumerate(replicas):
            targets.append(f"create-target --node-id {10001 + index} --disk-index 0 --target-id {target} --chain-id {chain} --chunk-size 512KB")
    (config_dir / "chains.csv").write_text("ChainId," + ",".join(["TargetId"] * args.storage_count) + "\n" +
        "\n".join(",".join(map(str, row)) for row in chains) + "\n", encoding="utf-8")
    (config_dir / "chain-table.csv").write_text("ChainId\n" + "\n".join(str(c[0]) for c in chains) + "\n", encoding="utf-8")
    (config_dir / "create-targets.txt").write_text("\n".join(targets) + "\n", encoding="utf-8")
    manifest = {"guest_root": root, "guest_ip": ip, "storage_count": args.storage_count, "cluster_id": "ec_local",
                "chunk_bytes": 524288, "stripe_size": 1, "chain_count": 4, "source_config_sha256": inputs,
                "state": "generated_not_started", "tokens_created": False}
    (output / "cluster.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    scripts = output / "scripts"
    scripts.mkdir(exist_ok=True)
    for path in Path(__file__).resolve().parent.iterdir():
        if path.suffix in {".sh", ".py"}:
            shutil.copy2(path, scripts / path.name)
    print(f"Generated reviewable configuration in {config_dir}; no services or tokens created.")


if __name__ == "__main__":
    main()
