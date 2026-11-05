#!/usr/bin/env python3
"""Generate the local TCP V2 profile; never open a database or invent an instance."""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import tomllib
import uuid

from generate import put, to_toml, tune


PROFILE = "native-v2-local-1-storage-12-targets"
SERVICES = ("mgmtd_main", "meta_main", "storage_main", "admin_cli", "ec_stripe_cli")


def write_new(path, value):
    """Publish a new private file without following or replacing its final path."""
    payload = value.encode("utf-8") if isinstance(value, str) else value
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def replace_private(path, value):
    if path.is_symlink():
        raise RuntimeError(f"Refusing redirected file: {path}")
    temp = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    write_new(temp, value)
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def tcp_only(value):
    if isinstance(value, list):
        for item in value:
            tcp_only(item)
    elif isinstance(value, dict):
        for key, item in list(value.items()):
            if key in {"network_type", "addr_type"} and item == "RDMA":
                value[key] = "TCP"
            elif key == "force_use_tcp":
                value[key] = True
            else:
                tcp_only(item)


def generate_configs(source, root, port_base, authority, cluster_id):
    """Pure configuration generation, shared by prepare and configuration tests."""
    root = str(root)
    configs, hashes = {}, {}
    mgmtd_address = f"TCP://127.0.0.1:{port_base + 1}"

    def load(name):
        path = source / "configs" / f"{name}.toml"
        hashes[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        tune(data, mgmtd_address, root)
        tcp_only(data)
        return data

    def server(data, name, port, service):
        put(data, "common.monitor", {"collect_period": "10s", "num_collectors": 1, "reporters": []})
        put(data, "common.log", {
            "categories": [{"categories": ["."], "handlers": ["normal"], "level": "INFO"}],
            "handlers": [{"name": "normal", "writer_type": "FILE", "file_path": f"{root}/logs/{name}.log",
                          "async": True, "rotate": True, "rotate_on_open": False,
                          "max_file_size": "16MB", "max_files": 3, "start_level": "NONE"}],
        })
        group = copy.deepcopy(data["server"]["base"]["groups"][0])
        group.update(network_type="TCP", services=[service, "Core"], use_independent_thread_pool=False)
        group["listener"].update(listen_port=port, filter_list=["lo"], custom_tcp_nic_prefix="lo",
                                 reuse_port=False, listen_queue_depth=128)
        data["server"]["base"]["groups"] = [group]
        for key in ("mgmtd_client", "mgmtd"):
            if key in data["server"]:
                data["server"][key]["network_type"] = "TCP"

    for kind, node, offset, service in [("mgmtd", 1, 1, "Mgmtd"), ("meta", 100, 2, "MetaSerde")]:
        data = load(f"{kind}_main")
        server(data, kind, port_base + offset, service)
        if kind == "mgmtd":
            data["server"]["service"].update(authenticate=True, allow_heartbeat_from_unregistered=False, bootstrapping_length="5s",
                new_chain_bootstrap_interval="2s", check_status_interval="1s", heartbeat_fail_interval="30s",
                extend_lease_interval="5s", lease_length="30s", suspicious_lease_interval="10s")
        else:
            # Bootstrap is deliberately disabled until administrator discovery
            # supplies the real twelve physical endpoints. No zero UUID pool.
            data["server"]["meta"].update(authenticate=True, enable_ec_catalog=True, enable_ec_v2=False,
                ec_allow_colocated_test_targets=True, ec_allow_unauthorized_storage_for_tests=False,
                ec_capability_key_file=f"{root}/secrets/data.key", ec_v2_control_key_file=f"{root}/secrets/control.key",
                ec_v2_helper_key_file=f"{root}/secrets/helper.key", ec_v2_control_authority=authority,
                ec_max_verifying_stripes=1, ec_grant_ttl_seconds=300, ec_verify_timeout="60s",
                ec_v2_drain_timeout="60s", ec_v2_drain_poll_interval="100ms")
            put(data, "server.meta.event_trace_log.enabled", False)
            # The local profile does not evaluate legacy namespace GC. V2
            # physical collection is not implemented by this wrapper.
            put(data, "server.meta.gc.enable", False)
            put(data, "server.meta.session_manager.enable", False)
        configs[f"{kind}_main.toml"] = data
        launcher = load(f"{kind}_main_launcher")
        launcher["cluster_id"] = cluster_id
        launcher["ib_devices"].update(allow_no_usable_devices=True, device_filter=[])
        put(launcher, "mgmtd_client.network_type", "TCP")
        configs[f"{kind}_main_launcher.toml"] = launcher
        configs[f"{kind}_main_app.toml"] = {"allow_empty_node_id": False, "node_id": node}

    data = load("storage_main")
    server(data, "storage-10001", port_base + 3, "StorageSerde")
    store = data["server"]
    # Ten nested helpers with four blocks can occupy forty live RPC frames
    # on one colocated Storage process. Keep room for their data/control RPCs;
    # the helper runtime retains its independent fixed 64-request budget.
    store["base"]["groups"][0]["processor"].update(
        max_coroutines_num=128, max_processing_requests_num=128)
    store["speed_up_quit"] = False
    store["buffer_pool"].update(rdmabuf_count=16, rdmabuf_size="1MB", big_rdmabuf_count=4, big_rdmabuf_size="4MB")
    store["aio_read_worker"].update(num_threads=1, queue_size=128, max_events=32, min_complete=1,
        inflight_control_offset=8, enable_io_uring=False, ioengine="libaio")
    store["allocate_worker"].update(min_remain_groups=0, max_remain_groups=0, min_remain_ultra_groups=0,
        max_remain_ultra_groups=0, max_reserved_chunks="64MB")
    store["storage"].update(enable_ec_fragments=True, allow_unsafe_ec_fragment_rpc_for_testing=False,
        ec_capability_key_file=f"{root}/secrets/data.key", enable_ec_scope_control=True,
        ec_scope_control_key_file=f"{root}/secrets/control.key", ec_scope_control_authority=authority,
        enable_ec_helpers=True, ec_helper_key_file=f"{root}/secrets/helper.key", max_concurrent_ec_requests=16,
        max_concurrent_rdma_reads=8, max_concurrent_rdma_writes=8)
    store["storage"]["event_trace_log"]["enabled"] = False
    store["storage"]["write_worker"].update(num_threads=2, bg_num_threads=1, queue_size=128)
    store["sync_worker"].update(num_threads=2, num_channels=8, batch_size=4)
    store["sync_worker"]["batch_concurrency_limiter"]["max_concurrency"] = 2
    store["targets"].update(target_paths=[f"{root}/data/storage-10001"], ec_only=True, ec_staging_v2=True,
                            allow_disk_without_uuid=True)
    store["targets"]["storage_target"]["force_persist"] = True
    configs["storage_main.toml"] = data
    launcher = load("storage_main_launcher")
    launcher["cluster_id"] = cluster_id
    launcher["ib_devices"].update(allow_no_usable_devices=True, device_filter=[])
    put(launcher, "mgmtd_client.network_type", "TCP")
    configs["storage_main_launcher.toml"] = launcher
    configs["storage_main_app.toml"] = {"allow_empty_node_id": False, "node_id": 10001}

    admin = load("admin_cli")
    admin.update(cluster_id=cluster_id, num_timeout_ms=30000, break_multi_line_command_on_failure=True,
        log=f"INFO:normal; normal=file:path={root}/logs/admin.log,async=true,sync_level=ERR")
    admin["ib_devices"].update(allow_no_usable_devices=True, device_filter=[])
    admin["user_info"].update(uid=0, gid=0, token="")
    put(admin, "mgmtd_client.network_type", "TCP")
    configs["admin_cli.toml"] = admin
    client_path = source / "scripts/ec/stripe-client.example.toml"
    hashes[str(client_path.relative_to(source))] = hashlib.sha256(client_path.read_bytes()).hexdigest()
    client = tomllib.loads(client_path.read_text(encoding="utf-8"))
    client.update(cluster_id=cluster_id, worker_threads=2, max_operations=1,
                  max_application_bytes=33554432, write_fragments=2, read_blocks=1)
    client["user_info"].update(uid=1000, gid=1000, token_file=f"{root}/client/user.token")
    client["mgmtd_client"]["mgmtd_server_addresses"] = [mgmtd_address]
    configs["stripe-client.toml"] = client
    return configs, hashes


def prepare(root, source, port_base):
    if os.name != "posix":
        raise RuntimeError("prepare requires the target Linux filesystem and permission semantics")
    original = root.absolute()
    root = root.resolve()
    if root != original or not root.name.startswith("3fs-ec-native-") or root.parent == Path("/"):
        raise RuntimeError("Use a new absolute, non-symlink task directory named 3fs-ec-native-*")
    if not root.parent.is_dir() or root.exists():
        raise RuntimeError("Parent must exist; the task directory must not exist (no overwrite or adoption)")
    if not 1024 <= port_base <= 65532:
        raise RuntimeError("port-base must be in [1024, 65532]")
    authority, cluster_id = str(uuid.uuid4()), "ec_native_" + secrets.token_hex(6)
    configs, hashes = generate_configs(source.resolve(strict=True), root, port_base, authority, cluster_id)
    root.mkdir(mode=0o700)
    for name in ("config", "secrets", "client", "state", "logs", "scripts", "data", "bin", "lib", "provenance"):
        (root / name).mkdir(mode=0o700)
    for role in ("data", "control", "helper"):
        write_new(root / "secrets" / f"{role}.key", secrets.token_bytes(32))
    for name, data in configs.items():
        destination = root / ("client" if name == "stripe-client.toml" else "config") / name
        write_new(destination, to_toml(data))
    write_new(root / "config/fdb.cluster", f"{cluster_id}:{secrets.token_hex(8)}@127.0.0.1:{port_base}\n")
    endpoints = [{"node": 10001, "chain": 910001 + i, "target": 1100001 + i} for i in range(12)]
    write_new(root / "config/chains.csv", "ChainId,TargetId\n" + "".join(f"{e['chain']},{e['target']}\n" for e in endpoints))
    write_new(root / "config/chain-table.csv", "ChainId\n" + "".join(f"{e['chain']}\n" for e in endpoints))
    manifest = {"schema": 1, "profile": PROFILE, "root": str(root), "cluster_id": cluster_id,
        "authority": authority, "port_base": port_base, "storage_count": 1, "logical_target_count": 12,
        "independent_storage_failure_domains": 1, "endpoints": endpoints, "source_config_sha256": hashes,
        "fdb_version": "7.3.63", "state": "prepared_not_started", "performance_validated": False}
    write_new(root / "cluster.json", json_text(manifest))
    for name in ("generate.py", "run-cluster.py", "native_v2_config.py", "native-v2.py", "fetch-fdb.sh"):
        shutil.copy2(Path(__file__).parent / name, root / "scripts" / name)
    print(f"Prepared {root}: private keys and configuration only; no services, targets or database opened.")


def pool_from_observations(manifest, observations):
    if len(observations) != 12:
        raise ValueError("Require twelve fresh administrator-verified observations")
    pool = []
    for expected, observation in zip(manifest["endpoints"], observations, strict=True):
        if observation.get("schema") != 1 or observation.get("protocol") != 2 or \
                observation.get("authority") != manifest["authority"] or \
                observation.get("verification") != "control_mac_verified" or \
                any(observation.get(k) != v for k, v in expected.items()):
            raise ValueError("Discovery observation does not bind the expected logical endpoint")
        item = dict(expected)
        for key in ("engine_uuid", "target_incarnation"):
            parsed = uuid.UUID(observation[key])
            if not parsed.int:
                raise ValueError("Discovery returned a zero persistent instance")
            item[key] = str(parsed)
        pool.append(item)
    if len({(p["chain"], p["target"]) for p in pool}) != 12:
        raise ValueError("Duplicate logical endpoint")
    return pool
