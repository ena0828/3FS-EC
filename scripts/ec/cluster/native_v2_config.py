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
GC_PROFILE = "native-gc-local-1-storage-12-targets"
MULTI_PROFILE = "native-v2-local-12-storage-12-targets"
MULTI_GC_PROFILE = "native-gc-local-12-storage-12-targets"
SPARE_GC_PROFILE = "native-gc-local-14-storage-14-targets"
PROFILES = {"v2": PROFILE, "gc": GC_PROFILE, "v2-12": MULTI_PROFILE,
            "gc-12": MULTI_GC_PROFILE, "gc-14": SPARE_GC_PROFILE}


def authenticated_user(manifest):
    """Missing metadata means the historical 1000/1000 user, never this OS user."""
    user = manifest.get("authenticated_user", {"uid": 1000, "gid": 1000})
    if type(user) is not dict or set(user) != {"uid", "gid"} or \
            type(user["uid"]) is not int or not 1 <= user["uid"] < (1 << 32) - 1 or \
            type(user["gid"]) is not int or not 0 <= user["gid"] < (1 << 32) - 1:
        raise ValueError("Require an explicit ordinary UID and GID; no root, booleans or reserved IDs")
    return dict(user)


def validate_initialized_user(manifest, initialized):
    """An existing database cannot acquire a different user through configuration."""
    if type(manifest.get("cluster_id")) is not str or not manifest["cluster_id"] or \
            type(initialized) is not dict or type(initialized.get("schema")) is not int or initialized["schema"] != 1 or \
            initialized.get("cluster_id") != manifest.get("cluster_id") or \
            authenticated_user(initialized) != authenticated_user(manifest):
        raise ValueError("Initialized cluster/user differs; prepare a fresh lab instead of migrating old state")


def storage_process_count(manifest):
    profile = manifest.get("profile")
    if profile in (PROFILE, GC_PROFILE):
        return 1
    if profile in (MULTI_PROFILE, MULTI_GC_PROFILE):
        return 12
    if profile == SPARE_GC_PROFILE:
        return 14
    raise ValueError("Unknown native process topology")


def target_count(manifest):
    return 14 if manifest.get("profile") == SPARE_GC_PROFILE else 12


def storage_specs(manifest):
    count = storage_process_count(manifest)
    root, port = Path(manifest["root"]), manifest["port_base"]
    if type(port) is not int or not 1024 <= port <= 65535 - (count + 2):
        raise ValueError("Native topology requires a valid complete port interval")
    return [dict(node=10001 + i, name="storage" if count == 1 else f"storage-{10001+i}",
                 stem="storage_main" if count == 1 else f"storage-{10001+i}", port=port + 3 + i,
                 data_path=str(root / f"data/storage-{10001+i}")) for i in range(count)]


def topology_problems(manifest):
    count = storage_process_count(manifest)
    problems = []
    if type(manifest.get("storage_count")) is not int or manifest["storage_count"] != count or \
            type(manifest.get("logical_target_count")) is not int or manifest["logical_target_count"] != target_count(manifest):
        problems.append("Storage process/target count differs from explicit profile")
    expected = [dict(node=10001 + (i if count > 1 else 0), chain=910001+i, target=1100001+i) for i in range(target_count(manifest))]
    actual = manifest.get("endpoints", [])
    if actual != expected or any(type(e.get(k)) is not int for e in actual for k in ("node", "chain", "target")):
        problems.append("Endpoint map must be the fixed profile target/chain identities for this profile")
    if type(manifest.get("independent_storage_failure_domains")) is not int or manifest["independent_storage_failure_domains"] != 1:
        problems.append("A local process topology still has one physical machine failure domain")
    if count > 1 and (type(manifest.get("storage_process_failure_domains")) is not int or
                        manifest["storage_process_failure_domains"] != count or
                        manifest.get("deployment_scope") != "single_machine_distinct_processes_not_physical_hosts" or
                        manifest.get("remote_global_storage_config_policy") != "pinned_local_mismatch_rejected_not_version_acked"):
        problems.append("Twelve-process manifest must explicitly preserve physical/configuration limitations")
    if count == 14 and (manifest.get("initial_placement_nodes") != list(range(10001, 10013)) or
                        manifest.get("spare_nodes") != [10013, 10014] or manifest.get("file_api") is not True):
        problems.append("Spare profile requires file API and explicit initial twelve plus two spare nodes")
    storage_specs(manifest)
    return problems


def nonzero_uuid(value):
    if not isinstance(value, str):
        raise ValueError("Require a nonzero canonical UUID string")
    parsed = uuid.UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError("Require a nonzero canonical UUID string")
    return str(parsed)


def gc_settings(manifest):
    """Validate requested configuration, never infer a live target's format."""
    if manifest.get("profile") in (PROFILE, MULTI_PROFILE):
        if "gc" in manifest:
            raise ValueError("V2 bundle cannot acquire GC settings; prepare a new GC root")
        return None
    if manifest.get("profile") not in (GC_PROFILE, MULTI_GC_PROFILE, SPARE_GC_PROFILE):
        raise ValueError("Unknown native profile")
    config = manifest.get("gc", {})
    if not isinstance(config, dict):
        raise ValueError("GC settings must be an object")
    for key in ("authority", "key_id", "client_namespace"):
        nonzero_uuid(config.get(key))
    if config["authority"] == nonzero_uuid(manifest.get("authority")):
        raise ValueError("G authority must be distinct from the control authority")
    expected = {"data_protocol": 2, "disk_format": 3,
                "gc_protocol": 2 if manifest.get("file_api") is True else 1}
    if any(type(config.get(key)) is not int or config[key] != value for key, value in expected.items()):
        raise ValueError("GC profile requires data protocol 2, disk format 3 and its explicitly selected GC protocol")
    return config


def key_roles(manifest):
    roles = ("data", "control", "helper", "gc") if gc_settings(manifest) else ("data", "control", "helper")
    return roles + ("rmw",) if file_api_enabled(manifest) else roles


def file_api_enabled(manifest):
    enabled = manifest.get("file_api", False)
    if type(enabled) is not bool:
        raise ValueError("file_api must be an explicit boolean")
    if enabled and not gc_settings(manifest):
        raise ValueError("File API requires a fresh GC profile with staging disk format 3")
    return enabled


def required_services(manifest):
    return SERVICES + ("ec_file_cli",) if file_api_enabled(manifest) else SERVICES


def profile_config_problems(manifest, configs):
    """Fail closed on profile/config drift before opening any target root."""
    gc = gc_settings(manifest)
    file_api = file_api_enabled(manifest)
    meta = configs["meta_main.toml"]["server"]["meta"]
    count = storage_process_count(manifest)
    # Preserve the original one-process names and values. Twelve-process roots
    # use actual per-node paths; no generic STORAGE template can replace them.
    names = ["storage_main.toml"] if count == 1 else [f"storage-{10001+i}.toml" for i in range(count)]
    problems = []
    user = authenticated_user(manifest)
    for name in ("stripe-client.toml", "file-client.toml") if file_api else ("stripe-client.toml",):
        configured = configs.get(name, {}).get("user_info", {})
        if any(type(configured.get(key)) is not int or configured[key] != value for key, value in user.items()):
            problems.append(f"{name} authenticated UID/GID differs from the prepared user")
    for name in names:
        storage = configs[name]["server"]
        targets, service = storage["targets"], storage["storage"]
        if service.get("enable_ec_rmw", False) is not file_api:
            problems.append(f"{name} RMW gate differs from the prepared file API selection")
        if file_api:
            expected_rmw = {"ec_rmw_authority": manifest["authority"],
                            "ec_rmw_key_file": str(Path(manifest["root"]) / "secrets/rmw.key")}
            for label, settings in (("Meta", meta), (name, service)):
                if any(settings.get(key) != value for key, value in expected_rmw.items()):
                    problems.append(f"{label} RMW key/authority differs from prepared identity")
        if not gc:
            if targets.get("ec_exact_gc", False) or service.get("enable_ec_gc", False) or \
                    meta.get("enable_ec_exact_gc", False) or meta.get("enable_ec_revision_retirement", False):
                problems.append("V2 profile cannot be converted to GC; use a fresh explicitly prepared GC root")
            continue
        flags = [targets.get(key) for key in ("ec_only", "ec_staging_v2", "ec_exact_gc")]
        flags += [service.get(key) for key in ("enable_ec_fragments", "enable_ec_gc")]
        if any(value is not True for value in flags):
            problems.append(f"{name} requires explicit EC-only staging format 3 and enabled GC")
        expected = {"ec_gc_authority": gc["authority"], "ec_gc_key_id": gc["key_id"],
                    "ec_gc_key_file": str(Path(manifest["root"]) / "secrets/gc.key")}
        for label, settings in (("Meta", meta), (name, service)):
            if any(settings.get(key) != value for key, value in expected.items()):
                problems.append(f"{label} G key/authority configuration differs from prepared identity")
    if gc:
        gates = [meta.get(key) for key in ("enable_ec_v2", "enable_ec_exact_gc", "enable_ec_revision_retirement")]
        if any(type(value) is not bool for value in gates) or gates[1] != gates[0] or gates[2] != gates[0]:
            problems.append("Meta V2/GC/retirement gates must be enabled together after discovery")
        if configs["admin_cli.toml"].get("client_uuid") != gc["client_namespace"]:
            problems.append("actual administrator client namespace differs from the prepared GC bundle")
    for key in ("enable_ec_rmw", "enable_ec_file_ranges"):
        expected = bool(file_api and meta.get("enable_ec_v2") is True)
        if meta.get(key, False) is not expected:
            problems.append(f"Meta {key} must follow the prepared file API and verified V2 pool")
    if count > 1:
        if meta.get("ec_allow_colocated_test_targets") is not False:
            problems.append("Twelve-process placement requires twelve distinct Storage node IDs")
        for spec in storage_specs(manifest):
            config = configs[spec["stem"] + ".toml"]
            groups = config["server"]["base"]["groups"]
            app = configs[spec["stem"] + "_app.toml"]
            if len(groups) != 1 or type(groups[0]["listener"].get("listen_port")) is not int or \
                    groups[0]["listener"]["listen_port"] != spec["port"] or \
                    config["server"]["targets"].get("target_paths") != [spec["data_path"]] or \
                    type(app.get("node_id")) is not int or app["node_id"] != spec["node"] or \
                    config["common"]["log"]["handlers"][0].get("file_path") != str(Path(manifest["root"])/"logs"/(spec["name"]+".log")):
                problems.append(f"{spec['name']} port/path/node/log differs from its prepared topology")
    return problems


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


def generate_configs(source, root, port_base, authority, cluster_id, *, profile="v2", gc=None, file_api=False,
                     user_uid=1000, user_gid=1000):
    """Pure configuration generation, shared by prepare and configuration tests."""
    user = authenticated_user({"authenticated_user": {"uid": user_uid, "gid": user_gid}})
    if profile not in PROFILES:
        raise ValueError("Unknown native profile")
    requested = {"profile": PROFILES[profile], "authority": authority}
    if gc is not None:
        requested["gc"] = gc
    requested["file_api"] = file_api
    file_api = file_api_enabled(requested)
    if profile == "gc-14" and not file_api:
        raise ValueError("gc-14 requires explicit --file-api; old flat repair does not prove lost-source publication")
    gc = gc_settings(requested)
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
            # Legacy namespace GC remains disabled. Exact EC GC is a separate,
            # explicitly selected administrator path, never a background scan.
            if gc:
                data["server"]["meta"].update(enable_ec_exact_gc=False, enable_ec_revision_retirement=False,
                    ec_gc_key_file=f"{root}/secrets/gc.key", ec_gc_key_id=gc["key_id"],
                    ec_gc_authority=gc["authority"], ec_gc_request_ttl_seconds=60,
                    ec_gc_timeout="60s", ec_gc_max_concurrent=1)
            if file_api:
                data["server"]["meta"].update(enable_ec_rmw=False, enable_ec_file_ranges=False,
                    ec_rmw_key_file=f"{root}/secrets/rmw.key", ec_rmw_authority=authority,
                    ec_rmw_grant_ttl_seconds=60,
                    ec_rmw_transport=copy.deepcopy(data["server"]["background_client"]))
            put(data, "server.meta.gc.enable", False)
            put(data, "server.meta.session_manager.enable", False)
        configs[f"{kind}_main.toml"] = data
        launcher = load(f"{kind}_main_launcher")
        launcher["cluster_id"] = cluster_id
        launcher["ib_devices"].update(allow_no_usable_devices=True, device_filter=[])
        # Mgmtd's launcher loads FDB directly and has no mgmtd_client object.
        if "mgmtd_client" in launcher:
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
    # StorageServer installs Components.getCoroutinesPool for ingress. Its
    # default workers retain a whole nested helper RPC until downstream joins;
    # the processor limit above cannot enlarge that distinct custom pool.
    # Leave ingress room beyond the helper runtime's 64 admitted requests for
    # control RPCs and other default-pool methods in this single-node profile.
    store["coroutines_pool_default"]["coroutines_num"] = 128
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
    if gc:
        store["targets"]["ec_exact_gc"] = True
        store["storage"].update(enable_ec_gc=True, ec_gc_key_file=f"{root}/secrets/gc.key",
                                ec_gc_key_id=gc["key_id"], ec_gc_authority=gc["authority"])
    if file_api:
        store["storage"].update(enable_ec_rmw=True, ec_rmw_key_file=f"{root}/secrets/rmw.key",
            ec_rmw_authority=authority, ec_rmw_transport=copy.deepcopy(store["client"]),
            ec_rmw_client=copy.deepcopy(configs["meta_main.toml"]["server"]["storage_client"]))
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
    if gc:
        admin["client_uuid"] = gc["client_namespace"]
    configs["admin_cli.toml"] = admin
    client_path = source / "scripts/ec/stripe-client.example.toml"
    hashes[str(client_path.relative_to(source))] = hashlib.sha256(client_path.read_bytes()).hexdigest()
    client = tomllib.loads(client_path.read_text(encoding="utf-8"))
    client.update(cluster_id=cluster_id, worker_threads=2, max_operations=1,
                  max_application_bytes=33554432, write_fragments=2, read_blocks=1)
    client["user_info"].update(**user, token_file=f"{root}/client/user.token")
    client["mgmtd_client"]["mgmtd_server_addresses"] = [mgmtd_address]
    configs["stripe-client.toml"] = client
    if file_api:
        file_client = {key: copy.deepcopy(client[key]) for key in
                       ("cluster_id", "worker_threads", "deadline_seconds", "user_info",
                        "mgmtd_client", "meta_client", "storage_client") if key in client}
        file_client["client"] = {"force_use_tcp": True}
        file_client["log"] = f"INFO:normal; normal=file:path={root}/logs/ec-file.log,async=true,sync_level=ERR"
        configs["file-client.toml"] = file_client
    if profile in ("v2-12", "gc-12", "gc-14"):
        storage = configs.pop("storage_main.toml")
        launcher = configs.pop("storage_main_launcher.toml")
        configs.pop("storage_main_app.toml")
        meta = configs["meta_main.toml"]["server"]["meta"]
        meta["ec_allow_colocated_test_targets"] = False
        manifest = dict(profile=PROFILES[profile], root=root, port_base=port_base)
        for spec in storage_specs(manifest):
            node = copy.deepcopy(storage)
            node["server"]["base"]["groups"][0]["listener"]["listen_port"] = spec["port"]
            node["server"]["targets"]["target_paths"] = [spec["data_path"]]
            node["common"]["log"]["handlers"][0]["file_path"] = f"{root}/logs/{spec['name']}.log"
            configs[spec["stem"] + ".toml"] = node
            configs[spec["stem"] + "_launcher.toml"] = copy.deepcopy(launcher)
            configs[spec["stem"] + "_app.toml"] = {"allow_empty_node_id": False, "node_id": spec["node"]}
    return configs, hashes


def prepare(root, source, port_base, profile="v2", *, file_api=False, user_uid=1000, user_gid=1000):
    if os.name != "posix":
        raise RuntimeError("prepare requires the target Linux filesystem and permission semantics")
    original = root.absolute()
    root = root.resolve()
    if root != original or not root.name.startswith("3fs-ec-native-") or root.parent == Path("/"):
        raise RuntimeError("Use a new absolute, non-symlink task directory named 3fs-ec-native-*")
    if not root.parent.is_dir() or root.exists():
        raise RuntimeError("Parent must exist; the task directory must not exist (no overwrite or adoption)")
    user = authenticated_user({"authenticated_user": {"uid": user_uid, "gid": user_gid}})
    count = storage_process_count({"profile": PROFILES.get(profile)})
    if type(port_base) is not int or not 1024 <= port_base <= 65535 - (count + 2):
        raise RuntimeError("port-base leaves insufficient consecutive ports for this profile")
    authority, cluster_id = str(uuid.uuid4()), "ec_native_" + secrets.token_hex(6)
    gc = None
    if profile in ("gc", "gc-12", "gc-14"):
        gc = {"authority": str(uuid.uuid4()), "key_id": str(uuid.uuid4()), "client_namespace": str(uuid.uuid4()),
              "data_protocol": 2, "disk_format": 3, "gc_protocol": 2 if file_api else 1}
    configs, hashes = generate_configs(source.resolve(strict=True), root, port_base, authority, cluster_id,
                                       profile=profile, gc=gc, file_api=file_api,
                                       user_uid=user["uid"], user_gid=user["gid"])
    root.mkdir(mode=0o700)
    for name in ("config", "secrets", "client", "state", "logs", "scripts", "data", "bin", "lib", "provenance"):
        (root / name).mkdir(mode=0o700)
    if file_api:
        (root / "client/runs").mkdir(mode=0o700)
        (root / "client/outputs").mkdir(mode=0o700)
    roles = ("data", "control", "helper", "gc") if gc else ("data", "control", "helper")
    for role in (roles + ("rmw",) if file_api else roles):
        write_new(root / "secrets" / f"{role}.key", secrets.token_bytes(32))
    for name, data in configs.items():
        destination = root / ("client" if name in ("stripe-client.toml", "file-client.toml") else "config") / name
        write_new(destination, to_toml(data))
    write_new(root / "config/fdb.cluster", f"{cluster_id}:{secrets.token_hex(8)}@127.0.0.1:{port_base}\n")
    endpoints = [{"node": 10001 + (i if count > 1 else 0), "chain": 910001 + i, "target": 1100001 + i} for i in range(14 if count == 14 else 12)]
    write_new(root / "config/chains.csv", "ChainId,TargetId\n" + "".join(f"{e['chain']},{e['target']}\n" for e in endpoints))
    write_new(root / "config/chain-table.csv", "ChainId\n" + "".join(f"{e['chain']}\n" for e in endpoints))
    manifest = {"schema": 1, "profile": PROFILES[profile], "root": str(root), "cluster_id": cluster_id,
        "authenticated_user": user,
        "authority": authority, "port_base": port_base, "storage_count": count, "logical_target_count": len(endpoints),
        "independent_storage_failure_domains": 1, "endpoints": endpoints, "source_config_sha256": hashes,
        "fdb_version": "7.3.63", "state": "prepared_not_started", "performance_validated": False}
    if gc:
        manifest["gc"] = gc
    if file_api:
        manifest["file_api"] = True
    if count > 1:
        manifest["storage_process_failure_domains"] = count
        manifest["deployment_scope"] = "single_machine_distinct_processes_not_physical_hosts"
        manifest["remote_global_storage_config_policy"] = "pinned_local_mismatch_rejected_not_version_acked"
    if count == 14:
        manifest.update(initial_placement_nodes=list(range(10001, 10013)), spare_nodes=[10013, 10014])
    write_new(root / "cluster.json", json_text(manifest))
    for name in ("generate.py", "run-cluster.py", "native_v2_config.py", "native-v2.py", "fetch-fdb.sh",
                 "experiment-runner.py", "experiment-menu.py", "file-command.py", "ack-service-acceptance.py",
                 "ack-expected-scripts.json", "gc-acceptance.py", "native_fault_control.py"):
        shutil.copy2(Path(__file__).parent / name, root / "scripts" / name)
    print(f"Prepared {root}: private keys and configuration only; no services, targets or database opened.")


def pool_from_observations(manifest, observations):
    expected_count = len(manifest["endpoints"])
    if expected_count not in (12, 14) or len(observations) != expected_count:
        raise ValueError("Require every fixed endpoint fresh administrator-verified observation")
    pool = []
    for expected, observation in zip(manifest["endpoints"], observations, strict=True):
        if any(type(observation.get(k)) is not int for k in ("schema", "protocol", "node", "chain", "target")) or \
                observation.get("schema") != 1 or observation.get("protocol") != 2 or \
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
    if len({(p["chain"], p["target"]) for p in pool}) != expected_count:
        raise ValueError("Duplicate logical endpoint")
    if manifest.get("profile") in (MULTI_PROFILE, MULTI_GC_PROFILE, SPARE_GC_PROFILE):
        if len({p["node"] for p in pool}) != expected_count or len({p["engine_uuid"] for p in pool}) != expected_count or \
                len({p["target_incarnation"] for p in pool}) != expected_count:
            raise ValueError("Twelve-process topology requires twelve actual independent Engine/target identities")
    return pool


def gc_inventory_from_observations(manifest, pool, observations, now_seconds):
    """Cross-check fresh verified RPC29 exports against C-discovered instances.

    Exports are audit observations, never a reusable authorization or receipt.
    Boot nonce and timestamps remain in each run's exports, not the persistent
    inventory compared on restart. Meta RPC38/39 performs fresh discovery again.
    """
    gc = gc_settings(manifest)
    if type(now_seconds) is not int or now_seconds <= 0:
        raise ValueError("Discovery comparison time must be a positive integer")
    if gc is None or len(pool) not in (12, 14) or len(observations) != len(pool):
        raise ValueError("Require the GC profile and twelve actual C/G observations")
    inventory, boots, boots_by_node = [], set(), {}
    for endpoint, observed in zip(pool, observations, strict=True):
        integers = ("schema", "discovery_protocol", "node", "chain", "target", "data_protocol",
                    "disk_format", "gc_protocol", "capabilities")
        if any(type(observed.get(key)) is not int for key in integers) or \
                any(type(endpoint.get(key)) is not int for key in ("node", "chain", "target")):
            raise ValueError("G discovery identity/version fields must be integers, not booleans or floats")
        if observed.get("schema") != 1 or observed.get("discovery_protocol") != 2 or \
                observed.get("verification") != "gc_mac_verified" or \
                observed.get("authority") != gc["authority"] or observed.get("key_id") != gc["key_id"] or \
                any(observed.get(key) != value for key, value in endpoint.items()):
            raise ValueError("G observation does not bind the configured authority and actual C instance")
        if (observed.get("data_protocol"), observed.get("disk_format"), observed.get("capabilities")) != (2, 3, 3) or \
                observed["gc_protocol"] not in (1, 2) or observed["gc_protocol"] < gc["gc_protocol"]:
            raise ValueError("Actual target does not admit format-3 Collect and Query at the required GC protocol")
        observed_at, verified_at = observed.get("observed_at_seconds"), observed.get("verified_at_seconds")
        if type(observed_at) is not int or type(verified_at) is not int or \
                not 0 < observed_at <= verified_at <= now_seconds or now_seconds - observed_at > 60:
            raise ValueError("G discovery is not a fresh observation")
        boot = nonzero_uuid(observed.get("boot_nonce"))
        boots.add(boot)
        boots_by_node.setdefault(endpoint["node"], set()).add(boot)
        # Record actual observed support, never project the requested minimum
        # back into the observation. G2 explicitly includes G1 support.
        inventory.append(dict(endpoint, data_protocol=2, disk_format=3, gc_protocol=observed["gc_protocol"]))
    if storage_process_count(manifest) == 1:
        if len(boots) != 1:
            raise ValueError("One-Storage profile observed multiple process boot sessions; retry startup")
    elif len(boots_by_node) != len(pool) or len(boots) != len(pool) or any(len(values) != 1 for values in boots_by_node.values()):
        raise ValueError("Twelve-process discovery must bind a distinct live boot session to each Storage node")
    return inventory
