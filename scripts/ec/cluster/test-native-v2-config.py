#!/usr/bin/env python3
"""Pure configuration checks; no services, databases, keys or target directories."""
import argparse
import ast
import contextlib
import copy
import io
from pathlib import Path, PurePosixPath
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

from native_v2_config import (GC_PROFILE, PROFILE, PROFILES, authenticated_user, validate_initialized_user,
                              gc_inventory_from_observations, gc_settings,
                              generate_configs, key_roles, pool_from_observations,
                              profile_config_problems, to_toml)
import native_v2_config as configuration


class AuthenticatedLabUser(unittest.TestCase):
    def test_defaults_and_rejects_ambiguous_or_reserved_user_identity(self):
        self.assertEqual(authenticated_user({}), {"uid": 1000, "gid": 1000})
        self.assertEqual(authenticated_user({"authenticated_user": {"uid": 2345, "gid": 3456}}),
                         {"uid": 2345, "gid": 3456})
        for user in (None, [], {}, {"uid": 2345}, {"uid": 2345, "gid": 3456, "other": 1},
                     {"uid": True, "gid": 1000}, {"uid": 0, "gid": 1000},
                     {"uid": "2345", "gid": 1000}, {"uid": 1 << 32, "gid": 1000},
                     {"uid": (1 << 32) - 1, "gid": 1000}, {"uid": 2345, "gid": False},
                     {"uid": 2345, "gid": -1}, {"uid": 2345, "gid": (1 << 32) - 1}):
            with self.subTest(user=user), self.assertRaises(ValueError):
                authenticated_user({"authenticated_user": user})

    def test_generated_file_and_stripe_configs_only_change_explicit_user(self):
        source = Path(__file__).resolve().parents[3]
        authority, gc_authority, key, namespace = (str(uuid.UUID(int=n)) for n in range(80, 84))
        gc = dict(authority=gc_authority, key_id=key, client_namespace=namespace,
                  data_protocol=2, disk_format=3, gc_protocol=2)
        root = "/tmp/3fs-ec-native-user-test"
        manifest = dict(profile=GC_PROFILE, root=root, port_base=13500, authority=authority, gc=gc, file_api=True,
                        authenticated_user={"uid": 2345, "gid": 3456})
        default, default_hashes = generate_configs(source, root, 13500, authority, "user-test",
                                                  profile="gc", gc=gc, file_api=True)
        actual, hashes = generate_configs(source, root, 13500, authority, "user-test",
                                         profile="gc", gc=gc, file_api=True, user_uid=2345, user_gid=3456)
        self.assertEqual(hashes, default_hashes)
        for name in ("stripe-client.toml", "file-client.toml"):
            self.assertEqual(default[name]["user_info"]["uid"], 1000)
            self.assertEqual(default[name]["user_info"]["gid"], 1000)
            default[name]["user_info"].update(uid=2345, gid=3456)
        self.assertEqual(actual, default)
        # These are Linux configuration strings; only the pure path comparison
        # uses a POSIX flavour when this test runs on Windows.
        with mock.patch("native_v2_config.Path", PurePosixPath):
            self.assertEqual(profile_config_problems(manifest, actual), [])
            for name in ("stripe-client.toml", "file-client.toml"):
                for key in ("uid", "gid"):
                    wrong = copy.deepcopy(actual)
                    wrong[name]["user_info"][key] = 1000
                    with self.subTest(name=name, key=key):
                        self.assertTrue(profile_config_problems(manifest, wrong))
            legacy = dict(manifest)
            legacy.pop("authenticated_user")
            self.assertTrue(profile_config_problems(legacy, actual))

    def test_existing_initialization_never_migrates_user_or_cluster(self):
        legacy = dict(schema=1, cluster_id="fixed")
        validate_initialized_user(legacy, legacy)
        current = dict(legacy, authenticated_user={"uid": 2345, "gid": 3456})
        validate_initialized_user(current, copy.deepcopy(current))
        for manifest, state in ((current, legacy), (legacy, current),
                                (current, dict(current, authenticated_user={"uid": 2345, "gid": 3457})),
                                (current, dict(current, cluster_id="changed")),
                                (current, dict(current, schema=True))):
            with self.subTest(manifest=manifest, state=state), self.assertRaises(ValueError):
                validate_initialized_user(manifest, state)

    def test_real_prepare_parser_forwards_pair_and_rejects_nonprepare_overrides(self):
        # Execute the real main's parsing/prepare branch, with no Linux imports,
        # disk preparation or service entry. An unexpected later path must fail.
        path = Path(__file__).with_name("native-v2.py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        create = mock.Mock()
        load = mock.Mock(side_effect=AssertionError("must not inspect an existing root"))
        system = SimpleNamespace(platform="linux", argv=[])
        namespace = dict(argparse=argparse, Path=Path, sys=system, os=SimpleNamespace(umask=mock.Mock()),
                         __file__=str(path), __doc__="parser test", PROFILES=PROFILES,
                         authenticated_user=authenticated_user, requested_transport=configuration.requested_transport,
                         prepare=create, load_manifest=load)
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
        for flags, expected in (([], {"uid": 1000, "gid": 1000}),
                                (["--user-uid", "2345", "--user-gid", "3456"], {"uid": 2345, "gid": 3456})):
            system.argv = [str(path), "prepare", "--root", "/unused", "--profile", "gc", "--file-api", *flags]
            with mock.patch("sys.argv", system.argv):
                self.assertEqual(namespace["main"](), 0)
            self.assertEqual(create.call_args.kwargs,
                             dict(file_api=True, user_uid=expected["uid"], user_gid=expected["gid"],
                                  transport="tcp", rdma_interface=None, rdma_address=None, rdma_device=None))
        for command, flags in [("prepare", ["--user-uid", "2345"]), ("prepare", ["--user-gid", "3456"])] + [
                (command, ["--user-uid", "2345", "--user-gid", "3456"])
                for command in ("start", "doctor", "status", "stop", "fault-storage")]:
            system.argv = [str(path), command, "--root", "/unused", *flags]
            with self.subTest(command=command), mock.patch("sys.argv", system.argv), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                namespace["main"]()
        self.assertEqual(create.call_count, 2)
        load.assert_not_called()

    def test_user_bootstrap_forwards_primary_gid_to_real_admin_command_builder(self):
        path = Path(__file__).with_name("native-v2.py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        cluster = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "NativeCluster")
        node = next(n for n in cluster.body if isinstance(n, ast.FunctionDef) and n.name == "add_user")
        namespace = {"re": re}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
        token = "A" * 24
        owner = SimpleNamespace(run_id="fixed-run", admin=mock.Mock(return_value=f"Token {token}(Expired at N/A)"))
        cases = [(2345, "ordinary", False, {"gid": 3456}, ["user-add", "--gid", "3456", "2345", "ordinary"]),
                 (1000, "legacy", False, {}, ["user-add", "1000", "legacy"]),
                 (0, "administrator", True, {}, ["user-add", "--root", "--admin", "0", "administrator"])]
        for uid, name, administrator, options, expected in cases:
            with self.subTest(uid=uid):
                self.assertEqual(namespace["add_user"](owner, uid, name, administrator, **options), token)
                owner.admin.assert_called_with(expected, f"fixed-run-create-user-{uid}.log", secret=True)


class NativeV2Configuration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = "76800862-07b8-4b3b-9638-19cfed87e2e0"
        cls.configs, cls.hashes = generate_configs(Path(__file__).resolve().parents[3],
            "/tmp/3fs-ec-native-config-test", 13500, cls.authority, "test_native_config")

    def test_bootstrap_cannot_issue_v2_grants_before_discovery(self):
        meta = self.configs["meta_main.toml"]["server"]["meta"]
        self.assertTrue(meta["authenticate"])
        self.assertFalse(meta["enable_ec_v2"])
        self.assertNotIn("ec_targets", meta)
        self.assertFalse(meta["ec_allow_unauthorized_storage_for_tests"])
        client = to_toml(self.configs["stripe-client.toml"])
        for secret in ("data.key", "control.key", "helper.key", "admin_cli"):
            self.assertNotIn(secret, client)
        self.assertEqual(self.configs["stripe-client.toml"]["user_info"]["uid"], 1000)

    def test_tcp_listener_is_reachable_without_rdma_or_external_nics(self):
        for kind, service, port in [("mgmtd", "Mgmtd", 13501), ("meta", "MetaSerde", 13502),
                                    ("storage", "StorageSerde", 13503)]:
            data = self.configs[f"{kind}_main.toml"]
            group, = data["server"]["base"]["groups"]
            self.assertEqual(group["network_type"], "TCP")
            self.assertEqual(group["services"], [service, "Core"])
            self.assertEqual(group["listener"]["filter_list"], ["lo"])
            self.assertEqual(group["listener"]["custom_tcp_nic_prefix"], "lo")
            self.assertEqual(group["listener"]["listen_port"], port)
            self.assertTrue(self.configs[f"{kind}_main_launcher.toml"]["ib_devices"]["allow_no_usable_devices"])
            to_toml(data)  # Existing generator checks the complete TOML round trip.
        # MgmtdLauncherConfig uses FDB directly; ServerLauncherConfig (used by
        # Meta and Storage) contains the mgmtd client. The real Mgmtd binary
        # rejects an injected mgmtd_client section before it can start.
        self.assertNotIn("mgmtd_client", self.configs["mgmtd_main_launcher.toml"])
        for kind in ("meta", "storage"):
            self.assertEqual(self.configs[f"{kind}_main_launcher.toml"]["mgmtd_client"]["network_type"], "TCP")

    def test_one_engine_profile_has_bounded_positive_io_resources(self):
        storage = self.configs["storage_main.toml"]["server"]
        self.assertEqual(len(storage["targets"]["target_paths"]), 1)
        self.assertTrue(storage["targets"]["ec_only"])
        self.assertTrue(storage["targets"]["ec_staging_v2"])
        self.assertNotIn("only_chunk_engine", storage["targets"])
        self.assertNotIn("allow_existing_targets", storage["targets"])
        self.assertEqual(storage["aio_read_worker"]["num_threads"], 1)
        self.assertEqual(storage["buffer_pool"]["rdmabuf_count"], 16)
        self.assertEqual(storage["buffer_pool"]["big_rdmabuf_count"], 4)
        self.assertFalse(storage["storage"]["allow_unsafe_ec_fragment_rpc_for_testing"])
        self.assertEqual(storage["mgmtd"]["network_type"], "TCP")

    def test_only_storage_service_expands_slots_for_nested_helper_requests(self):
        storage = self.configs["storage_main.toml"]["server"]
        processor = storage["base"]["groups"][0]["processor"]
        self.assertEqual(processor["max_coroutines_num"], 128)
        self.assertEqual(processor["max_processing_requests_num"], 128)
        self.assertGreater(processor["max_coroutines_num"], 10 * 4)
        # Production StorageServer bypasses the processor coroutine pool with
        # its own getter. Nested helpers retain those ingress workers as well.
        self.assertGreater(storage["coroutines_pool_default"]["coroutines_num"], 64)
        self.assertEqual(storage["coroutines_pool_default"]["threads_num"], 1)
        self.assertEqual(storage["storage"]["max_concurrent_ec_requests"], 16)
        for kind in ("mgmtd", "meta"):
            other = self.configs[f"{kind}_main.toml"]["server"]["base"]["groups"][0]["processor"]
            self.assertEqual(other["max_coroutines_num"], 32)
            self.assertEqual(other["max_processing_requests_num"], 128)

    def observation_fixture(self):
        endpoints = [{"node": 10001, "chain": 910001 + i, "target": 1100001 + i} for i in range(12)]
        manifest = {"authority": self.authority, "endpoints": endpoints}
        observations = [dict(endpoint, schema=1, protocol=2, authority=self.authority,
            verification="control_mac_verified", engine_uuid="cbeae9fc-e4dc-4b4d-b027-07946088079b",
            target_incarnation=str(uuid.UUID(int=i + 1))) for i, endpoint in enumerate(endpoints)]
        return manifest, observations

    def test_discovered_pool_preserves_actual_instance_and_fixed_logical_order(self):
        manifest, observations = self.observation_fixture()
        pool = pool_from_observations(manifest, observations)
        self.assertEqual(len(pool), 12)
        self.assertEqual(len({entry["engine_uuid"] for entry in pool}), 1)
        self.assertEqual(len({entry["target_incarnation"] for entry in pool}), 12)
        changed = copy.deepcopy(observations)
        changed[0]["target_incarnation"] = str(uuid.UUID(int=100))
        self.assertNotEqual(pool, pool_from_observations(manifest, changed))

    def test_incomplete_wrong_authority_wrong_endpoint_and_zero_instance_are_rejected(self):
        manifest, observations = self.observation_fixture()
        with self.assertRaises(ValueError):
            pool_from_observations(manifest, observations[:-1])
        for field, value in (("authority", str(uuid.UUID(int=1))), ("node", 10002), ("chain", 1), ("target", 1),
                             ("protocol", 1), ("verification", "unverified"), ("engine_uuid", str(uuid.UUID(int=0))),
                             ("target_incarnation", "not-a-uuid")):
            wrong = copy.deepcopy(observations)
            wrong[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                pool_from_observations(manifest, wrong)


class NativeGcConfiguration(unittest.TestCase):
    def setUp(self):
        # Validate Linux configuration paths even on a Windows authoring host.
        self.enterContext(mock.patch("native_v2_config.Path", PurePosixPath))

    @classmethod
    def setUpClass(cls):
        NativeV2Configuration.setUpClass.__func__(cls)

    observation_fixture = NativeV2Configuration.observation_fixture
    def gc_fixture(self):
        manifest, c_observations = self.observation_fixture()
        manifest.update(profile=GC_PROFILE, root="/tmp/3fs-ec-native-gc-config-test", port_base=13500, gc={
            "authority": str(uuid.UUID(int=80)), "key_id": str(uuid.UUID(int=81)),
            "client_namespace": str(uuid.UUID(int=82)),
            "data_protocol": 2, "disk_format": 3, "gc_protocol": 1})
        configs, _ = generate_configs(Path(__file__).resolve().parents[3], manifest["root"],
            13500, self.authority, "test_native_gc", profile="gc", gc=manifest["gc"])
        pool = pool_from_observations(manifest, c_observations)
        g_observations = [dict(endpoint, schema=1, discovery_protocol=2,
            authority=manifest["gc"]["authority"], key_id=manifest["gc"]["key_id"],
            data_protocol=2, disk_format=3, gc_protocol=1, capabilities=3,
            boot_nonce=str(uuid.UUID(int=83)), observed_at_seconds=990, verified_at_seconds=995,
            verification="gc_mac_verified") for endpoint in pool]
        return manifest, configs, pool, g_observations

    def test_gc_is_explicit_and_bootstrap_meta_cannot_issue_gc_or_retirement(self):
        manifest, configs, _, _ = self.gc_fixture()
        meta, storage = configs["meta_main.toml"]["server"]["meta"], configs["storage_main.toml"]["server"]
        self.assertTrue(storage["targets"]["ec_exact_gc"])
        self.assertTrue(storage["targets"]["ec_staging_v2"])
        self.assertTrue(storage["storage"]["enable_ec_gc"])
        for flag in ("enable_ec_v2", "enable_ec_exact_gc", "enable_ec_revision_retirement"):
            self.assertFalse(meta[flag])
        self.assertNotIn("ec_targets", meta)
        self.assertEqual(meta["ec_gc_key_file"], manifest["root"] + "/secrets/gc.key")
        self.assertEqual(meta["ec_gc_authority"], storage["storage"]["ec_gc_authority"])
        self.assertNotEqual(meta["ec_gc_authority"], meta["ec_v2_control_authority"])
        self.assertEqual(configs["admin_cli.toml"]["client_uuid"], manifest["gc"]["client_namespace"])
        self.assertEqual(key_roles(manifest), ("data", "control", "helper", "gc"))
        self.assertEqual(profile_config_problems(manifest, configs), [])
        for config in configs.values():
            to_toml(config)
        user = to_toml(configs["stripe-client.toml"])
        for private in ("gc.key", manifest["gc"]["key_id"], manifest["gc"]["client_namespace"]):
            self.assertNotIn(private, user)

    def test_default_v2_never_selects_gc_or_a_stable_admin_identity(self):
        self.assertNotIn("ec_exact_gc", self.configs["storage_main.toml"]["server"]["targets"])
        self.assertNotIn("enable_ec_gc", self.configs["storage_main.toml"]["server"]["storage"])
        self.assertNotIn("enable_ec_exact_gc", self.configs["meta_main.toml"]["server"]["meta"])
        self.assertNotIn("client_uuid", self.configs["admin_cli.toml"])
        manifest = {"profile": PROFILE, "root": "/tmp/3fs-ec-native-config-test", "port_base": 13500}
        self.assertIsNone(gc_settings(manifest))
        self.assertEqual(key_roles(manifest), ("data", "control", "helper"))
        self.assertEqual(profile_config_problems(manifest, self.configs), [])

    def test_profile_cannot_relabel_v2_root_or_accept_invalid_gc_identity(self):
        manifest, _, _, _ = self.gc_fixture()
        wrong = copy.deepcopy(manifest)
        wrong["profile"] = PROFILE
        with self.assertRaises(ValueError):
            gc_settings(wrong)
        for field, value in (("authority", self.authority), ("key_id", str(uuid.UUID(int=0))),
                             ("client_namespace", "not-a-uuid"), ("disk_format", 2), ("gc_protocol", 2),
                             ("data_protocol", 2.0), ("disk_format", 3.0), ("gc_protocol", True)):
            wrong = copy.deepcopy(manifest)
            wrong["gc"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                gc_settings(wrong)

    def test_config_drift_fails_before_target_open(self):
        manifest, configs, _, _ = self.gc_fixture()
        for section, field, value in (("targets", "ec_exact_gc", False),
                ("storage", "enable_ec_gc", False), ("storage", "ec_gc_authority", self.authority)):
            wrong = copy.deepcopy(configs)
            wrong["storage_main.toml"]["server"][section][field] = value
            self.assertTrue(profile_config_problems(manifest, wrong))
        for field in ("enable_ec_exact_gc", "enable_ec_revision_retirement"):
            wrong = copy.deepcopy(configs)
            wrong["meta_main.toml"]["server"]["meta"][field] = True
            self.assertTrue(profile_config_problems(manifest, wrong))
        wrong = copy.deepcopy(configs)
        wrong["admin_cli.toml"]["client_uuid"] = str(uuid.UUID(int=84))
        self.assertTrue(profile_config_problems(manifest, wrong))
        wrong = copy.deepcopy(self.configs)
        wrong["storage_main.toml"]["server"]["targets"]["ec_exact_gc"] = True
        self.assertTrue(profile_config_problems(
            {"profile": PROFILE, "root": "/tmp/3fs-ec-native-config-test", "port_base": 13500}, wrong))
        for section, fields in (("targets", ("ec_only", "ec_staging_v2", "ec_exact_gc")),
                                ("storage", ("enable_ec_fragments", "enable_ec_gc"))):
            for field in fields:
                for value in (1, 1.0, "true", None):
                    wrong = copy.deepcopy(configs)
                    wrong["storage_main.toml"]["server"][section][field] = value
                    with self.subTest(section=section, field=field, value=value):
                        self.assertTrue(profile_config_problems(manifest, wrong))
        for field in ("enable_ec_v2", "enable_ec_exact_gc", "enable_ec_revision_retirement"):
            for value in (0, 1, 0.0, "false", None):
                wrong = copy.deepcopy(configs)
                wrong["meta_main.toml"]["server"]["meta"][field] = value
                with self.subTest(field=field, value=value):
                    self.assertTrue(profile_config_problems(manifest, wrong))

    def test_gc_inventory_preserves_instances_but_not_old_boot_observations(self):
        manifest, _, pool, observed = self.gc_fixture()
        inventory = gc_inventory_from_observations(manifest, pool, observed, 1000)
        self.assertEqual(len(inventory), 12)
        self.assertEqual(inventory[0]["engine_uuid"], pool[0]["engine_uuid"])
        self.assertEqual(inventory[0]["disk_format"], 3)
        self.assertNotIn("boot_nonce", inventory[0])
        restarted = [dict(item, boot_nonce=str(uuid.UUID(int=84)), observed_at_seconds=1990,
                          verified_at_seconds=1995) for item in observed]
        self.assertEqual(inventory, gc_inventory_from_observations(manifest, pool, restarted, 2000))
        newer = [dict(item, gc_protocol=2) for item in observed]
        actual = gc_inventory_from_observations(manifest, pool, newer, 1000)
        self.assertEqual({item["gc_protocol"] for item in actual}, {2})
        file_manifest = dict(manifest, file_api=True, gc=dict(manifest["gc"], gc_protocol=2))
        self.assertEqual(actual, gc_inventory_from_observations(file_manifest, pool, newer, 1000))
        with self.assertRaises(ValueError):
            gc_inventory_from_observations(file_manifest, pool, observed, 1000)

    def test_missing_stale_wrong_instance_wrong_format_and_readonly_are_not_success(self):
        manifest, _, pool, observed = self.gc_fixture()
        with self.assertRaises(ValueError):
            gc_inventory_from_observations(manifest, pool, observed[:-1], 1000)
        for field, value in (("verification", "unverified"), ("authority", self.authority),
                ("key_id", str(uuid.UUID(int=85))), ("engine_uuid", str(uuid.UUID(int=86))),
                ("target_incarnation", str(uuid.UUID(int=87))), ("chain", 1), ("target", 1),
                ("data_protocol", 3), ("disk_format", 2), ("gc_protocol", 3), ("capabilities", 2),
                ("boot_nonce", str(uuid.UUID(int=0))), ("observed_at_seconds", 900),
                ("verified_at_seconds", 1001), ("observed_at_seconds", "990"),
                ("schema", True), ("discovery_protocol", 2.0), ("node", 10001.0),
                ("chain", 910001.0), ("target", 1100001.0), ("data_protocol", 2.0),
                ("disk_format", 3.0), ("gc_protocol", True), ("capabilities", 3.0)):
            wrong = copy.deepcopy(observed)
            wrong[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                gc_inventory_from_observations(manifest, pool, wrong, 1000)
        for value in (True, False, 1000.0, "1000", 0, -1):
            with self.subTest(now_seconds=value), self.assertRaises(ValueError):
                gc_inventory_from_observations(manifest, pool, observed, value)
        for field in ("node", "chain", "target"):
            wrong = copy.deepcopy(pool)
            wrong[0][field] = float(wrong[0][field])
            with self.subTest(pool_field=field), self.assertRaises(ValueError):
                gc_inventory_from_observations(manifest, wrong, observed, 1000)

    def test_one_storage_boot_cannot_change_mid_inventory(self):
        manifest, _, pool, observed = self.gc_fixture()
        observed[0]["boot_nonce"] = str(uuid.UUID(int=84))
        with self.assertRaises(ValueError):
            gc_inventory_from_observations(manifest, pool, observed, 1000)


class ExplicitDataTransport(unittest.TestCase):
    OPTIONS = dict(transport="rdma", rdma_interface="enp1s0", rdma_address="192.0.2.17", rdma_device="mlx5_0")

    def setUp(self):
        self.enterContext(mock.patch("native_v2_config.Path", PurePosixPath))

    def fixture(self, file_api=False):
        manifest = dict(profile=GC_PROFILE if file_api else PROFILE, root="/tmp/3fs-ec-native-rdma-test",
                        port_base=15000, authority=str(uuid.UUID(int=90)), file_api=file_api)
        if file_api:
            manifest["gc"] = dict(authority=str(uuid.UUID(int=91)), key_id=str(uuid.UUID(int=92)),
                                  client_namespace=str(uuid.UUID(int=93)), data_protocol=2, disk_format=3, gc_protocol=2)
        manifest["data_transport"] = configuration.requested_transport(**self.OPTIONS)
        configs, _ = generate_configs(Path(__file__).resolve().parents[3], manifest["root"], 15000,
            manifest["authority"], "rdma-test", profile="gc" if file_api else "v2",
            gc=manifest.get("gc"), file_api=file_api, **self.OPTIONS)
        return manifest, configs

    def test_transport_input_and_manifest_reject_ambiguous_or_noncanonical_values(self):
        self.assertIsNone(configuration.requested_transport())
        self.assertIsNone(configuration.requested_transport(transport="tcp"))
        self.assertIsNone(configuration.transport_settings({}))
        expected = {"schema": 1, "mode": "rdma", "interface": "enp1s0", "ipv4": "192.0.2.17", "ib_device": "mlx5_0"}
        self.assertEqual(configuration.requested_transport(**self.OPTIONS), expected)
        self.assertEqual(configuration.transport_settings({"data_transport": expected}), expected)
        for field, value in (("transport", "auto"), ("transport", None), ("transport", "TCP"),
                             ("rdma_interface", None), ("rdma_interface", "lo"), ("rdma_interface", "eth0:1"),
                             ("rdma_interface", "x" * 16), ("rdma_interface", "../eth0"),
                             ("rdma_device", "mlx5 0"), ("rdma_device", "mlx5_0\n"),
                             ("rdma_address", "127.0.0.1"), ("rdma_address", "0.0.0.0"),
                             ("rdma_address", "224.0.0.1"), ("rdma_address", "255.255.255.255"),
                             ("rdma_address", "192.0.2.017"), ("rdma_address", "::1")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                configuration.requested_transport(**dict(self.OPTIONS, **{field: value}))
        with self.assertRaises(ValueError):
            configuration.requested_transport(transport="tcp", rdma_device="mlx5_0")
        for changed in (None, {}, [], dict(expected, schema=True), dict(expected, schema=2),
                        dict(expected, mode="tcp"), dict(expected, extra=True)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                configuration.transport_settings({"data_transport": changed})

    def test_initialized_transport_is_fixed_in_both_directions(self):
        legacy = {"schema": 1, "cluster_id": "fixed"}
        current = dict(legacy, data_transport=configuration.requested_transport(**self.OPTIONS))
        configuration.validate_initialized_profile(legacy, dict(legacy))
        configuration.validate_initialized_profile(current, copy.deepcopy(current))
        for left, right in ((legacy, current), (current, legacy),
                            (current, dict(current, data_transport=dict(current["data_transport"], ipv4="192.0.2.18"))),
                            (current, dict(current, authenticated_user={"uid": 1100, "gid": 1100}))):
            with self.subTest(left=left, right=right), self.assertRaises(ValueError):
                configuration.validate_initialized_profile(left, right)
        # The old user-only API remains available; it does not migrate transport.
        configuration.validate_initialized_user(legacy, current)

    def test_single_storage_exact_data_roles_and_groups_reject_drift(self):
        for file_api in (False, True):
            manifest, configs = self.fixture(file_api)
            self.assertEqual(profile_config_problems(manifest, configs), [])
            groups = configs["storage_main.toml"]["server"]["base"]["groups"]
            self.assertEqual([group["services"] for group in groups], [["StorageSerde", "Core"], ["StorageSerde"]])
            self.assertEqual([group["network_type"] for group in groups], ["TCP", "RDMA"])
            self.assertEqual([group["listener"]["listen_port"] for group in groups], [15003, 15004])
            self.assertTrue(configs["storage_main.toml"]["server"]["client"]["force_use_tcp"])
            mutations = [
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"].pop(),
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"].__setitem__(0, None),
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"].append(copy.deepcopy(groups[1])),
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"][1].update(services=["StorageSerde", "Core"]),
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"][1]["listener"].update(filter_list=["lo"]),
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"][1]["listener"].update(reuse_port=0),
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"][1].update(use_independent_thread_pool=0),
                lambda c: c["storage_main.toml"]["server"]["base"]["groups"][0].update(network_type="RDMA"),
                lambda c: c["storage_main.toml"]["server"]["forward_client"].update(force_use_tcp=True),
                lambda c: c["storage_main_launcher.toml"]["ib_devices"].update(allow_no_usable_devices=True),
                lambda c: c["meta_main.toml"]["server"]["meta"].update(ec_storage_transport="tcp"),
                lambda c: c["meta_main.toml"]["server"]["storage_client"]["net_client_for_updates"].update(force_use_tcp=True),
            ]
            if file_api:
                mutations += [
                    lambda c: c["meta_main.toml"]["server"]["meta"]["ec_rmw_transport"].update(force_use_tcp=True),
                    lambda c: c["storage_main.toml"]["server"]["storage"]["ec_rmw_client"]["net_client"].update(force_use_tcp=True),
                    lambda c: c["storage_main.toml"]["server"]["storage"]["ec_rmw_transport"].update(force_use_tcp=False),
                ]
            for index, mutate in enumerate(mutations):
                changed = copy.deepcopy(configs)
                mutate(changed)
                with self.subTest(file_api=file_api, mutation=index):
                    self.assertTrue(profile_config_problems(manifest, changed))
            if file_api:
                for key in ("enable_ec_v2", "enable_ec_exact_gc", "enable_ec_revision_retirement",
                            "enable_ec_rmw", "enable_ec_file_ranges"):
                    configs["meta_main.toml"]["server"]["meta"][key] = True
                self.assertEqual(profile_config_problems(manifest, configs), [])

    def test_shared_client_gate_is_strict_for_rdma_and_preserves_legacy_tcp(self):
        self.assertEqual(configuration.client_transport_problems({}, {}), [])
        self.assertEqual(configuration.client_transport_problems({}, {"custom": "legacy", "storage_transport": "tcp"}), [])
        self.assertTrue(configuration.client_transport_problems({}, {"storage_transport": "rdma"}))
        manifest, configs = self.fixture(True)
        client = configs["file-client.toml"]
        self.assertEqual(configuration.client_transport_problems(manifest, client, file_api=True), [])
        for path, wrong in (("storage_transport", "tcp"), ("client.force_use_tcp", True),
                            ("storage_client.net_client.force_use_tcp", 0),
                            ("storage_client.net_client_for_updates.force_use_tcp", True),
                            ("ib_devices.device_filter", []), ("ib_devices.allow_no_usable_devices", True)):
            changed = copy.deepcopy(client)
            configuration.put(changed, path, wrong)
            with self.subTest(path=path):
                self.assertTrue(configuration.client_transport_problems(manifest, changed, file_api=True))

    def test_complete_listener_interval_and_exact_storage_selection(self):
        for profile, count in (("v2", 1), ("v2-12", 12), ("gc-14", 14)):
            manifest = dict(profile=PROFILES[profile], root="/tmp/3fs-ec-native-ports", port_base=65535 - (2 * count + 2),
                            data_transport=configuration.requested_transport(**self.OPTIONS))
            result = configuration.transport_listeners(manifest)
            self.assertEqual(result, [("127.0.0.1", manifest["port_base"] + i) for i in range(count + 3)] +
                             [("192.0.2.17", manifest["port_base"] + count + 3 + i) for i in range(count)])
            self.assertEqual(result[-1][1], 65535)
            self.assertEqual(configuration.transport_listeners(manifest, node=10000 + count),
                             [("127.0.0.1", manifest["port_base"] + count + 2), ("192.0.2.17", 65535)])
            for node in (True, 10000, 10001 + count, "10001"):
                with self.subTest(node=node), self.assertRaises(ValueError):
                    configuration.transport_listeners(manifest, node=node)
            manifest["port_base"] += 1
            with self.assertRaises(ValueError):
                configuration.transport_listeners(manifest)
            manifest.pop("data_transport")
            manifest["port_base"] = 65535 - (count + 2)
            self.assertEqual(configuration.transport_listeners(manifest)[-1], ("127.0.0.1", 65535))

    def test_prepare_rejects_bad_inputs_before_creating_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "3fs-ec-native-untouched"
            source = Path(__file__).resolve().parents[3]
            with mock.patch.object(configuration.os, "name", "posix"), \
                 mock.patch.object(type(root), "mkdir") as mkdir:
                for kwargs, port, reason in ((dict(self.OPTIONS, rdma_device=None), 15000, "device name"),
                                            (self.OPTIONS, 65532, "additional port interval"),
                                            ({"transport": "tcp", "rdma_address": "192.0.2.17"}, 15000, "explicit RDMA")):
                    with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                        configuration.prepare(root, source, port, **kwargs)
                mkdir.assert_not_called()
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
