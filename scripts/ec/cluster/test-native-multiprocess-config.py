#!/usr/bin/env python3
"""Pure local-12 topology checks; no process, key, target or database startup."""
import copy
import os
from pathlib import Path, PurePosixPath
import sys
import unittest
from unittest import mock
import uuid

SOURCE = Path(os.environ.get("EC_SOURCE", Path(__file__).resolve().parents[3]))
sys.path.append(str(SOURCE / "scripts/ec/cluster"))
from native_v2_config import (GC_PROFILE, MULTI_GC_PROFILE, MULTI_PROFILE, PROFILE, gc_inventory_from_observations,
                              generate_configs, pool_from_observations, profile_config_problems,
                              storage_process_count, storage_specs, topology_problems)
import native_v2_config as configuration


class NativeMultiProcessConfiguration(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch("native_v2_config.Path", PurePosixPath))

    def fixture(self, gc=False):
        manifest = dict(profile=MULTI_GC_PROFILE if gc else MULTI_PROFILE,
                        root="/tmp/3fs-ec-native-local12", port_base=14000, storage_count=12, logical_target_count=12,
                        independent_storage_failure_domains=1, storage_process_failure_domains=12,
                        deployment_scope="single_machine_distinct_processes_not_physical_hosts",
                        remote_global_storage_config_policy="pinned_local_mismatch_rejected_not_version_acked",
                        authority=str(uuid.UUID(int=70)),
                        endpoints=[dict(node=10001+i, chain=910001+i, target=1100001+i) for i in range(12)])
        if gc:
            manifest["gc"] = dict(authority=str(uuid.UUID(int=80)), key_id=str(uuid.UUID(int=81)),
                                  client_namespace=str(uuid.UUID(int=82)), data_protocol=2, disk_format=3, gc_protocol=1)
        return manifest

    def configs(self, manifest):
        return generate_configs(SOURCE, manifest["root"], manifest["port_base"], manifest["authority"], "local12_test",
                                profile="gc-12" if "gc" in manifest else "v2-12", gc=manifest.get("gc"))[0]

    def discoveries(self, manifest):
        control = [dict(endpoint, schema=1, protocol=2, authority=manifest["authority"], verification="control_mac_verified",
                        engine_uuid=str(uuid.UUID(int=100+i)), target_incarnation=str(uuid.UUID(int=200+i)))
                   for i, endpoint in enumerate(manifest["endpoints"])]
        pool = pool_from_observations(manifest, control)
        observed = [dict(endpoint, schema=1, discovery_protocol=2, authority=manifest["gc"]["authority"],
                         key_id=manifest["gc"]["key_id"], data_protocol=2, disk_format=3, gc_protocol=1,
                         capabilities=3, boot_nonce=str(uuid.UUID(int=300+i)), observed_at_seconds=1000,
                         verified_at_seconds=1001, verification="gc_mac_verified") for i, endpoint in enumerate(pool)]
        return control, pool, observed

    def test_twelve_processes_have_distinct_fixed_ports_roots_logs_and_nodes(self):
        manifest = self.fixture()
        configs = self.configs(manifest)
        self.assertEqual(topology_problems(manifest), [])
        self.assertEqual(profile_config_problems(manifest, configs), [])
        self.assertNotIn("storage_main.toml", configs)
        self.assertEqual(len(storage_specs(manifest)), 12)
        self.assertEqual({spec["port"] for spec in storage_specs(manifest)}, set(range(14003, 14015)))
        roots, logs = set(), set()
        for spec in storage_specs(manifest):
            current = configs[spec["stem"] + ".toml"]
            roots.update(current["server"]["targets"]["target_paths"])
            logs.add(current["common"]["log"]["handlers"][0]["file_path"])
            self.assertEqual(current["server"]["coroutines_pool_default"]["coroutines_num"], 128)
            self.assertEqual(configs[spec["stem"] + "_app.toml"]["node_id"], spec["node"])
        self.assertEqual(len(roots), 12)
        self.assertEqual(len(logs), 12)
        self.assertFalse(configs["meta_main.toml"]["server"]["meta"]["ec_allow_colocated_test_targets"])

    def test_three_nodes_four_shards_and_lookalike_counts_are_rejected(self):
        for key, value in (("storage_count", 3), ("storage_count", 12.0), ("logical_target_count", True),
                           ("storage_process_failure_domains", 12.0), ("independent_storage_failure_domains", True),
                           ("independent_storage_failure_domains", 12)):
            manifest = self.fixture()
            manifest[key] = value
            with self.subTest(key=key, value=value):
                self.assertTrue(topology_problems(manifest))
        manifest = self.fixture()
        for i, endpoint in enumerate(manifest["endpoints"]):
            endpoint["node"] = 10001 + i // 4
        self.assertTrue(topology_problems(manifest))

    def test_each_node_config_drift_is_rejected_before_opening_engine(self):
        manifest = self.fixture()
        configs = self.configs(manifest)
        for index in (0, 5, 11):
            for mutation in ("port", "root", "node", "log"):
                changed = copy.deepcopy(configs)
                stem = f"storage-{10001+index}"
                current = changed[stem + ".toml"]
                if mutation == "port": current["server"]["base"]["groups"][0]["listener"]["listen_port"] = 14003.0
                if mutation == "root": current["server"]["targets"]["target_paths"] = ["/tmp/other"]
                if mutation == "node": changed[stem + "_app.toml"]["node_id"] = 10001.0
                if mutation == "log": current["common"]["log"]["handlers"][0]["file_path"] = "/tmp/shared.log"
                with self.subTest(index=index, mutation=mutation):
                    self.assertTrue(profile_config_problems(manifest, changed))

    def test_gc_requires_all_twelve_real_engines_and_distinct_boot_sessions(self):
        manifest = self.fixture(True)
        control, pool, observed = self.discoveries(manifest)
        inventory = gc_inventory_from_observations(manifest, pool, observed, 1002)
        self.assertEqual(len(inventory), 12)
        duplicate = copy.deepcopy(control)
        duplicate[1]["engine_uuid"] = duplicate[0]["engine_uuid"]
        with self.assertRaises(ValueError): pool_from_observations(manifest, duplicate)
        for key, value in (("schema", True), ("protocol", 2.0), ("node", 10002.0)):
            wrong_control = copy.deepcopy(control)
            wrong_control[1][key] = value
            with self.subTest(control_field=key), self.assertRaises(ValueError):
                pool_from_observations(manifest, wrong_control)
        for key, value in (("boot_nonce", observed[0]["boot_nonce"]), ("disk_format", 2),
                           ("disk_format", 3.0), ("engine_uuid", str(uuid.UUID(int=999)))):
            wrong = copy.deepcopy(observed)
            wrong[1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gc_inventory_from_observations(manifest, pool, wrong, 1002)
        restarted = copy.deepcopy(observed)
        for i, row in enumerate(restarted): row["boot_nonce"] = str(uuid.UUID(int=400+i))
        self.assertEqual(inventory, gc_inventory_from_observations(manifest, pool, restarted, 1002))

    def test_gc_gates_stay_closed_until_all_nodes_discovered(self):
        manifest = self.fixture(True)
        configs = self.configs(manifest)
        self.assertEqual(profile_config_problems(manifest, configs), [])
        meta = configs["meta_main.toml"]["server"]["meta"]
        for name in ("enable_ec_v2", "enable_ec_exact_gc", "enable_ec_revision_retirement"):
            self.assertIs(meta[name], False)
        for i in range(12):
            changed = copy.deepcopy(configs)
            changed[f"storage-{10001+i}.toml"]["server"]["targets"]["ec_exact_gc"] = False
            with self.subTest(node=i): self.assertTrue(profile_config_problems(manifest, changed))

    def test_default_one_process_spec_and_port_bound_remain_explicit(self):
        for profile in (PROFILE, GC_PROFILE):
            manifest = dict(profile=profile, root="/tmp/3fs-ec-native-single", port_base=13500)
            self.assertEqual(storage_process_count(manifest), 1)
            self.assertEqual(storage_specs(manifest)[0]["stem"], "storage_main")
            self.assertEqual(storage_specs(manifest)[0]["port"], 13503)
        for value in (65522, True, 14000.0):
            manifest = self.fixture()
            manifest["port_base"] = value
            with self.subTest(port=value), self.assertRaises(ValueError): storage_specs(manifest)

    def test_rdma_twelve_processes_keep_tcp_control_and_unique_data_endpoints(self):
        options = dict(transport="rdma", rdma_interface="enp1s0", rdma_address="192.0.2.17", rdma_device="mlx5_0")
        for use_gc in (False, True):
            manifest = self.fixture(use_gc)
            manifest["data_transport"] = configuration.requested_transport(**options)
            configs, _ = generate_configs(SOURCE, manifest["root"], 14000, manifest["authority"], "rdma12",
                profile="gc-12" if use_gc else "v2-12", gc=manifest.get("gc"), **options)
            self.assertEqual(profile_config_problems(manifest, configs), [])
            self.assertEqual(configuration.transport_listeners(manifest),
                [("127.0.0.1", port) for port in range(14000, 14015)] +
                [("192.0.2.17", port) for port in range(14015, 14027)])
            for i in range(12):
                stem = f"storage-{10001+i}"
                groups = configs[stem + ".toml"]["server"]["base"]["groups"]
                self.assertEqual([(g["network_type"], g["services"], g["listener"]["listen_port"]) for g in groups],
                    [("TCP", ["StorageSerde", "Core"], 14003+i), ("RDMA", ["StorageSerde"], 14015+i)])
                self.assertEqual(configs[stem + "_launcher.toml"]["ib_devices"]["device_filter"], ["mlx5_0"])
                changed = copy.deepcopy(configs)
                changed[stem + ".toml"]["server"]["base"]["groups"][1]["listener"]["listen_port"] = 14015
                if i == 0:
                    changed[stem + ".toml"]["server"]["base"]["groups"][1]["listener"]["listen_port"] = 14015.0
                self.assertTrue(profile_config_problems(manifest, changed))


if __name__ == "__main__":
    unittest.main()
