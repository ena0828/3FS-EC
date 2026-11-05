#!/usr/bin/env python3
"""Pure configuration checks; no services, databases, keys or target directories."""
import copy
from pathlib import Path
import unittest
import uuid

from native_v2_config import generate_configs, pool_from_observations, to_toml


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


if __name__ == "__main__":
    unittest.main()
