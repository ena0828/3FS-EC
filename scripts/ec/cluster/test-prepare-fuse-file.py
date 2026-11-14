"""Pure configuration checks only; no mount, process, token or database."""
import copy
import hashlib
import importlib.util
from pathlib import Path, PurePosixPath
import unittest

import native_v2_config


HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


prepare = module("mode4_fuse_prepare", HERE / "prepare-fuse-file.py")
package = module("mode4_fuse_package", HERE.parent / "package-services.py")
lifecycle = module("mode4_fuse_lifecycle", HERE / "mode4-lifecycle-acceptance.py")


class Mode4MountPreparation(unittest.TestCase):
    def inputs(self):
        root, output, mount, token = map(Path, ("/private/bundle", "/private/config", "/private/mount", "/private/user.token"))
        manifest = dict(schema=1, root=str(root), cluster_id="actual", file_api=True,
                        profile="native-gc-local-1-storage-12-targets",
                        authority="11111111-1111-4111-8111-111111111111",
                        gc=dict(authority="22222222-2222-4222-8222-222222222222",
                                key_id="33333333-3333-4333-8333-333333333333",
                                client_namespace="44444444-4444-4444-8444-444444444444",
                                data_protocol=2, disk_format=3, gc_protocol=2))
        fuse = dict(common={"log": {"handlers": [{"writer_type": "FILE", "file_path": "", "name": "normal"}]}},
                    ec_read={"enable": False}, ec_file={"enable": False},
                    io_worker_coros={}, io_jobq_sizes={}, io_bufs={})
        launcher = {"ib_devices": {}, "allow_other": True}
        client = dict(cluster_id="actual", user_info=dict(uid=1000, gid=1000, token_file=str(token)),
                      client={"force_use_tcp": True}, mgmtd_client={"network_type": "TCP", "mgmtd_server_addresses": ["TCP://127.0.0.1:12345"]},
                      meta_client={"network_type": "TCP"}, storage_client={"traffic_control": {"read": {"max_concurrent_requests": 16}}})
        options = dict(effective_uid=1000, root=root, output=output, mountpoint=mount, token=token)
        return manifest, fuse, launcher, client, options

    def rdma_inputs(self):
        m, f, l, _, options = self.inputs()
        requested = dict(transport="rdma", rdma_interface="enp2s0", rdma_address="192.0.2.10",
                         rdma_device="mlx5_0")
        m["data_transport"] = native_v2_config.requested_transport(**requested)
        configs, _ = native_v2_config.generate_configs(
            HERE.parents[2], options["root"], 13500, m["authority"], m["cluster_id"],
            profile="gc", gc=m["gc"], file_api=True, **requested)
        return m, f, l, configs["file-client.toml"], options

    def test_first_and_resume_keep_same_identity_and_only_change_creation_bit(self):
        m, f, l, c, options = self.inputs()
        original = copy.deepcopy((m, f, l, c))
        result = prepare.render(m, f, l, c, **options, create_new=True)
        first, resume = result["fuse-first.toml"], result["fuse-resume.toml"]
        self.assertIs(first["ec_read"]["enable"], False)
        self.assertIs(first["ec_file"]["create_state"], True)
        self.assertIs(first["ec_file"]["create_new"], True)
        expected = copy.deepcopy(first)
        expected["ec_file"]["create_state"] = False
        self.assertEqual(resume, expected)
        self.assertEqual(result["launcher.toml"]["token_file"], str(options["token"]))
        self.assertIs(result["launcher.toml"]["allow_other"], False)
        self.assertEqual(first["storage"], c["storage_client"])
        self.assertEqual(first["mgmtd"]["mgmtd_server_addresses"], c["mgmtd_client"]["mgmtd_server_addresses"])
        self.assertIs(first["mgmtd"]["enable_auto_extend_client_session"], True)
        self.assertEqual(original, (m, f, l, c))

    def test_default_tcp_render_retains_frozen_output_bytes(self):
        m, f, l, c, options = self.inputs()
        # Stable POSIX strings make this a byte check on Windows as well.
        for key in ("root", "output", "mountpoint", "token"):
            options[key] = PurePosixPath(str(options[key]).replace("\\", "/"))
        m["root"] = str(options["root"])
        c["user_info"]["token_file"] = str(options["token"])
        configs = prepare.render(m, f, l, c, **options, create_new=True)
        # Captured from the fixed cb8a4b99 pre-RDMA renderer, not this function.
        expected = {"fuse-first.toml": "7ab08a5aa0bbea68daa49fc6e54aa2ab53b5aaecba8f12d73f94aaebc81aa668",
                    "fuse-resume.toml": "38c93f64993cea5398bb7573a9f53f5b6bfa311dee07c94d405b74ae04d871d3",
                    "launcher.toml": "82506fcd9f41cbb1840bccca526e52ccb9962d873747411b77b3d4edb7b2afbf"}
        self.assertEqual({name: hashlib.sha256(prepare.to_toml(value).encode()).hexdigest()
                          for name, value in configs.items()}, expected)

    def test_rejects_profile_uid_transport_and_type_substitutions(self):
        cases = [("manifest", "file_api", False), ("manifest", "file_api", 1),
                 ("client", "cluster_id", "other")]
        for scope, key, value in cases:
            m, f, l, c, options = self.inputs()
            (m if scope == "manifest" else c)[key] = value
            with self.subTest(scope=scope, key=key), self.assertRaises(ValueError):
                prepare.render(m, f, l, c, **options)

        for value in (True, 1.5, "128", 0, 4097):
            m, f, l, c, options = self.inputs()
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare.render(m, f, l, c, **options, retained_sessions=value)
        for mutation in (lambda f, c: f["ec_read"].update(enable=True),
                         lambda f, c: f.update(ec_storage_transport="rdma"),
                         lambda f, c: c["user_info"].update(uid=0),
                         lambda f, c: c["client"].update(force_use_tcp=1),
                         lambda f, c: c["meta_client"].update(network_type="RDMA"),
                         lambda f, c: c["user_info"].update(token="inline-secret")):
            m, f, l, c, options = self.inputs()
            mutation(f, c)
            with self.assertRaises(ValueError):
                prepare.render(m, f, l, c, **options)

    def test_nondefault_authenticated_mount_uid_keeps_original_recipe(self):
        m, f, l, c, options = self.inputs()
        m["authenticated_user"] = {"uid": 2345, "gid": 3456}
        c["user_info"].update(uid=2345, gid=3456)
        options["effective_uid"] = 2345
        result = prepare.render(m, f, l, c, **options, create_new=True)
        self.assertFalse(result["launcher.toml"]["allow_other"])
        self.assertEqual(result["launcher.toml"]["token_file"], str(options["token"]))
        expected = copy.deepcopy(result["fuse-first.toml"])
        expected["ec_file"]["create_state"] = False
        self.assertEqual(result["fuse-resume.toml"], expected)
        options["effective_uid"] = 1000
        with self.assertRaises(ValueError):
            prepare.render(m, f, l, c, **options, create_new=True)

    def test_packaging_opt_in_preserves_defaults_and_requires_file_api(self):
        m, *_ = self.inputs()
        without = package.selected_services(m, native_gc=True)
        self.assertEqual(without, package.NATIVE_V2_SERVICES + ("ec_file_cli",))
        self.assertNotIn("hf3fs_fuse_main", without)
        self.assertEqual(package.selected_services(m, native_gc=True, ec_file_mount=True),
                         without + ("hf3fs_fuse_main", "ec_mount_read_probe"))
        self.assertEqual(package.selected_services({}), package.SERVICES)
        for invalid in (dict(m, file_api=False), dict(m, file_api=1), dict(m, profile="native-v2-local-1-storage-12-targets")):
            with self.assertRaises(ValueError):
                package.selected_services(invalid, native_gc=True, ec_file_mount=True)

    def test_rdma_render_uses_generated_data_client_and_keeps_tcp_control(self):
        m, f, l, c, options = self.rdma_inputs()
        original = copy.deepcopy((m, f, l, c))
        result = prepare.render(m, f, l, c, **options, create_new=True)
        first = result["fuse-first.toml"]
        self.assertEqual(first["ec_storage_transport"], "rdma")
        self.assertIs(first["client"]["force_use_tcp"], False)
        for key in ("net_client", "net_client_for_updates"):
            self.assertIs(first["storage"][key]["force_use_tcp"], False)
        self.assertEqual(first["meta"]["network_type"], "TCP")
        self.assertEqual(first["mgmtd"]["network_type"], "TCP")
        self.assertTrue(all(address.startswith("TCP://") for address in first["mgmtd"]["mgmtd_server_addresses"]))
        self.assertEqual(result["launcher.toml"]["ib_devices"], c["ib_devices"])
        self.assertEqual(result["launcher.toml"]["ib_devices"]["device_filter"], ["mlx5_0"])
        self.assertIs(result["launcher.toml"]["ib_devices"]["allow_no_usable_devices"], False)
        self.assertIs(result["launcher.toml"]["allow_other"], False)
        expected = copy.deepcopy(first)
        expected["ec_file"]["create_state"] = False
        self.assertEqual(result["fuse-resume.toml"], expected)
        for name, value in result.items():
            self.assertEqual(prepare.tomllib.loads(prepare.to_toml(value)), value, name)
        self.assertEqual(original, (m, f, l, c))

    def test_rdma_render_rejects_mixed_transport_and_device_configuration(self):
        mutations = (
            lambda m, c: c.update(storage_transport="tcp"),
            lambda m, c: c["storage_client"]["net_client"].update(force_use_tcp=True),
            lambda m, c: c["storage_client"]["net_client_for_updates"].update(force_use_tcp=True),
            lambda m, c: c["client"].update(force_use_tcp=True),
            lambda m, c: c["ib_devices"].update(device_filter=["mlx5_1"]),
            lambda m, c: c["ib_devices"].update(allow_no_usable_devices=True),
            lambda m, c: c["meta_client"].update(network_type="RDMA"),
            lambda m, c: c["mgmtd_client"].update(mgmtd_server_addresses=["RDMA://192.0.2.10:13501"]),
            lambda m, c: m.update(data_transport=None),
            lambda m, c: m["data_transport"].update(schema=True),
            lambda m, c: m.pop("data_transport"),
        )
        for index, mutate in enumerate(mutations):
            m, f, l, c, options = self.rdma_inputs()
            mutate(m, c)
            with self.subTest(index=index), self.assertRaises(ValueError):
                prepare.render(m, f, l, c, **options)

    def test_rdma_provenance_preserves_service_set_without_claiming_validation(self):
        m, *_ = self.rdma_inputs()
        tcp = copy.deepcopy(m)
        tcp.pop("data_transport")
        self.assertEqual(prepare.transport_evidence(tcp), {})
        self.assertEqual(package.transport_provenance(tcp), {})
        expected = {"data_transport_requested": m["data_transport"], "transport_validation": "configuration_only"}
        self.assertEqual(prepare.transport_evidence(m), expected)
        self.assertEqual(package.transport_provenance(m), expected)
        lifecycle.validate_prepared_profile(m, copy.deepcopy(m), prepare.transport_evidence(m))
        for mount in (False, True):
            self.assertEqual(package.selected_services(m, native_gc=True, ec_file_mount=mount),
                             package.selected_services(tcp, native_gc=True, ec_file_mount=mount))
        for bad in (dict(m, data_transport=None), dict(m, profile="unmanaged")):
            with self.assertRaises(ValueError):
                package.transport_provenance(bad)


if __name__ == "__main__":
    unittest.main()
