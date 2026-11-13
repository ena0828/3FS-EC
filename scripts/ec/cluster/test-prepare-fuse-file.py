"""Pure configuration checks only; no mount, process, token or database."""
import copy
import importlib.util
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


prepare = module("mode4_fuse_prepare", HERE / "prepare-fuse-file.py")
package = module("mode4_fuse_package", HERE.parent / "package-services.py")


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


if __name__ == "__main__":
    unittest.main()
