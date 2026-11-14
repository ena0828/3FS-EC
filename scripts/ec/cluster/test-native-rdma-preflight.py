"""Exercise native-v2 admission/dispatch with fake sysfs; never open a device or start services."""
import contextlib
import copy
import errno
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock
import uuid

import native_v2_config as config


# The production supervisor is Linux-only. These imports merely let its actual
# Python functions run against explicit mocks on Windows; no gate is relaxed.
modules = {}
if sys.platform == "win32":
    modules = {"fcntl": types.SimpleNamespace(), "resource": types.SimpleNamespace(
        RLIMIT_NOFILE=7, RLIMIT_MEMLOCK=8, RLIM_INFINITY=-1,
        getrlimit=lambda _: (1 << 40, 1 << 40), setrlimit=lambda *_: None)}
with mock.patch.dict(sys.modules, modules):
    spec = importlib.util.spec_from_file_location("native_rdma_supervisor", Path(__file__).with_name("native-v2.py"))
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)


SETTINGS = config.requested_transport(transport="rdma", rdma_interface="eth7",
                                      rdma_address="192.0.2.17", rdma_device="mlx5_7")


class NativeRdmaPreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sysfs = self.root / "sys"
        self.dev = self.root / "dev"
        self.port = self.sysfs / "class/infiniband/mlx5_7/ports/1"
        self.uverbs = self.sysfs / "class/infiniband_verbs/uverbs3"
        self.write(self.sysfs / "class/net/eth7/operstate", "up\n")
        self.write(self.port / "state", "4: ACTIVE\n")
        self.write(self.port / "gid_attrs/ndevs/0", "eth7\n")
        self.write(self.uverbs / "ibdev", "mlx5_7\n")
        self.write(self.uverbs / "dev", "231:3\n")
        self.ip = [{"ifname": "eth7", "operstate": "UP", "flags": ["UP", "LOWER_UP"],
                    "addr_info": [{"family": "inet", "local": "192.0.2.17"}]}]

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def manifest(self, rdma=True):
        result = {"schema": 1, "root": str(self.root), "cluster_id": "fixed-cluster",
                  "profile": config.PROFILE, "port_base": 13500, "fdb_version": "7.3.63"}
        if rdma:
            result["data_transport"] = copy.deepcopy(SETTINGS)
        return result

    def admission(self, *, stdout=None, stderr="", returncode=0, usable=True, limits=(1 << 40, 1 << 40), error=None):
        with mock.patch.object(native.subprocess, "run", side_effect=error,
                               return_value=subprocess.CompletedProcess([], returncode,
                                   json.dumps(self.ip) if stdout is None else stdout, stderr)) as command, \
                mock.patch.object(native.resource, "getrlimit", return_value=limits), \
                mock.patch.object(native, "_uverbs_access", return_value=usable) as access:
            result = native.rdma_admission(SETTINGS, sysfs_root=self.sysfs, dev_root=self.dev)
        return result, command, access

    def test_read_only_admission_records_exact_nic_port_device_and_limits(self):
        (problems, observed), command, access = self.admission()
        self.assertEqual(problems, [])
        command.assert_called_once_with(["ip", "-j", "-4", "address", "show", "dev", "eth7"],
                                        text=True, capture_output=True, timeout=10)
        access.assert_called_once_with(self.dev / "infiniband/uverbs3", (231, 3))
        self.assertEqual(observed["ports"], [{"port": 1, "state": "4: ACTIVE", "netdevs": ["eth7"], "empty_gid_indices": []}])
        self.assertEqual(observed["interface"]["ipv4"], ["192.0.2.17"])
        self.assertEqual(observed["memlock"]["required_bytes"], 3 * 1024**3)
        self.assertNotIn("data_validated", observed)
        # Both documented kernel port-to-netdev layouts work without a PCI guess.
        (self.port / "gid_attrs/ndevs/0").unlink()
        (self.port / "net/eth7").mkdir(parents=True)
        self.assertEqual(self.admission()[0][0], [])

    def test_interface_absent_down_ambiguous_or_wrong_address_is_rejected(self):
        original = copy.deepcopy(self.ip)
        variants = [[], original + original, [{**original[0], "ifname": "eth8"}],
                    [{**original[0], "operstate": "DOWN"}], [{**original[0], "flags": ["UP", "LOOPBACK"]}],
                    [{**original[0], "addr_info": [{"family": "inet", "local": "192.0.2.18"}]}],
                    [{**original[0], "addr_info": original[0]["addr_info"] * 2}]]
        for value in variants:
            with self.subTest(value=value):
                self.ip = value
                self.assertTrue(any("interface admission" in item for item in self.admission()[0][0]))
        self.ip = original
        for state in ("down", "unknown"):
            self.write(self.sysfs / "class/net/eth7/operstate", state)
            (_, _), command, _ = self.admission()
            command.assert_not_called()
            self.assertTrue(self.admission()[0][0])

    def test_ip_failure_timeout_bad_json_and_output_bound_fail_closed(self):
        for values in ({"returncode": 1}, {"stdout": "not JSON"}, {"stdout": "x" * 65537},
                       {"stderr": "x" * 65537}, {"error": subprocess.TimeoutExpired(["ip"], 10)},
                       {"error": FileNotFoundError("ip unavailable")}):
            with self.subTest(values=tuple(values)):
                problems = self.admission(**values)[0][0]
                self.assertTrue(any("interface admission" in item for item in problems))

    def test_verbs_requires_active_port_with_actual_netdev_mapping(self):
        for state, netdev in (("2: INIT", "eth7"), ("4: ACTIVE", "eth8"), ("4: ACTIVE", "")):
            with self.subTest(state=state, netdev=netdev):
                self.write(self.port / "state", state)
                self.write(self.port / "gid_attrs/ndevs/0", netdev)
                self.assertTrue(any("verbs port" in item for item in self.admission()[0][0]))
        self.write(self.port / "state", "4: ACTIVE")
        self.write(self.port / "gid_attrs/ndevs/0", "eth7")
        self.write(self.port / "gid_attrs/ndevs/1", "unused")
        inactive = self.port.parent / "2"
        self.write(inactive / "state", "2: INIT")
        self.write(inactive / "gid_attrs/ndevs/0", "unavailable")
        original = native._sysfs_text
        def read(path):
            if path == inactive / "gid_attrs/ndevs/0":
                raise AssertionError("Inactive-port mapping must not be needed")
            if path == self.port / "gid_attrs/ndevs/1":
                raise OSError(errno.EINVAL, "empty GID slot")
            return original(path)
        with mock.patch.object(native, "_sysfs_text", side_effect=read):
            problems, observed = self.admission()[0]
            self.assertEqual(problems, [])
            self.assertEqual(observed["ports"][0]["empty_gid_indices"], ["1"])
            self.assertEqual(observed["ports"][1]["state"], "2: INIT")
            for code in (errno.EACCES, errno.ENODEV):
                def failed(path):
                    if path == self.port / "gid_attrs/ndevs/1":
                        raise OSError(code, "not an empty-slot observation")
                    return read(path)
                with mock.patch.object(native, "_sysfs_text", side_effect=failed):
                    self.assertTrue(any("verbs port" in item for item in self.admission()[0][0]))
            (self.port / "gid_attrs/ndevs/0").unlink()
            self.assertTrue(any("verbs port" in item for item in self.admission()[0][0]))
        (self.port / "gid_attrs/ndevs/1").unlink()
        self.assertTrue(any("verbs port" in item for item in self.admission()[0][0]))

    def test_uverbs_identity_access_and_memlock_are_required(self):
        self.assertTrue(any("uverbs" in item for item in self.admission(usable=False)[0][0]))
        self.write(self.uverbs / "ibdev", "other_device")
        result, _, access = self.admission()
        access.assert_not_called()
        self.assertTrue(any("uverbs" in item for item in result[0]))
        self.write(self.uverbs / "ibdev", "mlx5_7")
        self.write(self.uverbs / "dev", "invalid")
        self.assertTrue(any("uverbs" in item for item in self.admission()[0][0]))
        self.write(self.uverbs / "dev", "231:3")
        for values in ((0, 1 << 40), (1 << 40, 0)):
            self.assertTrue(any("memlock" in item for item in self.admission(limits=values)[0][0]))
        self.assertEqual(self.admission(limits=(native.resource.RLIM_INFINITY,) * 2)[0][0], [])

    def test_uverbs_node_requires_matching_character_number_and_effective_permissions(self):
        path = self.dev / "infiniband/uverbs3"
        with mock.patch.object(Path, "stat", return_value=types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=99)) as info, \
                mock.patch.object(native.os, "major", return_value=231, create=True), \
                mock.patch.object(native.os, "minor", return_value=3, create=True), \
                mock.patch.object(native.os, "access", return_value=True) as access:
            self.assertTrue(native._uverbs_access(path, (231, 3)))
            access.assert_called_once_with(path, os.R_OK | os.W_OK, effective_ids=True)
            access.reset_mock()
            self.assertFalse(native._uverbs_access(path, (231, 4)))
            access.assert_not_called()
            info.return_value.st_mode = stat.S_IFREG
            self.assertFalse(native._uverbs_access(path, (231, 3)))
            access.assert_not_called()

    def test_prepare_forwards_grouped_parameters_and_resume_cannot_override(self):
        base = ["native-v2.py", "prepare", "--root", str(self.root)]
        with mock.patch.object(native.sys, "platform", "linux"), mock.patch.object(native.os, "umask"), \
                mock.patch.object(native, "prepare") as prepare, mock.patch.object(native, "load_manifest") as load:
            with mock.patch.object(native.sys, "argv", base):
                self.assertEqual(native.main(), 0)
            self.assertEqual(prepare.call_args.kwargs["transport"], "tcp")
            options = ["--transport", "rdma", "--rdma-interface", "eth7", "--rdma-address", "192.0.2.17",
                       "--rdma-device", "mlx5_7"]
            with mock.patch.object(native.sys, "argv", base + options):
                self.assertEqual(native.main(), 0)
            self.assertEqual({key: prepare.call_args.kwargs[key] for key in
                ("transport", "rdma_interface", "rdma_address", "rdma_device")},
                dict(transport="rdma", rdma_interface="eth7", rdma_address="192.0.2.17", rdma_device="mlx5_7"))
            prepare.reset_mock()
            for flags in (["--transport", "rdma"], ["--rdma-interface", "eth7"]):
                with mock.patch.object(native.sys, "argv", base + flags), self.assertRaises(ValueError):
                    native.main()
            prepare.assert_not_called()
            for command in ("start", "doctor", "status", "stop"):
                for flags in (["--transport", "tcp"], options):
                    with mock.patch.object(native.sys, "argv", [base[0], command, *base[2:], *flags]), \
                            contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        native.main()
            load.assert_not_called()

    def test_status_records_only_rdma_profile_without_validation_claim(self):
        cluster = object.__new__(native.NativeCluster)
        cluster.status_lock, cluster.run_id, cluster.stage = threading.Lock(), "run-fixed", "ready"
        cluster.root, cluster.processes, cluster.failure = self.root, [], None
        cluster.fault_control = mock.Mock(snapshot=lambda: {})
        for rdma in (False, True):
            cluster.manifest = self.manifest(rdma)
            result = cluster.status()
            self.assertEqual("data_transport" in result, rdma)
            if rdma:
                self.assertEqual(result["data_transport"], SETTINGS)
            self.assertFalse(result["performance_validated"])
            self.assertNotIn("data_validated", result)
            initialized = native.transport_record(cluster.manifest, {"schema": 1, "cluster_id": "fixed-cluster"})
            config.validate_initialized_profile(cluster.manifest, initialized)
        with self.assertRaises(ValueError):
            config.validate_initialized_profile(self.manifest(False), initialized)
        with self.assertRaises(ValueError):
            config.validate_initialized_profile(self.manifest(), {"schema": 1, "cluster_id": "fixed-cluster"})

    def test_doctor_checks_all_listeners_and_only_rdma_runs_admission(self):
        for name in ("config", "client", "state", "lib"):
            (self.root / name).mkdir(exist_ok=True)
        (self.root / "lib/libfdb_c.so").touch()
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            return "MemAvailable: 99999999 kB\n" if str(path) in ("/proc/meminfo", "\\proc\\meminfo") else original_read(path, *args, **kwargs)
        with mock.patch.object(native, "required_services", return_value=[]), \
                mock.patch.object(native, "profile_config_problems", return_value=[]), \
                mock.patch.object(native, "key_roles", return_value=[]), \
                mock.patch.object(Path, "read_text", read), \
                mock.patch.object(native.os, "statvfs", return_value=types.SimpleNamespace(f_bavail=1 << 40, f_frsize=1), create=True), \
                mock.patch.object(native.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ext4\n", "")), \
                mock.patch.object(native.resource, "getrlimit", return_value=(1 << 40, 1 << 40)), \
                mock.patch.object(native, "rdma_admission", return_value=(["injected admission failure"], {"scope": "test"})) as admission, \
                mock.patch.object(native, "probe_listeners") as listeners:
            for rdma in (False, True):
                with mock.patch.object(native, "load_manifest", return_value=self.manifest(rdma)):
                    result = native.doctor(self.root)
                listeners.assert_called_with(config.transport_listeners(self.manifest(rdma)), result["problems"])
                self.assertEqual("rdma" in result["observations"], rdma)
                self.assertEqual("injected admission failure" in result["problems"], rdma)
                if not rdma:
                    admission.assert_not_called()
            admission.assert_called_once_with(SETTINGS)

    def test_restart_refuses_occupied_rdma_listener_before_any_child_launch(self):
        cluster = object.__new__(native.NativeCluster)
        cluster.manifest = self.manifest()
        cluster.root = self.root
        cluster.manifest.update(profile=config.GC_PROFILE, file_api=True, authority=str(uuid.UUID(int=70)),
            gc=dict(authority=str(uuid.UUID(int=71)), key_id=str(uuid.UUID(int=72)),
                    client_namespace=str(uuid.UUID(int=73)), data_protocol=2, disk_format=3, gc_protocol=2))
        cluster.processes = [("storage", mock.Mock())]
        listeners = config.transport_listeners(cluster.manifest, node=10001)
        with mock.patch.object(config, "Path", PurePosixPath):
            configs, _ = config.generate_configs(Path(__file__).resolve().parents[3], str(self.root), 13500,
                cluster.manifest["authority"], "fixed-cluster", profile="gc", gc=cluster.manifest["gc"], file_api=True,
                transport="rdma", rdma_interface="eth7", rdma_address="192.0.2.17", rdma_device="mlx5_7")
        def save_configs(values):
            for name, value in values.items():
                self.write(self.root / ("client" if name in {"stripe-client.toml", "file-client.toml"} else "config") / name,
                           config.to_toml(value))
        save_configs(configs)
        probe = mock.MagicMock()
        probe.__enter__.return_value = probe
        probe.bind.side_effect = lambda address: (_ for _ in ()).throw(OSError("occupied")) if address == listeners[-1] else None
        with mock.patch.object(native.socket, "socket", return_value=probe) as socket_call, \
                mock.patch.object(native.subprocess, "Popen") as popen, \
                mock.patch.object(config, "Path", PurePosixPath), \
                mock.patch.object(native, "load_manifest", return_value=cluster.manifest) as load:
            with self.assertRaises(OSError):
                cluster._start_owned("storage", ["never-start"])
            self.assertEqual(probe.bind.call_args_list, [mock.call(value) for value in listeners])
            popen.assert_not_called()
            problems = []
            native.probe_listeners(listeners, problems)
            self.assertEqual(len(problems), 1)
            self.assertIn("RDMA bootstrap listener", problems[0])
            # Enabling the already-selected Meta file/GC features after discovery
            # is a legitimate startup transition, not a transport change.
            for name in ("enable_ec_v2", "enable_ec_exact_gc", "enable_ec_revision_retirement",
                         "enable_ec_rmw", "enable_ec_file_ranges"):
                configs["meta_main.toml"]["server"]["meta"][name] = True
            save_configs(configs)
            native.validate_launch_profile(self.root, cluster.manifest)
            socket_call.reset_mock()
            for file, path, wrong in (("storage_main.toml", "server.forward_client.force_use_tcp", True),
                                     ("storage_main_launcher.toml", "ib_devices.device_filter", ["mlx5_8"]),
                                     ("meta_main.toml", "server.meta.ec_storage_transport", "tcp"),
                                     ("file-client.toml", "storage_transport", "tcp")):
                changed = copy.deepcopy(configs)
                config.put(changed[file], path, wrong)
                save_configs(changed)
                with self.subTest(file=file, path=path), self.assertRaisesRegex(RuntimeError, "RDMA configuration changed"):
                    cluster._start_owned("storage", ["never-start"])
                socket_call.assert_not_called()
                popen.assert_not_called()
            save_configs(configs)
            load.return_value = self.manifest(False)
            with self.assertRaisesRegex(RuntimeError, "transport changed"):
                cluster._start_owned("storage", ["never-start"])
            socket_call.assert_not_called()
            popen.assert_not_called()

    def test_preflight_rejects_profile_change_and_initialized_mismatch_before_effects(self):
        cluster = object.__new__(native.NativeCluster)
        cluster.root, cluster.manifest, cluster.mode, cluster.managed = self.root, self.manifest(), "resume", None
        cluster.start_sampler, cluster.disk_snapshot = mock.Mock(), mock.Mock()
        with mock.patch.object(native, "load_manifest", return_value=self.manifest(False)), \
                mock.patch.object(native, "doctor") as doctor:
            with self.assertRaisesRegex(RuntimeError, "transport changed"):
                cluster.preflight()
            doctor.assert_not_called()
        self.write(self.root / "state/initialized.json", json.dumps({"schema": 1, "cluster_id": "fixed-cluster"}))
        with mock.patch.object(native, "load_manifest", return_value=self.manifest()), \
                mock.patch.object(native, "doctor", return_value={"problems": []}):
            with self.assertRaisesRegex(ValueError, "transport differs"):
                cluster.preflight()
        self.assertFalse((self.root / "data").exists())
        cluster.start_sampler.assert_not_called()
        cluster.disk_snapshot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
