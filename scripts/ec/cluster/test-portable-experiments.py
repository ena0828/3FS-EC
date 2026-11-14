"""Deployment-entry and supervisor compatibility checks; no services or workloads."""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from native_v2_config import prepare, file_api_enabled, key_roles, profile_config_problems, required_services
import tomllib

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gc_acceptance", SCRIPTS / "gc-acceptance.py")
gc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gc)
spec = importlib.util.spec_from_file_location("experiment_runner", SCRIPTS / "experiment-runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
spec = importlib.util.spec_from_file_location("file_command", SCRIPTS / "file-command.py")
file_command = importlib.util.module_from_spec(spec)
spec.loader.exec_module(file_command)


class PortableExperiments(unittest.TestCase):
    def test_read_allocation_export_forwards_only_local_paths_without_creating_output(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve()
            (root / "cluster.json").write_text(json.dumps({"root": str(root), "file_api": True}))
            run, output = root / "released read", root / "new snapshot.json"
            args = ["--root", str(root), "export-read-allocations", "--run-dir", str(run), "--output", str(output)]
            before = {path.name: path.read_bytes() for path in root.iterdir()}
            actual = file_command.command(file_command.parser().parse_args(args))
            self.assertEqual(actual, [str(root / "bin/ec_file_cli"), "--cfg=" + str(root / "client/file-client.toml"),
                                     "--config.run_dir=" + str(run), "--config.output_file=" + str(output),
                                     "mode4-export-read-allocations"])
            self.assertFalse(run.exists())
            self.assertFalse(output.exists())
            self.assertEqual({path.name: path.read_bytes() for path in root.iterdir()}, before)
            for extra in (["--metrics"], ["--session", str(run)], ["--offset", "0"]):
                with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    file_command.parser().parse_args(args + extra)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                file_command.parser().parse_args(args[:-2])
            parsed = file_command.parser().parse_args(args)
            parsed.output = Path("relative.json")
            with self.assertRaises(ValueError):
                file_command.command(parsed)

    def test_read_allocation_export_exec_skips_initialized_gate_and_transport_sidecar(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve()
            run, output = root / "released read", root / "export.json"
            run.mkdir()
            (run / "record.data").write_bytes(b"fixed journal bytes")
            for transport in (None, {"schema": 1, "mode": "rdma", "interface": "eth0",
                                     "ipv4": "192.0.2.1", "ib_device": "mlx5_0"}):
                with self.subTest(transport=transport):
                    manifest = {"root": str(root), "file_api": True}
                    if transport is not None:
                        manifest["data_transport"] = transport
                    (root / "cluster.json").write_text(json.dumps(manifest))
                    module = mock.Mock()
                    before = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
                    args = ["file-command.py", "--root", str(root), "export-read-allocations", "--run-dir", str(run),
                            "--output", str(output)]
                    with mock.patch.object(file_command.sys, "argv", args), mock.patch.object(file_command.sys, "platform", "linux"), \
                         mock.patch.object(file_command, "transport_module", return_value=module) as provider, \
                         mock.patch.object(file_command.os, "execve", side_effect=RuntimeError("captured exec"), create=True) as execute, \
                         contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, "captured exec"):
                        file_command.main()
                    execute.assert_called_once()
                    self.assertEqual(execute.call_args.args[0], str(root / "bin/ec_file_cli"))
                    self.assertEqual(execute.call_args.args[1][-1], "mode4-export-read-allocations")
                    module.bind_transport_run.assert_not_called()
                    if transport is None:
                        provider.assert_not_called()
                    else:
                        module.prepared_transport.assert_called_once_with(root, root / "client/file-client.toml",
                                                                        file_api=True, require_initialized=False)
                    self.assertEqual({str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}, before)
                    self.assertFalse(output.exists())
            # Ordinary data/recovery commands keep their original admission and sidecar.
            module = mock.Mock()
            args = ["file-command.py", "--root", str(root), "query", "--run-dir", str(run)]
            with mock.patch.object(file_command.sys, "argv", args), mock.patch.object(file_command.sys, "platform", "linux"), \
                 mock.patch.object(file_command, "transport_module", return_value=module), \
                 mock.patch.object(file_command.os, "execve", side_effect=RuntimeError("captured exec"), create=True), \
                 contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, "captured exec"):
                file_command.main()
            module.prepared_transport.assert_called_with(root, root / "client/file-client.toml", file_api=True)
            module.bind_transport_run.assert_called_once_with(root, run, module.prepared_transport.return_value,
                                                             [str(root / "bin/ec_file_cli")])

    def test_repair_metrics_only_forwards_explicit_choice_without_changing_run(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve()
            (root / "cluster.json").write_text(json.dumps({"root": str(root), "file_api": True}))
            run, session = root / "fixed repair", root / "fixed session"
            before = sorted(path.name for path in root.iterdir())
            for action in ("repair", "resume-repair", "query-repair", "close-repair-debt"):
                args = ["--root", str(root), action, "--run-dir", str(run)]
                if action == "repair":
                    args += ["--session", str(session), "--stripe", "0", "--targets", "0,11",
                             "--sources", "10,9,8,7,6,5,4,3,2,1", "--strategy", "helper", "--window", "4"]
                baseline = file_command.command(file_command.parser().parse_args(args))
                self.assertFalse(any(value.startswith("--config.repair_metrics=") for value in baseline))
                for flag, expected in (("--metrics", "true"), ("--no-metrics", "false")):
                    with self.subTest(action=action, flag=flag):
                        actual = file_command.command(file_command.parser().parse_args([*args, flag]))
                        self.assertEqual(actual, baseline[:-1] + ["--config.repair_metrics=" + expected, baseline[-1]])
                        self.assertIn("--config.run_dir=" + str(run), actual)
                self.assertEqual(sorted(path.name for path in root.iterdir()), before)
            for action in ("query", "resume", "close"):
                with self.subTest(rejected=action), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    file_command.parser().parse_args(["--root", str(root), action, "--run-dir", str(run), "--metrics"])

    def test_file_wrapper_preserves_paths_and_decimal_arguments_without_creating_runs(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve()
            (root / "cluster.json").write_text(json.dumps({"root": str(root), "file_api": True}))
            run, session, source = root / "new write", root / "old session", root / "input with spaces.bin"
            args = file_command.parser().parse_args(["--root", str(root), "pwrite", "--run-dir", str(run),
                "--session", str(session), "--offset", "9007199254740993", "--input", str(source)])
            argv = file_command.command(args)
            self.assertEqual(argv[-1], "mode4-pwrite")
            self.assertIn("--config.offset_decimal=9007199254740993", argv)
            self.assertIn("--config.input_file=" + str(source), argv)
            self.assertIn("--config.session_run_dir=" + str(session), argv)
            self.assertFalse(run.exists())
            self.assertFalse(session.exists())
            # New actions must preserve native recovery IDs and leave run creation to the CLI.
            cases = {
                "truncate": ["--session", str(session), "--length", "9007199254740993"],
                "append": ["--session", str(session), "--input", str(source)],
                "fsync": ["--session", str(session)],
                **{action: [] for action in ("resume-truncate", "query-truncate", "close-truncate-debt",
                    "resume-append", "query-append", "seal-append", "resume-fsync")},
            }
            for action, extra in cases.items():
                with self.subTest(action=action):
                    parsed = file_command.parser().parse_args(["--root", str(root), action,
                        "--run-dir", str(run), *extra])
                    forwarded = file_command.command(parsed)
                    self.assertEqual(forwarded[-1], "mode4-" + action)
                    self.assertIn("--config.run_dir=" + str(run), forwarded)
                    self.assertFalse(any(value.startswith("--config.offset_decimal=") for value in forwarded))
                    if action == "truncate":
                        self.assertIn("--config.length_decimal=9007199254740993", forwarded)
                    if action not in ("truncate", "append", "fsync"):
                        self.assertEqual(len(forwarded), 4)
                    self.assertFalse(run.exists())
            repair_args = ["--root", str(root), "repair", "--run-dir", str(run), "--session", str(session),
                           "--stripe", "9007199254740993", "--targets", "0,11",
                           "--sources", "10,9,8,7,6,5,4,3,2,1", "--strategy", "helper", "--window", "4"]
            repair = file_command.command(file_command.parser().parse_args(repair_args))
            self.assertIn("--config.repair_mask_decimal=2049", repair)
            self.assertIn("--config.repair_source_order=10,9,8,7,6,5,4,3,2,1", repair)
            self.assertIn("--config.repair_mode=helper", repair)
            self.assertIn("--config.repair_window_decimal=4", repair)
            self.assertIn("--config.repair_stripe_decimal=9007199254740993", repair)
            self.assertFalse(any(value.startswith("--config.repair_delivery=") for value in repair))
            for delivery in ("return", "direct"):
                forwarded = file_command.command(file_command.parser().parse_args(
                    repair_args + ["--delivery", delivery]))
                self.assertIn("--config.repair_delivery=" + delivery, forwarded)
                self.assertEqual(len(forwarded), len(repair) + 1)
            for strategy in ("central", "pipeline"):
                invalid_delivery = file_command.parser().parse_args(repair_args + ["--delivery", "direct"])
                invalid_delivery.strategy = strategy
                with self.assertRaises(ValueError):
                    file_command.command(invalid_delivery)
            overlapping = file_command.parser().parse_args(repair_args)
            overlapping.sources = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
            with self.assertRaises(ValueError):
                file_command.command(overlapping)
            for action in ("resume-repair", "query-repair", "close-repair-debt"):
                forwarded = file_command.command(file_command.parser().parse_args(
                    ["--root", str(root), action, "--run-dir", str(run)]))
                self.assertEqual(forwarded[-1], "mode4-" + action)
                self.assertEqual(len(forwarded), 4)
            self.assertFalse(run.exists())
            for value in ("01", "-1", "1.5", "18446744073709551616", "１"):
                with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                    file_command.decimal(value)

    @unittest.skipUnless(sys.platform == "linux", "prepare requires Linux permission semantics")
    def test_file_api_requires_format3_and_independent_key_with_discovery_gate(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve() / "3fs-ec-native-file-api"
            with self.assertRaises(ValueError):
                prepare(root, ROOT, 19000, "v2", file_api=True)
            self.assertFalse(root.exists())
            prepare(root, ROOT, 19000, "gc", file_api=True, user_uid=2345, user_gid=3456)
            for name in ("kv-replay.py", "kv-replay-native.py"):
                self.assertEqual((root / "scripts" / name).read_bytes(), (SCRIPTS / name).read_bytes())
            traces = SCRIPTS.parent / "traces"
            for name in ("kv_trace.py", "replay_input.py", "replay_model.py"):
                self.assertEqual((root / "scripts" / name).read_bytes(), (traces / name).read_bytes())
            for original in (traces / "inputs").glob("*.source.json"):
                self.assertEqual((root / "scripts/trace-inputs" / original.name).read_bytes(), original.read_bytes())
            self.assertEqual((root / "scripts/trace-inputs/Qwen-Bailian-LICENSE").read_bytes(),
                             (traces / "licenses/Qwen-Bailian-LICENSE").read_bytes())
            help_result = subprocess.run([sys.executable, '-B', str(root / 'scripts/kv-replay.py'), '--help'],
                                         cwd=root, capture_output=True, text=True, check=True)
            self.assertIn('start,resume,status', help_result.stdout)
            manifest = json.loads((root / "cluster.json").read_text())
            self.assertEqual(manifest["authenticated_user"], {"uid": 2345, "gid": 3456})
            self.assertTrue(file_api_enabled(manifest))
            self.assertEqual(key_roles(manifest), ("data", "control", "helper", "gc", "rmw"))
            self.assertIn("ec_file_cli", required_services(manifest))
            file_client = tomllib.loads((root / "client/file-client.toml").read_text())
            self.assertEqual((file_client["user_info"]["uid"], file_client["user_info"]["gid"]), (2345, 3456))
            self.assertEqual(file_client["cluster_id"], manifest["cluster_id"])
            self.assertEqual(file_client["user_info"]["token_file"], str(root / "client/user.token"))
            self.assertNotIn("max_operations", file_client)
            self.assertIs(file_client["client"]["force_use_tcp"], True)
            keys = [(root / "secrets" / (role + ".key")).read_bytes() for role in key_roles(manifest)]
            self.assertEqual(len(set(keys)), 5)
            self.assertEqual({len(key) for key in keys}, {32})
            configs = {path.name: tomllib.loads(path.read_text()) for directory in ("config", "client")
                       for path in (root / directory).glob("*.toml")}
            self.assertEqual(profile_config_problems(manifest, configs), [])
            meta = configs["meta_main.toml"]["server"]["meta"]
            self.assertIs(meta["enable_ec_rmw"], False)
            self.assertIs(meta["enable_ec_file_ranges"], False)
            storage = configs["storage_main.toml"]["server"]["storage"]
            self.assertIs(storage["enable_ec_rmw"], True)
            self.assertIs(storage["ec_rmw_transport"]["force_use_tcp"], True)
            self.assertIs(storage["ec_rmw_client"]["net_client"]["force_use_tcp"], True)
            for key in ("enable_ec_v2", "enable_ec_exact_gc", "enable_ec_revision_retirement",
                        "enable_ec_rmw", "enable_ec_file_ranges"):
                meta[key] = True
            self.assertEqual(profile_config_problems(manifest, configs), [])
            storage["ec_rmw_key_file"] = meta["ec_capability_key_file"]
            self.assertTrue(profile_config_problems(manifest, configs))
            for value in (1, "true", None):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    file_api_enabled(dict(manifest, file_api=value))

    @unittest.skipUnless(sys.platform == "linux", "prepare requires Linux permission semantics")
    def test_fresh_prepare_includes_entry_points_and_exact_dependency_lock(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve() / "3fs-ec-native-portable"
            prepare(root, ROOT, 19000, "gc")
            self.assertEqual(json.loads((root / "cluster.json").read_text())["authenticated_user"],
                             {"uid": 1000, "gid": 1000})
            for name in ("experiment-runner.py", "experiment-menu.py", "file-command.py", "ack-service-acceptance.py",
                         "ack-expected-scripts.json", "gc-acceptance.py", "tree-gc-runner.py"):
                self.assertEqual((root / "scripts" / name).read_bytes(), (SCRIPTS / name).read_bytes())
            expected = json.loads((root / "scripts/ack-expected-scripts.json").read_text())
            self.assertEqual(set(expected), {"experiment-runner.py", "run-cluster.py", "generate.py",
                                             "native-v2.py", "native_v2_config.py", "native_fault_control.py", "native_managed_domain.py"})
            for name, digest in expected.items():
                self.assertEqual(hashlib.sha256((root / "scripts" / name).read_bytes()).hexdigest(), digest)
            self.assertFalse((root / "state/control.sock").exists())
            self.assertEqual(json.loads((root / "cluster.json").read_text())["state"], "prepared_not_started")

    def test_single_process_receipt_accepts_both_explicit_schema_variants(self):
        stopped = {"schema": 1, "run": "run-20261105T161825.639679Z", "stage": "stopped",
                   "root": "/tmp/3fs-ec-native-portable", "profile": "native-gc-local-1-storage-12-targets",
                   "processes": [{"name": name, "pid": 12000 + i, "exit_code": -15 if i == 0 else 0}
                                 for i, name in enumerate(("fdb", "mgmtd", "storage", "meta"))],
                   "logical_targets": 12, "storage_processes": 1, "independent_storage_failure_domains": 1,
                   "performance_validated": False, "failure": None}
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent).resolve() / "last-supervisor.json"
            for value in (stopped, dict(stopped, storage_process_failure_domains=1)):
                path.write_text(json.dumps(value))
                self.assertEqual(gc.load_stopped_supervisor(runner, path), value)
            for count in (True, 1.0, 0, 12, "1", None):
                value = dict(stopped, storage_process_failure_domains=count)
                path.write_text(json.dumps(value))
                with self.subTest(count=count), self.assertRaises(RuntimeError):
                    gc.load_stopped_supervisor(runner, path)
            value = copy.deepcopy(stopped)
            value["unexpected"] = 1
            path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):
                gc.load_stopped_supervisor(runner, path)


if __name__ == "__main__":
    unittest.main()
