#!/usr/bin/env python3
"""Small portable standard-library tests; fake CLI only, no native services."""
import importlib.util
import contextlib
import io
import os
import signal
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("experiment_runner", HERE / "experiment-runner.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ec-executor-fake-", dir=HERE)
        self.root = Path(self.temp.name).resolve()
        self.assertEqual(self.root.parent, HERE)
        self.addCleanup(self.temp.cleanup)
        self.root.chmod(0o700)
        for name in ("client", "logs", "lib"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "client/stripe-client.toml").write_text("# Fake only, no token or service address\n")
        mod.generate_inputs(self.root)

    def runner(self, mode="normal"):
        return mod.Runner(self.root, [sys.executable, str(HERE / "testdata/fake-ec-cli.py")],
                          extra_env={"EC_FAKE_MODE": mode})

    def calls(self):
        return [json.loads(line) for line in (self.root / "fake-invocations.jsonl").read_text().splitlines()]

    def rdma_profile(self):
        import native_v2_config as profile
        # The generated server settings are Linux paths; the fake CLI journals
        # themselves remain real host-native files under the test's private root.
        self.enterContext(patch.object(profile, "Path", PurePosixPath))
        authority = "11111111-1111-1111-1111-111111111111"
        gc = {"authority": "22222222-2222-2222-2222-222222222222",
              "key_id": "33333333-3333-3333-3333-333333333333",
              "client_namespace": "44444444-4444-4444-4444-444444444444",
              "data_protocol": 2, "disk_format": 3, "gc_protocol": 2}
        choice = dict(transport="rdma", rdma_interface="eth0", rdma_address="192.0.2.10", rdma_device="mlx5_0")
        configs, _ = profile.generate_configs(HERE.parents[2], self.root, 20000, authority, "FAKE_ONLY",
                                               profile="gc", gc=gc, file_api=True, **choice)
        (self.root / "config").mkdir(mode=0o700)
        (self.root / "state").mkdir(mode=0o700)
        for name, value in configs.items():
            folder = "client" if name in ("stripe-client.toml", "file-client.toml") else "config"
            (self.root / folder / name).write_text(profile.to_toml(value), encoding="utf-8")
        manifest = {"schema": 1, "profile": profile.GC_PROFILE, "file_api": True, "gc": gc,
                    "root": str(self.root), "port_base": 20000, "authority": authority, "cluster_id": "FAKE_ONLY",
                    "data_transport": profile.requested_transport(**choice)}
        (self.root / "cluster.json").write_bytes(mod.json_data(manifest))
        (self.root / "state/initialized.json").write_bytes(mod.json_data({
            "schema": 1, "cluster_id": "FAKE_ONLY", "data_transport": manifest["data_transport"]}))
        return manifest

    def test_rdma_case_binds_actual_commands_outside_native_journals(self):
        manifest = self.rdma_profile()
        r = self.runner()
        r.case("bound", "kv112", "helper", 2, "direct")
        self.assertEqual(len(self.calls()), 5)
        for call in self.calls():
            self.assertEqual(call["options"]["config.storage_transport"], "rdma")
            self.assertNotIn("transport", mod.load_json(Path(call["run"]) / "record.json"))
        bindings = list((self.root / "client/transport-bindings").glob("*.json"))
        self.assertEqual(len(bindings), 3)
        for path in bindings:
            value = mod.load_json(path)
            self.assertEqual(value["profile"]["data_transport_requested"], manifest["data_transport"])
            self.assertEqual(value["profile"]["transport_validation"], "configuration_only")
            self.assertEqual(Path(value["run_dir"]).parent, r.runs)
        result = r.summary("passed")
        self.assertEqual(result["transport"], r.transport)
        self.assertFalse(result["performance_validated"])
        self.assertTrue(result["checks"][0]["readback"]["remote_released"])

    def test_rdma_drift_and_unbound_recovery_are_rejected_before_child(self):
        self.rdma_profile()
        r = self.runner()
        run = r.runs / "unstarted"
        with patch.object(mod.subprocess, "Popen") as popen:
            manifest_path = self.root / "cluster.json"
            manifest_bytes = manifest_path.read_bytes()
            changed_manifest = json.loads(manifest_bytes)
            changed_manifest["schema"] = True
            manifest_path.write_bytes(mod.json_data(changed_manifest))
            with self.assertRaisesRegex(mod.CheckError, "matching prepared native root"):
                r.invoke(run, "new-write")
            manifest_path.write_bytes(manifest_bytes)
            with self.assertRaisesRegex(mod.CheckError, "per-command override"):
                r.invoke(run, "new-write", storage_transport="tcp")
            original = r.config.read_bytes()
            r.config.write_bytes(original + b"\n# changed experiment condition\n")
            with self.assertRaisesRegex(mod.CheckError, "changed during"):
                r.invoke(run, "new-write")
            r.config.write_bytes(original)
            run.mkdir(mode=0o700)
            with self.assertRaisesRegex(mod.CheckError, "no wrapper transport binding"):
                r.invoke(run, "resume")
            popen.assert_not_called()
        self.assertFalse((self.root / "client/transport-bindings").exists())
        self.assertEqual(list(run.iterdir()), [])
        other = self.root / "client/other.toml"
        other.write_bytes(original)
        with self.assertRaisesRegex(mod.CheckError, "external override"):
            mod.Runner(self.root, config=other)

    def test_rdma_record_only_failure_keeps_original_binding_for_resume(self):
        self.rdma_profile()
        r = self.runner("record-only")
        run = r.runs / "record-only"
        info = mod.sample_info(self.root, "kv112")
        with self.assertRaisesRegex(mod.CheckError, "CLI failed with exit2"):
            r.invoke(run, "new-write", input_file=info[0], remote_path="/ec-lab/record-only", shard_bytes=info[2])
        before = (run / "record.json").read_bytes()
        original = {p.name: p.read_bytes() for p in (self.root / "client/transport-bindings").iterdir()}
        resumed = self.runner()
        resumed.invoke(run, "resume")
        mod.published(run, info)
        self.assertEqual((run / "record.json").read_bytes(), before)
        self.assertEqual({p.name: p.read_bytes() for p in (self.root / "client/transport-bindings").iterdir()}, original)
        self.assertEqual([item["command"] for item in self.calls()], ["new-write", "resume"])
        binding_path = next((self.root / "client/transport-bindings").iterdir())
        binding_bytes = binding_path.read_bytes()
        for nested in (False, True):
            changed = json.loads(binding_bytes)
            if nested:
                changed["profile"]["data_transport_requested"]["schema"] = True
            else:
                changed["schema"] = True
            binding_path.write_bytes(mod.json_data(changed))
            with patch.object(mod.subprocess, "Popen") as popen, \
                 self.assertRaisesRegex(mod.CheckError, "binding differs"):
                resumed.invoke(run, "resume")
            popen.assert_not_called()
        binding_path.write_bytes(binding_bytes)
        with self.assertRaisesRegex(mod.CheckError, "continued as an unbound TCP"):
            mod.bind_transport_run(self.root, run, None, resumed.cli)

    def test_rdma_file_wrapper_and_formal_child_owner_use_same_bound_config(self):
        self.rdma_profile()
        def load(name, filename):
            spec = importlib.util.spec_from_file_location(name, HERE / filename)
            value = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(value)
            return value
        wrapper = load("rdma_file_wrapper", "file-command.py")
        transport = load("rdma_formal_child", "ack-service-acceptance.py")
        run = self.root / "client/new-file-operation"
        args = wrapper.parser().parse_args(["--root", str(self.root), "--show-command", "create",
                                            "--run-dir", str(run), "--path", "/ec-lab/rdma-file"])
        argv = wrapper.command(args)
        self.assertIn("--config.storage_transport=rdma", argv)
        self.assertFalse(run.exists())
        self.assertFalse((self.root / "client/transport-bindings").exists())
        r = mod.Runner(self.root, config=self.root / "client/file-client.toml")
        proc = Mock(pid=123, returncode=0)
        proc.poll.return_value = 0
        with patch.object(transport.os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), create=True), \
             patch.object(transport.subprocess, "Popen", return_value=proc) as popen:
            changed = [arg.replace("--config.storage_transport=rdma", "--config.storage_transport=tcp") for arg in argv]
            with self.assertRaisesRegex(RuntimeError, "differs from prepared"):
                transport.command(r, mod, changed)
            popen.assert_not_called()
            self.assertEqual(transport.command(r, mod, argv), "")
            self.assertEqual(popen.call_args.args[0], argv)
        proc.wait.assert_called_once()
        self.assertIsNone(r.child)
        self.assertFalse(run.exists())  # Only the native process may create this path.
        self.assertEqual(len(list((self.root / "client/transport-bindings").glob("*.json"))), 1)
        self.assertEqual(r.commands[0]["transport"]["transport_validation"], "configuration_only")
        control = mod.Runner(self.root, config=self.root / "config/admin_cli.toml")
        self.assertIsNone(control.check_transport())

    def test_root_is_mandatory_and_preserves_explicit_paths(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing:
                mod.parser().parse_args(["inputs"])
        self.assertEqual(missing.exception.code, 2)
        supplied = self.root / "bundle with spaces"
        parsed = mod.parser().parse_args(["--root", str(supplied), "inputs"])
        self.assertEqual(parsed.root, supplied)
        self.assertFalse(supplied.exists())  # Parsing cannot initialize a lab.

    @unittest.skipUnless(sys.platform == "linux", "Real POSIX signals require Linux; not native 3FS")
    def test_linux_signals_wait_for_actual_child_exit_without_starting_another(self):
        worker = (
            "import os,signal,sys,time;from pathlib import Path;"
            "assert os.getsid(0)!=os.getsid(os.getppid());"
            "os.kill(os.getppid(),int(sys.argv[1]));time.sleep(0.2);"
            "Path(sys.argv[2]).write_text('child completed')"
        )
        for name in ("SIGINT", "SIGTERM", "SIGHUP"):
            with self.subTest(signal=name):
                marker = self.root / (name + "-completed")
                r = mod.Runner(self.root, [sys.executable, "-c", worker,
                    str(int(getattr(signal, name))), str(marker)])
                with r.signal_scope():
                    with self.assertRaises(mod.StopRequested):
                        r.invoke(r.runs / ("signal-" + name), "new-write")
                    with self.assertRaises(mod.StopRequested):
                        r.invoke(r.runs / ("after-" + name), "new-write")
                self.assertEqual(marker.read_text(), "child completed")
                self.assertIsNone(r.child)
                self.assertEqual(len(r.commands), 1)
                self.assertEqual(r.commands[0]["returncode"], 0)
                self.assertTrue(r.commands[0]["process_exited"])
                self.assertFalse(r.commands[0]["remote_release_proven_by_exit"])
                self.assertEqual(r.interrupt_count, 1)

    def test_reporting_failure_after_launch_still_joins_the_owned_child(self):
        r = self.runner("delayed")
        original = r.event
        def failed_event(value):
            if value["event"] == "command_started":
                raise OSError("injected report failure after Popen")
            original(value)
        r.event = failed_event
        with self.assertRaisesRegex(OSError, "after Popen"):
            r.case("report-failure", "multi", "central", 1)
        self.assertTrue((self.root / "fake-exited").exists())
        self.assertIsNone(r.child)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(r.commands[0]["returncode"], 0)
        self.assertTrue(r.commands[0]["process_exited"])
        self.assertFalse(r.commands[0]["remote_release_proven_by_exit"])

    def test_inputs_are_deterministic_and_never_overwritten(self):
        report = mod.generate_inputs(self.root)
        self.assertEqual(report["samples"]["multi"]["bytes"], 1048576)
        path = self.root / "client/inputs/multi.bin"
        path.write_bytes(b"modified")
        with self.assertRaises(mod.CheckError):
            mod.generate_inputs(self.root)
        self.assertEqual(path.read_bytes(), b"modified")

    def test_six_cases_boundaries_and_new_read_use_exact_explicit_commands(self):
        r = self.runner()
        r.matrix("six")
        r.boundaries("bounds")
        self.assertEqual(len(r.checked), 8)
        for item in r.checked:
            self.assertTrue(item["readback"]["byte_equal"])
            self.assertTrue(item["readback"]["remote_released"])
            self.assertFalse(item["fault_injected"])
        source = r.runs / "repair-six-multi-helper-two"
        r.read_from(source, r.runs / "read-new-after-restart", mod.sample_info(self.root, "multi"))
        self.assertEqual(len(self.calls()), 42)
        result = r.summary("passed")
        self.assertTrue(result["all_started_cli_processes_exited"])
        self.assertFalse(result["cluster_stop_or_restart_performed"])
        with self.assertRaises(mod.CheckError):
            r.matrix("six")

    def test_exit_zero_without_published_stops_before_repair(self):
        r = self.runner("false-published")
        with self.assertRaisesRegex(mod.CheckError, "Published"):
            r.case("bad", "multi", "central", 1)
        self.assertEqual([c["command"] for c in self.calls()], ["new-write"])
        self.assertTrue((r.runs / "write-bad-multi-central-one/record.json").is_file())

    def test_direct_case_preserves_delivery_through_release_read_and_same_record_resume(self):
        r = self.runner()
        for count in (1, 2):
            with self.subTest(replacements=count):
                stem, paths = r.case_paths("direct", "kv112", "helper", count, "direct")
                self.assertTrue(stem.endswith("-direct"))
                self.assertNotEqual(paths, r.case_paths("direct", "kv112", "helper", count)[1])
                r.case("direct", "kv112", "helper", count, "direct")
                repair = paths[1]
                fixed = (repair / "record.json").read_bytes()
                record, state = mod.journal(repair)
                self.assertEqual((record["version"], record["delivery"], state["state"]),
                                 (3, "direct", "ReadReleased"))
                self.assertTrue(r.checked[-1]["readback"]["byte_equal"])
                self.assertTrue(r.checked[-1]["readback"]["remote_released"])
                self.assertEqual(r.checked[-1]["delivery"], "direct")
                r.invoke(repair, "resume")
                mod.published(repair, mod.sample_info(self.root, "kv112"))
                self.assertEqual((repair / "record.json").read_bytes(), fixed)
                r.release(repair)
                self.assertEqual((repair / "record.json").read_bytes(), fixed)
        for call in self.calls():
            options = call["options"]
            if call["command"] == "new-repair":
                self.assertEqual(options["config.delivery"], "direct")
            else:
                self.assertNotIn("config.delivery", options)

    def test_direct_cannot_be_downgraded_to_a_successful_return_record(self):
        r = self.runner("delivery-downgrade")
        with self.assertRaisesRegex(mod.CheckError, "changed requested delivery"):
            r.case("downgrade", "kv112", "helper", 1, "direct")
        self.assertEqual([c["command"] for c in self.calls()], ["new-write", "new-repair"])
        _, paths = r.case_paths("downgrade", "kv112", "helper", 1, "direct")
        record, state = mod.journal(paths[1])
        self.assertEqual((record["version"], state["state"]), (1, "Published"))
        self.assertEqual(r.checked, [])

    def test_delivery_and_version_mismatches_are_rejected_before_another_process(self):
        r = self.runner()
        for strategy, delivery in (("central", "direct"), ("pipeline", "direct"), ("helper", "unknown")):
            with self.subTest(strategy=strategy, delivery=delivery), self.assertRaises(mod.CheckError):
                r.case("invalid", "kv112", strategy, 1, delivery)
        self.assertFalse((self.root / "fake-invocations.jsonl").exists())
        r.case("record", "kv112", "helper", 1, "direct")
        _, paths = r.case_paths("record", "kv112", "helper", 1, "direct")
        record_path = paths[1] / "record.json"
        fixed = record_path.read_bytes()
        original = json.loads(fixed)
        calls = self.calls()
        changes = ({"version": 1}, {"version": 2}, {"version": 4}, {"delivery": "return"},
                   {"delivery": None}, {"strategy": "central"}, {"action": "write"},
                   {"recoverySource": None})
        for changed in changes:
            with self.subTest(changed=changed):
                record_path.write_text(json.dumps(dict(original, **changed)), encoding="utf-8")
                with self.assertRaises(mod.CheckError):
                    r.invoke(paths[1], "resume")
                self.assertEqual(self.calls(), calls)
        missing = dict(original)
        del missing["delivery"]
        record_path.write_text(json.dumps(missing), encoding="utf-8")
        with self.assertRaises(mod.CheckError):
            r.release(paths[1])
        self.assertEqual(self.calls(), calls)
        record_path.write_bytes(fixed)

    def test_incomplete_ack_does_not_become_remote_released(self):
        r = self.runner("incomplete-release")
        with self.assertRaisesRegex(mod.CheckError, "ACK"):
            r.case("ack", "multi", "pipeline", 2)
        self.assertEqual([c["command"] for c in self.calls()], ["new-write", "new-repair", "release"])

    def test_stale_success_and_changed_permanent_record_are_rejected(self):
        for index, (mode, message) in enumerate((("stale-release", "new observation"),
                                                 ("mutated-record", "immutable run record"))):
            r = self.runner(mode)
            with self.assertRaisesRegex(mod.CheckError, message):
                r.case(f"stale{index}", "multi", "central", 1)
            self.assertEqual(r.commands[-1]["command"], "release")

    def test_corrupt_read_preserves_journal_and_does_not_release_failed_read(self):
        r = self.runner("corrupt-read")
        with self.assertRaisesRegex(mod.CheckError, "bytes differ"):
            r.case("crc", "multi", "helper", 2)
        self.assertEqual(self.calls()[-1]["command"], "new-read")
        self.assertEqual(len(self.calls()), 4)
        self.assertTrue((r.runs / "read-crc-multi-helper-two/record.json").exists())

    def test_unknown_is_not_retried_with_a_new_operation(self):
        r = self.runner("unknown")
        with self.assertRaisesRegex(mod.CheckError, "exit1"):
            r.case("unknown", "multi", "central", 1)
        self.assertEqual(len(self.calls()), 1)
        record, observation = mod.journal(r.runs / "write-unknown-multi-central-one")
        self.assertEqual(observation["errorCode"], 4085)
        self.assertTrue(record["operation"])

    def test_record_only_failure_resumes_same_ids_and_requires_first_observation(self):
        info = mod.sample_info(self.root, "multi")
        early = self.runner("record-only")
        run = early.runs / "write-record-only"
        with self.assertRaisesRegex(mod.CheckError, "exit2"):
            early.invoke(run, "new-write", input_file=info[0],
                         remote_path="/ec-lab/record-only", shard_bytes=info[2])
        fixed = (run / "record.json").read_bytes()
        record = json.loads(fixed)
        identities = {name: record[name] for name in (
            "clientNamespace", "createRequest", "operation", "beginRequest", "bindRequest", "publishRequest",
            "getRequest", "prepareRepairRequest", "pin", "acquireRequest", "releaseRequest", "planId")}
        self.assertFalse(list(run.glob("state-*.json")))
        # Only resume admission permits this shape, never success/release evidence.
        for check in (lambda: mod.journal(run), lambda: mod.published(run, info),
                      lambda: mod.verify_read(run, info), lambda: mod.released(run),
                      lambda: self.runner().release(run)):
            with self.assertRaisesRegex(mod.CheckError, "No observation"):
                check()
        with self.assertRaisesRegex(mod.CheckError, "No observation"):
            self.runner("record-only-no-observation").invoke(run, "resume")
        self.assertEqual((run / "record.json").read_bytes(), fixed)
        self.assertFalse(list(run.glob("state-*.json")))
        # Exercise main's real resume dispatch as well as invoke's before/after
        # checks. The child is still the explicit Windows fake, never native 3FS.
        resumed = self.runner()
        with patch.object(mod.sys, "platform", "linux"), \
             patch.object(mod.sys, "argv", ["experiment-runner.py", "--root", str(self.root),
                                             "resume", "--run-dir", str(run), "--sample", "multi"]), \
             patch.object(mod, "Runner", return_value=resumed):
            self.assertEqual(mod.main(), 0)
        self.assertEqual((run / "record.json").read_bytes(), fixed)
        recovered, state = mod.published(run, info)
        self.assertEqual({name: recovered[name] for name in identities}, identities)
        self.assertEqual(state["sequence"], 0)
        self.assertEqual([p.name for p in run.glob("state-*.json")], ["state-00000000000000000000.json"])
        self.assertEqual([entry["command"] for entry in self.calls()], ["new-write", "resume", "resume"])

    def test_offline_read_verification_does_not_trust_a_release_label_alone(self):
        r = self.runner()
        r.case("offline", "kv112", "central", 1)
        run = r.runs / "read-offline-kv112-central-one"
        info = mod.sample_info(self.root, "kv112")
        self.assertTrue(mod.verify_read(run, info)["remote_released"])
        state = sorted(run.glob("state-*.json"))[-1]
        value = json.loads(state.read_text())
        value["acknowledgedEndpoints"] = 11
        state.write_text(json.dumps(value))
        with self.assertRaisesRegex(mod.CheckError, "ACK"):
            mod.verify_read(run, info)

    def test_stop_request_waits_for_the_owned_child_and_starts_nothing_else(self):
        r = self.runner("delayed")
        outcome = []
        def work():
            try:
                r.case("interrupt", "multi", "central", 1)
            except BaseException as error:
                outcome.append(error)
        thread = threading.Thread(target=work)
        thread.start()
        deadline = time.monotonic() + 10
        while not (self.root / "fake-started").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue((self.root / "fake-started").exists())
        r.request_stop()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(outcome[0], mod.StopRequested)
        self.assertTrue((self.root / "fake-exited").exists())
        self.assertIsNone(r.child)
        self.assertEqual(len(self.calls()), 1)
        summary = r.summary("interrupted_after_child_exit")
        self.assertTrue(summary["all_started_cli_processes_exited"])
        self.assertFalse(summary["commands"][0]["remote_release_proven_by_exit"])

    def test_malformed_json_numbers_and_sequence_gaps_are_rejected(self):
        path = self.root / "bad.json"
        for text in ('{"x":1,"x":2}', '{"x":-1}', '{"x":1.5}', '{"x":NaN}'):
            path.write_text(text)
            with self.assertRaises(mod.CheckError):
                mod.load_json(path)
        r = self.runner()
        r.case("gap", "kv112", "central", 1)
        run = r.runs / "repair-gap-kv112-central-one"
        (run / "state-00000000000000000001.json").rename(run / "state-00000000000000000003.json")
        with self.assertRaisesRegex(mod.CheckError, "gapped"):
            mod.journal(run)


if __name__ == "__main__":
    unittest.main()
