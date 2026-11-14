"""Pure menu tests: temporary metadata and mocked exec, never business processes."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("experiment_menu_tested", SCRIPTS / "experiment-menu.py")
menu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu)


class MenuAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "bundle with spaces"
        self.root.mkdir()
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        self.manifest = {"root": str(self.root), "file_api": True,
                         "profile": "native-gc-local-1-storage-12-targets"}
        self.write_manifest()
        self.preparation = self.root / "preparation.json"
        self.preparation.write_text("{}", encoding="utf-8")
        self.file = self.root / "new data.bin"
        self.output = self.root / "new local report"
        self.record = self.root / "original result.json"
        self.record.write_text(json.dumps({"state": "confirmed", "phase": "prepare", "root": str(self.root),
                                          "preparation": str(self.preparation), "file": str(self.file)}), encoding="utf-8")

    def write_manifest(self):
        (self.root / "cluster.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def choose(self, function, answers):
        with mock.patch("builtins.input", side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            return function(self.root, self.scripts)

    def snapshot(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))

    def test_basic_and_repair_forward_only_fixed_phase_arguments_without_writing(self):
        before = self.snapshot()
        for number, phase in (("1", "basic"), ("2", "repair")):
            with self.subTest(phase=phase):
                command = self.choose(menu.file_acceptance_selection, [number, "sample-1"])
                self.assertEqual(command, [sys.executable, "-B", str(self.scripts / "file-cli-acceptance.py"),
                                           "--root", str(self.root), "--label", "sample-1", phase])
                self.assertEqual(self.snapshot(), before)

    def test_flat_helper_delivery_is_explicit_and_six_case_matrix_stays_unchanged(self):
        before = self.snapshot()
        for choice, delivery in (("1", "return"), ("2", "direct")):
            with self.subTest(delivery=delivery):
                command = self.choose(menu.selection, ["3", "single", "3", choice, "2", "1"])
                self.assertEqual(command, [sys.executable, "-B", str(self.scripts / "experiment-runner.py"),
                    "--root", str(self.root), "case", "--label", "single", "--strategy", "helper",
                    "--delivery", delivery, "--replacements", "2", "--sample", "kv112"])
        central = self.choose(menu.selection, ["3", "single", "1", "1", "1"])
        self.assertNotIn("--delivery", central)
        matrix = self.choose(menu.selection, ["4", "six"])
        self.assertEqual(matrix[-3:], ["matrix", "--label", "six"])
        self.assertNotIn("--delivery", matrix)
        self.assertEqual(self.snapshot(), before)

    def test_explicit_file_api_profile_is_required_and_not_modified(self):
        for changed in ({"file_api": False}, {"file_api": 1}, {"profile": "native-v2-local-1-storage-12-targets"},
                        {"profile": []}, {"root": str(self.root / "another")}):
            with self.subTest(changed=changed):
                manifest = dict(self.manifest, **changed)
                (self.root / "cluster.json").write_text(json.dumps(manifest), encoding="utf-8")
                before = (self.root / "cluster.json").read_bytes()
                with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                    menu.file_api_profile(self.root)
                self.assertEqual((self.root / "cluster.json").read_bytes(), before)
        self.manifest["profile"] = "native-gc-local-12-storage-12-targets"
        self.write_manifest()
        with contextlib.redirect_stdout(io.StringIO()):
            menu.file_api_profile(self.root)

    def test_label_reprompts_above_native_48_character_limit_and_for_injection(self):
        command = self.choose(menu.file_acceptance_selection, ["1", "x" * 49, "bad;name", "ok_" + "x" * 45])
        self.assertEqual(command[-2], "ok_" + "x" * 45)
        self.assertEqual(len(command[-2]), 48)

    def test_existing_phase_is_rejected_without_recovery_or_new_identity(self):
        phase = self.root / "client/file-cli-acceptance/fixed/basic"
        phase.mkdir(parents=True)
        original = phase / "result.json"
        original.write_bytes(b"original failed receipt")
        with self.assertRaisesRegex(ValueError, "该阶段已存在"):
            self.choose(menu.file_acceptance_selection, ["1", "fixed"])
        self.assertEqual(original.read_bytes(), b"original failed receipt")

    def test_usrbio_prepare_forwards_new_paths_and_packaged_helpers(self):
        before = self.snapshot()
        command = self.choose(menu.usrbio_selection, ["1", str(self.preparation), str(self.file), str(self.output)])
        self.assertEqual(command, [sys.executable, "-B", str(self.scripts / "mode4-usrbio-acceptance.py"), "prepare",
                                   "--root", str(self.root), "--preparation", str(self.preparation),
                                   "--helpers-dir", str(self.scripts), "--file", str(self.file),
                                   "--output-dir", str(self.output)])
        self.assertEqual(self.snapshot(), before)

    def test_usrbio_verify_uses_exact_original_paths_and_does_not_read_data(self):
        before = self.snapshot()
        command = self.choose(menu.usrbio_selection, ["2", str(self.record), str(self.output)])
        self.assertEqual(command[-2:], ["--prepared-record", str(self.record)])
        self.assertEqual(command[command.index("--preparation") + 1], str(self.preparation))
        self.assertEqual(command[command.index("--file") + 1], str(self.file))
        self.assertFalse(self.file.exists())  # Actual mount/data validation is left to the driver.
        self.assertEqual(self.snapshot(), before)

    def test_usrbio_rejects_failed_wrong_root_or_relative_original_receipt(self):
        original = json.loads(self.record.read_text(encoding="utf-8"))
        for changed in ({"state": "unconfirmed"}, {"phase": "verify"}, {"root": str(self.root / "other")},
                        {"preparation": "relative.json"}, {"file": 42}):
            with self.subTest(changed=changed):
                self.record.write_text(json.dumps(dict(original, **changed)), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.choose(menu.usrbio_selection, ["2", str(self.record)])
        self.assertFalse(self.output.exists())

    def test_new_path_reprompts_for_existing_file_and_unprepared_parent(self):
        with mock.patch("builtins.input", side_effect=[str(self.record), str(self.root / "missing/new"), str(self.output)]), \
                contextlib.redirect_stdout(io.StringIO()):
            result = menu.new_path("new")
        self.assertEqual(result, self.output)
        self.assertFalse(result.exists())

    def main(self, answers, print_only=False, create_driver=True):
        target = self.scripts / "file-cli-acceptance.py"
        if create_driver:
            target.write_text("# not executable in this test\n", encoding="utf-8")
        argv = ["experiment-menu.py", "--root", str(self.root)]
        if print_only:
            argv += ["--print-only"]
        output = io.StringIO()
        with mock.patch.object(menu, "__file__", str(self.scripts / "experiment-menu.py")), \
                mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", side_effect=answers) as prompts, \
                mock.patch.object(menu.os, "execv", side_effect=RuntimeError("mocked exec only")) as execute, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                code = menu.main()
            except RuntimeError as error:
                self.assertEqual(str(error), "mocked exec only")
                code = "exec"
            except SystemExit as error:
                code = error.code
            return code, prompts.call_count, execute.call_args_list, output.getvalue()

    def test_print_only_never_requests_execution_confirmation_or_executes(self):
        code, count, executed, text = self.main(["11", "1", "dry-run"], print_only=True)
        self.assertEqual((code, count, executed), (0, 3, []))
        self.assertIn("file-cli-acceptance.py", text)
        self.assertIn("仅显示命令", text)
        self.assertFalse((self.root / "client").exists())

    def test_new_phase_requires_confirmation_after_showing_command(self):
        code, count, executed, text = self.main(["11", "2", "matrix", "取消"])
        self.assertEqual((code, count, executed), (0, 4, []))
        self.assertIn("file-cli-acceptance.py", text)
        self.assertIn("已取消", text)
        code, _, executed, text = self.main(["11", "1", "basic", "执行"])
        self.assertEqual(code, "exec")
        self.assertEqual(len(executed), 1)
        args = executed[0].args
        self.assertEqual(args[0], sys.executable)
        self.assertEqual(args[1][-1], "basic")
        self.assertNotIn("shell", args[1])
        self.assertFalse((self.root / "client").exists())

    def test_missing_packaged_driver_rejected_before_confirmation_or_dispatch(self):
        code, count, executed, _ = self.main(["11", "1", "fresh"], create_driver=False)
        self.assertEqual((code, count, executed), (2, 3, []))

    def test_existing_status_and_data_inputs_selection_unchanged(self):
        for number, expected in (("1", ["native-v2.py", "status", "--root", str(self.root)]),
                                 ("2", ["experiment-runner.py", "--root", str(self.root), "inputs"])):
            with self.subTest(number=number):
                command = self.choose(menu.selection, [number])
                self.assertEqual(command[:2], [sys.executable, "-B"])
                self.assertEqual(command[2:], [str(self.scripts / expected[0]), *expected[1:]])


if __name__ == "__main__":
    unittest.main()
