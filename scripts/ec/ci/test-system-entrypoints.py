#!/usr/bin/env python3
"""Receipt and budget checks only; no subprocess, service, or network calls."""
import contextlib
import ast
import copy
import fnmatch
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


regression = load("checked_regressions", "run-native-regressions.py")
budget = load("checked_system_budget", "system-job-budget.py")


class SystemEntrypoints(unittest.TestCase):
    def test_required_target_retirement_cases_are_selected_by_real_driver(self):
        driver = regression.module(Path(__file__).parent.parent / "test-native-fragments.py", "retirement_native_driver")
        filters = {"storage": driver.STORAGE_FILTER, "service": driver.SERVICE_FILTER, "client": driver.CLIENT_FILTER}
        self.assertTrue(all(regression.TARGET_RETIREMENT_REQUIRED.values()))
        required = {**regression.TARGET_RETIREMENT_REQUIRED, "client": regression.CLIENT_MANDATORY}
        for kind, names in required.items():
            for name in names:
                with self.subTest(suite=kind, case=name):
                    self.assertTrue(any(fnmatch.fnmatchcase(name, pattern) for pattern in filters[kind].split(":")))

    def test_other_green_cases_do_not_satisfy_target_retirement_acceptance(self):
        required = {"storage": {"Retirement.DurableAndHeldTicket"},
                    "service": {"Retirement.RealRpcAndDisabled"}}
        def case(name):
            return {"name": name, "executed": True, "failed": False, "skipped": False}
        rows = [{"suite": kind, "xml_results": {"cases": [case("Unrelated.Passed"), case(name)]}}
                for kind, names in required.items() for name in names]
        with mock.patch.object(regression, "TARGET_RETIREMENT_REQUIRED", required):
            self.assertEqual(regression.check_target_retirement({"suites": rows}),
                             {kind: sorted(names) for kind, names in required.items()})
            for mutation in ("missing", "duplicate_suite", "wrong_suite", "duplicate_case",
                             "not_executed", "failed", "skipped"):
                changed = copy.deepcopy(rows)
                if mutation == "missing":
                    changed[0]["xml_results"]["cases"].pop()
                elif mutation == "duplicate_suite":
                    changed.append(copy.deepcopy(changed[0]))
                elif mutation == "wrong_suite":
                    changed[0]["xml_results"], changed[1]["xml_results"] = (
                        changed[1]["xml_results"], changed[0]["xml_results"])
                elif mutation == "duplicate_case":
                    changed[0]["xml_results"]["cases"].append(copy.deepcopy(changed[0]["xml_results"]["cases"][-1]))
                else:
                    changed[0]["xml_results"]["cases"][-1][
                        "executed" if mutation == "not_executed" else mutation] = mutation != "not_executed"
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    regression.check_target_retirement({"suites": changed})
        with mock.patch.object(regression, "TARGET_RETIREMENT_REQUIRED", {"storage": set(), "service": set()}):
            with self.assertRaisesRegex(ValueError, "inventory is incomplete"):
                regression.check_target_retirement({"suites": rows})

    def test_ready_loop_stop_race_is_normal_but_child_and_action_failures_propagate(self):
        source = Path(__file__).parent.parent / "cluster/native-v2.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        loops = [node for node in ast.walk(main) if isinstance(node, ast.While)
                 and isinstance(node.test, ast.UnaryOp) and isinstance(node.test.operand, ast.Call)
                 and ast.unparse(node.test.operand.func) == "cluster.halt.wait"]
        self.assertEqual(len(loops), 1)
        actual = compile(ast.fix_missing_locations(ast.Module(body=loops, type_ignores=[])), str(source), "exec")
        for failure in (None, "child", "action"):
            halt = SimpleNamespace(stopped=False, calls=0)
            def wait(_seconds):
                halt.calls += 1
                halt.stopped = True  # stop arrives immediately after wait returned false
                return halt.calls > 1
            def cancellation_guard():
                if halt.stopped:
                    raise InterruptedError("normal ready-loop stop")
            def child_health():
                if failure == "child":
                    raise RuntimeError("unexpected owned child exit")
            def action():
                if failure == "action":
                    cancellation_guard()
            cluster = SimpleNamespace(halt=SimpleNamespace(wait=wait), healthy=cancellation_guard,
                fault_control=SimpleNamespace(execute_one=action, healthy=child_health))
            if failure is None:
                exec(actual, {"cluster": cluster})
                self.assertEqual(halt.calls, 2)
            else:
                with self.assertRaises(RuntimeError if failure == "child" else InterruptedError):
                    exec(actual, {"cluster": cluster})

    def test_backend_requires_one_successful_actual_cpp_property(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "storage.xml"
            case = ('<testcase classname="TestEcCodec" name="IndependentGoldenVectorEmptyInputAndOwnedOutput" '
                    'status="run" result="completed"><properties>{}</properties>{}</testcase>')
            prop = '<property name="ec_codec_backend" value="{}"/>'
            for backend in ("scalar", "isal"):
                path.write_text("<testsuites>" + case.format(prop.format(backend), "") + "</testsuites>")
                self.assertEqual(regression.backend_property(path, backend), backend)
            for body in (
                "", case.format("", ""), case.format(prop.format("scalar"), ""),
                case.format(prop.format("isal") * 2, ""), case.format(prop.format("isal"), "<failure/>"),
                case.format(prop.format("isal"), "<skipped/>"), case.format(prop.format("isal"), "") * 2,
                case.format(prop.format("isal"), "").replace('status="run"', 'status="notrun"'),
            ):
                path.write_text("<testsuites>" + body + "</testsuites>")
                with self.subTest(body=body), self.assertRaises(ValueError):
                    regression.backend_property(path, "isal")

    def test_native_receipt_rejects_omission_changed_binary_and_incomplete_commands(self):
        build = Path("/fixed/build")
        built = {"binaries": {name: str(index) * 64 for index, name in enumerate(regression.TARGETS)}}
        suites = []
        for kind, target in zip(("storage", "service", "client"), regression.TARGETS):
            names = sorted(regression.MANDATORY) if kind == "storage" else (
                sorted(regression.CLIENT_MANDATORY) if kind == "client" else [kind + ".Case"])
            suites.append({"suite": kind, "status": "passed", "failures": [],
                           "binary": str(build / "tests" / target), "binary_sha256": built["binaries"][target],
                           "binary_sha256_after": built["binaries"][target],
                           "listed_tests": [{"name": name, "disabled": False} for name in names],
                           "xml_results": {"cases": [{"name": name, "executed": True, "failed": False,
                                                       "skipped": False} for name in names]},
                           "listing": {"exitcode": 0}, "execution": {"exitcode": 0}})
        original = {"status": "passed", "exitcode": 0, "failures": [], "suites": suites}
        regression.check_suites(original, build, built)
        changes = [
            lambda r: r["suites"].pop(),
            lambda r: r["suites"][0].update(binary_sha256_after="f" * 64),
            lambda r: r["suites"][0]["execution"].update(timed_out=True),
            lambda r: r["suites"][0]["execution"].update(termination={"leader_reaped": True}),
            lambda r: r["suites"][0]["xml_results"]["cases"][0].update(skipped=True),
            lambda r: (r["suites"][0]["listed_tests"].pop(), r["suites"][0]["xml_results"]["cases"].pop()),
            lambda r: (r["suites"][2]["listed_tests"].pop(), r["suites"][2]["xml_results"]["cases"].pop()),
        ]
        for change in changes:
            value = copy.deepcopy(original)
            change(value)
            with self.assertRaises(ValueError):
                regression.check_suites(value, build, built)

    def test_system_profile_does_not_modify_default_budget_module(self):
        native = load("untouched_native_budget", "job-budget.py")
        system = budget.budget_module()
        self.assertEqual(native.REF, "refs/heads/feat/ec-distributed")
        self.assertEqual((native.REQUIRED_MINUTES, native.LAB_STEP_MINUTES), (50, 45))
        self.assertEqual(system.REF, "refs/heads/feat/ec-system-acceptance")
        self.assertEqual((system.REQUIRED_MINUTES, system.LAB_STEP_MINUTES), (90, 80))
        self.assertNotEqual(native.RECORD_NAME, system.RECORD_NAME)
        target = budget.budget_module("target-meta")
        self.assertEqual(target.REF, "refs/heads/feat/ec-target-meta")
        self.assertEqual(target.JOB_MINUTES, 350)
        self.assertNotEqual(target.RECORD_NAME, system.RECORD_NAME)
        self.assertNotEqual(target.BODY_NAME, system.BODY_NAME)
        self.assertEqual(system.REF, "refs/heads/feat/ec-system-acceptance")
        with self.assertRaises(ValueError):
            budget.budget_module("arbitrary")

    def test_file_and_spare_gates_keep_the_verified_anchor_and_exact_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "base.py"
            path.write_bytes(b"bound base")
            identity = {"run_id": "7", "attempt": "1", "system_driver_sha256": "wrapper"}
            row = {"driver_sha256": "digest", "job_id": 91}
            base = SimpleNamespace(__file__=str(path), RECORD_NAME="receipt", BODY_NAME="body", MAX_BODY=100,
                NANO=1_000_000_000, digest=lambda _: "digest", read_private=mock.Mock(return_value=b"body"),
                parse_json=lambda _: row, require=regression.require, clock=lambda: 77,
                remaining=mock.Mock())
            for stage, minutes, step in (("repair", 80, 75), ("file", 90, 45), ("spare", 40, 35),
                                         ("regression", 40, 35), ("target-meta", 80, 75), ("core", 100, 95)):
                for delta, expected in ((0, 0), (-1, 1)):
                    base.remaining.return_value = minutes * 60 * base.NANO + delta
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(budget.check(base, Path(temp), identity, stage), expected)
                    base.remaining.assert_called_with(row, b"body", identity, 77)
                    printed = json.loads(output.getvalue())
                    self.assertEqual(printed["required_seconds"], minutes * 60)
                    self.assertEqual(printed["step_minutes"], step)
                    self.assertEqual(printed["stage"], stage)
            row["driver_sha256"] = "changed"
            with self.assertRaises(ValueError):
                budget.check(base, Path(temp), identity, "file")

    def test_retirement_fix_branch_is_explicit_and_keeps_public_job_identity_gate(self):
        ref = "refs/heads/fix/ec-retirement-keys"
        fixed = budget.budget_module("target-meta", ref=ref)
        self.assertEqual(fixed.REF, ref)
        self.assertEqual(fixed.JOB, "native")
        self.assertEqual(fixed.JOB_MINUTES, 350)
        self.assertEqual(fixed.RECORD_NAME, "ec-target-meta-job-budget.json")
        self.assertEqual(budget.budget_module("target-meta").REF, "refs/heads/feat/ec-target-meta")
        for profile, other in (("system", ref), ("target-meta", "refs/heads/main"),
                               ("target-meta", "refs/heads/fix/unreviewed"), ("target-meta", "")):
            with self.subTest(profile=profile, ref=other), self.assertRaises(ValueError):
                budget.budget_module(profile, ref=other)
        owned = SimpleNamespace(context=mock.Mock(return_value=(Path("/private"), {})),
                                digest=lambda _: "wrapper", record=mock.Mock(return_value=0))
        with mock.patch.dict(budget.os.environ, {"GITHUB_REF": ref}), \
             mock.patch.object(budget.sys, "argv", ["budget", "record", "--profile", "target-meta"]), \
             mock.patch.object(budget, "budget_module", return_value=owned) as selected:
            self.assertEqual(budget.main(), 0)
            selected.assert_called_once_with("target-meta", ref=ref)
            owned.context.assert_called_once_with()
            owned.record.assert_called_once_with(Path("/private"), {"system_driver_sha256": "wrapper"})


if __name__ == "__main__":
    unittest.main()
