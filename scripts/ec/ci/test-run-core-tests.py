#!/usr/bin/env python3
"""Pure acceptance-contract tests; no ELF, FDB, WSL or service is executed."""

import copy
import importlib.util
import json
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("core_runner", Path(__file__).with_name("run-core-tests.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def xml(names):
    return {"cases": [{"name": name, "executed": True, "failed": False, "skipped": False}
                      for name in names],
            "declared_tests": str(len(names)), "declared_failures": "0", "declared_errors": "0"}


def receipt(binary, output, cases=RUNNER.META_CASES, test_filter=RUNNER.META_FILTER):
    return {"status": "passed", "exitcode": 0, "bootstrap": "passed", "failures": [],
            "selected": list(cases), "test_results": xml(cases),
            "passed_tests": len(cases),
            "commands": [{"argv": [str(binary), *RUNNER.flags(test_filter), *ending], "exitcode": 0}
                         for ending in (["--gtest_list_tests"],
                                        ["--gtest_output=xml:" + str(output / "tests.xml")])],
            "server": {"exitcode_before_cleanup": None, "exitcode_after_cleanup": -15,
                       "cleanup": {"leader_reaped": True}},
            "binaries": {name: {"path": str(binary), "sha256": "a" * 64, "sha256_after": "a" * 64}
                         for name in ("test_meta", "fdbcli", "fdbserver")}}


class TestCoreAcceptanceContract(unittest.TestCase):
    def test_auth_user_profile_requires_both_backends_default_and_explicit_gid(self):
        cases, test_filter, fuse = RUNNER.selection("auth-user")
        expected = ("TestAuth/0.Basic", "TestAuth/0.ExplicitPrimaryGroup",
                    "TestAuth/1.Basic", "TestAuth/1.ExplicitPrimaryGroup")
        self.assertEqual(cases, expected)
        self.assertEqual(test_filter, ":".join(expected))
        self.assertEqual(fuse, ())
        binary, output = Path("/build/tests/test_meta"), Path("/work/meta")
        sample = receipt(binary, output, cases, test_filter)
        RUNNER.check_meta_receipt(sample, binary, output, cases, test_filter)
        for field in ("selected", "test_results", "commands", "server"):
            bad = copy.deepcopy(sample)
            if field == "selected":
                bad[field] = list(cases[:2])
            elif field == "test_results":
                bad[field]["cases"][-1]["skipped"] = True
            elif field == "commands":
                bad[field][0]["argv"][1] = "--gtest_filter=TestAuth/*.Basic"
            else:
                bad[field]["cleanup"]["leader_reaped"] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                RUNNER.check_meta_receipt(bad, binary, output, cases, test_filter)
        self.assertEqual(len(RUNNER.selection("core")[0]) + len(RUNNER.selection("core")[2]), 26)
        combined, combined_filter, combined_fuse = RUNNER.selection("service-contracts")
        self.assertEqual(combined, expected + (
            "TestMetaServiceReflection.RegistersAll71IncludingBeyondDefaultFieldRank",))
        self.assertEqual(combined_filter, ":".join(combined))
        self.assertEqual(combined_fuse, ())
        RUNNER.check_meta_receipt(receipt(binary, output, combined, combined_filter), binary, output,
                                  combined, combined_filter)
        with self.assertRaises(ValueError):
            RUNNER.check_meta_receipt(sample, binary, output, combined, combined_filter)

    def test_target_meta_profile_requires_all_nine_cases_and_exact_commands(self):
        cases, test_filter, fuse = RUNNER.selection("target-meta")
        self.assertEqual(len(cases), 9)
        self.assertEqual(len(set(cases)), 9)
        self.assertEqual(test_filter, ":".join(cases))
        self.assertEqual(fuse, ())
        binary, output = Path("/build/tests/test_meta"), Path("/work/meta")
        sample = receipt(binary, output, cases, test_filter)
        RUNNER.check_meta_receipt(sample, binary, output, cases, test_filter)
        for mutation in ("missing", "skip", "wrong_filter", "other_profile", "unjoined"):
            value = copy.deepcopy(sample)
            if mutation == "missing":
                value["selected"].pop()
                value["test_results"]["cases"].pop()
                value["test_results"]["declared_tests"] = "8"
                value["passed_tests"] = 8
            elif mutation == "skip":
                value["test_results"]["cases"][-1]["skipped"] = True
            elif mutation == "wrong_filter":
                value["commands"][0]["argv"][1] = "--gtest_filter=TestEcTargetRetirementNative.*"
            elif mutation == "other_profile":
                value = receipt(binary, output)
            else:
                value["server"]["cleanup"]["leader_reaped"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                RUNNER.check_meta_receipt(value, binary, output, cases, test_filter)

    def test_target_meta_inventory_matches_compiled_fixture_sources(self):
        import re
        source = Path(__file__).resolve().parents[3]
        files = ("tests/meta/store/TestEcTargetRetirementCatalog.cc",
                 "tests/meta/EcTargetRetirementNativeTests.inc",
                 "tests/meta/store/TestEcTargetRetirementEvidence.inc")
        names = []
        for filename in files:
            body = (source / filename).read_text(encoding="utf-8")
            names.extend(suite + "." + name for suite, name in re.findall(
                r"TEST_F\(\s*(\w+)\s*,\s*(\w+)\s*\)", body))
        RUNNER.exact_names(names, RUNNER.TARGET_META_CASES)
        self.assertIn('#include "EcTargetRetirementNativeTests.inc"',
                      (source / "tests/meta/TestEcV2NativeLifecycle.cc").read_text(encoding="utf-8"))
        self.assertIn('#include "TestEcTargetRetirementEvidence.inc"',
                      (source / "tests/meta/store/TestEcFileTree.cc").read_text(encoding="utf-8"))

    def test_failed_meta_keeps_cleanup_evidence_without_accepting_stage(self):
        for cleanup in (None, {"signals": ["SIGTERM"], "leader_reaped": True},
                        {"signals": ["SIGTERM", "SIGKILL"], "leader_reaped": False}):
            with self.subTest(cleanup=cleanup), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                output = work / "meta"
                output.mkdir()
                binary = work / "build/tests/test_meta"
                sample = receipt(binary, output)
                sample.update(status="failed", exitcode=1, failures=["XML failure"], passed_tests=0)
                sample["server"].update(private_config="must not appear in console")
                if cleanup is None:
                    sample["server"].pop("cleanup")
                else:
                    sample["server"]["cleanup"] = cleanup
                (output / "results.json").write_text(json.dumps(sample), encoding="utf-8")
                common = SimpleNamespace(listed_tests=mock.Mock(), sha256=lambda _: "b" * 64)
                module = SimpleNamespace(main=lambda: 1)
                report = {}
                with mock.patch.object(RUNNER, "load_module", return_value=module):
                    with self.assertRaisesRegex(ValueError, "Meta driver returned nonzero"):
                        RUNNER.run_meta(work / "source", work / "build", work / "fdb", work,
                                        common, SimpleNamespace(received=[]), report)
                stage = report["meta"]
                self.assertNotIn("status", stage)
                self.assertNotIn("passed_tests", stage)
                self.assertEqual(stage["receipt_sha256"], "b" * 64)
                observed = stage["driver_observation"]
                self.assertEqual(observed["status"], "failed")
                self.assertEqual(observed["exitcode"], 1)
                self.assertIsNone(observed["server"]["exitcode_before_cleanup"])
                self.assertEqual(observed["server"]["exitcode_after_cleanup"], -15)
                self.assertEqual(observed["server"]["cleanup"], cleanup or {})
                self.assertNotIn("private_config", observed["server"])

    def test_repair_driver_uses_exact_filter_and_restores_listing_hook(self):
        # The external FDB owner is faked; exercise the real wrapper's argv,
        # pre-dispatch selection, receipt/XML checks and hook restoration.
        cases, test_filter, _ = RUNNER.selection("repair")
        for invalid_listing in (False, True):
            with self.subTest(invalid_listing=invalid_listing), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                source, build, fdb = work / "source", work / "build", work / "fdb"
                output = work / "meta"
                output.mkdir()
                binary = build / "tests/test_meta"
                names = RUNNER.META_CASES if invalid_listing else cases
                listing = mock.Mock(return_value=[{"name": name, "disabled": False} for name in names])
                common = SimpleNamespace(listed_tests=listing, xml_tests=lambda _: xml(cases),
                                         sha256=lambda _: "a" * 64)
                module = SimpleNamespace()
                def child_main():
                    argv = RUNNER.sys.argv
                    self.assertEqual(argv[argv.index("--filter") + 1], test_filter)
                    self.assertEqual(module.helpers(), common)
                    common.listed_tests(output / "test-list.log")
                    (output / "results.json").write_text(
                        json.dumps(receipt(binary, output, cases, test_filter)), encoding="utf-8")
                    return 0
                module.main = child_main
                original_argv = RUNNER.sys.argv
                report = {}
                with mock.patch.object(RUNNER, "load_module", return_value=module):
                    if invalid_listing:
                        with self.assertRaises(ValueError):
                            RUNNER.run_meta(source, build, fdb, work, common, SimpleNamespace(received=[]),
                                            report, cases, test_filter)
                        self.assertFalse((output / "results.json").exists())
                    else:
                        RUNNER.run_meta(source, build, fdb, work, common, SimpleNamespace(received=[]),
                                        report, cases, test_filter)
                        self.assertEqual(report["meta"]["passed_tests"], len(cases))
                        self.assertEqual(report["meta"]["status"], "passed")
                self.assertIs(RUNNER.sys.argv, original_argv)
                self.assertIs(common.listed_tests, listing)

    def test_repair_profile_is_fixed_and_cannot_replace_core_evidence(self):
        base = ["--source", "/source", "--build", "/build",
                "--fdb-bin-dir", "/fdb", "--work", "/private/new"]
        self.assertEqual(RUNNER.parser().parse_args(base).profile, "core")
        self.assertEqual(RUNNER.parser().parse_args(base + ["--profile", "repair"]).profile, "repair")
        cases, test_filter, fuse = RUNNER.selection("repair")
        self.assertEqual(cases, (
            "TestEcFileNativeRepair.ThreeStrategiesPublishFreshTwelveAndKeepSourceDebtExplicit",
            "TestEcFileNativeRepair.HealthyCopyPendingIntentResumesSameJournalAfterEngineReopen",
            "TestEcFileNativeRepair.HelperDirectCommittedIssuanceLostReplyAndFreshTwelvePublication",
            "TestEcV2NativeHelperPlan.FlatDirectSingleAndDoubleTargetsKeepPermanentDelivery",
            "TestEcV2NativeHelperPlan.FlatDirectCommittedReplyLossAndClosingOnlyObserve",
            "TestEcV2RepairPlanCatalog.DirectDeliveryVersionsOnlyPermanentRecord",
            "TestEcV2NativeHelperPlan.StripeManagerRunsAllExplicitRepairStrategiesThroughMetaIssuedPlan",
            "TestEcV2NativeHelperPlan.CommittedPlanRenewalRetainsSelectionAndClosingStopsEveryGrant",
        ))
        self.assertEqual(test_filter, ":".join(cases))
        self.assertEqual(fuse, ())
        binary, output = Path("/build/tests/test_meta"), Path("/work/meta")
        sample = receipt(binary, output, cases, test_filter)
        RUNNER.check_meta_receipt(sample, binary, output, cases, test_filter)
        with self.assertRaises(ValueError):
            RUNNER.check_meta_receipt(sample, binary, output)
        with self.assertRaises(ValueError):
            RUNNER.check_meta_receipt(receipt(binary, output), binary, output, cases, test_filter)
        for broken in ("filter", "skip", "unjoined", "pending_case_missing"):
            invalid = copy.deepcopy(sample)
            if broken == "filter":
                invalid["commands"][0]["argv"][1] = "--gtest_filter=TestEcFileNativeRepair.*"
            elif broken == "skip":
                invalid["test_results"]["cases"][0]["skipped"] = True
            elif broken == "unjoined":
                invalid["server"]["cleanup"]["leader_reaped"] = False
            else:
                invalid["test_results"]["cases"].pop()
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                RUNNER.check_meta_receipt(invalid, binary, output, cases, test_filter)

    def test_fixed_sets_and_required_cli(self):
        self.assertEqual(len(set(RUNNER.META_CASES)), 12)
        self.assertEqual(len(set(RUNNER.FUSE_CASES)), 14)
        parsed = RUNNER.parser().parse_args(["--source", "/source", "--build", "/build",
                                            "--fdb-bin-dir", "/fdb", "--work", "/private/new"])
        self.assertEqual(parsed.work, Path("/private/new"))
        RUNNER.check_listing([{"name": name, "disabled": False}
                              for name in reversed(RUNNER.META_CASES)], RUNNER.META_CASES)

    def test_listing_rejects_missing_extra_duplicate_and_disabled(self):
        original = [{"name": name, "disabled": False} for name in RUNNER.META_CASES]
        disabled = copy.deepcopy(original)
        disabled[0]["disabled"] = True
        for invalid in (original[:-1], original + [{"name": "Other.Test", "disabled": False}],
                        original[:-1] + original[:1], disabled):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                RUNNER.check_listing(invalid, RUNNER.META_CASES)

    def test_xml_rejects_failure_skip_unexecuted_and_suite_failure(self):
        RUNNER.check_xml(xml(RUNNER.FUSE_CASES), RUNNER.FUSE_CASES)
        for field, value in (("failed", True), ("skipped", True), ("executed", False)):
            record = xml(RUNNER.FUSE_CASES)
            record["cases"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                RUNNER.check_xml(record, RUNNER.FUSE_CASES)
        for field, value in (("declared_tests", "13"), ("declared_failures", "1"),
                             ("declared_errors", None)):
            record = xml(RUNNER.FUSE_CASES)
            record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                RUNNER.check_xml(record, RUNNER.FUSE_CASES)

    def test_xml_rejects_duplicate_case_even_when_total_matches(self):
        record = xml(RUNNER.META_CASES)
        record["cases"][-1] = record["cases"][0]
        with self.assertRaises(ValueError):
            RUNNER.check_xml(record, RUNNER.META_CASES)

    def test_limits_check_does_not_upgrade_lower_soft_limits(self):
        high = RUNNER.MEMLOCK_BYTES
        nofile, memlock = RUNNER.checked_limits((65536, 65536), (high, high), -1)
        self.assertEqual(nofile["soft_after"], 65536)
        self.assertFalse(memlock["hard_limit_changed"])
        RUNNER.checked_limits((-1, -1), (-1, -1), -1)
        for arguments in (((1024, 65536), (high, high)), ((65536, 65536), (high - 1, high))):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                RUNNER.checked_limits(*arguments, -1)

    def test_meta_receipt_accepts_exact_commands_join_and_binary_binding(self):
        binary, output = Path("/build/tests/test_meta"), Path("/work/meta")
        RUNNER.check_meta_receipt(receipt(binary, output), binary, output)

    def test_meta_receipt_rejects_nonzero_exit_extra_run_or_unjoined_fdb(self):
        binary, output = Path("/build/tests/test_meta"), Path("/work/meta")
        variants = []
        item = receipt(binary, output)
        item["commands"][-1]["exitcode"] = 1
        variants.append(item)
        item = receipt(binary, output)
        item["commands"].append(copy.deepcopy(item["commands"][-1]))
        variants.append(item)
        item = receipt(binary, output)
        item["server"]["cleanup"]["leader_reaped"] = False
        variants.append(item)
        item = receipt(binary, output)
        item["binaries"]["test_meta"]["sha256_after"] = "b" * 64
        variants.append(item)
        for item in variants:
            with self.subTest(item=item), self.assertRaises(ValueError):
                RUNNER.check_meta_receipt(item, binary, output)

    def test_zero_exit_does_not_hide_timeout_interruption_or_launch_failure(self):
        for field, value in (("timed_out", True), ("interrupted", True), ("launch_error", "error"),
                             ("interrupted_or_timeout", "KeyboardInterrupt")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                RUNNER.command_ok({"exitcode": 0, field: value})

    def test_case_diagnostics_preserves_identity_and_bounds_assertion_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tests.xml"
            detail = "x" * 3000
            path.write_text('<testsuites><testsuite><testcase classname="Fixture" name="Case" status="run">'
                            '<failure>' + detail + '</failure></testcase></testsuite></testsuites>',
                            encoding="utf-8")
            case, = RUNNER.case_diagnostics(path)
            self.assertEqual(case["name"], "Fixture.Case")
            self.assertTrue(case["executed"])
            self.assertTrue(case["failed"])
            self.assertFalse(case["skipped"])
            self.assertEqual(len(case["detail"].encode("utf-8")), 2048)
            self.assertTrue(case["detail_truncated"])

    def test_signal_requests_existing_cleanup_once_and_defers_during_join(self):
        # Direct handler calls and fake stop: no OS signal or child process.
        helper = SimpleNamespace(stop_owned_process=mock.Mock(return_value={"leader_reaped": True}))
        guard = RUNNER.Interrupts(helper)
        guard.original_stop = helper.stop_owned_process
        with mock.patch.object(signal, "setitimer", create=True), \
             mock.patch.object(signal, "ITIMER_REAL", 0, create=True):
            with self.assertRaises(KeyboardInterrupt):
                guard.handle(15, None)
            guard.handle(15, None)
            self.assertEqual(len(guard.received), 2)
            guard = RUNNER.Interrupts(helper)
            def finish_join(process):
                guard.handle(15, None)
                self.assertEqual(guard.cleaning, 1)
                return {"leader_reaped": True}
            guard.original_stop = finish_join
            self.assertTrue(guard.stop(object())["leader_reaped"])
            self.assertEqual(guard.cleaning, 0)
            self.assertEqual(guard.received[0]["signal"], 15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
