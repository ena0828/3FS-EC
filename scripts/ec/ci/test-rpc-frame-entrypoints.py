#!/usr/bin/env python3
"""Pure source/filter/XML and safe failure checks; no native binary or socket."""
from contextlib import redirect_stdout
import copy
import fnmatch
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
regression = load("rpc_frame_regression", HERE / "run-native-regressions.py")
driver = load("rpc_frame_fragments", HERE.parent / "test-native-fragments.py")


def case(name):
    return {"name": name, "executed": True, "failed": False, "skipped": False}


def client_record():
    return {"suites": [{"suite": "client", "xml_results": {"cases": [
        case(name) for name in regression.RPC_FRAME_CASES + regression.RPC_OBSERVER_CASES]}}]}


class RpcFrameEntrypoints(unittest.TestCase):
    def test_real_source_names_and_actual_native_filter_select_exact_five(self):
        text = (SOURCE / "tests/client/TestEcRpcFrameSizes.cc").read_text(encoding="utf-8")
        names = re.findall(r"TEST_F\(TestEcRpcFrameSizes,\s*([A-Za-z0-9_]+)\)", text)
        self.assertEqual(len(names), 5)
        self.assertEqual({"TestEcRpcFrameSizes." + name for name in names}, set(regression.RPC_FRAME_CASES))
        self.assertEqual(len(regression.RPC_FRAME_CASES), len(set(regression.RPC_FRAME_CASES)))
        for name in regression.RPC_FRAME_CASES + regression.RPC_OBSERVER_CASES:
            self.assertIn(name, regression.CLIENT_MANDATORY)
            self.assertTrue(any(fnmatch.fnmatchcase(name, part) for part in driver.CLIENT_FILTER.split(":")))
        observer = (SOURCE / "tests/client/TestEcRepairPipeline.cc").read_text(encoding="utf-8")
        for name in regression.RPC_OBSERVER_CASES:
            self.assertRegex(observer, r"TEST\(TestEcRepairPipeline,\s*" + name.split(".")[1] + r"\)")
        selection = "TestEcStripeRead.ReplacementAndSelfMoveRetainOutputChargeAcrossLateCleanupAndClose"
        selection_source = (SOURCE / "tests/client/TestEcStripeRead.cc").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"TEST\(TestEcStripeRead,\s*" + selection.split(".")[1] + r"\)",
                                       selection_source)), 1)
        self.assertIn(selection, regression.CLIENT_MANDATORY)
        self.assertTrue(any(fnmatch.fnmatchcase(selection, part) for part in driver.CLIENT_FILTER.split(":")))
        for suite, method in (
            ("TestEcTreeReadJournal", "ReadOnlyExportRejectsMissingLockIncompleteAndConflictingOutput"),
            ("TestEcTreeReadJournal", "SnapshotExportBoundsZeroEofAndEightDistinctRevisions"),
            ("TestEcTreeReadClient", "ReleasedReadExportPreservesTwelveIdentitiesAndJournalBytes"),
        ):
            source = (SOURCE / "tests/client/TestEcTreeReadClient.cc").read_text(encoding="utf-8")
            self.assertEqual(len(re.findall(r"TEST(?:_F)?\(" + suite + r",\s*" + method + r"\)", source)), 1)
            name = suite + "." + method
            self.assertIn(name, regression.CLIENT_MANDATORY)
            self.assertTrue(any(fnmatch.fnmatchcase(name, part) for part in driver.CLIENT_FILTER.split(":")))

    def test_real_xml_parser_accepts_all_and_rejects_skip_failure_or_missing_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cases.xml"
            root = ET.Element("testsuites", tests="7", failures="0", errors="0")
            suite = ET.SubElement(root, "testsuite", name="selected")
            for name in regression.RPC_FRAME_CASES + regression.RPC_OBSERVER_CASES:
                classname, method = name.split(".", 1)
                ET.SubElement(suite, "testcase", classname=classname, name=method, status="run", result="completed")
            def parse(value):
                ET.ElementTree(value).write(path, encoding="utf-8", xml_declaration=True)
                return {"suites": [{"suite": "client", "xml_results": driver.xml_tests(path)}]}
            self.assertEqual(regression.check_rpc_frames(parse(root))["tcp_cases"], list(regression.RPC_FRAME_CASES))
            for failure in ("skipped", "failure", "error", "notrun", "wrong_class"):
                value = copy.deepcopy(root)
                first = next(value.iter("testcase"))
                if failure == "notrun":
                    first.set("status", "notrun")
                elif failure == "wrong_class":
                    first.set("classname", "Unrelated")
                else:
                    ET.SubElement(first, failure)
                with self.subTest(failure=failure), self.assertRaises(ValueError):
                    regression.check_rpc_frames(parse(value))

    def test_exact_set_rejects_missing_extra_duplicate_wrong_suite_and_observer(self):
        original = client_record()
        regression.check_rpc_frames(original)
        for mutation in ("missing", "extra", "duplicate", "wrong_suite", "duplicate_suite",
                         "missing_observer", "duplicate_observer", "unknown_execution"):
            value = copy.deepcopy(original)
            row = value["suites"][0]
            cases = row["xml_results"]["cases"]
            if mutation == "missing":
                cases.pop(0)
            elif mutation == "extra":
                cases.append(case("TestEcRpcFrameSizes.UnreviewedCase"))
            elif mutation == "duplicate":
                cases.append(copy.deepcopy(cases[0]))
            elif mutation == "wrong_suite":
                row["suite"] = "storage"
            elif mutation == "duplicate_suite":
                value["suites"].append(copy.deepcopy(row))
            elif mutation == "missing_observer":
                cases.pop()
            elif mutation == "duplicate_observer":
                cases.append(copy.deepcopy(cases[-1]))
            else:
                del cases[0]["executed"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                regression.check_rpc_frames(value)

    def test_full_receipt_requires_real_success_and_complete_listing_not_only_xml(self):
        build = Path("/fixed/build")
        built = {"binaries": {name: str(i) * 64 for i, name in enumerate(regression.TARGETS)}}
        rows = []
        for kind, target, names in zip(("storage", "service", "client"), regression.TARGETS,
                                       (regression.MANDATORY, regression.SERVICE_MANDATORY,
                                        regression.CLIENT_MANDATORY)):
            rows.append({"suite": kind, "status": "passed", "failures": [],
                         "binary": str(build / "tests" / target),
                         "binary_sha256": built["binaries"][target],
                         "binary_sha256_after": built["binaries"][target],
                         "listed_tests": [{"name": name, "disabled": False} for name in sorted(names)],
                         "xml_results": {"cases": [case(name) for name in sorted(names)]},
                         "listing": {"exitcode": 0}, "execution": {"exitcode": 0}})
        original = {"status": "passed", "exitcode": 0, "failures": [], "suites": rows}
        regression.check_suites(original, build, built)
        for mutation in ("nonzero", "timeout", "interrupted", "termination", "missing_listing", "changed_binary",
                         "missing_selection"):
            value = copy.deepcopy(original)
            row = value["suites"][2]
            if mutation == "nonzero":
                row["execution"]["exitcode"] = 1
            elif mutation == "missing_listing":
                row["listed_tests"].pop()
            elif mutation == "changed_binary":
                row["binary_sha256_after"] = "f" * 64
            elif mutation == "missing_selection":
                selected = "TestEcStripeRead.ReplacementAndSelfMoveRetainOutputChargeAcrossLateCleanupAndClose"
                row["listed_tests"] = [item for item in row["listed_tests"] if item["name"] != selected]
                row["xml_results"]["cases"] = [item for item in row["xml_results"]["cases"] if item["name"] != selected]
            else:
                row["execution"][{"timeout": "timed_out"}.get(mutation, mutation)] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                regression.check_suites(value, build, built)


class NativeFailureDiagnostics(unittest.TestCase):
    relative = "tests/storage/service/TestEcStageService.cc"

    def parse_case(self, failures, *, tag="failure", skipped=False):
        # This is the pinned GoogleTest XML shape: compiler-independent location
        # then summary in the attribute, plus private full detail in CDATA/text.
        root = ET.Element("testsuites", tests="1", failures=str(int(bool(failures))))
        item = ET.SubElement(root, "testcase", classname="TestFixture", name="Case",
                             status="run", result="completed")
        for message in failures:
            node = ET.SubElement(item, tag, message=message)
            node.text = message + "\nStack trace: PRIVATE_STACK_TOKEN"
        if skipped:
            ET.SubElement(item, "skipped")
        with tempfile.TemporaryDirectory(prefix="native failure XML ") as folder:
            path = Path(folder) / "result.xml"
            ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
            return driver.xml_tests(path)

    def test_real_xml_shape_exposes_only_source_and_scalar_assertions(self):
        message = ("/private/PRIVATE_BUILD_TOKEN/source/" + self.relative + ":1750\n"
                   "Expected equality of these values:\n  privateExpression\n    Which is: 2\n"
                   "  anotherPrivateExpression\n    Which is: 1\nPRIVATE_BEARER_TOKEN")
        parsed = self.parse_case([message])
        row = parsed["cases"][0]
        self.assertTrue(row["failed"])
        detail = row["failure_diagnostics"]["assertions"][0]
        self.assertEqual(detail["source"], {"file": self.relative, "line": 1750})
        self.assertEqual(detail["classification"], "equality")
        self.assertEqual(detail["scalar_values"], [{"role": "operand", "value": 2},
                                                   {"role": "operand", "value": 1}])
        output = io.StringIO()
        with redirect_stdout(output):
            driver.print_summary({"suites": [{"suite": "service", "status": "failed",
                                  "executed_count": 1, "selected_count": 1,
                                  "xml_results": parsed, "failures": []}], "failures": []})
        line = output.getvalue().split("NATIVE_CASE_FAILURE ", 1)[1].splitlines()[0]
        self.assertEqual(json.loads(line)["diagnostics"], row["failure_diagnostics"])
        for secret in ("PRIVATE_", "privateExpression", "anotherPrivateExpression", "Stack trace"):
            self.assertNotIn(secret, json.dumps(parsed) + output.getvalue())

    def test_boolean_error_node_and_missing_or_untrusted_location_are_explicit(self):
        messages = ["C:\\private\\source\\" + self.relative.replace("/", "\\") +
                    ":12\nValue of: privatePredicate()\n  Actual: false\nExpected: true",
                    "/private/not-in-repository.cc:7\nunknown private message",
                    "../prefix/" + self.relative + ":9\nExpected: true"]
        rows = self.parse_case(messages, tag="error")["cases"][0]
        details = rows["failure_diagnostics"]["assertions"]
        self.assertTrue(rows["failed"])
        self.assertEqual(details[0]["kind"], "error")
        self.assertEqual(details[0]["classification"], "boolean")
        self.assertEqual(details[0]["source"], {"file": self.relative, "line": 12})
        self.assertEqual(details[0]["scalar_values"], [{"role": "actual", "value": False},
                                                     {"role": "expected", "value": True}])
        for row in details[1:]:
            self.assertNotIn("source", row)
            self.assertTrue(row["details_redacted"])
        self.assertNotIn("privatePredicate", json.dumps(rows))

    def test_size_assertion_and_numeric_bounds_do_not_echo_strings_or_stack(self):
        prefix = self.relative + ":99\nExpected equality of these values:\n"
        lines = ["Which is: 1", "Actual: -3.5", "Expected: 1e3", "Which is: true",
                 "Which is: 999", "Actual: nan", "Actual: inf", "Actual: 1e9999",
                 "Which is: 99999999999999999999999999999999", 'Which is: "PRIVATE_TOKEN"',
                 "Actual: 10 PRIVATE_SUFFIX"]
        message = prefix + "\n".join(lines) + "\n" + ("PRIVATE_PADDING" * 1000)
        row = self.parse_case([message] * 9)["cases"][0]
        details = row["failure_diagnostics"]
        self.assertEqual((details["assertion_count"], details["assertions_omitted"]), (9, 6))
        self.assertEqual(len(details["assertions"]), 3)
        for item in details["assertions"]:
            self.assertTrue(item["input_truncated"])
            self.assertEqual([value["value"] for value in item["scalar_values"]], [1, -3.5, 1000, True])
        encoded = json.dumps(details)
        self.assertLess(len(encoded), 3000)
        self.assertNotIn("PRIVATE", encoded)
        for scalar in ("nan", "inf", "1e9999", "99999999999999999999999999999999", '"123"', "0x123"):
            self.assertIsNone(driver.failure_scalar(scalar))
        many = ET.Element("testsuites", tests="17", failures="17")
        for index in range(17):
            item = ET.SubElement(many, "testcase", classname="TestFixture", name="Case" + str(index),
                                 status="run", result="completed")
            ET.SubElement(item, "failure", message=message)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "many.xml"
            ET.ElementTree(many).write(path, encoding="utf-8")
            parsed = driver.xml_tests(path)
        self.assertEqual(len(parsed["cases"]), 17)
        self.assertTrue(all(item["failed"] for item in parsed["cases"]))
        self.assertEqual(parsed["cases"][-1]["failure_diagnostics"]["status"], "case_limit")
        output = io.StringIO()
        with redirect_stdout(output):
            driver.print_summary({"suites": [{"suite": "service", "status": "failed",
                                  "executed_count": 17, "selected_count": 17,
                                  "xml_results": parsed, "failures": []}], "failures": []})
        self.assertEqual(output.getvalue().count("NATIVE_CASE_FAILURE "), 16)
        self.assertIn('NATIVE_CASE_FAILURE_LIMIT {"omitted_cases": 1}', output.getvalue())

    def test_diagnostic_exception_preserves_original_failure_and_skip_flags(self):
        with mock.patch.object(driver, "failure_diagnostics", side_effect=OSError("PRIVATE_DISK_ERROR")):
            parsed = self.parse_case([self.relative + ":1\nValue of: x\nActual: false"], skipped=True)
        row = parsed["cases"][0]
        self.assertEqual({key: row[key] for key in ("name", "executed", "failed", "skipped")},
                         {"name": "TestFixture.Case", "executed": True, "failed": True, "skipped": True})
        self.assertEqual(row["failure_diagnostics"], {"status": "unavailable", "details_redacted": True})
        self.assertNotIn("PRIVATE", json.dumps(parsed))

    def test_success_four_fields_and_existing_exact_set_rejection_are_unchanged(self):
        row = self.parse_case([])["cases"][0]
        self.assertEqual(row, {"name": "TestFixture.Case", "executed": True, "failed": False, "skipped": False})
        original = client_record()
        regression.check_rpc_frames(original)
        failed = self.parse_case([self.relative + ":1\nValue of: x\nActual: false\nExpected: true"])["cases"][0]
        failed["name"] = original["suites"][0]["xml_results"]["cases"][0]["name"]
        original["suites"][0]["xml_results"]["cases"][0] = failed
        with self.assertRaises(ValueError):
            regression.check_rpc_frames(original)


    def test_summary_attribute_uses_only_complete_bounded_cdata_first_line_for_location(self):
        summary = "Expected equality of these values:\nWhich is: 2\nWhich is: 1"
        body = "/PRIVATE_BUILD/" + self.relative + ":1750\nPRIVATE_TOKEN\nStack trace: PRIVATE_STACK"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "result.xml"
            path.write_text('<testsuites tests="1" failures="1"><testcase classname="TestFixture" '
                            'name="Case" status="run"><failure message="Expected equality of these values:">'
                            '<![CDATA[' + body + ']]></failure></testcase></testsuites>', encoding="utf-8")
            row = driver.xml_tests(path)["cases"][0]
        self.assertTrue(row["failed"])
        detail = row["failure_diagnostics"]["assertions"][0]
        self.assertEqual(detail["source"], {"file": self.relative, "line": 1750})
        self.assertEqual(detail["classification"], "equality")
        self.assertNotIn("PRIVATE", json.dumps(row))
        for text in ("../private/" + self.relative + ":1750\nPRIVATE_TOKEN",
                     "PRIVATE_FIRST_LINE\n" + self.relative + ":1750",
                     "x" * 8192 + "/" + self.relative + ":1750\n",
                     "\u754c" * 2800 + "/" + self.relative + ":1750\n"):
            node = ET.Element("failure", message=summary)
            node.text = text
            with self.subTest(text_length=len(text)):
                value = driver.assertion_diagnostic(node)
                self.assertNotIn("source", value)
                self.assertNotIn("PRIVATE", json.dumps(value))
        node = ET.Element("failure", message=self.relative + ":2\n" + summary)
        node.text = body
        self.assertEqual(driver.assertion_diagnostic(node)["source"]["line"], 2)


class NativeRunProgress(unittest.TestCase):
    selected = [{"name": "TestFixture.First", "disabled": False},
                {"name": "TestFixture.Second", "disabled": False},
                {"name": "TestFixture.DISABLED_Private", "disabled": True}]

    def test_only_complete_listed_markers_leave_no_payload_or_failure_summary(self):
        data = (b"PRIVATE_TOKEN at /private/build\n"
                b"[ RUN      ] TestFixture.First\r\n"
                b"[       OK ] TestFixture.First (123 ms)\r\n"
                b"[ RUN      ] TestFixture.Second\n"
                b"[  FAILED  ] TestFixture.Second (1 ms)\n"
                b"[  FAILED  ] TestFixture.Second\n"  # End-of-suite summary is not completion.
                b"[ RUN      ] TestFixture.FORGED_PRIVATE\n"
                b"[ RUN      ] TestFixture.DISABLED_Private\n"
                b"prefix [ RUN      ] TestFixture.First\n"
                b"[ RUN      ] TestFixture.First PRIVATE_PAYLOAD\n"
                b"[       OK ] TestFixture.Second (0 ms) PRIVATE_PAYLOAD\n"
                b"[ RUN      ] TestFixture.First")  # Incomplete EOF is not a full marker.
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "client.run.log"
            path.write_bytes(data)
            value = driver.run_progress(path, self.selected, ended=True)
        self.assertEqual(value["scope"], "bounded_progress_not_acceptance")
        self.assertEqual((value["started_markers"], value["ok_markers"], value["failed_markers"]), (2, 1, 1))
        self.assertEqual((value["last_started"], value["last_completed"]),
                         ("TestFixture.Second", "TestFixture.Second"))
        self.assertFalse(value["truncated"])
        self.assertTrue(value["last_partial_line_discarded"])
        self.assertNotIn("executed_count", value)
        self.assertNotIn("PRIVATE", json.dumps(value))

    def test_tail_bound_missing_file_and_read_exception_are_safe(self):
        tail = (b"[ RUN      ] TestFixture.First\n" + b"x" * (driver.PROGRESS_LOG_BYTES - 100) +
                b"\n[ RUN      ] TestFixture.Second\n")
        data = b"PRIVATE_PREFIX" * 100 + tail
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "client.run.log"
            path.write_bytes(data)
            value = driver.run_progress(path, self.selected, ended=True)
            self.assertTrue(value["truncated"])
            self.assertEqual(value["bytes_read"], driver.PROGRESS_LOG_BYTES)
            self.assertTrue(value["first_partial_line_discarded"])
            self.assertEqual(value["last_started"], "TestFixture.Second")
            self.assertEqual(value["started_markers"], 1)
            self.assertIsNone(value["last_completed"])
            self.assertNotIn("PRIVATE", json.dumps(value))
            missing = driver.run_progress(Path(folder) / "missing.run.log", self.selected, ended=True)
            with mock.patch.object(driver.os, "fstat", side_effect=OSError("PRIVATE_DISK_TOKEN")):
                failed = driver.run_progress(path, self.selected, ended=True)
            with mock.patch.object(Path, "open", side_effect=AssertionError("must not read live log")):
                self.assertEqual(driver.run_progress(path, self.selected), missing)
        self.assertEqual(missing, failed)
        self.assertEqual(failed, {"status": "unavailable", "scope": "bounded_progress_not_acceptance",
                                  "details_redacted": True})

    def test_actual_main_keeps_nonzero_missing_xml_and_failed_xml_failures(self):
        for mode in ("signal", "missing_xml", "failed_xml", "diagnostic_error", "unjoined", "passed"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                binary = root / "test_client"
                binary.write_bytes(b"NOT_AN_EXECUTED_NATIVE_BINARY")
                output = root / "result"
                def command(argv, cwd, env, log, *rest):
                    listing = "--gtest_list_tests" in argv
                    log.write_text("TestFixture.\n  First\n" if listing else
                                   "[ RUN      ] TestFixture.First\n[       OK ] TestFixture.First (1 ms)\n"
                                   "PRIVATE_BEARER_TOKEN\n", encoding="utf-8")
                    if not listing and mode in ("failed_xml", "passed"):
                        (output / "client.xml").write_text(
                            '<testsuites tests="1" failures="' + ("1" if mode == "failed_xml" else "0") +
                            '"><testcase classname="TestFixture" name="First" status="run">' +
                            ('<failure message="PRIVATE_FAILURE" />' if mode == "failed_xml" else '') +
                            '</testcase></testsuites>', encoding="utf-8")
                    return {"log": str(log), "exitcode": 0 if listing or mode in ("missing_xml", "passed") else
                            None if mode == "unjoined" else
                            1 if mode == "failed_xml" else -11, "timed_out": False, "interrupted": False}
                captured = io.StringIO()
                with mock.patch.object(driver.sys, "platform", "linux"), \
                     mock.patch.object(driver.signal, "signal"), \
                     mock.patch.object(driver, "resource_snapshot", return_value={}), \
                     mock.patch.object(driver, "mount_for", return_value={"filesystem": "ext4"}), \
                     mock.patch.object(driver.os, "access", return_value=True), \
                     mock.patch.object(driver, "plans", return_value=[("client", "test_client", "TestFixture.*")]), \
                     mock.patch.object(driver, "prepare_nofile", return_value={}), \
                     mock.patch.object(driver, "prepare_memlock", side_effect=lambda r, _: r.update(memlock={})), \
                     mock.patch.object(driver, "run_command", side_effect=command) as invoked, \
                     mock.patch.object(driver.os, "fstat", side_effect=OSError("PRIVATE_DIAGNOSTIC")
                                       if mode == "diagnostic_error" else None,
                                       wraps=driver.os.fstat), redirect_stdout(captured):
                    result = driver.main(["--bin-dir", str(root), "--tmp-root", str(root),
                                          "--output", str(output), "--suite", "client"])
                receipt = json.loads((output / "results.json").read_text(encoding="utf-8"))
                suite = receipt["suites"][0]
                self.assertEqual(invoked.call_count, 2)
                if mode == "passed":
                    self.assertEqual((result, receipt["status"], suite["status"]), (0, "passed", "passed"))
                    self.assertNotIn("run_progress", suite)
                    self.assertNotIn("NATIVE_SUITE_PROGRESS ", captured.getvalue())
                    continue
                self.assertEqual(result, 1)
                self.assertEqual((receipt["status"], suite["status"]), ("failed", "failed"))
                self.assertEqual(suite["executed_count"], 1 if mode == "failed_xml" else 0)
                self.assertEqual(suite["execution"]["exitcode"], 0 if mode == "missing_xml" else
                                 None if mode == "unjoined" else
                                 1 if mode == "failed_xml" else -11)
                self.assertTrue(any(("test XML contains failed" if mode == "failed_xml" else
                                     "missing or invalid test XML") in reason for reason in suite["failures"]))
                self.assertEqual(suite["run_progress"]["status"],
                                 "unavailable" if mode in ("diagnostic_error", "unjoined") else "available")
                self.assertIn("NATIVE_SUITE_PROGRESS ", captured.getvalue())
                self.assertNotIn("PRIVATE", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
