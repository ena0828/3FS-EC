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
        for mutation in ("nonzero", "timeout", "interrupted", "termination", "missing_listing", "changed_binary"):
            value = copy.deepcopy(original)
            row = value["suites"][2]
            if mutation == "nonzero":
                row["execution"]["exitcode"] = 1
            elif mutation == "missing_listing":
                row["listed_tests"].pop()
            elif mutation == "changed_binary":
                row["binary_sha256_after"] = "f" * 64
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


if __name__ == "__main__":
    unittest.main()
