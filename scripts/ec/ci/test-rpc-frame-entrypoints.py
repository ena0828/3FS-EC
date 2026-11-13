#!/usr/bin/env python3
"""Pure source/filter/XML admission checks; no native binary or socket is opened."""
import copy
import fnmatch
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
