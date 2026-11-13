#!/usr/bin/env python3
"""Check acceptance parsing without executing Cargo or a native service."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("codec_runner", Path(__file__).with_name("run-codec-tests.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class AcceptanceOutput(unittest.TestCase):
    def test_suites_keep_distinct_exact_inventories(self):
        codec_filter, codec = RUNNER.test_inventory("codec")
        scope_filter, scope = RUNNER.test_inventory("scope")
        self.assertEqual((codec_filter, len(codec)), ("ec_codec::tests::", 10))
        self.assertEqual((scope_filter, len(scope)), ("ec_scope::", 40))
        self.assertTrue(all(name.startswith(scope_filter) for name in scope))
        self.assertEqual(sum("::target_retirement_tests::" in name for name in scope), 9)
        self.assertTrue(codec.isdisjoint(scope))
        with self.assertRaises(ValueError):
            RUNNER.test_inventory("all")

    def test_listing_rejects_missing_duplicate_and_unrelated_cases(self):
        expected = {"scope::first", "scope::second"}
        listing = "scope::first: test\nscope::second: test\n2 tests, 0 benchmarks\n"
        RUNNER.validate_listing(listing, expected)
        for invalid in ("scope::first: test\n", listing + "scope::first: test\n",
                        listing.replace("scope::second", "codec::second")):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                RUNNER.validate_listing(invalid, expected)

    def test_results_require_all_passed_zero_skipped_and_one_summary(self):
        expected = {"scope::first", "scope::second"}
        output = ("test scope::first ... ok\ntest scope::second ... ok\n\n"
                  "successes:\nother captured output\n"
                  "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 0.50s\n")
        self.assertEqual(RUNNER.validate_results(output, expected), sorted(expected))
        for invalid in (
            output.replace("second ... ok", "second ... ignored"),
            output.replace("second ... ok", "second ... FAILED"),
            output.replace("0 ignored", "1 ignored"),
            output.replace("0 failed", "1 failed"),
            output.replace("2 passed", "1 passed"),
            output + "test scope::first ... ok\n",
            output + output[output.index("test result:"):],
            output.replace("scope::second", "codec::second"),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                RUNNER.validate_results(invalid, expected)


if __name__ == "__main__":
    unittest.main()
