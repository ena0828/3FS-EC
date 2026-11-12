"""Candidate tests only; synthetic fixtures are not public trace evidence."""

import copy
import hashlib
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

import kv_trace as kv
import fetch_prefix


def row(hashes=None, tokens=128, timestamp=0, chat=1):
    return {"chat_id": chat, "parent_chat_id": -1, "timestamp": timestamp,
            "input_length": tokens, "output_length": 3, "type": "api", "turn": 1,
            "hash_ids": list(range((tokens + 15) // 16)) if hashes is None else hashes}


def fixture_source(raw):
    # These local test bytes exercise parser/commit behavior, not provenance.
    path = "qwen_traceA_blksz_16.jsonl"
    oid, size = kv.UPSTREAM[path]
    return {"schema": "qwen-bailian-input/v1", "repository": kv.REPOSITORY,
            "commit": kv.COMMIT, "path": path, "license_spdx": "Apache-2.0",
            "upstream_lfs_sha256": oid, "upstream_lfs_bytes_decimal": str(size),
            "input_sha256": kv.sha(raw), "input_bytes_decimal": str(len(raw)),
            "input_scope": "bounded-prefix", "first_line_decimal": "1", "byte_offset_decimal": "0"}


def config(reuse="synthetic-tenant", **changes):
    args = {"model": "synthetic-model", "kv_format": "mapped-128-v1", "user": "tenant-a", "reuse": reuse}
    args.update(changes)
    return kv.parameters(**args)


def objects(value, params=None, line=1, source=None):
    # Decimal timestamp is handled separately by the exact-time test.
    raw = kv.canonical(value) + b"\n"
    source = fixture_source(raw) if source is None else source
    return [event["object"] for event in kv.row_events(value, source, params or config(), line, 0, raw)
            if event["kind"] == "input_block_observation"]


class KvTraceTests(unittest.TestCase):
    def test_complete_prefix_chain_prevents_suffix_false_reuse(self):
        first = row(list(range(16)), 256)
        changed = copy.deepcopy(first)
        changed["hash_ids"][0] = 999
        self.assertEqual(first["hash_ids"][8:], changed["hash_ids"][8:])
        self.assertNotEqual(objects(first)[1]["key_sha256"], objects(changed)[1]["key_sha256"])

    def test_synthetic_tenant_reuses_complete_blocks_across_requests(self):
        first, second = row(chat=1), row(chat=2)
        second["timestamp"] = 1
        self.assertEqual(objects(first)[0]["key_sha256"], objects(second, line=2)[0]["key_sha256"])

    def test_default_request_isolation_is_explicit(self):
        params = kv.parameters("model", "format", "user")
        self.assertTrue(params["cross_request_reuse_artificially_disabled"])
        self.assertNotEqual(objects(row(), params, 1)[0]["key_sha256"], objects(row(), params, 2)[0]["key_sha256"])

    def test_model_format_user_and_source_domains_are_distinct(self):
        base = objects(row())[0]["key_sha256"]
        for changed in ({"model": "model-b"}, {"kv_format": "format-b"}, {"user": "user-b"}):
            with self.subTest(changed=changed):
                self.assertNotEqual(base, objects(row(), config(**changed))[0]["key_sha256"])
        raw = kv.canonical(row()) + b"\n"
        source = fixture_source(raw)
        source["path"] = "qwen_traceB_blksz_16.jsonl"
        source["upstream_lfs_sha256"], size = kv.UPSTREAM[source["path"]]
        source["upstream_lfs_bytes_decimal"] = str(size)
        self.assertNotEqual(base, objects(row(), source=source)[0]["key_sha256"])

    def test_tail_is_request_isolated_with_no_padding_bytes(self):
        for tokens in (1, 16, 127, 129, 144):
            with self.subTest(tokens=tokens):
                first, second = objects(row(tokens=tokens), line=1), objects(row(tokens=tokens), line=2)
                tail = first[-1]
                self.assertEqual(tail["reuse_scope"], "request")
                self.assertNotEqual(tail["key_sha256"], second[-1]["key_sha256"])
                self.assertEqual(int(tail["logical_bytes_decimal"]), (tokens % 128) * 896)
                self.assertEqual(tail["tail_padding_uncertain"], tokens % 16 != 0)
                if tokens > 128:
                    self.assertEqual(first[0]["key_sha256"], second[0]["key_sha256"])

    def test_integer_time_scaling_rejects_rounding_and_bad_types(self):
        raw = b'{"chat_id":1,"parent_chat_id":-1,"timestamp":0.000000001,"input_length":0,"output_length":0,"type":"api","turn":1,"hash_ids":[]}\n'
        value = kv.parse_json(raw)
        exact = list(kv.row_events(value, fixture_source(raw), config(numerator=3, denominator=1), 1, 0, raw))[0]
        self.assertEqual(exact["clock"]["source_ns_decimal"], "1")
        self.assertEqual(exact["clock"]["scaled_ns_decimal"], "3")
        with self.assertRaises(ValueError):
            list(kv.row_events(value, fixture_source(raw), config(numerator=1, denominator=3), 1, 0, raw))
        for bad in (True, -1, Decimal("NaN"), Decimal("1e-10"), Decimal("1e999999"), 1.0):
            with self.subTest(bad=str(bad)), self.assertRaises(ValueError):
                kv.timestamp_ns(bad)
        for key in ("numerator", "denominator", "measurement_ns"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                config(**{key: True})

    def test_strict_json_counts_types_and_hash_bounds(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":1e999999}', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                kv.parse_json(raw)
        for field, bad in (("input_length", True), ("chat_id", 1.0), ("turn", -1),
                           ("hash_ids", [0]), ("hash_ids", [False] * 8), ("hash_ids", [1 << 64] * 8)):
            value = row()
            value[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                kv.validate_row(value)
        value = row()
        value["unexpected"] = 1
        with self.assertRaises(ValueError):
            kv.validate_row(value)

    def test_warmup_is_retained_and_equal_times_stable(self):
        raw = b"".join(kv.canonical(row(timestamp=time, chat=index)) + b"\n" for index, time in enumerate((0, 1, 1, 2)))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "input.jsonl"
            source_path.write_bytes(raw)
            result = kv.convert(source_path, fixture_source(raw), config(measurement_ns=1000000000), root / "out")
            events = [json.loads(line) for line in (root / "out/events.jsonl").read_bytes().splitlines()]
            requests = [item for item in events if item["kind"] == "request_arrival"]
            self.assertEqual([item["clock"]["region"] for item in requests], ["warmup", "measurement", "measurement", "measurement"])
            self.assertEqual([item["source"]["line_decimal"] for item in requests], ["1", "2", "3", "4"])
            self.assertEqual([int(item["sequence_decimal"]) for item in events], list(range(8)))
            self.assertEqual(result["events_sha256"], kv.sha((root / "out/events.jsonl").read_bytes()))
            self.assertFalse(result["claims"]["unique_objects_counted"])
            self.assertEqual(result["request_regions"], {"warmup": 1, "measurement": 3})

    def test_reverse_time_and_incomplete_line_leave_no_complete_manifest(self):
        good = kv.canonical(row(timestamp=1)) + b"\n"
        cases = (good + kv.canonical(row(timestamp=0)) + b"\n", good.rstrip(b"\n"), b" " * (kv.MAX_LINE + 1) + b"\n")
        for raw in cases:
            with self.subTest(length=len(raw)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "input").write_bytes(raw)
                with self.assertRaises(ValueError):
                    kv.convert(root / "input", fixture_source(raw), config(), root / "out")
                self.assertFalse((root / "out/manifest.json").exists())
                self.assertTrue((root / "out/failed.json").exists())

    def test_input_sha_mismatch_fails_before_output_adoption(self):
        raw = kv.canonical(row()) + b"\n"
        source = fixture_source(raw)
        source["input_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_bytes(raw)
            with self.assertRaises(ValueError):
                kv.convert(root / "input", source, config(), root / "out")
            self.assertFalse((root / "out").exists())

    def test_parameter_float_alias_cannot_change_locked_mapping(self):
        raw = kv.canonical(row()) + b"\n"
        params = config()
        params["block_tokens"] = 128.0
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_bytes(raw)
            with self.assertRaises(ValueError):
                kv.convert(root / "input", fixture_source(raw), params, root / "out")
            self.assertFalse((root / "out").exists())

    def test_existing_output_is_never_adopted_or_overwritten(self):
        raw = kv.canonical(row()) + b"\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_bytes(raw)
            (root / "out").mkdir()
            marker = root / "out/marker"
            marker.write_bytes(b"retained")
            with self.assertRaises(FileExistsError):
                kv.convert(root / "input", fixture_source(raw), config(), root / "out")
            self.assertEqual(marker.read_bytes(), b"retained")
            self.assertEqual(list((root / "out").iterdir()), [marker])

    def test_commit_failure_keeps_partial_evidence(self):
        raw = kv.canonical(row()) + b"\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_bytes(raw)
            with mock.patch.object(kv.os, "rename", side_effect=OSError("injected rename failure")):
                with self.assertRaises(OSError):
                    kv.convert(root / "input", fixture_source(raw), config(), root / "out")
            self.assertTrue((root / "out/events.partial").exists())
            self.assertTrue((root / "out/failed.json").exists())
            self.assertFalse((root / "out/manifest.json").exists())

    def test_full_source_identity_cannot_be_claimed_by_prefix(self):
        source = fixture_source(kv.canonical(row()) + b"\n")
        source["input_scope"] = "full-file"
        with self.assertRaises(ValueError):
            kv.validate_source(source)
        for field, value in (("input_bytes_decimal", True), ("first_line_decimal", "2"), ("commit", "0" * 40)):
            candidate = fixture_source(kv.canonical(row()) + b"\n")
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                kv.validate_source(candidate)

    def test_payload_chunking_and_ranges_have_independent_counter_oracle(self):
        key = "01" * 32
        expected = b"".join(hashlib.sha256(b"ec-kv-payload-v1\x00" + bytes.fromhex(key) + index.to_bytes(8, "big")).digest() for index in range(5))
        for chunk in (1, 7, 32, 65536):
            with self.subTest(chunk=chunk):
                self.assertEqual(b"".join(kv.iter_payload(key, 130, chunk_size=chunk)), expected[:130])
        self.assertEqual(b"".join(kv.iter_payload(key, 77, offset=17)), expected[17:94])
        self.assertNotEqual(b"".join(kv.iter_payload("02" * 32, 130)), expected[:130])
        with self.assertRaises(ValueError):
            list(kv.iter_payload(key, 10, offset=kv.BLOCK_BYTES - 1))

    def test_zero_input_and_u64_hash_do_not_round(self):
        self.assertEqual(objects(row(tokens=0)), [])
        value = row(hashes=[(1 << 64) - 1] * 8)
        self.assertEqual(objects(value)[0]["source_hash_ids_decimal"], ["18446744073709551615"] * 8)

    def test_bounded_fetch_checks_range_and_exact_prefix_identity(self):
        complete = kv.canonical(row()) + b"\n"
        body = complete + b"x" * (65536 - len(complete))
        source = fixture_source(complete)
        headers = {"Content-Range": "bytes 0-65535/" + source["upstream_lfs_bytes_decimal"], "Content-Encoding": "identity"}
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 206
        response.headers = headers
        response.read.return_value = body
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kv.write_new_json(root / "source.json", source)
            with mock.patch.object(fetch_prefix, "urlopen", return_value=response):
                result = fetch_prefix.fetch(root / "source.json", root / "fetch")
            response.read.assert_called_once_with(65537)
            self.assertEqual((root / "fetch/input.jsonl").read_bytes(), complete)
            self.assertFalse(result["full_lfs_object_verified"])

    def test_bounded_fetch_rejects_ignored_range_and_hash_mismatch(self):
        complete = kv.canonical(row()) + b"\n"
        source = fixture_source(complete)
        for status, body in ((200, b""), (206, b"a\n" + b"x" * 65534)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kv.write_new_json(root / "source.json", source)
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.status = status
                response.headers = {"Content-Range": "bytes 0-65535/" + source["upstream_lfs_bytes_decimal"]}
                response.read.return_value = body
                with mock.patch.object(fetch_prefix, "urlopen", return_value=response):
                    with self.assertRaises(ValueError):
                        fetch_prefix.fetch(root / "source.json", root / "fetch")
                self.assertFalse((root / "fetch").exists())
                if status == 200:
                    response.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
