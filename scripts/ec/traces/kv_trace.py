#!/usr/bin/env python3
"""Bounded Qwen input observations and synthetic bytes; no workload execution."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from decimal import Decimal
from pathlib import Path

COMMIT = "5f7439c51ec248a0c585f7d90a41a6f57773b912"
REPOSITORY = "https://github.com/alibaba-edu/qwen-bailian-usagetraces-anon"
UPSTREAM = {
    "qwen_traceA_blksz_16.jsonl": ("07cedc9ed8aff301994ac68ed4aede8123b7603673575eeba9dd677de663db17", 56354493),
    "qwen_traceB_blksz_16.jsonl": ("68e3f98e2d601d60d0abf4b89bc8a3654372abab7b1cde6373a13d0054379d59", 96209982),
    "qwen_thinking_blksz_16.jsonl": ("41ac36d9d1b54d084eeb6b05e9d142ba9d02f8bf79cfc9fff418d8ab7cdee906", 27901454),
    "qwen_coder_blksz_16.jsonl": ("3d74974cebb7bccb69b1ca6ea210a44d9a3033443c0271ed015327284dea1aff", 132054902),
}
MAX_NS = (1 << 63) - 1
MAX_LINE = 1048576
MAX_HASHES = 65536
TOKENS = 128
BLOCK_BYTES = 114688
EVENT_SCHEMA = "ec-kv-observation/v1"
PAYLOAD_ALGORITHM = "sha256-counter-v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, low=0, high=(1 << 64) - 1):
    require(type(value) is int and low <= value <= high, f"invalid integer: {name}")
    return value


def decimal_integer(value, name, high=(1 << 64) - 1):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), name)
    return integer(int(value), name, high=high)


def digest(value, name):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), name)
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_integer(text):
    require(len(text) <= 21, "oversized JSON integer")
    return int(text)


def parse_decimal(text):
    require(len(text) <= 64, "oversized JSON decimal")
    value = Decimal(text)
    require(value.is_finite(), "non-finite JSON decimal")
    parts = value.as_tuple()
    require(-9 <= parts.exponent <= 10 and len(parts.digits) <= 20, "unsupported decimal precision/range")
    return value


def reject_constant(text):
    raise ValueError(f"non-finite JSON constant: {text}")


def parse_json(raw):
    if type(raw) is bytes:
        raw = raw.decode("utf8", errors="strict")
    return json.loads(raw, object_pairs_hook=unique_object, parse_float=parse_decimal,
                      parse_int=parse_integer, parse_constant=reject_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_hash(stream):
    result = hashlib.sha256()
    length = 0
    while True:
        chunk = stream.read(1048576)
        if not chunk:
            return result.hexdigest(), length
        result.update(chunk)
        length += len(chunk)


def read_json_file(path, limit=65536):
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "JSON control file too large")
    return parse_json(raw)


def validate_source(source):
    keys = {"schema", "repository", "commit", "path", "license_spdx", "upstream_lfs_sha256",
            "upstream_lfs_bytes_decimal", "input_sha256", "input_bytes_decimal", "input_scope",
            "first_line_decimal", "byte_offset_decimal"}
    require(type(source) is dict and set(source) == keys, "source descriptor fields")
    require(source["schema"] == "qwen-bailian-input/v1", "source schema")
    require(source["repository"] == REPOSITORY and source["commit"] == COMMIT, "fixed source revision")
    require(type(source["path"]) is str and source["path"] in UPSTREAM, "fixed source path")
    require(source["license_spdx"] == "Apache-2.0", "source license")
    expected_hash, expected_size = UPSTREAM[source["path"]]
    require(source["upstream_lfs_sha256"] == expected_hash and
            source["upstream_lfs_bytes_decimal"] == str(expected_size), "fixed LFS declaration")
    digest(source["input_sha256"], "input SHA")
    size = decimal_integer(source["input_bytes_decimal"], "input bytes", expected_size)
    require(size > 0, "empty input")
    require(source["first_line_decimal"] == "1" and source["byte_offset_decimal"] == "0", "prefix origin required")
    require(source["input_scope"] in ("full-file", "bounded-prefix"), "input scope")
    if source["input_scope"] == "full-file":
        require(size == expected_size and source["input_sha256"] == expected_hash, "full LFS identity")
    else:
        require(size < expected_size, "bounded prefix must be shorter than full object")
    return source


def parameters(model, kv_format, user, reuse="request", numerator=1, denominator=1, measurement_ns=0):
    for name, value in (("model", model), ("kv_format", kv_format), ("user", user)):
        require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value), name)
    require(reuse in ("request", "synthetic-tenant"), "reuse mode")
    integer(numerator, "scale numerator", 1, 1000000)
    integer(denominator, "scale denominator", 1, 1000000)
    integer(measurement_ns, "measurement start", 0, MAX_NS)
    return {"model_namespace": model, "kv_format_namespace": kv_format, "user_namespace": user,
            "reuse_mode": reuse, "scale_numerator": numerator, "scale_denominator": denominator,
            "measurement_start_ns_decimal": str(measurement_ns), "block_tokens": TOKENS,
            "block_bytes_decimal": str(BLOCK_BYTES), "tail_bytes_rule": "valid_tokens*896",
            "payload_algorithm": PAYLOAD_ALGORITHM, "source_block_tokens": 16,
            "mapping_is_assumption": True, "actual_user_and_model_identity_available": False,
            "cross_request_reuse_artificially_disabled": reuse == "request"}


def namespace(source, params):
    domain = {key: source[key] for key in ("repository", "commit", "path", "upstream_lfs_sha256")}
    mapping = {key: params[key] for key in ("model_namespace", "kv_format_namespace", "user_namespace",
               "reuse_mode", "block_tokens", "block_bytes_decimal", "tail_bytes_rule", "payload_algorithm")}
    return sha(b"ec-kv-namespace-v1\x00" + canonical({"source_hash_domain": domain, "mapping": mapping}))


def timestamp_ns(value):
    require(type(value) in (int, Decimal), "timestamp must be a JSON number")
    if type(value) is int:
        result = value * 1000000000
    else:
        require(value.is_finite(), "timestamp must be finite")
        parts = value.as_tuple()
        require(-9 <= parts.exponent <= 10 and len(parts.digits) <= 20, "timestamp precision/range")
        numerator, denominator = value.as_integer_ratio()
        numerator *= 1000000000
        require(numerator % denominator == 0, "timestamp is not exact nanoseconds")
        result = numerator // denominator
    return integer(result, "source timestamp ns", 0, MAX_NS)


def validate_row(row):
    required = {"chat_id", "parent_chat_id", "timestamp", "input_length", "output_length", "type", "turn", "hash_ids"}
    require(type(row) is dict and set(row) == required, "unexpected Qwen row fields")
    integer(row["chat_id"], "chat_id")
    integer(row["parent_chat_id"], "parent_chat_id", -1)
    integer(row["turn"], "turn")
    integer(row["input_length"], "input_length", 0, MAX_HASHES * 16)
    integer(row["output_length"], "output_length")
    require(type(row["type"]) is str and 0 < len(row["type"].encode("utf8")) <= 64, "request type")
    hashes = row["hash_ids"]
    require(type(hashes) is list and len(hashes) <= MAX_HASHES, "hash array bound")
    require(len(hashes) == (row["input_length"] + 15) // 16, "hash count does not match input tokens")
    for item in hashes:
        integer(item, "hash ID")
    return timestamp_ns(row["timestamp"])


def row_events(row, source, params, line, offset, raw):
    source_ns = validate_row(row)
    scaled, remainder = divmod(source_ns * params["scale_numerator"], params["scale_denominator"])
    require(remainder == 0, "time scale produces fractional nanoseconds")
    integer(scaled, "scaled timestamp ns", 0, MAX_NS)
    locator = {"path": source["path"], "line_decimal": str(line), "byte_offset_decimal": str(offset), "line_sha256": sha(raw)}
    domain = {key: source[key] for key in ("repository", "commit", "path", "upstream_lfs_sha256")}
    request_id = sha(b"ec-kv-request-v1\x00" + canonical({"domain": domain, "locator": locator}))
    ns = namespace(source, params)
    clock = {"source_seconds_decimal": str(row["timestamp"]), "source_ns_decimal": str(source_ns),
             "scaled_ns_decimal": str(scaled), "region": "warmup" if scaled < int(params["measurement_start_ns_decimal"]) else "measurement"}
    common = {"schema": EVENT_SCHEMA, "request_id": request_id, "source": locator, "clock": clock, "namespace_sha256": ns}
    yield {**common, "kind": "request_arrival", "request": {
        "chat_id_decimal": str(row["chat_id"]), "parent_chat_id_decimal": str(row["parent_chat_id"]),
        "turn_decimal": str(row["turn"]), "type": row["type"], "input_tokens_decimal": str(row["input_length"]),
        "output_tokens_decimal": str(row["output_length"]), "source_hash_count_decimal": str(len(row["hash_ids"]))}}
    binding = bytes.fromhex(request_id) if params["reuse_mode"] == "request" else b""
    chain = hashlib.sha256(b"ec-kv-prefix-v1\x00" + bytes.fromhex(ns) + binding).digest()
    hashes = row["hash_ids"]
    for index, value in enumerate(hashes):
        chain = hashlib.sha256(b"ec-kv-step-v1\x00" + chain + index.to_bytes(8, "big") + value.to_bytes(8, "big")).digest()
        if (index + 1) % 8 and index + 1 != len(hashes):
            continue
        block_index = index // 8
        valid = min(TOKENS, row["input_length"] - block_index * TOKENS)
        tail = valid < TOKENS
        object_binding = bytes.fromhex(request_id) if tail else b""
        key = sha(b"ec-kv-object-v1\x00" + chain + block_index.to_bytes(8, "big") + valid.to_bytes(2, "big") + object_binding)
        start = block_index * 8
        yield {**common, "kind": "input_block_observation", "object": {
            "key_sha256": key, "block_index_decimal": str(block_index), "valid_tokens": valid,
            "logical_bytes_decimal": str(valid * 896), "reuse_scope": "request" if tail else params["reuse_mode"],
            "prefix_chain_sha256": chain.hex(), "source_hash_start_decimal": str(start),
            "source_hash_ids_decimal": [str(item) for item in hashes[start:index + 1]],
            "tail_padding_uncertain": tail and row["input_length"] % 16 != 0}}


def sync_directory(path):
    if os.name == "nt":
        return False
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def write_new_json(path, value):
    with open(path, "xb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def fingerprint(stream):
    info = os.fstat(stream.fileno())
    require(stat.S_ISREG(info.st_mode), "input must be regular file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def convert(input_path, source, params, output_dir):
    validate_source(source)
    # Revalidate programmatic callers just as strictly as command-line callers.
    checked = parameters(params["model_namespace"], params["kv_format_namespace"], params["user_namespace"],
                         params["reuse_mode"], params["scale_numerator"], params["scale_denominator"],
                         decimal_integer(params["measurement_start_ns_decimal"], "measurement start", MAX_NS))
    require(canonical(params) == canonical(checked), "unsupported conversion parameters")
    output = Path(output_dir)
    with open(input_path, "rb") as source_stream:
        before = fingerprint(source_stream)
        first_sha, first_bytes = file_hash(source_stream)
        require(first_sha == source["input_sha256"] and str(first_bytes) == source["input_bytes_decimal"], "input identity mismatch")
        require(fingerprint(source_stream) == before, "input changed during initial hash")
        output.mkdir(mode=0o700)  # Exclusive: never adopt an existing output tree.
        try:
            write_new_json(output / "started.json", {"schema": "ec-kv-conversion/v1", "status": "incomplete", "source": source, "parameters": params})
            source_stream.seek(0)
            input_hash, event_hash = hashlib.sha256(), hashlib.sha256()
            offset, lines, count, blocks, logical_bytes = 0, 0, 0, 0, 0
            previous_time = -1
            region_counts = {"warmup": 0, "measurement": 0}
            with open(output / "events.partial", "xb") as target:
                while True:
                    raw = source_stream.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    require(len(raw) <= MAX_LINE and raw.endswith(b"\n"), "oversized or incomplete JSONL line")
                    input_hash.update(raw)
                    lines += 1
                    row = parse_json(raw)
                    time_ns = validate_row(row)
                    require(time_ns >= previous_time, "input timestamps are not nondecreasing; no implicit sort")
                    previous_time = time_ns
                    for event in row_events(row, source, params, lines, offset, raw):
                        event["sequence_decimal"] = str(count)
                        encoded = canonical(event) + b"\n"
                        target.write(encoded)
                        event_hash.update(encoded)
                        count += 1
                        if event["kind"] == "request_arrival":
                            region_counts[event["clock"]["region"]] += 1
                        else:
                            blocks += 1
                            logical_bytes += int(event["object"]["logical_bytes_decimal"])
                    offset += len(raw)
                require(lines > 0, "no source records")
                require(input_hash.hexdigest() == first_sha and offset == first_bytes, "input changed during conversion")
                require(fingerprint(source_stream) == before, "input file metadata changed during conversion")
                target.flush()
                os.fsync(target.fileno())
            # Both names are inside a newly owned directory. No existing result is replaced.
            os.rename(output / "events.partial", output / "events.jsonl")
            directory_synced = sync_directory(output)
            manifest = {"schema": "ec-kv-conversion/v1", "status": "complete", "source": source, "parameters": params,
                        "namespace_sha256": namespace(source, params), "events_sha256": event_hash.hexdigest(),
                        "records_decimal": str(lines), "events_decimal": str(count), "block_observations_decimal": str(blocks),
                        "logical_bytes_observed_decimal": str(logical_bytes), "request_regions": region_counts,
                        "full_lfs_object_verified": source["input_scope"] == "full-file", "directory_fsync_supported": directory_synced,
                        "claims": {"actual_kv_tensors": False, "hit_rate_measured": False, "unique_objects_counted": False,
                                   "storage_io_performed": False, "trace_prestart_cache_known": False}}
            write_new_json(output / "manifest.json", manifest)
            sync_directory(output)
            return manifest
        except BaseException as error:
            try:
                write_new_json(output / "failed.json", {"status": "failed", "error_type": type(error).__name__, "message": str(error)[:1024]})
            except BaseException:
                pass  # Preserve the original failure, including disk-full errors.
            raise


def iter_payload(key, length, offset=0, chunk_size=65536):
    digest(key, "payload object key")
    integer(length, "payload length", 0, BLOCK_BYTES)
    integer(offset, "payload offset", 0, BLOCK_BYTES)
    require(offset + length <= BLOCK_BYTES, "payload range exceeds mapping bound")
    integer(chunk_size, "payload chunk", 1, 1048576)
    seed = bytes.fromhex(key)
    remaining = length
    counter, skip = divmod(offset, 32)
    buffer = bytearray()
    while remaining:
        raw = hashlib.sha256(b"ec-kv-payload-v1\x00" + seed + counter.to_bytes(8, "big")).digest()[skip:]
        counter += 1
        skip = 0
        take = min(len(raw), remaining)
        buffer.extend(raw[:take])
        remaining -= take
        while len(buffer) >= chunk_size:
            yield bytes(buffer[:chunk_size])
            del buffer[:chunk_size]
    if buffer:
        yield bytes(buffer)


def write_payload(key, length, output, offset=0):
    result = hashlib.sha256()
    # A partial file remains on failure; only successful stdout reports its SHA.
    with open(output, "xb") as stream:
        for chunk in iter_payload(key, length, offset):
            stream.write(chunk)
            result.update(chunk)
        stream.flush()
        os.fsync(stream.fileno())
    return {"algorithm": PAYLOAD_ALGORITHM, "key_sha256": key, "offset_decimal": str(offset),
            "length_decimal": str(length), "sha256": result.hexdigest(), "actual_kv_tensor": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    conv = sub.add_parser("convert")
    conv.add_argument("--input", required=True)
    conv.add_argument("--source", required=True)
    conv.add_argument("--output-dir", required=True)
    conv.add_argument("--model-namespace", required=True)
    conv.add_argument("--format-namespace", required=True)
    conv.add_argument("--user-namespace", required=True)
    conv.add_argument("--reuse-mode", choices=("request", "synthetic-tenant"), default="request")
    conv.add_argument("--scale-numerator", type=int, default=1)
    conv.add_argument("--scale-denominator", type=int, default=1)
    conv.add_argument("--measurement-start-ns", type=int, default=0)
    payload = sub.add_parser("payload")
    payload.add_argument("--key", required=True)
    payload.add_argument("--length", required=True, type=int)
    payload.add_argument("--offset", default=0, type=int)
    payload.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "convert":
        params = parameters(args.model_namespace, args.format_namespace, args.user_namespace, args.reuse_mode,
                            args.scale_numerator, args.scale_denominator, args.measurement_start_ns)
        result = convert(args.input, read_json_file(args.source), params, args.output_dir)
    else:
        result = write_payload(args.key, args.length, args.output, args.offset)
    print(canonical(result).decode("ascii"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
