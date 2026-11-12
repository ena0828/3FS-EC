#!/usr/bin/env python3
"""Optional bounded source acquisition; never downloads a whole trace."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from urllib.request import Request, urlopen

import kv_trace as kv


def fetch(source_path, output_path):
    source = kv.validate_source(kv.read_json_file(source_path))
    kv.require(source["input_scope"] == "bounded-prefix", "only the fixed small prefix is supported")
    url = ("https://media.githubusercontent.com/media/alibaba-edu/qwen-bailian-usagetraces-anon/"
           + source["commit"] + "/" + source["path"])
    request = Request(url, headers={"Range": "bytes=0-65535", "Accept-Encoding": "identity"})
    with urlopen(request, timeout=30) as response:
        kv.require(response.status == 206, "server must honor bounded HTTP Range")
        expected_range = "bytes 0-65535/" + source["upstream_lfs_bytes_decimal"]
        kv.require(response.headers.get("Content-Range") == expected_range, "unexpected range/total size")
        kv.require(response.headers.get("Content-Encoding", "identity") == "identity", "encoded response rejected")
        prefix = response.read(65537)
        kv.require(len(prefix) == 65536, "unexpected bounded prefix length")
        headers = {name: response.headers.get(name) for name in ("Content-Range", "Content-Length", "ETag")}
    end = prefix.rfind(b"\n") + 1
    kv.require(end > 0, "no complete records in prefix")
    complete = prefix[:end]
    kv.require(kv.sha(complete) == source["input_sha256"] and str(len(complete)) == source["input_bytes_decimal"],
               "download does not match locked complete-prefix bytes")
    output = Path(output_path)
    output.mkdir(mode=0o700)  # A fresh, exclusively owned acquisition directory.
    try:
        for name, raw in (("http-prefix.bin", prefix), ("input.jsonl", complete)):
            with open(output / name, "xb") as stream:
                stream.write(raw)
                stream.flush()
                kv.os.fsync(stream.fileno())
        kv.write_new_json(output / "source.json", source)
        record = {"schema": "ec-qwen-prefix-fetch/v1", "status": "complete", "url": url,
                  "fetched_utc": datetime.now(timezone.utc).isoformat(), "http_status": 206, "headers": headers,
                  "http_prefix_bytes": len(prefix), "http_prefix_sha256": kv.sha(prefix),
                  "discarded_partial_line_bytes": len(prefix) - len(complete), "source": source,
                  "full_lfs_object_verified": False, "directory_fsync_supported": kv.sync_directory(output)}
        kv.write_new_json(output / "fetch.json", record)
        kv.sync_directory(output)
        return record
    except BaseException as error:
        try:
            kv.write_new_json(output / "failed.json", {"status": "failed", "error_type": type(error).__name__})
        except BaseException:
            pass
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    try:
        print(kv.canonical(fetch(args.source, args.output_dir)).decode("ascii"))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
