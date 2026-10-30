#!/usr/bin/env python3
"""Run the native example with paired, randomized execution order."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261029)
    parser.add_argument("--bytes", type=int, default=112 * 1024)
    parser.add_argument("--slice-bytes", type=int, default=4096)
    parser.add_argument("--queue-depth", type=int, default=2)
    args = parser.parse_args()
    if not 2 <= args.repetitions <= 100:
        parser.error("repetitions must be in 2..100")
    executable = args.executable.resolve(strict=True)
    root = args.root.resolve(strict=True)
    # A fresh result directory prevents accidental mixing of experiments.
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = {
        "schema": "3fs-ec-paired-experiment-v1",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "executable": str(executable),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "data_root": str(root),
        "parameters": {key: str(value) if isinstance(value, Path) else value
                       for key, value in vars(args).items()},
        "cache_condition": "uncontrolled; fresh logical stores do not imply cold caches",
        "scope": "single-engine functional repetitions; no distributed performance claim",
        "timing_scope": "repair including output verification and manifest commit; excludes preparation and reopen",
    }
    (args.output / "environment.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    order_rng = random.Random(args.seed)
    samples = []
    with (args.output / "samples.jsonl").open("w", encoding="utf-8") as stream:
        for repetition in range(args.repetitions):
            modes = ["sequential", "pipeline"]
            order_rng.shuffle(modes)
            for position, mode in enumerate(modes):
                command = [str(executable), "--root", str(root), "--mode", mode,
                           "--bytes", str(args.bytes), "--seed", str(args.seed),
                           "--slice-bytes", str(args.slice_bytes),
                           "--queue-depth", str(args.queue_depth)]
                started = time.monotonic()
                load = os.getloadavg()
                failure = None
                try:
                    result = subprocess.run(command, text=True, capture_output=True, timeout=180)
                except subprocess.TimeoutExpired as exc:
                    def decoded(value):
                        return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
                    result = subprocess.CompletedProcess(command, 124, decoded(exc.stdout), decoded(exc.stderr))
                    failure = "example exceeded the 180 second timeout"
                record = {"repetition": repetition, "position": position, "mode": mode,
                          "command": command, "load_before": load,
                          "process_seconds": time.monotonic() - started,
                          "returncode": result.returncode, "stdout": result.stdout,
                          "stderr": result.stderr}
                if result.returncode == 0:
                    try:
                        rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
                        if len(rows) != 1 or not isinstance(rows[0], dict) or not rows[0].get("reopen_verified"):
                            raise ValueError("example did not produce one verified result")
                        record["result"] = rows[0]
                        samples.append(record)
                    except (json.JSONDecodeError, ValueError) as exc:
                        failure = str(exc)
                if failure:
                    record["failure"] = failure
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                stream.flush()
                if result.returncode != 0 or failure:
                    raise RuntimeError(f"example failed; inspect {args.output / 'samples.jsonl'}")
    summary = {"scope": metadata["scope"], "samples_per_mode": args.repetitions, "modes": {}}
    for mode in ("sequential", "pipeline"):
        values = [row["result"]["elapsed_us"] for row in samples if row["mode"] == mode]
        median = statistics.median(values)
        summary["modes"][mode] = {
            "median_us": median,
            "median_absolute_deviation_us": statistics.median(abs(v - median) for v in values),
            "min_us": min(values), "max_us": max(values), "samples_us": values,
        }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
