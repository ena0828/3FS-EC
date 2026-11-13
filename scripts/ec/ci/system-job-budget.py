#!/usr/bin/env python3
"""Use the existing public-job time anchor for sequential system acceptance.

The combined file/spare admission estimate is not a cleanup guarantee. No
workflow cancellation, credential, build or service operation is performed.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys


STAGES = {"repair": (80, 75), "file": (90, 45), "spare": (40, 35),
          "regression": (40, 35), "service-contracts": (80, 75), "target-meta": (80, 75), "core": (100, 95)}
PROFILE_REFS = {
    "system": ("refs/heads/feat/ec-system-acceptance",),
    "target-meta": ("refs/heads/feat/ec-target-meta", "refs/heads/fix/ec-retirement-keys",
                    "refs/heads/fix/ec-meta-reflection"),
}


def budget_module(profile="system", ref=None):
    if profile not in PROFILE_REFS:
        raise ValueError("unknown fixed job budget profile")
    if ref is None:
        ref = PROFILE_REFS[profile][0]
    if ref not in PROFILE_REFS[profile]:
        raise ValueError("ref is outside the fixed job budget profile")
    path = Path(__file__).with_name("job-budget.py")
    spec = importlib.util.spec_from_file_location("system_budget_base", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.REF = ref
    module.REQUIRED_MINUTES = 90
    module.LAB_STEP_MINUTES = 80  # File 45 + spare 35; both remain separately capped.
    module.RECORD_NAME = "ec-" + profile + "-job-budget.json"
    module.BODY_NAME = "ec-" + profile + "-job-budget-api.json"
    return module


def check(base, parent, identity, stage):
    required, step = STAGES[stage]
    encoded = base.read_private(parent / base.RECORD_NAME, 64 << 10)
    value = base.parse_json(encoded)
    base.require(value.get("driver_sha256") == base.digest(Path(base.__file__).read_bytes()),
                 "base budget driver changed")
    data = base.read_private(parent / base.BODY_NAME, base.MAX_BODY)
    left = base.remaining(value, data, identity, base.clock())
    admitted = left >= required * 60 * base.NANO
    print(json.dumps({"status": "admitted" if admitted else "insufficient-budget",
                      "stage": stage, "job_id": value["job_id"], "run_id": identity["run_id"],
                      "attempt": identity["attempt"], "required_seconds": required * 60,
                      "step_minutes": step, "remaining_seconds_conservative_estimate": left // base.NANO,
                      "receipt_sha256": base.digest(encoded),
                      "scope": "admission_only_job_cap_authoritative"}, sort_keys=True))
    return 0 if admitted else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("record", "check"))
    parser.add_argument("--stage", choices=tuple(STAGES))
    parser.add_argument("--profile", choices=("system", "target-meta"), default="system")
    args = parser.parse_args()
    if (args.command == "record" and args.stage is not None) or (args.command == "check" and args.stage is None):
        parser.error("record takes no stage; check requires --stage")
    if args.profile == "system" and args.stage in ("regression", "service-contracts", "target-meta", "core"):
        parser.error("this stage requires --profile target-meta")
    base = budget_module(args.profile, ref=os.environ.get("GITHUB_REF"))
    parent, identity = base.context()
    identity["system_driver_sha256"] = base.digest(Path(__file__).read_bytes())
    return base.record(parent, identity) if args.command == "record" else check(base, parent, identity, args.stage)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"status": "system-budget-gate-failed", "error_type": type(error).__name__}))
        sys.exit(1)
