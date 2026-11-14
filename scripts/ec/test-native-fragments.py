#!/usr/bin/env python3
"""Run existing native fragment tests on Linux; functional acceptance, not a benchmark."""

import argparse
import datetime
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET


STORAGE_FILTER = "TestEcProtocol.*:TestEcTarget.*:TestEcIntegrity.*:TestEcCodec.*:TestEcAuthorization.*:TestEcScopeBridge.*:TestEcScopeLoadBudget.*:TestEcStagingBridge.*:TestEcAuthorizationV2.*:TestEcScopeControl.*:TestEcScopeControlExecutor.*:TestEcRepairPlan.*:TestEcHelperAuthorization.*:TestEcTargetDiscovery.*:TestEcDiskMaintenance.*:TestEcGcControl.*:TestEcGcExecutor.*:TestEcEmptyGroupTrim.*:TestEcGcTargetFormat.*:TestEcKeyFileIdentity.*:TestEcGcDiscovery.*:TestEcGcDiscoveryRuntime.*:TestEcGcDiscoveryFormat2.*:TestEcRmw.*"
SERVICE_FILTER = "TestEcService.*:TestEcServiceWithoutEngine.*:TestEcAuthorizedService.*:TestEcAuthorizedNoKeyService.*:TestEcCapabilityComponents.*:TestEcScopeControlService.*:TestEcStageService.*:TestEcNativeRepairService.*:TestEcTargetDiscoveryService.*:TestEcTargetDiscoveryDisabled.*:TestEcGcDiscoveryDisabled.*:TestEcGcDiscoveryService.*:TestEcRmwNative.*"
CLIENT_FILTER = "TestEcStripeRead.*:TestEcBlockRead.*:TestEcRepairPipeline.*:TestFakeMgmtdRoutingListeners.*:TestEcStripeClient.*:TestEcStripeRunRecord.*:TestEcStripeFragmentRecovery.*:TestEcStripeCompletion.*:TestEcGcCommands.*:TestEcRevisionRetirementCommands.*:TestEcAllocationExport.*:TestEcFilePlanning.*:TestEcFilePayload.*:TestEcFileRunJournal.*:TestEcFileClient.*:TestEcReadDispatcher.*:TestEcTreeReadJournal.*:TestEcTreeReadClient.*:TestEcFilePwriteClient.*:TestEcTruncateJournal.*:TestEcAppendJournal.*:TestEcTreeRepairJournal.*:TestEcMetadataRouting.*"
STORAGE_FILTER += ":TestEcTargetRetirementControl.*:TestEcTargetRetirementExecutor.*"
STORAGE_FILTER += ":TestEcHelperDirectAuthorization.*"
SERVICE_FILTER += ":TestEcTargetRetirementService.*:TestEcTargetRetirementDisabledService.*"
CLIENT_FILTER += ":TestEcTargetRetirementCommands.*"
CLIENT_FILTER += ":TestEcRpcFrameSizes.*"
CLIENT_FILTER += ":TestEcTransportPolicy.*:TestEcNativeTransportPolicy.*"
CLIENT_FILTER += ":TestEcNamespaceJournal.*:TestEcNamespaceClient.*"
CLIENT_FILTER += ":TestEcFileOutputIdentity.*"
LEGACY_FILTER = "TestChunkEngine.ReadWrite:TestStorageTarget.ReadWrite:TestStorageTarget.Uncommitted"
# TestChunkEngine.ReadWrite retains default 4 MiB/64 MiB buffers and 32 AIO
# workers: (4 * 4 + 64) * 32 = 2560 MiB of repeated ring registration accounting.
# 3 GiB leaves bounded headroom; it does not allocate 3 GiB of physical buffers.
LEGACY_MEMLOCK_BYTES = 3 * 1024**3
GTEST_ENV = {
    "GTEST_FILTER", "GTEST_REPEAT", "GTEST_SHUFFLE", "GTEST_RANDOM_SEED",
    "GTEST_TOTAL_SHARDS", "GTEST_SHARD_INDEX", "GTEST_SHARD_STATUS_FILE",
    "GTEST_ALSO_RUN_DISABLED_TESTS", "GTEST_OUTPUT", "GTEST_LIST_TESTS",
    "GTEST_BREAK_ON_FAILURE", "GTEST_THROW_ON_FAILURE", "GTEST_FAIL_FAST",
}
DIAGNOSTIC_CASE_LIMIT = 16
PROGRESS_LOG_BYTES = 1024 * 1024


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def positive_seconds(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return result


def parser():
    result = argparse.ArgumentParser(
        description=__doc__,
        epilog=("No build, installation, cluster startup, periodic resource sampling or performance tuning is performed. "
                "The output directory and TMPDIR are retained, including after failure. "
                "With --suite service or client, --include-legacy additionally schedules the storage regression cases. "
                "Its memlock requirement follows the current test buffer/thread defaults, not a universal platform requirement."),
    )
    result.add_argument("--bin-dir", required=True, type=Path, help="directory containing already-built test binaries")
    result.add_argument("--tmp-root", required=True, type=Path, help="existing writable directory on ext4")
    result.add_argument("--output", required=True, type=Path, help="new results directory; its parent must exist")
    result.add_argument("--suite", choices=("all", "storage", "service", "client"), default="all")
    result.add_argument("--include-legacy", action="store_true", help="also run the three named legacy storage regressions (requires 3 GiB memlock limit)")
    result.add_argument("--timeout", type=positive_seconds, default=300.0, help="seconds per listing/test command (default: 300)")
    return result


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def mount_for(path):
    """Resolve Linux mountinfo escaping and choose the most specific mount."""
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)

    matches = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        fields, filesystem = left.split(), right.split()
        mount = Path(unescape(fields[4]))
        if path == mount or mount in path.parents:
            matches.append({"mountpoint": str(mount), "filesystem": filesystem[0],
                            "source": unescape(filesystem[1]), "options": fields[5]})
    if not matches:
        raise RuntimeError(f"cannot determine filesystem for {path}")
    return max(matches, key=lambda item: len(item["mountpoint"]))


def prepare_nofile():
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 65536:
        raise RuntimeError(f"RLIMIT_NOFILE hard limit {hard} is below required 65536; raise it before running")
    requested = soft if soft == resource.RLIM_INFINITY else max(soft, 65536)
    if requested != soft:
        resource.setrlimit(resource.RLIMIT_NOFILE, (requested, hard))
    actual, actual_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if actual != resource.RLIM_INFINITY and actual < 65536:
        raise RuntimeError(f"RLIMIT_NOFILE soft limit remains {actual}, below required 65536")
    def value(number):
        return "unlimited" if number == resource.RLIM_INFINITY else number
    return {"soft_before": value(soft), "soft_after": value(actual), "hard": value(actual_hard)}


def prepare_memlock(report, include_legacy):
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    required = LEGACY_MEMLOCK_BYTES if include_legacy else 0
    def value(number):
        return "unlimited" if number == resource.RLIM_INFINITY else number
    record = {"soft_before_bytes": value(soft), "soft_after_bytes": value(soft),
              "hard_bytes": value(hard), "required_bytes": required,
              "hard_limit_changed": False}
    report["memlock"] = record
    if include_legacy:
        record.update(buffer_pool_bytes=80 * 1024**2, ring_count=32,
                      estimated_registration_accounting_bytes=2560 * 1024**2,
                      basis="TestChunkEngine.ReadWrite: 4 x 4 MiB + 1 x 64 MiB, registered by each of 32 AIO workers",
                      scope="current test defaults; re-evaluate if the test configuration changes; not a platform-wide minimum")
    if required and hard != resource.RLIM_INFINITY and hard < required:
        raise RuntimeError(
            f"RLIMIT_MEMLOCK hard limit {hard} bytes is below {required} bytes required for --include-legacy. "
            "Set limits on a dedicated launcher process (prlimit --memlock=3221225472:3221225472), "
            "then drop privileges with setpriv to the normal test user before invoking this runner; "
            "do not run tests as root or change global limits."
        )
    if required and soft != resource.RLIM_INFINITY and soft < required:
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (required, hard))
    actual, _ = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    record["soft_after_bytes"] = value(actual)


def resource_snapshot():
    snapshot = {"uid": os.getuid(), "effective_uid": os.geteuid(),
                "gid": os.getgid(), "kernel_release": os.uname().release}
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("CapEff:"):
            snapshot["effective_capabilities_hex"] = line.split()[1]
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        fields = line.split()
        if fields[0] in ("MemTotal:", "MemAvailable:", "Mlocked:", "Unevictable:"):
            memory[fields[0][:-1] + "_bytes"] = int(fields[1]) * 1024
    snapshot["memory_before"] = memory
    return snapshot


def save_report(output, report):
    temporary = output / "results.json.tmp"
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(output / "results.json")


def print_summary(report):
    for suite in report["suites"]:
        print(f"{suite['suite']}: {suite['status'].upper()} — "
              f"{suite['executed_count']}/{suite['selected_count']} executed/selected", flush=True)
        if suite["status"] != "passed":
            if "run_progress" in suite:
                print("NATIVE_SUITE_PROGRESS " + json.dumps(
                    {"suite": suite["suite"], "diagnostics": suite["run_progress"]},
                    sort_keys=True, ensure_ascii=True), flush=True)
            diagnostic_count = 0
            for case in suite.get("xml_results", {}).get("cases", []):
                if case.get("failed") and "failure_diagnostics" in case:
                    diagnostic_count += 1
                    if diagnostic_count <= DIAGNOSTIC_CASE_LIMIT:
                        print("NATIVE_CASE_FAILURE " + json.dumps(
                            {"name": case["name"], "diagnostics": case["failure_diagnostics"]},
                            sort_keys=True, ensure_ascii=True), flush=True)
            if diagnostic_count > DIAGNOSTIC_CASE_LIMIT:
                print("NATIVE_CASE_FAILURE_LIMIT " + json.dumps(
                    {"omitted_cases": diagnostic_count - DIAGNOSTIC_CASE_LIMIT}), flush=True)
            for reason in suite["failures"]:
                print("  reason: " + (reason if len(reason) <= 200 else reason[:197] + "..."), flush=True)
            for stage in ("listing", "execution"):
                if stage in suite:
                    print(f"  {stage} log: {suite[stage]['log']}", flush=True)
    for reason in report["failures"]:
        print("error: " + (reason if len(reason) <= 200 else reason[:197] + "..."), flush=True)


def stop_owned_process(process):
    # start_new_session gives this invocation its own process group. Never use
    # name matching, killall, or any PID belonging to an existing cluster.
    actions = []
    for signum, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        try:
            os.killpg(process.pid, signum)
            actions.append(signal.Signals(signum).name)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=grace)
            if signum == signal.SIGKILL:
                return {"signals": actions, "leader_reaped": True}
            # The group leader can exit before its children. Apply the final
            # signal to this same owned group, never to a process-name search.
        except subprocess.TimeoutExpired:
            continue
    return {"signals": actions, "leader_reaped": process.poll() is not None}


def shell_command(command, cwd, env, removed_env, nofile, memlock):
    environment = ["env"]
    for name in sorted(removed_env):
        environment.extend(["-u", name])
    environment.append("TMPDIR=" + env["TMPDIR"])
    if "LD_LIBRARY_PATH" in env:
        environment.append("LD_LIBRARY_PATH=" + env["LD_LIBRARY_PATH"])
    # Shell ulimit -l is expressed in KiB; resource/prlimit use bytes.
    locked_bytes = memlock["soft_after_bytes"]
    locked_kib = "unlimited" if locked_bytes == "unlimited" else locked_bytes // 1024
    return (f"( ulimit -Sn {nofile['soft_after']} && ulimit -Sl {locked_kib} && cd {shlex.quote(str(cwd))} && "
            + shlex.join(environment + command) + " )")


def run_command(command, cwd, env, log, timeout, removed_env, nofile, memlock):
    rendered = shell_command(command, cwd, env, removed_env, nofile, memlock)
    print(rendered, flush=True)
    result = {"argv": command, "cwd": str(cwd), "shell_command": rendered,
              "log": str(log), "started_utc": utc(), "timeout_seconds": timeout,
              "exitcode": None, "timed_out": False, "interrupted": False}
    started = time.monotonic()
    with log.open("xb") as stream:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as error:
            result["launch_error"] = str(error)
        else:
            result["pid"] = process.pid
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                result["termination"] = stop_owned_process(process)
            except KeyboardInterrupt:
                result["interrupted"] = True
                result["termination"] = stop_owned_process(process)
            result["exitcode"] = process.returncode
    result.update(ended_utc=utc(), elapsed_seconds=time.monotonic() - started)
    return result


def listed_tests(log):
    suite = None
    tests = []
    for raw in log.read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if re.fullmatch(r"[A-Za-z0-9_/]+\.", line):
            suite = line[:-1]
        elif suite and re.fullmatch(r"  [A-Za-z0-9_/]+", line):
            case = line.strip()
            disabled = any(part.startswith("DISABLED_") for part in (suite + "/" + case).split("/"))
            tests.append({"name": suite + "." + case, "disabled": disabled})
    return tests


def failure_location(message):
    """Publish a checked repository-relative source location, never its build prefix."""
    first = message.split("\n", 1)[0].rstrip("\r")
    match = re.fullmatch(r"(.+):([1-9][0-9]{0,7})", first)
    if not match:
        return None
    raw = match[1].replace("\\", "/")
    if any(part in (".", "..") for part in raw.split("/")):
        return None
    # A path is useful only if its suffix is an actual file in this source tree.
    # No caller-provided path is opened, and '..' or unfamiliar filename syntax
    # is never normalized into an accepted location.
    suffix = re.search(r"(?:^|/)((?:tests|src)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:cc|cpp|c|h|hpp|inc))$", raw)
    if not suffix:
        return None
    relative = suffix[1]
    if any(part in (".", "..") for part in relative.split("/")):
        return None
    source = Path(__file__).resolve().parents[2]
    candidate = source / relative
    if not candidate.is_file() or candidate.resolve() != candidate:
        return None
    return {"file": relative, "line": int(match[2])}


def failure_scalar(text):
    """Only complete scalar values from standard assertion lines are public."""
    if text in ("true", "false"):
        return text == "true"
    if len(text) > 32 or not re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", text):
        return None
    value = float(text) if any(char in text for char in ".eE") else int(text)
    if isinstance(value, float):
        return value if math.isfinite(value) and abs(value) <= 1e18 else None
    return value if -(1 << 63) <= value < 1 << 63 else None


def assertion_diagnostic(node):
    # The full XML remains private. Bounded parsing is diagnostic only, not a
    # second assertion interpreter or a reason to accept an otherwise failed case.
    raw = node.get("message") or node.text or ""
    message = raw[:8192]
    lines = message.splitlines()[:64]
    result = {"kind": node.tag, "classification": "unclassified",
              "input_truncated": len(raw) > 8192 or len(message.splitlines()) > 64,
              "details_redacted": True}
    location = failure_location(message)
    if location is None:
        # Some GoogleTest versions put only the summary in the attribute and
        # the compiler location in CDATA. Never treat a cut first line as a path.
        text = node.text or ""
        prefix = text[:8192].encode("utf-8")[:8192].decode("utf-8", errors="ignore")
        if "\n" in prefix or prefix == text:
            location = failure_location(prefix)
    if location is not None:
        result["source"] = location
    for line in lines:
        if line.startswith("Expected equality of these values:"):
            result["classification"] = "equality"
            break
        if line.startswith("Value of:"):
            result["classification"] = "boolean"
            break
        if line.startswith("The difference between "):
            result["classification"] = "near"
            break
        if line.startswith("Expected:") and re.search(r" (?:<|<=|>|>=|!=) ", line):
            result["classification"] = "comparison"
            break
    values = []
    for line in lines:
        match = re.fullmatch(r"[ \t]*(Which is|Actual|Expected):[ \t]*(\S+)[ \t]*", line)
        if match:
            value = failure_scalar(match[2])
            if value is not None and len(values) < 4:
                values.append({"role": {"Which is": "operand", "Actual": "actual",
                                        "Expected": "expected"}[match[1]], "value": value})
    if values:
        result["scalar_values"] = values
    return result


def failure_diagnostics(case):
    count = 0
    summaries = []
    for node in case:
        if node.tag in ("failure", "error"):
            count += 1
            if len(summaries) < 3:
                summaries.append(assertion_diagnostic(node))
    return {"status": "available", "assertion_count": count,
            "assertions_omitted": max(0, count - len(summaries)), "assertions": summaries,
            "scope": "source_location_and_scalar_assertions_only_not_raw_log"}


def xml_tests(path):
    root = ET.parse(path).getroot()
    if root.tag not in ("testsuites", "testsuite"):
        raise ValueError(f"unexpected GoogleTest XML root: {root.tag}")
    cases = []
    diagnostic_count = 0
    for case in root.iter("testcase"):
        row = {"name": case.get("classname", "") + "." + case.get("name", ""),
               "executed": case.get("status") == "run",
               "failed": bool(case.findall("failure") or case.findall("error")),
               "skipped": bool(case.findall("skipped")) or case.get("result") == "skipped"}
        if row["failed"]:
            diagnostic_count += 1
            if diagnostic_count > DIAGNOSTIC_CASE_LIMIT:
                row["failure_diagnostics"] = {"status": "case_limit", "details_redacted": True}
            else:
                try:
                    row["failure_diagnostics"] = failure_diagnostics(case)
                except Exception:
                    row["failure_diagnostics"] = {"status": "unavailable", "details_redacted": True}
        cases.append(row)
    return {"cases": cases, "declared_tests": root.get("tests"),
            "declared_failures": root.get("failures"), "declared_errors": root.get("errors")}


def run_progress(path, selected, *, ended=False):
    """Read ended private output for bounded progress, never acceptance evidence."""
    unavailable = {"status": "unavailable", "scope": "bounded_progress_not_acceptance",
                   "details_redacted": True}
    if ended is not True:
        return unavailable
    try:
        allowed = {row["name"] for row in selected if row["disabled"] is False}
        with path.open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            start = max(0, size - PROGRESS_LOG_BYTES)
            stream.seek(start)
            data = stream.read(PROGRESS_LOG_BYTES)
        result = {"status": "available", "scope": "bounded_progress_not_acceptance",
                  "details_redacted": True, "bytes_read": len(data), "truncated": start > 0,
                  "first_partial_line_discarded": start > 0,
                  "last_partial_line_discarded": bool(data and not data.endswith(b"\n")),
                  "started_markers": 0, "ok_markers": 0, "failed_markers": 0,
                  "last_started": None, "last_completed": None}
        # At a tail boundary the first line may be partial; discard even if its
        # bytes happen to look like a full marker. EOF without newline is partial.
        lines = data.split(b"\n")
        if start:
            lines = lines[1:]
        lines = lines[:-1]
        for line in lines:
            if line.endswith(b"\r"):
                line = line[:-1]
            started = re.fullmatch(rb"\[ RUN      \] ([A-Za-z0-9_/]+\.[A-Za-z0-9_/]+)", line)
            completed = re.fullmatch(
                rb"\[ (      OK| FAILED ) \] ([A-Za-z0-9_/]+\.[A-Za-z0-9_/]+) \([0-9]{1,12} ms\)", line)
            name = (started[1] if started else completed[2] if completed else b"").decode("ascii")
            if name not in allowed:
                continue
            if started:
                result["started_markers"] += 1
                result["last_started"] = name
            else:
                result["ok_markers" if completed[1] == b"      OK" else "failed_markers"] += 1
                result["last_completed"] = name
        return result
    except Exception:
        return unavailable


def plans(args):
    selected = []
    if args.suite in ("all", "storage"):
        pattern = STORAGE_FILTER + (":" + LEGACY_FILTER if args.include_legacy else "")
        selected.append(("storage", "test_storage_store", pattern))
    elif args.include_legacy:
        selected.append(("storage_legacy", "test_storage_store", LEGACY_FILTER))
    if args.suite in ("all", "service"):
        selected.append(("service", "test_storage_service", SERVICE_FILTER))
    if args.suite in ("all", "client"):
        selected.append(("client", "test_client", CLIENT_FILTER))
    return selected


def main(argv=None):
    args = parser().parse_args(argv)
    output = args.output.expanduser().resolve()
    try:
        output.mkdir()  # Never overwrite prior results or create arbitrary parents.
    except OSError as error:
        print(f"Cannot create new output directory {output}: {error}", file=sys.stderr)
        return 2
    report = {"schema_version": 1, "purpose": "functional acceptance; not a performance benchmark",
              "started_utc": utc(), "status": "running", "output": str(output),
              "suites": [], "failures": [], "temporary_directory_retained": True}
    exitcode = 2
    try:
        if not sys.platform.startswith("linux"):
            raise RuntimeError("this runner requires Linux")
        report["resources"] = resource_snapshot()
        def terminate_runner(_signum, _frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, terminate_runner)
        binary_dir = args.bin_dir.expanduser().resolve(strict=True)
        temporary_root = args.tmp_root.expanduser().resolve(strict=True)
        if not binary_dir.is_dir() or not temporary_root.is_dir():
            raise RuntimeError("--bin-dir and --tmp-root must be existing directories")
        report["tmp_root_mount"] = mount_for(temporary_root)
        if report["tmp_root_mount"]["filesystem"] != "ext4":
            raise RuntimeError("--tmp-root must be on ext4; observed " + report["tmp_root_mount"]["filesystem"])
        for name, executable, pattern in plans(args):
            binary = (binary_dir / executable).resolve(strict=True)
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError(f"test binary is not an executable regular file: {binary}")
            report["suites"].append({"suite": name, "binary": str(binary), "binary_sha256": sha256(binary),
                                     "filter": pattern, "status": "pending", "selected_count": 0,
                                     "executed_count": 0, "failures": []})
        report["nofile"] = prepare_nofile()
        prepare_memlock(report, args.include_legacy)
        temporary = Path(tempfile.mkdtemp(prefix="native-fragments-", dir=temporary_root))
        report["tmpdir"] = str(temporary)
        env = dict(os.environ, TMPDIR=str(temporary))
        removed_env = GTEST_ENV | {name for name in env if name.startswith("GTEST_")}
        for name in removed_env:
            env.pop(name, None)
        report["environment"] = {"TMPDIR": str(temporary), "removed_variables": sorted(removed_env)}
        if "LD_LIBRARY_PATH" in env:
            report["environment"]["LD_LIBRARY_PATH"] = env["LD_LIBRARY_PATH"]
        save_report(output, report)
        exitcode = 0
        for suite in report["suites"]:
            name = suite["suite"]
            cwd = temporary / name
            cwd.mkdir()
            flags = ["--gtest_filter=" + suite["filter"], "--gtest_repeat=1", "--gtest_shuffle=0", "--gtest_color=no"]
            listing = run_command([suite["binary"], *flags, "--gtest_list_tests"], cwd, env,
                                  output / (name + ".list.log"), args.timeout, removed_env, report["nofile"], report["memlock"])
            suite["listing"] = listing
            selected = listed_tests(Path(listing["log"]))
            suite["listed_tests"] = selected
            expected = [case["name"] for case in selected if not case["disabled"]]
            suite["selected_count"] = len(expected)
            if listing["exitcode"] != 0 or listing["timed_out"] or listing["interrupted"]:
                suite["failures"].append("GoogleTest listing did not complete successfully")
            if not expected or len(set(expected)) != len(expected):
                suite["failures"].append("filter selected zero runnable tests or duplicate test names")
            for pattern in suite["filter"].split(":"):
                if not any(fnmatch.fnmatchcase(name, pattern) for name in expected):
                    suite["failures"].append("filter component selected no runnable tests: " + pattern)
            if not suite["failures"]:
                xml = output / (name + ".xml")
                suite["xml"] = str(xml)
                execution = run_command([suite["binary"], *flags, "--gtest_output=xml:" + str(xml)], cwd, env,
                                        output / (name + ".run.log"), args.timeout, removed_env, report["nofile"], report["memlock"])
                suite["execution"] = execution
                if execution["exitcode"] != 0 or execution["timed_out"] or execution["interrupted"]:
                    suite["failures"].append("test command failed, timed out, or was interrupted")
                try:
                    suite["xml_results"] = xml_tests(xml)
                    cases = suite["xml_results"]["cases"]
                    actual = [case["name"] for case in cases if case["executed"]]
                    suite["executed_count"] = len(actual)
                    suite["failed_count"] = sum(case["failed"] for case in cases)
                    suite["skipped_count"] = sum(case["skipped"] for case in cases)
                    if not actual or len(set(actual)) != len(actual) or sorted(actual) != sorted(expected):
                        suite["failures"].append("executed tests differ from the nonempty selected test set")
                    if suite["failed_count"] or suite["skipped_count"]:
                        suite["failures"].append("test XML contains failed or skipped cases")
                    if any(suite["xml_results"][field] not in (None, "0") for field in ("declared_failures", "declared_errors")):
                        suite["failures"].append("test XML declares failures or errors")
                except (OSError, ET.ParseError, ValueError) as error:
                    suite["failures"].append("missing or invalid test XML: " + str(error))
                if suite["failures"]:
                    suite["run_progress"] = run_progress(
                        output / (name + ".run.log"), selected, ended=type(execution["exitcode"]) is int)
            suite["binary_sha256_after"] = sha256(Path(suite["binary"]))
            if suite["binary_sha256_after"] != suite["binary_sha256"]:
                suite["failures"].append("test binary changed during this run")
            suite["status"] = "failed" if suite["failures"] else "passed"
            if suite["failures"]:
                exitcode = 1
            save_report(output, report)
            if listing["interrupted"] or suite.get("execution", {}).get("interrupted"):
                exitcode = 130
                break
        if any(suite["status"] != "passed" for suite in report["suites"]):
            exitcode = exitcode or 1
    except KeyboardInterrupt:
        report["failures"].append("runner interrupted")
        exitcode = 130
    except (OSError, RuntimeError, ValueError) as error:
        report["failures"].append(str(error))
        exitcode = exitcode or 1
    finally:
        report.update(ended_utc=utc(), exitcode=exitcode, status="passed" if exitcode == 0 else "failed")
        save_report(output, report)
        print_summary(report)
        print(f"{report['status'].upper()}: {output / 'results.json'}", flush=True)
    return exitcode


if __name__ == "__main__":
    raise SystemExit(main())
