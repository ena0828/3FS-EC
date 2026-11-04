#!/usr/bin/env python3
"""Run EC metadata tests against a newly created, private FoundationDB instance."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET


def helpers():
    path = Path(__file__).with_name("test-native-fragments.py")
    spec = importlib.util.spec_from_file_location("native_test_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    common = helpers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path)
    parser.add_argument("--fdb-bin-dir", type=Path, required=True)
    parser.add_argument("--tmp-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--filter", default="TestEcCatalog*.*")
    parser.add_argument("--timeout", type=common.positive_seconds, default=300)
    parser.add_argument("--bootstrap-only", action="store_true",
                        help="check private FDB startup and a read/write probe; no GoogleTests")
    args = parser.parse_args()
    if not args.bootstrap_only and args.test_binary is None:
        parser.error("--test-binary is required unless --bootstrap-only is selected")
    output = args.output.expanduser().resolve()
    try:
        output.mkdir()  # New result directory only; never reuse a database.
    except OSError as error:
        print(f"Cannot create output: {error}", file=sys.stderr)
        return 2
    report = {"schema_version": 1, "started_utc": common.utc(), "status": "running",
              "purpose": "private FDB bootstrap" if args.bootstrap_only else "EC metadata functional tests",
              "commands": [], "failures": [], "data_retained": True}
    server = None
    server_log = None
    exitcode = 1
    try:
        if sys.platform != "linux":
            raise RuntimeError("This runner requires Linux")
        root = args.tmp_root.expanduser().resolve(strict=True)
        report["mount"] = common.mount_for(root)
        if report["mount"]["filesystem"] not in ("ext4", "xfs"):
            raise RuntimeError("FDB temporary root must be on ext4 or XFS")
        report["resources"] = common.resource_snapshot()
        report["nofile"] = common.prepare_nofile()
        binaries = {name: (args.fdb_bin_dir / name).resolve(strict=True) for name in ("fdbserver", "fdbcli")}
        if not args.bootstrap_only:
            binaries["test_meta"] = args.test_binary.resolve(strict=True)
        for binary in binaries.values():
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError(f"Not an executable file: {binary}")
        report["binaries"] = {name: {"path": str(path), "sha256": common.sha256(path)}
                              for name, path in binaries.items()}
        temporary = Path(tempfile.mkdtemp(prefix="ec-meta-", dir=root))
        report["tmpdir"] = str(temporary)
        data, trace = temporary / "data", temporary / "trace"
        data.mkdir()
        trace.mkdir()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        address = f"127.0.0.1:{port}"
        cluster = temporary / "fdb.cluster"
        cluster.write_text(f"ec_catalog_test:{secrets.token_hex(16)}@{address}\n")
        report["cluster_file"] = str(cluster)
        report["cluster_sha256"] = common.sha256(cluster)
        env = dict(os.environ)
        removed = {name for name in env if name.startswith("GTEST_") or name.startswith("FDB_")
                   or name == "EC_CATALOG_TEST_CLUSTER"}
        for name in removed:
            env.pop(name, None)
        env.update(TMPDIR=str(temporary), FDB_UNITTEST_CLUSTER=str(cluster), FDB_CLUSTER_FILE=str(cluster),
                   EC_CATALOG_TEST_CLUSTER=str(cluster))
        report["environment"] = {key: env[key] for key in ("TMPDIR", "FDB_UNITTEST_CLUSTER", "FDB_CLUSTER_FILE",
                                                          "EC_CATALOG_TEST_CLUSTER")}
        if "LD_LIBRARY_PATH" in env:
            report["environment"]["LD_LIBRARY_PATH"] = env["LD_LIBRARY_PATH"]
        report["removed_environment"] = sorted(removed)

        def call(argv, name, timeout=15, required=True):
            command = list(map(str, argv))
            log = output / (name + ".log")
            record = {"argv": command, "cwd": str(temporary), "log": str(log),
                      "started_utc": common.utc(), "timeout_seconds": timeout}
            environment = ["env"]
            for key in sorted(removed):
                environment.extend(["-u", key])
            environment.extend(key + "=" + value for key, value in report["environment"].items())
            record["shell_command"] = (f"( ulimit -Sn {report['nofile']['soft_after']} && cd "
                                       + shlex.quote(str(temporary)) + " && "
                                       + shlex.join(environment + command) + " )")
            report["commands"].append(record)
            common.save_report(output, report)
            with log.open("xb") as stream:
                process = subprocess.Popen(command, cwd=temporary, env=env, stdout=stream,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                record["pid"] = process.pid
                try:
                    process.wait(timeout=timeout)
                except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                    record["termination"] = common.stop_owned_process(process)
                    record["exitcode"] = process.returncode
                    record["interrupted_or_timeout"] = type(error).__name__
                    raise
                record["exitcode"] = process.returncode
            record["ended_utc"] = common.utc()
            common.save_report(output, report)
            if required and process.returncode != 0:
                raise RuntimeError(f"{name} failed with exit {process.returncode}; see {log}")
            return log.read_text(errors="replace")

        for name in ("fdbserver", "fdbcli"):
            report["binaries"][name]["version"] = call([binaries[name], "--version"], name + "-version").strip()
        argv = [str(binaries["fdbserver"]), "-p", address, "-l", address, "-C", str(cluster),
                "-d", str(data), "-L", str(trace), "--memory", "1536MiB", "--cache-memory", "128MiB",
                "--logsize", "10MiB", "--maxlogssize", "100MiB"]
        server_log = (output / "fdbserver.log").open("xb")
        server = subprocess.Popen(argv, cwd=temporary, env=env, stdout=server_log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
        report["server"] = {"argv": argv, "pid": server.pid, "cwd": str(temporary),
                            "started_utc": common.utc(), "shell_command": shlex.join(argv)}
        common.save_report(output, report)
        cli = [binaries["fdbcli"], "-C", cluster, "--exec"]
        call(cli + ["configure new single ssd logs=1 commit_proxies=1 grv_proxies=1 resolvers=1"],
             "configure", timeout=30)
        ready = False
        for attempt in range(20):
            if server.poll() is not None:
                raise RuntimeError(f"Owned FDB server exited: {server.returncode}")
            status = call(cli + ["status json"], f"status-{attempt:02d}", required=False)
            try:
                ready = json.loads(status).get("client", {}).get("database_status", {}).get("available") is True
            except json.JSONDecodeError:
                ready = False
            if ready:
                break
            time.sleep(0.5)
        if not ready:
            raise RuntimeError("Private FDB instance did not become available")
        marker = secrets.token_hex(16)
        probe = call(cli + [f"writemode on; set ec_runner_probe {marker}; get ec_runner_probe"], "read-write-probe")
        if marker not in probe:
            raise RuntimeError("Private FDB read/write probe did not return its unique value")
        report["bootstrap"] = "passed"
        print(f"Private FoundationDB ready: {cluster}", flush=True)
        if not args.bootstrap_only:
            binary = binaries["test_meta"]
            flags = ["--gtest_filter=" + args.filter, "--gtest_repeat=1", "--gtest_shuffle=0", "--gtest_color=no"]
            call([binary, *flags, "--gtest_list_tests"], "test-list", timeout=args.timeout)
            selected = [case["name"] for case in common.listed_tests(output / "test-list.log") if not case["disabled"]]
            if not selected or len(set(selected)) != len(selected):
                raise RuntimeError("Test filter selected zero tests or duplicate names")
            report["selected"] = selected
            xml = output / "tests.xml"
            call([binary, *flags, "--gtest_output=xml:" + str(xml)], "test-run", timeout=args.timeout, required=False)
            report["test_results"] = common.xml_tests(xml)
            cases = report["test_results"]["cases"]
            executed = [case["name"] for case in cases if case["executed"]]
            if sorted(executed) != sorted(selected) or any(case["failed"] or case["skipped"] for case in cases):
                raise RuntimeError("Test XML contains failures, skips or differs from the selected set")
            if any(report["test_results"][key] not in (None, "0")
                   for key in ("declared_failures", "declared_errors")):
                raise RuntimeError("Test XML declares suite-level failures or errors")
            if report["commands"][-1]["exitcode"] != 0:
                raise RuntimeError("Test process failed despite its XML results")
            report["passed_tests"] = len(executed)
        for name, binary in binaries.items():
            after = common.sha256(binary)
            report["binaries"][name]["sha256_after"] = after
            if after != report["binaries"][name]["sha256"]:
                raise RuntimeError(f"Binary changed during testing: {name}")
        exitcode = 0
    except KeyboardInterrupt:
        report["failures"].append("interrupted")
        exitcode = 130
    except (OSError, RuntimeError, ValueError, ET.ParseError, subprocess.TimeoutExpired) as error:
        report["failures"].append(str(error))
    finally:
        if server is not None:
            report["server"]["exitcode_before_cleanup"] = server.poll()
            if server.poll() is None:
                report["server"]["cleanup"] = common.stop_owned_process(server)
            else:
                report["failures"].append("FDB server exited before controlled cleanup")
                exitcode = exitcode or 1
            report["server"]["exitcode_after_cleanup"] = server.poll()
            if server.poll() is None:
                report["failures"].append("FDB server remains alive after cleanup")
                exitcode = exitcode or 1
        if server_log:
            server_log.close()
        report.update(ended_utc=common.utc(), exitcode=exitcode, status="passed" if exitcode == 0 else "failed")
        common.save_report(output, report)
        print(f"{report['status'].upper()}: {output / 'results.json'}", flush=True)
        for error in report["failures"]:
            print(error, file=sys.stderr)
    return exitcode


if __name__ == "__main__":
    raise SystemExit(main())
