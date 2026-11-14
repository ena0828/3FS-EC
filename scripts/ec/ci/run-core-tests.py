#!/usr/bin/env python3
"""Run the fixed Linux EC native-write and FUSE component acceptance sets.

This is functional acceptance, not a mounted-filesystem test or a benchmark.
Detailed reports, private FDB data and command logs remain under --work.
"""

import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import xml.etree.ElementTree as ET


META_FILTER = "TestEcFileNativeWrite.*:TestEcMountedTruncateRecovery.*:TestEcStorageTransportConfig.*"
FUSE_FILTER = "TestEcFuseRead.*:TestEcFuseShutdown.*:TestEcFileMount.*:TestEcFuseTransportConfig.*"
META_CASES = tuple("TestEcFileNativeWrite." + name for name in (
    "AppendLostAcceptanceUsesSameEofAndFsyncRequiresPublishedData",
    "CommittedSourceChildWithoutExecutionCanBeFencedAndReleased",
    "FreshPublicationRejectsOrphanedPermanentEditBeforeInstallingManifest",
    "WriteOnlyZeroThenDataPatchPublishesAndReadsThroughTreeSession",
    "RenameMovesReplacesAndKeepsOpenObjectsWithPermanentReplay",
    "TruncateTailLostReplyAndExtensionDoNotResurrectBytes",
    "TruncatePublicationSurvivesClosingLastUnlinkedSession",
)) + tuple("TestEcMountedTruncateRecovery." + name for name in (
    "BeginConflictReplaysOriginalIntent",
    "PublishedConflictAfterDataTailReplaysOriginalIntent",
    "EightConflictsKeepDebtAndRecoveryCapacity",
    "FixedDeadlineStopsConflictRecovery",
    "LostCommittedBeginReplyIsNotRetried",
)) + ("TestEcStorageTransportConfig.RejectsImplicitModesAndHotTransportChanges",)
# The two flat manager cases also verify opt-in repair metrics, joined failure
# scopes and history/default-off isolation against real Meta/FDB + Storage.
REPAIR_CASES = (
    "TestEcFileNativeRepair.ThreeStrategiesPublishFreshTwelveAndKeepSourceDebtExplicit",
    "TestEcFileNativeRepair.HealthyCopyPendingIntentResumesSameJournalAfterEngineReopen",
    "TestEcFileNativeRepair.HelperDirectCommittedIssuanceLostReplyAndFreshTwelvePublication",
    "TestEcV2NativeHelperPlan.FlatDirectSingleAndDoubleTargetsKeepPermanentDelivery",
    "TestEcV2NativeHelperPlan.FlatDirectCommittedReplyLossAndClosingOnlyObserve",
    "TestEcV2RepairPlanCatalog.DirectDeliveryVersionsOnlyPermanentRecord",
    "TestEcV2NativeHelperPlan.StripeManagerRunsAllExplicitRepairStrategiesThroughMetaIssuedPlan",
    "TestEcV2NativeHelperPlan.CommittedPlanRenewalRetainsSelectionAndClosingStopsEveryGrant",
)
AUTH_USER_CASES = tuple(f"TestAuth/{backend}.{case}" for backend in (0, 1)
                        for case in ("Basic", "ExplicitPrimaryGroup"))
SERVICE_CONTRACT_CASES = AUTH_USER_CASES + (
    "TestMetaServiceReflection.RegistersAll71IncludingBeyondDefaultFieldRank",
)
TARGET_META_CASES = (
    "TestEcTargetRetirementCatalog.RealFdbImmutableIntentAndRequestIdentity",
    "TestEcTargetRetirementCatalog.RealFdbAcceptedIntentConflictsWithAssignmentSnapshot",
    "TestEcTargetRetirementCatalog.RealFdbMissingIndexAndInvalidVersionFailClosed",
    "TestEcTargetRetirementNative.LostPrepareReplySameIdQueryAndFirstCompletionSurviveRestart",
    "TestEcTargetRetirementNative.AcceptedButUnsentIntentQueryCannotPrepareAndRootAuthenticationIsMandatory",
    "TestEcTargetRetirementNative.FlatReadAndFencedAbortUseOneRetirementButNeverPublish",
    "TestEcFileTree.DrainEvidenceVersionsPreserveV1BytesAndRejectPublication",
    "TestEcFileTree.RealFdbEightDataRetirementRangeRevalidatesAndFitsSingleBudget",
    "TestEcFileTree.RealFdbRepairTwentyTwoRetirementsFencePublicationAndRevalidateGc",
)
FUSE_CASES = (
    "TestEcFuseRead.FlagsAndCopiedIdentityUseActualAuthentication",
    "TestEcFuseRead.WindowBoundsAndZeroEofPreserveReceiptAndOutputLease",
    "TestEcFuseRead.ExclusiveInspectionRejectsAttachmentAndReleasesAfterException",
    "TestEcFuseRead.PrivateArchiveOutsideSpoolAndExistingFlockAreRequired",
    "TestEcFuseRead.ActualRingMixedReplicatedFailureKeepsEcSuccessAndInvalidIndex",
    "TestEcFuseRead.ActualRingRejectsEcWriteBeforeLegacyMutationAndRegistration",
    "TestEcFuseRead.ClaimedSqeAndArgumentsRemainOwnedAfterSharedMemoryChanges",
    "TestEcFuseShutdown.EmptyAndFailedInitStopIsIdempotentBeforeConfigurationDestruction",
    "TestEcFuseShutdown.StickyJoinUsesActualTopLevelExitBeforeHooksAndDestructors",
    "TestEcFuseShutdown.FullClaimedBatchDrainsBeforeOwnedJoinAndStopsFurtherClaims",
    "TestEcFileMount.DurableNamespaceExclusiveStateAndUnsupportedFlags",
    "TestEcFileMount.DroppedWaiterStillJoinsOwnedWorkerAndHeldOutputKeepsAdmission",
    "TestEcFileMount.TerminalHistoryDoesNotConsumeActiveQuotaAndNamesNeverRepeat",
    "TestEcFileMount.OutputLeaseDefersTerminalIndexRemovalAndLegacyFormatIsRejected",
    "TestEcFuseTransportConfig.ExplicitPolicyCannotChangeDuringAMount",
)
COMMAND_TIMEOUT = 1800
META_DEADLINE = 4200  # Two commands plus bounded FDB bootstrap and owned cleanup.
FUSE_DEADLINE = 1100  # 60-second listing, 900-second execution, owned cleanup.
MEMLOCK_BYTES = 3 * 1024**3  # Explicit CI profile, not a universal minimum.


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "build", "fdb-bin-dir", "work"):
        result.add_argument("--" + name, required=True, type=Path)
    result.add_argument("--profile", choices=("core", "repair", "target-meta", "auth-user", "service-contracts"), default="core",
                        help="core: 13 Meta + 15 FUSE; repair: file and flat repair, Direct delivery and recovery fixtures; "
                             "target-meta: 9 retirement catalogue, RPC and evidence cases; "
                             "auth-user: default and explicit primary GID with MemKV and FDB; "
                             "service-contracts: auth-user plus all Meta dispatch IDs")
    return result


def selection(profile):
    if profile == "core":
        return META_CASES, META_FILTER, FUSE_CASES
    if profile == "repair":
        return REPAIR_CASES, ":".join(REPAIR_CASES), ()
    if profile == "target-meta":
        return TARGET_META_CASES, ":".join(TARGET_META_CASES), ()
    if profile == "auth-user":
        return AUTH_USER_CASES, ":".join(AUTH_USER_CASES), ()
    if profile == "service-contracts":
        return SERVICE_CONTRACT_CASES, ":".join(SERVICE_CONTRACT_CASES), ()
    raise ValueError("unknown fixed acceptance profile")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_names(names, expected):
    require(len(names) == len(expected) and len(set(names)) == len(names)
            and set(names) == set(expected), "test names differ from the fixed acceptance set")


def check_listing(cases, expected):
    require(not any(case["disabled"] for case in cases), "disabled tests are not acceptance")
    exact_names([case["name"] for case in cases], expected)


def check_xml(result, expected):
    cases = result["cases"]
    exact_names([case["name"] for case in cases], expected)
    require(all(case["executed"] and not case["failed"] and not case["skipped"]
                for case in cases), "XML contains a failure, skip, or unexecuted test")
    require(result["declared_tests"] == str(len(expected)), "XML test total differs")
    require(result["declared_failures"] == "0" and result["declared_errors"] == "0",
            "XML suite failures/errors are absent or nonzero")


def checked_limits(nofile, memlock, infinity):
    for value, minimum, label in ((nofile[0], 65536, "nofile soft"),
                                  (nofile[1], 65536, "nofile hard"),
                                  (memlock[0], MEMLOCK_BYTES, "memlock soft"),
                                  (memlock[1], MEMLOCK_BYTES, "memlock hard")):
        require(value == infinity or value >= minimum, label + " limit is below the CI profile")
    def rendered(value):
        return "unlimited" if value == infinity else value
    return (
        {"soft_before": rendered(nofile[0]), "soft_after": rendered(nofile[0]),
         "hard": rendered(nofile[1])},
        {"soft_before_bytes": rendered(memlock[0]), "soft_after_bytes": rendered(memlock[0]),
         "hard_bytes": rendered(memlock[1]), "required_bytes": MEMLOCK_BYTES,
         "hard_limit_changed": False},
    )


def existing_path(path):
    path = path.expanduser()
    require(path.is_absolute() and ".." not in path.parts, "paths must be absolute without '..'")
    for item in (path, *path.parents):
        require(not item.is_symlink(), "symlink paths are not accepted")
    return path.resolve(strict=True)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command_ok(record):
    require(record.get("exitcode") == 0 and not record.get("timed_out")
            and not record.get("interrupted") and not record.get("interrupted_or_timeout")
            and not record.get("launch_error"),
            "command did not complete successfully")


def flags(test_filter):
    return ["--gtest_filter=" + test_filter, "--gtest_repeat=1",
            "--gtest_shuffle=0", "--gtest_color=no"]


def case_diagnostics(path):
    """Bounded XML-only diagnostics, never FDB traces or configuration contents."""
    require(path.stat().st_size <= 16 * 1024**2, "XML exceeds diagnostic size bound")
    root = ET.parse(path).getroot()
    result = []
    for case in root.iter("testcase"):
        if len(result) == 32:
            raise ValueError("XML exceeds diagnostic case bound")
        details = "\n".join((item.text or item.get("message", ""))
                            for tag in ("failure", "error", "skipped") for item in case.findall(tag))
        encoded = details.encode("utf-8")
        result.append({"name": (case.get("classname", "") + "." + case.get("name", ""))[:256],
                       "executed": case.get("status") == "run",
                       "failed": bool(case.findall("failure") or case.findall("error")),
                       "skipped": bool(case.findall("skipped")) or case.get("result") == "skipped",
                       "detail": encoded[:2048].decode("utf-8", errors="ignore"),
                       "detail_truncated": len(encoded) > 2048})
    return result


def check_meta_receipt(receipt, binary, output, cases=META_CASES, test_filter=META_FILTER):
    require(receipt.get("status") == "passed" and receipt.get("exitcode") == 0
            and receipt.get("bootstrap") == "passed" and not receipt.get("failures"),
            "Meta driver did not pass")
    exact_names(receipt["selected"], cases)
    check_xml(receipt["test_results"], cases)
    require(receipt.get("passed_tests") == len(cases), "Meta receipt count differs")
    commands = receipt["commands"]
    for ending in (["--gtest_list_tests"], ["--gtest_output=xml:" + str(output / "tests.xml")]):
        expected = [str(binary), *flags(test_filter), *ending]
        records = [record for record in commands if record.get("argv") == expected]
        require(len(records) == 1, "Meta command missing or repeated")
        command_ok(records[0])
    test_commands = [record for record in commands if record.get("argv", [None])[0] == str(binary)]
    require(len(test_commands) == 2, "unexpected additional Meta test invocation")
    server = receipt["server"]
    require(server.get("exitcode_before_cleanup") is None
            and server.get("exitcode_after_cleanup") is not None
            and server.get("cleanup", {}).get("leader_reaped") is True,
            "private FDB did not reach controlled, joined cleanup")
    for name in ("test_meta", "fdbserver", "fdbcli"):
        record = receipt["binaries"][name]
        digest = record["sha256"]
        require(len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
                and digest == record.get("sha256_after"), "Meta binary hash changed or is invalid")
    require(receipt["binaries"]["test_meta"]["path"] == str(binary), "Meta binary binding differs")


class Interrupts:
    """Translate catchable termination to existing helpers' cleanup path.

    Repeated signals are recorded without interrupting cleanup. No process-name
    searches or global kill operations are used. SIGKILL cannot be handled.
    """

    def __init__(self, common):
        self.common = common
        self.received = []
        self.cleaning = 0
        self.phase = None

    def handle(self, signum, _frame):
        first = not self.received
        self.received.append({"signal": signum, "phase": self.phase})
        signal.setitimer(signal.ITIMER_REAL, 0)
        if first and not self.cleaning:
            raise KeyboardInterrupt

    def stop(self, process):
        self.cleaning += 1
        try:
            return self.original_stop(process)
        finally:
            self.cleaning -= 1

    def __enter__(self):
        self.original_stop = self.common.stop_owned_process
        self.common.stop_owned_process = self.stop
        self.previous = {number: signal.getsignal(number)
                         for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
        for number in self.previous:
            signal.signal(number, self.handle)
        return self

    def __exit__(self, *_args):
        signal.setitimer(signal.ITIMER_REAL, 0)
        self.common.stop_owned_process = self.original_stop
        for number, handler in self.previous.items():
            signal.signal(number, handler)

    @contextlib.contextmanager
    def deadline(self, phase, seconds):
        require(not self.received, "termination already requested")
        self.phase = phase
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def exitcode(self):
        if not self.received:
            return None
        number = self.received[0]["signal"]
        return 124 if number == signal.SIGALRM else 128 + number


def run_meta(source, build, fdb, work, common, interrupts, report,
             cases=META_CASES, test_filter=META_FILTER):
    module = load_module(source / "scripts/ec/test-meta-catalog.py", "ec_hosted_meta")
    # Same implementation and ownership rules; the stop wrapper only prevents
    # a second signal from interrupting its existing bounded cleanup.
    module.helpers = lambda: common
    output = work / "meta"
    argv = [str(source / "scripts/ec/test-meta-catalog.py"),
            "--test-binary", str(build / "tests/test_meta"),
            "--fdb-bin-dir", str(fdb), "--tmp-root", str(work / "tmp"),
            "--output", str(output), "--filter", test_filter,
            "--timeout", str(COMMAND_TIMEOUT)]
    stage = report["meta"] = {"argv": [sys.executable, *argv], "driver_exitcode": None}
    previous = sys.argv
    original_listing = common.listed_tests
    def fixed_listing(log):
        listed = original_listing(log)
        check_listing(listed, cases)
        return listed
    try:
        sys.argv = argv
        # Refuse an unexpected selection before the existing driver dispatches it.
        common.listed_tests = fixed_listing
        with (work / "meta-driver.log").open("x", encoding="utf-8") as console:
            with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                stage["driver_exitcode"] = module.main()
    finally:
        sys.argv = previous
        common.listed_tests = original_listing
    receipt_path = output / "results.json"
    stage.update(receipt=str(receipt_path), receipt_sha256=common.sha256(receipt_path))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    stage["driver_failures"] = receipt.get("failures", [])
    stage["command_exitcodes"] = [record.get("exitcode") for record in receipt.get("commands", [])]
    stage["binary_sha256"] = receipt.get("binaries", {}).get("test_meta", {}).get("sha256")
    # Preserve directly observed cleanup even when the test process failed.
    # This is diagnostic evidence, separate from this stage's acceptance status.
    stage["driver_observation"] = {key: receipt[key] for key in (
        "status", "exitcode", "bootstrap", "passed_tests") if key in receipt}
    server = receipt.get("server", {})
    observed_server = {key: server[key] for key in (
        "exitcode_before_cleanup", "exitcode_after_cleanup") if key in server}
    cleanup = server.get("cleanup", {})
    observed_server["cleanup"] = {key: cleanup[key] for key in (
        "signals", "leader_reaped") if key in cleanup}
    stage["driver_observation"]["server"] = observed_server
    require(not interrupts.received, "Meta phase interrupted")
    require(stage["driver_exitcode"] == 0, "Meta driver returned nonzero")
    check_meta_receipt(receipt, build / "tests/test_meta", output, cases, test_filter)
    check_listing(common.listed_tests(output / "test-list.log"), cases)
    xml = common.xml_tests(output / "tests.xml")
    check_xml(xml, cases)
    require(xml == receipt["test_results"], "Meta XML and receipt differ")
    stage.update(passed_tests=len(cases), skipped_tests=0,
                 xml_sha256=common.sha256(output / "tests.xml"),
                 listing_sha256=common.sha256(output / "test-list.log"), status="passed")


def run_fuse(build, work, common, interrupts, report):
    output, temporary = work / "fuse", work / "tmp/fuse"
    output.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    binary = build / "tests/test_fuse_ec"
    stage = report["fuse"] = {"binary": str(binary), "binary_sha256": common.sha256(binary)}
    env = dict(os.environ)
    removed = {name for name in env if name.startswith(("GTEST_", "FDB_"))
               or name == "EC_CATALOG_TEST_CLUSTER"}
    for name in removed:
        env.pop(name, None)
    env["TMPDIR"] = str(temporary)
    stage["removed_environment"] = sorted(removed)
    with (output / "driver.log").open("x", encoding="utf-8") as console:
        with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
            stage["listing"] = common.run_command(
                [str(binary), *flags(FUSE_FILTER), "--gtest_list_tests"], temporary, env,
                output / "list.log", 60, removed, report["nofile"], report["memlock"])
            common.save_report(work, report)
            require(not interrupts.received, "FUSE listing interrupted")
            command_ok(stage["listing"])
            check_listing(common.listed_tests(output / "list.log"), FUSE_CASES)
            stage["execution"] = common.run_command(
                [str(binary), *flags(FUSE_FILTER), "--gtest_output=xml:" + str(output / "tests.xml")],
                temporary, env, output / "run.log", 900, removed,
                report["nofile"], report["memlock"])
            common.save_report(work, report)
            require(not interrupts.received, "FUSE execution interrupted")
            command_ok(stage["execution"])
    xml = common.xml_tests(output / "tests.xml")
    check_xml(xml, FUSE_CASES)
    stage["binary_sha256_after"] = common.sha256(binary)
    require(stage["binary_sha256_after"] == stage["binary_sha256"], "FUSE binary changed")
    stage.update(xml_results=xml, passed_tests=len(FUSE_CASES), skipped_tests=0,
                 xml_sha256=common.sha256(output / "tests.xml"),
                 listing_sha256=common.sha256(output / "list.log"), status="passed")


def main(argv=None):
    args = parser().parse_args(argv)
    meta_cases, meta_filter, fuse_cases = selection(args.profile)
    phases = ("meta", "fuse") if fuse_cases else ("meta",)
    expected_total = len(meta_cases) + len(fuse_cases)
    work, common, report = None, None, None
    old_umask = None
    try:
        require(sys.platform == "linux", "this runner requires Linux")
        require(os.getuid() == os.geteuid() and os.geteuid() != 0, "run as an ordinary real/effective UID")
        sys.dont_write_bytecode = True
        import resource
        nofile, memlock = checked_limits(resource.getrlimit(resource.RLIMIT_NOFILE),
                                        resource.getrlimit(resource.RLIMIT_MEMLOCK), resource.RLIM_INFINITY)
        source, build, fdb = map(existing_path, (args.source, args.build, args.fdb_bin_dir))
        for path in (source, build, fdb):
            require(path.is_dir(), "source/build/FDB path is not a directory")
        binaries = [build / "tests/test_meta", fdb / "fdbserver", fdb / "fdbcli"]
        if fuse_cases:
            binaries.append(build / "tests/test_fuse_ec")
        for path in binaries:
            resolved = existing_path(path)
            require(resolved.is_file() and os.access(resolved, os.X_OK), "required binary is not executable")
        candidate = args.work.expanduser()
        require(candidate.is_absolute() and ".." not in candidate.parts, "--work must be absolute without '..'")
        parent = existing_path(candidate.parent)
        info = parent.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_mode & 0o077 == 0, "--work parent must be an owned private directory")
        require(not os.path.lexists(candidate), "--work must not already exist")
        common = load_module(source / "scripts/ec/test-native-fragments.py", "ec_hosted_common")
        mount = common.mount_for(parent)
        require(mount["filesystem"] == "ext4", "native-write fixtures require ext4")
        old_umask = os.umask(0o077)
        candidate.mkdir(mode=0o700)
        work = candidate.resolve(strict=True)
        (work / "tmp").mkdir(mode=0o700)
        report = {"schema_version": 1, "status": "running", "started_utc": common.utc(),
                  "profile": args.profile,
                  "source": str(source), "build": str(build), "work": str(work),
                  "mount": mount, "nofile": nofile, "memlock": memlock,
                  "resources": common.resource_snapshot(), "failures": [],
                  "runner_sha256": common.sha256(Path(__file__)),
                  "helpers_sha256": {name: common.sha256(source / "scripts/ec" / name)
                                     for name in ("test-meta-catalog.py", "test-native-fragments.py")},
                  "expected_tests": {"meta": list(meta_cases), "fuse": list(fuse_cases)}}
        common.save_report(work, report)
        with Interrupts(common) as interrupts:
            code = 1
            try:
                with interrupts.deadline("meta", META_DEADLINE):
                    run_meta(source, build, fdb, work, common, interrupts, report, meta_cases, meta_filter)
                common.save_report(work, report)
                print(f"meta: passed {len(meta_cases)}/{len(meta_cases)}, skipped=0, driver_exit=0, xml_sha256="
                      + report["meta"]["xml_sha256"], flush=True)
                if fuse_cases:
                    with interrupts.deadline("fuse", FUSE_DEADLINE):
                        run_fuse(build, work, common, interrupts, report)
                code = 0
            except KeyboardInterrupt:
                report["failures"].append("interrupted")
                code = interrupts.exitcode() or 130
            except Exception as error:
                report["failures"].append(type(error).__name__ + ": " + str(error))
                code = interrupts.exitcode() or 1
            finally:
                for name in phases:
                    xml_path = work / name / "tests.xml"
                    if name in report and xml_path.is_file():
                        try:
                            report[name]["xml_sha256"] = common.sha256(xml_path)
                            report[name]["case_diagnostics"] = case_diagnostics(xml_path)
                        except Exception as error:
                            report[name]["diagnostic_error"] = type(error).__name__
                            if code == 0:
                                code = 1
                                report["failures"].append("XML diagnostic extraction failed")
                report.update(ended_utc=common.utc(), exitcode=code, signals=interrupts.received,
                              status="passed" if code == 0 else "failed",
                              passed_tests=sum(report.get(name, {}).get("passed_tests", 0)
                                               for name in phases))
                common.save_report(work, report)
                for name in phases:
                    stage = report.get(name, {})
                    print(name + ": " + json.dumps(
                        {key: stage[key] for key in ("status", "passed_tests", "skipped_tests",
                         "driver_exitcode", "command_exitcodes", "binary_sha256", "xml_sha256",
                         "receipt_sha256", "driver_observation") if key in stage},
                        sort_keys=True), flush=True)
                    for key in ("listing", "execution"):
                        if key in stage:
                            record = stage[key]
                            print(name + "." + key + ": " + json.dumps(
                                {field: record.get(field) for field in ("exitcode", "timed_out", "interrupted")},
                                sort_keys=True), flush=True)
                    for case in stage.get("case_diagnostics", []):
                        # JSON escaping keeps assertion newlines/control characters
                        # from becoming CI annotations or unbounded console output.
                        print(name + ".case: " + json.dumps(case, sort_keys=True), flush=True)
                    if stage.get("driver_failures"):
                        print(name + ".driver_failures: "
                              + json.dumps([str(item)[:512] for item in stage["driver_failures"][:4]]), flush=True)
                    if stage.get("diagnostic_error"):
                        print(name + ".diagnostic_error: " + stage["diagnostic_error"], flush=True)
                print(args.profile + ": status=" + report["status"] + ", exit=" + str(code)
                      + ", passed=" + str(report["passed_tests"]) + "/" + str(expected_total) + ", receipt_sha256="
                      + common.sha256(work / "results.json"), flush=True)
            return code
    except Exception as error:
        # Detailed exception text is local; console never dumps FDB or test logs.
        if work is not None and common is not None:
            report = report or {"schema_version": 1, "failures": []}
            report.update(status="failed", exitcode=2)
            report["failures"].append(type(error).__name__ + ": " + str(error))
            common.save_report(work, report)
        print("core: preflight/report failure (" + type(error).__name__ + "), exit=2", file=sys.stderr)
        return 2
    finally:
        if old_umask is not None:
            os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
