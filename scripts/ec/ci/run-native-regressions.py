#!/usr/bin/env python3
"""Bind existing Storage/service/client regressions to one native build.

This delegates the actual tests and process cleanup to test-native-fragments.py.
It checks the production C++ wrapper's backend property and loader resolution;
it does not run a benchmark or certify the SIMD kernel chosen by ISA-L.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET


TARGETS = ("test_storage_store", "test_storage_service", "test_client")
BACKEND_CASE = "TestEcCodec.IndependentGoldenVectorEmptyInputAndOwnedOutput"
MANDATORY = {
    "TestEcCodec." + name for name in (
        "IndependentGoldenVectorEmptyInputAndOwnedOutput",
        "RecoversAllSixtySixTenSourceSetsInArbitraryOrder",
        "RejectsParityCorruptionAndEvenSelfConsistentNonzeroPadding",
        "HelperContributionsReconstructOrderedTargetsAndSlices",
        "RejectsInvalidShapeSourcesAndUnsupportedFormats",
        "ContributionValidatesPlanAndOneMiBInputBound",
    )
} | {
    "TestEcRmw." + name for name in (
        "ExactPlanRightsPatchAndSparseTail",
        "DataRecoveryUsesParityAndKeepsReadOomDistinctFromMutationUnknown",
        "ShortSubmitAndStopJoinTheActualOwnedTask",
    )
} | {"TestChunkEngine.ReadWrite", "TestStorageTarget.ReadWrite", "TestStorageTarget.Uncommitted"}

CLIENT_MANDATORY = {
    "TestEcTargetRetirementCommands." + name for name in (
        "UnknownPrepareAndNewClientQueryPreserveExactIntent",
        "PreparedDoesNotClaimStorageDrainOrPhysicalReclamation",
        "MismatchedOrContradictoryResponsesNeverConfirmRetirement",
        "InvalidIdentityAndExistingArchivePreventDispatch",
        "WrongActualNamespaceAndGetterExceptionRetainPreparedIdentity",
        "QueryErrorsNeverPrepareAndDirectClientRejectsNilRequestIds",
    )
}

RPC_FRAME_CASES = tuple("TestEcRpcFrameSizes." + name for name in (
    "ActualEncodedFramesIncludeHeaderAcrossCompression",
    "ReverseRepliesOnOneConnectionKeepUuidAttribution",
    "BusinessAndDecodeErrorsRetainValidFrameSamples",
    "TimeoutLateAndDuplicateRepliesDoNotRewriteCompletedOutputs",
    "InvalidOuterFrameHasNoResponseSample",
))
RPC_OBSERVER_CASES = (
    "TestEcRepairPipeline.RpcObservationSeparatesHostClocksMissingErrorsAndOverflow",
    "TestEcRepairPipeline.RpcFrameObservationCountsMissingErrorsExceptionsAndSaturates",
)
CLIENT_MANDATORY |= set(RPC_FRAME_CASES) | set(RPC_OBSERVER_CASES)

SERVICE_MANDATORY = {
    "TestEcStageService.LostSealReplyIsUnknownAndRetryDoesNotDoubleAccount",
    "TestEcNativeRepairService.UnknownSealSurvivesCancellationUntilSameStageIsReconciled",
    "TestEcNativeRepairService.ThreeStrategiesRecoverLostAppendReplyOnOriginalStages",
    "TestEcNativeRepairService.ThreeStrategiesRecoverLostSealReplyAfterEngineReopen",
    "TestEcNativeRepairService.WindowTwoLostAppendReplyRecoversBothOriginalTargets",
}

# Exact names prevent unrelated green suites from satisfying the control profile.
TARGET_RETIREMENT_REQUIRED = {
    "storage": {
        "TestEcTargetRetirementControl." + name for name in (
            "RequestCanonicalMacGoldenAndRedactedSerde",
            "ObservationCanonicalMacGoldenAndExactRequest",
            "EveryRequestFieldIsAuthenticated",
            "EveryObservationFieldIsAuthenticated",
            "LifetimeAuthorityActionAndWrongKeyFailClosed",
            "MalformedFramesAndContradictoryStatesFailClosed",
            "ScopeAndRetirementDomainsCannotCross",
            "RetirementDigestExcludesRequestAuthorityNodeAndNonce",
        )
    } | {
        "TestEcTargetRetirementExecutor." + name for name in (
            "HeldScopesProducePendingThenLocalDataDrained",
            "MissingAndMismatchedIntentNeverSigns",
            "SameIdReplayCannotResurrectAdmission",
            "ColdReopenPreservesIdentityAndRetirement",
            "LegacyTargetCannotIssueObservation",
            "PostEnqueueFailureAndStopWaitForRealWorker",
            "ExpiredAfterPersistenceReturnsUnknown",
        )
    },
    "service": {
        "TestEcTargetRetirementService.RealClientPrepareQueryAndReplayBindExactObservation",
        "TestEcTargetRetirementService.ChangedAuthorityIdentityAndTamperedRequestHaveNoEffect",
        "TestEcTargetRetirementDisabledService.DisabledRequestsHaveNoPersistentEffects",
    },
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def revision_binding(revision, local_revision, environment):
    expected = environment.get("GITHUB_SHA") if local_revision is None else local_revision
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{40}", expected)
            and revision == expected, "source differs from the explicit or triggering revision")
    return {"mode": "github-revision" if local_revision is None else "local-revision",
            "expected_revision": expected}


def local_build_root(build, uid, gid, euid, egid):
    require(uid == euid != 0 and gid == egid, "local mode requires unchanged ordinary UID and GID")
    info = build.parent.stat()
    require(build.name == "build" and stat.S_ISDIR(info.st_mode)
            and info.st_uid == euid and not (stat.S_IMODE(info.st_mode) & 0o077),
            "local build parent must be a private same-user directory")


def backend_property(xml, expected):
    require(expected in ("scalar", "isal"), "unknown expected backend")
    cases = [case for case in ET.parse(xml).getroot().iter("testcase")
             if case.get("classname", "") + "." + case.get("name", "") == BACKEND_CASE]
    require(len(cases) == 1, "production backend observation case missing or repeated")
    case = cases[0]
    require(case.get("status") == "run" and case.get("result") != "skipped"
            and not any(case.findall(tag) for tag in ("failure", "error", "skipped")),
            "backend observation case did not execute successfully")
    values = [prop.get("value") for prop in case.findall("./properties/property")
              if prop.get("name") == "ec_codec_backend"]
    require(values == [expected], "production C++ wrapper backend differs from build choice")
    return values[0]


def check_suites(record, build, built):
    require(record.get("status") == "passed" and record.get("exitcode") == 0
            and record.get("failures") == [], "native regression driver failed")
    suites = record.get("suites", [])
    require([row.get("suite") for row in suites] == ["storage", "service", "client"],
            "required regression suites omitted or repeated")
    for row, target in zip(suites, TARGETS, strict=True):
        require(row.get("status") == "passed" and row.get("failures") == []
                and row.get("binary") == str(build / "tests" / target)
                and row.get("binary_sha256") == row.get("binary_sha256_after") == built["binaries"][target],
                "regression result is not bound to the current target")
        selected = [case["name"] for case in row["listed_tests"] if not case["disabled"]]
        cases = row["xml_results"]["cases"]
        actual = [case["name"] for case in cases]
        require(selected and len(set(selected)) == len(selected) and sorted(actual) == sorted(selected)
                and all(case["executed"] and not case["failed"] and not case["skipped"] for case in cases),
                "regression XML differs from the actual nonempty listing")
        for phase in ("listing", "execution"):
            cmd = row[phase]
            require(cmd.get("exitcode") == 0 and not any(cmd.get(key) for key in
                    ("timed_out", "interrupted", "launch_error", "termination")),
                    "regression command was incomplete or required forced cleanup")
    names = {case["name"] for case in suites[0]["xml_results"]["cases"]}
    require(MANDATORY <= names, "codec/RMW/legacy storage coverage is incomplete")
    client_names = {case["name"] for case in suites[2]["xml_results"]["cases"]}
    require(CLIENT_MANDATORY <= client_names, "required client coverage is incomplete")
    service_names = {case["name"] for case in suites[1]["xml_results"]["cases"]}
    require(SERVICE_MANDATORY <= service_names, "native repair unknown-outcome coverage is incomplete")
    check_rpc_frames(record)


def check_rpc_frames(record):
    rows = [row for row in record.get("suites", []) if row.get("suite") == "client"]
    require(len(rows) == 1, "RPC frame client suite missing or repeated")
    cases = rows[0].get("xml_results", {}).get("cases", [])
    frames = [case for case in cases if case.get("name", "").startswith("TestEcRpcFrameSizes.")]
    names = [case["name"] for case in frames]
    require(len(names) == len(RPC_FRAME_CASES) and set(names) == set(RPC_FRAME_CASES),
            "RPC frame XML does not contain exactly the five real TCP cases")
    observers = [case for case in cases if case.get("name") in RPC_OBSERVER_CASES]
    require(len(observers) == len(RPC_OBSERVER_CASES)
            and {case["name"] for case in observers} == set(RPC_OBSERVER_CASES),
            "RPC frame observation cases missing or repeated")
    require(all(case.get("executed") is True and case.get("failed") is False
                and case.get("skipped") is False for case in frames + observers),
            "RPC frame or observation case did not execute successfully")
    return {"tcp_cases": list(RPC_FRAME_CASES), "observation_cases": list(RPC_OBSERVER_CASES)}


def check_target_retirement(record):
    require(set(TARGET_RETIREMENT_REQUIRED) == {"storage", "service"}
            and all(TARGET_RETIREMENT_REQUIRED.values()), "target retirement inventory is incomplete")
    for kind, required in TARGET_RETIREMENT_REQUIRED.items():
        rows = [row for row in record.get("suites", []) if row.get("suite") == kind]
        require(len(rows) == 1, "target retirement suite missing or repeated")
        cases = rows[0].get("xml_results", {}).get("cases", [])
        actual = [case["name"] for case in cases if case.get("executed") is True
                  and case.get("failed") is False and case.get("skipped") is False]
        require(len(actual) == len(set(actual)) and required <= set(actual),
                "required target retirement test did not execute successfully")
    return {kind: sorted(names) for kind, names in TARGET_RETIREMENT_REQUIRED.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--build", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--backend", required=True, choices=("scalar", "isal"))
    parser.add_argument("--require-target-retirement", action="store_true")
    parser.add_argument("--local-revision", help="explicit full source commit for an ordinary Linux acceptance host; "
                        "omitting it keeps the GITHUB_SHA binding")
    args = parser.parse_args()
    require(sys.platform == "linux" and os.getuid() == os.geteuid() != 0, "ordinary Linux UID required")
    sys.dont_write_bytecode = True
    os.umask(0o077)
    core = module(Path(__file__).with_name("run-core-tests.py"), "regression_core")
    source, build = map(core.existing_path, (args.source, args.build))
    require(Path(__file__).resolve() == source / "scripts/ec/ci/run-native-regressions.py",
            "use the source-bound formal entry point")
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    binding = revision_binding(revision, args.local_revision, os.environ)
    if args.local_revision is not None:
        local_build_root(build, os.getuid(), os.getgid(), os.geteuid(), os.getegid())
    subprocess.run(["git", "-C", str(source), "diff", "--exit-code", "HEAD", "--ignore-submodules=all"],
                   check=True, stdout=subprocess.DEVNULL)
    record_path = build.parent / "provenance/native-build.json"
    built = json.loads(record_path.read_text(encoding="utf-8"))
    require(built.get("schema") == 1 and built.get("revision") == revision
            and built.get("source") == str(source) and built.get("build") == str(build)
            and built.get("backend") == args.backend and built.get("ec_regression_targets_requested") is True,
            "explicit regression build receipt differs")
    require(built["build_script_sha256"] == digest(source / "scripts/ec/ci/build-native.sh")
            and built["cmake_cache_sha256"] == digest(build / "CMakeCache.txt"), "build inputs changed")
    for target in TARGETS:
        require(target in built["targets"] and digest(core.existing_path(build / "tests" / target)) == built["binaries"][target],
                "regression executable differs from build receipt")
    work = args.work
    require(work.is_absolute() and work == build.parent / "regressions" and not os.path.lexists(work),
            "fresh fixed regression directory required")
    work.mkdir(mode=0o700)
    (work / "tmp").mkdir(mode=0o700)
    inputs = {str(path): digest(path) for path in (
        Path(__file__), source / "scripts/ec/test-native-fragments.py", record_path,
        source / "tests/storage/store/TestEcCodec.cc", source / "tests/storage/store/TestEcRmw.cc",
        source / "tests/client/TestEcTargetRetirementCommands.cc",
        source / "tests/client/TestEcRpcFrameSizes.cc", source / "tests/client/TestEcRepairPipeline.cc",
        source / "tests/storage/service/TestEcStageService.cc")}
    if args.require_target_retirement:
        inputs.update({str(source / path): digest(source / path) for path in (
            "tests/storage/store/TestEcTargetRetirementControl.cc",
            "tests/storage/store/TestEcTargetRetirementExecutor.cc",
            "tests/storage/service/TestEcTargetRetirementService.cc",
        )})
    report = {"schema": 1, "revision": revision, "revision_binding": binding,
              "backend": args.backend, "status": "incomplete",
              "native_build_sha256": digest(record_path), "inputs_sha256": inputs,
              "target_retirement_required": args.require_target_retirement,
              "required_client_cases": sorted(CLIENT_MANDATORY),
              "required_rpc_frame_cases": list(RPC_FRAME_CASES),
              "required_rpc_observer_cases": list(RPC_OBSERVER_CASES),
              "required_service_cases": sorted(SERVICE_MANDATORY),
              "scope": "native functional regressions; not a benchmark or real Storage process fault"}
    result = 1
    try:
        os.environ.pop("LD_PRELOAD", None)
        os.environ.pop("LD_AUDIT", None)
        os.environ["LD_LIBRARY_PATH"] = "/usr/local/lib"
        loader = subprocess.run(["ldd", str(build / "tests/test_storage_store")], capture_output=True,
                                text=True, timeout=30, check=True)
        (work / "ldd.stdout").write_text(loader.stdout, encoding="utf-8")
        (work / "ldd.stderr").write_text(loader.stderr, encoding="utf-8")
        require("not found" not in loader.stdout, "native test loader dependency missing")
        providers = re.findall(r"^\s*libisal\.so(?:\.\d+)*\s+=>\s+(/\S+)\s+\(", loader.stdout, re.M)
        if args.backend == "isal":
            require(len(providers) == 1, "exactly one ISA-L dependency required")
            provider = Path(providers[0]).resolve(strict=True)
            require(str(provider) == built["isal"]["provider"]["path"]
                    and digest(provider) == built["isal"]["provider"]["sha256"], "ISA-L loader provider differs")
            report["isal_provider"] = built["isal"]["provider"]
        else:
            require(not providers and built.get("isal") is None, "Scalar build unexpectedly links ISA-L")
        common = module(source / "scripts/ec/test-native-fragments.py", "system_native_fragments")
        report["driver_exitcode"] = common.main([
            "--bin-dir", str(build / "tests"), "--tmp-root", str(work / "tmp"),
            "--output", str(work / "tests"), "--suite", "all", "--include-legacy", "--timeout", "300"])
        receipt = work / "tests/results.json"
        actual = json.loads(receipt.read_text(encoding="utf-8"))
        report["regressions"] = actual
        report["regression_receipt_sha256"] = digest(receipt)
        require(report["driver_exitcode"] == 0, "existing native regression driver returned nonzero")
        check_suites(actual, build, built)
        if args.require_target_retirement:
            report["target_retirement_verified"] = check_target_retirement(actual)
        report["actual_backend"] = backend_property(work / "tests/storage.xml", args.backend)
        report["evidence_sha256"] = {str(path): digest(path) for path in sorted((work / "tests").glob("*"))
                                     if path.is_file()}
        if args.backend == "isal":
            require(digest(provider) == built["isal"]["provider"]["sha256"], "ISA-L library changed during tests")
        require(all(digest(Path(path)) == value for path, value in inputs.items()), "regression input changed")
        report.update(status="passed", passed=sum(row["executed_count"] for row in actual["suites"]))
        result = 0
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)[:500]}
    finally:
        path = work / "result.json"
        with path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"native_ec_regressions": report, "receipt_sha256": digest(path)}), flush=True)
    return result


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"native_regression_admission": "failed", "error_type": type(error).__name__}))
        sys.exit(1)
