#!/usr/bin/env python3
"""Explicit GC functional acceptance against an already running native GC bundle.

No service startup, signals to services, database access, key export, or benchmark.
The official experiment runner supplies native journal and byte-readback checks.
Each invocation is single-use except query; unknown results retain all identities.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time
import tomllib
import uuid


def require(value, message):
    if not value:
        raise RuntimeError(message)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def uid(value):
    require(isinstance(value, str), "UUID must be text")
    parsed = uuid.UUID(value)
    require(parsed.int != 0, "Zero UUID is not a durable identity")
    return str(parsed)


def decimal(value, positive=False):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value), "Expected canonical decimal string")
    require(int(value) <= 2**64 - 1 and (not positive or int(value) > 0), "Decimal identity outside uint64")
    return value


def sync_parent(path):
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(w, path, value):
    w.write_exclusive(path, w.json_data(value))
    sync_parent(path)


def hash_file(w, path):
    path = w.canonical(path)
    require(path.is_file(), f"Missing regular input: {path}")
    # Binaries can be larger than the bounded JSON reader permits.
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def load_stopped_supervisor(w, path):
    # Popen uses negative return codes for signals. These are process results,
    # not unsigned native journal identities; never relax w.load_json for them.
    def reject_constant(_):
        raise RuntimeError("Nonfinite supervisor JSON")
    result = json.loads(w.regular_bytes(path, 65536), object_pairs_hook=w.unique_object,
                        parse_constant=reject_constant)
    fields = {"schema", "run", "stage", "root", "profile", "processes", "logical_targets",
              "storage_processes", "independent_storage_failure_domains", "performance_validated", "failure"}
    require(type(result) is dict and set(result) in (fields, fields | {"storage_process_failure_domains"}),
            "Unexpected supervisor record fields")
    if "storage_process_failure_domains" in result:
        require(type(result["storage_process_failure_domains"]) is int
                and result["storage_process_failure_domains"] == 1,
                "Single-Storage acceptance requires one process failure domain")
    for key, expected in (("schema", 1), ("logical_targets", 12), ("storage_processes", 1),
                          ("independent_storage_failure_domains", 1)):
        require(type(result[key]) is int and result[key] == expected, "Invalid supervisor count/version")
    require(result["stage"] == "stopped" and result["failure"] is None
            and result["performance_validated"] is False, "Supervisor did not confirm a clean owned stop")
    require(result["profile"] == "native-gc-local-1-storage-12-targets"
            and type(result["root"]) is str and result["root"].startswith("/")
            and type(result["run"]) is str
            and re.fullmatch(r"run-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z", result["run"]), "Wrong supervisor identity")
    processes = result["processes"]
    require(type(processes) is list and len(processes) == 4, "Expected four owned process results")
    names, pids = set(), set()
    for process in processes:
        require(type(process) is dict and set(process) == {"name", "pid", "exit_code"}, "Invalid process record")
        require(type(process["name"]) is str and process["name"] in {"fdb", "mgmtd", "storage", "meta"}
                and process["name"] not in names, "Duplicate/unknown owned service")
        require(type(process["pid"]) is int and 0 < process["pid"] <= 2**31 - 1
                and process["pid"] not in pids, "Invalid/repeated owned PID")
        require(type(process["exit_code"]) is int and process["exit_code"] in (0, -15),
                "Owned stop result must be success or SIGTERM; unknown/crash is not accepted")
        names.add(process["name"]); pids.add(process["pid"])
    return result


def check_restart_failure(w, root, folder, report, manifest):
    # A narrow continuation for the recorded parser failure only. It does not
    # infer a safe retry from arbitrary errors or from a child having exited.
    report = w.canonical(report)
    require(report.parent == folder and re.fullmatch(r"after-restart-[0-9a-f]{32}", report.name),
            "Failure report is not an original after-restart attempt of this case")
    w.private_directory(report)
    result = w.load_json(report / "result.json")
    require(result.get("state") == "not_confirmed" and result.get("error") == "Journal integer outside exact v1 range"
            and result.get("checks") == [] and type(result.get("interruption_requests")) is int
            and result["interruption_requests"] == 0
            and result.get("all_started_cli_processes_exited") is True, "Not the isolated supervisor parser failure")
    commands = result.get("commands")
    require(type(commands) is list and len(commands) == 12, "Failure must precede all retirement/GC queries and new reads")
    targets = set()
    for index, command in enumerate(commands):
        argv = command.get("argv")
        require(type(command.get("index")) is int and command["index"] == index and command.get("process_started") is True
                and command.get("process_exited") is True and type(command.get("returncode")) is int
                and command["returncode"] == 0 and type(argv) is list and len(argv) == 5
                and argv[:4] == [str(root / "bin/admin_cli"), "--cfg", str(root / "config/admin_cli.toml"), "--"],
                "Unexpected prior process or unfinished command")
        tokens = shlex.split(argv[4])
        require(tokens and tokens[0] == "discover-ec-gc-target" and len(tokens) == 15,
                "Prior command was not one GC discovery")
        options = dict(zip(tokens[1::2], tokens[2::2]))
        require(len(options) == 7 and set(options) == {"--node-id", "--chain-id", "--target-id", "--authority",
                "--gc-key-id", "--gc-key-file", "--output"}, "Unexpected prior discovery arguments")
        target = options["--target-id"]
        endpoint = next((e for e in manifest["endpoints"] if str(e["target"]) == target), None)
        require(endpoint is not None and target not in targets and options["--node-id"] == str(endpoint["node"])
                and options["--chain-id"] == str(endpoint["chain"])
                and options["--authority"] == manifest["gc"]["authority"]
                and options["--gc-key-id"] == manifest["gc"]["key_id"]
                and options["--gc-key-file"] == str(root / "secrets/gc.key")
                and options["--output"] == str(report / ("gc-instance-" + target + ".json")),
                "Prior discovery belongs to another instance or output")
        targets.add(target)
    return {"failed_report": str(report), "failed_report_sha256": hash_file(w, report / "result.json")}


def status(root):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(root / "state/control.sock"))
        client.sendall(b"status\n")
        data = bytearray()
        while part := client.recv(4096):
            data.extend(part)
            require(len(data) <= 65536, "Oversized supervisor response")
    result = json.loads(data)
    require(result.get("stage") == "ready" and result.get("failure") is None, "Supervisor is not ready")
    require(result.get("root") == str(root) and result.get("profile") == "native-gc-local-1-storage-12-targets",
            "This driver requires the explicit fresh GC profile")
    processes = result.get("processes", [])
    require(len(processes) == 4 and {p["name"] for p in processes} == {"fdb", "mgmtd", "storage", "meta"}
            and all(p.get("exit_code") is None for p in processes), "Expected four live owned services")
    return result


def binary_lock(w, root):
    names = ("bin/admin_cli", "bin/ec_stripe_cli", "bin/storage_main", "bin/meta_main", "bin/mgmtd_main", "bin/fdbserver",
             "scripts/experiment-runner.py", "scripts/native-v2.py", "scripts/native_v2_config.py", "scripts/generate.py",
             "scripts/run-cluster.py", "scripts/gc-acceptance.py")
    return {name: hash_file(w, root / name) for name in names}


def allocation(w, path, run, info):
    result = w.load_json(path)
    record, observed = w.published(run, info, allow_released=True)
    require(type(result.get("schema")) is int and result["schema"] == 1 and result.get("query_rpc") == 33,
            "Unsupported public allocation export")
    require(result.get("mutation_state") == "Published" and result.get("metadata_observation_only") is True
            and result.get("gc_authorized") is False, "Export is not the required metadata observation")
    inode, incarnation = w.object_identity(observed)
    require(decimal(result["object"]["inode_decimal"], True) == str(inode)
            and uid(result["object"]["incarnation"]) == incarnation, "Export changed object")
    require(decimal(result["revision_decimal"], True) == str(observed["revision"])
            and decimal(result["logical_bytes_decimal"], True) == str(info[1])
            and result.get("shard_bytes") == info[2] and result.get("content_sha256") == info[3], "Export changed content")
    require(result.get("cluster") == record["cluster"] and uid(result["client_namespace"]) == uid(record["clientNamespace"])
            and uid(result["operation"]) == uid(record["operation"])
            and uid(result["request_id"]) == uid(record["getRequest"])
            and result.get("owner_uid") == observed["ownerUid"], "Export changed original owner or operation")
    items = result["allocations"]
    require(isinstance(items, list) and len(items) == 12, "Expected twelve complete allocation bindings")
    for index, item in enumerate(items):
        identity = item["identity"]
        require(type(identity.get("shard")) is int and identity["shard"] == index
                and uid(identity["object"]) == incarnation
                and decimal(identity["stripe_decimal"]) == decimal(result["stripe_decimal"]), "Wrong fragment identity")
        decimal(identity["generation_decimal"], True)
        uid(identity["allocation"])
        uid(item["engine_uuid"])
        uid(item["target_incarnation"])
        decimal(item["placement"]["target_decimal"], True)
    require(len({uid(x["identity"]["allocation"]) for x in items}) == 12, "Repeated allocation")
    return result


def allocation_instances(exported, inventory):
    for item in exported["allocations"]:
        placement = item["placement"]
        matched = [endpoint for endpoint in inventory if endpoint["node"] == placement["node"]
                   and endpoint["chain"] == placement["chain"] and str(endpoint["target"]) == placement["target_decimal"]]
        require(len(matched) == 1 and uid(matched[0]["engine_uuid"]) == uid(item["engine_uuid"])
                and uid(matched[0]["target_incarnation"]) == uid(item["target_incarnation"]),
                "Public allocation does not bind the actual discovered instance")


def same_publication(old, new):
    require(old["object"] == new["object"] and old["stripe_decimal"] == new["stripe_decimal"]
            and int(new["revision_decimal"]) > int(old["revision_decimal"]), "Replacement did not advance same object")
    require(old["allocations"][0]["identity"]["allocation"] != new["allocations"][0]["identity"]["allocation"],
            "Shard zero was not replaced")
    require(old["allocations"][1:] == new["allocations"][1:], "A single-shard repair changed retained bindings")


def bind_lines(w, path, expected, code):
    raw = w.regular_bytes(path, 65536)
    lines = [json.loads(x, object_pairs_hook=w.unique_object) for x in raw.decode().splitlines()]
    require(len(lines) == 2 and lines[0].get("phase") == "prepared" and lines[1].get("phase") == "result",
            "Prepared-only or malformed administration archive is inconclusive")
    for row in lines:
        require(type(row.get("schema")) is int and row["schema"] == 1, "Unknown administration archive schema")
        for key, value in expected.items():
            actual = row.get(key)
            if key in {"request_id", "claim_id", "allocation", "object_incarnation", "client_namespace"}:
                actual, value = uid(actual), uid(value)
            require(type(actual) is type(value) and actual == value, f"Administration tuple changed: {key}")
    final = lines[1]
    require(type(final.get("status_code")) is int and final["status_code"] == code, "Unexpected service status; stop")
    require(final.get("outcome") == ("confirmed" if code == 0 else "not_confirmed"), "Unknown result is not acceptance")
    if code == 0 and "claim_id" in expected:
        decimal(final["terminal_revision_decimal"], True)
        for key in ("claim_sha256", "ledger_sha256"):
            require(isinstance(final.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", final[key])
                    and int(final[key], 16) != 0, "Missing terminal GC evidence")
    if code == 0 and "revision_decimal" in expected:
        require(final.get("references_released") is True, "Retirement did not release references")
        decimal(final["generation_decimal"], True)
    return final


def execute(args):
    require(sys.platform == "linux", "Execution requires Linux/Python 3.11; this is not a Windows service launcher")
    os.umask(0o077)
    root = Path(args.root).absolute()
    require(root == root.resolve(), "Root must be canonical")
    sys.path.insert(0, str(root / "scripts"))
    w = module(root / "scripts/experiment-runner.py", "ec_acceptance_runner")
    cfg = module(root / "scripts/native_v2_config.py", "ec_acceptance_config")
    launcher = module(root / "scripts/run-cluster.py", "ec_acceptance_launcher")
    w.private_directory(root)
    manifest = w.load_json(root / "cluster.json")
    require(manifest.get("root") == str(root) and cfg.gc_settings(manifest), "Not an explicit GC bundle")
    admin_cfg = root / "config/admin_cli.toml"
    admin = tomllib.loads(w.regular_bytes(admin_cfg, 1024 * 1024).decode())
    require(uid(admin["client_uuid"]) == uid(manifest["gc"]["client_namespace"])
            and type(admin["user_info"]["uid"]) is int and admin["user_info"]["uid"] == 0, "Wrong actual admin namespace")
    require(w.LABEL.fullmatch(args.label), "Invalid case label")
    if getattr(args, "complete_failed_restart", None) or getattr(args, "completion_attempt", None):
        require(args.command == "after-restart", "Continuation is restricted to after-restart verification")
    parent = w.private_directory(root / "client/gc-acceptance", create=True)
    folder = parent / args.label
    live = status(root)
    if args.command == "prepare-case":
        require(not folder.exists(), "Case already exists; never regenerate identities")
        w.private_directory(folder, create=True)
        w.generate_inputs(root)
        case = {"schema": 1, "root": str(root), "cluster": manifest["cluster_id"], "label": args.label,
                "initial_supervisor_run": live["run"], "administrator_namespace": uid(admin["client_uuid"]),
                "cluster_manifest_sha256": hash_file(w, root / "cluster.json"),
                "retire_request": str(uuid.uuid4()), "gc_claim": str(uuid.uuid4()), "gc_request": str(uuid.uuid4()),
                "shared_claim": str(uuid.uuid4()), "shared_request": str(uuid.uuid4()), "binary_lock": binary_lock(w, root),
                "sample": "multi", "physical_fault_injected": False, "performance_validated": False}
        save(w, folder / "case.json", case)
        print(folder / "case.json")
        return
    w.private_directory(folder)
    case = w.load_json(folder / "case.json")
    require(case["root"] == str(root) and case["cluster"] == manifest["cluster_id"]
            and case["administrator_namespace"] == uid(admin["client_uuid"]), "Case belongs to another root/owner")
    require(case["cluster_manifest_sha256"] == hash_file(w, root / "cluster.json"), "Prepared cluster manifest changed")
    require(case["binary_lock"] == binary_lock(w, root), "Binaries or reused driver dependencies changed")
    continuation = getattr(args, "complete_failed_restart", None)
    attempt = getattr(args, "completion_attempt", None)
    require(bool(continuation) == bool(attempt), "Continuation needs both original failure report and new attempt label")
    marker = folder / (args.command + ".started.json")
    continuation_evidence = None
    if continuation:
        require(args.command == "after-restart" and w.LABEL.fullmatch(attempt), "Only explicit restart verification can continue")
        started = w.load_json(marker)
        require(started.get("case_sha256") == hash_file(w, folder / "case.json")
                and started.get("supervisor_run") == live["run"], "Continuation must use the original resumed service run")
        require(not (folder / "after-restart-complete.json").exists(), "Restart was already completed")
        continuation_evidence = check_restart_failure(w, root, folder, Path(continuation), manifest)
        report = folder / ("after-restart-completion-" + attempt)
        require(not report.exists(), "Completion report attempt already exists")
    else:
        report = folder / (args.command + "-" + uuid.uuid4().hex)
    if args.command != "query" and not continuation:
        save(w, marker, {"supervisor_run": live["run"], "case_sha256": hash_file(w, folder / "case.json")})
    runner = w.Runner(root, report=report)
    info = w.sample_info(root, case["sample"])
    write = runner.runs / ("gc-write-" + args.label)
    repair = runner.runs / ("gc-repair-" + args.label)
    pinned = runner.runs / ("gc-held-read-" + args.label)
    old_path, new_path = folder / "old-allocations.json", folder / "new-allocations.json"

    def command(argv, expected_success=True):
        require(not runner.stop_requested, "Stop requested; no new command dispatched")
        index = len(runner.commands)
        entry = {"index": index, "argv": [str(x) for x in argv], "process_started": False, "process_exited": False,
                 "remote_release_proven_by_exit": False, "equivalent_bash": shlex.join([str(x) for x in argv])}
        runner.commands.append(entry)
        runner.event({"event": "command_planned", **entry})
        print(entry["equivalent_bash"], flush=True)
        log_path = runner.report / f"command-{index:03d}.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as log:
            proc = subprocess.Popen(entry["argv"], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    env=runner.env, cwd=root, start_new_session=True)
            runner.child = proc
            try:
                # Event/report I/O can fail after launch (including ENOSPC).
                # Ownership begins at Popen, before any such operation.
                entry.update(process_started=True, pid=proc.pid)
                runner.event({"event": "command_started", **entry})
                while proc.poll() is None:
                    try:
                        proc.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                proc.wait()  # No hard timeout or detached borrowed request.
                runner.child = None
                entry.update(process_exited=True, returncode=proc.returncode)
        runner.event({"event": "command_exited", **entry})
        require(not runner.stop_requested, "Owned command joined; stop requested, preserve journals")
        require((proc.returncode == 0) == expected_success, f"Unexpected CLI exit; inspect {log_path}")

    def admin_command(parts, success=True):
        # admin_cli joins its remaining argv and Dispatcher reparses that text.
        # Use the launcher's checked single-command encoding, including its
        # rejection of semicolons/empty arguments/CRLF/NUL before dispatch.
        command([root / "bin/admin_cli", "--cfg", admin_cfg, "--", launcher.admin_command_line(parts)], success)

    def export(run, target):
        command([root / "bin/ec_stripe_cli", f"--cfg={runner.config}", f"--config.run_dir={run}",
                 f"--config.allocation_output={target}", "export-allocations"])
        return allocation(w, target, run, info)

    def discovery():
        observed = []
        for endpoint in manifest["endpoints"]:
            output = runner.report / f"gc-instance-{endpoint['target']}.json"
            admin_command(["discover-ec-gc-target", "--node-id", endpoint["node"], "--chain-id", endpoint["chain"],
                           "--target-id", endpoint["target"], "--authority", manifest["gc"]["authority"],
                           "--gc-key-id", manifest["gc"]["key_id"], "--gc-key-file", root / "secrets/gc.key", "--output", output])
            observed.append(w.load_json(output))
        pool = json.loads(w.regular_bytes(root / "state/physical-pool.json", 65536))
        inventory = cfg.gc_inventory_from_observations(manifest, pool, observed, int(time.time()))
        require(inventory == json.loads(w.regular_bytes(root / "state/gc-physical-pool.json", 65536)),
                "Real observed GC instance/format differs from initialized inventory")
        return {"inventory": inventory, "boot_nonce": uid(observed[0]["boot_nonce"]), "supervisor_run": live["run"]}

    def retirement(old, tag, query=False, code=0):
        expected = {"action": "query_revision_retirement" if query else "retire_revision",
                    "client_namespace": case["administrator_namespace"], "request_id": case["retire_request"],
                    "inode_decimal": old["object"]["inode_decimal"], "object_incarnation": old["object"]["incarnation"],
                    "stripe_decimal": old["stripe_decimal"], "revision_decimal": old["revision_decimal"]}
        output = runner.report / (tag + ".jsonl")
        parts = ["ec-query-revision-retirement" if query else "ec-retire-revision"]
        for option, key in (("client-namespace", "client_namespace"), ("request-id", "request_id"), ("inode", "inode_decimal"),
                            ("object-incarnation", "object_incarnation"), ("stripe", "stripe_decimal"), ("revision", "revision_decimal")):
            parts += ["--" + option, expected[key]]
        admin_command(parts + ["--output", output], code == 0)
        return bind_lines(w, output, expected, code)

    def gc(old, tag, shard=0, query=False, code=0):
        fragment = old["allocations"][shard]["identity"]
        expected = {"action": "query" if query else "collect", "inode_decimal": old["object"]["inode_decimal"],
                    "object_incarnation": old["object"]["incarnation"], "stripe_decimal": fragment["stripe_decimal"],
                    "generation_decimal": fragment["generation_decimal"], "shard": shard, "allocation": fragment["allocation"],
                    "claim_id": case["shared_claim" if shard else "gc_claim"],
                    "request_id": case["shared_request" if shard else "gc_request"]}
        output = runner.report / (tag + ".jsonl")
        parts = ["ec-gc-query" if query else "ec-gc-collect"]
        for option, key in (("inode", "inode_decimal"), ("object-incarnation", "object_incarnation"), ("stripe", "stripe_decimal"),
                            ("generation", "generation_decimal"), ("shard", "shard"), ("allocation", "allocation"),
                            ("claim-id", "claim_id"), ("request-id", "request_id")):
            parts += ["--" + option, expected[key]]
        admin_command(parts + ["--output", output], code == 0)
        return bind_lines(w, output, expected, code)

    with runner.signal_scope():
        try:
            if continuation_evidence is not None:
                runner.fresh([runner.runs / ("gc-read-after-" + args.label)])
                save(w, runner.report / "continuation.json", {**continuation_evidence,
                     "case_sha256": hash_file(w, folder / "case.json"),
                     "original_started_sha256": hash_file(w, marker),
                     "continuation_driver_sha256": hash_file(w, Path(__file__)),
                     "supervisor_run": live["run"], "repeats_collect_retirement_repair": False})
            discovered = discovery()
            if args.command == "exercise":
                require(live["run"] == case["initial_supervisor_run"], "Exercise must use original ready supervisor")
                runner.fresh([write, repair, pinned])
                runner.invoke(write, "new-write", input_file=info[0], remote_path="/ec-lab/gc-" + args.label, shard_bytes=info[2])
                old = export(write, old_path)
                allocation_instances(old, discovered["inventory"])
                runner.invoke(pinned, "new-read", source_run=write)
                w.verify_read(pinned, info)
                retirement(old, "reject-current-head", code=66)
                gc(old, "reject-referenced-allocation", code=66)
                runner.invoke(repair, "new-repair", source_run=write, strategy="central", replacement_mask=1,
                              source_order="[1,2,3,4,5,6,7,8,9,10]", block_window=2)
                runner.release(repair)
                new = export(repair, new_path)
                same_publication(old, new)
                allocation_instances(new, discovered["inventory"])
                retirement(old, "reject-held-pin", code=66)
                runner.release(pinned)
                retired = retirement(old, "retire")
                repeated = retirement(old, "retire-idempotent")
                require(retired == repeated, "Retirement replay changed terminal result")
                retirement(old, "retire-query", query=True)
                gc(old, "reject-still-shared", shard=1, code=66)
                gc(old, "query-before-gc", query=True, code=66)
                collected = gc(old, "collect")
                queried = gc(old, "query", query=True)
                require({k: v for k, v in collected.items() if k != "action"}
                        == {k: v for k, v in queried.items() if k != "action"}, "GC query changed permanent evidence")
                readback = runner.read_from(repair, runner.runs / ("gc-read-before-" + args.label), info)
                save(w, folder / "exercise-complete.json", {"discovery": discovered, "retirement": retired,
                     "gc": collected, "readback": readback, "report": str(runner.report), "performance_validated": False})
            else:
                old = allocation(w, old_path, write, info)
                allocation_instances(old, discovered["inventory"])
                if args.command == "after-restart":
                    new = allocation(w, new_path, repair, info)
                    same_publication(old, new)
                    allocation_instances(new, discovered["inventory"])
                    prior = w.load_json(folder / "exercise-complete.json")
                    stopped = load_stopped_supervisor(w, root / "state/last-supervisor.json")
                    require(len(stopped.get("processes", [])) == 4
                            and {p["name"] for p in stopped["processes"]} == {"fdb", "mgmtd", "storage", "meta"}
                            and stopped.get("run") == prior["discovery"]["supervisor_run"] and stopped.get("stage") == "stopped"
                            and stopped.get("root") == str(root)
                            and all(p.get("exit_code") is not None for p in stopped.get("processes", [])),
                            "No matching graceful stop observation")
                    require(live["run"] != stopped["run"] and discovered["boot_nonce"] != prior["discovery"]["boot_nonce"]
                            and discovered["inventory"] == prior["discovery"]["inventory"], "Restart identity/boot check failed")
                retired = retirement(old, "retire-query", query=True)
                queried = gc(old, "gc-query", query=True)
                if args.command == "after-restart":
                    require({k: v for k, v in retired.items() if k != "action"}
                            == {k: v for k, v in prior["retirement"].items() if k != "action"}, "Restart changed retirement")
                    require({k: v for k, v in queried.items() if k != "action"}
                            == {k: v for k, v in prior["gc"].items() if k != "action"}, "Restart changed GC terminal evidence")
                    readback = runner.read_from(repair, runner.runs / ("gc-read-after-" + args.label), info)
                    save(w, folder / "after-restart-complete.json", {"discovery": discovered, "readback": readback,
                         "retirement": retired, "gc": queried, "report": str(runner.report), "physical_delete_repeated": False})
            runner.checked.append({"action": args.command, "checks_completed": True,
                                   "gc_query_can_replay_metadata_terminal": True, "performance_validated": False})
            runner.summary("completed")
        except Exception as error:
            runner.summary("not_confirmed", str(error))
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--complete-failed-restart", type=Path)
    parser.add_argument("--completion-attempt")
    parser.add_argument("command", choices=("prepare-case", "exercise", "query", "after-restart"))
    try:
        execute(parser.parse_args())
        return 0
    except Exception as error:
        print(f"Acceptance stopped: {error}. Preserve the case, all run journals and prepared archives.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
