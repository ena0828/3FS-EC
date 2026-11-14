#!/usr/bin/env python3
"""One gc-14 real process-failure case against a fresh already-running root.

Reuses the file CLI Acceptance and formal owned-command transport. No direct
service signals, cluster startup, automatic business retry or fabricated T2.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import uuid


FILE_DRIVER_SHA = "690503171dcafc1fafb0c21d878e18d920a54cfa36894b8dbbbee72a12ba5a3a"
PROFILE = "native-gc-local-14-storage-14-targets"
BUNDLE_SCRIPTS = {
    "native_managed_domain.py": "5e8a91992d6bf8f2f54f30089d2145a100465885b8d356f70f89d69911527128",
    "experiment-runner.py": "ccace8d2eb1b9af7389ccceeaf89dbd8a9aaa002c5e8b8c5e29ed8d959ffaa98",
    "ack-service-acceptance.py": "9e65e8190b685e8b15ea61a7cc5529de45ab8c764588d24c9637dda097daf64e",
    "file-command.py": "5d9e4efb66aace6d390ee9fc61e18028c735faa24ed1521a1aee363a5a3b80ce",
    "native-v2.py": "5379e32e1ee6dd4917f99d3ed4f0c8dfef42b5748c8cef84e30ea6ef9ff3646b",
    "native_v2_config.py": "3d003da7ecf8a7af2a92cb5f36f5b8f1b112308e38549a6c17ad19d3de21598a",
    "native_fault_control.py": "b409e69d65283f2cf75d0305940b5850968047b3758eec99430a229d7590cf87",
    "run-cluster.py": "baad4f20addd5e4c788b2bcabbe0dfbc266fa44821750e381d659cfc70e8822c",
    "generate.py": "0847c990c675440d0ec0f9059eb7655369013dd6604098f6af47e092e3b13bba",
    "ack-expected-scripts.json": "bd6300367790fff543f4fffdab697c7b6476feca57c28c11b6c151fb4bff4250",
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def control_json(w, text):
    # The native controller prints pretty JSON documents, including signed
    # negative process exit codes. Do not use the unsigned business parser.
    def reject(_):
        raise ValueError("Noninteger/nonfinite control number")
    decoder = json.JSONDecoder(object_pairs_hook=w.unique_object, parse_float=reject, parse_constant=reject)
    values = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        require(type(value) is dict, "Control observation must be an object")
        values.append(value)
        text = text.lstrip()[end:]
    require(values, "No control observation")
    return values


class FaultCase:
    def __init__(self, acceptance, file_driver, strategy, failures):
        self.a, self.f = acceptance, file_driver
        self.strategy, self.failures = strategy, failures
        self.run = None
        self.expected_processes = {}
        self.controls = []
        self.actions = {}

    def control(self, operation, action=None):
        a = self.a
        a.guard()
        argv = [sys.executable, str(a.runner.root / "scripts/native-v2.py"), operation,
                "--root", str(a.runner.root)]
        if action:
            argv += ["--run", action["run"], "--action-id", action["action_id"]]
            if operation != "action-status":
                key = "nodes" if "nodes" in action else "replacements"
                argument = ",".join(map(str, action[key])) if key == "nodes" else ",".join(
                    f"{old}:{new}" for old, new in action[key])
                argv += ["--nodes" if key == "nodes" else "--replace", argument, "--wait-seconds", "600"]
        index = len(a.runner.commands)
        item = {"index": index, "operation": operation, "fixed_action": action, "argv": argv}
        self.controls.append(item)
        try:
            text = a.transport.command(a.runner, a.w, argv)
            item["observations"] = control_json(a.w, text)
            return item["observations"][-1]
        except BaseException as error:
            item["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            # The shared transport has waited for the actual command exit first.
            path = a.runner.report / f"command-{index:03d}.log"
            if path.exists():
                item["log_sha256"] = a.hash(path)
                if "observations" not in item:
                    try:
                        item["observations"] = control_json(a.w, a.w.regular_bytes(path, 2 * 1024**2).decode())
                    except Exception as error:
                        item["parse_error"] = str(error)
            item["process"] = a.runner.commands[index] if index < len(a.runner.commands) else None
            a.save(f"control-{index:03d}.json", item)

    def action(self, name):
        intent = self.actions[name]
        try:
            value = self.control(intent["operation"], intent)
            self.f.eq(value, "schema", 1)
            require(value.get("request") == intent, "Controller returned a different action identity")
            self.f.eq(value, "state", "completed")
            self.f.eq(value, "cleanup_or_T2_claimed", False)
            return value
        except BaseException:
            # Observe at most once, preserving the original failure. Never resend
            # the mutation, regenerate its UUID or automatically restore services.
            if not self.a.runner.stop_requested and self.a.runner.child is None:
                try:
                    self.control("action-status", intent)
                except Exception as error:
                    print(f"Original action remains unconfirmed: {error}", file=sys.stderr)
            raise

    def observe(self, name, new_live=()):
        value = self.control("status")
        for key, expected in (("schema", 1), ("profile", PROFILE), ("root", str(self.a.runner.root)),
                              ("stage", "ready"), ("failure", None)):
            self.f.eq(value, key, expected)
        require(self.run is None or value.get("run") == self.run, "Supervisor run changed")
        rows = value.get("processes")
        require(type(rows) is list, "Missing Popen observations")
        actual = {}
        for row in rows:
            require(type(row) is dict and type(row.get("pid")) is int and row["pid"] > 0 and
                    type(row.get("name")) is str, "Malformed owned process observation")
            key = (row["name"], row["pid"])
            require(key not in actual, "Duplicate process identity")
            code = row.get("exit_code")
            require(code is None or type(code) is int, "Malformed process exit code")
            actual[key] = code
        for service in new_live:
            live = [key for key, code in actual.items() if key[0] == service and code is None]
            require(len(live) == 1 and live[0] not in self.expected_processes, "Missing fresh owned process")
            self.expected_processes[live[0]] = None
        if self.expected_processes:
            require(actual == self.expected_processes, "Owned process set/exit observations differ")
        maintenance = value.get("maintenance", {})
        require(maintenance.get("enabled") is True and maintenance.get("failed") is False and
                maintenance.get("pending") is None and maintenance.get("running") is None,
                "Supervisor has unresolved maintenance")
        self.a.save(name + "-supervisor.json", {"supervisor_uid": os.geteuid(), "observation": value,
                    "ownership_basis": "private same-UID socket and supervisor-held Popen records; no PID-file signalling"})
        return value, actual

    def read_retained(self, session, payload):
        a = self.a
        run, output = a.runs / "degraded-read", a.outputs / "degraded.bin"
        value = a.one("read", run, "--session", session, "--offset", 0,
                      "--length", len(payload) + 1, "--output", output)
        self.f.eq(value, "data_ready", True)
        self.f.eq(value, "all_cleanup_complete", False)
        require(self.f.decimal(value, "readable_length_decimal") == len(payload), "Wrong degraded read EOF")
        actual = a.w.regular_bytes(output, len(payload) + 1)
        require(actual == payload, "Degraded read differs byte-for-byte")
        fixed = self.f.identity(value, ("range",))
        a.checked(byte_equal=True, sha256=hashlib.sha256(actual).hexdigest(), range_identity=fixed,
                  source_cleanup_retained=True, process_fault_observed=True)
        return run, fixed

    def execute(self, initial, pool, placement):
        a = self.a
        live, processes = self.observe("initial")
        require(initial.get("run") == live.get("run"), "Requires the first initialized supervisor, not resumed services")
        self.run = live["run"]
        names = {"fdb", "mgmtd", "meta"} | {f"storage-{node}" for node in range(10001, 10015)}
        require(len(processes) == 17 and {key[0] for key in processes} == names and
                all(code is None for code in processes.values()), "Expected exactly seventeen live original children")
        self.expected_processes = dict(processes)
        old_pids = {key[0]: key[1] for key in processes}
        nodes = list(range(10001, 10001 + self.failures))
        replacements = [[node, 10013 + n] for n, node in enumerate(nodes)]
        for name, operation, fields in (
            ("fault", "fault-storage", {"nodes": nodes}),
            ("placement", "replace-placement", {"replacements": replacements}),
            ("restore", "restart-storage", {"nodes": nodes}),
        ):
            self.actions[name] = {"operation": operation, "run": self.run, "action_id": str(uuid.uuid4()), **fields}
        # Exclusive file, atomic final name, file fsync + directory fsync all
        # precede any action request. Retain the preparation link for diagnosis.
        prepared, accepted = a.folder / "actions-prepared.json", a.folder / "actions.json"
        a.w.write_exclusive(prepared, a.w.json_data(self.actions))
        os.link(prepared, accepted, follow_symlinks=False)
        a.transport.sync_parent(accepted)
        a.locks[str(accepted)] = a.hash(accepted)
        a.locks[str(prepared)] = a.hash(prepared)
        a.save("plan.json", {"schema": 1, "strategy": self.strategy, "failures": self.failures,
                            "supervisor_uid": os.geteuid(), "supervisor_run": self.run,
                            "original_processes": live["processes"], "source_sha256": a.locks,
                            "file_driver_sha256": FILE_DRIVER_SHA, "actions": self.actions,
                            "initial_placement": placement, "physical_inventory": pool,
                            "physical_machine_failure_domains": 1, "performance_validated": False})
        session, session_id = a.session("fault", 65536)
        path, payload = a.input("spare-fault-single-stripe", 262144)
        a.write("initial-write", session, 0, path, payload)
        killed = self.action("fault")
        require(type(killed.get("steps")) is list and len(killed["steps"]) == self.failures, "Wrong fault steps")
        for step, node in zip(killed["steps"], nodes, strict=True):
            name = f"storage-{node}"
            for key, expected in (("name", name), ("pid", old_pids[name]), ("exit_code", -9), ("signal", "SIGKILL")):
                self.f.eq(step, key, expected)
            self.expected_processes[(name, old_pids[name])] = -9
        self.observe("faulted")
        old_range, range_id = self.read_retained(session, payload)
        placed = self.action("placement")
        require(type(placed.get("steps")) is list and len(placed["steps"]) == 2, "Wrong placement observations")
        for key, expected in (("name", "meta"), ("pid", old_pids["meta"]), ("exit_code", 0), ("signal", "SIGTERM")):
            self.f.eq(placed["steps"][0], key, expected)
        selected = list(pool[:12])
        for n in range(self.failures):
            selected[n] = pool[12 + n]
        stored_placement = a.w.load_json(a.runner.root / "state/placement.json")
        require(placed["steps"][1].get("placement") == selected and
                placed["steps"][1].get("old_allocations_changed") is False and
                stored_placement.get("pool") == selected and
                stored_placement.get("action_id") == self.actions["placement"]["action_id"],
                "Replacement does not match the exact twelve expected instances")
        a.locks[str(a.runner.root / "state/placement.json")] = a.hash(a.runner.root / "state/placement.json")
        self.expected_processes[("meta", old_pids["meta"])] = 0
        self.observe("replaced", ("meta",))
        sources = list(range(self.failures, self.failures + 10))
        repair = a.runs / "repair"
        value = a.one("repair", repair, "--session", session, "--stripe", 0,
                      "--targets", ",".join(map(str, range(self.failures))), "--sources", ",".join(map(str, sources)),
                      "--strategy", self.strategy, "--window", 2)
        a.repair_state(value)
        for key, expected in (("strategy", self.strategy), ("window", 2), ("source_order", sources),
                              ("source_released", False), ("all_cleanup_complete", False)):
            self.f.eq(value, key, expected)
        require(self.f.decimal(value, "stripe_decimal") == 0 and
                self.f.decimal(value, "replacement_mask_decimal") == (1 << self.failures) - 1, "Wrong repair selection")
        repair_id = self.f.identity(value, self.f.REPAIR)
        a.checked(repair_identity=repair_id, output_t2_confirmed=True, original_source_debt_retained=True)
        a.readback(session, payload, "repaired-while-original-processes-dead")
        self.observe("published-with-source-debt")
        restored = self.action("restore")
        require(type(restored.get("steps")) is list and len(restored["steps"]) == self.failures, "Wrong restart steps")
        for step, node in zip(restored["steps"], nodes, strict=True):
            self.f.eq(step, "node", node)
            self.f.eq(step, "restarted_same_persistent_instance", True)
            boot = step.get("observed_boot_nonce")
            require(type(boot) is str and str(uuid.UUID(boot)) == boot and uuid.UUID(boot).int, "Invalid boot observation")
        self.observe("restored-original-instances", tuple(f"storage-{node}" for node in nodes))
        released = a.one("release-read", old_range)
        self.f.eq(released, "all_cleanup_complete", True)
        require(self.f.identity(released, ("range",)) == range_id, "Original range identity changed")
        a.checked(original_range_t2_confirmed=True, range_identity=range_id)
        closed = a.one("close-repair-debt", repair)
        a.repair_state(closed)
        require(self.f.identity(closed, self.f.REPAIR) == repair_id, "Original repair identity changed")
        self.f.eq(closed, "source_released", True)
        self.f.eq(closed, "all_cleanup_complete", True)
        a.checked(original_source_t2_confirmed=True, repair_identity=repair_id)
        a.readback(session, payload, "after-original-instance-recovery")
        a.close(session, session_id)
        self.observe("completed")
        a.guard()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--file-driver", type=Path,
                        help="exact file-cli-acceptance.py; defaults to the prepared bundle's scripts directory")
    parser.add_argument("--strategy", choices=("central", "pipeline", "helper"), required=True)
    parser.add_argument("--failures", type=int, choices=(1, 2), required=True)
    args = parser.parse_args()
    require(sys.platform == "linux", "Requires already-running Linux services; this script never launches WSL")
    os.umask(0o077)
    if args.file_driver is None:
        args.file_driver = args.root / "scripts/file-cli-acceptance.py"
    for path in (args.root, args.file_driver):
        require(path.is_absolute() and path == path.resolve(), "Paths must be absolute and nonredirected")
    scripts = args.root / "scripts"
    require(digest(args.file_driver) == FILE_DRIVER_SHA, "File acceptance dependency differs")
    for name, expected in BUNDLE_SCRIPTS.items():
        require(digest(scripts / name) == expected, f"Bundle dependency differs: {name}")
    f = module(args.file_driver, "spare_file_acceptance")
    w = module(scripts / "experiment-runner.py", "spare_owned_runner")
    transport = module(scripts / "ack-service-acceptance.py", "spare_owned_commands")
    wrapper = module(scripts / "file-command.py", "spare_file_command")
    root = w.private_directory(args.root)
    client = w.private_directory(root / "client")
    manifest = w.load_json(root / "cluster.json")
    require(manifest.get("root") == str(root) and manifest.get("profile") == PROFILE and
            manifest.get("file_api") is True, "Requires explicit gc-14 --file-api")
    for path in client.iterdir():
        require(path.name in {"stripe-client.toml", "file-client.toml", "user.token", "runs", "reports", "outputs"},
                "Fresh root only; an existing experiment must retain its original journals")
        if path.is_dir():
            require(path.name in {"runs", "reports", "outputs"} and not any(path.iterdir()), "Prior experiment records exist")
    require(not any(w.private_directory(root / "state/fault-actions").iterdir()), "Existing action history is not a fresh case")
    socket_info = (root / "state/control.sock").lstat()
    require(stat.S_ISSOCK(socket_info.st_mode) and socket_info.st_uid == os.geteuid() and
            not socket_info.st_mode & 0o077, "Expected private same-UID supervisor socket")
    initial = w.load_json(root / "state/initialized.json")
    pool = json.loads(w.regular_bytes(root / "state/physical-pool.json", 65536), object_pairs_hook=w.unique_object)
    placement = w.load_json(root / "state/placement.json")
    require(type(pool) is list and len(pool) == 14 and all(type(row) is dict for row in pool) and
            all(type(row.get("node")) is int for row in pool) and
            [row["node"] for row in pool] == list(range(10001, 10015)),
            "Expected the full original fourteen-instance inventory")
    require(placement.get("schema") == 1 and placement.get("pool") == pool[:12] and
            placement.get("action_id") is None and initial.get("physical_pool") == pool,
            "Placement must still be the initial twelve; no previously reserved repair may be redirected")
    folder = root / "client/spare-fault-acceptance"
    folder.mkdir(mode=0o700)  # Exclusive per-root admission; never resume this driver.
    transport.sync_parent(folder)
    runner = w.Runner(root, config=root / "client/file-client.toml", report=folder / "report")
    a = f.Acceptance(w, transport, wrapper, runner, folder, f"spare-{args.strategy}-{args.failures}", "fault")
    case = FaultCase(a, f, args.strategy, args.failures)
    success, failure = False, None
    try:
        with runner.signal_scope():
            locked = [Path(__file__).resolve(), args.file_driver, a.binary, root / "client/file-client.toml",
                      root / "cluster.json", root / "state/initialized.json", root / "state/physical-pool.json",
                      root / "state/gc-physical-pool.json", *[scripts / name for name in BUNDLE_SCRIPTS]]
            a.locks = {str(path): a.hash(path) for path in locked}
            a.binary_identity = a.file_identity(a.binary)
            case.execute(initial, pool, placement)
            require(a.hash(a.binary) == a.locks[str(a.binary)], "Final native binary SHA changed")
            success = True
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
        print(f"Case stopped: {failure}; retain {folder}; no automatic retry or restoration", file=sys.stderr)
    finally:
        require(runner.child is None, "Owned command has not joined; cannot report completion")
        a.save("result.json", {
            "schema": 1, "state": "completed" if success else "failed_retained", "success": success,
            "failure": failure, "strategy": args.strategy, "failures": args.failures,
            "file_driver_sha256": FILE_DRIVER_SHA, "supervisor_uid": os.geteuid(), "supervisor_run": case.run,
            "actions": case.actions, "controls": case.controls, "steps": a.steps, "commands": runner.commands,
            "journal_sha256": a.records,
            "all_owned_commands_joined": all(not c.get("process_started") or c.get("process_exited") for c in runner.commands),
            "whole_cluster_started_or_stopped": False,
            "fault_control_command_started": any(
                item["operation"] == "fault-storage" and (item.get("process") or {}).get("process_started") is True
                for item in case.controls),
            "confirmed_sigkill_exit_observations": [
                {"name": name, "pid": pid, "exit_code": code}
                for (name, pid), code in case.expected_processes.items() if code == -9],
            "physical_machine_failure_domains": 1, "physical_disk_or_power_failure_tested": False,
            "old_debt_completion_requires_actual_cli_T2": True, "performance_validated": False,
        })
    print(str(runner.report / "result.json"))
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Fault acceptance did not complete: {error}; preserve existing records", file=sys.stderr)
        sys.exit(1)
