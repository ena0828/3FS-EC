#!/usr/bin/env python3
"""Bounded mode4 CLI functional acceptance against already running real services.

No service lifecycle, fault injection, throughput measurement or GC.
Only valid Planned truncate observations allow bounded SAME-run continuation.
The native journals own all persistent IDs. A failed phase is never resumed here.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import time
import uuid


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def decimal(obj, key):
    value = obj.get(key)
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None,
            f"Missing/noncanonical decimal {key}")
    result = int(value)
    require(result < 2**64, f"Overflowing {key}")
    return result


def eq(obj, key, value):
    require(type(obj.get(key)) is type(value) and obj[key] == value, f"Unexpected {key}: {obj.get(key)!r}")


def identity(obj, keys):
    result = {key: obj.get(key) for key in keys}
    require(all(type(value) is str and value for value in result.values()), "Missing fixed identity field")
    return result


SESSION = ("client_namespace", "session", "operation", "inode_decimal", "incarnation", "birth")
REPAIR = ("cluster", "client_namespace", "inode_decimal", "incarnation", "session", "operation", "child",
          "plan", "source_pin", "captured_root", "captured_sequence_decimal", "captured_epoch_decimal",
          "stripe_decimal", "replacement_mask_decimal", "strategy")


TRUNCATE_KEYS = {"operation", "length_decimal", "observed", "published", "aborted",
                 "all_cleanup_complete", "error_code"}


def truncate_value(value, operation, length, pending=False):
    require(set(value) == TRUNCATE_KEYS, "Unexpected truncate JSON fields")
    eq(value, "observed", True)
    eq(value, "aborted", False)
    eq(value, "error_code", 0)
    require(type(value["published"]) is bool and type(value["all_cleanup_complete"]) is bool,
            "Truncate state flags must be boolean")
    require(decimal(value, "length_decimal") == length, "Truncate length changed")
    require(type(value["operation"]) is str and str(uuid.UUID(value["operation"])) == value["operation"]
            and uuid.UUID(value["operation"]).int != 0, "Invalid truncate operation")
    require(operation is None or value["operation"] == operation, "Original truncate operation changed")
    if pending or not value["published"]:
        eq(value, "published", False)
        eq(value, "all_cleanup_complete", False)
    return value


class Acceptance:
    def __init__(self, w, transport, wrapper, runner, folder, label, phase):
        self.w, self.transport, self.wrapper, self.runner = w, transport, wrapper, runner
        self.folder, self.label, self.phase = folder, label, phase
        self.runs = w.private_directory(folder / "runs", create=True)
        self.inputs = w.private_directory(folder / "inputs", create=True)
        self.outputs = w.private_directory(folder / "outputs", create=True)
        self.locks = {}
        self.records = {}
        self.input_locks = {}
        self.steps = []
        self.read_index = 0
        self.binary = runner.root / "bin/ec_file_cli"
        self.binary_identity = None

    def save(self, name, data):
        path = self.runner.report / name
        self.w.write_exclusive(path, self.w.json_data(data))
        self.transport.sync_parent(path)

    def hash(self, path):
        return self.transport.hash_file(self.w, path)

    def guard(self):
        require(not self.runner.stop_requested, "Stop requested; retain the original phase and journals")
        if self.binary_identity is not None:
            require(self.file_identity(self.binary) == self.binary_identity, "Native binary identity changed")
        for path, expected in {**self.locks, **self.input_locks, **self.records}.items():
            if path == str(self.binary):
                continue  # Full binary SHA at phase boundaries; avoid repeated large executable reads.
            require(self.hash(Path(path)) == expected, f"Immutable input changed: {path}")

    @staticmethod
    def file_identity(path):
        info = path.stat()
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def input(self, name, size):
        data = hashlib.shake_256(("3fs-mode4-cli-functional-v1/" + name).encode("ascii")).digest(size)
        path = self.inputs / (name + ".bin")
        self.w.write_exclusive(path, data)
        self.transport.sync_parent(path)
        self.input_locks[str(path)] = hashlib.sha256(data).hexdigest()
        self.save(name + "-input.json", {"recipe": "SHAKE256(UTF8(3fs-mode4-cli-functional-v1/NAME),bytes)",
                                       "name": name, "bytes": size, "path": str(path),
                                       "sha256": self.input_locks[str(path)], "synthetic": True})
        return path, data

    def parse(self, text):
        result = []
        for line in text.splitlines():
            if line.lstrip().startswith("{"):
                value = json.loads(line, object_pairs_hook=self.w.unique_object,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
                require(type(value) is dict, "Business JSON is not an object")
                self.w.exact_numbers(value)
                result.append(value)
        require(result, "Native command produced no business JSON")
        return result

    def capture_records(self, run):
        found = {}
        for relative in ("record.json", "record.data", "pwrite/record.json"):
            path = run / relative
            if path.exists():
                digest = self.hash(path)
                require(str(path) not in self.records or self.records[str(path)] == digest,
                        f"Fixed journal body changed: {path}")
                self.records[str(path)] = digest
                found[relative] = digest
        return found

    def invoke(self, action, run, *options, truncate_context=None):
        self.guard()
        friendly = ["--root", str(self.runner.root), action, "--run-dir", str(run), *map(str, options)]
        argv = self.wrapper.command(self.wrapper.parser().parse_args(friendly))
        index = len(self.runner.commands)
        item = {"index": index, "action": action, "run": str(run), "file_command_arguments": friendly,
                "argv": argv, "input_sha256": dict(self.input_locks), "checks_complete": False}
        self.steps.append(item)
        try:
            try:
                text = self.transport.command(self.runner, self.w, argv)
            except RuntimeError as error:
                log = self.runner.report / f"command-{index:03d}.log"
                expected = f"Admin command failed; inspect {log}; no automatic retry or restoration"
                if truncate_context is None or action not in ("truncate", "resume-truncate") or str(error) != expected:
                    raise
                require(not self.runner.stop_requested and self.runner.child is None
                        and len(self.runner.commands) == index + 1, "Interrupted or unjoined command is not progress")
                row = self.runner.commands[index]
                require(row.get("process_started") is True and row.get("process_exited") is True
                        and type(row.get("returncode")) is int and row["returncode"] == 1
                        and row.get("argv") == argv and argv[-1] == "mode4-" + action,
                        "Only the actual joined truncate exit 1 can carry Planned progress")
                text = self.w.regular_bytes(log, 2 * 1024**2).decode("utf-8")
                values = self.parse(text)
                require(len(values) == 1, "Pending truncate must emit exactly one JSON object")
                truncate_value(values[0], *truncate_context, pending=True)
                item["accepted_pending"] = True  # Preserve the actual returncode=1 in process evidence.
            values = self.parse(text)
            item["business"] = values
            item["journal_sha256"] = self.capture_records(run)
            require(item["journal_sha256"], "Successful CLI did not retain its immutable record")
            self.guard()
            return values
        except BaseException as error:
            item["failure"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            # command() has already joined its owned process even if logging failed.
            # Preserve nonzero business output as evidence; never convert it to success.
            log = self.runner.report / f"command-{index:03d}.log"
            try:
                if log.exists():
                    item["log_sha256"] = self.hash(log)
                    if "business" not in item:
                        try:
                            item["business"] = self.parse(self.w.regular_bytes(log, 2 * 1024**2).decode("utf-8"))
                        except Exception as parse_error:
                            item["business_parse_error"] = str(parse_error)
                item["journal_sha256"] = self.capture_records(run)
                if "--output" in options:
                    output = Path(options[options.index("--output") + 1])
                    if output.exists():
                        item["output"] = {"path": str(output), "bytes": output.stat().st_size,
                                          "sha256": self.hash(output)}
                item["process"] = self.runner.commands[index] if index < len(self.runner.commands) else None
                self.save(f"step-{index:03d}-observed.json", item)
            except Exception as report_error:
                print(f"Evidence write failed after owned child join: {report_error}", file=sys.stderr)
                # A reporting failure is a phase failure, including after exit zero.
                raise

    def checked(self, **extra):
        item = self.steps[-1]
        item.update(extra, checks_complete=True)
        self.save(f"step-{item['index']:03d}-checked.json", item)

    def one(self, action, run, *options):
        values = self.invoke(action, run, *options)
        require(len(values) == 1, f"Expected exactly one {action} JSON object")
        value = values[0]
        if action.endswith("repair") or action == "close-repair-debt":
            eq(value, "failure", None)
        else:
            eq(value, "error_code", 0)
        return value

    def session(self, name, shard):
        run = self.runs / (name + "-session")
        value = self.one("create", run, "--path", f"/ec-lab/{self.label}-{name}",
                         "--shard-bytes", shard, "--rights", "read-write")
        eq(value, "session_state", 1)
        eq(value, "shard_bytes", shard)
        fixed = identity(value, SESSION)
        self.checked(session_identity=fixed)
        replay = self.one("resume-open", run)
        eq(replay, "session_state", 1)
        require(identity(replay, SESSION) == fixed, "Open replay changed identity")
        self.checked(session_identity=fixed)
        return run, fixed

    def close(self, session, fixed):
        for _ in range(2):  # Second close is explicit SAME-ID terminal replay, never a failure retry.
            value = self.one("close", session)
            eq(value, "session_state", 3)
            require(identity(value, SESSION) == fixed, "Close changed session identity")
            self.checked(session_identity=fixed, closed=True)

    def complete_write(self, value, size):
        for key in ("logical_closed", "logical_complete", "all_cleanup_complete"):
            eq(value, key, True)
        eq(value, "error_code", 0)
        require(decimal(value, "confirmed_prefix_decimal") == size and
                decimal(value, "revalidated_prefix_decimal") == size, "Write prefix not fully revalidated")

    def write(self, name, session, offset, path, data, replay=False):
        run = self.runs / name
        actions = (("pwrite", ("--session", session, "--offset", offset, "--input", path)),)
        if replay:
            actions += (("resume", ()),)
        fixed = None
        for action, options in actions:
            values = self.invoke(action, run, *options)
            require(len(values) == 2, "Pwrite must emit its journal and outcome")
            show, value = values
            eq(show, "error_code", 0)
            eq(value, "observed", True)
            current = identity(show, ("client_namespace", "session", "operation", "offset_decimal", "length_decimal"))
            require(decimal(show, "offset_decimal") == offset and decimal(show, "length_decimal") == len(data),
                    "Write extent differs")
            require(fixed is None or current == fixed, "Pwrite replay changed original operation")
            fixed = current
            self.complete_write(value, len(data))
            self.checked(write_identity=fixed)

    def readback(self, session, expected, name):
        self.read_index += 1
        run = self.runs / f"read-{self.read_index:02d}-{name}"
        output = self.outputs / (run.name + ".bin")
        value = self.one("read", run, "--session", session, "--offset", 0,
                         "--length", len(expected) + 1, "--output", output)
        eq(value, "data_ready", True)
        eq(value, "all_cleanup_complete", False)
        require(decimal(value, "readable_length_decimal") == len(expected), "Read length/EOF differs")
        actual = self.w.regular_bytes(output, len(expected) + 1)
        require(actual == expected, "Readback differs byte-for-byte; retain output and original range")
        fixed_range = identity(value, ("range",))
        self.checked(byte_equal=True, eof_checked=True, output=str(output), bytes=len(actual),
                     output_sha256=hashlib.sha256(actual).hexdigest(),
                     expected_sha256=hashlib.sha256(expected).hexdigest())
        released = self.one("release-read", run)
        eq(released, "all_cleanup_complete", True)
        require(identity(released, ("range",)) == fixed_range, "Release changed range")
        self.checked(remote_range_released=True)

    def truncate(self, name, session, length):
        run = self.runs / name
        operation = None

        def advance(action, *options):
            values = self.invoke(action, run, *options, truncate_context=(operation, length))
            require(len(values) == 1, "Truncate must emit exactly one JSON object")
            value = truncate_value(values[0], operation, length)
            code = self.runner.commands[-1]["returncode"]
            require(type(code) is int and code == (0 if value["published"] else 1),
                    "Truncate exit/state mismatch")
            self.checked(truncate_identity={"operation": value["operation"]},
                         terminal_published=value["published"], accepted_pending=not value["published"],
                         original_exitcode=code)
            return value

        value = advance("truncate", "--session", session, "--length", length)
        operation = value["operation"]
        if not value["published"]:
            # Query observes the SAME original journal; exit0 alone is not publication.
            value = self.one("query-truncate", run)
            truncate_value(value, operation, length)
            self.checked(same_identity_query=True, truncate_identity={"operation": operation},
                         terminal_published=value["published"])
            # The window bounds starting up to 64 new advances after the query.
            # A started CLI uses its configured deadline and always joins naturally;
            # this is not a 60s wall-clock bound on command/cleanup completion.
            until = time.monotonic() + 60
            for _ in range(64):
                if value["published"]:
                    break
                require(time.monotonic() < until, "Truncate start window exhausted; retain original run")
                value = advance("resume-truncate")
                if not value["published"]:
                    time.sleep(min(0.1, max(0, until - time.monotonic())))
            require(value["published"], "Truncate remains Planned after 64 continuations; retain original run")

        # Terminal replay and remote debt cleanup are strict exit0 commands.
        for action in ("resume-truncate", "close-truncate-debt"):
            replay = self.one(action, run)
            truncate_value(replay, operation, length)
            eq(replay, "published", True)
            if action == "close-truncate-debt":
                eq(replay, "all_cleanup_complete", True)
            self.checked(truncate_identity={"operation": operation}, terminal_replay=action == "resume-truncate",
                         remote_debt_released=action == "close-truncate-debt")

    def basic(self):
        shard = 65536
        capacity = 10 * shard
        session, fixed = self.session("basic", shard)
        path, payload = self.input("cross-stripe", 2 * shard + 31)
        offset = capacity - 17
        expected = bytes(offset) + payload
        self.write("hole-write", session, offset, path, payload, replay=True)
        self.readback(session, expected, "hole-cross-stripe")
        # First cut inside the Data tail, then at an exact stripe boundary.
        for name, length in (("tail-cut", capacity + 13), ("boundary-cut", capacity)):
            self.truncate(name, session, length)
            expected = expected[:length]
            self.readback(session, expected, name)
        extended = 2 * capacity + 23
        self.truncate("zero-extend", session, extended)
        expected += bytes(extended - len(expected))
        self.readback(session, expected, "no-old-byte-revival")
        suffix_path, suffix = self.input("append-suffix", 65543)
        append_run = self.runs / "append"
        for action, options in (("append", ("--session", session, "--input", suffix_path)), ("resume-append", ())):
            value = self.one(action, append_run, *options)
            require(decimal(value, "accepted_offset_decimal") == len(expected), "Append did not accept exact old EOF")
            self.complete_write(value, len(suffix))
            self.checked(accepted_offset=len(expected), prefix_bytes=len(suffix))
        expected += suffix
        sync = self.runs / "fsync"
        original = None
        for action, options in (("fsync", ("--session", session)), ("resume-fsync", ())):
            value = self.one(action, sync, *options)
            eq(value, "synced", True)
            eq(value, "durability_contract", 1)
            require(decimal(value, "length_decimal") == len(expected), "Fsync length differs")
            current = identity(value, ("request", "root_sequence_decimal", "length_decimal"))
            require(original is None or current == original, "Historical fsync replay changed barrier")
            original = current
            self.checked(durable_barrier=current)
        self.readback(session, expected, "append-replay-once")
        self.close(session, fixed)

    def repair(self):
        shard = 131072  # Two 64 KiB blocks per shard exercise a nontrivial window.
        path, payload = self.input("repair-shared", 10 * shard + 257)
        for strategy in ("central", "pipeline", "helper"):
            session, session_id = self.session("repair-" + strategy, shard)
            self.write(strategy + "-initial", session, 0, path, payload)
            self.readback(session, payload, strategy + "-initial")
            for count, targets, sources in ((1, "0", tuple(range(1, 11))), (2, "0,1", tuple(range(2, 12)))):
                run = self.runs / f"{strategy}-repair-{count}"
                fixed = None
                actions = (("repair", ("--session", session, "--stripe", 0, "--targets", targets,
                                       "--sources", ",".join(map(str, sources)), "--strategy", strategy, "--window", 2)),
                           ("resume-repair", ()), ("query-repair", ()))
                for action, options in actions:
                    value = self.one(action, run, *options)
                    self.repair_state(value)
                    eq(value, "strategy", strategy)
                    eq(value, "window", 2)
                    eq(value, "source_order", list(sources))
                    require(decimal(value, "stripe_decimal") == 0 and
                            decimal(value, "replacement_mask_decimal") == (1 if count == 1 else 3), "Repair selection differs")
                    current = identity(value, REPAIR)
                    require(fixed is None or current == fixed, "Repair replay changed accepted identity")
                    fixed = current
                    self.checked(repair_identity=fixed, physical_fault_injected=False)
                self.readback(session, payload, f"{strategy}-after-{count}")
                value = self.one("close-repair-debt", run)
                self.repair_state(value)
                require(identity(value, REPAIR) == fixed, "Repair cleanup changed operation")
                eq(value, "source_released", True)
                eq(value, "all_cleanup_complete", True)
                self.checked(repair_identity=fixed, remote_source_released=True)
            self.close(session, session_id)

    @staticmethod
    def repair_state(value):
        eq(value, "schema", 1)
        for key in ("observed", "published", "output_drained", "revalidated"):
            eq(value, key, True)
        eq(value, "state", "Published")
        eq(value, "failure", None)
        for key in ("source_released", "output_closing", "all_cleanup_complete"):
            require(type(value.get(key)) is bool, f"Missing explicit repair {key}")
        require(value["all_cleanup_complete"] == (value["output_drained"] and value["source_released"]),
                "Repair cleanup summary disagrees with its two debts")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--label", required=True, help="new ASCII label; failed labels are never overwritten")
    p.add_argument("phase", choices=("basic", "repair"))
    args = p.parse_args()
    require(sys.platform == "linux", "Actual acceptance requires Linux; no Windows/WSL launch is performed here")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", args.label) is not None, "Invalid label")
    require(args.root.is_absolute(), "Root must be absolute")
    scripts = args.root / "scripts"
    w = module(scripts / "experiment-runner.py", "mode4_acceptance_runner")
    transport = module(scripts / "ack-service-acceptance.py", "mode4_acceptance_commands")
    wrapper = module(scripts / "file-command.py", "mode4_acceptance_file_command")
    root = w.private_directory(args.root)
    manifest = w.load_json(root / "cluster.json")
    require(manifest.get("root") == str(root) and manifest.get("file_api") is True, "Requires an existing file-api root")
    parent = w.private_directory(root / "client/file-cli-acceptance", create=True)
    label = w.private_directory(parent / args.label, create=True)
    folder = label / args.phase
    require(not folder.exists(), "Phase already exists; preserve it and use original native run commands to recover")
    folder.mkdir(mode=0o700)
    runner = w.Runner(root, config=root / "client/file-client.toml", report=folder / "report")
    a = Acceptance(w, transport, wrapper, runner, folder, args.label, args.phase)
    success = False
    failure = None
    try:
        with runner.signal_scope():
            lock_paths = [Path(__file__).resolve(), root / "bin/ec_file_cli", root / "client/file-client.toml",
                          root / "cluster.json", scripts / "experiment-runner.py", scripts / "ack-service-acceptance.py",
                          scripts / "file-command.py"]
            a.locks = {str(path): a.hash(path) for path in lock_paths}
            a.binary_identity = a.file_identity(a.binary)
            a.save("plan.json", {"schema": 1, "root": str(root), "label": args.label, "phase": args.phase,
                                 "source_sha256": a.locks, "run_parent": str(a.runs),
                                 "binary_file_identity": a.binary_identity,
                                 "physical_fault_injected": False, "performance_measurement": False,
                                 "remote_directory_precondition": "/ec-lab owned by configured authenticated user",
                                 "failure_policy": "stop on error; only valid Planned truncate may continue same run",
                                 "truncate_continuation": {"max_resumes": 64, "start_window_seconds": 60,
                                                           "command_deadline": "existing CLI config; natural join",
                                                           "wall_clock_bound_claimed": False}})
            getattr(a, args.phase)()
            a.guard()
            require(a.hash(a.binary) == a.locks[str(a.binary)], "Final binary SHA differs from phase start")
            success = True
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
        print(f"Acceptance stopped: {failure}; original runs: {a.runs}", file=sys.stderr)
    finally:
        require(runner.child is None, "Owned command has not joined; cannot report completion")
        a.save("result.json", {"schema": 1, "phase": args.phase, "success": success, "failure": failure,
                               "commands": runner.commands, "steps": a.steps, "journal_sha256": a.records,
                               "all_owned_children_joined": all(not c.get("process_started") or c.get("process_exited")
                                                                for c in runner.commands),
                               "services_started_or_stopped": False, "physical_fault_injected": False,
                               "concurrent_append_linearizability_tested": False, "performance_validated": False})
    print(str(runner.report / "result.json"))
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"Acceptance could not complete: {error}", file=sys.stderr)
        sys.exit(1)
