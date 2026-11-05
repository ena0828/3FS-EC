#!/usr/bin/env python3
"""Native EC CLI functional experiments; no service startup, deletion or killing.

Linux/Python 3.11 standard library. The imported classes are also exercised by a
Windows fake-CLI test. This wrapper never claims a local process exit is a remote
drain proof. Ctrl-C/SIGTERM requests stop-after-current-command; an isolated child
session is allowed to finish its actual CLI join before the wrapper exits.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import uuid


SAMPLES = {"kv112": (112 * 1024, 11469), "multi": (1024 * 1024, 131072),
           "max16": (10 * 1024 * 1024, 1048576)}
STRATEGIES = ("central", "pipeline", "helper")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MAX_JSON = 65536


class CheckError(RuntimeError):
    pass


class StopRequested(CheckError):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def canonical(path):
    path = Path(path).absolute()
    require(path == path.resolve(), f"Redirected/non-canonical path: {path}")
    return path


def private_directory(path, create=False):
    path = canonical(path)
    if create and not path.exists():
        path.mkdir(mode=0o700)  # Parent must already exist; never creates task root.
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode), f"Not a directory: {path}")
    if os.name == "posix":
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                f"Directory must be current-UID owned and private: {path}")
    return path


def regular_bytes(path, limit):
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit, f"Invalid/big file: {path}")
        data = stream.read(limit + 1)
        require(len(data) == info.st_size, f"File changed while reading: {path}")
        return data


def write_exclusive(path, data):
    path = canonical(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def json_data(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON object key")
        result[key] = value
    return result


def exact_numbers(value, depth=0):
    require(depth <= 32, "Excessive JSON nesting")
    if type(value) is int:
        require(0 <= value <= 2**63 - 1, "Journal integer outside exact v1 range")
    elif isinstance(value, float):
        raise CheckError("Floating point is not valid in journal v1")
    elif isinstance(value, (list, dict)):
        for child in (value.values() if isinstance(value, dict) else value):
            exact_numbers(child, depth + 1)


def load_json(path):
    data = json.loads(regular_bytes(path, MAX_JSON), object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(CheckError("Nonfinite JSON")))
    require(isinstance(data, dict), "Journal JSON must be an object")
    exact_numbers(data)
    return data


def number(data, key, minimum=0, maximum=2**63 - 1):
    value = data.get(key)
    require(type(value) is int and minimum <= value <= maximum, f"Invalid journal integer: {key}")
    return value


def object_identity(observation):
    value = observation.get("object")
    require(isinstance(value, dict) and isinstance(value.get("object"), dict), "Missing persisted object DTO")
    reference = value["object"]
    number(reference, "inode", 1)
    try:
        incarnation = uuid.UUID(reference["incarnation"])
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        raise CheckError("Invalid object incarnation") from error
    require(incarnation.int != 0, "Zero object incarnation")
    return reference["inode"], str(incarnation)


def journal(path, allow_record_only=False):
    path = private_directory(path)
    record = load_json(path / "record.json")
    require(number(record, "version") == 1 and record.get("action") in ("write", "repair", "read"),
            "Unsupported record version/action")
    names = sorted(p.name for p in path.iterdir() if p.name.startswith("state-"))
    require(len(names) <= 100000, "Excessive observation count")
    if not names:
        # The native CLI persists its fixed IDs before token/network/auth
        # initialization. Resume may legitimately precede its first observation.
        require(allow_record_only, "No observation")
        return record, None
    for index, name in enumerate(names):
        require(name == f"state-{index:020d}.json", "Malformed/gapped journal sequence")
    latest = load_json(path / names[-1])
    require(number(latest, "version") == 1 and number(latest, "sequence") == len(names) - 1,
            "Observation version/sequence mismatch")
    return record, latest


def sample_bytes(name):
    size, _ = SAMPLES[name]
    return hashlib.shake_256(("3fs-ec-functional-v1/" + name).encode()).digest(size)


def sample_info(root, name):
    size, shard = SAMPLES[name]
    path = canonical(root / "client/inputs" / f"{name}.bin")
    data = regular_bytes(path, size)
    expected = sample_bytes(name)
    require(data == expected, f"Input differs from fixed synthetic recipe: {name}")
    return path, size, shard, hashlib.sha256(data).hexdigest()


def generate_inputs(root):
    folder = private_directory(root / "client/inputs", create=True)
    report = {"schema": 1, "kind": "synthetic_functional_data_not_production_trace", "samples": {}}
    for name, (size, shard) in SAMPLES.items():
        data = sample_bytes(name)
        path = folder / f"{name}.bin"
        if path.exists():
            require(regular_bytes(path, size) == data, f"Refusing to replace different input: {path}")
        else:
            write_exclusive(path, data)
        report["samples"][name] = {"bytes": size, "shard_bytes": shard, "sha256": hashlib.sha256(data).hexdigest()}
    # Distinct name avoids replacing the manual's older inputs.json schema.
    target = folder / "executor-inputs.json"
    encoded = json_data(report)
    if target.exists():
        require(regular_bytes(target, MAX_JSON) == encoded, "Existing input report differs")
    else:
        write_exclusive(target, encoded)
    return report


def check_content_record(record, latest, info):
    _, size, shard, sha = info
    require(number(record, "inputBytes", 1) == size and number(record, "shardBytes", 1) == shard,
            "Record input/shard length differs from requested sample")
    require(record.get("inputSha256") == sha, "Record SHA differs from fixed input")
    require(number(latest, "logicalBytes", 1) == size and number(latest, "shardBytes", 1) == shard,
            "Observation input/shard length mismatch")
    require(number(latest, "blocksPerShard", 1, 16) == (shard + 65535) // 65536, "Wrong block count")
    require(number(latest, "errorCode", 0, 65535) == 0, "Latest observation retains an error")


def published(path, info, allow_released=False):
    record, latest = journal(path)
    check_content_record(record, latest, info)
    allowed = ("Published", "ReadReleased") if allow_released and record["action"] == "repair" else ("Published",)
    require(record["action"] in ("write", "repair") and latest.get("state") in allowed
            and latest.get("mutationPublished") is True, "No successful Published observation")
    number(latest, "revision", 1)
    object_identity(latest)
    return record, latest


def released(path):
    record, latest = journal(path)
    require(record["action"] in ("read", "repair") and latest.get("state") == "ReadReleased"
            and number(latest, "errorCode", 0, 65535) == 0, "No successful ReadReleased observation")
    expected = number(latest, "expectedEndpoints", 1, 24)
    require(number(latest, "acknowledgedEndpoints", 1, 24) == expected, "Incomplete remote endpoint ACK count")
    require(object_identity(latest) == object_identity(record), "Released observation changed its fixed object")
    return latest


def verify_read(path, info):
    record, latest = journal(path)
    check_content_record(record, latest, info)
    require(record["action"] == "read" and latest.get("state") in ("ReadReadyLocalCleaned", "ReadReleased"),
            "No successful read observation")
    require(number(latest, "revision", 1) == number(record, "expectedRevision", 1), "Read revision changed")
    require(object_identity(latest) == object_identity(record), "Read object changed")
    name = latest.get("readOutput")
    require(isinstance(name, str) and re.fullmatch(r"read-[0-9a-fA-F-]+\.bin", name), "Invalid read output basename")
    input_path, size, _, sha = info
    actual = regular_bytes(Path(path) / name, size)
    require(actual == regular_bytes(input_path, size), "Read bytes differ from original input")
    require(hashlib.sha256(actual).hexdigest() == sha, "Read SHA differs from original input")
    if latest["state"] == "ReadReleased":
        released(path)
    return {"byte_equal": True, "bytes": size, "sha256": sha, "file": name,
            "revision": latest["revision"], "remote_released": latest["state"] == "ReadReleased"}


class Runner:
    def __init__(self, root, cli_prefix=None, config=None, deadline=300, report=None, extra_env=None):
        self.root = private_directory(root)
        private_directory(self.root / "client")
        self.runs = private_directory(self.root / "client/runs", create=True)
        reports = private_directory(self.root / "client/reports", create=True)
        self.report = Path(report) if report else reports / ("execution-" + uuid.uuid4().hex)
        require(not self.report.exists(), "Execution report directory must be new")
        self.report = private_directory(self.report, create=True)
        self.cli = list(cli_prefix or [str(self.root / "bin/ec_stripe_cli")])
        self.config = canonical(config or self.root / "client/stripe-client.toml")
        require(self.config.is_file(), "Missing CLI config; no cluster is initialized by this wrapper")
        require(1 <= deadline <= 3600, "CLI deadline must be1..3600 seconds")
        self.deadline = deadline
        self.env = os.environ.copy()
        self.env.pop("LD_PRELOAD", None)
        self.env["LD_LIBRARY_PATH"] = str(self.root / "lib")
        if extra_env:  # Dependency injection for the isolated fake-CLI tests only.
            self.env.update(extra_env)
        self.stop_requested = False
        self.child = None
        self.commands = []
        self.checked = []
        self.interrupt_count = 0

    def request_stop(self, *_):
        self.stop_requested = True
        self.interrupt_count += 1

    @contextmanager
    def signal_scope(self):
        signals = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGHUP"):
            signals.append(signal.SIGHUP)
        old = {sig: signal.signal(sig, self.request_stop) for sig in signals}
        try:
            yield
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)

    def event(self, value):
        data = json.dumps(value, ensure_ascii=False).encode() + b"\n"
        path = self.report / "events.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "ab") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def invoke(self, run, command, **options):
        if self.stop_requested:
            raise StopRequested("Stopped before starting another CLI command")
        run = canonical(run)
        prior = None
        if run.exists():
            require(command in ("release", "resume"), "New operations require a new run directory")
            _, previous = journal(run, allow_record_only=command == "resume")
            prior = (previous["sequence"] if previous is not None else -1,
                     regular_bytes(run / "record.json", MAX_JSON))
        argv = self.cli + [f"--cfg={self.config}", f"--config.run_dir={run}",
                           "--config.max_application_bytes=67108864", f"--config.deadline_seconds={self.deadline}",
                           f"--config.log=INFO:normal; normal=file:path={self.root}/logs/ec-stripe-cli.log,async=true,sync_level=ERR"]
        argv += [f"--config.{key}={value}" for key, value in options.items()]
        argv.append(command)
        index = len(self.commands)
        entry = {"index": index, "command": command, "run_dir": str(run), "argv": argv,
                 "equivalent_bash": "env -u LD_PRELOAD " + shlex.quote("LD_LIBRARY_PATH=" + self.env["LD_LIBRARY_PATH"])
                                    + " " + shlex.join(argv),
                 "process_started": False, "process_exited": False, "remote_release_proven_by_exit": False}
        self.commands.append(entry)
        self.event({"event": "command_planned", **entry})
        print(entry["equivalent_bash"], flush=True)
        log_path = self.report / f"cli-{index:03d}.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as log:
            kwargs = {"start_new_session": True} if os.name == "posix" else {
                "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=self.root, env=self.env, **kwargs)
            self.child = proc
            warned = False
            try:
                entry.update(process_started=True, pid=proc.pid, isolated_child_session=True)
                self.event({"event": "command_started", **entry})
                while proc.poll() is None:
                    if self.stop_requested and not warned:
                        print("Stop requested: waiting for the owned CLI to exit; no signal/kill or remote release is implied.",
                              file=sys.stderr, flush=True)
                        warned = True
                    try:
                        proc.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                # Keep output handles and the parent alive for all dispatched work.
                # This is deliberately not a hard wall-clock timeout.
                proc.wait()
                self.child = None
                entry.update(process_exited=True, returncode=proc.returncode,
                             interrupted=self.stop_requested)
        self.event({"event": "command_exited", **entry})
        if self.stop_requested:
            raise StopRequested("Owned CLI exited; no further commands were started. Preserve journals and inspect/resume explicitly.")
        require(proc.returncode == 0, f"CLI failed with exit{proc.returncode}; private log retained at {log_path}")
        output = regular_bytes(log_path, 8 * 1024 * 1024)
        require(b"Local manager joined; active_operations=0 reserved_application_bytes=0." in output,
                "CLI exited0 without the expected joined-manager marker")
        _, observed = journal(run)
        if prior is not None:
            require(observed["sequence"] > prior[0], "CLI returned success without a new observation")
            require(regular_bytes(run / "record.json", MAX_JSON) == prior[1], "CLI changed the immutable run record")

    def fresh(self, paths):
        for path in paths:
            require(not canonical(path).exists(), f"Run directory already exists; explicit resume required: {path}")

    def case_paths(self, label, sample, strategy, replacements):
        require(LABEL.fullmatch(label), "Invalid experiment label")
        suffix = "one" if replacements == 1 else "two"
        stem = f"{label}-{sample}-{strategy}-{suffix}"
        return stem, [self.runs / (kind + "-" + stem) for kind in ("write", "repair", "read")]

    def case(self, label, sample, strategy, replacements):
        require(strategy in STRATEGIES and replacements in (1, 2), "Unsupported repair choice")
        info = sample_info(self.root, sample)
        stem, (write, repair, read) = self.case_paths(label, sample, strategy, replacements)
        self.fresh([write, repair, read])
        mask = 1 if replacements == 1 else 3
        order = list(range(1, 11)) if replacements == 1 else list(range(2, 12))
        self.invoke(write, "new-write", input_file=info[0], remote_path="/ec-lab/" + stem, shard_bytes=info[2])
        wr, wo = published(write, info)
        require(wr.get("inputPath") == str(info[0]) and wr.get("remotePath") == "/ec-lab/" + stem,
                "Write journal does not bind requested paths")
        self.invoke(repair, "new-repair", source_run=write, strategy=strategy, replacement_mask=mask,
                    source_order=json.dumps(order, separators=(",", ":")), block_window=2)
        rr, ro = published(repair, info)
        require(rr.get("strategy") == strategy and number(rr, "replacementMask") == mask
                and rr.get("sourceOrder") == order and number(rr, "blockWindow") == 2,
                "Repair journal differs from requested fixed plan")
        require(rr.get("cluster") == wr.get("cluster") and rr.get("clientNamespace") == wr.get("clientNamespace")
                and number(rr, "expectedRevision", 1) == wo["revision"]
                and object_identity(ro) == object_identity(wo), "Repair source/object/revision binding mismatch")
        self.release(repair)
        result = self.read_from(repair, read, info)
        self.checked.append({"case": stem, "strategy": strategy, "replacement_count": replacements,
                             "fault_injected": False, "readback": result, "repair_pin_released": True})

    def read_from(self, source, read, info):
        sr, so = published(source, info, allow_released=True)
        self.fresh([read])
        self.invoke(read, "new-read", source_run=source)
        rr, ro = journal(read)
        require(rr.get("cluster") == sr.get("cluster") and number(rr, "expectedRevision", 1) == so["revision"]
                and object_identity(ro) == object_identity(so), "Read does not bind the requested source")
        result = verify_read(read, info)
        self.release(read)
        result["remote_released"] = True
        return result

    def release(self, run):
        record, state = journal(run)
        require(record["action"] != "write", "Write run has no auxiliary read pin")
        if record["action"] == "repair":
            require(state.get("mutationPublished") is True and state.get("state") in ("Published", "ReadReleased"),
                    "Cannot release the base read pin of a pending repair")
        self.invoke(run, "release")
        released(run)

    def matrix(self, label):
        choices = [(strategy, count) for strategy in STRATEGIES for count in (1, 2)]
        self.fresh([path for strategy, count in choices for path in self.case_paths(label, "multi", strategy, count)[1]])
        for strategy, count in choices:
            self.case(label, "multi", strategy, count)

    def boundaries(self, label):
        choices = [("kv112", "central", 1), ("max16", "helper", 2)]
        self.fresh([p for sample, strategy, count in choices for p in self.case_paths(label, sample, strategy, count)[1]])
        for sample, strategy, count in choices:
            self.case(label, sample, strategy, count)

    def summary(self, state, error=None):
        require(self.child is None, "Cannot report a settled wrapper while child remains owned")
        result = {"schema": 1, "state": state, "error": error, "commands": self.commands,
                  "checks": self.checked, "interruption_requests": self.interrupt_count,
                  "all_started_cli_processes_exited": all(c["process_exited"] for c in self.commands if c["process_started"]),
                  "cluster_stop_or_restart_performed": False, "physical_fault_injected": False,
                  "performance_validated": False,
                  "timing": "Wrapper wall time is not a benchmark. Keep CLI core/data-phase journal metrics separate.",
                  "remote_state": "Only explicitly validated ReadReleased observations support pin release; process exit alone does not."}
        write_exclusive(self.report / "result.json", json_data(result))
        return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True, help="Explicit existing native bundle root; never created automatically")
    p.add_argument("--cli", type=Path)
    p.add_argument("--config", type=Path)
    p.add_argument("--deadline-seconds", type=int, default=300)
    p.add_argument("--report-dir", type=Path)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("inputs")
    for name in ("matrix", "boundaries", "case"):
        q = sub.add_parser(name)
        q.add_argument("--label", required=True)
        if name == "case":
            q.add_argument("--strategy", choices=STRATEGIES, required=True)
            q.add_argument("--replacements", type=int, choices=(1, 2), required=True)
            q.add_argument("--sample", choices=SAMPLES, default="multi")
    q = sub.add_parser("after-restart")
    q.add_argument("--source-run", type=Path, required=True)
    q.add_argument("--read-label", required=True)
    q.add_argument("--sample", choices=SAMPLES, default="multi")
    for name in ("resume", "release", "verify-read"):
        q = sub.add_parser(name)
        q.add_argument("--run-dir", type=Path, required=True)
        if name != "release":
            q.add_argument("--sample", choices=SAMPLES, default="multi")
    return p


def main():
    args = parser().parse_args()
    require(sys.platform == "linux", "Real execution requires Linux; Windows tests use only the explicit fake-CLI harness")
    os.umask(0o077)
    root = private_directory(args.root)
    if args.command == "inputs":
        private_directory(root / "client")
        print(json.dumps(generate_inputs(root), indent=2))
        return 0
    if args.command == "verify-read":
        print(json.dumps(verify_read(args.run_dir, sample_info(root, args.sample)), indent=2))
        return 0
    runner = Runner(root, [str(canonical(args.cli))] if args.cli else None,
                    args.config, args.deadline_seconds, args.report_dir)
    with runner.signal_scope():
        try:
            if args.command == "matrix":
                runner.matrix(args.label)
            elif args.command == "boundaries":
                runner.boundaries(args.label)
            elif args.command == "case":
                runner.case(args.label, args.sample, args.strategy, args.replacements)
            elif args.command == "after-restart":
                require(LABEL.fullmatch(args.read_label), "Invalid read label")
                result = runner.read_from(canonical(args.source_run), runner.runs / ("read-" + args.read_label),
                                          sample_info(root, args.sample))
                runner.checked.append({"new_read_only": True, "restart_not_verified_by_wrapper": True, **result})
            elif args.command == "release":
                runner.release(canonical(args.run_dir))
            elif args.command == "resume":
                info = sample_info(root, args.sample)
                record, prior = journal(args.run_dir, allow_record_only=True)
                require(not (record["action"] == "read" and prior is not None
                             and prior.get("state") == "ReadReleased"),
                        "A released read requires a new run, not resume")
                runner.invoke(args.run_dir, "resume")
                if record["action"] == "read":
                    runner.checked.append(verify_read(args.run_dir, info))
                else:
                    published(args.run_dir, info)
                # Recovery is deliberately one command. Explicit release follows separately.
            if runner.stop_requested:
                raise StopRequested("Stop requested after the owned command completed")
            runner.summary("passed")
            print(f"Checks passed; private report: {runner.report}")
            return 0
        except StopRequested as error:
            runner.summary("interrupted_after_child_exit", str(error))
            print(f"Interrupted; retained report/journals: {runner.report}", file=sys.stderr)
            return 130
        except Exception as error:
            runner.summary("failed", str(error))
            print(f"Failed: {error}. Journals retained; report: {runner.report}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CheckError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(2)
