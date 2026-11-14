#!/usr/bin/env python3
"""Bounded, explicit tree GC of caller-specified published revisions.

This collector does not settle writers/readers, discover unpublished output,
return capacity, or prove namespace deletion. Its Linux adapter uses the existing
experiment Runner/ack command owner and inherits the object flock into admin_cli.
Reacquiring that lease permits same-ID recovery, never a fabricated historical
join or a claim that local process exit proves remote drain.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib
import uuid


MAX_JSON = 2 * 1024 * 1024
MAX_REVISIONS = 256
MAX_NODES = 4096
MAX_COMMANDS = 16384
ZERO = str(uuid.UUID(int=0))
SCOPE = "exact_expected_published_revisions_and_allocations"


class CheckError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise CheckError(message)


def uid(value, zero=False):
    require(type(value) is str, "UUID must be text")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise CheckError("Invalid UUID") from None
    require(zero or parsed.int != 0, "Zero identity is not allowed")
    return str(parsed)


def decimal(value, positive=False):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), "Noncanonical decimal")
    require(int(value) <= 2**64 - 1 and (not positive or int(value) > 0), "Decimal outside uint64")
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "Invalid SHA256")
    return value


def canonical(path):
    path = Path(path).absolute()
    require(path == path.resolve(), "Redirected path")
    return path


def private(path, create=False):
    path = canonical(path)
    if create:
        path.mkdir(mode=0o700)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode), "Expected directory")
    if os.name == "posix":
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "Directory is not private/current-UID")
    return path


def regular(path, limit=MAX_JSON):
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit, "Nonregular/oversized evidence")
        data = stream.read(limit + 1)
        require(len(data) == info.st_size, "Evidence changed while reading")
        return data


def file_sha(path):
    path = canonical(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "Nonregular input")
        h = hashlib.sha256()
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), "Input changed while hashing")
        return h.hexdigest()


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "Duplicate JSON key")
        out[key] = value
    return out


def parse(data):
    def bad(_):
        raise CheckError("Noninteger JSON number")
    return json.loads(data, object_pairs_hook=unique, parse_float=bad, parse_constant=bad)


def load(path):
    return parse(regular(path))


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def sync_dir(path):
    # Windows is only the pure-state test host; execution is explicitly Linux-only.
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def save(path, value):
    path = canonical(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(path.parent)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()), "Unexpected/missing record fields")


def identity(value):
    fields(value, "stripe_decimal generation_decimal shard allocation")
    decimal(value["stripe_decimal"])
    decimal(value["generation_decimal"], True)
    require(type(value["shard"]) is int and 0 <= value["shard"] < 12, "Invalid shard")
    return {**value, "allocation": uid(value["allocation"])}


def key(value):
    return encoded(value).decode().strip()


def expected(value):
    fields(value, "schema object settled_ledger revisions")
    require(type(value["schema"]) is int and value["schema"] == 1, "Unknown expected schema")
    fields(value["object"], "inode_decimal incarnation")
    obj = {"inode_decimal": decimal(value["object"]["inode_decimal"], True),
           "incarnation": uid(value["object"]["incarnation"])}
    fields(value["settled_ledger"], "path sha256")
    ledger = {"path": str(canonical(value["settled_ledger"]["path"])),
              "sha256": digest(value["settled_ledger"]["sha256"])}
    require(type(value["revisions"]) is list and 1 <= len(value["revisions"]) <= MAX_REVISIONS,
            "Expected revisions must be nonempty and bounded")
    revisions, seen = [], set()
    for row in value["revisions"]:
        fields(row, "stripe_decimal revision_decimal generation_decimal allocations")
        stripe, revision = decimal(row["stripe_decimal"]), decimal(row["revision_decimal"], True)
        require((stripe, revision) not in seen, "Repeated expected revision")
        seen.add((stripe, revision))
        generation = decimal(row["generation_decimal"], True)
        require(type(row["allocations"]) is list and len(row["allocations"]) == 12, "Revision needs twelve identities")
        allocations = [identity(x) for x in row["allocations"]]
        require({x["shard"] for x in allocations} == set(range(12)) and
                all(x["stripe_decimal"] == stripe for x in allocations), "Incomplete/wrong revision fragments")
        require(len({x["allocation"] for x in allocations}) == 12, "Repeated allocation in revision")
        revisions.append({"stripe_decimal": stripe, "revision_decimal": revision, "generation_decimal": generation,
                          "allocations": sorted(allocations, key=lambda x: x["shard"])})
    return {"schema": 1, "object": obj, "settled_ledger": ledger,
            "revisions": sorted(revisions, key=lambda x: (int(x["stripe_decimal"]), int(x["revision_decimal"])))}


def allocation_set(expect):
    return {key(item): item for row in expect["revisions"] for item in row["allocations"]}


def new_plan(root, expect, binding, nodes, commands):
    require(type(nodes) is int and 1 <= nodes <= MAX_NODES, "Invalid node bound")
    require(type(commands) is int and 1 <= commands <= MAX_COMMANDS, "Invalid command bound")
    value = expected(expect)
    return {"schema": 1, "collector_id": str(uuid.uuid4()), "root": str(canonical(root)), "expected": value,
            "binding": binding, "limits": {"nodes": nodes, "commands": commands},
            "revision_ids": [str(uuid.uuid4()) for _ in value["revisions"]],
            "allocation_ids": [{"identity": item, "request_id": str(uuid.uuid4()), "claim_id": str(uuid.uuid4())}
                               for _, item in sorted(allocation_set(value).items())]}


def validate_plan(plan):
    fields(plan, "schema collector_id root expected binding limits revision_ids allocation_ids")
    require(type(plan["schema"]) is int and plan["schema"] == 1, "Unknown plan schema")
    uid(plan["collector_id"])
    canonical(plan["root"])
    fields(plan["binding"], "client_namespace cluster files")
    uid(plan["binding"]["client_namespace"])
    require(type(plan["binding"]["files"]) is dict and plan["binding"]["files"], "Missing source binding")
    for path, sha in plan["binding"]["files"].items():
        canonical(path)
        digest(sha)
    require(expected(plan["expected"]) == plan["expected"], "Noncanonical expected plan")
    fields(plan["limits"], "nodes commands")
    for field, maximum in (("nodes", MAX_NODES), ("commands", MAX_COMMANDS)):
        require(type(plan["limits"][field]) is int and 1 <= plan["limits"][field] <= maximum, "Invalid plan bound")
    require(type(plan["revision_ids"]) is list and len(plan["revision_ids"]) == len(plan["expected"]["revisions"]),
            "Missing revision request IDs")
    ids = [uid(x) for x in plan["revision_ids"]]
    actual = []
    require(type(plan["allocation_ids"]) is list, "Missing allocation request IDs")
    for row in plan["allocation_ids"]:
        fields(row, "identity request_id claim_id")
        actual.append(key(identity(row["identity"])))
        ids += [uid(row["request_id"]), uid(row["claim_id"])]
    require(actual == sorted(allocation_set(plan["expected"])) and len(ids) == len(set(ids)), "Plan identities changed")


def archive(path, operation):
    """Same prepared/result contract as gc-acceptance.bind_lines, plus tree shape."""
    raw = regular(path, 256 * 1024)
    lines = [parse(line) for line in raw.decode("utf-8").splitlines()]
    require(len(lines) == 2, "Incomplete administration archive")
    fixed = operation["expected"]
    for index, row in enumerate(lines):
        require(type(row) is dict and type(row.get("schema")) is int and row["schema"] == 1,
                "Unknown administration archive")
        require(row.get("phase") == ("prepared" if index == 0 else "result"), "Wrong archive phase")
        for name, value in fixed.items():
            actual = row.get(name)
            if name in {"client_namespace", "request_id", "claim_id", "allocation", "object_incarnation", "node"}:
                actual = uid(actual, zero=name == "node")
            require(type(actual) is type(value) and actual == value, "Administration identity changed")
        require(type(row.get("status_code")) is int and 0 <= row["status_code"] <= 2**32 - 1, "Invalid status code")
    result = lines[1]
    require(result["status_code"] == 0 and result.get("outcome") == "confirmed", "Administration result unconfirmed")
    if operation["kind"] == "tree":
        require(type(result.get("reclaimed")) is bool and result["reclaimed"] == (fixed["node"] != ZERO),
                "Tree reclaim flag mismatch")
        uid(result.get("next_node"), zero=True)
        revisions, candidates = result.get("retire_candidates"), result.get("gc_candidates")
        require(type(revisions) is list and len(revisions) <= 16 and type(candidates) is list and len(candidates) <= 192,
                "Unbounded tree candidates")
        parsed = set()
        for item in revisions:
            require(type(item) is str and item.count(":") == 1, "Invalid revision candidate")
            a, b = item.split(":")
            pair = (decimal(a), decimal(b, True))
            require(pair not in parsed, "Repeated leaf revision")
            parsed.add(pair)
        groups = {pair: [] for pair in parsed}
        for item in candidates:
            fields(item, "stripe_decimal revision_decimal generation_decimal shard allocation")
            pair = (decimal(item["stripe_decimal"]), decimal(item["revision_decimal"], True))
            require(pair in groups, "Unpaired allocation candidate")
            groups[pair].append(identity({k: v for k, v in item.items() if k != "revision_decimal"}))
        for items in groups.values():
            require(len(items) == 12 and {x["shard"] for x in items} == set(range(12))
                    and len({x["allocation"] for x in items}) == 12, "Incomplete leaf revision identities")
        require(fixed["node"] != ZERO or not revisions and not candidates, "Inspect cannot supply reclaimed candidates")
    elif operation["kind"] == "retire":
        require(result.get("references_released") is True, "Revision references not released")
        require(decimal(result.get("generation_decimal"), True) == operation["generation"], "Retired generation changed")
    else:
        decimal(result.get("terminal_revision_decimal"), True)
        for name in ("claim_sha256", "ledger_sha256"):
            require(int(digest(result.get(name)), 16) != 0, "Missing permanent GC evidence")
    return result


class Collector:
    """Persistent state machine; adapter supplies an already joined actual command."""
    def __init__(self, folder, plan, adapter):
        self.folder, self.plan, self.adapter = private(folder), plan, adapter
        validate_plan(plan)
        self.operations = private(self.folder / "operations")
        self.attempts = private(self.folder / "attempts")
        self.common = {"inode_decimal": plan["expected"]["object"]["inode_decimal"],
                       "object_incarnation": plan["expected"]["object"]["incarnation"]}
        self.checked_joins = {}
        self.recovered = set()
        self._attempt_paths = None
        self._attempts_by_operation = {}

    def operation(self, name, kind, fixed, generation=None):
        path = self.operations / (name + ".json")
        value = {"name": name, "kind": kind, "expected": fixed}
        if generation is not None:
            value["generation"] = generation
        if path.exists():
            require(load(path) == value, "Operation identity changed")
        else:
            save(path, value)  # Every UUID/claim is durable before its first RPC.
        return value

    def tree(self, number, node=ZERO):
        name = ("inspect-" + str(number)) if node == ZERO else ("node-" + node)
        path = self.operations / (name + ".json")
        request = load(path)["expected"]["request_id"] if path.exists() else str(uuid.uuid4())
        return self.operation(name, "tree", {**self.common, "client_namespace": self.adapter.namespace,
                              "request_id": request, "node": node,
                              "action": "tree_reclaim_inspect" if node == ZERO else "tree_reclaim"})

    def attempt_paths(self):
        if self._attempt_paths is not None:
            return self._attempt_paths
        paths = sorted(self.attempts.iterdir())
        require(len(paths) <= self.plan["limits"]["commands"] and
                [p.name for p in paths] == [f"{i:06d}" for i in range(len(paths))], "Invalid attempt ledger")
        for path in paths:
            private(path)
            intent = load(path / "intent.json")
            # Every historical attempt is checked before an operation may return
            # an earlier success. In particular, trailing unknown observations
            # must remain in the completion's historical-unjoined count.
            self.verify_join(path, intent)
            self._attempts_by_operation.setdefault(intent["operation"]["name"], []).append((path, intent))
        self._attempt_paths = paths
        return self._attempt_paths

    def verify_join(self, path, intent):
        if path.name in self.checked_joins:
            return self.checked_joins[path.name]
        require(intent.get("operation") == load(self.operations / (intent["operation"]["name"] + ".json")),
                "Attempt operation differs from durable operation")
        require(intent.get("argv") == self.adapter.argv(intent["operation"], path / "archive.jsonl"),
                "Attempt command differs from fixed operation")
        if not (path / "joined.json").exists():
            require(self.adapter.lease_reacquired(), "Unknown child without reacquired inherited object lease")
            proof = path / "lease-recovered.json"
            value = {"scope": "cooperative_inherited_local_lease_only", "historical_join_proven": False,
                     "intent_sha256": file_sha(path / "intent.json")}
            if proof.exists():
                require(load(proof) == value, "Lease recovery evidence changed")
            else:
                save(proof, value)
            self.recovered.add(path.name)
            self.checked_joins[path.name] = None
            return None
        joined = load(path / "joined.json")
        require(joined.get("argv") == intent["argv"] and joined.get("process_started") is True
                and joined.get("process_exited") is True and type(joined.get("returncode")) is int,
                "Command has no actual joined exit")
        require(file_sha(path / "command.log") == joined.get("log_sha256"), "Command log changed")
        self.checked_joins[path.name] = joined
        return joined

    def perform(self, operation):
        self.adapter.check()
        paths = self.attempt_paths()
        unknown_after = None
        for path, intent in self._attempts_by_operation.get(operation["name"], []):
            require(intent["operation"] == operation, "Indexed operation identity changed")
            joined = self.verify_join(path, intent)
            if joined is None:
                unknown_after = path.name
                continue
            if joined["returncode"] == 0:
                result = archive(path / "archive.jsonl", operation)
                accepted = {"operation_sha256": file_sha(self.operations / (operation["name"] + ".json")),
                            "archive_sha256": file_sha(path / "archive.jsonl"),
                            "joined_sha256": file_sha(path / "joined.json")}
                if (path / "accepted.json").exists():
                    require(load(path / "accepted.json") == accepted, "Accepted evidence changed")
                else:
                    save(path / "accepted.json", accepted)
                return result
        if unknown_after is not None and operation["kind"] in ("retire", "gc") and not operation["name"].startswith("recovery-"):
            # First explicit recovery queries the same permanent identity. If
            # that query failed with a joined nonzero exit, a later explicit
            # resume may replay the original idempotent mutation. No error code
            # is interpreted as evidence that the original mutation did not run.
            recovery_name = "recovery-" + operation["name"]
            query_action = "query_revision_retirement" if operation["kind"] == "retire" else "query"
            query = self.operation(recovery_name, operation["kind"],
                                   {**operation["expected"], "action": query_action}, operation.get("generation"))
            # A successful recovery query is itself the required confirmation.
            latest_query = None
            for path, intent in self._attempts_by_operation.get(recovery_name, []):
                require(intent["operation"] == query, "Indexed query identity changed")
                joined = self.verify_join(path, intent)
                if joined is not None and joined["returncode"] == 0:
                    return self.perform(query)
                if path.name > unknown_after:
                    latest_query = joined
            # An intent alone is not a failed query. The latest query after the
            # latest unknown mutation must have a real joined nonzero exit.
            # Re-querying an unknown attempt may fail this invocation; only a
            # subsequent explicit resume can then replay the original mutation.
            if latest_query is None:
                return self.perform(query)
        require(len(paths) < self.plan["limits"]["commands"], "Command bound exhausted; preserve original plan")
        path = private(self.attempts / f"{len(paths):06d}", create=True)
        argv = self.adapter.argv(operation, path / "archive.jsonl")
        intent = {"operation": operation, "argv": argv}
        save(path / "intent.json", intent)
        # This index is invocation-local, under the original object lease. Disk
        # remains authoritative: every new invocation rebuilds and validates it.
        paths.append(path)
        self._attempts_by_operation.setdefault(operation["name"], []).append((path, intent))
        # Adapter never returns before the existing Owner's wait. If that owner
        # is lost, recovery requires the inherited object lease to be reacquired.
        joined = self.adapter.execute(argv, path)
        save(path / "joined.json", joined)
        require(self.verify_join(path, load(path / "intent.json"))["returncode"] == 0,
                "Actual CLI failed; explicit resume retains the same request")
        require(joined.get("owner_error_type") is None, "Owner reported an error; preserve evidence for explicit resume")
        result = archive(path / "archive.jsonl", operation)
        save(path / "accepted.json", {"operation_sha256": file_sha(self.operations / (operation["name"] + ".json")),
                                      "archive_sha256": file_sha(path / "archive.jsonl"),
                                      "joined_sha256": file_sha(path / "joined.json")})
        return result

    def run(self):
        expected_rows = {(x["stripe_decimal"], x["revision_decimal"]): x for x in self.plan["expected"]["revisions"]}
        observed, nodes = {}, set()

        def consume(result):
            for token in result["retire_candidates"]:
                pair = tuple(token.split(":"))
                require(pair in expected_rows, "Unexpected revision; caller must clarify its ledger")
                items = [identity({k: v for k, v in x.items() if k != "revision_decimal"})
                         for x in result["gc_candidates"] if (x["stripe_decimal"], x["revision_decimal"]) == pair]
                items.sort(key=lambda x: x["shard"])
                require(items == expected_rows[pair]["allocations"], "Unexpected allocation; no implicit GC")
                require(pair not in observed or observed[pair] == items, "Revision candidate changed")
                observed[pair] = items
        # Restore candidates from every durable node operation before looking at
        # today's queue. Successful node receipts survive deletion of the leaf;
        # interrupted nodes must replay their original request, not mint a new ID.
        for path in sorted(self.operations.glob("node-*.json")):
            node = uid(path.stem.removeprefix("node-"))
            require(len(nodes) < self.plan["limits"]["nodes"], "Cumulative node bound exhausted")
            nodes.add(node)
            consume(self.perform(self.tree(0, node)))
        if not (self.folder / "completion.json").exists():
            inspections = [int(p.stem.removeprefix("inspect-")) for p in self.operations.glob("inspect-*.json")]
            number = max(inspections, default=-1) + 1
            while True:
                require(number < self.plan["limits"]["commands"] and
                        len(self.attempt_paths()) < self.plan["limits"]["commands"], "Cumulative command bound exhausted")
                # Inspect is not permanent on the server: never reuse a prior
                # nil/next observation across an explicit recovery invocation.
                current = self.perform(self.tree(number))
                number += 1
                node = uid(current["next_node"], zero=True)
                if node == ZERO:
                    break
                require(len(nodes) < self.plan["limits"]["nodes"] and node not in nodes, "Node bound/repeated queued node")
                nodes.add(node)
                consume(self.perform(self.tree(0, node)))
        require(set(observed) == set(expected_rows), "Empty/incomplete queue does not cover expected revisions")
        for n, row in enumerate(self.plan["expected"]["revisions"]):
            fixed = {**self.common, "client_namespace": self.adapter.namespace,
                     "request_id": self.plan["revision_ids"][n], "stripe_decimal": row["stripe_decimal"],
                     "revision_decimal": row["revision_decimal"]}
            for action in ("retire_revision", "query_revision_retirement"):
                self.perform(self.operation(action + "-" + str(n), "retire", {**fixed, "action": action}, row["generation_decimal"]))
        for n, row in enumerate(self.plan["allocation_ids"]):
            fixed = {**self.common, **row["identity"], "request_id": row["request_id"], "claim_id": row["claim_id"]}
            collected = None
            for action in ("collect", "query"):
                result = self.perform(self.operation(action + "-" + str(n), "gc", {**fixed, "action": action}))
                confirmation = {name: result[name] for name in ("claim_sha256", "ledger_sha256", "terminal_revision_decimal")}
                require(collected is None or confirmation == collected, "Collect/query permanent GC evidence changed")
                collected = confirmation
        result = {"schema": 1, "collector_id": self.plan["collector_id"], "state": "confirmed",
                  "completion_scope": SCOPE, "plan_sha256": file_sha(self.folder / "plan.json"),
                  "revisions_confirmed": len(expected_rows), "allocations_confirmed": len(self.plan["allocation_ids"]),
                  "nodes_reclaimed": len(nodes), "capacity_returned": False,
                  "namespace_deleted": False, "unpublished_outputs_covered": False,
                  "historical_unjoined_attempts": len(self.recovered),
                  "all_started_commands_joined": not self.recovered,
                  "current_owner_commands_joined": True}
        target = self.folder / "completion.json"
        if target.exists():
            require(load(target) == result, "Completion changed")
        else:
            save(target, result)
        return result


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class NativeAdapter:
    def __init__(self, root, report, binding, w, ack, launcher, lease_fd, lease_path):
        self.root, self.binding, self.w, self.ack, self.launcher = root, binding, w, ack, launcher
        self.namespace = binding["client_namespace"]
        self.lease_fd, self.lease_path = lease_fd, lease_path
        self.lease_stat = os.fstat(lease_fd)
        self.binary_stat = (root / "bin/admin_cli").stat()
        self.runner = w.Runner(root, config=root / "config/admin_cli.toml", report=report)
        require(self.runner.transport_role == "control", "Wrong command owner role")

    def check(self):
        require(not self.runner.stop_requested, "Stop requested; preserve collector state")
        require(self.lease_reacquired(), "Object lease identity changed")
        for path, sha in self.binding["files"].items():
            if Path(path) == self.root / "bin/admin_cli":
                info = canonical(path).stat()
                require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
                        (self.binary_stat.st_dev, self.binary_stat.st_ino, self.binary_stat.st_size, self.binary_stat.st_mtime_ns),
                        "Bound executable changed")
                continue
            require(file_sha(path) == sha, "Bound source/config/ledger changed")

    def lease_reacquired(self):
        info, path = os.fstat(self.lease_fd), canonical(self.lease_path).stat()
        return (info.st_dev, info.st_ino) == (path.st_dev, path.st_ino) == (self.lease_stat.st_dev, self.lease_stat.st_ino)

    def argv(self, operation, output):
        fixed = operation["expected"]
        if operation["kind"] == "tree":
            command, options = "ec-advance-tree-reclaim", ("inode_decimal", "object_incarnation", "node", "client_namespace", "request_id")
        elif operation["kind"] == "retire":
            command = "ec-retire-revision" if fixed["action"] == "retire_revision" else "ec-query-revision-retirement"
            options = ("inode_decimal", "object_incarnation", "stripe_decimal", "revision_decimal", "client_namespace", "request_id")
        else:
            command = "ec-gc-collect" if fixed["action"] == "collect" else "ec-gc-query"
            options = ("inode_decimal", "object_incarnation", "stripe_decimal", "generation_decimal", "shard", "allocation", "claim_id", "request_id")
        parts = [command]
        for name in options:
            value = "inspect" if name == "node" and fixed[name] == ZERO else fixed[name]
            parts += ["--" + name.removesuffix("_decimal").replace("_", "-"), str(value)]
        parts += ["--output", str(output)]
        return [str(self.root / "bin/admin_cli"), "--cfg", str(self.runner.config), "--",
                self.launcher.admin_command_line(parts)]

    def execute(self, argv, attempt):
        index = len(self.runner.commands)
        owner_error = None
        try:
            self.ack.command(self.runner, self.w, argv, pass_fds=(self.lease_fd,))
        except BaseException as error:
            # Preserve the actual business exit below, but never swallow an
            # exception unless the retained Owner proves a completed command.
            if self.runner.child is not None or len(self.runner.commands) != index + 1:
                raise
            row = self.runner.commands[index]
            if row.get("process_exited") is not True or type(row.get("returncode")) is not int:
                raise
            owner_error = type(error).__name__
        row = self.runner.commands[index]
        require(row.get("argv") == argv and row.get("process_started") is True
                and row.get("process_exited") is True and type(row.get("returncode")) is int
                and self.runner.child is None, "Owner did not join original CLI")
        raw = regular(self.runner.report / f"command-{index:03d}.log", 2 * 1024 * 1024)
        target = attempt / "command.log"
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        sync_dir(attempt)
        return {"argv": argv, "process_started": True, "process_exited": True,
                "returncode": row["returncode"], "log_sha256": file_sha(target), "owner_error_type": owner_error}


@contextmanager
def object_lock(directory):
    import fcntl
    lock = directory / "lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and not info.st_mode & 0o077, "Invalid object lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def bind_inputs(root, expect, cfg):
    manifest = load(root / "cluster.json")
    require(manifest.get("root") == str(root) and cfg.gc_settings(manifest) and cfg.file_api_enabled(manifest),
            "Collector requires a prepared file/format3 GC root")
    cfg.validate_initialized_profile(manifest, load(root / "state/initialized.json"))
    paths = sorted([*root.glob("config/*.toml"), *root.glob("client/*.toml")])
    configs = {p.name: tomllib.loads(regular(p).decode()) for p in paths}
    require(not cfg.profile_config_problems(manifest, configs), "Prepared configuration differs")
    admin = configs["admin_cli.toml"]
    namespace = uid(admin["client_uuid"])
    require(namespace == uid(manifest["gc"]["client_namespace"]) and type(admin["user_info"]["uid"]) is int
            and admin["user_info"]["uid"] == 0, "Admin scope differs")
    ledger = expect["settled_ledger"]
    require(file_sha(ledger["path"]) == ledger["sha256"], "Caller ledger changed")
    paths += [root / "cluster.json", root / "state/initialized.json", root / "state/gc-physical-pool.json",
              root / "bin/admin_cli", Path(ledger["path"]), canonical(__file__)]
    paths += [root / "scripts" / name for name in ("experiment-runner.py", "ack-service-acceptance.py",
                                                   "run-cluster.py", "native_v2_config.py")]
    return {"client_namespace": namespace, "cluster": manifest["cluster_id"],
            "files": {str(canonical(p)): file_sha(p) for p in paths}}


def execute(args):
    require(sys.platform == "linux" and os.getuid() == os.geteuid() != 0
            and os.getgid() == os.getegid() != 0, "Linux ordinary real/effective UID/GID required")
    os.umask(0o077)
    root = private(args.root)
    folder = canonical(args.run_dir)
    private(folder.parent)
    require(folder != root and root not in folder.parents or root / "client" in folder.parents,
            "Collector evidence must not overwrite lab data/config")
    sys.path.insert(0, str(root / "scripts"))
    w = module(root / "scripts/experiment-runner.py", "tree_gc_experiment")
    ack = module(root / "scripts/ack-service-acceptance.py", "tree_gc_ack")
    launcher = module(root / "scripts/run-cluster.py", "tree_gc_launcher")
    cfg = module(root / "scripts/native_v2_config.py", "tree_gc_config")
    if args.action == "start":
        expect = expected(load(args.expected))
    else:
        private(folder)
        plan = load(folder / "plan.json")
        validate_plan(plan)
        require(plan["root"] == str(root), "Resume root differs")
        expect = plan["expected"]
    binding = bind_inputs(root, expect, cfg)
    object_name = expect["object"]["inode_decimal"] + "-" + expect["object"]["incarnation"]
    registry = root / "state" / ("tree-gc-" + object_name)
    if not registry.exists():
        private(registry, create=True)
        sync_dir(registry.parent)
    private(registry)
    with object_lock(registry) as lease_fd:
        epochs = sorted(p for p in registry.iterdir() if re.fullmatch(r"epoch-[0-9]{6}\.json", p.name))
        require([p.name for p in epochs] == [f"epoch-{n:06d}.json" for n in range(len(epochs))], "Invalid object epoch ledger")
        previous = load(epochs[-1]) if epochs else None
        if args.action == "start":
            if previous is not None:
                end = registry / (epochs[-1].stem + ".complete.json")
                require(end.exists(), "Object has an unfinished collector; resume its original run")
                proof = load(end)
                require(file_sha(Path(previous["run"]) / "plan.json") == previous["plan_sha256"]
                        and file_sha(Path(previous["run"]) / "completion.json") == proof["completion_sha256"],
                        "Previous object completion changed")
            require(not folder.exists(), "Run already exists; explicit resume only")
            private(folder, create=True)
            plan = new_plan(root, expect, binding, args.max_nodes, args.max_commands)
            save(folder / "plan.json", plan)
            for name in ("operations", "attempts", "owners"):
                private(folder / name, create=True)
            sync_dir(folder)
            epoch = registry / f"epoch-{len(epochs):06d}.json"
            save(epoch, {"run": str(folder), "collector_id": plan["collector_id"], "plan_sha256": file_sha(folder / "plan.json")})
        else:
            require(previous is not None and previous["run"] == str(folder)
                    and previous["collector_id"] == plan["collector_id"]
                    and previous["plan_sha256"] == file_sha(folder / "plan.json"), "Resume is not the current object epoch")
            require(plan["binding"] == binding, "Resume source/config/ledger binding differs")
            epoch = epochs[-1]
        report = folder / "owners" / ("invocation-" + uuid.uuid4().hex)
        adapter = NativeAdapter(root, report, binding, w, ack, launcher, lease_fd, registry / "lock")
        with adapter.runner.signal_scope():
            result = Collector(folder, plan, adapter).run()
            adapter.check()
            require(adapter.runner.child is None and not adapter.runner.stop_requested, "Unfinished/interrupted owner")
            require(file_sha(root / "bin/admin_cli") == binding["files"][str(root / "bin/admin_cli")], "Executable changed during collection")
        end = registry / (epoch.stem + ".complete.json")
        proof = {"completion_sha256": file_sha(folder / "completion.json")}
        if end.exists():
            require(load(end) == proof, "Object completion changed")
        else:
            save(end, proof)
        return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    for name in ("start", "resume"):
        child = sub.add_parser(name)
        child.add_argument("--root", type=Path, required=True)
        child.add_argument("--run-dir", type=Path, required=True)
        if name == "start":
            child.add_argument("--expected", type=Path, required=True)
            child.add_argument("--max-nodes", type=int, default=256)
            child.add_argument("--max-commands", type=int, default=8192)
    return p


def main():
    try:
        result = execute(parser().parse_args())
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        # Private archives retain detail. Do not echo runtime messages/configs.
        print(json.dumps({"state": "not_confirmed", "error_type": type(error).__name__,
                          "capacity_returned": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
