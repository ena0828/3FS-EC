#!/usr/bin/env python3
"""Pure collector state/CLI-contract tests. No child, socket, FDB or native GC.

The adapter below models permanent replies in memory and writes actual private
archives. It deliberately does not claim that its joins or GC are native proof.
"""
import copy
import importlib.util
import json
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid


spec = importlib.util.spec_from_file_location("tree_gc_runner", Path(__file__).with_name("tree-gc-runner.py"))
gc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gc)


def uid(n):
    return str(uuid.UUID(int=n))


class LostOwner(RuntimeError):
    pass


class MemoryAdapter:
    """Real Collector's adapter contract, with no operating-system process."""
    namespace = uid(10)

    def __init__(self, plan, leaves):
        self.plan = plan
        self.leaves = copy.deepcopy(leaves)
        self.queue = list(leaves)
        self.permanent_nodes, self.retired, self.collected = {}, {}, {}
        self.calls = []
        self.failure = None
        self.lease = True
        self.block_retirement = False
        self.corrupt = None

    def check(self):
        pass

    def lease_reacquired(self):
        return self.lease

    def argv(self, operation, output):
        return ["in-memory-admin-adapter", gc.encoded(operation).decode().strip(), str(output)]

    def response(self, op):
        fixed = op["expected"]
        out = {"schema": 1, **fixed, "phase": "result", "status_code": 0, "outcome": "confirmed"}
        if op["kind"] == "tree":
            node, request = fixed["node"], fixed["request_id"]
            if node == gc.ZERO:
                out.update(next_node=self.queue[0] if self.queue else gc.ZERO, reclaimed=False,
                           retire_candidates=[], gc_candidates=[])
                return out
            if (node, request) in self.permanent_nodes:
                return copy.deepcopy(self.permanent_nodes[node, request])
            if node not in self.queue:
                return {**out, "status_code": 2001, "outcome": "not_confirmed"}
            self.queue.remove(node)
            rows = self.leaves[node]
            out.update(next_node=self.queue[0] if self.queue else gc.ZERO, reclaimed=True,
                       retire_candidates=[row["stripe_decimal"] + ":" + row["revision_decimal"] for row in rows],
                       gc_candidates=[{**item, "revision_decimal": row["revision_decimal"]}
                                      for row in rows for item in row["allocations"]])
            self.permanent_nodes[node, request] = copy.deepcopy(out)
        elif op["kind"] == "retire":
            request = fixed["request_id"]
            if fixed["action"] == "retire_revision" and not self.block_retirement:
                self.retired[request] = op["generation"]
            if request not in self.retired:
                return {**out, "status_code": 2002, "outcome": "not_confirmed"}
            out.update(generation_decimal=self.retired[request], references_released=True)
        else:
            request = fixed["claim_id"]
            if fixed["action"] == "collect":
                self.collected[request] = {"claim_sha256": "1" * 64, "ledger_sha256": "2" * 64,
                                           "terminal_revision_decimal": "7"}
            if request not in self.collected:
                return {**out, "status_code": 2003, "outcome": "not_confirmed"}
            out.update(self.collected[request])
        return out

    def execute(self, argv, attempt):
        op = json.loads(argv[1])
        # This is a behavior assertion at the dispatch boundary, not a mocked
        # equality-only test: crash/recovery exercises these exact durable files.
        assert gc.load(attempt / "intent.json") == {"operation": op, "argv": argv}
        assert gc.load(attempt.parent.parent / "operations" / (op["name"] + ".json")) == op
        assert gc.load(attempt.parent.parent / "plan.json") == self.plan
        self.calls.append(copy.deepcopy(op))
        fail = self.failure if self.failure and self.failure[0] == op["expected"]["action"] else None
        if fail:
            self.failure = None
        if fail and fail[1] == "before":
            raise LostOwner("before simulated dispatch")
        result = self.response(op)
        if fail and fail[1] == "after-rpc":
            raise LostOwner("after durable in-memory RPC, before archive")
        if self.corrupt:
            result = self.corrupt(op, result)
        prepared = {"schema": 1, **op["expected"], "phase": "prepared", "status_code": 0, "outcome": "not_confirmed"}
        (attempt / "archive.jsonl").write_bytes(gc.encoded(prepared) + gc.encoded(result))
        (attempt / "command.log").write_text("private synthetic adapter log\n", encoding="utf-8")
        if fail and fail[1] == "after-archive":
            raise LostOwner("after archive before joined evidence")
        return {"argv": argv, "process_started": True, "process_exited": True,
                "returncode": 0 if result["status_code"] == 0 else 1,
                "log_sha256": gc.file_sha(attempt / "command.log"), "owner_error_type": None}


class TreeCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.root = gc.private(self.base / "lab", create=True)
        self.folder = gc.private(self.base / "collector", create=True)
        ledger = self.base / "settled.json"
        ledger.write_text('{"caller_claim":"settled"}\n', encoding="utf-8")
        self.expected = {"schema": 1, "object": {"inode_decimal": "100", "incarnation": uid(11)},
                         "settled_ledger": {"path": str(ledger), "sha256": gc.file_sha(ledger)},
                         "revisions": [{"stripe_decimal": "0", "revision_decimal": "2", "generation_decimal": "3",
                                        "allocations": [{"stripe_decimal": "0", "generation_decimal": "3", "shard": n,
                                                         "allocation": uid(100 + n)} for n in range(12)]}]}
        self.binding = {"client_namespace": MemoryAdapter.namespace, "cluster": uid(12),
                        "files": {str(ledger): gc.file_sha(ledger)}}
        self.plan = gc.new_plan(self.root, self.expected, self.binding, 8, 200)
        self.node = uid(20)
        self.adapter = MemoryAdapter(self.plan, {self.node: self.expected["revisions"]})
        self.prepare()
        self.no_process = mock.patch("subprocess.Popen", side_effect=AssertionError("Pure tests must not spawn"))
        self.no_process.start()

    def tearDown(self):
        self.no_process.stop()
        self.tmp.cleanup()

    def prepare(self):
        gc.save(self.folder / "plan.json", self.plan)
        for name in ("operations", "attempts", "owners"):
            gc.private(self.folder / name, create=True)

    def run_collector(self):
        return gc.Collector(self.folder, self.plan, self.adapter).run()

    def restart_with(self, revisions, leaves=None, commands=200, nodes=8):
        self.folder = gc.private(self.base / ("collector-" + uuid.uuid4().hex), create=True)
        value = copy.deepcopy(self.expected)
        value["revisions"] = revisions
        self.plan = gc.new_plan(self.root, value, self.binding, nodes, commands)
        self.adapter = MemoryAdapter(self.plan, leaves or {self.node: revisions})
        self.prepare()

    def test_full_order_exact_scope_and_completed_recheck(self):
        result = self.run_collector()
        actions = [x["expected"]["action"] for x in self.adapter.calls]
        self.assertEqual(actions[:3], ["tree_reclaim_inspect", "tree_reclaim", "tree_reclaim_inspect"])
        self.assertEqual(actions[3:5], ["retire_revision", "query_revision_retirement"])
        self.assertEqual(actions[5:], ["collect", "query"] * 12)
        self.assertEqual(result["allocations_confirmed"], 12)
        self.assertEqual(result["completion_scope"], gc.SCOPE)
        self.assertFalse(result["capacity_returned"])
        self.assertFalse(result["namespace_deleted"])
        self.assertFalse(result["unpublished_outputs_covered"])
        self.assertTrue(result["all_started_commands_joined"])
        self.assertEqual(self.run_collector(), result)
        self.assertEqual(len(self.adapter.calls), 29)  # Completed resume only verifies original evidence.

    def test_shared_identity_dedup_preserves_both_revision_retirements(self):
        first = self.expected["revisions"][0]
        second = {**copy.deepcopy(first), "revision_decimal": "3"}
        self.restart_with([first, second], {self.node: [first], uid(21): [second]})
        result = self.run_collector()
        actions = [x["expected"]["action"] for x in self.adapter.calls]
        self.assertEqual(result["revisions_confirmed"], 2)
        self.assertEqual(actions.count("retire_revision"), 2)
        self.assertEqual(actions.count("collect"), 12)
        self.assertLess(max(i for i, x in enumerate(actions) if x == "query_revision_retirement"), actions.index("collect"))

    def test_empty_queue_or_extra_candidate_never_confirms(self):
        self.adapter.queue.clear()
        with self.assertRaisesRegex(gc.CheckError, "does not cover"):
            self.run_collector()
        self.assertFalse((self.folder / "completion.json").exists())
        other = {**copy.deepcopy(self.expected["revisions"][0]), "revision_decimal": "99"}
        self.restart_with(self.expected["revisions"], {self.node: [other]})
        with self.assertRaisesRegex(gc.CheckError, "Unexpected revision"):
            self.run_collector()
        self.assertFalse(any(x["kind"] != "tree" for x in self.adapter.calls))

    def test_strict_input_twelve_shards_and_identity_types(self):
        for mutate in (lambda x: x.update(schema=True), lambda x: x.update(revisions=[]),
                       lambda x: x["revisions"][0]["allocations"].pop(),
                       lambda x: x["revisions"][0]["allocations"][0].update(shard=False),
                       lambda x: x["object"].update(incarnation=gc.ZERO),
                       lambda x: x["revisions"].append(copy.deepcopy(x["revisions"][0]))):
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.expected)
                mutate(value)
                with self.assertRaises(gc.CheckError):
                    gc.expected(value)

    def test_fresh_inspect_after_reference_release_keeps_previous_candidates(self):
        self.adapter.block_retirement = True
        with self.assertRaisesRegex(gc.CheckError, "Actual CLI failed"):
            self.run_collector()
        first_request = next(x["expected"]["request_id"] for x in self.adapter.calls if x["kind"] == "retire")
        node_b = uid(22)
        self.adapter.leaves[node_b] = copy.deepcopy(self.expected["revisions"])
        self.adapter.queue.append(node_b)
        self.adapter.block_retirement = False
        result = self.run_collector()
        self.assertEqual(result["nodes_reclaimed"], 2)
        retire_ids = [x["expected"]["request_id"] for x in self.adapter.calls if x["expected"]["action"] == "retire_revision"]
        self.assertEqual(retire_ids, [first_request, first_request])
        self.assertEqual(sum(x["expected"]["node"] == node_b for x in self.adapter.calls if x["kind"] == "tree"), 1)

    def test_lost_owner_after_node_commit_replays_permanent_candidate_same_id(self):
        self.adapter.failure = ("tree_reclaim", "after-rpc")
        with self.assertRaises(LostOwner):
            self.run_collector()
        original = self.adapter.calls[-1]
        self.assertFalse(self.adapter.queue)
        result = self.run_collector()
        replay = [x for x in self.adapter.calls if x["expected"]["action"] == "tree_reclaim"]
        self.assertEqual(replay, [original, original])
        self.assertFalse(result["all_started_commands_joined"])
        self.assertEqual(result["historical_unjoined_attempts"], 1)
        self.assertFalse((self.folder / "attempts/000001/joined.json").exists())
        self.assertFalse(gc.load(self.folder / "attempts/000001/lease-recovered.json")["historical_join_proven"])

    def test_lost_owner_before_dispatch_queries_then_later_resume_replays(self):
        self.adapter.failure = ("retire_revision", "before")
        with self.assertRaises(LostOwner):
            self.run_collector()
        original = self.adapter.calls[-1]
        count = len(self.adapter.calls)
        with self.assertRaisesRegex(gc.CheckError, "Actual CLI failed"):
            self.run_collector()
        self.assertEqual([x["expected"]["action"] for x in self.adapter.calls[count:]],
                         ["tree_reclaim_inspect", "query_revision_retirement"])
        self.assertFalse(self.adapter.retired)
        result = self.run_collector()
        self.assertEqual([x for x in self.adapter.calls if x["expected"]["action"] == "retire_revision"], [original, original])
        self.assertEqual(result["allocations_confirmed"], 12)

    def test_lost_owner_after_gc_archive_queries_without_recollect(self):
        self.adapter.failure = ("collect", "after-archive")
        with self.assertRaises(LostOwner):
            self.run_collector()
        original = self.adapter.calls[-1]
        result = self.run_collector()
        same = [x for x in self.adapter.calls if x["expected"].get("claim_id") == original["expected"]["claim_id"]]
        self.assertEqual([x["expected"]["action"] for x in same], ["collect", "query", "query"])
        self.assertEqual(result["historical_unjoined_attempts"], 1)

    def test_unknown_owner_without_lease_cannot_dispatch(self):
        self.adapter.failure = ("tree_reclaim", "before")
        with self.assertRaises(LostOwner):
            self.run_collector()
        self.adapter.lease = False
        before = len(self.adapter.calls)
        with self.assertRaisesRegex(gc.CheckError, "without reacquired"):
            self.run_collector()
        self.assertEqual(len(self.adapter.calls), before)

    def test_cumulative_bounds_stop_without_new_identity_or_completion(self):
        self.restart_with(self.expected["revisions"], commands=5)
        with self.assertRaisesRegex(gc.CheckError, "bound exhausted"):
            self.run_collector()
        before = copy.deepcopy(self.plan)
        with self.assertRaisesRegex(gc.CheckError, "bound exhausted"):
            self.run_collector()
        self.assertEqual(gc.load(self.folder / "plan.json"), before)
        self.assertEqual(len(self.adapter.calls), 5)
        self.assertFalse((self.folder / "completion.json").exists())
        self.restart_with(self.expected["revisions"], {self.node: self.expected["revisions"], uid(23): []}, nodes=1)
        with self.assertRaisesRegex(gc.CheckError, "Node bound"):
            self.run_collector()
        self.assertFalse(any(x["kind"] != "tree" for x in self.adapter.calls))

    def test_missing_or_tampered_archive_and_query_digest_never_pass(self):
        self.adapter.corrupt = lambda op, row: ({**row, "reclaimed": True} if row.get("action") == "tree_reclaim_inspect" else row)
        with self.assertRaisesRegex(gc.CheckError, "flag mismatch"):
            self.run_collector()
        self.restart_with(self.expected["revisions"])
        self.adapter.corrupt = lambda op, row: ({**row, "ledger_sha256": "3" * 64} if row.get("action") == "query" else row)
        with self.assertRaisesRegex(gc.CheckError, "permanent GC evidence changed"):
            self.run_collector()
        self.assertFalse((self.folder / "completion.json").exists())
        self.restart_with(self.expected["revisions"])
        self.run_collector()
        path = self.folder / "attempts/000001/archive.jsonl"
        path.write_text('{"phase":"prepared"}\n', encoding="utf-8")
        with self.assertRaises(gc.CheckError):
            self.run_collector()

    def test_real_argument_builder_uses_fixed_admin_scope_and_no_shell(self):
        adapter = gc.NativeAdapter.__new__(gc.NativeAdapter)
        adapter.root = self.root
        adapter.runner = SimpleNamespace(config=self.root / "config/admin_cli.toml")
        adapter.launcher = SimpleNamespace(admin_command_line=lambda parts: shlex.join(parts))
        collector = gc.Collector(self.folder, self.plan, self.adapter)
        op = collector.tree(0)
        output = self.folder / "archive with spaces.jsonl"
        argv = adapter.argv(op, output)
        self.assertEqual(argv[:4], [str(self.root / "bin/admin_cli"), "--cfg", str(adapter.runner.config), "--"])
        parts = shlex.split(argv[4])
        self.assertEqual(parts[0], "ec-advance-tree-reclaim")
        self.assertEqual(parts[parts.index("--node") + 1], "inspect")
        self.assertEqual(parts[parts.index("--request-id") + 1], op["expected"]["request_id"])
        self.assertEqual(parts[-2:], ["--output", str(output)])

    def test_resume_parser_refuses_expected_or_limit_override(self):
        with mock.patch("sys.stderr"):
            for extra in (["--expected", "x"], ["--max-commands", "100"]):
                with self.assertRaises(SystemExit):
                    gc.parser().parse_args(["resume", "--root", str(self.root), "--run-dir", str(self.folder), *extra])

    def test_history_index_reads_intents_and_logs_once_and_rejects_invalid_tail(self):
        original_load, original_sha = gc.load, gc.file_sha
        intents, logs = {}, {}

        def counted_load(path):
            path = Path(path)
            if path.name == "intent.json":
                intents[path] = intents.get(path, 0) + 1
            return original_load(path)

        def counted_sha(path):
            path = Path(path)
            if path.name == "command.log":
                logs[path] = logs.get(path, 0) + 1
            return original_sha(path)

        with mock.patch.object(gc, "load", side_effect=counted_load):
            result = self.run_collector()
        paths = sorted((self.folder / "attempts").iterdir())
        # New dispatch reads its persisted intent in the adapter assertion and
        # once in Collector's post-join validation, never through prefix scans.
        self.assertEqual(intents, {path / "intent.json": 2 for path in paths})
        intents.clear()
        before = len(self.adapter.calls)
        with mock.patch.object(gc, "load", side_effect=counted_load), \
             mock.patch.object(gc, "file_sha", side_effect=counted_sha):
            collector = gc.Collector(self.folder, self.plan, self.adapter)
            self.assertEqual(collector.run(), result)
            self.assertEqual(collector.run(), result)
        self.assertEqual(len(self.adapter.calls), before)
        self.assertEqual(intents, {path / "intent.json": 1 for path in paths})
        self.assertEqual(logs, {path / "command.log": 1 for path in paths})

        log = paths[-1] / "command.log"
        prior = log.read_bytes()
        log.write_bytes(prior + b"changed")
        with self.assertRaisesRegex(gc.CheckError, "Command log changed"):
            self.run_collector()
        log.write_bytes(prior)
        joined = paths[-1] / "joined.json"
        prior = joined.read_bytes()
        value = gc.load(joined)
        value["process_exited"] = False
        joined.write_bytes(gc.encoded(value))
        with self.assertRaisesRegex(gc.CheckError, "actual joined exit"):
            self.run_collector()
        joined.write_bytes(prior)
        gc.private(self.folder / "attempts" / f"{len(paths):06d}", create=True)
        with self.assertRaises(FileNotFoundError):
            self.run_collector()
        self.assertEqual(len(self.adapter.calls), before)

    def test_unknown_recovery_query_must_join_before_later_same_id_mutation(self):
        self.adapter.failure = ("retire_revision", "before")
        with self.assertRaises(LostOwner):
            self.run_collector()
        original = self.adapter.calls[-1]
        self.adapter.failure = ("query_revision_retirement", "before")
        with self.assertRaises(LostOwner):
            self.run_collector()
        before = len(self.adapter.calls)
        with self.assertRaisesRegex(gc.CheckError, "Actual CLI failed"):
            self.run_collector()
        self.assertEqual([op["expected"]["action"] for op in self.adapter.calls[before:]],
                         ["tree_reclaim_inspect", "query_revision_retirement"])
        self.assertFalse(self.adapter.retired)
        self.assertEqual([op for op in self.adapter.calls if op["expected"]["action"] == "retire_revision"],
                         [original])

        # A joined negative query permits only the next explicit invocation to
        # replay. Losing that new mutation requires another query; an older
        # negative observation cannot authorize bypassing the newer unknown.
        self.adapter.failure = ("retire_revision", "before")
        with self.assertRaises(LostOwner):
            self.run_collector()
        before = len(self.adapter.calls)
        with self.assertRaisesRegex(gc.CheckError, "Actual CLI failed"):
            self.run_collector()
        self.assertEqual([op["expected"]["action"] for op in self.adapter.calls[before:]],
                         ["tree_reclaim_inspect", "query_revision_retirement"])
        self.assertFalse(self.adapter.retired)
        result = self.run_collector()
        mutations = [op for op in self.adapter.calls if op["expected"]["action"] == "retire_revision"]
        self.assertEqual(mutations, [original, original, original])
        self.assertEqual(result["historical_unjoined_attempts"], 3)
        self.assertFalse(result["all_started_commands_joined"])
        self.assertTrue(result["current_owner_commands_joined"])

    def test_completed_resume_rechecks_unknown_inspection_after_last_business_success(self):
        original_save = gc.save

        def lose_completion(path, value):
            if Path(path).name == "completion.json":
                raise LostOwner("before completion publication, after every business command joined")
            return original_save(path, value)

        with mock.patch.object(gc, "save", side_effect=lose_completion), self.assertRaises(LostOwner):
            self.run_collector()
        self.assertFalse((self.folder / "completion.json").exists())
        tail = len(self.adapter.calls)
        self.adapter.failure = ("tree_reclaim_inspect", "before")
        with self.assertRaises(LostOwner):
            self.run_collector()
        unknown = self.folder / "attempts" / f"{tail:06d}"
        self.assertFalse((unknown / "joined.json").exists())
        result = self.run_collector()
        self.assertEqual(result["historical_unjoined_attempts"], 1)
        self.assertFalse(result["all_started_commands_joined"])
        self.assertTrue(result["current_owner_commands_joined"])
        calls = len(self.adapter.calls)
        self.assertEqual(self.run_collector(), result)
        self.assertEqual(len(self.adapter.calls), calls)
        self.assertFalse((unknown / "joined.json").exists())
        self.assertFalse(gc.load(unknown / "lease-recovered.json")["historical_join_proven"])


if __name__ == "__main__":
    unittest.main()
