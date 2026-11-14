"""Pure orchestration tests with explicit synthetic receipts, no native I/O."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('kv_replay_entry_test', Path(__file__).with_name('kv-replay.py'))
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


class FakeBackend:
    def __init__(self, plan, fail_at=None, corrupt_gc=False):
        self.plan, self.fail_at, self.corrupt_gc, self.calls = plan, fail_at, corrupt_gc, []

    def perform(self, name, spec):
        self.calls.append(name)
        if name == self.fail_at: raise ValueError('synthetic unknown native attempt')
        step = next(s for s in self.plan['steps'] if s['name'] == name)
        gc = None
        if spec['kind'] == 'evict':
            count = int(step['model']['required_confirmed_gc_allocation_bytes_decimal']) // self.plan['shard_bytes']
            gc = {'confirmed_allocation_model_bytes_decimal': '0' if self.corrupt_gc else str(count * self.plan['shard_bytes']),
                  'completion': {'state': 'confirmed', 'completion_scope': 'exact_expected_published_revisions_and_allocations',
                                 'capacity_returned': False, 'namespace_deleted': False, 'unpublished_outputs_covered': False,
                                 'allocations_confirmed': count}}
        return {'schema': 1, 'state': 'confirmed', 'name': name, 'kind': spec['kind'], 'instance': spec['instance'],
                'key_sha256': spec['key_sha256'], 'logical_bytes_decimal': spec['logical_bytes_decimal'],
                'plan_sha256': entry.digest(self.plan), 'spec_sha256': entry.digest(spec),
                'snapshot_exports': [{}] if spec['kind'] in ('put', 'repair') else [], 'gc': gc,
                'historical_unconfirmed_attempts': 1, 'historical_join_proven': False,
                'current_owner_children_joined': True, 'namespace_deleted': False,
                'physical_capacity_returned': False, 'performance_validated': False}


class ReplayEntryTests(unittest.TestCase):
    def fixture(self, temporary):
        root = Path(temporary).resolve(); root.chmod(0o700)
        binding, observations = entry.replay_model.synthetic()
        plan = entry.replay_model.build(binding, observations, trace_id='dff02455-143f-43e3-94c4-ecdc9f5687a8', ttl_ns=5 * 10**9)
        return root, plan

    def run_quietly(self, *args, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()): return entry.execute(*args, **kwargs)

    def test_completion_resume_revalidates_every_action_without_changing_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, plan = self.fixture(temporary)
            first = FakeBackend(plan)
            value = self.run_quietly(plan, run, first)
            before = (run / 'completion.json').read_bytes()
            again = FakeBackend(plan)
            self.assertEqual(self.run_quietly(plan, run, again), value)
            self.assertEqual(first.calls, again.calls)
            self.assertEqual(before, (run / 'completion.json').read_bytes())

    def test_unknown_action_retains_confirmed_prefix_and_never_advances_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, plan = self.fixture(temporary)
            backend = FakeBackend(plan, fail_at=plan['steps'][2]['name'])
            with self.assertRaisesRegex(ValueError, 'unknown'): self.run_quietly(plan, run, backend)
            self.assertEqual(len(list((run / 'confirmed').iterdir())), 2)
            self.assertFalse((run / 'completion.json').exists())
            self.assertEqual(backend.calls[-1], plan['steps'][2]['name'])
            self.run_quietly(plan, run, FakeBackend(plan))
            self.assertTrue((run / 'completion.json').is_file())

    def test_gc_mismatch_does_not_credit_capacity_or_finish(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, plan = self.fixture(temporary)
            evict = next(s for s in plan['steps'] if s['spec']['kind'] == 'evict')
            with self.assertRaisesRegex(ValueError, 'settle'): self.run_quietly(plan, run, FakeBackend(plan, corrupt_gc=True))
            self.assertFalse((run / 'confirmed' / (evict['name'] + '.json')).exists())
            self.assertFalse((run / 'completion.json').exists())

    def test_changed_input_at_end_retains_actions_but_no_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, plan = self.fixture(temporary)
            def invalid(): raise ValueError('source changed')
            with self.assertRaisesRegex(ValueError, 'source changed'):
                self.run_quietly(plan, run, FakeBackend(plan), invalid)
            self.assertEqual(len(list((run / 'confirmed').iterdir())), len(plan['steps']))
            self.assertFalse((run / 'completion.json').exists())

    def test_rejects_receipt_identity_join_capacity_and_boolean_overclaims(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan = self.fixture(temporary)
            step = plan['steps'][0]
            good = FakeBackend(plan).perform(step['name'], step['spec'])
            for key, value in (('schema', True), ('spec_sha256', '0' * 64), ('current_owner_children_joined', False),
                               ('physical_capacity_returned', True), ('historical_join_proven', True), ('gc', {})):
                altered = copy.deepcopy(good); altered[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError): entry.validate_receipt(step, plan, altered)

    def test_changed_receipt_and_unknown_local_marker_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, plan = self.fixture(temporary)
            self.run_quietly(plan, run, FakeBackend(plan))
            marker = run / 'confirmed' / (plan['steps'][0]['name'] + '.json')
            before = entry.read(marker); before['receipt_sha256'] = '0' * 64
            marker.write_bytes(entry.encoded(before))
            with self.assertRaisesRegex(ValueError, 'Immutable'): self.run_quietly(plan, run, FakeBackend(plan))
            extra = run / 'confirmed/unknown.json'; extra.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'Unexpected'): self.run_quietly(plan, run, FakeBackend(plan))

    def test_parser_exposes_independent_strategy_and_same_run_resume(self):
        for strategy in ('central', 'pipeline', 'helper'):
            args = entry.parser().parse_args(['start', '--root', '/lab', '--run-dir', '/run', '--synthetic', '--strategy', strategy])
            self.assertEqual(args.strategy, strategy)
        args = entry.parser().parse_args(['resume', '--run-dir', '/run'])
        self.assertEqual(vars(args), {'command': 'resume', 'run_dir': Path('/run')})


if __name__ == '__main__':
    unittest.main(verbosity=2)
