import copy
import unittest

import replay_model as model


class ReplayModelTests(unittest.TestCase):
    def plan(self, **kwargs):
        binding, events = model.synthetic()
        options = {'ttl_ns': 5 * 10**9} | kwargs
        return model.build(binding, events, trace_id='dff02455-143f-43e3-94c4-ecdc9f5687a8', **options)

    def test_functional_recipe_hits_ttl_lru_repairs_and_exact_drain(self):
        plan = self.plan()
        self.assertEqual((plan['summary']['model_hits'], plan['summary']['model_misses'], plan['summary']['scheduled_repairs']), (2, 4, 2))
        steps = plan['steps']
        self.assertEqual([s['model']['reason'] for s in steps if s['spec']['kind'] == 'evict'],
                         ['model_capacity', 'inactivity_ttl', 'inactivity_ttl', 'explicit_end_of_selection_drain'])
        self.assertEqual(plan['summary']['final']['allocation_reservation_bytes_decimal'], '0')
        self.assertEqual(sum(int(s['model'].get('required_confirmed_gc_allocation_bytes_decimal', 0)) for s in steps), 6 * 12 * 11469)
        self.assertTrue(all(not value for value in plan['claims'].values()))

    def test_reservation_counts_old_repair_revisions_until_gc(self):
        plan = self.plan(allocation_budget=3 * 12 * 11469)
        self.assertLessEqual(int(plan['summary']['peak_allocation_reservation_bytes_decimal']), 3 * 12 * 11469)
        self.assertEqual(sum(s['spec']['kind'] == 'repair' for s in plan['steps']), 2)
        with self.assertRaisesRegex(ValueError, 'Budget cannot retain'):
            self.plan(allocation_budget=12 * 11469)

    def test_full_history_fits_fixed_tree_and_command_bounds_before_any_native_dispatch(self):
        binding, source = model.synthetic()
        events = []
        for index in range(128):
            event = copy.deepcopy(source[0]); event['sequence_decimal'] = str(index)
            event['clock']['scaled_ns_decimal'] = str(index)
            events.append(event)
        binding.update(selected_observations=127, horizon_ns_decimal='128')
        plan = model.build(binding, events[:127], trace_id='dff02455-143f-43e3-94c4-ecdc9f5687a8',
                           repair_every=1, allocation_budget=1 << 30)
        revisions = 1 + plan['summary']['scheduled_repairs']
        self.assertEqual(revisions, 128)
        nodes = 16 * (revisions + 1)
        normal_commands = 2 * nodes + 26 * revisions + 1
        self.assertEqual(nodes, 2064); self.assertEqual(normal_commands, 7457)
        self.assertEqual(plan['collector_limits'], {'nodes': nodes, 'commands': 16384})
        self.assertGreater(plan['collector_limits']['commands'], 2 * normal_commands)
        binding['selected_observations'] = 128
        with self.assertRaisesRegex(ValueError, 'published revision limit'):
            model.build(binding, events, trace_id=plan['trace_id'], repair_every=1, allocation_budget=1 << 30)

    def test_expiry_is_inclusive_and_never_wraps_large_time(self):
        binding, events = model.synthetic()
        events = events[:1]
        events[0]['clock']['scaled_ns_decimal'] = str(model.kv.MAX_NS - 1)
        binding.update(selected_observations=1, horizon_ns_decimal=str(model.kv.MAX_NS))
        plan = model.build(binding, events, trace_id='dff02455-143f-43e3-94c4-ecdc9f5687a8', ttl_ns=model.kv.MAX_NS)
        self.assertEqual(plan['steps'][-1]['model']['reason'], 'explicit_end_of_selection_drain')

    def test_selection_horizon_expires_after_trailing_empty_requests(self):
        binding, events = model.synthetic()
        events = events[:1]; binding.update(selected_observations=1, horizon_ns_decimal=str(10**10))
        plan = model.build(binding, events, trace_id='dff02455-143f-43e3-94c4-ecdc9f5687a8', ttl_ns=5 * 10**9)
        self.assertEqual(plan['steps'][-1]['model']['reason'], 'inactivity_ttl')

    def test_reject_changed_key_length_order_geometry_and_limits(self):
        for change in ('size', 'order', 'time'):
            binding, events = model.synthetic()
            if change == 'size': events[2]['object']['logical_bytes_decimal'] = '1'
            if change == 'order': events[2]['sequence_decimal'] = '1'
            if change == 'time': events[2]['clock']['scaled_ns_decimal'] = '0'
            with self.assertRaises(ValueError):
                model.build(binding, events, trace_id='dff02455-143f-43e3-94c4-ecdc9f5687a8')
        for kwargs in ({'slots': True}, {'shard_bytes': 1}, {'logical_budget': 1}, {'repair_every': -1}, {'ttl_ns': 0}):
            with self.assertRaises(ValueError): self.plan(**kwargs)
        for field in ('schema', 'selected_observations'):
            binding, events = model.synthetic()
            binding[field] = True
            with self.assertRaises(ValueError):
                model.build(binding, events, trace_id='dff02455-143f-43e3-94c4-ecdc9f5687a8')

    def test_strategy_selection_is_exclusive_and_reproducible(self):
        for strategy, delivery in (('central', 'return'), ('pipeline', 'return'), ('helper', 'return'), ('helper', 'direct')):
            config = model.repair_options(strategy, delivery, 4, [11])
            plan = self.plan(repair=config)
            self.assertEqual(plan, self.plan(repair=copy.deepcopy(config)))
            for step in plan['steps']:
                if step['spec']['kind'] == 'repair':
                    self.assertEqual({key: step['spec'][key] for key in config}, config)
        with self.assertRaises(ValueError): model.repair_options('pipeline', 'direct')
        plan = self.plan(repair_every=0)
        self.assertFalse(any(s['spec']['kind'] == 'repair' for s in plan['steps']))

    def test_recovery_attempt_policy_is_bounded_without_adding_logical_actions_or_credit(self):
        first = self.plan(max_mutation_attempts=1)
        last = self.plan(max_mutation_attempts=4)
        self.assertEqual(first['steps'], last['steps'])
        self.assertEqual(first['summary'], last['summary'])
        self.assertFalse(last['model']['unpublished_unknown_outputs_credit'])
        self.assertEqual(last['recovery'], {'schema': 1, 'max_mutation_attempts': 4,
                                           'policy': 'explicit_settle_original_candidates'})
        for value in (0, 5, True):
            with self.assertRaises(ValueError): self.plan(max_mutation_attempts=value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
