#!/usr/bin/env python3
"""Pure durable-adapter fault tests. Synthetic CLI observations are NOT native evidence."""
import copy
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), HERE / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


n = load('kv-replay-native.py')
w = load('experiment-runner.py')
gc = load('tree-gc-runner.py')
cli = load('file-command.py')
trace = n.module(HERE.parent / 'traces/kv_trace.py', 'test_kv_native_payload')


def uid(number): return str(uuid.UUID(int=number))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class NativeAdapterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kv-native-contract-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        for name in ('client', 'config', 'scripts', 'bin', 'run'):
            (self.root / name).mkdir(mode=0o700)
        self.save(self.root / 'cluster.json', {'root': str(self.root), 'file_api': True, 'cluster_id': 'test-cluster'})
        self.backend = b = n.NativeBackend.__new__(n.NativeBackend)
        b.root = self.root; b.run_dir = self.root / 'run'; b.w = w; b.gc = gc; b.cli = cli; b.trace = trace
        b.lease_fd = 9876; b.stopped = False; b.active_owner = None
        b.ack = SimpleNamespace(sync_parent=lambda _: None, checked_pass_fds=lambda fds: fds,
                               hash_file=lambda _w, path: sha(path), command=self.execute, collector_command=self.execute)
        b.plan = {'schema': 1, 'trace_id': uid(1), 'namespace': '/ec-lab', 'shard_bytes': 11469,
                  'repair': {'strategy': 'helper', 'delivery': 'direct', 'window': 2,
                             'targets': [0, 11], 'sources': list(range(1, 11))}}
        b.plan['steps'] = [{'name': name, 'spec': self.spec(kind, instance), 'model': {}}
                           for name, kind, instance in [('put-0', 'put', 'put-0'), ('get-0', 'get', 'put-0'),
                             ('repair-0', 'repair', 'put-0'), ('evict-0', 'evict', 'put-0'),
                             ('get-late', 'get', 'put-0'), ('put-1', 'put', 'put-1')]]
        b.plan_sha = n.digest(b.plan); b.manifest = {'cluster_id': 'test-cluster'}
        b.binding = {'files': {str(self.root / 'cluster.json'): sha(self.root / 'cluster.json')}}
        b.folder = b.directory(b.run_dir / 'native'); b.actions = b.directory(b.folder / 'actions')
        self.enterContext(patch.object(n.os, 'O_NOFOLLOW', getattr(n.os, 'O_NOFOLLOW', 0), create=True))
        if sys.platform == 'win32':
            # Windows CRT refuses fsync on read-only descriptors. Only this
            # fixture's reopen uses RDWR; production is Linux-only and unchanged.
            original_open = os.open
            proxy = SimpleNamespace(**vars(os))
            proxy.open = lambda path, flags, *args: original_open(
                path, os.O_RDWR if flags == (os.O_RDONLY | n.os.O_NOFOLLOW) else flags, *args)
            self.enterContext(patch.object(n, 'os', proxy))
        self.enterContext(patch.object(w, 'Runner', side_effect=self.owner))
        self.calls = []; self.fail_action = None; self.fail_without_record = False; self.fail_read_output = False
        self.session = {'client_namespace': uid(4), 'session': uid(5), 'operation': uid(0),
                        'inode_decimal': '42', 'incarnation': uid(2), 'birth': uid(3)}
        self.generation = 1

    def save(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(n.encoded(value))

    def owner(self, root, config, report):
        report.mkdir(mode=0o700)
        return SimpleNamespace(root=root, config=config, report=report, commands=[], child=None,
                               stop_requested=False, signal_scope=lambda: nullcontext())

    def spec(self, kind, instance='put-0'):
        result = {'kind': kind, 'instance': instance, 'key_sha256': 'a' * 64, 'logical_bytes_decimal': '896'}
        if kind == 'repair': result.update(self.backend.plan['repair'])
        return result

    def snapshot(self, run):
        size = 896; generation = str(self.generation)
        row = {'stripe_decimal': '0', 'revision_decimal': str(self.generation + 4), 'generation_decimal': generation,
               'logical_length_decimal': str(size),
               'content_sha256': hashlib.sha256(b''.join(trace.iter_payload('a' * 64, size))).hexdigest(),
               'endpoint_set_sha256': 'd' * 64,
               'allocations': [{'version': 1, 'object': uid(2), 'stripe_decimal': '0', 'generation_decimal': generation,
                                'shard': s, 'allocation': uid(self.generation * 100 + s)} for s in range(12)],
               'endpoints': [{'shard': s, 'origin_operation': uid(1000), 'engine_uuid': uid(1100 + s),
                              'target_incarnation': uid(1200 + s), 'node_decimal': str(10001 + s),
                              'chain_decimal': str(20001 + s), 'target_decimal': str(30001 + s)} for s in range(12)]}
        return {'schema': 1, 'kind': 'ec_tree_read_allocations', 'scope': 'captured_read_snapshot',
                'metadata_observation_only': True, 'gc_authorized': False, 'network_io_performed': False,
                'cluster': 'test-cluster', 'object': {'inode_decimal': '42', 'incarnation': uid(2)},
                'session': uid(5), 'birth': uid(3), 'owner': {'client_namespace': uid(4), 'uid_decimal': '1000'},
                'range': uid(20), 'request': uid(21), 'shard_bytes': 11469,
                'root': {'visible_length_decimal': str(size)},
                'selection': {'offset_decimal': '0', 'requested_length_decimal': str(size + 1),
                              'readable_length_decimal': str(size), 'stripe_count': 1},
                'journal': {'record_sha256': sha(run / 'record.data'), 'latest_sequence_decimal': '0',
                            'latest_state_sha256': sha(run / 'state-00000000000000000000.data'),
                            'snapshot_state': 'released'},
                'slots': [{'kind': 'data', 'stripe_decimal': '0', 'revision_decimal': row['revision_decimal']}],
                'revisions': [row]}

    def execute(self, owner, _w, argv, *, pass_fds):
        self.assertEqual(pass_fds, (9876,))
        collector = argv[0] == sys.executable
        if collector:
            action = argv[3]; run = Path(argv[7]); options = {}
        else:
            action = argv[-1][6:]
            options = dict(arg[9:].split('=', 1) for arg in argv[2:-1])
            run = Path(options['run_dir'])
        self.calls.append((action, run, options))
        row = {'argv': argv, 'process_started': True, 'process_exited': True, 'returncode': 0}
        owner.commands.append(row)
        failing = action == self.fail_action
        if failing: self.fail_action = None
        if not (failing and self.fail_without_record):
            run.mkdir(parents=True, exist_ok=True, mode=0o700)
            record = run / ('record.data' if 'read' in action or 'allocations' in action else 'record.json')
            if not record.exists(): record.write_bytes(b'FIXTURE: stable original journal identity')
        values = []
        if collector:
            if action == 'start':
                expect = gc.load(argv[9])
                binding = {'client_namespace': uid(4), 'cluster': 'test-cluster',
                           'files': {str(self.root / 'cluster.json'): sha(self.root / 'cluster.json')}}
                plan = gc.new_plan(self.root, expect, binding, 256, 8192)
                self.save(run / 'plan.json', plan)
            plan = gc.load(run / 'plan.json')
            # Actual collector uses a separate six-digit attempt directory and
            # joined.json, not backend observed.json. These are synthetic bytes
            # with that real producer shape, never an executed admin request.
            collector_attempt = run / 'attempts/000000'
            admin_argv = [str(self.root / 'bin/admin_cli'), '--cfg', str(self.root / 'config/admin_cli.toml'),
                          '--', 'ec-gc-query FIXTURE_ONLY']
            self.save(collector_attempt / 'intent.json', {'operation': {'name': 'fixture-query'}, 'argv': admin_argv})
            (collector_attempt / 'command.log').write_text('FIXTURE_ONLY\n', encoding='utf8')
            self.save(collector_attempt / 'joined.json', {'argv': admin_argv, 'process_started': True,
                      'process_exited': True, 'returncode': 0, 'log_sha256': sha(collector_attempt / 'command.log'),
                      'owner_error_type': None})
            completion = {'schema': 1, 'state': 'confirmed', 'completion_scope': gc.SCOPE,
                          'plan_sha256': sha(run / 'plan.json'), 'revisions_confirmed': len(plan['expected']['revisions']),
                          'allocations_confirmed': len(plan['allocation_ids']), 'current_owner_commands_joined': True,
                          'capacity_returned': False, 'namespace_deleted': False, 'unpublished_outputs_covered': False,
                          'historical_unjoined_attempts': 0, 'all_started_commands_joined': True}
            self.save(run / 'completion.json', completion)
        elif action in ('create', 'resume-open', 'close'):
            values = [self.session | {'error_code': 0, 'session_state': 3 if action == 'close' else 1, 'shard_bytes': 11469}]
        elif action in ('pwrite', 'resume'):
            values = [self.session | {'operation': uid(6), 'error_code': 0, 'offset_decimal': '0', 'length_decimal': '896'},
                      {'observed': True, 'logical_closed': True, 'logical_complete': True,
                       'all_cleanup_complete': True, 'error_code': 0,
                       'confirmed_prefix_decimal': '896', 'revalidated_prefix_decimal': '896'}]
        elif action in ('read', 'resume-read'):
            data = b'' if run.parent.name == 'empty' else b''.join(trace.iter_payload('a' * 64, 896))
            output = Path(options['output_file'])
            self.assertFalse(output.exists())
            output.write_bytes(data[:1] if failing and self.fail_read_output else data)
            (run / 'state-00000000000000000000.data').write_bytes(b'FIXTURE: same pinned snapshot')
            values = [{'error_code': 0, 'data_ready': True, 'all_cleanup_complete': False,
                       'readable_length_decimal': str(len(data)), 'range': uid(20)}]
        elif action == 'release-read':
            self.assertTrue((run.parent / 'read/done.json').is_file(), 'Verified proof must precede release')
            values = [{'error_code': 0, 'all_cleanup_complete': True, 'range': uid(20)}]
        elif action == 'export-read-allocations':
            self.assertTrue((run.parent / 'release/done.json').is_file())
            self.save(Path(options['output_file']), self.snapshot(run))
            values = [{'kind': 'ec_tree_read_allocations_exported', 'network_io_performed': False}]
        elif action in ('repair', 'resume-repair', 'close-repair-debt'):
            self.generation = 2
            values = [self.session | {'operation': uid(30), 'failure': None, 'revalidated': True, 'observed': True, 'published': True,
                       'output_drained': True, 'source_released': True, 'all_cleanup_complete': True,
                       'child': uid(31), 'plan': uid(32), 'source_pin': uid(33)}]
        elif action in ('truncate', 'resume-truncate', 'close-truncate-debt'):
            values = [{'length_decimal': '0', 'observed': True, 'aborted': False, 'error_code': 0,
                       'operation': uid(40), 'published': True, 'all_cleanup_complete': True}]
        else: self.fail('Unexpected native operation ' + action)
        text = ''.join(json.dumps(value) + '\n' for value in values)
        (owner.report / 'command-000.log').write_text(text, encoding='utf8')
        if failing:
            row['returncode'] = 1
            raise RuntimeError('FIXTURE lost reply or incomplete local output')
        return text

    def test_complete_put_get_repair_evict_uses_all_original_snapshots(self):
        put = self.backend.perform('put-0', self.spec('put'))
        self.backend.perform('get-0', self.spec('get'))
        repair = self.backend.perform('repair-0', self.spec('repair'))
        evict = self.backend.perform('evict-0', self.spec('evict'))
        self.assertEqual(len(put['snapshot_exports']), 1)
        self.assertEqual(len(repair['snapshot_exports']), 1)
        self.assertEqual(evict['gc']['completion']['allocations_confirmed'], 24)
        self.assertEqual(evict['gc']['confirmed_allocation_model_bytes_decimal'], str(24 * 11469))
        self.assertEqual(evict['historical_unconfirmed_attempts'], 0)
        self.assertTrue(evict['historical_join_proven'])
        collector_join = Path(evict['gc']['run']) / 'attempts/000000/joined.json'
        self.assertEqual(evict['files'][str(collector_join)], sha(collector_join))
        self.assertFalse(evict['physical_capacity_returned']); self.assertFalse(evict['namespace_deleted'])
        before = len(self.calls)
        self.assertEqual(self.backend.perform('evict-0', self.spec('evict')), evict)
        self.assertEqual(len(self.calls), before)
        old_join = collector_join.read_bytes()
        collector_join.write_bytes(b'changed joined evidence')
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            self.backend.perform('evict-0', self.spec('evict'))
        collector_join.write_bytes(old_join)
        with self.assertRaisesRegex(ValueError, 'evicted'):
            self.backend.perform('get-late', self.spec('get'))

    def test_lost_write_reply_resumes_same_journal_and_blocks_later_event(self):
        self.fail_action = 'pwrite'
        with self.assertRaisesRegex(RuntimeError, 'FIXTURE'): self.backend.perform('put-0', self.spec('put'))
        record = self.backend.actions / 'put-0/write-run/record.json'
        original = record.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Earlier planned|Another action'):
            self.backend.perform('put-1', self.spec('put', 'put-1'))
        completed = self.backend.perform('put-0', self.spec('put'))
        self.assertEqual(record.read_bytes(), original)
        self.assertEqual([x[0] for x in self.calls].count('pwrite'), 1)
        self.assertEqual([x[0] for x in self.calls].count('resume'), 1)
        self.assertEqual(completed['state'], 'confirmed')

    def test_missing_started_journal_never_recreates_mutation_identity(self):
        self.fail_action = 'create'; self.fail_without_record = True
        with self.assertRaises(RuntimeError): self.backend.perform('put-0', self.spec('put'))
        before = len(self.calls)
        with self.assertRaisesRegex(ValueError, 'missing/partial'):
            self.backend.perform('put-0', self.spec('put'))
        self.assertEqual(len(self.calls), before)
        self.assertEqual([x[0] for x in self.calls], ['create'])

    def test_partial_read_output_uses_new_output_same_read_identity_before_release(self):
        self.fail_action = 'read'; self.fail_read_output = True
        with self.assertRaises(RuntimeError): self.backend.perform('put-0', self.spec('put'))
        completed = self.backend.perform('put-0', self.spec('put'))
        reads = [x for x in self.calls if x[0] in ('read', 'resume-read')]
        self.assertEqual([x[0] for x in reads], ['read', 'resume-read'])
        self.assertEqual(reads[0][1], reads[1][1])
        self.assertNotEqual(reads[0][2]['output_file'], reads[1][2]['output_file'])
        self.assertEqual(Path(reads[0][2]['output_file']).read_bytes().__len__(), 1)
        self.assertEqual(completed['snapshot_exports'][0]['range'], uid(20))

    def test_lost_release_reply_keeps_verified_bytes_and_never_rereads_released_range(self):
        self.fail_action = 'release-read'
        with self.assertRaises(RuntimeError): self.backend.perform('put-0', self.spec('put'))
        self.backend.perform('put-0', self.spec('put'))
        names = [x[0] for x in self.calls]
        self.assertEqual(names.count('read'), 1); self.assertNotIn('resume-read', names)
        self.assertEqual(names.count('release-read'), 2)
        self.assertLess(names.index('release-read'), names.index('export-read-allocations'))

    def test_export_projection_rejects_incomplete_scope_boolean_alias_and_wrong_identity(self):
        put = self.backend.perform('put-0', self.spec('put'))
        entry = put['snapshot_exports'][0]; raw = gc.load(entry['path'])
        for change in (lambda v: v['revisions'][0]['allocations'].pop(),
                       lambda v: v['selection'].update(stripe_count=True),
                       lambda v: v['journal'].update(snapshot_state='active'),
                       lambda v: v['object'].update(incarnation=uid(999)),
                       lambda v: v['revisions'][0]['allocations'][1].update(allocation=v['revisions'][0]['allocations'][0]['allocation'])):
            value = copy.deepcopy(raw); change(value)
            with self.assertRaises((ValueError, gc.CheckError)):
                n.snapshot_revision(value, self.session, 'test-cluster', 11469, 896, uid(20),
                                    raw['journal']['record_sha256'], gc)

    def test_changed_spec_payload_and_evidence_refuse_cached_success(self):
        self.backend.perform('put-0', self.spec('put'))
        changed = self.spec('put'); changed['logical_bytes_decimal'] = '897'
        with self.assertRaisesRegex(ValueError, 'spec changed'): self.backend.perform('put-0', changed)
        path = self.backend.actions / 'put-0/payload.bin'; path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            self.backend.perform('put-0', self.spec('put'))
        with patch.object(n.sys, 'platform', 'linux'), \
             patch.object(n.os, 'getuid', return_value=1100, create=True), \
             patch.object(n.os, 'geteuid', return_value=1100, create=True), \
             patch.object(n.os, 'getgid', return_value=1100, create=True), \
             patch.object(n.os, 'getegid', return_value=1100, create=True), \
             patch.dict(n.sys.modules, {'native_v2_config': SimpleNamespace(__file__=str(self.root / 'other.py'))}):
            with self.assertRaisesRegex(ValueError, 'provider is already imported'):
                n.NativeBackend(self.root, self.backend.run_dir, self.backend.plan, 9876)

    def test_unknown_attempt_is_not_historical_join_and_same_plan_is_fixed(self):
        self.fail_action = 'pwrite'
        with self.assertRaises(RuntimeError): self.backend.perform('put-0', self.spec('put'))
        observed = self.backend.actions / 'put-0/write/attempts/0000/observed.json'
        observed.unlink()  # Simulate wrapper loss after its child, before recording actual wait result.
        completed = self.backend.perform('put-0', self.spec('put'))
        self.assertEqual(completed['historical_unconfirmed_attempts'], 1)
        self.assertFalse(completed['historical_join_proven'])
        self.assertTrue(completed['current_owner_children_joined'])
        bad = self.spec('repair'); bad['window'] = 4
        with self.assertRaisesRegex(ValueError, 'fixed replay plan'):
            self.backend.perform('repair-bad', bad)
        self.backend.perform('get-0', self.spec('get'))
        self.backend.perform('repair-0', self.spec('repair'))
        collect = self.backend.collect

        def lose_direct_observations(folder, fixed, history):
            value = collect(folder, fixed, history)
            # Unknown directly owned empty-range release and collector child
            # must still count; the collector admin-grandchild ledger must not.
            for phase in ('empty/release', 'collector'):
                (folder / phase / 'attempts/0000/observed.json').unlink()
            return value

        with patch.object(self.backend, 'collect', side_effect=lose_direct_observations):
            evict = self.backend.perform('evict-0', self.spec('evict'))
        self.assertEqual(evict['historical_unconfirmed_attempts'], 2)
        self.assertFalse(evict['historical_join_proven'])

    def test_visible_verified_marker_after_sync_failure_is_reconfirmed_before_release(self):
        original = self.backend.seal
        failed = False

        def uncertain(path, value):
            nonlocal failed
            result = original(path, value)
            if not failed and path == self.backend.actions / 'put-0/read/done.json':
                failed = True
                raise OSError('FIXTURE directory fsync lost confirmation')
            return result

        with patch.object(self.backend, 'seal', side_effect=uncertain):
            with self.assertRaisesRegex(OSError, 'fsync'):
                self.backend.perform('put-0', self.spec('put'))
        self.assertNotIn('release-read', [row[0] for row in self.calls])
        with patch.object(self.backend, 'seal', wraps=original) as sealing:
            self.backend.perform('put-0', self.spec('put'))
            self.assertTrue(any(call.args[0] == self.backend.actions / 'put-0/read/done.json'
                                for call in sealing.call_args_list))
        self.assertEqual([row[0] for row in self.calls].count('read'), 1)
        self.assertEqual([row[0] for row in self.calls].count('release-read'), 1)

    def test_incomplete_gc_even_exit_zero_never_returns_allocation_model_credit(self):
        self.backend.perform('put-0', self.spec('put'))
        self.backend.perform('get-0', self.spec('get'))
        self.backend.perform('repair-0', self.spec('repair'))
        original = self.backend.ack.collector_command

        def incomplete(owner, wrapper, argv, **kwargs):
            text = original(owner, wrapper, argv, **kwargs)
            path = Path(argv[7]) / 'completion.json'
            value = gc.load(path); value['allocations_confirmed'] = 23
            self.save(path, value)
            return text

        with patch.object(self.backend.ack, 'collector_command', side_effect=incomplete):
            with self.assertRaisesRegex(ValueError, 'allocations_confirmed'):
                self.backend.perform('evict-0', self.spec('evict'))
        self.assertFalse((self.backend.actions / 'evict-0/completion.json').exists())
        with self.assertRaisesRegex(ValueError, 'Earlier planned|Another action'):
            self.backend.perform('put-1', self.spec('put', 'put-1'))

    def test_resume_revalidates_completed_prefix_before_same_third_action_recovery(self):
        put = self.backend.perform('put-0', self.spec('put'))
        get = self.backend.perform('get-0', self.spec('get'))
        self.fail_action = 'repair'
        with self.assertRaises(RuntimeError): self.backend.perform('repair-0', self.spec('repair'))
        original = self.backend.actions / 'repair-0/repair-run/record.json'
        before = sha(original)
        count = len(self.calls)
        self.assertEqual(self.backend.perform('put-0', self.spec('put')), put)
        self.assertEqual(self.backend.perform('get-0', self.spec('get')), get)
        self.assertEqual(len(self.calls), count, 'Completed prefix verification must not dispatch commands')
        with self.assertRaisesRegex(ValueError, 'Earlier planned|Another action'):
            self.backend.perform('evict-0', self.spec('evict'))
        repaired = self.backend.perform('repair-0', self.spec('repair'))
        self.assertEqual(sha(original), before)
        self.assertEqual(repaired['state'], 'confirmed')
        self.assertEqual([x[0] for x in self.calls].count('repair'), 1)
        self.assertEqual([x[0] for x in self.calls].count('resume-repair'), 1)


if __name__ == '__main__': unittest.main()
