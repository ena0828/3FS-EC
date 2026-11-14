#!/usr/bin/env python3
"""Pure receipt, projection and signal-owner checks; no native child or GC."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

SCRIPTS = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), SCRIPTS / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

bridge = load('tree-gc-acceptance')
gc = load('tree-gc-runner')
w = load('experiment-runner')

def uid(number):
    return str(uuid.UUID(int=number))

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf8')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def sample(index):
    generation = str(index + 1)
    payload = hashlib.shake_256(('3fs-mode4-cli-functional-v1/' + bridge.NAMES[index]).encode()).digest(bridge.READ_BYTES)
    digest = hashlib.sha256(payload).hexdigest()
    row = {'stripe_decimal': '0', 'revision_decimal': str(index + 4), 'generation_decimal': generation,
           'logical_length_decimal': str(bridge.READ_BYTES), 'content_sha256': digest, 'endpoint_set_sha256': 'a' * 64,
           'allocations': [{'version': 1, 'object': uid(2), 'stripe_decimal': '0', 'generation_decimal': generation,
                            'shard': shard, 'allocation': uid(1000 + index * 12 + shard)} for shard in range(12)],
           'endpoints': [{'shard': shard, 'origin_operation': uid(100 + index), 'node_decimal': str(10001 + shard),
                          'chain_decimal': str(20001 + shard), 'target_decimal': str(30001 + shard),
                          'engine_uuid': uid(400 + shard), 'target_incarnation': uid(500 + shard)} for shard in range(12)]}
    return {'schema': 1, 'kind': 'ec_tree_read_allocations', 'scope': 'captured_read_snapshot',
            'metadata_observation_only': True, 'gc_authorized': False, 'network_io_performed': False,
            'cluster': 'test-cluster', 'object': {'inode_decimal': '42', 'incarnation': uid(2)}, 'birth': uid(3),
            'owner': {'uid_decimal': '1000', 'client_namespace': uid(4)}, 'session': uid(5),
            'range': uid(10 + index), 'request': uid(20 + index), 'shard_bytes': bridge.SHARD_BYTES,
            'root': {'node': uid(30 + index), 'sequence_decimal': str(index + 2), 'epoch_decimal': str(index + 2),
                     'visible_length_decimal': str(bridge.READ_BYTES)},
            'selection': {'offset_decimal': '0', 'requested_length_decimal': str(bridge.READ_BYTES + 1),
                          'readable_length_decimal': str(bridge.READ_BYTES), 'stripe_count': 1},
            'journal': {'record_sha256': 'b' * 64, 'latest_state_sha256': 'c' * 64, 'latest_sequence_decimal': '0',
                        'attempt_decimal': '2', 'snapshot_state': 'released'},
            'slots': [{'kind': 'data', 'stripe_decimal': '0', 'revision_decimal': row['revision_decimal']}],
            'revisions': [row]}

SESSION = {'inode_decimal': '42', 'incarnation': uid(2), 'birth': uid(3), 'client_namespace': uid(4), 'session': uid(5)}


def receipt(root):
    """Actual private files with synthetic native records: never business proof."""
    folder = root / 'client/tree-gc-acceptance/case'
    folder.mkdir(parents=True)
    (root / 'scripts').mkdir()
    shutil.copyfile(SCRIPTS / 'tree-gc-runner.py', root / 'scripts/tree-gc-runner.py')
    (root / 'client/file-client.toml').write_text('[user_info]\nuid=1000\n', encoding='utf8')
    save(root / 'cluster.json', {'cluster_id': 'test-cluster'})
    exports, entries, records = [], [], {}
    for index, name in enumerate(bridge.NAMES):
        value = sample(index)
        run = folder / 'runs' / f'read-{index + 1:02d}-{name}'
        run.mkdir(parents=True)
        (run / 'record.data').write_bytes(b'synthetic typed journal record')
        (run / 'state-00000000000000000000.data').write_bytes(b'synthetic final Released state')
        value['journal']['record_sha256'] = records[str(run / 'record.data')] = sha(run / 'record.data')
        value['journal']['latest_state_sha256'] = sha(run / 'state-00000000000000000000.data')
        output = folder / 'outputs' / (name + '-allocations.json')
        save(output, value)
        exports.append(value)
        entries.append({'path': str(output), 'sha256': sha(output), 'read_run': str(run), 'range': value['range'],
                        'input_sha256': value['revisions'][0]['content_sha256']})
    actions = ['create', 'resume-open', 'pwrite', 'read', 'release-read', 'pwrite', 'read', 'release-read',
               'truncate', 'resume-truncate', 'close-truncate-debt', 'read', 'release-read', 'close', 'close']
    steps, commands = [], []
    for index, action in enumerate(actions):
        run = entries[0]['read_run'] if index in (3, 4) else entries[1]['read_run'] if index in (6, 7) else str(folder / 'runs' / action)
        command = {'index': index, 'argv': ['synthetic-file-cli', action], 'process_started': True,
                   'process_exited': True, 'returncode': 0}
        log = folder / 'report' / f'command-{index:03d}.log'
        log.parent.mkdir(exist_ok=True)
        log.write_bytes(b'explicit synthetic pure-test child receipt')
        step = {'index': index, 'action': action, 'run': run, 'checks_complete': True, 'argv': command['argv'],
                'process': command, 'log_sha256': sha(log), 'input_sha256': {}, 'business': [{}]}
        if index in (3, 4, 6, 7):
            entry = entries[0 if index in (3, 4) else 1]
            step['business'] = [{'range': entry['range']}]
            step['journal_sha256'] = {'record.data': records[str(Path(run) / 'record.data')]}
            if action == 'read':
                step.update(byte_equal=True, eof_checked=True, bytes=bridge.READ_BYTES,
                            expected_sha256=entry['input_sha256'], output_sha256=entry['input_sha256'])
            else:
                step['remote_range_released'] = True
        if index == 10:
            step['remote_debt_released'] = True
        if index == 11:
            step.update(byte_equal=True, eof_checked=True, bytes=0)
        if index == 12:
            step['remote_range_released'] = True
        if action == 'close':
            step['closed'] = True
        steps.append(step)
        commands.append(command)
    ledger = folder / 'report/settled-ledger.json'
    save(ledger, {'schema': 1, 'logical_length_decimal': '0', 'session': SESSION, 'steps': steps,
                  'journal_sha256': records, 'exports': entries})
    expected = bridge.expected_from_exports(exports, SESSION, 'test-cluster', ledger, sha(ledger), gc)
    expected_path = folder / 'report/expected.json'
    save(expected_path, expected)
    binding = {'cluster': 'test-cluster', 'client_namespace': uid(9),
               'files': {str(root / 'cluster.json'): sha(root / 'cluster.json')}}
    plan = gc.new_plan(root, expected, binding, 32, 256)
    plan_path = folder / 'collector/plan.json'
    save(plan_path, plan)
    completion = {'schema': 1, 'collector_id': plan['collector_id'], 'state': 'confirmed',
                  'completion_scope': gc.SCOPE, 'plan_sha256': sha(plan_path), 'revisions_confirmed': 2,
                  'allocations_confirmed': 24, 'nodes_reclaimed': 2, 'historical_unjoined_attempts': 0,
                  'all_started_commands_joined': True, 'current_owner_commands_joined': True,
                  'capacity_returned': False, 'namespace_deleted': False, 'unpublished_outputs_covered': False}
    save(folder / 'collector/completion.json', completion)
    argv = [[str(root / 'bin/ec_file_cli'), '--cfg=' + str(root / 'client/file-client.toml'),
             '--config.run_dir=' + entry['read_run'], '--config.output_file=' + entry['path'],
             'mode4-export-read-allocations'] for entry in entries]
    for action in ('start', 'resume'):
        current = ['/usr/bin/python3', '-B', str(root / 'scripts/tree-gc-runner.py'), action, '--root', str(root),
                   '--run-dir', str(folder / 'collector')]
        argv.append(current + (['--expected', str(expected_path)] if action == 'start' else []))
    local = [{'index': i, 'argv': args, 'kind': 'local_snapshot_export' if i < 2 else 'tree_gc_collector',
              'process_started': True, 'process_exited': True, 'returncode': 0} for i, args in enumerate(argv)]
    return {'schema': 1, 'success': True, 'failure': None, 'phase': 'tree-gc', 'commands': commands, 'steps': steps,
            'local_commands': local, 'collector': str(folder / 'collector'), 'completion': completion,
            'all_owned_children_joined': True, 'performance_validated': False, 'capacity_returned': False,
            'namespace_deleted': False, 'unpublished_outputs_covered': False, 'exports': entries,
            'expected_sha256': sha(expected_path), 'python_executable': '/usr/bin/python3'}, folder


class TreeGcAcceptance(unittest.TestCase):
    def test_projection_accepts_identity_v1_and_rejects_partial_or_foreign_snapshots(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary).resolve() / 'ledger.json'
            original = [sample(0), sample(1)]
            projected = bridge.expected_from_exports(original, SESSION, 'test-cluster', ledger, 'a' * 64, gc)
            self.assertEqual(len(projected['revisions']), 2)
            self.assertEqual(sum(len(row['allocations']) for row in projected['revisions']), 24)
            self.assertEqual(set(projected['revisions'][0]['allocations'][0]),
                             {'stripe_decimal', 'generation_decimal', 'shard', 'allocation'})
            changes = [lambda x: x[0]['revisions'][0]['allocations'][0].update(version=2),
                       lambda x: x[0]['selection'].update(readable_length_decimal='1'),
                       lambda x: x[0]['root'].update(visible_length_decimal='1'),
                       lambda x: x[0]['journal'].update(snapshot_state='closing'),
                       lambda x: x[0]['owner'].update(client_namespace=uid(90)),
                       lambda x: x[0]['revisions'][0]['endpoints'].pop(),
                       lambda x: x[1]['revisions'][0]['allocations'][0].update(allocation=x[0]['revisions'][0]['allocations'][0]['allocation']),
                       lambda x: x[0].update(schema=True)]
            for number, change in enumerate(changes):
                with self.subTest(number=number):
                    values = copy.deepcopy(original)
                    change(values)
                    with self.assertRaises((ValueError, gc.CheckError)):
                        bridge.expected_from_exports(values, SESSION, 'test-cluster', ledger, 'a' * 64, gc)

    def test_result_rechecks_real_export_journal_ledger_and_exact_local_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            value, folder = receipt(root)
            bridge.validate_result(value, root, 'case')
            wrong_steps = copy.deepcopy(value['steps'])
            record = str(Path(value['exports'][0]['read_run']) / 'record.data')
            wrong_steps[4]['journal_sha256'] = {record: wrong_steps[4]['journal_sha256']['record.data']}
            with self.assertRaisesRegex(ValueError, 'original read journal'):
                bridge.load_exports(value['exports'], wrong_steps, folder, gc)
            for field, replacement in (('kind', 'supervisor_control'), ('returncode', 1), ('process_exited', False),
                                       ('transport', {'mode': 'rdma'})):
                with self.subTest(field=field):
                    broken = copy.deepcopy(value)
                    broken['local_commands'][0][field] = replacement
                    with self.assertRaises(ValueError):
                        bridge.validate_result(broken, root, 'case')
            broken = copy.deepcopy(value)
            broken['local_commands'][3]['argv'][0] = '/arbitrary/python'
            with self.assertRaises(ValueError):
                bridge.validate_result(broken, root, 'case')
            for path in (Path(value['exports'][0]['path']), Path(value['exports'][0]['read_run']) / 'record.data',
                         Path(value['exports'][0]['read_run']) / 'state-00000000000000000000.data',
                         folder / 'report/settled-ledger.json', folder / 'collector/plan.json'):
                with self.subTest(path=path.name):
                    original = path.read_bytes()
                    path.write_bytes(original + b' ')
                    try:
                        with self.assertRaises((ValueError, gc.CheckError)):
                            bridge.validate_result(value, root, 'case')
                    finally:
                        path.write_bytes(original)
            bridge.validate_result(value, root, 'case')

    def test_combined_signal_stops_both_owners_and_preserves_shared_join_path(self):
        data, local = w.Runner.__new__(w.Runner), w.Runner.__new__(w.Runner)
        for owner in (data, local):
            owner.stop_requested, owner.interrupt_count = False, 0
        local.transport_role = 'control'
        local.check_transport = mock.Mock(return_value=None)
        ack = SimpleNamespace(_owned_command=mock.Mock(return_value='joined output'))
        handlers, original = {}, {}
        def install(number, handler):
            prior = handlers.get(number, 'original-' + str(number))
            original.setdefault(number, prior)
            handlers[number] = handler
            return prior
        with mock.patch.object(bridge.signal, 'signal', side_effect=install):
            with bridge.signal_scope(data, local):
                self.assertEqual(bridge.local_command(data, local, ack, w, ['fixed-command'], 'local_snapshot_export'),
                                 'joined output')
                ack._owned_command.assert_called_once_with(local, w, ['fixed-command'], None, kind='local_snapshot_export')
                handlers[signal.SIGTERM](signal.SIGTERM, None)
                self.assertTrue(data.stop_requested and local.stop_requested)
                self.assertEqual((data.interrupt_count, local.interrupt_count), (1, 1))
                with self.assertRaises(ValueError):
                    bridge.local_command(data, local, ack, w, ['next-command'], 'tree_gc_collector')
                ack._owned_command.assert_called_once()
            self.assertEqual(handlers, original)

    def test_completion_requires_exact_confirmed_counts_without_capacity_or_unknown_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            value, folder = receipt(root)
            complete = value['completion']
            bridge.confirmed(complete, complete['plan_sha256'])
            for key, changed in (('state', 'pending'), ('allocations_confirmed', 23), ('revisions_confirmed', 1),
                                 ('historical_unjoined_attempts', 1), ('all_started_commands_joined', False),
                                 ('current_owner_commands_joined', False), ('capacity_returned', True),
                                 ('namespace_deleted', True), ('unpublished_outputs_covered', True),
                                 ('nodes_reclaimed', 0), ('schema', True), ('plan_sha256', 'f' * 64)):
                with self.subTest(key=key):
                    broken = copy.deepcopy(complete)
                    broken[key] = changed
                    with self.assertRaises(ValueError):
                        bridge.confirmed(broken, complete['plan_sha256'])
            broken = copy.deepcopy(value)
            broken['success'] = False
            with self.assertRaises(ValueError):
                bridge.validate_result(broken, root, 'case')
            broken = copy.deepcopy(value)
            broken['steps'][10]['remote_debt_released'] = False
            save(folder / 'report/settled-ledger.json', {'schema': 1, 'logical_length_decimal': '0', 'session': SESSION,
                 'steps': broken['steps'], 'exports': broken['exports'], 'journal_sha256': {}})
            with self.assertRaises(ValueError):
                bridge.validate_result(broken, root, 'case')


if __name__ == '__main__':
    unittest.main()
