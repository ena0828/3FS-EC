#!/usr/bin/env python3
"""Pure gates and Linux private-file FD checks; no chown, subprocess or service."""
import copy
import argparse
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('file_lab_under_test', Path(__file__).with_name('run-file-lab.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def passed_mount():
    probes = []
    for kind in ('posix', 'usrbio'):
        for phase in ('prepare', 'verify'):
            probes.append({'kind': kind, 'phase': phase, 'state': 'confirmed', 'bytes': 123,
                           'sha256': 'a' * 64, 'inode': 99, 'actual_abi_reads': 3})
    return {'schema': 1, 'status': 'passed', 'exitcode': 0, 'services_started_or_stopped': False,
            'cleanup': {'all_fuse_joined': True, 'all_commands_joined': True, 'unmounted': True,
                        'normal_unmounts': 2, 'fuse_exitcodes': [0, 0], 'unknown_owned_processes': []},
            'probes': probes}


class FileLabGates(unittest.TestCase):
    def replay_fixture(self, root):
        """Synthetic receipts only; actual native work remains in the hosted phase."""
        scripts = root / 'scripts'; scripts.mkdir()
        source = Path(__file__).resolve().parents[1]
        for name in ('kv-replay.py', 'kv-replay-native.py', 'ack-service-acceptance.py', 'experiment-runner.py',
                     'native_v2_config.py', 'generate.py', 'file-command.py', 'tree-gc-runner.py'):
            shutil.copyfile(source / 'cluster' / name, scripts / name)
        for name in ('kv_trace.py', 'replay_input.py', 'replay_model.py'):
            shutil.copyfile(source / 'traces' / name, scripts / name)
        run = root / 'client/kv-replay-hosted'; run.mkdir(parents=True)
        saved_path = list(sys.path)
        names = ('kv_trace', 'replay_input', 'replay_model')
        saved = {name: sys.modules.pop(name, None) for name in names}
        try:
            sys.path.insert(0, str(scripts))
            entry = lab.module(scripts / 'kv-replay.py', 'test_lab_kv_entry')
            request = {'schema': 1, 'root': str(root), 'trace_id': '11111111-1111-4111-8111-111111111111',
                       'input': {'kind': 'synthetic'}, 'policy': {'shard_bytes': 11469, 'slots': 2,
                       'logical_budget': 229376, 'allocation_budget': 16777216, 'ttl_ns': 5 * 10**9,
                       'repair_every': 3, 'repair': entry.replay_model.repair_options()}}
            plan = entry.derive(request)
            def save(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(entry.encoded(value))
            save(run / 'request.json', request); save(run / 'plan.json', plan)
            inputs = [root / name for name in ('cluster.json', 'state/initialized.json', 'client/file-client.toml',
                      'config/admin_cli.toml', 'bin/ec_file_cli', 'bin/admin_cli')]
            for path in inputs:
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'pure fixture input only')
            inputs += [scripts / name for name in ('kv-replay-native.py', 'kv_trace.py', 'file-command.py',
                       'ack-service-acceptance.py', 'experiment-runner.py', 'tree-gc-runner.py', 'native_v2_config.py')]
            save(run / 'native/binding.json', {'schema': 1, 'root': str(root), 'run_dir': str(run), 'plan_sha256': entry.digest(plan),
                                              'files': {str(path): lab.sha(path) for path in inputs}})
            rows, values = [], []
            for step in plan['steps']:
                name, spec = step['name'], step['spec']; folder = run / 'native/actions' / name
                session = run / 'native/actions' / spec['instance'] / 'session-run'
                choices = {'put': ['create', 'pwrite', 'read', 'release-read', 'export-read-allocations'],
                           'get': ['read', 'release-read'],
                           'repair': ['repair', 'close-repair-debt', 'read', 'release-read', 'export-read-allocations'],
                           'evict': ['truncate', 'close-truncate-debt', 'read', 'release-read', 'close', 'unlink', 'collector']}[spec['kind']]
                files, command_paths = {}, []
                for index, action in enumerate(choices):
                    phase_name = {'create': 'session', 'pwrite': 'write', 'read': 'read', 'release-read': 'release',
                                  'export-read-allocations': 'export', 'repair': 'repair',
                                  'close-repair-debt': 'repair-debt', 'truncate': 'truncate',
                                  'close-truncate-debt': 'truncate-debt', 'close': 'close', 'unlink': 'unlink', 'collector': 'collector'}[action]
                    if spec['kind'] == 'evict' and action in ('read', 'release-read'):
                        phase_name = 'empty/' + phase_name
                    attempt = folder / phase_name / 'attempts/0000'
                    if action == 'collector':
                        argv = ['/usr/bin/python3', '-B', str(scripts / 'tree-gc-runner.py'), 'start', '--root', str(root),
                                '--run-dir', str(folder / 'collector-run'), '--expected', str(folder / 'expected.json'),
                                '--max-nodes', '2064', '--max-commands', '16384']
                        kind = 'tree_gc_collector'
                    else:
                        if action == 'create': native_run = folder / 'session-run'
                        elif action == 'pwrite': native_run = folder / 'write-run'
                        elif action in ('repair', 'close-repair-debt'): native_run = folder / 'repair-run'
                        elif action in ('truncate', 'close-truncate-debt'): native_run = folder / 'truncate-run'
                        elif action == 'unlink': native_run = folder / 'unlink-run'
                        elif action == 'close': native_run = session
                        else: native_run = folder / ('empty/read-run' if spec['kind'] == 'evict' else 'read-run')
                        native_run.mkdir(parents=True, exist_ok=True)
                        options = {'run_dir': str(native_run)}
                        if action == 'create': options.update(file_path='/ec-lab/test', shard_bytes='11469', permission='384', session_rights='3')
                        if action == 'pwrite': options.update(session_run_dir=str(session), offset_decimal='0', input_file=str(folder / 'payload.bin'))
                        if action == 'read': options.update(session_run_dir=str(session), offset_decimal='0', length_decimal='114689',
                                                           output_file=str(folder / 'read/output-0000.bin'))
                        if action == 'repair': options.update(session_run_dir=str(session), repair_stripe_decimal='0', repair_mask_decimal='3',
                            repair_source_order=','.join(map(str, range(2,12))), repair_mode='helper', repair_window_decimal='1', repair_delivery='direct')
                        if action == 'truncate': options.update(session_run_dir=str(session), length_decimal='0')
                        if action == 'unlink': options.update(session_run_dir=str(session),
                            file_path='/ec-lab/kv-' + plan['trace_id'] + '-' + spec['instance'])
                        if action == 'export-read-allocations':
                            output = folder / 'export/allocations-0000.json'; save(output, {'synthetic': True})
                            options['output_file'] = str(output)
                        argv = [str(root / 'bin/ec_file_cli'), '--cfg=' + str(root / 'client/file-client.toml'),
                                *['--config.' + key + '=' + value for key, value in options.items()], 'mode4-' + action]
                        kind = ('local_read_export' if action == 'export-read-allocations' else
                                'namespace_control' if action == 'unlink' else None)
                    command = {'argv': argv, 'process_started': True, 'process_exited': True, 'returncode': 0,
                               'inherited_collector_lease': True}
                    if kind: command['kind'] = kind
                    save(attempt / 'intent.json', {'argv': argv})
                    save(attempt / 'observed.json', {'commands': [command]})
                    files[str(attempt / 'intent.json')] = lab.sha(attempt / 'intent.json')
                    files[str(attempt / 'observed.json')] = lab.sha(attempt / 'observed.json')
                    command_paths.append((attempt / 'observed.json', command))
                commands = [command for _, command in sorted(command_paths, key=lambda pair: pair[0])]
                value = {'schema': 1, 'state': 'confirmed', 'name': name, 'kind': spec['kind'], 'instance': spec['instance'],
                         'key_sha256': spec['key_sha256'], 'logical_bytes_decimal': spec['logical_bytes_decimal'],
                         'plan_sha256': entry.digest(plan), 'spec_sha256': entry.digest(spec), 'current_owner_children_joined': True,
                         'namespace_deleted': False, 'physical_capacity_returned': False, 'performance_validated': False,
                         'historical_unconfirmed_attempts': 0, 'historical_join_proven': True,
                         'snapshot_exports': [{'synthetic': True}] if spec['kind'] in ('put', 'repair') else [],
                         'gc': None, 'files': files, 'owned_commands': commands, 'namespace_unlink': None}
                if spec['kind'] == 'evict':
                    obj = {'client_namespace': '00000000-0000-0000-0000-000000000001', 'inode_decimal': '42',
                           'incarnation': '00000000-0000-0000-0000-000000000002', 'birth': '00000000-0000-0000-0000-000000000003'}
                    value['object'] = obj
                    value['namespace_unlink'] = obj | {'schema': 1, 'kind': 'ec_file_namespace_unlink',
                        'namespace_unlink_acknowledged': True, 'revalidated': True, 'network_io_performed': True,
                        'physical_capacity_returned': False, 'namespace_deleted': False, 'failure': None,
                        'path': '/ec-lab/kv-' + plan['trace_id'] + '-' + spec['instance'],
                        'request': '00000000-0000-0000-0000-000000000004'}
                    cost = step['model']['required_confirmed_gc_allocation_bytes_decimal']
                    value['gc'] = {'confirmed_allocation_model_bytes_decimal': cost, 'completion': {'state': 'confirmed',
                        'completion_scope': 'exact_expected_published_revisions_and_allocations', 'capacity_returned': False,
                        'namespace_deleted': False, 'unpublished_outputs_covered': False, 'allocations_confirmed': int(cost)//11469}}
                save(folder / 'spec.json', spec); save(folder / 'completion.json', value)
                row = {'schema': 1, 'plan_sha256': entry.digest(plan), 'name': name, 'receipt_sha256': entry.digest(value),
                       'receipt_path': str(folder / 'completion.json'), 'model_after': step['model']['after']}
                save(run / 'confirmed' / (name + '.json'), row); rows.append(row); values.append(value)
            result = {'schema': 1, 'kind': 'bounded_native_kv_replay_result', 'state': 'confirmed',
                      'plan_sha256': entry.digest(plan), 'actions_confirmed': 12, 'summary': plan['summary'],
                      'claims': plan['claims'], 'source_binding': plan['source_binding'], 'confirmed_actions_sha256': entry.digest(rows)}
            save(run / 'completion.json', result)
            return run, plan, values, save
        finally:
            sys.path[:] = saved_path
            for name, value in saved.items():
                if value is None: sys.modules.pop(name, None)
                else: sys.modules[name] = value

    def test_native_kv_recipe_revalidates_exact_counts_files_and_original_action_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); run, plan, values, save = self.replay_fixture(root)
            proof = lab.require_kv_replay_result(root, None)
            self.assertEqual((proof['actions'], proof['misses'], proof['hits'], proof['repairs']), (12, 4, 2, 2))
            self.assertFalse(proof['performance_validated']); self.assertFalse(proof['physical_capacity_returned'])
            self.assertEqual(lab.require_kv_replay_result(root, None), proof)
            result = lab.read_json(run / 'completion.json')
            for changes in ({'actions_confirmed': 11}, {'state': 'partial'}, {'plan_sha256': '0' * 64},
                            {'claims': dict(result['claims'], performance_result=True)}):
                save(run / 'completion.json', dict(result, **changes))
                with self.assertRaises((lab.GateError, ValueError)): lab.require_kv_replay_result(root, None)
            save(run / 'completion.json', result)
            first = run / 'native/actions' / plan['steps'][0]['name'] / 'completion.json'
            changed = copy.deepcopy(values[0]); changed['historical_unconfirmed_attempts'] = 1; changed['historical_join_proven'] = False
            save(first, changed)
            with self.assertRaisesRegex(lab.GateError, 'unconfirmed historical'): lab.require_kv_replay_result(root, None)
            save(first, values[0])
            file = Path(next(iter(values[0]['files']))); file.write_bytes(b'changed')
            with self.assertRaisesRegex(lab.GateError, 'evidence changed'): lab.require_kv_replay_result(root, None)

    def test_native_kv_local_commands_never_claim_rdma_or_change_exact_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); run, plan, values, _ = self.replay_fixture(root)
            step = next(row for row in plan['steps'] if row['spec']['kind'] == 'put')
            value = next(row for row in values if row['name'] == step['name'])
            commands = copy.deepcopy(value['owned_commands'])
            for row in commands:
                row['argv'].insert(-1, '--config.storage_transport=rdma')
                if 'kind' not in row: row['transport'] = {'configuration_only': True}
            with mock.patch.object(lab, 'validate_command_transports') as data_gate:
                data, local = lab.kv_replay_command_gate(root, run, step, commands, {'mode': 'rdma'})
                self.assertEqual(local, 1)
                self.assertEqual(len(data_gate.call_args.args[2]), data)
                self.assertTrue(all('kind' not in row for row in data_gate.call_args.args[2]))
            exported = next(row for row in commands if row.get('kind') == 'local_read_export')
            exported['transport'] = {'mode': 'rdma'}
            with self.assertRaisesRegex(lab.GateError, 'data or GC authority'):
                lab.kv_replay_command_gate(root, run, step, commands, {'mode': 'rdma'})
            step = next(row for row in plan['steps'] if row['spec']['kind'] == 'evict')
            commands = copy.deepcopy(next(row for row in values if row['name'] == step['name'])['owned_commands'])
            unlink = next(row for row in commands if row.get('kind') == 'namespace_control')
            unlink['transport'] = {'mode': 'rdma'}
            with self.assertRaisesRegex(lab.GateError, 'data authority'):
                lab.kv_replay_command_gate(root, run, step, commands, None)
            del unlink['transport']
            collector = next(row for row in commands if row.get('kind') == 'tree_gc_collector')
            collector['argv'][7] = str(run / 'other-collector')
            with self.assertRaisesRegex(lab.GateError, 'original run'):
                lab.kv_replay_command_gate(root, run, step, commands, None)

    def test_flat_direct_gate_rejects_other_delivery_missing_commands_and_unjoined_children(self):
        # Synthetic receipt checks only; the runtime also parses native journals
        # and rereads the real output after this gate.
        root = Path('/private/lab')
        stem = 'hosted-kv112-helper-two-direct'
        sequence = (('new-write', 'write'), ('new-repair', 'repair'), ('release', 'repair'),
                    ('new-read', 'read'), ('release', 'read'))
        value = {'schema': 1, 'state': 'passed', 'error': None,
                 'all_started_cli_processes_exited': True, 'interruption_requests': 0,
                 'commands': [{'index': index, 'command': command,
                    'run_dir': str(root / 'client/runs' / (kind + '-' + stem)),
                    'process_started': True, 'process_exited': True, 'interrupted': False, 'returncode': 0}
                    for index, (command, kind) in enumerate(sequence)],
                 'checks': [{'case': stem, 'strategy': 'helper', 'delivery': 'direct', 'replacement_count': 2,
                    'fault_injected': False, 'repair_pin_released': True,
                    'readback': {'byte_equal': True, 'remote_released': True}}]}
        self.assertEqual(lab.require_flat_direct_result(value, root), stem)
        for changes in ({'schema': True}, {'state': 'failed'}, {'error': 'actual failure'},
                        {'all_started_cli_processes_exited': False}, {'interruption_requests': 1},
                        {'interruption_requests': False}, {'commands': value['commands'][:-1]}, {'checks': []}):
            with self.subTest(changes=changes), self.assertRaises(lab.GateError):
                lab.require_flat_direct_result(dict(value, **changes), root)
        for changes in ({'index': True}, {'command': 'resume'}, {'run_dir': str(root / 'another')},
                        {'process_started': False}, {'process_exited': False}, {'interrupted': True},
                        {'returncode': 1}, {'returncode': False}):
            bad = copy.deepcopy(value)
            bad['commands'][1].update(changes)
            with self.subTest(command_changes=changes), self.assertRaises(lab.GateError):
                lab.require_flat_direct_result(bad, root)
        for changes in ({'case': 'other'}, {'strategy': 'central'}, {'delivery': 'return'},
                        {'replacement_count': 1}, {'fault_injected': True}, {'repair_pin_released': False},
                        {'readback': {'byte_equal': False, 'remote_released': True}},
                        {'readback': {'byte_equal': True, 'remote_released': False}}):
            bad = copy.deepcopy(value)
            bad['checks'][0].update(changes)
            with self.subTest(check_changes=changes), self.assertRaises(lab.GateError):
                lab.require_flat_direct_result(bad, root)

    def test_core_gate_accepts_current_exact_29_and_rejects_stale_failed_or_incomplete_evidence(self):
        # Synthetic private receipts/files exercise the actual parsers and
        # validators. No ELF, FDB process or acceptance workload is executed.
        source = Path(__file__).resolve().parents[3]
        core = lab.module(source / 'scripts/ec/ci/run-core-tests.py', 'core_gate_fixture')
        common = lab.module(source / 'scripts/ec/test-native-fragments.py', 'core_gate_common_fixture')
        self.assertEqual((len(core.META_CASES), len(core.FUSE_CASES)), (14, 15))
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            build, fdb, output = parent / 'build', parent / 'fdb', parent / 'acceptance'
            (build / 'tests').mkdir(parents=True)
            fdb.mkdir()
            for path in (build / 'tests/test_meta', build / 'tests/test_fuse_ec', fdb / 'fdbcli', fdb / 'fdbserver'):
                path.write_bytes(b'synthetic non-executable receipt fixture\n')

            def xml(path, names, failed=False):
                root = ET.Element('testsuites', tests=str(len(names)), failures=str(int(failed)), errors='0')
                suite = ET.SubElement(root, 'testsuite')
                for index, name in enumerate(names):
                    classname, method = name.rsplit('.', 1)
                    case = ET.SubElement(suite, 'testcase', classname=classname, name=method,
                                         status='run', result='completed')
                    if failed and index == 0:
                        ET.SubElement(case, 'failure').text = 'synthetic failure'
                ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)

            def listing(path, names):
                lines, previous = [], None
                for name in names:
                    suite, method = name.rsplit('.', 1)
                    if suite != previous:
                        lines.append(suite + '.')
                        previous = suite
                    lines.append('  ' + method)
                path.write_text('\n'.join(lines) + '\n', encoding='utf-8')

            record = {'status': 'passed', 'exitcode': 0, 'passed_tests': 29, 'failures': [], 'signals': [],
                      'source': str(source), 'build': str(build), 'work': str(output),
                      'runner_sha256': lab.sha(source / 'scripts/ec/ci/run-core-tests.py'),
                      'helpers_sha256': {name: lab.sha(source / 'scripts/ec' / name)
                                         for name in ('test-meta-catalog.py', 'test-native-fragments.py')}}
            for name, cases, binary, log in (('meta', core.META_CASES, 'test_meta', 'test-list.log'),
                                             ('fuse', core.FUSE_CASES, 'test_fuse_ec', 'list.log')):
                folder = output / name
                folder.mkdir(parents=True)
                xml(folder / 'tests.xml', cases)
                listing(folder / log, cases)
                record[name] = {'status': 'passed', 'passed_tests': len(cases), 'skipped_tests': 0,
                                'xml_sha256': lab.sha(folder / 'tests.xml'),
                                'listing_sha256': lab.sha(folder / log),
                                'binary_sha256': lab.sha(build / 'tests' / binary)}
            meta = {'status': 'passed', 'exitcode': 0, 'bootstrap': 'passed', 'failures': [],
                    'selected': list(core.META_CASES), 'passed_tests': len(core.META_CASES),
                    'test_results': common.xml_tests(output / 'meta/tests.xml'),
                    'commands': [{'argv': [str(build / 'tests/test_meta'), *core.flags(core.META_FILTER), *ending],
                                  'exitcode': 0} for ending in (['--gtest_list_tests'],
                                      ['--gtest_output=xml:' + str(output / 'meta/tests.xml')])],
                    'server': {'exitcode_before_cleanup': None, 'exitcode_after_cleanup': -15,
                               'cleanup': {'leader_reaped': True}},
                    'binaries': {name: {'path': str(path), 'sha256': lab.sha(path), 'sha256_after': lab.sha(path)}
                                 for name, path in (('test_meta', build / 'tests/test_meta'),
                                                    ('fdbserver', fdb / 'fdbserver'), ('fdbcli', fdb / 'fdbcli'))}}
            (output / 'meta/results.json').write_text(json.dumps(meta), encoding='utf-8')
            record['meta']['receipt_sha256'] = lab.sha(output / 'meta/results.json')
            record['fuse'].update(listing={'exitcode': 0}, execution={'exitcode': 0})
            path = output / 'results.json'

            def check(value):
                path.write_text(json.dumps(value), encoding='utf-8')
                return lab.core_gate(source, build, fdb, path)

            accepted = check(record)
            self.assertEqual(accepted['passed_tests'], 29)
            self.assertEqual(accepted['binaries']['test_meta'], lab.sha(build / 'tests/test_meta'))
            for update in ({'passed_tests': 21}, {'passed_tests': 26}, {'status': 'failed'}, {'exitcode': 1}, {'failures': ['synthetic']}):
                with self.subTest(update=update), self.assertRaises(ValueError):
                    check(dict(record, **update))
            for names, failed in ((core.META_CASES, True), (core.META_CASES[:-1], False)):
                xml(output / 'meta/tests.xml', names, failed)
                bad = copy.deepcopy(record)
                bad['meta']['xml_sha256'] = lab.sha(output / 'meta/tests.xml')
                with self.subTest(xml_names=len(names), failed=failed), self.assertRaises(ValueError):
                    check(bad)
            xml(output / 'meta/tests.xml', core.META_CASES)
            listing(output / 'fuse/list.log', core.FUSE_CASES[:-1])
            bad = copy.deepcopy(record)
            bad['fuse']['listing_sha256'] = lab.sha(output / 'fuse/list.log')
            with self.assertRaises(ValueError):
                check(bad)
            listing(output / 'fuse/list.log', core.FUSE_CASES)
            (build / 'tests/test_meta').write_bytes(b'changed synthetic binary')
            with self.assertRaises(ValueError):
                check(record)

    def test_ec_failure_markers_keep_order_and_reject_unknown_or_partial_fields(self):
        raw = (b'private prefix EC_FILE_MOUNT_FAILURE operation=truncate stage=guard code=100 '
               b'debt=1 retained_reader=0 local_join_unconfirmed=0 exception=0\n'
               b'EC_FILE_CALLBACK_FAILURE operation=setattr stage=truncate code=100 exception=0\n'
               b'EC_FILE_CALLBACK_FAILURE operation=flush stage=recover code=101 exception=1\n')
        rows = lab.ec_failure_markers(raw)
        self.assertEqual([row['layer'] for row in rows], ['mount', 'callback', 'callback'])
        self.assertTrue(rows[0]['debt'])
        self.assertEqual(rows[1]['stage'], 'truncate')
        self.assertTrue(rows[2]['exception'])
        for changed in (raw.replace(b'code=100', b'code=9999999999'),
                        raw.replace(b'stage=guard', b'stage=private_secret'),
                        raw.replace(b'debt=1', b'debt=true')):
            self.assertFalse(any(row['layer'] == 'mount' for row in lab.ec_failure_markers(changed)))
        self.assertEqual(lab.ec_failure_markers(raw.splitlines()[1]), [])
        self.assertEqual(len(lab.ec_failure_markers(raw * 10)), 8)
        self.assertNotIn('private', json.dumps(rows))

    def test_probe_failure_and_close_are_distinct_and_sink_text_stays_private(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            work = parent / 'mode4'
            work.mkdir()
            receipt = {'commands': [{'name': 'posix-prepare', 'sequence': 7, 'exitcode': 1, 'joined': True}]}
            (work / 'result.json').write_text(json.dumps(receipt), encoding='utf-8')
            rows = [dict(operation='open_append', state='operation_failed', expected_failure=True,
                         failure_source='syscall', error_type='OSError', errno=errno.EOPNOTSUPP),
                    dict(operation='ftruncate', state='operation_entered'),
                    dict(operation='ftruncate', state='operation_failed', failure_source='syscall',
                         expected_failure=False, error_type='OSError', errno=5),
                    dict(operation='close', state='operation_entered'),
                    dict(operation='close', state='operation_failed', failure_source='syscall',
                         expected_failure=False, secondary=True, error_type='OSError', errno=6)]
            (work / 'posix-prepare.jsonl').write_text('\n'.join(map(json.dumps, rows)), encoding='utf-8')
            sink = {'operation': 'ftruncate', 'state': 'operation_confirmed',
                    'evidence_error_type': 'OSError', 'evidence_errno': 28, 'token': 'SECRET'}
            path = work / '007-posix-prepare.stderr'
            path.write_text('PRIVATE traceback\nMODE4_PROBE_EVIDENCE_FAILURE ' + json.dumps(sink) + '\n', encoding='utf-8')
            summary = lab.failure_evidence(parent, {'failure_phase': 'mode4-lifecycle'})['probes'][0]
            self.assertEqual(summary['first_failed_operation'], 'ftruncate')
            self.assertEqual(summary['errno'], 5)
            self.assertEqual(summary['secondary_close_error'], {'error_type': 'OSError', 'errno': 6})
            self.assertEqual(summary['last_entered_operation'], 'close')
            self.assertEqual(summary['evidence_sink']['failures'][0]['evidence_errno'], 28)
            for forbidden in ('SECRET', 'PRIVATE', str(parent)):
                self.assertNotIn(forbidden, json.dumps(summary))
            path.write_bytes(b'x' * 16384 + b'MODE4_PROBE_EVIDENCE_FAILURE ' + json.dumps(sink).encode() + b'\n')
            self.assertEqual(lab.probe_sink_summary(path)['failures'], [])
            self.assertTrue(lab.probe_sink_summary(path)['truncated'])
            for sequence in (True, 0, 4097, '../secret'):
                receipt['commands'][0]['sequence'] = sequence
                (work / 'result.json').write_text(json.dumps(receipt), encoding='utf-8')
                with mock.patch.object(lab, 'probe_sink_summary') as read:
                    lab.failure_evidence(parent, {'failure_phase': 'mode4-lifecycle'})
                    read.assert_not_called()

    def test_actual_lifecycle_preflight_failure_is_observed_without_a_result_receipt(self):
        spec = importlib.util.spec_from_file_location(
            'lifecycle_preflight_under_test', Path(__file__).parents[1] / 'cluster/mode4-lifecycle-acceptance.py')
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            stderr = io.StringIO()
            with mock.patch.object(lifecycle, 'preflight', side_effect=ValueError('fusermount3 is required')), \
                    mock.patch.object(lifecycle, 'run_sequence') as run, redirect_stderr(stderr):
                result = lifecycle.main(['--root', str(parent / 'lab'), '--preparation', str(parent / 'prep'),
                                         '--work', str(parent / 'mode4')])
            self.assertEqual(result, 2)
            run.assert_not_called()
            self.assertFalse((parent / 'mode4').exists())
            runtime = parent / 'runtime'
            runtime.mkdir()
            log = runtime / '007-mode4-lifecycle.stderr'
            log.write_text(stderr.getvalue(), encoding='utf-8')
            before_log = log.read_bytes()
            report = {'failure_phase': 'mode4-lifecycle', 'failed_command':
                      {'phase': 'mode4-lifecycle', 'returncode': 2, 'sequence': 7}, 'exitcode': 1}
            before_report = copy.deepcopy(report)
            summary = lab.failure_evidence(parent, report)
            self.assertEqual(summary['lifecycle_preflight']['code'], 'unmount_tool_missing')
            self.assertTrue(summary['lifecycle_preflight']['single_preflight_message_observed'])
            self.assertEqual(summary['lifecycle']['source']['availability'], 'unavailable')
            self.assertEqual(summary['lifecycle']['subphase'], 'unknown')
            self.assertEqual(log.read_bytes(), before_log)
            self.assertEqual(report, before_report)

    def test_preflight_message_is_bounded_exact_and_never_echoes_private_text(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / 'child.stderr'
            prefix = 'mode4 lifecycle preflight failed: '
            cases = [(prefix + 'prepared config changed\n', 'prepared_config_changed'),
                     (prefix + 'PRIVATE_TOKEN=/private/file\n', 'unclassified_private_preflight_error'),
                     (prefix + 'prepared config changed PRIVATE_TOKEN\n', 'unclassified_private_preflight_error'),
                     ('PRIVATE_TOKEN\n' + prefix + 'prepared config changed\n', 'unknown')]
            for value, expected in cases:
                path.write_text(value, encoding='utf-8')
                summary = lab.lifecycle_preflight_summary(path)
                self.assertEqual(summary['code'], expected)
                self.assertNotIn('PRIVATE_TOKEN', json.dumps(summary))
                self.assertNotIn(str(path), json.dumps(summary))
            for raw in (b'x' * 16385, b'\xff'):
                path.write_bytes(raw)
                self.assertEqual(lab.lifecycle_preflight_summary(path)['availability'], 'unavailable')
            path.write_bytes(b'small')
            os.link(path, path.with_suffix('.second'))
            self.assertEqual(lab.lifecycle_preflight_summary(path)['availability'], 'unavailable')
            self.assertEqual(lab.lifecycle_preflight_summary(path.with_suffix('.missing'))['availability'], 'unavailable')

    def test_preflight_log_is_selected_only_by_failed_owned_command_ordinal(self):
        base = {'failure_phase': 'mode4-lifecycle', 'failed_command':
                {'phase': 'mode4-lifecycle', 'returncode': 2, 'sequence': 7, 'path': '/private/arbitrary'}}
        variants = [('sequence', True), ('sequence', 0), ('sequence', 4097), ('sequence', '../other'),
                    ('returncode', 1), ('returncode', True), ('phase', 'cli-basic')]
        with mock.patch.object(lab, 'diagnostic_file', return_value=(None, {'availability': 'unavailable'})), \
                mock.patch.object(lab, 'fuse_log_summary', return_value={'availability': 'unavailable'}), \
                mock.patch.object(lab, 'lifecycle_preflight_summary', return_value={'availability': 'read'}) as read:
            for key, value in variants:
                report = copy.deepcopy(base)
                report['failed_command'][key] = value
                self.assertNotIn('lifecycle_preflight', lab.failure_evidence(Path('/fixed'), report))
            read.assert_not_called()
            lab.failure_evidence(Path('/fixed'), base)
            read.assert_called_once_with(Path('/fixed/runtime/007-mode4-lifecycle.stderr'))

    def test_first_business_failure_survives_cleanup_exception(self):
        report = {}
        with mock.patch.object(lab, 'PHASE', 'mode4-lifecycle'):
            lab.remember_failure(report, ValueError('private business detail'))
            lab.phase('cleanup')
            lab.remember_failure(report, OSError(5, 'private cleanup detail'))
        self.assertEqual(report['failure_phase'], 'mode4-lifecycle')
        self.assertEqual(report['first_failure'], {'phase': 'mode4-lifecycle', 'error_type': 'ValueError'})

    def test_lifecycle_diagnostic_distinguishes_stages_without_authorizing_cleanup(self):
        cases = [
            ({'mounts': [{'phase': 'prepare', 'ready': False}]}, 'first-mount-readiness'),
            ({'mounts': [{'phase': 'prepare', 'ready': True}, {'phase': 'verify', 'ready': False}]}, 'remount-readiness'),
            ({'commands': [{'name': 'posix-prepare', 'exitcode': 1, 'joined': True},
                           {'name': 'unmount-prepare', 'exitcode': 1, 'joined': True}],
              'errors': ['ValueError: posix-prepare failed, timed out or has an unknown join']}, 'posix-prepare'),
            ({'commands': [{'name': 'usrbio-verify', 'exitcode': 1, 'joined': True}]}, 'usrbio-verify'),
            ({'errors': ['ValueError: normal unmount and successful FUSE join are required before continuing']},
             'unmount-or-join'),
            ({'errors': ['ValueError: USRBIO receipt did not confirm this file and the actual ABI']}, 'receipt-verification'),
            ({'errors': ['ValueError: first-start to remount-ready crossed the locked configured session timeout']},
             'remount-session-window')]
        for fields, expected in cases:
            with self.subTest(expected=expected):
                receipt = dict(passed_mount(), **fields, status='failed', exitcode=1)
                before = copy.deepcopy(receipt)
                summary = lab.lifecycle_summary(receipt)
                self.assertEqual(summary['subphase'], expected)
                self.assertEqual(receipt, before)
                with self.assertRaises(lab.GateError):
                    lab.require_mount_result(receipt)
        self.assertEqual(lab.lifecycle_summary({})['cleanup'], {})
        self.assertEqual(lab.lifecycle_summary({'cleanup': {'unmounted': False}})['cleanup'], {'unmounted': False})

    def test_private_receipts_expose_only_bounded_failure_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            work = parent / 'mode4'
            work.mkdir()
            secret = 'PRIVATE_TOKEN_AND_PATH_' * 64
            value = dict(passed_mount(), status='failed', exitcode=1,
                         errors=['ValueError: posix-prepare failed, timed out or has an unknown join'],
                         commands=[{'name': 'posix-prepare', 'exitcode': 1, 'joined': True, 'argv': [secret]}],
                         mounts=[{'phase': 'prepare', 'ready': True, 'joined': True, 'exitcode': 0,
                                  'normal_unmount': True, 'cleanup_error': 'OSError: [Errno 5] ' + secret}],
                         config={'token': secret})
            (work / 'result.json').write_text(json.dumps(value), encoding='utf-8')
            events = [{'operation': 'pwrite', 'state': 'operation_confirmed', 'file': secret, 'payload': secret},
                      {'operation': 'probe', 'state': 'unconfirmed', 'error': 'OSError: [Errno 5] ' + secret}]
            (work / 'posix-prepare.jsonl').write_text('\n'.join(map(json.dumps, events)), encoding='utf-8')
            (work / 'usrbio-prepare').mkdir()
            (work / 'usrbio-prepare/result.json').write_text(json.dumps(
                {'state': 'unconfirmed', 'error': 'ValueError: ' + secret, 'driver_argv': [secret]}), encoding='utf-8')
            before = {p: p.read_bytes() for p in work.rglob('*') if p.is_file()}
            report = {'failure_phase': 'mode4-lifecycle',
                      'first_failure': {'phase': 'mode4-lifecycle', 'error_type': 'ValueError'},
                      'supervisor_exitcode': 0, 'cleanup_blocked': False}
            output = io.StringIO()
            with redirect_stdout(output):
                lab.emit_failure_evidence(parent, report, 'after-native-cleanup')
            raw = output.getvalue()
            self.assertLess(len(raw), 24576 + 64)
            self.assertNotIn('PRIVATE_TOKEN', raw)
            self.assertNotIn(str(parent), raw)
            summary = json.loads(raw.removeprefix('FILE_LAB_FAILURE '))
            self.assertEqual(summary['lifecycle']['subphase'], 'posix-prepare')
            self.assertEqual(summary['probes'][0]['error'], {'code': 'os_error', 'error_type': 'OSError', 'errno': 5})
            self.assertEqual(summary['probes'][0]['recent_confirmed_operations'], ['pwrite'])
            self.assertEqual(summary['probes'][2]['source']['availability'], 'unavailable')
            self.assertTrue(summary['observations_only_not_acceptance'])
            self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_fuse_log_sampling_extracts_static_status_without_leaking_config(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / 'fuse.log'
            secret = b'SECRET_CONFIG_TOKEN=/private/key'
            head = b'Start to init fuse clients\nFull Config:\n' + secret + b'\n'
            head += b'Try to establish client session failed: Mgmtd::ExtendClientSessionMismatch(5014) ' + secret + b'\n'
            tail = b'Init application failed: kInvalidArg(13) ' + secret + b'\n'
            raw = head + b'x' * (128 << 10) + tail
            path.write_bytes(raw)
            summary = lab.fuse_log_summary(path)
            self.assertEqual(summary['events'], [{'event': 'client_session_failed', 'status_code': 5014},
                                                  {'event': 'application_init_failed', 'status_code': 13}])
            self.assertEqual(summary['progress_markers'], ['client_initialization_entered'])
            self.assertTrue(summary['omitted_middle'])
            self.assertEqual(summary['sampled_bytes'], 65536)
            for forbidden in ('SECRET', 'Mgmtd', 'ExtendClientSessionMismatch', 'kInvalidArg', str(path), 'Full Config'):
                self.assertNotIn(forbidden, json.dumps(summary))
            self.assertEqual(path.read_bytes(), raw)
            path.write_bytes(b'Init application failed: SecretName(9999999999) hidden\n')
            self.assertEqual(lab.fuse_log_summary(path)['events'], [])

    def test_diagnostic_inputs_reject_missing_malformed_oversized_and_linked_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / 'result.json'
            self.assertIsNone(lab.diagnostic_file(path)[0])
            for text in ('{"token":1,"token":2}', '[]', '{"x":NaN}', 'x' * (lab.DIAGNOSTIC_LIMIT + 1)):
                path.write_text(text, encoding='utf-8')
                value, source = lab.diagnostic_file(path)
                self.assertIsNone(value)
                self.assertEqual(source['availability'], 'unavailable')
            path.write_text('{"exitcode":1}', encoding='utf-8')
            os.link(path, path.with_name('alias.json'))
            self.assertIsNone(lab.diagnostic_file(path)[0])
            self.assertEqual(lab.fuse_log_summary(path)['availability'], 'unavailable')

    def test_diagnostic_failure_cannot_mask_business_failure_or_scan_other_phase(self):
        with mock.patch.object(lab, 'failure_evidence', side_effect=OSError('private failure')), \
             mock.patch('builtins.print', side_effect=BrokenPipeError('private output failure')):
            lab.emit_failure_evidence(Path('/not-read'), {}, 'after-native-cleanup')
        with mock.patch.object(lab, 'diagnostic_file') as read, mock.patch.object(lab, 'fuse_log_summary') as logs:
            summary = lab.failure_evidence(Path('/not-read'), {'failure_phase': 'cli-basic'})
            self.assertNotIn('lifecycle', summary)
            read.assert_not_called()
            logs.assert_not_called()
            report = {'failure_phase': 'cli-basic', 'final_supervisor_observation': {'stage': 'stopped'}}
            self.assertNotIn('supervisor_reported_failure', lab.failure_evidence(Path('/not-read'), report)['cleanup'])
            report['final_supervisor_observation']['failure'] = None
            self.assertIs(lab.failure_evidence(Path('/not-read'), report)['cleanup']['supervisor_reported_failure'], False)
            report['final_supervisor_observation']['failure'] = 'private failure detail'
            observed = lab.failure_evidence(Path('/not-read'), report)
            self.assertIs(observed['cleanup']['supervisor_reported_failure'], True)
            self.assertNotIn('private failure detail', json.dumps(observed))

    def test_local_identity_requires_same_nonroot_user_and_binds_distinct_gid(self):
        request = {'execution_mode': 'local-same-user', 'creator_uid': 1234,
                   'target_uid': 1234, 'target_gid': 2345}
        lab.local_identity(request, 1234, 1234, 2345, 2345)
        for ids in ((0, 0, 0, 0), (1234, 0, 2345, 2345), (1234, 1234, 2345, 0)):
            with self.subTest(ids=ids), self.assertRaises(lab.GateError):
                lab.local_identity(request, *ids)
        for changes in ({'creator_uid': 1001}, {'target_uid': 1000}, {'target_gid': 1234},
                        {'target_uid': True}, {'execution_mode': 'hosted-handoff'}):
            with self.subTest(changes=changes), self.assertRaises(lab.GateError):
                lab.local_identity(dict(request, **changes), 1234, 1234, 2345, 2345)

    def test_local_root_remains_bound_to_prepared_inode_and_actual_owner(self):
        parent = Path('/private/file-case')
        request = {'schema': 1, 'parent': str(parent), 'parent_identity': [4, 20],
                   'execution_mode': 'local-same-user', 'creator_uid': 1234,
                   'target_uid': 1234, 'target_gid': 2345}
        with mock.patch.object(lab.os, 'getuid', return_value=1234, create=True), \
             mock.patch.object(lab.os, 'geteuid', return_value=1234, create=True), \
             mock.patch.object(lab.os, 'getgid', return_value=2345, create=True), \
             mock.patch.object(lab.os, 'getegid', return_value=2345, create=True), \
             mock.patch.object(lab, 'private') as private, \
             mock.patch.object(Path, 'stat', return_value=mock.Mock(st_dev=4, st_ino=20)):
            lab.local_shape(parent, request)
            private.assert_has_calls([mock.call(parent, 1234), mock.call(parent.parent, 1234)])
            for changes in ({'parent_identity': [4, 21]}, {'parent_identity': [5, 20]},
                            {'parent': '/other'}, {'schema': True}, {'target_gid': 1000}):
                with self.subTest(changes=changes), self.assertRaises(lab.GateError):
                    lab.local_shape(parent, dict(request, **changes))

    def test_formal_build_requires_matching_revision_backend_and_all_eight_targets(self):
        built = {'schema': 1, 'source': str(Path('/source')), 'build': str(Path('/build')), 'revision': 'revision',
                 'backend': 'isal', 'isal': {'provider': {'path': '/private/libisal.so.2',
                 'sha256': '40ccd5e5abaff0451feff750d2b011370a546ac4706d1b06b9285ac26eda2c3c'}},
                 'acceptance_executed': False, 'targets': list(lab.TARGETS),
                 'binaries': {name: 'a' * 64 for name in lab.TARGETS},
                 'build_script_sha256': 'b' * 64, 'cmake_cache_sha256': 'c' * 64}
        native = dict(copy.deepcopy(built), lab_targets_requested=True)
        lab.build_gate(built, native, Path('/source'), Path('/build'), 'revision')
        for field, changed in (('schema', True), ('source', '/other'), ('build', '/other'),
                               ('revision', 'other'), ('backend', 'scalar'), ('isal', None),
                               ('acceptance_executed', True), ('lab_targets_requested', False),
                               ('binaries', {}), ('build_script_sha256', 'd' * 64),
                               ('cmake_cache_sha256', 'd' * 64)):
            with self.subTest(field=field), self.assertRaises(lab.GateError):
                lab.build_gate(built, dict(native, **{field: changed}), Path('/source'), Path('/build'), 'revision')
        for changes in ({'targets': list(lab.TARGETS[:-1])}, {'binaries': {}}, {'schema': True}):
            with self.subTest(changes=changes), self.assertRaises(lab.GateError):
                lab.build_gate(dict(built, **changes), native, Path('/source'), Path('/build'), 'revision')
        for backend in ('scalar', 'isal'):
            changed = copy.deepcopy(built)
            changed['backend'] = backend
            changed['isal'] = None if backend == 'scalar' else {'provider': {'sha256': 'd' * 64}}
            if backend == 'scalar':
                lab.build_gate(changed, dict(changed, lab_targets_requested=True), Path('/source'), Path('/build'), 'revision')
            else:
                with self.assertRaises(lab.GateError):
                    lab.build_gate(changed, dict(changed, lab_targets_requested=True), Path('/source'), Path('/build'), 'revision')

    def test_mount_prerequisites_refuse_missing_helper_limits_and_noncharacter_device(self):
        resource = mock.Mock(RLIMIT_NOFILE=1, RLIMIT_MEMLOCK=2, RLIM_INFINITY=-1)
        resource.getrlimit.return_value = (3 << 30, 3 << 30)
        with mock.patch.dict(sys.modules, {'resource': resource}), \
             mock.patch.object(lab.shutil, 'which', return_value=None), \
             mock.patch.object(lab.os, 'open') as opened:
            with self.assertRaisesRegex(lab.GateError, 'fusermount3'):
                lab.mount_host_gate()
            opened.assert_not_called()
            resource.getrlimit.return_value = (65536, 8 << 20)
            with self.assertRaisesRegex(lab.GateError, 'resource limit'):
                lab.mount_host_gate()
            opened.assert_not_called()
        resource.getrlimit.return_value = (-1, -1)
        with tempfile.TemporaryDirectory() as temp:
            tool = Path(temp) / 'fusermount3'
            tool.write_bytes(b'only a prerequisite fixture, never executed')
            # Linux descriptor semantics are mocked here; the real FD tree tests
            # below remain Linux-only and are not replaced by this fixture.
            with mock.patch.dict(sys.modules, {'resource': resource}), \
                 mock.patch.object(lab.shutil, 'which', return_value=str(tool)), \
                 mock.patch.object(lab.os, 'access', return_value=True), \
                 mock.patch.object(lab.os, 'O_NOFOLLOW', 0, create=True), \
                 mock.patch.object(lab.os, 'O_CLOEXEC', 0, create=True), \
                 mock.patch.object(lab.os, 'open', return_value=42) as opened, \
                 mock.patch.object(lab.os, 'close') as closed, \
                 mock.patch.object(lab.os, 'fstat') as info:
                info.return_value.st_mode = stat.S_IFREG
                with self.assertRaisesRegex(lab.GateError, 'character device'):
                    lab.mount_host_gate()
                closed.assert_called_once_with(42)
                closed.reset_mock()
                info.return_value.st_mode = stat.S_IFCHR
                result = lab.mount_host_gate()
                self.assertTrue(result['device_opened'])
                self.assertFalse(result['mount_permission_proven'])
                self.assertEqual(result['sha256'], hashlib.sha256(tool.read_bytes()).hexdigest())
                self.assertEqual(opened.call_count, 2)
                closed.assert_called_once_with(42)

    def test_loader_checks_copied_provider_paths_and_real_fuse_dependency(self):
        root = Path('/private/lab')
        isal = 'libisal.so.2 => ' + str(root / 'lib/libisal.so.2') + ' (0xabc)\n'
        fuse = 'libfuse3.so.3 => ' + str(root / 'lib/libfuse3.so.3') + ' (0xdef)\n'
        fdb = 'libfdb_c.so => ' + str(root / 'lib/libfdb_c.so') + ' (0x123)\n'
        self.assertEqual(set(lab.resolution_gate('isal', isal + fuse + fdb, root, fuse=True)),
                         {'libisal.so.2', 'libfuse3.so.3', 'libfdb_c.so'})
        lab.resolution_gate('scalar', fuse + fdb, root, fuse=True)
        for text in (isal, fuse, isal + fuse + 'libx.so => not found\n', isal + isal + fuse,
                     isal + fuse.replace(str(root / 'lib/libfuse3.so.3'), '/other/libfuse3.so.3'),
                     isal.replace(str(root / 'lib/libisal.so.2'), '/other/libisal.so.2') + fuse):
            with self.subTest(text=text), self.assertRaises(lab.GateError):
                lab.resolution_gate('isal', text, root, fuse=True)
        with self.assertRaises(lab.GateError):
            lab.resolution_gate('scalar', isal + fuse, root, fuse=True)

    def test_shutdown_accepts_only_normal_fdb_zero_or_sigterm(self):
        final = {'run': 'fixed-run', 'stage': 'stopped', 'failure': None}
        for fdb_code in (0, -15):
            with self.subTest(fdb_code=fdb_code):
                cleanup = {'clean': True, 'exit_codes': dict.fromkeys(lab.SERVICE_NAMES, 0)}
                cleanup['exit_codes']['fdb'] = fdb_code
                lab.require_shutdown(final, cleanup, 'fixed-run', 0)

    def test_shutdown_rejects_invalid_codes_names_and_unknown_join(self):
        final = {'run': 'fixed-run', 'stage': 'stopped', 'failure': None}
        valid = {'clean': True, 'exit_codes': dict.fromkeys(lab.SERVICE_NAMES, 0)}
        invalid = []
        for name in sorted(lab.SERVICE_NAMES):
            for code in (None, False, True, '0', 0.0, -9, 1):
                bad = copy.deepcopy(valid)
                bad['exit_codes'][name] = code
                invalid.append(bad)
            if name != 'fdb':
                bad = copy.deepcopy(valid)
                bad['exit_codes'][name] = -15
                invalid.append(bad)
            bad = copy.deepcopy(valid)
            del bad['exit_codes'][name]
            invalid.append(bad)
        extra = copy.deepcopy(valid)
        extra['exit_codes']['other'] = 0
        invalid.extend((extra, {'clean': True}, {'clean': True, 'exit_codes': []},
                        dict(valid, clean=False), dict(valid, clean=1)))
        for bad in invalid:
            with self.subTest(cleanup=bad):
                with self.assertRaises(lab.GateError):
                    lab.require_shutdown(final, bad, 'fixed-run', 0)

    def test_shutdown_still_requires_same_run_stopped_and_successful_supervisor(self):
        final = {'run': 'fixed-run', 'stage': 'stopped', 'failure': None}
        cleanup = {'clean': True, 'exit_codes': dict.fromkeys(lab.SERVICE_NAMES, 0)}
        for update in ({'run': 'other'}, {'stage': 'ready'}, {'failure': 'failed'}):
            with self.subTest(update=update):
                with self.assertRaises(lab.GateError):
                    lab.require_shutdown(dict(final, **update), cleanup, 'fixed-run', 0)
        for missing in final:
            with self.subTest(missing=missing):
                incomplete = {key: value for key, value in final.items() if key != missing}
                with self.assertRaises(lab.GateError):
                    lab.require_shutdown(incomplete, cleanup, 'fixed-run', 0)
        for code in (None, False, True, 0.0, '0', -15, 1):
            with self.subTest(supervisor_code=code):
                with self.assertRaises(lab.GateError):
                    lab.require_shutdown(final, cleanup, 'fixed-run', code)

    def test_terminal_proof_accepts_exact_two_mount_four_probe_result(self):
        lab.require_mount_result(passed_mount())
        self.assertTrue(lab.mount_cleanup_known(passed_mount()))

    def test_unknown_ownership_or_mount_never_authorizes_native_stop(self):
        for key, value in [('all_fuse_joined', False), ('all_commands_joined', False),
                           ('unmounted', False), ('unknown_owned_processes', [{'pid': 42}])]:
            with self.subTest(key=key):
                record = passed_mount()
                record['cleanup'][key] = value
                self.assertFalse(lab.mount_cleanup_known(record))
                with self.assertRaises(ValueError):
                    lab.require_mount_result(record)

    def test_known_cleanup_does_not_turn_failed_business_into_success(self):
        record = passed_mount()
        record.update(status='failed', exitcode=1)
        self.assertTrue(lab.mount_cleanup_known(record))
        with self.assertRaises(ValueError):
            lab.require_mount_result(record)

    def test_probe_omission_duplicate_or_changed_bytes_are_rejected(self):
        for mode in ('missing', 'duplicate', 'bytes', 'inode', 'abi'):
            with self.subTest(mode=mode):
                record = passed_mount()
                if mode == 'missing':
                    record['probes'].pop()
                elif mode == 'duplicate':
                    record['probes'][-1] = copy.deepcopy(record['probes'][0])
                elif mode == 'bytes':
                    record['probes'][-1]['sha256'] = 'b' * 64
                elif mode == 'inode':
                    record['probes'][-1]['inode'] = 100
                else:
                    record['probes'][-1]['actual_abi_reads'] = 2
                with self.assertRaises(ValueError):
                    lab.require_mount_result(record)

    def test_cli_checked_pending_history_is_not_a_failed_final_phase(self):
        record = {'success': True, 'failure': None, 'all_owned_children_joined': True,
                  'steps': [{'checks_complete': True, 'pending': True}, {'checks_complete': True}]}
        lab.require_cli_result(record)
        for changed in ({'success': False}, {'all_owned_children_joined': False}, {'steps': []},
                        {'steps': [{'checks_complete': False}]}):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    lab.require_cli_result(dict(record, **changed))

    def test_handoff_is_bound_to_exact_fixed_root_and_distinct_inventory(self):
        parent = Path('/tmp/ec-h-123-1')
        request = {'schema': 1, 'parent': str(parent), 'creator_uid': 1001, 'target_uid': 1000,
                   'run_id': '123', 'run_attempt': '1', 'inventory': [{'path': '.'}, {'path': 'bin/x'}]}
        lab.handoff_shape(parent, request)
        for changed in ({'target_uid': 0}, {'creator_uid': 0}, {'run_id': '124'}, {'schema': True},
                        {'inventory': [{'path': '.'}, {'path': '../outside'}]},
                        {'inventory': [{'path': '.'}, {'path': '/etc/passwd'}]},
                        {'inventory': [{'path': '.'}, {'path': 'bin/x'}, {'path': 'bin/x'}]}):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    lab.handoff_shape(parent, dict(request, **changed))
        for path in (Path('/etc/ec-h-123-1'), Path('/tmp/ordinary'), Path('/tmp/ec-h-0-1')):
            with self.assertRaises(ValueError):
                lab.handoff_shape(path, dict(request, parent=str(path)))

    def test_json_rejects_duplicate_nonobject_and_nonfinite_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'record.json'
            for text in ('{"ok":true,"ok":false}', '[]', 'null', '{"number":NaN}'):
                path.write_text(text, encoding='utf-8')
                with self.assertRaises(ValueError):
                    lab.read_json(path)
            path.write_text(json.dumps({'ok': True}), encoding='utf-8')
            self.assertEqual(lab.read_json(path), {'ok': True})


class LabTransportGates(unittest.TestCase):
    OPTIONS = ['--transport', 'rdma', '--rdma-interface', 'eth0',
               '--rdma-address', '192.0.2.10', '--rdma-device', 'mlx5_0']

    def setUp(self):
        self.source = Path(__file__).resolve().parents[3]
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / '3fs-ec-native-test'
        self.root.mkdir(mode=0o700)
        for name in ('config', 'client', 'state', 'scripts', 'provenance', 'logs', 'lib', 'bin'):
            (self.root / name).mkdir(mode=0o700)
        for name in ('generate.py', 'native_v2_config.py', 'experiment-runner.py', 'ack-service-acceptance.py'):
            shutil.copyfile(self.source / 'scripts/ec/cluster' / name, self.root / 'scripts' / name)
        original = lab.transport_config

        @contextmanager
        def linux_config(scripts=None):
            with original(scripts) as config:
                # Linux server path generation only; receipt IO stays host-native.
                with mock.patch.object(config, 'Path', PurePosixPath):
                    yield config
        self.enterContext(mock.patch.object(lab, 'transport_config', linux_config))
        self.parser = argparse.ArgumentParser()
        lab.add_transport_arguments(self.parser)
        self.selection = lab.lab_transport_selection(self.parser.parse_args(self.OPTIONS), self.source)

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')

    def profile(self, selection=True):
        with lab.transport_config(self.root / 'scripts') as config:
            gc = {'authority': '22222222-2222-2222-2222-222222222222',
                  'key_id': '33333333-3333-3333-3333-333333333333',
                  'client_namespace': '44444444-4444-4444-4444-444444444444',
                  'data_protocol': 2, 'disk_format': 3, 'gc_protocol': 2}
            options = dict(transport='rdma', rdma_interface='eth0', rdma_address='192.0.2.10', rdma_device='mlx5_0') \
                if selection else {}
            configs, _ = config.generate_configs(self.source, self.root, 20000,
                '11111111-1111-1111-1111-111111111111', 'TRANSPORT_FIXTURE',
                profile='gc', gc=gc, file_api=True, **options)
            for name, value in configs.items():
                folder = 'client' if name in ('file-client.toml', 'stripe-client.toml') else 'config'
                (self.root / folder / name).write_text(config.to_toml(value), encoding='utf-8')
            self.cluster = {'schema': 1, 'root': str(self.root), 'profile': config.GC_PROFILE,
                            'file_api': True, 'gc': gc, 'port_base': 20000, 'cluster_id': 'TRANSPORT_FIXTURE',
                            'authority': '11111111-1111-1111-1111-111111111111'}
        self.initialized = {'schema': 1, 'cluster_id': self.cluster['cluster_id']}
        value = self.selection if selection else None
        if value is not None:
            self.cluster['data_transport'] = copy.deepcopy(value)
            self.initialized['data_transport'] = copy.deepcopy(value)
        self.write(self.root / 'cluster.json', self.cluster)
        self.write(self.root / 'state/initialized.json', self.initialized)
        self.package = {'files': {}, **lab.transport_fields(value)}
        self.package_path = self.root / 'provenance/services-test/manifest.json'
        self.write(self.package_path, self.package)
        self.request = {'package_manifest_sha256': lab.sha(self.package_path), **lab.transport_fields(value)}
        return value

    def command(self, file_api=True):
        with lab.transport_config(self.root / 'scripts'):
            wrapper = lab.module(self.root / 'scripts/experiment-runner.py', 'transport_real_binding')
            config = self.root / 'client' / ('file-client.toml' if file_api else 'stripe-client.toml')
            binding = wrapper.prepared_transport(self.root, config, file_api=file_api)
            run = self.root / 'client/runs' / ('file-case' if file_api else 'stripe-case')
            binary = self.root / 'bin' / ('ec_file_cli' if file_api else 'ec_stripe_cli')
            # Use the real writer once; validators must never repair a missing sidecar.
            wrapper.bind_transport_run(self.root, run, binding, [str(binary)])
            run.mkdir(parents=True)
        row = {'index': 0, 'argv': [str(binary), '--cfg=' + str(config),
                                  '--config.run_dir=' + str(run), '--config.storage_transport=rdma',
                                  'mode4-create' if file_api else 'new-write'],
               'process_started': True, 'process_exited': True, 'returncode': 0, 'transport': binding}
        sidecar = self.root / 'client/transport-bindings' / (hashlib.sha256(str(run).encode()).hexdigest() + '.json')
        return row, sidecar

    def test_prepare_arguments_preserve_tcp_and_reject_owned_overrides_before_source_access(self):
        for argv in ([], ['--transport', 'tcp']):
            args = self.parser.parse_args(argv)
            value = lab.lab_transport_selection(args, self.source)
            self.assertIsNone(value)
            self.assertEqual(lab.transport_cli_args(value), [])
            self.assertEqual(lab.transport_fields(value), {})
        self.assertEqual(lab.transport_cli_args(self.selection), self.OPTIONS)
        for argv in (['--rdma-device', 'mlx5_0'], ['--transport', 'rdma'],
                     ['--transport', 'tcp', '--rdma-address', '192.0.2.10'],
                     self.OPTIONS[:-1] + ['../device']):
            with self.subTest(argv=argv), self.assertRaises(lab.GateError):
                lab.lab_transport_selection(self.parser.parse_args(argv), self.source)
        for internal in ('handoff', 'run_owned'):
            for argv in (['--transport', 'tcp'], self.OPTIONS, ['--rdma-device', 'mlx5_0']):
                args = self.parser.parse_args(argv)
                setattr(args, internal, self.root)
                with self.subTest(internal=internal, argv=argv), mock.patch.object(lab, 'transport_config') as load:
                    with self.assertRaises(lab.GateError):
                        lab.lab_transport_selection(args, None)
                    load.assert_not_called()
            args = self.parser.parse_args([])
            setattr(args, internal, self.root)
            self.assertIsNone(lab.lab_transport_selection(args, None))
        # A caller-supplied source is not imported before the formal-driver gate.
        source, work = self.root / 'untrusted-source', self.root / 'build-work'
        build, fdb = work / 'build', work / 'fdb/bin'
        core = self.root / 'core/result.json'
        for directory in (source, build, fdb, core.parent):
            directory.mkdir(parents=True, exist_ok=True)
        self.write(core, {})
        args = argparse.Namespace(source=source, build=build, fdb_bin_dir=fdb, core_record=core,
                                  local_work=Path(self.temp.name) / 'x')
        with mock.patch.object(lab.os, 'getuid', return_value=1000, create=True), \
             mock.patch.object(lab.os, 'geteuid', return_value=1000, create=True), \
             mock.patch.object(lab.os, 'getgid', return_value=1000, create=True), \
             mock.patch.object(lab.os, 'getegid', return_value=1000, create=True), \
             mock.patch.object(lab, 'private'), mock.patch.object(lab, 'mount_host_gate'), \
             mock.patch.object(lab, 'lab_transport_selection') as load, \
             mock.patch.object(lab.subprocess, 'Popen') as child:
            with self.assertRaisesRegex(lab.GateError, 'checked-out formal driver'):
                lab.prepare(args)
            load.assert_not_called()
            child.assert_not_called()

    def test_request_and_supervisor_receipts_reject_partial_null_and_boolean_substitution(self):
        fields = lab.transport_fields(self.selection)
        self.assertEqual(lab.request_transport(fields), self.selection)
        self.assertIsNone(lab.request_transport({}))
        bad = copy.deepcopy(fields)
        bad['data_transport_requested']['schema'] = True
        for value in (bad, {'data_transport_requested': self.selection},
                      {'transport_validation': 'configuration_only'},
                      dict(fields, data_transport_requested=None), dict(fields, transport_validation='hardware_validated')):
            with self.subTest(value=value), self.assertRaises(lab.GateError):
                lab.request_transport(value)
        lab.require_transport_observation({}, None)
        lab.require_transport_observation({'data_transport': self.selection}, self.selection)
        for value, expected in (({}, self.selection), ({'data_transport': None}, None),
                                ({'data_transport': self.selection}, None),
                                ({'data_transport': dict(self.selection, schema=True)}, self.selection)):
            with self.subTest(value=value), self.assertRaises(lab.GateError):
                lab.require_transport_observation(value, expected)

    def test_actual_generated_profile_is_bound_to_request_package_initialized_and_all_roles(self):
        self.profile()
        observed = {'data_transport': self.selection}
        self.assertEqual(lab.validate_lab_transport(self.root, self.request, self.package,
                         initialized=True, observations=(observed, observed)), self.selection)
        mutations = [(self.root / 'cluster.json', dict(self.cluster, data_transport=dict(self.selection, schema=True))),
                     (self.root / 'state/initialized.json', dict(self.initialized, data_transport=dict(self.selection, ib_device='mlx5_1'))),
                     (self.package_path, dict(self.package, transport_validation='hardware_validated'))]
        for path, value in mutations:
            old = path.read_bytes()
            try:
                self.write(path, value)
                with self.subTest(path=path), self.assertRaises((ValueError, lab.GateError)):
                    lab.validate_lab_transport(self.root, self.request, initialized=True)
            finally:
                path.write_bytes(old)
        with lab.transport_config(self.root / 'scripts') as config:
            path = self.root / 'config/storage_main.toml'
            old = path.read_bytes()
            import tomllib
            data = tomllib.loads(old.decode())
            # A non-client role drift must also fail before any child can start.
            data['server']['forward_client']['force_use_tcp'] = True
            path.write_text(config.to_toml(data), encoding='utf-8')
            try:
                with self.assertRaises(RuntimeError), mock.patch.object(lab.subprocess, 'Popen') as child:
                    lab.validate_lab_transport(self.root, self.request)
                child.assert_not_called()
            finally:
                path.write_bytes(old)

    def test_tcp_receipts_stay_empty_but_mixed_rdma_cluster_or_client_is_rejected(self):
        self.profile(selection=False)
        before = copy.deepcopy(self.request)
        self.assertIsNone(lab.validate_lab_transport(self.root, self.request, initialized=True, observations=({},)))
        self.assertEqual(self.request, before)
        self.assertEqual(lab.transport_fields(None), {})
        self.write(self.root / 'cluster.json', dict(self.cluster, data_transport=self.selection))
        with self.assertRaises(lab.GateError):
            lab.validate_lab_transport(self.root, self.request)
        self.write(self.root / 'cluster.json', self.cluster)
        path = self.root / 'client/file-client.toml'
        path.write_text('storage_transport="rdma"\n' + path.read_text(encoding='utf-8'), encoding='utf-8')
        with self.assertRaises(RuntimeError):
            lab.validate_lab_transport(self.root, self.request)

    def test_real_run_sidecars_bind_both_cli_argv_and_config_hash_without_repairing_missing_evidence(self):
        self.profile()
        for file_api in (True, False):
            row, sidecar = self.command(file_api)
            lab.validate_command_transports(self.root, self.selection, [row])
            for index, replacement in ((0, str(self.root / 'bin/admin_cli')),
                                       (1, '--cfg=' + str(self.root / 'client/other.toml')),
                                       (3, '--config.storage_transport=tcp')):
                bad = copy.deepcopy(row)
                bad['argv'][index] = replacement
                with self.subTest(file_api=file_api, index=index), self.assertRaises(ValueError):
                    lab.validate_command_transports(self.root, self.selection, [bad])
            original = sidecar.read_bytes()
            changed = json.loads(original)
            changed['schema'] = True
            self.write(sidecar, changed)
            with self.assertRaises(lab.GateError):
                lab.validate_command_transports(self.root, self.selection, [row])
            sidecar.unlink()
            with self.assertRaises(FileNotFoundError):
                lab.validate_command_transports(self.root, self.selection, [row])
            self.assertFalse(sidecar.exists())
            sidecar.write_bytes(original)
            config = Path(row['transport']['client_config']['path'])
            config_original = config.read_bytes()
            config.write_bytes(config_original + b'\n# changed bytes\n')
            with self.assertRaises(lab.GateError):
                lab.validate_command_transports(self.root, self.selection, [row])
            config.write_bytes(config_original)

    def test_control_is_only_fixed_supervisor_grammar_and_cannot_claim_data_transport(self):
        self.profile()
        row = {'kind': 'supervisor_control', 'argv': ['/usr/bin/python3', str(self.root / 'scripts/native-v2.py'),
                                                    'status', '--root', str(self.root)]}
        # A legitimate inspecting parent may have another Python executable.
        with mock.patch.object(sys, 'executable', '/private/parent/python3'):
            lab.validate_command_transports(self.root, self.selection, [row], allow_control=True)
        for changed in (dict(row, transport=lab.transport_fields(self.selection)),
                        dict(row, argv=row['argv'] + ['--transport', 'tcp']),
                        dict(row, argv=['/private/parent/python3', *row['argv'][1:]]),
                        dict(row, argv=['/usr/bin/python3', row['argv'][1], 'start', *row['argv'][3:]]),
                        dict(row, argv=['/usr/bin/python3', str(self.root / 'other.py'), *row['argv'][2:]])):
            with self.subTest(row=changed), self.assertRaises((ValueError, RuntimeError)):
                lab.validate_command_transports(self.root, self.selection, [changed], allow_control=True)
        with self.assertRaises(lab.GateError):
            lab.validate_command_transports(self.root, self.selection, [row])
        with self.assertRaises(lab.GateError):
            lab.validate_command_transports(self.root, None, [row], allow_control=True)

    def test_doctor_binds_read_only_admission_not_hardware_success(self):
        value = {'status': 'ready', 'problems': [], 'services_started': False, 'observations': {}}
        lab.validate_transport_doctor(value, None)
        value['observations']['rdma'] = {'requested': self.selection,
            'scope': 'read-only device/resource admission; no verbs or data operation'}
        lab.validate_transport_doctor(value, self.selection)
        for bad in (dict(value, problems=['device missing']), dict(value, services_started=True),
                    dict(value, observations={'rdma': {'requested': dict(self.selection, ipv4='192.0.2.11'),
                                                       'scope': value['observations']['rdma']['scope']}})):
            with self.subTest(value=bad), self.assertRaises(lab.GateError):
                lab.validate_transport_doctor(bad, self.selection)
        with self.assertRaises(lab.GateError):
            lab.validate_transport_doctor(value, None)

    def test_fuse_first_remount_and_supervisor_evidence_bind_original_preparation(self):
        self.profile()
        folder = self.root.parent / 'fuse-config'
        folder.mkdir()
        outputs = {}
        for name in ('fuse-first.toml', 'fuse-resume.toml', 'launcher.toml'):
            (folder / name).write_text('# synthetic locked config; no mount\n', encoding='utf-8')
            outputs[name] = lab.sha(folder / name)
        prep = {**lab.transport_fields(self.selection), 'outputs': outputs,
                'first_mount_argv': ['fuse', '--cfg', str(folder / 'fuse-first.toml')],
                'remount_argv': ['fuse', '--cfg', str(folder / 'fuse-resume.toml')]}
        path = folder / 'preparation.json'
        self.write(path, prep)
        value = {'preparation': str(path), 'source_sha256': {str(path): lab.sha(path),
                 **{str(folder / name): digest for name, digest in outputs.items()}},
                 'mounts': [{'argv': prep['first_mount_argv']}, {'argv': prep['remount_argv']}],
                 'services': [{'snapshot': {'data_transport': self.selection}}]}
        lab.validate_fuse_transport(self.root, self.selection, prep, value)
        for bad in (dict(value, mounts=[value['mounts'][0]] * 2),
                    dict(value, services=[{'snapshot': {}}]), dict(value, source_sha256={})):
            with self.subTest(value=bad), self.assertRaises(lab.GateError):
                lab.validate_fuse_transport(self.root, self.selection, prep, bad)
        (folder / 'launcher.toml').write_text('# drift\n', encoding='utf-8')
        with self.assertRaises(lab.GateError):
            lab.validate_fuse_transport(self.root, self.selection, prep, value)


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux directory-FD and O_NOFOLLOW semantics')
class LinuxTreeDescriptors(unittest.TestCase):
    def make_tree(self, parent):
        root = parent / 'private-tree'
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        folder = root / 'nested'
        folder.mkdir(mode=0o700)
        folder.chmod(0o700)
        payload = folder / 'payload'
        payload.write_bytes(b'bounded FD handoff fixture\n')
        payload.chmod(0o600)
        return root, payload

    def test_private_tree_inventory_and_retained_fds_are_real(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.make_tree(Path(temp))
            expected = [
                {'path': '.', 'kind': 'directory', 'mode': 0o700},
                {'path': 'nested', 'kind': 'directory', 'mode': 0o700},
                {'path': 'nested/payload', 'kind': 'file', 'mode': 0o600,
                 'size': payload.stat().st_size, 'sha256': hashlib.sha256(payload.read_bytes()).hexdigest()},
            ]
            self.assertEqual(lab.tree_rows(root, os.getuid()), expected)
            rows, fds = lab.tree_rows(root, os.getuid(), retain=True)
            try:
                self.assertEqual(rows, expected)
                self.assertEqual(len(fds), len(expected))
                for row, fd in zip(rows, fds):
                    path = root if row['path'] == '.' else root / row['path']
                    held, actual = os.fstat(fd), path.stat()
                    self.assertEqual((held.st_dev, held.st_ino), (actual.st_dev, actual.st_ino))
                    self.assertEqual(held.st_uid, os.getuid())
                    self.assertEqual(stat.S_IMODE(held.st_mode), row['mode'])
                self.assertEqual(os.pread(fds[-1], payload.stat().st_size, 0), payload.read_bytes())
            finally:
                for fd in reversed(fds):
                    os.close(fd)
            for fd in fds:
                with self.assertRaises(OSError) as raised:
                    os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_symlink_is_rejected_without_following_its_target(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root, _ = self.make_tree(parent)
            outside = parent / 'outside'
            outside.write_bytes(b'outside must not enter the inventory\n')
            outside.chmod(0o600)
            before = outside.stat()
            (root / 'alias').symlink_to(outside)
            with self.assertRaises(OSError) as raised:
                lab.tree_rows(root, os.getuid(), retain=True)
            self.assertEqual(raised.exception.errno, errno.ELOOP)
            after = outside.stat()
            self.assertEqual((after.st_dev, after.st_ino, after.st_uid, after.st_mode),
                             (before.st_dev, before.st_ino, before.st_uid, before.st_mode))
            self.assertEqual(outside.read_bytes(), b'outside must not enter the inventory\n')

    def test_regular_file_with_another_hardlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root, payload = self.make_tree(parent)
            alias = parent / 'outside-hardlink'
            os.link(payload, alias)
            self.assertEqual(payload.stat().st_nlink, 2)
            self.assertEqual(payload.stat().st_ino, alias.stat().st_ino)
            with self.assertRaisesRegex(lab.GateError, 'single|unlinked-to-other-paths'):
                lab.tree_rows(root, os.getuid(), retain=True)
            self.assertEqual(payload.stat().st_nlink, 2)
            self.assertEqual(alias.read_bytes(), payload.read_bytes())


if __name__ == '__main__':
    unittest.main()
