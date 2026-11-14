#!/usr/bin/env python3
"""Pure receipt/resource/identity gates; no processes, sockets, chown or services."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

spec = importlib.util.spec_from_file_location('spare_lab_under_test', Path(__file__).with_name('run-spare-lab.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
ROOT = Path('/tmp/example-spare')
RDMA = {'schema': 1, 'mode': 'rdma', 'interface': 'eth7', 'ipv4': '192.0.2.17', 'ib_device': 'mlx5_7'}


def example(failures=2, strategy='helper'):
    names = ['fdb', 'mgmtd', *[f'storage-{n}' for n in range(10001, 10015)], 'meta']
    rows = [dict(name=name, pid=100 + i, exit_code=None) for i, name in enumerate(names)]
    ready = dict(schema=1, root=str(ROOT), run='run-20261113T123456.123456Z', profile=lab.PROFILE,
                 stage='ready', failure=None, processes=rows,
                 logical_targets=14, storage_processes=14, storage_process_failure_domains=14,
                 independent_storage_failure_domains=1, performance_validated=False,
                 maintenance=dict(enabled=True, failed=False, pending=None, running=None,
                                  expected_exits=[], faulted_storage_nodes=[]))
    completed = copy.deepcopy(ready)
    nodes = list(range(10001, 10001 + failures))
    killed = []
    for row in completed['processes']:
        if row['name'] in [f'storage-{n}' for n in nodes]:
            row['exit_code'] = -9
            killed.append(copy.deepcopy(row))
        elif row['name'] == 'meta':
            row['exit_code'] = 0
    completed['processes'] += [dict(name='meta', pid=500, exit_code=None)]
    completed['processes'] += [dict(name=f'storage-{n}', pid=501 + i, exit_code=None) for i, n in enumerate(nodes)]
    actions, controls = {}, []
    for index, (name, operation, fields) in enumerate((
            ('fault', 'fault-storage', {'nodes': nodes}),
            ('placement', 'replace-placement', {'replacements': [[n, 10013 + i] for i, n in enumerate(nodes)]}),
            ('restore', 'restart-storage', {'nodes': nodes}))):
        action = dict(operation=operation, run=ready['run'], action_id=str(uuid.UUID(int=index + 1)), **fields)
        steps = [dict(node=n, restarted_same_persistent_instance=True, observed_boot_nonce=str(uuid.UUID(int=n)))
                 for n in nodes] if name == 'restore' else []
        actions[name] = action
        controls.append(dict(operation=operation, fixed_action=action,
                             observations=[dict(request=action, state='completed', cleanup_or_T2_claimed=False, steps=steps)]))
    result = dict(schema=1, state='completed', success=True, failure=None, strategy=strategy, failures=failures,
                  supervisor_uid=1000, supervisor_run=ready['run'], whole_cluster_started_or_stopped=False,
                  old_debt_completion_requires_actual_cli_T2=True, physical_machine_failure_domains=1,
                  physical_disk_or_power_failure_tested=False, performance_validated=False,
                  all_owned_commands_joined=True,
                  commands=[dict(index=0, process_started=True, process_exited=True, returncode=0)],
                  steps=[dict(checks_complete=True, original_source_debt_retained=True),
                         dict(checks_complete=True, original_source_t2_confirmed=True),
                         dict(checks_complete=True, original_range_t2_confirmed=True)],
                  actions=actions, controls=controls, confirmed_sigkill_exit_observations=killed)
    return result, ready, completed


def stopped(completed, fdb=-15):
    final = copy.deepcopy(completed)
    final['stage'] = 'stopped'
    for row in final['processes']:
        if row['exit_code'] is None:
            row['exit_code'] = fdb if row['name'] == 'fdb' else 0
    cleanup = dict(clean=True, exit_codes={row['name']: row['exit_code'] for row in final['processes']})
    return final, cleanup


class SpareLabGates(unittest.TestCase):
    def test_prepare_command_preserves_tcp_and_forwards_only_normalized_rdma_selection(self):
        source = Path(__file__).resolve().parents[3]
        args = SimpleNamespace(transport=None, rdma_interface=None, rdma_address=None, rdma_device=None,
                               handoff=None, run_owned=None)
        self.assertIsNone(lab.shared.lab_transport_selection(args, source))
        expected = [lab.sys.executable, '-B', source / 'scripts/ec/cluster/native-v2.py', 'prepare', '--root', ROOT,
                    '--source', source, '--profile', 'gc-14', '--file-api', '--port-base', '14500']
        self.assertEqual(lab.native_prepare_command(source, ROOT), expected)
        self.assertEqual(lab.shared.transport_fields(None), {})
        args.transport, args.rdma_interface, args.rdma_address, args.rdma_device = 'rdma', 'eth7', '192.0.2.17', 'mlx5_7'
        selected = lab.shared.lab_transport_selection(args, source)
        self.assertEqual(selected, RDMA)
        self.assertEqual(lab.native_prepare_command(source, ROOT, selected), expected + [
            '--transport', 'rdma', '--rdma-interface', 'eth7', '--rdma-address', '192.0.2.17', '--rdma-device', 'mlx5_7'])
        fields = lab.shared.transport_fields(selected)
        self.assertEqual(lab.shared.request_transport(fields), selected)
        self.assertEqual(fields['transport_validation'], 'configuration_only')
        for change in ({'transport': 'tcp'}, {'rdma_device': None}, {'rdma_address': '127.0.0.1'}):
            invalid = SimpleNamespace(**(vars(args) | change))
            with self.subTest(change=change), self.assertRaises(ValueError):
                lab.shared.lab_transport_selection(invalid, source)

    def test_internal_runtime_and_handoff_cannot_override_sealed_transport(self):
        overrides = [['--transport', 'tcp'], ['--transport', 'rdma'], ['--rdma-device', 'mlx5_7']]
        with mock.patch.object(lab.sys, 'platform', 'linux'), mock.patch.object(lab.os, 'umask'), \
                mock.patch.object(lab.os.environ, 'pop'), mock.patch.object(lab, 'runtime', return_value=7) as runtime, \
                mock.patch.object(lab, 'read_json') as read, \
                mock.patch.object(lab.shared, 'privileged_handoff') as handoff, \
                mock.patch.object(lab, 'prepare') as prepare:
            for internal in ('--handoff', '--run-owned'):
                for flags in overrides:
                    with self.subTest(internal=internal, flags=flags), \
                            mock.patch.object(lab.sys, 'argv', ['run-spare-lab.py', internal, str(ROOT), *flags]), \
                            contextlib.redirect_stderr(io.StringIO()), self.assertRaises(ValueError):
                        lab.main()
            runtime.assert_not_called()
            handoff.assert_not_called()
            read.assert_not_called()
            prepare.assert_not_called()
            with mock.patch.object(lab.sys, 'argv', ['run-spare-lab.py', '--run-owned', str(ROOT)]):
                self.assertEqual(lab.main(), 7)
            runtime.assert_called_once_with(ROOT)

    def test_rdma_ready_completion_and_final_receipts_cannot_change_or_omit_transport(self):
        result, ready, completed = example()
        ready['data_transport'] = copy.deepcopy(RDMA)
        completed['data_transport'] = copy.deepcopy(RDMA)
        self.assertEqual(len(lab.case_gate(result, ready, completed, ROOT, 'helper', 2, transport=RDMA)), 20)
        final, cleanup = stopped(completed)
        self.assertTrue(lab.shutdown_gate(final, cleanup, completed, ROOT, 0, RDMA)['all_owned_processes_exited'])
        for index in range(3):
            for value in (None, dict(RDMA, ipv4='192.0.2.18'), dict(RDMA, schema=True)):
                before, after, stopped_state = copy.deepcopy((ready, completed, final))
                target = (before, after, stopped_state)[index]
                if value is None:
                    target.pop('data_transport')
                else:
                    target['data_transport'] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    if index == 2:
                        lab.shutdown_gate(stopped_state, cleanup, after, ROOT, 0, RDMA)
                    else:
                        lab.case_gate(result, before, after, ROOT, 'helper', 2, transport=RDMA)
        with self.assertRaises(ValueError):
            lab.ready_gate(ready, ROOT)  # Legacy TCP cannot acquire an RDMA label.
        failed = copy.deepcopy(result)
        failed['commands'][0]['returncode'] = 1
        with self.assertRaises(ValueError):
            lab.case_gate(failed, ready, completed, ROOT, 'helper', 2, transport=RDMA)

    def test_rdma_doctor_requires_matching_canonical_request_and_original_resource_gates(self):
        doctor = dict(profile=lab.PROFILE, status='ready', problems=[], services_started=False,
                      observations=dict(required_available_memory_gib=7, memory_kib={'MemAvailable': 7 * 1024**2},
                          free_bytes=10 * 1024**3, free_inodes=60000, active_build_processes=[],
                          rdma={'requested': copy.deepcopy(RDMA),
                                'scope': 'read-only device/resource admission; no verbs or data operation'}))
        lab.resource_gate(doctor, RDMA)
        admitted = doctor['observations']['rdma']
        for rdma in (None, {}, dict(admitted, requested=dict(RDMA, interface='eth8')),
                     dict(admitted, requested=dict(RDMA, schema=True)), dict(admitted, scope='data validated')):
            changed = copy.deepcopy(doctor)
            if rdma is None:
                changed['observations'].pop('rdma')
            else:
                changed['observations']['rdma'] = rdma
            with self.subTest(rdma=rdma), self.assertRaises(ValueError):
                lab.resource_gate(changed, RDMA)
        with self.assertRaises(ValueError):
            lab.resource_gate(doctor)
        changed = copy.deepcopy(doctor)
        changed['observations']['free_bytes'] -= 1
        with self.assertRaises(ValueError):
            lab.resource_gate(changed, RDMA)

    def test_one_and_two_fault_ledgers_include_old_and_restarted_instances(self):
        for failures in (1, 2):
            for strategy in ('central', 'pipeline', 'helper'):
                with self.subTest(failures=failures, strategy=strategy):
                    result, ready, completed = example(failures, strategy)
                    rows = lab.case_gate(result, ready, completed, ROOT, strategy, failures)
                    self.assertEqual(len(rows), 18 + failures)
                    self.assertTrue(lab.case_cleanup_known(result, ready, strategy, failures))
                    for fdb in (0, -15):
                        final, cleanup = stopped(completed, fdb)
                        self.assertEqual(lab.shutdown_gate(final, cleanup, completed, ROOT, 0)['all_process_rows'],
                                         18 + failures)

    def test_projection_cannot_hide_missing_old_popen_or_wrong_exit(self):
        result, ready, completed = example()
        for mode in ('old_missing', 'duplicate', 'old_code', 'extra_pid', 'unrestored'):
            bad = copy.deepcopy(completed)
            if mode == 'old_missing':
                bad['processes'] = [row for row in bad['processes'] if row['exit_code'] != -9]
            elif mode == 'duplicate':
                bad['processes'].append(copy.deepcopy(bad['processes'][0]))
            elif mode == 'old_code':
                next(row for row in bad['processes'] if row['exit_code'] == -9)['exit_code'] = 0
            elif mode == 'extra_pid':
                bad['processes'].append(dict(name='storage-10014', pid=900, exit_code=None))
            else:
                bad['processes'][-1]['exit_code'] = -9
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                lab.case_gate(result, ready, bad, ROOT, 'helper', 2)

    def test_failed_unknown_or_reissued_commands_never_become_case_success(self):
        result, ready, completed = example()
        for mode in ('unjoined', 'failed', 'reissued', 'missing_debt', 'wrong_run', 'wrong_restore'):
            bad = copy.deepcopy(result)
            if mode == 'unjoined':
                bad['commands'][0]['process_exited'] = False
                self.assertFalse(lab.case_cleanup_known(bad, ready, 'helper', 2))
            elif mode == 'failed':
                bad['commands'][0]['returncode'] = 1
                self.assertTrue(lab.case_cleanup_known(bad, ready, 'helper', 2))
            elif mode == 'reissued':
                bad['controls'].append(copy.deepcopy(bad['controls'][0]))
            elif mode == 'missing_debt':
                bad['steps'][1].pop('original_source_t2_confirmed')
            elif mode == 'wrong_run':
                bad['supervisor_run'] = 'other'
                self.assertFalse(lab.case_cleanup_known(bad, ready, 'helper', 2))
            else:
                bad['controls'][-1]['observations'][-1]['steps'][0]['restarted_same_persistent_instance'] = False
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                lab.case_gate(bad, ready, completed, ROOT, 'helper', 2)

    def test_shutdown_rejects_unknown_history_failure_and_bad_fdb_signal(self):
        _, _, completed = example()
        for mode in ('unknown', 'fdb_kill', 'old_hidden', 'meta_term', 'projection', 'failed', 'supervisor'):
            final, cleanup = stopped(completed)
            code = 0
            if mode == 'unknown':
                final['processes'][-1]['exit_code'] = None
            elif mode == 'fdb_kill':
                final['processes'][0]['exit_code'] = -9
            elif mode == 'old_hidden':
                final['processes'] = [row for row in final['processes'] if row['exit_code'] != -9]
            elif mode == 'meta_term':
                next(row for row in final['processes'] if row['name'] == 'meta')['exit_code'] = -15
            elif mode == 'projection':
                cleanup['exit_codes']['storage-10001'] = -9
            elif mode == 'failed':
                final['failure'] = {'type': 'RuntimeError'}
            else:
                code = 1
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                lab.shutdown_gate(final, cleanup, completed, ROOT, code)

    def test_resource_gate_preserves_gc14_thresholds(self):
        value = dict(profile=lab.PROFILE, status='ready', problems=[], services_started=False,
                     observations=dict(required_available_memory_gib=7,
                                       memory_kib={'MemAvailable': 7 * 1024**2},
                                       free_bytes=10 * 1024**3, free_inodes=60000, active_build_processes=[]))
        lab.resource_gate(value)
        for key, low in (('free_bytes', 10 * 1024**3 - 1), ('free_inodes', 59999),
                         ('active_build_processes', [{'pid': 1, 'comm': 'ninja'}]),
                         ('memory_kib', {'MemAvailable': 7 * 1024**2 - 1})):
            bad = copy.deepcopy(value)
            bad['observations'][key] = low
            with self.subTest(key=key), self.assertRaises(ValueError):
                lab.resource_gate(bad)

    def test_shared_handoff_default_unchanged_and_suffix_binds_exact_case(self):
        request = dict(schema=1, parent=str(Path('/tmp/ec-h-123-1')), creator_uid=1001, target_uid=1000,
                       run_id='123', run_attempt='1', inventory=[{'path': '.'}])
        lab.shared.handoff_shape(Path(request['parent']), request)
        request.update(strategy='helper', failures=2, parent=str(Path('/tmp/ec-h-123-1-spare-helper-2')))
        lab.shared.handoff_shape(Path(request['parent']), request, suffix='-spare-helper-2')
        for case_suffix in ('-spare-helper-1', '-spare-central-2', '/../else', '-spare-helper-2/other'):
            with self.subTest(suffix=case_suffix), self.assertRaises(ValueError):
                lab.shared.handoff_shape(Path(request['parent']), request, suffix=case_suffix)
        request['failures'] = True
        with self.assertRaises(ValueError):
            lab.shared.handoff_shape(Path(request['parent']), request, suffix='-spare-helper-2')

    def test_build_backend_and_source_must_match_both_receipts(self):
        common = dict(schema=1, source=str(Path('/source')), build=str(Path('/build')), revision='head', backend='scalar', isal=None,
                      acceptance_executed=False, build_script_sha256='a' * 64, cmake_cache_sha256='b' * 64)
        built = dict(common, targets=list(lab.shared.TARGETS), binaries={name: 'c' * 64 for name in lab.shared.TARGETS})
        native = dict(built, lab_targets_requested=True)
        lab.build_gate(built, native, Path('/source'), Path('/build'), 'head')
        for key, wrong in (('revision', 'old'), ('backend', 'isal'), ('cmake_cache_sha256', 'd' * 64),
                           ('acceptance_executed', True), ('lab_targets_requested', False)):
            bad = dict(native, **{key: wrong})
            with self.subTest(key=key), self.assertRaises(ValueError):
                lab.build_gate(built, bad, Path('/source'), Path('/build'), 'head')

    def test_owned_command_receipt_requires_real_terminal_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '001-doctor.started.json').write_text(json.dumps({'pid': 100, 'argv': ['fixed']}))
            with self.assertRaises((ValueError, FileNotFoundError)):
                lab.command_records(root, 1)
            (root / '001-doctor.finished.json').write_text(json.dumps({'returncode': 0, 'wall_ns': 10}))
            self.assertEqual(lab.command_records(root, 1)[0]['returncode'], 0)

    def test_package_provider_binds_canonical_source_and_both_byte_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            provider = root / 'private source/libisal.so.2.0.31'
            provider.parent.mkdir()
            provider.write_bytes(b'provider fixture')
            bundle = root / 'bundle'
            (bundle / 'lib').mkdir(parents=True)
            payload = bundle / 'lib/libisal.so.2'
            payload.write_bytes(provider.read_bytes())
            checksum = hashlib.sha256(provider.read_bytes()).hexdigest()
            built = dict(backend='isal', isal={'provider': {'path': str(provider), 'sha256': checksum}})
            package = {'files': {'lib/libisal.so.2': dict(source=str(provider), sha256=checksum, kind='shared-library')}}
            result = lab.shared.package_backend_gate(built, package, bundle)
            self.assertTrue(result['provider_verified'])
            twin = root / 'different-source'
            twin.write_bytes(provider.read_bytes())
            bad = copy.deepcopy(package)
            bad['files']['lib/libisal.so.2']['source'] = str(twin)
            with self.assertRaises(ValueError):
                lab.shared.package_backend_gate(built, bad, bundle)
            payload.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                lab.shared.package_backend_gate(built, package, bundle)
            with self.assertRaises(ValueError):
                lab.shared.package_backend_gate(dict(backend='scalar', isal=None), package, bundle)
            self.assertEqual(lab.shared.package_backend_gate({}, package, bundle)['backend'], 'unrecorded')
            self.assertEqual(lab.shared.package_backend_gate(dict(backend='scalar', isal=None), {'files': {}}, bundle)['backend'], 'scalar')

    def test_packaged_loader_must_resolve_selected_provider(self):
        path = ROOT / 'lib/libisal.so.2'
        lab.resolution_gate('isal', f'libisal.so.2 => {path} (0x123)\n', ROOT)
        lab.resolution_gate('scalar', 'libc.so.6 => /lib/libc.so.6 (0x123)\n', ROOT)
        for backend, text in (('isal', 'libisal.so.2 => /outside/libisal.so.2 (0x123)'),
                              ('isal', 'libisal.so.2 => not found'),
                              ('scalar', f'libisal.so.2 => {path} (0x123)')):
            with self.subTest(backend=backend, text=text), self.assertRaises(ValueError):
                lab.resolution_gate(backend, text, ROOT)


if __name__ == '__main__':
    unittest.main(verbosity=2)
