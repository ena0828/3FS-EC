#!/usr/bin/env python3
"""Pure matrix/identity/receipt contracts: no child processes, services or chown."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


matrix = load('fault_matrix_tested', 'run-fault-matrix.py')
fixtures = load('existing_spare_fixtures', 'test-run-spare-lab.py')
RDMA = {'schema': 1, 'mode': 'rdma', 'interface': 'eth1', 'ipv4': '192.0.2.20', 'ib_device': 'rxe0'}


def completed(strategy, failures):
    index = matrix.CASES.index((strategy, failures))
    return dict(strategy=strategy, failures=failures, status='passed', returncode=0,
                complete_receipts_verified=True, all_owned_processes_exited=True,
                parent='work-' + str(index), cluster_id='cluster-' + str(index),
                client_namespace=str(uuid.UUID(int=index + 1)), authority=str(uuid.UUID(int=index + 20)),
                engine_uuids=[str(uuid.UUID(int=1000 + index * 14 + slot)) for slot in range(14)],
                target_incarnations=[str(uuid.UUID(int=2000 + index * 14 + slot)) for slot in range(14)],
                supervisor_run='run-' + str(index),
                action_ids=[str(uuid.UUID(int=100 + index * 3 + slot)) for slot in range(3)])


class FaultMatrixContracts(unittest.TestCase):
    def test_rdma_doctor_is_bound_to_original_stdout_and_exact_owned_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            lab = parent / '3fs-ec-native-spare'
            (parent / 'runtime').mkdir()
            output = parent / 'runtime/001-doctor.stdout'
            started = parent / 'runtime/001-doctor.started.json'
            doctor = dict(profile=matrix.spare.PROFILE, status='ready', problems=[], services_started=False,
                          observations=dict(required_available_memory_gib=7, memory_kib={'MemAvailable': 7 * 1024**2},
                                            free_bytes=10 * 1024**3, free_inodes=60000, active_build_processes=[],
                                            rdma={'requested': RDMA,
                                                  'scope': 'read-only device/resource admission; no verbs or data operation'}))
            argv = ['/usr/bin/python3', '-B', str(lab / 'scripts/native-v2.py'), 'doctor', '--root', str(lab)]
            def original():
                output.write_text(json.dumps(doctor), encoding='utf-8')
                started.write_text(json.dumps({'argv': argv, 'pid': 1234}), encoding='utf-8')
                return {'transport_doctor': {'sequence': 1, 'path': str(output), 'sha256': matrix.sha(output),
                                              'observation': copy.deepcopy(doctor)},
                        'commands': [{'started': str(started), 'started_sha256': matrix.sha(started)}]}
            matrix.verify_transport_doctor(parent, lab, original(), RDMA)
            matrix.verify_transport_doctor(parent, lab, {}, None)
            with self.assertRaises(ValueError):
                matrix.verify_transport_doctor(parent, lab, original(), None)
            for mode in ('hash', 'observation', 'executable', 'ledger', 'bool_sequence', 'request'):
                report = original()
                if mode == 'hash':
                    report['transport_doctor']['sha256'] = '0' * 64
                elif mode == 'observation':
                    report['transport_doctor']['observation']['services_started'] = 0
                elif mode == 'executable':
                    started.write_text(json.dumps({'argv': ['other-program', *argv[1:]], 'pid': 1234}), encoding='utf-8')
                    report['commands'][0]['started_sha256'] = matrix.sha(started)
                elif mode == 'ledger':
                    report['commands'][0]['started_sha256'] = '0' * 64
                elif mode == 'bool_sequence':
                    report['transport_doctor']['sequence'] = True
                else:
                    changed = copy.deepcopy(doctor)
                    changed['observations']['rdma']['requested']['ipv4'] = '192.0.2.21'
                    output.write_text(json.dumps(changed), encoding='utf-8')
                    report['transport_doctor'].update(observation=changed, sha256=matrix.sha(output))
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    matrix.verify_transport_doctor(parent, lab, report, RDMA)

    def test_rdma_is_forwarded_to_every_original_case_without_changing_case_selection(self):
        for strategy, failures in matrix.CASES:
            args = (Path('/src'), Path('/native/build'), Path('/native/fdb/bin'),
                    Path('/core/results.json'), Path('/private/cases') / matrix.case_name(strategy, failures),
                    strategy, failures)
            baseline = matrix.command(*args)
            explicit = matrix.command(*args, transport=RDMA)
            self.assertEqual(explicit, baseline + ['--transport', 'rdma', '--rdma-interface', 'eth1',
                                                  '--rdma-address', '192.0.2.20', '--rdma-device', 'rxe0'])
            self.assertNotIn('--transport', baseline)
            self.assertEqual(explicit.count('--transport'), 1)

    def test_rdma_matrix_needs_six_matching_transport_receipts_and_stops_on_drift(self):
        rows = []
        def run(strategy, failures):
            return {**completed(strategy, failures), **matrix.shared.transport_fields(RDMA)}
        matrix.execute_cases(rows, run, transport=RDMA)
        matrix.complete_gate(rows, transport=RDMA)
        self.assertEqual(len(rows), 6)
        with self.assertRaises(ValueError):
            matrix.complete_gate(rows)  # A TCP matrix cannot adopt six RDMA cases.
        for mode in ('missing', 'address', 'schema_bool', 'missing_validation', 'extra_field'):
            calls, attempted = [], []
            def drift(strategy, failures):
                calls.append((strategy, failures))
                value = run(strategy, failures)
                value = copy.deepcopy(value)
                if len(calls) == 2:
                    if mode == 'missing':
                        del value['data_transport_requested']
                        del value['transport_validation']
                    elif mode == 'address':
                        value['data_transport_requested']['ipv4'] = '192.0.2.21'
                    elif mode == 'schema_bool':
                        value['data_transport_requested']['schema'] = True
                    elif mode == 'missing_validation':
                        del value['transport_validation']
                    else:
                        value['data_transport_requested']['extra'] = 'unbound'
                return value
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                matrix.execute_cases(attempted, drift, transport=RDMA)
            self.assertEqual(tuple(calls), matrix.CASES[:2])
            self.assertEqual([row['status'] for row in attempted], ['passed', 'attempting'])

    def test_case_request_transport_mismatch_is_rejected_before_consuming_runtime_evidence(self):
        expected = matrix.shared.transport_fields(RDMA)
        for request in ({}, matrix.shared.transport_fields(dict(RDMA, ib_device='rxe1')),
                        {'data_transport_requested': None, 'transport_validation': 'configuration_only'}):
            with self.subTest(request=request), patch.object(matrix.shared, 'private'), \
                    patch.object(matrix, 'read_json', return_value=request) as read, \
                    patch.object(matrix.spare, 'local_shape') as shape, self.assertRaises(ValueError):
                matrix.verify_case(Path('/private/case'), expected, 'helper', 2, 1000)
            read.assert_called_once_with(Path('/private/case/handoff-request.json'))
            shape.assert_not_called()

    def test_exact_six_commands_keep_existing_single_case_driver(self):
        self.assertEqual(matrix.CASES, (('central', 1), ('central', 2), ('pipeline', 1),
                                        ('pipeline', 2), ('helper', 1), ('helper', 2)))
        parents = []
        for strategy, failures in matrix.CASES:
            parent = Path('/private/cases') / matrix.case_name(strategy, failures)
            parents.append(parent)
            argv = list(map(str, matrix.command(Path('/src'), Path('/native/build'), Path('/native/fdb/bin'),
                                               Path('/core/results.json'), parent, strategy, failures)))
            self.assertEqual(argv[1:3], ['-B', str(Path('/src/scripts/ec/ci/run-spare-lab.py'))])
            self.assertEqual(argv[argv.index('--local-work') + 1], str(parent))
            self.assertEqual(argv[-4:], ['--strategy', strategy, '--failures', str(failures)])
            self.assertNotIn('sudo', argv)
        self.assertEqual(len(set(parents)), 6)

    def test_serial_completion_needs_all_six_unique_terminal_receipts(self):
        calls, rows = [], []
        def run(strategy, failures):
            self.assertEqual(len(calls), len(rows) - 1)
            self.assertTrue(all(row['status'] == 'passed' for row in rows[:-1]))
            calls.append((strategy, failures))
            return completed(strategy, failures)
        matrix.execute_cases(rows, run)
        self.assertEqual(tuple(calls), matrix.CASES)
        matrix.complete_gate(rows)
        for mode in ('missing', 'duplicate', 'unjoined', 'false_exit', 'unverified', 'wrong_strategy', 'reused_identity'):
            bad = copy.deepcopy(rows)
            if mode == 'missing':
                bad.pop()
            elif mode == 'duplicate':
                bad[-1] = copy.deepcopy(bad[0])
            elif mode == 'unjoined':
                bad[0]['all_owned_processes_exited'] = False
            elif mode == 'false_exit':
                bad[0]['returncode'] = False
            elif mode == 'unverified':
                bad[0]['complete_receipts_verified'] = False
            elif mode == 'wrong_strategy':
                bad[0]['strategy'] = 'helper'
            else:
                bad[1]['client_namespace'] = bad[0]['client_namespace']
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                matrix.complete_gate(bad)

    def test_first_failed_or_unconfirmed_case_stops_without_retry_or_suffix(self):
        for failed in range(6):
            calls, rows = [], []
            def run(strategy, failures):
                calls.append((strategy, failures))
                if len(calls) == failed + 1:
                    raise RuntimeError('retained real-command failure or unknown cleanup')
                return completed(strategy, failures)
            with self.subTest(failed=failed), self.assertRaises(RuntimeError):
                matrix.execute_cases(rows, run)
            self.assertEqual(tuple(calls), matrix.CASES[:failed + 1])
            self.assertEqual(len(rows), failed + 1)
            self.assertEqual(rows[-1]['status'], 'attempting')
            self.assertIsNone(rows[-1]['returncode'])
            self.assertEqual(sum(row['status'] == 'passed' for row in rows), failed)

    def test_invalid_terminal_or_reused_identity_stops_before_next_case(self):
        for mode in ('exit', 'join', 'reused_action', 'reused_engine'):
            calls, rows = [], []
            def run(strategy, failures):
                calls.append((strategy, failures))
                value = completed(strategy, failures)
                if len(calls) == 2:
                    if mode == 'exit':
                        value['returncode'] = 1
                    elif mode == 'join':
                        value['all_owned_processes_exited'] = False
                    elif mode == 'reused_engine':
                        value['engine_uuids'][0] = rows[0]['engine_uuids'][0]
                    else:
                        value['action_ids'][0] = rows[0]['action_ids'][0]
                return value
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                matrix.execute_cases(rows, run)
            self.assertEqual(tuple(calls), matrix.CASES[:2])
            self.assertEqual(rows[-1]['status'], 'attempting')
            self.assertEqual(sum(row['status'] == 'passed' for row in rows), 1)
        with self.assertRaises(ValueError):
            matrix.execute_cases([completed(*matrix.CASES[0])], lambda *_: self.fail('must not adopt'))

    def test_same_user_mode_binds_real_effective_uid_gid_and_rejects_root(self):
        for uid, gid in ((1000, 1000), (1001, 1001), (12345, 23456)):
            request = dict(execution_mode='local-same-user', creator_uid=uid, target_uid=uid, target_gid=gid)
            matrix.spare.local_identity(request, uid, uid, gid, gid)
            for identity in ((0, 0, gid, gid), (uid, uid + 1, gid, gid), (uid, uid, gid, gid + 1)):
                with self.assertRaises(ValueError):
                    matrix.spare.local_identity(request, *identity)
            for key, value in (('target_uid', uid + 1), ('creator_uid', True), ('target_gid', gid + 1),
                               ('execution_mode', 'hosted-handoff')):
                with self.subTest(uid=uid, key=key), self.assertRaises(ValueError):
                    matrix.spare.local_identity(dict(request, **{key: value}), uid, uid, gid, gid)

    def test_existing_full_process_and_debt_gates_use_explicit_os_uid(self):
        for uid in (1000, 1001, 23456):
            result, ready, ended = fixtures.example()
            result['supervisor_uid'] = uid
            matrix.spare.case_gate(result, ready, ended, fixtures.ROOT, 'helper', 2, uid)
            self.assertTrue(matrix.spare.case_cleanup_known(result, ready, 'helper', 2, uid))
            with self.assertRaises(ValueError):
                matrix.spare.case_gate(result, ready, ended, fixtures.ROOT, 'helper', 2, uid + 1)
            self.assertFalse(matrix.spare.case_cleanup_known(result, ready, 'helper', 2, uid + 1))
            if uid != 1000:
                with self.assertRaises(ValueError):
                    matrix.spare.case_gate(result, ready, ended, fixtures.ROOT, 'helper', 2)
            final, cleanup = fixtures.stopped(ended)
            self.assertTrue(matrix.spare.shutdown_gate(final, cleanup, ended, fixtures.ROOT, 0)['all_owned_processes_exited'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
