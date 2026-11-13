#!/usr/bin/env python3
"""Pure matrix/identity/receipt contracts: no child processes, services or chown."""
import copy
import importlib.util
from pathlib import Path
import unittest
import uuid


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


matrix = load('fault_matrix_tested', 'run-fault-matrix.py')
fixtures = load('existing_spare_fixtures', 'test-run-spare-lab.py')


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
