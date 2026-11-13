#!/usr/bin/env python3
"""Pure gates and Linux private-file FD checks; no chown, subprocess or service."""
import copy
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout

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
