#!/usr/bin/env python3
"""Pure gates and Linux private-file FD checks; no chown, subprocess or service."""
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

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
