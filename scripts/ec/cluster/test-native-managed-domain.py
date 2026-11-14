#!/usr/bin/env python3
"""Managed admission contracts; Linux cases own small Python children, never 3FS."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
import uuid

import native_managed_domain as domain
from native_v2_config import SPARE_GC_PROFILE, storage_specs


def uid(n):
    return str(uuid.UUID(int=n))


def adapter():
    """Run the actual supervisor methods without importing Linux-only launch machinery."""
    tree = ast.parse(Path(__file__).with_name('native-v2.py').read_text(encoding='utf-8'))
    source = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeCluster')
    wanted = {'managed_submit', 'managed_execute_one', 'start', '_start_owned'}
    cls = ast.ClassDef(name='Adapter', bases=[ast.Name(id='Base', ctx=ast.Load())], keywords=[],
                       body=[n for n in source.body if isinstance(n, ast.FunctionDef) and n.name in wanted],
                       decorator_list=[])
    class Base:
        def start(self, name, command):
            self.processes.append((name, self.fake))
    namespace = dict(Base=Base, SPARE_GC_PROFILE=SPARE_GC_PROFILE, storage_specs=storage_specs,
                     managed_id=domain.identifier, Path=Path, uuid=uuid, json=json,
                     validate_launch_profile=mock.Mock(),  # Profile I/O is covered by the RDMA preflight suite.
                     artifact_identity=mock.Mock(side_effect=AssertionError('unexpected binary observation')),
                     observe_owned_executable=mock.Mock(side_effect=AssertionError('unexpected proc observation')))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), '<actual-native-methods>', 'exec'), namespace)
    return namespace['Adapter'], namespace


class PortableContracts(unittest.TestCase):
    def test_identifier_and_bounded_encoding(self):
        self.assertEqual(domain.identifier(uid(1)), uid(1))
        for value in (None, True, '', uid(0), uid(1).upper() + ' ', []):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError, AttributeError)):
                domain.identifier(value)
        with self.assertRaises(ValueError):
            domain.encoded({'value': 'x' * domain.MAX_BYTES})
        self.assertEqual(domain.digest({'b': 2, 'a': 1}), domain.digest({'a': 1, 'b': 2}))

    def test_legacy_start_has_no_new_executable_or_proc_gate(self):
        cls, namespace = adapter()
        value = cls()
        value.manifest = {'profile': 'v2', 'root': '/unused', 'port_base': 14000}
        value.root = Path('/unused')
        value.managed_uncertain = False
        value.managed = None
        value.fake = object()
        value.processes = []
        # Supply just topology, not any real process/executable. This exercises
        # the actual legacy branch; the new Linux owned-child cases test observation.
        namespace['storage_specs'] = lambda m: [{'name': 'storage', 'stem': 'storage'}]
        self.assertIs(value.start('storage', ['unchanged-legacy-command']), value.fake)
        namespace['validate_launch_profile'].assert_called_once_with(value.root, value.manifest)
        namespace['artifact_identity'].assert_not_called()
        namespace['observe_owned_executable'].assert_not_called()

    def test_same_action_retry_and_fault_queue_exclusion(self):
        cls, namespace = adapter()
        value = cls()
        value.manifest = {'profile': SPARE_GC_PROFILE}
        namespace['storage_specs'] = lambda m: [{'node': 10001}]
        value.run_id = 'same-live-owner'
        value.managed_lock = threading.Lock()
        value.managed_pending = None
        value.managed_actions = {}
        value.managed_enrollment_owner = (object(), object())
        value.stage = 'ready'
        value.halt = threading.Event()
        fault = mock.Mock()
        fault.lock = threading.Lock()
        fault.pending = fault.running = None
        fault.failed = False
        value.fault_control = fault
        request = dict(operation='managed-enroll', action_id=uid(1), run=value.run_id, domain=uid(2),
                       node=10001, control='/independent/control', resource_generation=uid(3))
        for field in ('pending', 'running', 'failed'):
            setattr(fault, field, True)
            with self.subTest(field=field), self.assertRaises(ValueError):
                value.managed_submit(request)
            setattr(fault, field, False if field == 'failed' else None)
        self.assertEqual(value.managed_submit(request)['state'], 'queued')
        with self.assertRaises(ValueError):
            value.managed_submit(dict(request, action_id=uid(4)))
        value.managed_pending = None
        value.managed_actions[uid(1)]['state'] = 'failed'
        value.stage = 'managed_unknown'
        with self.assertRaises(ValueError):
            value.managed_submit(dict(request, domain=uid(5)))
        with self.assertRaises(ValueError):
            value.managed_submit(dict(request, action_id=uid(4)))
        self.assertEqual(value.managed_submit(request)['state'], 'queued')
        self.assertEqual(value.managed_pending, request)
        value.managed_actions[uid(1)]['state'] = 'completed'
        self.assertEqual(value.managed_submit(request)['state'], 'completed')

    def test_adapter_gate_precedes_every_owned_storage_start(self):
        cls, namespace = adapter()
        value = cls()
        value.manifest = {'profile': SPARE_GC_PROFILE}
        namespace['storage_specs'] = lambda m: [{'name': 'storage-10001'}]
        value.managed_uncertain = True
        value.managed = None
        value._start_owned = mock.Mock()
        with self.assertRaises(RuntimeError):
            value.start('storage-10001', ['storage'])
        value._start_owned.assert_not_called()
        value.managed_uncertain = False
        value.managed = mock.Mock(locator={'binding': {'service': 'storage-10001'}})
        value.managed.launch.side_effect = ValueError('durable deny')
        with self.assertRaises(ValueError):
            value.start('storage-10001', ['storage'])
        value.managed.launch.assert_called_once()
        value._start_owned.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux', 'Requires real Linux flock/fsync/proc and owned Python children')
class LinuxOwnedLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        parent = Path(self.temp.name).resolve()
        self.root, self.control = parent / 'lab', parent / 'control'
        for path in (self.root, self.control, self.root / 'state', self.root / 'data'):
            path.mkdir(mode=0o700)
        self.manifest = {'schema': 1, 'authority': uid(80), 'root': str(self.root)}
        domain.durable_replace(self.root / 'cluster.json', self.manifest, create=True)
        self.binary = domain.artifact_identity(Path(sys.executable).resolve())
        self.config = self.root / 'launch-input.txt'
        self.config.write_bytes(b'fixed launch input\n')
        self.config.chmod(0o600)
        self.argv = [self.binary['path'], '-I', '-B', '-c',
                     'import sys; print("ready", flush=True); sys.stdin.buffer.read()']
        self.binding = {'schema': 1, 'root': str(self.root), 'authority': uid(80),
                        'endpoint': {'node': 10001, 'chain': 11, 'target': 21,
                                     'engine_uuid': uid(81), 'target_incarnation': uid(82)},
                        'service': 'storage-10001', 'resource_generation': uid(83),
                        'manifest_digest': domain.digest(self.manifest),
                        'data': domain.directory_identity(self.root / 'data'),
                        'binary': self.binary, 'configs': [domain.artifact_identity(self.config)], 'argv': self.argv}
        self.proc = self.spawn()
        self.inputs = {key: self.binding[key] for key in ('argv', 'binary', 'configs')}
        self.inputs.update(launch_id=uid(84), owned=domain.observe_owned_executable(self.proc, self.binary))

    def spawn(self):
        proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
        self.addCleanup(cleanup)
        self.assertEqual(proc.stdout.readline(), b'ready\n')
        return proc

    def enroll(self, **replace):
        args = dict(root=self.root, manifest=self.manifest, control=self.control, domain=uid(1),
                    enrollment=uid(2), binding=self.binding, owner_run='original-owner',
                    proc=self.proc, launch_inputs=self.inputs)
        args.update(replace)
        return domain.ManagedDomain.enroll(**args)

    def joined(self, gate):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        gate.observe_join(self.proc)

    def test_real_enroll_deny_join_and_fresh_owner_stays_closed(self):
        gate = self.enroll()
        self.assertEqual(gate.query()['runtime']['state'], 'running')
        self.assertIs(gate.prepare_deny(uid(3)), self.proc)
        self.assertIsNone(self.proc.poll())  # Component has not signalled anything.
        self.joined(gate)
        result = gate.query()
        self.assertEqual(result['runtime']['exitcode'], -15)
        for field in ('external_fence', 'scope_T2', 'publication_authorized', 'physical_gc_confirmed'):
            self.assertFalse(result[field])
        attached = domain.ManagedDomain.attach(self.root, domain.read_private(self.root / 'cluster.json'), 'next-owner')
        with self.assertRaises(ValueError):
            attached.assert_startable()
        with self.assertRaises(ValueError):
            gate.prepare_deny(uid(4))
        self.assertIs(gate.prepare_deny(uid(3)), self.proc)

    def test_marker_visible_after_sync_error_only_exact_original_owner_can_complete(self):
        real_sync = domain.os.fsync
        replaced = threading.Event()
        real_replace = domain.os.replace
        def rename(*args, **kwargs):
            result = real_replace(*args, **kwargs)
            if args[1] == 'cluster.json':
                replaced.set()
            return result
        def sync(fd):
            if replaced.is_set():
                raise OSError('directory sync acknowledgement lost')
            return real_sync(fd)
        with mock.patch.object(domain.os, 'replace', side_effect=rename), mock.patch.object(domain.os, 'fsync', side_effect=sync):
            with self.assertRaises(OSError):
                self.enroll()
        self.assertNotIn(domain.KEY, self.manifest)  # Deliberately stale caller state.
        marker = domain.read_private(self.root / 'cluster.json')
        self.assertIn(domain.KEY, marker)
        self.assertFalse((self.control / 'domain.json').exists())
        with self.assertRaises((ValueError, FileNotFoundError)):
            domain.ManagedDomain.attach(self.root, marker, 'next-owner')
        for change in ({'domain': uid(5)}, {'enrollment': uid(6)}, {'owner_run': 'new-owner'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.enroll(**change)
        self.assertEqual(domain.read_private(self.root / 'cluster.json'), marker)
        gate = self.enroll()
        self.assertIs(gate.handle, self.proc)
        self.assertEqual(gate.query()['runtime']['state'], 'running')

    def test_deny_sync_failure_never_signals_and_only_same_id_reconfirms(self):
        gate = self.enroll()
        real_replace = domain.os.replace
        renamed = threading.Event()
        def replace(*args, **kwargs):
            value = real_replace(*args, **kwargs)
            if args[1] == 'domain.json':
                renamed.set()
            return value
        real_sync = domain.os.fsync
        def sync(fd):
            if renamed.is_set():
                raise OSError('deny parent sync failed')
            return real_sync(fd)
        with mock.patch.object(domain.os, 'replace', side_effect=replace), mock.patch.object(domain.os, 'fsync', side_effect=sync):
            with self.assertRaises(OSError):
                gate.prepare_deny(uid(3))
        self.assertTrue(gate.poisoned)
        self.assertIsNone(self.proc.poll())
        self.assertEqual(domain.read_private(gate.path)['deny'], uid(3))
        self.assertFalse(gate.query()['persistence_confirmed'])
        with self.assertRaises(ValueError):
            gate.prepare_deny(uid(4))
        with self.assertRaises(ValueError):
            gate.assert_startable()
        self.assertIs(gate.prepare_deny(uid(3)), self.proc)
        self.assertFalse(gate.poisoned)
        self.joined(gate)

    def test_launch_intent_precedes_spawn_and_owns_process_before_deny(self):
        gate = self.enroll()
        self.joined(gate)
        fresh = domain.ManagedDomain.attach(self.root, self.manifest, 'second-owner')
        fresh.assert_startable()
        entered, release, deny_attempted, denied = (threading.Event() for _ in range(4))
        results, errors = {}, []
        def spawn():
            record = domain.read_private(fresh.path)
            self.assertEqual((record['runtime']['state'], record['runtime']['pid']), ('launching', None))
            self.assertEqual(record['runtime']['owner_run'], 'second-owner')
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test release missing')
            return self.spawn()
        def launch():
            try:
                results['proc'] = fresh.launch(self.argv, spawn)
            except BaseException as error:
                errors.append(error)
        def deny():
            deny_attempted.set()
            try:
                results['denied_proc'] = fresh.prepare_deny(uid(3))
                denied.set()
            except BaseException as error:
                errors.append(error)
        first, second = threading.Thread(target=launch), threading.Thread(target=deny)
        first.start()
        try:
            self.assertTrue(entered.wait(5))
            second.start()
            self.assertTrue(deny_attempted.wait(5))
            self.assertFalse(denied.is_set())  # Spawn callback retains the exact admission lock.
        finally:
            release.set()
            first.join(10)
            if second.ident is not None:
                second.join(10)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(errors, [])
        self.assertIs(results['proc'], results['denied_proc'])
        self.assertEqual(fresh.query()['retirement_id'], uid(3))

    def test_launch_sync_failure_and_spawn_unknown_never_adopt_pid(self):
        gate = self.enroll()
        self.joined(gate)
        spawn = mock.Mock()
        with mock.patch.object(domain.os, 'fsync', side_effect=OSError('failed intent sync')):
            with self.assertRaises(OSError):
                gate.launch(self.argv, spawn)
        spawn.assert_not_called()
        # Restore the fixture's prior acknowledged state only in a fresh lab is
        # unnecessary: the original owner itself remains poisoned and cannot launch.
        with self.assertRaises(ValueError):
            gate.launch(self.argv, spawn)
        self.assertTrue(gate.query()['launch_denied'])

    def test_spawn_exception_after_intent_blocks_new_supervisor(self):
        gate = self.enroll()
        self.joined(gate)
        def unknown_spawn():
            self.spawn()  # A real child exists, but the caller loses this return handle.
            raise OSError('Popen registration outcome unknown')
        with self.assertRaises(OSError):
            gate.launch(self.argv, unknown_spawn)
        record = domain.read_private(gate.path)
        self.assertEqual((record['runtime']['state'], record['runtime']['pid']), ('launching', None))
        attached = domain.ManagedDomain.attach(self.root, self.manifest, 'new-owner')
        with self.assertRaises(ValueError):
            attached.assert_startable()
        with self.assertRaises(ValueError):
            attached.observe_join(self.proc)
        self.assertFalse(attached.query()['current_owner_handle'])

    def test_reopen_running_record_does_not_adopt_even_exact_pid(self):
        gate = self.enroll()
        attached = domain.ManagedDomain.attach(self.root, self.manifest, 'original-owner')
        self.assertEqual(attached.query()['runtime']['pid'], self.proc.pid)
        for action in (attached.assert_startable, lambda: attached.prepare_deny(uid(3)),
                       lambda: attached.observe_join(self.proc)):
            with self.assertRaises(ValueError):
                action()
        self.assertIsNone(self.proc.poll())
        self.assertIs(gate.handle, self.proc)

    def test_changed_data_config_or_argv_refused_before_spawn(self):
        gate = self.enroll()
        self.joined(gate)
        spawn = mock.Mock()
        with self.assertRaises(ValueError):
            gate.launch(self.argv + ['different'], spawn)
        self.config.write_bytes(b'replaced fixed config\n')
        with self.assertRaises(ValueError):
            gate.launch(self.argv, spawn)
        self.config.write_bytes(b'fixed launch input\n')
        (self.root / 'data').rename(self.root / 'old-data')
        (self.root / 'data').mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            gate.launch(self.argv, spawn)
        spawn.assert_not_called()

    def test_redirected_or_shared_record_and_bool_schema_fail_closed(self):
        gate = self.enroll()
        record = domain.read_private(gate.path)
        domain.durable_replace(gate.path, dict(record, schema=True))
        with self.assertRaises(ValueError):
            gate.query()
        domain.durable_replace(gate.path, record)
        alias = self.control / 'other-link'
        os.link(gate.path, alias)
        with self.assertRaises(ValueError):
            gate.query()
        alias.unlink()
        real = self.control / 'original.json'
        gate.path.rename(real)
        gate.path.symlink_to(real)
        with self.assertRaises(OSError):
            gate.query()

    def test_control_inside_data_and_different_owned_executable_refused(self):
        nested = self.root / 'data/control'
        nested.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.enroll(control=nested)
        wrong = dict(self.binary, sha256='0' * 64)
        with self.assertRaises(ValueError):
            domain.observe_owned_executable(self.proc, wrong)
        self.assertNotIn(domain.KEY, domain.read_private(self.root / 'cluster.json'))


if __name__ == '__main__':
    unittest.main()
