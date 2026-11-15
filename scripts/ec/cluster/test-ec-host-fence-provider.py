#!/usr/bin/env python3
"""Provider state-machine tests with fake kernel/signing; not fencing acceptance.

These exercise the real durable JSON state transitions and canonical encoder.
The separate privileged acceptance must use real UID/cgroup/Storage and Ed25519.
"""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

spec = importlib.util.spec_from_file_location('host_fence', Path(__file__).with_name('ec-host-fence-provider.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def uid(number):
    return str(uuid.UUID(int=number))


class Kernel:
    def __init__(self):
        self.events = []
        self.live_uid = False
        self.killed = False
        self.quarantined = False
        self.fail_kill = False
        self.fail_quarantine = False
        self.changed_inputs = False

    def trusted(self, *args, **kwargs):
        return None

    def inputs(self, value):
        return {'resources': {'data': [1, 2], 'logs': [1, 3]}, 'files': {}}

    def uid_processes(self, value):
        return [42] if self.live_uid else []

    def cgroup(self, *args, **kwargs):
        self.events.append('create_cgroup')

    def check_inputs(self, record):
        m.require(not self.changed_inputs, 'Changed immutable input')

    def live(self, record):
        m.require(self.live_uid and record['launch']['state'] == 'running', 'No real live launch')

    def probe(self, record, identity, folder):
        # Fake adapter evidence only. Privileged acceptance runs the actual Admin CLI.
        path = folder / 'simulated-discovery.json'
        path.write_text(json.dumps(identity))
        raw = path.read_bytes()
        return {'identity': identity, 'artifacts': {str(path): {'bytes': len(raw), 'sha256': m.sha(raw)}}}

    def kill_and_empty(self, record, timeout):
        self.events.append('kill')
        m.require(record['deny'] is not None, 'Kill before durable deny')
        # Also read the actual persisted state, rather than trusting in-memory order.
        persisted = m.read_json(self.path)
        m.require(persisted['deny'] == record['deny'], 'Deny not persisted before kill')
        m.require(not self.fail_kill, 'Kernel still populated')
        self.live_uid = False
        self.killed = True

    def quarantine(self, record):
        self.events.append('quarantine')
        m.require(not self.fail_quarantine, 'Quarantine failed')
        self.quarantined = True

    def fenced(self, record):
        m.require(self.killed and self.quarantined and not self.live_uid, 'No complete kernel fence')
        return {'path': record['spec']['data'], 'device_decimal': '1', 'inode_decimal': '2',
                'owner_uid': 0, 'owner_gid': 0, 'mode_octal': '0700'}


class StateProvider(m.Provider):
    @contextlib.contextmanager
    def locked(self):
        # No interprocess/kernel lock is claimed by these pure tests.
        yield

    def sign(self, value):
        self.kernel.events.append('sign')
        self.kernel.fenced(self.read(uid(2)))
        return b'\xa5' * 64


class HostFenceProvider(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'enrollments').mkdir()
        (self.root / 'provider.json').write_text(json.dumps({'provider_id': uid(1)}))
        self.kernel = Kernel()
        self.provider = StateProvider(self.root, self.kernel)
        self.enrollment = {'schema': 1, 'provider_id': uid(1), 'enrollment_id': uid(2),
            'resource_generation': uid(3), 'uid': 23456, 'gid': 23456,
            'domain': '/var/lib/3fs-ec-fence/domains/' + uid(2), 'data': '/unused/data',
            'logs': '/unused/logs', 'argv': ['/unused/bin/storage_main'], 'env': {}}
        self.kernel.path = self.root / 'enrollments' / (uid(2) + '.json')
        self.identity = {'authority': uid(4), 'endpoint': {'node': 10001, 'chain': 1, 'target': 7,
            'engine_uuid': uid(5), 'target_incarnation': uid(6)}}

    def bound(self):
        self.provider.enroll(copy.deepcopy(self.enrollment))
        record = self.provider.read(uid(2))
        record['launch'] = {'state': 'running', 'pid': 42, 'start_ticks': 99, 'id': uid(7), 'exitcode': None}
        self.provider.save(record)
        self.kernel.live_uid = True
        binding = self.provider.bind(uid(2), copy.deepcopy(self.identity))
        return dict(schema=1, **self.identity, provider_id=uid(1), enrollment_id=uid(2),
                    resource_generation=uid(3), retirement_id=uid(8), owner_namespace=uid(9),
                    owner_uid=0, request_id=uid(10), binding_digest=binding['binding_digest'])

    def test_canonical_fixed_fields_and_signature_boundary(self):
        intent = self.bound()
        payload = m.certificate_payload(intent, '11' * 32)
        self.assertEqual(len(payload), 248)
        self.assertEqual(payload[:12], b'3FSEHF01\x00\x01\x00\x01')
        self.assertEqual(payload[12:28], uuid.UUID(uid(4)).bytes)
        self.assertEqual(payload[28:44], struct.pack('>IIQ', 10001, 1, 7))
        self.assertEqual(payload[-8:], struct.pack('>Q', 1))
        for mutate in (lambda x: x.update(owner_uid=True), lambda x: x.update(schema=True),
                       lambda x: x['endpoint'].update(target=2**64), lambda x: x.update(extra=0)):
            bad = copy.deepcopy(intent)
            mutate(bad)
            with self.assertRaises(ValueError):
                m.certificate_payload(bad, '11' * 32)

    def test_enrollment_rejects_preexisting_process_and_uid_reuse(self):
        self.kernel.live_uid = True
        with self.assertRaises(ValueError):
            self.provider.enroll(self.enrollment)
        self.assertFalse(self.kernel.path.exists())
        self.kernel.live_uid = False
        self.provider.enroll(self.enrollment)
        another = dict(self.enrollment, enrollment_id=uid(20), resource_generation=uid(21), domain='/new')
        with self.assertRaises(ValueError):
            self.provider.enroll(another)

    def test_binding_requires_original_live_launch_and_is_immutable(self):
        self.provider.enroll(self.enrollment)
        with self.assertRaises((ValueError, TypeError)):
            self.provider.bind(uid(2), self.identity)
        self.assertIsNone(self.provider.read(uid(2))['bound'])
        record = self.provider.read(uid(2))
        record['launch'] = {'state': 'running'}
        self.provider.save(record)
        self.kernel.live_uid = True
        first = self.provider.bind(uid(2), self.identity)
        self.assertEqual(self.provider.bind(uid(2), self.identity), first)
        with self.assertRaises(ValueError):
            self.provider.bind(uid(2), dict(self.identity, authority=uid(30)))

    def test_kill_failure_keeps_durable_deny_without_certificate(self):
        intent = self.bound()
        self.kernel.fail_kill = True
        with self.assertRaises(ValueError):
            self.provider.fence(intent)
        record = self.provider.read(uid(2))
        self.assertEqual(record['deny']['intent'], intent)
        self.assertIsNone(record['completion'])
        self.assertNotIn('sign', self.kernel.events)
        before = self.kernel.path.read_bytes()
        with self.assertRaises(ValueError):
            StateProvider(self.root, self.kernel).query(intent)
        self.assertEqual(self.kernel.path.read_bytes(), before)

    def test_quarantine_failure_retries_original_intent_after_restart(self):
        intent = self.bound()
        self.kernel.fail_quarantine = True
        with self.assertRaises(ValueError):
            self.provider.fence(intent)
        self.assertIsNone(self.provider.read(uid(2))['completion'])
        self.kernel.fail_quarantine = False
        restarted = StateProvider(self.root, self.kernel)
        result = restarted.fence(intent)
        self.assertEqual(len(bytes.fromhex(result['certificate_hex'])), 312)
        self.assertFalse(result['physical_reclamation_confirmed'])
        self.assertEqual(result['resource_disposition']['state'], 'RetiredInaccessible')
        self.assertTrue(result['resource_disposition']['capacity_retained'])
        self.assertFalse(result['resource_disposition']['physical_capacity_returned'])
        self.assertEqual(self.kernel.events[-3:], ['kill', 'quarantine', 'sign'])

    def test_completed_query_and_same_intent_replay_do_not_kill_or_resign(self):
        intent = self.bound()
        first = self.provider.fence(intent)
        before = self.kernel.path.read_bytes()
        events = list(self.kernel.events)
        restarted = StateProvider(self.root, self.kernel)
        self.assertEqual(restarted.query(intent), first)
        self.assertEqual(restarted.fence(intent), first)
        self.assertEqual(events, self.kernel.events)
        self.assertEqual(self.kernel.path.read_bytes(), before)

    def test_changed_intent_or_endpoint_never_reuses_certificate(self):
        intent = self.bound()
        self.provider.fence(intent)
        for key in ('retirement_id', 'request_id', 'owner_namespace', 'provider_id', 'resource_generation'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.provider.query(dict(intent, **{key: uid(40)}))
        altered = copy.deepcopy(intent)
        altered['endpoint']['target'] += 1
        with self.assertRaises(ValueError):
            self.provider.query(altered)

    def test_changed_inputs_or_reappeared_uid_blocks_query(self):
        intent = self.bound()
        self.provider.fence(intent)
        self.kernel.changed_inputs = True
        with self.assertRaises(ValueError):
            self.provider.query(intent)
        self.kernel.changed_inputs = False
        self.kernel.live_uid = True
        with self.assertRaises(ValueError):
            self.provider.query(intent)

    def test_new_binding_after_denial_and_fabricated_deny_digest_rejected(self):
        intent = self.bound()
        self.provider.fence(intent)
        with self.assertRaises(ValueError):
            self.provider.bind(uid(2), self.identity)
        record = self.provider.read(uid(2))
        record['completion']['deny_digest'] = '22' * 32
        self.provider.save(record)
        with self.assertRaises(ValueError):
            self.provider.query(intent)
        # Exact leaf ownership exception: it does not relax any ancestor gate
        # or permit F/root keys to become generally storage-owned.
        kernel = object.__new__(m.Linux)
        info = SimpleNamespace(st_uid=23456, st_mode=stat.S_IFREG | 0o400, st_nlink=1)
        path = SimpleNamespace(parents=[], lstat=lambda: info)
        with mock.patch.object(m, 'safe_path', return_value=path):
            self.assertIs(kernel.trusted('/fixed-role', role_uid=23456), info)
            with self.assertRaises(ValueError):
                kernel.trusted('/fixed-role')
            for owner, mode in [(23456, 0o440), (23456, 0o600), (23457, 0o400), (0, 0o600)]:
                info.st_uid, info.st_mode = owner, stat.S_IFREG | mode
                with self.subTest(owner=owner, mode=mode), self.assertRaises(ValueError):
                    kernel.trusted('/fixed-role', role_uid=23456)

    def test_actual_probe_parsers_reject_wrong_process_and_instance(self):
        line = '10001 STORAGE HEARTBEAT_CONNECTED host-a 42 [] 2026-11-15 1 v1\n'
        self.assertEqual(m.routing_row(line, 10001, 42, 'host-a')[-1], '42')
        for text in (line + line, line.replace(' 42 ', ' 43 '),
                     line.replace('host-a', 'host-b'), line.replace('HEARTBEAT_CONNECTED', 'OFFLINE')):
            with self.assertRaises(ValueError):
                m.routing_row(text, 10001, 42, 'host-a')
        actual = dict(schema=1, authority=uid(4), node=10001, chain=1, target=7,
                      engine_uuid=uid(5), target_incarnation=uid(6), protocol=2,
                      observed_at_seconds=100, verified_at_seconds=101, verification='control_mac_verified')
        self.assertEqual(m.discovery_identity(actual, self.identity, 102), self.identity)
        for key, value in [('engine_uuid', uid(99)), ('target_incarnation', uid(99)),
                           ('node', 10002), ('schema', True), ('protocol', 1),
                           ('observed_at_seconds', 1), ('verification', 'unverified')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.discovery_identity(dict(actual, **{key: value}), self.identity, 102)


if __name__ == '__main__':
    unittest.main(verbosity=2)
