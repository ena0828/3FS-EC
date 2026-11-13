#!/usr/bin/env python3
"""Pure topology and supervisor seams; never signals a real process."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import stat
import sys
import threading
import unittest
from unittest import mock
import uuid
from types import MethodType, SimpleNamespace
import native_fault_control as fault
from native_v2_config import (SPARE_GC_PROFILE, generate_configs, storage_process_count,
                              storage_specs, topology_problems, profile_config_problems)
SOURCE = Path(os.environ.get('EC_SOURCE', Path(__file__).resolve().parents[3]))


def manifest(root='/tmp/3fs-ec-native-spare-test'):
    return dict(
        profile=SPARE_GC_PROFILE, root=root, port_base=14500, authority=str(uuid.UUID(int=80)),
        storage_count=14, logical_target_count=14, storage_process_failure_domains=14,
        independent_storage_failure_domains=1,
        deployment_scope='single_machine_distinct_processes_not_physical_hosts',
        remote_global_storage_config_policy='pinned_local_mismatch_rejected_not_version_acked',
        file_api=True, initial_placement_nodes=list(range(10001, 10013)), spare_nodes=[10013, 10014],
        endpoints=[dict(node=10001 + i, chain=910001 + i, target=1100001 + i) for i in range(14)],
        gc=dict(authority=str(uuid.UUID(int=81)), key_id=str(uuid.UUID(int=82)),
                client_namespace=str(uuid.UUID(int=83)), data_protocol=2, disk_format=3, gc_protocol=2),
    )


def inventory(m):
    return [dict(v, engine_uuid=str(uuid.UUID(int=100 + i)), target_incarnation=str(uuid.UUID(int=200 + i)))
            for i, v in enumerate(m['endpoints'])]


class Process:

    def __init__(self, pid):
        self.pid = pid
        self.returncode = None
        self.kills = 0
        self.terms = 0
        self.waits = 0

    def poll(self):
        return self.returncode

    def kill(self):
        self.kills += 1
        self.returncode = -9
    def terminate(self):
        self.terms += 1
        # fake of Meta's handled graceful termination
        self.returncode = 0

    def wait(self, timeout=None):
        self.waits += 1
        return self.returncode


def controller(cluster):
    value = fault.FaultController.__new__(fault.FaultController)
    value.cluster = cluster
    value.enabled = True
    value.lock = threading.Lock()
    value.pending = None
    value.running = None
    value.expected = {}
    value.faulted = {}
    value.failed = False
    records = {}
    value._read = lambda key: copy.deepcopy(records.get(key))
    value._save = lambda record: records.__setitem__(record['request']['action_id'], copy.deepcopy(record))
    return (value, records)


class SpareStorageTests(unittest.TestCase):

    def test_fourteen_inventory_twelve_placement_and_legacy_unchanged(self):
        m = manifest()
        configs, _ = generate_configs(SOURCE, m['root'], m['port_base'], m['authority'], 'spare_test',
                                      profile='gc-14', gc=m['gc'], file_api=True)
        self.assertEqual(storage_process_count(m), 14)
        self.assertEqual(topology_problems(m), [])
        self.assertEqual(profile_config_problems(m, configs), [])
        self.assertEqual({s['port'] for s in storage_specs(m)}, set(range(14503, 14517)))
        self.assertEqual(len({s['data_path'] for s in storage_specs(m)}), 14)
        self.assertNotIn('ec_targets', configs['meta_main.toml']['server']['meta'])
        self.assertEqual(len(fault.initial_placement(m, inventory(m))), 12)
        with self.assertRaises(ValueError):
            generate_configs(SOURCE, m['root'], 14500, m['authority'], 'bad', profile='gc-14', gc=m['gc'], file_api=False)
        legacy, _ = generate_configs(SOURCE, m['root'], 14500, m['authority'], 'legacy')
        self.assertIn('storage_main.toml', legacy)
        self.assertNotIn('storage-10013.toml', legacy)

    def test_replacement_requires_confirmed_failure_and_exact_unused_spares(self):
        m = manifest()
        all_targets = inventory(m)
        old = fault.initial_placement(m, all_targets)
        saved = copy.deepcopy(all_targets)
        new = fault.replacement_placement(m, all_targets, old, [[10001, 10013], [10002, 10014]], {10001, 10002})
        self.assertEqual([r['node'] for r in new[:2]], [10013, 10014])
        self.assertEqual(new[2:], old[2:])
        self.assertEqual(all_targets, saved)
        for pairs, failed in (
            ([[10001, 10013]], set()), ([[10001, 10003]], {10001}),
            ([[10001, 10013], [10002, 10013]], {10001, 10002}), ([[True, 10013]], {10001}),
        ):
            with self.subTest(pairs=pairs):
                with self.assertRaises(ValueError):
                    fault.replacement_placement(m, all_targets, old, pairs, failed)

    def test_only_owned_live_popen_is_signalled_and_uuid_replay_is_not_reexecuted(self):
        child = Process(41)
        other = Process(42)
        cluster = SimpleNamespace(manifest=manifest(), run_id='owned-run', stage='ready',
                                  halt=threading.Event(), processes=[('storage-10001', child), ('meta', other)])
        c, records = controller(cluster)
        with self.assertRaises(RuntimeError):
            c._exit('storage-99999', fault=True)
        req = dict(operation='fault-storage', run='owned-run', action_id=str(uuid.UUID(int=900)), nodes=[10001])
        self.assertEqual(c.submit(req)['state'], 'queued')
        c.execute_one()
        self.assertEqual(c.submit(req)['state'], 'completed')
        c.execute_one()
        self.assertEqual((child.kills, child.waits, other.kills), (1, 1, 0))
        c.healthy()
        with self.assertRaises(ValueError):
            c.submit(dict(req, nodes=[10002]))
        with self.assertRaises(ValueError):
            c.submit(dict(req, run='wrong-run'))
        with self.assertRaises(RuntimeError):
            c._exit('storage-10001', fault=True)
        other.returncode = 3
        with self.assertRaises(RuntimeError):
            c.healthy()

    def test_configuration_failure_is_not_completed_and_does_not_restart_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            (root / 'config').mkdir()
            m = manifest(str(root))
            pool = inventory(m)
            (root / 'state/physical-pool.json').write_text(json.dumps(pool))
            (root / 'state/placement.json').write_text(json.dumps(dict(schema=1, pool=pool[:12], action_id=None)))
            (root / 'config/meta_main.toml').write_text('[server.meta]\nenable_ec_v2=true\n')
            cluster = SimpleNamespace(
                root=root, config=root / 'config', manifest=m, run_id='owned-run', stage='ready',
                halt=threading.Event(),
                processes=[(f'storage-{n}', Process(n)) for n in range(10002, 10015)] + [('meta', Process(100))],
                start_service=mock.Mock(),
            )
            c, _ = controller(cluster)
            c.faulted[10001] = {'exit_code': -9}
            c._discover = mock.Mock()
            req = dict(operation='replace-placement', run='owned-run', action_id=str(uuid.UUID(int=901)), replacements=[[10001, 10013]])
            c.submit(req)

            def publish(path, content):
                if path.name == 'meta_main.toml':
                    raise OSError('injected config persistence failure')
                path.write_text(content)
            with mock.patch.object(fault, 'replace_private', side_effect=publish):
                c.execute_one()
            self.assertEqual(c._read(req['action_id'])['state'], 'failed')
            self.assertTrue(c.failed)
            cluster.start_service.assert_not_called()
            self.assertEqual(cluster.stage, 'maintenance_failed')
            self.assertEqual(json.loads((root / 'state/physical-pool.json').read_text()), pool)
            self.assertEqual(c.submit(req)['state'], 'failed')

    def test_restart_requires_prior_owned_fault_and_rechecks_same_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            m = manifest(str(root))
            pool = inventory(m)
            (root / 'state/physical-pool.json').write_text(json.dumps(pool))
            old = Process(1)
            old.returncode = -9
            cluster = SimpleNamespace(
                root=root, manifest=m, run_id='owned-run', stage='ready', halt=threading.Event(),
                processes=[('storage-10001', old)], start_service=mock.Mock(),
                wait=mock.Mock(), node_ready=mock.Mock(return_value=True),
            )
            c, _ = controller(cluster)
            c.faulted[10001] = {'pid': old.pid, 'exit_code': -9}
            c._discover_one = mock.Mock(return_value=str(uuid.UUID(int=990)))
            req = dict(operation='restart-storage', run='owned-run', action_id=str(uuid.UUID(int=902)), nodes=[10001])
            c.submit(req)
            c.execute_one()
            cluster.start_service.assert_called_once_with('storage-10001')
            c._discover_one.assert_called_once()
            self.assertEqual(c._discover_one.call_args.args[0], pool[0])
            self.assertEqual(c.faulted, {})
            self.assertEqual(c.submit(req)['state'], 'completed')
            cluster.start_service.assert_called_once()

    def test_corrupt_retained_action_is_never_replaced_or_requeued(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = Process(41)
            cluster = SimpleNamespace(manifest=manifest(str(root)), run_id='owned-run', stage='ready',
                                      halt=threading.Event(), processes=[('storage-10001', child)])
            c, _ = controller(cluster)
            c.folder = root
            c._read = MethodType(fault.FaultController._read, c)
            c._save = mock.Mock()
            req = dict(operation='fault-storage', run='owned-run', action_id=str(uuid.UUID(int=903)), nodes=[10001])
            retained = dict(schema=1, request=req, state='queued', scope='owned_process_only_not_physical_host', steps=[])
            cases = [{}, [], None, dict(retained, schema=True), dict(retained, state=[]),
                     dict(retained, request=dict(req, action_id=str(uuid.UUID(int=904)))),
                     dict(retained, request=dict(req, run=[]))]
            path = c._path(req['action_id'])
            for body in cases:
                with self.subTest(body=body):
                    original = json.dumps(body).encode()
                    path.write_bytes(original)
                    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_size=len(original))
                    # Supply POSIX ownership metadata only; parse the actual bytes
                    # through production _read on Windows as well as Linux.
                    with (mock.patch.object(Path, 'lstat', return_value=info),
                          mock.patch.object(fault.os, 'geteuid', return_value=0, create=True)):
                        with self.assertRaises(ValueError):
                            c.submit(req)
                        with self.assertRaises(ValueError):
                            c.submit(dict(operation='action-status', run='owned-run', action_id=req['action_id']))
                    self.assertEqual(path.read_bytes(), original)
                    self.assertIsNone(c.pending)
                    self.assertEqual(child.kills, 0)
                    c._save.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Uses a real private Unix control socket, not Storage services')
    def test_invalid_operation_does_not_kill_control_thread_or_block_status_stop(self):
        path = Path(__file__).with_name('native-v2.py')
        spec = importlib.util.spec_from_file_location('spare_test_supervisor', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'state').mkdir()
            cluster = module.NativeCluster.__new__(module.NativeCluster)
            cluster.root = root
            cluster.manifest = manifest(str(root))
            cluster.run_id = 'owned-run'
            cluster.stage = 'ready'
            cluster.processes = []
            cluster.failure = None
            cluster.halt = threading.Event()
            cluster.socket_halt = threading.Event()
            cluster.status_lock = threading.Lock()
            cluster.control_path = root / 'state/control.sock'
            cluster.fault_control, _ = controller(cluster)
            cluster.control()
            try:
                for operation in ([], {}):
                    response = module.request_control(
                        root, dict(operation=operation, run='owned-run', action_id=str(uuid.UUID(int=905))))
                    self.assertIn('error', response)
                    self.assertTrue(cluster.control_thread.is_alive())
                    self.assertEqual(module.request_control(root, 'status')['stage'], 'ready')
                    self.assertIsNone(cluster.fault_control.pending)
                module.request_control(root, 'stop')
                self.assertTrue(cluster.halt.is_set())
            finally:
                cluster.socket_halt.set()
                cluster.control_socket.close()
                cluster.control_thread.join(timeout=5)
            self.assertFalse(cluster.control_thread.is_alive())
if __name__ == '__main__':
    unittest.main()
