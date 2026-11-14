"""Local command grammar and owned-child checks; no native services or RDMA."""
import copy
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import native_v2_config as profile


HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


ACK = module('supervisor_command_ack', 'ack-service-acceptance.py')
RUNNER = module('supervisor_command_runner', 'experiment-runner.py')
FAULT = module('supervisor_command_fault', 'spare-fault-acceptance.py')


class SupervisorCommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='supervisor-command-', dir=HERE)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        for name in ('client', 'client/runs', 'client/reports', 'config', 'state', 'scripts', 'lib', 'logs'):
            (self.root / name).mkdir(mode=0o700)
        self.enterContext(mock.patch.object(profile, 'Path', PurePosixPath))
        # The owner runs only on Linux in production. This narrow constant seam
        # lets Windows exercise the exact owner with a fake Popen, not a service.
        self.enterContext(mock.patch.object(ACK.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True))
        self.run = 'fixed-supervisor-run'
        self.action = dict(operation='fault-storage', run=self.run,
                           action_id='11111111-1111-1111-1111-111111111111', nodes=[10001, 10002])
        self.processes = []

    def runner(self, rdma=True):
        authority = '22222222-2222-2222-2222-222222222222'
        gc = dict(authority='33333333-3333-3333-3333-333333333333',
                  key_id='44444444-4444-4444-4444-444444444444',
                  client_namespace='55555555-5555-5555-5555-555555555555',
                  data_protocol=2, disk_format=3, gc_protocol=2)
        selection = dict(transport='rdma', rdma_interface='enp1s0', rdma_address='192.0.2.10', rdma_device='mlx5_0') if rdma else {}
        configs, _ = profile.generate_configs(HERE.parents[2], self.root, 20000, authority, 'FAKE_ONLY',
                                               profile='gc-14', gc=gc, file_api=True, **selection)
        for name, value in configs.items():
            folder = 'client' if name in ('stripe-client.toml', 'file-client.toml') else 'config'
            (self.root / folder / name).write_text(profile.to_toml(value), encoding='utf8')
        manifest = dict(schema=1, profile=profile.SPARE_GC_PROFILE, file_api=True, gc=gc, root=str(self.root),
                        port_base=20000, authority=authority, cluster_id='FAKE_ONLY')
        initialized = dict(schema=1, cluster_id='FAKE_ONLY')
        if rdma:
            manifest['data_transport'] = profile.requested_transport(**selection)
            initialized['data_transport'] = copy.deepcopy(manifest['data_transport'])
        (self.root / 'cluster.json').write_bytes(RUNNER.json_data(manifest))
        (self.root / 'state/initialized.json').write_bytes(RUNNER.json_data(initialized))
        return RUNNER.Runner(self.root, config=self.root / 'client/file-client.toml')

    def argv(self, operation='status', action=None):
        args = [sys.executable, str(self.root / 'scripts/native-v2.py'), operation, '--root', str(self.root)]
        if action is not None:
            args += ['--run', action['run'], '--action-id', action['action_id']]
            if operation != 'action-status':
                if 'nodes' in action:
                    args += ['--nodes', ','.join(map(str, action['nodes']))]
                else:
                    args += ['--replace', ','.join(f'{old}:{new}' for old, new in action['replacements'])]
                args += ['--wait-seconds', '600']
        return args

    def fake_popen(self, *, on_wait=None, returncode=0):
        owner = self
        class Child:
            pid = 12345
            def __init__(self, argv, **kwargs):
                self.argv, self.kwargs, self.returncode, self.waits = argv, kwargs, None, []
                kwargs['stdout'].write(b'{"observed":true}\n')
                owner.processes.append(self)
            def poll(self):
                return self.returncode
            def wait(self, timeout=None):
                self.waits.append(timeout)
                if on_wait is not None:
                    on_wait()
                self.returncode = returncode
                return self.returncode
        return Child

    def execute(self, runner, operation='status', action=None, argv=None):
        return ACK.supervisor_command(runner, RUNNER, argv if argv is not None else self.argv(operation, action),
                                      operation=operation, run=self.run if action is not None else None, action=action)

    def test_rdma_all_allowed_controls_join_without_data_transport_claim(self):
        runner = self.runner()
        actions = [None, self.action, dict(self.action, operation='restart-storage'),
                   dict(operation='replace-placement', run=self.run, action_id=self.action['action_id'],
                        replacements=[[10001, 10013], [10002, 10014]]), self.action]
        operations = ['status', 'fault-storage', 'restart-storage', 'replace-placement', 'action-status']
        with mock.patch.object(ACK.subprocess, 'Popen', self.fake_popen()), \
                mock.patch.object(runner, 'check_transport', wraps=runner.check_transport) as check:
            for operation, action in zip(operations, actions, strict=True):
                self.assertEqual(json.loads(self.execute(runner, operation, action)), {'observed': True})
            self.assertEqual(check.call_count, 5)
        self.assertEqual(len(runner.commands), 5)
        for child, row in zip(self.processes, runner.commands, strict=True):
            self.assertEqual(row['kind'], 'supervisor_control')
            self.assertNotIn('transport', row)
            self.assertTrue(row['process_started'] and row['process_exited'])
            self.assertFalse(row['remote_release_proven_by_exit'])
            self.assertEqual(row['returncode'], 0)
            self.assertEqual(child.waits, [0.2, None])
            self.assertTrue(child.kwargs['start_new_session'])
        self.assertIsNone(runner.child)
        self.assertFalse((self.root / 'client/transport-bindings').exists())

    def test_tcp_keeps_previous_argv_and_ledger_shape(self):
        runner = self.runner(False)
        with mock.patch.object(ACK.subprocess, 'Popen', self.fake_popen()):
            self.execute(runner, 'fault-storage', self.action)
        row = runner.commands[0]
        self.assertEqual(row['argv'], self.argv('fault-storage', self.action))
        self.assertEqual(set(row), {'index', 'argv', 'process_started', 'process_exited',
                                   'remote_release_proven_by_exit', 'equivalent_bash', 'pid', 'returncode'})
        self.assertNotIn('transport', row)
        self.assertNotIn('kind', row)

    def test_rejects_arbitrary_executable_paths_operations_flags_and_fixed_action_changes(self):
        runner = self.runner()
        original = self.argv('fault-storage', self.action)
        mutations = [(0, '/different/python'), (1, str(self.root / 'scripts/other.py')),
                     (2, 'stop'), (4, str(self.root / 'other-root')), (6, 'another-run'),
                     (8, '66666666-6666-6666-6666-666666666666'), (10, '10003'), (12, '601'),
                     (9, '--replace'), (10, '010001'), (8, '00000000-0000-0000-0000-000000000000')]
        with mock.patch.object(ACK.subprocess, 'Popen') as popen:
            for index, value in mutations:
                args = list(original)
                args[index] = value
                with self.subTest(index=index, value=value), self.assertRaises((RuntimeError, ValueError)):
                    self.execute(runner, 'fault-storage', self.action, args)
            for args in (original + ['--transport', 'tcp'], self.argv() + ['--run', self.run],
                         original[:-2], original + ['--root', str(self.root)]):
                with self.assertRaises(RuntimeError):
                    self.execute(runner, 'fault-storage', self.action, args)
            for action in (dict(self.action, nodes=[True]), dict(self.action, extra='ignored')):
                with self.assertRaises(RuntimeError):
                    self.execute(runner, 'fault-storage', action, original)
            recorded = ['/usr/bin/python3', *original[1:]]
            with mock.patch.object(ACK.sys, 'executable', '/different/receipt-reader'):
                self.assertEqual(ACK.validate_supervisor_command(
                    self.root, recorded, expected_executable='/usr/bin/python3'), self.action)
                with self.assertRaises(RuntimeError):
                    ACK.validate_supervisor_command(self.root, recorded)
                with self.assertRaises(RuntimeError):
                    ACK.validate_supervisor_command(self.root, ['/other/python', *recorded[1:]],
                                                    expected_executable='/usr/bin/python3')
                # The dispatch API cannot inherit a receipt reader's override.
                with self.assertRaises(RuntimeError):
                    self.execute(runner, 'fault-storage', self.action, recorded)
            popen.assert_not_called()
        self.assertEqual(runner.commands, [])

    def test_data_entry_cannot_dispatch_supervisor_but_still_binds_real_file_command(self):
        runner = self.runner()
        with mock.patch.object(ACK.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'original native executable'):
                ACK.command(runner, RUNNER, self.argv())
            popen.assert_not_called()
        run = runner.runs / 'file-command'
        argv = [str(self.root / 'bin/ec_file_cli'), '--cfg=' + str(runner.config),
                '--config.storage_transport=rdma', '--config.run_dir=' + str(run), 'query']
        with mock.patch.object(ACK.subprocess, 'Popen', self.fake_popen()):
            ACK.command(runner, RUNNER, argv)
        row = runner.commands[0]
        self.assertEqual(row['transport'], runner.transport)
        self.assertNotIn('kind', row)
        self.assertEqual(len(list((self.root / 'client/transport-bindings').glob('*.json'))), 1)

    def test_profile_drift_and_stop_before_control_never_start_a_child(self):
        runner = self.runner()
        original = runner.config.read_bytes()
        runner.config.write_bytes(original + b'\n# profile changed\n')
        with mock.patch.object(ACK.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RUNNER.CheckError, 'changed during'):
                self.execute(runner)
            runner.config.write_bytes(original)
            runner.request_stop()
            with self.assertRaisesRegex(RuntimeError, 'Stop requested'):
                self.execute(runner)
            popen.assert_not_called()
        self.assertEqual(runner.commands, [])

    def test_stop_after_dispatch_waits_for_owned_child_and_prevents_following_control(self):
        runner = self.runner()
        with mock.patch.object(ACK.subprocess, 'Popen', self.fake_popen(on_wait=runner.request_stop)):
            with self.assertRaisesRegex(RuntimeError, 'Owned command joined'):
                self.execute(runner)
            with self.assertRaisesRegex(RuntimeError, 'Stop requested'):
                self.execute(runner)
        self.assertEqual(len(self.processes), 1)
        self.assertEqual(self.processes[0].waits, [0.2, None])
        self.assertTrue(runner.commands[0]['process_exited'])
        self.assertIsNone(runner.child)

    def test_event_error_after_spawn_still_joins_and_keeps_original_error(self):
        runner = self.runner()
        original_event = runner.event
        def event(value):
            if value['event'] == 'command_started':
                raise OSError('injected event write failure')
            original_event(value)
        with mock.patch.object(ACK.subprocess, 'Popen', self.fake_popen()), mock.patch.object(runner, 'event', event):
            with self.assertRaisesRegex(OSError, 'injected event write'):
                self.execute(runner)
        self.assertEqual(self.processes[0].waits, [None])
        self.assertTrue(runner.commands[0]['process_exited'])
        self.assertIsNone(runner.child)

    def test_fault_case_uses_same_saved_action_and_never_replaces_or_retries_it(self):
        runner = self.runner()
        action_path = runner.report / 'actions.json'
        action_path.write_bytes(RUNNER.json_data({'fault': self.action}))
        saved = action_path.read_bytes()
        acceptance = SimpleNamespace(runner=runner, w=RUNNER, transport=ACK, folder=runner.report,
                                     guard=mock.Mock(), save=mock.Mock(), hash=lambda p: RUNNER.regular_bytes(p, 2 << 20).hex())
        case = FAULT.FaultCase(acceptance, None, 'helper', 2)
        case.run = self.run
        with mock.patch.object(ACK.subprocess, 'Popen', self.fake_popen()):
            self.assertEqual(case.control('fault-storage', self.action), {'observed': True})
            for altered in (dict(self.action, action_id='66666666-6666-6666-6666-666666666666'),
                            dict(self.action, nodes=[10003]), dict(self.action, run='other')):
                with self.assertRaisesRegex(RuntimeError, 'persisted intent'):
                    case.control('fault-storage', altered)
        self.assertEqual(len(self.processes), 1)
        self.assertEqual(action_path.read_bytes(), saved)
        self.assertEqual(len(case.controls), 1)
        self.assertTrue(case.controls[0]['process']['process_exited'])

    @unittest.skipUnless(sys.platform == 'linux', 'real owned Python child/session requires Linux')
    def test_linux_real_python_control_exit_is_joined_even_when_nonzero(self):
        runner = self.runner()
        script = self.root / 'scripts/native-v2.py'
        script.write_text('import json,sys\nprint(json.dumps({"argv":sys.argv[1:]}))\nraise SystemExit(7)\n')
        with self.assertRaisesRegex(RuntimeError, 'Admin command failed'):
            self.execute(runner)
        self.assertEqual(len(runner.commands), 1)
        row = runner.commands[0]
        self.assertEqual(row['returncode'], 7)
        self.assertTrue(row['process_started'] and row['process_exited'])
        self.assertIsNone(runner.child)
        self.assertEqual(json.loads((runner.report / 'command-000.log').read_text())['argv'],
                         ['status', '--root', str(self.root)])


if __name__ == '__main__':
    unittest.main()
