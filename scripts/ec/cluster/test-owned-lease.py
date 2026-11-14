"""Owned CLI lease handoff: mock boundaries and Linux-only private Python children."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


ACK = module('owned_lease_ack', 'ack-service-acceptance.py')
WRAPPER = module('owned_lease_wrapper', 'experiment-runner.py')


class OwnedLeaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='owned-lease-', dir=HERE)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        for name in ('client', 'config', 'lib', 'logs'):
            (self.root / name).mkdir(mode=0o700)
        (self.root / 'config/admin_cli.toml').write_text('# No native service or token\n', encoding='utf8')
        self.enterContext(patch.object(ACK.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True))

    def runner(self):
        return WRAPPER.Runner(self.root, config=self.root / 'config/admin_cli.toml')

    def argv(self):
        return [str(self.root / 'bin/admin_cli'), '--cfg', str(self.root / 'config/admin_cli.toml'),
                '--', 'ec-gc-query FIXTURE_ONLY']

    def test_control_descriptor_handoff_and_logging_failure_still_join(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=123, st_nlink=1)
        for report_failure in (False, True):
            with self.subTest(report_failure=report_failure):
                runner = self.runner()
                child = Mock(pid=456, returncode=0)
                child.poll.return_value = 0
                event = runner.event

                def emit(value):
                    if report_failure and value['event'] == 'command_started':
                        raise OSError('injected after actual child registration')
                    event(value)

                runner.event = emit
                original_fstat = os.fstat
                with patch.object(ACK.sys, 'platform', 'linux'), \
                     patch.object(ACK.os, 'geteuid', return_value=123, create=True), \
                     patch.object(ACK.os, 'fstat', side_effect=lambda fd: info if fd == 9876 else original_fstat(fd)), \
                     patch.object(ACK.subprocess, 'Popen', return_value=child) as popen:
                    if report_failure:
                        with self.assertRaisesRegex(OSError, 'injected'):
                            ACK.command(runner, WRAPPER, self.argv(), pass_fds=(9876,))
                    else:
                        self.assertEqual(ACK.command(runner, WRAPPER, self.argv(), pass_fds=(9876,)), '')
                    self.assertEqual(popen.call_args.kwargs['pass_fds'], (9876,))
                child.wait.assert_called_once()
                self.assertIsNone(runner.child)
                self.assertTrue(runner.commands[0]['process_exited'])
                self.assertTrue(runner.commands[0]['inherited_collector_lease'])
                self.assertFalse(runner.commands[0]['remote_release_proven_by_exit'])

    def test_invalid_lease_or_data_role_never_starts_a_child(self):
        runner = self.runner()
        with patch.object(ACK.subprocess, 'Popen') as popen:
            for descriptors in (None, [], (True,), (0,), (1,), (2,), (3, 4)):
                with self.subTest(descriptors=descriptors), self.assertRaises(RuntimeError):
                    ACK.command(runner, WRAPPER, self.argv(), pass_fds=descriptors)
            with patch.object(ACK.sys, 'platform', 'linux'), \
                 patch.object(ACK.os, 'geteuid', return_value=123, create=True):
                for mode, uid, links in ((stat.S_IFREG | 0o644, 123, 1),
                                         (stat.S_IFREG | 0o600, 124, 1),
                                         (stat.S_IFREG | 0o600, 123, 2),
                                         (stat.S_IFIFO | 0o600, 123, 1)):
                    with patch.object(ACK.os, 'fstat', return_value=SimpleNamespace(
                            st_mode=mode, st_uid=uid, st_nlink=links)), self.assertRaises(RuntimeError):
                        ACK.command(runner, WRAPPER, self.argv(), pass_fds=(9876,))
            with patch.object(ACK.sys, 'platform', 'win32'), self.assertRaises(RuntimeError):
                ACK.command(runner, WRAPPER, self.argv(), pass_fds=(9876,))
            runner.transport_role = 'file'
            with self.assertRaisesRegex(RuntimeError, 'executable/config'):
                ACK.command(runner, WRAPPER, self.argv(), pass_fds=(9876,))
            popen.assert_not_called()
        self.assertEqual(runner.commands, [])
        self.assertIsNone(runner.child)

    def file_argv(self, action='create'):
        values = [str(self.root / 'bin/ec_file_cli'), '--cfg=' + str(self.root / 'client/file-client.toml'),
                  '--config.run_dir=' + str(self.root / 'client/runs/original')]
        if action == 'create':
            values += ['--config.file_path=/ec-lab/trace-instance', '--config.shard_bytes=11469',
                       '--config.permission=384', '--config.session_rights=3']
        if action == 'export-read-allocations':
            values += ['--config.output_file=' + str(self.root / 'client/snapshot.json')]
        return values + ['--config.storage_transport=rdma', 'mode4-' + action]

    def test_file_lease_keeps_transport_gate_join_and_local_export_scope(self):
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=123, st_nlink=1)
        for action in ('create', 'export-read-allocations'):
            with self.subTest(action=action):
                runner = self.runner(); runner.transport_role = 'file'
                runner.config = self.root / 'client/file-client.toml'
                runner.check_transport = Mock(return_value={'mode': 'rdma'})
                child = Mock(pid=456, returncode=0); child.poll.return_value = 0
                original_fstat = os.fstat
                with patch.object(ACK.sys, 'platform', 'linux'), \
                     patch.object(ACK.os, 'geteuid', return_value=123, create=True), \
                     patch.object(ACK.os, 'fstat', side_effect=lambda fd: info if fd == 9876 else original_fstat(fd)), \
                     patch.object(WRAPPER, 'bind_transport_run') as bind, \
                     patch.object(ACK.subprocess, 'Popen', return_value=child) as popen:
                    ACK.command(runner, WRAPPER, self.file_argv(action), pass_fds=(9876,))
                    self.assertEqual(popen.call_args.kwargs['pass_fds'], (9876,))
                    runner.check_transport.assert_called_once()
                    if action == 'create':
                        bind.assert_called_once()
                        self.assertEqual(runner.commands[0]['transport'], {'mode': 'rdma'})
                    else:
                        bind.assert_not_called()
                        self.assertNotIn('transport', runner.commands[0])
                        self.assertEqual(runner.commands[0]['kind'], 'local_read_export')
                child.wait.assert_called_once()
                self.assertIsNone(runner.child)
                self.assertTrue(runner.commands[0]['process_exited'])

    def test_file_lease_rejects_program_config_operation_and_path_drift(self):
        runner = self.runner(); runner.transport_role = 'file'
        runner.config = self.root / 'client/file-client.toml'
        original = self.file_argv()
        variants = [
            ['other-program', *original[1:]],
            [original[0], '--cfg=' + str(self.root / 'config/admin_cli.toml'), *original[2:]],
            [*original[:-1], 'mode4-seal'],
            [*original[:2], '--config.run_dir=relative', *original[3:]],
            [*original[:-1], '--config.run_dir=' + str(self.root / 'another'), original[-1]],
            [*original[:-1], '--config.user_info.uid=0', original[-1]],
            [*original[:-1], '--cfg=' + str(runner.config), original[-1]],
        ]
        with patch.object(ACK.subprocess, 'Popen') as popen:
            for argv in variants:
                with self.subTest(argv=argv), self.assertRaises(RuntimeError):
                    ACK.command(runner, WRAPPER, argv, pass_fds=(9876,))
            runner.stop_requested = True
            with self.assertRaisesRegex(RuntimeError, 'Stop requested'):
                ACK.command(runner, WRAPPER, original, pass_fds=(9876,))
            popen.assert_not_called()

    def test_namespace_lease_is_control_only_and_resume_forbids_replacement_identity(self):
        runner = self.runner(); runner.transport_role = 'file'
        runner.config = self.root / 'client/file-client.toml'
        runner.check_transport = Mock(return_value={'mode': 'rdma'})
        for action in ('unlink', 'resume-unlink', 'inspect-unlink'):
            argv = self.file_argv(action)
            if action == 'unlink':
                argv[2:2] = ['--config.session_run_dir=' + str(self.root / 'original-session'),
                             '--config.file_path=/ec-lab/fixed-instance']
            with self.subTest(action=action), patch.object(ACK, '_owned_command', return_value='observed') as owned, \
                 patch.object(WRAPPER, 'bind_transport_run') as bind:
                self.assertEqual(ACK.command(runner, WRAPPER, argv, pass_fds=(9876,)), 'observed')
                self.assertIsNone(owned.call_args.args[3])
                self.assertEqual(owned.call_args.kwargs['pass_fds'], (9876,))
                self.assertEqual(owned.call_args.kwargs['kind'],
                                 'local_namespace_inspect' if action == 'inspect-unlink' else 'namespace_control')
                bind.assert_not_called()
                if action != 'unlink':
                    with self.assertRaisesRegex(RuntimeError, 'argument set'):
                        ACK.command(runner, WRAPPER, argv[:-1] + ['--config.file_path=/replacement', argv[-1]],
                                    pass_fds=(9876,))
            with patch.object(ACK, '_owned_command') as owned, self.assertRaisesRegex(RuntimeError, 'executable/config'):
                ACK.command(runner, WRAPPER, ['other-program', *argv[1:]])
            owned.assert_not_called()

    def test_collector_trace_lease_only_allows_fixed_start_and_resume(self):
        base = [sys.executable, '-B', str(self.root / 'scripts/tree-gc-runner.py'), 'start',
                '--root', str(self.root), '--run-dir', str(self.root / 'client/collector'),
                '--expected', str(self.root / 'client/expected.json')]
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=123, st_nlink=1)
        recorded = ['/usr/bin/python3', *base[1:]]
        self.assertEqual(ACK.validate_collector_command(self.root, recorded,
                         expected_executable='/usr/bin/python3')['action'], 'start')
        bounded = base + ['--max-nodes', '2064', '--max-commands', '16384']
        self.assertEqual(ACK.validate_collector_command(self.root, bounded)['limits'], {'nodes': 2064, 'commands': 16384})
        for limits in (['--max-nodes', '0', '--max-commands', '16384'],
                       ['--max-nodes', '2064', '--max-commands', '16385'],
                       ['--max-nodes', '02064', '--max-commands', '16384']):
            with self.assertRaises(RuntimeError): ACK.validate_collector_command(self.root, base + limits)
        with patch.object(ACK.sys, 'executable', '/different/reader/python3'), \
             patch.object(ACK.subprocess, 'Popen') as forbidden:
            with self.assertRaisesRegex(RuntimeError, 'executable/root'):
                ACK.collector_command(self.runner(), WRAPPER, recorded, pass_fds=(9876,))
            forbidden.assert_not_called()
        original_fstat = os.fstat
        for argv in (base, base[:3] + ['resume'] + base[4:8]):
            runner = self.runner(); child = Mock(pid=456, returncode=0); child.poll.return_value = 0
            with patch.object(ACK.sys, 'platform', 'linux'), \
                 patch.object(ACK.os, 'geteuid', return_value=123, create=True), \
                 patch.object(ACK.os, 'fstat', side_effect=lambda fd: info if fd == 9876 else original_fstat(fd)), \
                 patch.object(ACK.subprocess, 'Popen', return_value=child) as popen:
                ACK.collector_command(runner, WRAPPER, argv, pass_fds=(9876,))
                self.assertEqual(popen.call_args.kwargs['pass_fds'], (9876,))
            child.wait.assert_called_once()
            self.assertEqual(runner.commands[0]['kind'], 'tree_gc_collector')
            self.assertNotIn('transport', runner.commands[0])
        for index, replacement in ((0, 'python-other'), (2, str(self.root / 'scripts/arbitrary.py')),
                                   (3, 'delete'), (5, str(self.root / 'other-root')), (7, 'relative')):
            argv = list(base); argv[index] = replacement
            with patch.object(ACK.subprocess, 'Popen') as popen, self.assertRaises(RuntimeError):
                ACK.collector_command(self.runner(), WRAPPER, argv, pass_fds=(9876,))
            popen.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Requires Linux flock and private Python processes')
    def test_child_keeps_kernel_lock_after_parent_descriptor_is_closed(self):
        import fcntl
        lock = self.root / 'lease'
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        probe = os.open(lock, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        runner = self.runner()
        original_event = runner.event
        parent_closed = False

        def event(value):
            nonlocal parent_closed
            if value['event'] == 'command_started':
                os.close(fd)
                parent_closed = True
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            original_event(value)

        # The child waits for a release marker so the parent's lock assertion is
        # tied to an actual live handle, not to a scheduling delay.
        release = self.root / 'release'
        child_code = ('import os,sys,time;from pathlib import Path;'
                      'assert os.fstat(int(sys.argv[1])).st_nlink == 1;'
                      'until=time.monotonic()+10;'
                      '\nwhile not Path(sys.argv[2]).exists() and time.monotonic()<until: time.sleep(.01)\n'
                      'assert Path(sys.argv[2]).exists()')

        def releasing_event(value):
            try:
                event(value)
            finally:
                if value['event'] == 'command_started':
                    release.touch(exist_ok=True)

        runner.event = releasing_event
        try:
            ACK._owned_command(runner, WRAPPER, [sys.executable, '-c', child_code, str(fd), str(release)],
                               None, pass_fds=(fd,))
            self.assertTrue(parent_closed)
            self.assertEqual(runner.commands[0]['returncode'], 0)
            self.assertTrue(runner.commands[0]['process_exited'])
            self.assertIsNone(runner.child)
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            release.touch(exist_ok=True)
            if not parent_closed:
                os.close(fd)
            os.close(probe)

    @unittest.skipUnless(sys.platform == 'linux', 'Requires Linux flock and private Python processes')
    def test_abrupt_owner_exit_does_not_release_its_live_child_lease(self):
        lock = self.root / 'crash-lease'
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
        ready, release, done = [self.root / name for name in ('ready', 'release', 'done')]
        child_code = ('import os,sys,time;from pathlib import Path;'
                      'assert os.fstat(int(sys.argv[1])).st_nlink == 1;'
                      'ready=Path(sys.argv[2]);pending=ready.with_suffix(".tmp");'
                      'pending.write_text(str(os.getpid()));os.replace(pending,ready);until=time.monotonic()+15;'
                      '\nwhile not Path(sys.argv[3]).exists() and time.monotonic()<until: time.sleep(.01)\n'
                      'assert Path(sys.argv[3]).exists();Path(sys.argv[4]).write_text("done")')
        owner_code = '''import fcntl,importlib.util,os,sys
from pathlib import Path
base,root,lock,ready,release,done,code=map(str,sys.argv[1:])
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(base)/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
ack=load('crash_ack','ack-service-acceptance.py')
w=load('crash_runner','experiment-runner.py')
fd=os.open(lock,os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
r=w.Runner(Path(root),config=Path(root)/'config/admin_cli.toml')
ack._owned_command(r,w,[sys.executable,'-c',code,str(fd),ready,release,done],None,pass_fds=(fd,))
os.close(fd)
'''
        # Isolate subreaper state from unittest and its unrelated children. The
        # helper adopts the holder after owner death and waits for it, including
        # assertion/error paths; obtaining the lock alone is not a process join.
        subreaper_code = '''import ctypes,fcntl,os,signal,subprocess,sys,time
from pathlib import Path
base,root,lock,ready,release,done,child_code,owner_code=sys.argv[1:]
root,ready,release,done=map(Path,(root,ready,release,done))
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(36,1,0,0,0) != 0:  # PR_SET_CHILD_SUBREAPER
    raise OSError(ctypes.get_errno(),'Cannot establish private child subreaper')
children_file=Path('/proc/self/task')/str(os.getpid())/'children'
def children():
    return [int(pid) for pid in children_file.read_text().split()]
def reap_ready(reaped):
    for pid in children():
        try:
            found,status=os.waitpid(pid,os.WNOHANG)
        except ChildProcessError:
            continue
        if found:
            reaped[found]=status
probe=os.open(lock,os.O_RDWR)
owner=None
holder=None
reaped={}
try:
    with open(root/'owner.log','xb') as log:
        owner=subprocess.Popen([sys.executable,'-B','-c',owner_code,base,str(root),
                                lock,str(ready),str(release),str(done),child_code],
                               stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                               start_new_session=True)
        until=time.monotonic()+8
        while not ready.exists() and owner.poll() is None and time.monotonic()<until:
            time.sleep(.01)
        assert ready.exists(),'Owned Python child did not become ready'
        holder=int(ready.read_text())
        owner.kill()  # This helper's exact Popen; never a PID-file lookup.
        assert owner.wait(timeout=5) == -signal.SIGKILL
        try:
            fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise AssertionError('Owner death released its live holder lease')
finally:
    try:
        try:
            release.touch(exist_ok=True)
        finally:
            if owner is not None:
                if owner.poll() is None:
                    owner.kill()
                owner.wait()  # Reap owner before collecting its adopted child.
            until=time.monotonic()+5
            while children() and time.monotonic()<until:
                reap_ready(reaped)
                time.sleep(.01)
            for pid in children():
                try:
                    found,status=os.waitpid(pid,os.WNOHANG)
                except ChildProcessError:
                    continue  # Never signal a process we do not own.
                if not found:
                    # waitpid just established ownership. With no other reaper,
                    # this child PID cannot be reused before our following wait.
                    try:
                        os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    found,status=os.waitpid(pid,0)
                reaped[found]=status
            assert not children(),'Private helper left an unreaped child'
    finally:
        os.close(probe)
assert holder in reaped,'Holder was not actually reaped by its subreaper'
assert os.waitstatus_to_exitcode(reaped[holder]) == 0,'Holder did not complete normally'
assert done.read_text() == 'done'
probe=os.open(lock,os.O_RDWR)
try:
    fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
finally:
    os.close(probe)
'''
        with open(self.root / 'subreaper.log', 'xb') as log:
            helper = subprocess.Popen([sys.executable, '-B', '-c', subreaper_code, str(HERE), str(self.root),
                                       str(lock), str(ready), str(release), str(done), child_code, owner_code],
                                      stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            try:
                returncode = helper.wait()
            finally:
                # Do not kill the cleanup owner and orphan its children. Its
                # internal waits are bounded before exact-child kill + wait.
                helper.wait()
        self.assertEqual(returncode, 0, 'Private subreaper scenario failed; see subreaper.log')


if __name__ == '__main__':
    unittest.main()
