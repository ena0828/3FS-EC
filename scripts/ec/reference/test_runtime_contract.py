"""Candidate guard regressions, not full-system acceptance. Not executed during preparation."""
import io
import json
from pathlib import Path
import socket
import signal
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from prepare_reference import extract
from runtime_common import Owned, check_build, mul, sha, reference_lease

class RuntimeContract(unittest.TestCase):
    def test_polynomial_boundary(self):
        self.assertEqual(mul(0x80,2),0x1d)
        self.assertEqual(mul(0x53,0),0)
        self.assertEqual(mul(0x53,1),0x53)

    def test_archive_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);archive=root/'bad.tar'
            with tarfile.open(archive,'w') as tar:
                item=tarfile.TarInfo('../escaped');item.size=1
                tar.addfile(item,io.BytesIO(b'x'))
            with self.assertRaises(ValueError):extract(archive,root/'source')
            self.assertFalse((root/'escaped').exists())

    def test_build_identity_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);binary=root/'binary';binary.write_bytes(b'one')
            record=root/'record.json'
            record.write_text(json.dumps({'project':'openec','status':'built','binaries':[
                {'path':str(binary),'sha256':sha(binary)}],'sources':[],'dependency_files':[]}))
            binary.write_bytes(b'two')
            with self.assertRaises(ValueError):check_build(record,'openec')

    def test_nonempty_boundary_rejected_without_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner=Owned(Path(tmp))
            def bounded_failure(description,predicate,seconds):
                self.assertFalse(predicate())
                raise TimeoutError(description)
            try:
                with patch('runtime_common.redis_command',return_value=1) as command:
                    with patch.object(runner,'wait_for',side_effect=bounded_failure):
                        with self.assertRaises(TimeoutError):
                            runner.require_empty_redis(['127.91.0.1'],'stale-data')
                    self.assertEqual(command.call_args_list[0].args,('127.91.0.1','DBSIZE'))
                    self.assertEqual(command.call_count,1)
            finally:runner.stop()

    @unittest.skipUnless(sys.platform=='linux','signal ownership contract requires Linux')
    def test_signal_between_popen_and_registration_is_deferred(self):
        class FakeProcess:
            pid=12345
            returncode=None
            def poll(self):return self.returncode
            def wait(self,timeout=None):self.returncode=-15;return self.returncode
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runner=Owned(root);proc=FakeProcess()
            def returned_from_popen(*args,**kwargs):
                # Deterministic boundary injection: no sleep and no real signal timing race.
                runner.interrupted(signal.SIGTERM,None)
                return proc
            try:
                with patch('runtime_common.subprocess.Popen',side_effect=returned_from_popen):
                    with self.assertRaises(KeyboardInterrupt):runner.start('boundary',['unused'],root)
                self.assertEqual(len(runner.children),1)
                self.assertIs(runner.children[0][1],proc)
            finally:
                with patch('runtime_common.os.killpg') as kill:runner.stop()
            self.assertIsNotNone(proc.returncode)

    @unittest.skipUnless(sys.platform=='linux','SIGHUP contract requires Linux')
    def test_hup_only_marks_stop_and_is_restored(self):
        before=signal.getsignal(signal.SIGHUP)
        with tempfile.TemporaryDirectory() as tmp:
            runner=Owned(Path(tmp))
            try:
                self.assertEqual(signal.getsignal(signal.SIGHUP),runner.interrupted)
                runner.interrupted(signal.SIGHUP,None)
                self.assertTrue(runner.stop_requested)
                self.assertEqual(runner.stop_signal,signal.SIGHUP)
            finally:runner.stop()
        self.assertEqual(signal.getsignal(signal.SIGHUP),before)

    @unittest.skipUnless(sys.platform=='linux','flock contract requires Linux')
    def test_common_lease_is_nonblocking_and_released(self):
        with reference_lease():
            with self.assertRaises(RuntimeError):
                with reference_lease():self.fail('second reference runtime acquired lease')
        with reference_lease():pass

    @unittest.skipUnless(sys.platform=='linux','real owned-process regression requires Linux')
    def test_event_failure_after_launch_still_joins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runner=Owned(root)
            try:
                with patch.object(runner,'event',side_effect=OSError('simulated full disk')):
                    with self.assertRaises(OSError):
                        runner.start('owned',[sys.executable,'-c','import time; time.sleep(30)'],root)
                self.assertEqual(len(runner.children),1)
            finally:
                runner.stop()
            self.assertIsNotNone(runner.children[0][1].returncode)

    @unittest.skipUnless(sys.platform=='linux','loopback ownership regression requires Linux')
    def test_borrowed_port_never_spawns_or_signals(self):
        with tempfile.TemporaryDirectory() as tmp,socket.socket() as held:
            try:held.bind(('127.254.0.250',6379))
            except OSError:self.skipTest('test-specific endpoint already occupied')
            held.listen()
            runner=Owned(Path(tmp))
            try:
                with self.assertRaises(OSError):runner.redis(Path(sys.executable),['127.254.0.250'])
                self.assertEqual(runner.children,[])
                self.assertEqual(held.getsockname(),('127.254.0.250',6379))
            finally:runner.stop()

    @unittest.skipUnless(sys.platform=='linux','owned cleanup contract requires Linux')
    def test_persistent_exit_before_teardown_is_failure(self):
        class AlreadyExited:
            pid=12345
            returncode=0
            def poll(self):return self.returncode
            def wait(self,timeout=None):return self.returncode
        with tempfile.TemporaryDirectory() as tmp:
            runner=Owned(Path(tmp));runner.children.append(('daemon',AlreadyExited(),True))
            with patch('runtime_common.os.killpg') as kill:
                self.assertFalse(runner.stop())
                kill.assert_not_called()
            self.assertEqual(len(runner.cleanup_errors),1)
            self.assertEqual(runner.events[-1]['returncode'],0)

if __name__=='__main__':unittest.main()
