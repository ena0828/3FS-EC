#!/usr/bin/env python3
"""Pure ordering and evidence tests; no native process, mount or signal."""
import importlib.util
import errno
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "mode4_lifecycle", Path(__file__).parent / "cluster/mode4-lifecycle-acceptance.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class FakeLifecycle:
    def __init__(self, fail=None, dirty=False):
        self.events, self.fail, self.dirty = [], fail, dirty

    def event(self, *event):
        self.events.append(event)
        if event == self.fail:
            raise ValueError("injected unconfirmed operation")

    def services(self, label):
        self.event("services", label)

    def start(self, phase):
        self.event("start", phase)

    def probe(self, kind, phase):
        self.event("probe", kind, phase)

    def close(self, phase):
        self.event("close", phase)

    def clean_last(self):
        return not self.dirty

    def finish(self):
        self.event("finish")


class TestMode4Lifecycle(unittest.TestCase):
    def test_prepared_transport_matches_initialized_user_and_same_mount_profile(self):
        scripts = Path(__file__).parent / "cluster"
        with mock.patch.object(sys, "path", [str(scripts), *sys.path]):
            from native_v2_config import requested_transport
            tcp = {"schema": 1, "cluster_id": "fixed", "authenticated_user": {"uid": 2345, "gid": 3456}}
            DRIVER.validate_prepared_profile(tcp, copy.deepcopy(tcp), {})
            transport = requested_transport(transport="rdma", rdma_interface="enp2s0",
                                            rdma_address="192.0.2.10", rdma_device="mlx5_0")
            manifest = dict(tcp, data_transport=transport)
            initialized = copy.deepcopy(manifest)
            receipt = {"data_transport_requested": copy.deepcopy(transport),
                       "transport_validation": "configuration_only"}
            DRIVER.validate_prepared_profile(manifest, initialized, receipt)
            changed_device = dict(transport, ib_device="mlx5_1")
            cases = (
                (manifest, tcp, receipt), (tcp, initialized, {}),
                (manifest, dict(initialized, data_transport=changed_device), receipt),
                (manifest, dict(initialized, authenticated_user={"uid": 2345, "gid": 3457}), receipt),
                (manifest, initialized, {}), (tcp, tcp, receipt),
                (manifest, initialized, dict(receipt, transport_validation="validated")),
                (manifest, initialized, dict(receipt, data_transport_requested=changed_device)),
                (manifest, initialized, dict(receipt, data_transport_requested=dict(transport, schema=True))),
                (manifest, initialized, dict(receipt, data_transport_requested=None)),
            )
            for index, (current, prior, prepared) in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    DRIVER.validate_prepared_profile(current, prior, prepared)

    def test_diagnostic_entries_require_completion_and_exact_expected_refusals(self):
        path = Path('/mount/file')
        def receipt(events):
            result = [dict(state='prepared', command='prepare', file=str(path)), *events,
                      dict(state='confirmed', operation='probe', bytes=7, sha256='hash')]
            return [dict(row, schema=1, sequence=i) for i, row in enumerate(result)]
        barrier = [dict(state='operation_entered', operation='fsync'),
                   dict(state='operation_confirmed', operation='fsync', file_data_barrier=True)]
        for operation, code in (('open_append', errno.EOPNOTSUPP), ('create_append', errno.EOPNOTSUPP),
                                ('lstat', errno.ENOENT)):
            refused = [dict(state='operation_entered', operation=operation),
                       dict(state='operation_failed', operation=operation, failure_source='syscall',
                            expected_failure=True, errno=code)]
            DRIVER.posix_receipt(receipt(barrier + refused), 'prepare', path, 7, 'hash')
            for change in ({'errno': 5}, {'errno': True}, {'expected_failure': 1},
                           {'failure_source': 'evidence'}, {'operation': 'ftruncate'}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    DRIVER.posix_receipt(receipt(barrier + [refused[0], dict(refused[1], **change)]),
                                         'prepare', path, 7, 'hash')
        for events in (barrier[:1], [dict(state='operation_entered', operation='fsync', file_data_barrier=True)],
                       [barrier[0], dict(state='operation_confirmed', operation='close')],
                       barrier + [dict(state='operation_failed', operation='ftruncate', errno=5)]):
            with self.assertRaises(ValueError):
                DRIVER.posix_receipt(receipt(events), 'prepare', path, 7, 'hash')

    def test_mount_identity_binds_prepared_client_and_actual_uid_gid(self):
        user = {"uid": 2345, "gid": 3456}
        client = {"user_info": dict(user)}
        preparation = {"uid": 2345}
        DRIVER.same_user(user, client, preparation, 2345, 2345, 3456, 3456)
        DRIVER.same_user({"uid": 1000, "gid": 1000}, {"user_info": {"uid": 1000, "gid": 1000}},
                         {"uid": 1000}, 1000, 1000, 1000, 1000)
        for values in ((0, 0, 3456, 3456), (2345, 0, 3456, 3456), (2345, 2345, 3456, 0),
                       (True, True, 3456, 3456), (2345, 2345, False, False)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                DRIVER.same_user(user, client, preparation, *values)
        for changed_user, changed_client, changed_prep in (
                ({"uid": 1000, "gid": 3456}, client, preparation),
                ({"uid": 2345, "gid": 1000}, client, preparation),
                (user, {"user_info": {"uid": 1000, "gid": 3456}}, preparation),
                (user, {"user_info": {"uid": 2345, "gid": 1000}}, preparation),
                (user, client, {"uid": 1000})):
            with self.subTest(user=changed_user, client=changed_client, prep=changed_prep), self.assertRaises(ValueError):
                DRIVER.same_user(changed_user, changed_client, changed_prep, 2345, 2345, 3456, 3456)

    def test_order_requires_close_and_join_before_same_state_verify(self):
        life = FakeLifecycle()
        DRIVER.run_sequence(life)
        self.assertEqual(life.events, [
            ("services", "before-first"), ("start", "prepare"),
            ("probe", "posix", "prepare"), ("probe", "usrbio", "prepare"), ("close", "prepare"),
            ("services", "after-prepare"), ("start", "verify"),
            ("probe", "posix", "verify"), ("probe", "usrbio", "verify"), ("close", "verify"),
            ("services", "after-verify"), ("finish",)])

    def test_first_mount_failure_never_probes_or_remounts(self):
        life = FakeLifecycle(fail=("start", "prepare"))
        with self.assertRaises(ValueError):
            DRIVER.run_sequence(life)
        self.assertEqual(life.events, [("services", "before-first"), ("start", "prepare"), ("close", "prepare")])

    def test_first_unmount_or_join_failure_blocks_remount(self):
        life = FakeLifecycle(dirty=True)
        with self.assertRaises(ValueError):
            DRIVER.run_sequence(life)
        self.assertNotIn(("start", "verify"), life.events)
        self.assertEqual(life.events[-1], ("close", "prepare"))

    def test_cancelled_probe_runs_cleanup_without_next_probe(self):
        life = FakeLifecycle(fail=("probe", "posix", "prepare"))
        with self.assertRaises(ValueError):
            DRIVER.run_sequence(life)
        self.assertNotIn(("probe", "usrbio", "prepare"), life.events)
        self.assertNotIn(("start", "verify"), life.events)
        self.assertEqual(life.events[-1], ("close", "prepare"))

    def test_remount_failure_never_runs_verify_probes(self):
        life = FakeLifecycle(fail=("start", "verify"))
        with self.assertRaises(ValueError):
            DRIVER.run_sequence(life)
        self.assertFalse(any(event[:1] == ("probe",) and event[-1:] == ("verify",) for event in life.events))
        self.assertEqual(life.events[-1], ("close", "verify"))

    def test_mgmtd_timeout_bound_starts_before_first_process_spawn(self):
        self.assertEqual(DRIVER.configured_timeout("20min"), 1200)
        self.assertEqual(DRIVER.rapid_remount(10, 11, 1200), 1)
        for value in (10, 9, 1200_000_000_010):
            with self.assertRaises(ValueError):
                DRIVER.rapid_remount(10, value, 1200)
        for value in ("0s", "disabled", "20"):
            with self.assertRaises(ValueError):
                DRIVER.configured_timeout(value)

    def test_posix_verify_rejects_wrong_file_unconfirmed_and_data_write(self):
        file = Path("/mount/ec-lab/a.bin")
        rows = [{"schema": 1, "sequence": 0, "state": "prepared", "command": "verify", "file": str(file)},
                {"schema": 1, "sequence": 1, "state": "confirmed", "operation": "probe", "bytes": 7, "sha256": "hash"}]
        DRIVER.posix_receipt(rows, "verify", file, 7, "hash")
        with self.assertRaises(ValueError):
            DRIVER.posix_receipt(rows, "verify", Path("/mount/other.bin"), 7, "hash")
        rows[1]["state"] = "unconfirmed"
        with self.assertRaises(ValueError):
            DRIVER.posix_receipt(rows, "verify", file, 7, "hash")
        rows[1]["state"] = "confirmed"
        rows.insert(1, {"schema": 1, "sequence": 1, "state": "operation_confirmed", "operation": "pwrite"})
        rows[2]["sequence"] = 2
        with self.assertRaises(ValueError):
            DRIVER.posix_receipt(rows, "verify", file, 7, "hash")

    def test_service_identity_retains_run_and_mgmtd_start_time(self):
        root = Path("/lab")
        cluster = {"profile": "native-gc-local-1-storage-12-targets", "storage_count": 1}
        snapshot = {"schema": 1, "stage": "ready", "root": str(root), "profile": cluster["profile"],
                    "failure": None, "logical_targets": 12, "storage_processes": 1, "run": "run-one",
                    "processes": [{"name": name, "pid": i + 10, "exit_code": None}
                                  for i, name in enumerate(("fdb", "mgmtd", "storage", "meta"))]}
        identities = {row["name"]: {"pid": row["pid"], "start_ticks": "10"} for row in snapshot["processes"]}
        before = DRIVER.service_contract(snapshot, root, cluster, identities)
        altered = {name: dict(row) for name, row in identities.items()}
        altered["mgmtd"]["start_ticks"] = "20"
        self.assertNotEqual(before, DRIVER.service_contract(snapshot, root, cluster, altered))
        snapshot["processes"][0]["exit_code"] = 0
        with self.assertRaises(ValueError):
            DRIVER.service_contract(snapshot, root, cluster, identities)

    def test_owned_command_timeout_unknown_join_is_never_success(self):
        helper = mock.Mock()
        owner = mock.Mock()
        command = DRIVER.Commands(helper, owner, {})
        process = mock.Mock()
        process.pid = 123
        process.poll.return_value = None
        process.wait.side_effect = DRIVER.subprocess.TimeoutExpired("owned", 10)
        row = {"identity": {"pid": 123, "start_ticks": "7", "executable": "/owned"}}
        with mock.patch.object(DRIVER, "process_identity", return_value=row["identity"]):
            command.terminate(process, row)
        process.terminate.assert_called_once_with()
        self.assertTrue(row["join_unknown"])
        self.assertFalse(row["joined"])
        self.assertIsNone(row["exitcode"])

    def test_short_command_zero_exit_survives_zombie_or_setuid_observation(self):
        for error in (ValueError("zombie"), PermissionError("setuid proc access")):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                helper = mock.Mock()
                helper.read_file.return_value = b"ok"
                owner = mock.Mock(result=Path(directory), sequence=0, stop=False)
                process = mock.Mock(pid=42)
                process.poll.return_value = 0
                command = DRIVER.Commands(helper, owner, {})
                with mock.patch.object(DRIVER.subprocess, "Popen", return_value=process), \
                     mock.patch.object(DRIVER, "process_identity", side_effect=error):
                    self.assertEqual(command.run("short", ["/owned"], 1), b"ok")
                row = command.children[0][1]
                self.assertEqual(row["exitcode"], 0)
                self.assertTrue(row["joined"])
                self.assertEqual(row["identity_observation_unavailable"], type(error).__name__)
                process.terminate.assert_not_called()

    def test_started_receipt_failure_still_terminates_and_joins_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = mock.Mock()
            helper.write_new.side_effect = OSError("receipt disk full")
            owner = mock.Mock(result=Path(directory), sequence=0, stop=False)
            process = mock.Mock(pid=42)
            process.poll.return_value = None
            process.wait.side_effect = lambda **_: setattr(process.poll, "return_value", -15)
            command = DRIVER.Commands(helper, owner, {})
            with mock.patch.object(DRIVER.subprocess, "Popen", return_value=process), \
                 mock.patch.object(DRIVER, "process_identity", return_value={"pid": 42}):
                with self.assertRaises(OSError):
                    command.run("receipt-failure", ["/owned"], 1)
            process.terminate.assert_called_once_with()
            self.assertTrue(command.children[0][1]["joined"])
            self.assertEqual(command.children[0][1]["exitcode"], -15)

    def test_signal_flag_during_spawn_cancels_owned_command_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = mock.Mock()
            owner = mock.Mock(result=Path(directory), sequence=0, stop=False)
            process = mock.Mock(pid=42)
            process.poll.return_value = None
            process.wait.side_effect = lambda **_: setattr(process.poll, "return_value", -15)
            def spawn(*_args, **_kwargs):
                owner.stop = True
                return process
            command = DRIVER.Commands(helper, owner, {})
            with mock.patch.object(DRIVER.subprocess, "Popen", side_effect=spawn), \
                 mock.patch.object(DRIVER, "process_identity", return_value={"pid": 42}):
                with self.assertRaises(ValueError):
                    command.run("cancelled", ["/owned"], 1)
            row = command.children[0][1]
            self.assertTrue(row["cancelled"])
            self.assertTrue(row["joined"])
            self.assertEqual(row["exitcode"], -15)

    def test_failed_unmount_with_remaining_or_unknown_mount_never_terminates_fuse(self):
        mount = {"id": "20", "fs": "fuse.hf3fs", "source": "hf3fs.cluster"}
        for remaining in ([mount], OSError("mountinfo unavailable")):
            with self.subTest(remaining=remaining):
                life = DRIVER.Lifecycle.__new__(DRIVER.Lifecycle)
                process = mock.Mock(pid=42)
                process.poll.return_value = None
                row = {"phase": "verify", "argv": ["/fuse"], "ready": True, "normal_unmount": False,
                       "joined": False, "exitcode": None, "mount": mount, "identity": {"pid": 42}}
                life.active = {"process": process, "row": row}
                life.report = {"mounts": [row]}
                life.h = mock.Mock()
                life.h.mounts_at.side_effect = [[mount], remaining]
                life.mountpoint, life.unmount = Path("/mount"), Path("/fusermount3")
                life.mounted_identity = mock.Mock(return_value=({"pid": 42}, mount))
                life.commands = mock.Mock()
                life.commands.run.side_effect = ValueError("normal unmount refused")
                life.args = SimpleNamespace(join_timeout=1)
                life.save = mock.Mock()
                life.close("verify")
                life.commands.terminate.assert_not_called()
                self.assertTrue(row["join_unknown"])
                self.assertFalse(row["joined"])
                self.assertIn("termination_withheld", row)
                life.save.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
