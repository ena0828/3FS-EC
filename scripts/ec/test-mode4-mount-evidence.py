#!/usr/bin/env python3
"""Pure failure-injection checks; no mounted files or native services."""
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PATH = Path(__file__).parent / "cluster/mode4-mount-acceptance.py"
SPEC = importlib.util.spec_from_file_location("mount_probe", PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class Sink(io.StringIO):
    def __init__(self, failure=None, close_error=None):
        super().__init__()
        self.failure = failure
        self.close_error = close_error
        self.closed_once = False

    def write(self, value):
        event = json.loads(value)
        if self.failure and self.failure(event):
            raise OSError(errno.ENOSPC, "injected evidence write failure")
        return super().write(value)

    def fileno(self):
        return 88

    def close(self):
        self.closed_once = True
        if self.close_error:
            error, self.close_error = self.close_error, None
            raise error
        # Retain in-memory evidence for assertions; no actual descriptor exists.


class MountedCalls:
    def __init__(self, sink, truncate_error=None, close_error=None, append_allowed=False):
        self.sink = sink
        self.truncate_error = truncate_error
        self.close_error = close_error
        self.append_allowed = append_allowed
        self.calls = []
        self.data = bytearray()

    def open(self, path, flags, mode=0o600):
        if Path(path).name == "report.jsonl":
            return 88
        self.calls.append(("open", flags))
        if flags & os.O_APPEND and not self.append_allowed:
            raise OSError(errno.EOPNOTSUPP, "expected append refusal")
        return 7

    def pwrite(self, fd, data, offset):
        self.calls.append(("pwrite", len(data), offset))
        if len(self.data) < offset + len(data):
            self.data.extend(bytes(offset + len(data) - len(self.data)))
        self.data[offset:offset + len(data)] = data
        return len(data)

    def ftruncate(self, fd, size):
        self.calls.append(("ftruncate", size))
        if self.truncate_error:
            raise self.truncate_error
        del self.data[size:]
        self.data.extend(bytes(max(0, size - len(self.data))))

    def fsync(self, fd):
        if fd != 88:
            self.calls.append(("fsync",))

    def fstat(self, fd):
        self.calls.append(("fstat",))
        return SimpleNamespace(st_size=len(self.data))

    def pread(self, fd, size, offset):
        self.calls.append(("pread", size, offset))
        return bytes(self.data[offset:offset + size])

    def lstat(self, path):
        self.calls.append(("lstat",))
        raise FileNotFoundError(errno.ENOENT, "expected absent sibling")

    def close(self, fd):
        self.calls.append(("close",))
        if self.close_error:
            raise self.close_error

    def os_api(self):
        constants = {key: getattr(os, key) for key in ("O_RDWR", "O_WRONLY", "O_RDONLY", "O_APPEND",
                                                      "O_CREAT", "O_EXCL")}
        constants["O_NOFOLLOW"] = getattr(os, "O_NOFOLLOW", 0x20000)
        return SimpleNamespace(**constants, **{key: getattr(self, key) for key in
                               ("open", "pwrite", "ftruncate", "fsync", "fstat", "pread", "lstat", "close")},
                               fdopen=lambda *args, **kwargs: self.sink)


class MountEvidenceTests(unittest.TestCase):
    def run_probe(self, calls):
        # Absolute names only; all OS calls below are injected in memory.
        root = Path.cwd()
        args = [str(PATH), "prepare", "--file", str(root / "mounted-file"),
                "--report", str(root / "report.jsonl")]
        with patch.object(probe, "os", calls.os_api()), patch.object(probe.sys, "argv", args):
            probe.main()

    def events(self, sink):
        return [json.loads(line) for line in sink.getvalue().splitlines()]

    def test_success_keeps_payload_order_and_acceptance(self):
        sink = Sink()
        calls = MountedCalls(sink)
        self.run_probe(calls)
        self.assertEqual(calls.calls[1:6], [("pwrite", 180000, 0), ("pwrite", 75000, 65531),
                                          ("ftruncate", 120123), ("ftruncate", 210123), ("fsync",)])
        self.assertEqual(bytes(calls.data), probe.expected()[1])
        rows = self.events(sink)
        self.assertEqual(rows[-1]["state"], "confirmed")
        self.assertEqual(rows[-1]["operation"], "probe")
        self.assertEqual(sum(r["operation"] == "reject_open_append" for r in rows), 2)
        self.assertEqual(sum(r["operation"] == "reject_create_append" for r in rows), 1)
        self.assertEqual([r["sequence"] for r in rows], list(range(len(rows))))
        spec = importlib.util.spec_from_file_location(
            "probe_lifecycle_gate", PATH.with_name("mode4-lifecycle-acceptance.py"))
        lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lifecycle)
        lifecycle.posix_receipt(rows, "prepare", Path.cwd() / "mounted-file", len(probe.expected()[1]),
                                hashlib.sha256(probe.expected()[1]).hexdigest())

    def test_first_truncate_and_close_fail_preserves_first_exception(self):
        first, close = OSError(errno.EIO, "truncate first"), OSError(errno.EBADF, "close second")
        sink = Sink()
        calls = MountedCalls(sink, first, close)
        with self.assertRaises(OSError) as caught:
            self.run_probe(calls)
        self.assertIs(caught.exception, first)
        failures = [r for r in self.events(sink) if r["state"] == "operation_failed"]
        self.assertEqual([(r["operation"], r["errno"]) for r in failures],
                         [("ftruncate", errno.EIO), ("close", errno.EBADF)])
        self.assertTrue(failures[1]["secondary"])
        self.assertTrue(all(not r["expected_failure"] for r in failures))
        self.assertEqual(calls.calls[-2:], [("ftruncate", 120123), ("close",)])
        self.assertTrue(any("Secondary close" in n for n in first.__notes__))

    def test_only_close_failure_is_not_lost(self):
        failure = OSError(errno.EIO, "close only")
        sink = Sink()
        calls = MountedCalls(sink, close_error=failure)
        with self.assertRaises(OSError) as caught:
            self.run_probe(calls)
        self.assertIs(caught.exception, failure)
        failures = [r for r in self.events(sink) if r["state"] == "operation_failed"]
        self.assertEqual([r["operation"] for r in failures], ["close"])
        self.assertFalse(failures[0]["secondary"])
        self.assertEqual(calls.calls[-1], ("close",))
        self.assertFalse(any(r["operation"] == "probe" and r["state"] == "confirmed"
                             for r in self.events(sink)))

    def test_sink_failure_before_syscall_does_not_call_or_blame_it(self):
        sink = Sink(lambda r: r["operation"] == "ftruncate" and r["state"] == "operation_entered")
        calls, stderr = MountedCalls(sink), io.StringIO()
        with patch.object(probe.sys, "stderr", stderr), self.assertRaises(probe.EvidenceFailure):
            self.run_probe(calls)
        self.assertNotIn(("ftruncate", 120123), calls.calls)
        self.assertEqual(calls.calls[-1], ("close",))
        self.assertFalse(any(r["state"] == "operation_failed" for r in self.events(sink)))
        self.assertIn("MODE4_PROBE_EVIDENCE_FAILURE", stderr.getvalue())

    def test_open_confirmation_sink_failure_still_closes_owned_fd(self):
        sink = Sink(lambda r: r["operation"] == "open" and r["state"] == "operation_confirmed")
        calls = MountedCalls(sink)
        with patch.object(probe.sys, "stderr", io.StringIO()), self.assertRaises(probe.EvidenceFailure):
            self.run_probe(calls)
        self.assertEqual([r[0] for r in calls.calls], ["open", "close"])

    def test_close_entered_sink_failure_still_attempts_close(self):
        sink = Sink(lambda r: r["operation"] == "close" and r["state"] == "operation_entered")
        calls = MountedCalls(sink)
        with patch.object(probe.sys, "stderr", io.StringIO()), self.assertRaises(probe.EvidenceFailure):
            self.run_probe(calls)
        self.assertEqual(calls.calls[-1], ("close",))
        self.assertEqual(sum(r[0] == "close" for r in calls.calls), 1)

    def test_confirmation_fsync_failure_is_evidence_not_syscall_failure(self):
        sink = Sink()
        calls = MountedCalls(sink)
        ordinary_fsync = calls.fsync

        def fsync(fd):
            last = self.events(sink)[-1]
            if fd == 88 and last["operation"] == "ftruncate" and last["state"] == "operation_confirmed":
                raise OSError(errno.ENOSPC, "evidence fsync")
            ordinary_fsync(fd)

        calls.fsync = fsync
        with patch.object(probe.sys, "stderr", io.StringIO()), self.assertRaises(probe.EvidenceFailure):
            self.run_probe(calls)
        self.assertEqual(calls.calls[-2:], [("ftruncate", 120123), ("close",)])
        self.assertFalse(any(r["operation"] == "ftruncate" and r["state"] == "operation_failed"
                             for r in self.events(sink)))
        self.assertEqual(self.events(sink)[-1]["failure_source"], "evidence")

    def test_primary_error_survives_failure_record_and_sink_close_failure(self):
        first = OSError(errno.EIO, "truncate first")
        sink = Sink(lambda r: r["state"] == "operation_failed", OSError(errno.ENOSPC, "sink close"))
        calls, stderr = MountedCalls(sink, truncate_error=first), io.StringIO()
        with patch.object(probe.sys, "stderr", stderr), self.assertRaises(OSError) as caught:
            self.run_probe(calls)
        self.assertIs(caught.exception, first)
        self.assertEqual(calls.calls[-1], ("close",))
        self.assertIn('"failure_source": "syscall"', stderr.getvalue())
        self.assertIn('"operation": "evidence_close"', stderr.getvalue())

    def test_close_error_cannot_masquerade_as_expected_append_rejection(self):
        sink = Sink()
        calls = MountedCalls(sink, append_allowed=True)
        original_close = calls.close

        def close(fd):
            if len([c for c in calls.calls if c[0] == "open"]) == 2:
                raise OSError(errno.EOPNOTSUPP, "close, not append refusal")
            original_close(fd)

        calls.close = close
        with self.assertRaises(OSError):
            self.run_probe(calls)
        self.assertFalse(any(r["operation"] == "reject_open_append" for r in self.events(sink)))


if __name__ == "__main__":
    unittest.main()
