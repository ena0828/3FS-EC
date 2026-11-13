#!/usr/bin/env python3
"""Explicit mounted mode4 probe. Does not start/stop services or remove files.

prepare writes a NEW exclusive path through the actual FUSE mount. verify is
independent and can run after a supervised unmount/remount. Each successful
operation is recorded before proceeding. Unsupported OPEN/CREATE must fail
without disabling later FUSE OPEN callbacks. Synthetic input, no timing.
"""
import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
import os
import sys
from pathlib import Path


class EvidenceFailure(RuntimeError):
    """The evidence sink failed; this is not a mounted syscall result."""


def secondary_note(error, message):
    # Structured records remain authoritative on Python versions without notes.
    if hasattr(error, "add_note"):
        error.add_note(message)


def report_sink_failure(operation, state, error, details=None):
    details = details or {}
    diagnostic = {"operation": operation, "state": state,
                  **{key: details[key] for key in ("failure_source", "error_type", "errno", "expected_failure", "secondary")
                     if key in details},
                  "evidence_error_type": type(error).__name__,
                  "evidence_errno": error.errno if isinstance(error, OSError) else None}
    try:
        print("MODE4_PROBE_EVIDENCE_FAILURE " + json.dumps(diagnostic), file=sys.stderr, flush=True)
    except BaseException:
        pass  # Preserve the original sink failure even if stderr is unavailable.


@contextmanager
def report_stream(fd):
    report = os.fdopen(fd, "w", encoding="utf-8")
    try:
        yield report
    finally:
        primary = sys.exc_info()[1]
        try:
            report.close()
        except BaseException as error:
            report_sink_failure("evidence_close", "operation_failed", error)
            if primary is None:
                raise EvidenceFailure("closing probe evidence sink failed") from error
            secondary_note(primary, "Closing the evidence sink also failed.")


def failure_fields(error, source):
    return {"failure_source": source, "error_type": type(error).__name__,
            "errno": error.errno if isinstance(error, OSError) else None}


def record_failure(emit, operation, error, source, **details):
    try:
        emit(operation, state="operation_failed", **({"expected_failure": False} | details),
             **failure_fields(error, source))
    except EvidenceFailure:
        secondary_note(error, "Recording this failure also failed; see evidence-sink diagnostic.")


def syscall(emit, operation, function, *args, confirm=None, expected_errno=None, **details):
    emit(operation, state="operation_entered", **details)
    try:
        value = function(*args)
    except BaseException as error:
        record_failure(emit, operation, error, "syscall", **details,
                       expected_failure=expected_errno is not None and isinstance(error, OSError)
                       and error.errno == expected_errno)
        raise
    try:
        fields = confirm(value) if confirm else {}
    except BaseException as error:
        record_failure(emit, operation, error, "validation", **details)
        raise
    emit(operation, **(details | fields))
    return value


def close_owned(fd, emit, primary, **details):
    # A broken evidence sink must never prevent the one owned close attempt.
    failure = None
    try:
        emit("close", state="operation_entered", **details)
    except EvidenceFailure as error:
        failure = error
    try:
        os.close(fd)
    except BaseException as error:
        record_failure(emit, "close", error, "syscall", secondary=primary is not None, **details)
        if failure is None:
            failure = error
        else:
            secondary_note(failure, "Close also failed: " + json.dumps(failure_fields(error, "syscall")))
    else:
        try:
            emit("close", **details)
        except EvidenceFailure as error:
            if failure is None:
                failure = error
    if failure is not None:
        if primary is None:
            raise failure
        secondary_note(primary, "Secondary close/evidence failure: " +
                       json.dumps(failure_fields(failure, "evidence" if isinstance(failure, EvidenceFailure)
                                                 else "syscall")))


@contextmanager
def opened(emit, path, flags, operation="open", expected_errno=None, **details):
    fields = {"file": str(path), "flags": flags, **details}
    emit(operation, state="operation_entered", **fields)
    try:
        fd = os.open(path, flags, 0o600)
    except BaseException as error:
        record_failure(emit, operation, error, "syscall", **fields,
                       expected_failure=expected_errno is not None and isinstance(error, OSError)
                       and error.errno == expected_errno)
        raise
    try:
        # The descriptor is already owned if this evidence write fails.
        emit(operation, **fields)
        yield fd
    finally:
        close_owned(fd, emit, sys.exc_info()[1], file=str(path), **details)


def emitter(report):
    sequence = 0

    def emit(operation, state="operation_confirmed", **details):
        nonlocal sequence
        try:
            report.write(json.dumps({"schema": 1, "sequence": sequence, "state": state,
                                     "operation": operation, **details}) + "\n")
            report.flush()
            os.fsync(report.fileno())  # Evidence durability, not mounted data fsync.
        except BaseException as error:
            report_sink_failure(operation, state, error, details)
            raise EvidenceFailure("probe evidence sink failed") from error
        sequence += 1

    return emit


def expected():
    initial = bytes((i * 29 + 7) % 251 for i in range(180_000))
    data = bytearray(initial)
    data[65_531:65_531 + 75_000] = bytes((i * 17 + 11) % 253 for i in range(75_000))
    del data[120_123:]
    data.extend(bytes(90_000))
    return initial, bytes(data)


def write_all(fd, value, offset, emit):
    def confirmed(count):
        if count <= 0:
            raise RuntimeError("pwrite made no confirmed progress")
        return {"bytes": count}

    while value:
        count = syscall(emit, "pwrite", os.pwrite, fd, value, offset,
                        confirm=confirmed, offset=offset, requested_bytes=len(value))
        value, offset = value[count:], offset + count


def check_bytes(fd, final, emit, phase):
    def size(value):
        if value.st_size != len(final):
            raise RuntimeError("actual file length differs")
        return {"bytes": len(final)}

    def content(value):
        if value != final:
            raise RuntimeError("actual mounted bytes differ")
        return {"bytes": len(value), "byte_equal": True, "sha256": hashlib.sha256(value).hexdigest()}

    def eof(value):
        if value != b"":
            raise RuntimeError("EOF read returned unexpected bytes")
        return {"bytes": 0}

    syscall(emit, "fstat", os.fstat, fd, confirm=size, phase=phase)
    syscall(emit, "pread", os.pread, fd, len(final) + 1, 0, confirm=content, phase=phase)
    syscall(emit, "pread_eof", os.pread, fd, 64, len(final), confirm=eof, phase=phase, offset=len(final))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if not args.file.is_absolute() or not args.report.is_absolute():
        parser.error("file and report must be explicit absolute paths")
    rejected_create = args.file.with_name(args.file.name + ".append-denied")
    report_fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with report_stream(report_fd) as report:
        emit = emitter(report)

        emit("probe", state="prepared", command=args.command, file=str(args.file),
             rejected_create=str(rejected_create))
        try:
            initial, final = expected()
            flags = os.O_RDWR | os.O_NOFOLLOW
            if args.command == "prepare":
                flags |= os.O_CREAT | os.O_EXCL
            with opened(emit, args.file, flags) as fd:
                if args.command == "prepare":
                    write_all(fd, initial, 0, emit)
                    write_all(fd, bytes((i * 17 + 11) % 253 for i in range(75_000)), 65_531, emit)
                    syscall(emit, "ftruncate", os.ftruncate, fd, 120_123, bytes=120_123)
                    syscall(emit, "ftruncate", os.ftruncate, fd, len(final), bytes=len(final))
                    syscall(emit, "fsync", os.fsync, fd, file_data_barrier=True)  # Actual Meta63 barrier.
                check_bytes(fd, final, emit, "before-rejected-open")
            for attempt in (1, 2):
                did_open = False
                try:
                    with opened(emit, args.file, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW,
                                operation="open_append", expected_errno=errno.EOPNOTSUPP, attempt=attempt):
                        did_open = True
                except OSError as error:
                    if did_open or error.errno != errno.EOPNOTSUPP:
                        raise
                    emit("reject_open_append", attempt=attempt, errno=error.errno)
                else:
                    emit("open_append", state="unexpected_success", attempt=attempt)
                    raise RuntimeError("FUSE O_APPEND was silently accepted")
            with opened(emit, args.file, os.O_RDONLY | os.O_NOFOLLOW, phase="after-rejected-open") as fd:
                check_bytes(fd, final, emit, "after-rejected-open")
            try:
                syscall(emit, "lstat", os.lstat, rejected_create, expected_errno=errno.ENOENT,
                        phase="before-rejected-create")
            except FileNotFoundError:
                emit("lstat_absent", path=str(rejected_create), phase="before-rejected-create")
            else:
                raise RuntimeError("Rejected-create sibling must be a new nonexistent path")
            emit("create_append", state="prepared", path=str(rejected_create))
            did_open = False
            try:
                with opened(emit, rejected_create,
                            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW,
                            operation="create_append", expected_errno=errno.EOPNOTSUPP):
                    did_open = True
            except OSError as error:
                if did_open or error.errno != errno.EOPNOTSUPP:
                    raise
                emit("reject_create_append", path=str(rejected_create), errno=error.errno)
            else:
                emit("create_append", state="unexpected_success", path=str(rejected_create))
                raise RuntimeError("FUSE unsupported CREATE fell back or was accepted; retain the unexpected file")
            try:
                syscall(emit, "lstat", os.lstat, rejected_create, expected_errno=errno.ENOENT,
                        phase="after-rejected-create")
            except FileNotFoundError:
                emit("lstat_absent", path=str(rejected_create), phase="after-rejected-create")
            else:
                raise RuntimeError("Rejected CREATE left an unexpected inode; retain it")
            emit("probe", state="confirmed", bytes=len(final), sha256=hashlib.sha256(final).hexdigest())
        except BaseException as error:
            try:
                emit("probe", state="unconfirmed", error=f"{type(error).__name__}: {error}",
                     **failure_fields(error, "evidence" if isinstance(error, EvidenceFailure) else "probe"),
                     retain_mount_state=True)
            except EvidenceFailure:
                secondary_note(error, "Final failure summary could not be persisted.")
            raise


if __name__ == "__main__":
    main()
