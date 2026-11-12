#!/usr/bin/env python3
"""Explicit mounted mode4 probe. Does not start/stop services or remove files.

prepare writes a NEW exclusive path through the actual FUSE mount. verify is
independent and can run after a supervised unmount/remount. Each successful
operation is recorded before proceeding. Unsupported OPEN/CREATE must fail
without disabling later FUSE OPEN callbacks. Synthetic input, no timing.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path


def expected():
    initial = bytes((i * 29 + 7) % 251 for i in range(180_000))
    data = bytearray(initial)
    data[65_531:65_531 + 75_000] = bytes((i * 17 + 11) % 253 for i in range(75_000))
    del data[120_123:]
    data.extend(bytes(90_000))
    return initial, bytes(data)


def write_all(fd, value, offset, emit):
    while value:
        count = os.pwrite(fd, value, offset)
        if count <= 0:
            raise RuntimeError("pwrite made no confirmed progress")
        emit("pwrite", offset=offset, bytes=count)
        value, offset = value[count:], offset + count


def check_bytes(fd, final, emit, phase):
    if os.fstat(fd).st_size != len(final):
        raise RuntimeError("actual file length differs")
    emit("fstat", phase=phase, bytes=len(final))
    got = os.pread(fd, len(final) + 1, 0)
    if got != final:
        raise RuntimeError("actual mounted bytes differ")
    emit("pread", phase=phase, bytes=len(got), byte_equal=True, sha256=hashlib.sha256(got).hexdigest())
    if os.pread(fd, 64, len(final)) != b"":
        raise RuntimeError("EOF read returned unexpected bytes")
    emit("pread_eof", phase=phase, offset=len(final), bytes=0)


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
    with os.fdopen(report_fd, "w", encoding="utf-8") as report:
        sequence = 0

        def emit(operation, state="operation_confirmed", **details):
            nonlocal sequence
            report.write(json.dumps({"schema": 1, "sequence": sequence, "state": state,
                                     "operation": operation, **details}) + "\n")
            report.flush()
            os.fsync(report.fileno())  # Local evidence durability, not the file's data fsync.
            sequence += 1

        emit("probe", state="prepared", command=args.command, file=str(args.file),
             rejected_create=str(rejected_create))
        try:
            initial, final = expected()
            flags = os.O_RDWR | os.O_NOFOLLOW
            if args.command == "prepare":
                flags |= os.O_CREAT | os.O_EXCL
            fd = os.open(args.file, flags, 0o600)
            try:
                emit("open", file=str(args.file), flags=flags)
                if args.command == "prepare":
                    write_all(fd, initial, 0, emit)
                    write_all(fd, bytes((i * 17 + 11) % 253 for i in range(75_000)), 65_531, emit)
                    os.ftruncate(fd, 120_123)
                    emit("ftruncate", bytes=120_123)
                    os.ftruncate(fd, len(final))
                    emit("ftruncate", bytes=len(final))
                    os.fsync(fd)  # Actual Meta63 barrier.
                    emit("fsync", file_data_barrier=True)
                check_bytes(fd, final, emit, "before-rejected-open")
            finally:
                os.close(fd)
                emit("close", file=str(args.file))
            for attempt in (1, 2):
                try:
                    fd = os.open(args.file, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
                except OSError as error:
                    if error.errno != errno.EOPNOTSUPP:
                        raise
                    emit("reject_open_append", attempt=attempt, errno=error.errno)
                else:
                    os.close(fd)
                    emit("open_append", state="unexpected_success", attempt=attempt)
                    raise RuntimeError("FUSE O_APPEND was silently accepted")
            fd = os.open(args.file, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                emit("open", file=str(args.file), flags=os.O_RDONLY | os.O_NOFOLLOW,
                     phase="after-rejected-open")
                check_bytes(fd, final, emit, "after-rejected-open")
            finally:
                os.close(fd)
                emit("close", file=str(args.file), phase="after-rejected-open")
            try:
                os.lstat(rejected_create)
            except FileNotFoundError:
                emit("lstat_absent", path=str(rejected_create), phase="before-rejected-create")
            else:
                raise RuntimeError("Rejected-create sibling must be a new nonexistent path")
            emit("create_append", state="prepared", path=str(rejected_create))
            try:
                fd = os.open(rejected_create, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            except OSError as error:
                if error.errno != errno.EOPNOTSUPP:
                    raise
                emit("reject_create_append", path=str(rejected_create), errno=error.errno)
            else:
                os.close(fd)
                emit("create_append", state="unexpected_success", path=str(rejected_create))
                raise RuntimeError("FUSE unsupported CREATE fell back or was accepted; retain the unexpected file")
            try:
                os.lstat(rejected_create)
            except FileNotFoundError:
                emit("lstat_absent", path=str(rejected_create), phase="after-rejected-create")
            else:
                raise RuntimeError("Rejected CREATE left an unexpected inode; retain it")
            emit("probe", state="confirmed", bytes=len(final), sha256=hashlib.sha256(final).hexdigest())
        except BaseException as error:
            emit("probe", state="unconfirmed", error=f"{type(error).__name__}: {error}", retain_mount_state=True)
            raise


if __name__ == "__main__":
    main()
