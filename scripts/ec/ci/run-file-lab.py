#!/usr/bin/env python3
"""Compose native-GC file CLI and two-mount acceptance on a fresh private tree.

The ordinary hosted runner packages one new tree, hands only that tree to UID
1000, then execs the ordinary-UID runtime. Explicit local mode keeps the actual
ordinary UID/GID and inherited resource limits without sudo or chown.
No RPC, FUSE ownership or recovery
protocol is implemented here. Private logs/keys remain on the disposable host.
Owner.command and final wait retain ownership without a local wall-clock cap;
the enclosing workflow cap may interrupt them and is not a clean-stop proof.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

TARGETS = ('storage_main', 'mgmtd_main', 'meta_main', 'admin_cli', 'ec_stripe_cli',
           'ec_file_cli', 'hf3fs_fuse_main', 'ec_mount_read_probe')
SERVICE_NAMES = {'fdb', 'mgmtd', 'storage', 'meta'}
PHASE = 'arguments'
PHASES = {'arguments', 'source', 'core', 'lab-build', 'prepare', 'package', 'copy-fdb',
          'inventory', 'handoff', 'uid-handoff', 'exec-uid1000', 'exec-same-user', 'runtime-preflight',
          'doctor', 'packaged-loader', 'bootstrap', 'cli-basic', 'cli-repair', 'dump-fuse-default.toml',
          'dump-launcher-default.toml', 'prepare-fuse', 'mode4-lifecycle', 'cleanup',
          'cleanup-unknown', 'receipt'}


class GateError(ValueError):
    """Only static messages written in this driver are safe for public logs."""


def phase(value):
    global PHASE
    if value not in PHASES:
        raise GateError('unexpected internal phase')
    PHASE = value


def diagnostic(error):
    result = {'phase': PHASE, 'error_type': type(error).__name__}
    if isinstance(error, GateError):
        result['detail'] = str(error)[:240]
    elif isinstance(error, OSError):
        result['errno'] = error.errno
    elif isinstance(error, subprocess.CalledProcessError):
        result['returncode'] = error.returncode
    return result


DIAGNOSTIC_LIMIT = 1 << 20
ERROR_TYPES = {'ValueError', 'GateError', 'RuntimeError', 'AssertionError', 'OSError',
               'FileNotFoundError', 'PermissionError', 'FileExistsError', 'TimeoutExpired',
               'InterruptedError', 'KeyboardInterrupt', 'JSONDecodeError', 'KeyError', 'TypeError'}
# Match complete static messages, never echo exception text, paths, argv or log tails.
ERROR_CODES = {
    'owned FUSE exited before mount readiness': 'fuse_exited_before_ready',
    'mount readiness deadline exceeded; probes are forbidden': 'mount_ready_timeout',
    'normal unmount and successful FUSE join are required before continuing': 'normal_unmount_or_join_failed',
    'normal unmount did not remove the owned mount': 'mount_remained_after_unmount',
    'cannot unmount a changed mount': 'mount_identity_changed_before_unmount',
    'first-start to remount-ready crossed the locked configured session timeout': 'remount_session_window_exceeded',
    'native supervisor run or service PID/start time changed': 'service_identity_changed',
    'original namespace/index or state directory changed': 'state_identity_changed',
    'owned mount or FUSE process changed': 'mount_identity_changed',
    'ec-lab must belong to this mount': 'mount_directory_mismatch',
    'USRBIO receipt did not confirm this file and the actual ABI': 'usrbio_receipt_mismatch',
    'USRBIO verify did not consume the original receipt': 'usrbio_original_receipt_mismatch',
    'POSIX receipt sequence differs': 'posix_receipt_sequence_mismatch',
    'POSIX receipt belongs to another invocation': 'posix_receipt_identity_mismatch',
    'POSIX receipt contains unconfirmed work': 'posix_receipt_unconfirmed',
    'POSIX bytes or terminal receipt differ': 'posix_receipt_bytes_mismatch',
    'file data changed across remount': 'remount_bytes_mismatch',
    'USRBIO inode changed across remount': 'remount_inode_mismatch',
    'a completed probe receipt changed': 'probe_receipt_changed',
    'actual file length differs': 'posix_length_mismatch',
    'actual mounted bytes differ': 'posix_bytes_mismatch',
    'EOF read returned unexpected bytes': 'posix_eof_mismatch',
    'FUSE O_APPEND was silently accepted': 'unsupported_open_accepted',
    'FUSE unsupported CREATE fell back or was accepted; retain the unexpected file': 'unsupported_create_accepted',
    'Rejected CREATE left an unexpected inode; retain it': 'unsupported_create_left_inode',
    'Actual FUSE readback differs byte-for-byte': 'usrbio_posix_bytes_mismatch',
    'Actual FUSE EOF differs': 'usrbio_posix_eof_mismatch',
    'Probe did not confirm the actual USRBIO ABI, all CQEs, boundaries and bytes': 'usrbio_abi_receipt_mismatch',
    'usrbio failed; see preserved stdout/stderr': 'usrbio_binary_nonzero',
}
LIFECYCLE_COMMANDS = {prefix + suffix for prefix in ('posix-', 'usrbio-', 'unmount-')
                      for suffix in ('prepare', 'verify')}
LIFECYCLE_COMMANDS |= {'status-' + label for label in
                       ('before-first', 'before-prepare', 'before-verify', 'ready-prepare', 'ready-verify',
                        'before-posix-prepare', 'before-posix-verify', 'before-usrbio-prepare',
                        'before-usrbio-verify', 'after-prepare', 'after-verify')}
POSIX_OPERATIONS = {'probe', 'open', 'pwrite', 'ftruncate', 'fsync', 'fstat', 'pread', 'pread_eof',
                    'close', 'reject_open_append', 'open_append', 'lstat_absent', 'create_append',
                    'reject_create_append', 'lstat', 'evidence_close'}
PREFLIGHT_CODES = {
    'use one ordinary real/effective UID and GID': 'ordinary_identity_required',
    'timeouts out of range': 'timeout_configuration_invalid',
    'wrong preparation contract': 'preparation_contract_mismatch',
    'preparation input changed': 'preparation_input_changed',
    'preparation belongs to another root': 'preparation_root_mismatch',
    'prepared config changed': 'prepared_config_changed',
    'fresh unmounted mountpoint required': 'mountpoint_not_fresh',
    'original new mount state must not yet exist': 'mount_state_not_fresh',
    'mode4 requires the same ordinary real/effective UID and GID': 'ordinary_identity_required',
    'prepared authenticated user differs from the mount user': 'authenticated_user_mismatch',
    'authenticated client/preparation differs from the mount user': 'authenticated_client_mismatch',
    'configs differ from the original mode4 preparation contract': 'rendered_config_mismatch',
    'FUSE binary differs from preparation': 'fuse_binary_mismatch',
    'prepared mount argv differs': 'mount_arguments_mismatch',
    'normal fusermount3 -u only': 'unmount_arguments_mismatch',
    'fusermount3 is required': 'unmount_tool_missing',
    'fusermount3 is not executable': 'unmount_tool_not_executable',
    'new local WORK outside the mount required': 'work_directory_invalid',
    'unsupported native process count': 'native_process_count_invalid',
    'unsupported configured Mgmtd session timeout': 'session_timeout_invalid',
}


def error_summary(text):
    result = {'code': 'unclassified_private_error'}
    if type(text) is not str or len(text) > 16384:
        return result
    kind, separator, message = text.partition(': ')
    if separator and kind in ERROR_TYPES:
        result['error_type'] = kind
    else:
        message = text
    if message in ERROR_CODES:
        result['code'] = ERROR_CODES[message]
    elif message.endswith(' failed, timed out or has an unknown join'):
        name = message.removesuffix(' failed, timed out or has an unknown join')
        if name in LIFECYCLE_COMMANDS:
            result.update(code='lifecycle_command_failed', command=name)
    # Only the numeric errno prefix is public; filenames and message bodies stay private.
    match = re.match(r'^\[Errno ([0-9]{1,4})\](?: |$)', message)
    if match and kind in ERROR_TYPES:
        result.update(code='os_error', errno=int(match.group(1)))
    return result


def diagnostic_fields(row, fields):
    if type(row) is not dict:
        return {}
    return {key: row[key] for key in fields if key in row and
            (type(row[key]) is bool or row[key] is None or
             (type(row[key]) is int and -(1 << 63) < row[key] < 1 << 63))}


def diagnostic_choice(value, choices):
    return value if type(value) is str and value in choices else 'unknown'


def diagnostic_file(path, *, lines=False):
    """Read only fixed caller-selected private evidence, bounded before parsing."""
    try:
        canonical(path)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'diagnostic input is not an ordinary file')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino)
                    and stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                    and opened.st_size <= DIAGNOSTIC_LIMIT, 'invalid diagnostic input')
            raw = stream.read(DIAGNOSTIC_LIMIT + 1)
        require(len(raw) <= DIAGNOSTIC_LIMIT, 'oversized diagnostic input')
        parts = raw.splitlines() if lines else [raw]
        require(len(parts) <= 256, 'too many diagnostic records')
        values = [json.loads(part, object_pairs_hook=unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError())) for part in parts]
        require(all(type(value) is dict for value in values), 'diagnostic object required')
        return (values if lines else values[0]), {'availability': 'read', 'sha256': hashlib.sha256(raw).hexdigest()}
    except Exception as error:
        return None, {'availability': 'unavailable', 'error_type':
                      type(error).__name__ if type(error).__name__ in ERROR_TYPES else 'other'}


CALLBACK_STAGES = {
    'setattr': {'handle', 'open', 'truncate', 'temporary_release', 'error_reply', 'observed_length', 'stat', 'reply'},
    'flush': {'recover', 'callback'},
    'release': {'close', 'callback'},
}
MOUNT_STAGES = {'guard', 'reopen', 'reserve', 'prepare', 'journal', 'reader', 'deadline', 'advance',
                'close_debt', 'close_reader', 'archive', 'result'}


def ec_failure_markers(sample):
    """Decode fixed error markers only; arbitrary log contents remain private."""
    result = []
    field = rb'([a-z_]{1,24})'
    callback = (rb'EC_FILE_CALLBACK_FAILURE operation=' + field + rb' stage=' + field +
                rb' code=([0-9]{1,10}) exception=([01])(?=\r?\n)')
    mount = (rb'EC_FILE_MOUNT_FAILURE operation=truncate stage=' + field + rb' code=([0-9]{1,10})'
             rb' debt=([01]) retained_reader=([01]) local_join_unconfirmed=([01]) exception=([01])(?=\r?\n)')
    # Preserve sample order, including a mount error preceding its callback error.
    for match in re.finditer(callback + b'|' + mount, sample):
        if match.group(1) is not None:
            operation, stage = match.group(1).decode('ascii'), match.group(2).decode('ascii')
            code = int(match.group(3))
            if stage not in CALLBACK_STAGES.get(operation, ()) or code > 0xffffffff:
                continue
            row = {'layer': 'callback', 'operation': operation, 'stage': stage, 'status_code': code,
                   'exception': match.group(4) == b'1'}
        else:
            stage, code = match.group(5).decode('ascii'), int(match.group(6))
            if stage not in MOUNT_STAGES or code > 0xffffffff:
                continue
            row = {'layer': 'mount', 'operation': 'truncate', 'stage': stage, 'status_code': code,
                   'debt': match.group(7) == b'1', 'retained_reader': match.group(8) == b'1',
                   'local_join_unconfirmed': match.group(9) == b'1', 'exception': match.group(10) == b'1'}
        result.append(row)
        if len(result) == 8:
            break
    return result


def fuse_log_summary(path):
    """Sample fixed logs without publishing text; markers are observations, not causal proof."""
    markers = {'Init application failed: ': 'application_init_failed',
               'Parse flags failed: ': 'flags_parse_failed',
               'Failed to init launcher: ': 'launcher_init_failed',
               'Try to establish client session failed: ': 'client_session_failed'}
    try:
        canonical(path)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'invalid diagnostic log')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino)
                    and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'diagnostic log changed')
            head = stream.read(32768)
            tail_start = max(len(head), info.st_size - 32768)
            stream.seek(tail_start)
            tail = stream.read(32768)
        events, progress, ec_failures = [], [], []
        # Never concatenate samples: a marker must not span an omitted section.
        for sample in (head, tail):
            ec_failures.extend(ec_failure_markers(sample)[:8 - len(ec_failures)])
            for marker, event in ((b'Start to init fuse clients', 'client_initialization_entered'),
                                  (b'Init fuse clients finished', 'client_initialization_returned')):
                if marker in sample and event not in progress:
                    progress.append(event)
            for marker, event in markers.items():
                name = rb'[A-Za-z_][A-Za-z_0-9]{0,127}(?:::[A-Za-z_][A-Za-z_0-9]{0,127}){0,3}'
                pattern = re.escape(marker.encode()) + name + rb'\(([0-9]{1,10})\)(?: |\r|\n|$)'
                for match in re.finditer(pattern, sample):
                    code = int(match.group(1))
                    row = {'event': event, 'status_code': code}
                    if code <= 0xffffffff and row not in events and len(events) < 8:
                        events.append(row)
        return {'availability': 'sampled', 'size_at_open': info.st_size,
                'sampled_bytes': len(head) + len(tail), 'omitted_middle': tail_start > len(head),
                'events': events, 'progress_markers': progress, 'event_limit_reached': len(events) == 8,
                'ec_failures': ec_failures, 'ec_failure_limit_reached': len(ec_failures) == 8}
    except Exception as error:
        return {'availability': 'unavailable', 'error_type':
                type(error).__name__ if type(error).__name__ in ERROR_TYPES else 'other'}


def lifecycle_preflight_summary(path):
    """Classify one bounded private child message, never publish its text."""
    try:
        canonical(path)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'invalid preflight log')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino)
                    and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_size <= 16384, 'invalid or oversized preflight log')
            raw = stream.read(16385)
        require(len(raw) <= 16384, 'oversized preflight log')
        lines = raw.decode('utf-8').splitlines()
        prefix = 'mode4 lifecycle preflight failed: '
        marker = len(lines) == 1 and lines[0].startswith(prefix)
        code = PREFLIGHT_CODES.get(lines[0][len(prefix):], 'unclassified_private_preflight_error') if marker else 'unknown'
        return {'availability': 'read', 'sha256': hashlib.sha256(raw).hexdigest(),
                'single_preflight_message_observed': marker, 'code': code}
    except Exception as error:
        return {'availability': 'unavailable', 'error_type':
                type(error).__name__ if type(error).__name__ in ERROR_TYPES else 'other'}


def probe_sink_summary(path):
    """Bound one fixed child's stderr; export only evidence failure enums/numbers."""
    try:
        canonical(path)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'invalid probe stderr')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino)
                    and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'probe stderr changed')
            raw = stream.read(16384)
        rows = []
        for line in raw.splitlines(keepends=True):
            prefix = b'MODE4_PROBE_EVIDENCE_FAILURE '
            if not line.endswith(b'\n') or not line.startswith(prefix):
                continue
            try:
                row = json.loads(line[len(prefix):], object_pairs_hook=unique,
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeError):
                continue
            if type(row) is not dict:
                continue
            safe = {'operation': diagnostic_choice(row.get('operation'), POSIX_OPERATIONS),
                    'state': diagnostic_choice(row.get('state'), ('prepared', 'confirmed', 'unconfirmed',
                        'operation_entered', 'operation_confirmed', 'operation_failed', 'unexpected_success')),
                    'evidence_error_type': diagnostic_choice(row.get('evidence_error_type'), ERROR_TYPES)}
            for key in ('evidence_errno', 'errno'):
                if type(row.get(key)) is int and 0 < row[key] < 4096:
                    safe[key] = row[key]
            if 'failure_source' in row:
                safe['failure_source'] = diagnostic_choice(row['failure_source'], ('syscall', 'validation', 'evidence', 'probe'))
            if 'error_type' in row:
                safe['error_type'] = diagnostic_choice(row['error_type'], ERROR_TYPES)
            for key in ('expected_failure', 'secondary'):
                if type(row.get(key)) is bool:
                    safe[key] = row[key]
            rows.append(safe)
            if len(rows) == 4:
                break
        return {'availability': 'sampled', 'sampled_bytes': len(raw), 'size_at_open': info.st_size,
                'truncated': info.st_size > len(raw), 'failures': rows, 'limit_reached': len(rows) == 4}
    except Exception as error:
        return {'availability': 'unavailable', 'error_type': diagnostic_choice(type(error).__name__, ERROR_TYPES)}


def lifecycle_summary(value):
    """Observations only: never used to authorize cleanup or declare acceptance."""
    result = {'subphase': 'unknown', 'subphase_basis': 'inferred_from_private_receipt'}
    if type(value) is not dict:
        return result
    result.update(diagnostic_fields(value, ('exitcode',)))
    result['status'] = diagnostic_choice(value.get('status'), ('started', 'passed', 'failed'))
    errors = value.get('errors')
    result['errors'] = [error_summary(row) for row in errors[:3]] if type(errors) is list else []
    commands = value.get('commands')
    result['commands'] = []
    if type(commands) is list and len(commands) <= 64:
        for row in commands:
            if type(row) is not dict or diagnostic_choice(row.get('name'), LIFECYCLE_COMMANDS) == 'unknown':
                continue
            item = {'name': row['name'], **diagnostic_fields(row, ('exitcode', 'joined', 'timed_out', 'cancelled', 'join_unknown'))}
            result['commands'].append(item)
            if not row['name'].startswith('unmount-'):
                result['last_noncleanup_command'] = row['name']
            # Ignore later cleanup errors when locating the first failed business command.
            if result['subphase'] == 'unknown' and not row['name'].startswith('unmount-') and (
                    row.get('exitcode') != 0 or row.get('joined') is not True or
                    row.get('timed_out') is True or row.get('cancelled') is True):
                result['subphase'] = row['name']
    mounts = value.get('mounts')
    result['mounts'] = []
    if type(mounts) is list and len(mounts) <= 2:
        for row in mounts:
            if type(row) is not dict or row.get('phase') not in ('prepare', 'verify'):
                continue
            item = {'phase': row['phase'], **diagnostic_fields(row, ('ready', 'joined', 'exitcode', 'normal_unmount',
                    'normal_join_timed_out', 'join_unknown', 'late_mount_observed', 'unmounted_without_owned_command'))}
            if 'cleanup_error' in row:
                item['error'] = error_summary(row['cleanup_error'])
            result['mounts'].append(item)
            if result['subphase'] == 'unknown' and row.get('ready') is not True:
                result['subphase'] = 'first-mount-readiness' if row['phase'] == 'prepare' else 'remount-readiness'
    cleanup = value.get('cleanup')
    result['cleanup'] = diagnostic_fields(cleanup, ('all_fuse_joined', 'all_commands_joined', 'unmounted', 'normal_unmounts'))
    if type(cleanup) is dict and type(cleanup.get('unknown_owned_processes')) is list:
        result['cleanup']['unknown_owned_process_count'] = len(cleanup['unknown_owned_processes'])
    if result['errors']:
        result['first_reported_error'] = result['errors'][0]
        code = result['errors'][0]['code']
        if code in ('normal_unmount_or_join_failed', 'mount_remained_after_unmount', 'mount_identity_changed_before_unmount'):
            result['subphase'] = 'unmount-or-join'
        elif code == 'remount_session_window_exceeded':
            result['subphase'] = 'remount-session-window'
        elif 'receipt' in code or code in ('remount_bytes_mismatch', 'remount_inode_mismatch'):
            result['subphase'] = 'receipt-verification'
    if result['subphase'] == 'unknown' and 'last_noncleanup_command' in result:
        result['subphase'] = 'after-' + result['last_noncleanup_command']
    return result


def failure_evidence(parent, report):
    """No arbitrary logfile/receipt paths are followed; all output fields are selected."""
    evidence = {'first_failure': report.get('first_failure'),
                'cleanup': diagnostic_fields(report, ('cleanup_blocked', 'supervisor_exitcode'))}
    if 'failed_command' in report:
        evidence['failed_command'] = report['failed_command']
    final = report.get('final_supervisor_observation')
    if type(final) is dict:
        evidence['cleanup']['supervisor_stage'] = final.get('stage') if final.get('stage') in ('stopped', 'failed') else 'other'
        if 'failure' in final:
            evidence['cleanup']['supervisor_reported_failure'] = final['failure'] is not None
    if report.get('failure_phase') != 'mode4-lifecycle':
        return evidence
    failed = report.get('failed_command')
    if (type(failed) is dict and failed.get('phase') == 'mode4-lifecycle'
            and type(failed.get('returncode')) is int and failed['returncode'] == 2
            and type(failed.get('sequence')) is int and 1 <= failed['sequence'] <= 4096):
        # The retained Owner supplies only its ordinal, never an arbitrary log path.
        # This observation cannot establish cleanup, success, or a historical cause.
        evidence['lifecycle_preflight'] = lifecycle_preflight_summary(
            parent / 'runtime' / f"{failed['sequence']:03}-mode4-lifecycle.stderr")
    value, source = diagnostic_file(parent / 'mode4/result.json')
    evidence['lifecycle'] = {'source': source, **lifecycle_summary(value)}
    probes = []
    for stage in ('prepare', 'verify'):
        rows, source = diagnostic_file(parent / ('mode4/posix-' + stage + '.jsonl'), lines=True)
        item = {'kind': 'posix', 'phase': stage, 'source': source}
        if rows:
            item['record_count'] = len(rows)
            item['last_operation'] = diagnostic_choice(rows[-1].get('operation'), POSIX_OPERATIONS)
            item['last_state'] = diagnostic_choice(rows[-1].get('state'), (
                'prepared', 'confirmed', 'unconfirmed', 'operation_confirmed', 'unexpected_success',
                'operation_entered', 'operation_failed'))
            failed = next((row for row in rows if row.get('state') == 'operation_failed'
                           and row.get('expected_failure') is not True), None)
            if failed is not None:
                item['first_failed_operation'] = diagnostic_choice(failed.get('operation'), POSIX_OPERATIONS)
                item['failure_source'] = diagnostic_choice(failed.get('failure_source'), ('syscall', 'validation', 'evidence'))
                item['error_type'] = diagnostic_choice(failed.get('error_type'), ERROR_TYPES)
                number = failed.get('errno')
                if type(number) is int and 0 < number < 4096:
                    item['errno'] = number
            failed = next((row for row in rows if 'error' in row), None)
            if failed is not None:
                item['error'] = error_summary(failed['error'])
            entered = [row for row in rows if row.get('state') == 'operation_entered']
            if entered:
                item['last_entered_operation'] = diagnostic_choice(entered[-1].get('operation'), POSIX_OPERATIONS)
            secondary = [row for row in rows if row.get('operation') == 'close'
                         and row.get('state') == 'operation_failed' and row.get('secondary') is True]
            if secondary:
                item['secondary_close_error'] = {
                    'error_type': diagnostic_choice(secondary[0].get('error_type'), ERROR_TYPES)}
                number = secondary[0].get('errno')
                if type(number) is int and 0 < number < 4096:
                    item['secondary_close_error']['errno'] = number
            confirmed = [row for row in rows if row.get('state') == 'operation_confirmed']
            if confirmed:
                item['last_confirmed_operation'] = diagnostic_choice(confirmed[-1].get('operation'), POSIX_OPERATIONS)
                item['recent_confirmed_operations'] = [diagnostic_choice(row.get('operation'), POSIX_OPERATIONS)
                                                       for row in confirmed[-4:]]
        commands = value.get('commands') if type(value) is dict else None
        if type(commands) is list and len(commands) <= 64:
            matches = [row for row in commands if type(row) is dict and row.get('name') == 'posix-' + stage]
            if len(matches) == 1:
                sequence = matches[0].get('sequence')
                if type(sequence) is int and 1 <= sequence <= 4096:
                    item['evidence_sink'] = probe_sink_summary(
                        parent / 'mode4' / f'{sequence:03}-posix-{stage}.stderr')
        probes.append(item)
        row, source = diagnostic_file(parent / ('mode4/usrbio-' + stage + '/result.json'))
        item = {'kind': 'usrbio', 'phase': stage, 'source': source}
        if row is not None:
            item['state'] = row.get('state') if row.get('state') in ('started', 'confirmed', 'unconfirmed') else 'unknown'
            if 'error' in row:
                item['error'] = error_summary(row['error'])
        probes.append(item)
    evidence['probes'] = probes
    evidence['fuse_log_samples'] = {
        stage + '-stderr': fuse_log_summary(parent / ('mode4/' + stage + '-fuse.stderr'))
        for stage in ('prepare', 'verify')}
    # The preparer assigns fixed handler indices. Do not enumerate arbitrary logs or use receipt paths.
    evidence['fuse_log_samples'].update({
        'handler-' + str(index): fuse_log_summary(parent / ('fuse-config/logs/fuse-' + str(index) + '.log'))
        for index in range(2)})
    return evidence


def remember_failure(report, error):
    # Called before cleanup changes PHASE. Later cleanup failures cannot overwrite this.
    report.setdefault('failure_phase', PHASE)
    report.setdefault('first_failure', diagnostic(error))


def emit_failure_evidence(parent, report, observation_stage):
    # Diagnostic failure must never change process ownership, exit status or the first cause.
    try:
        evidence = failure_evidence(parent, report)
        evidence['observation_stage'] = observation_stage
        evidence['observations_only_not_acceptance'] = True
        encoded = json.dumps(evidence, sort_keys=True, ensure_ascii=True)
        if len(encoded) > 24576:
            encoded = '{"diagnostic_unavailable":"summary_limit"}'
        print('FILE_LAB_FAILURE ' + encoded, flush=True)
    except Exception:
        try:
            print('FILE_LAB_FAILURE {"diagnostic_unavailable":"observation_or_output_error"}', flush=True)
        except Exception:
            pass


def require(ok, message):
    if not ok:
        raise GateError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 << 20,
            'invalid or oversized JSON input')
    value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    require(type(value) is dict, 'JSON object required')
    return value


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(path):
    require(path.is_absolute() and '..' not in path.parts, 'absolute canonical path required')
    require(path == path.resolve(strict=True), 'redirected path rejected')
    for item in (path, *path.parents):
        require(not item.is_symlink(), 'symlink ancestor rejected')
    return path


def private(path, uid):
    canonical(path)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o077,
            'private owner directory required')


def write_new(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def copy_new(source, target, mode=0o600):
    canonical(source)
    before = sha(source)
    with source.open('rb') as incoming:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as outgoing:
            while block := incoming.read(1 << 20):
                outgoing.write(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    require(sha(target) == before and sha(source) == before, 'exclusive copy hash differs')
    return before


def tree_rows(root, uid, *, retain=False):
    """Open every entry by a held parent FD; never follow links during handoff.

    The only privileged mutations use these verified FDs after the full check.
    No recursive chown, path concatenation traversal or adopted tree is used.
    """
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds, rows = [root_fd], []
    device = os.fstat(root_fd).st_dev
    try:
        def visit(fd, relative, depth):
            require(depth <= 16 and len(rows) < 4096, 'handoff tree exceeds bounds')
            info = os.fstat(fd)
            directory = stat.S_ISDIR(info.st_mode)
            require(info.st_dev == device and info.st_uid == uid, 'foreign device or owner in handoff')
            require(directory or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                    'only unlinked-to-other-paths regular files and directories are allowed')
            mode = stat.S_IMODE(info.st_mode)
            require(not mode & 0o7000 and (not mode & 0o077 if directory else not mode & 0o022),
                    'unsafe handoff permissions')
            row = {'path': relative, 'kind': 'directory' if directory else 'file', 'mode': mode}
            if not directory:
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    row.update(size=info.st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
            rows.append(row)
            if directory:
                for name in sorted(os.listdir(fd)):
                    require(name not in ('.', '..') and '/' not in name, 'invalid directory entry')
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    fds.append(child)
                    visit(child, name if relative == '.' else relative + '/' + name, depth + 1)
        visit(root_fd, '.', 0)
        if retain:
            return rows, fds
        return rows
    finally:
        if not retain or sys.exc_info()[0] is not None:
            for fd in reversed(fds):
                os.close(fd)


def handoff_shape(parent, request, *, suffix=''):
    require(suffix == '' or re.fullmatch(r'-spare-(central|pipeline|helper)-[12]', suffix) is not None,
            'invalid fixed handoff suffix')
    if suffix:
        require(request.get('strategy') in ('central', 'pipeline', 'helper')
                and type(request.get('failures')) is int and request['failures'] in (1, 2)
                and suffix == '-spare-' + request['strategy'] + '-' + str(request['failures']),
                'handoff suffix differs from the requested fault case')
    require(re.fullmatch(r'ec-h-[1-9][0-9]*-[1-9][0-9]*' + re.escape(suffix), parent.name) is not None
            and parent.parent == Path('/tmp'), 'handoff path must be the fixed fresh CI root')
    require(type(request['schema']) is int and request['schema'] == 1 and request['parent'] == str(parent)
            and request['creator_uid'] == 1001 and request['target_uid'] == 1000,
            'handoff identity differs')
    require(parent.name == 'ec-h-' + request['run_id'] + '-' + request['run_attempt'] + suffix, 'run identity differs')
    paths = [row['path'] for row in request['inventory']]
    require(len(paths) == len(set(paths)) and '.' in paths, 'duplicate or missing inventory root')
    require(all(p == '.' or (not p.startswith('/') and all(part not in ('', '.', '..')
                for part in p.split('/'))) for p in paths), 'inventory path escapes root')


def privileged_handoff(parent, expected_sha, *, suffix='', driver_name='run-file-lab.py'):
    phase('uid-handoff')
    require(os.getuid() == os.geteuid() == 0, 'handoff requires the scoped sudo invocation')
    private(parent, 1001)
    request_path = parent / 'handoff-request.json'
    require(sha(request_path) == expected_sha, 'handoff request hash differs')
    request = read_json(request_path)
    require((not suffix and driver_name == 'run-file-lab.py')
            or (bool(suffix) and driver_name == 'run-spare-lab.py'), 'unexpected handoff driver')
    handoff_shape(parent, request, suffix=suffix)
    info = parent.stat()
    require([info.st_dev, info.st_ino] == request['parent_identity'], 'original directory was replaced')
    rows, fds = tree_rows(parent, 1001, retain=True)
    try:
        require([row for row in rows if row['path'] != 'handoff-request.json'] == request['inventory'],
                'fresh tree differs from the pre-handoff inventory')
        require(sha(parent / 'tools' / driver_name) == request['driver_sha256'], 'copied driver differs')
        if suffix:
            require(sha(parent / 'tools/run-file-lab.py') == request['shared_driver_sha256'],
                    'copied shared handoff driver differs')
        # Refuse to borrow an account that already owns unrelated live work.
        for path in Path('/proc').iterdir():
            if path.name.isdecimal():
                try:
                    fields = re.search(r'^Uid:\s+(.+)$', (path / 'status').read_text(), re.M)
                except (FileNotFoundError, ProcessLookupError):
                    continue
                require(fields is not None and 1000 not in map(int, fields[1].split()),
                        'UID1000 already owns an active process')
        import grp
        import pwd
        try:
            grp.getgrgid(1000)
        except KeyError:
            subprocess.run(['/usr/sbin/groupadd', '--gid', '1000', 'ec-native-1000'], check=True)
        try:
            account = pwd.getpwuid(1000)
        except KeyError:
            subprocess.run(['/usr/sbin/useradd', '--uid', '1000', '--gid', '1000', '--no-create-home',
                            '--home-dir', str(parent / 'home'), '--shell', '/usr/sbin/nologin',
                            'ec-native-1000'], check=True)
            account = pwd.getpwuid(1000)
        require(account.pw_uid == 1000 and account.pw_gid == 1000, 'unexpected UID1000 primary group')
        # All checks complete before changing any FD; children before root.
        for fd in reversed(fds):
            require(os.fstat(fd).st_uid == 1001, 'owner changed during handoff')
            os.fchown(fd, 1000, 1000)
        marker = {'schema': 1, 'request_sha256': expected_sha, 'uid': 1000, 'gid': 1000,
                  'user': account.pw_name, 'parent_identity': request['parent_identity'],
                  'services_started': False}
        write_new(parent / 'handoff-complete.json', marker)
        os.chown(parent / 'handoff-complete.json', 1000, 1000, follow_symlinks=False)
        os.fsync(fds[0])
        print(json.dumps(marker, sort_keys=True))
    finally:
        for fd in reversed(fds):
            os.close(fd)


def core_gate(source, build, fdb, path):
    core = module(source / 'scripts/ec/ci/run-core-tests.py', 'lab_core_receipts')
    common = module(source / 'scripts/ec/test-native-fragments.py', 'lab_core_common')
    record = read_json(path)
    expected_count = len(core.META_CASES) + len(core.FUSE_CASES)
    require(record['status'] == 'passed' and record['exitcode'] == 0 and record['passed_tests'] == expected_count
            and not record['failures'] and not record['signals'], 'real current core acceptance is required')
    require(record['source'] == str(source) and record['build'] == str(build)
            and record['work'] == str(path.parent), 'core receipt path binding differs')
    require(record['runner_sha256'] == sha(source / 'scripts/ec/ci/run-core-tests.py'), 'core driver changed')
    for name, expected in record['helpers_sha256'].items():
        require(expected == sha(source / 'scripts/ec' / name), 'core helper changed')
    require(set(record['helpers_sha256']) == {'test-meta-catalog.py', 'test-native-fragments.py'}, 'core helper set differs')
    for name, expected in [('meta', core.META_CASES), ('fuse', core.FUSE_CASES)]:
        stage = record[name]
        folder = path.parent / name
        require(stage['status'] == 'passed' and stage['passed_tests'] == len(expected)
                and stage['skipped_tests'] == 0, 'incomplete core phase')
        core.check_xml(common.xml_tests(folder / 'tests.xml'), expected)
        core.check_listing(common.listed_tests(folder / ('test-list.log' if name == 'meta' else 'list.log')), expected)
        require(stage['xml_sha256'] == sha(folder / 'tests.xml'), 'core XML changed')
        require(stage['listing_sha256'] == sha(folder / ('test-list.log' if name == 'meta' else 'list.log')), 'core listing changed')
        require(stage['binary_sha256'] == sha(build / 'tests' / ('test_meta' if name == 'meta' else 'test_fuse_ec')),
                'accepted core binary changed')
    meta = read_json(path.parent / 'meta/results.json')
    require(record['meta']['receipt_sha256'] == sha(path.parent / 'meta/results.json'), 'Meta receipt changed')
    core.check_meta_receipt(meta, build / 'tests/test_meta', path.parent / 'meta')
    for name in ('fdbserver', 'fdbcli'):
        require(meta['binaries'][name]['sha256'] == sha(fdb / name), 'accepted FDB binary changed')
    core.command_ok(record['fuse']['listing'])
    core.command_ok(record['fuse']['execution'])
    return {'path': str(path), 'sha256': sha(path), 'passed_tests': expected_count,
            'binaries': {binary: record[stage]['binary_sha256']
                         for stage, binary in (('meta', 'test_meta'), ('fuse', 'test_fuse_ec'))}}


def build_gate(built, native, source, build, revision):
    """Require the same formal build producer and backend as the spare lab."""
    require(type(built.get('schema')) is int and built['schema'] == 1
            and tuple(built.get('targets', [])) == TARGETS
            and set(built.get('binaries', {})) == set(TARGETS), 'explicit eight-target lab build required')
    for item in (built, native):
        require(type(item.get('schema')) is int and item['schema'] == 1
                and item.get('source') == str(source) and item.get('build') == str(build)
                and item.get('revision') == revision and item.get('backend') in ('scalar', 'isal')
                and item.get('acceptance_executed') is False, 'same-source backend build identity differs')
    require(native.get('lab_targets_requested') is True
            and all(built.get(key) == native.get(key) for key in
                    ('backend', 'isal', 'build_script_sha256', 'cmake_cache_sha256'))
            and all(native.get('binaries', {}).get(name) == digest for name, digest in built['binaries'].items()),
            'native and lab build receipts differ')
    if built['backend'] == 'scalar':
        require(built.get('isal') is None, 'Scalar receipt unexpectedly selects ISA-L')
    else:
        provider = built.get('isal', {}).get('provider', {})
        require(provider.get('sha256') == '40ccd5e5abaff0451feff750d2b011370a546ac4706d1b06b9285ac26eda2c3c',
                'unexpected ISA-L provider digest')


def local_identity(request, uid, euid, gid, egid):
    require(type(uid) is int and uid > 0 and uid == euid and type(gid) is int and gid >= 0 and gid == egid,
            'local mode requires unchanged ordinary real/effective UID and GID')
    require(request.get('execution_mode') == 'local-same-user'
            and type(request.get('creator_uid')) is int and request['creator_uid'] == uid
            and type(request.get('target_uid')) is int and request['target_uid'] == uid
            and type(request.get('target_gid')) is int and request['target_gid'] == gid,
            'local OS identity differs from preparation')


def local_shape(parent, request):
    local_identity(request, os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    private(parent, os.geteuid())
    private(parent.parent, os.geteuid())
    require(type(request.get('schema')) is int and request['schema'] == 1
            and request.get('parent') == str(parent)
            and request.get('parent_identity') == [parent.stat().st_dev, parent.stat().st_ino],
            'local preparation identity differs')


def mount_host_gate():
    """Check prerequisites without mounting or changing host permissions."""
    import resource
    for which, minimum in ((resource.RLIMIT_NOFILE, 65536), (resource.RLIMIT_MEMLOCK, 3 << 30)):
        require(all(value == resource.RLIM_INFINITY or value >= minimum for value in resource.getrlimit(which)),
                'runtime resource limit insufficient')
    tool = shutil.which('fusermount3')
    require(tool is not None, 'system fusermount3 is required')
    unmount = Path(tool).resolve(strict=True)
    require(unmount.is_file() and os.access(unmount, os.X_OK), 'fusermount3 is not executable')
    fd = os.open('/dev/fuse', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode), '/dev/fuse is not a character device')
    finally:
        os.close(fd)
    return {'fusermount3': str(unmount), 'sha256': sha(unmount), 'device_opened': True,
            'mount_permission_proven': False}


def resolution_gate(backend, text, lab, *, fuse=False):
    require('not found' not in text, 'packaged runtime library unresolved')
    observed = {}
    for name in ('libisal.so.2', 'libfdb_c.so', 'libfuse3.so.3'):
        matches = re.findall(r'^\s*' + re.escape(name) + r'\s+=>\s+(\S+)\s+\(', text, re.M)
        if matches:
            require(matches == [str(lab / 'lib' / name)], 'loader resolved a provider outside the package')
            observed[name] = matches[0]
    require((backend == 'isal' and 'libisal.so.2' in observed)
            or (backend == 'scalar' and 'libisal' not in text), 'loader differs from the selected codec backend')
    require(not fuse or 'libfuse3.so.3' in observed, 'FUSE loader provider is missing')
    return observed


def require_cli_result(value):
    require(value.get('success') is True and value.get('failure') is None
            and value.get('all_owned_children_joined') is True and value.get('steps'), 'CLI phase incomplete')
    require(all(step.get('checks_complete') is True for step in value['steps']), 'CLI step lacks checks')


def require_shutdown(final, cleanup, ready_run, supervisor_code):
    codes = cleanup.get('exit_codes') if type(cleanup) is dict else None
    require(type(final) is dict and {'run', 'stage', 'failure'} <= set(final)
            and type(supervisor_code) is int and supervisor_code == 0
            and final.get('run') == ready_run and final.get('stage') == 'stopped'
            and final.get('failure') is None and type(cleanup) is dict and cleanup.get('clean') is True
            and type(codes) is dict and set(codes) == SERVICE_NAMES
            and all(type(code) is int and code in ({0, -15} if name == 'fdb' else {0})
                    for name, code in codes.items()), 'native shutdown not fully confirmed')


def package_backend_gate(built, package, lab):
    """Bind an explicitly selected codec provider; legacy receipts stay unlabelled."""
    if 'backend' not in built and 'isal' not in built:
        return {'backend': 'unrecorded', 'provider_verified': False}
    require(built.get('backend') in ('scalar', 'isal') and 'isal' in built, 'incomplete codec backend receipt')
    files = package.get('files', {})
    isal_files = {name for name in files if Path(name).name.startswith('libisal')}
    if built['backend'] == 'scalar':
        require(built['isal'] is None and not isal_files, 'Scalar package must not carry ISA-L')
        return {'backend': 'scalar', 'provider_verified': False}
    require(isal_files == {'lib/libisal.so.2'} and type(built['isal']) is dict, 'ISA-L package provider missing or ambiguous')
    provider = built['isal'].get('provider', {})
    require(type(provider.get('path')) is str and type(provider.get('sha256')) is str
            and re.fullmatch(r'[0-9a-f]{64}', provider['sha256']) is not None, 'invalid bound ISA-L provider')
    item = files['lib/libisal.so.2']
    expected = canonical(Path(provider['path']))
    actual = canonical(Path(item['source']))
    require(actual == expected and item.get('kind') == 'shared-library'
            and item.get('sha256') == provider['sha256']
            and sha(actual) == sha(canonical(lab / 'lib/libisal.so.2')) == provider['sha256'],
            'packaged ISA-L source or bytes differ from the selected build')
    return {'backend': 'isal', 'provider_verified': True, 'provider_source': str(expected),
            'packaged_provider': str(lab / 'lib/libisal.so.2'), 'provider_sha256': provider['sha256']}


def require_mount_result(value):
    cleanup = value.get('cleanup', {})
    require(value.get('schema') == 1 and value.get('status') == 'passed' and value.get('exitcode') == 0
            and value.get('services_started_or_stopped') is False, 'lifecycle phase failed')
    require(cleanup.get('all_fuse_joined') is True and cleanup.get('all_commands_joined') is True
            and cleanup.get('unmounted') is True and cleanup.get('normal_unmounts') == 2
            and cleanup.get('fuse_exitcodes') == [0, 0] and cleanup.get('unknown_owned_processes') == [],
            'lifecycle did not confirm both normal joins')
    probes = value.get('probes', [])
    expected = {(kind, phase, 'confirmed') for kind in ('posix', 'usrbio') for phase in ('prepare', 'verify')}
    require(len(probes) == 4 and {(p['kind'], p['phase'], p['state']) for p in probes} == expected,
            'lifecycle probe set differs')
    for kind in ('posix', 'usrbio'):
        before = next(p for p in probes if p['kind'] == kind and p['phase'] == 'prepare')
        after = next(p for p in probes if p['kind'] == kind and p['phase'] == 'verify')
        require(type(before['bytes']) is int and before['bytes'] > 0 and after['bytes'] == before['bytes']
                and re.fullmatch(r'[0-9a-f]{64}', before['sha256']) is not None
                and after['sha256'] == before['sha256'], 'lifecycle remount bytes differ')
        if kind == 'usrbio':
            require(type(before['inode']) is int and before['inode'] > 0 and after['inode'] == before['inode']
                    and before['actual_abi_reads'] == after['actual_abi_reads'] == 3, 'actual USRBIO identity/ABI differs')


def mount_cleanup_known(value):
    cleanup = value.get('cleanup', {})
    return (cleanup.get('all_fuse_joined') is True and cleanup.get('all_commands_joined') is True
            and cleanup.get('unmounted') is True and cleanup.get('unknown_owned_processes') == [])


def process_identity(pid):
    path = Path('/proc') / str(pid)
    text = (path / 'stat').read_text()
    fields = text[text.rfind(')') + 2:].split()
    require(len(fields) > 19 and fields[0] not in ('Z', 'X'), 'owned process is not live')
    return {'pid': pid, 'start_ticks': fields[19], 'executable': os.readlink(path / 'exe')}


def stop_signals(owner):
    return {sig: signal.signal(sig, owner.interrupted) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}


def runtime(parent):
    phase('runtime-preflight')
    private(parent, os.geteuid())
    request = read_json(parent / 'handoff-request.json')
    local = request.get('execution_mode') == 'local-same-user'
    if local:
        local_shape(parent, request)
    else:
        require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1000,
                'hosted runtime requires actual UID/GID1000')
        handoff_shape(parent, request)
    marker = read_json(parent / 'handoff-complete.json')
    require(marker.get('uid') == os.geteuid() and marker.get('gid') == os.getegid(), 'prepared owner differs')
    require(not local or marker.get('ownership_changed') is False, 'local mode cannot change ownership')
    require(marker['request_sha256'] == sha(parent / 'handoff-request.json')
            and marker['parent_identity'] == request['parent_identity']
            and request['parent_identity'] == [parent.stat().st_dev, parent.stat().st_ino]
            and sha(Path(__file__).resolve()) == request['driver_sha256'], 'handoff/source proof differs')
    require([row for row in tree_rows(parent, os.geteuid()) if row['path'] not in
             ('handoff-request.json', 'handoff-complete.json')] == request['inventory'], 'post-handoff inputs changed')
    lab = parent / '3fs-ec-native-file'
    sys.path.insert(0, str(lab / 'scripts'))
    helper = module(lab / 'scripts/fuse-read-acceptance.py', 'lab_owner')
    native = module(lab / 'scripts/native-v2.py', 'lab_native')
    output = parent / 'runtime'
    output.mkdir(mode=0o700)
    owner = helper.Owner(output)
    previous = stop_signals(owner)
    report = {'schema': 1, 'status': 'running', 'revision': request['revision'], 'uid': os.geteuid(),
              'gid': os.getegid(), 'execution_mode': request.get('execution_mode', 'hosted-handoff'),
              'preparation_sha256': sha(parent / 'handoff-request.json'),
              'native_build_sha256': request['native_build_sha256'], 'lab_build_sha256': request['lab_build_sha256'],
              'backend_validation': request['backend_validation'],
              'core': request['core'], 'receipts': [], 'services_started': False, 'exitcode': 1}
    supervisor = None
    failure = None
    lifecycle_started = False
    try:
        report['mount_host'] = mount_host_gate()
        manifest = read_json(lab / 'cluster.json')
        remote_user = manifest.get('authenticated_user', {'uid': 1000, 'gid': 1000})
        require(remote_user == {'uid': os.geteuid(), 'gid': os.getegid()},
                'fresh remote file identity differs from runtime UID/GID')
        report['authenticated_user'] = remote_user
        os.environ.pop('LD_PRELOAD', None)
        os.environ['LD_LIBRARY_PATH'] = str(lab / 'lib')
        def command(name, argv):
            phase(name)
            owner.checkpoint()
            try:
                result = owner.command(name, argv)
            except BaseException:
                # Owner has already waited its retained child, but its original
                # ValueError does not expose the actual return code to the parent.
                row, source = diagnostic_file(output / f'{owner.sequence:03}-{name}.finished.json')
                report['failed_command'] = {'phase': name, 'source': source, 'sequence': owner.sequence,
                                            **diagnostic_fields(row, ('returncode',))}
                raise
            owner.checkpoint()
            return result
        command('doctor', [sys.executable, '-B', lab / 'scripts/native-v2.py', 'doctor', '--root', lab])
        report['packaged_loader'] = {}
        for name in ('storage_main', 'hf3fs_fuse_main'):
            listing = command('packaged-loader', ['ldd', lab / 'bin' / name]).decode('utf-8')
            report['packaged_loader'][name] = resolution_gate(
                request['backend_validation']['backend'], listing, lab, fuse=name == 'hf3fs_fuse_main')
        phase('bootstrap')
        log = (output / 'supervisor.log').open('xb')
        try:
            supervisor = subprocess.Popen([sys.executable, '-B', str(lab / 'scripts/native-v2.py'),
                                           'start', '--root', str(lab), '--mode', 'initialize'],
                                          cwd=lab, stdout=log, stderr=subprocess.STDOUT)
            report.update(services_started=True, supervisor_pid=supervisor.pid)
            report['supervisor_identity'] = process_identity(supervisor.pid)
            write_new(output / 'supervisor-started.json', report)
            deadline = time.monotonic() + 900
            ready = None
            while time.monotonic() < deadline:
                owner.checkpoint()
                require(supervisor.poll() is None, 'native supervisor exited before readiness')
                try:
                    state = native.request_control(lab, 'status')
                except (FileNotFoundError, ConnectionRefusedError):
                    time.sleep(0.25)
                    continue
                if state['stage'] == 'ready':
                    ready = state
                    break
                time.sleep(0.25)
            require(ready is not None, 'native readiness timed out')
            ready_identities = {row['name']: process_identity(row['pid']) for row in ready['processes']}
            def healthy():
                owner.checkpoint()
                require(supervisor.poll() is None, 'owned supervisor exited')
                now = native.request_control(lab, 'status')
                require(now['stage'] == 'ready' and now['failure'] is None and now['run'] == ready['run']
                        and now['processes'] == ready['processes'] and now['root'] == str(lab)
                        and {row['name'] for row in now['processes']} == SERVICE_NAMES
                        and len(now['processes']) == 4
                        and all(row['exit_code'] is None for row in now['processes']), 'native identity/readiness changed')
                require({row['name']: process_identity(row['pid']) for row in now['processes']} == ready_identities,
                        'service process birth identity changed')
                disk = os.statvfs(lab)
                require(disk.f_bavail * disk.f_frsize >= 4 << 30, 'less than existing 4GiB lab disk reserve')
            healthy()
            report['ready'] = ready
            report['ready_process_identities'] = ready_identities
            for cli_phase in ('basic', 'repair'):
                healthy()
                command('cli-' + cli_phase, [sys.executable, '-B', lab / 'scripts/file-cli-acceptance.py',
                                            '--root', lab, '--label', 'hosted-' + cli_phase, cli_phase])
                receipt = lab / 'client/file-cli-acceptance' / ('hosted-' + cli_phase) / cli_phase / 'report/result.json'
                require_cli_result(read_json(receipt))
                report['receipts'].append({'phase': cli_phase, 'path': str(receipt), 'sha256': sha(receipt)})
            healthy()
            mountpoint = parent / 'mount'
            mountpoint.mkdir(mode=0o700)
            for flag, name in (('--dump_default_cfg', 'fuse-default.toml'),
                               ('--dump_default_launcher_cfg', 'launcher-default.toml')):
                data = command('dump-' + name, [lab / 'bin/hf3fs_fuse_main', flag])
                fd = os.open(parent / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            command('prepare-fuse', [sys.executable, '-B', lab / 'scripts/prepare-fuse-file.py', '--root', lab,
                    '--fuse-default', parent / 'fuse-default.toml', '--launcher-default', parent / 'launcher-default.toml',
                    '--output-dir', parent / 'fuse-config', '--mountpoint', mountpoint, '--create-new', '--shard-bytes', '65536'])
            healthy()
            lifecycle_started = True
            command('mode4-lifecycle', [sys.executable, '-B', lab / 'scripts/mode4-lifecycle-acceptance.py',
                    '--root', lab, '--preparation', parent / 'fuse-config/preparation.json', '--work', parent / 'mode4'])
            receipt = parent / 'mode4/result.json'
            lifecycle = read_json(receipt)
            require_mount_result(lifecycle)
            for probe in lifecycle['probes']:
                proof = canonical(Path(probe['receipt']))
                require(proof.is_relative_to(parent / 'mode4') and sha(proof) == probe['receipt_sha256'],
                        'lifecycle probe receipt hash differs')
            report['receipts'].append({'phase': 'mode4-lifecycle', 'path': str(receipt), 'sha256': sha(receipt)})
            healthy()
            report['business_passed'] = True
        except BaseException as error:
            remember_failure(report, error)
            emit_failure_evidence(parent, report, 'before-native-cleanup')
            raise
        finally:
            phase('cleanup')
            # Only this owned supervisor is signalled if its private control
            # endpoint is unavailable. No PID files or adopted descendants.
            if supervisor is not None:
                safe_to_stop = not lifecycle_started
                if lifecycle_started:
                    try:
                        lifecycle = read_json(parent / 'mode4/result.json')
                        safe_to_stop = mount_cleanup_known(lifecycle) and not helper.mounts_at(parent / 'mount')
                    except Exception:
                        safe_to_stop = False
                if not safe_to_stop and supervisor.poll() is None:
                    # The lifecycle driver still owns its unknown FUSE/probe
                    # descendants. Do not tear down their services or adopt them.
                    report['cleanup_blocked'] = True
                    phase('cleanup-unknown')
                    try:
                        write_new(output / 'cleanup-blocked.json', report)
                        print('file-lab: cleanup unconfirmed; retaining owned supervisor, no forced stop', flush=True)
                        emit_failure_evidence(parent, report, 'native-cleanup-blocked')
                    finally:
                        supervisor.wait()  # External cancellation is not a cleanup-success receipt.
                try:
                    if supervisor.poll() is None:
                        try:
                            native.request_control(lab, 'stop')
                        except Exception:
                            supervisor.terminate()
                finally:
                    supervisor.wait()
                report['supervisor_exitcode'] = supervisor.returncode
                final_path = lab / 'state/last-supervisor.json'
                if final_path.is_file():
                    report['final_supervisor_observation'] = read_json(final_path)
            log.close()
        final = read_json(lab / 'state/last-supervisor.json')
        cleanup = read_json(lab / 'logs' / report['ready']['run'] / 'cleanup.json')
        require_shutdown(final, cleanup, report['ready']['run'], supervisor.returncode)
        require(not helper.mounts_at(parent / 'mount'), 'mount still present after lifecycle')
        report.update(status='passed', exitcode=0, cleanup=cleanup)
    except BaseException as error:
        failure = error
        remember_failure(report, error)
        report.update(status='failed', error_type=type(error).__name__, error=str(error), exitcode=1,
                      diagnostic=diagnostic(error))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        write_new(output / 'result.json', report)
    if report['status'] == 'failed':
        emit_failure_evidence(parent, report, 'after-native-cleanup')
    print(json.dumps({'status': report['status'], 'exitcode': report['exitcode'], 'revision': report['revision'],
                      'receipt_sha256': sha(output / 'result.json'), 'receipts': report['receipts'],
                      'services_started': report['services_started'], 'diagnostic': report.get('diagnostic'),
                      'failure_phase': report.get('failure_phase'), 'first_failure': report.get('first_failure')},
                     sort_keys=True), flush=True)
    return report['exitcode']


def prepare(args):
    phase('source')
    local = args.local_work is not None
    source, build, fdb, core_path = map(canonical, (args.source, args.build, args.fdb_bin_dir, args.core_record))
    if local:
        require(os.getuid() == os.geteuid() and os.getuid() > 0 and os.getgid() == os.getegid(),
                'local mode requires unchanged ordinary real/effective UID and GID')
        work = canonical(build.parent)
        require(build.name == 'build' and fdb == work / 'fdb/bin', 'local build/FDB layout differs')
        private(args.local_work.parent, os.geteuid())
        require(args.local_work.is_absolute() and '..' not in args.local_work.parts
                and not os.path.lexists(args.local_work), 'fresh canonical local work required')
        require(all(not args.local_work.is_relative_to(path) and not path.is_relative_to(args.local_work)
                    for path in (source, work, core_path.parent)), 'local lab overlaps source/build/core work')
        require(len(os.fsencode(args.local_work / '3fs-ec-native-file/state/control.sock')) < 104,
                'local work path is too long for the control socket')
        mount_host_gate()
        run_id, attempt = None, None
    else:
        require(os.getuid() == os.geteuid() == 1001, 'preparation requires the observed ordinary hosted UID1001')
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'hosted Linux job required')
        run_id, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
        require(all(re.fullmatch(r'[1-9][0-9]*', x) for x in (run_id, attempt)), 'invalid hosted run identity')
        work = canonical(Path(os.environ['RUNNER_TEMP']) / 'ec-native')
        require(source == canonical(Path(os.environ['GITHUB_WORKSPACE'])) and build == work / 'build'
                and fdb == work / 'fdb/bin' and core_path == work / 'acceptance/results.json', 'unexpected source/build/core paths')
    require(Path(__file__).resolve() == source / 'scripts/ec/ci/run-file-lab.py', 'use the checked-out formal driver')
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    require(local or revision == os.environ['GITHUB_SHA'], 'source is not the triggering revision')
    subprocess.run(['git', '-C', str(source), 'diff', '--exit-code', 'HEAD', '--ignore-submodules=all'], check=True,
                   stdout=subprocess.DEVNULL)
    phase('core')
    core = core_gate(source, build, fdb, core_path)
    phase('lab-build')
    built = read_json(work / 'provenance/lab-build.json')
    native_path = work / 'provenance/native-build.json'
    native_build = read_json(native_path)
    build_gate(built, native_build, source, build, revision)
    require(all(native_build['binaries'].get(name) == digest for name, digest in core['binaries'].items()),
            'accepted core binaries differ from the same native build')
    require(built['build_script_sha256'] == sha(source / 'scripts/ec/ci/build-native.sh')
            and built.get('cmake_cache_sha256') == sha(build / 'CMakeCache.txt')
            and built.get('native_build_receipt_sha256') == sha(native_path), 'backend/native build input binding differs')
    require(all(built['binaries'][name] == sha(build / 'bin' / name) for name in TARGETS), 'lab binary changed')
    output = args.local_work.with_name(args.local_work.name + '-preparation') if local else work / 'lab-preparation'
    output.mkdir(mode=0o700)
    helper = module(source / 'scripts/ec/cluster/fuse-read-acceptance.py', 'lab_prepare_owner')
    owner = helper.Owner(output)
    previous = stop_signals(owner)
    parent = args.local_work if local else Path('/tmp') / ('ec-h-' + run_id + '-' + attempt)
    require(not os.path.lexists(parent) and (local or canonical(parent.parent) == Path('/tmp')),
            'fresh preparation root required')
    parent.mkdir(mode=0o700)
    lab = parent / '3fs-ec-native-file'
    try:
        def command(name, argv):
            phase(name)
            owner.checkpoint()
            data = owner.command(name, argv)
            owner.checkpoint()
            return data
        prepare_argv = [sys.executable, '-B', source / 'scripts/ec/cluster/native-v2.py', 'prepare',
                        '--root', lab, '--source', source, '--profile', 'gc', '--file-api', '--port-base', '13500']
        if local:
            prepare_argv.extend(['--user-uid', str(os.geteuid()), '--user-gid', str(os.getegid())])
        command('prepare', prepare_argv)
        command('package', [sys.executable, '-B', source / 'scripts/ec/package-services.py', '--build', build,
                           '--output', lab, '--native-gc', '--ec-file-mount'])
        manifests = list((lab / 'provenance').glob('services-*/manifest.json'))
        require(len(manifests) == 1, 'one new package manifest required')
        package = read_json(manifests[0])
        require(package['build_directory'] == str(build) and package['bundle_directory'] == str(lab), 'package path binding differs')
        for relative, item in package['files'].items():
            require(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'invalid package relative path')
            require(sha(lab / relative) == item['sha256'], 'packaged contents differ')
            if item['kind'] == 'service':
                name = Path(relative).name
                require(item['source'] == str(build / 'bin' / name) and item['sha256'] == built['binaries'][name],
                        'packaged service differs from the current lab build')
        require({Path(p).name for p, item in package['files'].items() if item['kind'] == 'service'} == set(TARGETS),
                'package runtime target set differs')
        require('scripts/mode4-lifecycle-acceptance.py' in package['files'], 'lifecycle must be in formal package manifest')
        backend_validation = package_backend_gate(built, package, lab)
        phase('copy-fdb')
        for name in ('fdbserver', 'fdbcli'):
            copy_new(fdb / name, lab / 'bin' / name, 0o755)
        require(sha(lab / 'lib/libfdb_c.so') == sha(fdb.parent / 'lib/libfdb_c.so'), 'FDB shared library differs')
        for name in ('home', 'tmp', 'tools'):
            (parent / name).mkdir(mode=0o700)
        driver_sha = copy_new(Path(__file__).resolve(), parent / 'tools/run-file-lab.py')
        phase('inventory')
        request = {'schema': 1, 'parent': str(parent), 'parent_identity': [parent.stat().st_dev, parent.stat().st_ino],
                   'creator_uid': os.geteuid() if local else 1001, 'target_uid': os.geteuid() if local else 1000,
                   'target_gid': os.getegid() if local else 1000, 'run_id': run_id, 'run_attempt': attempt,
                   'execution_mode': 'local-same-user' if local else 'hosted-handoff',
                   'revision': revision, 'core': core, 'driver_sha256': driver_sha,
                   'backend_validation': backend_validation,
                   'package_manifest_sha256': sha(manifests[0]), 'lab_build_sha256': sha(work / 'provenance/lab-build.json'),
                   'native_build_sha256': sha(native_path),
                   'inventory': tree_rows(parent, os.geteuid())}
        write_new(parent / 'handoff-request.json', request)
        request_sha = sha(parent / 'handoff-request.json')
        if local:
            import pwd
            marker = {'schema': 1, 'request_sha256': request_sha, 'uid': os.geteuid(), 'gid': os.getegid(),
                      'user': pwd.getpwuid(os.geteuid()).pw_name, 'parent_identity': request['parent_identity'],
                      'services_started': False, 'ownership_changed': False}
            write_new(parent / 'handoff-complete.json', marker)
        else:
            marker = json.loads(command('handoff', ['sudo', '-n', '/usr/bin/python3', '-I', parent / 'tools/run-file-lab.py',
                                                   '--handoff', parent, '--request-sha256', request_sha]))
        require(marker['request_sha256'] == request_sha and marker['uid'] == (os.geteuid() if local else 1000),
                'handoff response differs')
        write_new(output / 'prepared.json', {'schema': 1, 'parent': str(parent), 'revision': revision,
                  'request_sha256': request_sha, 'handoff': marker, 'services_started': False})
        owner.checkpoint()
        phase('exec-same-user' if local else 'exec-uid1000')
        argv = ['/usr/bin/sudo', '-n', 'prlimit', '--memlock=3221225472:3221225472', '--nofile=65536:65536', '--',
                'setpriv', '--reuid=1000', '--regid=1000', '--clear-groups', 'env', '--chdir=' + str(parent),
                'HOME=' + str(parent / 'home'), 'USER=' + marker['user'], 'LOGNAME=' + marker['user'],
                'TMPDIR=' + str(parent / 'tmp'), 'LD_LIBRARY_PATH=' + str(lab / 'lib'),
                'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/bin/python3', '-I', parent / 'tools/run-file-lab.py',
                '--run-owned', parent]
        if local:
            argv = ['/usr/bin/env', '--chdir=' + str(parent), 'HOME=' + str(parent / 'home'),
                    'USER=' + marker['user'], 'LOGNAME=' + marker['user'], 'TMPDIR=' + str(parent / 'tmp'),
                    'LD_LIBRARY_PATH=' + str(lab / 'lib'), 'PATH=/usr/local/bin:/usr/bin:/bin',
                    '/usr/bin/python3', '-I', parent / 'tools/run-file-lab.py', '--run-owned', parent]
        # Replace this foreground command with its runtime. Hosted sudo forwards
        # signals/exit to UID1000; local exec keeps the same user and limits.
        # No cross-UID background Popen is discarded or adopted later.
        for sig in previous:
            signal.signal(sig, signal.SIG_DFL)
        os.execv(argv[0], list(map(str, argv)))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'fdb-bin-dir', 'core-record'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--local-work', type=Path, help='fresh private same-user work; no hosted environment or chown')
    internal = parser.add_mutually_exclusive_group()
    internal.add_argument('--handoff', type=Path, help=argparse.SUPPRESS)
    internal.add_argument('--run-owned', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--request-sha256', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.version_info >= (3, 11), 'Python 3.11 or newer required')
    require(sys.platform == 'linux', 'Linux only; no WSL/VM launcher is implemented')
    os.umask(0o077)
    sys.dont_write_bytecode = True
    os.environ.pop('LD_PRELOAD', None)
    if args.handoff:
        privileged_handoff(args.handoff, args.request_sha256)
        return 0
    if args.run_owned:
        return runtime(args.run_owned)
    require(all(getattr(args, name) is not None for name in ('source', 'build', 'fdb_bin_dir', 'core_record')),
            'source/build/fdb-bin-dir/core-record are required')
    prepare(args)
    return 1  # execv never returns on success.


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('file-lab: ' + json.dumps(diagnostic(error), sort_keys=True) + '; preserve private receipts', file=sys.stderr)
        raise SystemExit(2)
