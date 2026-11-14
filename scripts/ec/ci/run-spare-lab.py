#!/usr/bin/env python3
"""One explicit fresh gc-14 fault case, using the existing acceptance and owners.

No automatic retry, replacement identity, force kill or physical-host claim.
Owned command/final supervisor waits deliberately have no local kill timeout;
an enclosing job timeout is not evidence of a clean join.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

spec = importlib.util.spec_from_file_location('spare_shared_file_lab', Path(__file__).with_name('run-file-lab.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
require, read_json, sha = shared.require, shared.read_json, shared.sha
PROFILE = 'native-gc-local-14-storage-14-targets'
NAMES = {'fdb', 'mgmtd', 'meta'} | {f'storage-{n}' for n in range(10001, 10015)}
PACKAGED = {'storage_main', 'mgmtd_main', 'meta_main', 'admin_cli', 'ec_stripe_cli', 'ec_file_cli'}
STAGE = 'arguments'


def suffix(strategy, failures):
    require(strategy in ('central', 'pipeline', 'helper') and type(failures) is int and failures in (1, 2),
            'one explicit strategy and one/two failures required')
    return '-spare-' + strategy + '-' + str(failures)


def ledger(rows):
    require(type(rows) is list and rows, 'missing owned process ledger')
    result = {}
    for row in rows:
        require(type(row) is dict and set(row) == {'name', 'pid', 'exit_code'}
                and row['name'] in NAMES and type(row['pid']) is int and row['pid'] > 0
                and (row['exit_code'] is None or type(row['exit_code']) is int), 'invalid process row')
        key = (row['name'], row['pid'])
        require(key not in result, 'duplicate process identity')
        result[key] = row['exit_code']
    return result


def status_gate(value, root, run=None, transport=None):
    shared.require_transport_observation(value, transport)
    require(type(value.get('schema')) is int and value['schema'] == 1
            and value.get('profile') == PROFILE and value.get('root') == str(root)
            and value.get('stage') == 'ready' and value.get('failure') is None
            and value.get('logical_targets') == 14 and value.get('storage_processes') == 14
            and value.get('storage_process_failure_domains') == 14
            and value.get('independent_storage_failure_domains') == 1
            and value.get('performance_validated') is False
            and (run is None or value.get('run') == run)
            and isinstance(value.get('run'), str)
            and re.fullmatch(r'run-[0-9]{8}T[0-9]{6}\.[0-9]{6}Z', value['run']) is not None,
            'wrong supervisor readiness or identity')
    maintenance = value.get('maintenance', {})
    require(maintenance.get('enabled') is True and maintenance.get('failed') is False
            and maintenance.get('pending') is None and maintenance.get('running') is None,
            'unresolved supervisor maintenance')
    return ledger(value.get('processes'))


def ready_gate(value, root, transport=None):
    rows = status_gate(value, root, transport=transport)
    require(len(rows) == 17 and {name for name, _ in rows} == NAMES
            and all(code is None for code in rows.values())
            and value['maintenance'].get('expected_exits') == []
            and value['maintenance'].get('faulted_storage_nodes') == [], 'not the original seventeen live processes')
    return rows


def command_joins(value):
    commands = value.get('commands')
    return (value.get('all_owned_commands_joined') is True and type(commands) is list and bool(commands)
            and all(type(row) is dict and type(row.get('index')) is int and row['index'] == index
                    and row.get('process_started') is True
                    and row.get('process_exited') is True and type(row.get('returncode')) is int
                    for index, row in enumerate(commands)))


def case_cleanup_known(value, ready, strategy, failures, expected_uid=1000):
    return (ready is not None and type(value.get('schema')) is int and value['schema'] == 1
            and value.get('strategy') == strategy and type(value.get('failures')) is int
            and value['failures'] == failures and value.get('supervisor_uid') == expected_uid
            and value.get('supervisor_run') == ready['run'] and command_joins(value))


def case_gate(value, ready, completed, root, strategy, failures, expected_uid=1000, transport=None):
    """Bind the formal driver's proof, not a second implementation of repair/T2."""
    initial = ready_gate(ready, root, transport)
    require(type(value.get('schema')) is int and value['schema'] == 1
            and value.get('state') == 'completed' and value.get('success') is True
            and value.get('failure') is None and value.get('strategy') == strategy
            and type(value.get('failures')) is int and value['failures'] == failures
            and value.get('supervisor_uid') == expected_uid and value.get('supervisor_run') == ready['run']
            and value.get('whole_cluster_started_or_stopped') is False
            and value.get('old_debt_completion_requires_actual_cli_T2') is True
            and value.get('physical_machine_failure_domains') == 1
            and value.get('physical_disk_or_power_failure_tested') is False
            and value.get('performance_validated') is False and command_joins(value), 'formal fault case did not complete')
    require(all(row['returncode'] == 0 for row in value['commands']), 'failed owned case command')
    steps = value.get('steps')
    require(type(steps) is list and steps and all(row.get('checks_complete') is True for row in steps),
            'formal business step lacks its own checks')
    require(any(row.get('original_source_t2_confirmed') is True for row in steps)
            and any(row.get('original_range_t2_confirmed') is True for row in steps)
            and any(row.get('original_source_debt_retained') is True for row in steps), 'formal debt milestones absent')
    actions = value.get('actions')
    require(type(actions) is dict and set(actions) == {'fault', 'placement', 'restore'}, 'wrong fixed action set')
    nodes = list(range(10001, 10001 + failures))
    ids = set()
    for name, operation, fields in (
            ('fault', 'fault-storage', {'nodes': nodes}),
            ('placement', 'replace-placement', {'replacements': [[n, 10013 + i] for i, n in enumerate(nodes)]}),
            ('restore', 'restart-storage', {'nodes': nodes})):
        action = actions[name]
        action_id = action.get('action_id')
        require(type(action_id) is str and str(uuid.UUID(action_id)) == action_id and uuid.UUID(action_id).int
                and action_id not in ids, 'invalid or reused action UUID')
        ids.add(action_id)
        require(action == {'operation': operation, 'run': ready['run'], 'action_id': action_id, **fields},
                'action identity or selection changed')
        matching = [row for row in value.get('controls', []) if row.get('operation') == operation]
        require(len(matching) == 1 and matching[0].get('fixed_action') == action,
                'action was missing or reissued')
        observations = matching[0].get('observations', [])
        require(observations and observations[-1].get('request') == action
                and observations[-1].get('state') == 'completed'
                and observations[-1].get('cleanup_or_T2_claimed') is False, 'controller action not confirmed')
    actual = status_gate(completed, root, ready['run'], transport)
    require(set(initial) <= set(actual) and len(actual) == 18 + failures, 'complete process history missing')
    killed = {(name, pid): -9 for name, pid in initial if name in {f'storage-{n}' for n in nodes}}
    old_meta = next(key for key in initial if key[0] == 'meta')
    for key in initial:
        require(actual[key] == (killed[key] if key in killed else 0 if key == old_meta else None),
                'old owned process exit changed')
    added = set(actual) - set(initial)
    require({name for name, _ in added} == {'meta'} | {f'storage-{n}' for n in nodes}
            and len(added) == 1 + failures and all(actual[key] is None for key in added),
            'fresh Meta/Storage process identities missing')
    observed_kills = value.get('confirmed_sigkill_exit_observations')
    require(type(observed_kills) is list and ledger(observed_kills) == killed, 'original SIGKILL observations differ')
    restore = next(row for row in value['controls'] if row['operation'] == 'restart-storage')['observations'][-1]
    restored = restore.get('steps')
    require(type(restored) is list and len(restored) == failures
            and [row.get('node') for row in restored] == nodes
            and all(row.get('restarted_same_persistent_instance') is True
                    and type(row.get('observed_boot_nonce')) is str
                    and str(uuid.UUID(row['observed_boot_nonce'])) == row['observed_boot_nonce']
                    and uuid.UUID(row['observed_boot_nonce']).int for row in restored), 'original instance restore unconfirmed')
    require(completed['maintenance'].get('faulted_storage_nodes') == [], 'faulted instances remain')
    return actual


def shutdown_gate(final, cleanup, completed, root, supervisor_code, transport=None):
    shared.require_transport_observation(completed, transport)
    shared.require_transport_observation(final, transport)
    before = ledger(completed.get('processes'))
    after = ledger(final.get('processes'))
    require(supervisor_code == 0 and type(final.get('schema')) is int and final['schema'] == 1
            and final.get('root') == str(root)
            and final.get('profile') == PROFILE and final.get('run') == completed['run']
            and final.get('stage') == 'stopped' and final.get('failure') is None
            and final.get('maintenance') == completed.get('maintenance')
            and cleanup.get('clean') is True and set(before) == set(after), 'shutdown history incomplete')
    for key, old_code in before.items():
        allowed = {old_code} if old_code is not None else ({0, -15} if key[0] == 'fdb' else {0})
        require(after[key] in allowed and type(after[key]) is int, 'unexpected owned process shutdown code')
    projection = {row['name']: row['exit_code'] for row in final['processes']}
    require(cleanup.get('exit_codes') == projection and set(projection) == NAMES,
            'legacy cleanup projection differs from the full process ledger')
    return {'all_process_rows': len(after), 'all_owned_processes_exited': True,
            'fdb_exitcode': next(code for (name, _), code in after.items() if name == 'fdb')}


def resource_gate(doctor, transport=None):
    observations = doctor.get('observations', {})
    require(doctor.get('profile') == PROFILE and doctor.get('status') == 'ready' and doctor.get('problems') == []
            and doctor.get('services_started') is False
            and observations.get('required_available_memory_gib') == 7
            and observations.get('memory_kib', {}).get('MemAvailable', 0) >= 7 * 1024**2
            and observations.get('free_bytes', 0) >= 10 * 1024**3
            and observations.get('free_inodes', 0) >= 60000
            and observations.get('active_build_processes') == [], 'gc14 startup resource gate failed')
    shared.validate_transport_doctor(doctor, transport)


def resolution_gate(backend, text, lab):
    matches = re.findall(r'^\s*libisal\.so\.2\s+=>\s+(\S+)\s+\(', text, re.M)
    require('not found' not in text, 'packaged runtime library unresolved')
    if backend == 'isal':
        require(matches == [str(lab / 'lib/libisal.so.2')], 'actual ISA-L loader path differs from package')
    else:
        require(backend == 'scalar' and 'libisal' not in text, 'Scalar runtime unexpectedly loads ISA-L')


def command_records(output, count):
    rows = []
    for index in range(1, count + 1):
        starts = list(output.glob(f'{index:03}-*.started.json'))
        require(len(starts) == 1, 'owned command start record missing')
        start = starts[0]
        started = read_json(start)
        require(type(started.get('pid')) is int and started['pid'] > 0
                and type(started.get('argv')) is list and started['argv']
                and all(type(part) is str for part in started['argv']), 'invalid owned command start')
        finish = start.with_name(start.name.replace('.started.json', '.finished.json'))
        observed = read_json(finish)
        require(type(observed.get('returncode')) is int and type(observed.get('wall_ns')) is int
                and observed['wall_ns'] >= 0, 'owned command join record missing')
        rows.append({'started': str(start), 'started_sha256': sha(start), 'finished': str(finish),
                     'finished_sha256': sha(finish), 'returncode': observed['returncode']})
    return rows


def build_gate(built, native, source, build, revision):
    require(type(built.get('schema')) is int and built['schema'] == 1
            and tuple(built.get('targets', [])) == shared.TARGETS
            and set(built.get('binaries', {})) == set(shared.TARGETS), 'explicit eight-target lab build required')
    for item in (built, native):
        require(item.get('schema') == 1 and item.get('source') == str(source) and item.get('build') == str(build)
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
    """Same-UID mode has no privileged handoff and adopts no pre-existing tree."""
    local_identity(request, os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    shared.private(parent, os.geteuid())
    shared.private(parent.parent, os.geteuid())
    require(request.get('execution_mode') == 'local-same-user'
            and type(request.get('schema')) is int and request['schema'] == 1
            and request.get('parent') == str(parent)
            and request.get('parent_identity') == [parent.stat().st_dev, parent.stat().st_ino],
            'local preparation identity differs')
    suffix(request['strategy'], request['failures'])


def runtime(parent):
    global STAGE
    STAGE = 'runtime-preflight'
    shared.private(parent, os.geteuid())
    request = read_json(parent / 'handoff-request.json')
    case_suffix = suffix(request['strategy'], request['failures'])
    local = request.get('execution_mode') == 'local-same-user'
    if local:
        local_shape(parent, request)
    else:
        require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1000,
                'hosted runtime requires actual UID/GID1000')
        shared.handoff_shape(parent, request, suffix=case_suffix)
    marker = read_json(parent / 'handoff-complete.json')
    require(marker.get('uid') == os.geteuid() and marker.get('gid') == os.getegid(), 'prepared owner differs')
    require(not local or marker.get('ownership_changed') is False, 'local mode cannot change ownership')
    require(marker['request_sha256'] == sha(parent / 'handoff-request.json')
            and marker['parent_identity'] == request['parent_identity']
            and request['parent_identity'] == [parent.stat().st_dev, parent.stat().st_ino]
            and sha(Path(__file__).resolve()) == request['driver_sha256']
            and sha(parent / 'tools/run-file-lab.py') == request['shared_driver_sha256'], 'handoff/source proof differs')
    require([row for row in shared.tree_rows(parent, os.geteuid())
             if row['path'] not in ('handoff-request.json', 'handoff-complete.json')] == request['inventory'],
            'post-handoff inputs changed')
    lab = parent / '3fs-ec-native-spare'
    sys.path.insert(0, str(lab / 'scripts'))
    owner_module = shared.module(parent / 'tools/fuse-read-acceptance.py', 'spare_command_owner')
    native = shared.module(lab / 'scripts/native-v2.py', 'spare_native_supervisor')
    transport = shared.request_transport(request)  # The inventory-checked bundle has now loaded its config helper.
    output = parent / 'runtime'
    output.mkdir(mode=0o700)
    owner = owner_module.Owner(output)
    previous = shared.stop_signals(owner)
    report = {'schema': 1, 'status': 'running', 'exitcode': 1, 'revision': request['revision'],
              'strategy': request['strategy'], 'failures': request['failures'], 'backend': request['backend'],
              'core': request['core'], 'services_started': False, 'performance_validated': False,
              'preparation_sha256': sha(parent / 'handoff-request.json'),
              'lab_build_sha256': request['lab_build_sha256'],
              'native_build_sha256': request['native_build_sha256'],
              'execution_mode': request.get('execution_mode', 'hosted-handoff'),
              'backend_validation': request['backend_validation'],
              'physical_machine_failure_domains': 1, **shared.transport_fields(transport)}
    supervisor, log, ready, completed = None, None, None, None
    case_started, safe_stop = False, True
    result_path = lab / 'client/spare-fault-acceptance/report/result.json'
    try:
        import resource
        for which, minimum in ((resource.RLIMIT_NOFILE, 65536), (resource.RLIMIT_MEMLOCK, 3 << 30)):
            require(resource.getrlimit(which)[0] == resource.RLIM_INFINITY
                    or resource.getrlimit(which)[0] >= minimum, 'runtime resource limit insufficient')
        os.environ.pop('LD_PRELOAD', None)
        os.environ['LD_LIBRARY_PATH'] = str(lab / 'lib')
        packages = list((lab / 'provenance').glob('services-*/manifest.json'))
        require(len(packages) == 1 and sha(packages[0]) == request['package_manifest_sha256'],
                'prepared package receipt changed')
        package = read_json(packages[0])
        shared.validate_lab_transport(lab, request, package=package)
        STAGE = 'doctor'
        owner.checkpoint()
        doctor = json.loads(owner.command('doctor', [sys.executable, '-B', lab / 'scripts/native-v2.py',
                                                   'doctor', '--root', lab]), object_pairs_hook=shared.unique)
        resource_gate(doctor, transport)
        if transport is not None:
            doctor_path = output / f'{owner.sequence:03}-doctor.stdout'
            require(read_json(doctor_path) == doctor, 'doctor stdout differs from parsed observation')
            report['transport_doctor'] = {'sequence': owner.sequence, 'path': str(doctor_path),
                                          'sha256': sha(doctor_path), 'observation': doctor}
        owner.checkpoint()
        STAGE = 'packaged-loader'
        resolution_gate(request['backend'], owner.command('packaged-ldd', ['ldd', lab / 'bin/storage_main']).decode('utf-8'), lab)
        owner.checkpoint()
        STAGE = 'bootstrap'
        log = (output / 'supervisor.log').open('xb')
        supervisor = subprocess.Popen([sys.executable, '-B', str(lab / 'scripts/native-v2.py'), 'start',
                                       '--root', str(lab), '--mode', 'initialize'], cwd=lab,
                                      stdout=log, stderr=subprocess.STDOUT)
        report.update(services_started=True, supervisor_pid=supervisor.pid)
        report['supervisor_identity'] = shared.process_identity(supervisor.pid)
        shared.write_new(output / 'supervisor-started.json', report)
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            owner.checkpoint()
            require(supervisor.poll() is None, 'native supervisor exited before readiness')
            try:
                value = native.request_control(lab, 'status')
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.25)
                continue
            if value.get('stage') == 'ready':
                ready_gate(value, lab, transport)
                ready = value
                break
            time.sleep(0.25)
        require(ready is not None, 'native readiness timed out')
        shared.validate_lab_transport(lab, request, package=package, initialized=True, observations=(ready,))
        report['ready'] = ready
        report['ready_process_identities'] = [dict(name=row['name'], **shared.process_identity(row['pid']))
                                             for row in ready['processes']]
        shared.write_new(output / 'initial-ready.json', report['ready'])
        STAGE = 'fault-case'
        owner.checkpoint()
        case_started, safe_stop = True, False
        owner.command('fault-case', [sys.executable, '-B', lab / 'scripts/spare-fault-acceptance.py', '--root', lab,
                                    '--strategy', request['strategy'], '--failures', str(request['failures'])])
        value = read_json(result_path)
        safe_stop = case_cleanup_known(value, ready, request['strategy'], request['failures'], os.geteuid())
        completed = native.request_control(lab, 'status')
        case_gate(value, ready, completed, lab, request['strategy'], request['failures'], os.geteuid(), transport)
        shared.validate_lab_transport(lab, request, package=package, initialized=True, observations=(ready, completed))
        shared.validate_command_transports(lab, transport, value['commands'], allow_control=True)
        require(value.get('file_driver_sha256') == sha(lab / 'scripts/file-cli-acceptance.py'), 'file driver receipt differs')
        for row in value['controls']:
            if row.get('operation') in {'fault-storage', 'restart-storage', 'replace-placement'}:
                action = row['fixed_action']
                persisted = lab / 'state/fault-actions' / (action['action_id'] + '.json')
                require(read_json(persisted) == row['observations'][-1], 'persisted action/result differs')
        immutable = value.get('journal_sha256')
        require(type(immutable) is dict and immutable, 'missing immutable journal bindings')
        for path, expected in immutable.items():
            actual = shared.canonical(Path(path))
            require(actual.is_relative_to(lab / 'client') and sha(actual) == expected, 'retained journal changed')
        saved = read_json(result_path.parent / 'completed-supervisor.json')
        require(saved.get('supervisor_uid') == os.geteuid() and saved.get('observation') == completed,
                'current supervisor differs from formal case completion')
        report['completed'] = completed
        report['completed_process_identities'] = [dict(name=row['name'], **shared.process_identity(row['pid']))
                                                  for row in completed['processes'] if row['exit_code'] is None]
        report['case_result'] = {'path': str(result_path), 'sha256': sha(result_path),
                                 'actions': value['actions'], 'confirmed_sigkill': value['confirmed_sigkill_exit_observations']}
        owner.checkpoint()
        report['business_passed'] = True
    except BaseException as error:
        report.update(failure_phase=STAGE, error_type=type(error).__name__, error=str(error))
    finally:
        STAGE = 'cleanup'
        try:
            if case_started and not safe_stop:
                try:
                    safe_stop = case_cleanup_known(read_json(result_path), ready, request['strategy'], request['failures'], os.geteuid())
                except Exception:
                    safe_stop = False
            if supervisor is not None:
                if not safe_stop and supervisor.poll() is None:
                    report['cleanup_unknown'] = True
                    shared.write_new(output / 'cleanup-unknown.json', report)
                    print('spare-lab: child cleanup unknown; retaining owned supervisor without forced stop', flush=True)
                    supervisor.wait()
                if supervisor.poll() is None:
                    try:
                        reply = native.request_control(lab, 'stop')
                        require(reply.get('root') == str(lab) and (ready is None or reply.get('run') == ready['run']),
                                'stop response belongs to another supervisor')
                        shared.require_transport_observation(reply, transport)
                        report['stop_method'] = 'private_control'
                    except Exception as error:
                        report['stop_control_error'] = type(error).__name__
                        if 'supervisor_identity' in report:
                            require(shared.process_identity(supervisor.pid) == report['supervisor_identity'],
                                    'owned supervisor birth identity changed')
                        supervisor.terminate()  # Its handler requests orderly shutdown; never SIGKILL.
                        report['stop_method'] = 'owned_SIGTERM_fallback'
                supervisor.wait()
                report['supervisor_exitcode'] = supervisor.returncode
                final = read_json(lab / 'state/last-supervisor.json')
                report['final_supervisor_observation'] = final
                cleanup = read_json(lab / 'logs' / final['run'] / 'cleanup.json')
                report['cleanup_observation'] = cleanup
                if completed is not None:
                    report['cleanup'] = shutdown_gate(final, cleanup, completed, lab, supervisor.returncode, transport)
                if report.get('business_passed') and not report.get('cleanup_unknown'):
                    shared.validate_lab_transport(lab, request, package=package, initialized=True, observations=(final,))
                    shared.validate_command_transports(lab, transport, value['commands'], allow_control=True)
                    if transport is not None:
                        proof = report['transport_doctor']
                        require(sha(output / f"{proof['sequence']:03}-doctor.stdout") == proof['sha256'],
                                'doctor stdout changed after admission')
                    require(report.get('stop_method') == 'private_control', 'normal control stop was not confirmed')
                    report['commands'] = command_records(output, owner.sequence)
                    require(all(row['returncode'] == 0 for row in report['commands']), 'owned command failed')
                    report.update(status='passed', exitcode=0)
        except BaseException as error:
            report.update(cleanup_error_type=type(error).__name__, cleanup_error=str(error))
        finally:
            # Retain the direct Popen even if logging, socket validation or the
            # orderly-stop request failed. Waiting is not a remote cleanup proof.
            if supervisor is not None and supervisor.poll() is None:
                try:
                    supervisor.wait()
                except BaseException as error:
                    report.update(cleanup_unknown=True, final_wait_error=type(error).__name__)
            if log is not None:
                log.close()
            if report['exitcode'] != 0:
                report['status'] = 'failed_retained'
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            shared.write_new(output / 'result.json', report)
    print('SPARE_LAB_RESULT ' + json.dumps({'status': report['status'], 'exitcode': report['exitcode'],
          'revision': request['revision'], 'strategy': request['strategy'], 'failures': request['failures'],
          'backend': request['backend'], 'receipt_sha256': sha(output / 'result.json'),
          'case_result': report.get('case_result'), 'cleanup': report.get('cleanup'),
          'failure_phase': report.get('failure_phase'), 'error_type': report.get('error_type'),
          'cleanup_unknown': report.get('cleanup_unknown', False), 'performance_validated': False}, sort_keys=True), flush=True)
    return report['exitcode']


def native_prepare_command(source, lab, transport=None):
    return [sys.executable, '-B', source / 'scripts/ec/cluster/native-v2.py', 'prepare', '--root', lab,
            '--source', source, '--profile', 'gc-14', '--file-api', '--port-base', '14500',
            *shared.transport_cli_args(transport)]


def prepare(args):
    global STAGE
    STAGE = 'source'
    local = args.local_work is not None
    case_suffix = suffix(args.strategy, args.failures)
    source, build, fdb, core_path = map(shared.canonical, (args.source, args.build, args.fdb_bin_dir, args.core_record))
    if local:
        require(os.getuid() == os.geteuid() and os.getuid() > 0 and os.getgid() == os.getegid(),
                'local mode requires unchanged ordinary real/effective UID and GID')
        work = shared.canonical(build.parent)
        require(build.name == 'build' and fdb == work / 'fdb/bin', 'local build/FDB layout differs')
        shared.private(args.local_work.parent, os.geteuid())
        require(args.local_work.is_absolute() and '..' not in args.local_work.parts
                and not os.path.lexists(args.local_work), 'fresh canonical local work required')
        run_id, attempt = None, None
    else:
        require(os.getuid() == os.geteuid() == 1001 and os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_OS') == 'Linux', 'ordinary hosted Linux UID1001 required')
        run_id, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
        require(all(re.fullmatch(r'[1-9][0-9]*', item) for item in (run_id, attempt)), 'invalid hosted run identity')
        work = shared.canonical(Path(os.environ['RUNNER_TEMP']) / 'ec-native')
        require(source == shared.canonical(Path(os.environ['GITHUB_WORKSPACE'])) and build == work / 'build'
                and fdb == work / 'fdb/bin' and core_path == work / 'acceptance/results.json', 'unexpected build/core paths')
    require(Path(__file__).resolve() == source / 'scripts/ec/ci/run-spare-lab.py', 'use formal checked-out driver')
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    require(local or revision == os.environ['GITHUB_SHA'], 'source is not triggering revision')
    subprocess.run(['git', '-C', str(source), 'diff', '--exit-code', 'HEAD', '--ignore-submodules=all'],
                   stdout=subprocess.DEVNULL, check=True)
    transport = shared.lab_transport_selection(args, source)
    STAGE = 'core'
    core = shared.core_gate(source, build, fdb, core_path)
    built_path = work / 'provenance/lab-build.json'
    built = read_json(built_path)
    native = read_json(work / 'provenance/native-build.json')
    build_gate(built, native, source, build, revision)
    require(built['build_script_sha256'] == sha(source / 'scripts/ec/ci/build-native.sh')
            and all(built['binaries'][name] == sha(build / 'bin' / name) for name in shared.TARGETS),
            'same-source lab build receipt differs')
    require(built.get('cmake_cache_sha256') == sha(build / 'CMakeCache.txt')
            and built.get('native_build_receipt_sha256') == sha(work / 'provenance/native-build.json'),
            'backend/native build input binding differs')
    output = (args.local_work.with_name(args.local_work.name + '-preparation') if local
              else work / ('spare-preparation' + case_suffix))
    output.mkdir(mode=0o700)
    helper = shared.module(source / 'scripts/ec/cluster/fuse-read-acceptance.py', 'spare_prepare_owner')
    owner = helper.Owner(output)
    previous = shared.stop_signals(owner)
    parent = args.local_work if local else Path('/tmp') / ('ec-h-' + run_id + '-' + attempt + case_suffix)
    require(not os.path.lexists(parent) and (local or shared.canonical(parent.parent) == Path('/tmp')),
            'fresh preparation root required')
    parent.mkdir(mode=0o700)
    lab = parent / '3fs-ec-native-spare'
    try:
        def command(name, argv):
            global STAGE
            STAGE = name
            owner.checkpoint()
            value = owner.command(name, argv)
            owner.checkpoint()
            return value
        # Keep this case's listeners separate from the preceding file lab.
        command('prepare', native_prepare_command(source, lab, transport))
        command('package', [sys.executable, '-B', source / 'scripts/ec/package-services.py', '--build', build,
                            '--output', lab, '--native-gc'])
        manifests = list((lab / 'provenance').glob('services-*/manifest.json'))
        require(len(manifests) == 1, 'exactly one new package manifest required')
        package = read_json(manifests[0])
        require(package['build_directory'] == str(build) and package['bundle_directory'] == str(lab), 'package binding differs')
        for relative, item in package['files'].items():
            require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
                    and sha(lab / relative) == item['sha256'], 'packaged file binding differs')
            if item['kind'] == 'service':
                name = Path(relative).name
                require(item['source'] == str(build / 'bin' / name) and item['sha256'] == built['binaries'][name],
                        'packaged binary differs from selected build')
        require({Path(path).name for path, item in package['files'].items() if item['kind'] == 'service'} == PACKAGED
                and {'scripts/file-cli-acceptance.py', 'scripts/spare-fault-acceptance.py'} <= set(package['files']),
                'fault package closure incomplete')
        backend_validation = shared.package_backend_gate(built, package, lab)
        for name in ('fdbserver', 'fdbcli'):
            shared.copy_new(fdb / name, lab / 'bin' / name, 0o755)
        require(sha(lab / 'lib/libfdb_c.so') == sha(fdb.parent / 'lib/libfdb_c.so'), 'FDB shared library differs')
        for name in ('home', 'tmp', 'tools'):
            (parent / name).mkdir(mode=0o700)
        driver_sha = shared.copy_new(Path(__file__).resolve(), parent / 'tools/run-spare-lab.py')
        shared_sha = shared.copy_new(source / 'scripts/ec/ci/run-file-lab.py', parent / 'tools/run-file-lab.py')
        shared.copy_new(source / 'scripts/ec/cluster/fuse-read-acceptance.py', parent / 'tools/fuse-read-acceptance.py')
        request = {'schema': 1, 'parent': str(parent), 'parent_identity': [parent.stat().st_dev, parent.stat().st_ino],
                   'creator_uid': os.geteuid() if local else 1001, 'target_uid': os.geteuid() if local else 1000,
                   'target_gid': os.getegid() if local else 1000, 'run_id': run_id, 'run_attempt': attempt,
                   'execution_mode': 'local-same-user' if local else 'hosted-handoff',
                   'strategy': args.strategy, 'failures': args.failures, 'revision': revision, 'backend': built['backend'],
                   'backend_validation': backend_validation,
                   'core': core, 'driver_sha256': driver_sha, 'shared_driver_sha256': shared_sha,
                   'package_manifest_sha256': sha(manifests[0]), 'lab_build_sha256': sha(built_path),
                   'native_build_sha256': sha(work / 'provenance/native-build.json'),
                   'preparation_commands': command_records(output, owner.sequence),
                   'inventory': shared.tree_rows(parent, os.geteuid()), **shared.transport_fields(transport)}
        shared.validate_lab_transport(lab, request, package=package)
        shared.write_new(parent / 'handoff-request.json', request)
        request_sha = sha(parent / 'handoff-request.json')
        if local:
            import pwd
            marker = {'schema': 1, 'request_sha256': request_sha, 'uid': os.geteuid(), 'gid': os.getegid(),
                      'user': pwd.getpwuid(os.geteuid()).pw_name, 'parent_identity': request['parent_identity'],
                      'services_started': False, 'ownership_changed': False}
            shared.write_new(parent / 'handoff-complete.json', marker)
        else:
            marker = json.loads(command('handoff', ['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I',
                                parent / 'tools/run-spare-lab.py', '--handoff', parent, '--request-sha256', request_sha]))
        require(marker['request_sha256'] == request_sha and marker['uid'] == (os.geteuid() if local else 1000), 'handoff response differs')
        shared.write_new(output / 'prepared.json', {'parent': str(parent), 'revision': revision, 'request_sha256': request_sha,
                         'handoff': marker, 'services_started': False, 'commands': command_records(output, owner.sequence)})
        owner.checkpoint()
        STAGE = 'exec-same-user' if local else 'exec-uid1000'
        argv = ['/usr/bin/sudo', '-n', 'prlimit', '--memlock=3221225472:3221225472', '--nofile=65536:65536', '--',
                'setpriv', '--reuid=1000', '--regid=1000', '--clear-groups', 'env', '--chdir=' + str(parent),
                'HOME=' + str(parent / 'home'), 'USER=' + marker['user'], 'LOGNAME=' + marker['user'],
                'TMPDIR=' + str(parent / 'tmp'), 'LD_LIBRARY_PATH=' + str(lab / 'lib'), 'PATH=/usr/local/bin:/usr/bin:/bin',
                '/usr/bin/python3', '-I', parent / 'tools/run-spare-lab.py', '--run-owned', parent]
        if local:
            # Keep the same ordinary UID and inherited resource limits. No sudo,
            # account creation, permission change or adoption of another tree.
            argv = ['/usr/bin/env', '--chdir=' + str(parent), 'HOME=' + str(parent / 'home'),
                    'USER=' + marker['user'], 'LOGNAME=' + marker['user'], 'TMPDIR=' + str(parent / 'tmp'),
                    'LD_LIBRARY_PATH=' + str(lab / 'lib'), 'PATH=/usr/local/bin:/usr/bin:/bin',
                    '/usr/bin/python3', '-I', parent / 'tools/run-spare-lab.py', '--run-owned', parent]
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
    parser.add_argument('--strategy', choices=('central', 'pipeline', 'helper'))
    parser.add_argument('--failures', type=int, choices=(1, 2))
    shared.add_transport_arguments(parser)
    internal = parser.add_mutually_exclusive_group()
    internal.add_argument('--handoff', type=Path, help=argparse.SUPPRESS)
    internal.add_argument('--run-owned', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--request-sha256', help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.version_info >= (3, 11), 'Python 3.11 or newer required')
    require(sys.platform == 'linux', 'Linux only; no WSL/VM launcher')
    os.umask(0o077)
    sys.dont_write_bytecode = True
    os.environ.pop('LD_PRELOAD', None)
    if args.handoff or args.run_owned:
        shared.lab_transport_selection(args, None)  # Internal ownership transitions cannot override the sealed profile.
    if args.handoff:
        request = read_json(args.handoff / 'handoff-request.json')
        shared.privileged_handoff(args.handoff, args.request_sha256,
                                  suffix=suffix(request['strategy'], request['failures']), driver_name='run-spare-lab.py')
        return 0
    if args.run_owned:
        return runtime(args.run_owned)
    require(all(getattr(args, name) is not None for name in ('source', 'build', 'fdb_bin_dir', 'core_record', 'strategy', 'failures')),
            'source/build/fdb/core and explicit strategy/failures required')
    prepare(args)
    return 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        detail = str(error)[:240] if isinstance(error, shared.GateError) else None
        print('SPARE_LAB_FAILED ' + json.dumps({'phase': STAGE, 'error_type': type(error).__name__, 'detail': detail}),
              file=sys.stderr)
        raise SystemExit(2)
