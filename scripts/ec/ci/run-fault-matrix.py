#!/usr/bin/env python3
"""Run six fresh process-fault cases serially through the existing single-case owner.

Linux ordinary same-user mode; no sudo, service signals, retries or cleanup GC.
Retain all private per-case evidence. A workflow/host deadline is not a clean join.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

spec = importlib.util.spec_from_file_location('matrix_spare_lab', Path(__file__).with_name('run-spare-lab.py'))
spare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spare)
shared = spare.shared
require, read_json, sha = shared.require, shared.read_json, shared.sha
CASES = tuple((strategy, failures) for strategy in ('central', 'pipeline', 'helper') for failures in (1, 2))


def case_name(strategy, failures):
    spare.suffix(strategy, failures)
    return strategy + '-' + str(failures)


def command(source, build, fdb, core, parent, strategy, failures, transport=None):
    return [sys.executable, '-B', source / 'scripts/ec/ci/run-spare-lab.py',
            '--source', source, '--build', build, '--fdb-bin-dir', fdb, '--core-record', core,
            '--local-work', parent, '--strategy', strategy, '--failures', str(failures),
            *shared.transport_cli_args(transport)]


def fixed_prefix(rows):
    require(type(rows) is list and len(rows) <= len(CASES), 'invalid matrix result list')
    for row, (strategy, failures) in zip(rows, CASES):
        require(type(row) is dict and row.get('strategy') == strategy
                and type(row.get('failures')) is int and row['failures'] == failures,
                'matrix cases must be a unique fixed-order prefix')


def complete_gate(rows, transport=None):
    fixed_prefix(rows)
    require(len(rows) == len(CASES), 'six actual cases required')
    for row in rows:
        require(shared.request_transport(row) == transport, 'case transport differs from the fixed matrix selection')
        require(row.get('status') == 'passed' and type(row.get('returncode')) is int and row['returncode'] == 0
                and row.get('complete_receipts_verified') is True
                and row.get('all_owned_processes_exited') is True,
                'failed, missing or unjoined case cannot pass the matrix')
    identity_gate(rows)


def identity_gate(rows):
    for field in ('parent', 'cluster_id', 'client_namespace', 'authority', 'supervisor_run'):
        values = [row.get(field) for row in rows]
        require(all(type(value) is str and value for value in values) and len(set(values)) == len(rows),
                'matrix reused a case identity')
    for field in ('engine_uuids', 'target_incarnations'):
        groups = [row.get(field) for row in rows]
        require(all(type(group) is list and len(group) == 14 for group in groups), 'missing fresh instance identities')
        values = [value for group in groups for value in group]
        require(all(type(value) is str and str(spare.uuid.UUID(value)) == value and spare.uuid.UUID(value).int
                    for value in values) and len(set(values)) == 14 * len(rows), 'matrix reused a persistent instance')
    actions = [action for row in rows for action in row.get('action_ids', [])]
    require(len(actions) == 3 * len(rows) and len(set(actions)) == len(actions), 'matrix reused an action ID')


def input_snapshot(source, build, fdb, core_path, transport=None):
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    subprocess.run(['git', '-C', str(source), 'diff', '--exit-code', 'HEAD', '--ignore-submodules=all'],
                   stdout=subprocess.DEVNULL, check=True)
    core = shared.core_gate(source, build, fdb, core_path)
    provenance = build.parent / 'provenance'
    built, native = read_json(provenance / 'lab-build.json'), read_json(provenance / 'native-build.json')
    spare.build_gate(built, native, source, build, revision)
    require(built['build_script_sha256'] == sha(source / 'scripts/ec/ci/build-native.sh')
            and built['cmake_cache_sha256'] == sha(build / 'CMakeCache.txt')
            and built['native_build_receipt_sha256'] == sha(provenance / 'native-build.json'),
            'build source or configuration changed')
    require(all(built['binaries'][name] == sha(build / 'bin' / name) for name in shared.TARGETS),
            'build binary changed')
    drivers = ('scripts/ec/ci/run-fault-matrix.py', 'scripts/ec/ci/run-spare-lab.py',
               'scripts/ec/ci/run-file-lab.py', 'scripts/ec/cluster/fuse-read-acceptance.py')
    return {'revision': revision, 'source': str(source), 'build': str(build), 'fdb': str(fdb),
            'backend': built['backend'], 'core': core, 'binaries': built['binaries'],
            'lab_build_sha256': sha(provenance / 'lab-build.json'),
            'native_build_sha256': sha(provenance / 'native-build.json'),
            'drivers': {path: sha(source / path) for path in drivers}, **shared.transport_fields(transport)}


def verify_transport_doctor(parent, lab, report, transport):
    """Bind admission to the actual owned command output; not a data-transfer claim."""
    if transport is None:
        require('transport_doctor' not in report, 'TCP matrix has an unexpected RDMA doctor receipt')
        return
    value = report.get('transport_doctor')
    require(type(value) is dict and set(value) == {'sequence', 'path', 'sha256', 'observation'}
            and type(value['sequence']) is int and value['sequence'] == 1,
            'missing first owned RDMA doctor observation')
    path = parent / 'runtime/001-doctor.stdout'
    require(value['path'] == str(path) and shared.canonical(path) == path and sha(path) == value['sha256'],
            'RDMA doctor output differs from original command')
    actual = read_json(path)
    require(json.dumps(actual, sort_keys=True, separators=(',', ':')) ==
            json.dumps(value['observation'], sort_keys=True, separators=(',', ':')),
            'RDMA doctor observation differs from original output')
    start_path = parent / 'runtime/001-doctor.started.json'
    started = read_json(start_path)
    require(started.get('argv') == ['/usr/bin/python3', '-B', str(lab / 'scripts/native-v2.py'),
                                    'doctor', '--root', str(lab)], 'RDMA doctor executable or root changed')
    commands = report.get('commands')
    require(type(commands) is list and commands and commands[0].get('started') == str(start_path)
            and commands[0].get('started_sha256') == sha(start_path), 'doctor is not bound to the command ledger')
    spare.resource_gate(actual, transport=transport)


def verify_case(parent, expected, strategy, failures, uid):
    """Re-read full private evidence; stdout is diagnostic, never a pass oracle."""
    shared.private(parent, uid)
    lab = parent / '3fs-ec-native-spare'
    request_path = parent / 'handoff-request.json'
    request = read_json(request_path)
    transport = shared.request_transport(expected)
    require(shared.request_transport(request) == transport, 'prepared case transport differs from matrix input')
    spare.local_shape(parent, request)
    marker = read_json(parent / 'handoff-complete.json')
    require(marker.get('request_sha256') == sha(request_path) and marker.get('ownership_changed') is False,
            'same-user preparation seal changed')
    for field in ('revision', 'backend', 'core', 'lab_build_sha256', 'native_build_sha256'):
        require(request.get(field) == expected[field], 'case input receipt differs from the fixed matrix input')
    require(request.get('strategy') == strategy and type(request.get('failures')) is int
            and request['failures'] == failures
            and request['driver_sha256'] == expected['drivers']['scripts/ec/ci/run-spare-lab.py']
            and request['shared_driver_sha256'] == expected['drivers']['scripts/ec/ci/run-file-lab.py'],
            'case driver or selection differs')
    report_path = parent / 'runtime/result.json'
    report = read_json(report_path)
    require(shared.request_transport(report) == transport, 'runtime transport differs from matrix input')
    require(report.get('status') == 'passed' and type(report.get('exitcode')) is int and report['exitcode'] == 0
            and report.get('business_passed') is True and report.get('cleanup_unknown', False) is False
            and not report.get('cleanup_error') and report.get('stop_method') == 'private_control'
            and report.get('execution_mode') == 'local-same-user'
            and report.get('preparation_sha256') == sha(request_path), 'case runtime did not complete normally')
    for field in ('revision', 'backend', 'core', 'lab_build_sha256', 'native_build_sha256', 'strategy', 'failures'):
        require(report.get(field) == request[field], 'runtime receipt identity differs')
    case_path = lab / 'client/spare-fault-acceptance/report/result.json'
    case = read_json(case_path)
    require(report['case_result']['path'] == str(case_path) and report['case_result']['sha256'] == sha(case_path),
            'business receipt changed')
    ready, completed = report['ready'], report['completed']
    spare.case_gate(case, ready, completed, lab, strategy, failures, uid, transport=transport)
    final = read_json(lab / 'state/last-supervisor.json')
    cleanup = read_json(lab / 'logs' / final['run'] / 'cleanup.json')
    require(final == report['final_supervisor_observation'] and cleanup == report['cleanup_observation'],
            'final supervisor receipt changed')
    joined = spare.shutdown_gate(final, cleanup, completed, lab, report['supervisor_exitcode'], transport=transport)
    require(joined == report['cleanup'], 'shutdown projection changed')
    commands = spare.command_records(parent / 'runtime', len(report['commands']))
    require(commands == report['commands'] and all(row['returncode'] == 0 for row in commands),
            'single-case commands did not all join successfully')
    verify_transport_doctor(parent, lab, report, transport)
    for control in case['controls']:
        if control.get('operation') in {'fault-storage', 'replace-placement', 'restart-storage'}:
            action = control['fixed_action']
            require(read_json(lab / 'state/fault-actions' / (action['action_id'] + '.json')) == control['observations'][-1],
                    'persisted controller action changed')
    for path, digest in case['journal_sha256'].items():
        actual = shared.canonical(Path(path))
        require(actual.is_relative_to(lab / 'client') and sha(actual) == digest, 'retained journal changed')
    manifests = list((lab / 'provenance').glob('services-*/manifest.json'))
    require(len(manifests) == 1 and sha(manifests[0]) == request['package_manifest_sha256'], 'package receipt changed')
    package = read_json(manifests[0])
    for path, value in package['files'].items():
        actual = shared.canonical(lab / path)
        require(actual.is_relative_to(lab) and sha(actual) == value['sha256'], 'packaged input changed')
        if value['kind'] == 'service':
            require(value['sha256'] == expected['binaries'][Path(path).name], 'packaged binary differs from matrix build')
    cluster = read_json(lab / 'cluster.json')
    initialized = read_json(lab / 'state/initialized.json')
    shared.validate_lab_transport(lab, request, package=package, initialized=True,
                                  observations=(ready, completed, final))
    shared.validate_command_transports(lab, transport, case['commands'], allow_control=True)
    pool = json.loads((lab / 'state/physical-pool.json').read_text(), object_pairs_hook=shared.unique)
    require(pool == initialized.get('physical_pool') and type(pool) is list and len(pool) == 14,
            'original persistent instance inventory changed')
    return {'strategy': strategy, 'failures': failures, 'status': 'passed', 'returncode': 0,
            'parent': str(parent), 'cluster_id': cluster['cluster_id'],
            'client_namespace': cluster['gc']['client_namespace'], 'authority': cluster['gc']['authority'],
            'engine_uuids': [item['engine_uuid'] for item in pool],
            'target_incarnations': [item['target_incarnation'] for item in pool], 'supervisor_run': ready['run'],
            'action_ids': [case['actions'][name]['action_id'] for name in ('fault', 'placement', 'restore')],
            'runtime_receipt': str(report_path), 'runtime_receipt_sha256': sha(report_path),
            'business_receipt': str(case_path), 'business_receipt_sha256': sha(case_path),
            'complete_receipts_verified': True, **shared.transport_fields(transport), **joined}


def execute_cases(rows, run_case, transport=None):
    """Stop at the first error; an unrun suffix is never represented as passing."""
    require(rows == [], 'matrix cannot resume or adopt previous cases')
    for strategy, failures in CASES:
        rows.append({'strategy': strategy, 'failures': failures, 'status': 'attempting', 'returncode': None})
        value = run_case(strategy, failures)
        require(shared.request_transport(value) == transport, 'case transport changed within the serial matrix')
        require(value.get('strategy') == strategy and type(value.get('failures')) is int
                and value['failures'] == failures and value.get('status') == 'passed'
                and type(value.get('returncode')) is int and value['returncode'] == 0
                and value.get('complete_receipts_verified') is True and value.get('all_owned_processes_exited') is True,
                'case completion evidence insufficient')
        identity_gate([*rows[:-1], value])
        rows[-1] = value
    complete_gate(rows, transport)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'fdb-bin-dir', 'core-record', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    shared.add_transport_arguments(parser)
    args = parser.parse_args()
    require(sys.version_info >= (3, 11), 'Python 3.11 or newer required')
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid(),
            'ordinary same-user Linux execution required')
    os.umask(0o077)
    sys.dont_write_bytecode = True
    import resource
    for limit, minimum in ((resource.RLIMIT_NOFILE, 65536), (resource.RLIMIT_MEMLOCK, 3 << 30)):
        value = resource.getrlimit(limit)[0]
        require(value == resource.RLIM_INFINITY or value >= minimum, 'inherited nofile/memlock insufficient')
    source, build, fdb, core = map(shared.canonical, (args.source, args.build, args.fdb_bin_dir, args.core_record))
    require(Path(__file__).resolve() == source / 'scripts/ec/ci/run-fault-matrix.py', 'use formal source driver')
    require(build.name == 'build' and fdb == build.parent / 'fdb/bin', 'existing build/FDB layout required')
    shared.private(args.work.parent, os.geteuid())
    require(args.work.is_absolute() and '..' not in args.work.parts and not os.path.lexists(args.work), 'fresh matrix work required')
    require(all(len(os.fsencode(args.work / 'cases' / case_name(s, n) / '3fs-ec-native-spare/state/control.sock')) < 104
                for s, n in CASES), 'matrix path exceeds Unix control socket limit; use a shorter private parent')
    inputs = input_snapshot(source, build, fdb, core)
    # Validate the source revision and clean tree before importing its transport helpers.
    transport = shared.lab_transport_selection(args, source)
    inputs.update(shared.transport_fields(transport))
    args.work.mkdir(mode=0o700)
    for name in ('cases', 'commands'):
        (args.work / name).mkdir(mode=0o700)
    shared.write_new(args.work / 'inputs.json', inputs)
    owner_module = shared.module(source / 'scripts/ec/cluster/fuse-read-acceptance.py', 'matrix_command_owner')
    owner = owner_module.Owner(args.work / 'commands')
    previous = shared.stop_signals(owner)
    report = {'schema': 1, 'status': 'running', 'exitcode': 1, 'inputs': inputs, 'cases': [],
              'expected_cases': [{'strategy': s, 'failures': n} for s, n in CASES],
              'uid': os.geteuid(), 'gid': os.getegid(), 'performance_validated': False,
              'physical_machine_failure_domains': 1, 'physical_disk_or_power_failure_tested': False,
              **shared.transport_fields(transport)}
    try:
        def run_case(strategy, failures):
            owner.checkpoint()
            require(input_snapshot(source, build, fdb, core, transport) == inputs, 'matrix inputs changed before case')
            parent = args.work / 'cases' / case_name(strategy, failures)
            owner.command(case_name(strategy, failures), command(source, build, fdb, core, parent, strategy, failures, transport))
            value = verify_case(parent, inputs, strategy, failures, os.geteuid())
            require(input_snapshot(source, build, fdb, core, transport) == inputs, 'matrix inputs changed after case')
            shared.write_new(args.work / (case_name(strategy, failures) + '.json'), value)
            return value
        execute_cases(report['cases'], run_case, transport)
        owner.checkpoint()
        report.update(status='passed', exitcode=0)
    except BaseException as error:
        report.update(status='failed_retained', error_type=type(error).__name__)
        if isinstance(error, shared.GateError):
            report['detail'] = str(error)[:240]
    finally:
        try:
            report['commands'] = spare.command_records(args.work / 'commands', owner.sequence)
            report['all_direct_commands_joined'] = True
        except Exception as error:
            report.update(status='failed_retained', exitcode=1, all_direct_commands_joined=False,
                          command_observation_error=type(error).__name__)
        for index, row in enumerate(report['cases']):
            observed = report.get('commands', [])
            row['direct_command_joined'] = index < len(observed)
            if row['status'] == 'attempting':
                row['status'] = 'failed_or_unconfirmed'
                if index < len(observed):
                    row['returncode'] = observed[index]['returncode']
        report['not_attempted_cases'] = report['expected_cases'][len(report['cases']):]
        report['passed_cases'] = sum(row.get('status') == 'passed' for row in report['cases'])
        report['all_services_confirmed_stopped'] = report['status'] == 'passed'
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        shared.write_new(args.work / 'result.json', report)
    print('FAULT_MATRIX_RESULT ' + json.dumps({key: report[key] for key in
          ('status', 'exitcode', 'passed_cases', 'all_direct_commands_joined', 'all_services_confirmed_stopped')}) +
          ' receipt_sha256=' + sha(args.work / 'result.json'), flush=True)
    return report['exitcode']


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('FAULT_MATRIX_PREFLIGHT_FAILED ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
