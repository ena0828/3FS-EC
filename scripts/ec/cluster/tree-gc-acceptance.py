#!/usr/bin/env python3
"""Two real published generations, released snapshots, then bounded explicit GC.

Uses an existing prepared file/format3 GC lab. No service lifecycle, physical
fault, capacity credit, namespace deletion or performance claim is made here.
On failure preserve the original run; collector recovery is explicit same-ID.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
from pathlib import Path
import re
import signal
import sys
import tomllib
import uuid


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def require(ok, message):
    if not ok:
        raise ValueError(message)


def uid(value):
    require(type(value) is str and uuid.UUID(value).int != 0, 'Invalid nonzero UUID')
    require(str(uuid.UUID(value)) == value, 'Noncanonical UUID')
    return value


SHARD_BYTES = 65536
READ_BYTES = 10 * SHARD_BYTES
NAMES = ('generation-a', 'generation-b')


def expected_from_exports(exports, session, cluster, ledger, ledger_sha, gc):
    """Validate this particular two-generation experiment, not arbitrary history."""
    require(type(exports) is list and len(exports) == 2, 'Need both actual snapshot exports')
    obj = {'inode_decimal': session['inode_decimal'], 'incarnation': uid(session['incarnation'])}
    revisions = []
    seen = set()
    for value in exports:
        for key, expected in (('schema', 1), ('kind', 'ec_tree_read_allocations'),
                              ('scope', 'captured_read_snapshot'), ('metadata_observation_only', True),
                              ('gc_authorized', False), ('network_io_performed', False), ('cluster', cluster)):
            require(type(value.get(key)) is type(expected) and value[key] == expected, 'Snapshot scope differs')
        require(value['object']['inode_decimal'] == obj['inode_decimal']
                and uid(value['object']['incarnation']) == obj['incarnation']
                and uid(value['session']) == uid(session['session'])
                and uid(value['birth']) == uid(session['birth'])
                and uid(value['owner']['client_namespace']) == uid(session['client_namespace']),
                'Snapshot object/session differs')
        require(value['journal']['snapshot_state'] == 'released', 'Actual read range was not released')
        require(type(value['shard_bytes']) is int and value['shard_bytes'] == SHARD_BYTES
                and value['selection']['requested_length_decimal'] == str(READ_BYTES + 1)
                and value['selection']['readable_length_decimal'] == str(READ_BYTES)
                and value['root']['visible_length_decimal'] == str(READ_BYTES),
                'Snapshot does not cover this complete published file')
        uid(value['root']['node'])
        gc.decimal(value['root']['sequence_decimal'], True)
        gc.decimal(value['root']['epoch_decimal'], True)
        gc.decimal(value['owner']['uid_decimal'], True)
        gc.decimal(value['journal']['latest_sequence_decimal'])
        gc.decimal(value['journal']['attempt_decimal'])
        gc.digest(value['journal']['record_sha256'])
        gc.digest(value['journal']['latest_state_sha256'])
        uid(value['range'])
        uid(value['request'])
        require(value['selection']['offset_decimal'] == '0'
                and type(value['selection']['stripe_count']) is int and value['selection']['stripe_count'] == 1
                and len(value['slots']) == len(value['revisions']) == 1, 'Snapshot is not the one-stripe experiment')
        row = value['revisions'][0]
        require(value['slots'][0] == {'kind': 'data', 'stripe_decimal': '0',
                                      'revision_decimal': row['revision_decimal']}
                and row['stripe_decimal'] == '0', 'Snapshot omitted the actual Data slot')
        require(row['logical_length_decimal'] == str(READ_BYTES), 'Published stripe length differs')
        gc.digest(row['content_sha256'])
        gc.digest(row['endpoint_set_sha256'])
        require(type(row['allocations']) is list and len(row['allocations']) == 12
                and type(row['endpoints']) is list and len(row['endpoints']) == 12, 'Incomplete captured endpoint set')
        for shard, endpoint in enumerate(row['endpoints']):
            require(type(endpoint['shard']) is int and endpoint['shard'] == shard, 'Endpoint shard changed')
            for key in ('origin_operation', 'engine_uuid', 'target_incarnation'):
                uid(endpoint[key])
            for key in ('node_decimal', 'chain_decimal', 'target_decimal'):
                gc.decimal(endpoint[key], True)
        items = []
        for item in row['allocations']:
            require(type(item['version']) is int and item['version'] == 1
                    and uid(item['object']) == obj['incarnation']
                    and item['generation_decimal'] == row['generation_decimal'], 'Fragment identity differs')
            identity = {key: item[key] for key in ('stripe_decimal', 'generation_decimal', 'shard', 'allocation')}
            identity['allocation'] = uid(identity['allocation'])
            require(identity['allocation'] not in seen, 'Two full overwrites must have distinct allocations')
            seen.add(identity['allocation'])
            items.append(identity)
        revisions.append({key: row[key] for key in ('stripe_decimal', 'revision_decimal', 'generation_decimal')}
                         | {'allocations': items})
    require(len({value['range'] for value in exports}) == 2
            and len({value['request'] for value in exports}) == 2, 'Read snapshots reused an acquisition identity')
    require(exports[0]['owner'] == exports[1]['owner'], 'Read owner changed')
    require(int(exports[0]['root']['sequence_decimal']) < int(exports[1]['root']['sequence_decimal']),
            'Overwrite did not advance the captured root')
    require(len({row['generation_decimal'] for row in revisions}) == 2, 'Overwrite did not produce another generation')
    return gc.expected({'schema': 1, 'object': obj, 'settled_ledger': {'path': str(ledger), 'sha256': ledger_sha},
                        'revisions': revisions})


def confirmed(value, plan_sha):
    require(value.get('state') == 'confirmed'
            and value.get('completion_scope') == 'exact_expected_published_revisions_and_allocations'
            and value.get('plan_sha256') == plan_sha, 'Collector did not confirm its original plan')
    for key, expected in (('schema', 1), ('revisions_confirmed', 2), ('allocations_confirmed', 24),
                          ('historical_unjoined_attempts', 0), ('all_started_commands_joined', True),
                          ('current_owner_commands_joined', True), ('capacity_returned', False),
                          ('namespace_deleted', False), ('unpublished_outputs_covered', False)):
        require(type(value.get(key)) is type(expected) and value[key] == expected, 'Incomplete collector receipt')
    require(type(value.get('nodes_reclaimed')) is int and value['nodes_reclaimed'] > 0, 'No actual tree node reclaimed')


@contextmanager
def signal_scope(data, local):
    """One handler marks both owners; neither scope hides the other's stop."""
    def stop(*args):
        data.request_stop(*args)
        local.request_stop(*args)
    previous = {}
    try:
        for number in (signal.SIGINT, signal.SIGTERM, *([signal.SIGHUP] if hasattr(signal, 'SIGHUP') else [])):
            previous[number] = signal.signal(number, stop)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def local_command(data, local, ack, w, argv, kind):
    require(not data.stop_requested and not local.stop_requested, 'Stopped; no new local child')
    # This owner uses admin config and has no data transport claim. The actual
    # child is still registered, waited and joined by the shared command owner.
    require(local.transport_role == 'control' and local.check_transport() is None, 'Local owner profile changed')
    return ack._owned_command(local, w, argv, None, kind=kind)


def load_exports(entries, steps, folder, gc):
    require(type(entries) is list and len(entries) == 2, 'Missing two original exports')
    result = []
    for index, (entry, name) in enumerate(zip(entries, NAMES), 1):
        output = folder / 'outputs' / (name + '-allocations.json')
        run = folder / 'runs' / f'read-{index:02d}-{name}'
        require(entry['path'] == str(output) and entry['read_run'] == str(run)
                and gc.file_sha(output) == gc.digest(entry['sha256']), 'Export path/bytes changed')
        value = gc.load(output)
        require(value['range'] == entry['range'], 'Export range differs from the released read')
        reads = [step for step in steps if step['run'] == str(run) and step['action'] == 'read']
        releases = [step for step in steps if step['run'] == str(run) and step['action'] == 'release-read']
        require(len(reads) == len(releases) == 1, 'Missing unique actual read/release pair')
        read, release = reads[0], releases[0]
        expected_sha = hashlib.sha256(hashlib.shake_256(
            ('3fs-mode4-cli-functional-v1/' + name).encode('ascii')).digest(READ_BYTES)).hexdigest()
        require(read.get('checks_complete') is True and read.get('byte_equal') is True
                and read.get('eof_checked') is True and type(read.get('bytes')) is int and read['bytes'] == READ_BYTES
                and read['expected_sha256'] == read['output_sha256'] == entry['input_sha256'] == expected_sha
                and release.get('checks_complete') is True and release.get('remote_range_released') is True,
                'Export does not follow a byte-checked complete read and release')
        require(len(read['business']) == len(release['business']) == 1
                and read['business'][0]['range'] == release['business'][0]['range'] == entry['range'],
                'Read/release identity differs')
        record = run / 'record.data'
        require(gc.file_sha(record) == value['journal']['record_sha256'] == release['journal_sha256'].get('record.data'),
                'Export does not bind the original read journal')
        sequence = int(gc.decimal(value['journal']['latest_sequence_decimal']))
        require(sequence < 4096, 'Unbounded journal sequence')
        state = run / f'state-{sequence:020}.data'
        require(gc.file_sha(state) == value['journal']['latest_state_sha256'], 'Read state changed after export')
        require(len(list(run.glob('state-*.data'))) == sequence + 1, 'Read journal advanced after export')
        require(len(value['revisions']) == 1 and value['revisions'][0]['content_sha256'] == expected_sha,
                'Export revision does not contain the bytes read back')
        result.append(value)
    return result


def validate_result(value, root, label, *, expected_executable='/usr/bin/python3'):
    """Read-only formal receipt gate; no command, cleanup or recovery is started."""
    require(type(label) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}', label), 'Invalid receipt label')
    root = Path(root)
    require(root.is_absolute() and root == root.resolve(), 'Noncanonical lab root')
    folder = root / 'client/tree-gc-acceptance' / label
    gc = module(root / 'scripts/tree-gc-runner.py', 'tree_gc_acceptance_receipt')
    require(type(value.get('schema')) is int and value['schema'] == 1
            and value.get('success') is True and value.get('failure') is None and value.get('phase') == 'tree-gc'
            and value.get('all_owned_children_joined') is True, 'Tree GC phase is not a joined success')
    for key in ('performance_validated', 'capacity_returned', 'namespace_deleted', 'unpublished_outputs_covered'):
        require(value.get(key) is False, 'Unsupported acceptance claim')
    require(value['collector'] == str(folder / 'collector') and value['python_executable'] == expected_executable,
            'Collector location/interpreter changed')
    ledger = folder / 'report/settled-ledger.json'
    settled = gc.load(ledger)
    require(type(settled['schema']) is int and settled['schema'] == 1 and settled['logical_length_decimal'] == '0'
            and settled['steps'] == value['steps'] and settled['exports'] == value['exports'], 'Settled ledger differs')
    steps, commands = value['steps'], value['commands']
    require(type(steps) is list and steps and type(commands) is list and len(commands) == len(steps),
            'Missing actual operation/command ledger')
    for index, (step, command) in enumerate(zip(steps, commands)):
        require(step['index'] == command['index'] == index and step.get('checks_complete') is True
                and step['process'] == command and step['argv'] == command['argv']
                and command.get('process_started') is True and command.get('process_exited') is True,
                'Incomplete owned operation')
        code = command.get('returncode')
        require(type(code) is int and (code == 0 or (code == 1 and step.get('accepted_pending') is True
                and step['action'] in ('truncate', 'resume-truncate')
                and step['business'][0].get('published') is False)), 'Unconfirmed command in settled ledger')
        require(gc.file_sha(folder / 'report' / f'command-{index:03d}.log') == step['log_sha256'],
                'Original data command output changed')
    actions = [step['action'] for step in steps]
    require(actions[:8] == ['create', 'resume-open', 'pwrite', 'read', 'release-read', 'pwrite', 'read', 'release-read']
            and actions[8:9] == ['truncate']
            and actions[-5:] == ['close-truncate-debt', 'read', 'release-read', 'close', 'close'],
            'Actual two-generation workflow order differs')
    require(steps[-4].get('byte_equal') is True and steps[-4].get('eof_checked') is True
            and type(steps[-4].get('bytes')) is int and steps[-4]['bytes'] == 0
            and steps[-3].get('remote_range_released') is True, 'Final empty range was not verified/released')
    require(sum(step['action'] == 'pwrite' for step in steps) == 2
            and any(step.get('remote_debt_released') is True for step in steps)
            and len(steps) >= 2 and all(step['action'] == 'close' and step.get('closed') is True for step in steps[-2:]),
            'Write/truncate/session history is not settled')
    for path, digest in settled['journal_sha256'].items():
        require(gc.file_sha(path) == digest, 'Immutable operation journal changed')
    for step in steps:
        for path, digest in step['input_sha256'].items():
            require(gc.file_sha(path) == digest, 'Original write input changed')
    exports = load_exports(value['exports'], steps, folder, gc)
    manifest = gc.load(root / 'cluster.json')
    client_config = tomllib.loads(gc.regular(root / 'client/file-client.toml').decode('utf8'))
    owner_uid = client_config['user_info']['uid']
    require(type(owner_uid) is int and 0 < owner_uid < 2**32 - 1
            and all(item['owner']['uid_decimal'] == str(owner_uid) for item in exports), 'Original read UID differs')
    expected = expected_from_exports(exports, settled['session'], manifest['cluster_id'], ledger, gc.file_sha(ledger), gc)
    expected_path = folder / 'report/expected.json'
    require(gc.load(expected_path) == expected and gc.file_sha(expected_path) == value['expected_sha256'],
            'Expected allocation set changed')
    plan_path = folder / 'collector/plan.json'
    plan = gc.load(plan_path)
    gc.validate_plan(plan)
    require(plan['root'] == str(root) and plan['expected'] == expected and plan['binding']['cluster'] == manifest['cluster_id'],
            'Collector plan differs from the actual settled snapshots')
    completion = gc.load(folder / 'collector/completion.json')
    confirmed(completion, gc.file_sha(plan_path))
    require(value['completion'] == completion and completion['collector_id'] == plan['collector_id'],
            'Collector completion identity changed')
    local = value['local_commands']
    require(type(local) is list and len(local) == 4, 'Need exactly two exports and start/terminal-resume')
    expected_argv = []
    for entry in value['exports']:
        argv = [str(root / 'bin/ec_file_cli'), '--cfg=' + str(root / 'client/file-client.toml'),
                '--config.run_dir=' + entry['read_run'], '--config.output_file=' + entry['path']]
        if manifest.get('data_transport') is not None:
            argv.append('--config.storage_transport=rdma')
        expected_argv.append(argv + ['mode4-export-read-allocations'])
    for action in ('start', 'resume'):
        argv = [expected_executable, '-B', str(root / 'scripts/tree-gc-runner.py'), action,
                '--root', str(root), '--run-dir', str(folder / 'collector')]
        expected_argv.append(argv + (['--expected', str(expected_path)] if action == 'start' else []))
    for index, (command, argv) in enumerate(zip(local, expected_argv)):
        require(command['index'] == index and command['argv'] == argv and 'transport' not in command
                and command.get('kind') == ('local_snapshot_export' if index < 2 else 'tree_gc_collector')
                and command.get('process_started') is True and command.get('process_exited') is True
                and type(command.get('returncode')) is int and command['returncode'] == 0, 'Local command receipt differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux', 'Native acceptance requires Linux')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}', args.label), 'Invalid new label')
    scripts = args.root / 'scripts'
    w = module(scripts / 'experiment-runner.py', 'tree_gc_acceptance_runner')
    ack = module(scripts / 'ack-service-acceptance.py', 'tree_gc_acceptance_owner')
    cli = module(scripts / 'file-command.py', 'tree_gc_acceptance_wrapper')
    file = module(scripts / 'file-cli-acceptance.py', 'tree_gc_acceptance_file')
    gc = module(scripts / 'tree-gc-runner.py', 'tree_gc_acceptance_collector')
    root = w.private_directory(args.root)
    manifest = w.load_json(root / 'cluster.json')
    require(manifest.get('file_api') is True and manifest.get('gc'), 'Requires prepared file/GC lab')
    parent = w.private_directory(root / 'client/tree-gc-acceptance', create=True)
    folder = parent / args.label
    require(not folder.exists(), 'Acceptance already exists; preserve original runs and collector')
    folder.mkdir(mode=0o700)
    data = w.Runner(root, config=root / 'client/file-client.toml', report=folder / 'report')
    local = w.Runner(root, config=root / 'config/admin_cli.toml', report=folder / 'local-owner')
    a = file.Acceptance(w, ack, cli, data, folder, args.label, 'tree-gc')
    success, failure, completion = False, None, None
    export_files, expected_sha = [], None
    collector = folder / 'collector'
    try:
        # Both scopes observe a stop; a started child still belongs to its owner.
        with signal_scope(data, local):
            locks = [Path(__file__).resolve(), root / 'bin/ec_file_cli', root / 'client/file-client.toml',
                     root / 'cluster.json', *[scripts / name for name in
                     ('experiment-runner.py', 'ack-service-acceptance.py', 'file-command.py',
                      'file-cli-acceptance.py', 'tree-gc-runner.py')]]
            a.locks = {str(path): a.hash(path) for path in locks}
            a.binary_identity = a.file_identity(a.binary)
            a.save('plan.json', {'schema': 1, 'source_sha256': a.locks, 'phase': 'tree-gc',
                                'scope': 'two successful full-stripe overwrites only', 'performance_validated': False})
            session, fixed = a.session('tree-gc', SHARD_BYTES)
            exports, export_files = [], []
            for name in NAMES:
                path, payload = a.input(name, READ_BYTES)
                a.write(name, session, 0, path, payload)
                a.readback(session, payload, name)
                read_run = Path(a.steps[-1]['run'])
                require(a.steps[-1].get('remote_range_released') is True, 'Read range remains held')
                output = a.outputs / (name + '-allocations.json')
                argv = cli.command(cli.parser().parse_args(['--root', str(root), 'export-read-allocations',
                                                            '--run-dir', str(read_run), '--output', str(output)]))
                # This native command only reads a locked local journal. It has
                # no data transport receipt and does not create a transport binding.
                local_command(data, local, ack, w, argv, 'local_snapshot_export')
                exports.append(w.load_json(output))
                export_files.append({'path': str(output), 'sha256': a.hash(output), 'read_run': str(read_run),
                                     'range': a.steps[-1]['business'][0]['range'],
                                     'input_sha256': hashlib.sha256(payload).hexdigest()})
            a.truncate('remove-visible-data', session, 0)
            a.readback(session, b'', 'empty-file')
            a.close(session, fixed)
            a.guard()
            require(all(step.get('checks_complete') is True for step in a.steps), 'Unsettled operation step')
            ledger = data.report / 'settled-ledger.json'
            a.save(ledger.name, {'schema': 1, 'session': fixed, 'steps': a.steps, 'journal_sha256': a.records,
                                 'exports': export_files, 'logical_length_decimal': '0',
                                 'scope': 'actual successful operation history of this private acceptance file'})
            exports = load_exports(export_files, a.steps, folder, gc)
            expectation = expected_from_exports(exports, fixed, manifest['cluster_id'], ledger, a.hash(ledger), gc)
            expected_path = data.report / 'expected.json'
            a.save(expected_path.name, expectation)
            expected_sha = a.hash(expected_path)
            for action in ('start', 'resume'):
                argv = [sys.executable, '-B', str(scripts / 'tree-gc-runner.py'), action,
                        '--root', str(root), '--run-dir', str(collector)]
                if action == 'start':
                    argv += ['--expected', str(expected_path)]
                local_command(data, local, ack, w, argv, 'tree_gc_collector')
                value = w.load_json(collector / 'completion.json')
                confirmed(value, a.hash(collector / 'plan.json'))
                require(completion is None or completion == value, 'Explicit terminal resume changed completion')
                completion = value
            a.guard()
            require(a.hash(a.binary) == a.locks[str(a.binary)], 'Native file binary changed')
            success = True
    except BaseException as error:
        failure = type(error).__name__
        print('Tree GC acceptance stopped; preserve original runs and collector', file=sys.stderr)
    finally:
        require(data.child is None and local.child is None, 'Owned child not joined')
        result = {'schema': 1, 'success': success, 'failure': failure, 'phase': 'tree-gc',
                              'commands': data.commands, 'local_commands': local.commands, 'steps': a.steps,
                              'collector': str(collector), 'completion': completion,
                              'all_owned_children_joined': all(not c.get('process_started') or c.get('process_exited')
                                                              for c in data.commands + local.commands),
                              'performance_validated': False, 'capacity_returned': False,
                              'namespace_deleted': False, 'unpublished_outputs_covered': False,
                              'exports': export_files, 'expected_sha256': expected_sha,
                              'python_executable': sys.executable}
        if success:
            try:
                validate_result(result, root, args.label, expected_executable=sys.executable)
            except BaseException as error:
                success = False
                result.update(success=False, failure=type(error).__name__)
        a.save('result.json', result)
    print(str(data.report / 'result.json'))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
