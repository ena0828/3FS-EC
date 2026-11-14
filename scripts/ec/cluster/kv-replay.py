#!/usr/bin/env python3
"""Start/resume bounded native KV observation replay with an exclusive lease.

Runs against an already initialized private file API lab. No service startup,
mount, recursive deletion, timeout reclamation or physical capacity claim.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import uuid


HERE = Path(__file__).resolve().parent
PROVIDERS = HERE if (HERE / 'kv_trace.py').is_file() else HERE.parent / 'traces'
sys.path.insert(0, str(PROVIDERS))
import kv_trace as kv
import replay_input
import replay_model

MAX_JSON = 32 * 1024**2


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def encoded(value):
    return kv.canonical(value) + b'\n'


def digest(value):
    return kv.sha(encoded(value))


def canonical(path):
    path = Path(path)
    kv.require(path.is_absolute() and path == path.resolve(), 'Use a canonical absolute path')
    return path


def private(path):
    path = canonical(path)
    info = path.stat()
    kv.require(stat.S_ISDIR(info.st_mode), 'Not a private directory')
    if os.name == 'posix':
        kv.require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'Directory is not current-user private')
    return path


def read(path):
    path = canonical(path)
    with replay_input.regular(path) as stream:
        before = kv.fingerprint(stream)
        value = stream.read(MAX_JSON + 1)
        kv.require(len(value) <= MAX_JSON and kv.fingerprint(stream) == before, 'Oversized/changing replay record')
    return kv.parse_json(value)


def sync_parent(path):
    if os.name == 'posix':
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


def seal(path, value):
    path = canonical(path)
    raw = encoded(value)
    kv.require(len(raw) <= MAX_JSON, 'Replay record exceeds bound')
    if path.exists():
        fd = os.open(path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'r+b') as stream:
            kv.fingerprint(stream)
            kv.require(stream.read(MAX_JSON + 1) == raw, 'Immutable replay record differs: ' + path.name)
            os.fsync(stream.fileno())
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync_parent(path)
    return value


@contextmanager
def lease(run, new):
    """Close only: inherited open descriptions must retain flock after owner loss."""
    import fcntl
    private(run)
    path = run / '.lock'
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if new else 0), 0o600)
    try:
        info = os.fstat(fd)
        kv.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                   and not info.st_mode & 0o077, 'Invalid private trace lease')
        kv.require((path.stat().st_dev, path.stat().st_ino) == (info.st_dev, info.st_ino), 'Lease identity changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(fd); sync_parent(path)
        yield fd
    finally:
        os.close(fd)


def providers():
    paths = [Path(__file__).resolve(), Path(kv.__file__).resolve(), Path(replay_input.__file__).resolve(),
             Path(replay_model.__file__).resolve(), HERE / 'kv-replay-native.py']
    return {str(path): kv.sha(path.read_bytes()) for path in paths}


def derive(request):
    if request['input']['kind'] == 'synthetic':
        binding, events = replay_model.synthetic()
    else:
        kv.require(request['input']['kind'] == 'public', 'Unknown replay input mode')
        value = request['input']
        binding, events = replay_input.load(value['conversion'], value['source'], value['max_observations'])
    plan = replay_model.build(binding, events, trace_id=request['trace_id'], **request['policy'])
    plan['root'] = request['root']
    plan['providers'] = providers()
    return plan


def validate_receipt(step, plan, receipt):
    spec = step['spec']
    for key, expected in {'schema': 1, 'state': 'confirmed', 'name': step['name'], 'kind': spec['kind'],
        'instance': spec['instance'], 'key_sha256': spec['key_sha256'],
        'logical_bytes_decimal': spec['logical_bytes_decimal'], 'plan_sha256': digest(plan),
        'spec_sha256': digest(spec), 'current_owner_children_joined': True,
        'namespace_deleted': False, 'physical_capacity_returned': False, 'performance_validated': False}.items():
        kv.require(type(receipt.get(key)) is type(expected) and receipt[key] == expected, 'Native receipt differs: ' + key)
    unknown = kv.integer(receipt['historical_unconfirmed_attempts'], 'historical unknown attempts')
    kv.require(receipt['historical_join_proven'] is (unknown == 0), 'Historical join overclaim')
    kv.require(type(receipt['snapshot_exports']) is list and len(receipt['snapshot_exports']) ==
               (1 if spec['kind'] in ('put', 'repair') else 0), 'Published snapshot inventory differs')
    if spec['kind'] == 'evict':
        unlink = receipt['namespace_unlink']
        for key, expected in {'schema': 1, 'kind': 'ec_file_namespace_unlink',
                              'namespace_unlink_acknowledged': True, 'revalidated': True,
                              'network_io_performed': True, 'physical_capacity_returned': False,
                              'namespace_deleted': False, 'failure': None,
                              'path': '/ec-lab/kv-' + plan['trace_id'] + '-' + spec['instance']}.items():
            kv.require(type(unlink.get(key)) is type(expected) and unlink[key] == expected,
                       'Unconfirmed identity-bound namespace unlink: ' + key)
        for key in ('client_namespace', 'inode_decimal', 'incarnation', 'birth'):
            kv.require(unlink[key] == receipt['object'][key], 'Unlink object identity differs: ' + key)
        kv.require(type(unlink['request']) is str and str(uuid.UUID(unlink['request'])) == unlink['request'] and
                   uuid.UUID(unlink['request']).int != 0, 'Invalid fixed namespace request')
        gc = receipt['gc']
        kv.require(type(gc) is dict and gc['confirmed_allocation_model_bytes_decimal'] ==
                   step['model']['required_confirmed_gc_allocation_bytes_decimal'], 'GC does not settle model reservation')
        completion = gc['completion']
        for key, expected in {'state': 'confirmed', 'completion_scope': 'exact_expected_published_revisions_and_allocations',
                             'capacity_returned': False, 'namespace_deleted': False, 'unpublished_outputs_covered': False}.items():
            kv.require(type(completion.get(key)) is type(expected) and completion[key] == expected,
                       'Collector completion differs: ' + key)
        kv.require(type(completion['allocations_confirmed']) is int and
                   completion['allocations_confirmed'] * plan['shard_bytes'] ==
                   int(step['model']['required_confirmed_gc_allocation_bytes_decimal']), 'Allocation count differs from budget')
    else:
        kv.require(receipt['namespace_unlink'] is None, 'Unexpected unlink on live cache action')
        kv.require(receipt['gc'] is None, 'Unexpected GC on live cache action')


def execute(plan, run, backend, verify_input=None):
    """Commit model state only after actual native receipt validation.

    A previous receipt is still revalidated by backend.perform during resume.
    Failure leaves the action and its original native identity in place.
    """
    completed = run / 'confirmed'
    if not completed.exists():
        completed.mkdir(mode=0o700); sync_parent(completed)
    private(completed)
    expected = {step['name'] + '.json' for step in plan['steps']}
    kv.require(all(path.name in expected and path.is_file() for path in completed.iterdir()), 'Unexpected completed action')
    rows = []
    for index, step in enumerate(plan['steps']):
        receipt = backend.perform(step['name'], step['spec'])
        validate_receipt(step, plan, receipt)
        row = {'schema': 1, 'plan_sha256': digest(plan), 'name': step['name'], 'receipt_sha256': digest(receipt),
               'receipt_path': str(run / 'native/actions' / step['name'] / 'completion.json'),
               'model_after': step['model']['after'], 'scope': 'validated native action; logical allocation reservation only'}
        seal(completed / (step['name'] + '.json'), row)
        rows.append(row)
        print(json.dumps({'action': index + 1, 'of': len(plan['steps']), 'kind': step['spec']['kind'],
                          'name': step['name'], 'state': 'confirmed', 'model_after': row['model_after']}, sort_keys=True), flush=True)
    if verify_input is not None:
        verify_input()
    result = {'schema': 1, 'kind': 'bounded_native_kv_replay_result', 'state': 'confirmed',
              'plan_sha256': digest(plan), 'source_binding': plan['source_binding'], 'actions_confirmed': len(rows),
              'confirmed_actions_sha256': digest(rows), 'summary': plan['summary'], 'claims': plan['claims'],
              'historical_child_join_claim': 'per-action receipts; recovery does not prove historical exit',
              'scope': 'bounded serial native functional replay; not a performance or physical capacity result'}
    seal(run / 'completion.json', result)
    return result


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest='command', required=True)
    start = sub.add_parser('start', help='Validate inputs and run a new, exclusively owned replay')
    start.add_argument('--root', required=True, type=Path)
    start.add_argument('--run-dir', required=True, type=Path)
    modes = start.add_mutually_exclusive_group(required=True)
    modes.add_argument('--synthetic', action='store_true', help='Invented six-observation functional recipe')
    modes.add_argument('--conversion', type=Path, help='Directory produced by pinned kv_trace.py convert')
    start.add_argument('--source', type=Path, help='Exact raw source used for the public conversion')
    start.add_argument('--max-observations', type=int, default=32)
    start.add_argument('--slots', type=int, default=2)
    start.add_argument('--logical-budget', type=int, default=229376)
    start.add_argument('--allocation-budget', type=int, default=16777216)
    start.add_argument('--ttl-seconds', type=int, help='Inactivity TTL model; default synthetic=5, public=259200')
    start.add_argument('--shard-bytes', type=int, default=11469)
    start.add_argument('--repair-every', type=int, default=3, help='Every N selected block observations; 0 disables')
    start.add_argument('--strategy', choices=('central', 'pipeline', 'helper'), default='helper')
    start.add_argument('--delivery', choices=('return', 'direct'), help='Default helper=direct, other=return')
    start.add_argument('--window', type=int, default=1)
    start.add_argument('--targets', default='0,1', help='One or two distinct shard indices')
    for command in ('resume', 'status'):
        child = sub.add_parser(command)
        child.add_argument('--run-dir', required=True, type=Path)
    return result


def main(argv=None):
    options = parser().parse_args(argv)
    run = canonical(options.run_dir)
    if options.command == 'status':
        plan = read(run / 'plan.json')
        done = run / 'confirmed'
        names = sorted(path.stem for path in done.glob('*.json')) if done.exists() else []
        print(json.dumps({'run_dir': str(run), 'actions_planned': len(plan['steps']), 'local_receipts': len(names),
                          'completion_record_exists': (run / 'completion.json').exists(),
                          'remote_state_checked': False, 'instruction': 'resume revalidates all receipts before continuing'}, sort_keys=True))
        return
    kv.require(sys.platform == 'linux' and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0,
               'Native replay requires ordinary Linux real/effective UID/GID')
    if options.command == 'start':
        root = private(options.root)
        private(run.parent)
        kv.require(run.is_relative_to(root / 'client') and run != root / 'client',
                   'Replay run must be inside the private lab client directory')
        kv.require(not run.exists(), 'Use a new run directory; resume preserves existing identity')
        kv.require(bool(options.source) is (not options.synthetic), 'Public mode requires --source; synthetic mode rejects it')
        ttl = options.ttl_seconds if options.ttl_seconds is not None else (5 if options.synthetic else 259200)
        selection = {'kind': 'synthetic'} if options.synthetic else {'kind': 'public',
                     'conversion': str(canonical(options.conversion)), 'source': str(canonical(options.source)),
                     'max_observations': options.max_observations}
        request = {'schema': 1, 'root': str(root), 'trace_id': str(uuid.uuid4()), 'input': selection,
                   'policy': {'shard_bytes': options.shard_bytes, 'slots': options.slots,
                    'logical_budget': options.logical_budget, 'allocation_budget': options.allocation_budget,
                    'ttl_ns': ttl * 10**9, 'repair_every': options.repair_every,
                    'repair': replay_model.repair_options(options.strategy,
                         options.delivery or ('direct' if options.strategy == 'helper' else 'return'),
                         options.window, [int(x) for x in options.targets.split(',')])}}
        plan = derive(request)  # Validate entire source and policy before creating any remote identity.
        run.mkdir(mode=0o700); sync_parent(run)
    with lease(run, options.command == 'start') as fd:
        if options.command == 'resume':
            request = read(run / 'request.json')
            plan = derive(request)
            kv.require(encoded(read(run / 'plan.json')) == encoded(plan), 'Original replay plan or provenance changed')
        seal(run / 'request.json', request)
        seal(run / 'plan.json', plan)
        backend_module = module(HERE / 'kv-replay-native.py', 'kv_replay_backend')
        backend = backend_module.NativeBackend(Path(request['root']), run, plan, fd)
        old = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            for sig in old: signal.signal(sig, backend.request_stop)
            def verify_input():
                kv.require(encoded(derive(request)) == encoded(plan), 'Replay inputs changed during execution')
            result = execute(plan, run, backend, verify_input)
            print(json.dumps(result, sort_keys=True))
        finally:
            for sig, handler in old.items(): signal.signal(sig, handler)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError) as error:
        print('Replay stopped: ' + str(error) + '; preserve this run and use resume.', file=sys.stderr)
        raise SystemExit(1)
