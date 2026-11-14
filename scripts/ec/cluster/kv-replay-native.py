#!/usr/bin/env python3
"""Serial, same-journal native mode4 adapter for a bounded observation replay.

No service lifecycle, PID adoption or timeout-based reclamation. Eviction
acknowledges one identity-bound namespace unlink before allocation collection.
The caller owns one trace flock, inherited by each backend-owned child.
Collector admin grandchildren instead retain the collector's object lease;
an unfinished eviction cannot advance or return its model slot before recovery.
Receipts distinguish current real joins from interrupted historical attempts.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid


def require(ok, message):
    if not ok:
        raise ValueError(message)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def name_checked(value):
    require(type(value) is str and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', value), 'Invalid fixed action name')
    return value


def exact(value, key, expected):
    require(type(value.get(key)) is type(expected) and value[key] == expected, 'Unexpected ' + key)


def spec_checked(name, spec, plan):
    name_checked(name)
    require(type(spec) is dict and spec.get('kind') in ('put', 'get', 'repair', 'evict'), 'Unknown native action')
    required = {'kind', 'instance', 'key_sha256', 'logical_bytes_decimal'}
    if spec['kind'] == 'repair':
        required |= {'strategy', 'delivery', 'window', 'targets', 'sources'}
    require(set(spec) == required, 'Native action fields differ')
    name_checked(spec['instance'])
    require(spec['kind'] != 'put' or spec['instance'] == name, 'Put must create its own immutable instance')
    require(type(spec['key_sha256']) is str and re.fullmatch('[0-9a-f]{64}', spec['key_sha256']), 'Invalid key SHA')
    raw = spec['logical_bytes_decimal']
    require(type(raw) is str and re.fullmatch('[1-9][0-9]{0,5}', raw), 'Invalid logical size')
    require(1 <= int(raw) <= 114688 and int(raw) <= 10 * plan['shard_bytes'], 'Payload is not one bounded stripe')
    if spec['kind'] == 'repair':
        repair = {key: spec[key] for key in ('strategy', 'delivery', 'window', 'targets', 'sources')}
        require(encoded(repair) == encoded(plan['repair']), 'Repair differs from the fixed replay plan')
        require(repair['strategy'] in ('central', 'pipeline', 'helper') and repair['delivery'] in ('return', 'direct')
                and (repair['strategy'] == 'helper' or repair['delivery'] == 'return'), 'Invalid delivery/strategy')
        require(type(repair['window']) is int and 1 <= repair['window'] <= 4, 'Invalid window')
        for key, counts in (('targets', (1, 2)), ('sources', (10,))):
            values = repair[key]
            require(type(values) is list and len(values) in counts and
                    all(type(x) is int and 0 <= x < 12 for x in values) and len(set(values)) == len(values),
                    'Invalid repair selection')
        require(not set(repair['targets']) & set(repair['sources']), 'Repair sources overlap targets')
    return json.loads(encoded(spec))


def snapshot_revision(value, session, cluster, shard_bytes, size, range_id, record_sha, gc):
    """One full Data stripe; projection never grants GC or covers unknown output."""
    for key, want in (('schema', 1), ('kind', 'ec_tree_read_allocations'),
                      ('scope', 'captured_read_snapshot'), ('metadata_observation_only', True),
                      ('gc_authorized', False), ('network_io_performed', False), ('cluster', cluster)):
        exact(value, key, want)
    obj = {'inode_decimal': session['inode_decimal'], 'incarnation': session['incarnation']}
    require(value['object'] == obj and value['session'] == session['session'] and
            value['birth'] == session['birth'] and value['owner']['client_namespace'] == session['client_namespace'],
            'Export changed object/session/owner')
    require(value['range'] == range_id and value['journal']['record_sha256'] == record_sha and
            value['journal']['snapshot_state'] == 'released', 'Export is not the verified released range')
    exact(value, 'shard_bytes', shard_bytes)
    require(encoded(value['selection']) == encoded({'offset_decimal': '0', 'requested_length_decimal': str(size + 1),
                                   'readable_length_decimal': str(size), 'stripe_count': 1})
            and value['root']['visible_length_decimal'] == str(size), 'Snapshot does not cover the entire object')
    require(len(value['revisions']) == len(value['slots']) == 1, 'Incomplete one-stripe snapshot')
    row = value['revisions'][0]
    require(row['stripe_decimal'] == '0' and row['logical_length_decimal'] == str(size) and
            value['slots'] == [{'kind': 'data', 'stripe_decimal': '0', 'revision_decimal': row['revision_decimal']}],
            'Snapshot is not the published Data stripe')
    gc.digest(row['content_sha256']); gc.digest(row['endpoint_set_sha256'])
    require(type(row['endpoints']) is list and len(row['endpoints']) == 12 and
            type(row['allocations']) is list and len(row['allocations']) == 12, 'Twelve endpoints/allocations required')
    projected = []
    for shard, endpoint in enumerate(row['endpoints']):
        exact(endpoint, 'shard', shard)
        for key in ('origin_operation', 'engine_uuid', 'target_incarnation'):
            gc.uid(endpoint[key])
        for key in ('node_decimal', 'chain_decimal', 'target_decimal'):
            gc.decimal(endpoint[key], True)
    for item in row['allocations']:
        exact(item, 'version', 1)
        require(item['object'] == obj['incarnation'] and item['stripe_decimal'] == '0' and
                item['generation_decimal'] == row['generation_decimal'], 'Allocation binding differs')
        projected.append(gc.identity({key: item[key] for key in ('stripe_decimal', 'generation_decimal', 'shard', 'allocation')}))
    require({x['shard'] for x in projected} == set(range(12)) and
            len({x['allocation'] for x in projected}) == 12, 'Incomplete or repeated allocation identity')
    return {key: row[key] for key in ('stripe_decimal', 'revision_decimal', 'generation_decimal')} | {
        'allocations': sorted(projected, key=lambda x: x['shard'])}


class NativeBackend:
    def __init__(self, root, run_dir, plan, lease_fd):
        require(sys.platform == 'linux' and os.getuid() == os.geteuid() != 0 and
                os.getgid() == os.getegid() != 0, 'Native replay requires ordinary Linux real/effective UID/GID')
        self.root, self.run_dir = Path(root), Path(run_dir)
        scripts = self.root / 'scripts'
        # file-command uses the shared config module by its normal import name.
        # Source-tree invocation must still select this exact prepared bundle.
        cached = sys.modules.get('native_v2_config')
        require(cached is None or Path(cached.__file__).resolve() == (scripts / 'native_v2_config.py').resolve(),
                'Another native config provider is already imported')
        sys.path.insert(0, str(scripts))
        self.w = module(scripts / 'experiment-runner.py', 'kv_native_owner')
        self.ack = module(scripts / 'ack-service-acceptance.py', 'kv_native_ack')
        self.cli = module(scripts / 'file-command.py', 'kv_native_file')
        self.gc = module(scripts / 'tree-gc-runner.py', 'kv_native_gc')
        payload_source = scripts / 'kv_trace.py'
        self.trace = module(payload_source, 'kv_native_payload')
        self.w.private_directory(self.root); self.w.private_directory(self.run_dir)
        self.lease_fd = lease_fd
        self.ack.checked_pass_fds((lease_fd,))
        require(type(plan) is dict and type(plan.get('schema')) is int and plan['schema'] == 1, 'Unknown replay plan')
        self.gc.uid(plan['trace_id'])
        require(plan.get('namespace') == '/ec-lab' and type(plan.get('shard_bytes')) is int and
                1 <= plan['shard_bytes'] <= 2**32 - 1, 'Invalid fixed namespace/geometry')
        require(type(plan.get('steps')) is list and len(plan['steps']) <= 65536 and
                all(type(step) is dict and set(step) == {'name', 'spec', 'model'} for step in plan['steps']),
                'Missing/bounded fixed native step list')
        names = [name_checked(step['name']) for step in plan['steps']]
        require(len(set(names)) == len(names), 'Repeated fixed action name')
        self.plan = json.loads(encoded(plan)); self.plan_sha = digest(plan)
        require(encoded(plan.get('collector_limits')) == encoded({'nodes': 2064, 'commands': 16384}) and
                plan.get('bounds', {}).get('max_revisions_per_instance') == 128,
                'Replay collector limits must be fixed before native I/O')
        self.manifest = self.w.load_json(self.root / 'cluster.json')
        require(self.manifest.get('file_api') is True and self.manifest.get('root') == str(self.root), 'Not a file API bundle')
        self.folder = self.directory(self.run_dir / 'native')
        self.actions = self.directory(self.folder / 'actions')
        self.active_owner = None
        self.stopped = False
        paths = [self.root / p for p in ('cluster.json', 'state/initialized.json', 'client/file-client.toml',
                 'config/admin_cli.toml', 'bin/ec_file_cli', 'bin/admin_cli')]
        paths += [scripts / p for p in ('kv-replay-native.py', 'kv_trace.py', 'file-command.py',
                  'ack-service-acceptance.py', 'experiment-runner.py', 'tree-gc-runner.py', 'native_v2_config.py')]
        self.binding = {'schema': 1, 'root': str(self.root), 'run_dir': str(self.run_dir), 'plan_sha256': self.plan_sha,
                        'files': {str(p): self.sha(p) for p in paths}}
        self.seal(self.folder / 'binding.json', self.binding)
        self.guard()

    def directory(self, path):
        exists = path.exists()
        result = self.w.private_directory(path, create=True)
        if not exists:
            self.ack.sync_parent(path)
        return result

    def sha(self, path):
        return self.ack.hash_file(self.w, Path(path))

    def load(self, path):
        return self.gc.load(Path(path))

    def seal(self, path, value):
        """Write once; visible after a failed fsync is re-confirmed, not assumed durable."""
        raw = encoded(value)
        require(len(raw) <= self.gc.MAX_JSON, 'Native evidence exceeds its fixed JSON bound')
        if path.exists():
            require(self.w.regular_bytes(path, 16 * 1024**2) == raw, 'Immutable evidence differs: ' + path.name)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            self.w.write_exclusive(path, raw)
        self.ack.sync_parent(path)
        return value

    def request_stop(self, *_):
        self.stopped = True
        if self.active_owner is not None:
            self.active_owner.request_stop()

    def guard(self):
        require(not self.stopped, 'Stopped; retain all original native runs')
        self.ack.checked_pass_fds((self.lease_fd,))
        for raw, expected in self.binding['files'].items():
            require(self.sha(raw) == expected, 'Replay source/config/binary binding changed')

    def verify_files(self, value):
        for raw, expected in value.get('files', {}).items():
            require(self.sha(raw) == expected, 'Fixed action evidence changed')

    def json_objects(self, text):
        values = []
        for line in text.splitlines():
            if line.lstrip().startswith('{'):
                value = json.loads(line, object_pairs_hook=self.w.unique_object)
                require(type(value) is dict, 'Nonobject native JSON')
                self.w.exact_numbers(value)
                values.append(value)
        require(values, 'No native business JSON')
        return values

    def records(self, run):
        found = {}
        for relative in ('record.json', 'record.data', 'pwrite/record.json'):
            path = run / relative
            if path.exists():
                found[str(path)] = self.sha(path)
        require(found, 'Started native journal is missing/partial; no new identity may replace it')
        return found

    def command(self, phase, action, run, options=(), *, collector=False, pending=False):
        self.guard()
        attempts = self.directory(phase / 'attempts')
        prior = sorted(attempts.iterdir())
        require([p.name for p in prior] == [f'{n:04d}' for n in range(len(prior))] and len(prior) < 256,
                'Attempt ledger invalid or exhausted')
        for previous in prior:
            observed = previous / 'observed.json'
            if observed.exists(): self.verify_files(self.load(observed))
        attempt = self.directory(attempts / f'{len(prior):04d}')
        if collector:
            argv = [sys.executable, '-B', str(self.root / 'scripts/tree-gc-runner.py'), action,
                    '--root', str(self.root), '--run-dir', str(run), *map(str, options)]
            config = self.root / 'config/admin_cli.toml'
        else:
            friendly = ['--root', str(self.root), action, '--run-dir', str(run), *map(str, options)]
            argv = self.cli.command(self.cli.parser().parse_args(friendly))
            config = self.root / 'client/file-client.toml'
        self.seal(attempt / 'intent.json', {'schema': 1, 'action': action, 'run': str(run), 'argv': argv,
                                           'trace_lease_inherited': True})
        owner = self.w.Runner(self.root, config=config, report=attempt / 'owner')
        self.active_owner = owner
        failure = None
        text = None
        try:
            with owner.signal_scope():
                if collector:
                    text = self.ack.collector_command(owner, self.w, argv, pass_fds=(self.lease_fd,))
                else:
                    text = self.ack.command(owner, self.w, argv, pass_fds=(self.lease_fd,))
        except BaseException as error:
            failure = error
        finally:
            self.active_owner = None
            self.stopped |= owner.stop_requested
            require(owner.child is None, 'Owned child is not joined')
            log = owner.report / 'command-000.log'
            files = {str(log): self.sha(log)} if log.exists() else {}
            if not collector:
                for relative in ('record.json', 'record.data', 'pwrite/record.json'):
                    path = run / relative
                    if path.exists(): files[str(path)] = self.sha(path)
            value = {'schema': 1, 'commands': owner.commands, 'files': files,
                     'error_class': type(failure).__name__ if failure else None}
            self.seal(attempt / 'observed.json', value)
        joined = (len(owner.commands) == 1 and owner.commands[0].get('process_started') is True and
                  owner.commands[0].get('process_exited') is True and type(owner.commands[0].get('returncode')) is int)
        require(joined and not self.stopped, 'Command is interrupted or unconfirmed')
        row = owner.commands[0]
        if failure is not None:
            if not pending or row['returncode'] != 1:
                raise failure
            text = self.w.regular_bytes(log, 2 * 1024**2).decode('utf8')
        require(row['returncode'] == 0 or pending and row['returncode'] == 1, 'Business command failed')
        self.guard()
        if collector:
            return {'returncode': row['returncode'], 'business': [], 'files': files}
        return {'returncode': row['returncode'], 'business': self.json_objects(text),
                'files': files | self.records(run)}

    def phase(self, folder, label, run, fresh, resume, options, check, *, new_run=False, pending=False):
        phase = self.directory(folder / label)
        done = phase / 'done.json'
        if done.exists():
            value = self.load(done); self.verify_files(value)
            self.seal(done, value)
            return value['value']
        intent = phase / 'intent.json'
        first = not intent.exists()
        if first and new_run:
            require(not run.exists(), 'Fresh operation path already exists')
        self.seal(intent, {'run': str(run), 'fresh': fresh, 'resume': resume, 'options': list(map(str, options))})
        attempted = (phase / 'attempts').exists() and any((phase / 'attempts').iterdir())
        if new_run and not attempted:
            require(not run.exists(), 'Unstarted native operation path unexpectedly exists')
        if attempted or not new_run:
            self.records(run)  # Native resume does the real full journal decoder/identity verification.
        result = self.command(phase, resume if attempted else fresh, run, () if attempted else options, pending=pending)
        value = check(result)
        self.seal(done, {'value': value, 'files': result['files']})
        return value

    @staticmethod
    def one(result):
        require(result['returncode'] == 0 and len(result['business']) == 1, 'Expected one successful business result')
        return result['business'][0]

    def session_check(self, result, closed=False, fixed=None):
        value = self.one(result)
        exact(value, 'error_code', 0); exact(value, 'session_state', 3 if closed else 1)
        exact(value, 'shard_bytes', self.plan['shard_bytes'])
        keys = ('client_namespace', 'session', 'operation', 'inode_decimal', 'incarnation', 'birth')
        identity = {key: value[key] for key in keys}
        self.gc.decimal(identity['inode_decimal'], True)
        for key in keys:
            if key != 'inode_decimal': self.gc.uid(identity[key], zero=key == 'operation')
        require(identity['operation'] == self.gc.ZERO, 'Session journal must not pretend to be a write operation')
        require(fixed is None or fixed == identity, 'Session identity changed')
        return identity

    def payload(self, folder, spec):
        path = folder / 'payload.bin'
        data = b''.join(self.trace.iter_payload(spec['key_sha256'], int(spec['logical_bytes_decimal'])))
        if path.exists():
            require(self.w.regular_bytes(path, 114688) == data, 'Original payload missing/changed/partial')
        else:
            self.w.write_exclusive(path, data); self.ack.sync_parent(path)
        return path, data

    def readback(self, folder, session_run, fixed, data, *, export=False):
        run = folder / 'read-run'
        phase = self.directory(folder / 'read')
        verified = phase / 'done.json'
        if verified.exists():
            proof = self.load(verified); self.verify_files(proof); self.seal(verified, proof)
            reading = proof['value']
        else:
            intent = phase / 'intent.json'
            fresh = not intent.exists()
            if fresh: require(not run.exists(), 'Fresh read path already exists')
            self.seal(intent, {'run': str(run), 'session': str(session_run), 'size': len(data),
                               'expected_sha256': hashlib.sha256(data).hexdigest()})
            previous = sorted((phase / 'attempts').iterdir()) if (phase / 'attempts').exists() else []
            if previous: self.records(run)
            else: require(not run.exists(), 'Unstarted read path unexpectedly exists')
            output = phase / f'output-{len(previous):04d}.bin'
            options = ['--output', output] if previous else ['--session', session_run, '--offset', 0,
                       '--length', len(data) + 1, '--output', output]
            result = self.command(phase, 'resume-read' if previous else 'read', run, options)
            reading = self.one(result)
            for key, want in (('error_code', 0), ('data_ready', True), ('all_cleanup_complete', False),
                              ('readable_length_decimal', str(len(data)))): exact(reading, key, want)
            self.gc.uid(reading['range'])
            require(self.w.regular_bytes(output, len(data) + 1) == data, 'Readback/EOF differs byte-for-byte')
            result['files'][str(output)] = self.sha(output)
            self.seal(verified, {'value': reading, 'files': result['files'], 'byte_equal': True, 'eof_checked': True})
        # This durable verified marker MUST precede any release. A released range
        # cannot be re-read; recovery uses this original proof and readonly export.
        def released(result):
            value = self.one(result)
            exact(value, 'error_code', 0); exact(value, 'all_cleanup_complete', True)
            require(value['range'] == reading['range'], 'Release changed original range')
            return value
        self.phase(folder, 'release', run, 'release-read', 'release-read', (), released)
        if not export: return None
        phase = self.directory(folder / 'export')
        marker = phase / 'done.json'
        if marker.exists():
            value = self.load(marker); self.verify_files(value); self.seal(marker, value)
            return value['value']
        previous = sorted((phase / 'attempts').iterdir()) if (phase / 'attempts').exists() else []
        output = phase / f'allocations-{len(previous):04d}.json'
        # The exporter has no network/IB/token or journal mutation. A new local
        # output filename recovers a failed exclusive write, not a new range ID.
        result = self.command(phase, 'export-read-allocations', run, ['--output', output])
        value = self.load(output)
        require(type(value.get('revisions')) is list and len(value['revisions']) == 1 and
                value['revisions'][0]['content_sha256'] == hashlib.sha256(data).hexdigest(),
                'Published snapshot digest differs from byte-verified payload')
        revision = snapshot_revision(value, fixed, self.manifest['cluster_id'], self.plan['shard_bytes'],
                                     len(data), reading['range'], self.sha(run / 'record.data'), self.gc)
        sequence = self.gc.decimal(value['journal']['latest_sequence_decimal'])
        state = run / f'state-{int(sequence):020d}.data'
        require(self.sha(state) == value['journal']['latest_state_sha256'], 'Export latest state differs from journal bytes')
        result['files'][str(state)] = self.sha(state)
        result['files'][str(output)] = self.sha(output)
        entry = {'path': str(output), 'sha256': self.sha(output), 'read_run': str(run), 'range': reading['range'],
                 'revision': revision, 'logical_length_decimal': str(len(data))}
        self.seal(marker, {'value': entry, 'files': result['files']})
        return entry

    def receipt(self, folder):
        value = self.load(folder / 'completion.json')
        exact(value, 'schema', 1); exact(value, 'state', 'confirmed')
        require(value['plan_sha256'] == self.plan_sha and value['name'] == folder.name and
                value['spec_sha256'] == digest(self.load(folder / 'spec.json')), 'Action completion binding changed')
        self.verify_files(value)
        self.seal(folder / 'completion.json', value)
        return value

    def history(self, instance):
        result = []
        for folder in sorted(self.actions.iterdir()):
            if (folder / 'completion.json').exists():
                value = self.receipt(folder)
                if value['instance'] == instance:
                    result.append(value)
        return result

    def repair_check(self, result, fixed, debt=False):
        value = self.one(result)
        for key, want in (('failure', None), ('revalidated', True), ('observed', True),
                          ('published', True), ('output_drained', True)): exact(value, key, want)
        if debt:
            exact(value, 'source_released', True); exact(value, 'all_cleanup_complete', True)
        for key in ('client_namespace', 'session', 'inode_decimal', 'incarnation'):
            require(value[key] == fixed[key], 'Repair changed original session/object')
        return value

    def truncate(self, folder, session_run):
        run = folder / 'truncate-run'
        phase = self.directory(folder / 'truncate')
        marker = phase / 'done.json'
        if marker.exists():
            value = self.load(marker); self.verify_files(value); self.seal(marker, value)
            return value['value']
        intent = phase / 'intent.json'
        first = not intent.exists()
        if first: require(not run.exists(), 'Fresh truncate path exists')
        self.seal(intent, {'run': str(run), 'session': str(session_run), 'length_decimal': '0'})
        until = time.monotonic() + 60  # Bounds starting continuations, never interrupts an owned CLI.
        for _ in range(64):
            previous = (phase / 'attempts').exists() and any((phase / 'attempts').iterdir())
            if previous: self.records(run)
            else: require(not run.exists(), 'Unstarted truncate path unexpectedly exists')
            require(time.monotonic() < until, 'Truncate continuation window exhausted; same-ID resume required')
            result = self.command(phase, 'resume-truncate' if previous else 'truncate', run,
                                  () if previous else ['--session', session_run, '--length', 0], pending=True)
            require(len(result['business']) == 1, 'Truncate needs exactly one progress record')
            value = result['business'][0]
            for key, want in (('length_decimal', '0'), ('observed', True), ('aborted', False), ('error_code', 0)):
                exact(value, key, want)
            self.gc.uid(value['operation'])
            identity = phase / 'operation.json'
            self.seal(identity, {'operation': value['operation']})
            require(type(value['published']) is bool and type(value['all_cleanup_complete']) is bool and
                    result['returncode'] == (0 if value['published'] else 1), 'Truncate exit/progress mismatch')
            if value['published']:
                self.seal(marker, {'value': value, 'files': result['files']})
                return value
            require(value['all_cleanup_complete'] is False, 'Pending truncate claimed cleanup')
        raise ValueError('Truncate still Planned; preserve original journal')

    def collect(self, folder, fixed, history):
        exports = [entry for receipt in history for entry in receipt['snapshot_exports']]
        require(1 <= len(exports) <= min(128, self.gc.MAX_REVISIONS), 'Missing/unbounded published revision history')
        revisions, seen, allocations = [], set(), set()
        for entry in exports:
            require(self.sha(entry['path']) == entry['sha256'], 'Captured export changed')
            row = entry['revision']; key = (row['stripe_decimal'], row['revision_decimal'])
            require(key not in seen, 'Repeated published revision; history is not independent mutations')
            seen.add(key)
            for item in row['allocations']:
                require(item['allocation'] not in allocations, 'Allocation reused across published revisions')
                allocations.add(item['allocation'])
            revisions.append(row)
        ledger = folder / 'settled-ledger.json'
        values = {'schema': 1, 'instance': fixed, 'published_actions': [
                    {'name': value['name'], 'kind': value['kind'],
                     'completion_path': str(self.actions / value['name'] / 'completion.json'),
                     'completion_sha256': self.sha(self.actions / value['name'] / 'completion.json'),
                     'snapshot_exports': value['snapshot_exports']} for value in history],
                  'truncate': self.load(folder / 'truncate/done.json'),
                  'truncate_debt': self.load(folder / 'truncate-debt/done.json'),
                  'empty_read': self.load(folder / 'empty/read/done.json'),
                  'empty_release': self.load(folder / 'empty/release/done.json'),
                  'session_close': self.load(folder / 'close/done.json'),
                  'namespace_unlink': self.load(folder / 'unlink/done.json'),
                  'scope': 'all completed mutations of this exclusive replay instance; no unknown unpublished outputs'}
        self.seal(ledger, values)
        expect = self.gc.expected({'schema': 1,
            'object': {'inode_decimal': fixed['inode_decimal'], 'incarnation': fixed['incarnation']},
            'settled_ledger': {'path': str(ledger), 'sha256': self.sha(ledger)}, 'revisions': revisions})
        expected_path = folder / 'expected.json'; self.seal(expected_path, expect)
        phase = self.directory(folder / 'collector')
        run = folder / 'collector-run'
        intent = phase / 'intent.json'
        first = not intent.exists()
        if first: require(not run.exists(), 'Fresh collector run exists')
        limits = self.plan['collector_limits']
        self.seal(intent, {'run': str(run), 'expected_sha256': self.sha(expected_path), 'limits': limits})
        attempted = (phase / 'attempts').exists() and any((phase / 'attempts').iterdir())
        if attempted:
            require((run / 'plan.json').is_file(), 'Collector started without intact plan; do not replace its identity')
        else:
            require(not run.exists(), 'Unstarted collector path unexpectedly exists')
        self.command(phase, 'resume' if attempted else 'start', run,
                     () if attempted else ['--expected', expected_path, '--max-nodes', limits['nodes'],
                                           '--max-commands', limits['commands']], collector=True)
        plan = self.load(run / 'plan.json'); self.gc.validate_plan(plan)
        require(encoded(plan['expected']) == encoded(expect) and plan['root'] == str(self.root) and
                encoded(plan['limits']) == encoded(limits), 'Collector plan differs')
        completion = self.load(run / 'completion.json')
        for key, want in (('schema', 1), ('state', 'confirmed'),
                          ('completion_scope', 'exact_expected_published_revisions_and_allocations'),
                          ('plan_sha256', self.sha(run / 'plan.json')), ('revisions_confirmed', len(revisions)),
                          ('allocations_confirmed', len(allocations)), ('current_owner_commands_joined', True),
                          ('capacity_returned', False), ('namespace_deleted', False), ('unpublished_outputs_covered', False)):
            exact(completion, key, want)
        return {'run': str(run), 'plan_sha256': self.sha(run / 'plan.json'),
                'completion_sha256': self.sha(run / 'completion.json'), 'completion': completion,
                'confirmed_allocation_model_bytes_decimal': str(len(allocations) * self.plan['shard_bytes'])}

    def perform(self, name, spec):
        self.guard()
        spec = spec_checked(name, spec, self.plan)
        folder = self.actions / name
        matches = [index for index, step in enumerate(self.plan['steps']) if step['name'] == name]
        require(len(matches) == 1 and encoded(self.plan['steps'][matches[0]]['spec']) == encoded(spec),
                'Action spec changed or is outside the fixed step list')
        for step in self.plan['steps'][:matches[0]]:
            prior = self.actions / step['name']
            require((prior / 'completion.json').exists(), 'Earlier planned native action has not completed')
            self.receipt(prior)
        if (folder / 'completion.json').exists():
            require(encoded(self.load(folder / 'spec.json')) == encoded(spec), 'Action spec changed')
            return self.receipt(folder)
        # Entry resume revalidates completed actions from the start of the plan.
        # An unfinished later action cannot block this read-only verification;
        # it still blocks dispatch of any different unfinished action.
        for existing in self.actions.iterdir():
            require(existing == folder or (existing / 'completion.json').exists(),
                    'Another action remains unconfirmed; no later event may bypass it')
        self.directory(folder); self.seal(folder / 'spec.json', spec)
        instance = spec['instance']; history = self.history(instance)
        if spec['kind'] == 'put':
            require(not history, 'Put instance already exists')
            instance_folder = folder
            session_run = folder / 'session-run'
            fixed = self.phase(folder, 'session', session_run, 'create', 'resume-open',
                ['--path', '/ec-lab/kv-' + self.plan['trace_id'] + '-' + instance,
                 '--shard-bytes', self.plan['shard_bytes'], '--rights', 'read-write'], self.session_check, new_run=True)
        else:
            puts = [value for value in history if value['kind'] == 'put']
            require(len(puts) == 1 and not any(value['kind'] == 'evict' for value in history), 'Instance missing or evicted')
            put = puts[0]
            require(put['key_sha256'] == spec['key_sha256'] and put['logical_bytes_decimal'] == spec['logical_bytes_decimal'],
                    'Action changed original instance payload')
            fixed = put['object']; instance_folder = self.actions / instance
            session_run = instance_folder / 'session-run'
        payload, data = self.payload(instance_folder, spec)
        exports, collection, namespace_unlink = [], None, None
        if spec['kind'] == 'put':
            def written(result):
                require(result['returncode'] == 0 and len(result['business']) == 2, 'Pwrite journal/outcome missing')
                show, value = result['business']
                exact(show, 'error_code', 0)
                self.gc.uid(show['operation'])
                for key in ('client_namespace', 'session'): require(show[key] == fixed[key], 'Write session changed')
                exact(show, 'offset_decimal', '0'); exact(show, 'length_decimal', str(len(data)))
                for key, want in (('observed', True), ('logical_closed', True), ('logical_complete', True),
                                  ('all_cleanup_complete', True), ('error_code', 0),
                                  ('confirmed_prefix_decimal', str(len(data))), ('revalidated_prefix_decimal', str(len(data)))):
                    exact(value, key, want)
                return {'journal': show, 'outcome': value}
            self.phase(folder, 'write', folder / 'write-run', 'pwrite', 'resume',
                       ['--session', session_run, '--offset', 0, '--input', payload], written, new_run=True)
        elif spec['kind'] == 'repair':
            require(sum(len(value['snapshot_exports']) for value in history) < min(128, self.gc.MAX_REVISIONS),
                    'Published revision capacity exhausted before starting another mutation')
            options = ['--session', session_run, '--stripe', 0, '--targets', ','.join(map(str, spec['targets'])),
                       '--sources', ','.join(map(str, spec['sources'])), '--strategy', spec['strategy'], '--window', spec['window']]
            if spec['strategy'] == 'helper': options += ['--delivery', spec['delivery']]
            run = folder / 'repair-run'
            repaired = self.phase(folder, 'repair', run, 'repair', 'resume-repair', options,
                                  lambda r: self.repair_check(r, fixed), new_run=True)
            def closed_repair(result):
                value = self.repair_check(result, fixed, debt=True)
                for key in ('operation', 'child', 'plan', 'source_pin'):
                    require(value[key] == repaired[key], 'Repair debt changed fixed identity')
                return value
            self.phase(folder, 'repair-debt', run, 'close-repair-debt', 'close-repair-debt', (), closed_repair)
        if spec['kind'] in ('put', 'get', 'repair'):
            entry = self.readback(folder, session_run, fixed, data, export=spec['kind'] != 'get')
            if entry is not None: exports.append(entry)
        else:
            truncated = self.truncate(folder, session_run)
            def closed_truncate(result):
                value = self.one(result)
                for key, want in (('error_code', 0), ('published', True), ('aborted', False),
                                  ('all_cleanup_complete', True), ('observed', True), ('length_decimal', '0'),
                                  ('operation', truncated['operation'])): exact(value, key, want)
                return value
            self.phase(folder, 'truncate-debt', folder / 'truncate-run', 'close-truncate-debt',
                       'close-truncate-debt', (), closed_truncate)
            self.readback(self.directory(folder / 'empty'), session_run, fixed, b'')
            self.phase(folder, 'close', session_run, 'close', 'close', (),
                       lambda r: self.session_check(r, closed=True, fixed=fixed))
            path = '/ec-lab/kv-' + self.plan['trace_id'] + '-' + instance
            def unlinked(result):
                value = self.one(result)
                for key, want in (('schema', 1), ('kind', 'ec_file_namespace_unlink'),
                                  ('cluster', self.manifest['cluster_id']), ('path', path),
                                  ('namespace_unlink_acknowledged', True), ('revalidated', True),
                                  ('network_io_performed', True), ('physical_capacity_returned', False),
                                  ('namespace_deleted', False), ('failure', None)):
                    exact(value, key, want)
                for key in ('client_namespace', 'inode_decimal', 'incarnation', 'birth'):
                    require(value[key] == fixed[key], 'Unlink changed original object/owner/birth')
                require(value['command'] in ('mode4-unlink', 'mode4-resume-unlink'), 'Unlink was not remotely acknowledged')
                self.gc.uid(value['request'])
                return value
            namespace_unlink = self.phase(folder, 'unlink', folder / 'unlink-run', 'unlink', 'resume-unlink',
                ['--session', session_run, '--path', path], unlinked, new_run=True)
            collection = self.collect(folder, fixed, history)
        self.guard()
        files, commands, unknown = {}, [], 0
        # Only these direct-child ledgers use our four-digit attempts and
        # observed.json. collector-run owns an independent six-digit ledger
        # with joined.json; its historical unknowns remain in GC completion.
        owned_attempts = {folder / phase / 'attempts' for phase in (
            'session', 'write', 'read', 'release', 'export', 'repair', 'repair-debt',
            'truncate', 'truncate-debt', 'close', 'unlink', 'collector', 'empty/read', 'empty/release')}
        for path in sorted(folder.rglob('*')):
            direct_attempt = path.parent.parent in owned_attempts and re.fullmatch('[0-9]{4}', path.parent.name) is not None
            collector_join = (collection is not None and path.name == 'joined.json' and
                              path.is_relative_to(Path(collection['run'])))
            if path.is_file() and (path.name in ('done.json', 'intent.json', 'observed.json', 'record.json', 'record.data',
                                               'expected.json', 'settled-ledger.json') or path.suffix in ('.bin', '.log')
                                   or collector_join):
                files[str(path)] = self.sha(path)
                if path.name == 'done.json': self.verify_files(self.load(path))
                if path.name == 'observed.json' and direct_attempt: commands.extend(self.load(path)['commands'])
            if path.name == 'intent.json' and direct_attempt:
                observed = path.parent / 'observed.json'
                rows = self.load(observed)['commands'] if observed.exists() else []
                if not (len(rows) == 1 and rows[0].get('process_started') is True and
                        rows[0].get('process_exited') is True and type(rows[0].get('returncode')) is int):
                    unknown += 1
        for entry in exports: files[entry['path']] = entry['sha256']
        if collection:
            for filename in ('plan.json', 'completion.json'):
                files[str(Path(collection['run']) / filename)] = self.sha(Path(collection['run']) / filename)
        value = {'schema': 1, 'state': 'confirmed', 'kind': spec['kind'], 'name': name, 'instance': instance,
                 'plan_sha256': self.plan_sha, 'spec_sha256': digest(spec), 'key_sha256': spec['key_sha256'],
                 'logical_bytes_decimal': spec['logical_bytes_decimal'], 'object': fixed, 'files': files,
                 'snapshot_exports': exports, 'gc': collection, 'namespace_unlink': namespace_unlink, 'owned_commands': commands,
                 'historical_unconfirmed_attempts': unknown, 'historical_join_proven': unknown == 0,
                 'current_owner_children_joined': True, 'namespace_deleted': False,
                 'physical_capacity_returned': False, 'performance_validated': False,
                 'scope': 'same-journal serial replay instance; confirmed published snapshots only'}
        self.seal(folder / 'completion.json', value)
        return self.receipt(folder)
