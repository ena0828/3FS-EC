"""Explicit owned-child faults and twelve-of-fourteen placement maintenance.

No startup, process discovery, or signalling occurs at import. All mutation is
executed by the foreground supervisor main thread, never the socket thread.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import threading
import time
import tomllib
import uuid
from native_v2_config import (
    SPARE_GC_PROFILE, gc_inventory_from_observations, gc_settings, json_text,
    pool_from_observations, replace_private, storage_specs, to_toml, write_new,
)


def canonical_id(text):
    if not isinstance(text, str) or str(uuid.UUID(text)) != text or (not uuid.UUID(text).int):
        raise ValueError('Require nonzero canonical action UUID')
    return text


def initial_placement(manifest, inventory):
    if manifest['profile'] != SPARE_GC_PROFILE:
        return inventory
    expected = manifest['initial_placement_nodes']
    by_node = {row['node']: row for row in inventory}
    return [by_node[node] for node in expected]


def validate_placement(manifest, inventory, placement):
    if (not isinstance(placement, list) or len(placement) != 12 or
            any((not isinstance(row, dict) or type(row.get('node')) is not int for row in placement)) or
            len({row['node'] for row in placement}) != 12):
        raise ValueError('Placement must contain exactly twelve distinct discovered nodes')
    known = {row['node']: row for row in inventory}
    if any((row != known.get(row['node']) for row in placement)):
        raise ValueError('Placement cannot alter a persistent target identity')
    return placement


def replacement_placement(manifest, inventory, current, replacements, failed_nodes):
    validate_placement(manifest, inventory, current)
    if not isinstance(replacements, list) or not 1 <= len(replacements) <= 2:
        raise ValueError('Require one or two explicit old:new node mappings')
    if any((not isinstance(pair, list) or len(pair) != 2 or any((type(v) is not int for v in pair)) for pair in replacements)):
        raise ValueError('Replacement node IDs must be exact integers')
    old = [v[0] for v in replacements]
    new = [v[1] for v in replacements]
    selected = {row['node'] for row in current}
    known = {row['node']: row for row in inventory}
    if len(set(old)) != len(old) or len(set(new)) != len(new) or any((n not in selected or n not in failed_nodes for n in old)):
        raise ValueError('Only an explicitly faulted current placement node may be replaced')
    if any((n not in manifest['spare_nodes'] or n in selected for n in new)):
        raise ValueError('Replacement must be a distinct unused prepared spare')
    mapping = dict(replacements)
    return validate_placement(manifest, inventory, [known[mapping.get(row['node'], row['node'])] for row in current])


class FaultController:

    def __init__(self, cluster):
        self.cluster = cluster
        self.enabled = cluster.manifest['profile'] == SPARE_GC_PROFILE
        self.lock = threading.Lock()
        self.pending = None
        self.running = None
        # exact Popen object identity, never a PID-file lookup
        self.expected = {}
        self.faulted = {}
        self.failed = False
        self.folder = cluster.root / 'state/fault-actions'
        if self.enabled:
            if not self.folder.exists():
                self.folder.mkdir(mode=0o700)
                fd = os.open(self.folder.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            info = self.folder.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError('Invalid private fault action directory')

    def snapshot(self):
        with self.lock:
            return {
                'enabled': self.enabled,
                'pending': self.pending,
                'running': self.running,
                'failed': self.failed,
                'faulted_storage_nodes': sorted(self.faulted),
                'expected_exits': [dict(value, exit_code=proc.poll()) for proc, value in self.expected.values()],
            }

    def healthy(self):
        with self.lock:
            for name, proc in self.cluster.processes:
                if proc.poll() is not None and id(proc) not in self.expected:
                    raise RuntimeError(f'{name} exited unexpectedly with {proc.returncode}; no process is adopted')

    def _path(self, action_id):
        return self.folder / (canonical_id(action_id) + '.json')

    def _validate_request(self, request):
        """Validate stored mutation intent without requiring its run to be current."""
        if not isinstance(request, dict):
            raise ValueError('Action must be an object')
        canonical_id(request.get('action_id'))
        operation = request.get('operation')
        if not isinstance(operation, str) or operation not in {'fault-storage', 'restart-storage', 'replace-placement'}:
            raise ValueError('Invalid fault operation')
        if not isinstance(request.get('run'), str) or not request['run'] or len(request['run']) > 128:
            raise ValueError('Invalid supervisor run identity')
        key = 'replacements' if operation == 'replace-placement' else 'nodes'
        if set(request) != {'operation', 'run', 'action_id', key}:
            raise ValueError('Invalid fault operation fields')
        if key == 'nodes':
            nodes = request[key]
            known = {row['node'] for row in storage_specs(self.cluster.manifest)}
            if (not isinstance(nodes, list) or not 1 <= len(nodes) <= 2 or
                    any((type(n) is not int or n not in known for n in nodes)) or len(set(nodes)) != len(nodes)):
                raise ValueError('Require one/two distinct prepared Storage node integers')
        else:
            value = request[key]
            if (not isinstance(value, list) or not 1 <= len(value) <= 2 or
                    any((not isinstance(p, list) or len(p) != 2 or
                         any((type(v) is not int for v in p)) for p in value))):
                raise ValueError('Require one/two exact old:new integer pairs')

    def _read(self, action_id):
        path = self._path(action_id)
        try:
            info = path.lstat()
        except FileNotFoundError:
            # Only absence, never JSON null/empty/corrupt.
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError('Invalid private action record')
        record = json.loads(path.read_text(encoding='utf-8'))
        if (not isinstance(record, dict) or type(record.get('schema')) is not int or record['schema'] != 1 or
                not isinstance(record.get('state'), str) or
                record['state'] not in {'queued', 'running', 'completed', 'failed'} or
                not isinstance(record.get('steps'), list) or
                any((not isinstance(s, dict) for s in record['steps'])) or
                record.get('scope') != 'owned_process_only_not_physical_host'):
            raise ValueError('Invalid retained action record body; it will not be replaced')
        self._validate_request(record.get('request'))
        if record['request']['action_id'] != action_id:
            raise ValueError('Retained action record identity differs from its filename')
        if record['state'] == 'completed' and record.get('cleanup_or_T2_claimed') is not False:
            raise ValueError('Invalid retained completion scope')
        if record['state'] == 'failed':
            error = record.get('error')
            if not isinstance(error, dict) or not isinstance(error.get('type'), str) or (not isinstance(error.get('message'), str)):
                raise ValueError('Invalid retained failure observation')
        return record

    def _save(self, record):
        path = self._path(record['request']['action_id'])
        if path.exists():
            replace_private(path, json_text(record))
        else:
            write_new(path, json_text(record))
            fd = os.open(self.folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def submit(self, request):
        if not self.enabled:
            raise ValueError('Fault actions require the explicit gc-14 profile')
        if not isinstance(request, dict):
            raise ValueError('Action must be an object')
        action_id = canonical_id(request.get('action_id'))
        operation = request.get('operation')
        if not isinstance(operation, str):
            raise ValueError('Action operation must be a string')
        if not isinstance(request.get('run'), str) or not request['run'] or len(request['run']) > 128:
            raise ValueError('Invalid supervisor run identity')
        if operation == 'action-status':
            if set(request) != {'operation', 'run', 'action_id'}:
                raise ValueError('Invalid status request')
            with self.lock:
                old = self._read(action_id)
                if old is None:
                    return {'state': 'not_observed', 'action_id': action_id, 'not_execution_proof': True}
                if old['request']['run'] != request['run']:
                    raise ValueError('Action belongs to a different supervisor run')
                return old
        self._validate_request(request)
        if request['run'] != self.cluster.run_id:
            raise ValueError('Supervisor run mismatch; stale requests never execute')
        with self.lock:
            old = self._read(action_id)
            if old is not None:
                if old['request'] != request:
                    raise ValueError('Action UUID payload conflict')
                return old
            if self.cluster.stage != 'ready' or self.cluster.halt.is_set() or self.failed or self.pending or self.running:
                raise ValueError('Supervisor must be ready with no pending/failed maintenance')
            record = {'schema': 1, 'request': request, 'state': 'queued', 'scope': 'owned_process_only_not_physical_host', 'steps': []}
            self._save(record)
            self.pending = request
            return record

    def _owned(self, name):
        matches = [proc for child, proc in self.cluster.processes if child == name and proc.poll() is None]
        if len(matches) != 1:
            raise RuntimeError(f'Expected exactly one currently owned live {name}')
        return matches[0]

    def _exit(self, name, *, fault):
        proc = self._owned(name)
        with self.lock:
            if fault:
                proc.kill()
            else:
                proc.terminate()
            self.expected[id(proc)] = (proc, {
                'name': name, 'pid': proc.pid,
                'reason': 'explicit_SIGKILL_fault' if fault else 'placement_meta_restart',
            })
        code = proc.wait(timeout=45)
        if code != (-9 if fault else 0):
            raise RuntimeError(f"Owned {name} pid={proc.pid} exited {code}; expected {('SIGKILL/-9' if fault else 'graceful Meta exit 0')}")
        return {'name': name, 'pid': proc.pid, 'exit_code': code, 'signal': 'SIGKILL' if fault else 'SIGTERM'}

    def _discover(self, endpoints, record):
        c = self.cluster
        observations = []
        gc_observations = []
        action = record['request']['action_id']
        for endpoint in endpoints:
            c.healthy()
            stem = f"action-{action}-{endpoint['node']}"
            # New exclusive outputs per action; no archived MAC export is reused.
            output = c.run_dir / (stem + '-instance.json')
            c.admin([
                'discover-ec-target', '--node-id', endpoint['node'], '--chain-id', endpoint['chain'],
                '--target-id', endpoint['target'], '--authority', c.manifest['authority'],
                '--control-key-file', c.root / 'secrets/control.key', '--output', output,
            ], stem + '-control.log')
            observations.append(json.loads(output.read_text(encoding='utf-8')))
            gc = gc_settings(c.manifest)
            output = c.run_dir / (stem + '-gc.json')
            c.admin([
                'discover-ec-gc-target', '--node-id', endpoint['node'], '--chain-id', endpoint['chain'],
                '--target-id', endpoint['target'], '--authority', gc['authority'], '--gc-key-id', gc['key_id'],
                '--gc-key-file', c.root / 'secrets/gc.key', '--output', output,
            ], stem + '-gc.log')
            gc_observations.append(json.loads(output.read_text(encoding='utf-8')))
        logical = [{key: row[key] for key in ('node', 'chain', 'target')} for row in endpoints]
        view = dict(c.manifest, endpoints=logical)
        actual = pool_from_observations(view, observations)
        if actual != endpoints:
            raise RuntimeError('Actual instance differs from immutable discovered inventory')
        gc_inventory_from_observations(c.manifest, actual, gc_observations, int(time.time()))
        return actual

    def execute_one(self):
        with self.lock:
            request = self.pending
            if request is None:
                return
            self.pending = None
            self.running = request
        record = self._read(request['action_id'])
        record['state'] = 'running'
        self._save(record)
        c = self.cluster
        c.stage = 'maintenance'
        try:
            if request['operation'] == 'fault-storage':
                with self.lock:
                    if len(set(self.faulted) | set(request['nodes'])) > 2:
                        raise RuntimeError('At most two simultaneous explicit Storage failures')
                for node in request['nodes']:
                    step = self._exit(f'storage-{node}', fault=True)
                    with self.lock:
                        self.faulted[node] = step
                    record['steps'].append(step)
                    self._save(record)
            elif request['operation'] == 'restart-storage':
                inventory = json.loads((c.root / 'state/physical-pool.json').read_text(encoding='utf-8'))
                for node in request['nodes']:
                    with self.lock:
                        if node not in self.faulted:
                            raise RuntimeError('Only a confirmed owned fault can be restarted')
                    if any((name == f'storage-{node}' and proc.poll() is None for name, proc in c.processes)):
                        raise RuntimeError('Old child still alive')
                    c.start_service(f'storage-{node}')
                    c.wait('restarted Storage', lambda node=node: c.node_ready(node, 'STORAGE'))
                    # Discover a full live subset via the method below; a singleton
                    # needs the same canonical validation with its fixed endpoint.
                    endpoint = next((row for row in inventory if row['node'] == node))
                    boot = self._discover_one(endpoint, record)
                    with self.lock:
                        self.faulted.pop(node)
                    record['steps'].append({'node': node, 'restarted_same_persistent_instance': True, 'observed_boot_nonce': boot})
                    self._save(record)
            else:
                inventory = json.loads((c.root / 'state/physical-pool.json').read_text(encoding='utf-8'))
                path = c.root / 'state/placement.json'
                old = json.loads(path.read_text(encoding='utf-8'))
                with self.lock:
                    failed = set(self.faulted)
                candidate = replacement_placement(c.manifest, inventory, old['pool'], request['replacements'], failed)
                for row in candidate:
                    self._owned(f"storage-{row['node']}")
                self._discover(candidate, record)
                record['steps'].append(self._exit('meta', fault=False))
                self._save(record)
                # Save the selected placement first. Resume re-generates Meta from
                # this exact subset after re-verifying the full immutable inventory.
                selected = {
                    'schema': 1, 'pool': candidate, 'action_id': request['action_id'],
                    'previous_sha256': hashlib.sha256(json_text(old).encode()).hexdigest(),
                }
                replace_private(path, json_text(selected))
                config = c.config / 'meta_main.toml'
                data = tomllib.loads(config.read_text(encoding='utf-8'))
                data['server']['meta']['ec_targets'] = candidate
                replace_private(config, to_toml(data))
                c.admin(['set-config', '-t', 'META', '-f', config, '--desc', f"spare placement {request['action_id']}"],
                        f"action-{request['action_id']}-set-meta.log")
                c.start_service('meta')
                c.wait('replacement Meta', lambda: c.node_ready(100, 'META'))
                output = c.run_dir / f"action-{request['action_id']}-effective-meta.toml"
                c.admin(['get-config', '-n', '100', '-o', output], f"action-{request['action_id']}-get-meta.log")
                effective = tomllib.loads(output.read_text(encoding='utf-8'))
                if effective['server']['meta']['ec_targets'] != candidate:
                    raise RuntimeError('Actual Meta config did not adopt exact placement')
                record['steps'].append({
                    'placement': candidate,
                    'actual_meta_config_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                    'old_allocations_changed': False,
                })
            record['state'] = 'completed'
            record['cleanup_or_T2_claimed'] = False
            self._save(record)
            c.stage = 'ready'
        except BaseException as error:
            record['state'] = 'failed'
            record['error'] = {'type': type(error).__name__, 'message': str(error)}
            with self.lock:
                self.failed = True
            c.stage = 'maintenance_failed'
            self._save(record)
        finally:
            with self.lock:
                self.running = None

    def _discover_one(self, endpoint, record):
        # The public validator expects a complete pool, so verify one by
        # retaining the exact request's logical identity then compare all actual
        # fields. This does not invent extra observations or call pool validation.
        c = self.cluster
        node = endpoint['node']
        stem = f"action-{record['request']['action_id']}-{node}"
        output = c.run_dir / (stem + '-instance.json')
        c.admin([
            'discover-ec-target', '--node-id', node, '--chain-id', endpoint['chain'],
            '--target-id', endpoint['target'], '--authority', c.manifest['authority'],
            '--control-key-file', c.root / 'secrets/control.key', '--output', output,
        ], stem + '-control.log')
        observed = json.loads(output.read_text(encoding='utf-8'))
        if (any((type(observed.get(k)) is not int for k in ('schema', 'protocol', 'node', 'chain', 'target'))) or
                observed.get('schema') != 1 or observed.get('protocol') != 2 or
                observed.get('authority') != c.manifest['authority'] or
                observed.get('verification') != 'control_mac_verified' or
                any((observed.get(k) != v for k, v in endpoint.items()))):
            raise RuntimeError('Restarted target changed actual persistent identity')
        gc = gc_settings(c.manifest)
        output = c.run_dir / (stem + '-gc.json')
        c.admin([
            'discover-ec-gc-target', '--node-id', node, '--chain-id', endpoint['chain'],
            '--target-id', endpoint['target'], '--authority', gc['authority'], '--gc-key-id', gc['key_id'],
            '--gc-key-file', c.root / 'secrets/gc.key', '--output', output,
        ], stem + '-gc.log')
        value = json.loads(output.read_text(encoding='utf-8'))
        now = int(time.time())
        numeric = ('schema', 'discovery_protocol', 'node', 'chain', 'target', 'data_protocol', 'disk_format',
                   'gc_protocol', 'capabilities', 'observed_at_seconds', 'verified_at_seconds')
        if (any((type(value.get(k)) is not int for k in numeric)) or
                value.get('verification') != 'gc_mac_verified' or value.get('authority') != gc['authority'] or
                value.get('key_id') != gc['key_id'] or any((value.get(k) != v for k, v in endpoint.items()))):
            raise RuntimeError('Restarted G observation did not bind the same actual instance')
        if ((value['schema'], value['discovery_protocol'], value['data_protocol'],
             value['disk_format'], value['capabilities']) != (1, 2, 2, 3, 3) or
                value['gc_protocol'] < gc['gc_protocol'] or value['gc_protocol'] not in (1, 2) or
                not 0 < value['observed_at_seconds'] <= value['verified_at_seconds'] <= now or
                now - value['observed_at_seconds'] > 60):
            raise RuntimeError('Restarted G capability is not current and usable')
        return canonical_id(value.get('boot_nonce'))
