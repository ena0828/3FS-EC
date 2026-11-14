#!/usr/bin/env python3
"""Explicit, bounded classification of one original mutation's output candidates.

This does not complete the workload, close its session, alter the replay model,
or claim physical capacity. Missing ECFE remains unknown. All child identities
come from the original native journal and authenticated Meta72 observations.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tomllib
import uuid


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


gc = module(Path(__file__).with_name('tree-gc-runner.py'), 'output_reservation_gc_util')
require, load, save, encoded = gc.require, gc.load, gc.save, gc.encoded
MAX_COMMANDS = 8192
MAX_INVENTORY = 32 * 1024 * 1024
# Existing MetaCode::kNotFound in common/utils/StatusCodeDetails.h; never
# substitute transport Unknown, auth failure or an incomplete archive.
META_NOT_FOUND = 3000
KIND = {'pwrite': 1, 'truncate-tail': 2, 'repair': 3}
CLOSE = {'pwrite': 'seal', 'repair': 'close-repair-debt', 'truncate': 'close-truncate-debt'}
QUERY = {'pwrite': 'query', 'repair': 'query-repair', 'truncate': 'query-truncate'}


def same(a, b):
    return encoded(a) == encoded(b)


def sha(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def nonzero_digest(value):
    require(int(gc.digest(value), 16) != 0, 'Missing evidence digest')
    return value


def evidence_ref(value):
    return {key: value[key] for key in ('attempt', 'archive_sha256', 'joined_sha256')}


def inventory(folder, exclude=()):
    """Bind failures and partial raw files too; their presence never proves join."""
    result = {}
    for path in sorted(folder.rglob('*')):
        relative = path.relative_to(folder).as_posix()
        if relative in exclude: continue
        if path.is_dir(): gc.private(path)
        else: result[relative] = gc.file_sha(path)
    require(len(encoded(result)) <= MAX_INVENTORY, 'Evidence inventory exceeds bound')
    return result


def export_identity(value):
    gc.fields(value, 'inode_decimal object_incarnation owner_uid owner_client parent child owner_kind')
    gc.decimal(value['inode_decimal'], True)
    for key in ('object_incarnation', 'owner_client', 'parent', 'child'):
        gc.uid(value[key])
    require(type(value['owner_uid']) is int and 0 <= value['owner_uid'] < 2**32 and
            value['owner_kind'] in KIND, 'Invalid original owner')
    return value


def dto_identity(value):
    value = export_identity(value)
    return {'object': {'inode': value['inode_decimal'], 'incarnation': value['object_incarnation']},
            'owner': {'uid': value['owner_uid'], 'client': value['owner_client']},
            'parent': value['parent'], 'child': value['child'], 'ownerKind': KIND[value['owner_kind']]}


def candidates(observation, identity):
    require(same(observation.get('identity'), dto_identity(identity)), 'Meta output identity differs')
    require(type(observation.get('version')) is int and observation['version'] == 1 and
            observation.get('physicalReclamationConfirmed') is False and
            observation.get('outputT2Confirmed') is True, 'Output is not closed metadata evidence')
    nonzero_digest(observation.get('recordDigest'))
    rows = observation.get('candidates')
    require(type(rows) is list and len(rows) == 12, 'Meta must supply all twelve original candidates')
    result, seen = [], set()
    for n, row in enumerate(rows):
        require(type(row) is dict and same(row.get('writer'), dto_identity(identity)['owner']) and
                row.get('operation') == identity['child'], 'Candidate writer/operation differs')
        f = row.get('identity')
        require(type(f) is dict and f.get('object') == identity['object_incarnation'] and
                type(f.get('shard')) is int and f['shard'] == n, 'Wrong candidate object/shard')
        gc.uid(f.get('allocation')); gc.decimal(f.get('stripe')); gc.decimal(f.get('generation'), True)
        require(f['allocation'] not in seen, 'Duplicate candidate allocation')
        seen.add(f['allocation'])
        require(f['stripe'] == observation['stripe'] and f['generation'] == observation['generation'],
                'Candidate stripe/generation differs')
        require(type(row.get('endpoint')) is dict, 'Candidate endpoint missing')
        result.append({'inode_decimal': identity['inode_decimal'], 'object_incarnation': f['object'],
                       'stripe_decimal': f['stripe'], 'generation_decimal': f['generation'],
                       'shard': n, 'allocation': f['allocation']})
    allocations = observation.get('allocations')
    if allocations is not None:
        require(type(allocations) is list and len(allocations) == 12, 'Incomplete bound allocations')
        for n, a in enumerate(allocations):
            c = rows[n]
            require(same(a.get('object'), dto_identity(identity)['object']) and same(a.get('writer'), c['writer']) and
                    same(a.get('fragment', {}).get('identity'), c['identity']) and
                    a['fragment'].get('operation') == identity['child'] and
                    same(a['fragment'].get('placement'), c['endpoint'].get('placement')) and
                    a.get('engineUuid') == c['endpoint'].get('engineUuid') and
                    a.get('targetIncarnation') == c['endpoint'].get('targetIncarnation'),
                    'Binding differs from original candidate')
    return result


def close_result(kind, rows, *, allow_incomplete=False):
    require(type(rows) is list, 'Missing business result')
    if kind == 'pwrite':
        require(len(rows) == 2, 'Expected original journal and pwrite result')
        value = rows[1]
        require(all(type(value.get(key)) is bool for key in
                    ('observed', 'logical_closed', 'logical_complete', 'all_cleanup_complete')) and
                type(value.get('error_code')) is int and value['error_code'] == 0, 'Invalid pwrite result')
        prefix = gc.decimal(value['confirmed_prefix_decimal'])
        revalidated = gc.decimal(value['revalidated_prefix_decimal'])
        complete = value['observed'] and value['logical_closed'] and value['all_cleanup_complete'] and prefix == revalidated
    elif kind == 'repair':
        require(len(rows) == 1, 'Expected one repair result')
        value = rows[0]
        require(value.get('state') in ('Missing', 'Planned', 'Published', 'Aborted') and
                all(type(value.get(key)) is bool for key in ('observed', 'published', 'output_drained',
                    'source_released', 'all_cleanup_complete', 'revalidated')) and
                value['observed'] is (value['state'] != 'Missing') and
                value['published'] is (value['state'] == 'Published') and value.get('failure') is None,
                'Invalid repair result')
        complete = value['state'] in ('Published', 'Aborted') and value['output_drained'] and \
                   value['source_released'] and value['all_cleanup_complete'] and value['revalidated']
    else:
        require(len(rows) == 1, 'Expected one truncate result')
        value = rows[0]
        require(all(type(value.get(key)) is bool for key in ('observed', 'published', 'aborted', 'all_cleanup_complete')) and
                not (value['published'] and value['aborted']) and type(value.get('error_code')) is int and
                value['error_code'] == 0, 'Invalid truncate result')
        complete = value['observed'] and (value['published'] or value['aborted']) and value['all_cleanup_complete']
    require(complete or allow_incomplete, 'Original output/source cleanup incomplete')
    if not complete: return None
    return value


def admin_archive(path, operation, *, allow_incomplete=False):
    if not path.exists():
        require(allow_incomplete, 'Successful Admin process has no archive')
        return None
    raw = gc.regular(path, 1024 * 1024)
    try: lines = raw.decode().splitlines()
    except UnicodeDecodeError:
        require(allow_incomplete, 'Unreadable successful Admin archive')
        return None
    require(len(lines) == 2 or allow_incomplete and len(lines) <= 1, 'Incomplete Admin archive')
    rows = []
    for n, line in enumerate(lines):
        try: row = gc.parse(line)
        except (ValueError, gc.CheckError):
            # A failed child can leave a torn prepared/result write. Retain its
            # exact raw digest, treat the attempt as unknown, then Query.
            require(allow_incomplete, 'Unreadable successful Admin archive')
            return None
        require(type(row) is dict and type(row.get('schema')) is int and row['schema'] == 1 and
                row.get('phase') == ('prepared' if n == 0 else 'result'), 'Wrong Admin archive phase')
        for key, value in operation['expected'].items():
            require(same(row.get(key), value), 'Admin archive changed fixed identity')
        require(type(row.get('status_code')) is int and 0 <= row['status_code'] < 2**32, 'Invalid Admin status')
        rows.append(row)
    return rows[1] if len(rows) == 2 else None


def positive(operation, result):
    action = operation['expected']['action']
    if result['status_code'] != 0:
        return False
    outcome = 'observed' if action in ('observe_file_output', 'query_file_output_resolution', 'query_absent') else 'confirmed'
    require(result.get('outcome') == outcome, 'Inconsistent successful Admin result')
    if action in ('observe_file_output', 'confirm_file_output_resolution', 'query_file_output_resolution'):
        require(result.get('uint64_encoding') == 'unsigned_decimal_strings' and
                result.get('physical_reclamation_confirmed') is False, 'Invalid metadata projection encoding')
        if action == 'observe_file_output':
            require(result.get('metadata_observation_only') is True, 'Not a metadata observation')
        else:
            require(result.get('metadata_resolution_only') is True and result.get('collected') is False,
                    'Not a candidate reservation resolution')
    elif action in ('collect', 'query'):
        nonzero_digest(result.get('claim_sha256')); nonzero_digest(result.get('ledger_sha256'))
        gc.decimal(result.get('terminal_revision_decimal'), True)
    elif action in ('confirm_absent', 'query_absent'):
        require(result.get('kind') == 'ec_fragment_absence' and type(result.get('absence_protocol')) is int and
                result['absence_protocol'] == 1 and result.get('state') == 'absent_after_close' and
                result.get('absence_record_revision_decimal') == '1' and
                result.get('candidate_reservation_release_eligible') is True and
                result.get('storage_absence_observed') is True and result.get('collected') is False and
                result.get('physical_reclamation_confirmed') is False, 'Invalid absence observation')
        for key in ('claim_sha256', 'closure_sha256', 'ledger_sha256'):
            nonzero_digest(result.get(key))
    return True


class Classifier:
    def __init__(self, folder, plan, adapter, authorize_absence=False):
        self.folder, self.plan, self.adapter = gc.private(folder), plan, adapter
        validate_plan(plan)
        require(same(load(self.folder / 'plan.json'), plan), 'In-memory plan differs from durable plan')
        self.operations, self.attempts = self.folder / 'operations', self.folder / 'attempts'
        self.history, self.records = {}, []
        self.authorize_absence = authorize_absence
        paths = sorted(self.attempts.iterdir())
        require([p.name for p in paths] == [f'{n:06d}' for n in range(len(paths))] and
                len(paths) <= plan['max_commands'], 'Invalid attempt ledger')
        for p in paths:
            intent = load(p / 'intent.json'); op = intent['operation']
            require(same(op, load(self.operations / (op['name'] + '.json'))) and
                    intent['argv'] == adapter.argv(op, p / 'archive.jsonl'), 'Attempt identity changed')
            joined = load(p / 'joined.json') if (p / 'joined.json').exists() else None
            if joined is None:
                require(adapter.lease_reacquired(), 'Unjoined child without reacquired inherited lease')
                evidence = {'historical_join_proven': False, 'scope': 'cooperative_inherited_local_lease_only',
                            'intent_sha256': gc.file_sha(p / 'intent.json'),
                            'retained_files': inventory(p, ('lease-recovered.json',))}
                self.seal(p / 'lease-recovered.json', evidence)
            else:
                self.check_join(p, intent, joined)
            self.records.append((p, op, joined))
            self.history.setdefault(op['name'], []).append((p, joined))

    @staticmethod
    def seal(path, value):
        if path.exists(): require(same(load(path), value), 'Immutable evidence changed')
        else: save(path, value)

    @staticmethod
    def check_join(path, intent, joined):
        require(joined.get('argv') == intent['argv'] and joined.get('process_started') is True and
                joined.get('process_exited') is True and type(joined.get('returncode')) is int and
                joined.get('log_sha256') == gc.file_sha(path / 'command.log'), 'No exact joined command/log')
        archive = path / 'archive.jsonl'
        require(joined.get('archive_sha256') == (gc.file_sha(archive) if archive.exists() else None),
                'Original Admin/export archive changed')

    def fixed_id(self, name):
        return str(uuid.uuid5(uuid.UUID(self.plan['id_namespace']), name))

    def operation(self, name, kind, expected=None, arguments=None):
        value = {'name': name, 'kind': kind, 'expected': expected or {}, 'arguments': arguments or []}
        self.seal(self.operations / (name + '.json'), value)
        return value

    def result(self, op, path, joined):
        if joined is None:
            return None
        require(joined['returncode'] != 0 or joined.get('owner_error_type') is None,
                'Owner failed after a successful process; preserve evidence')
        if op['kind'] == 'admin':
            result = admin_archive(path / 'archive.jsonl', op, allow_incomplete=joined['returncode'] != 0)
            if joined['returncode'] != 0:
                require(result is None or result['status_code'] != 0, 'Failed process with success archive')
                return None
            require(positive(op, result), 'Exit zero without confirmed business result')
        else:
            if joined['returncode'] != 0: return None
            rows = []
            for line in gc.regular(path / 'command.log').decode().splitlines():
                if line.lstrip().startswith('{'): rows.append(gc.parse(line))
            if op['kind'] == 'export':
                result = load(path / 'archive.jsonl')
            else:
                result = close_result(self.plan['output_kind'], rows,
                                      allow_incomplete=op['arguments'][0] == QUERY[self.plan['output_kind']])
                if result is None: return None
        return {'value': result, 'attempt': str(path), 'archive_sha256': gc.file_sha(
            path / ('archive.jsonl' if op['kind'] in ('admin', 'export') else 'command.log')),
                'joined_sha256': gc.file_sha(path / 'joined.json')}

    def prior(self, op):
        for path, joined in self.history.get(op['name'], []):
            result = self.result(op, path, joined)
            if result is not None: return result
        return None

    def require_missing_resolution_query(self, op):
        attempts = self.history.get(op['name'], [])
        require(attempts, 'Original resolution Query was not executed')
        path, joined = attempts[-1]
        require(joined is not None and joined['returncode'] != 0, 'Resolution Query remains unknown')
        result = admin_archive(path / 'archive.jsonl', op)
        require(result['status_code'] == META_NOT_FOUND and result.get('outcome') == 'not_observed',
                'Only a complete explicit Missing resolution Query permits same-ID Confirm replay')

    def perform(self, op, *, failure_ok=False):
        previous = self.prior(op)
        if previous is not None: return previous
        self.adapter.check()
        require(len(self.records) < self.plan['max_commands'], 'Command budget exhausted; keep original run')
        path = gc.private(self.attempts / f'{len(self.records):06d}', create=True)
        argv = self.adapter.argv(op, path / 'archive.jsonl')
        save(path / 'intent.json', {'operation': op, 'argv': argv})
        # An exception before joined.json remains unknown, never an empty success.
        joined = self.adapter.execute(argv, path)
        archive = path / 'archive.jsonl'
        joined['archive_sha256'] = gc.file_sha(archive) if archive.exists() else None
        save(path / 'joined.json', joined)
        self.check_join(path, load(path / 'intent.json'), joined)
        self.records.append((path, op, joined)); self.history.setdefault(op['name'], []).append((path, joined))
        result = self.result(op, path, joined)
        require(result is not None or failure_ok, 'Actual command unconfirmed; explicit recovery required')
        return result

    def admin(self, name, action, identity, **extras):
        fixed = {'action': action, 'request_id': self.fixed_id(name), **extras}
        if action in ('observe_file_output', 'confirm_file_output_resolution', 'query_file_output_resolution'):
            fixed.update(identity=dto_identity(identity), client_namespace=self.adapter.namespace)
        else:
            fixed.update(identity)
            if action.endswith('_absent'): fixed['client_namespace'] = self.adapter.namespace
        return self.operation(name, 'admin', fixed)

    def cleanup(self):
        close = self.operation('cleanup', 'close', arguments=[CLOSE[self.plan['output_kind']]])
        previous = self.prior(close)
        if previous: return previous
        if self.history.get('cleanup'):
            # Observe first; a failed/missing Query is not permission to invent a new mutation.
            query = self.operation('cleanup-query', 'close', arguments=[QUERY[self.plan['output_kind']]])
            observed = self.perform(query, failure_ok=True)
            if observed: return observed
        return self.perform(close)

    def exported(self):
        op = self.operation('export', 'export', arguments=['export-output-identities'])
        evidence = self.perform(op); value = evidence['value']
        require(type(value.get('schema')) is int and value['schema'] == 1 and
                value.get('kind') == 'ec_file_output_identities' and value.get('output_kind') == self.plan['output_kind'] and
                value.get('cluster') == self.plan['binding']['cluster'] and
                value.get('source_record_sha256') == self.plan['source_record_sha256'] and
                value.get('source_record_file') == Path(self.plan['source_record']).name and
                value.get('candidate_identities_only') is True and value.get('network_io_performed') is False and
                value.get('metadata_observation_performed') is False and value.get('remote_absence_confirmed') is False and
                value.get('physical_reclamation_confirmed') is False, 'Original journal export differs')
        rows = value.get('identities')
        require(type(rows) is list and len(rows) <= 64 and (rows or self.plan['output_kind'] == 'truncate' and
                value.get('tail_requirement') == 'not_required'), 'Missing original child identities')
        for row in rows:
            export_identity(row)
            want = 'truncate-tail' if self.plan['output_kind'] == 'truncate' else self.plan['output_kind']
            require(row['owner_kind'] == want, 'Export owner kind changed')
        require(len({sha(row) for row in rows}) == len(rows), 'Duplicate original child')
        return evidence

    def bound(self, name, candidate):
        claim = self.fixed_id(name + '-claim')
        collect = self.admin(name + '-collect', 'collect', candidate, claim_id=claim)
        absent = self.admin(name + '-absent', 'confirm_absent', candidate, claim_id=claim)
        queries = (self.admin(name + '-gc-query', 'query', candidate, claim_id=claim),
                   self.admin(name + '-absent-query', 'query_absent', candidate, claim_id=claim))
        # Either permanent fact settles the candidate; preserve the first full evidence.
        for operation, classification in ((collect, 'Collected'), (queries[0], 'Collected'),
                                           (absent, 'AbsentAfterClose'), (queries[1], 'AbsentAfterClose')):
            previous = self.prior(operation)
            if previous: return {**candidate, 'classification': classification, 'eligible': True,
                                  'claim_id': claim, 'evidence': evidence_ref(previous)}
        for query, classification in zip(queries, ('Collected', 'AbsentAfterClose')):
            found = self.perform(query, failure_ok=True)
            if found: return {**candidate, 'classification': classification, 'eligible': True,
                              'claim_id': claim, 'evidence': evidence_ref(found)}
        if self.history.get(collect['name']) or self.history.get(absent['name']):
            require(self.authorize_absence, 'Collect unconfirmed; absence confirmation requires explicit authorization')
            authorization = {'schema': 1, 'plan_sha256': gc.file_sha(self.folder / 'plan.json'),
                             'candidate': candidate, 'claim_id': claim, 'operation_sha256': sha(absent),
                             'attempt': f'{len(self.records):06d}',
                             'scope': 'explicit_new_absence_confirmation_not_inferred_from_QueryMissing'}
            self.seal(self.folder / (name + '-absence-authorization-' + authorization['attempt'] + '.json'), authorization)
            found = self.perform(absent)
            classification = 'AbsentAfterClose'
        else:
            found = self.perform(collect)
            classification = 'Collected'
        return {**candidate, 'classification': classification, 'eligible': True, 'claim_id': claim,
                'evidence': evidence_ref(found)}

    def child(self, n, identity):
        name = f'child-{n:02d}'
        op = self.admin(name + '-observe', 'observe_file_output', identity)
        observation = self.perform(op)
        value = observation['value'].get('observation')
        require(type(value) is dict, 'Missing ECFE is not a resolution')
        rows = candidates(value, identity)
        require(type(value.get('state')) is int and value['state'] in (5, 6), 'Candidate execution is not terminal')
        if value['state'] == 5:
            require(value.get('allocations') is not None, 'Published allocation binding missing')
            state = 'Published_retained'
            classified = [{**r, 'classification': state, 'eligible': False} for r in rows]
        elif value.get('allocations') is None:
            resolution = self.fixed_id(name + '-resolution')
            query = self.admin(name + '-resolution-query', 'query_file_output_resolution', identity,
                               resolution_id=resolution)
            confirm = self.admin(name + '-resolution-confirm', 'confirm_file_output_resolution', identity,
                                 resolution_id=resolution)
            result = self.prior(confirm) or self.perform(query, failure_ok=True)
            if result is None:
                # An explicit invocation may replay its originally authorized
                # Confirm, but only after a fresh, fully joined Missing Query.
                # This is not the separate new absence-confirmation authority.
                self.require_missing_resolution_query(query)
                result = self.perform(confirm)
            r = result['value'].get('resolution')
            require(type(r) is dict and same(r.get('identity'), dto_identity(identity)) and
                    r.get('resolutionId') == resolution and same(r.get('candidates'), value['candidates']) and
                    r.get('candidateReservationsReleaseEligible') is True and r.get('collected') is False and
                    r.get('physicalReclamationConfirmed') is False and
                    result['value'].get('candidate_reservations_release_eligible') is True and
                    result['value'].get('metadata_resolution_only') is True, 'Resolution differs from exact candidate set')
            gc.uid(r.get('confirmingClientNamespace'))
            seq = gc.decimal(r.get('issuanceSequence'))
            require(type(r.get('kind')) is int and r['kind'] == (1 if seq == '0' else 2), 'Resolution kind differs')
            for field in ('candidateDigest', 'executionDigest', 'outputClosureDigest', 'sourceClosureDigest'):
                nonzero_digest(r.get(field))
            state = 'NoIssuanceAfterClose' if seq == '0' else 'NeverBoundAfterClose'
            classified = [{**row, 'classification': state, 'eligible': True,
                           'resolution_id': resolution, 'evidence': evidence_ref(result)} for row in rows]
        else:
            state = 'Bound_classified'
            classified = [self.bound(f'{name}-shard-{n:02d}', row) for n, row in enumerate(rows)]
        return {'identity': identity, 'state': state, 'observation': evidence_ref(observation),
                'candidate_set_sha256': sha(value['candidates']),
                'candidate_set_sha256_encoding': 'canonical_json_not_Meta_binary_digest', 'candidates': classified}

    def run(self):
        self.adapter.check()
        cleanup = self.cleanup()
        exported = self.exported()
        children = [self.child(n, value) for n, value in enumerate(exported['value']['identities'])]
        allocations = [row for child in children for row in child['candidates']]
        require(len({row['allocation'] for row in allocations}) == len(allocations), 'Allocation repeated across children')
        result = {'schema': 1, 'kind': 'ec_output_reservation_classification', 'root': self.plan['root'],
                  'source_run': self.plan['source_run'], 'output_kind': self.plan['output_kind'],
                  'cluster': self.plan['binding']['cluster'], 'plan_sha256': gc.file_sha(self.folder / 'plan.json'),
                  'source_record_sha256': self.plan['source_record_sha256'],
                  'provider_binding_sha256': sha(self.plan['binding']), 'cleanup': cleanup, 'export': exported,
                  'children': children, 'candidate_count': len(allocations),
                  'eligible_candidate_count': sum(row['eligible'] for row in allocations),
                  'source_cleanup_confirmed': True, 'candidate_set_classified': True,
                  'business_action_completed': False, 'physical_capacity_returned': False,
                  'session_closed_by_runner': False, 'scope': 'exact_original_output_children_only',
                  'historical_join_proven': all(joined is not None for _, _, joined in self.records)}
        files = inventory(self.folder, ('completion.json', 'final-evidence.json'))
        evidence_path = self.folder / 'final-evidence.json'
        if evidence_path.exists():
            require(same(gc.parse(gc.regular(evidence_path, MAX_INVENTORY)), files), 'Sealed evidence changed')
        self.adapter.final_check()
        if not evidence_path.exists(): save(evidence_path, files)
        result['evidence_inventory'] = {'path': str(evidence_path), 'sha256': gc.file_sha(evidence_path),
                                        'files': len(files), 'includes_failed_and_unknown_attempts': True}
        self.seal(self.folder / 'completion.json', result)
        return result


def validate_plan(plan):
    require(type(plan) is dict and type(plan.get('schema')) is int and plan['schema'] == 1 and
            plan.get('kind') == 'ec_output_reservation_plan' and plan.get('output_kind') in CLOSE,
            'Unknown output reservation plan')
    gc.uid(plan.get('id_namespace')); gc.digest(plan.get('source_record_sha256'))
    for field in ('root', 'source_run', 'source_record'): gc.canonical(plan[field])
    require(type(plan.get('max_commands')) is int and 1 <= plan['max_commands'] <= MAX_COMMANDS,
            'Invalid cumulative command bound')
    require(plan.get('policy') == 'collect_first_absence_requires_explicit_resume_authorization', 'Unknown classification policy')


class NativeAdapter(gc.NativeAdapter):
    def __init__(self, root, binding, modules, lease_fd, lease_path, plan, check_owner=None):
        self.root, self.binding, self.plan = root, binding, plan
        self.check_owner = check_owner
        self.w, self.ack, self.launcher, self.cli = modules
        self.namespace = binding['client_namespace']
        self.lease_fd, self.lease_path = lease_fd, lease_path
        self.lease_stat = os.fstat(lease_fd)
        self.stopped, self.runner = False, None
        self.binary_stats = {str(p): p.stat() for p in (root / 'bin/admin_cli', root / 'bin/ec_file_cli')}

    def check(self):
        # An in-process replay owner can receive a stop between child signal
        # scopes. Consult that owner before every subsequent native dispatch.
        if self.check_owner is not None: self.check_owner()
        require(not self.stopped and self.lease_reacquired(), 'Stopped or lease identity changed')
        for path, digest in self.binding['files'].items():
            if path in self.binary_stats:
                before, after = self.binary_stats[path], gc.canonical(path).stat()
                require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Bound executable changed')
            else: require(gc.file_sha(path) == digest, 'Bound provider/config/original record changed')

    def final_check(self):
        self.check()
        for path in self.binary_stats:
            require(gc.file_sha(path) == self.binding['files'][path], 'Executable changed during classification')

    def argv(self, op, output):
        if op['kind'] != 'admin':
            args = ['--root', str(self.root), op['arguments'][0], '--run-dir', self.plan['source_run']]
            if op['kind'] == 'export': args += ['--kind', self.plan['output_kind'], '--output', str(output)]
            return self.cli.command(self.cli.parser().parse_args(args))
        f = op['expected']; action = f['action']
        names = {'observe_file_output': 'ec-observe-file-output',
                 'confirm_file_output_resolution': 'ec-confirm-file-output-resolution',
                 'query_file_output_resolution': 'ec-query-file-output-resolution',
                 'collect': 'ec-gc-collect', 'query': 'ec-gc-query',
                 'confirm_absent': 'ec-gc-confirm-absent', 'query_absent': 'ec-gc-query-absent'}
        if 'identity' in f:
            i = f['identity']
            options = {'inode': i['object']['inode'], 'object-incarnation': i['object']['incarnation'],
                       'owner-uid': i['owner']['uid'], 'owner-client': i['owner']['client'],
                       'parent': i['parent'], 'child': i['child'],
                       'owner-kind': next(k for k, v in KIND.items() if v == i['ownerKind'])}
            if 'resolution_id' in f: options['resolution-id'] = f['resolution_id']
        else:
            options = {k.removesuffix('_decimal').replace('_', '-'): f[k] for k in
                       ('inode_decimal', 'object_incarnation', 'stripe_decimal', 'generation_decimal',
                        'shard', 'allocation', 'claim_id')}
        if 'client_namespace' in f: options['client-namespace'] = f['client_namespace']
        options.update({'request-id': f['request_id'], 'output': str(output)})
        parts = [names[action]]
        for key, value in options.items(): parts += ['--' + key, str(value)]
        return [str(self.root / 'bin/admin_cli'), '--cfg', str(self.root / 'config/admin_cli.toml'), '--',
                self.launcher.admin_command_line(parts)]

    def execute(self, argv, attempt):
        config = self.root / ('config/admin_cli.toml' if argv[0] == str(self.root / 'bin/admin_cli')
                              else 'client/file-client.toml')
        self.runner = self.w.Runner(self.root, config=config, report=attempt / 'owner')
        try:
            with self.runner.signal_scope():
                return super().execute(argv, attempt)
        finally:
            self.stopped |= self.runner.stop_requested
            require(self.runner.child is None, 'Original child not joined')


def binding(root, source_record, cfg):
    manifest = load(root / 'cluster.json')
    require(manifest.get('root') == str(root) and cfg.gc_settings(manifest) and cfg.file_api_enabled(manifest),
            'Prepared mode4/format3 GC profile required')
    cfg.validate_initialized_profile(manifest, load(root / 'state/initialized.json'))
    paths = sorted([*root.glob('config/*.toml'), *root.glob('client/*.toml')])
    configs = {p.name: tomllib.loads(gc.regular(p).decode()) for p in paths}
    require(not cfg.profile_config_problems(manifest, configs), 'Prepared configuration differs')
    admin = configs['admin_cli.toml']; namespace = gc.uid(admin['client_uuid'])
    require(namespace == gc.uid(manifest['gc']['client_namespace']) and
            type(admin['user_info']['uid']) is int and admin['user_info']['uid'] == 0, 'Admin scope differs')
    paths += [root / 'cluster.json', root / 'state/initialized.json', root / 'state/gc-physical-pool.json',
              root / 'bin/admin_cli', root / 'bin/ec_file_cli', source_record, gc.canonical(__file__),
              gc.canonical(gc.__file__)]
    paths += [root / 'scripts' / name for name in ('tree-gc-runner.py', 'experiment-runner.py',
              'ack-service-acceptance.py', 'run-cluster.py', 'native_v2_config.py', 'generate.py', 'file-command.py')]
    return {'client_namespace': namespace, 'cluster': manifest['cluster_id'],
            'files': {str(gc.canonical(p)): gc.file_sha(p) for p in paths}}


def execute(args, *, check_owner=None):
    if check_owner is not None: check_owner()
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0,
            'Linux ordinary real/effective UID/GID required')
    os.umask(0o077)
    root, folder = gc.private(args.root), gc.canonical(args.run_dir)
    gc.private(folder.parent)
    require(root / 'client' in folder.parents, 'Run must be inside this lab client directory')
    sys.path.insert(0, str(root / 'scripts'))
    cfg = module(root / 'scripts/native_v2_config.py', 'output_config')
    if args.action == 'start':
        original = gc.private(args.source_run)
        require(root / 'client' in original.parents and original != folder and original not in folder.parents,
                'Original journal must be separate within this lab client directory')
        record = original / ('record.json' if args.kind == 'pwrite' else 'record.data')
    else:
        gc.private(folder); plan = load(folder / 'plan.json'); validate_plan(plan)
        require(plan['root'] == str(root), 'Resume root changed')
        original, record = Path(plan['source_run']), Path(plan['source_record'])
    bound = binding(root, record, cfg)
    registry = root / 'state' / ('output-reservation-' + hashlib.sha256(str(original).encode()).hexdigest())
    if not registry.exists(): gc.private(registry, create=True); gc.sync_dir(registry.parent)
    with gc.object_lock(gc.private(registry)) as lease:
        locator = registry / 'run.json'
        if args.action == 'start':
            require(not locator.exists() and not folder.exists(), 'Original mutation already has a classifier; resume it')
            gc.private(folder, create=True)
            plan = {'schema': 1, 'kind': 'ec_output_reservation_plan', 'root': str(root), 'source_run': str(original),
                    'source_record': str(record), 'source_record_sha256': gc.file_sha(record),
                    'output_kind': args.kind, 'id_namespace': str(uuid.uuid4()), 'binding': bound,
                    'max_commands': args.max_commands,
                    'policy': 'collect_first_absence_requires_explicit_resume_authorization'}
            validate_plan(plan); save(folder / 'plan.json', plan)
            for name in ('operations', 'attempts'): gc.private(folder / name, create=True)
            save(locator, {'run': str(folder), 'plan_sha256': gc.file_sha(folder / 'plan.json')})
        else:
            require(same(load(locator), {'run': str(folder), 'plan_sha256': gc.file_sha(folder / 'plan.json')}) and
                    same(plan['binding'], bound), 'Original plan/source/config binding changed')
        modules = [module(root / 'scripts' / path, name) for path, name in
                   [('experiment-runner.py', 'output_experiment'), ('ack-service-acceptance.py', 'output_ack'),
                    ('run-cluster.py', 'output_launcher'), ('file-command.py', 'output_file_cli')]]
        adapter = NativeAdapter(root, bound, modules, lease, registry / 'lock', plan, check_owner)
        return Classifier(folder, plan, adapter, getattr(args, 'authorize_absence_confirmation', False)).run()


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    for action in ('start', 'resume'):
        c = sub.add_parser(action)
        c.add_argument('--root', type=Path, required=True)
        c.add_argument('--run-dir', type=Path, required=True)
        if action == 'start':
            c.add_argument('--source-run', type=Path, required=True)
            c.add_argument('--kind', choices=tuple(CLOSE), required=True)
            c.add_argument('--max-commands', type=int, default=4096)
        else:
            c.add_argument('--authorize-absence-confirmation', action='store_true',
                           help='Explicit new absence mutation after unconfirmed Collect; never inferred from Missing')
    return p


def main():
    try:
        print(json.dumps(execute(parser().parse_args()), sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({'state': 'not_confirmed', 'error_type': type(error).__name__,
                          'business_action_completed': False, 'physical_capacity_returned': False}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
