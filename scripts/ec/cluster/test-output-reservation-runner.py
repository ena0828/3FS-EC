#!/usr/bin/env python3
"""Pure state/real-file receipt tests, with an explicitly simulated CLI adapter.

No native, process, socket or FDB is executed. Simulated joins are not runtime
proof; these tests exercise the actual runner's persistent decisions and gates.
"""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import uuid

spec = importlib.util.spec_from_file_location('output_runner', Path(__file__).with_name('output-reservation-runner.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def uid(n):
    return str(uuid.UUID(int=n))


class LostOwner(RuntimeError):
    pass


def identity(n=0):
    return {'inode_decimal': '100', 'object_incarnation': uid(10), 'owner_uid': 1000,
            'owner_client': uid(11), 'parent': uid(20 + n), 'child': uid(100 + n), 'owner_kind': 'repair'}


def readable_identity(i):
    # Independent C++ readable-JSON fixture, not the production projection.
    return {'object': {'inode': i['inode_decimal'], 'incarnation': i['object_incarnation']},
            'owner': {'uid': i['owner_uid'], 'client': i['owner_client']},
            'parent': i['parent'], 'child': i['child'],
            'ownerKind': {'pwrite': 'Pwrite', 'truncate-tail': 'TruncateTail', 'repair': 'Repair'}[i['owner_kind']]}


def observation(i, state='Aborted', bound=True, seq='1'):
    rows, allocations = [], []
    for n in range(12):
        fragment = {'object': i['object_incarnation'], 'stripe': '0', 'generation': '3',
                    'shard': n, 'allocation': uid(int(uuid.UUID(i['child'])) * 100 + n)}
        endpoint = {'placement': {'node': 61, 'chain': n + 1, 'target': str(n + 1)},
                    'engineUuid': uid(300), 'targetIncarnation': uid(301 + n)}
        rows.append({'identity': fragment, 'operation': i['child'], 'writer': readable_identity(i)['owner'],
                     'endpoint': endpoint})
        allocations.append({'object': readable_identity(i)['object'], 'writer': readable_identity(i)['owner'],
                            'fragment': {'identity': fragment, 'operation': i['child'], 'placement': endpoint['placement']},
                            'engineUuid': endpoint['engineUuid'], 'targetIncarnation': endpoint['targetIncarnation']})
    return {'version': 1, 'identity': readable_identity(i), 'state': state, 'stripe': '0', 'generation': '3',
            'issuanceSequence': seq, 'candidates': rows, 'allocations': allocations if bound else None,
            'outputT2Confirmed': True, 'recordDigest': '1' * 64, 'physicalReclamationConfirmed': False}


class Adapter:
    namespace = uid(500)

    def __init__(self, plan, observations):
        self.plan = plan; self.observations = observations
        self.collected, self.absent, self.resolutions = {}, {}, {}
        self.present = set(range(12)); self.calls = []; self.loss = None
        self.drift = False; self.lease = True; self.corrupt = None; self.owner_error = False
        self.final_drift = False; self.prepared_only = None; self.torn_result = None; self.incomplete_close = False
        self.confirm_failure = False
        self.collect_failures = 0
        self.cleanup = {'observed': True, 'state': 'Aborted', 'published': False, 'output_drained': True,
                        'source_released': True, 'all_cleanup_complete': True, 'revalidated': True, 'failure': None}

    def check(self):
        m.require(not self.drift, 'Simulated provider drift')

    def final_check(self):
        self.check()
        m.require(not self.final_drift, 'Simulated final binary digest mismatch')

    def lease_reacquired(self):
        return self.lease

    def argv(self, op, output):
        return ['simulated-cli', m.encoded(op).decode().strip(), str(output)]

    def response(self, op):
        f = op['expected']; action = f['action']
        row = {'schema': 1, **copy.deepcopy(f), 'phase': 'result', 'status_code': 0,
               'outcome': 'observed' if action in ('observe_file_output', 'query_file_output_resolution', 'query_absent') else 'confirmed'}
        if 'identity' in f:
            row['identity'] = readable_identity(next(i for i in self.exported if i['child'] == f['identity']['child']))
        if action == 'observe_file_output':
            row.update(uint64_encoding='unsigned_decimal_strings', physical_reclamation_confirmed=False,
                       metadata_observation_only=True)
            value = self.observations.get(f['identity']['child'])
            if value is None: return {**row, 'status_code': m.META_NOT_FOUND, 'outcome': 'not_observed', 'observation': None}
            return {**row, 'observation': copy.deepcopy(value)}
        if action in ('confirm_unreserved_repair', 'query_unreserved_repair'):
            rid = f['resolution_id']
            row.update(metadata_resolution_only=True, collected=False, physical_reclamation_confirmed=False,
                       candidate_reservations_release_eligible=False, uint64_encoding='unsigned_decimal_strings')
            if action == 'confirm_unreserved_repair':
                self.resolutions[rid] = {'version': 1, 'identity': copy.deepcopy(row['identity']),
                    'resolutionId': rid, 'confirmingClientNamespace': self.namespace,
                    'birth': self.cleanup['birth'], 'childEpoch': self.cleanup['captured_epoch_decimal'],
                    'sourcePin': self.cleanup['source_pin'], 'repairDigest': '5' * 64, 'sourceClosureDigest': '6' * 64}
            if rid not in self.resolutions:
                return {**row, 'status_code': m.META_NOT_FOUND, 'outcome': 'not_observed', 'resolution': None,
                        'actual_candidate_count': None, 'logical_reservation_release_eligible': False}
            return {**row, 'outcome': 'observed' if action.startswith('query') else 'confirmed',
                    'resolution': copy.deepcopy(self.resolutions[rid]),
                    'actual_candidate_count': 0, 'logical_reservation_release_eligible': True}
        if 'file_output_resolution' in action:
            row.update(uint64_encoding='unsigned_decimal_strings', physical_reclamation_confirmed=False,
                       collected=False, metadata_resolution_only=True)
            rid = f['resolution_id']
            if action.startswith('confirm'):
                if self.confirm_failure:
                    self.confirm_failure = False
                    return {**row, 'status_code': 4085, 'outcome': 'unknown'}
                o = self.observations[f['identity']['child']]
                self.resolutions[rid] = {'identity': copy.deepcopy(row['identity']), 'resolutionId': rid,
                    'confirmingClientNamespace': self.namespace, 'candidates': o['candidates'],
                    'candidateReservationsReleaseEligible': True, 'collected': False,
                    'physicalReclamationConfirmed': False, 'issuanceSequence': o['issuanceSequence'],
                    'kind': 'NoIssuanceAfterClose' if o['issuanceSequence'] == '0' else 'NeverBoundAfterClose',
                    **{k: '2' * 64 for k in ('candidateDigest', 'executionDigest', 'outputClosureDigest', 'sourceClosureDigest')}}
            if rid not in self.resolutions: return {**row, 'status_code': m.META_NOT_FOUND, 'outcome': 'not_observed'}
            return {**row, 'resolution': copy.deepcopy(self.resolutions[rid]),
                    'candidate_reservations_release_eligible': True, 'metadata_resolution_only': True}
        claim = f['claim_id']
        if action == 'collect' and self.collect_failures:
            self.collect_failures -= 1
            return {**row, 'status_code': 4085, 'outcome': 'unknown'}
        if action == 'collect' and f['shard'] in self.present:
            m.require(claim not in self.absent, 'Synthetic service rejects opposite terminal')
            self.collected[claim] = True
        if action == 'confirm_absent' and f['shard'] not in self.present:
            m.require(claim not in self.collected, 'Synthetic service rejects opposite terminal')
            self.absent[claim] = True
        if action in ('collect', 'query'):
            if claim not in self.collected: return {**row, 'status_code': 4085, 'outcome': 'unknown'}
            return {**row, 'claim_sha256': '3' * 64, 'ledger_sha256': '4' * 64, 'terminal_revision_decimal': '9'}
        if claim not in self.absent: return {**row, 'status_code': 4085, 'outcome': 'not_observed'}
        return {**row, 'kind': 'ec_fragment_absence', 'absence_protocol': 1, 'state': 'absent_after_close',
                'claim_sha256': '3' * 64, 'closure_sha256': '5' * 64, 'ledger_sha256': '6' * 64,
                'absence_record_revision_decimal': '1', 'candidate_reservation_release_eligible': True,
                'storage_absence_observed': True, 'collected': False, 'physical_reclamation_confirmed': False}

    def execute(self, argv, attempt):
        op = json.loads(argv[1]); self.calls.append(copy.deepcopy(op))
        assert m.same(m.load(attempt / 'intent.json'), {'operation': op, 'argv': argv})
        assert m.same(m.load(attempt.parent.parent / 'plan.json'), self.plan)
        assert m.same(m.load(attempt.parent.parent / 'operations' / (op['name'] + '.json')), op)
        rc = 0
        if op['kind'] == 'close':
            cleanup = self.cleanup
            if self.incomplete_close:
                cleanup = {**cleanup, 'state': 'Planned', 'published': False,
                           'output_drained': False, 'source_released': False, 'all_cleanup_complete': False}
                if op['arguments'][0] == 'close-repair-debt':
                    rc = 1
                    self.incomplete_close = 'query'
                else:
                    self.incomplete_close = False
            log = m.encoded(cleanup)
        elif op['kind'] == 'export':
            value = {'schema': 1, 'kind': 'ec_file_output_identities', 'cluster': self.plan['binding']['cluster'],
                     'output_kind': self.plan['output_kind'], 'source_record_file': Path(self.plan['source_record']).name,
                     'source_record_sha256': self.plan['source_record_sha256'], 'source_latest_state_sha256': '1' * 64,
                     'candidate_identities_only': True, 'network_io_performed': False,
                     'metadata_observation_performed': False, 'remote_absence_confirmed': False,
                     'physical_reclamation_confirmed': False, 'identities': self.exported}
            (attempt / 'archive.jsonl').write_bytes(m.encoded(value)); log = b'{"local_export":true}\n'
        else:
            row = self.response(op)
            if self.corrupt: row = self.corrupt(op, row)
            if self.loss == op['expected']['action']:
                self.loss = None
                raise LostOwner('after simulated remote result; no joined evidence')
            prepared = {'schema': 1, **op['expected'], 'phase': 'prepared', 'status_code': 0}
            if 'identity' in op['expected']:
                prepared['identity'] = readable_identity(next(i for i in self.exported
                                                             if i['child'] == op['expected']['identity']['child']))
            if self.torn_result == op['expected']['action']:
                self.torn_result = None
                (attempt / 'archive.jsonl').write_bytes(m.encoded(prepared) + b'{"phase":"res'); rc = 1
            elif self.prepared_only == op['expected']['action']:
                self.prepared_only = None
                (attempt / 'archive.jsonl').write_bytes(m.encoded(prepared)); rc = 1
            else:
                (attempt / 'archive.jsonl').write_bytes(m.encoded(prepared) + m.encoded(row))
                rc = 0 if row['status_code'] == 0 else 1
            log = b'private simulated CLI log\n'
        (attempt / 'command.log').write_bytes(log)
        return {'argv': argv, 'process_started': True, 'process_exited': True, 'returncode': rc,
                'log_sha256': m.gc.file_sha(attempt / 'command.log'),
                'owner_error_type': 'LoggerFailure' if self.owner_error else None}


class OutputReservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.base = Path(self.tmp.name).resolve()
        self.folder = m.gc.private(self.base / 'run', create=True)
        for name in ('operations', 'attempts'): m.gc.private(self.folder / name, create=True)
        original = m.gc.private(self.base / 'original', create=True)
        record = original / 'record.data'; record.write_bytes(b'fixed native journal fixture\n')
        self.plan = {'schema': 1, 'kind': 'ec_output_reservation_plan', 'root': str(self.base),
                     'source_run': str(original), 'source_record': str(record), 'source_record_sha256': m.gc.file_sha(record),
                     'output_kind': 'repair', 'id_namespace': uid(600), 'max_commands': 8192,
                     'policy': 'collect_first_absence_requires_explicit_resume_authorization',
                     'binding': {'cluster': uid(700), 'client_namespace': Adapter.namespace, 'files': {}}}
        m.save(self.folder / 'plan.json', self.plan)
        self.identities = [identity()]
        self.adapter = Adapter(self.plan, {i['child']: observation(i) for i in self.identities})
        self.adapter.exported = self.identities

    def tearDown(self): self.tmp.cleanup()

    def test_unreserved_repair_requires_affirmative_fact_after_lost_confirm(self):
        original = self.identities[0]
        self.plan['confirm_unreserved_repair'] = True
        (self.folder / 'plan.json').write_bytes(m.encoded(self.plan))
        self.adapter.observations.clear()
        self.adapter.cleanup.update(birth=uid(3), source_pin=uid(33), captured_epoch_decimal='7',
                                    child=original['child'], operation=original['parent'], inode_decimal=original['inode_decimal'],
                                    incarnation=original['object_incarnation'], client_namespace=original['owner_client'])
        self.adapter.loss = 'confirm_unreserved_repair'
        with self.assertRaises(LostOwner):
            self.run_classifier()
        self.assertFalse((self.folder / 'completion.json').exists())
        self.adapter.corrupt = lambda op, row: (
            {**row, 'resolution': {**row['resolution'], 'sourcePin': uid(900)}}
            if row.get('resolution') is not None else row)
        with self.assertRaises(m.gc.CheckError):
            self.run_classifier()
        self.assertFalse((self.folder / 'completion.json').exists())
        self.assertEqual(sum(op['expected'].get('action') == 'confirm_unreserved_repair' for op in self.adapter.calls), 1)

    def run_classifier(self, authorized=False, *, authorize_collection_retry=False):
        return m.Classifier(self.folder, self.plan, self.adapter, authorized,
                            authorize_collection_retry=authorize_collection_retry).run()

    def test_explicit_collection_retry_queries_first_reuses_claim_and_dispatches_once(self):
        self.adapter.collect_failures = 2
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        original = next(c for c in self.adapter.calls if c['expected'].get('action') == 'collect')
        first_files = m.inventory(self.folder / 'attempts')
        for absent, retry in ((True, True), (False, 1)):
            before = len(self.adapter.calls)
            with self.assertRaisesRegex(m.gc.CheckError, 'Conflicting or invalid'):
                self.run_classifier(absent, authorize_collection_retry=retry)
            self.assertEqual(len(self.adapter.calls), before)
        before = len(self.adapter.calls)
        with self.assertRaisesRegex(m.gc.CheckError, 'explicit authorization'): self.run_classifier()
        self.assertEqual([c['expected']['action'] for c in self.adapter.calls[before:]], ['query', 'query_absent'])
        before = len(self.adapter.calls)
        with self.assertRaises(m.gc.CheckError): self.run_classifier(authorize_collection_retry=True)
        delta = self.adapter.calls[before:]
        self.assertEqual([c['expected']['action'] for c in delta], ['query', 'query_absent', 'collect'])
        self.assertEqual(delta[-1], original)
        self.assertFalse((self.folder / 'completion.json').exists())
        result = self.run_classifier(authorize_collection_retry=True)
        self.assertEqual(result['eligible_candidate_count'], 12)
        self.assertFalse(result['business_action_completed']); self.assertFalse(result['physical_capacity_returned'])
        repeats = [c for c in self.adapter.calls if c['expected'].get('action') == 'collect' and
                   c['expected']['claim_id'] == original['expected']['claim_id']]
        self.assertEqual(repeats, [original] * 3)
        self.assertFalse(any(c['expected'].get('action') == 'confirm_absent' for c in self.adapter.calls))
        authorizations = list(self.folder.glob('*-collection-retry-authorization-*.json'))
        self.assertEqual(len(authorizations), 2)
        for path in authorizations:
            auth = m.load(path)
            self.assertEqual(auth['plan_sha256'], m.gc.file_sha(self.folder / 'plan.json'))
            self.assertEqual(auth['operation_sha256'], m.sha(original))
            self.assertEqual(auth['claim_id'], original['expected']['claim_id'])
            self.assertEqual(auth['candidate']['allocation'], original['expected']['allocation'])
            self.assertEqual(m.load(self.folder / 'attempts' / auth['attempt'] / 'intent.json')['operation'], original)
        for relative, digest in first_files.items():
            self.assertEqual(m.gc.file_sha(self.folder / 'attempts' / relative), digest)
        before = len(self.adapter.calls)
        self.assertEqual(self.run_classifier(authorize_collection_retry=True), result)
        self.assertEqual(len(self.adapter.calls), before, 'A full positive receipt prevents all new dispatch')

    def test_complete_bound_set_and_repeat_do_not_dispatch_again(self):
        result = self.run_classifier()
        self.assertEqual(result['candidate_count'], 12); self.assertEqual(result['eligible_candidate_count'], 12)
        self.assertFalse(result['business_action_completed']); self.assertFalse(result['physical_capacity_returned'])
        count = len(self.adapter.calls)
        self.assertEqual(self.run_classifier(), result); self.assertEqual(len(self.adapter.calls), count)

    def test_admin_readable_enum_contract_accepts_names_and_rejects_numeric_shapes(self):
        cases = [('pwrite', 'Aborted', False, '0', 'NoIssuanceAfterClose'),
                 ('truncate-tail', 'Aborted', False, '7', 'NeverBoundAfterClose'),
                 ('repair', 'Published', True, '1', 'Published_retained'),
                 ('repair', 'Aborted', True, '1', 'Bound_classified')]
        variants = [(case, None, None) for case in cases]
        variants += [(case, 'owner', bad) for case, bad in zip(cases, (1, 2, 3, True))]
        variants += [(cases[3], 'state', bad) for bad in (5, 6, True, '6', 'aborted', 'Missing')]
        variants += [(case, 'resolution', bad) for case, bad in
                     ((cases[0], 1), (cases[1], 2), (cases[0], True),
                      (cases[1], '2'), (cases[1], 'never_bound_after_close'))]
        for n, (case, field, bad) in enumerate(variants):
            kind, state, bound, seq, expected = case
            with self.subTest(kind=kind, state=state, field=field, bad=bad):
                folder = m.gc.private(self.base / f'enum-{n:02d}', create=True)
                for name in ('operations', 'attempts'): m.gc.private(folder / name, create=True)
                plan = {**self.plan, 'output_kind': 'truncate' if kind == 'truncate-tail' else kind}
                m.save(folder / 'plan.json', plan)
                original = {**identity(), 'owner_kind': kind}
                observed = observation(original, state, bound, seq)
                adapter = Adapter(plan, {original['child']: observed}); adapter.exported = [original]
                self.assertEqual(m.dto_identity(original), readable_identity(original))
                def corrupt(op, row):
                    if field == 'owner' and 'identity' in row:
                        row['identity']['ownerKind'] = bad
                    elif field == 'state' and row.get('observation') is not None:
                        row['observation']['state'] = bad
                    elif field == 'resolution' and row.get('resolution') is not None:
                        row['resolution']['kind'] = bad
                    return row
                adapter.corrupt = corrupt
                classifier = m.Classifier(folder, plan, adapter)
                if field is not None:
                    with self.assertRaises(m.gc.CheckError): classifier.child(0, original)
                    self.assertFalse(any(c['expected']['action'] in ('collect', 'confirm_absent')
                                         for c in adapter.calls))
                else:
                    result = classifier.child(0, original)
                    self.assertEqual(result['state'], expected)
                    self.assertEqual(len(result['candidates']), 12)
                    self.assertEqual(sum(r['eligible'] for r in result['candidates']),
                                     0 if state == 'Published' else 12)
                    # Real adapter argv maps the readable name back to the fixed CLI spelling.
                    op = classifier.admin('argv-only', 'observe_file_output', original)
                    cli = SimpleNamespace(root=self.base, launcher=SimpleNamespace(admin_command_line=lambda parts: parts))
                    parts = m.NativeAdapter.argv(cli, op, folder / 'unused.jsonl')[-1]
                    self.assertEqual(parts[parts.index('--owner-kind') + 1], kind)

    def test_mixed_set_requires_explicit_authorization_and_preserves_failures(self):
        self.adapter.present = {0, 3, 7, 11}
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertFalse(any(c['expected'].get('action') == 'confirm_absent' for c in self.adapter.calls))
        for _ in range(9):
            try: result = self.run_classifier(True); break
            except m.gc.CheckError: pass
        else: self.fail('bounded explicit recoveries did not finish')
        rows = result['children'][0]['candidates']
        self.assertEqual(sum(r['classification'] == 'Collected' for r in rows), 4)
        self.assertEqual(sum(r['classification'] == 'AbsentAfterClose' for r in rows), 8)
        authorizations = list(self.folder.glob('*-absence-authorization-*.json'))
        self.assertEqual(len(authorizations), 8)
        for path in authorizations:
            auth = m.load(path); attempt = self.folder / 'attempts' / auth['attempt']
            op = m.load(attempt / 'intent.json')['operation']
            self.assertEqual(auth['claim_id'], op['expected']['claim_id'])
            self.assertEqual(auth['operation_sha256'], m.sha(op))
            self.assertEqual(auth['candidate']['allocation'], op['expected']['allocation'])
        self.assertGreater(sum(m.load(p / 'joined.json')['returncode'] != 0 for p in (self.folder / 'attempts').iterdir()), 0)
        files = m.gc.parse(m.gc.regular(Path(result['evidence_inventory']['path']), m.MAX_INVENTORY))
        for path in (self.folder / 'attempts').iterdir():
            for name in ('command.log', 'archive.jsonl', 'joined.json'):
                if (path / name).exists():
                    self.assertEqual(files[(path / name).relative_to(self.folder).as_posix()], m.gc.file_sha(path / name))

    def test_lost_collect_reply_queries_same_claim_and_never_confirms_absence(self):
        self.adapter.loss = 'collect'
        with self.assertRaises(LostOwner): self.run_classifier()
        result = self.run_classifier()
        self.assertFalse(result['historical_join_proven'])
        first = next(c for c in self.adapter.calls if c['expected'].get('action') == 'collect')
        same = [c for c in self.adapter.calls if c['expected'].get('claim_id') == first['expected']['claim_id']]
        self.assertEqual(sum(c['expected']['action'] == 'collect' for c in same), 1)
        self.assertFalse(any(c['expected']['action'] == 'confirm_absent' for c in same))

    def test_lost_absence_reply_recovers_by_query_without_new_mutation(self):
        self.adapter.present = set(range(1, 12))
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.adapter.loss = 'confirm_absent'
        with self.assertRaises(LostOwner): self.run_classifier(True)
        result = self.run_classifier()
        self.assertFalse(result['historical_join_proven'])
        self.assertEqual(sum(c['expected'].get('action') == 'confirm_absent' for c in self.adapter.calls), 1)

    def test_unbound_two_kinds_and_published_partial_set_keep_correct_credit(self):
        self.identities[:] = [identity(n) for n in range(3)]
        self.adapter.observations = {self.identities[0]['child']: observation(self.identities[0], bound=False, seq='0'),
                                     self.identities[1]['child']: observation(self.identities[1], bound=False, seq='7'),
                                     self.identities[2]['child']: observation(self.identities[2], state='Published')}
        result = self.run_classifier()
        self.assertEqual([c['state'] for c in result['children']],
                         ['NoIssuanceAfterClose', 'NeverBoundAfterClose', 'Published_retained'])
        self.assertEqual(result['candidate_count'], 36); self.assertEqual(result['eligible_candidate_count'], 24)
        self.assertFalse(any(c['eligible'] for c in result['children'][2]['candidates']))

    def test_missing_ecfe_never_becomes_resolution_or_empty_success(self):
        self.adapter.observations.clear()
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertFalse((self.folder / 'completion.json').exists())
        self.assertFalse(any('resolution' in c['expected'].get('action', '') for c in self.adapter.calls))

    def test_incomplete_candidate_set_or_mismatched_binding_stops_before_gc(self):
        for mode in ('short', 'wrong-binding'):
            with self.subTest(mode=mode):
                row = observation(identity())
                if mode == 'short': row['candidates'].pop()
                else: row['allocations'][0]['writer'] = {'uid': 999, 'client': uid(11)}
                with self.assertRaises(m.gc.CheckError): m.candidates(row, identity())
        row = observation(identity()); row['candidates'][0]['identity']['shard'] = False
        with self.assertRaises(m.gc.CheckError): m.candidates(row, identity())

    def test_archive_log_and_provider_tampering_are_rejected(self):
        self.run_classifier()
        path = next(p for p in (self.folder / 'attempts').iterdir() if (p / 'archive.jsonl').exists())
        old = (path / 'archive.jsonl').read_bytes(); (path / 'archive.jsonl').write_bytes(old + b' ')
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        (path / 'archive.jsonl').write_bytes(old)
        (path / 'command.log').write_text('changed', encoding='utf-8')
        with self.assertRaises(m.gc.CheckError): self.run_classifier()

    def test_budget_exhaustion_and_source_cleanup_failure_do_not_dispatch_candidates(self):
        self.plan['max_commands'] = 1
        # Arrange the bounded plan before any simulated dispatch, just as start does.
        (self.folder / 'plan.json').write_bytes(m.encoded(self.plan))
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertEqual(len(self.adapter.calls), 1)
        for field in ('output_drained', 'source_released', 'all_cleanup_complete'):
            row = dict(self.adapter.cleanup); row[field] = False
            with self.assertRaises(m.gc.CheckError): m.close_result('repair', [row])
        with self.assertRaises(m.gc.CheckError): m.close_result('truncate', [{'observed': True, 'published': True,
             'aborted': True, 'all_cleanup_complete': True, 'error_code': 0}])

    def test_unknown_child_requires_inherited_lease_and_unknown_owner_is_not_success(self):
        self.adapter.loss = 'collect'
        with self.assertRaises(LostOwner): self.run_classifier()
        self.adapter.lease = False
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.adapter.lease = True; self.adapter.owner_error = True
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertFalse((self.folder / 'completion.json').exists())
        # The real adapter consults its caller between owned-child scopes,
        # before touching the lease/provider or dispatching another command.
        class ParentStopped(RuntimeError): pass
        observed = []
        def parent_check():
            observed.append('parent-check')
            raise ParentStopped()
        fake = SimpleNamespace(check_owner=parent_check)
        with self.assertRaises(ParentStopped): m.NativeAdapter.check(fake)
        with self.assertRaises(ParentStopped): m.execute(None, check_owner=parent_check)
        self.assertEqual(observed, ['parent-check', 'parent-check'])

    def test_resolution_or_absence_scalar_mismatch_never_grants_credit(self):
        op = {'expected': {'action': 'query_absent'}}
        row = {'status_code': 0, 'outcome': 'observed', 'kind': 'ec_fragment_absence', 'absence_protocol': 1,
               'state': 'absent_after_close', 'absence_record_revision_decimal': '1',
               'candidate_reservation_release_eligible': True, 'storage_absence_observed': True,
               'collected': False, 'physical_reclamation_confirmed': False,
               'claim_sha256': '1' * 64, 'closure_sha256': '2' * 64, 'ledger_sha256': '3' * 64}
        self.assertTrue(m.positive(op, row))
        for key, value in [('candidate_reservation_release_eligible', 1), ('physical_reclamation_confirmed', True),
                           ('absence_record_revision_decimal', '2'), ('closure_sha256', '0' * 64)]:
            with self.subTest(key=key), self.assertRaises(m.gc.CheckError): m.positive(op, {**row, key: value})

    def test_authorization_is_resume_only_and_completed_record_is_immutable(self):
        flags = ('--authorize-absence-confirmation', '--authorize-collection-retry')
        for flag in flags:
            with self.assertRaises(SystemExit):
                m.parser().parse_args(['start', '--root', str(self.base), '--run-dir', str(self.folder),
                    '--source-run', self.plan['source_run'], '--kind', 'repair', flag])
            args = m.parser().parse_args(['resume', '--root', str(self.base), '--run-dir', str(self.folder), flag])
            self.assertTrue(getattr(args, flag[2:].replace('-', '_')))
        with self.assertRaises(SystemExit):
            m.parser().parse_args(['resume', '--root', str(self.base), '--run-dir', str(self.folder), *flags])
        with self.assertRaisesRegex(m.gc.CheckError, 'Conflicting or invalid'):
            m.execute(SimpleNamespace(authorize_absence_confirmation=True, authorize_collection_retry=True))
        with self.assertRaisesRegex(m.gc.CheckError, 'original classifier'):
            m.execute(SimpleNamespace(action='start', authorize_collection_retry=True))
        self.run_classifier(); result = m.load(self.folder / 'completion.json'); result['eligible_candidate_count'] = 999
        (self.folder / 'completion.json').write_bytes(m.encoded(result))
        with self.assertRaises(m.gc.CheckError): self.run_classifier()

    def test_incomplete_close_queries_before_same_run_cleanup_and_partial_admin_recovers(self):
        self.adapter.incomplete_close = True
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.adapter.torn_result = 'collect'
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertEqual([c['arguments'][0] for c in self.adapter.calls if c['kind'] == 'close'],
                         ['close-repair-debt', 'query-repair', 'close-repair-debt'])
        result = self.run_classifier()
        self.assertEqual(result['eligible_candidate_count'], 12)
        first = next(c for c in self.adapter.calls if c['expected'].get('action') == 'collect')
        self.assertEqual(sum(c['expected'].get('action') == 'collect' and
                             c['expected'].get('claim_id') == first['expected']['claim_id']
                             for c in self.adapter.calls), 1)

    def test_final_hash_failure_does_not_publish_completion(self):
        self.adapter.final_drift = True
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertFalse((self.folder / 'completion.json').exists())
        self.assertFalse((self.folder / 'final-evidence.json').exists())

    def test_resolution_replays_same_confirm_only_after_joined_missing_query(self):
        self.adapter.observations[identity()['child']] = observation(identity(), bound=False, seq='0')
        self.adapter.confirm_failure = True
        self.adapter.prepared_only = 'confirm_file_output_resolution'
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        original = next(c for c in self.adapter.calls if c['expected'].get('action') == 'confirm_file_output_resolution')
        self.adapter.prepared_only = 'query_file_output_resolution'
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertEqual(sum(c == original for c in self.adapter.calls), 1)
        self.adapter.corrupt = lambda op, row: ({**row, 'status_code': 20} if
            op['expected']['action'] == 'query_file_output_resolution' else row)
        with self.assertRaises(m.gc.CheckError): self.run_classifier()
        self.assertEqual(sum(c == original for c in self.adapter.calls), 1)
        self.adapter.corrupt = None
        result = self.run_classifier()
        self.assertEqual(sum(c == original for c in self.adapter.calls), 2)
        self.assertEqual(result['children'][0]['state'], 'NoIssuanceAfterClose')

    def test_real_file_command_and_lease_grammar_accept_seal_but_reject_input(self):
        # Actual command builder and actual owner grammar, without launching a process.
        cluster = Path(__file__).parent
        cli = m.module(cluster / 'file-command.py', 'output_test_file_cli')
        ack = m.module(cluster / 'ack-service-acceptance.py', 'output_test_ack')
        m.save(self.base / 'cluster.json', {'root': str(self.base), 'file_api': True})
        args = cli.parser().parse_args(['--root', str(self.base), 'seal', '--run-dir', self.plan['source_run']])
        argv = cli.command(args)
        owner = SimpleNamespace(root=self.base, config=self.base / 'client/file-client.toml')
        self.assertFalse(ack.validate_leased_file_command(owner, argv))
        self.assertEqual(argv[-1], 'mode4-seal')
        with self.assertRaises(RuntimeError):
            ack.validate_leased_file_command(owner, argv[:-1] + ['--config.input_file=' + self.plan['source_record'], argv[-1]])


if __name__ == '__main__': unittest.main()
