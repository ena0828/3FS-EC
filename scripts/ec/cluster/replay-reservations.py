"""Fixed, bounded replay mutation reservations; never a physical capacity ledger.

Only explicit settlement may close an original operation. An exact twelve-row
classification can release that attempt's model reservation, but cannot finish
the logical action. A retained publication must still pass normal readback.
"""
from pathlib import Path
from types import SimpleNamespace


POLICY = 'explicit_settle_original_candidates'


def require(ok, text):
    if not ok:
        raise ValueError(text)


def policy(plan):
    value = plan.get('recovery')
    require(type(value) is dict and set(value) == {'schema', 'max_mutation_attempts', 'policy'} and
            type(value['schema']) is int and value['schema'] == 1 and value['policy'] == POLICY and
            type(value['max_mutation_attempts']) is int and 1 <= value['max_mutation_attempts'] <= 4,
            'Invalid fixed explicit settlement policy')
    return value


class Reservations:
    def __init__(self, backend, folder, spec, fixed):
        self.b, self.folder, self.spec, self.fixed = backend, folder, spec, fixed
        self.limit = policy(backend.plan)['max_mutation_attempts']
        require(spec['kind'] in ('put', 'repair'), 'Only fixed one-stripe mutation reservations are supported')
        self.kind = 'pwrite' if spec['kind'] == 'put' else 'repair'
        self.phase = 'write' if spec['kind'] == 'put' else 'repair'
        self.cost = 12 * backend.plan['shard_bytes']
        self.root = backend.directory(folder / 'reservations')

    def plans(self):
        paths = sorted(self.root.glob('[0-9][0-9][0-9][0-9]'))
        require([p.name for p in paths] == [f'{i:04d}' for i in range(len(paths))] and len(paths) <= self.limit,
                'Mutation reservation sequence is invalid or exhausted')
        result = []
        for index, path in enumerate(paths):
            self.b.w.private_directory(path)
            value = self.b.load(path / 'plan.json')
            expected = self.plan(index)
            require(self.b.same(value, expected), 'Immutable mutation reservation differs')
            self.b.seal(path / 'plan.json', value)
            result.append(value)
        return result

    def plan(self, index):
        work = self.folder if index == 0 else self.folder / 'mutation-attempts' / f'{index:04d}'
        return {'schema': 1, 'index': index, 'plan_sha256': self.b.plan_sha,
                'spec': self.spec, 'object': self.fixed, 'kind': self.kind,
                'work': str(work), 'source_run': str(work / (self.phase + '-run')),
                'reservation_bytes_decimal': str(self.cost), 'candidate_count': 12}

    def reserve(self, index):
        require(index < self.limit, 'Fixed mutation attempt limit exhausted; no new identity permitted')
        step = next(s for s in self.b.plan['steps'] if s['name'] == self.folder.name)
        before = int(step['model']['before']['allocation_reservation_bytes_decimal'])
        budget = int(self.b.plan['model']['allocation_budget_decimal'])
        require(before + self.cost <= budget, 'Actual mutation reservation exceeds fixed model budget')
        # Earlier reservations must be individually and durably released before
        # this new full reservation. Never subtract saturating or partial counts.
        credited = set()
        for value in self.plans():
            result = self.settlement(value)
            require(value['index'] < index and result['state'] == 'released',
                    'An original reservation is still retained/unknown')
            for row in result['classification']['children'][0]['candidates']:
                require(row['allocation'] not in credited, 'Candidate credited more than once')
                credited.add(row['allocation'])
        path = self.b.directory(self.root / f'{index:04d}')
        value = self.b.seal(path / 'plan.json', self.plan(index))
        if index:
            self.b.directory(self.folder / 'mutation-attempts')
        self.b.directory(Path(value['work']))
        return value

    def active(self):
        plans = self.plans()
        if not plans:
            return self.reserve(0), None
        for value in plans[:-1]:
            require(self.settlement(value)['state'] == 'released', 'Earlier reservation is not released')
        value = plans[-1]
        path = self.root / f"{value['index']:04d}"
        if (path / 'settle-intent.json').exists():
            result = self.settlement(value)  # Incomplete settlement blocks normal resume.
            if result['state'] == 'released':
                require((path / 'replacement-authorized.json').exists(), 'Replacement requires explicit settle')
                self.b.seal(path / 'replacement-authorized.json', {'schema': 1,
                    'settlement_sha256': self.b.sha(path / 'settlement.json'), 'next_index': value['index'] + 1})
                return self.reserve(value['index'] + 1), None
            return value, result
        # A crash may occur after the reservation plan is durable and before
        # the private attempt directory exists. No native intent exists yet;
        # the same fixed directory is prepared, never a new operation identity.
        if value['index']:
            self.b.directory(self.folder / 'mutation-attempts')
        self.b.directory(Path(value['work']))
        return value, None

    def classification(self, value):
        b, runner = self.b, self.b.resolution_runner
        folder = self.root / f"{value['index']:04d}" / 'classification'
        plan = b.load(folder / 'plan.json'); runner.validate_plan(plan)
        record = Path(value['source_run']) / ('record.json' if self.kind == 'pwrite' else 'record.data')
        require(plan['root'] == str(b.root) and plan['source_run'] == value['source_run'] and
                plan['source_record'] == str(record) and plan['output_kind'] == self.kind and
                plan['source_record_sha256'] == b.sha(record), 'Classifier changed original journal')
        for raw, sha in plan['binding']['files'].items():
            require(b.sha(raw) == sha, 'Classifier provider/config/source changed')
        result = b.load(folder / 'completion.json')
        for key, want in {'schema': 1, 'kind': 'ec_output_reservation_classification', 'root': str(b.root),
                'source_run': value['source_run'], 'output_kind': self.kind, 'cluster': b.manifest['cluster_id'],
                'plan_sha256': b.sha(folder / 'plan.json'), 'source_record_sha256': b.sha(record),
                'provider_binding_sha256': runner.sha(plan['binding']), 'source_cleanup_confirmed': True,
                'candidate_set_classified': True, 'business_action_completed': False,
                'physical_capacity_returned': False, 'session_closed_by_runner': False,
                'scope': 'exact_original_output_children_only', 'candidate_count': 12}.items():
            require(type(result.get(key)) is type(want) and result[key] == want, 'Classifier result differs: ' + key)
        inventory = folder / 'final-evidence.json'
        require(result['evidence_inventory']['path'] == str(inventory) and
                result['evidence_inventory']['sha256'] == b.sha(inventory), 'Classifier inventory binding differs')
        files = b.load(inventory)
        require(b.same(files, runner.inventory(folder, ('completion.json', 'final-evidence.json'))),
                'Original classification evidence changed')
        checker = runner.Classifier.__new__(runner.Classifier); checker.plan = plan

        def evidence(ref):
            attempt = Path(ref['attempt'])
            require(attempt.parent == folder / 'attempts', 'Classification evidence escaped its original run')
            intent, joined = b.load(attempt / 'intent.json'), b.load(attempt / 'joined.json')
            op = intent['operation']
            require(b.same(op, b.load(folder / 'operations' / (op['name'] + '.json'))), 'Original operation changed')
            checker.check_join(attempt, intent, joined)
            checked = checker.result(op, attempt, joined)
            require(checked is not None and b.same(runner.evidence_ref(checked), runner.evidence_ref(ref)),
                    'Incomplete original evidence')
            return checked

        cleanup = evidence(result['cleanup'])
        require(b.same(cleanup, result['cleanup']), 'Cleanup projection changed')
        exported = evidence(result['export'])
        require(b.same(exported, result['export']), 'Export projection changed')
        for key, want in {'schema': 1, 'kind': 'ec_file_output_identities', 'output_kind': self.kind,
                         'cluster': b.manifest['cluster_id'], 'source_record_file': record.name,
                         'source_record_sha256': b.sha(record), 'candidate_identities_only': True,
                         'network_io_performed': False, 'metadata_observation_performed': False,
                         'remote_absence_confirmed': False, 'physical_reclamation_confirmed': False}.items():
            require(type(exported['value'].get(key)) is type(want) and exported['value'][key] == want,
                    'Original local identity export differs: ' + key)
        identities = exported['value']['identities']
        require(len(identities) == 1 and len(result['children']) == 1,
                'Only the complete original one-child/twelve-candidate reservation may be credited')
        child = result['children'][0]; identity = runner.export_identity(identities[0])
        require(b.same(child['identity'], identity) and identity['owner_kind'] == self.kind and
                identity['inode_decimal'] == self.fixed['inode_decimal'] and
                identity['object_incarnation'] == self.fixed['incarnation'] and
                identity['owner_client'] == self.fixed['client_namespace'], 'Original output ownership differs')
        observation = evidence(child['observation'])['value']['observation']
        original = runner.candidates(observation, identity)
        require(child['candidate_set_sha256'] == runner.sha(observation['candidates']) and
                len(child['candidates']) == 12, 'Exact candidate set digest differs')
        eligible = []
        for old, row in zip(original, child['candidates']):
            require(all(type(row.get(k)) is type(v) and row[k] == v for k, v in old.items()), 'Candidate identity differs')
            require(type(row.get('eligible')) is bool, 'Candidate eligibility is not boolean')
            if row['eligible']:
                require(row['classification'] in ('NoIssuanceAfterClose', 'NeverBoundAfterClose', 'Collected', 'AbsentAfterClose'),
                        'Unknown cannot return a reservation')
                confirmed = evidence(row['evidence'])
                proof = confirmed['value']
                if row['classification'] in ('NoIssuanceAfterClose', 'NeverBoundAfterClose'):
                    resolution = proof.get('resolution', {})
                    require(b.same(resolution.get('identity'), runner.dto_identity(identity)) and
                            b.same(resolution.get('candidates'), observation['candidates']) and
                            resolution.get('resolutionId') == row.get('resolution_id') and
                            resolution.get('candidateReservationsReleaseEligible') is True and
                            resolution.get('collected') is False and resolution.get('physicalReclamationConfirmed') is False and
                            type(resolution.get('kind')) is int and resolution['kind'] ==
                            (1 if row['classification'] == 'NoIssuanceAfterClose' else 2) and
                            observation['state'] == 6 and observation.get('allocations') is None and
                            child['state'] == row['classification'],
                            'Resolution does not settle these original candidates')
                else:
                    require(all(type(proof.get(k)) is type(v) and proof[k] == v for k, v in old.items()) and
                            proof.get('claim_id') == row.get('claim_id') and observation['state'] == 6 and
                            child['state'] == 'Bound_classified' and
                            observation.get('allocations') is not None and
                            proof.get('action') in (('collect', 'query') if row['classification'] == 'Collected'
                                                   else ('confirm_absent', 'query_absent')),
                            'Terminal fragment evidence belongs to another candidate')
            else:
                require(row['classification'] == 'Published_retained' and child['state'] == 'Published_retained' and
                        observation['state'] == 5, 'Unclassified candidate')
            eligible.append(row['eligible'])
        require(all(eligible) or not any(eligible), 'Partial candidate eligibility cannot release a twelve-slot reservation')
        require(type(result['eligible_candidate_count']) is int and result['eligible_candidate_count'] == sum(eligible),
                'Eligibility count differs')
        rows = b.json_objects(b.w.regular_bytes(Path(cleanup['attempt']) / 'command.log', 1024**2).decode())
        parent = rows[0].get('operation')
        require(parent == identity['parent'], 'Cleanup changed original parent identity')
        if all(eligible):
            require(child['state'] != 'Published_retained' and
                    (rows[1]['logical_complete'] is False if self.kind == 'pwrite' else rows[0]['published'] is False),
                    'Published workload cannot be replaced after a reservation release')
        return result, {'returncode': 0, 'business': rows,
                        'files': {str(folder / raw): sha for raw, sha in files.items()}}, all(eligible)

    def settlement(self, value):
        path = self.root / f"{value['index']:04d}" / 'settlement.json'
        require(path.exists(), 'Explicit settlement is incomplete; use settle, not normal resume')
        saved = self.b.load(path)
        result, cleanup, released = self.classification(value)
        expected = {'schema': 1, 'state': 'released' if released else 'published_retained',
                    'classification_sha256': self.b.sha(path.parent / 'classification/completion.json'),
                    'reservation_plan_sha256': self.b.sha(path.parent / 'plan.json'),
                    'released_model_bytes_decimal': str(self.cost if released else 0),
                    'business_action_completed': False, 'physical_capacity_returned': False}
        require(self.b.same(saved, expected), 'Settlement evidence changed')
        self.b.seal(path, saved)
        return saved | {'cleanup_result': cleanup, 'classification': result}

    def settle(self, authorize_absence=False):
        plans = self.plans()
        require(plans, 'No reserved original mutation exists; normal resume must start it first')
        value = plans[-1]; path = self.root / f"{value['index']:04d}"
        self.b.records(Path(value['source_run']))  # Missing/partial cannot authorize a new journal.
        self.b.seal(path / 'settle-intent.json', {'schema': 1, 'reservation_plan_sha256': self.b.sha(path / 'plan.json'),
            'scope': 'explicit_original_close_and_candidate_classification_not_business_success'})
        target = path / 'classification'
        if not (path / 'settlement.json').exists():
            authorizations = self.b.directory(path / 'authorizations')
            number = len(list(authorizations.iterdir()))
            require(number < 256, 'Explicit settlement invocation bound exhausted')
            self.b.seal(authorizations / f'{number:04d}.json', {'schema': 1,
                'authorize_absence_confirmation': authorize_absence,
                'reservation_plan_sha256': self.b.sha(path / 'plan.json')})
            action = 'resume' if (target / 'plan.json').exists() else 'start'
            require(not target.exists() or action == 'resume', 'Partial classifier plan; preserve original Unknown')
            self.b.run_classifier(SimpleNamespace(action=action, root=self.b.root, run_dir=target,
                source_run=Path(value['source_run']), kind=self.kind, max_commands=4096,
                authorize_absence_confirmation=authorize_absence))
            result, _, released = self.classification(value)
            self.b.seal(path / 'settlement.json', {'schema': 1, 'state': 'released' if released else 'published_retained',
                'classification_sha256': self.b.sha(target / 'completion.json'),
                'reservation_plan_sha256': self.b.sha(path / 'plan.json'),
                'released_model_bytes_decimal': str(self.cost if released else 0),
                'business_action_completed': False, 'physical_capacity_returned': False})
        result = self.settlement(value)
        if result['state'] == 'released' and value['index'] + 1 < self.limit:
            self.b.seal(path / 'replacement-authorized.json', {'schema': 1,
                'settlement_sha256': self.b.sha(path / 'settlement.json'), 'next_index': value['index'] + 1})
        return {key: v for key, v in result.items() if key not in ('cleanup_result', 'classification')}

    def summary(self, exports):
        values = self.plans(); released = []; seen = set()
        for value in values[:-1]:
            result = self.settlement(value)
            require(result['state'] == 'released', 'Earlier mutation reservation not settled')
            for row in result['classification']['children'][0]['candidates']:
                require(row['allocation'] not in seen, 'Candidate credited more than once')
                seen.add(row['allocation'])
            released.append(self.b.sha(self.root / f"{value['index']:04d}" / 'settlement.json'))
        require(len(exports) == 1 and not seen.intersection(
            row['allocation'] for row in exports[0]['revision']['allocations']),
            'A released candidate cannot also be a retained published allocation')
        return {'schema': 1, 'attempts': len(values), 'max_attempts': self.limit,
                'released_model_bytes_decimal': str(len(released) * self.cost),
                'retained_model_bytes_decimal': str(self.cost), 'settlement_sha256': released,
                'physical_capacity_returned': False, 'scope': 'exact_original_candidate_reservations_only'}
