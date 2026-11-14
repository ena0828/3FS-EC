"""Deterministic cache policy for serial, bounded native observation replay.

Source times order policy decisions; they do not pace RPCs or measure arrival
latency. Allocation reservations are released only by a confirmed exact GC
action. Empty inodes and metadata are deliberately outside that byte budget.
"""
import uuid

import kv_trace as kv


def repair_options(strategy='helper', delivery='direct', window=1, targets=(0, 1)):
    kv.require(strategy in ('central', 'pipeline', 'helper') and delivery in ('return', 'direct')
               and (strategy == 'helper' or delivery == 'return'), 'Invalid repair strategy/delivery')
    kv.integer(window, 'repair window', 1, 4)
    targets = list(targets)
    kv.require(len(targets) in (1, 2) and all(type(x) is int and 0 <= x < 12 for x in targets)
               and len(set(targets)) == len(targets), 'Invalid repair targets')
    return {'strategy': strategy, 'delivery': delivery, 'window': window, 'targets': targets,
            'sources': [x for x in range(12) if x not in targets][:10]}


def synthetic():
    """Six invented observations exercise reuse, LRU, TTL and two repairs."""
    events = []
    for sequence, (second, name) in enumerate(((0, 'a'), (1, 'b'), (2, 'a'), (3, 'c'), (4, 'a'), (9, 'a'))):
        events.append({'kind': 'input_block_observation', 'sequence_decimal': str(sequence),
                       'clock': {'scaled_ns_decimal': str(second * 10**9), 'region': 'measurement'},
                       'object': {'key_sha256': kv.sha(('ec-functional-replay/v1/' + name).encode()),
                                  'logical_bytes_decimal': str(kv.BLOCK_BYTES)}})
    return {'schema': 1, 'kind': 'synthetic_functional_observations', 'recipe': 'lru-ttl-repair-six/v1',
            'selected_observations': len(events), 'horizon_ns_decimal': str(9 * 10**9),
            'actual_kv_tensors': False, 'observed_cache_decisions': False,
            'public_trace': False}, events


def build(binding, events, *, trace_id, shard_bytes=11469, slots=2, logical_budget=229376,
          allocation_budget=16777216, ttl_ns=259200000000000, repair_every=3, repair=None):
    kv.require(str(uuid.UUID(trace_id)) == trace_id, 'Require canonical fixed trace UUID')
    kv.require(type(binding) is dict and type(binding.get('schema')) is int and binding.get('schema') == 1 and binding.get('kind') in (
        'verified_public_input_observations', 'synthetic_functional_observations'), 'Unknown observation provenance')
    kv.require(binding.get('actual_kv_tensors') is False and binding.get('observed_cache_decisions') is False,
               'Observation provenance overclaims payload or cache decisions')
    kv.require(type(events) is list and 1 <= len(events) <= 4096 and type(binding.get('selected_observations')) is int and
               binding.get('selected_observations') == len(events), 'Invalid bounded observation count')
    kv.integer(shard_bytes, 'shard bytes', 1, 1048576)
    kv.integer(slots, 'resident slots', 1, 4096)
    kv.integer(logical_budget, 'logical byte budget', 1, 4096 * kv.BLOCK_BYTES)
    kv.integer(allocation_budget, 'allocation reservation byte budget', 1, 1 << 40)
    kv.integer(ttl_ns, 'inactivity TTL ns', 1, kv.MAX_NS)
    kv.integer(repair_every, 'repair period (zero disables)', 0, 4096)
    if repair is None:
        repair = repair_options()
    kv.require(kv.canonical(repair) == kv.canonical(repair_options(
        repair['strategy'], repair['delivery'], repair['window'], repair['targets'])), 'Repair sources/options differ')
    horizon = kv.decimal_integer(binding['horizon_ns_decimal'], 'observation horizon', kv.MAX_NS)
    resident, sizes, steps = {}, {}, []
    used_logical = used_allocations = previous_time = 0
    previous_sequence = -1
    hits = misses = repairs = 0
    peak_logical = peak_allocations = peak_slots = 0
    allocation_cost = 12 * shard_bytes

    def counters():
        return {'resident_objects': len(resident), 'logical_bytes_decimal': str(used_logical),
                'allocation_reservation_bytes_decimal': str(used_allocations)}

    def action(kind, item, now, reason, sequence=None, region=None):
        name = 'a' + str(len(steps)).zfill(6)
        spec = {'kind': kind, 'instance': name if kind == 'put' else item['instance'],
                'key_sha256': item['key'], 'logical_bytes_decimal': str(item['size'])}
        if kind == 'repair': spec.update(repair)
        step = {'name': name, 'spec': spec, 'model': {'reason': reason, 'virtual_time_ns_decimal': str(now),
                'source_sequence_decimal': sequence, 'region': region, 'before': counters()}}
        steps.append(step)
        return step

    def evict(key, now, reason, sequence=None, region=None):
        nonlocal used_logical, used_allocations
        item = resident[key]
        step = action('evict', item, now, reason, sequence, region)
        used_logical -= item['size']
        used_allocations -= item['revisions'] * allocation_cost
        del resident[key]
        step['model']['after'] = counters()
        step['model']['required_confirmed_gc_allocation_bytes_decimal'] = str(item['revisions'] * allocation_cost)

    def expire(now, sequence=None, region=None):
        for key, item in sorted(list(resident.items()), key=lambda pair: (pair[1]['last'] + ttl_ns, pair[1]['instance'])):
            if item['last'] + ttl_ns <= now:
                evict(key, now, 'inactivity_ttl', sequence, region)

    def victim(exclude=None):
        choices = [item for key, item in resident.items() if key != exclude]
        kv.require(choices, 'Budget cannot retain current data and reserve this mutation; increase budget or disable repair')
        return min(choices, key=lambda item: (item['last_order'], item['instance']))['key']

    for order, event in enumerate(events):
        kv.require(event.get('kind') == 'input_block_observation', 'Only block observations may drive cache policy')
        sequence = kv.decimal_integer(event['sequence_decimal'], 'source sequence')
        now = kv.decimal_integer(event['clock']['scaled_ns_decimal'], 'source virtual time', kv.MAX_NS)
        region = event['clock']['region']
        kv.require(sequence > previous_sequence and previous_time <= now <= horizon and region in ('warmup', 'measurement'),
                   'Observation order/time/region differs')
        previous_sequence, previous_time = sequence, now
        key = kv.digest(event['object']['key_sha256'], 'object key')
        size = kv.decimal_integer(event['object']['logical_bytes_decimal'], 'logical bytes', kv.BLOCK_BYTES)
        kv.require(1 <= size <= 10 * shard_bytes and size <= logical_budget, 'Object exceeds single stripe or resident budget')
        kv.require(key not in sizes or sizes[key] == size, 'Repeated key changed logical length')
        sizes[key] = size
        expire(now, str(sequence), region)
        if key in resident:
            item = resident[key]
            step = action('get', item, now, 'model_hit', str(sequence), region)
            item['last'], item['last_order'] = now, order
            hits += 1
        else:
            kv.require(allocation_cost <= allocation_budget, 'Budget cannot reserve one 10+2 object')
            while len(resident) >= slots or used_logical + size > logical_budget or used_allocations + allocation_cost > allocation_budget:
                evict(victim(), now, 'model_capacity', str(sequence), region)
            item = {'key': key, 'size': size, 'last': now, 'last_order': order, 'revisions': 1}
            step = action('put', item, now, 'model_miss', str(sequence), region)
            item['instance'] = step['name']; resident[key] = item
            used_logical += size; used_allocations += allocation_cost
            misses += 1
        step['model']['after'] = counters()
        peak_logical, peak_slots = max(peak_logical, used_logical), max(peak_slots, len(resident))
        peak_allocations = max(peak_allocations, used_allocations)
        if repair_every and (order + 1) % repair_every == 0:
            kv.require(item['revisions'] < 256, 'Per-instance published revision limit reached; shorten replay or reduce repairs')
            while used_allocations + allocation_cost > allocation_budget:
                evict(victim(exclude=key), now, 'repair_reservation', str(sequence), region)
            step = action('repair', item, now, 'configured_repair_period', str(sequence), region)
            item['revisions'] += 1; used_allocations += allocation_cost; repairs += 1
            step['model']['after'] = counters()
            peak_allocations = max(peak_allocations, used_allocations)
    expire(horizon)
    for key in sorted(list(resident), key=lambda key: resident[key]['instance']):
        evict(key, horizon, 'explicit_end_of_selection_drain')
    kv.require(len(steps) <= 16384 and used_logical == used_allocations == 0, 'Invalid bounded final accounting')
    return {'schema': 1, 'kind': 'bounded_serial_native_kv_replay', 'trace_id': trace_id, 'namespace': '/ec-lab',
            'source_binding': binding, 'selected_observations_sha256': kv.sha(kv.canonical(events)),
            'shard_bytes': shard_bytes, 'repair': repair,
            'model': {'slots': slots, 'logical_budget_decimal': str(logical_budget),
                      'allocation_budget_decimal': str(allocation_budget), 'ttl_ns_decimal': str(ttl_ns),
                      'repair_every': repair_every, 'eviction_policy': 'source-time-inactivity-ttl-then-lru',
                      'arrival_pacing': False, 'execution': 'serial_closed_loop',
                      'allocation_cost_per_revision_decimal': str(allocation_cost),
                      'allocation_credit_requires': 'exact_confirmed_published_allocation_gc',
                      'namespace_metadata_in_budget': False, 'unpublished_unknown_outputs_credit': False},
            'bounds': {'observations': len(events), 'actions': len(steps), 'instances': misses,
                       'max_revisions_per_instance': 256, 'max_actions': 16384},
            'summary': {'observation_regions': 'warmup_and_measurement_combined',
                        'model_hits': hits, 'model_misses': misses, 'scheduled_repairs': repairs,
                        'peak_resident_objects': peak_slots, 'peak_logical_bytes_decimal': str(peak_logical),
                        'peak_allocation_reservation_bytes_decimal': str(peak_allocations), 'final': counters()},
            'claims': {'actual_kv_tensors': False, 'observed_cache_hit_rate': False,
                       'physical_disk_capacity_measured': False, 'namespace_deleted': False,
                       'open_loop_arrival_replay': False, 'performance_result': False}, 'steps': steps}
