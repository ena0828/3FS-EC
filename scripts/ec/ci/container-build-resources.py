#!/usr/bin/env python3
"""Read-only resource admission for the explicit local container build profile."""
import os
from pathlib import Path, PurePosixPath
import re


GIB = 1024 ** 3
# v1 uses a page-rounded LONG_MAX sentinel for an unconstrained memory cgroup.
V1_UNLIMITED = 1 << 60


def require(value, message):
    if not value:
        raise ValueError(message)


def number(path, negative=False):
    raw = path.read_text(encoding='utf-8').strip()
    require(re.fullmatch(r'-?[0-9]+' if negative else r'[0-9]+', raw), 'invalid cgroup integer: ' + str(path))
    return int(raw)


def mount_path(raw):
    # mountinfo escapes whitespace and backslashes with octal sequences.
    value = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), raw)
    path = PurePosixPath(value)
    require(path.is_absolute() and '..' not in path.parts, 'invalid cgroup mount path')
    return path


def map_controller(controller, membership, mountinfo, pid):
    entries = []
    for line in membership.splitlines():
        fields = line.split(':', 2)
        require(len(fields) == 3, 'malformed cgroup membership')
        if (controller == 'unified' and fields[:2] == ['0', '']) or controller in fields[1].split(','):
            entries.append(mount_path(fields[2]))
    require(len(entries) == 1, 'missing or ambiguous ' + controller + ' membership')
    member = entries[0]
    candidates = []
    for line in mountinfo.splitlines():
        sides = line.split(' - ')
        require(len(sides) == 2, 'malformed mountinfo')
        before, after = sides[0].split(), sides[1].split()
        require(len(before) >= 6 and len(after) >= 3, 'malformed mountinfo fields')
        version = 2 if after[0] == 'cgroup2' else 1 if after[0] == 'cgroup' else 0
        if not ((controller == 'unified' and version == 2) or
                (controller != 'unified' and version == 1 and controller in after[2].split(','))):
            continue
        root, mounted = mount_path(before[3]), Path(str(mount_path(before[4])))
        # Either the absolute hierarchy path is visible, or membership is
        # relative to a cgroup namespace root. Verify the actual leaf with PID
        # membership in both cases; never assume a mountpoint is our cgroup.
        relatives = []
        if member == root or root in member.parents:
            relatives.append(member.relative_to(root))
        if root != PurePosixPath('/'):
            relatives.append(member.relative_to('/'))
        base = mounted.resolve(strict=True)
        require(base == mounted, 'cgroup mountpoint is not canonical')
        matched = set()
        for relative in relatives:
            leaf = base.joinpath(*relative.parts)
            if not leaf.is_dir():
                continue
            resolved = leaf.resolve(strict=True)
            require(resolved == leaf and (leaf == base or base in leaf.parents), 'cgroup path escapes mount')
            procs = (leaf / 'cgroup.procs').read_text(encoding='utf-8').split()
            require(all(item.isdigit() for item in procs), 'invalid cgroup process membership')
            if str(pid) in procs:
                matched.add(leaf)
        for leaf in matched:
            candidates.append({'controller': controller, 'version': version, 'mount_root': str(root),
                               'mountpoint': str(base), 'membership': str(member), 'leaf': str(leaf),
                               'pid_membership_verified': True})
    require(len(candidates) == 1, 'unverified or ambiguous ' + controller + ' mount/membership mapping')
    return candidates[0]


def ancestors(mapping):
    base, current = Path(mapping['mountpoint']), Path(mapping['leaf'])
    result = []
    while True:
        require(len(result) < 64, 'cgroup ancestor bound exceeded')
        result.append(current)
        if current == base:
            return result
        current = current.parent


def observe_groups(membership, mountinfo, pid):
    unified = any(row.startswith('0::') for row in membership.splitlines())
    # A hybrid hierarchy with v1 memory/cpu must use those actual controllers.
    v1 = set().union(*(set(row.split(':', 2)[1].split(',')) & {'cpu', 'memory'}
                      for row in membership.splitlines() if len(row.split(':', 2)) == 3))
    require(not v1 or v1 == {'cpu', 'memory'}, 'split v1/v2 resource controllers are unsupported')
    mappings = [map_controller('unified', membership, mountinfo, pid)] if unified and not v1 else [
        map_controller(name, membership, mountinfo, pid) for name in ('cpu', 'memory')]
    rows = []
    for mapping in mappings:
        for path in ancestors(mapping):
            row = {'path': str(path), 'controller': mapping['controller'], 'version': mapping['version'],
                   'cpu_quota': None, 'cpu_period': None, 'memory_limit': None, 'memory_usage': None,
                   'hierarchical_memory_limit': None}
            if mapping['version'] == 1:
                if mapping['controller'] == 'cpu':
                    quota, period = number(path / 'cpu.cfs_quota_us', True), number(path / 'cpu.cfs_period_us')
                    require((quota == -1 or quota > 0) and period > 0, 'invalid v1 CPU bandwidth')
                    row.update(cpu_quota=None if quota == -1 else quota, cpu_period=period)
                else:
                    limit, usage = number(path / 'memory.limit_in_bytes'), number(path / 'memory.usage_in_bytes')
                    stats = {}
                    for line in (path / 'memory.stat').read_text(encoding='utf-8').splitlines():
                        fields = line.split()
                        require(len(fields) == 2 and fields[1].isdigit() and fields[0] not in stats,
                                'invalid v1 memory.stat')
                        stats[fields[0]] = int(fields[1])
                    hierarchy = stats.get('hierarchical_memory_limit')
                    require(hierarchy is not None and hierarchy > 0 and limit > 0, 'missing hierarchical memory limit')
                    row.update(memory_limit=None if limit >= V1_UNLIMITED else limit, memory_usage=usage,
                               hierarchical_memory_limit=None if hierarchy >= V1_UNLIMITED else hierarchy)
            else:
                # Missing max files are allowed only on the visible hierarchy
                # root, where the kernel does not expose parent-imposed limits.
                for name in ('cpu.max', 'memory.max'):
                    require((path / name).is_file() or str(path) == mapping['mountpoint'],
                            'missing container controller limit: ' + name)
                if (path / 'cpu.max').exists():
                    quota, period = (path / 'cpu.max').read_text(encoding='utf-8').split()
                    require(period.isdigit() and int(period) > 0 and
                            (quota == 'max' or quota.isdigit() and int(quota) > 0), 'invalid v2 CPU bandwidth')
                    row.update(cpu_quota=None if quota == 'max' else int(quota), cpu_period=int(period))
                if (path / 'memory.max').exists():
                    limit = (path / 'memory.max').read_text(encoding='utf-8').strip()
                    require(limit == 'max' or limit.isdigit() and int(limit) > 0, 'invalid v2 memory limit')
                    row.update(memory_limit=None if limit == 'max' else int(limit),
                               memory_usage=number(path / 'memory.current'))
            rows.append(row)
    return {'mappings': mappings, 'ancestors': rows}


def resource_plan(jobs, memory, affinity, observation):
    require(type(jobs) is int and jobs > 0, 'container build jobs must be a positive integer')
    require(type(affinity) is int and affinity > 0, 'CPU affinity unavailable')
    total, available = memory['MemTotal'], memory['MemAvailable']
    require(type(total) is int and type(available) is int and 0 <= available <= total, 'invalid host memory')
    cpu_limits, limits, headrooms = [], [], []
    for row in observation['ancestors']:
        if row['cpu_quota'] is not None:
            cpu_limits.append(row['cpu_quota'] // row['cpu_period'])
        for name in ('memory_limit', 'hierarchical_memory_limit'):
            if row[name] is not None:
                limits.append(row[name])
                headrooms.append(max(0, row[name] - row['memory_usage']))
    require(cpu_limits and limits, 'container build requires visible finite CPU and memory constraints')
    cpus, headroom = min(affinity, *cpu_limits), min(available, *headrooms)
    by_memory = max(0, (headroom - 4 * GIB) // (3 * GIB))
    capacity = min(cpus, by_memory)
    admitted = jobs <= capacity
    return {'schema': 1, 'profile': 'local-container-build-only',
            'status': 'admitted' if admitted else 'insufficient-container-resources',
            'requested_jobs': jobs, 'effective_jobs': jobs if admitted else None,
            'affinity_cpus': affinity, 'visible_cpu_budget_limit': cpus,
            'host_memory_bytes': memory, 'visible_memory_limit_bytes': min(limits),
            'visible_memory_headroom_bytes': headroom, 'admission_job_capacity': capacity,
            'admission_estimate': {'bytes_per_job': 3 * GIB, 'reserve_bytes': 4 * GIB},
            'cgroup_observation': observation, 'pools': {'compile': jobs, 'link': 1},
            'nested_jobs': {'cmake_environment': 1, 'cargo': 1, 'make': 1, 'jemalloc': 1, 'arrow': 1},
            'scope': 'build admission estimate only; hidden ancestors and sibling competition unknown; '
                     'v1 hierarchical limit minus visible usage is not guaranteed free memory; '
                     'no peak RSS, completion-time or acceptance guarantee',
            'acceptance_executed': False}


def observe(jobs, memory):
    membership = Path('/proc/self/cgroup').read_text(encoding='utf-8')
    groups = observe_groups(membership, Path('/proc/self/mountinfo').read_text(encoding='utf-8'), os.getpid())
    # Refuse migration during the observation rather than mixing two budgets.
    require(Path('/proc/self/cgroup').read_text(encoding='utf-8') == membership, 'cgroup membership changed')
    return resource_plan(jobs, memory, len(os.sched_getaffinity(0)), groups)
