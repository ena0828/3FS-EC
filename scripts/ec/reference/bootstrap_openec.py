"""Fresh official inputs and a single OpenEC RSPIPE experiment; no system services."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import sys
import time
import urllib.request

from runtime_common import Owned, check_build, new_json, reference_lease, sha
import prepare_reference
import prepare_redis
import run_openec

HERE = Path(__file__).resolve().parent
LIBRARIES = ('libhiredis', 'libgf_complete', 'libisal')


@contextmanager
def arguments(values):
    previous = sys.argv
    sys.argv = [previous[0], *map(str, values)]
    try:
        yield
    finally:
        sys.argv = previous


def resources(path):
    if sys.platform != 'linux' or os.uname().machine != 'x86_64' or os.geteuid() == 0:
        raise ValueError('ordinary Linux x86-64 user required')
    flags = [set(line.partition(':')[2].split()) for line in Path('/proc/cpuinfo').read_text().splitlines()
             if line.startswith('flags')]
    if not flags or any(not {'sse4_2', 'avx', 'pclmulqdq'} <= row for row in flags):
        raise ValueError('upstream SSE4.2/AVX/PCLMUL instruction support required on every CPU')
    memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemAvailable:'))) * 1024
    free = shutil.disk_usage(path).free
    if memory < 3 * 1024**3 or free < 5 * 1024**3:
        raise ValueError('at least 3 GiB available RAM and 5 GiB free disk required')
    if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < 4096:
        raise ValueError('nofile soft limit must be at least 4096')
    return {'uname': list(os.uname()), 'uid': os.geteuid(), 'memory_available': memory,
            'disk_available': free, 'nofile': list(resource.getrlimit(resource.RLIMIT_NOFILE)),
            'instruction_flags_checked': ['sse4_2', 'avx', 'pclmulqdq']}


def owned_work(path, fresh):
    if not path.is_absolute() or path != path.resolve() or any(ch in str(path) for ch in '\r\n\0,'):
        raise ValueError('unredirected absolute work path required')
    parent = path.parent
    if parent.stat().st_uid != os.geteuid():
        raise ValueError('work parent must belong to the ordinary runner user')
    if fresh:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('exclusive private owned work directory required')


def download(item, destination):
    if not item['url'].startswith(('https://archive.ubuntu.com/ubuntu/pool/',
                                    'https://codeload.github.com/ukulililixl/openec/tar.gz/',
                                    'https://download.redis.io/releases/')):
        raise ValueError('download URL is outside the explicit official inputs')
    # Fixed hashes authenticate content; a changed upstream archive fails closed.
    h = hashlib.sha256()
    count = 0
    request = urllib.request.Request(item['url'], headers={'User-Agent': 'ec-openec-fixed-input/1'})
    with urllib.request.urlopen(request, timeout=60) as response, destination.open('xb') as output:
        if response.status != 200 or response.url != item['url']:
            raise ValueError('unexpected status or redirect for fixed official input')
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            count += len(chunk)
            if count > item['size']:
                raise ValueError('fixed download exceeds locked size')
            output.write(chunk)
            h.update(chunk)
    if count != item['size'] or h.hexdigest() != item['sha256']:
        raise ValueError('fixed official input digest/size mismatch')
    return {'url': item['url'], 'path': str(destination), 'bytes': count, 'sha256': h.hexdigest()}


def prepare(work):
    host = resources(work.parent)
    owned_work(work, True)
    lock = json.loads((HERE / 'downloads.json').read_text())
    inputs = json.loads((HERE / 'inputs.json').read_text())['openec']
    if lock['openec']['sha256'] != inputs['archive_sha256']:
        raise ValueError('source archive locks disagree')
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(('GIT_', 'CMAKE_', 'MAKEFLAGS', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'LD_PRELOAD')):
            del env[key]
    env.update(CC='/usr/bin/gcc', CXX='/usr/bin/g++', CMAKE_BUILD_PARALLEL_LEVEL='1',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    runner = Owned(work, env)
    runner.deadline = time.monotonic() + 1500
    proof = {'schema': 1, 'status': 'failed', 'phase': 'downloads', 'host': host,
             'input_lock_sha256': sha(HERE / 'inputs.json'), 'download_lock_sha256': sha(HERE / 'downloads.json'),
             'commit': inputs['commit'], 'tree': inputs['tree'], 'downloads': [], 'packages': [],
             'source_scripts': {p.name: sha(p) for p in sorted(HERE.iterdir()) if p.is_file()},
             'system_package_install': False, 'maintainer_scripts_executed': False}
    try:
        packages = work / 'packages'
        packages.mkdir(mode=0o700)
        prefix = work / 'prefix'
        prefix.mkdir(mode=0o700)
        for index, item in enumerate(lock['packages']):
            runner.check_stop()
            archive = packages / item['url'].rsplit('/', 1)[-1]
            proof['downloads'].append(download(item, archive))
            runner.command('package-metadata-' + str(index), ['dpkg-deb', '-f', archive,
                           'Package', 'Version', 'Architecture'], work, 30)
            metadata = dict(line.split(': ', 1) for line in (work / ('package-metadata-' + str(index) + '.log')).read_text().splitlines())
            if metadata != {'Package': item['package'], 'Version': item['version'], 'Architecture': item['architecture']}:
                raise ValueError('deb identity differs from fixed lock')
            runner.command('extract-package-' + str(index), ['dpkg-deb', '-x', archive, prefix], work, 30)
            proof['packages'].append(dict(item, metadata=metadata))
        reference = work / 'reference'
        archive = reference / inputs['archive']
        archive.parent.mkdir(parents=True, mode=0o700)
        proof['downloads'].append(download(lock['openec'], archive))
        redis_archive = work / 'redis-7.2.11.tar.gz'
        proof['downloads'].append(download(lock['redis'], redis_archive))
        proof['phase'] = 'prepare-sources'
        # No daemon is active here. Existing preparers verify every archive/patch and
        # preserve upstream LICENSE/COPYING plus private package copyright files.
        with arguments(['--project', 'openec', '--reference-root', reference, '--output', work / 'prepared']):
            prepare_reference.main()
        with arguments(['--archive', redis_archive, '--output', work / 'redis']):
            prepare_redis.main()
        proof['phase'] = 'build-private-redis'
        runner.command('build-redis', ['make', '-C', work / 'redis/source', '-j1',
                                     'MALLOC=libc', 'BUILD_TLS=no', 'redis-server'], work, 900)
        binary = work / 'redis/source/src/redis-server'
        runner.command('redis-version', [binary, '--version'], work, 30)
        version = (work / 'redis-version.log').read_text().strip()
        if not re.search(r'\bv=7\.2\.11\b', version):
            raise ValueError('private Redis version mismatch')
        proof['redis'] = {'path': str(binary), 'sha256': sha(binary), 'version_output': version}
        proof['prepared_sha256'] = sha(work / 'prepared/prepared.json')
        proof['status'] = 'prepared-redis-built-openec-not-built'
    except BaseException as exc:
        proof['error_type'] = type(exc).__name__
        proof['error'] = str(exc)[:512]
    finally:
        if runner.stop_requested:
            proof['status'] = 'interrupted'
        if not runner.stop():
            proof['status'] = 'failed-cleanup'
        proof['events'] = runner.events
        proof['cleanup_errors'] = runner.cleanup_errors
        new_json(work / 'bootstrap.json', proof)
    print(json.dumps({'phase': proof['phase'], 'status': proof['status'],
                      'error_type': proof.get('error_type'), 'error': proof.get('error'),
                      'bootstrap_sha256': sha(work / 'bootstrap.json')}))
    return 0 if proof['status'] == 'prepared-redis-built-openec-not-built' else 1


def linked_providers(work, build):
    lib = (work / 'prefix/usr/lib/x86_64-linux-gnu').resolve()
    expected = {name: (lib / (name + '.so')).resolve(strict=True) for name in LIBRARIES}
    result = []
    all_matched = set()
    for index, binary in enumerate(build['binaries']):
        logfile = work / 'openec-build' / ('linked-libraries-' + str(index) + '.log')
        if not any(row['path'] == str(logfile) and row['sha256'] == sha(logfile) for row in build['build_logs']):
            raise ValueError('ldd log is not bound to the actual build')
        text = logfile.read_text()
        if 'not found' in text:
            raise ValueError('unresolved library in actual OpenEC build')
        providers = []
        matched = set()
        for line in text.splitlines():
            match = re.match(r'\s*(\S+)\s+=>\s+(/\S+)\s+\(', line)
            direct = re.match(r'\s*(/\S+)\s+\(', line)
            if not match and not direct:
                if re.match(r'\s*linux-vdso\.so\.\d+\s+\(', line):
                    continue  # Kernel virtual DSO has no file to hash.
                raise ValueError('unrecognized ldd provider line')
            soname = match[1] if match else Path(direct[1]).name
            path = Path(match[2] if match else direct[1]).resolve(strict=True)
            for name, locked_path in expected.items():
                if soname.startswith(name + '.so'):
                    if name in matched or path != locked_path or not path.is_relative_to(lib):
                        raise ValueError('OpenEC resolved an unexpected private library provider')
                    matched.add(name)
            providers.append({'soname': soname, 'path': str(path), 'sha256': sha(path)})
        # Static-library extraction can leave a client without unused coding DSOs.
        # Every present provider must be private; the three-program closure must
        # actually contain all three dependencies, not merely have them on disk.
        all_matched.update(matched)
        result.append({'binary': binary, 'providers': providers, 'ldd_log_sha256': sha(logfile)})
    if all_matched != set(expected):
        raise ValueError('three-program closure did not use all locked private libraries')
    return result


def run(work):
    owned_work(work, False)
    host = resources(work)
    prepared = json.loads((work / 'bootstrap.json').read_text())
    if prepared['status'] != 'prepared-redis-built-openec-not-built':
        raise ValueError('successful private bootstrap required')
    for name, digest in prepared['source_scripts'].items():
        if sha(HERE / name) != digest:
            raise ValueError('adapter source changed after bootstrap')
    if sha(work / 'prepared/prepared.json') != prepared['prepared_sha256']:
        raise ValueError('prepared input changed after bootstrap')
    record = work / 'openec-build/build-record.json'
    build, binaries = check_build(record, 'openec')
    if set(binaries) != {'OECCoordinator', 'OECAgent', 'OECClient'} or build.get('cleanup_errors'):
        raise ValueError('exact successful three-program build and cleanup required')
    providers = linked_providers(work, build)
    redis = Path(prepared['redis']['path'])
    if redis != work / 'redis/source/src/redis-server' or sha(redis) != prepared['redis']['sha256']:
        raise ValueError('private Redis changed before runtime')
    proof = {'schema': 1, 'status': 'failed', 'host': host, 'project': 'openec', 'code': 'RSPIPE',
             'bootstrap_sha256': sha(work / 'bootstrap.json'), 'build_record_sha256': sha(record),
             'redis_before_sha256': sha(redis), 'dynamic_providers': providers,
             'scope': 'single missing file; one host; no process-failure or performance claim'}
    code = 1
    try:
        # Same process, so the existing runner owns the only daemon handles and
        # signal/finally path. No outer supervisor can orphan nested new sessions.
        with arguments(['--build-record', record, '--redis-server', redis, '--run-root', work / 'runtime', '--code', 'RSPIPE']):
            code = run_openec.main()
        result_path = work / 'runtime/result.json'
        result = json.loads(result_path.read_text())
        proof['runtime_result_sha256'] = sha(result_path)
        proof['runtime_exitcode'] = code
        proof['checks'] = result['checks']
        proof['input_sha256'] = result.get('input', {}).get('sha256')
        rebuilt = next((row for row in result['checks'] if row['stage'] == 'all-postrepair-objects'), None)
        proof['rebuilt_object0_sha256'] = rebuilt['files'][0]['sha256'] if rebuilt else None
        proof['helper_compute_participants'] = result.get('helper_compute_participants', [])
        proof['helper_persist_participants'] = result.get('helper_persist_participants', [])
        starts = [e for e in result['events'] if e['event'] == 'started']
        stops = [e for e in result['events'] if e['event'] == 'stopped']
        proof['owned_started'] = len(starts)
        proof['owned_joined'] = len(stops)
        proof['forced_kills'] = [e['name'] for e in stops if e['forced_kill']]
        proof['cleanup_errors'] = result['cleanup_errors']
        foreground = {'write', 'read-healthy', 'read-degraded', 'start-repair', 'read-after-repair'}
        proof['failed_commands'] = [{'name': row['name'], 'returncode': row['returncode']}
                                    for row in stops if row['name'] in foreground and row['returncode'] != 0]
        if {(e['name'], e['pid']) for e in starts} != {(e['name'], e['pid']) for e in stops} or len(starts) != len(stops):
            raise ValueError('runtime did not record a join for every owned process')
        if any(e['returncode'] is None for e in stops):
            raise ValueError('runtime has unknown process exit')
        # Recheck the same complete build inventory after all runtime children join.
        after, _ = check_build(record, 'openec')
        if after != build or sha(record) != proof['build_record_sha256']:
            raise ValueError('build evidence changed during runtime')
        if sha(redis) != proof['redis_before_sha256']:
            raise ValueError('private Redis changed during runtime')
        for group in providers:
            for library in group['providers']:
                if sha(library['path']) != library['sha256']:
                    raise ValueError('dynamic provider changed during runtime')
        for name, digest in prepared['source_scripts'].items():
            if sha(HERE / name) != digest:
                raise ValueError('adapter source changed during runtime')
        proof['redis_after_sha256'] = sha(redis)
        proof['post_runtime_inputs_unchanged'] = True
        proof['status'] = ('passed-functional-runtime' if code == 0 and
                           result['status'] == 'passed-functional-runtime' and not result['cleanup_errors'] else 'failed')
        if 'error' in result:
            proof['error'] = result['error'][:512]
    except BaseException as exc:
        proof['error_type'] = type(exc).__name__
        proof['error'] = str(exc)[:512]
    finally:
        new_json(work / 'acceptance.json', proof)
    print(json.dumps({key: proof.get(key) for key in ('status', 'project', 'code', 'runtime_exitcode',
        'owned_started', 'owned_joined', 'forced_kills', 'post_runtime_inputs_unchanged',
        'failed_commands', 'helper_compute_participants', 'helper_persist_participants',
        'input_sha256', 'rebuilt_object0_sha256', 'error_type', 'error')}))
    print(json.dumps({'confirmed_check_count': len(proof.get('checks', [])),
                      'confirmed_stages': [row['stage'] for row in proof.get('checks', [])]}))
    if proof['status'] != 'passed-functional-runtime':
        # Only logs generated by this fixed experiment; never environment/configs.
        # Replace non-ASCII/control bytes, then JSON-escape the retained text:
        # at most 3 * 1024 raw bytes and < 7 KiB total JSON. These are not evidence
        # that a failed or missing cleanup receipt completed normally.
        failed = proof.get('failed_commands', [])
        command = failed[-1]['name'] if failed else None
        allowed = {'write', 'read-healthy', 'read-degraded', 'start-repair', 'read-after-repair'}
        names = ([command] if command in allowed else []) + ['coordinator', 'agent-01']
        for name in names:
            path = work / 'runtime' / (name + '.log')
            if path.is_file() and not path.is_symlink():
                with path.open('rb') as stream:
                    stream.seek(max(0, path.stat().st_size - 1024))
                    text = stream.read(1024).decode(errors='replace')
                    tail = ''.join(ch if ch in '\r\n\t' or ' ' <= ch <= '~' else '?' for ch in text)
                    print(json.dumps({'diagnostic_log': name, 'tail': tail}))
    print(json.dumps({'acceptance_sha256': sha(work / 'acceptance.json'),
                      'runtime_result_sha256': proof.get('runtime_result_sha256'),
                      'build_record_sha256': proof['build_record_sha256']}))
    return 0 if proof['status'] == 'passed-functional-runtime' else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare', 'run'])
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    with reference_lease():
        return prepare(args.work) if args.phase == 'prepare' else run(args.work)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({'status': 'preflight-or-evidence-failure', 'error_type': type(exc).__name__, 'error': str(exc)[:512]}))
        sys.exit(2)
