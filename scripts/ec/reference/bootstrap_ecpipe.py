"""Private ECPipe standalone/basicSingle cold start; never an in-place block repair.

Reuse current OpenEC-tested ownership, extraction and package/Redis download
helpers. No source vendor, global services, retries, or 3FS compilation.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import time
import urllib.request

from bootstrap_openec import arguments, download, owned_work, resources
from prepare_reference import extract
import prepare_redis
import run_ecpipe
from runtime_common import Owned, check_build, new_json, reference_lease, sha

HERE = Path(__file__).resolve().parent
LOCK = HERE / 'ecpipe-inputs.json'
PROGRAMS = {'ECCoordinator', 'ECHelper', 'ECPipeClient'}


def inputs():
    value = json.loads(LOCK.read_text())
    for name, digest in value['shared_modules'].items():
        if sha(HERE / name) != digest:
            raise ValueError('shared module differs from tested parent: ' + name)
    return value


def environment(prefix=None):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(('GIT_', 'CMAKE_', 'MAKEFLAGS', 'CFLAGS', 'CXXFLAGS',
                           'LDFLAGS', 'LD_PRELOAD', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH',
                           'LIBRARY_PATH', 'LD_LIBRARY_PATH')):
            del env[key]
    env.update(CC='/usr/bin/gcc', CXX='/usr/bin/g++', MAKEFLAGS='-j1',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    if prefix:
        env.update(dependency_environment(prefix))
    return env


def dependency_environment(prefix):
    return {'C_INCLUDE_PATH': str(prefix / 'usr/include'),
            'CPLUS_INCLUDE_PATH': str(prefix / 'usr/include'),
            'LIBRARY_PATH': str(prefix / 'usr/lib/x86_64-linux-gnu'),
            'LD_LIBRARY_PATH': str(prefix / 'usr/lib/x86_64-linux-gnu')}


def download_source(cfg, destination):
    url = 'https://codeload.github.com/ukulililixl/ecpipe-v1.1/tar.gz/' + cfg['commit']
    if cfg['archive_url'] != url or cfg['commit'] != '99e199dddbf4bd803480aa75c1f518579f01f7cb':
        raise ValueError('unexpected fixed ECPipe source')
    request = urllib.request.Request(url, headers={'User-Agent': 'ec-ecpipe-fixed-input/1'})
    total, digest = 0, hashlib.sha256()
    with urllib.request.urlopen(request, timeout=60) as response, destination.open('xb') as out:
        if response.status != 200 or response.url != url:
            raise ValueError('unexpected source status/redirect')
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > cfg['archive_size']:
                raise ValueError('source exceeds locked size')
            out.write(chunk)
            digest.update(chunk)
    if total != cfg['archive_size'] or digest.hexdigest() != cfg['archive_sha256']:
        raise ValueError('fixed ECPipe archive mismatch')
    return {'url': url, 'path': str(destination), 'bytes': total, 'sha256': digest.hexdigest()}


def script_lock():
    return {path.name: sha(path) for path in sorted(HERE.iterdir()) if path.is_file()}


def check_bootstrap(work):
    inputs()
    record = json.loads((work / 'bootstrap.json').read_text())
    if record['status'] != 'prepared-redis-built-ecpipe-not-built':
        raise ValueError('successful ECPipe bootstrap required')
    if record['source_scripts'] != script_lock():
        raise ValueError('adapter sources changed after bootstrap')
    if sha(work / 'prepared/prepared.json') != record['prepared_sha256']:
        raise ValueError('prepared source record changed')
    redis = work / 'redis/source/src/redis-server'
    if str(redis) != record['redis']['path'] or sha(redis) != record['redis']['sha256']:
        raise ValueError('private Redis changed')
    return record


def tails(folder, names):
    # Fixed experimental logs only; at most three 1024-byte tails, JSON escaped.
    for name in names[:3]:
        path = folder / (name + '.log')
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as f:
                f.seek(max(0, path.stat().st_size - 1024))
                raw = f.read(1024).decode(errors='replace')
            text = ''.join(c if c in '\r\n\t' or ' ' <= c <= '~' else '?' for c in raw)
            print(json.dumps({'diagnostic_log': name, 'tail': text}))


def apply_edits(source, cfg, private_diff):
    """Apply our new lines only after exact whole-file and original-span checks.

    The upstream-context diff is generated only inside the private runtime tree.
    Neither it nor the downloaded source is uploaded by the workflow.
    """
    recipe_path = HERE / cfg['recipes']['path']
    if sha(recipe_path) != cfg['recipes']['sha256']:
        raise ValueError('fixed edit recipe changed')
    recipes = json.loads(recipe_path.read_text())
    if (recipes.get('schema') != 1 or recipes.get('upstream_commit') != cfg['commit'] or
            [step['name'] for step in recipes['steps']] != [step['name'] for step in cfg['edit_steps']]):
        raise ValueError('edit step identity mismatch')
    diffs = []
    for step, locked in zip(recipes['steps'], cfg['edit_steps']):
        if [{'path': f['path'], 'sha256': f['after_sha256']} for f in step['files']] != locked['after']:
            raise ValueError('edit result lock mismatch')
        for row in step['files']:
            target = source / row['path']
            if target.is_symlink() or not target.resolve().is_relative_to(source.resolve()):
                raise ValueError('edit path escapes private source')
            before = target.read_bytes()
            if hashlib.sha256(before).hexdigest() != row['before_sha256']:
                raise ValueError('edit input file mismatch: ' + row['path'])
            lines = before.splitlines(keepends=True)
            last_end = 0
            for edit in row['edits']:
                first, end = edit['start_line_0'], edit['end_line_0_exclusive']
                if not 0 <= last_end <= first <= end <= len(lines):
                    raise ValueError('invalid/overlapping edit span')
                if hashlib.sha256(b''.join(lines[first:end])).hexdigest() != edit['before_sha256']:
                    raise ValueError('edit span mismatch')
                last_end = end
            for edit in reversed(row['edits']):
                lines[edit['start_line_0']:edit['end_line_0_exclusive']] = [edit['replacement'].encode('utf-8')]
            after = b''.join(lines)
            if hashlib.sha256(after).hexdigest() != row['after_sha256']:
                raise ValueError('edit result differs from fixed patched bytes')
            target.write_bytes(after)
            if sha(target) != row['after_sha256']:
                raise ValueError('edit write readback mismatch')
            diffs.extend(difflib.unified_diff(before.decode().splitlines(keepends=True),
                         after.decode().splitlines(keepends=True),
                         fromfile='a/' + row['path'], tofile='b/' + row['path']))
    with private_diff.open('x', encoding='utf-8', newline='\n') as out:
        out.writelines(diffs)


def prepare_source(source, cfg, prepared):
    apply_edits(source, cfg, prepared / 'source-edits.private.patch')
    rows = [{'relative': p.relative_to(source).as_posix(), 'sha256': sha(p)}
            for p in sorted(source.rglob('*')) if p.is_file()]
    new_json(prepared / 'prepared.json', {'schema': 1, 'project': 'ecpipe',
             'status': 'prepared-not-built', 'original_commit': cfg['commit'],
             'archive_sha256': cfg['archive_sha256'], 'edit_steps': cfg['edit_steps'],
             'recipes_sha256': cfg['recipes']['sha256'], 'sources': rows})


def prepare(work):
    cfg = inputs()
    host = resources(work.parent)
    owned_work(work, True)
    packages_lock = json.loads((HERE / 'downloads.json').read_text())
    runner = Owned(work, environment())
    runner.deadline = time.monotonic() + 1500
    record = {'schema': 1, 'status': 'failed', 'phase': 'packages', 'host': host,
              'project': 'ecpipe', 'commit': cfg['commit'], 'tree': cfg['tree'],
              'input_lock_sha256': sha(LOCK), 'shared_download_lock_sha256': sha(HERE / 'downloads.json'),
              'source_scripts': script_lock(), 'downloads': [], 'packages': [],
              'maintainer_scripts_executed': False, 'system_package_install': False}
    try:
        packages, prefix = work / 'packages', work / 'prefix'
        packages.mkdir(mode=0o700)
        prefix.mkdir(mode=0o700)
        for i, item in enumerate(packages_lock['packages']):
            runner.check_stop()
            archive = packages / item['url'].rsplit('/', 1)[-1]
            record['downloads'].append(download(item, archive))
            label = 'package-metadata-' + str(i)
            runner.command(label, ['/usr/bin/dpkg-deb', '-f', archive,
                                   'Package', 'Version', 'Architecture'], work, 30)
            metadata = dict(line.split(': ', 1) for line in (work / (label + '.log')).read_text().splitlines())
            if metadata != {key: item[key.lower()] for key in ('Package', 'Version', 'Architecture')}:
                raise ValueError('package identity differs from fixed lock')
            runner.command('extract-package-' + str(i), ['/usr/bin/dpkg-deb', '-x', archive, prefix], work, 30)
            record['packages'].append(dict(item, metadata=metadata))
        record['phase'] = 'source-and-edits'
        archive = work / 'ecpipe-source.tar.gz'
        record['downloads'].append(download_source(cfg, archive))
        prepared = work / 'prepared'
        prepared.mkdir(mode=0o700)
        source = prepared / 'source'
        extract(archive, source, cfg['prefix'])
        prepare_source(source, cfg, prepared)
        record['prepared_sha256'] = sha(prepared / 'prepared.json')
        record['phase'] = 'private-redis'
        redis_archive = work / 'redis-7.2.11.tar.gz'
        record['downloads'].append(download(packages_lock['redis'], redis_archive))
        with arguments(['--archive', redis_archive, '--output', work / 'redis']):
            prepare_redis.main()
        runner.command('build-redis', ['/usr/bin/make', '-C', work / 'redis/source', '-j1',
                                     'MALLOC=libc', 'BUILD_TLS=no', 'redis-server'], work, 900)
        redis = work / 'redis/source/src/redis-server'
        runner.command('redis-version', [redis, '--version'], work, 30)
        version = (work / 'redis-version.log').read_text().strip()
        if not re.search(r'\bv=7\.2\.11\b', version):
            raise ValueError('private Redis version mismatch')
        record['redis'] = {'path': str(redis), 'sha256': sha(redis), 'version_output': version}
        record['status'] = 'prepared-redis-built-ecpipe-not-built'
    except BaseException as exc:
        record.update(error_type=type(exc).__name__, error=str(exc)[:512])
    finally:
        if runner.stop_requested:
            record['status'] = 'interrupted'
        if not runner.stop():
            record['status'] = 'failed-cleanup'
        record.update(events=runner.events, cleanup_errors=runner.cleanup_errors)
        new_json(work / 'bootstrap.json', record)
    print(json.dumps({key: record.get(key) for key in ('phase', 'status', 'error_type', 'error')}))
    print(json.dumps({'bootstrap_sha256': sha(work / 'bootstrap.json')}))
    if record['status'] != 'prepared-redis-built-ecpipe-not-built':
        tails(work, ['build-redis'])
        return 1
    return 0


def hiredis_binding(source, prefix, cfg):
    patches = [p for p in cfg['edit_steps'] if p['name'] == 'ecpipe-hiredis-headers']
    if len(patches) != 1:
        raise ValueError('missing unique ECPipe hiredis edit')
    for item in patches[0]['after']:
        if sha(source / item['path']) != item['sha256']:
            raise ValueError('active hiredis include differs')
    binding = cfg['hiredis_binding']
    header = (prefix / binding['header_relative']).resolve(strict=True)
    library = (prefix / binding['library_link_relative']).resolve(strict=True)
    if not header.is_relative_to(prefix) or not library.is_relative_to(prefix):
        raise ValueError('private hiredis escapes prefix')
    if sha(header) != binding['header_sha256'] or sha(library) != binding['library_sha256']:
        raise ValueError('hiredis header/library ABI pair differs')
    version = tuple(int(re.search(r'^#define HIREDIS_' + part + r'\s+(\d+)\s*$',
                                 header.read_text(), re.M)[1]) for part in ('MAJOR', 'MINOR', 'PATCH'))
    if version != (1, 2, 0):
        raise ValueError('hiredis ABI must be 1.2.0')
    return {'header': {'path': str(header), 'sha256': sha(header)},
            'library': {'path': str(library), 'sha256': sha(library)},
            'version': '1.2.0', 'legacy_archive_linked': False, 'edit': patches[0]}


def linked_providers(folder, binaries, prefix):
    lib = (prefix / 'usr/lib/x86_64-linux-gnu').resolve()
    expected = {name: (lib / (name + '.so')).resolve(strict=True)
                for name in ('libhiredis', 'libgf_complete', 'libisal')}
    result, used = [], set()
    for i, binary in enumerate(binaries):
        path = folder / ('linked-libraries-' + str(i) + '.log')
        providers, found = [], set()
        for line in path.read_text().splitlines():
            match = re.match(r'\s*(\S+)\s+=>\s+(/\S+)\s+\(', line)
            direct = re.match(r'\s*(/\S+)\s+\(', line)
            if not match and not direct:
                if re.match(r'\s*linux-vdso\.so\.\d+\s+\(', line):
                    continue
                raise ValueError('unresolved/unrecognized ldd provider')
            soname = match[1] if match else Path(direct[1]).name
            provider = Path(match[2] if match else direct[1]).resolve(strict=True)
            for name, locked in expected.items():
                if soname.startswith(name + '.so'):
                    if name in found or provider != locked or not provider.is_relative_to(lib):
                        raise ValueError('unexpected private library provider')
                    found.add(name)
            providers.append({'soname': soname, 'path': str(provider), 'sha256': sha(provider)})
        if 'libhiredis' not in found:
            raise ValueError('each actual ECPipe executable must use private hiredis')
        used.update(found)
        result.append({'binary': str(binary), 'providers': providers, 'ldd_log_sha256': sha(path)})
    if not {'libhiredis', 'libgf_complete'} <= used:
        raise ValueError('ECPipe closure did not use hiredis and GF-Complete')
    return result


def verify_prepared_sources(source, prepared):
    """Before make's wildcard expansion, require exactly the prepared file set."""
    expected = {}
    for row in prepared['sources']:
        relative = row['relative']
        path = PurePosixPath(relative)
        if (path.is_absolute() or '..' in path.parts or '\\' in relative or
                path.as_posix() != relative or relative in expected):
            raise ValueError('invalid or duplicate prepared source path')
        expected[relative] = row['sha256']
    actual = {}
    resolved = source.resolve(strict=True)
    for path in [source, *source.rglob('*')]:
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400 or
                not path.resolve(strict=True).is_relative_to(resolved)):
            raise ValueError('linked or escaping prepared source')
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('nonregular prepared source')
        actual[path.relative_to(source).as_posix()] = path
    if set(actual) != set(expected):
        raise ValueError('prepared source inventory changed before build')
    result = []
    for relative, digest in expected.items():
        path = actual[relative]
        if sha(path) != digest:
            raise ValueError('prepared source changed: ' + relative)
        result.append({'path': str(path), 'sha256': digest})
    return result


def build(work):
    cfg = inputs()
    owned_work(work, False)
    resources(work)
    check_bootstrap(work)
    for comm in Path('/proc').glob('[0-9]*/comm'):
        try:
            name = comm.read_text().strip()
        except OSError:
            continue
        if name in {'ninja', 'make', 'cmake', 'cc1plus', 'clang', 'clang++', 'rustc', 'cargo', 'ld', 'ld.lld'}:
            raise RuntimeError('another build is active on this host')
    prefix, source = work / 'prefix', work / 'prepared/source'
    prepared = json.loads((work / 'prepared/prepared.json').read_text())
    if (prepared['project'] != 'ecpipe' or prepared['original_commit'] != cfg['commit'] or
            prepared['edit_steps'] != cfg['edit_steps'] or prepared['recipes_sha256'] != cfg['recipes']['sha256']):
        raise ValueError('wrong prepared ECPipe identity')
    sources = verify_prepared_sources(source, prepared)
    abi = hiredis_binding(source, prefix, cfg)
    folder = work / 'ecpipe-build'
    folder.mkdir(mode=0o700)
    runner = Owned(folder, environment(prefix))
    runner.deadline = time.monotonic() + 1800
    record = {'schema': 1, 'status': 'failed', 'project': 'ecpipe', 'sources': sources,
              'prepared_manifest_sha256': sha(work / 'prepared/prepared.json'),
              'dependency_environment': dependency_environment(prefix),
              'dependency_files': [{'path': str(p), 'sha256': sha(p)} for p in sorted(prefix.rglob('*')) if p.is_file()],
              'ecpipe_hiredis_binding': abi}
    try:
        runner.command('compiler-version', ['/usr/bin/g++', '--version'], folder, 30)
        runner.command('c-compiler-version', ['/usr/bin/gcc', '--version'], folder, 30)
        flags = re.search(r'^CFLAGS = ([^\n]+)$', (source / 'Makefile').read_text(), re.M)
        if flags is None:
            raise ValueError('unexpected ECPipe Makefile flags')
        cflags = flags[1] + ' -I' + shlex.quote(str(prefix / 'usr/include'))
        lib = str(prefix / 'usr/lib/x86_64-linux-gnu')
        clibs = '-pthread -L' + shlex.quote(lib) + ' -Wl,-rpath,' + shlex.quote(lib) + ' -lgf_complete -lhiredis'
        abi.update(compile_flags=cflags, link_flags=clibs)
        runner.command('build', ['/usr/bin/make', '-B', '-j1', 'CC=/usr/bin/g++ -std=c++11',
                                'JCC=/usr/bin/gcc', 'CFLAGS=' + cflags, 'CLIBS=' + clibs, 'all'], source, 1700)
        binaries = [source / name for name in sorted(PROGRAMS)]
        record['binaries'] = [{'path': str(p), 'sha256': sha(p)} for p in binaries]
        for i, binary in enumerate(binaries):
            runner.command('linked-libraries-' + str(i), ['/usr/bin/ldd', binary], folder, 30)
        record['dynamic_providers'] = linked_providers(folder, binaries, prefix)
        record['build_logs'] = [{'path': str(p), 'sha256': sha(p)} for p in sorted(folder.glob('*.log'))]
        record['status'] = 'built'
    except BaseException as exc:
        record.update(error_type=type(exc).__name__, error=str(exc)[:512])
    finally:
        if runner.stop_requested:
            record['status'] = 'interrupted'
        if not runner.stop():
            record['status'] = 'failed-cleanup'
        record.update(events=runner.events, cleanup_errors=runner.cleanup_errors)
        new_json(folder / 'build-record.json', record)
    print(json.dumps({key: record.get(key) for key in ('project', 'status', 'error_type', 'error')}))
    print(json.dumps({'build_record_sha256': sha(folder / 'build-record.json')}))
    if record['status'] != 'built':
        tails(folder, ['build'])
        return 1
    return 0


def run(work):
    owned_work(work, False)
    host = resources(work)
    bootstrap = check_bootstrap(work)
    path = work / 'ecpipe-build/build-record.json'
    built, binaries = check_build(path, 'ecpipe')
    if set(binaries) != PROGRAMS or built['cleanup_errors']:
        raise ValueError('exact successful ECPipe build required')
    providers = linked_providers(work / 'ecpipe-build', [Path(p['path']) for p in built['binaries']], work / 'prefix')
    if providers != built['dynamic_providers']:
        raise ValueError('actual provider paths/bytes changed after build')
    redis = Path(bootstrap['redis']['path'])
    result = {'schema': 1, 'status': 'failed', 'project': 'ecpipe', 'profile': 'standalone/basicSingle',
              'host': host, 'bootstrap_sha256': sha(work / 'bootstrap.json'), 'build_record_sha256': sha(path),
              'redis_before_sha256': sha(redis), 'dynamic_providers': providers,
              'scope': 'one missing block file; helpers alive; client output is not original block replacement',
              'performance_measurement': False}
    try:
        with arguments(['--build-record', path, '--redis-server', redis, '--run-root', work / 'runtime']):
            code = run_ecpipe.main()
        record_path = work / 'runtime/result.json'
        actual = json.loads(record_path.read_text())
        result.update(runtime_exitcode=code, runtime_result_sha256=sha(record_path),
                      checks=actual['checks'], actual_helper_completions=actual.get('actual_helper_completions', []),
                      cleanup_errors=actual['cleanup_errors'])
        starts = [e for e in actual['events'] if e['event'] == 'started']
        stops = [e for e in actual['events'] if e['event'] == 'stopped']
        result.update(owned_started=len(starts), owned_joined=len(stops),
                      forced_kills=[e['name'] for e in stops if e['forced_kill']],
                      failed_commands=[{'name': e['name'], 'returncode': e['returncode']}
                                       for e in stops if e['name'] == 'client-repair' and e['returncode'] != 0])
        if len(starts) != len(stops) or {(e['name'], e['pid']) for e in starts} != {(e['name'], e['pid']) for e in stops}:
            raise ValueError('not every owned process has a recorded join')
        if any(e['returncode'] is None for e in stops):
            raise ValueError('unknown owned process exit')
        after, _ = check_build(path, 'ecpipe')
        if after != built or sha(path) != result['build_record_sha256']:
            raise ValueError('build evidence changed during runtime')
        if check_bootstrap(work) != bootstrap or sha(work / 'bootstrap.json') != result['bootstrap_sha256']:
            raise ValueError('bootstrap evidence changed during runtime')
        for group in providers:
            for library in group['providers']:
                if sha(library['path']) != library['sha256']:
                    raise ValueError('dynamic provider changed during runtime')
        result.update(redis_after_sha256=sha(redis), post_runtime_inputs_unchanged=True)
        if code == 0 and actual['status'] == 'passed-functional-runtime' and not actual['cleanup_errors']:
            if [row['stage'] for row in actual['checks']] != ['all-original-blocks', 'decoded-client-file', 'healthy-blocks-unchanged']:
                raise ValueError('missing or unexpected ECPipe oracle stage')
            helpers = actual['actual_helper_completions']
            if len(helpers) != 10 or len(set(helpers)) != 10 or 'helper-03' in helpers:
                raise ValueError('exact ten healthy helper completions required')
            if actual['output_is_original_block_replacement'] is not False:
                raise ValueError('unexpected replacement semantics')
            result['decoded_client_file_sha256'] = actual['checks'][1]['sha256']
            result['decoded_client_file_bytes'] = actual['checks'][1]['bytes']
            result['status'] = 'passed-functional-runtime'
        if 'error' in actual:
            result['error'] = actual['error'][:512]
    except BaseException as exc:
        result.update(error_type=type(exc).__name__, error=str(exc)[:512])
    finally:
        new_json(work / 'acceptance.json', result)
    print(json.dumps({key: result.get(key) for key in ('status', 'project', 'profile', 'runtime_exitcode',
         'owned_started', 'owned_joined', 'forced_kills', 'failed_commands', 'post_runtime_inputs_unchanged',
         'actual_helper_completions', 'decoded_client_file_sha256', 'decoded_client_file_bytes', 'error_type', 'error')}))
    print(json.dumps({'confirmed_stages': [row['stage'] for row in result.get('checks', [])],
                      'acceptance_sha256': sha(work / 'acceptance.json'),
                      'runtime_result_sha256': result.get('runtime_result_sha256'),
                      'build_record_sha256': result['build_record_sha256']}))
    if result['status'] != 'passed-functional-runtime':
        tails(work / 'runtime', ['client-repair', 'coordinator', 'helper-03'])
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare', 'build', 'run'])
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    with reference_lease():
        return {'prepare': prepare, 'build': build, 'run': run}[args.phase](args.work)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({'status': 'preflight-or-evidence-failure',
                          'error_type': type(exc).__name__, 'error': str(exc)[:512]}))
        sys.exit(2)
