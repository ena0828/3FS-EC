#!/usr/bin/env python3
"""Small offline checks; no native build, package extraction or network request."""
import ast
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'build-native.sh'
spec = importlib.util.spec_from_file_location('prepare_isal', HERE / 'prepare-isal.py')
isal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isal)
spec = importlib.util.spec_from_file_location('prepare_local', HERE / 'prepare-local-build.py')
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)
spec = importlib.util.spec_from_file_location('container_resources', HERE / 'container-build-resources.py')
container = importlib.util.module_from_spec(spec)
spec.loader.exec_module(container)

spec = importlib.util.spec_from_file_location('arrow_cache', HERE / 'prepare-arrow-cache.py')
arrow_cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arrow_cache)


def bash_path():
    if os.name == 'nt':
        candidate = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe'
        return str(candidate) if candidate.is_file() else None  # Never fall back to WSL bash.
    return shutil.which('bash')


class BuildInputs(unittest.TestCase):
    def test_script_and_embedded_python_parse(self):
        text = SCRIPT.read_text(encoding='utf-8')
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", text, re.S)
        self.assertEqual(len(blocks), 6)
        for block in blocks:
            ast.parse(block)
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        result = subprocess.run([bash, '-n'], input=text, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_argument_parser_accepts_and_rejects_before_side_effects(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        text = SCRIPT.read_text(encoding='utf-8')
        marker = '\n# END ARGUMENT PARSER'
        self.assertEqual(text.count(marker), 1)
        parser = text.split(marker, 1)[0] + '\nprintf "%s %s %s %s\\n" "$backend" "$with_lab" "$with_regression" "$build_jobs"\n'
        cases = [([], 'scalar false false 1'),
                 (['--with-lab-targets'], 'scalar true false 1'),
                 (['--backend', 'isal'], 'isal false false 1'),
                 (['--with-ec-regression-targets', '--backend', 'isal', '--with-lab-targets'], 'isal true true 1'),
                 (['--with-lab-targets', '--backend', 'scalar', '--with-ec-regression-targets'], 'scalar true true 1'),
                 (['--build-jobs', '2', '--backend', 'isal'], 'isal false false 2'),
                 (['--build-jobs', '4', '--backend', 'isal'], 'isal false false 4'),
                 (['--build-jobs', '1'], 'scalar false false 1'),
                 (['--local-source', '/fixed/source', '--local-work', '/fixed/native',
                   '--local-revision', 'a' * 40], 'scalar false false 1'),
                 (['--local-container-build-only', '--local-source', '/fixed/source',
                   '--local-work', '/fixed/native', '--local-revision', 'a' * 40,
                   '--build-jobs', '12'], 'scalar false false 12'),
                 (['--local-container-build-only', '--local-source', '/fixed/source',
                   '--local-work', '/fixed/native', '--local-revision', 'a' * 40,
                   '--container-fdb-cache', '/fixed/cache'], 'scalar false false 1'),
                 (['--local-container-build-only', '--local-source', '/fixed/source',
                   '--local-work', '/fixed/native', '--local-revision', 'a' * 40,
                   '--container-arrow-cache', '/fixed/arrow'], 'scalar false false 1'),
                 (['--local-container-build-only', '--local-source', '/fixed/source',
                   '--local-work', '/fixed/native', '--local-revision', 'a' * 40,
                   '--container-libfuse-bundle', '/fixed/fuse.bundle',
                   '--container-libfuse-bundle-sha256', 'b' * 64], 'scalar false false 1')]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                result = subprocess.run([bash, '-s', '--', *argv], input=parser, text=True, capture_output=True)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, expected), result.stderr)
        for argv in (['--container-arrow-cache'], ['--container-arrow-cache', '/cache'],
                     ['--local-source', '/a', '--local-work', '/b', '--local-revision', 'a' * 40,
                      '--container-arrow-cache', '/cache'],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-arrow-cache', 'relative'],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-arrow-cache', '/a', '--container-arrow-cache', '/b'],
                     ['--backend'], ['--backend', 'avx'], ['--backend=isal'], ['extra'],
                     ['--backend', 'scalar', '--backend', 'isal'],
                     ['--with-lab-targets', '--with-lab-targets'],
                     ['--with-ec-regression-targets', '--with-ec-regression-targets'],
                     ['--build-jobs'], ['--build-jobs', '0'], ['--build-jobs', '3'],
                     ['--build-jobs', '5'], ['--build-jobs', '8'],
                     ['--build-jobs', '02'], ['--build-jobs=2'],
                     ['--build-jobs', '1', '--build-jobs', '2'],
                     ['--local-source', '/fixed/source'], ['--local-work', '/fixed/native'],
                     ['--local-revision', 'a' * 40], ['--local-source', 'relative'],
                     ['--local-source', '/a', '--local-source', '/b'],
                     ['--local-revision', 'a' * 39], ['--local-revision', 'A' * 40],
                     ['--local-work', '/a', '--local-work', '/b'],
                     ['--local-container-build-only'],
                     ['--local-container-build-only', '--local-container-build-only'],
                     ['--container-fdb-cache', '/fixed/cache'],
                     ['--container-fdb-cache'],
                     ['--local-container-build-only', '--container-fdb-cache', '/fixed/cache'],
                     ['--local-source', '/a', '--local-work', '/b', '--local-revision', 'a' * 40,
                      '--container-fdb-cache', '/fixed/cache'],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-fdb-cache', 'relative'],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-fdb-cache', '/cache',
                      '--container-fdb-cache', '/cache2'],
                     ['--container-libfuse-bundle', '/cache/fuse.bundle', '--container-libfuse-bundle-sha256', 'b' * 64],
                     ['--local-source', '/a', '--local-work', '/b', '--local-revision', 'a' * 40,
                      '--container-libfuse-bundle', '/cache/fuse.bundle', '--container-libfuse-bundle-sha256', 'b' * 64],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-libfuse-bundle', '/cache/fuse.bundle'],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-libfuse-bundle-sha256', 'b' * 64],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-libfuse-bundle', 'relative',
                      '--container-libfuse-bundle-sha256', 'b' * 64],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-libfuse-bundle', '/cache/fuse.bundle',
                      '--container-libfuse-bundle-sha256', 'B' * 64],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-libfuse-bundle', '/cache/fuse.bundle',
                      '--container-libfuse-bundle', '/cache/other.bundle', '--container-libfuse-bundle-sha256', 'b' * 64],
                     ['--local-container-build-only', '--local-source', '/a', '--local-work', '/b',
                      '--local-revision', 'a' * 40, '--container-libfuse-bundle', '/cache/fuse.bundle',
                      '--container-libfuse-bundle-sha256', 'b' * 64, '--container-libfuse-bundle-sha256', 'c' * 64],
                     ['--local-source', '/a', '--local-work', '/b', '--local-revision', 'a' * 40,
                      '--build-jobs', '12']):
            with self.subTest(rejected=argv):
                result = subprocess.run([bash, '-s', '--', *argv], input=parser, text=True, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('true false', result.stdout)

    def test_real_fdb_fetch_default_and_explicit_cache_argv(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        text = SCRIPT.read_text(encoding='utf-8')
        block = text.split('# BEGIN FDB FETCH\n', 1)[1].split('# END FDB FETCH', 1)[0]
        prefix = '''set -euo pipefail
source_root=/fixed/source
work=/fixed/native
bash() { printf '%s\\n' "$@"; }
'''
        for cache in ('', '/fixed/cache'):
            result = subprocess.run([bash, '-s'],
                                    input=prefix + 'container_fdb_cache=' + shlex.quote(cache) + '\n' + block,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = ['/fixed/source/scripts/ec/cluster/fetch-fdb.sh', '/fixed/native/fdb']
            if cache:
                expected += ['--container-fdb-cache', cache, '--source', '/fixed/source', '--work', '/fixed/native']
            self.assertEqual(result.stdout.splitlines(), expected)
        fetch = HERE.parent / 'cluster/fetch-fdb.sh'
        result = subprocess.run([bash, '-n'], input=fetch.read_text(encoding='utf-8'),
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_libfuse_source_branch_argv(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        text = SCRIPT.read_text(encoding='utf-8')
        block = text.split('# BEGIN LIBFUSE SOURCE\n', 1)[1].split('# END LIBFUSE SOURCE', 1)[0]
        # Substitute only the fixed interpreter executable with an argv recorder.
        block = block.replace('/usr/bin/python3 ', 'python_helper ')
        prefix = '''set -euo pipefail
source_root=/fixed/source
work=/fixed/native
fuse_revision=7a92727d97c10290b3501d86a194738973edb61d
python_helper() { printf '%s\\n' "$@"; }
git() {
  if [[ "$*" == *'rev-parse HEAD' ]]; then printf '%s\\n' "$fuse_revision";
  else printf 'git %s\\n' "$*"; fi
}
'''
        for bundle in ('', '/fixed/cache/fuse.bundle'):
            result = subprocess.run([bash, '-s'], input=prefix + 'container_libfuse_bundle=' + shlex.quote(bundle)
                                    + '\ncontainer_libfuse_bundle_sha256=' + 'b' * 64 + '\n' + block,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            if bundle:
                self.assertEqual(result.stdout.splitlines(), ['-I', '/fixed/source/scripts/ec/ci/prepare-libfuse-cache.py',
                                 '--source', '/fixed/source', '--work', '/fixed/native', '--bundle', bundle,
                                 '--bundle-sha256', 'b' * 64])
            else:
                self.assertEqual(result.stdout.splitlines(), [
                    'git init -q /fixed/native/libfuse',
                    'git -C /fixed/native/libfuse remote add origin https://github.com/libfuse/libfuse.git',
                    'git -C /fixed/native/libfuse fetch --depth 1 origin 7a92727d97c10290b3501d86a194738973edb61d',
                    'git -C /fixed/native/libfuse checkout --detach FETCH_HEAD'])

    def resource_functions(self):
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", SCRIPT.read_text(encoding='utf-8'), re.S)
        block, = [item for item in blocks if 'def resource_plan(' in item]
        tree = ast.parse(block)
        # Load the real pure functions without /proc reads or report writes.
        selected = [item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
        scope = {'GIB': 1024 ** 3}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(SCRIPT), 'exec'), scope)
        return scope

    def test_resource_gate_exact_thresholds_and_ancestor_restrictions(self):
        plan = self.resource_functions()['resource_plan']
        gib = 1024 ** 3
        memory = {'MemTotal': 15 * gib, 'MemAvailable': 12 * gib}
        self.assertEqual(plan(2, memory, 4, [])['effective_jobs'], 2)
        four = plan(4, memory, 4, [])
        self.assertEqual(four['effective_jobs'], 4)
        self.assertEqual(four['pools'], {'compile': 4, 'link': 1})
        self.assertEqual(four['j4_thresholds'], {'memtotal_bytes': 15 * gib, 'headroom_bytes': 12 * gib,
                                                'cpu_floor': 4})
        for mem, cpu, groups in [
            ({**memory, 'MemTotal': 15 * gib - 1}, 4, []),
            ({**memory, 'MemAvailable': 12 * gib - 1}, 4, []),
            (memory, 3, []),
            (memory, 8, [{'cpu_max': '399999 100000', 'memory_max': None, 'memory_current': None}]),
            (memory, 8, [{'cpu_max': 'max 100000', 'memory_max': str(13 * gib), 'memory_current': gib + 1}]),
        ]:
            with self.subTest(mem=mem, cpu=cpu, groups=groups):
                self.assertIsNone(plan(2, mem, cpu, groups)['effective_jobs'])
                self.assertIsNone(plan(4, mem, cpu, groups)['effective_jobs'])
                self.assertEqual(plan(1, mem, cpu, groups)['effective_jobs'], 1)
        for jobs in (0, 3, 5, True):
            with self.assertRaises(ValueError):
                plan(jobs, memory, 4, [])

    def test_cgroup_mapping_and_absent_controller_are_explicit(self):
        read = self.resource_functions()['cgroup_rows']
        with tempfile.TemporaryDirectory(prefix='build-cgroup-') as folder:
            root = Path(folder).resolve()
            mount = '1 0 0:0 / ' + str(root) + ' rw - cgroup2 none rw\n'
            self.assertEqual(len(read(root, '0::/\n', mount)), 1)
            child = root / 'job'
            child.mkdir()
            (root / 'cgroup.subtree_control').write_text('cpu memory')
            (child / 'cpu.max').write_text('400000 100000')
            (child / 'memory.max').write_text(str(15 * 1024 ** 3))
            (child / 'memory.current').write_text('123')
            rows = read(root, '0::/job\n', mount)
            self.assertEqual((len(rows), rows[0]['memory_current'], rows[0]['cpu_max']), (2, 123, '400000 100000'))
            (child / 'cpu.max').unlink()
            with self.assertRaises(ValueError):
                read(root, '0::/job\n', mount)
            (root / 'cgroup.subtree_control').write_text('memory')
            self.assertEqual(read(root, '0::/job\n', mount)[0]['cpu_scope'], 'parent-controller-disabled')
            (child / 'memory.current').unlink()
            with self.assertRaises(OSError):
                read(root, '0::/job\n', mount)
            for membership, wrong_mount in [('0::/../escape\n', mount), ('0::/\n', mount.replace(' / ', ' /hidden ', 1)),
                                              ('0::/\n', ''), ('1:cpu:/\n', mount)]:
                with self.assertRaises(ValueError):
                    read(root, membership, wrong_mount)

    def test_real_requested_build_block_calls_one_aggregate_and_keeps_nested_serial(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        text = SCRIPT.read_text(encoding='utf-8')
        block = text.split('# BEGIN REQUESTED BUILD\n', 1)[1].split('# END REQUESTED BUILD', 1)[0]
        workflows = HERE.parents[2] / '.github/workflows'
        for name in ('ec-hosted-native.yml', 'ec-hosted-system.yml', 'ec-hosted-target-control.yml',
                     'ec-hosted-target-meta.yml'):
            source = (workflows / name).read_text(encoding='utf-8')
            calls = re.findall(r'^\s*run: (bash scripts/ec/ci/build-native\.sh[^\n]*)$', source, re.M)
            self.assertEqual(len(calls), 1, name)
            args = shlex.split(calls[0])
            self.assertEqual(args.count('--build-jobs'), 1, name)
            self.assertEqual(args[args.index('--build-jobs') + 1], '4', name)
        env_block = text.split('export CC=/usr/bin/gcc-12', 1)[1].split('# END BUILD ENVIRONMENT', 1)[0]
        base = ['test_meta', 'test_fuse_ec']
        regression = ['test_storage_store', 'test_storage_service', 'test_client']
        lab = ['storage_main', 'mgmtd_main', 'meta_main', 'admin_cli', 'ec_stripe_cli',
               'ec_file_cli', 'hf3fs_fuse_main', 'ec_mount_read_probe']
        with tempfile.TemporaryDirectory(prefix='build-argv-') as folder:
            env = dict(os.environ, CAPTURE=Path(folder).as_posix())
            prefix = '''set -euo pipefail
source_root=/fixed/source
work=/fixed/work
gcc_toolchain=/fixed/gcc12
backend_cmake_args=(-DHF3FS_EC_BACKEND=isal -DHF3FS_EC_ISAL_ROOT=/fixed/isal)
cmake() {
    printf '%s\\n' "$@" >> "$CAPTURE/cmake-argv"
    printf '%s\\n' END >> "$CAPTURE/cmake-argv"
    printf '%s\\n' "$CMAKE_BUILD_PARALLEL_LEVEL" "$CARGO_BUILD_JOBS" "$MAKEFLAGS" > "$CAPTURE/nested"
}
python3() { cat >/dev/null; }
'''
            for jobs, full, mode in [(1, False, False), (2, False, False), (4, False, False),
                                     (1, True, False), (2, True, False), (4, True, False),
                                     (1, True, True), (2, True, True), (4, True, True), (12, True, True)]:
                (Path(folder) / 'cmake-argv').write_text('')
                dependency = '/fixed/work/deps' if mode else '/usr/local'
                flags = (f'build_jobs={jobs}\nwith_lab={str(full).lower()}\nwith_regression={str(full).lower()}\n'
                         f'local_mode={str(mode).lower()}\ndependency_prefix={dependency}\n')
                result = subprocess.run([bash, '-s'], input=prefix + flags + env_block + '\n' + block,
                                        text=True, capture_output=True, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                chunks = (Path(folder) / 'cmake-argv').read_text().split('END\n')
                self.assertEqual(len(chunks), 3)  # Exactly configure + one aggregate build.
                configure, actual = (part.splitlines() for part in chunks[:2])
                self.assertIn(f'-DCMAKE_JOB_POOLS=ec_compile={jobs};ec_link=1', configure)
                self.assertIn('-DCMAKE_JOB_POOL_COMPILE=ec_compile', configure)
                self.assertIn('-DCMAKE_JOB_POOL_LINK=ec_link', configure)
                self.assertIn('-DHF3FS_EXTERNAL_BUILD_JOBS=1', configure)
                self.assertIn('-DCMAKE_EXE_LINKER_FLAGS=-L' + dependency + '/lib', configure)
                self.assertIn('-DCMAKE_SHARED_LINKER_FLAGS=-L' + dependency + '/lib', configure)
                if mode:
                    self.assertIn('-DCMAKE_CXX_FLAGS=-I' + dependency + '/include', configure)
                    self.assertIn('-DCMAKE_C_FLAGS=-I' + dependency + '/include', configure)
                    self.assertIn('-DCMAKE_BUILD_RPATH=' + dependency + '/lib', configure)
                else:
                    self.assertFalse(any(item.startswith('-DCMAKE_BUILD_RPATH=') for item in configure))
                self.assertEqual(actual, ['--build', '/fixed/work/build', '--parallel', str(jobs), '--target',
                                          *base, *(regression + lab if full else [])])
                self.assertEqual((Path(folder) / 'nested').read_text().splitlines(), ['1', '1', '-j1'])

    def test_package_lock_rejects_drift_duplicate_and_missing(self):
        packages = [{'package': name, 'version': '2.31.0-0.1build1', 'architecture': 'amd64',
                     'url': 'https://archive.ubuntu.com/ubuntu/pool/universe/libi/libisal/'
                            + name + '_2.31.0-0.1build1_amd64.deb', 'sha256': sha, 'size': size}
                    for name, (sha, size) in isal.PACKAGES.items()]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'lock.json'
            path.write_text(json.dumps({'packages': packages}), encoding='utf-8')
            self.assertEqual(isal.packages_from_lock(path), packages)
            bad = [packages[:1], packages + [packages[0]]]
            for key, value in [('url', 'https://example.invalid/a.deb'), ('sha256', '0' * 64),
                               ('size', True), ('architecture', 'arm64'), ('version', 'next')]:
                changed = copy.deepcopy(packages)
                changed[0][key] = value
                bad.append(changed)
            for values in bad:
                path.write_text(json.dumps({'packages': values}), encoding='utf-8')
                with self.assertRaises(ValueError):
                    isal.packages_from_lock(path)

    def test_real_cargo_wrapper_preserves_existing_lock_and_forces_missing(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        text = SCRIPT.read_text(encoding='utf-8')
        wrappers = re.findall(r"cat > \"\$work/bin/cargo\" <<'SH'\n(.*?)\nSH\n", text, re.S)
        self.assertEqual(len(wrappers), 1)
        with tempfile.TemporaryDirectory(prefix='cargo-wrapper-') as folder:
            fake = Path(folder) / 'fake cargo'
            captured = Path(folder) / 'argv.txt'
            fake.write_bytes(b'#!/usr/bin/env bash\nset -eu\nprintf "%s\\n" "offline=${CARGO_NET_OFFLINE:-}" "$@" > "${EC_ARGV_CAPTURE:?}"\n')
            fake.chmod(0o700)
            env = dict(os.environ, EC_REAL_CARGO=fake.as_posix(), EC_ARGV_CAPTURE=captured.as_posix(),
                       CARGO_NET_OFFLINE='true')
            for argv, expected in [(['build', '--locked', '--features', 'chunk_engine/isal-backend'],
                                    ['build', '--locked', '--features', 'chunk_engine/isal-backend']),
                                   (['build', '--release'], ['build', '--locked', '--release']),
                                   (['test', '--lib'], ['test', '--lib'])]:
                with self.subTest(argv=argv):
                    result = subprocess.run([bash, '-s', '--', *argv], input=wrappers[0],
                                            text=True, capture_output=True, env=env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(captured.read_text().splitlines(), ['offline=true', *expected])

    def test_download_is_bounded_exact_exclusive_and_no_redirect(self):
        body = b'fixed archive bytes'
        item = {'url': 'https://archive.ubuntu.com/test', 'size': len(body),
                'sha256': hashlib.sha256(body).hexdigest()}
        def response(data=body, url=item['url'], status=200):
            value = io.BytesIO(data)
            value.url, value.status = url, status
            return value
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ok.deb'
            with mock.patch.object(isal.urllib.request, 'urlopen', return_value=response()) as opener:
                isal.fetch(item, path)
                self.assertEqual(path.read_bytes(), body)
                self.assertEqual(opener.call_args.kwargs['timeout'], 60)
            with mock.patch.object(isal.urllib.request, 'urlopen', return_value=response()):
                with self.assertRaises(FileExistsError):
                    isal.fetch(item, path)
            for i, bad in enumerate([response(body + b'!'), response(body[:-1]), response(b'x' * len(body)),
                                     response(url='https://other.invalid/archive'), response(status=404)]):
                with mock.patch.object(isal.urllib.request, 'urlopen', return_value=bad):
                    with self.assertRaises(ValueError):
                        isal.fetch(item, Path(folder) / (str(i) + '.deb'))

    def test_provider_rejects_unversioned_regular_file(self):
        # An arbitrary .so file is not a substitute for the canonical locked DSO.
        with tempfile.TemporaryDirectory() as folder:
            prefix = Path(folder)
            path = prefix / 'usr/lib/x86_64-linux-gnu/libisal.so'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'not the fixed library')
            with self.assertRaises(ValueError):
                isal.provider_record(prefix)

    def test_local_dependency_list_and_inherited_configuration_rejection(self):
        required = local.packages(HERE.parent / 'install-build-deps.sh')
        self.assertIn('libclang-18-dev', required)
        self.assertIn('lld-14', required)
        self.assertNotIn('rustup', required)  # An explicit separate preparation step.
        local.clean_environment({'PATH': '/usr/bin:/bin', 'HOME': '/home/test'})
        for name in ('LD_PRELOAD', 'CPATH', 'RUSTFLAGS', 'RUSTUP_HOME', 'CARGO_BUILD_RUSTFLAGS',
                     'CARGO_REGISTRIES_CRATES_IO_INDEX', 'RUSTUP_DIST_SERVER',
                     'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER', 'GIT_CONFIG_COUNT', 'BASH_FUNC_cmake%%'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                local.clean_environment({name: 'injected'})
        with tempfile.TemporaryDirectory(prefix='local-cargo-') as folder:
            parent = Path(folder)
            source = parent / 'source'
            source.mkdir()
            local.cargo_ancestor_configs(source)
            (parent / '.cargo').mkdir()
            (parent / '.cargo/config.toml').write_text('[build]\nrustflags = ["--cfg", "injected"]')
            with self.assertRaises(ValueError):
                local.cargo_ancestor_configs(source)

    def test_local_path_policy_accepts_siblings_rejects_reuse_nesting_and_permissions(self):
        # Filesystem ownership/Unix mode observations are injected on Windows;
        # the real containment and existence checks still operate on new files.
        with tempfile.TemporaryDirectory(prefix='local-shape-') as folder:
            parent = Path(folder)
            source = parent / 'source'
            source.mkdir()
            work = parent / 'native'
            info = SimpleNamespace(st_mode=0o40700, st_uid=1234)
            with mock.patch.object(local, 'canonical', side_effect=lambda value: value), \
                    mock.patch.object(Path, 'stat', return_value=info):
                # stat mock would make nonexistent paths exist; retain the real
                # existence results independently, including the fresh-work bit.
                with mock.patch.object(Path, 'exists', return_value=False), \
                        mock.patch.object(Path, 'is_symlink', return_value=False):
                    local.fresh_paths(source, work, 1234)
                    with self.assertRaises(ValueError):
                        local.fresh_paths(source, source / 'native', 1234)
                    with self.assertRaises(ValueError):
                        local.fresh_paths(source, work, 1235)
                    info.st_mode = 0o40755
                    with self.assertRaises(ValueError):
                        local.fresh_paths(source, work, 1234)
                with self.assertRaises(ValueError):
                    local.fresh_paths(source, work, 1234)

    def test_local_git_gate_rejects_wrong_revision_dirty_and_unpinned_submodule(self):
        source, revision = Path('/fixed/source'), 'a' * 40
        def check(dirty='', submodule=' ' + 'b' * 40 + ' third_party/one\n', head=revision):
            def output(argv, **kwargs):
                if argv[3:] == ['rev-parse', '--show-toplevel']:
                    return str(source) + '\n'
                if argv[3:] == ['rev-parse', 'HEAD']:
                    return head + '\n'
                if argv[3] == 'status':
                    return dirty
                if argv[3:] == ['submodule', 'status', '--recursive']:
                    return submodule
                self.fail('Unexpected Git query: ' + repr(argv))
            with mock.patch.object(local.subprocess, 'check_output', side_effect=output), \
                    mock.patch.object(local.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
                return local.git_state(source, revision)
        self.assertTrue(check())
        for args in ({'head': 'c' * 40}, {'dirty': '!! target/\n'}, {'submodule': ''},
                     {'submodule': '+' + 'b' * 40 + ' third_party/one\n'},
                     {'submodule': '-' + 'b' * 40 + ' third_party/one\n'}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                check(**args)

    def test_real_install_branches_keep_local_unprivileged(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        text = SCRIPT.read_text()
        blocks = [text.split('# BEGIN ' + name + ' INSTALL\n', 1)[1].split('# END ' + name + ' INSTALL', 1)[0]
                  for name in ('FDB', 'FUSE')]
        blocks.append(text.split('# BEGIN RUST TOOLCHAIN INSTALL\n', 1)[1].split('# END RUST TOOLCHAIN INSTALL', 1)[0])
        with tempfile.TemporaryDirectory(prefix='local-install-') as folder:
            captured = Path(folder) / 'calls'
            env = dict(os.environ, CAPTURE=captured.as_posix())
            prefix = '''set -euo pipefail
work=/private/native
dependency_prefix=/private/native/deps
RUSTUP_TOOLCHAIN=1.99.1
record() { printf '%s\\n' "$*" >> "$CAPTURE"; }
sudo() { record "sudo $*"; }
install() { record "install $*"; }
cp() { record "cp $*"; }
meson() { record "meson $*"; }
ninja() { record "ninja $*"; }
rustup() { record "rustup $*"; }
'''
            for mode in (True, False):
                captured.write_text('')
                result = subprocess.run([bash, '-s'], input=prefix + 'local_mode=' + str(mode).lower() + '\n' + '\n'.join(blocks),
                                        text=True, capture_output=True, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = captured.read_text().splitlines()
                if mode:
                    self.assertFalse(any(row.startswith('sudo ') for row in calls))
                    self.assertTrue(any('-Dutils=false -Duseroot=false' in row for row in calls))
                    self.assertTrue(any(row.startswith('install -m 755 ') and row.endswith('/deps/lib/libfdb_c.so') for row in calls))
                    self.assertIn('rustup toolchain install 1.99.1 --profile minimal --no-self-update', calls)
                else:
                    self.assertEqual(sum(row.startswith('sudo ') for row in calls), 5)
                    self.assertFalse(any('-Dutils=false' in row for row in calls))
                    self.assertIn('rustup toolchain install 1.99.1 --profile minimal', calls)

    def test_real_final_receipt_profiles_and_loader_mismatch(self):
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", SCRIPT.read_text(), re.S)
        block, = [item for item in blocks if "path = work / 'provenance/native-build.json'" in item]
        code = compile(block, str(SCRIPT) + ':actual-final-receipt', 'exec')
        fixed_isal = '40ccd5e5abaff0451feff750d2b011370a546ac4706d1b06b9285ac26eda2c3c'
        for backend, mode, bad_loader, container_mode in [
                ('scalar', False, False, False), ('isal', False, False, False),
                ('scalar', True, False, False), ('isal', True, False, False), ('scalar', True, True, False),
                ('isal', True, False, True), ('scalar', True, True, True)]:
            with self.subTest(backend=backend, local=mode, bad_loader=bad_loader), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                source, work, deps = root / 'source', root / 'native', root / 'native/deps'
                def put(path, data=b'fixture'):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                    path.chmod(0o700)
                    return path
                def sha(path):
                    return hashlib.sha256(path.read_bytes()).hexdigest()
                for name in ('build-native.sh', 'prepare-isal.py', 'container-build-resources.py'):
                    put(source / 'scripts/ec/ci' / name)
                put(source / 'scripts/ec/reference/downloads.json')
                for name in ('libfdb_c.so', 'libfuse3.so.3'):
                    put(deps / 'lib' / name)
                names = ['test_meta', 'test_fuse_ec', 'test_storage_store', 'test_storage_service', 'test_client']
                names += ['storage_main', 'mgmtd_main', 'meta_main', 'admin_cli', 'ec_stripe_cli',
                          'ec_file_cli', 'hf3fs_fuse_main', 'ec_mount_read_probe']
                for name in names:
                    put(work / 'build' / ('tests' if name.startswith('test_') else 'bin') / name)
                cache = 'HF3FS_EC_BACKEND:STRING=' + backend + '\n'
                isal_prefix = work / 'isal-prefix'
                provider = isal_prefix / 'usr/lib/x86_64-linux-gnu/libisal.so.2.0.31'
                if backend == 'isal':
                    put(provider)
                    # resolve() of the unversioned path is mocked below for
                    # portable testing; no privilege-dependent Windows symlink.
                    put(provider.parent / 'libisal.so')
                    cache += 'HF3FS_EC_ISAL_ROOT:PATH=' + str(isal_prefix) + '\n'
                    receipt = {'status': 'private-packages-prepared-not-executed', 'backend': backend,
                               'prefix': str(isal_prefix), 'provider': {'path': str(provider), 'sha256': fixed_isal},
                               'source_lock_sha256': sha(source / 'scripts/ec/reference/downloads.json'),
                               'helper_sha256': sha(source / 'scripts/ec/ci/prepare-isal.py')}
                    put(work / 'provenance/isal-prepare.json', json.dumps(receipt).encode())
                put(work / 'build/CMakeCache.txt', cache.encode())
                for name in ('build-resources.json', 'build-command.json'):
                    put(work / 'provenance' / name, b'{}')
                put(work / 'provenance/local-preflight.json',
                    b'{"tools":{},"filesystems":[{"path":"/private/work","filesystem":"xfs"}]}')
                fuse_cache = put(work / 'provenance/libfuse-cache.json',
                                 b'{"status":"fixed-libfuse-source-prepared","build_executed":false}')
                arrow_proof = put(work / 'provenance/arrow-cache.json', b'fixture preparation')
                # The actual receipt writer must call verification before emitting
                # either receipt. The helper's real filesystem checks are tested below.
                put(source / 'scripts/ec/ci/prepare-arrow-cache.py', ("from pathlib import Path\n"
                    "import hashlib\n"
                    "def verify_preparation(source, work, cache, *, verify_upstream):\n"
                    "    assert verify_upstream and cache == work.parent / 'arrow-input'\n"
                    "    proof = work / 'provenance/arrow-cache.json'\n"
                    "    return {'path': str(proof), 'sha256': hashlib.sha256(proof.read_bytes()).hexdigest()}\n").encode())
                original_digest, original_resolve = hashlib.file_digest, Path.resolve
                def digest(stream, algorithm):
                    if Path(stream.name) == provider:
                        return SimpleNamespace(hexdigest=lambda: fixed_isal)
                    return original_digest(stream, algorithm)
                def resolve(path, *args, **kwargs):
                    if path == provider.parent / 'libisal.so':
                        return provider
                    return original_resolve(path, *args, **kwargs)
                calls = []
                def ldd(argv, **kwargs):
                    self.assertEqual(argv[0], 'ldd')
                    calls.append(kwargs['env'].get('LD_LIBRARY_PATH'))
                    lib = deps / 'lib/libfdb_c.so'
                    if bad_loader and kwargs['env'].get('LD_LIBRARY_PATH') == '/usr/local/lib':
                        lib = put(root / 'wrong/libfdb_c.so')
                    rows = ['libfdb_c.so => ' + str(lib) + ' (0x1)',
                            'libfuse3.so.3 => ' + str(deps / 'lib/libfuse3.so.3') + ' (0x2)']
                    if backend == 'isal':
                        rows.append('libisal.so.2 => ' + str(provider) + ' (0x3)')
                    return '\n'.join(rows)
                argv = ['-', str(source), str(work), backend, 'true', 'true', 'a' * 40,
                        str(mode).lower(), str(deps), str(container_mode).lower(), str(root / 'arrow-input') if container_mode else '']
                with mock.patch('sys.argv', argv), mock.patch.object(hashlib, 'file_digest', side_effect=digest), \
                        mock.patch.object(Path, 'resolve', resolve), \
                        mock.patch.object(subprocess, 'check_output', side_effect=ldd), \
                        mock.patch('sys.stdout', new=io.StringIO()):
                    if bad_loader:
                        with self.assertRaises(SystemExit):
                            exec(code, {})
                        self.assertFalse((work / 'provenance/native-build.json').exists())
                        continue
                    exec(code, {})
                native = json.loads((work / 'provenance/native-build.json').read_text())
                lab = json.loads((work / 'provenance/lab-build.json').read_text())
                self.assertEqual(native['revision'], 'a' * 40)
                self.assertEqual(native['dependency_prefix'], str(deps))
                self.assertEqual((len(native['targets']), len(lab['targets'])), (13, 8))
                self.assertFalse(native['acceptance_executed'])
                if container_mode:
                    self.assertTrue(native['build_only'])
                    self.assertEqual(native['execution_environment'], 'local-linux-container-build-only')
                    self.assertEqual(native['filesystems'][0]['filesystem'], 'xfs')
                    self.assertEqual(native['libfuse_cache_provenance'], {'path': str(fuse_cache), 'sha256': sha(fuse_cache)})
                    self.assertEqual(lab['libfuse_cache_provenance'], native['libfuse_cache_provenance'])
                    self.assertEqual(native['arrow_cache_provenance'], {'path': str(arrow_proof), 'sha256': sha(arrow_proof)})
                    self.assertEqual(lab['arrow_cache_provenance'], native['arrow_cache_provenance'])
                else:
                    self.assertNotIn('build_only', native)
                    self.assertNotIn('libfuse_cache_provenance', native)
                    self.assertNotIn('arrow_cache_provenance', native)
                self.assertEqual(lab['native_build_receipt_sha256'], sha(work / 'provenance/native-build.json'))
                self.assertEqual(calls, [None, '/usr/local/lib'] * 13 if mode else [])


class ContainerBuildResources(unittest.TestCase):
    def fixture(self):
        gib = 1024 ** 3
        files = {
            '/cg/cpu/cgroup.procs': '123\n', '/cg/cpu/cpu.cfs_quota_us': '1200000',
            '/cg/cpu/cpu.cfs_period_us': '100000', '/cg/memory/cgroup.procs': '123\n',
            '/cg/memory/memory.limit_in_bytes': str(43 * gib),
            '/cg/memory/memory.usage_in_bytes': str(gib),
            '/cg/memory/memory.stat': 'hierarchical_memory_limit ' + str(43 * gib),
        }
        membership = '4:cpu,cpuacct:/docker/one\n8:memory:/docker/one\n0::/docker/one\n'
        mounts = ('1 0 0:1 /docker/one /cg/cpu ro - cgroup cgroup rw,cpu,cpuacct\n'
                  '2 0 0:2 /docker/one /cg/memory ro - cgroup cgroup rw,memory\n')
        return files, membership, mounts

    def observe(self, files, membership, mounts, pid=123):
        # Emulate proc/cgroup files only, including on Windows. No live cgroup,
        # service, namespace or native compiler is used by these fixtures.
        def key(path):
            return path.as_posix()
        with mock.patch.object(Path, 'resolve', autospec=True, side_effect=lambda path, **_: path), \
                mock.patch.object(Path, 'is_dir', autospec=True,
                                  side_effect=lambda path: key(path) + '/cgroup.procs' in files), \
                mock.patch.object(Path, 'is_file', autospec=True, side_effect=lambda path: key(path) in files), \
                mock.patch.object(Path, 'exists', autospec=True, side_effect=lambda path: key(path) in files), \
                mock.patch.object(Path, 'read_text', autospec=True,
                                  side_effect=lambda path, **_: files[key(path)]):
            return container.observe_groups(membership, mounts, pid)

    def test_v1_verified_mapping_caps_host_and_admits_twelve(self):
        files, membership, mounts = self.fixture()
        observed = self.observe(files, membership, mounts)
        self.assertEqual(len(observed['mappings']), 2)
        memory = {'MemTotal': 375 * container.GIB, 'MemAvailable': 300 * container.GIB}
        plan = container.resource_plan(12, memory, 96, observed)
        self.assertEqual(plan['effective_jobs'], 12)
        self.assertEqual(plan['visible_cpu_budget_limit'], 12)
        self.assertEqual(plan['visible_memory_headroom_bytes'], 42 * container.GIB)
        self.assertEqual(plan['visible_memory_limit_bytes'], 43 * container.GIB)
        self.assertIsNone(container.resource_plan(13, memory, 96, observed)['effective_jobs'])
        self.assertIsNone(container.resource_plan(12, memory, 11, observed)['effective_jobs'])
        # The same actual leaf is verifiable under a cgroup namespace too.
        self.assertEqual(len(self.observe(files, membership.replace('/docker/one', '/'), mounts)['mappings']), 2)

    def test_v1_hierarchical_limit_memory_boundary_and_no_unbounded_fallback(self):
        files, membership, mounts = self.fixture()
        memory = {'MemTotal': 375 * container.GIB, 'MemAvailable': 300 * container.GIB}
        files['/cg/memory/memory.limit_in_bytes'] = str(1 << 63)
        for used, expected in [(3 * container.GIB, 12), (3 * container.GIB + 1, None)]:
            files['/cg/memory/memory.usage_in_bytes'] = str(used)
            self.assertEqual(container.resource_plan(12, memory, 96,
                             self.observe(files, membership, mounts))['effective_jobs'], expected)
        for field, value in [('/cg/memory/memory.stat', 'hierarchical_memory_limit ' + str(1 << 63)),
                             ('/cg/cpu/cpu.cfs_quota_us', '-1')]:
            bad = dict(files, **{field: value})
            with self.assertRaises(ValueError):
                container.resource_plan(1, memory, 96, self.observe(bad, membership, mounts))
        for jobs in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                container.resource_plan(jobs, memory, 96, self.observe(files, membership, mounts))

    def test_mapping_and_invalid_observations_fail_closed(self):
        files, membership, mounts = self.fixture()
        for bad_member, bad_mounts, pid in [
                (membership, mounts, 456), (membership, mounts + mounts, 123),
                (membership.replace('/docker/one', '/../escape'), mounts, 123),
                (membership.replace('4:cpu,cpuacct', '4:cpuacct'), mounts, 123),
                (membership, mounts.replace('/docker/one', '/foreign'), 123)]:
            with self.subTest(member=bad_member, mounts=bad_mounts), self.assertRaises(ValueError):
                self.observe(files, bad_member, bad_mounts, pid)
        for field, value in [('/cg/cpu/cpu.cfs_quota_us', '0'), ('/cg/cpu/cpu.cfs_period_us', '0'),
                             ('/cg/memory/memory.stat', 'cache 12'),
                             ('/cg/memory/memory.usage_in_bytes', '-1')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.observe(dict(files, **{field: value}), membership, mounts)

    def test_v2_visible_ancestors_restrict_admission(self):
        files = {'/cg/job/cgroup.procs': '123', '/cg/cgroup.procs': '',
                 '/cg/job/cpu.max': '1200000 100000', '/cg/job/memory.max': str(43 * container.GIB),
                 '/cg/job/memory.current': str(container.GIB),
                 '/cg/cpu.max': '800000 100000', '/cg/memory.max': str(50 * container.GIB),
                 '/cg/memory.current': str(20 * container.GIB)}
        groups = self.observe(files, '0::/job', '1 0 0:1 / /cg rw - cgroup2 none rw')
        plan = container.resource_plan(12, {'MemTotal': 375 * container.GIB,
                                           'MemAvailable': 300 * container.GIB}, 96, groups)
        self.assertIsNone(plan['effective_jobs'])
        self.assertEqual(plan['visible_cpu_budget_limit'], 8)
        self.assertEqual(plan['visible_memory_headroom_bytes'], 30 * container.GIB)

    def test_filesystem_opt_in_does_not_relax_default(self):
        local.check_filesystem('ext4', False)
        for kind in ('ext4', 'xfs'):
            local.check_filesystem(kind, True)
        for kind, container_mode in [('xfs', False), ('overlay', True), ('nfs', True), ('tmpfs', False)]:
            with self.assertRaises(ValueError):
                local.check_filesystem(kind, container_mode)


class ArrowDownload(unittest.TestCase):
    '''Check the actual native CMake argument lists with offline command fixtures.'''

    @classmethod
    def setUpClass(cls):
        cmake = shutil.which('cmake')
        if cmake is None:
            raise unittest.SkipTest('Native CMake required; no WSL fallback')
        text = (HERE.parents[2] / 'cmake/ApacheArrow.cmake').read_text(encoding='utf-8')
        configure = re.findall(r'\bCONFIGURE_COMMAND\s+(.*?)\n\s+BUILD_COMMAND\b', text, re.S)
        build = re.findall(r'\bBUILD_COMMAND\s+(.*?)\n\s+BUILD_JOB_SERVER_AWARE\b', text, re.S)
        parallel = re.findall(r'if\(CMAKE_VERSION VERSION_GREATER_EQUAL 3\.28\).*?endif\(\)', text, re.S)
        if any(len(items) != 1 for items in (configure, build, parallel)):
            raise AssertionError('Expected unique actual Arrow command and parallelism blocks')
        cls.commands = {}
        # CMake itself expands the actual command lists and version branch. This
        # script-mode check does not generate or run a native build system.
        with tempfile.TemporaryDirectory(prefix='arrow-argv-') as directory:
            root = Path(directory).resolve()
            parser = root / 'capture.cmake'
            parser.write_text('''cmake_minimum_required(VERSION 3.16)
set(CMAKE_VERSION "${TEST_VERSION}")
function(capture label)
  math(EXPR count "${ARGC} - 1")
  file(WRITE "${OUTPUT}/${label}-count" "${count}")
  foreach(index RANGE 1 ${count})
    math(EXPR output_index "${index} - 1")
    file(WRITE "${OUTPUT}/${label}-${output_index}" "${ARGV${index}}")
  endforeach()
endfunction()
''' + parallel[0] + '\ncapture(configure\n' + configure[0]
                              + '\n)\ncapture(build\n' + build[0] + '\n)\n', encoding='utf-8')
            for version in ('3.27', '3.28'):
                output = root / version
                output.mkdir()
                result = subprocess.run([cmake, '-DOUTPUT=' + output.as_posix(),
                                         '-DTEST_VERSION=' + version, '-P', str(parser)],
                                        text=True, capture_output=True)
                if result.returncode != 0:
                    raise AssertionError(result.stdout + result.stderr)
                cls.commands[version] = {}
                for phase in ('configure', 'build'):
                    count = int((output / (phase + '-count')).read_text())
                    argv = [(output / (phase + '-' + str(i))).read_text(encoding='utf-8')
                            for i in range(count)]
                    if not argv or not Path(argv[0]).samefile(cmake):
                        raise AssertionError('Arrow must invoke CMAKE_COMMAND directly, without a shell')
                    cls.commands[version][phase] = argv

    def run_fixture(self, argv, exitcode=0):
        with tempfile.TemporaryDirectory(prefix='arrow-direct-') as directory:
            root = Path(directory).resolve()
            thirdparty = root / 'thirdparty'
            thirdparty.mkdir()
            # Either source/export or the former all-dependency prefetch would
            # leave this marker. The existing partial file must remain unused.
            old = 'printf unexpected > "$ARROW_TEST_MARKER"\nexport ARROW_ABSL_URL=partial\n'
            export = thirdparty / 'export.sh'
            export.write_text(old, encoding='utf-8')
            downloader = thirdparty / 'download_dependencies.sh'
            downloader.write_text('#!/usr/bin/env bash\nprintf unexpected > "$ARROW_TEST_MARKER"\nexit 91\n',
                                  encoding='utf-8')
            downloader.chmod(0o700)
            fake = root / 'fake-cmake.py'
            fake.write_text('''import json, os, sys
from pathlib import Path
Path('invoked.json').write_text(json.dumps(sys.argv[1:]), encoding='utf-8')
raise SystemExit(int(os.environ['ARROW_TEST_EXIT']))
''', encoding='utf-8')
            environment = dict(os.environ)
            environment.update(ARROW_TEST_MARKER=(root / 'unexpected').as_posix(),
                               ARROW_TEST_EXIT=str(exitcode))
            # Replace only the CMake executable, preserving its actual parsed
            # arguments. Python makes the fake tool executable on both platforms.
            result = subprocess.run([sys.executable, str(fake), *argv[1:]], cwd=root,
                                    env=environment, text=True, capture_output=True)
            return {'result': result, 'argv': json.loads((root / 'invoked.json').read_text()),
                    'unexpected': (root / 'unexpected').exists(), 'export': export.read_text(),
                    'old_export': old}

    def test_native_commands_preserve_options_and_both_parallelism_branches(self):
        expected = ['-S', '.', '-B', '.', '-DCMAKE_BUILD_TYPE=Release', '-DARROW_USE_CCACHE=OFF',
                    '-DARROW_USE_SCCACHE=OFF', '-DARROW_DEPENDENCY_SOURCE=BUNDLED', '-DARROW_BUILD_STATIC=ON',
                    '-DARROW_JEMALLOC=ON', '-DARROW_SIMD_LEVEL=DEFAULT', '-DARROW_BUILD_EXAMPLES=OFF',
                    '-DARROW_PARQUET=ON', '-DARROW_CSV=ON', '-DARROW_WITH_ZSTD=ON', '-DARROW_WITH_LZ4=ON',
                    '-DARROW_WITH_ZLIB=ON']
        for version, commands in self.commands.items():
            with self.subTest(version=version):
                self.assertEqual(commands['configure'][1:], expected)
                self.assertEqual(commands['build'][1:], ['--build', '.'] + (['-j8'] if version == '3.27' else []))

    def test_partial_export_and_all_dependency_script_are_not_executed(self):
        for phase, argv in self.commands['3.28'].items():
            with self.subTest(phase=phase):
                observed = self.run_fixture(argv)
                self.assertEqual(observed['result'].returncode, 0, observed['result'].stderr)
                self.assertEqual(observed['argv'], argv[1:])
                self.assertFalse(observed['unexpected'])
                self.assertEqual(observed['export'], observed['old_export'])

    def test_configure_and_build_nonzero_results_are_not_masked(self):
        for phase, exitcode in (('configure', 23), ('build', 29)):
            with self.subTest(phase=phase):
                argv = self.commands['3.28'][phase]
                observed = self.run_fixture(argv, exitcode)
                self.assertEqual(observed['result'].returncode, exitcode)
                self.assertEqual(observed['argv'], argv[1:])
                self.assertFalse(observed['unexpected'])
                self.assertEqual(observed['export'], observed['old_export'])


class ArrowCache(unittest.TestCase):
    @contextmanager
    def fixture(self):
        # Synthetic small bytes substitute only the locked archive contents.
        # No real upstream download, extraction or compiler is invoked.
        with tempfile.TemporaryDirectory(prefix='arrow cache ') as folder:
            root = Path(folder).resolve()
            source, work, cache = (root / name for name in ('source', 'work', 'cache'))
            for directory in (source, work, cache, work / 'provenance', source / 'cmake'):
                directory.mkdir()
            (source / 'cmake/ApacheArrow.cmake').write_bytes((HERE.parents[2] / 'cmake/ApacheArrow.cmake').read_bytes())
            versions = b'synthetic fixed version table\n'
            table = work / 'build/src/apache-arrow-cpp/cpp/thirdparty/versions.txt'
            table.parent.mkdir(parents=True)
            table.write_bytes(versions)
            specs = []
            for original in arrow_cache.ARCHIVES:
                data = ('synthetic archive ' + original['name']).encode()
                spec = dict(original, sha256=hashlib.sha256(data).hexdigest())
                (cache / (spec['sha256'] + spec['extension'])).write_bytes(data)
                specs.append(spec)
            original_fstat = os.fstat
            def posix_fstat(fd):
                info = original_fstat(fd)
                if os.name == 'nt':
                    # Windows Python lstat ctime is creation-time while fstat
                    # exposes change-time. Normalize only that platform field;
                    # inode, size, mode, link count, mtime and real bytes remain.
                    for spec in specs:
                        candidate = cache / (spec['sha256'] + spec['extension'])
                        if candidate.exists():
                            path_info = candidate.lstat()
                            if (info.st_dev, info.st_ino) == (path_info.st_dev, path_info.st_ino):
                                return SimpleNamespace(**{name: getattr(info, name) for name in
                                    ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_nlink')},
                                    st_ctime_ns=path_info.st_ctime_ns)
                return info
            with mock.patch.object(arrow_cache, 'ARCHIVES', tuple(specs)), \
                    mock.patch.object(arrow_cache, 'VERSIONS_SHA256', hashlib.sha256(versions).hexdigest()), \
                    mock.patch.object(os, 'fstat', posix_fstat):
                yield source, work, cache, specs

    def test_complete_private_copies_and_postbuild_proof_use_fixed_inputs(self):
        with self.fixture() as (source, work, cache, specs):
            record = arrow_cache.prepare(source, work, cache)
            self.assertEqual(len(record['archives']), 7)
            self.assertFalse(record['network_fetch_performed'])
            self.assertFalse(record['build_executed'])
            urls = (work / 'arrow-cache/urls.nul').read_bytes().split(b'\0')
            self.assertEqual(len(urls), 8)
            self.assertEqual(urls[-1], b'')
            for spec, item, url in zip(specs, record['archives'], urls):
                copied = Path(item['path'])
                self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(), spec['sha256'])
                self.assertEqual(url.decode(), copied.as_uri())
                self.assertIn('%20', item['url'])  # The actual private path contains a space.
                (cache / (spec['sha256'] + spec['extension'])).write_bytes(b'changed original after copy')
            # Consumers verify and use only the exclusive private copies.
            proof = arrow_cache.verify_preparation(source, work, cache, verify_upstream=True)
            self.assertEqual(proof['archive_count'], 7)
            self.assertEqual(proof['sha256'], hashlib.sha256((work / 'provenance/arrow-cache.json').read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                arrow_cache.prepare(source, work, cache)

    def test_missing_corrupt_and_output_failure_never_publish_success_or_resume(self):
        for failure in ('missing', 'corrupt', 'output'):
            with self.subTest(failure=failure), self.fixture() as (source, work, cache, specs):
                item = cache / (specs[2]['sha256'] + specs[2]['extension'])
                if failure == 'missing':
                    item.unlink()
                elif failure == 'corrupt':
                    item.write_bytes(b'wrong content')
                    item.with_suffix('.sha256').write_text(hashlib.sha256(item.read_bytes()).hexdigest())
                original_open = Path.open
                def opened(path, *args, **kwargs):
                    if failure == 'output' and path == work / 'arrow-cache' / specs[2]['filename']:
                        raise OSError('controlled output failure')
                    return original_open(path, *args, **kwargs)
                with mock.patch.object(Path, 'open', opened), self.assertRaises((ValueError, OSError)):
                    arrow_cache.prepare(source, work, cache)
                self.assertFalse((work / 'provenance/arrow-cache.json').exists())
                with self.assertRaises(FileExistsError):
                    arrow_cache.prepare(source, work, cache)

    def test_hardlink_symlink_shape_nesting_and_feature_drift_are_rejected(self):
        for failure in ('hardlink', 'symlink_shape', 'nested', 'features'):
            with self.subTest(failure=failure), self.fixture() as (source, work, cache, specs):
                item = cache / (specs[0]['sha256'] + specs[0]['extension'])
                original_lstat = Path.lstat
                if failure == 'hardlink':
                    os.link(item, cache / 'second-link')
                elif failure == 'nested':
                    cache = source / 'nested'
                    cache.mkdir()
                elif failure == 'features':
                    (source / 'cmake/ApacheArrow.cmake').write_text('changed options')
                def lstat(path, *args, **kwargs):
                    info = original_lstat(path, *args, **kwargs)
                    if failure == 'symlink_shape' and path == item:
                        # Portable stat input boundary; actual Windows symlink
                        # creation privileges are not a prerequisite for this check.
                        return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_nlink=1)
                    return info
                with mock.patch.object(Path, 'lstat', lstat), self.assertRaises(ValueError):
                    arrow_cache.prepare(source, work, cache)
                self.assertFalse((work / 'provenance/arrow-cache.json').exists())

    def test_postbuild_rejects_changed_copy_proof_urls_and_upstream_table(self):
        for failure in ('copy', 'proof', 'urls', 'versions'):
            with self.subTest(failure=failure), self.fixture() as (source, work, cache, specs):
                arrow_cache.prepare(source, work, cache)
                if failure == 'copy':
                    (work / 'arrow-cache' / specs[0]['filename']).write_bytes(b'changed copy')
                elif failure == 'proof':
                    proof = work / 'provenance/arrow-cache.json'
                    record = json.loads(proof.read_text())
                    record['archives'][0]['url'] = 'https://untrusted.invalid/archive'
                    proof.write_text(json.dumps(record))
                elif failure == 'urls':
                    (work / 'arrow-cache/urls.nul').write_bytes(b'wrong\0')
                else:
                    (work / 'build/src/apache-arrow-cpp/cpp/thirdparty/versions.txt').write_bytes(b'changed version table')
                with self.assertRaises(ValueError):
                    arrow_cache.verify_preparation(source, work, cache, verify_upstream=True)

    def test_actual_builder_branch_keeps_default_and_exports_only_after_success(self):
        bash = bash_path()
        if bash is None:
            self.skipTest('Native Bash unavailable; no WSL fallback')
        block = SCRIPT.read_text().split('# BEGIN ARROW CACHE\n', 1)[1].split('# END ARROW CACHE', 1)[0]
        block = block.replace('/usr/bin/python3 ', 'python_helper ')
        for enabled, code in ((False, 0), (True, 0), (True, 37)):
            with self.subTest(enabled=enabled, code=code), self.fixture() as (source, work, cache, specs):
                record = arrow_cache.prepare(source, work, cache)
                prefix = ('set -euo pipefail\nsource_root=/fixed/source\nwork=' + shlex.quote(work.as_posix())
                          + '\ncontainer_arrow_cache=' + shlex.quote(cache.as_posix() if enabled else '')
                          + '\npython_helper() { printf "helper %s\\n" "$@"; return ' + str(code) + '; }\n')
                names = ['ARROW_' + spec['name'] + '_URL' for spec in specs]
                prefix += ''.join('export ' + name + '=unchanged\n' for name in names)
                suffix = '\nprintf "exports\\n"\n' + ''.join('printf "%s\\n" "$' + name + '"\n' for name in names)
                result = subprocess.run([bash, '-s'], input=prefix + block + suffix, text=True, capture_output=True)
                self.assertEqual(result.returncode, code, result.stderr)
                if code:
                    self.assertNotIn('exports', result.stdout)
                    self.assertFalse((work / 'provenance/arrow-cache-proof.sha256').exists())
                else:
                    exported = result.stdout.split('exports\n', 1)[1].splitlines()
                    self.assertEqual(exported, [item['url'] for item in record['archives']] if enabled else ['unchanged'] * 7)
                    self.assertEqual((work / 'provenance/arrow-cache-proof.sha256').exists(), enabled)
                    if enabled:
                        self.assertIn('helper /fixed/source/scripts/ec/ci/prepare-arrow-cache.py', result.stdout)
                        self.assertIn('helper --cache', result.stdout)


if __name__ == '__main__':
    unittest.main()
