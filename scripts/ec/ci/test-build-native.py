#!/usr/bin/env python3
"""Small offline checks; no native build, package extraction or network request."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
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
                   '--local-revision', 'a' * 40], 'scalar false false 1')]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                result = subprocess.run([bash, '-s', '--', *argv], input=parser, text=True, capture_output=True)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, expected), result.stderr)
        for argv in (['--backend'], ['--backend', 'avx'], ['--backend=isal'], ['extra'],
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
                     ['--local-work', '/a', '--local-work', '/b']):
            with self.subTest(rejected=argv):
                result = subprocess.run([bash, '-s', '--', *argv], input=parser, text=True, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('true false', result.stdout)

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
                                     (1, True, True), (2, True, True), (4, True, True)]:
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

    def test_real_final_receipt_four_modes_and_loader_mismatch(self):
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY\n", SCRIPT.read_text(), re.S)
        block, = [item for item in blocks if "path = work / 'provenance/native-build.json'" in item]
        code = compile(block, str(SCRIPT) + ':actual-final-receipt', 'exec')
        fixed_isal = '40ccd5e5abaff0451feff750d2b011370a546ac4706d1b06b9285ac26eda2c3c'
        for backend, mode, bad_loader in [('scalar', False, False), ('isal', False, False),
                                           ('scalar', True, False), ('isal', True, False), ('scalar', True, True)]:
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
                for name in ('build-native.sh', 'prepare-isal.py'):
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
                put(work / 'provenance/local-preflight.json', b'{"tools":{}}')
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
                argv = ['-', str(source), str(work), backend, 'true', 'true', 'a' * 40, str(mode).lower(), str(deps)]
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
                self.assertEqual(lab['native_build_receipt_sha256'], sha(work / 'provenance/native-build.json'))
                self.assertEqual(calls, [None, '/usr/local/lib'] * 13 if mode else [])


if __name__ == '__main__':
    unittest.main()
