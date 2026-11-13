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
import subprocess
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'build-native.sh'
spec = importlib.util.spec_from_file_location('prepare_isal', HERE / 'prepare-isal.py')
isal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isal)


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
        marker = '\n[[ "${GITHUB_ACTIONS:-}"'
        self.assertEqual(text.count(marker), 1)
        parser = text.split(marker, 1)[0] + '\nprintf "%s %s %s %s\\n" "$backend" "$with_lab" "$with_regression" "$build_jobs"\n'
        cases = [([], 'scalar false false 1'),
                 (['--with-lab-targets'], 'scalar true false 1'),
                 (['--backend', 'isal'], 'isal false false 1'),
                 (['--with-ec-regression-targets', '--backend', 'isal', '--with-lab-targets'], 'isal true true 1'),
                 (['--with-lab-targets', '--backend', 'scalar', '--with-ec-regression-targets'], 'scalar true true 1'),
                 (['--build-jobs', '2', '--backend', 'isal'], 'isal false false 2'),
                 (['--build-jobs', '1'], 'scalar false false 1')]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                result = subprocess.run([bash, '-s', '--', *argv], input=parser, text=True, capture_output=True)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, expected), result.stderr)
        for argv in (['--backend'], ['--backend', 'avx'], ['--backend=isal'], ['extra'],
                     ['--backend', 'scalar', '--backend', 'isal'],
                     ['--with-lab-targets', '--with-lab-targets'],
                     ['--with-ec-regression-targets', '--with-ec-regression-targets'],
                     ['--build-jobs'], ['--build-jobs', '0'], ['--build-jobs', '3'],
                     ['--build-jobs', '02'], ['--build-jobs=2'],
                     ['--build-jobs', '1', '--build-jobs', '2']):
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
        for mem, cpu, groups in [
            ({**memory, 'MemTotal': 15 * gib - 1}, 4, []),
            ({**memory, 'MemAvailable': 12 * gib - 1}, 4, []),
            (memory, 3, []),
            (memory, 8, [{'cpu_max': '399999 100000', 'memory_max': None, 'memory_current': None}]),
            (memory, 8, [{'cpu_max': 'max 100000', 'memory_max': str(13 * gib), 'memory_current': gib + 1}]),
        ]:
            with self.subTest(mem=mem, cpu=cpu, groups=groups):
                self.assertIsNone(plan(2, mem, cpu, groups)['effective_jobs'])
                self.assertEqual(plan(1, mem, cpu, groups)['effective_jobs'], 1)
        for jobs in (0, 3, True):
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
        env_block = text.split('export CC=/usr/bin/gcc-12', 1)[1].split('\nbash "$source_root/scripts/ec/cluster/fetch-fdb.sh"', 1)[0]
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
            for jobs, full in [(1, False), (2, False), (1, True), (2, True)]:
                (Path(folder) / 'cmake-argv').write_text('')
                flags = f'build_jobs={jobs}\nwith_lab={str(full).lower()}\nwith_regression={str(full).lower()}\n'
                result = subprocess.run([bash, '-s'], input=prefix + env_block + '\n' + flags + block,
                                        text=True, capture_output=True, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                chunks = (Path(folder) / 'cmake-argv').read_text().split('END\n')
                self.assertEqual(len(chunks), 3)  # Exactly configure + one aggregate build.
                configure, actual = (part.splitlines() for part in chunks[:2])
                self.assertIn(f'-DCMAKE_JOB_POOLS=ec_compile={jobs};ec_link=1', configure)
                self.assertIn('-DCMAKE_JOB_POOL_COMPILE=ec_compile', configure)
                self.assertIn('-DCMAKE_JOB_POOL_LINK=ec_link', configure)
                self.assertIn('-DHF3FS_EXTERNAL_BUILD_JOBS=1', configure)
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


if __name__ == '__main__':
    unittest.main()
