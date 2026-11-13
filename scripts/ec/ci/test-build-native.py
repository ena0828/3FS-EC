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
        self.assertEqual(len(blocks), 4)
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
        parser = text.split(marker, 1)[0] + '\nprintf "%s %s %s\\n" "$backend" "$with_lab" "$with_regression"\n'
        cases = [([], 'scalar false false'),
                 (['--with-lab-targets'], 'scalar true false'),
                 (['--backend', 'isal'], 'isal false false'),
                 (['--with-ec-regression-targets', '--backend', 'isal', '--with-lab-targets'], 'isal true true'),
                 (['--with-lab-targets', '--backend', 'scalar', '--with-ec-regression-targets'], 'scalar true true')]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                result = subprocess.run([bash, '-s', '--', *argv], input=parser, text=True, capture_output=True)
                self.assertEqual((result.returncode, result.stdout.strip()), (0, expected), result.stderr)
        for argv in (['--backend'], ['--backend', 'avx'], ['--backend=isal'], ['extra'],
                     ['--backend', 'scalar', '--backend', 'isal'],
                     ['--with-lab-targets', '--with-lab-targets'],
                     ['--with-ec-regression-targets', '--with-ec-regression-targets']):
            with self.subTest(rejected=argv):
                result = subprocess.run([bash, '-s', '--', *argv], input=parser, text=True, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('true false', result.stdout)

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
