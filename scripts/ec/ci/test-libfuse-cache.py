#!/usr/bin/env python3
"""Small offline Git fixtures; no compiler, dependency build or network access."""
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('libfuse_cache', HERE / 'prepare-libfuse-cache.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)
GIT = shutil.which('git')


@contextmanager
def fixture(kind='complete', surprise=None):
    with tempfile.TemporaryDirectory(prefix='libfuse-cache-') as folder:
        root = Path(folder).resolve()
        source, work, cached, original = (root / name for name in ('source', 'work', 'cache', 'original'))
        for path in (source, work, cached, original):
            path.mkdir()
        (work / 'provenance').mkdir()
        config = root / 'empty-config'
        config.touch()
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(config), GIT_TERMINAL_PROMPT='0')

        def git(*args):
            return subprocess.check_output([GIT, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                                            '-c', 'core.autocrlf=false', '-C', str(original), *args],
                                           env=env, text=True, stderr=subprocess.PIPE).strip()
        git('init', '-q', '--template=')
        (original / 'tracked.txt').write_text('fixed first content\n', encoding='utf-8')
        git('add', 'tracked.txt')
        git('commit', '-qm', 'fixture base')
        base = git('rev-parse', 'HEAD')
        if surprise == 'gitlink':
            git('update-index', '--add', '--cacheinfo', '160000,' + base + ',nested')
        elif surprise == 'gitmodules':
            (original / '.gitmodules').write_text(
                '[submodule "unexpected"]\n\tpath = nested\n\turl = https://example.invalid/nested.git\n', encoding='utf-8')
            git('add', '.gitmodules')
        (original / 'tracked.txt').write_text('fixed second content\n', encoding='utf-8')
        git('add', 'tracked.txt')
        git('commit', '-qm', 'fixture target')
        revision, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
        bundle = cached / 'fixed.bundle'
        git('bundle', 'create', str(bundle), 'HEAD', *(['^' + base] if kind == 'prerequisite' else []))
        expected = hashlib.sha256(bundle.read_bytes()).hexdigest()
        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(cache, 'GIT', GIT))
            patches.enter_context(mock.patch.object(cache, 'REVISION', revision))
            patches.enter_context(mock.patch.object(cache, 'EXPECTED_TREE', tree))
            if os.name == 'nt':
                # Windows Python 3.13 lstat reports creation-time while fstat
                # reports change-time for Git-renamed files. Emulate matching
                # POSIX ctime observations only; retain actual inode/size/mtime,
                # link counts, bytes and all real Git commands. Linux's helper
                # still compares the full unmodified ctime-bearing identity.
                original_fstat = os.fstat
                def posix_fstat(fd):
                    actual = original_fstat(fd)
                    if bundle.exists():
                        path_info = bundle.lstat()
                        if (actual.st_dev, actual.st_ino) == (path_info.st_dev, path_info.st_ino):
                            return SimpleNamespace(**{name: getattr(actual, name) for name in
                                ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode', 'st_nlink')},
                                st_ctime_ns=path_info.st_ctime_ns)
                    return actual
                patches.enter_context(mock.patch.object(cache.os, 'fstat', side_effect=posix_fstat))
            yield SimpleNamespace(root=root, source=source, work=work, bundle=bundle,
                                  sha=expected, revision=revision, tree=tree, base=base)


class LibfuseCache(unittest.TestCase):
    def no_prepared(self, case):
        self.assertFalse((case.work / 'provenance/libfuse-cache.json').exists())

    def test_complete_local_bundle_reaches_fixed_clean_checkout_and_records_provenance(self):
        with fixture() as case:
            # A hostile inherited rewrite must not affect the helper's local-only Git context.
            with mock.patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1',
                    'GIT_CONFIG_KEY_0': 'url.https://invalid.invalid/.insteadOf',
                    'GIT_CONFIG_VALUE_0': str(case.work)}):
                record = cache.prepare(case.source, case.work, case.bundle, case.sha)
            self.assertEqual((record['revision'], record['tree']), (case.revision, case.tree))
            self.assertEqual(record['original_remote'], cache.ORIGIN)
            self.assertEqual(record['bundle']['requested_sha256'], record['bundle']['actual_sha256'])
            self.assertIn('not an official', record['bundle']['digest_scope'])
            self.assertEqual((case.work / 'libfuse/tracked.txt').read_text(), 'fixed second content\n')
            copied = str(case.work / 'libfuse-cache/input.bundle')
            fetch = next(row for row in record['commands'] if 'fetch' in row['argv'])
            self.assertEqual(fetch['argv'][-2:], [copied, case.revision])
            self.assertTrue(all(row['exit_code'] == 0 for row in record['commands']))
            self.assertFalse(any('https://' in arg for arg in fetch['argv']))
            for flag in ('network_fetch_performed', 'build_executed', 'acceptance_executed'):
                self.assertIs(record[flag], False)
            self.assertEqual(json.loads((case.work / 'provenance/libfuse-cache.json').read_text()), record)
            self.assertEqual(record['status'], 'fixed-libfuse-source-prepared')
            with self.assertRaises(ValueError):
                cache.prepare(case.source, case.work, case.bundle, case.sha)

    def test_missing_or_corrupt_bundle_and_forged_sidecar_reject(self):
        for change in ('missing', 'bad-hash', 'invalid-digest'):
            with self.subTest(change=change), fixture() as case:
                requested = case.sha
                if change == 'missing':
                    case.bundle.unlink()
                elif change == 'bad-hash':
                    value = bytearray(case.bundle.read_bytes())
                    value[-1] ^= 1
                    case.bundle.write_bytes(value)
                    case.bundle.with_suffix('.sha256').write_text(hashlib.sha256(value).hexdigest())
                else:
                    requested = 'x' * 64
                with self.assertRaises((ValueError, OSError)):
                    cache.prepare(case.source, case.work, case.bundle, requested)
                self.no_prepared(case)

    def test_links_and_root_overlap_reject(self):
        for kind in ('hardlink', 'symlink', 'overlap'):
            with self.subTest(kind=kind), fixture() as case:
                source = case.source
                if kind == 'hardlink':
                    os.link(case.bundle, case.root / 'second.bundle')
                elif kind == 'overlap':
                    source = case.bundle.parent
                else:
                    # Only lstat's symlink mode is injected when Windows lacks privilege.
                    target = case.bundle.with_name('target.bundle')
                    case.bundle.rename(target)
                    try:
                        case.bundle.symlink_to(target)
                    except OSError:
                        case.bundle.write_bytes(target.read_bytes())
                        original = Path.lstat
                        def linked(path, *args, **kwargs):
                            value = original(path, *args, **kwargs)
                            if path == case.bundle:
                                fields = list(value)
                                fields[0] = stat.S_IFLNK | 0o777
                                return os.stat_result(fields)
                            return value
                        with mock.patch.object(Path, 'lstat', linked), self.assertRaises(ValueError):
                            cache.prepare(source, case.work, case.bundle, case.sha)
                        self.no_prepared(case)
                        continue
                with self.assertRaises(ValueError):
                    cache.prepare(source, case.work, case.bundle, case.sha)
                self.no_prepared(case)

    def test_prerequisite_bundle_is_rejected_in_empty_repository(self):
        with fixture('prerequisite') as case, self.assertRaises(ValueError):
            try:
                cache.prepare(case.source, case.work, case.bundle, case.sha)
            finally:
                self.no_prepared(case)
                rows = [json.loads(line) for line in (case.work / 'libfuse-cache/commands.jsonl').read_text().splitlines()]
                self.assertNotEqual(rows[-1]['exit_code'], 0)
                self.assertEqual(rows[-1]['argv'][-3:-1], ['bundle', 'verify'])

    def test_wrong_fixed_ref_or_tree_is_rejected(self):
        for bad in ('revision', 'tree'):
            with self.subTest(bad=bad), fixture() as case:
                name = 'REVISION' if bad == 'revision' else 'EXPECTED_TREE'
                with mock.patch.object(cache, name, case.base if bad == 'revision' else '0' * 40):
                    expected = 'does not advertise' if bad == 'revision' else 'tree differs from source lock'
                    with self.assertRaisesRegex(ValueError, expected):
                        cache.prepare(case.source, case.work, case.bundle, case.sha)
                self.no_prepared(case)
                rows = [json.loads(line) for line in (case.work / 'libfuse-cache/commands.jsonl').read_text().splitlines()]
                self.assertEqual(rows[-1]['exit_code'], 0)
                self.assertEqual(rows[-1]['argv'][-3:-1], ['bundle', 'list-heads'] if bad == 'revision'
                                 else [str(case.work / 'libfuse'), 'rev-parse'])

    def test_unexpected_gitlink_or_gitmodules_is_rejected(self):
        for surprise in ('gitlink', 'gitmodules'):
            with self.subTest(surprise=surprise), fixture(surprise=surprise) as case:
                with self.assertRaisesRegex(ValueError, 'Unexpected libfuse submodule'):
                    cache.prepare(case.source, case.work, case.bundle, case.sha)
                self.no_prepared(case)
                rows = [json.loads(line) for line in (case.work / 'libfuse-cache/commands.jsonl').read_text().splitlines()]
                self.assertEqual(rows[-1]['argv'][-4:-1], ['ls-tree', '-r', '-z'])
                self.assertEqual(rows[-1]['exit_code'], 0)


if __name__ == '__main__':
    unittest.main()
