#!/usr/bin/env python3
"""Offline cache boundary checks with fixture bytes and simulated dpkg-deb only."""
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.request


SCRIPT = Path(__file__).resolve().parents[1] / 'cluster/prepare-fdb-cache.py'
spec = importlib.util.spec_from_file_location('prepare_fdb_cache', SCRIPT)
fdb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fdb)


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix='ec-fdb-cache-') as temp:
        root = Path(temp).resolve()
        source, work, cache = (root / name for name in ('source', 'work', 'cache'))
        for directory in (source, work, cache):
            directory.mkdir(mode=0o700)
        packages = []
        contents = {}
        for role in ('clients', 'server'):
            name = 'foundationdb-' + role
            data = ('fixture bytes for ' + name + '\n').encode()
            digest = hashlib.sha256(data).hexdigest()
            package = {'package': name, 'version': '7.3.63', 'architecture': 'amd64',
                       'url': 'https://fixture.invalid/' + name + '.deb',
                       'sha256': digest, 'size': len(data)}
            packages.append(package)
            contents[name] = data
            (cache / (digest + '.deb')).write_bytes(data)
        yield SimpleNamespace(root=root, source=source, work=work, cache=cache,
                              packages=tuple(packages), contents=contents)


class FakeDpkg:
    """Reject every subprocess command except metadata and extraction of verified copies."""

    def __init__(self, test, case, metadata_override=None, fail_extract=0):
        self.test, self.case = test, case
        self.metadata_override = metadata_override or {}
        self.fail_extract = fail_extract
        self.events = []
        self.metadata_paths = {}
        self.extract_paths = {}

    def package(self, argv, operation):
        self.test.assertEqual(argv[:2], ['/usr/bin/dpkg-deb', operation])
        copied = Path(argv[2])
        self.test.assertTrue(copied.is_relative_to(self.case.work / 'fdb/downloads'))
        self.test.assertFalse(copied.is_relative_to(self.case.cache))
        data = copied.read_bytes()
        matches = [item for item in self.case.packages
                   if hashlib.sha256(data).hexdigest() == item['sha256']]
        self.test.assertEqual(len(matches), 1)
        item = matches[0]
        self.test.assertEqual(len(data), item['size'])
        self.test.assertEqual(data, self.case.contents[item['package']])
        return item, copied

    def metadata(self, argv, *, text):
        self.test.assertTrue(text)
        self.test.assertEqual(argv[3:], ['Package', 'Version', 'Architecture'])
        item, copied = self.package(argv, '--field')
        self.events.append(('metadata', item['package']))
        self.metadata_paths[item['package']] = copied
        fields = {'Package': item['package'], 'Version': item['version'],
                  'Architecture': item['architecture']}
        fields.update(self.metadata_override)
        return ''.join(key + ': ' + value + '\n' for key, value in fields.items())

    def extract(self, argv, *, check):
        self.test.assertTrue(check)
        self.test.assertEqual(len(argv), 4)
        self.test.assertEqual(len(self.metadata_paths), len(self.case.packages),
                              'Both package metadata checks must precede extraction')
        item, copied = self.package(argv, '--extract')
        self.test.assertEqual(copied, self.metadata_paths[item['package']])
        self.events.append(('extract', item['package']))
        self.extract_paths[item['package']] = copied
        if len(self.extract_paths) == self.fail_extract:
            raise subprocess.CalledProcessError(2, argv)
        destination = Path(argv[3])
        self.test.assertTrue(destination.is_relative_to(self.case.work / 'fdb'))
        paths = (('usr/bin/fdbcli', 'usr/lib/libfdb_c.so')
                 if item['package'].endswith('-clients') else ('usr/sbin/fdbserver',))
        for relative in paths:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(('simulated extracted ' + relative + '\n').encode())
        return subprocess.CompletedProcess(argv, 0)


@contextmanager
def simulated_commands(test, case, **options):
    dpkg = FakeDpkg(test, case, **options)
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(fdb, 'PACKAGES', case.packages))
        stack.enter_context(mock.patch.object(fdb.subprocess, 'check_output', side_effect=dpkg.metadata))
        stack.enter_context(mock.patch.object(fdb.subprocess, 'run', side_effect=dpkg.extract))
        stack.enter_context(mock.patch.object(urllib.request, 'urlopen',
                                             side_effect=AssertionError('No network is permitted')))
        stack.enter_context(mock.patch.object(socket, 'create_connection',
                                             side_effect=AssertionError('No network is permitted')))
        yield dpkg


class FdbCache(unittest.TestCase):
    def assert_no_prepared_record(self, work):
        self.assertFalse((work / 'fdb/fdb-cache-provenance.json').exists())

    def test_verified_work_copies_feed_metadata_and_extract_then_provenance(self):
        with fixture() as case, simulated_commands(self, case) as dpkg:
            result = fdb.prepare(case.source, case.work, case.cache)
            self.assertEqual([kind for kind, _ in dpkg.events],
                             ['metadata', 'metadata', 'extract', 'extract'])
            self.assertEqual(dpkg.metadata_paths, dpkg.extract_paths)
            provenance = json.loads((case.work / 'fdb/fdb-cache-provenance.json').read_text(encoding='utf-8'))
            self.assertEqual(result, provenance)
            self.assertEqual(provenance['status'], 'private-packages-extracted-from-verified-cache')
            for flag in ('network_fetch_performed', 'build_executed', 'acceptance_executed'):
                self.assertIs(provenance[flag], False)
            self.assertEqual(provenance['helper_sha256'], hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
            self.assertEqual(len(provenance['packages']), len(case.packages))
            records = {item['package']: item for item in provenance['packages']}
            for locked in case.packages:
                record = records[locked['package']]
                copied = dpkg.extract_paths[locked['package']]
                self.assertEqual(Path(record['path']), copied)
                self.assertEqual(record['sha256'], locked['sha256'])
                self.assertEqual(record['size'], locked['size'])
                self.assertEqual(Path(record['cache_path']), case.cache / (locked['sha256'] + '.deb'))
                self.assertEqual(record['metadata'], {'Package': locked['package'],
                                                     'Version': locked['version'],
                                                     'Architecture': locked['architecture']})
                self.assertEqual(copied.read_bytes(), case.contents[locked['package']])

    def test_missing_or_corrupt_package_and_forged_sidecar_are_rejected(self):
        for change in ('missing', 'same-size-corruption', 'wrong-size'):
            with self.subTest(change=change), fixture() as case, simulated_commands(self, case) as dpkg:
                item = case.packages[0]
                cached = case.cache / (item['sha256'] + '.deb')
                if change == 'missing':
                    cached.unlink()
                elif change == 'same-size-corruption':
                    cached.write_bytes(b'x' * item['size'])
                else:
                    cached.write_bytes(case.contents[item['package']] + b'extra')
                (case.cache / (cached.name + '.sha256')).write_text(
                    hashlib.sha256(b'x' * item['size']).hexdigest() + '  ' + cached.name + '\n',
                    encoding='utf-8')
                with self.assertRaises((ValueError, OSError)):
                    fdb.prepare(case.source, case.work, case.cache)
                self.assertEqual(dpkg.events, [])
                self.assert_no_prepared_record(case.work)

    def test_hardlinked_cache_file_is_rejected(self):
        with fixture() as case, simulated_commands(self, case) as dpkg:
            cached = case.cache / (case.packages[0]['sha256'] + '.deb')
            os.link(cached, case.root / 'second-link.deb')
            self.assertGreater(cached.stat().st_nlink, 1)
            with self.assertRaises(ValueError):
                fdb.prepare(case.source, case.work, case.cache)
            self.assertEqual(dpkg.events, [])
            self.assert_no_prepared_record(case.work)

    def test_copy_opens_cache_readonly_and_never_reuses_a_destination(self):
        with fixture() as case:
            downloads = case.work / 'downloads'
            downloads.mkdir()
            item = case.packages[0]
            cached = case.cache / (item['sha256'] + '.deb')
            with mock.patch.object(fdb.os, 'open', wraps=os.open) as opened:
                result = fdb.copy_package(case.cache, downloads, item)
            cached_opens = [call for call in opened.call_args_list if Path(call.args[0]) == cached]
            self.assertEqual(len(cached_opens), 1)
            flags = cached_opens[0].args[1]
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND), 0)
            copied = Path(result['path'])
            self.assertEqual(copied.read_bytes(), case.contents[item['package']])
            self.assertEqual(cached.read_bytes(), case.contents[item['package']])
            with self.assertRaises(FileExistsError):
                fdb.copy_package(case.cache, downloads, item)
            self.assertEqual(copied.read_bytes(), case.contents[item['package']])

    def test_symlink_cache_file_is_rejected_with_explicit_simulation_if_unavailable(self):
        with fixture() as case, simulated_commands(self, case) as dpkg, ExitStack() as stack:
            cached = case.cache / (case.packages[0]['sha256'] + '.deb')
            target = case.root / 'linked-package.deb'
            cached.rename(target)
            try:
                cached.symlink_to(target)
            except OSError:
                # Windows may lack symlink privilege: simulate only this path's lstat mode.
                cached.write_bytes(target.read_bytes())
                original_path_lstat, original_os_lstat = Path.lstat, os.lstat
                def fake_stat(value):
                    fields = list(value)
                    fields[0] = stat.S_IFLNK | 0o777
                    return os.stat_result(fields)
                def path_lstat(path, *args, **kwargs):
                    value = original_path_lstat(path, *args, **kwargs)
                    return fake_stat(value) if path == cached else value
                def os_lstat(path, *args, **kwargs):
                    value = original_os_lstat(path, *args, **kwargs)
                    return fake_stat(value) if Path(path) == cached else value
                stack.enter_context(mock.patch.object(Path, 'lstat', path_lstat))
                stack.enter_context(mock.patch.object(os, 'lstat', os_lstat))
            with self.assertRaises(ValueError):
                fdb.prepare(case.source, case.work, case.cache)
            self.assertEqual(dpkg.events, [])
            self.assert_no_prepared_record(case.work)

    def test_incorrect_metadata_prevents_any_extraction_and_success_record(self):
        for field, value in (('Package', 'wrong-package'), ('Version', '7.3.63-1'), ('Architecture', 'arm64')):
            with self.subTest(field=field), fixture() as case:
                with simulated_commands(self, case, metadata_override={field: value}) as dpkg:
                    with self.assertRaises(ValueError):
                        fdb.prepare(case.source, case.work, case.cache)
                    self.assertFalse(dpkg.extract_paths)
                    self.assert_no_prepared_record(case.work)

    def test_extraction_failure_does_not_publish_prepared_provenance(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at), fixture() as case:
                with simulated_commands(self, case, fail_extract=fail_at):
                    with self.assertRaises(subprocess.CalledProcessError):
                        fdb.prepare(case.source, case.work, case.cache)
                    self.assert_no_prepared_record(case.work)

    def test_all_source_work_cache_overlaps_are_rejected(self):
        for first, second in (('source', 'work'), ('source', 'cache'), ('work', 'cache')):
            for relation in ('equal', 'first-contains-second', 'second-contains-first'):
                with self.subTest(pair=(first, second), relation=relation), fixture() as case:
                    paths = {key: getattr(case, key) for key in ('source', 'work', 'cache')}
                    if relation == 'equal':
                        paths[second] = paths[first]
                    elif relation == 'first-contains-second':
                        paths[second] = paths[first] / 'nested'
                        paths[second].mkdir()
                    else:
                        paths[first] = paths[second] / 'nested'
                        paths[first].mkdir()
                    with simulated_commands(self, case) as dpkg:
                        with self.assertRaises(ValueError):
                            fdb.prepare(paths['source'], paths['work'], paths['cache'])
                        self.assertEqual(dpkg.events, [])
                        self.assert_no_prepared_record(paths['work'])

    def test_noncanonical_or_relative_roots_are_rejected(self):
        for name in ('source', 'work', 'cache'):
            for kind in ('parent-component', 'relative'):
                with self.subTest(root=name, kind=kind), fixture() as case:
                    paths = {key: getattr(case, key) for key in ('source', 'work', 'cache')}
                    paths[name] = (case.root / name / '..' / name if kind == 'parent-component'
                                   else Path(name))
                    previous = Path.cwd()
                    try:
                        os.chdir(case.root)
                        with simulated_commands(self, case) as dpkg:
                            with self.assertRaises(ValueError):
                                fdb.prepare(paths['source'], paths['work'], paths['cache'])
                            self.assertEqual(dpkg.events, [])
                            self.assert_no_prepared_record(case.work)
                    finally:
                        os.chdir(previous)

    def test_existing_bundle_is_never_adopted(self):
        with fixture() as case, simulated_commands(self, case) as dpkg:
            bundle = case.work / 'fdb'
            bundle.mkdir()
            marker = bundle / 'unfinished.txt'
            marker.write_text('keep existing bytes', encoding='utf-8')
            with self.assertRaises((ValueError, FileExistsError)):
                fdb.prepare(case.source, case.work, case.cache)
            self.assertEqual(marker.read_text(encoding='utf-8'), 'keep existing bytes')
            self.assertEqual(dpkg.events, [])
            self.assert_no_prepared_record(case.work)


if __name__ == '__main__':
    unittest.main()
