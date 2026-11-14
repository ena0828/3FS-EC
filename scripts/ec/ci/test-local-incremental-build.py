#!/usr/bin/env python3
"""Offline producer checks. No compiler, service, package install or network."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('managed_build', HERE / 'local-incremental-build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ManagedBuild(unittest.TestCase):
    def test_high_concurrency_uses_observed_headroom_cpu_and_prior_rss(self):
        gib = build.GIB
        memory = {'MemTotal': 64 * gib, 'MemAvailable': 62 * gib}
        groups = [{'cpu_max': '1600000 100000', 'memory_max': str(64 * gib), 'memory_current': 2 * gib}]
        for jobs in (8, 12, 16):
            self.assertEqual(build.resource_plan(jobs, memory, 16, groups)['effective_jobs'], jobs)
        for headroom in (51 * gib, 12 * gib):
            with self.subTest(headroom=headroom):
                self.assertIsNone(build.resource_plan(16, dict(memory, MemAvailable=headroom), 16, groups)['effective_jobs'])
        self.assertIsNone(build.resource_plan(12, memory, 8, groups)['effective_jobs'])
        self.assertIsNone(build.resource_plan(16, memory, 16, groups, {'max_compiler_rss_bytes': 4 * gib})['effective_jobs'])
        with self.assertRaises(ValueError):
            build.resource_plan(True, memory, 16, groups)

    def test_real_git_fingerprint_allows_business_commit_but_locks_dependency_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            def git(*args):
                return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
            git('config', 'user.name', 'fixture')
            git('config', 'user.email', 'fixture@invalid.example')
            for name, body in [('Cargo.lock', 'locked'), ('cmake/Dependency.cmake', 'pinned'), ('src/a.cc', 'old')]:
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_text(body)
            git('add', '.')
            git('commit', '-qm', 'initial')
            before = build.compatible_source_inputs(root)
            (root / 'src/a.cc').write_text('new business source')
            git('add', '.')
            git('commit', '-qm', 'business')
            build.source_identity(root, git('rev-parse', 'HEAD').stdout.decode().strip())
            self.assertEqual(build.compatible_source_inputs(root), before)
            (root / 'Cargo.lock').write_text('changed dependency')
            self.assertNotEqual(build.compatible_source_inputs(root), before)
            with self.assertRaises(ValueError):
                build.source_identity(root, git('rev-parse', 'HEAD').stdout.decode().strip())

    def test_checkpoint_refuses_cache_provider_or_patch_drift_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(build, 'sync_dir'):
            work = Path(folder)
            source = work / 'source'
            (work / 'provenance').mkdir()
            (work / 'build').mkdir()
            cache = work / 'build/CMakeCache.txt'
            cache.write_text('original cache')
            original = {'provider': 'exact', 'submodule_diff': 'exact'}
            build.write_new(work / 'provenance/local-build-ready.json', {'source': str(source), 'work': str(work), 'inputs': original})
            state = {'cmake_cache_sha256': build.sha(cache)}
            before = (work / 'provenance/local-build-ready.json').read_bytes()
            with mock.patch.object(build, 'epoch_inputs', return_value=original):
                build.verify_prepared(source, work, state)
                cache.write_text('edited cache')
                with self.assertRaises(ValueError):
                    build.verify_prepared(source, work, state)
            for changed in ({'provider': 'different', 'submodule_diff': 'exact'},
                            {'provider': 'exact', 'submodule_diff': 'extra dirty patch'}):
                with mock.patch.object(build, 'epoch_inputs', return_value=changed), self.assertRaises(ValueError):
                    build.verify_prepared(source, work, state)
            self.assertEqual((work / 'provenance/local-build-ready.json').read_bytes(), before)

    def test_archive_invalidates_old_success_and_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(build, 'sync_dir'):
            root = Path(folder)
            work, attempt = root / 'work', root / 'attempt'
            (work / 'provenance').mkdir(parents=True)
            attempt.mkdir()
            names = ('native-build.json', 'lab-build.json', 'build-resources.json', 'build-command.json')
            for name in names:
                (work / 'provenance' / name).write_bytes(('prior:' + name).encode())
            build.archive_previous(attempt, work)
            for name in names:
                self.assertFalse((work / 'provenance' / name).exists())
                self.assertEqual((attempt / 'previous' / name).read_bytes(), ('prior:' + name).encode())
            with self.assertRaises(FileExistsError):
                build.archive_previous(attempt, work)

    def fixture(self, root):
        work, attempt = root / 'work', root / 'attempt'
        (work / 'provenance').mkdir(parents=True)
        (attempt / 'staged').mkdir(parents=True)
        intent = {'work': str(work), 'revision': 'a' * 40, 'mode': 'resume'}
        (work / 'provenance/build-inputs.sha256').write_text('fixed input hashes')
        (work / 'provenance/source-head.txt').write_text('a' * 40 + '\n')
        for path, data in ((attempt / 'intent.json', intent), (attempt / 'monitor.json', {'samples': 2}),
                           (work / 'provenance/local-build-ready.json', {'fixed': True}),
                           (attempt / 'staged/native-build.json', {'revision': 'a' * 40, 'binaries': {'test_meta': 'exact'}}),
                           (attempt / 'staged/lab-build.json', {'revision': 'a' * 40, 'native_build_receipt_sha256': 'old'})):
            build.write_new(path, data)
        lab_path = attempt / 'staged/lab-build.json'
        lab = build.read(lab_path)
        lab['native_build_receipt_sha256'] = build.sha(attempt / 'staged/native-build.json')
        lab_path.write_bytes(build.encoded(lab))
        return work, attempt, intent

    def test_publish_uses_actual_bytes_and_native_is_last_success_marker(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(build, 'sync_dir'):
            work, attempt, intent = self.fixture(Path(folder))
            real = build.write_new
            calls = []
            def write(path, value):
                calls.append(Path(path))
                real(path, value)
            with mock.patch.object(build, 'write_new', side_effect=write):
                build.publish(attempt, intent, {})
            self.assertEqual(calls[-1], work / 'provenance/native-build.json')
            lab = build.read(work / 'provenance/lab-build.json')
            self.assertEqual(lab['native_build_receipt_sha256'], build.sha(work / 'provenance/native-build.json'))
            self.assertEqual((attempt / 'native-build.json').read_bytes(), (work / 'provenance/native-build.json').read_bytes())
            self.assertEqual(lab['managed_build']['intent_sha256'], build.sha(attempt / 'intent.json'))

    def test_failed_publication_cannot_leave_native_or_lab_success(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(build, 'sync_dir'):
            work, attempt, intent = self.fixture(Path(folder))
            real = build.write_new
            def fail(path, value):
                if Path(path) == work / 'provenance/native-build.json':
                    Path(path).write_bytes(b'partial')
                    raise OSError('simulated output failure')
                real(path, value)
            with mock.patch.object(build, 'write_new', side_effect=fail), self.assertRaises(OSError):
                build.publish(attempt, intent, {})
            self.assertFalse((work / 'provenance/native-build.json').exists())
            self.assertFalse((work / 'provenance/lab-build.json').exists())
            self.assertTrue((attempt / 'native-build.json').is_file())


if __name__ == '__main__':
    unittest.main()
