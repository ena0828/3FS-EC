#!/usr/bin/env python3
"""Offline producer checks. No compiler, service, package install or network."""
import importlib.util
import hashlib
import json
import os
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
    def repo(self, root):
        root.mkdir(parents=True, exist_ok=True)
        def git(*args):
            return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)
        git('init', '-q')
        git('config', 'user.name', 'fixture')
        git('config', 'user.email', 'fixture@invalid.example')
        git('config', 'core.autocrlf', 'false')
        return git

    def test_actual_patch_index_accepts_only_exact_added_bytes_and_complete_tracked_patch(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            module = root / 'module'
            git = self.repo(module)
            for name in ('edited.h', 'unrelated.h'):
                (module / name).write_bytes(b'original\n')
            git('add', '.')
            git('commit', '-qm', 'base')
            commit = git('rev-parse', 'HEAD').decode().strip()
            (module / 'edited.h').write_bytes(b'patched\n')
            (module / 'added.h').write_bytes(b'exact new input\n')
            git('add', '.')
            patch = root / 'fixed.patch'
            patch.write_bytes(git('diff', '--cached', '--binary'))
            git('reset', '-q', 'HEAD')
            index = (module / '.git/index').read_bytes()
            result = build.verified_submodule(module, commit, [patch])
            self.assertEqual(result['added_files']['added.h']['sha256'], hashlib.sha256(b'exact new input\n').hexdigest())
            self.assertEqual((module / '.git/index').read_bytes(), index)
            for name, value in (('added.h', b'wrong new input\n'), ('unrelated.h', b'extra unrelated dirty input\n'),
                                ('unexpected.h', b'not from patch\n')):
                path = module / name
                before = path.read_bytes() if path.exists() else None
                path.write_bytes(value)
                if name == 'unrelated.h':
                    git('apply', '--reverse', '--check', str(patch))  # This weaker check still passes.
                with self.subTest(name=name), self.assertRaises(ValueError):
                    build.verified_submodule(module, commit, [patch])
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)
            if os.name == 'posix':
                (module / 'added.h').chmod(0o755)
                with self.assertRaises(ValueError):
                    build.verified_submodule(module, commit, [patch])
                (module / 'added.h').chmod(0o644)
            with self.assertRaises(ValueError):
                build.verified_submodule(module, '0' * 40, [patch])
            git('add', 'edited.h')
            with self.assertRaises(ValueError):
                build.verified_submodule(module, commit, [patch])

    def recovery_fixture(self, root):
        source, work = root / 'source', root / 'work'
        git = self.repo(source)
        files = {build.MANAGER: 'old producer', 'scripts/ec/ci/prepare-isal.py': 'fixed isal helper',
                 'scripts/ec/reference/downloads.json': '{}', 'scripts/ec/install-build-deps.sh': 'fixed install',
                 'Cargo.lock': 'one', 'src/storage/ec/Cargo.lock': 'two', 'src/business.cc': 'old business',
                 'scripts/ec/ci/build-native.sh': 'sha256sum scripts/ec/install-build-deps.sh \\\n    scripts/ec/ci/local-incremental-build.py \\\n    | tee "$work/provenance/build-inputs.sha256"\n'}
        for name, text in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text.encode())
        git('add', '.')
        git('commit', '-qm', 'original')
        revision = git('rev-parse', 'HEAD').decode().strip()
        state_root = root / '.work-managed'
        previous = state_root / 'attempt-000001'
        previous.mkdir(parents=True)
        provenance = work / 'provenance'
        provenance.mkdir(parents=True)
        (work / 'build').mkdir()
        (work / 'build/CMakeCache.txt').write_bytes(b'original configured cache')
        intent = {'schema': 1, 'source': str(source), 'work': str(work), 'revision': revision,
                  'jobs': 8, 'mode': 'fresh', 'generation': 1, 'state_root': str(state_root), 'previous_attempt': None}
        state = dict(intent, attempt=str(previous), status='failed', exit_code=1,
                     cmake_cache_sha256=build.sha(work / 'build/CMakeCache.txt'))
        command = ['bash', str(source / 'scripts/ec/ci/build-native.sh'), '--backend', 'isal', '--build-jobs', '8',
                   '--with-lab-targets', '--with-ec-regression-targets', '--local-source', str(source),
                   '--local-work', str(work), '--local-revision', revision]
        for name, value in [('intent', intent), ('outcome', state), ('command', {'argv': command}),
                            ('process', {'pid': 12345, 'process_group': 12345}), ('monitor', {'remaining_group_pids': []})]:
            build.write_new(previous / (name + '.json'), value)
        (previous / 'build.stdout').write_bytes(b'configure done\ngenerate done\n')
        (previous / 'build.stderr').write_bytes(b' in checkpoint\n in epoch_inputs\nValueError: untracked submodule input\n')
        (provenance / 'source-head.txt').write_text(revision + '\n')
        (provenance / 'submodules.txt').write_bytes(b'')
        build.write_new(provenance / 'local-preflight.json', dict(revision=revision, source=str(source),
                         work=str(work), backend='isal', container_build_only=False, submodules=''))
        for name, paths in [('build-inputs.sha256', ['scripts/ec/install-build-deps.sh', build.MANAGER]),
                            ('cargo-locks.sha256', ['Cargo.lock', 'src/storage/ec/Cargo.lock'])]:
            (provenance / name).write_text(''.join(build.sha(source / p) + '  ' + p + '\n' for p in paths))
        isal = work / 'isal-prefix/libisal.so'
        isal.parent.mkdir()
        isal.write_bytes(b'original isal')
        build.write_new(provenance / 'isal-prepare.json', {
            'source_lock_sha256': build.sha(source / 'scripts/ec/reference/downloads.json'),
            'helper_sha256': build.sha(source / 'scripts/ec/ci/prepare-isal.py'), 'prefix': str(isal.parent),
            'provider': {'path': str(isal), 'sha256': build.sha(isal)}, 'packages': []})
        fdb = work / 'deps/lib/libfdb_c.so'
        fdb.parent.mkdir(parents=True)
        fdb.write_bytes(b'original fdb')
        build.write_new(provenance / 'fdb-link-probe.json', {
            'status': 'linked-and-loaded-fixed-client', 'provider': str(fdb),
            'provider_sha256': build.sha(fdb), 'expected_package_library_sha256': build.sha(fdb)})
        (source / build.MANAGER).write_text('corrected producer')
        (source / 'src/business.cc').write_text('new business')
        git('add', '.')
        git('commit', '-qm', 'producer fix and business')
        return source, work, state

    def test_configured_recovery_revalidates_old_git_evidence_and_keeps_original_records(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(build, 'sync_dir'), \
                mock.patch.object(build, 'sample_group', return_value={'live_pids': []}), \
                mock.patch.object(build, 'epoch_inputs', return_value={'current': 'verified'}):
            source, work, state = self.recovery_fixture(Path(folder))
            previous = Path(state['attempt'])
            before = {str(p): p.read_bytes() for p in previous.iterdir()}
            result = build.verify_configured_recovery(source, work, state)
            self.assertFalse(result['build_success'])
            self.assertTrue(result['reconfigure_required'])
            self.assertEqual(result['inputs'], {'current': 'verified'})
            self.assertIn('no previous full-tree epoch existed', result['epoch_scope'])
            self.assertEqual(before, {str(p): p.read_bytes() for p in previous.iterdir()})
            self.assertFalse((work / 'provenance/local-build-ready.json').exists())
            mutations = [(work / 'build/CMakeCache.txt', b'changed cache'),
                         (work / 'provenance/build-inputs.sha256', b'0' * 64 + b'  unknown\n'),
                         (source / 'Cargo.lock', b'different dependency'),
                         (previous / 'monitor.json', build.encoded({'remaining_group_pids': [9]})),
                         (previous / 'configured.json', b'{}'),
                         (work / 'provenance/build-command.json', b'{}')]
            for path, changed in mutations:
                original = path.read_bytes() if path.exists() else None
                path.write_bytes(changed)
                with self.subTest(path=path), self.assertRaises(ValueError):
                    build.verify_configured_recovery(source, work, state)
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
            with mock.patch.object(build, 'sample_group', return_value={'live_pids': [12345]}), self.assertRaises(ValueError):
                build.verify_configured_recovery(source, work, state)

    def test_recovery_checkpoint_requires_same_verified_inputs_before_creating_ready(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(build, 'sync_dir'), \
                mock.patch.object(build, 'source_identity'):
            root = Path(folder)
            work, attempt, intent = self.fixture(root)
            (work / 'provenance/local-build-ready.json').unlink()
            intent.update(mode='recover-configured', source=str(root / 'source'))
            build.write_new(attempt / 'recovery.json', {'inputs': {'exact': 'before configure'}})
            (work / 'build').mkdir()
            (work / 'build/CMakeCache.txt').write_text('actually reconfigured')
            with mock.patch.object(build, 'context', return_value=(attempt, intent)):
                with mock.patch.object(build, 'epoch_inputs', return_value={'drifted': True}), self.assertRaises(ValueError):
                    build.checkpoint()
                self.assertFalse((work / 'provenance/local-build-ready.json').exists())
                with mock.patch.object(build, 'epoch_inputs', return_value={'exact': 'before configure'}):
                    build.checkpoint()
            ready = build.read(work / 'provenance/local-build-ready.json')
            self.assertEqual(ready['recovery_sha256'], build.sha(attempt / 'recovery.json'))
            self.assertEqual(build.read(attempt / 'configured.json')['checkpoint_sha256'],
                             build.sha(work / 'provenance/local-build-ready.json'))

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
            (work / 'build').mkdir()
            (work / 'build/CMakeCache.txt').write_bytes(b'old configured cache')
            attempt.mkdir()
            names = ('native-build.json', 'lab-build.json', 'build-resources.json', 'build-command.json')
            for name in names:
                (work / 'provenance' / name).write_bytes(('prior:' + name).encode())
            build.archive_previous(attempt, work)
            for name in names:
                self.assertFalse((work / 'provenance' / name).exists())
                self.assertEqual((attempt / 'previous' / name).read_bytes(), ('prior:' + name).encode())
            self.assertEqual((work / 'build/CMakeCache.txt').read_bytes(), b'old configured cache')
            self.assertEqual((attempt / 'previous/CMakeCache.txt').read_bytes(), b'old configured cache')
            (work / 'build/CMakeCache.txt').write_bytes(b'new configure generation')
            self.assertEqual((attempt / 'previous/CMakeCache.txt').read_bytes(), b'old configured cache')
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
