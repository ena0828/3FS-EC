"""Windows-safe pure control-flow tests; never starts a process or business RPC."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
CLI = HERE / 'file-cli-acceptance.py'
SPEC = importlib.util.spec_from_file_location('file_cli_acceptance', CLI)
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
OP = '11111111-1111-4111-8111-111111111111'


def observation(published=False, cleaned=False, **updates):
    value = dict(operation=OP, length_decimal='101', observed=True, published=published,
                 aborted=False, all_cleanup_complete=cleaned, error_code=0)
    value.update(updates)
    return value


PENDING = (1, observation())
QUERY = (0, observation())
PUBLISHED = (0, observation(True))
CLEANED = (0, observation(True, True))


class W:
    @staticmethod
    def private_directory(path, create=False):
        if create:
            path.mkdir(parents=True)
        return path

    @staticmethod
    def write_exclusive(path, data):
        with path.open('xb') as output:
            output.write(data)

    @staticmethod
    def regular_bytes(path, limit):
        data = path.read_bytes()
        assert len(data) <= limit
        return data

    @staticmethod
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate key')
            value[key] = item
        return value

    @staticmethod
    def exact_numbers(value):
        if isinstance(value, dict):
            for item in value.values():
                W.exact_numbers(item)
        elif isinstance(value, list):
            for item in value:
                W.exact_numbers(item)
        elif isinstance(value, float):
            raise ValueError('float')

    json_data = staticmethod(lambda value: (json.dumps(value) + '\n').encode())


class Wrapper:
    @staticmethod
    def parser():
        return SimpleNamespace(parse_args=lambda arguments: arguments)

    @staticmethod
    def command(arguments):
        return ['fake-cli', *arguments, 'mode4-' + arguments[2]]


class Transport:
    def __init__(self, replies):
        self.replies = copy.deepcopy(replies)
        self.actions = []
        self.row_updates = {}
        self.exception = None
        self.extra_json = False
        self.mutate_record = False

    sync_parent = staticmethod(lambda _: None)
    hash_file = staticmethod(lambda _, path: hashlib.sha256(path.read_bytes()).hexdigest())

    def command(self, runner, w, argv):
        self.actions.append(argv[-1])
        index = len(runner.commands)
        code, value = self.replies.pop(0)
        row = dict(index=index, argv=argv, process_started=True, process_exited=True, returncode=code)
        row.update(self.row_updates)
        runner.commands.append(row)
        run = Path(argv[argv.index('--run-dir') + 1])
        run.mkdir(exist_ok=True)
        record = run / 'record.data'
        if not record.exists():
            record.write_bytes(b'fixed-test-record')
        elif self.mutate_record:
            record.write_bytes(b'wrong-test-record')
        text = json.dumps(value) + '\n'
        if self.extra_json:
            text += json.dumps(value) + '\n'
        log = runner.report / f'command-{index:03d}.log'
        log.write_text(text)
        if self.exception:
            raise RuntimeError(self.exception)
        if code:
            raise RuntimeError(f'Admin command failed; inspect {log}; no automatic retry or restoration')
        return text


class FileCliAcceptanceTests(unittest.TestCase):
    def harness(self, replies):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        report = root / 'report'
        report.mkdir()
        runner = SimpleNamespace(root=root, report=report, child=None, commands=[], stop_requested=False)
        transport = Transport(replies)
        accepted = driver.Acceptance(W, transport, Wrapper, runner, root / 'phase', 'label', 'basic')
        return accepted, transport, runner

    def test_immediate_publication_keeps_three_strict_commands(self):
        a, transport, _ = self.harness([PUBLISHED, PUBLISHED, CLEANED])
        a.truncate('cut', a.runs / 'session', 101)
        self.assertEqual(transport.actions, ['mode4-truncate', 'mode4-resume-truncate', 'mode4-close-truncate-debt'])
        self.assertTrue(all(item['checks_complete'] for item in a.steps))

    def test_pending_query_resume_keeps_nonzero_evidence_and_same_run(self):
        a, transport, runner = self.harness([PENDING, QUERY, PENDING, PUBLISHED, PUBLISHED, CLEANED])
        with patch.object(driver.time, 'sleep'):
            a.truncate('cut', a.runs / 'session', 101)
        self.assertEqual(transport.actions, ['mode4-truncate', 'mode4-query-truncate', 'mode4-resume-truncate',
                                            'mode4-resume-truncate', 'mode4-resume-truncate', 'mode4-close-truncate-debt'])
        self.assertEqual([item['returncode'] for item in runner.commands], [1, 0, 1, 0, 0, 0])
        self.assertEqual([item['index'] for item in a.steps if item.get('accepted_pending')], [0, 2])
        self.assertEqual({item['run'] for item in a.steps}, {str(a.runs / 'cut')})
        self.assertTrue(all(item['checks_complete'] for item in a.steps))
        saved = json.loads((runner.report / 'step-000-observed.json').read_text())
        self.assertEqual(saved['process']['returncode'], 1)
        self.assertFalse(saved['checks_complete'])

    def test_query_publication_does_not_issue_an_extra_advance(self):
        a, transport, _ = self.harness([PENDING, PUBLISHED, PUBLISHED, CLEANED])
        a.truncate('cut', a.runs / 'session', 101)
        self.assertEqual(transport.actions.count('mode4-resume-truncate'), 1)  # strict terminal replay

    def test_query_exit_zero_is_not_publication_and_resumes_are_bounded(self):
        a, transport, _ = self.harness([PENDING, QUERY] + [PENDING] * 64)
        with patch.object(driver.time, 'sleep'), patch.object(driver.time, 'monotonic', return_value=0):
            with self.assertRaisesRegex(RuntimeError, '64 continuations'):
                a.truncate('cut', a.runs / 'session', 101)
        self.assertEqual(transport.actions.count('mode4-resume-truncate'), 64)
        self.assertNotIn('mode4-close-truncate-debt', transport.actions)

    def test_expired_start_window_sends_no_resume_or_cleanup(self):
        a, transport, _ = self.harness([PENDING, QUERY])
        with patch.object(driver.time, 'monotonic', side_effect=[0, 61]):
            with self.assertRaisesRegex(RuntimeError, 'start window'):
                a.truncate('cut', a.runs / 'session', 101)
        self.assertEqual(transport.actions, ['mode4-truncate', 'mode4-query-truncate'])

    def test_nonterminal_whitelist_rejects_business_or_shape_errors(self):
        mutations = [dict(error_code=1), dict(error_code=False), dict(observed=False), dict(observed=1),
                     dict(aborted=True), dict(published=True), dict(published=0), dict(all_cleanup_complete=True),
                     dict(length_decimal='102'), dict(length_decimal=101), dict(operation=''),
                     dict(operation='00000000-0000-0000-0000-000000000000'), dict(extra='field')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                a, transport, _ = self.harness([(1, observation(**mutation))])
                with self.assertRaises((RuntimeError, ValueError)):
                    a.truncate('cut', a.runs / 'session', 101)
                self.assertEqual(transport.actions, ['mode4-truncate'])

    def test_exit_and_ownership_errors_cannot_become_pending(self):
        for updates in [dict(returncode=2), dict(returncode=True), dict(process_started=False),
                        dict(process_exited=False), dict(argv=['wrong'])]:
            with self.subTest(updates=updates):
                a, transport, _ = self.harness([PENDING])
                transport.row_updates = updates
                with self.assertRaises(RuntimeError):
                    a.truncate('cut', a.runs / 'session', 101)
                self.assertEqual(len(transport.actions), 1)

    def test_changed_operation_stops_before_cleanup(self):
        wrong = observation(operation='22222222-2222-4222-8222-222222222222')
        for replies in [[PENDING, (0, wrong)], [PENDING, QUERY, (1, wrong)]]:
            with self.subTest(replies=replies):
                a, transport, _ = self.harness(replies)
                with self.assertRaisesRegex(RuntimeError, 'operation changed'):
                    a.truncate('cut', a.runs / 'session', 101)
                self.assertNotIn('mode4-close-truncate-debt', transport.actions)

    def test_unrelated_transport_error_and_multiple_json_are_not_swallowed(self):
        for extra, error in [(True, None), (False, 'event write failed')]:
            with self.subTest(extra=extra, error=error):
                a, transport, _ = self.harness([PENDING])
                transport.extra_json, transport.exception = extra, error
                with self.assertRaises(RuntimeError):
                    a.truncate('cut', a.runs / 'session', 101)
                self.assertEqual(len(transport.actions), 1)

    def test_terminal_replay_exit_one_is_never_continued(self):
        a, transport, _ = self.harness([PUBLISHED, PENDING])
        with self.assertRaisesRegex(RuntimeError, 'Admin command failed'):
            a.truncate('cut', a.runs / 'session', 101)
        self.assertEqual(len(transport.actions), 2)
        self.assertNotIn('mode4-close-truncate-debt', transport.actions)

    def test_append_nonzero_has_no_pending_exemption(self):
        a, transport, _ = self.harness([PENDING])
        with self.assertRaisesRegex(RuntimeError, 'Admin command failed'):
            a.one('resume-append', a.runs / 'append')
        self.assertNotIn('accepted_pending', a.steps[0])

    def test_changed_journal_record_fails_same_run_guard(self):
        a, transport, _ = self.harness([PENDING, QUERY])
        transport.mutate_record = True
        with self.assertRaisesRegex(RuntimeError, 'Fixed journal body changed'):
            a.truncate('cut', a.runs / 'session', 101)
        self.assertEqual(len(transport.actions), 2)

    def test_packaging_explicit_opt_in_and_missing_helper_fail_preflight(self):
        path = HERE.parent / 'package-services.py'
        main = next(node for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        blocks = [node for node in main.body if isinstance(node, ast.If) and
                  ast.unparse(node.test) in ("bundle_manifest.get('file_api') is True", 'args.ec_file_mount')]
        self.assertEqual(len(blocks), 2)
        code = compile(ast.fix_missing_locations(ast.Module(body=blocks, type_ignores=[])), '<package-preflight>', 'exec')
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / 'package-services.py'
            sources = package.with_name('cluster')
            sources.mkdir()
            names = ['file-cli-acceptance.py', 'tree-gc-acceptance.py', 'prepare-fuse-file.py', 'prepare-fuse-read.py', 'generate.py',
                     'native_v2_config.py', 'mode4-mount-acceptance.py', 'mode4-usrbio-acceptance.py',
                     'fuse-read-acceptance.py', 'mode4-lifecycle-acceptance.py']
            for name in names:
                (sources / name).write_text('# source')
            for file_api, mount, expected in [(False, False, []), (True, False, names[:2]), (True, True, names)]:
                copied = []
                env = dict(Path=Path, __file__=str(package), bundle_manifest={'file_api': file_api},
                           args=SimpleNamespace(ec_file_mount=mount),
                           include=lambda source, relative, kind: copied.append(source.name))
                exec(code, env)
                self.assertEqual(copied, expected)
            (sources / 'fuse-read-acceptance.py').unlink()
            with self.assertRaisesRegex(RuntimeError, 'Missing mode4 preparation source'):
                exec(code, env)


if __name__ == '__main__':
    unittest.main()
