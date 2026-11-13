"""Pure file-integrity tests: no runtime import, subprocess, network or upstream source.

Extract only the real edit/prepared-record functions. This keeps the tests usable
on Windows while the full adapter correctly requires Linux/fcntl at runtime.
"""
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load_file_functions(folder, function='prepare_source'):
    namespace = {'HERE': folder, 'hashlib': hashlib, 'json': json,
                 'difflib': difflib, 'os': os, 'Path': Path,
                 'PurePosixPath': PurePosixPath, 'stat': stat}
    for name, functions in [('runtime_common.py', {'sha', 'new_json'}),
                            ('bootstrap_ecpipe.py', {'apply_edits', 'prepare_source', 'verify_prepared_sources'})]:
        tree = ast.parse((HERE / name).read_text())
        selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in functions]
        if {n.name for n in selected} != functions:
            raise RuntimeError('real file-integrity function missing')
        exec(compile(ast.Module(body=selected, type_ignores=[]), name, 'exec'), namespace)
    return namespace[function]


class EditIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.file = self.source / 'sample.txt'
        self.before = b'alpha\nbeta\ngamma\n'
        self.after = b'alpha\nnew-value\ngamma\n'
        self.file.write_bytes(self.before)
        self.digest = lambda b: hashlib.sha256(b).hexdigest()
        self.row = {'path': 'sample.txt', 'before_sha256': self.digest(self.before),
                    'after_sha256': self.digest(self.after), 'edits': [
                        {'start_line_0': 1, 'end_line_0_exclusive': 2,
                         'before_sha256': self.digest(b'beta\n'), 'replacement': 'new-value\n'}]}
        self.recipe = {'schema': 1, 'upstream_commit': 'fixed-test-commit',
                       'steps': [{'name': 'test-edit', 'files': [self.row]}]}
        self.prepare = load_file_functions(self.root)

    def invoke(self):
        encoded = (json.dumps(self.recipe) + '\n').encode()
        (self.root / 'edits.json').write_bytes(encoded)
        config = {'commit': 'fixed-test-commit', 'archive_sha256': 'test-archive-digest',
                  'recipes': {'path': 'edits.json', 'sha256': self.digest(encoded)},
                  'edit_steps': [{'name': 'test-edit', 'after': [
                      {'path': 'sample.txt', 'sha256': self.row['after_sha256']}]}]}
        self.prepare(self.source, config, self.root)

    def rejected(self):
        original = self.file.read_bytes()
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertFalse((self.root / 'prepared.json').exists())
        self.assertFalse((self.root / 'source-edits.private.patch').exists())
        self.assertEqual(self.file.read_bytes(), original)

    def test_correct_edit_and_prepared_record_bind_after_bytes(self):
        self.invoke()
        self.assertEqual(self.file.read_bytes(), self.after)
        record = json.loads((self.root / 'prepared.json').read_text())
        self.assertEqual(record['status'], 'prepared-not-built')
        self.assertEqual(record['sources'], [{'relative': 'sample.txt', 'sha256': self.digest(self.after)}])
        self.assertTrue((self.root / 'source-edits.private.patch').is_file())

    def test_changed_whole_input_is_rejected(self):
        self.file.write_bytes(self.before + b'changed\n')
        self.rejected()

    def test_changed_old_span_digest_is_rejected(self):
        self.row['edits'][0]['before_sha256'] = '0' * 64
        self.rejected()

    def test_overlapping_spans_are_rejected(self):
        self.row['edits'].append(dict(self.row['edits'][0]))
        self.rejected()

    def test_out_of_range_span_is_rejected(self):
        self.row['edits'][0]['end_line_0_exclusive'] = 4
        self.rejected()

    def test_wrong_after_digest_cannot_create_success_record(self):
        self.row['after_sha256'] = '0' * 64
        self.rejected()

    def test_first_build_rejects_unrecorded_translation_unit(self):
        self.invoke()
        record = json.loads((self.root / 'prepared.json').read_text())
        verify = load_file_functions(self.root, 'verify_prepared_sources')
        self.assertEqual(verify(self.source, record), [
            {'path': str(self.file), 'sha256': self.digest(self.after)}])
        (self.source / 'unrecorded.cc').write_bytes(b'int unrecorded_translation_unit;\n')
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            verify(self.source, record)


if __name__ == '__main__':
    unittest.main()
