"""Synthetic bytes with a mocked full-file hash; not public workload evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import kv_trace as kv
import replay_input as reader


class ReplayInputTests(unittest.TestCase):
    def fixture(self, directory, rows=None):
        rows = rows or [dict(chat_id=n, parent_chat_id=-1, timestamp=n, input_length=128,
                            output_length=4, type='synthetic', turn=1, hash_ids=list(range(8))) for n in range(3)]
        raw = b''.join(kv.canonical(row) + b'\n' for row in rows)
        path = 'qwen_traceA_blksz_16.jsonl'
        self.enterContext(patch.dict(kv.UPSTREAM, {path: (kv.sha(raw), len(raw))}))
        source = {'schema': 'qwen-bailian-input/v1', 'repository': kv.REPOSITORY, 'commit': kv.COMMIT,
                  'path': path, 'license_spdx': 'Apache-2.0', 'upstream_lfs_sha256': kv.sha(raw),
                  'upstream_lfs_bytes_decimal': str(len(raw)), 'input_sha256': kv.sha(raw),
                  'input_bytes_decimal': str(len(raw)), 'input_scope': 'full-file',
                  'first_line_decimal': '1', 'byte_offset_decimal': '0'}
        input_path = directory / 'raw.jsonl'
        input_path.write_bytes(raw)
        output = directory / 'converted'
        kv.convert(input_path, source, kv.parameters('synthetic', 'mapped', 'tenant', reuse='synthetic-tenant'), output)
        return output, input_path

    def test_reconstructs_source_and_selects_prefix_without_measured_cache_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            conversion, source = self.fixture(Path(temporary).resolve())
            binding, events = reader.load(conversion, source, 2)
            self.assertEqual(len(events), 2)
            self.assertTrue(binding['selection_truncated'])
            self.assertEqual(binding['last_selected_sequence_decimal'], '3')
            self.assertEqual(binding['horizon_ns_decimal'], '1000000000')
            self.assertFalse(binding['observed_cache_decisions'])
            self.assertEqual(events[0]['object']['key_sha256'], events[1]['object']['key_sha256'])
            full, all_events = reader.load(conversion, source, 4)
            self.assertFalse(full['selection_truncated'])
            self.assertEqual(len(all_events), 3)

    def test_rehashed_event_edit_and_edited_totals_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            conversion, source = self.fixture(Path(temporary).resolve())
            path = conversion / 'events.jsonl'
            original = path.read_bytes()
            manifest_path = conversion / 'manifest.json'
            manifest = json.loads(manifest_path.read_text())
            lines = original.splitlines()
            event = json.loads(lines[1]); event['object']['key_sha256'] = 'f' * 64
            lines[1] = kv.canonical(event)
            changed = b'\n'.join(lines) + b'\n'
            path.write_bytes(changed)
            altered = dict(manifest, events_sha256=kv.sha(changed))
            manifest_path.write_bytes(kv.canonical(altered))
            with self.assertRaisesRegex(ValueError, 'regeneration'):
                reader.load(conversion, source, 2)
            path.write_bytes(original)
            for key, value in (('records_decimal', '4'), ('request_regions', {'warmup': 3, 'measurement': 0}),
                               ('namespace_sha256', 'e' * 64), ('full_lfs_object_verified', False),
                               ('claims', dict(manifest['claims'], actual_kv_tensors=0)),
                               ('request_regions', dict(manifest['request_regions'], warmup=False))):
                with self.subTest(key=key):
                    manifest_path.write_bytes(kv.canonical(dict(manifest, **{key: value})))
                    with self.assertRaises(ValueError): reader.load(conversion, source, 2)

    def test_unselected_tail_and_source_mutation_cannot_escape_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            conversion, source = self.fixture(Path(temporary).resolve())
            events = conversion / 'events.jsonl'
            original = events.read_bytes()
            events.write_bytes(original + b'{}\n')
            with self.assertRaisesRegex(ValueError, 'Extra'):
                reader.load(conversion, source, 1)
            events.write_bytes(original)
            raw = source.read_bytes()
            source.write_bytes(raw[:-1])
            with self.assertRaisesRegex(ValueError, 'byte count'):
                reader.load(conversion, source, 1)

    def test_prefix_requires_pinned_descriptor_even_when_hash_is_self_consistent(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            conversion, source = self.fixture(directory)
            manifest = json.loads((conversion / 'manifest.json').read_text())
            descriptor = copy.deepcopy(manifest['source'])
            descriptor['input_scope'] = 'bounded-prefix'
            descriptor['upstream_lfs_bytes_decimal'] = str(int(descriptor['input_bytes_decimal']) + 1)
            kv.UPSTREAM[descriptor['path']] = (descriptor['upstream_lfs_sha256'], int(descriptor['upstream_lfs_bytes_decimal']))
            manifest.update(source=descriptor, full_lfs_object_verified=False)
            (conversion / 'manifest.json').write_bytes(kv.canonical(manifest))
            descriptors = directory / 'descriptors'; descriptors.mkdir()
            target = descriptors / (descriptor['path'] + '.prefix.source.json')
            bad = dict(descriptor, input_sha256='f' * 64)
            target.write_bytes(kv.canonical(bad))
            with self.assertRaisesRegex(ValueError, 'pinned published descriptor'):
                reader.load(conversion, source, 1, descriptors)
            target.write_bytes(kv.canonical(descriptor))
            binding, _ = reader.load(conversion, source, 1, descriptors)
            self.assertEqual(binding['prefix_descriptor_sha256'], kv.sha(target.read_bytes()))

    def test_empty_input_and_invalid_bound_never_form_an_execution_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            rows = [dict(chat_id=1, parent_chat_id=-1, timestamp=0, input_length=0,
                         output_length=4, type='synthetic', turn=1, hash_ids=[])]
            conversion, source = self.fixture(directory, rows)
            for bound in (False, 0, 4097, 1.5):
                with self.subTest(bound=bound), self.assertRaises(ValueError): reader.load(conversion, source, bound)
            with self.assertRaisesRegex(ValueError, 'No block observations'):
                reader.load(conversion, source, 1)


if __name__ == '__main__':
    unittest.main()
