"""Verify converted observations against the pinned source, then select a prefix.

This reader never interprets the observations as measured cache hits or PUTs.
Replay policy and synthetic payloads belong to the explicitly recorded model.
"""
import hashlib
import os
from pathlib import Path

import kv_trace as kv


def regular(path):
    path = Path(path)
    kv.require(path.is_absolute() and path == path.resolve(), 'Redirected input file')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    stream = os.fdopen(fd, 'rb')
    try:
        kv.fingerprint(stream)
        return stream
    except BaseException:
        stream.close()
        raise


def bounded(path):
    with regular(path) as stream:
        before = kv.fingerprint(stream)
        raw = stream.read(65537)
        kv.require(len(raw) <= 65536 and kv.fingerprint(stream) == before, 'Oversized/changing input manifest')
        return raw


def checked_parameters(value):
    result = kv.parameters(value['model_namespace'], value['kv_format_namespace'], value['user_namespace'],
                           value['reuse_mode'], value['scale_numerator'], value['scale_denominator'],
                           kv.decimal_integer(value['measurement_start_ns_decimal'], 'measurement start', kv.MAX_NS))
    kv.require(kv.canonical(value) == kv.canonical(result), 'Conversion parameters changed')
    return result


def load(conversion, source_path, max_observations, descriptors=None):
    """Read the entire source/event pair once; retain at most max_observations.

    The limit applies to selected block observations, not provenance checking.
    Exact regeneration detects edited events even if their manifest is rehashed.
    """
    kv.integer(max_observations, 'selected observation bound', 1, 4096)
    conversion, source_path = Path(conversion), Path(source_path)
    for path in (conversion, source_path):
        kv.require(path.is_absolute() and path == path.resolve(), 'Require original canonical input paths')
    manifest_path, events_path = conversion / 'manifest.json', conversion / 'events.jsonl'
    manifest_bytes = bounded(manifest_path)
    manifest = kv.parse_json(manifest_bytes)
    kv.require(manifest.get('schema') == 'ec-kv-conversion/v1' and manifest.get('status') == 'complete',
               'Incomplete conversion')
    source = kv.validate_source(manifest['source'])
    params = checked_parameters(manifest['parameters'])
    kv.require(manifest['namespace_sha256'] == kv.namespace(source, params), 'Conversion namespace differs')
    kv.require(kv.canonical(manifest['claims']) == kv.canonical({'actual_kv_tensors': False, 'hit_rate_measured': False,
               'unique_objects_counted': False, 'storage_io_performed': False, 'trace_prestart_cache_known': False}),
               'Unsupported conversion claims')
    kv.require(type(manifest['directory_fsync_supported']) is bool
               and manifest['full_lfs_object_verified'] is (source['input_scope'] == 'full-file'), 'Source scope differs')
    descriptor_sha = None
    if source['input_scope'] == 'bounded-prefix':
        if descriptors is None:
            base = Path(__file__).resolve().parent
            descriptors = base / ('inputs' if base.name == 'traces' else 'trace-inputs')
        descriptor = Path(descriptors) / (source['path'] + '.prefix.source.json')
        raw = bounded(descriptor)
        kv.require(len(raw) <= 65536 and kv.canonical(kv.parse_json(raw)) == kv.canonical(source),
                   'Prefix is not the pinned published descriptor; synthetic fixtures are separate evidence')
        descriptor_sha = kv.sha(raw)
    selected = []
    records = count = blocks = logical = offset = 0
    regions = {'warmup': 0, 'measurement': 0}
    previous = -1
    horizon = 0
    source_hash, event_hash = hashlib.sha256(), hashlib.sha256()
    with regular(source_path) as src, regular(events_path) as events:
        source_before, event_before = kv.fingerprint(src), kv.fingerprint(events)
        expected_bytes = int(source['input_bytes_decimal'])
        kv.require(os.fstat(src.fileno()).st_size == expected_bytes, 'Source byte count differs before validation')
        while True:
            raw = src.readline(kv.MAX_LINE + 1)
            if not raw:
                break
            kv.require(len(raw) <= kv.MAX_LINE and raw.endswith(b'\n'), 'Incomplete/oversized source row')
            kv.require(offset + len(raw) <= expected_bytes, 'Source grew beyond pinned byte count')
            source_hash.update(raw)
            records += 1
            row = kv.parse_json(raw)
            current = kv.validate_row(row)
            kv.require(current >= previous, 'Source clock moved backwards')
            previous = current
            for expected in kv.row_events(row, source, params, records, offset, raw):
                expected['sequence_decimal'] = str(count)
                actual = events.readline(kv.MAX_LINE + 1)
                kv.require(actual == kv.canonical(expected) + b'\n', 'Event differs from exact source regeneration')
                event_hash.update(actual)
                count += 1
                horizon = int(expected['clock']['scaled_ns_decimal'])
                if expected['kind'] == 'request_arrival':
                    regions[expected['clock']['region']] += 1
                else:
                    blocks += 1
                    logical += int(expected['object']['logical_bytes_decimal'])
                    if len(selected) < max_observations:
                        selected.append(expected)
            offset += len(raw)
        kv.require(not events.read(1), 'Extra converted events')
        kv.require(kv.fingerprint(src) == source_before and kv.fingerprint(events) == event_before,
                   'Input changed during validation')
    kv.require(records > 0 and selected, 'No block observations to execute')
    kv.require(source_hash.hexdigest() == source['input_sha256'] and str(offset) == source['input_bytes_decimal'],
               'Source bytes differ')
    kv.require(event_hash.hexdigest() == manifest['events_sha256'], 'Converted event digest differs')
    for name, actual in (('records_decimal', records), ('events_decimal', count),
                         ('block_observations_decimal', blocks), ('logical_bytes_observed_decimal', logical)):
        kv.require(manifest[name] == str(actual), 'Conversion totals differ')
    kv.require(kv.canonical(manifest['request_regions']) == kv.canonical(regions), 'Conversion regions differ')
    kv.require(bounded(manifest_path) == manifest_bytes, 'Manifest changed during validation')
    truncated = blocks > len(selected)
    binding = {'schema': 1, 'kind': 'verified_public_input_observations', 'source': source,
               'source_path': str(source_path), 'conversion_directory': str(conversion),
               'manifest_sha256': kv.sha(manifest_bytes), 'events_sha256': event_hash.hexdigest(),
               'prefix_descriptor_sha256': descriptor_sha, 'parameters': params,
               'namespace_sha256': manifest['namespace_sha256'], 'all_input_bytes_verified': True,
               'selected_observations': len(selected), 'selection_limit': max_observations,
               'selection_is_prefix': True, 'selection_truncated': truncated,
               'last_selected_sequence_decimal': selected[-1]['sequence_decimal'],
               'horizon_ns_decimal': str(int(selected[-1]['clock']['scaled_ns_decimal']) if truncated else horizon),
               'actual_kv_tensors': False, 'observed_cache_decisions': False,
               'reader_sha256': kv.sha(Path(__file__).read_bytes()),
               'converter_sha256': kv.sha(Path(kv.__file__).read_bytes())}
    return binding, selected
