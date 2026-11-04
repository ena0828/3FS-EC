use super::*;
use std::io::Write;

// Engine::open creates 5,632 descriptors. Serialize this module's real-engine
// tests rather than hiding resource failures with skipped tests or fake stores.
static ENGINE_TEST: Mutex<()> = Mutex::new(());
// The joint format record is owned by ec_scope, separate from stage records.
const STAGE_FORMAT_PREFIX: u8 = 15;

fn root() -> (tempfile::TempDir, EngineConfig) {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("engine", IMMUTABLE_STAGE_ROOT_MARKER),
        ("engine-ec-v1", IMMUTABLE_STAGE_V1_BLOCKER),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.path().join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    std::fs::File::open(dir.path()).unwrap().sync_all().unwrap();
    let config = EngineConfig {
        path: dir.path().join(IMMUTABLE_STAGE_ENGINE_DIRECTORY),
        create: true,
        prefix_len: 2,
    };
    (dir, config)
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(37).wrapping_add(seed))
        .collect()
}

fn spec(data: &[u8], id: u8) -> ImmutableStageSpec {
    ImmutableStageSpec {
        stage_id: [id; 16],
        length: data.len() as u32,
        checksum: crc32c::crc32c(data),
        chain_ver: 0,
        last_request_id: 81,
        last_client_low: 82,
        last_client_high: 83,
        etag: vec![id; 16],
    }
}

fn append_all(
    engine: &ImmutableStagingEngine,
    key: &[u8],
    spec: &ImmutableStageSpec,
    bytes: &[u8],
) {
    for (index, block) in bytes.chunks(IMMUTABLE_STAGE_BLOCK_BYTES).enumerate() {
        engine.append(key, &spec.stage_id, index, block).unwrap();
    }
}

fn position(engine: &ImmutableStagingEngine, key: &[u8]) -> Position {
    engine
        .slot(key)
        .unwrap()
        .lock()
        .unwrap()
        .record
        .as_ref()
        .unwrap()
        .pos
}

fn inject(engine: &ImmutableStagingEngine, point: StageWritePoint, after_commit: bool) {
    *engine.0.fault.lock().unwrap() = Some(StageFault {
        point,
        after_commit,
    });
}

fn raw_store(config: &EngineConfig, create: bool) -> RocksDB {
    if create {
        std::fs::create_dir_all(config.path.join("meta")).unwrap();
    }
    RocksDB::open::<MetaMergeOp>(&RocksDBConfig {
        path: config.path.join("meta"),
        create,
        read_only: false,
    })
    .unwrap()
}

fn raw_snapshot(raw: &RocksDB) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    raw.new_iterator()
        .iterate([], |key, value| {
            rows.push((key.to_vec(), value.to_vec()));
            Ok(())
        })
        .unwrap();
    rows
}

#[test]
fn test_immutable_stage_record_fixed_format_and_bounds() {
    let bytes = data(4097, 4);
    let key = b"ec-record";
    let mut record = StageRecord::new(
        key,
        spec(&bytes, 1),
        Position::new(GroupId::new(CHUNK_SIZE_SMALL, 0, 0), 0),
    );
    record.pending = Some(StageBlockProof::of(&bytes));
    let encoded = record.encode(key).unwrap();
    assert_eq!(encoded.len(), 1024);
    assert_eq!(StageRecord::decode(key, &encoded).unwrap(), record);
    assert!(StageRecord::decode(b"ec-another-key", &encoded).is_err());
    for offset in [0, 8, 9, 10, 11, 20, 40, 100, 200, 900, 1023] {
        let mut corrupt = encoded;
        corrupt[offset] ^= 1;
        assert!(
            StageRecord::decode(key, &corrupt).is_err(),
            "offset {offset}"
        );
    }
    assert!(StageRecord::decode(key, &encoded[..1023]).is_err());
    record.completed = 17;
    assert!(record.encode(key).is_err());
    let mut invalid = spec(&bytes, 1);
    invalid.length = IMMUTABLE_STAGE_MAX_BYTES as u32 + 1;
    assert!(invalid.validate().is_err());
    invalid = spec(&bytes, 1);
    invalid.etag.resize(65, 0);
    assert!(invalid.validate().is_err());
    invalid = spec(&bytes, 0);
    assert!(invalid.validate().is_err());
}

#[test]
fn test_immutable_stage_markers_reject_downgrade_paths_before_open() {
    let (_dir, mut config) = root();
    let limits = ImmutableStageLimits::default();
    assert!(Engine::open(&config).is_err());
    assert!(!config.path.exists());
    let parent = config.path.parent().unwrap();
    std::fs::write(parent.join("engine"), b"3FS_EC_ENGINE_ROOT_V1\n").unwrap();
    assert!(ImmutableStagingEngine::open(&config, limits).is_err());
    assert!(!config.path.exists());
    std::fs::write(parent.join("engine"), IMMUTABLE_STAGE_ROOT_MARKER).unwrap();
    std::fs::remove_file(parent.join("engine-ec-v1")).unwrap();
    std::os::unix::fs::symlink(parent.join("engine"), parent.join("engine-ec-v1")).unwrap();
    assert!(ImmutableStagingEngine::open(&config, limits).is_err());
    assert!(!config.path.exists());
    config.path = parent.join("engine-ec-v1");
    assert!(ImmutableStagingEngine::open(&config, limits).is_err());
}

#[test]
fn test_immutable_stage_stream_seal_reopen_and_account_once() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let bytes = data(112 * 1024 + 3, 7);
    let spec = spec(&bytes, 1);
    let key = b"ec-stream-roundtrip";
    let accounted;
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        let initial = engine.begin(key, &spec).unwrap();
        assert_eq!(initial.prefix_bytes, 0);
        assert!(!initial.needs_reconcile);
        assert!(engine
            .0
            .engine
            .meta_store
            .get_chunk_meta(key)
            .unwrap()
            .is_none());
        assert!(engine
            .0
            .engine
            .query_uncommitted_chunks(b"ec")
            .unwrap()
            .is_empty());
        assert_eq!(
            engine.0.engine.meta_store.query_used_size(b"ec").unwrap(),
            0
        );
        let pos = position(&engine, key);
        append_all(&engine, key, &spec, &bytes);
        assert_eq!(position(&engine, key), pos);
        assert_eq!(engine.0.engine.used_size().position_count, 1);
        let sealed = engine.seal(key, &spec.stage_id).unwrap();
        assert_eq!(sealed.pos, pos);
        assert_eq!(sealed.chain_ver, 0);
        assert_eq!(sealed.etag.as_slice(), spec.etag);
        assert_eq!(sealed.last_request_id, 81);
        assert!(!sealed.uncommitted);
        accounted = engine.0.engine.meta_store.query_used_size(b"ec").unwrap();
        assert_eq!(accounted, pos.chunk_size().0);
        for _ in 0..3 {
            assert_eq!(engine.seal(key, &spec.stage_id).unwrap(), sealed);
            assert_eq!(
                engine.0.engine.meta_store.query_used_size(b"ec").unwrap(),
                accounted
            );
        }
        let actual: Vec<u8> = (0..spec.block_count())
            .flat_map(|index| {
                engine
                    .read_sealed_block(key, &spec.stage_id, index)
                    .unwrap()
            })
            .collect();
        assert_eq!(actual, bytes);
    }
    config.create = false;
    let reopened = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    assert!(reopened.query(key, &spec.stage_id).unwrap().needs_reconcile);
    assert!(
        !reopened
            .reconcile(key, &spec.stage_id)
            .unwrap()
            .needs_reconcile
    );
    assert_eq!(
        reopened.0.engine.meta_store.query_used_size(b"ec").unwrap(),
        accounted
    );
    let actual: Vec<u8> = (0..spec.block_count())
        .flat_map(|index| {
            reopened
                .read_sealed_block(key, &spec.stage_id, index)
                .unwrap()
        })
        .collect();
    assert_eq!(actual, bytes);
}

#[test]
fn test_immutable_stage_empty_tail_maximum_and_duplicate_rules() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root();
    let engine = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    for (id, len) in [(1, 0), (2, 1), (3, 4097), (4, IMMUTABLE_STAGE_MAX_BYTES)] {
        let key = format!("ec-boundary-{id}");
        let bytes = data(len, id);
        let spec = spec(&bytes, id);
        engine.begin(key.as_bytes(), &spec).unwrap();
        if !bytes.is_empty() {
            assert!(engine
                .append(key.as_bytes(), &spec.stage_id, spec.block_count(), &[])
                .is_err());
            assert!(engine
                .append(key.as_bytes(), &spec.stage_id, 0, &[])
                .is_err());
        }
        append_all(&engine, key.as_bytes(), &spec, &bytes);
        if !bytes.is_empty() {
            let first = &bytes[..bytes.len().min(IMMUTABLE_STAGE_BLOCK_BYTES)];
            engine
                .append(key.as_bytes(), &spec.stage_id, 0, first)
                .unwrap();
            let mut conflict = first.to_vec();
            conflict[0] ^= 1;
            assert_eq!(
                engine.append(key.as_bytes(), &spec.stage_id, 0, &conflict),
                Err(ImmutableStageError::Conflict)
            );
        }
        let before = engine.0.engine.used_size().position_count;
        engine.seal(key.as_bytes(), &spec.stage_id).unwrap();
        assert_eq!(engine.0.engine.used_size().position_count, before);
        assert!(engine
            .cancel_after_fence(key.as_bytes(), &spec.stage_id)
            .is_err());
        let mut changed = spec.clone();
        changed.last_request_id += 1;
        assert_eq!(
            engine.begin(key.as_bytes(), &changed),
            Err(ImmutableStageError::Conflict)
        );
    }
}

#[test]
fn test_immutable_stage_reservation_unknown_never_reallocates() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root();
    let engine = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    let bytes = data(4097, 9);
    for (id, after_commit) in [(1, false), (2, true)] {
        let key = format!("ec-unknown-reserve-{id}");
        let spec = spec(&bytes, id);
        inject(&engine, StageWritePoint::Reservation, after_commit);
        assert!(matches!(
            engine.begin(key.as_bytes(), &spec),
            Err(ImmutableStageError::OutcomeUnknown(_))
        ));
        let pos = position(&engine, key.as_bytes());
        assert!(matches!(
            engine.append(key.as_bytes(), &spec.stage_id, 0, &bytes),
            Err(ImmutableStageError::OutcomeUnknown(_))
        ));
        let status = engine.reconcile(key.as_bytes(), &spec.stage_id).unwrap();
        assert_eq!(status.prefix_bytes, 0);
        assert!(!status.needs_reconcile);
        assert_eq!(position(&engine, key.as_bytes()), pos);
        assert!(engine
            .0
            .engine
            .meta_store
            .get_chunk_meta(key.as_bytes())
            .unwrap()
            .is_none());
        append_all(&engine, key.as_bytes(), &spec, &bytes);
        engine.seal(key.as_bytes(), &spec.stage_id).unwrap();
    }
    assert_eq!(engine.0.engine.used_size().position_count, 2);
}

#[test]
fn test_immutable_stage_intent_before_bytes_and_pending_survives_reopen() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let key = b"ec-pending-intent";
    let bytes = data(4097, 11);
    let spec = spec(&bytes, 1);
    let pos;
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        engine.begin(key, &spec).unwrap();
        pos = position(&engine, key);
        inject(&engine, StageWritePoint::Intent, true);
        assert!(matches!(
            engine.append(key, &spec.stage_id, 0, &bytes),
            Err(ImmutableStageError::OutcomeUnknown(_))
        ));
        // Actual durable intent exists; injected lost confirmation occurs
        // before the first payload pwrite. This is not a power-loss test.
        let mut disk = vec![1; bytes.len()];
        engine
            .slot(key)
            .unwrap()
            .lock()
            .unwrap()
            .chunk
            .as_ref()
            .unwrap()
            .pread(&mut disk, 0)
            .unwrap();
        assert!(disk.iter().all(|byte| *byte == 0));
        assert!(engine.query(key, &spec.stage_id).unwrap().pending_block);
    }
    config.create = false;
    let reopened = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    let status = reopened.reconcile(key, &spec.stage_id).unwrap();
    assert_eq!(status.prefix_bytes, 0);
    assert!(status.pending_block);
    assert_eq!(position(&reopened, key), pos);
    let mut conflict = bytes.clone();
    conflict[0] ^= 1;
    assert_eq!(
        reopened.append(key, &spec.stage_id, 0, &conflict),
        Err(ImmutableStageError::Conflict)
    );
    reopened.append(key, &spec.stage_id, 0, &bytes).unwrap();
    reopened.seal(key, &spec.stage_id).unwrap();
    assert_eq!(
        reopened.read_sealed_block(key, &spec.stage_id, 0).unwrap(),
        bytes
    );
}

#[test]
fn test_immutable_stage_data_without_progress_is_not_promoted() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let key = b"ec-data-before-prefix";
    let bytes = data(IMMUTABLE_STAGE_BLOCK_BYTES + 5, 17);
    let spec = spec(&bytes, 1);
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        engine.begin(key, &spec).unwrap();
        inject(&engine, StageWritePoint::Progress, false);
        assert!(matches!(
            engine.append(
                key,
                &spec.stage_id,
                0,
                &bytes[..IMMUTABLE_STAGE_BLOCK_BYTES]
            ),
            Err(ImmutableStageError::OutcomeUnknown(_))
        ));
        assert_eq!(engine.query(key, &spec.stage_id).unwrap().prefix_bytes, 0);
    }
    config.create = false;
    let reopened = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    assert_eq!(
        reopened
            .reconcile(key, &spec.stage_id)
            .unwrap()
            .prefix_bytes,
        0
    );
    assert!(reopened.seal(key, &spec.stage_id).is_err());
    assert!(reopened
        .append(
            key,
            &spec.stage_id,
            1,
            &bytes[IMMUTABLE_STAGE_BLOCK_BYTES..]
        )
        .is_err());
    append_all(&reopened, key, &spec, &bytes);
    reopened.seal(key, &spec.stage_id).unwrap();
    assert_eq!(
        reopened.read_sealed_block(key, &spec.stage_id, 1).unwrap(),
        bytes[IMMUTABLE_STAGE_BLOCK_BYTES..]
    );
}

#[test]
fn test_immutable_stage_progress_confirmation_loss_recovers_exact_prefix() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root();
    let engine = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    let bytes = data(IMMUTABLE_STAGE_BLOCK_BYTES + 3, 19);
    let spec = spec(&bytes, 1);
    let key = b"ec-progress-confirmation";
    engine.begin(key, &spec).unwrap();
    inject(&engine, StageWritePoint::Progress, true);
    assert!(matches!(
        engine.append(
            key,
            &spec.stage_id,
            0,
            &bytes[..IMMUTABLE_STAGE_BLOCK_BYTES]
        ),
        Err(ImmutableStageError::OutcomeUnknown(_))
    ));
    let query = engine.query(key, &spec.stage_id).unwrap();
    assert!(query.needs_reconcile);
    assert_eq!(query.prefix_bytes, IMMUTABLE_STAGE_BLOCK_BYTES as u32);
    let confirmed = engine.reconcile(key, &spec.stage_id).unwrap();
    assert!(!confirmed.needs_reconcile);
    assert_eq!(confirmed.prefix_bytes, query.prefix_bytes);
    append_all(&engine, key, &spec, &bytes);
    engine.seal(key, &spec.stage_id).unwrap();
}

#[test]
fn test_immutable_stage_seal_unknown_read_reconcile_no_double_account() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let bytes = data(4097, 23);
    let spec = spec(&bytes, 1);
    let key = b"ec-unknown-seal";
    let accounted;
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        engine.begin(key, &spec).unwrap();
        append_all(&engine, key, &spec, &bytes);
        inject(&engine, StageWritePoint::Seal, true);
        assert!(matches!(
            engine.seal(key, &spec.stage_id),
            Err(ImmutableStageError::OutcomeUnknown(_))
        ));
        let query = engine.query(key, &spec.stage_id).unwrap();
        assert_eq!(query.state, ImmutableStageState::Sealed);
        assert!(query.needs_reconcile);
        // Actual metadata committed, but the staging holder still owns its
        // position. The immutable lookup must not assert first_ref here.
        let read = engine.0.engine.get_immutable(key).unwrap().unwrap();
        let mut actual = vec![0; bytes.len()];
        read.pread(&mut actual, 0).unwrap();
        assert_eq!(actual, bytes);
        drop(read);
        accounted = engine.0.engine.meta_store.query_used_size(b"ec").unwrap();
        for _ in 0..3 {
            engine.reconcile(key, &spec.stage_id).unwrap();
            engine.seal(key, &spec.stage_id).unwrap();
            assert_eq!(
                engine.0.engine.meta_store.query_used_size(b"ec").unwrap(),
                accounted
            );
            assert_eq!(engine.0.engine.used_size().position_count, 1);
            assert_eq!(engine.0.engine.used_size().position_rc, 1);
        }
    }
    config.create = false;
    let reopened = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    reopened.reconcile(key, &spec.stage_id).unwrap();
    assert_eq!(
        reopened.read_sealed_block(key, &spec.stage_id, 0).unwrap(),
        bytes
    );
    assert_eq!(
        reopened.0.engine.meta_store.query_used_size(b"ec").unwrap(),
        accounted
    );
}

#[test]
fn test_immutable_stage_cancel_unknown_retains_reservation_until_confirmed() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root();
    let engine = ImmutableStagingEngine::open(
        &config,
        ImmutableStageLimits {
            max_active: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let bytes = data(4097, 29);
    let spec = spec(&bytes, 1);
    let key = b"ec-cancel";
    engine.begin(key, &spec).unwrap();
    inject(&engine, StageWritePoint::Abort, true);
    assert!(matches!(
        engine.cancel_after_fence(key, &spec.stage_id),
        Err(ImmutableStageError::OutcomeUnknown(_))
    ));
    assert_eq!(engine.0.engine.used_size().position_count, 1);
    assert_eq!(
        engine.begin(b"ec-another", &spec),
        Err(ImmutableStageError::Busy)
    );
    assert_eq!(
        engine.reconcile(key, &spec.stage_id).unwrap().state,
        ImmutableStageState::Aborted
    );
    assert_eq!(engine.0.engine.used_size().position_count, 0);
    assert_eq!(
        engine
            .cancel_after_fence(key, &spec.stage_id)
            .unwrap()
            .state,
        ImmutableStageState::Aborted
    );
    let mut changed = spec.clone();
    changed.checksum ^= 1;
    assert_eq!(
        engine.begin(key, &changed),
        Err(ImmutableStageError::Conflict)
    );
    assert!(engine.append(key, &spec.stage_id, 0, &bytes).is_err());
    engine.begin(b"ec-another", &spec).unwrap();
    assert_eq!(engine.0.engine.used_size().position_count, 1);
}

#[test]
fn test_immutable_stage_active_recovery_does_not_reuse_extent() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let bytes = data(4097, 31);
    let spec = spec(&bytes, 1);
    let key = b"ec-held-extent";
    let pos;
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        engine.begin(key, &spec).unwrap();
        pos = position(&engine, key);
        engine.append(key, &spec.stage_id, 0, &bytes).unwrap();
    }
    config.create = false;
    let reopened = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    assert_eq!(position(&reopened, key), pos);
    assert_eq!(reopened.0.engine.used_size().position_count, 1);
    reopened.begin(b"ec-other-extent", &spec).unwrap();
    assert_ne!(position(&reopened, b"ec-other-extent"), pos);
    reopened.reconcile(key, &spec.stage_id).unwrap();
    reopened.seal(key, &spec.stage_id).unwrap();
    assert_eq!(
        reopened.read_sealed_block(key, &spec.stage_id, 0).unwrap(),
        bytes
    );
    assert!(reopened
        .0
        .engine
        .query_uncommitted_chunks(b"ec")
        .unwrap()
        .is_empty());
}

#[test]
fn test_immutable_stage_corruption_blocks_reconcile_and_seal() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root();
    let engine = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    let bytes = data(4097, 37);
    let spec = spec(&bytes, 1);
    let key = b"ec-corrupt-block";
    engine.begin(key, &spec).unwrap();
    append_all(&engine, key, &spec, &bytes);
    let pos = position(&engine, key);
    engine
        .0
        .engine
        .allocators
        .select_by_pos(pos)
        .unwrap()
        .clusters
        .pwrite(pos, &[bytes[0] ^ 1], 0)
        .unwrap();
    assert!(matches!(
        engine.reconcile(key, &spec.stage_id),
        Err(ImmutableStageError::Corrupt(_))
    ));
    assert!(engine.seal(key, &spec.stage_id).is_err());
    assert!(engine
        .0
        .engine
        .meta_store
        .get_chunk_meta(key)
        .unwrap()
        .is_none());
    assert_eq!(engine.0.engine.used_size().position_count, 1);
}

#[test]
fn test_immutable_stage_concurrent_duplicate_and_io_bound() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root();
    let engine = ImmutableStagingEngine::open(
        &config,
        ImmutableStageLimits {
            max_concurrent_io: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let bytes = data(4097, 41);
    let spec = spec(&bytes, 1);
    let key = b"ec-parallel-duplicate";
    engine.begin(key, &spec).unwrap();
    std::thread::scope(|scope| {
        let one = scope.spawn(|| engine.append(key, &spec.stage_id, 0, &bytes));
        let two = scope.spawn(|| engine.append(key, &spec.stage_id, 0, &bytes));
        one.join().unwrap().unwrap();
        two.join().unwrap().unwrap();
    });
    assert_eq!(
        engine.query(key, &spec.stage_id).unwrap().prefix_bytes,
        bytes.len() as u32
    );
    assert_eq!(engine.0.engine.used_size().position_count, 1);
    let first = engine.permit().unwrap();
    let second = engine.permit().unwrap();
    assert!(matches!(engine.permit(), Err(ImmutableStageError::Busy)));
    drop((first, second));
    engine.seal(key, &spec.stage_id).unwrap();
    assert_eq!(
        engine.read_sealed_block(key, &spec.stage_id, 0).unwrap(),
        bytes
    );
    let buffer = StageBuffer::new().unwrap();
    assert_eq!(buffer.as_ptr() as usize % 4096, 0);
    assert_eq!(buffer.len(), IMMUTABLE_STAGE_BLOCK_BYTES);
    assert_eq!(buffer.bytes.len(), IMMUTABLE_STAGE_BLOCK_BYTES + 4095);
}

#[test]
fn test_immutable_stage_conflicting_position_index_blocks_write_and_recovery() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let bytes = data(4097, 43);
    let spec = spec(&bytes, 1);
    let key = b"ec-conflicting-position";
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        engine.begin(key, &spec).unwrap();
        let pos = position(&engine, key);
        let mut batch = RocksDB::new_write_batch();
        batch.put(
            MetaKey::pos_to_chunk_key(pos),
            b"ec-some-other-committed-key",
        );
        engine.0.engine.meta_store.write(batch, true).unwrap();
        assert!(engine.append(key, &spec.stage_id, 0, &bytes).is_err());
        assert!(engine.cancel_after_fence(key, &spec.stage_id).is_err());
        assert!(engine.reconcile(key, &spec.stage_id).is_err());
        let mut disk = vec![1; bytes.len()];
        engine
            .slot(key)
            .unwrap()
            .lock()
            .unwrap()
            .chunk
            .as_ref()
            .unwrap()
            .pread(&mut disk, 0)
            .unwrap();
        assert!(disk.iter().all(|byte| *byte == 0));
        assert_eq!(engine.0.engine.used_size().position_count, 1);
    }
    config.create = false;
    assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
}

#[test]
fn test_immutable_stage_orphan_oversized_index_is_rejected_on_recovery() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        let mut value = vec![STAGE_PREFIX; IMMUTABLE_STAGE_MAX_KEY_BYTES + 2];
        value[0] = STAGE_PREFIX;
        let mut batch = RocksDB::new_write_batch();
        batch.put(
            stage_position_key(Position::new(GroupId::new(CHUNK_SIZE_SMALL, 0, 0), 0)),
            value,
        );
        engine.0.engine.meta_store.write(batch, true).unwrap();
    }
    config.create = false;
    assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
}

#[test]
fn test_immutable_stage_legacy_log_is_rejected_before_occupy_or_vacate() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let key = b"ec-active-before-legacy-record";
    let bytes = data(4097, 47);
    let spec = spec(&bytes, 1);
    let record;
    {
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        engine.begin(key, &spec).unwrap();
        record = engine
            .0
            .engine
            .meta_store
            .stage_record(key)
            .unwrap()
            .unwrap();
        engine
            .0
            .engine
            .meta_store
            .persist_writing_chunk(b"ec-forbidden-legacy", &record.metadata())
            .unwrap();
    }
    config.create = false;
    assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
    let meta = MetaStore::open(&MetaStoreConfig {
        rocksdb: RocksDBConfig {
            path: config.path.join("meta"),
            create: false,
            ..Default::default()
        },
        prefix_len: config.prefix_len,
    })
    .unwrap();
    assert!(meta
        .stage_get_exact(MetaKey::writing_chunk_key(b"ec-forbidden-legacy").as_ref())
        .unwrap()
        .is_some());
    assert!(meta
        .stage_get_exact(MetaKey::pos_to_chunk_key(record.pos).as_ref())
        .unwrap()
        .is_none());
    assert_eq!(meta.stage_record(key).unwrap().unwrap(), record);
}

#[test]
fn test_immutable_stage_terminal_cache_is_not_lifetime_capacity() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let limits = ImmutableStageLimits {
        max_cached_records: 2,
        max_active: 1,
        max_concurrent_io: 1,
    };
    let bytes = data(4097, 53);
    {
        let engine = ImmutableStagingEngine::open(&config, limits).unwrap();
        for id in 1..=7 {
            let key = format!("ec-cache-capacity-{id}");
            let spec = spec(&bytes, id);
            engine.begin(key.as_bytes(), &spec).unwrap();
            append_all(&engine, key.as_bytes(), &spec, &bytes);
            engine.seal(key.as_bytes(), &spec.stage_id).unwrap();
            assert!(engine.0.registry.lock().unwrap().slots.len() <= 2);
        }
        let first = spec(&bytes, 1);
        assert_eq!(
            engine.begin(b"ec-cache-capacity-1", &first).unwrap().state,
            ImmutableStageState::Sealed
        );
        let mut changed = first.clone();
        changed.checksum ^= 1;
        assert_eq!(
            engine.begin(b"ec-cache-capacity-1", &changed),
            Err(ImmutableStageError::Conflict)
        );
        let before = engine.0.engine.meta_store.query_used_size(b"ec").unwrap();
        engine
            .seal(b"ec-cache-capacity-1", &first.stage_id)
            .unwrap();
        assert_eq!(
            engine.0.engine.meta_store.query_used_size(b"ec").unwrap(),
            before
        );
        assert_eq!(
            engine
                .read_sealed_block(b"ec-cache-capacity-1", &first.stage_id, 0)
                .unwrap(),
            bytes
        );
    }
    config.create = false;
    let reopened = ImmutableStagingEngine::open(&config, limits).unwrap();
    assert_eq!(reopened.0.registry.lock().unwrap().slots.len(), 0);
    for id in 1..=7 {
        let key = format!("ec-cache-capacity-{id}");
        let spec = spec(&bytes, id);
        // Cache misses reconfirm existing terminal state; they do not replay
        // add_chunk_mut or require every terminal record to remain resident.
        reopened.seal(key.as_bytes(), &spec.stage_id).unwrap();
        assert_eq!(
            reopened
                .read_sealed_block(key.as_bytes(), &spec.stage_id, 0)
                .unwrap(),
            bytes
        );
        assert!(reopened.0.registry.lock().unwrap().slots.len() <= 2);
    }
    let spec = spec(&bytes, 8);
    reopened
        .begin(b"ec-after-several-capacities", &spec)
        .unwrap();
}

#[test]
fn test_immutable_stage_process_exit_recovery() {
    const CHILD_PATH: &str = "HF3FS_IMMUTABLE_STAGE_TEST_CHILD";
    const CHILD_READY: &str = "HF3FS_IMMUTABLE_STAGE_TEST_READY";
    const FILTER: &str = "core::immutable_stage::tests::test_immutable_stage_process_exit_recovery";
    let key = b"ec-process-exit-stage";
    let bytes = data(IMMUTABLE_STAGE_BLOCK_BYTES + 7, 59);
    let spec = spec(&bytes, 1);
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let config = EngineConfig {
            path: path.into(),
            create: true,
            prefix_len: 2,
        };
        let engine =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        engine.begin(key, &spec).unwrap();
        inject(&engine, StageWritePoint::Progress, true);
        assert!(engine
            .append(
                key,
                &spec.stage_id,
                0,
                &bytes[..IMMUTABLE_STAGE_BLOCK_BYTES]
            )
            .is_err());
        let mut ready = std::fs::File::create(std::env::var_os(CHILD_READY).unwrap()).unwrap();
        ready
            .write_all(b"prefix committed; confirmation withheld\n")
            .unwrap();
        ready.sync_all().unwrap();
        loop {
            std::thread::park();
        }
    }
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let control = tempfile::tempdir().unwrap();
    let stderr_path = control.path().join("stage-test-child.stderr");
    let ready = control.path().join("stage-test-ready");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", FILTER, "--nocapture"])
        .env(CHILD_PATH, &config.path)
        .env(CHILD_READY, &ready)
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Reap(child);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    while !ready.exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "stage child exited early {status}: {}",
                std::fs::read_to_string(&stderr_path).unwrap()
            );
        }
        assert!(
            std::time::Instant::now() < deadline,
            "stage child readiness timeout"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // On Linux Child::kill sends SIGKILL. This exercises process failure with
    // no Rust destructors, not a kernel/power-loss or drive-cache fault.
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    config.create = false;
    let reopened = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    let status = reopened.reconcile(key, &spec.stage_id).unwrap();
    assert_eq!(status.prefix_bytes, IMMUTABLE_STAGE_BLOCK_BYTES as u32);
    assert_eq!(reopened.0.engine.used_size().position_count, 1);
    append_all(&reopened, key, &spec, &bytes);
    reopened.seal(key, &spec.stage_id).unwrap();
    assert_eq!(
        reopened.read_sealed_block(key, &spec.stage_id, 1).unwrap(),
        bytes[IMMUTABLE_STAGE_BLOCK_BYTES..]
    );
}

#[test]
fn test_immutable_stage_joint_provision_recovers_before_and_after_confirmation() {
    let _serial = ENGINE_TEST.lock().unwrap();
    for point in [
        StageOpenPoint::AfterEngineOpen,
        StageOpenPoint::AfterJointProvision,
    ] {
        let (_dir, mut config) = root();
        let mut observed_identity = None;
        let failure = ImmutableStagingEngine::open_with_hook(
            &config,
            ImmutableStageLimits::default(),
            |current, engine| {
                if current != point {
                    return Ok(());
                }
                let identity = engine.meta_store.stage_get_exact(&[11]).unwrap();
                let format = engine
                    .meta_store
                    .stage_get_exact(&[STAGE_FORMAT_PREFIX])
                    .unwrap();
                assert_eq!(identity.is_some(), format.is_some());
                assert_eq!(
                    identity.is_some(),
                    point == StageOpenPoint::AfterJointProvision
                );
                observed_identity = identity;
                Err(ImmutableStageError::OutcomeUnknown(
                    "test withheld initialization result".into(),
                ))
            },
        );
        assert!(matches!(
            failure,
            Err(ImmutableStageError::OutcomeUnknown(_))
        ));
        config.create = false;
        let reopened =
            ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
        let identity = reopened
            .0
            .engine
            .meta_store
            .stage_get_exact(&[11])
            .unwrap()
            .unwrap();
        assert_eq!(
            reopened
                .0
                .engine
                .meta_store
                .stage_get_exact(&[STAGE_FORMAT_PREFIX])
                .unwrap()
                .unwrap()
                .len(),
            32
        );
        if let Some(expected) = observed_identity {
            assert_eq!(identity, expected);
        }
        reopened
            .scopes()
            .confirm_staging_identity(config.prefix_len)
            .unwrap();
        let bytes = data(4097, 61);
        let spec = spec(&bytes, 1);
        reopened
            .begin(b"ec-after-initialization-retry", &spec)
            .unwrap();
        append_all(&reopened, b"ec-after-initialization-retry", &spec, &bytes);
        reopened
            .seal(b"ec-after-initialization-retry", &spec.stage_id)
            .unwrap();
    }
}

#[test]
fn test_immutable_stage_partial_empty_namespace_reuses_existing_zero_file() {
    use std::os::unix::fs::MetadataExt;
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root();
    let raw = raw_store(&config, true);
    raw.put(
        [MetaKey::USED_SIZE_PREFIX_LEN_KEY],
        (config.prefix_len as u32).to_le_bytes(),
        true,
    )
    .unwrap();
    drop(raw);
    let class_path = config.path.join(CHUNK_SIZE_SMALL.to_string());
    std::fs::create_dir(&class_path).unwrap();
    let file_path = class_path.join("00");
    std::fs::File::create(&file_path).unwrap();
    let old_inode = std::fs::metadata(&file_path).unwrap().ino();
    config.create = false;
    let engine = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    assert_eq!(std::fs::metadata(&file_path).unwrap().ino(), old_inode);
    assert_eq!(std::fs::metadata(&file_path).unwrap().len(), 0);
    assert!(config
        .path
        .join(CHUNK_SIZE_ULTRA.to_string())
        .join("FF")
        .is_file());
    assert_eq!(engine.0.engine.used_size().position_count, 0);
    engine
        .scopes()
        .confirm_staging_identity(config.prefix_len)
        .unwrap();
}

#[test]
fn test_immutable_stage_invalid_empty_baseline_is_not_rewritten() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let bad_rows = [
        (
            vec![MetaKey::USED_SIZE_PREFIX_LEN_KEY],
            3u32.to_le_bytes().to_vec(),
        ),
        (vec![MetaKey::VERSION_KEY], vec![0]),
        (vec![MetaKey::TIMESTAMP_KEY_PREFIX, 1, 2, 3], vec![9]),
        (
            MetaKey::group_bits_key(GroupId::new(CHUNK_SIZE_SMALL, 0, 0))
                .as_ref()
                .to_vec(),
            GroupState::empty().as_bytes().to_vec(),
        ),
        (vec![10, 1], vec![]),
        (vec![12, 1], vec![]),
        (vec![STAGE_PREFIX, 1], vec![]),
        (vec![99], vec![]),
    ];
    for (key, value) in bad_rows {
        let (_dir, mut config) = root();
        let raw = raw_store(&config, true);
        raw.put(
            [MetaKey::USED_SIZE_PREFIX_LEN_KEY],
            2u32.to_le_bytes(),
            true,
        )
        .unwrap();
        raw.put(key, value, true).unwrap();
        let before = raw_snapshot(&raw);
        drop(raw);
        config.create = false;
        assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
        let raw = raw_store(&config, false);
        assert_eq!(raw_snapshot(&raw), before);
        assert!(!config.path.join(CHUNK_SIZE_SMALL.to_string()).exists());
    }
}

#[test]
fn test_immutable_stage_one_sided_or_conflicting_provision_is_not_repaired() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_source, source_config) = root();
    let source =
        ImmutableStagingEngine::open(&source_config, ImmutableStageLimits::default()).unwrap();
    let identity = source
        .0
        .engine
        .meta_store
        .stage_get_exact(&[11])
        .unwrap()
        .unwrap();
    let format = source
        .0
        .engine
        .meta_store
        .stage_get_exact(&[STAGE_FORMAT_PREFIX])
        .unwrap()
        .unwrap();
    drop(source);
    for mode in 0..4 {
        let (_dir, mut config) = root();
        let raw = raw_store(&config, true);
        raw.put(
            [MetaKey::USED_SIZE_PREFIX_LEN_KEY],
            2u32.to_le_bytes(),
            true,
        )
        .unwrap();
        raw.put([MetaKey::VERSION_KEY], [MetaStore::LATEST_VERSION], true)
            .unwrap();
        if mode != 0 {
            raw.put([11], &identity, true).unwrap();
        }
        if mode != 1 {
            let mut candidate = format.clone();
            if mode == 2 {
                // Preserve a valid record CRC while contradicting the engine
                // identity, rather than testing only accidental corruption.
                candidate[6] ^= 1;
                let crc = crc32c::crc32c(&candidate[..28]);
                candidate[28..].copy_from_slice(&crc.to_be_bytes());
            } else if mode == 3 {
                candidate[0] ^= 1;
            }
            raw.put([STAGE_FORMAT_PREFIX], candidate, true).unwrap();
        }
        let before = raw_snapshot(&raw);
        drop(raw);
        config.create = false;
        assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
        assert_eq!(raw_snapshot(&raw_store(&config, false)), before);
        assert!(!config.path.join(CHUNK_SIZE_SMALL.to_string()).exists());
    }
}

#[test]
fn test_immutable_stage_missing_cluster_is_not_recreated_after_provision() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root();
    let engine = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    let identity = engine.scopes().engine_identity();
    drop(engine);
    let missing = config.path.join(CHUNK_SIZE_SMALL.to_string()).join("00");
    std::fs::remove_file(&missing).unwrap();
    // Even a caller's create=true cannot override an existing joint identity.
    assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
    assert!(!missing.exists());
    let raw = raw_store(&config, false);
    let record = raw.get([11]).unwrap().unwrap();
    assert!(record
        .windows(identity.len())
        .any(|window| window == identity));
}

#[test]
fn test_immutable_stage_nonempty_or_unknown_files_do_not_qualify_as_new() {
    let _serial = ENGINE_TEST.lock().unwrap();
    for mode in 0..3 {
        let (_dir, mut config) = root();
        let raw = raw_store(&config, true);
        if mode != 0 {
            raw.put(
                [MetaKey::USED_SIZE_PREFIX_LEN_KEY],
                2u32.to_le_bytes(),
                true,
            )
            .unwrap();
        }
        let before = raw_snapshot(&raw);
        drop(raw);
        let class_path = config.path.join(CHUNK_SIZE_SMALL.to_string());
        std::fs::create_dir(&class_path).unwrap();
        match mode {
            0 => std::fs::write(class_path.join("00"), b"existing allocated bytes").unwrap(),
            1 => {
                std::fs::File::create(class_path.join("unexpected")).unwrap();
            }
            _ => {
                std::os::unix::fs::symlink(config.path.join("meta"), class_path.join("00")).unwrap()
            }
        }
        config.create = false;
        assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
        assert_eq!(raw_snapshot(&raw_store(&config, false)), before);
        assert!(!class_path.join("01").exists());
    }
}
