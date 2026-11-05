use super::*;
use std::io::Write;

// Real Engine fixtures are resource-heavy. The root runner must also keep its
// global Rust test thread limit small on the 16-GiB development machine.
static ENGINE_TEST: Mutex<()> = Mutex::new(());

fn root(gc: bool) -> (tempfile::TempDir, EngineConfig) {
    let dir = tempfile::tempdir().unwrap();
    let markers = if gc {
        (IMMUTABLE_GC_ROOT_MARKER, IMMUTABLE_GC_V1_BLOCKER)
    } else {
        (IMMUTABLE_STAGE_ROOT_MARKER, IMMUTABLE_STAGE_V1_BLOCKER)
    };
    for (name, bytes) in [("engine", markers.0), ("engine-ec-v1", markers.1)] {
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
fn open(config: &EngineConfig) -> ImmutableStagingEngine {
    ImmutableStagingEngine::open_gc(config, ImmutableStageLimits::default()).unwrap()
}
fn data() -> Vec<u8> {
    (0..4097).map(|i| (i as u8).wrapping_mul(37)).collect()
}
fn spec(bytes: &[u8], id: u8) -> ImmutableStageSpec {
    ImmutableStageSpec {
        stage_id: [id; 16],
        length: bytes.len() as u32,
        checksum: crc32c::crc32c(bytes),
        chain_ver: 0,
        last_request_id: 81,
        last_client_low: 82,
        last_client_high: 83,
        etag: vec![id; 16],
    }
}
fn claim(engine: &ImmutableStagingEngine, spec: &ImmutableStageSpec, id: u8) -> EcStageGcClaim {
    EcStageGcClaim {
        claim_id: [id; 16],
        claim_digest: [id.wrapping_add(1); 32],
        eligibility_digest: [id.wrapping_add(2); 32],
        target: engine.scopes().register_target(1, 2).unwrap(),
        spec: spec.clone(),
    }
}
fn prepare(
    engine: &ImmutableStagingEngine,
    key: &[u8],
    id: u8,
    state: ImmutableStageState,
) -> EcStageGcClaim {
    let bytes = data();
    let spec = spec(&bytes, id);
    engine.begin(key, &spec).unwrap();
    if state == ImmutableStageState::Sealed {
        engine.append(key, &spec.stage_id, 0, &bytes).unwrap();
        engine.seal(key, &spec.stage_id).unwrap();
    }
    if state == ImmutableStageState::Aborted {
        engine.cancel_after_fence(key, &spec.stage_id).unwrap();
    }
    claim(engine, &spec, id)
}
fn inject(engine: &ImmutableStagingEngine, after_commit: bool) {
    *engine.0.fault.lock().unwrap() = Some(StageFault {
        point: StageWritePoint::ExactGc,
        after_commit,
    });
}
fn record(engine: &ImmutableStagingEngine, key: &[u8]) -> StageRecord {
    engine
        .0
        .engine
        .meta_store
        .stage_record(key)
        .unwrap()
        .unwrap()
}

#[test]
fn gc_fixed_ledger_rejects_truncation_changes_and_wrong_key() {
    let key = b"ec-ledger";
    let spec = spec(&data(), 1);
    let claim = EcStageGcClaim {
        claim_id: [1; 16],
        claim_digest: [2; 32],
        eligibility_digest: [3; 32],
        target: crate::ec_scope::EcTargetIdentity {
            engine: [4; 16],
            incarnation: [5; 16],
            chain: 1,
            target: 2,
        },
        spec: spec.clone(),
    };
    let before = StageRecord::new(
        key,
        spec,
        Position::new(GroupId::new(CHUNK_SIZE_SMALL, 0, 0), 0),
    );
    let mut terminal = before.clone();
    terminal.state = ImmutableStageState::Aborted;
    terminal.revision += 1;
    let ledger = EcStageGcRecord::new(key, &claim, &before, &terminal).unwrap();
    let bytes = ledger.encode();
    assert_eq!(bytes.len(), 384);
    assert_eq!(EcStageGcRecord::decode(key, &bytes).unwrap(), ledger);
    assert!(EcStageGcRecord::decode(key, &bytes[..383]).is_err());
    assert!(EcStageGcRecord::decode(b"ec-other", &bytes).is_err());
    for offset in [0, 8, 40, 90, 125, 180, 245, 275, 350, 383] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(EcStageGcRecord::decode(key, &changed).is_err());
    }
    let mut changed = bytes;
    changed[300] = 1;
    let digest = Sha256::digest(&changed[..352]);
    changed[352..].copy_from_slice(&digest);
    assert!(EcStageGcRecord::decode(key, &changed).is_err());
}

#[test]
fn gc_active_sealed_aborted_accounting_is_exact_once() {
    let _serial = ENGINE_TEST.lock().unwrap();
    for state in [
        ImmutableStageState::Active,
        ImmutableStageState::Sealed,
        ImmutableStageState::Aborted,
    ] {
        let (_dir, config) = root(true);
        let engine = open(&config);
        let key = b"ec-exact-once";
        let claim = prepare(&engine, key, 1, state);
        let old = record(&engine, key);
        let size = engine.committed_size(b"ec").unwrap();
        assert_eq!(
            size,
            if state == ImmutableStageState::Sealed {
                old.pos.chunk_size().0
            } else {
                0
            }
        );
        let receipt = engine.collect_known_stage_after_claim(key, &claim).unwrap();
        assert_eq!(engine.committed_size(b"ec").unwrap(), 0);
        assert_eq!(engine.0.engine.used_size().position_count, 0);
        assert_eq!(engine.0.registry.lock().unwrap().active, 0);
        assert_eq!(record(&engine, key).revision, old.revision + 1);
        assert_eq!(
            engine.collect_known_stage_after_claim(key, &claim).unwrap(),
            receipt
        );
        assert_eq!(engine.query_known_stage_gc(key, &claim).unwrap(), receipt);
        assert_eq!(engine.committed_size(b"ec").unwrap(), 0);
        assert!(engine
            .read_sealed_block(key, &claim.spec.stage_id, 0)
            .is_err());
        assert_eq!(
            engine.begin(key, &claim.spec).unwrap().state,
            ImmutableStageState::Aborted
        );
        assert!(engine
            .append(key, &claim.spec.stage_id, 0, &data())
            .is_err());
        assert!(engine.seal(key, &claim.spec.stage_id).is_err());
    }
}

#[test]
fn gc_absence_wrong_instance_and_changed_claim_fail_closed() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root(true);
    let engine = open(&config);
    let key = b"ec-claim-match";
    let original = prepare(&engine, key, 1, ImmutableStageState::Sealed);
    assert_eq!(
        engine.query_known_stage_gc(key, &original),
        Err(ImmutableStageError::Missing)
    );
    assert_eq!(
        engine.collect_known_stage_after_claim(b"ec-absent", &original),
        Err(ImmutableStageError::Missing)
    );
    let mut changed = original.clone();
    changed.target.incarnation[0] ^= 1;
    assert_eq!(
        engine.collect_known_stage_after_claim(key, &changed),
        Err(ImmutableStageError::Conflict)
    );
    changed = original.clone();
    changed.spec.last_client_high += 1;
    assert_eq!(
        engine.collect_known_stage_after_claim(key, &changed),
        Err(ImmutableStageError::Conflict)
    );
    let receipt = engine
        .collect_known_stage_after_claim(key, &original)
        .unwrap();
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.claim_id[0] ^= 1,
            1 => changed.claim_digest[0] ^= 1,
            2 => changed.eligibility_digest[0] ^= 1,
            _ => changed.spec.checksum ^= 1,
        }
        assert_eq!(
            engine.collect_known_stage_after_claim(key, &changed),
            Err(ImmutableStageError::Conflict)
        );
    }
    assert_eq!(
        engine.query_known_stage_gc(key, &original).unwrap(),
        receipt
    );
}

#[test]
fn gc_unknown_before_and_after_batch_retains_original_position() {
    let _serial = ENGINE_TEST.lock().unwrap();
    for state in [ImmutableStageState::Active, ImmutableStageState::Sealed] {
        for after in [false, true] {
            let (_dir, config) = root(true);
            let engine = open(&config);
            let key = b"ec-unknown";
            let claim = prepare(&engine, key, 1, state);
            let original = record(&engine, key);
            inject(&engine, after);
            assert!(matches!(
                engine.collect_known_stage_after_claim(key, &claim),
                Err(ImmutableStageError::OutcomeUnknown(_))
            ));
            assert_eq!(engine.0.engine.used_size().position_count, 1);
            let slot = engine.slot(key).unwrap();
            let slot = slot.lock().unwrap();
            assert!(slot.gc_pending.is_some());
            if state == ImmutableStageState::Sealed {
                assert!(slot.gc_pending.as_ref().unwrap()._sealed_holder.is_some());
            } else {
                assert!(slot.chunk.is_some());
            }
            drop(slot);
            assert!(matches!(
                engine.reconcile(key, &claim.spec.stage_id),
                Err(ImmutableStageError::OutcomeUnknown(_))
            ));
            assert!(matches!(
                engine.begin(key, &claim.spec),
                Err(ImmutableStageError::OutcomeUnknown(_))
            ));
            let other = b"ec-concurrent-position";
            let other_spec = spec(&data(), 2);
            engine.begin(other, &other_spec).unwrap();
            assert_ne!(record(&engine, other).pos, original.pos);
            let receipt = engine.collect_known_stage_after_claim(key, &claim).unwrap();
            assert_eq!(receipt.terminal_revision, original.revision + 1);
            assert_eq!(engine.0.engine.used_size().position_count, 1);
            assert_eq!(engine.committed_size(b"ec").unwrap(), 0);
        }
    }
}

#[test]
fn gc_wal_confirmation_failure_keeps_holder_and_does_not_acknowledge() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root(true);
    let engine = open(&config);
    let key = b"ec-wal-failure";
    let claim = prepare(&engine, key, 1, ImmutableStageState::Sealed);
    inject(&engine, true);
    assert!(engine.collect_known_stage_after_claim(key, &claim).is_err());
    let ledger = engine
        .0
        .engine
        .meta_store
        .stage_gc_record(key)
        .unwrap()
        .unwrap();
    let slot = engine.slot(key).unwrap();
    let mut guard = slot.lock().unwrap();
    let result = engine.finish_gc_locked_with(key, &mut guard, &ledger, |_| {
        Err(Error::IoError("test sync failure".into()))
    });
    assert!(matches!(
        result,
        Err(ImmutableStageError::OutcomeUnknown(_))
    ));
    assert!(guard.gc_pending.is_some());
    assert!(guard.unknown);
    assert_eq!(engine.0.engine.used_size().position_count, 1);
    drop(guard);
    engine.query_known_stage_gc(key, &claim).unwrap();
    assert_eq!(engine.0.engine.used_size().position_count, 0);
}

#[test]
fn gc_reopen_recovers_unknown_commit_without_repeating_accounting() {
    let _serial = ENGINE_TEST.lock().unwrap();
    for after in [false, true] {
        let (_dir, mut config) = root(true);
        let key = b"ec-reopen-gc";
        let claim;
        {
            let engine = open(&config);
            claim = prepare(&engine, key, 1, ImmutableStageState::Sealed);
            inject(&engine, after);
            assert!(engine.collect_known_stage_after_claim(key, &claim).is_err());
        }
        config.create = false;
        let engine = open(&config);
        let receipt = engine.collect_known_stage_after_claim(key, &claim).unwrap();
        assert_eq!(engine.committed_size(b"ec").unwrap(), 0);
        assert_eq!(engine.query_known_stage_gc(key, &claim).unwrap(), receipt);
        assert_eq!(engine.0.engine.used_size().position_count, 0);
    }
}

#[test]
fn gc_old_claim_cannot_free_a_reused_position() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root(true);
    let old_key = b"ec-old-position";
    let new_key = b"ec-new-position";
    let old_claim;
    let old_receipt;
    {
        let engine = open(&config);
        old_claim = prepare(&engine, old_key, 1, ImmutableStageState::Sealed);
        let old_pos = record(&engine, old_key).pos;
        old_receipt = engine
            .collect_known_stage_after_claim(old_key, &old_claim)
            .unwrap();
        let new_claim = prepare(&engine, new_key, 2, ImmutableStageState::Sealed);
        assert_eq!(
            record(&engine, new_key).pos,
            old_pos,
            "fixture must actually exercise position ABA"
        );
        let size = engine.committed_size(b"ec").unwrap();
        assert_eq!(
            engine
                .collect_known_stage_after_claim(old_key, &old_claim)
                .unwrap(),
            old_receipt
        );
        assert_eq!(engine.committed_size(b"ec").unwrap(), size);
        assert_eq!(
            engine
                .read_sealed_block(new_key, &new_claim.spec.stage_id, 0)
                .unwrap(),
            data()
        );
    }
    config.create = false;
    let engine = open(&config);
    assert_eq!(
        engine.query_known_stage_gc(old_key, &old_claim).unwrap(),
        old_receipt
    );
    assert_eq!(
        engine.read_sealed_block(new_key, &[2; 16], 0).unwrap(),
        data()
    );
    assert_eq!(
        engine.committed_size(b"ec").unwrap(),
        record(&engine, new_key).pos.chunk_size().0
    );
}

#[test]
fn gc_format_and_root_blockers_forbid_both_implicit_directions() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root(true);
    {
        let _engine = open(&config);
    }
    assert!(ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).is_err());
    assert!(Engine::open(&config).is_err());
    assert!(Engine::open_staging(&config).is_err());
    let (_v2dir, v2config) = root(false);
    {
        let engine =
            ImmutableStagingEngine::open(&v2config, ImmutableStageLimits::default()).unwrap();
        let claim = prepare(&engine, b"ec-v2-no-gc", 1, ImmutableStageState::Sealed);
        assert!(matches!(
            engine.collect_known_stage_after_claim(b"ec-v2-no-gc", &claim),
            Err(ImmutableStageError::Invalid(_))
        ));
    }
    assert!(ImmutableStagingEngine::open_gc(&v2config, ImmutableStageLimits::default()).is_err());
    assert!(Engine::open_staging_gc(&v2config).is_err());
}

#[test]
fn gc_startup_rejects_corrupt_ledger_and_orphan_tombstone_pair() {
    let _serial = ENGINE_TEST.lock().unwrap();
    for corrupt_stage in [false, true] {
        let (_dir, mut config) = root(true);
        let key = b"ec-corrupt-ledger";
        {
            let engine = open(&config);
            let claim = prepare(&engine, key, 1, ImmutableStageState::Sealed);
            engine.collect_known_stage_after_claim(key, &claim).unwrap();
            let mut batch = RocksDB::new_write_batch();
            if corrupt_stage {
                batch.delete(stage_key(key));
            } else {
                let mut bytes = engine
                    .0
                    .engine
                    .meta_store
                    .stage_gc_record(key)
                    .unwrap()
                    .unwrap()
                    .encode();
                bytes[30] ^= 1;
                batch.put(stage_gc_key(key), bytes);
            }
            engine.0.engine.meta_store.write(batch, true).unwrap();
        }
        config.create = false;
        assert!(ImmutableStagingEngine::open_gc(&config, ImmutableStageLimits::default()).is_err());
    }
}

#[test]
fn gc_concurrent_same_claim_is_one_transition() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, config) = root(true);
    let engine = open(&config);
    let key = b"ec-concurrent-claim";
    let claim = prepare(&engine, key, 1, ImmutableStageState::Sealed);
    let before = record(&engine, key);
    let start = Arc::new(std::sync::Barrier::new(3));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let engine = engine.clone();
            let claim = claim.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                engine.collect_known_stage_after_claim(key, &claim).unwrap()
            })
        })
        .collect();
    start.wait();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(record(&engine, key).revision, before.revision + 1);
    assert_eq!(engine.committed_size(b"ec").unwrap(), 0);
}

#[test]
fn gc_permanent_ledger_does_not_consume_lifetime_cache_capacity() {
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root(true);
    let limits = ImmutableStageLimits {
        max_cached_records: 2,
        max_active: 1,
        max_concurrent_io: 1,
    };
    let mut claims = Vec::new();
    {
        let engine = ImmutableStagingEngine::open_gc(&config, limits).unwrap();
        for id in 1..=7 {
            let key = format!("ec-gc-cache-{id}");
            let claim = prepare(&engine, key.as_bytes(), id, ImmutableStageState::Sealed);
            engine
                .collect_known_stage_after_claim(key.as_bytes(), &claim)
                .unwrap();
            claims.push((key, claim));
            assert!(engine.0.registry.lock().unwrap().slots.len() <= 2);
        }
    }
    config.create = false;
    let engine = ImmutableStagingEngine::open_gc(&config, limits).unwrap();
    for (key, claim) in claims {
        engine.query_known_stage_gc(key.as_bytes(), &claim).unwrap();
    }
    assert_eq!(engine.committed_size(b"ec").unwrap(), 0);
}

#[test]
fn gc_process_kill_after_atomic_batch_recovers_terminal_ledger() {
    const CHILD: &str = "HF3FS_EXACT_GC_TEST_CHILD";
    const READY: &str = "HF3FS_EXACT_GC_TEST_READY";
    const FILTER: &str = "core::immutable_stage::immutable_gc::tests::gc_process_kill_after_atomic_batch_recovers_terminal_ledger";
    let key = b"ec-gc-kill";
    if let Some(path) = std::env::var_os(CHILD) {
        let config = EngineConfig {
            path: path.into(),
            create: true,
            prefix_len: 2,
        };
        let engine = open(&config);
        let claim = prepare(&engine, key, 1, ImmutableStageState::Sealed);
        inject(&engine, true);
        assert!(engine.collect_known_stage_after_claim(key, &claim).is_err());
        let mut ready = std::fs::File::create(std::env::var_os(READY).unwrap()).unwrap();
        ready
            .write_all(b"GC batch committed; holders retained\n")
            .unwrap();
        ready.sync_all().unwrap();
        loop {
            std::thread::park();
        }
    }
    let _serial = ENGINE_TEST.lock().unwrap();
    let (_dir, mut config) = root(true);
    let control = tempfile::tempdir().unwrap();
    let ready = control.path().join("ready");
    let stderr_path = control.path().join("stderr");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", FILTER, "--nocapture"])
        .env(CHILD, &config.path)
        .env(READY, &ready)
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
                "GC child exited {status}: {}",
                std::fs::read_to_string(&stderr_path).unwrap()
            );
        }
        assert!(
            std::time::Instant::now() < deadline,
            "GC child readiness timeout"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    config.create = false;
    let engine = open(&config);
    let claim = claim(&engine, &spec(&data(), 1), 1);
    let receipt = engine.query_known_stage_gc(key, &claim).unwrap();
    assert_eq!(
        engine.collect_known_stage_after_claim(key, &claim).unwrap(),
        receipt
    );
    assert_eq!(engine.committed_size(b"ec").unwrap(), 0);
    assert_eq!(engine.0.engine.used_size().position_count, 0);
    // Process crash with no destructors; this is not power-failure validation.
}

#[test]
fn gc_joint_provision_reopens_after_both_initialization_boundaries() {
    let _serial = ENGINE_TEST.lock().unwrap();
    for point in [
        StageOpenPoint::AfterEngineOpen,
        StageOpenPoint::AfterJointProvision,
    ] {
        let (_dir, mut config) = root(true);
        let mut expected_identity = None;
        let result = ImmutableStagingEngine::open_format_with_hook(
            &config,
            ImmutableStageLimits::default(),
            EcStagingFormat::ExactGc,
            |at, engine| {
                if at == point {
                    if at == StageOpenPoint::AfterJointProvision {
                        expected_identity =
                            Some(engine.ec_scope_registry().unwrap().engine_identity());
                    }
                    return Err(ImmutableStageError::OutcomeUnknown(
                        "test factory confirmation lost".into(),
                    ));
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        config.create = false;
        let engine = open(&config);
        if let Some(expected) = expected_identity {
            assert_eq!(engine.scopes().engine_identity(), expected);
        }
        assert_eq!(engine.0.format, EcStagingFormat::ExactGc);
        assert!(engine
            .scopes()
            .confirm_staging_identity(config.prefix_len)
            .is_err());
    }
}
