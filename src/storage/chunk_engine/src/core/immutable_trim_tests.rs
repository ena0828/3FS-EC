use super::*;
use std::io::Write;

fn root(format3: bool) -> (tempfile::TempDir, EngineConfig) {
    let dir = tempfile::tempdir().unwrap();
    let markers = if format3 { (IMMUTABLE_GC_ROOT_MARKER, IMMUTABLE_GC_V1_BLOCKER) }
        else { (IMMUTABLE_STAGE_ROOT_MARKER, IMMUTABLE_STAGE_V1_BLOCKER) };
    for (name, bytes) in [("engine", markers.0), ("engine-ec-v1", markers.1)] {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(dir.path().join(name)).unwrap();
        file.write_all(bytes).unwrap(); file.sync_all().unwrap();
    }
    std::fs::File::open(dir.path()).unwrap().sync_all().unwrap();
    let config = EngineConfig { path: dir.path().join(IMMUTABLE_STAGE_ENGINE_DIRECTORY), create: true, prefix_len: 2 };
    (dir, config)
}
fn spec(data: &[u8], id: u8) -> ImmutableStageSpec {
    ImmutableStageSpec { stage_id: [id; 16], length: data.len() as u32, checksum: crc32c::crc32c(data),
        chain_ver: 0, last_request_id: 1, last_client_low: 2, last_client_high: 3, etag: vec![id; 16] }
}
fn limits() -> EmptyGroupTrimLimits {
    EmptyGroupTrimLimits { max_groups: 1, max_bytes: 256u64 << 20, keep_empty_groups: 0 }
}

#[test]
fn stage_trim_gc_unknown_and_retained_reader_hold_extent_until_actual_final_owner_drop() {
    let (_dir, mut config) = root(true);
    let engine = ImmutableStagingEngine::open_gc(&config, ImmutableStageLimits::default()).unwrap();
    let key = b"ec-old"; let bytes = vec![0xA9; 4097]; let old = spec(&bytes, 1);
    engine.begin(key, &old).unwrap(); engine.append(key, &old.stage_id, 0, &bytes).unwrap();
    engine.seal(key, &old.stage_id).unwrap();
    let held = engine.0.engine.get_immutable(key).unwrap().unwrap();
    let old_pos = held.meta().pos;
    let claim = EcStageGcClaim { claim_id: [4; 16], claim_digest: [5; 32], eligibility_digest: [6; 32],
        target: engine.scopes().register_target(1, 2).unwrap(), spec: old.clone() };
    *engine.0.fault.lock().unwrap() = Some(StageFault { point: StageWritePoint::ExactGc, after_commit: true });
    assert!(engine.collect_known_stage_after_claim(key, &claim).is_err());
    let mut unknown = EmptyGroupTrimReport::default();
    engine.trim_empty_groups(limits(), &mut unknown).unwrap(); assert_eq!(unknown.attempted_groups, 0);
    let ledger = engine.collect_known_stage_after_claim(key, &claim).unwrap();
    let mut retained = EmptyGroupTrimReport::default();
    engine.trim_empty_groups(limits(), &mut retained).unwrap(); assert_eq!(retained.attempted_groups, 0);
    let mut got = vec![0; bytes.len()]; held.pread(&mut got, 0).unwrap(); assert_eq!(got, bytes);
    drop(held);
    let mut final_owner = EmptyGroupTrimReport::default();
    engine.trim_empty_groups(limits(), &mut final_owner).unwrap();
    assert_eq!(final_owner.punch_confirmed_groups, 1);
    assert_eq!(final_owner.punch_confirmed_bytes, old_pos.group_id().size().0);
    assert_eq!(engine.query_known_stage_gc(key, &claim).unwrap(), ledger);
    drop(engine);
    config.create = false;
    let engine = ImmutableStagingEngine::open_gc(&config, ImmutableStageLimits::default()).unwrap();
    assert_eq!(engine.query_known_stage_gc(key, &claim).unwrap(), ledger);
    let replacement = vec![0x39; 4097]; let new_spec = spec(&replacement, 9); let new_key = b"ec-new";
    engine.begin(new_key, &new_spec).unwrap();
    engine.append(new_key, &new_spec.stage_id, 0, &replacement).unwrap();
    engine.seal(new_key, &new_spec.stage_id).unwrap();
    assert_eq!(engine.0.engine.meta_store.stage_record(new_key).unwrap().unwrap().pos, old_pos);
    let mut no_old_task = EmptyGroupTrimReport::default();
    engine.trim_empty_groups(limits(), &mut no_old_task).unwrap(); assert_eq!(no_old_task.attempted_groups, 0);
    assert_eq!(engine.read_sealed_block(new_key, &new_spec.stage_id, 0).unwrap(), replacement);
    assert_eq!(engine.query_known_stage_gc(key, &claim).unwrap(), ledger);
}

#[test]
fn stage_trim_rejects_v2_invalid_limits_and_busy_permit_without_touching_allocator() {
    let (_dir, config) = root(false);
    let engine = ImmutableStagingEngine::open(&config, ImmutableStageLimits::default()).unwrap();
    let mut report = EmptyGroupTrimReport::default();
    assert!(matches!(engine.trim_empty_groups(limits(), &mut report), Err(ImmutableStageError::Invalid(_))));
    assert_eq!(report.attempted_groups, 0); drop(engine);
    let (_gc_dir, config) = root(true);
    let engine = ImmutableStagingEngine::open_gc(&config, ImmutableStageLimits { max_concurrent_io: 1,
                ..ImmutableStageLimits::default() }).unwrap();
    for invalid in [EmptyGroupTrimLimits { max_groups: 0, ..limits() },
                    EmptyGroupTrimLimits { max_groups: 65, ..limits() },
                    EmptyGroupTrimLimits { max_bytes: 0, ..limits() },
                    EmptyGroupTrimLimits { max_bytes: (64u64 << 30) + 1, ..limits() },
                    EmptyGroupTrimLimits { keep_empty_groups: 1025, ..limits() }] {
        assert!(matches!(engine.trim_empty_groups(invalid, &mut report), Err(ImmutableStageError::Invalid(_))));
    }
    let permit = engine.permit().unwrap();
    assert_eq!(engine.trim_empty_groups(limits(), &mut report).unwrap_err(), ImmutableStageError::Busy);
    assert_eq!(report.attempted_groups, 0); assert!(report.complete); drop(permit);
    engine.trim_empty_groups(limits(), &mut report).unwrap(); assert_eq!(report.attempted_groups, 0);
    // Unlike a private allocator reservation, actual Begin records its holder
    // before data/directory sync and the first reservation batch. A failed
    // reservation therefore remains occupied even when its bitmap is absent.
    let bytes = vec![0x51; 4097]; let pending = spec(&bytes, 10); let key = b"ec-pending";
    *engine.0.fault.lock().unwrap() = Some(StageFault { point: StageWritePoint::Reservation, after_commit: false });
    assert!(engine.begin(key, &pending).is_err());
    assert!(engine.0.engine.meta_store.stage_record(key).unwrap().is_none());
    let before = engine.physical_used_size(); assert!(before.position_count > 0);
    let mut failed_begin = EmptyGroupTrimReport::default();
    engine.trim_empty_groups(limits(), &mut failed_begin).unwrap();
    assert_eq!(failed_begin.attempted_groups, 0);
    assert_eq!(engine.physical_used_size(), before);
}
