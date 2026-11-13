use super::*;
use crate::{MetaStoreConfig, RocksDBConfig};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

fn open_registry(
    root: &Path,
    create: bool,
    format: EcStagingFormat,
    max_gates: usize,
) -> EcScopeResult<Arc<EcScopeRegistry>> {
    let config = MetaStoreConfig {
        rocksdb: RocksDBConfig {
            path: root.join("meta"),
            create,
            read_only: false,
        },
        prefix_len: 4,
    };
    let (store, provision) = MetaStore::open_with_validation(&config, |raw| {
        preflight_staging_format(raw, 4, format)
            .map_err(|error| Error::MetaError(error.to_string()))
    })?;
    Ok(Arc::new(EcScopeRegistry::from_staging(
        Arc::new(store),
        &provision,
        max_gates,
    )?))
}

fn binding(target: EcTargetIdentity, scope: u8) -> EcScopeBinding {
    EcScopeBinding {
        target,
        object: [3; 16],
        kind: EcScopeKind::ReadPin,
        scope: [scope; 16],
        owner_uid: 1000,
        client_namespace: [5; 16],
    }
}

fn request(target: EcTargetIdentity) -> EcTargetRetirement {
    EcTargetRetirement { target, id: [9; 16] }
}

fn injected() -> EcScopeError {
    EcScopeError::Storage(Error::IoError("injected retirement confirmation failure".into()))
}

#[test]
fn target_retirement_counts_two_scopes_and_preserves_maintenance_and_other_targets() {
    for format in [EcStagingFormat::V2, EcStagingFormat::ExactGc] {
        let dir = tempfile::tempdir().unwrap();
        let registry = open_registry(dir.path(), true, format, 8).unwrap();
        let target = registry.register_target(11, 21).unwrap();
        let other = registry.register_target(12, 22).unwrap();
        let a = binding(target, 1);
        let b = binding(target, 2);
        registry.prepare_scope(a).unwrap();
        registry.prepare_scope(b).unwrap();
        let first = registry.try_admit(a).unwrap();
        let second = registry.try_admit(b).unwrap();
        let retire = request(target);
        assert_eq!(registry.query_target_retirement(retire), Err(EcScopeError::MissingFence));
        assert_eq!(registry.prepare_target_retirement(retire).unwrap(),
                   EcTargetRetirementStatus::Pending { inflight: 2, durable: true });
        assert_eq!(first.check_execution(), Err(EcScopeError::Revoked));
        for scope in [a, b, binding(target, 3)] {
            assert_eq!(registry.prepare_scope(scope), Err(EcScopeError::Revoked));
            assert!(matches!(registry.try_admit(scope), Err(EcScopeError::Revoked)));
        }
        first.complete();
        assert_eq!(registry.query_target_retirement(retire).unwrap(),
                   EcTargetRetirementStatus::Pending { inflight: 1, durable: true });
        second.complete();
        assert_eq!(registry.prepare_target_retirement(retire).unwrap(), EcTargetRetirementStatus::DataDrained);
        assert_eq!(registry.load_target(11, 21).unwrap(), target);
        assert_eq!(registry.register_target(11, 21), Err(EcScopeError::Revoked));
        assert_eq!(registry.prepare_target_retirement(EcTargetRetirement { id: [8; 16], ..retire }),
                   Err(EcScopeError::RevocationMismatch));
        let other_scope = binding(other, 4);
        registry.prepare_scope(other_scope).unwrap();
        registry.try_admit(other_scope).unwrap().complete();
        // Target retirement does not invent a scope revocation. The original
        // maintenance revoke really persists its own unchanged fence first.
        let revoke = EcScopeRevocation { binding: a, id: [6; 16], endpoint_set_digest: [7; 32] };
        assert_eq!(registry.drain_status(revoke), Err(EcScopeError::MissingFence));
        assert_eq!(registry.revoke(revoke).unwrap(), EcDrainStatus::Drained);
    }
}

#[test]
fn target_retirement_wins_stale_cold_load_and_scope_cache_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 1).unwrap();
    let target = registry.register_target(11, 21).unwrap();
    let a = binding(target, 1);
    let (loaded_tx, loaded_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || registry.prepare_with(a, |r, scope| {
            let old = r.load_fence(scope)?;
            loaded_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Ok(old)
        }))
    };
    loaded_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(registry.prepare_target_retirement(request(target)).unwrap(), EcTargetRetirementStatus::DataDrained);
    release_tx.send(()).unwrap();
    assert_eq!(worker.join().unwrap(), Err(EcScopeError::Revoked));
    assert!(matches!(registry.try_admit(a), Err(EcScopeError::Revoked)));
    for id in 2..5 {
        let scope = binding(target, id);
        assert_eq!(registry.prepare_scope(scope), Err(EcScopeError::Revoked));
        assert!(matches!(registry.try_admit(scope), Err(EcScopeError::Revoked)));
    }
    assert_eq!(lock(&registry.targets).unwrap().len(), 1);
    assert_eq!(registry.query_target_retirement(request(target)).unwrap(), EcTargetRetirementStatus::DataDrained);
}

#[test]
fn target_retirement_unknown_write_and_wal_failure_never_reopen_or_ack() {
    for visible in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 8).unwrap();
        let target = registry.register_target(11, 21).unwrap();
        let scope = binding(target, 1);
        registry.prepare_scope(scope).unwrap();
        let retire = request(target);
        assert!(registry.retire_target_with(retire, |r, req| {
            if visible {
                let mut batch = RocksDB::new_write_batch();
                batch.put(target_key(11, 21), encode_retired_target(req));
                r.store.write(batch, false)?;
            }
            Err(injected())
        }).is_err());
        let gate = registry.target_gate(target).unwrap();
        assert_eq!(lock(&gate.state).unwrap().observation(),
                   EcTargetRetirementStatus::Pending { inflight: 0, durable: false });
        assert!(registry.load_target_with(11, 21, |_| Err(injected())).is_err());
        assert_eq!(lock(&gate.state).unwrap().observation(),
                   EcTargetRetirementStatus::Pending { inflight: 0, durable: false });
        assert!(matches!(registry.try_admit(scope), Err(EcScopeError::Revoked)));
        assert_eq!(registry.register_target(11, 21), Err(EcScopeError::Revoked));
        if !visible {
            // Successful old-v1 maintenance read must not clear local Closing.
            assert_eq!(registry.load_target(11, 21).unwrap(), target);
            assert_eq!(registry.query_target_retirement(retire).unwrap(),
                       EcTargetRetirementStatus::Pending { inflight: 0, durable: false });
            assert!(matches!(registry.try_admit(scope), Err(EcScopeError::Revoked)));
        }
        assert_eq!(registry.prepare_target_retirement(retire).unwrap(), EcTargetRetirementStatus::DataDrained);
        assert_eq!(registry.query_target_retirement(retire).unwrap(), EcTargetRetirementStatus::DataDrained);
    }
}

#[test]
fn target_retirement_closes_before_persistence_without_holding_admission_locks() {
    let dir = tempfile::tempdir().unwrap();
    let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 8).unwrap();
    let target = registry.register_target(11, 21).unwrap();
    let scope = binding(target, 1);
    registry.prepare_scope(scope).unwrap();
    let held = registry.try_admit(scope).unwrap();
    let (closed_tx, closed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = {
        let registry = registry.clone();
        std::thread::spawn(move || registry.retire_target_with(request(target), |r, req| {
            closed_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            r.persist_target_retirement(req)
        }))
    };
    closed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(registry.try_admit(scope), Err(EcScopeError::Revoked)));
    assert_eq!(held.check_execution(), Err(EcScopeError::Revoked));
    held.complete(); // Can take both locks while disk persistence is paused.
    release_tx.send(()).unwrap();
    assert_eq!(worker.join().unwrap().unwrap(), EcTargetRetirementStatus::DataDrained);
    // Actual admission/retirement race: the returned ticket stays owned by
    // the join result, so an admitted branch cannot disappear before observe.
    for round in 0..8 {
        let target = registry.register_target(12 + round as u32, 30 + round).unwrap();
        let scope = binding(target, 1);
        registry.prepare_scope(scope).unwrap();
        let start = Arc::new(std::sync::Barrier::new(2));
        let worker = {
            let registry = registry.clone();
            let start = start.clone();
            std::thread::spawn(move || { start.wait(); registry.try_admit(scope) })
        };
        start.wait();
        let observed = registry.prepare_target_retirement(request(target)).unwrap();
        match worker.join().unwrap() {
            Ok(ticket) => {
                assert_eq!(observed, EcTargetRetirementStatus::Pending { inflight: 1, durable: true });
                ticket.complete();
            }
            Err(error) => {
                assert_eq!(error, EcScopeError::Revoked);
                assert_eq!(observed, EcTargetRetirementStatus::DataDrained);
            }
        }
        assert_eq!(registry.query_target_retirement(request(target)).unwrap(), EcTargetRetirementStatus::DataDrained);
    }
}

#[test]
fn target_retirement_reopens_with_same_identity_and_old_reader_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let (target, bytes) = {
        let registry = open_registry(dir.path(), true, EcStagingFormat::ExactGc, 8).unwrap();
        let target = registry.register_target(11, 21).unwrap();
        registry.prepare_target_retirement(request(target)).unwrap();
        (target, exact_get(&registry.store, &target_key(11, 21)).unwrap().unwrap())
    };
    assert_eq!(bytes.len(), RETIRED_TARGET_RECORD_BYTES);
    assert!(decode_target(&bytes).is_err()); // The unchanged actual v1 decoder.
    assert_eq!(decode_target_record(&bytes).unwrap().identity, target);
    for length in 0..bytes.len() {
        assert!(decode_target_record(&bytes[..length]).is_err());
    }
    for offset in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(decode_target_record(&corrupt).is_err());
    }
    let mut extended = bytes;
    extended.push(0);
    assert!(decode_target_record(&extended).is_err());
    let registry = open_registry(dir.path(), false, EcStagingFormat::ExactGc, 8).unwrap();
    assert_eq!(registry.load_target(11, 21).unwrap(), target);
    assert_eq!(registry.query_target_retirement(request(target)).unwrap(), EcTargetRetirementStatus::DataDrained);
    assert_eq!(registry.register_target(11, 21), Err(EcScopeError::Revoked));
    assert_eq!(registry.prepare_scope(binding(target, 1)), Err(EcScopeError::Revoked));
}

#[test]
fn target_retirement_ticket_keeps_original_writer_lease_until_real_drop() {
    let dir = tempfile::tempdir().unwrap();
    let (target, ticket) = {
        let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 8).unwrap();
        let target = registry.register_target(11, 21).unwrap();
        let scope = binding(target, 1);
        registry.prepare_scope(scope).unwrap();
        let ticket = registry.try_admit(scope).unwrap();
        assert_eq!(registry.prepare_target_retirement(request(target)).unwrap(),
                   EcTargetRetirementStatus::Pending { inflight: 1, durable: true });
        (target, ticket)
    };
    assert_eq!(ticket.check_execution(), Err(EcScopeError::Revoked));
    assert!(open_registry(dir.path(), false, EcStagingFormat::V2, 8).is_err());
    ticket.complete();
    let registry = open_registry(dir.path(), false, EcStagingFormat::V2, 8).unwrap();
    assert_eq!(registry.load_target(11, 21).unwrap(), target);
    assert_eq!(registry.query_target_retirement(request(target)).unwrap(), EcTargetRetirementStatus::DataDrained);
}

#[test]
fn target_retirement_rejects_ordinary_unloaded_identity_and_request_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 8).unwrap();
    let target = registry.register_target(11, 21).unwrap();
    let other_registry = EcScopeRegistry::from_identity(registry.store.clone(), registry.identity, 8);
    assert!(matches!(other_registry.prepare_target_retirement(request(target)), Err(EcScopeError::Invalid(_))));
    assert!(matches!(registry.prepare_target_retirement(EcTargetRetirement { id: [0;16], ..request(target) }), Err(EcScopeError::Invalid(_))));
    let mut wrong = request(target);
    wrong.target.incarnation = [88;16];
    assert_eq!(registry.prepare_target_retirement(wrong), Err(EcScopeError::IdentityMismatch));
    wrong.target = EcTargetIdentity { target: 22, ..target };
    assert_eq!(registry.prepare_target_retirement(wrong), Err(EcScopeError::MissingIdentity));
    registry.prepare_target_retirement(request(target)).unwrap();
    assert_eq!(registry.query_target_retirement(EcTargetRetirement { id: [8;16], ..request(target) }), Err(EcScopeError::RevocationMismatch));
    assert_eq!(registry.load_target(11,21).unwrap(), target);
}

#[test]
fn target_retirement_dual_count_overflow_is_atomic_and_poison_never_drains() {
    for scope_overflow in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 8).unwrap();
        let target = registry.register_target(11,21).unwrap();
        let scope = binding(target, 1);
        registry.prepare_scope(scope).unwrap();
        let target_gate = registry.target_gate(target).unwrap();
        let scope_gate = registry.get_gate(scope).unwrap();
        if scope_overflow { lock(&scope_gate.state).unwrap().inflight = u64::MAX; }
        else { lock(&target_gate.state).unwrap().inflight = u64::MAX; }
        assert!(matches!(registry.try_admit(scope), Err(EcScopeError::Busy)));
        assert_eq!(lock(&scope_gate.state).unwrap().inflight, if scope_overflow {u64::MAX} else {0});
        assert_eq!(lock(&target_gate.state).unwrap().inflight, if scope_overflow {0} else {u64::MAX});
    }
    for poison_target in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 8).unwrap();
        let target = registry.register_target(11,21).unwrap();
        let scope = binding(target, 1);
        registry.prepare_scope(scope).unwrap();
        let ticket = registry.try_admit(scope).unwrap();
        registry.prepare_target_retirement(request(target)).unwrap();
        let target_gate = registry.target_gate(target).unwrap();
        let scope_gate = registry.get_gate(scope).unwrap();
        let worker = std::thread::spawn(move || {
            if poison_target { let _guard = target_gate.state.lock().unwrap(); panic!("target poison"); }
            else { let _guard = scope_gate.state.lock().unwrap(); panic!("scope poison"); }
        });
        assert!(worker.join().is_err());
        drop(ticket); // Must not panic or turn a broken counter into DataDrained.
        assert!(registry.query_target_retirement(request(target)).is_err());
    }
}

#[test]
fn target_retirement_scope_underflow_keeps_target_broken_and_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let registry = open_registry(dir.path(), true, EcStagingFormat::V2, 8).unwrap();
    let target = registry.register_target(11,21).unwrap();
    let scope = binding(target, 1);
    registry.prepare_scope(scope).unwrap();
    let ticket = registry.try_admit(scope).unwrap();
    registry.prepare_target_retirement(request(target)).unwrap();
    lock(&registry.get_gate(scope).unwrap().state).unwrap().inflight = 0;
    drop(ticket);
    let gate = registry.target_gate(target).unwrap();
    let state = lock(&gate.state).unwrap();
    assert!(state.broken);
    assert_eq!(state.inflight, 1);
    drop(state);
    assert!(registry.query_target_retirement(request(target)).is_err());
}
