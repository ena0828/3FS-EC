use super::*;
use crate::{EngineConfig, MetaStoreConfig, RocksDBConfig};
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Barrier;
use std::time::{Duration, Instant};

struct Fixture {
    registry: Arc<EcScopeRegistry>,
    binding: EcScopeBinding,
    // Drop the live DB before removing its directory.
    _dir: tempfile::TempDir,
}

fn store(path: &Path, create: bool) -> Arc<MetaStore> {
    Arc::new(
        MetaStore::open(&MetaStoreConfig {
            rocksdb: RocksDBConfig {
                path: path.join("meta"),
                create,
                read_only: false,
            },
            prefix_len: 4,
        })
        .unwrap(),
    )
}

fn binding(target: EcTargetIdentity) -> EcScopeBinding {
    EcScopeBinding {
        target,
        object: [3; 16],
        kind: EcScopeKind::ReadPin,
        scope: [4; 16],
        owner_uid: 1000,
        client_namespace: [5; 16],
    }
}

fn revoke(binding: EcScopeBinding) -> EcScopeRevocation {
    EcScopeRevocation {
        binding,
        id: [6; 16],
        endpoint_set_digest: [7; 32],
    }
}

fn fixture(max_gates: usize) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let registry =
        Arc::new(EcScopeRegistry::open(store(dir.path(), true), true, max_gates).unwrap());
    let target = registry.register_target(11, 21).unwrap();
    Fixture {
        registry,
        binding: binding(target),
        _dir: dir,
    }
}

#[test]
fn engine_and_target_identity_survive_reopen_and_engine_clones_share_gate() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = EngineConfig {
        path: dir.path().into(),
        create: true,
        prefix_len: 4,
    };
    let identity;
    let target;
    {
        let engine = Engine::open(&config).unwrap();
        let registry = engine.ec_scope_registry().unwrap();
        identity = registry.engine_identity();
        target = registry.register_target(11, 21).unwrap();
        assert_eq!(target, registry.register_target(11, 21).unwrap());
        let cloned = engine.clone();
        assert!(Arc::ptr_eq(&registry, &cloned.ec_scope_registry().unwrap()));
        let scope = binding(target);
        registry.prepare_scope(scope).unwrap();
        let ticket = registry.try_admit(scope).unwrap();
        assert_eq!(
            cloned
                .ec_scope_registry()
                .unwrap()
                .revoke(revoke(scope))
                .unwrap(),
            EcDrainStatus::Pending {
                inflight: 1,
                durable: true
            }
        );
        ticket.complete();
    }
    config.create = false;
    let engine = Engine::open(&config).unwrap();
    let registry = engine.ec_scope_registry().unwrap();
    assert_eq!(registry.engine_identity(), identity);
    assert_eq!(registry.load_target(11, 21).unwrap(), target);
    assert_eq!(
        registry.prepare_scope(binding(target)),
        Err(EcScopeError::Revoked)
    );
    assert_eq!(
        registry.drain_status(revoke(binding(target))).unwrap(),
        EcDrainStatus::Drained
    );
}

#[test]
fn missing_or_corrupt_identity_is_not_reinitialized() {
    let dir = tempfile::tempdir().unwrap();
    let meta = store(dir.path(), true);
    assert!(matches!(
        EcScopeRegistry::open(meta.clone(), false, 4),
        Err(EcScopeError::MissingIdentity)
    ));
    let registry = EcScopeRegistry::open(meta.clone(), true, 4).unwrap();
    let identity = registry.engine_identity();
    assert_ne!(identity, [0; 16]);
    let mut bytes = encode_engine(identity);
    bytes[6] ^= 1;
    put_sync(&meta, &[ENGINE_PREFIX], &bytes).unwrap();
    assert!(matches!(
        EcScopeRegistry::open(meta, true, 4),
        Err(EcScopeError::Corrupt(_))
    ));
}

#[test]
fn existing_engine_without_scope_schema_fails_closed_even_when_create_was_requested() {
    let dir = tempfile::tempdir().unwrap();
    let config = EngineConfig {
        path: dir.path().into(),
        create: true,
        prefix_len: 4,
    };
    drop(Engine::open(&config).unwrap());
    // Existing metadata must not be treated as new just because a caller uses
    // create=true. No identity was initialized before the first process ended.
    let engine = Engine::open(&config).unwrap();
    assert!(matches!(
        engine.ec_scope_registry(),
        Err(EcScopeError::MissingIdentity)
    ));
}

#[test]
fn namespace_sync_failure_does_not_publish_a_registry_or_change_identity_on_retry() {
    let dir = tempfile::tempdir().unwrap();
    let config = EngineConfig {
        path: dir.path().into(),
        create: true,
        prefix_len: 4,
    };
    let engine = Engine::open(&config).unwrap();
    let result = engine.ec_scope_registry_with(|| {
        Err(EcScopeError::Storage(Error::IoError(
            "injected namespace sync failure".into(),
        )))
    });
    assert!(result.is_err());
    assert!(engine.ec_scope_bootstrap.registry.lock().unwrap().is_none());
    let bytes = exact_get(&engine.meta_store, &[ENGINE_PREFIX])
        .unwrap()
        .unwrap();
    let persisted = decode_engine(&bytes).unwrap();
    assert_eq!(
        engine.ec_scope_registry().unwrap().engine_identity(),
        persisted
    );
}

#[test]
fn record_extents_versions_crc_and_target_incarnation_are_checked() {
    let fixture = fixture(8);
    let request = revoke(fixture.binding);
    let bytes = encode_fence(request);
    assert_eq!(bytes.len(), FENCE_RECORD_BYTES);
    assert_eq!(
        encode_target(fixture.binding.target).len(),
        TARGET_RECORD_BYTES
    );
    assert_eq!(
        encode_engine(fixture.binding.target.engine).len(),
        ENGINE_RECORD_BYTES
    );
    assert_eq!(decode_fence(&bytes).unwrap(), request);
    for length in 0..bytes.len() {
        assert!(decode_fence(&bytes[..length]).is_err());
    }
    for offset in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(decode_fence(&corrupt).is_err());
    }
    let mut oversized = bytes;
    oversized.push(0);
    assert!(decode_fence(&oversized).is_err());
    let mut wrong = fixture.binding;
    wrong.target.incarnation[0] ^= 1;
    assert_eq!(
        fixture.registry.prepare_scope(wrong),
        Err(EcScopeError::IdentityMismatch)
    );
    let another = self::fixture(8);
    assert_ne!(
        another.registry.engine_identity(),
        fixture.registry.engine_identity()
    );
    assert_eq!(
        another.registry.prepare_scope(fixture.binding),
        Err(EcScopeError::IdentityMismatch)
    );
}

#[test]
fn target_identity_read_requires_successful_wal_confirmation() {
    let fixture = fixture(8);
    let registry = &fixture.registry;
    let target = EcTargetIdentity {
        engine: registry.engine_identity(),
        incarnation: [9; 16],
        chain: 11,
        target: 22,
    };
    // A genuinely visible asynchronous record has not yielded a synchronous
    // registration acknowledgment. Fail its read-side confirmation explicitly.
    let mut batch = RocksDB::new_write_batch();
    batch.put(
        target_key(target.chain, target.target),
        encode_target(target),
    );
    registry.store.write(batch, false).unwrap();
    assert!(registry
        .load_target_with(target.chain, target.target, |_| {
            Err(EcScopeError::Storage(Error::IoError(
                "injected target WAL confirmation failure".into(),
            )))
        })
        .is_err());
    assert_eq!(
        registry.load_target(target.chain, target.target).unwrap(),
        target
    );
    let scope = binding(target);
    registry.prepare_scope(scope).unwrap();
    registry.try_admit(scope).unwrap().complete();
}

#[test]
fn queued_and_executing_jobs_hold_drain_until_both_complete() {
    let fixture = fixture(8);
    let registry = &fixture.registry;
    let scope = fixture.binding;
    assert!(matches!(registry.try_admit(scope), Err(EcScopeError::Busy)));
    registry.prepare_scope(scope).unwrap();
    let executing = registry.try_admit(scope).unwrap();
    executing.check_execution().unwrap();
    let queued = registry.try_admit(scope).unwrap();
    let request = revoke(scope);
    // Called on the same thread while both tickets are held: this must return,
    // rather than wait for jobs that may be behind it on a single worker.
    assert_eq!(
        registry.revoke(request).unwrap(),
        EcDrainStatus::Pending {
            inflight: 2,
            durable: true
        }
    );
    assert!(matches!(
        registry.try_admit(scope),
        Err(EcScopeError::Revoked)
    ));
    assert_eq!(queued.check_execution(), Err(EcScopeError::Revoked));
    queued.complete();
    assert_eq!(
        registry.drain_status(request).unwrap(),
        EcDrainStatus::Pending {
            inflight: 1,
            durable: true
        }
    );
    executing.complete();
    assert_eq!(
        registry.drain_status(request).unwrap(),
        EcDrainStatus::Drained
    );
    assert_eq!(registry.revoke(request).unwrap(), EcDrainStatus::Drained);
}

#[test]
fn admission_and_closing_race_accounts_for_every_success_once() {
    let fixture = fixture(8);
    let registry = fixture.registry.clone();
    let scope = fixture.binding;
    registry.prepare_scope(scope).unwrap();
    let barrier = Arc::new(Barrier::new(17));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let registry = registry.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            registry.try_admit(scope)
        }));
    }
    barrier.wait();
    let request = revoke(scope);
    registry.revoke(request).unwrap();
    let mut admitted = Vec::new();
    for worker in workers {
        match worker.join().unwrap() {
            Ok(ticket) => admitted.push(ticket),
            Err(EcScopeError::Revoked) => {}
            other => panic!("unexpected admission: {other:?}"),
        }
    }
    let expected = if admitted.is_empty() {
        EcDrainStatus::Drained
    } else {
        EcDrainStatus::Pending {
            inflight: admitted.len() as u64,
            durable: true,
        }
    };
    assert_eq!(registry.drain_status(request).unwrap(), expected);
    drop(admitted);
    assert_eq!(
        registry.drain_status(request).unwrap(),
        EcDrainStatus::Drained
    );
}

#[test]
fn closing_blocks_new_admission_before_the_durable_write() {
    let fixture = fixture(8);
    let registry = fixture.registry.clone();
    let scope = fixture.binding;
    registry.prepare_scope(scope).unwrap();
    let ticket = registry.try_admit(scope).unwrap();
    let entered = Arc::new(Barrier::new(2));
    let proceed = Arc::new(Barrier::new(2));
    let request = revoke(scope);
    let worker = {
        let registry = registry.clone();
        let entered = entered.clone();
        let proceed = proceed.clone();
        std::thread::spawn(move || {
            registry.revoke_with(request, |registry, request| {
                entered.wait();
                proceed.wait();
                registry.persist_fence(request)
            })
        })
    };
    entered.wait();
    assert!(matches!(
        registry.try_admit(scope),
        Err(EcScopeError::Revoked)
    ));
    assert_eq!(
        registry.drain_status(request).unwrap(),
        EcDrainStatus::Pending {
            inflight: 1,
            durable: false
        }
    );
    ticket.complete();
    assert_eq!(
        registry.drain_status(request).unwrap(),
        EcDrainStatus::Pending {
            inflight: 0,
            durable: false
        }
    );
    proceed.wait();
    assert_eq!(worker.join().unwrap().unwrap(), EcDrainStatus::Drained);
}

#[test]
fn stale_negative_lookup_cannot_reopen_a_revoked_scope() {
    let fixture = fixture(8);
    let registry = fixture.registry.clone();
    let scope = fixture.binding;
    let loaded = Arc::new(Barrier::new(2));
    let proceed = Arc::new(Barrier::new(2));
    let worker = {
        let registry = registry.clone();
        let loaded = loaded.clone();
        let proceed = proceed.clone();
        std::thread::spawn(move || {
            registry.prepare_with(scope, |registry, binding| {
                let result = registry.load_fence(binding)?;
                assert!(result.is_none());
                loaded.wait();
                proceed.wait();
                Ok(result)
            })
        })
    };
    loaded.wait();
    assert_eq!(
        registry.revoke(revoke(scope)).unwrap(),
        EcDrainStatus::Drained
    );
    proceed.wait();
    assert_eq!(worker.join().unwrap(), Err(EcScopeError::Revoked));
    assert!(matches!(
        registry.try_admit(scope),
        Err(EcScopeError::Revoked)
    ));
}

#[test]
fn failure_before_or_after_persist_never_manufactures_a_durable_ack() {
    for persist_first in [false, true] {
        let fixture = fixture(8);
        let registry = &fixture.registry;
        registry.prepare_scope(fixture.binding).unwrap();
        let request = revoke(fixture.binding);
        let result = registry.revoke_with(request, |registry, request| {
            if persist_first {
                registry.persist_fence(request)?;
            }
            Err(EcScopeError::Storage(Error::IoError(
                "injected completion failure".into(),
            )))
        });
        assert!(result.is_err());
        assert_eq!(
            registry.drain_status(request).unwrap(),
            EcDrainStatus::Pending {
                inflight: 0,
                durable: false
            }
        );
        assert!(matches!(
            registry.try_admit(fixture.binding),
            Err(EcScopeError::Revoked)
        ));
        assert_eq!(registry.revoke(request).unwrap(), EcDrainStatus::Drained);
    }
}

#[test]
fn changed_owner_or_revocation_never_bypasses_the_original_scope() {
    let fixture = fixture(8);
    let registry = &fixture.registry;
    let request = revoke(fixture.binding);
    assert_eq!(registry.revoke(request).unwrap(), EcDrainStatus::Drained);
    let mut wrong = request;
    wrong.id[0] ^= 1;
    assert_eq!(
        registry.revoke(wrong),
        Err(EcScopeError::RevocationMismatch)
    );
    assert_eq!(
        registry.drain_status(wrong),
        Err(EcScopeError::RevocationMismatch)
    );
    wrong = request;
    wrong.binding.owner_uid += 1;
    assert_eq!(
        registry.prepare_scope(wrong.binding),
        Err(EcScopeError::IdentityMismatch)
    );
    wrong = request;
    wrong.endpoint_set_digest[0] ^= 1;
    assert_eq!(
        registry.revoke(wrong),
        Err(EcScopeError::RevocationMismatch)
    );
}

#[test]
fn cold_cache_preserves_original_revoke_and_corrupt_records_never_open() {
    let dir = tempfile::tempdir().unwrap();
    let request;
    {
        let registry = EcScopeRegistry::open(store(dir.path(), true), true, 8).unwrap();
        request = revoke(binding(registry.register_target(11, 21).unwrap()));
        assert_eq!(registry.revoke(request).unwrap(), EcDrainStatus::Drained);
    }
    let registry = EcScopeRegistry::open(store(dir.path(), false), false, 8).unwrap();
    let mut wrong = request;
    wrong.id[0] ^= 1;
    assert_eq!(
        registry.revoke(wrong),
        Err(EcScopeError::RevocationMismatch)
    );
    assert_eq!(
        registry.drain_status(request).unwrap(),
        EcDrainStatus::Drained
    );
    let mut corrupt_scope = request.binding;
    corrupt_scope.scope = [9; 16];
    put_sync(&registry.store, &corrupt_scope.key(), b"bad fence record").unwrap();
    assert!(matches!(
        registry.prepare_scope(corrupt_scope),
        Err(EcScopeError::Corrupt(_))
    ));
    assert!(matches!(
        registry.try_admit(corrupt_scope),
        Err(EcScopeError::Busy)
    ));
    let corrupt_revoke = revoke(corrupt_scope);
    assert!(registry.revoke(corrupt_revoke).is_err());
    assert_eq!(
        registry.drain_status(corrupt_revoke).unwrap(),
        EcDrainStatus::Pending {
            inflight: 0,
            durable: false
        }
    );
}

#[test]
fn bounded_cache_never_evicts_tickets_and_reloads_persistent_denial() {
    let fixture = fixture(1);
    let registry = &fixture.registry;
    let scope = fixture.binding;
    registry.prepare_scope(scope).unwrap();
    let old_gate = registry.get_gate(scope).unwrap();
    let ticket = registry.try_admit(scope).unwrap();
    let mut second = scope;
    second.scope = [8; 16];
    assert_eq!(registry.prepare_scope(second), Err(EcScopeError::Busy));
    ticket.complete();
    registry.prepare_scope(second).unwrap();
    assert_eq!(
        lock(&old_gate.state).unwrap().ensure_live(),
        Err(EcScopeError::Busy)
    );
    assert_eq!(
        registry.revoke(revoke(scope)).unwrap(),
        EcDrainStatus::Drained
    );
    registry.prepare_scope(second).unwrap();
    assert_eq!(registry.prepare_scope(scope), Err(EcScopeError::Revoked));
    assert_eq!(
        registry.drain_status(revoke(scope)).unwrap(),
        EcDrainStatus::Drained
    );
}

#[test]
fn ticket_unwind_completes_but_poisoned_gate_never_acks() {
    let fixture = fixture(8);
    let registry = &fixture.registry;
    registry.prepare_scope(fixture.binding).unwrap();
    let ticket = registry.try_admit(fixture.binding).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ticket = ticket;
            panic!("injected worker exception before returning owned bytes");
        }))
        .is_err()
    );
    assert_eq!(
        registry.revoke(revoke(fixture.binding)).unwrap(),
        EcDrainStatus::Drained
    );
    let gate = registry.get_gate(fixture.binding).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _state = gate.state.lock().unwrap();
            panic!("injected invariant panic under gate mutex");
        }))
        .is_err()
    );
    assert_eq!(
        registry.drain_status(revoke(fixture.binding)),
        Err(EcScopeError::Poisoned)
    );
}

const CHILD_ROOT: &str = "HF3FS_EC_SCOPE_TEST_CHILD_ROOT";

// Invoked only by the parent test below. An ordinary test run does no work.
#[test]
fn scope_crash_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = Path::new(&root);
    let registry = EcScopeRegistry::open(store(root, false), false, 8).unwrap();
    let scope = binding(registry.load_target(11, 21).unwrap());
    registry.prepare_scope(scope).unwrap();
    let _ticket = registry.try_admit(scope).unwrap();
    assert_eq!(
        registry.revoke(revoke(scope)).unwrap(),
        EcDrainStatus::Pending {
            inflight: 1,
            durable: true
        }
    );
    let ready = std::fs::File::create(root.join("ready")).unwrap();
    ready.sync_all().unwrap();
    loop {
        std::thread::park();
    }
}

struct KillChild(Child);

impl Drop for KillChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn durable_denial_survives_killed_process_with_an_outstanding_ticket() {
    let dir = tempfile::tempdir().unwrap();
    let target;
    {
        let registry = EcScopeRegistry::open(store(dir.path(), true), true, 8).unwrap();
        target = registry.register_target(11, 21).unwrap();
    }
    let mut child = KillChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ec_scope::tests::scope_crash_child",
                "--nocapture",
            ])
            .env(CHILD_ROOT, dir.path())
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !dir.path().join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "scope child exited before durable fence"
        );
        assert!(
            Instant::now() < deadline,
            "scope child did not reach durable fence"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    let registry = EcScopeRegistry::open(store(dir.path(), false), false, 8).unwrap();
    let scope = binding(target);
    assert_eq!(registry.load_target(11, 21).unwrap(), target);
    assert_eq!(registry.prepare_scope(scope), Err(EcScopeError::Revoked));
    assert!(matches!(
        registry.try_admit(scope),
        Err(EcScopeError::Revoked)
    ));
    assert_eq!(
        registry.drain_status(revoke(scope)).unwrap(),
        EcDrainStatus::Drained
    );
}

fn raw_store(path: &Path, create: bool) -> RocksDB {
    RocksDB::open::<crate::MetaMergeOp>(&RocksDBConfig {
        path: path.join("meta"),
        create,
        read_only: false,
    })
    .unwrap()
}

fn staging_store(
    path: &Path,
    create: bool,
    prefix_len: usize,
) -> EcScopeResult<(Arc<MetaStore>, EcStagingProvision)> {
    let config = MetaStoreConfig {
        rocksdb: RocksDBConfig {
            path: path.join("meta"),
            create,
            read_only: false,
        },
        prefix_len,
    };
    // The hook retains one writable RocksDB handle/lock across validation and
    // all normal MetaStore initialization. No read-only close/reopen shortcut.
    let (meta, provision) = MetaStore::open_with_validation(&config, |raw| {
        preflight_staging(raw, prefix_len).map_err(|error| Error::MetaError(error.to_string()))
    })?;
    Ok((Arc::new(meta), provision))
}

#[test]
fn staging_empty_preflight_accepts_only_exact_startup_baselines() {
    for prefix_len in [0usize, 4] {
        for mask in 0..8 {
            let dir = tempfile::tempdir().unwrap();
            let raw = raw_store(dir.path(), true);
            if mask & 1 != 0 {
                raw.put(
                    [MetaKey::USED_SIZE_PREFIX_LEN_KEY],
                    (prefix_len as u32).to_le_bytes(),
                    true,
                )
                .unwrap();
            }
            if mask & 2 != 0 {
                raw.put([MetaKey::VERSION_KEY], [MetaStore::LATEST_VERSION], true)
                    .unwrap();
            }
            if mask & 4 != 0 {
                raw.put([MetaKey::USED_SIZE_KEY_PREFIX], 0u64.to_le_bytes(), true)
                    .unwrap();
            }
            let result = preflight_staging(&raw, prefix_len);
            if prefix_len != 0 && mask & 4 != 0 {
                assert!(result.is_err());
            } else {
                let provision = result.unwrap();
                assert!(provision.is_empty());
                assert_ne!(provision.identity, [0; 16]);
            }
        }
    }
}

#[test]
fn staging_empty_preflight_rejects_live_or_noncanonical_keys_without_cleanup() {
    let cases = vec![
        (vec![MetaKey::CHUNK_META_KEY_PREFIX, 1], vec![0]),
        (vec![MetaKey::GROUP_BITS_KEY_PREFIX], vec![0]),
        (vec![MetaKey::POS_TO_CHUNK_KEY_PREFIX, 0], vec![0]),
        (
            vec![MetaKey::USED_SIZE_KEY_PREFIX],
            1u64.to_le_bytes().to_vec(),
        ),
        (
            vec![MetaKey::USED_SIZE_KEY_PREFIX, 0],
            0u64.to_le_bytes().to_vec(),
        ),
        (
            vec![MetaKey::USED_SIZE_PREFIX_LEN_KEY],
            7u32.to_le_bytes().to_vec(),
        ),
        (
            vec![MetaKey::USED_SIZE_PREFIX_LEN_KEY, 0],
            0u32.to_le_bytes().to_vec(),
        ),
        (vec![MetaKey::TIMESTAMP_KEY_PREFIX, 0], vec![0]),
        (vec![7], vec![]),
        (vec![MetaKey::VERSION_KEY], vec![0]),
        (
            vec![MetaKey::VERSION_KEY],
            vec![MetaStore::LATEST_VERSION, 0],
        ),
        (vec![MetaKey::WRITING_CHUNK_KEY_PREFIX, 0], vec![0]),
        (vec![DENY_PREFIX, 0], vec![0]),
        (vec![TARGET_PREFIX, 0], vec![0]),
        (vec![13, 0], vec![0]),
        (vec![14, 0], vec![0]),
        (vec![], vec![]),
    ];
    for (key, value) in cases {
        let dir = tempfile::tempdir().unwrap();
        {
            let raw = raw_store(dir.path(), true);
            raw.put(&key, &value, true).unwrap();
        }
        // Failure occurs before MetaStore can rewrite key 5 or Engine can
        // remove legacy timestamp keys as part of version normalization.
        assert!(staging_store(dir.path(), false, 0).is_err());
        let raw = raw_store(dir.path(), false);
        assert_eq!(raw.get(&key).unwrap().as_deref(), Some(value.as_slice()));
        assert!(raw.get([ENGINE_PREFIX]).unwrap().is_none());
        assert!(raw.get([STAGING_FORMAT_PREFIX]).unwrap().is_none());
    }
}

#[test]
fn staging_joint_commit_retries_keep_candidate_before_and_after_unknown_outcome() {
    for after_commit in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (meta, provision) = staging_store(dir.path(), true, 4).unwrap();
        assert!(provision.is_empty());
        let candidate = provision.identity;
        let result = joint_provision_staging_with(&meta, &provision, |store, batch| {
            if after_commit {
                store.write(batch, true)?;
            }
            Err(EcScopeError::Storage(Error::IoError(
                "injected joint initialization confirmation failure".into(),
            )))
        });
        assert!(result.is_err());
        let identity = exact_get(&meta, &[ENGINE_PREFIX]).unwrap();
        let format = exact_get(&meta, &[STAGING_FORMAT_PREFIX]).unwrap();
        assert_eq!(identity.is_some(), after_commit);
        assert_eq!(format.is_some(), after_commit);
        if after_commit {
            assert_eq!(
                decode_engine(identity.as_ref().unwrap()).unwrap(),
                candidate
            );
            decode_staging_format(format.as_ref().unwrap(), candidate, 4).unwrap();
        }
        assert_eq!(
            joint_provision_staging(&meta, &provision).unwrap(),
            candidate
        );
        assert_eq!(
            joint_provision_staging(&meta, &provision).unwrap(),
            candidate
        );
        drop(meta);
        let (meta, reopened) = staging_store(dir.path(), false, 4).unwrap();
        assert!(!reopened.is_empty());
        assert_eq!(
            joint_provision_staging(&meta, &reopened).unwrap(),
            candidate
        );
        let registry = EcScopeRegistry::from_identity(meta, candidate, 8);
        registry.confirm_staging_identity(4).unwrap();
        assert!(registry.confirm_staging_identity(0).is_err());
    }
}

#[test]
fn staging_pair_missing_side_wrong_identity_or_bad_baseline_is_never_repaired() {
    for case in 0..9 {
        let dir = tempfile::tempdir().unwrap();
        let identity = [41; 16];
        let mut expected_identity = Some(encode_engine(identity));
        let mut expected_format = Some(encode_staging_format(identity, 4));
        {
            let raw = raw_store(dir.path(), true);
            raw.put(
                [MetaKey::USED_SIZE_PREFIX_LEN_KEY],
                4u32.to_le_bytes(),
                true,
            )
            .unwrap();
            raw.put([MetaKey::VERSION_KEY], [MetaStore::LATEST_VERSION], true)
                .unwrap();
            match case {
                0 => expected_identity = None,
                1 => expected_format = None,
                2 => expected_format = Some(encode_staging_format([42; 16], 4)),
                3 => expected_format = Some(encode_staging_format(identity, 0)),
                4 => expected_format.as_mut().unwrap()[28] ^= 1,
                5 => raw
                    .delete([MetaKey::USED_SIZE_PREFIX_LEN_KEY], true)
                    .unwrap(),
                6 => raw.put([MetaKey::VERSION_KEY], [0], true).unwrap(),
                7 => raw.put([ENGINE_PREFIX, 0], b"alias", true).unwrap(),
                8 => raw
                    .put([MetaKey::WRITING_CHUNK_KEY_PREFIX, 0], b"legacy", true)
                    .unwrap(),
                _ => unreachable!(),
            }
            if let Some(bytes) = &expected_identity {
                raw.put([ENGINE_PREFIX], bytes, true).unwrap();
            }
            if let Some(bytes) = &expected_format {
                raw.put([STAGING_FORMAT_PREFIX], bytes, true).unwrap();
            }
        }
        assert!(staging_store(dir.path(), false, 4).is_err());
        let raw = raw_store(dir.path(), false);
        assert_eq!(
            exact_raw_get(&raw, &[ENGINE_PREFIX]).unwrap(),
            expected_identity
        );
        assert_eq!(
            exact_raw_get(&raw, &[STAGING_FORMAT_PREFIX]).unwrap(),
            expected_format
        );
    }
}

#[test]
fn staging_existing_prefix_zero_can_omit_prefix_key_but_not_version() {
    let dir = tempfile::tempdir().unwrap();
    let identity = [51; 16];
    {
        let raw = raw_store(dir.path(), true);
        raw.put([ENGINE_PREFIX], encode_engine(identity), true)
            .unwrap();
        raw.put(
            [STAGING_FORMAT_PREFIX],
            encode_staging_format(identity, 0),
            true,
        )
        .unwrap();
        raw.put([MetaKey::VERSION_KEY], [MetaStore::LATEST_VERSION], true)
            .unwrap();
    }
    let (meta, provision) = staging_store(dir.path(), false, 0).unwrap();
    assert!(!provision.is_empty());
    assert_eq!(
        joint_provision_staging(&meta, &provision).unwrap(),
        identity
    );
    assert!(exact_get(&meta, &[MetaKey::USED_SIZE_PREFIX_LEN_KEY])
        .unwrap()
        .is_none());
    drop(meta);
    {
        let raw = raw_store(dir.path(), false);
        raw.delete([MetaKey::VERSION_KEY], true).unwrap();
    }
    assert!(staging_store(dir.path(), false, 0).is_err());
}

#[test]
fn staging_joint_commit_rechecks_empty_state_and_never_overwrites_another_pair() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, provision) = staging_store(dir.path(), true, 4).unwrap();
    let mut live = RocksDB::new_write_batch();
    live.put(
        [MetaKey::GROUP_BITS_KEY_PREFIX, 0],
        b"even an empty allocation group is forbidden",
    );
    meta.write(live, true).unwrap();
    assert!(joint_provision_staging_with(&meta, &provision, |_, _| {
        panic!("a nonempty pre-initialization store must never reach commit")
    })
    .is_err());
    assert!(exact_get(&meta, &[ENGINE_PREFIX]).unwrap().is_none());
    let other = [61; 16];
    let mut changed = RocksDB::new_write_batch();
    changed.put([ENGINE_PREFIX], encode_engine(other));
    changed.put([STAGING_FORMAT_PREFIX], encode_staging_format(other, 4));
    changed.put([MetaKey::VERSION_KEY], [MetaStore::LATEST_VERSION]);
    meta.write(changed, true).unwrap();
    assert_eq!(
        joint_provision_staging(&meta, &provision),
        Err(EcScopeError::IdentityMismatch)
    );
    assert_eq!(
        decode_engine(&exact_get(&meta, &[ENGINE_PREFIX]).unwrap().unwrap()).unwrap(),
        other
    );
}

const PROVISION_CHILD_ROOT: &str = "HF3FS_EC_SCOPE_PROVISION_CHILD_ROOT";
const PROVISION_CHILD_PHASE: &str = "HF3FS_EC_SCOPE_PROVISION_CHILD_PHASE";

fn provision_child_ready(root: &Path, identity: EcIdentity) {
    let temporary = root.join("provision-ready.tmp");
    let mut ready = std::fs::File::create(&temporary).unwrap();
    ready.write_all(&identity).unwrap();
    ready.sync_all().unwrap();
    std::fs::rename(temporary, root.join("provision-ready")).unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn staging_provision_crash_child() {
    let Some(root) = std::env::var_os(PROVISION_CHILD_ROOT) else {
        return;
    };
    let root = Path::new(&root);
    let phase = std::env::var(PROVISION_CHILD_PHASE).unwrap();
    if phase == "raw-open" {
        let _raw = raw_store(root, true);
        provision_child_ready(root, [0; 16]);
    }
    let (meta, provision) = staging_store(root, true, 4).unwrap();
    assert!(provision.is_empty());
    if phase == "after-joint" {
        assert_eq!(
            joint_provision_staging(&meta, &provision).unwrap(),
            provision.identity
        );
    } else {
        assert_eq!(phase, "before-joint");
    }
    provision_child_ready(root, provision.identity);
}

#[test]
fn staging_initialization_recovers_after_killed_process_at_each_transaction_boundary() {
    for phase in ["raw-open", "before-joint", "after-joint"] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = KillChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ec_scope::tests::staging_provision_crash_child",
                    "--nocapture",
                ])
                .env(PROVISION_CHILD_ROOT, dir.path())
                .env(PROVISION_CHILD_PHASE, phase)
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let ready = dir.path().join("provision-ready");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "provision child exited before boundary"
            );
            assert!(
                Instant::now() < deadline,
                "provision child did not reach boundary"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let prior: EcIdentity = std::fs::read(ready).unwrap().try_into().unwrap();
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        let (meta, provision) = staging_store(dir.path(), false, 4).unwrap();
        assert_eq!(provision.is_empty(), phase != "after-joint");
        let identity = joint_provision_staging(&meta, &provision).unwrap();
        if phase == "after-joint" {
            assert_eq!(identity, prior);
        }
        assert_ne!(identity, [0; 16]);
        assert_eq!(
            decode_engine(&exact_get(&meta, &[ENGINE_PREFIX]).unwrap().unwrap()).unwrap(),
            identity
        );
        let format = exact_get(&meta, &[STAGING_FORMAT_PREFIX]).unwrap().unwrap();
        assert_eq!(format.len(), STAGING_FORMAT_RECORD_BYTES);
        decode_staging_format(&format, identity, 4).unwrap();
    }
}

#[test]
fn ticket_retains_exclusive_store_instance_until_completion() {
    let dir = tempfile::tempdir().unwrap();
    let config = EngineConfig {
        path: dir.path().into(),
        create: true,
        prefix_len: 4,
    };
    let (ticket, scope, identity) = {
        let engine = Engine::open(&config).unwrap();
        let registry = engine.ec_scope_registry().unwrap();
        let target = registry.register_target(11, 21).unwrap();
        let scope = binding(target);
        registry.prepare_scope(scope).unwrap();
        (
            registry.try_admit(scope).unwrap(),
            scope,
            registry.engine_identity(),
        )
    };
    // Both Engine and registry are gone, but admitted work may still hold the
    // ticket. A new instance must not open and report a fresh zero counter.
    assert!(ticket.check_execution().is_ok());
    let reopen = EngineConfig {
        create: false,
        ..config
    };
    assert!(Engine::open(&reopen).is_err());
    assert!(ticket.check_execution().is_ok());
    ticket.complete();
    let engine = Engine::open(&reopen).unwrap();
    let registry = engine.ec_scope_registry().unwrap();
    assert_eq!(registry.engine_identity(), identity);
    assert_eq!(registry.load_target(11, 21).unwrap(), scope.target);
    assert_eq!(
        registry.revoke(revoke(scope)).unwrap(),
        EcDrainStatus::Drained
    );
    assert_eq!(registry.prepare_scope(scope), Err(EcScopeError::Revoked));
}

#[test]
fn concurrent_cold_scope_singleflight_reuses_one_real_load() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let f = fixture(8);
    let registry = f.registry.clone();
    let binding = f.binding;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let loads = Arc::new(AtomicUsize::new(0));
    let leader = {
        let registry = registry.clone();
        let entered = entered.clone();
        let release = release.clone();
        let loads = loads.clone();
        std::thread::spawn(move || {
            registry.prepare_with(binding, |registry, binding| {
                loads.fetch_add(1, Ordering::SeqCst);
                let actual = registry.load_fence(binding)?;
                entered.wait();
                release.wait();
                Ok(actual)
            })
        })
    };
    entered.wait();
    // Deterministic reproduction of the old data admission path. It is still
    // deliberately the behavior of nonwaiting control prepare and wait=0.
    assert_eq!(registry.prepare_scope(binding), Err(EcScopeError::Busy));
    assert_eq!(
        registry.prepare_scope_wait(binding, 0),
        Err(EcScopeError::Busy)
    );
    let (waiting, observed) = std::sync::mpsc::channel();
    let follower = {
        let registry = registry.clone();
        std::thread::spawn(move || {
            registry.prepare_with_wait(
                binding,
                Duration::from_secs(1),
                |_, _| panic!("follower must not issue a second disk lookup"),
                || waiting.send(()).unwrap(),
            )
        })
    };
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    release.wait();
    assert_eq!(leader.join().unwrap(), Ok(()));
    assert_eq!(follower.join().unwrap(), Ok(()));
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    let first = registry.try_admit(binding).unwrap();
    let second = registry.try_admit(binding).unwrap();
    assert_eq!(
        registry.revoke(revoke(binding)).unwrap(),
        EcDrainStatus::Pending {
            inflight: 2,
            durable: true
        }
    );
    first.complete();
    second.complete();
    assert_eq!(
        registry.drain_status(revoke(binding)).unwrap(),
        EcDrainStatus::Drained
    );
}

#[test]
fn cold_scope_loader_failure_never_promotes_waiting_follower() {
    let f = fixture(8);
    let registry = f.registry.clone();
    let binding = f.binding;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let leader = {
        let registry = registry.clone();
        let entered = entered.clone();
        let release = release.clone();
        std::thread::spawn(move || {
            registry.prepare_with(binding, |_, _| {
                entered.wait();
                release.wait();
                Err(EcScopeError::Storage(Error::IoError(
                    "test load failure".into(),
                )))
            })
        })
    };
    entered.wait();
    let (waiting, observed) = std::sync::mpsc::channel();
    let follower = {
        let registry = registry.clone();
        std::thread::spawn(move || {
            registry.prepare_with_wait(
                binding,
                Duration::from_secs(1),
                |_, _| panic!("follower cannot replace an unconfirmed loader"),
                || waiting.send(()).unwrap(),
            )
        })
    };
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    release.wait();
    assert!(leader.join().unwrap().is_err());
    assert_eq!(follower.join().unwrap(), Err(EcScopeError::Busy));
    assert!(matches!(
        registry.try_admit(binding),
        Err(EcScopeError::Busy)
    ));
    registry.prepare_scope_wait(binding, 10).unwrap();
    registry.try_admit(binding).unwrap().complete();
}

#[test]
fn revoke_wakes_loading_followers_before_old_loader_completes() {
    let f = fixture(8);
    let registry = f.registry.clone();
    let binding = f.binding;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let leader = {
        let registry = registry.clone();
        let entered = entered.clone();
        let release = release.clone();
        std::thread::spawn(move || {
            registry.prepare_with(binding, |registry, binding| {
                let stale = registry.load_fence(binding)?;
                entered.wait();
                release.wait();
                Ok(stale)
            })
        })
    };
    entered.wait();
    let (waiting, observed) = std::sync::mpsc::channel();
    let (done, finished) = std::sync::mpsc::channel();
    let follower = {
        let registry = registry.clone();
        std::thread::spawn(move || {
            let result = registry.prepare_with_wait(
                binding,
                Duration::from_secs(1),
                |_, _| panic!("follower must share leader"),
                || waiting.send(()).unwrap(),
            );
            done.send(result).unwrap();
        })
    };
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(
        registry.revoke(revoke(binding)).unwrap(),
        EcDrainStatus::Drained
    );
    // The original loader remains blocked. This result requires Closing's
    // own notification, rather than a notification at loader completion.
    let result = finished.recv_timeout(Duration::from_millis(500));
    release.wait();
    follower.join().unwrap();
    assert_eq!(result.unwrap(), Err(EcScopeError::Revoked));
    assert_eq!(leader.join().unwrap(), Err(EcScopeError::Revoked));
    assert!(matches!(
        registry.try_admit(binding),
        Err(EcScopeError::Revoked)
    ));
}

#[test]
fn cold_scope_wait_timeout_is_bounded_under_spurious_notifications() {
    let f = fixture(8);
    let registry = f.registry.clone();
    let binding = f.binding;
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let leader = {
        let registry = registry.clone();
        let entered = entered.clone();
        let release = release.clone();
        std::thread::spawn(move || {
            registry.prepare_with(binding, |registry, binding| {
                let actual = registry.load_fence(binding)?;
                entered.wait();
                release.wait();
                Ok(actual)
            })
        })
    };
    entered.wait();
    let gate = registry.get_gate(binding).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let notifier = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                gate.loaded.notify_all();
                std::thread::yield_now();
            }
        })
    };
    let start = Instant::now();
    let result = registry.prepare_scope_wait(binding, 10);
    let elapsed = start.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Release);
    notifier.join().unwrap();
    release.wait();
    leader.join().unwrap().unwrap();
    assert_eq!(result, Err(EcScopeError::Busy));
    assert!(elapsed < Duration::from_secs(1));
    registry.try_admit(binding).unwrap().complete();
}

#[test]
fn cold_scope_wait_rejects_invalid_cap_and_zero_keeps_nonwaiting_load() {
    let f = fixture(8);
    assert!(matches!(
        f.registry.prepare_scope_wait(f.binding, 1001),
        Err(EcScopeError::Invalid(_))
    ));
    assert!(matches!(
        f.registry.try_admit(f.binding),
        Err(EcScopeError::Busy)
    ));
    // A single worker can itself synchronously load a cold scope with zero
    // follower-wait budget. No additional queued task is required.
    f.registry.prepare_scope_wait(f.binding, 0).unwrap();
    f.registry.try_admit(f.binding).unwrap().complete();
}
