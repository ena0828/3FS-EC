//! Process-local exact-GC bridge over the same owned staging facade.
//! It is not a network authorization interface. The future private Storage
//! executor must verify the independent GC capability before calling.
use super::{boundary, engine, error, stable_stage_spec, EcStageHandle};
use crate::cxx::ffi;
use crate::ec_scope::EcTargetIdentity;
use crate::*;

// This bridge is specific to 3FS's native u32 chain prefix plus the 64B
// EcFragmentIdentity::chunkId(). The generic Engine/core GC key stays opaque.
// Chain equality is necessary, but does not authenticate target ID, incarnation
// or fragment identity. Only a private verified-G adapter can establish those.
fn validate_3fs_key(key: &[u8], chain: u32) -> ImmutableStageResult<()> {
    if key.len() != 4 + 64 {
        return Err(ImmutableStageError::Invalid(
            "invalid 3FS exact GC key extent",
        ));
    }
    if u32::from_ne_bytes(key[..4].try_into().unwrap()) != chain {
        return Err(ImmutableStageError::Conflict);
    }
    Ok(())
}

fn claim(value: &ffi::RawEcStageGcClaim) -> ImmutableStageResult<EcStageGcClaim> {
    let claim = EcStageGcClaim {
        claim_id: value.claim_id,
        claim_digest: value.claim_digest,
        eligibility_digest: value.eligibility_digest,
        target: EcTargetIdentity {
            engine: value.target.engine,
            incarnation: value.target.incarnation,
            chain: value.target.chain,
            target: value.target.target,
        },
        spec: stable_stage_spec(&value.binding, &value.writer)?,
    };
    claim.validate()?;
    Ok(claim)
}

fn result(
    value: std::result::Result<EcStageGcReceipt, ffi::RawEcScopeStatus>,
) -> ffi::RawEcStageGcResult {
    match value {
        Ok(receipt) => ffi::RawEcStageGcResult {
            status: error(0, ""),
            receipt: ffi::RawEcStageGcReceipt {
                claim_id: receipt.claim_id,
                ledger_sha256: receipt.ledger_sha256,
                terminal_revision: receipt.terminal_revision,
            },
        },
        Err(status) => ffi::RawEcStageGcResult {
            status,
            receipt: ffi::RawEcStageGcReceipt::default(),
        },
    }
}

// A separate explicit opener, never automatic V2 upgrade/fallback. The caller
// uses this single facade for both staging data and GC; no second DB is opened.
pub(crate) fn stage_open_gc(
    path: &str,
    create: bool,
    prefix_len: u32,
    limits: &ffi::RawEcStageLimits,
) -> ffi::RawEcStageOpenResult {
    let opened = boundary(true, || {
        if prefix_len != 4 {
            return Err(ImmutableStageError::Invalid(
                "3FS exact GC requires native u32 chain prefix",
            ));
        }
        ImmutableStagingEngine::open_gc(
            &EngineConfig {
                path: path.into(),
                create,
                prefix_len: prefix_len as usize,
            },
            ImmutableStageLimits {
                max_cached_records: limits.max_cached_records as usize,
                max_active: limits.max_active as usize,
                max_concurrent_io: limits.max_concurrent_io as usize,
            },
        )
    });
    match opened {
        Ok(engine) => ffi::RawEcStageOpenResult {
            status: error(0, ""),
            handle: Box::new(EcStageHandle {
                engine: Some(engine),
            }),
        },
        Err(status) => ffi::RawEcStageOpenResult {
            status,
            handle: Box::new(EcStageHandle { engine: None }),
        },
    }
}

pub(crate) fn stage_gc_collect(
    handle: &EcStageHandle,
    key: &[u8],
    value: &ffi::RawEcStageGcClaim,
) -> ffi::RawEcStageGcResult {
    result(boundary(true, || {
        let claim = claim(value)?;
        validate_3fs_key(key, claim.target.chain)?;
        engine(handle)?.collect_known_stage_after_claim(key, &claim)
    }))
}

// Unlike ordinary stage_query, GC Query is a durability confirmation. It can
// settle a previous uncertain batch and release its held allocation only after
// terminal verification plus sync_wal. It never starts a new deletion batch.
pub(crate) fn stage_gc_query(
    handle: &EcStageHandle,
    key: &[u8],
    value: &ffi::RawEcStageGcClaim,
) -> ffi::RawEcStageGcResult {
    result(boundary(true, || {
        let claim = claim(value)?;
        validate_3fs_key(key, claim.target.chain)?;
        engine(handle)?.query_known_stage_gc(key, &claim)
    }))
}

pub(crate) fn stage_actual_disk_format(handle: &EcStageHandle) -> ffi::RawEcStageFormatResult {
    match boundary(false, || Ok(engine(handle)?.actual_disk_format())) {
        Ok(disk_format) => ffi::RawEcStageFormatResult {
            status: error(0, ""),
            disk_format,
        },
        Err(status) => ffi::RawEcStageFormatResult {
            status,
            disk_format: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    // The integration runner must additionally keep its global test-thread
    // count small: each real Engine opens many allocator files.
    static ENGINE_TEST: Mutex<()> = Mutex::new(());

    fn setup(gc: bool) -> (tempfile::TempDir, String, ffi::RawEcStageLimits) {
        let root = tempfile::tempdir().unwrap();
        let markers = if gc {
            (IMMUTABLE_GC_ROOT_MARKER, IMMUTABLE_GC_V1_BLOCKER)
        } else {
            (IMMUTABLE_STAGE_ROOT_MARKER, IMMUTABLE_STAGE_V1_BLOCKER)
        };
        for (name, bytes) in [("engine", markers.0), ("engine-ec-v1", markers.1)] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(root.path().join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        std::fs::File::open(root.path())
            .unwrap()
            .sync_all()
            .unwrap();
        let path = root
            .path()
            .join(IMMUTABLE_STAGE_ENGINE_DIRECTORY)
            .to_str()
            .unwrap()
            .to_owned();
        (
            root,
            path,
            ffi::RawEcStageLimits {
                max_cached_records: 8,
                max_active: 4,
                max_concurrent_io: 2,
            },
        )
    }

    fn make_claim(handle: &EcStageHandle, bytes: &[u8], id: u8) -> ffi::RawEcStageGcClaim {
        let target = engine(handle)
            .unwrap()
            .scopes()
            .register_target(1, 2)
            .unwrap();
        ffi::RawEcStageGcClaim {
            claim_id: [id; 16],
            claim_digest: [id.wrapping_add(1); 32],
            eligibility_digest: [id.wrapping_add(2); 32],
            target: ffi::RawEcScopeTarget {
                engine: target.engine,
                incarnation: target.incarnation,
                chain: target.chain,
                target: target.target,
            },
            binding: ffi::RawEcStageBinding {
                operation: [id.wrapping_add(3); 16],
                length: bytes.len() as u32,
                checksum: crc32c::crc32c(bytes),
            },
            writer: [id.wrapping_add(4); 16],
        }
    }

    fn key(id: u8) -> Vec<u8> {
        // Process-local chain prefix is native-endian, not the GC wire domain.
        // The C++ layer derives the following 64B suffix from fragment identity.
        // This test uses opaque exact keys, not a substitute fragment encoder.
        let mut value = 1u32.to_ne_bytes().to_vec();
        value.extend_from_slice(&[id; 64]);
        value
    }

    fn rejected(value: ffi::RawEcStageGcResult, code: u16) {
        assert_eq!(value.status.error_code, code, "{}", value.status.error);
        assert_eq!(value.receipt, ffi::RawEcStageGcReceipt::default());
    }

    #[test]
    fn gc_bridge_shared_spec_uses_original_operation_and_writer() {
        let binding = ffi::RawEcStageBinding {
            operation: std::array::from_fn(|i| (i + 1) as u8),
            length: 7,
            checksum: 0x12345678,
        };
        let writer = std::array::from_fn(|i| (i + 17) as u8);
        let expected = stable_stage_spec(&binding, &writer).unwrap();
        assert_eq!(expected.stage_id, binding.operation);
        assert_eq!(expected.etag, binding.operation);
        assert_eq!(expected.chain_ver, 0);
        assert_eq!(expected.last_request_id, 0x0102030405060708);
        assert_eq!(expected.last_client_low, 0x1112131415161718);
        assert_eq!(expected.last_client_high, 0x191a1b1c1d1e1f20);
        assert_eq!(expected.length, 7);
        assert_eq!(expected.checksum, 0x12345678);
        let raw = ffi::RawEcStageGcClaim {
            claim_id: [1; 16],
            claim_digest: [2; 32],
            eligibility_digest: [3; 32],
            target: ffi::RawEcScopeTarget {
                engine: [4; 16],
                incarnation: [5; 16],
                chain: 1,
                target: 2,
            },
            binding,
            writer,
        };
        assert_eq!(claim(&raw).unwrap().spec, expected);
        assert!(stable_stage_spec(&binding, &[0; 16]).is_err());
    }

    #[test]
    fn gc_bridge_exact_binding_rejects_changes_and_missing_without_receipt() {
        let _serial = ENGINE_TEST.lock().unwrap();
        let (_root, path, limits) = setup(true);
        let opened = stage_open_gc(&path, true, 4, &limits);
        assert_eq!(opened.status.error_code, 0, "{}", opened.status.error);
        let handle = opened.handle;
        let bytes = b"original sealed bytes";
        let original = make_claim(&handle, bytes, 1);
        let key = key(1);
        assert_eq!(
            super::super::stage_begin(&handle, &key, &original.binding, &original.writer)
                .status
                .error_code,
            0
        );
        assert_eq!(
            super::super::stage_append(&handle, &key, &original.binding, 0, bytes)
                .status
                .error_code,
            0
        );
        assert_eq!(
            super::super::stage_seal(&handle, &key, &original.binding).error_code,
            0
        );
        for field in 0..6 {
            let mut changed = original;
            match field {
                0 => changed.writer[0] ^= 1,
                1 => changed.binding.operation[0] ^= 1,
                2 => changed.binding.length += 1,
                3 => changed.binding.checksum ^= 1,
                4 => changed.target.engine[0] ^= 1,
                _ => changed.target.incarnation[0] ^= 1,
            }
            rejected(stage_gc_collect(&handle, &key, &changed), 64);
        }
        rejected(stage_gc_query(&handle, &key, &original), 4001);
        rejected(stage_gc_collect(&handle, &self::key(2), &original), 4001);
        rejected(
            stage_gc_collect(&handle, &[1; IMMUTABLE_STAGE_MAX_KEY_BYTES + 1], &original),
            3,
        );
        assert_eq!(
            super::super::stage_read_block(&handle, &key, &original.binding, 0).data,
            bytes
        );
        let done = stage_gc_collect(&handle, &key, &original);
        assert_eq!(done.status.error_code, 0, "{}", done.status.error);
        for field in 0..3 {
            let mut changed = original;
            match field {
                0 => changed.claim_id[0] ^= 1,
                1 => changed.claim_digest[0] ^= 1,
                _ => changed.eligibility_digest[0] ^= 1,
            }
            // Keep every field nonzero: this is a binding conflict, not schema rejection.
            if changed.claim_id == [0; 16] {
                changed.claim_id[1] = 7;
            }
            rejected(stage_gc_query(&handle, &key, &changed), 64);
        }
    }

    #[test]
    fn gc_bridge_rejects_registered_other_chain_key_binding() {
        let _serial = ENGINE_TEST.lock().unwrap();
        let (_root, path, limits) = setup(true);
        // The 3FS bridge rejects another prefix length before creating a DB.
        assert_eq!(stage_open_gc(&path, true, 0, &limits).status.error_code, 3);
        let opened = stage_open_gc(&path, true, 4, &limits);
        assert_eq!(opened.status.error_code, 0, "{}", opened.status.error);
        let handle = opened.handle;
        let bytes = b"the original chain must still own these bytes";
        let original = make_claim(&handle, bytes, 1);
        let key = key(1);
        assert_eq!(
            super::super::stage_begin(&handle, &key, &original.binding, &original.writer)
                .status
                .error_code,
            0
        );
        assert_eq!(
            super::super::stage_append(&handle, &key, &original.binding, 0, bytes)
                .status
                .error_code,
            0
        );
        assert_eq!(
            super::super::stage_seal(&handle, &key, &original.binding).error_code,
            0
        );

        let other = engine(&handle)
            .unwrap()
            .scopes()
            .register_target(2, 9)
            .unwrap();
        let mut changed = original;
        changed.target = ffi::RawEcScopeTarget {
            engine: other.engine,
            incarnation: other.incarnation,
            chain: other.chain,
            target: other.target,
        };
        // Both persistent targets really exist, but the supplied key belongs
        // to chain 1. Neither mutation nor confirmation may use chain 2.
        rejected(stage_gc_collect(&handle, &key, &changed), 64);
        rejected(stage_gc_query(&handle, &key, &changed), 64);
        rejected(stage_gc_collect(&handle, &key[..4], &original), 3);
        assert_eq!(
            super::super::stage_read_block(&handle, &key, &original.binding, 0).data,
            bytes
        );

        // Registry uniqueness is (chain,target), not chain alone. A raw local
        // caller must not treat the prefix check as proof of exact target ID.
        // No public adapter exists here; future verified-G execution must use
        // the still-owned actual StorageTarget and construct, not accept, key.
        let same_chain = engine(&handle)
            .unwrap()
            .scopes()
            .register_target(1, 3)
            .unwrap();
        assert_ne!(same_chain.target, original.target.target);
        let done = stage_gc_collect(&handle, &key, &original);
        assert_eq!(done.status.error_code, 0, "{}", done.status.error);
        assert_eq!(done.receipt.claim_id, original.claim_id);
    }

    #[test]
    fn gc_bridge_same_facade_confirms_three_states_and_reopens() {
        let _serial = ENGINE_TEST.lock().unwrap();
        let (_root, path, limits) = setup(true);
        let opened = stage_open_gc(&path, true, 4, &limits);
        assert_eq!(opened.status.error_code, 0, "{}", opened.status.error);
        let handle = opened.handle;
        let actual = stage_actual_disk_format(&handle);
        assert_eq!(actual.status.error_code, 0);
        assert_eq!(actual.disk_format, 3);
        let bytes = b"staging and exact GC share one Engine";
        let mut completed = Vec::new();
        for state in 0..3u8 {
            let key = key(state + 1);
            let raw = make_claim(&handle, bytes, state + 1);
            assert_eq!(
                super::super::stage_begin(&handle, &key, &raw.binding, &raw.writer)
                    .status
                    .error_code,
                0
            );
            if state == 1 {
                assert_eq!(
                    super::super::stage_append(&handle, &key, &raw.binding, 0, bytes)
                        .status
                        .error_code,
                    0
                );
                let sealed = super::super::stage_seal(&handle, &key, &raw.binding);
                assert_eq!(sealed.error_code, 0, "{}", sealed.error);
                assert_eq!(
                    sealed.meta.last_client_low,
                    u64::from_be_bytes(raw.writer[..8].try_into().unwrap())
                );
                assert!(super::super::stage_used_size(&handle, &1u32.to_ne_bytes()).committed > 0);
            } else if state == 2 {
                // Internal fixture transition, not a public abort/authorization API.
                engine(&handle)
                    .unwrap()
                    .cancel_after_fence(&key, &raw.binding.operation)
                    .unwrap();
            }
            let done = stage_gc_collect(&handle, &key, &raw);
            assert_eq!(done.status.error_code, 0, "{}", done.status.error);
            assert!(done.status.error.is_empty());
            assert_eq!(done.receipt.claim_id, raw.claim_id);
            assert_ne!(done.receipt.ledger_sha256, [0; 32]);
            assert!(done.receipt.terminal_revision >= 2);
            let replay = stage_gc_collect(&handle, &key, &raw);
            assert_eq!(replay.status.error_code, 0);
            assert_eq!(replay.receipt, done.receipt);
            let query = stage_gc_query(&handle, &key, &raw);
            assert_eq!(query.status.error_code, 0);
            assert_eq!(query.receipt, done.receipt);
            let usage = super::super::stage_used_size(&handle, &1u32.to_ne_bytes());
            assert_eq!(usage.status.error_code, 0);
            assert_eq!(usage.committed, 0);
            completed.push((key, raw, done.receipt));
        }
        drop(handle);
        let reopened = stage_open_gc(&path, false, 4, &limits);
        assert_eq!(reopened.status.error_code, 0, "{}", reopened.status.error);
        for (key, raw, receipt) in completed {
            let query = stage_gc_query(&reopened.handle, &key, &raw);
            assert_eq!(query.status.error_code, 0, "{}", query.status.error);
            assert_eq!(query.receipt, receipt);
        }
    }

    #[test]
    fn gc_bridge_format_openers_never_upgrade_or_substitute() {
        let _serial = ENGINE_TEST.lock().unwrap();
        let (_v2_root, v2_path, limits) = setup(false);
        let v2 = super::super::stage_open(&v2_path, true, 4, &limits);
        assert_eq!(v2.status.error_code, 0);
        let actual = stage_actual_disk_format(&v2.handle);
        assert_eq!(actual.status.error_code, 0);
        assert_eq!(actual.disk_format, 2);
        let raw = make_claim(&v2.handle, b"x", 1);
        rejected(stage_gc_collect(&v2.handle, &key(1), &raw), 3);
        rejected(stage_gc_query(&v2.handle, &key(1), &raw), 3);
        drop(v2.handle);
        let invalid = stage_open_gc(&v2_path, false, 4, &limits);
        assert_ne!(invalid.status.error_code, 0);
        let empty = stage_actual_disk_format(&invalid.handle);
        assert_ne!(empty.status.error_code, 0);
        assert_eq!(empty.disk_format, 0);
        rejected(stage_gc_query(&invalid.handle, &key(1), &raw), 3);

        let (_gc_root, gc_path, limits) = setup(true);
        let gc = stage_open_gc(&gc_path, true, 4, &limits);
        assert_eq!(gc.status.error_code, 0);
        drop(gc.handle);
        assert_ne!(
            super::super::stage_open(&gc_path, false, 4, &limits)
                .status
                .error_code,
            0
        );
    }

    #[test]
    fn gc_bridge_unknown_and_panic_clear_receipts() {
        // This checks ABI error normalization, not a simulated durable commit.
        // The separate core suite injects real before/after-batch and WAL faults.
        rejected(
            result(boundary(true, || {
                Err(ImmutableStageError::OutcomeUnknown("test".into()))
            })),
            4085,
        );
        rejected(
            result(boundary(true, || {
                Err(ImmutableStageError::Storage(Error::MetaError(
                    "test".into(),
                )))
            })),
            4085,
        );
        rejected(
            result(boundary(
                true,
                || -> ImmutableStageResult<EcStageGcReceipt> { panic!("GC bridge test panic") },
            )),
            4085,
        );
        rejected(
            result(boundary(true, || Err(ImmutableStageError::Missing))),
            4001,
        );
        rejected(
            result(boundary(true, || Err(ImmutableStageError::Conflict))),
            64,
        );
    }
}

fn absent(handle:&EcStageHandle,key:&[u8],v:&ffi::RawEcStageAbsentClaim,query:bool)->ffi::RawEcStageAbsentResult {
    use crate::ec_scope::{EcScopeBinding,EcScopeKind,EcScopeRevocation,EcTargetRetirement};
    let r=boundary(true,|| {
        let gc=claim(&v.gc)?;
        validate_3fs_key(key,gc.target.chain)?;
        if v.scope.binding.kind!=2 || v.scope.binding.target!=v.gc.target {
            return Err(ImmutableStageError::Conflict);
        }
        let scope=EcScopeRevocation { binding:EcScopeBinding {target:gc.target,object:v.scope.binding.object,
            kind:EcScopeKind::WriteOperation,scope:v.scope.binding.scope,owner_uid:v.scope.binding.owner_uid,
            client_namespace:v.scope.binding.client_namespace},id:v.scope.id,endpoint_set_digest:v.scope.endpoint_set_digest};
        let retirement=v.retirement.then_some(EcTargetRetirement {target:gc.target,id:v.retirement_id});
        let c=EcStageAbsentClaim {gc,closure_digest:v.closure_digest,scope,retirement};
        engine(handle)?.confirm_absent_after_close(key,&c,query)
    });
    match r {
        Ok(r)=>ffi::RawEcStageAbsentResult {status:error(0,""),receipt:ffi::RawEcStageAbsentReceipt {
            claim_id:r.claim_id,ledger_sha256:r.ledger_sha256,record_revision:r.record_revision}},
        Err(status)=>ffi::RawEcStageAbsentResult {status,receipt:ffi::RawEcStageAbsentReceipt::default()},
    }
}
pub(crate) fn stage_absent_confirm(h:&EcStageHandle,k:&[u8],c:&ffi::RawEcStageAbsentClaim)->ffi::RawEcStageAbsentResult {absent(h,k,c,false)}
pub(crate) fn stage_absent_query(h:&EcStageHandle,k:&[u8],c:&ffi::RawEcStageAbsentClaim)->ffi::RawEcStageAbsentResult {absent(h,k,c,true)}
