//! Owned, bounded CXX entry points for the V2 immutable staging facade.
//! These are local persistence primitives, not capability verification.
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::cxx::ffi;
use crate::*;

pub(crate) struct EcStageHandle {
    engine: Option<ImmutableStagingEngine>,
}

fn error(code: u16, message: impl Into<String>) -> ffi::RawEcScopeStatus {
    let mut message = message.into();
    if message.len() > 512 {
        let mut end = 512;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    ffi::RawEcScopeStatus {
        error_code: code,
        error: message,
    }
}

fn stage_error(value: ImmutableStageError) -> ffi::RawEcScopeStatus {
    let code = match &value {
        ImmutableStageError::Storage(
            Error::IoError(_)
            | Error::RocksDBError(_)
            | Error::MetaError(_)
            | Error::SerializationError(_),
        ) => 4085,
        ImmutableStageError::Storage(value) => crate::cxx::storage_error_code(value),
        ImmutableStageError::Invalid(_) => 3,
        ImmutableStageError::Conflict => 64,
        ImmutableStageError::Missing => 4001,
        ImmutableStageError::NotActive => 4086,
        ImmutableStageError::Busy => 7012,
        ImmutableStageError::Corrupt(_) => 4080,
        ImmutableStageError::OutcomeUnknown(_) => 4085,
    };
    error(code, value.to_string())
}

fn boundary<T>(
    durable: bool,
    operation: impl FnOnce() -> ImmutableStageResult<T>,
) -> std::result::Result<T, ffi::RawEcScopeStatus> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result.map_err(stage_error),
        Err(_) => Err(error(
            if durable { 4085 } else { 998 },
            "unexpected panic in EC staging bridge",
        )),
    }
}

fn engine(handle: &EcStageHandle) -> ImmutableStageResult<&ImmutableStagingEngine> {
    handle
        .engine
        .as_ref()
        .ok_or(ImmutableStageError::Invalid("empty EC stage handle"))
}

fn validate(value: &ffi::RawEcStageBinding) -> ImmutableStageResult<()> {
    if value.operation == [0; 16]
        || value.length as usize > IMMUTABLE_STAGE_MAX_BYTES
        || (value.length == 0 && value.checksum != 0)
    {
        return Err(ImmutableStageError::Invalid("invalid EC stage binding"));
    }
    Ok(())
}

fn bound<'a>(
    handle: &'a EcStageHandle,
    key: &[u8],
    value: &ffi::RawEcStageBinding,
) -> ImmutableStageResult<&'a ImmutableStagingEngine> {
    validate(value)?;
    let engine = engine(handle)?;
    engine.check_fragment_binding(key, &value.operation, value.length, value.checksum)?;
    Ok(engine)
}

fn raw_state(value: ImmutableStageStatus) -> ffi::RawEcStageState {
    ffi::RawEcStageState {
        operation: value.stage_id,
        state: match value.state {
            ImmutableStageState::Active => 1,
            ImmutableStageState::Sealed => 2,
            ImmutableStageState::Aborted => 3,
        },
        prefix_bytes: value.prefix_bytes,
        pending_block: value.pending_block,
        revision: value.revision,
        needs_reconcile: value.needs_reconcile,
    }
}

fn state_result(
    value: std::result::Result<ImmutableStageStatus, ffi::RawEcScopeStatus>,
) -> ffi::RawEcStageResult {
    match value {
        Ok(value) => ffi::RawEcStageResult {
            status: error(0, ""),
            state: raw_state(value),
        },
        Err(status) => ffi::RawEcStageResult {
            status,
            state: ffi::RawEcStageState::default(),
        },
    }
}

pub(crate) fn stage_open(
    path: &str,
    create: bool,
    prefix_len: u32,
    limits: &ffi::RawEcStageLimits,
) -> ffi::RawEcStageOpenResult {
    let opened = boundary(true, || {
        ImmutableStagingEngine::open(
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

pub(crate) fn stage_scope_open(handle: &EcStageHandle) -> ffi::RawEcScopeOpenResult {
    crate::ec_scope_bridge::scope_open_result(|| {
        handle
            .engine
            .as_ref()
            .map(|engine| engine.scopes().clone())
            .ok_or(crate::ec_scope::EcScopeError::Invalid(
                "empty EC stage handle",
            ))
    })
}

pub(crate) fn stage_begin(
    handle: &EcStageHandle,
    key: &[u8],
    binding: &ffi::RawEcStageBinding,
    writer: &[u8; 16],
) -> ffi::RawEcStageResult {
    state_result(boundary(true, || {
        validate(binding)?;
        if writer == &[0; 16] {
            return Err(ImmutableStageError::Invalid("zero writer namespace"));
        }
        // Stable metadata derives exclusively from signed original identities.
        // CRAQ routing versions and per-RPC tags must not alter retries.
        let spec = ImmutableStageSpec {
            stage_id: binding.operation,
            length: binding.length,
            checksum: binding.checksum,
            chain_ver: 0,
            last_request_id: u64::from_be_bytes(binding.operation[..8].try_into().unwrap()),
            last_client_low: u64::from_be_bytes(writer[..8].try_into().unwrap()),
            last_client_high: u64::from_be_bytes(writer[8..].try_into().unwrap()),
            etag: binding.operation.to_vec(),
        };
        engine(handle)?.begin(key, &spec)
    }))
}

pub(crate) fn stage_append(
    handle: &EcStageHandle,
    key: &[u8],
    binding: &ffi::RawEcStageBinding,
    index: u8,
    bytes: &[u8],
) -> ffi::RawEcStageResult {
    state_result(boundary(true, || {
        if bytes.len() > IMMUTABLE_STAGE_BLOCK_BYTES || index as usize >= IMMUTABLE_STAGE_MAX_BLOCKS
        {
            return Err(ImmutableStageError::Invalid(
                "stage slice exceeds fixed block limit",
            ));
        }
        bound(handle, key, binding)?.append(key, &binding.operation, index as usize, bytes)
    }))
}

pub(crate) fn stage_query(
    handle: &EcStageHandle,
    key: &[u8],
    binding: &ffi::RawEcStageBinding,
) -> ffi::RawEcStageResult {
    state_result(boundary(false, || {
        bound(handle, key, binding)?.query(key, &binding.operation)
    }))
}

pub(crate) fn stage_reconcile(
    handle: &EcStageHandle,
    key: &[u8],
    binding: &ffi::RawEcStageBinding,
) -> ffi::RawEcStageResult {
    state_result(boundary(true, || {
        bound(handle, key, binding)?.reconcile(key, &binding.operation)
    }))
}

pub(crate) fn stage_seal(
    handle: &EcStageHandle,
    key: &[u8],
    binding: &ffi::RawEcStageBinding,
) -> ffi::ImmutableReconcileResult {
    match boundary(true, || {
        bound(handle, key, binding)?.seal(key, &binding.operation)
    }) {
        Ok(meta) => ffi::ImmutableReconcileResult {
            error_code: 0,
            error: String::new(),
            meta: crate::cxx::raw_meta_value(&meta),
            etag: binding.operation.to_vec(),
        },
        Err(status) => ffi::ImmutableReconcileResult {
            error_code: status.error_code,
            error: status.error,
            meta: ffi::RawMeta::default(),
            etag: Vec::new(),
        },
    }
}

pub(crate) fn stage_read_block(
    handle: &EcStageHandle,
    key: &[u8],
    binding: &ffi::RawEcStageBinding,
    index: u8,
) -> ffi::RawEcStageReadResult {
    match boundary(false, || {
        if index as usize >= IMMUTABLE_STAGE_MAX_BLOCKS {
            return Err(ImmutableStageError::Invalid("invalid stage block index"));
        }
        bound(handle, key, binding)?.read_sealed_block(key, &binding.operation, index as usize)
    }) {
        Ok(data) => ffi::RawEcStageReadResult {
            status: error(0, ""),
            data,
        },
        Err(status) => ffi::RawEcStageReadResult {
            status,
            data: Vec::new(),
        },
    }
}

pub(crate) fn stage_used_size(handle: &EcStageHandle, prefix: &[u8]) -> ffi::RawEcStageUsedResult {
    match boundary(false, || engine(handle)?.committed_size(prefix)) {
        Ok(committed) => ffi::RawEcStageUsedResult {
            status: error(0, ""),
            committed,
        },
        Err(status) => ffi::RawEcStageUsedResult {
            status,
            committed: 0,
        },
    }
}

#[cfg(test)]
#[path = "ec_stage_bridge_tests.rs"]
mod tests;
