//! Process-local CXX bridge for persistent scope admission. No RPC authority is
//! implied by a successful call; the future instance-bound capability verifier
//! must supply the binding. Current v1 RPCs do not call this bridge for admission.
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use crate::cxx::ffi;
use crate::ec_scope::*;
use crate::Engine;

pub(crate) struct EcScopeHandle {
    registry: Option<Arc<EcScopeRegistry>>,
}

pub(crate) struct EcScopeTicketHandle {
    ticket: Option<EcAdmissionTicket>,
}

fn status(code: u16, message: impl Into<String>) -> ffi::RawEcScopeStatus {
    let mut error = message.into();
    if error.len() > 512 {
        let mut end = 512;
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        error.truncate(end);
    }
    ffi::RawEcScopeStatus {
        error_code: code,
        error,
    }
}

fn error_status(error: EcScopeError) -> ffi::RawEcScopeStatus {
    let code = match &error {
        EcScopeError::Storage(error) => crate::cxx::storage_error_code(error),
        EcScopeError::Invalid(_) => 3,
        EcScopeError::Corrupt(_) => 2,
        EcScopeError::IdentityMismatch | EcScopeError::RevocationMismatch => 64,
        EcScopeError::MissingIdentity => 4002,
        EcScopeError::MissingFence | EcScopeError::Busy => 7012,
        EcScopeError::Revoked => 66,
        EcScopeError::Poisoned => 998,
    };
    status(code, error.to_string())
}

fn boundary<T>(operation: impl FnOnce() -> EcScopeResult<T>) -> Result<T, ffi::RawEcScopeStatus> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result.map_err(error_status),
        Err(_) => Err(status(998, "unexpected panic in EC scope bridge")),
    }
}

fn registry(handle: &EcScopeHandle) -> EcScopeResult<&EcScopeRegistry> {
    handle
        .registry
        .as_deref()
        .ok_or(EcScopeError::Invalid("empty EC scope handle"))
}

fn target(value: &ffi::RawEcScopeTarget) -> EcTargetIdentity {
    EcTargetIdentity {
        engine: value.engine,
        incarnation: value.incarnation,
        chain: value.chain,
        target: value.target,
    }
}

fn raw_target(value: EcTargetIdentity) -> ffi::RawEcScopeTarget {
    ffi::RawEcScopeTarget {
        engine: value.engine,
        incarnation: value.incarnation,
        chain: value.chain,
        target: value.target,
    }
}

fn binding(value: &ffi::RawEcScopeBinding) -> EcScopeResult<EcScopeBinding> {
    Ok(EcScopeBinding {
        target: target(&value.target),
        object: value.object,
        kind: match value.kind {
            1 => EcScopeKind::ReadPin,
            2 => EcScopeKind::WriteOperation,
            _ => return Err(EcScopeError::Invalid("invalid EC scope kind")),
        },
        scope: value.scope,
        owner_uid: value.owner_uid,
        client_namespace: value.client_namespace,
    })
}

fn revocation(value: &ffi::RawEcScopeRevocation) -> EcScopeResult<EcScopeRevocation> {
    Ok(EcScopeRevocation {
        binding: binding(&value.binding)?,
        id: value.id,
        endpoint_set_digest: value.endpoint_set_digest,
    })
}

// Shared by the staging facade bridge without exposing its legacy Engine.
pub(crate) fn scope_open_result(
    operation: impl FnOnce() -> EcScopeResult<Arc<EcScopeRegistry>>,
) -> ffi::RawEcScopeOpenResult {
    match boundary(operation) {
        Ok(registry) => ffi::RawEcScopeOpenResult {
            status: status(0, ""),
            handle: Box::new(EcScopeHandle {
                registry: Some(registry),
            }),
        },
        Err(status) => ffi::RawEcScopeOpenResult {
            status,
            handle: Box::new(EcScopeHandle { registry: None }),
        },
    }
}

pub(crate) fn ec_scope_open(engine: &Engine) -> ffi::RawEcScopeOpenResult {
    scope_open_result(|| engine.ec_scope_registry())
}

fn target_result(
    result: Result<EcTargetIdentity, ffi::RawEcScopeStatus>,
) -> ffi::RawEcTargetResult {
    match result {
        Ok(value) => ffi::RawEcTargetResult {
            status: status(0, ""),
            target: raw_target(value),
        },
        Err(status) => ffi::RawEcTargetResult {
            status,
            target: ffi::RawEcScopeTarget::default(),
        },
    }
}

pub(crate) fn ec_scope_register_target(
    handle: &EcScopeHandle,
    chain: u32,
    target: u64,
) -> ffi::RawEcTargetResult {
    target_result(boundary(|| {
        registry(handle)?.register_target(chain, target)
    }))
}

pub(crate) fn ec_scope_load_target(
    handle: &EcScopeHandle,
    chain: u32,
    target: u64,
) -> ffi::RawEcTargetResult {
    target_result(boundary(|| registry(handle)?.load_target(chain, target)))
}

pub(crate) fn ec_scope_prepare(
    handle: &EcScopeHandle,
    value: &ffi::RawEcScopeBinding,
) -> ffi::RawEcScopeStatus {
    match boundary(|| registry(handle)?.prepare_scope(binding(value)?)) {
        Ok(()) => status(0, ""),
        Err(status) => status,
    }
}

pub(crate) fn ec_scope_prepare_wait(
    handle: &EcScopeHandle,
    value: &ffi::RawEcScopeBinding,
    wait_millis: u32,
) -> ffi::RawEcScopeStatus {
    match boundary(|| registry(handle)?.prepare_scope_wait(binding(value)?, wait_millis)) {
        Ok(()) => status(0, ""),
        Err(status) => status,
    }
}

pub(crate) fn ec_scope_try_admit(
    handle: &EcScopeHandle,
    value: &ffi::RawEcScopeBinding,
) -> ffi::RawEcTicketResult {
    match boundary(|| registry(handle)?.try_admit(binding(value)?)) {
        Ok(ticket) => ffi::RawEcTicketResult {
            status: status(0, ""),
            ticket: Box::new(EcScopeTicketHandle {
                ticket: Some(ticket),
            }),
        },
        Err(status) => ffi::RawEcTicketResult {
            status,
            ticket: Box::new(EcScopeTicketHandle { ticket: None }),
        },
    }
}

pub(crate) fn ec_scope_ticket_check(handle: &EcScopeTicketHandle) -> ffi::RawEcScopeStatus {
    match boundary(|| {
        handle
            .ticket
            .as_ref()
            .ok_or(EcScopeError::Invalid("empty EC scope ticket"))?
            .check_execution()
    }) {
        Ok(()) => status(0, ""),
        Err(status) => status,
    }
}

fn drain_result(result: Result<EcDrainStatus, ffi::RawEcScopeStatus>) -> ffi::RawEcDrainResult {
    match result {
        Ok(EcDrainStatus::Drained) => ffi::RawEcDrainResult {
            status: status(0, ""),
            durable: true,
            inflight: 0,
            drained: true,
        },
        Ok(EcDrainStatus::Pending { inflight, durable }) => ffi::RawEcDrainResult {
            status: status(0, ""),
            durable,
            inflight,
            drained: false,
        },
        Err(status) => ffi::RawEcDrainResult {
            status,
            durable: false,
            inflight: 0,
            drained: false,
        },
    }
}

pub(crate) fn ec_scope_revoke(
    handle: &EcScopeHandle,
    value: &ffi::RawEcScopeRevocation,
) -> ffi::RawEcDrainResult {
    drain_result(boundary(|| registry(handle)?.revoke(revocation(value)?)))
}

pub(crate) fn ec_scope_drain_status(
    handle: &EcScopeHandle,
    value: &ffi::RawEcScopeRevocation,
) -> ffi::RawEcDrainResult {
    drain_result(boundary(|| {
        registry(handle)?.drain_status(revocation(value)?)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EngineConfig;

    fn binding(target: ffi::RawEcScopeTarget) -> ffi::RawEcScopeBinding {
        ffi::RawEcScopeBinding {
            target,
            object: [1; 16],
            kind: 1,
            scope: [2; 16],
            owner_uid: 1000,
            client_namespace: [3; 16],
        }
    }
    fn revoke(binding: ffi::RawEcScopeBinding) -> ffi::RawEcScopeRevocation {
        ffi::RawEcScopeRevocation {
            binding,
            id: [4; 16],
            endpoint_set_digest: [5; 32],
        }
    }
    #[test]
    fn empty_handles_fail_without_false_drained_or_live_ticket() {
        let handle = EcScopeHandle { registry: None };
        let value = binding(ffi::RawEcScopeTarget::default());
        let result = ec_scope_try_admit(&handle, &value);
        assert_ne!(result.status.error_code, 0);
        assert!(result.ticket.ticket.is_none());
        assert_ne!(ec_scope_ticket_check(&result.ticket).error_code, 0);
        let drain = ec_scope_revoke(&handle, &revoke(value));
        assert_ne!(drain.status.error_code, 0);
        assert!(!drain.drained && !drain.durable);
    }
    #[test]
    fn bridge_boxes_share_registry_and_drop_completes_one_count() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(&EngineConfig {
            path: dir.path().into(),
            create: true,
            prefix_len: 4,
        })
        .unwrap();
        let first = ec_scope_open(&engine);
        let second = ec_scope_open(&engine.clone());
        assert_eq!(first.status.error_code, 0);
        assert_eq!(second.status.error_code, 0);
        let target = ec_scope_register_target(&first.handle, 10, 11);
        assert_eq!(target.status.error_code, 0);
        let value = binding(target.target);
        assert_eq!(ec_scope_prepare(&first.handle, &value).error_code, 0);
        let ticket = ec_scope_try_admit(&first.handle, &value);
        assert_eq!(ticket.status.error_code, 0);
        assert_eq!(ec_scope_ticket_check(&ticket.ticket).error_code, 0);
        let request = revoke(value);
        let pending = ec_scope_revoke(&second.handle, &request);
        assert_eq!(pending.status.error_code, 0);
        assert!(pending.durable && !pending.drained);
        assert_eq!(pending.inflight, 1);
        assert_eq!(ec_scope_ticket_check(&ticket.ticket).error_code, 66);
        drop(ticket);
        let drained = ec_scope_drain_status(&first.handle, &request);
        assert_eq!(drained.status.error_code, 0);
        assert!(drained.durable && drained.drained);
        assert_eq!(drained.inflight, 0);
    }
    #[test]
    fn boundary_panics_fail_closed_and_diagnostics_are_bounded() {
        let error = boundary::<()>(|| panic!("injected bridge panic"))
            .err()
            .unwrap();
        assert_eq!(error.error_code, 998);
        let large = status(3, "界".repeat(1000));
        assert!(large.error.len() <= 512);
        assert!(large.error.is_char_boundary(large.error.len()));
    }
    #[test]
    fn invalid_scope_kind_is_rejected_before_registry_lookup() {
        let value = ffi::RawEcScopeBinding {
            kind: 255,
            ..Default::default()
        };
        assert!(matches!(
            binding_result(&value),
            Err(EcScopeError::Invalid(_))
        ));
    }
    fn binding_result(value: &ffi::RawEcScopeBinding) -> EcScopeResult<EcScopeBinding> {
        super::binding(value)
    }
}

// Distinct local target observation; never converts to a scope Drained ACK.
fn retirement_result(
    result: Result<EcTargetRetirementStatus, ffi::RawEcScopeStatus>,
) -> ffi::RawEcTargetRetirementResult {
    match result {
        Ok(EcTargetRetirementStatus::DataDrained) => ffi::RawEcTargetRetirementResult {
            status: status(0, ""),
            durable: true,
            inflight: 0,
            data_drained: true,
        },
        Ok(EcTargetRetirementStatus::Pending { inflight, durable }) => ffi::RawEcTargetRetirementResult {
            status: status(0, ""),
            durable,
            inflight,
            data_drained: false,
        },
        Err(status) => ffi::RawEcTargetRetirementResult {
            status,
            durable: false,
            inflight: 0,
            data_drained: false,
        },
    }
}

pub(crate) fn ec_target_retirement_prepare(
    handle: &EcScopeHandle,
    request: &ffi::RawEcTargetRetirement,
) -> ffi::RawEcTargetRetirementResult {
    retirement_result(boundary(|| {
        registry(handle)?.prepare_target_retirement(EcTargetRetirement {
            target: target(&request.target),
            id: request.id,
        })
    }))
}

pub(crate) fn ec_target_retirement_query(
    handle: &EcScopeHandle,
    request: &ffi::RawEcTargetRetirement,
) -> ffi::RawEcTargetRetirementResult {
    retirement_result(boundary(|| {
        registry(handle)?.query_target_retirement(EcTargetRetirement {
            target: target(&request.target),
            id: request.id,
        })
    }))
}
