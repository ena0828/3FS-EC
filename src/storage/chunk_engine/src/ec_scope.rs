//! Persistent identities and local admission/drain primitives for EC scopes.
//!
//! This module does not authenticate RPCs, sign drain receipts, release Meta
//! pins, or delete fragments. Callers must validate control/data authority and
//! route identity first. Disk methods must run on a bounded disk executor;
//! `try_admit`, ticket completion and `drain_status` do not perform disk I/O.
//! A ticket must outlive queued work and every borrowed request/job reference.

use crate::{Engine, Error, MetaKey, MetaStore, RocksDB, RocksDBIterator};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

const DENY_PREFIX: u8 = 10;
const ENGINE_PREFIX: u8 = 11;
const TARGET_PREFIX: u8 = 12;
const VERSION: u16 = 1;
const MAX_GATES: usize = 16_384;
const ENGINE_RECORD_BYTES: usize = 26;
const TARGET_RECORD_BYTES: usize = 54;
const RETIRED_TARGET_VERSION: u16 = 2;
const RETIRED_TARGET_RECORD_BYTES: usize = 70;
const FENCE_RECORD_BYTES: usize = 155;
const STAGING_FORMAT_PREFIX: u8 = 15;
const STAGING_FORMAT_RECORD_BYTES: usize = 32;
const STAGING_FORMAT_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EcStagingFormat {
    V2,
    ExactGc,
}
impl EcStagingFormat {
    fn version(self) -> u16 {
        match self {
            Self::V2 => STAGING_FORMAT_VERSION,
            Self::ExactGc => 3,
        }
    }
}

pub type EcIdentity = [u8; 16];
pub type EcScopeResult<T> = std::result::Result<T, EcScopeError>;

#[derive(Debug, PartialEq)]
pub enum EcScopeError {
    Storage(Error),
    Invalid(&'static str),
    Corrupt(&'static str),
    IdentityMismatch,
    RevocationMismatch,
    MissingIdentity,
    MissingFence,
    Revoked,
    Busy,
    Poisoned,
}

impl From<Error> for EcScopeError {
    fn from(error: Error) -> Self {
        Self::Storage(error)
    }
}

impl fmt::Display for EcScopeError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EcScopeKind {
    ReadPin = 1,
    WriteOperation = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcTargetIdentity {
    pub engine: EcIdentity,
    pub incarnation: EcIdentity,
    pub chain: u32,
    pub target: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcScopeBinding {
    pub target: EcTargetIdentity,
    pub object: EcIdentity,
    pub kind: EcScopeKind,
    pub scope: EcIdentity,
    pub owner_uid: u32,
    // A retry namespace, not authenticated process identity.
    pub client_namespace: EcIdentity,
}

impl EcScopeBinding {
    fn validate(&self) -> EcScopeResult<()> {
        if self.target.engine == [0; 16]
            || self.target.incarnation == [0; 16]
            || self.target.chain == 0
            || self.target.target == 0
            || self.object == [0; 16]
            || self.scope == [0; 16]
            || self.client_namespace == [0; 16]
        {
            return Err(EcScopeError::Invalid("zero EC scope identity"));
        }
        Ok(())
    }

    // Owner is a checked value, not part of the deny lookup key. Changing an
    // owner must never create another admission namespace for the same scope.
    fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(62);
        key.push(DENY_PREFIX);
        key.extend_from_slice(&self.target.incarnation);
        key.extend_from_slice(&self.target.chain.to_be_bytes());
        key.extend_from_slice(&self.target.target.to_be_bytes());
        key.extend_from_slice(&self.object);
        key.push(self.kind as u8);
        key.extend_from_slice(&self.scope);
        key
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcScopeRevocation {
    pub binding: EcScopeBinding,
    pub id: EcIdentity,
    pub endpoint_set_digest: [u8; 32],
}

impl EcScopeRevocation {
    fn validate(&self) -> EcScopeResult<()> {
        self.binding.validate()?;
        if self.id == [0; 16] {
            return Err(EcScopeError::Invalid("zero EC revocation ID"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcDrainStatus {
    Pending { inflight: u64, durable: bool },
    Drained,
}

/// Trusted local control input, not an authenticated request or a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcTargetRetirement {
    pub target: EcTargetIdentity,
    pub id: EcIdentity,
}

impl EcTargetRetirement {
    fn validate(self) -> EcScopeResult<()> {
        validate_target_numbers(self.target.chain, self.target.target)?;
        if self.target.engine == [0; 16] || self.target.incarnation == [0; 16] || self.id == [0; 16] {
            return Err(EcScopeError::Invalid("zero target retirement identity"));
        }
        Ok(())
    }
}

/// Local data-ticket observation only. Never a scope ACK, remote-effects
/// certificate, or proof that maintenance I/O/GC has stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcTargetRetirementStatus {
    Pending { inflight: u64, durable: bool },
    DataDrained,
}

/// Created only by the raw, same-writer-handle preflight. It must remain bound
/// to that open MetaStore: closing and reopening between validation and use is
/// not an admissible initialization sequence. No public Empty constructor or
/// Clone implementation lets an RPC caller manufacture/reuse the permission.
#[derive(Debug)]
pub(crate) struct EcStagingProvision {
    empty: bool,
    identity: EcIdentity,
    prefix_len: u32,
    format: EcStagingFormat,
}

impl EcStagingProvision {
    pub(crate) fn is_empty(&self) -> bool {
        self.empty
    }
}

/// Run while RocksDB holds its writer lock, before MetaStore changes prefix
/// accounting or Engine performs a legacy version upgrade. The caller must
/// already validate the V2 root markers and must validate an Empty result's
/// physical namespace before using its provisioning permission. Metadata
/// emptiness alone cannot prove that data files are empty.
pub(crate) fn preflight_staging(
    raw: &RocksDB,
    prefix_len: usize,
) -> EcScopeResult<EcStagingProvision> {
    preflight_staging_format(raw, prefix_len, EcStagingFormat::V2)
}

pub(crate) fn preflight_staging_format(
    raw: &RocksDB,
    prefix_len: usize,
    format: EcStagingFormat,
) -> EcScopeResult<EcStagingProvision> {
    let prefix_len = u32::try_from(prefix_len)
        .map_err(|_| EcScopeError::Invalid("staging prefix length exceeds u32"))?;
    let identity = inspect_staging(
        |key| exact_raw_get(raw, key),
        raw.new_iterator(),
        prefix_len,
        format,
    )?;
    Ok(EcStagingProvision {
        empty: identity.is_none(),
        // Keep one candidate through unknown-commit retries within this open.
        identity: identity.unwrap_or_else(new_identity),
        prefix_len,
        format,
    })
}

/// Publish both protocol roots in one synchronous batch, with the exact
/// baseline metadata needed to reopen the pair. A partial/contradictory pair
/// is never repaired. The same writer handle remains open throughout. The
/// Engine caller synchronizes its physical namespace before publishing pair.
pub(crate) fn joint_provision_staging(
    store: &MetaStore,
    provision: &EcStagingProvision,
) -> EcScopeResult<EcIdentity> {
    joint_provision_staging_with(store, provision, |store, batch| {
        store.write(batch, true).map_err(EcScopeError::from)
    })
}

fn joint_provision_staging_with(
    store: &MetaStore,
    provision: &EcStagingProvision,
    commit: impl FnOnce(&MetaStore, rocksdb::WriteBatch) -> EcScopeResult<()>,
) -> EcScopeResult<EcIdentity> {
    let actual = inspect_staging(
        |key| exact_get(store, key),
        store.iterator(),
        provision.prefix_len,
        provision.format,
    )?;
    match actual {
        Some(identity) if identity == provision.identity => {}
        Some(_) => return Err(EcScopeError::IdentityMismatch),
        None if !provision.empty => return Err(EcScopeError::MissingIdentity),
        None => {
            let mut batch = RocksDB::new_write_batch();
            batch.put([ENGINE_PREFIX], encode_engine(provision.identity));
            batch.put(
                [STAGING_FORMAT_PREFIX],
                encode_staging_format_mode(
                    provision.identity,
                    provision.prefix_len,
                    provision.format,
                ),
            );
            batch.put(
                MetaKey::used_size_prefix_len_key(),
                provision.prefix_len.to_le_bytes(),
            );
            batch.put(MetaKey::version_key(), [MetaStore::LATEST_VERSION]);
            commit(store, batch)?;
        }
    }
    // Covers the unknown-write/cached-visible branch as well as a new batch.
    store.sync_wal()?;
    Ok(provision.identity)
}

fn inspect_staging(
    mut get: impl FnMut(&[u8]) -> EcScopeResult<Option<Vec<u8>>>,
    mut iterator: RocksDBIterator<'_>,
    prefix_len: u32,
    expected_format: EcStagingFormat,
) -> EcScopeResult<Option<EcIdentity>> {
    let identity = get(&[ENGINE_PREFIX])?;
    let format = get(&[STAGING_FORMAT_PREFIX])?;
    match (identity, format) {
        (None, None) => {
            // These are the only exact keys that pristine MetaStore/Engine
            // startup can have committed before the joint transaction.
            iterator.seek([])?;
            while iterator.valid() {
                let key = iterator
                    .key()
                    .ok_or(EcScopeError::Corrupt("missing metadata key"))?;
                let value = iterator
                    .value()
                    .ok_or(EcScopeError::Corrupt("missing metadata value"))?;
                let allowed = match key {
                    [MetaKey::USED_SIZE_PREFIX_LEN_KEY] => value == prefix_len.to_le_bytes(),
                    [MetaKey::VERSION_KEY] => value == [MetaStore::LATEST_VERSION],
                    [MetaKey::USED_SIZE_KEY_PREFIX] if prefix_len == 0 => {
                        value == 0u64.to_le_bytes()
                    }
                    _ => false,
                };
                if !allowed {
                    return Err(EcScopeError::Corrupt(
                        "unprovisioned staging database is not pristine",
                    ));
                }
                iterator.next();
            }
            iterator.status()?;
            Ok(None)
        }
        (Some(identity), Some(format)) => {
            let identity = decode_engine(&identity)?;
            decode_staging_format_mode(&format, identity, prefix_len, expected_format)?;
            let prefix = get(&[MetaKey::USED_SIZE_PREFIX_LEN_KEY])?;
            if !matches!(prefix.as_deref(), Some(bytes) if bytes == prefix_len.to_le_bytes())
                && !(prefix_len == 0 && prefix.is_none())
            {
                return Err(EcScopeError::Corrupt(
                    "provisioned staging prefix configuration mismatch",
                ));
            }
            if get(&[MetaKey::VERSION_KEY])?.as_deref() != Some(&[MetaStore::LATEST_VERSION]) {
                return Err(EcScopeError::Corrupt(
                    "provisioned staging baseline version mismatch",
                ));
            }
            // A singleton key with an appended suffix is not another valid
            // protocol root. Reject it before legacy normalization can run.
            for prefix in [
                MetaKey::USED_SIZE_PREFIX_LEN_KEY,
                MetaKey::VERSION_KEY,
                ENGINE_PREFIX,
                STAGING_FORMAT_PREFIX,
            ] {
                iterator.seek([prefix])?;
                while iterator.valid()
                    && iterator
                        .key()
                        .is_some_and(|key| key.first() == Some(&prefix))
                {
                    if iterator.key() != Some(&[prefix]) {
                        return Err(EcScopeError::Corrupt("noncanonical staging singleton key"));
                    }
                    iterator.next();
                }
                iterator.status()?;
            }
            iterator.seek([MetaKey::WRITING_CHUNK_KEY_PREFIX])?;
            if iterator
                .key()
                .is_some_and(|key| key.first() == Some(&MetaKey::WRITING_CHUNK_KEY_PREFIX))
            {
                return Err(EcScopeError::Corrupt(
                    "legacy writing log in staging database",
                ));
            }
            iterator.status()?;
            Ok(Some(identity))
        }
        _ => Err(EcScopeError::Corrupt(
            "one-sided staging identity/format initialization",
        )),
    }
}

// Shared by every clone of one Engine. It is deliberately not constructed by
// RPC callers. Existing stores without an identity cannot silently upgrade.
pub(crate) struct EcScopeBootstrap {
    mode: BootstrapMode,
    registry: Mutex<Option<Arc<EcScopeRegistry>>>,
}

enum BootstrapMode {
    Ordinary { allow_create_identity: bool },
    Staging(EcStagingProvision),
}

impl EcScopeBootstrap {
    pub(crate) fn new(allow_create_identity: bool) -> Self {
        Self {
            mode: BootstrapMode::Ordinary {
                allow_create_identity,
            },
            registry: Mutex::new(None),
        }
    }

    pub(crate) fn for_staging(provision: EcStagingProvision) -> Self {
        Self {
            mode: BootstrapMode::Staging(provision),
            registry: Mutex::new(None),
        }
    }
}

impl Engine {
    /// Disk-executor/startup operation. Initialize before advertising EC scope
    /// service. The Engine integration patch supplies the shared bootstrap.
    pub fn ec_scope_registry(&self) -> EcScopeResult<Arc<EcScopeRegistry>> {
        self.ec_scope_registry_with(|| self.sync_immutable_namespace().map_err(EcScopeError::from))
    }

    fn ec_scope_registry_with(
        &self,
        sync_namespace: impl FnOnce() -> EcScopeResult<()>,
    ) -> EcScopeResult<Arc<EcScopeRegistry>> {
        let bootstrap = &self.ec_scope_bootstrap;
        let mut slot = lock(&bootstrap.registry)?;
        if let Some(registry) = &*slot {
            return Ok(registry.clone());
        }
        let registry = match &bootstrap.mode {
            BootstrapMode::Ordinary {
                allow_create_identity,
            } => {
                let registry = EcScopeRegistry::open(
                    self.meta_store.clone(),
                    *allow_create_identity,
                    MAX_GATES,
                )?;
                sync_namespace()?;
                registry
            }
            BootstrapMode::Staging(provision) => {
                // Commit the protocol pair only after the fully opened V2
                // physical namespace has established directory reachability.
                sync_namespace()?;
                EcScopeRegistry::from_staging(self.meta_store.clone(), provision, MAX_GATES)?
            }
        };
        // A synchronous WAL alone does not establish a newly created parent
        // directory. No identity/receipt escapes before this succeeds.
        self.meta_store.sync_wal()?;
        let registry = Arc::new(registry);
        *slot = Some(registry.clone());
        Ok(registry)
    }
}

pub struct EcScopeRegistry {
    store: Arc<MetaStore>,
    identity: EcIdentity,
    // Disk mutation/load serialization, never held by data admission/Drop.
    // Lock order: mutation -> targets map (released) -> target state.
    // No target/scope state lock is held across disk I/O.
    target_registration: Mutex<()>,
    staging: bool,
    // Strong for the registry lifetime, unlike the evictable scope cache.
    // One immutable identity per logical target; no reincarnation alias gate.
    targets: Mutex<HashMap<(u32, u64), Arc<TargetGate>>>,
    gates: Mutex<HashMap<Vec<u8>, Arc<Gate>>>,
    max_gates: usize,
}

impl EcScopeRegistry {
    fn open(store: Arc<MetaStore>, allow_create: bool, max_gates: usize) -> EcScopeResult<Self> {
        let key = [ENGINE_PREFIX];
        let identity = match exact_get(&store, &key)? {
            Some(bytes) => decode_engine(&bytes)?,
            None if allow_create => {
                let identity = new_identity();
                put_sync(&store, &key, &encode_engine(identity))?;
                identity
            }
            None => return Err(EcScopeError::MissingIdentity),
        };
        store.sync_wal()?;
        Ok(Self::from_identity(store, identity, max_gates))
    }

    fn from_identity(store: Arc<MetaStore>, identity: EcIdentity, max_gates: usize) -> Self {
        Self {
            store,
            identity,
            target_registration: Mutex::new(()),
            staging: false,
            targets: Mutex::new(HashMap::new()),
            gates: Mutex::new(HashMap::new()),
            max_gates,
        }
    }

    fn from_staging(
        store: Arc<MetaStore>,
        provision: &EcStagingProvision,
        max_gates: usize,
    ) -> EcScopeResult<Self> {
        let identity = joint_provision_staging(&store, provision)?;
        let mut registry = Self::from_identity(store, identity, max_gates);
        registry.staging = true;
        Ok(registry)
    }

    pub fn engine_identity(&self) -> EcIdentity {
        self.identity
    }

    pub(crate) fn confirm_staging_identity(&self, prefix_len: usize) -> EcScopeResult<()> {
        self.confirm_staging_format(prefix_len, EcStagingFormat::V2)
    }

    pub(crate) fn confirm_staging_format(
        &self,
        prefix_len: usize,
        format: EcStagingFormat,
    ) -> EcScopeResult<()> {
        let prefix_len = u32::try_from(prefix_len)
            .map_err(|_| EcScopeError::Invalid("staging prefix length exceeds u32"))?;
        let actual = inspect_staging(
            |key| exact_get(&self.store, key),
            self.store.iterator(),
            prefix_len,
            format,
        )?;
        if actual != Some(self.identity) {
            return Err(EcScopeError::IdentityMismatch);
        }
        self.store.sync_wal()?;
        Ok(())
    }

    /// Trusted target-creation operation, not data admission. No removal or
    /// replacement API is provided. A repeated registration preserves identity.
    pub fn register_target(&self, chain: u32, target: u64) -> EcScopeResult<EcTargetIdentity> {
        validate_target_numbers(chain, target)?;
        let _mutation = lock(&self.target_registration)?;
        // Even a failed pre-write retirement must not be undone by registration.
        let existing = { lock(&self.targets)?.get(&(chain, target)).cloned() };
        if let Some(gate) = existing {
            lock(&gate.state)?.ensure_serving()?;
        }
        let key = target_key(chain, target);
        let record = match exact_get(&self.store, &key)? {
            Some(bytes) => decode_target_record(&bytes)?,
            None => {
                // A loaded identity cannot disappear and be replaced in place.
                if lock(&self.targets)?.contains_key(&(chain, target)) {
                    return Err(EcScopeError::MissingIdentity);
                }
                let identity = EcTargetIdentity {
                    engine: self.identity,
                    incarnation: new_identity(),
                    chain,
                    target,
                };
                put_sync(&self.store, &key, &encode_target(identity))?;
                TargetRecord { identity, retirement: None }
            }
        };
        self.check_target(record.identity, chain, target)?;
        let gate = self.merge_target_record(record, false)?;
        self.store.sync_wal()?;
        self.merge_target_record(record, true)?;
        lock(&gate.state)?.ensure_serving()?;
        Ok(record.identity)
    }

    /// Maintenance identity read. A retired identity remains readable; this
    /// method never grants data admission or resets an in-memory Closing state.
    pub fn load_target(&self, chain: u32, target: u64) -> EcScopeResult<EcTargetIdentity> {
        self.load_target_with(chain, target, |store| {
            store.sync_wal().map_err(EcScopeError::from)
        })
    }

    fn load_target_with(
        &self,
        chain: u32,
        target: u64,
        confirm: impl FnOnce(&MetaStore) -> EcScopeResult<()>,
    ) -> EcScopeResult<EcTargetIdentity> {
        validate_target_numbers(chain, target)?;
        let _mutation = lock(&self.target_registration)?;
        let record = self.read_target_record(chain, target)?;
        // Install denial before WAL confirmation, including the unknown branch.
        self.merge_target_record(record, false)?;
        confirm(&self.store)?;
        self.merge_target_record(record, true)?;
        Ok(record.identity)
    }

    fn read_target_record(&self, chain: u32, target: u64) -> EcScopeResult<TargetRecord> {
        let bytes = exact_get(&self.store, &target_key(chain, target))?
            .ok_or(EcScopeError::MissingIdentity)?;
        let record = decode_target_record(&bytes)?;
        self.check_target(record.identity, chain, target)?;
        if record.retirement.is_some() && !self.staging {
            return Err(EcScopeError::Corrupt("retired target requires staging registry"));
        }
        Ok(record)
    }

    // Caller holds mutation serialization; no I/O while target state is locked.
    fn merge_target_record(&self, record: TargetRecord, confirmed: bool) -> EcScopeResult<Arc<TargetGate>> {
        let gate = {
            let mut targets = lock(&self.targets)?;
            targets.entry((record.identity.chain, record.identity.target))
                .or_insert_with(|| Arc::new(TargetGate {
                    identity: record.identity,
                    state: Mutex::new(TargetState::default()),
                })).clone()
        };
        if gate.identity != record.identity {
            return Err(EcScopeError::IdentityMismatch);
        }
        {
            let mut state = lock(&gate.state)?;
            state.ensure_live()?;
            match (state.retirement, record.retirement) {
                (Some(old), Some(id)) if old != id => {
                    state.broken = true;
                    return Err(EcScopeError::RevocationMismatch);
                }
                (Some(_), None) if state.durable => {
                    state.broken = true;
                    return Err(EcScopeError::Corrupt("durable target denial disappeared"));
                }
                (_, Some(id)) => {
                    state.retirement = Some(id);
                    state.durable |= confirmed;
                }
                _ => {} // Never reopen Closing on a still-v1 disk observation.
            }
            state.identity_confirmed |= confirmed;
        }
        Ok(gate)
    }

    // Memory only. Never creates a gate from caller-supplied identity.
    fn target_gate(&self, identity: EcTargetIdentity) -> EcScopeResult<Arc<TargetGate>> {
        let gate = lock(&self.targets)?.get(&(identity.chain, identity.target))
            .cloned().ok_or(EcScopeError::MissingIdentity)?;
        if gate.identity != identity {
            return Err(EcScopeError::IdentityMismatch);
        }
        Ok(gate)
    }

    fn check_target_serving(&self, identity: EcTargetIdentity) -> EcScopeResult<()> {
        let target = self.target_gate(identity)?;
        let result = lock(&target.state)?.ensure_serving();
        result
    }

    /// Disk-executor operation for an already loaded V2/3 target. Closing is
    /// linearized before persistence. Errors keep admission closed; retry only
    /// the same request. This does not authenticate authority or sign evidence.
    pub fn prepare_target_retirement(&self, request: EcTargetRetirement) -> EcScopeResult<EcTargetRetirementStatus> {
        self.retire_target_with(request, |registry, request| registry.persist_target_retirement(request))
    }

    fn retirement_gate(&self, request: EcTargetRetirement) -> EcScopeResult<Arc<TargetGate>> {
        request.validate()?;
        if !self.staging {
            return Err(EcScopeError::Invalid("target retirement requires V2/3 staging"));
        }
        self.target_gate(request.target)
    }

    fn retire_target_with(
        &self,
        request: EcTargetRetirement,
        persist: impl FnOnce(&Self, EcTargetRetirement) -> EcScopeResult<()>,
    ) -> EcScopeResult<EcTargetRetirementStatus> {
        let gate = self.retirement_gate(request)?;
        let _mutation = lock(&self.target_registration)?;
        {
            let mut state = lock(&gate.state)?;
            state.ensure_live()?;
            if !state.identity_confirmed {
                return Err(EcScopeError::Busy);
            }
            state.check_request(request.id)?;
            state.retirement = Some(request.id);
        }
        persist(self, request)?;
        let mut state = lock(&gate.state)?;
        state.ensure_live()?;
        state.durable = true;
        Ok(state.observation())
    }

    fn persist_target_retirement(&self, request: EcTargetRetirement) -> EcScopeResult<()> {
        let record = self.read_target_record(request.target.chain, request.target.target)?;
        if record.identity != request.target {
            return Err(EcScopeError::IdentityMismatch);
        }
        if let Some(id) = record.retirement {
            if id != request.id {
                return Err(EcScopeError::RevocationMismatch);
            }
        } else {
            put_sync(&self.store, &target_key(request.target.chain, request.target.target),
                     &encode_retired_target(request))?;
        }
        self.store.sync_wal()?;
        Ok(())
    }

    /// Disk confirmation/query, not a second prepare. A missing retirement
    /// record may report only an existing local unknown Closing observation.
    pub fn query_target_retirement(&self, request: EcTargetRetirement) -> EcScopeResult<EcTargetRetirementStatus> {
        let gate = self.retirement_gate(request)?;
        let _mutation = lock(&self.target_registration)?;
        lock(&gate.state)?.check_request(request.id)?;
        let record = self.read_target_record(request.target.chain, request.target.target)?;
        if record.identity != request.target {
            return Err(EcScopeError::IdentityMismatch);
        }
        self.merge_target_record(record, false)?;
        {
            let state = lock(&gate.state)?;
            state.ensure_live()?;
            state.check_request(request.id)?;
            if state.retirement.is_none() {
                return Err(EcScopeError::MissingFence);
            }
        }
        if record.retirement.is_some() {
            self.store.sync_wal()?;
            self.merge_target_record(record, true)?;
        }
        let state = lock(&gate.state)?;
        state.ensure_live()?;
        Ok(state.observation())
    }

    fn check_target(
        &self,
        identity: EcTargetIdentity,
        chain: u32,
        target: u64,
    ) -> EcScopeResult<()> {
        if identity.engine != self.identity || identity.chain != chain || identity.target != target
        {
            return Err(EcScopeError::IdentityMismatch);
        }
        Ok(())
    }

    /// Disk-executor operation. Unknown scopes cannot be admitted until this
    /// exact persistent deny lookup completes. No global/gate lock spans I/O.
    pub fn prepare_scope(&self, binding: EcScopeBinding) -> EcScopeResult<()> {
        self.prepare_with(binding, |registry, binding| registry.load_fence(binding))
    }

    fn prepare_with(
        &self,
        binding: EcScopeBinding,
        load: impl FnOnce(&Self, EcScopeBinding) -> EcScopeResult<Option<EcScopeRevocation>>,
    ) -> EcScopeResult<()> {
        self.prepare_with_wait(binding, std::time::Duration::ZERO, load, || {})
    }

    /// Data-admission-only bounded singleflight wait. Zero preserves the
    /// existing nonwaiting semantics. This budget cannot interrupt the leader's
    /// already synchronous disk I/O and is not a client RPC deadline.
    pub fn prepare_scope_wait(
        &self,
        binding: EcScopeBinding,
        wait_millis: u32,
    ) -> EcScopeResult<()> {
        if wait_millis > 1000 {
            return Err(EcScopeError::Invalid(
                "scope cold-load wait exceeds 1000 ms",
            ));
        }
        self.prepare_with_wait(
            binding,
            std::time::Duration::from_millis(wait_millis.into()),
            |registry, binding| registry.load_fence(binding),
            || {},
        )
    }

    fn prepare_with_wait(
        &self,
        binding: EcScopeBinding,
        wait: std::time::Duration,
        load: impl FnOnce(&Self, EcScopeBinding) -> EcScopeResult<Option<EcScopeRevocation>>,
        on_wait: impl FnOnce(),
    ) -> EcScopeResult<()> {
        self.prepare_scope_state_with_wait(binding, wait, load, on_wait)?;
        // All scope locks have been released. Maintenance fence loading above
        // remains possible after retirement, but data preparation fails closed.
        self.check_target_serving(binding.target)
    }

    fn prepare_scope_state_with_wait(
        &self,
        binding: EcScopeBinding,
        wait: std::time::Duration,
        load: impl FnOnce(&Self, EcScopeBinding) -> EcScopeResult<Option<EcScopeRevocation>>,
        on_wait: impl FnOnce(),
    ) -> EcScopeResult<()> {
        let deadline = std::time::Instant::now() + wait;
        let gate = self.get_gate(binding)?;
        {
            let mut state = lock(&gate.state)?;
            state.ensure_live()?;
            match state.phase {
                Phase::Open => return Ok(()),
                Phase::Closing | Phase::Denied => return Err(EcScopeError::Revoked),
                Phase::Loading => {
                    if wait.is_zero() {
                        return Err(EcScopeError::Busy);
                    }
                    // The loader is already executing synchronous I/O on a
                    // different thread. No queued task behind this waiter is
                    // needed to finish it. The callback is private test sync.
                    on_wait();
                    while state.phase == Phase::Loading {
                        let remaining =
                            deadline.saturating_duration_since(std::time::Instant::now());
                        if remaining.is_zero() {
                            return Err(EcScopeError::Busy);
                        }
                        let (next, _) = gate
                            .loaded
                            .wait_timeout(state, remaining)
                            .map_err(|_| EcScopeError::Poisoned)?;
                        state = next;
                        state.ensure_live()?;
                    }
                    return match state.phase {
                        Phase::Open if std::time::Instant::now() < deadline => Ok(()),
                        Phase::Open => Err(EcScopeError::Busy),
                        Phase::Closing | Phase::Denied => Err(EcScopeError::Revoked),
                        // A failed leader leaves the scope unconfirmed. The
                        // follower never starts another load or promotes it.
                        Phase::Unloaded | Phase::Loading => Err(EcScopeError::Busy),
                    };
                }
                Phase::Unloaded => state.phase = Phase::Loading,
            }
        }
        let loaded = load(self, binding);
        let mut state = lock(&gate.state)?;
        state.ensure_live()?;
        // A concurrent revoke has a monotonic precedence over a stale miss.
        if state.phase != Phase::Loading {
            return Err(EcScopeError::Revoked);
        }
        let result = match loaded {
            Ok(Some(revocation)) => {
                state.phase = Phase::Denied;
                state.revocation = Some(revocation);
                state.durable = true;
                Err(EcScopeError::Revoked)
            }
            Ok(None) => {
                state.phase = Phase::Open;
                Ok(())
            }
            Err(error) => {
                state.phase = Phase::Unloaded;
                Err(error)
            }
        };
        gate.loaded.notify_all();
        result
    }

    /// No disk I/O. Successful admission is linearized under the same mutex
    /// that closes a scope. Call before waiting for chunk locks or job queues.
    pub fn try_admit(&self, binding: EcScopeBinding) -> EcScopeResult<EcAdmissionTicket> {
        let gate = self.get_gate(binding)?;
        let target = self.target_gate(binding.target)?;
        {
            // Fixed nested order: target -> scope. No map lock or I/O here.
            let mut target_state = lock(&target.state)?;
            target_state.ensure_serving()?;
            let mut state = lock(&gate.state)?;
            state.ensure_live()?;
            match state.phase {
                Phase::Open => {}
                Phase::Closing | Phase::Denied => return Err(EcScopeError::Revoked),
                Phase::Unloaded | Phase::Loading => return Err(EcScopeError::Busy),
            }
            let scope_next = state.inflight.checked_add(1).ok_or(EcScopeError::Busy)?;
            let target_next = target_state.inflight.checked_add(1).ok_or(EcScopeError::Busy)?;
            state.inflight = scope_next;
            target_state.inflight = target_next;
        }
        Ok(EcAdmissionTicket {
            gate,
            target,
            _store_lease: self.store.clone(),
        })
    }

    /// Disk-executor operation. Closes before persisting; never waits for
    /// admitted work. The caller polls status after queued jobs can run.
    pub fn revoke(&self, request: EcScopeRevocation) -> EcScopeResult<EcDrainStatus> {
        self.revoke_with(request, |registry, request| registry.persist_fence(request))
    }

    fn revoke_with(
        &self,
        request: EcScopeRevocation,
        persist: impl FnOnce(&Self, EcScopeRevocation) -> EcScopeResult<EcScopeRevocation>,
    ) -> EcScopeResult<EcDrainStatus> {
        request.validate()?;
        let gate = self.get_gate(request.binding)?;
        {
            let mut state = lock(&gate.state)?;
            state.ensure_live()?;
            if let Some(prior) = state.revocation {
                if prior != request {
                    return Err(EcScopeError::RevocationMismatch);
                }
            }
            if state.durable {
                return Ok(state.drain_status());
            }
            if state.persisting {
                return Err(EcScopeError::Busy);
            }
            state.phase = Phase::Closing;
            state.revocation = Some(request);
            state.persisting = true;
            // Closing has priority before the durable write; data waiters do
            // not wait for either that write or the original loader to finish.
            gate.loaded.notify_all();
        }
        let stored = persist(self, request);
        let mut state = lock(&gate.state)?;
        state.ensure_live()?;
        state.persisting = false;
        match stored {
            Ok(stored) => {
                // A reloaded persistent fence may identify an earlier revoke;
                // preserve that immutable identity even for a wrong retry.
                state.revocation = Some(stored);
                state.durable = true;
                state.phase = Phase::Denied;
                if stored != request {
                    return Err(EcScopeError::RevocationMismatch);
                }
                Ok(state.drain_status())
            }
            Err(error) => Err(error), // Closing remains fail-closed.
        }
    }

    /// No disk I/O. Use prepare_scope on a cold cache before querying. A
    /// missing or unconfirmed fence cannot produce a Drained observation.
    pub fn drain_status(&self, request: EcScopeRevocation) -> EcScopeResult<EcDrainStatus> {
        request.validate()?;
        let gate = self.get_gate(request.binding)?;
        let state = lock(&gate.state)?;
        state.ensure_live()?;
        match state.revocation {
            Some(prior) if prior == request => Ok(state.drain_status()),
            Some(_) => Err(EcScopeError::RevocationMismatch),
            None => Err(EcScopeError::MissingFence),
        }
    }

    fn load_fence(&self, binding: EcScopeBinding) -> EcScopeResult<Option<EcScopeRevocation>> {
        let target = self.load_target(binding.target.chain, binding.target.target)?;
        if target != binding.target {
            return Err(EcScopeError::IdentityMismatch);
        }
        match exact_get(&self.store, &binding.key())? {
            Some(bytes) => {
                let record = decode_fence(&bytes)?;
                if record.binding != binding {
                    return Err(EcScopeError::IdentityMismatch);
                }
                // A prior failed synchronous write may still be cache-visible.
                // Reconfirm durability instead of treating visibility as ACK.
                self.store.sync_wal()?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    fn persist_fence(&self, request: EcScopeRevocation) -> EcScopeResult<EcScopeRevocation> {
        if let Some(prior) = self.load_fence(request.binding)? {
            return Ok(prior);
        }
        put_sync(&self.store, &request.binding.key(), &encode_fence(request))?;
        self.store.sync_wal()?;
        Ok(request)
    }

    fn get_gate(&self, binding: EcScopeBinding) -> EcScopeResult<Arc<Gate>> {
        binding.validate()?;
        if binding.target.engine != self.identity {
            return Err(EcScopeError::IdentityMismatch);
        }
        let key = binding.key();
        let mut gates = lock(&self.gates)?;
        if let Some(gate) = gates.get(&key) {
            if gate.binding != binding {
                return Err(EcScopeError::IdentityMismatch);
            }
            return Ok(gate.clone());
        }
        if gates.len() >= self.max_gates {
            // Scope-map -> scope is separate from target -> scope; no path
            // takes a map or target lock while holding a scope lock. Retiring before
            // removal prevents an outstanding Arc from admitting on an old
            // gate while a cache miss creates another gate for the same key.
            let mut victim = None;
            for (key, gate) in gates.iter() {
                let mut state = lock(&gate.state)?;
                if state.inflight == 0
                    && !state.persisting
                    && matches!(state.phase, Phase::Unloaded | Phase::Open | Phase::Denied)
                {
                    state.retired = true;
                    gate.loaded.notify_all();
                    victim = Some(key.clone());
                    break;
                }
            }
            if let Some(key) = victim {
                gates.remove(&key);
            } else {
                return Err(EcScopeError::Busy);
            }
        }
        let gate = Arc::new(Gate {
            binding,
            state: Mutex::new(GateState::default()),
            loaded: Condvar::new(),
        });
        gates.insert(key, gate.clone());
        Ok(gate)
    }
}

#[derive(Clone, Copy)]
struct TargetRecord {
    identity: EcTargetIdentity,
    retirement: Option<EcIdentity>,
}

struct TargetGate {
    identity: EcTargetIdentity,
    state: Mutex<TargetState>,
}

#[derive(Default)]
struct TargetState {
    identity_confirmed: bool,
    retirement: Option<EcIdentity>,
    durable: bool,
    inflight: u64,
    broken: bool,
}

impl TargetState {
    fn ensure_live(&self) -> EcScopeResult<()> {
        if self.broken {
            return Err(EcScopeError::Corrupt("target admission counter invariant"));
        }
        Ok(())
    }
    fn ensure_serving(&self) -> EcScopeResult<()> {
        self.ensure_live()?;
        if self.retirement.is_some() {
            return Err(EcScopeError::Revoked);
        }
        if !self.identity_confirmed {
            return Err(EcScopeError::Busy);
        }
        Ok(())
    }
    fn check_request(&self, id: EcIdentity) -> EcScopeResult<()> {
        self.ensure_live()?;
        if self.retirement.is_some_and(|old| old != id) {
            return Err(EcScopeError::RevocationMismatch);
        }
        Ok(())
    }
    fn observation(&self) -> EcTargetRetirementStatus {
        if self.durable && self.inflight == 0 {
            EcTargetRetirementStatus::DataDrained
        } else {
            EcTargetRetirementStatus::Pending { inflight: self.inflight, durable: self.durable }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Unloaded,
    Loading,
    Open,
    Closing,
    Denied,
}

struct Gate {
    binding: EcScopeBinding,
    state: Mutex<GateState>,
    loaded: Condvar,
}

struct GateState {
    phase: Phase,
    revocation: Option<EcScopeRevocation>,
    inflight: u64,
    durable: bool,
    persisting: bool,
    retired: bool,
    broken: bool,
}

impl Default for GateState {
    fn default() -> Self {
        Self {
            phase: Phase::Unloaded,
            revocation: None,
            inflight: 0,
            durable: false,
            persisting: false,
            retired: false,
            broken: false,
        }
    }
}

impl GateState {
    fn ensure_live(&self) -> EcScopeResult<()> {
        if self.broken {
            return Err(EcScopeError::Corrupt("EC admission counter invariant"));
        }
        if self.retired {
            return Err(EcScopeError::Busy);
        }
        Ok(())
    }

    fn drain_status(&self) -> EcDrainStatus {
        if self.durable && self.inflight == 0 {
            EcDrainStatus::Drained
        } else {
            EcDrainStatus::Pending {
                inflight: self.inflight,
                durable: self.durable,
            }
        }
    }
}

/// Move-only ownership of one admitted job, including time spent queued.
/// Drop only after the worker and all borrowed request references have ended.
pub struct EcAdmissionTicket {
    gate: Arc<Gate>,
    target: Arc<TargetGate>,
    // Keep this physical instance exclusively open until its last old ticket
    // completes. Gate alone would let Engine/registry drop release the RocksDB
    // writer lock; a reopened registry could then falsely report zero inflight.
    // This field drops after Drop::drop decrements the original gate count.
    _store_lease: Arc<MetaStore>,
}

impl EcAdmissionTicket {
    pub fn binding(&self) -> EcScopeBinding {
        self.gate.binding
    }

    /// Worker-side recheck. No new admission is counted. A queued job can be
    /// rejected after revoke, while its ticket remains until completion.
    pub fn check_execution(&self) -> EcScopeResult<()> {
        let target = lock(&self.target.state)?;
        target.ensure_serving()?;
        let state = lock(&self.gate.state)?;
        state.ensure_live()?;
        if state.phase == Phase::Open {
            Ok(())
        } else {
            Err(EcScopeError::Revoked)
        }
    }

    pub fn complete(self) {
        drop(self);
    }
}

impl fmt::Debug for EcAdmissionTicket {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("EcAdmissionTicket")
            .field("binding", &self.gate.binding)
            .finish_non_exhaustive()
    }
}

impl Drop for EcAdmissionTicket {
    fn drop(&mut self) {
        // Never unwind. Poison/underflow must not manufacture target zero.
        // The original store lease drops only after both guarded transitions.
        if let Ok(mut target) = self.target.state.lock() {
            if let Ok(mut scope) = self.gate.state.lock() {
                match (scope.inflight.checked_sub(1), target.inflight.checked_sub(1)) {
                    (Some(scope_next), Some(target_next)) if !scope.broken && !target.broken => {
                        scope.inflight = scope_next;
                        target.inflight = target_next;
                    }
                    _ => { scope.broken = true; target.broken = true; }
                }
            } else {
                target.broken = true;
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> EcScopeResult<MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| EcScopeError::Poisoned)
}

fn validate_target_numbers(chain: u32, target: u64) -> EcScopeResult<()> {
    if chain == 0 || target == 0 {
        return Err(EcScopeError::Invalid("zero EC target or chain"));
    }
    Ok(())
}

fn new_identity() -> EcIdentity {
    loop {
        let value = rand::random::<EcIdentity>();
        if value != [0; 16] {
            return value;
        }
    }
}

fn exact_get(store: &MetaStore, key: &[u8]) -> EcScopeResult<Option<Vec<u8>>> {
    let mut iterator = store.iterator();
    iterator.seek(key)?;
    if iterator.key() != Some(key) {
        iterator.status()?;
        return Ok(None);
    }
    let bytes = iterator
        .value()
        .ok_or(EcScopeError::Corrupt("EC metadata value absent"))?;
    // All three records are smaller than this bound; malformed values never
    // allocate an attacker-controlled extent before their length is checked.
    if bytes.len() > FENCE_RECORD_BYTES {
        return Err(EcScopeError::Corrupt(
            "EC metadata exceeds fixed record size",
        ));
    }
    let value = bytes.to_vec();
    iterator.status()?;
    Ok(Some(value))
}

fn exact_raw_get(store: &RocksDB, key: &[u8]) -> EcScopeResult<Option<Vec<u8>>> {
    let Some(value) = store.get(key)? else {
        return Ok(None);
    };
    if value.len() > FENCE_RECORD_BYTES {
        return Err(EcScopeError::Corrupt(
            "EC raw metadata exceeds fixed record size",
        ));
    }
    Ok(Some(value.to_vec()))
}

fn put_sync(store: &MetaStore, key: &[u8], value: &[u8]) -> EcScopeResult<()> {
    let mut batch = RocksDB::new_write_batch();
    batch.put(key, value);
    store.write(batch, true)?;
    Ok(())
}

fn target_key(chain: u32, target: u64) -> Vec<u8> {
    let mut key = vec![TARGET_PREFIX];
    key.extend_from_slice(&chain.to_be_bytes());
    key.extend_from_slice(&target.to_be_bytes());
    key
}

fn record(magic: &[u8; 4]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FENCE_RECORD_BYTES);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes
}

fn checksum(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.extend_from_slice(&crc32c::crc32c(&bytes).to_be_bytes());
    bytes
}

fn checked_record<'a>(bytes: &'a [u8], magic: &[u8; 4], length: usize) -> EcScopeResult<&'a [u8]> {
    if bytes.len() != length
        || bytes[..4] != magic[..]
        || bytes[4..6] != VERSION.to_be_bytes()
        || bytes[length - 4..] != crc32c::crc32c(&bytes[..length - 4]).to_be_bytes()
    {
        return Err(EcScopeError::Corrupt(
            "EC metadata version, length, magic or checksum",
        ));
    }
    Ok(&bytes[6..length - 4])
}

fn encode_engine(identity: EcIdentity) -> Vec<u8> {
    let mut bytes = record(b"ECID");
    bytes.extend_from_slice(&identity);
    checksum(bytes)
}

fn decode_engine(bytes: &[u8]) -> EcScopeResult<EcIdentity> {
    let body = checked_record(bytes, b"ECID", ENGINE_RECORD_BYTES)?;
    let identity = body
        .try_into()
        .map_err(|_| EcScopeError::Corrupt("EC engine identity"))?;
    if identity == [0; 16] {
        return Err(EcScopeError::Corrupt("zero persistent EC engine identity"));
    }
    Ok(identity)
}

fn encode_staging_format(identity: EcIdentity, prefix_len: u32) -> Vec<u8> {
    encode_staging_format_mode(identity, prefix_len, EcStagingFormat::V2)
}

fn encode_staging_format_mode(
    identity: EcIdentity,
    prefix_len: u32,
    format: EcStagingFormat,
) -> Vec<u8> {
    let mut bytes = record(b"ECSF");
    bytes.extend_from_slice(&identity);
    bytes.extend_from_slice(&prefix_len.to_be_bytes());
    bytes.extend_from_slice(&format.version().to_be_bytes());
    checksum(bytes)
}

fn decode_staging_format(bytes: &[u8], identity: EcIdentity, prefix_len: u32) -> EcScopeResult<()> {
    decode_staging_format_mode(bytes, identity, prefix_len, EcStagingFormat::V2)
}

fn decode_staging_format_mode(
    bytes: &[u8],
    identity: EcIdentity,
    prefix_len: u32,
    format: EcStagingFormat,
) -> EcScopeResult<()> {
    let mut reader = Reader(checked_record(bytes, b"ECSF", STAGING_FORMAT_RECORD_BYTES)?);
    let recorded_identity: EcIdentity = reader.take()?;
    let recorded_prefix = u32::from_be_bytes(reader.take()?);
    let recorded_version = u16::from_be_bytes(reader.take()?);
    if recorded_identity != identity
        || recorded_prefix != prefix_len
        || recorded_version != format.version()
    {
        return Err(EcScopeError::Corrupt(
            "staging format and engine identity disagree",
        ));
    }
    Ok(())
}

fn encode_target(identity: EcTargetIdentity) -> Vec<u8> {
    let mut bytes = record(b"ECTG");
    encode_target_into(&mut bytes, identity);
    checksum(bytes)
}

fn encode_target_into(bytes: &mut Vec<u8>, identity: EcTargetIdentity) {
    bytes.extend_from_slice(&identity.engine);
    bytes.extend_from_slice(&identity.incarnation);
    bytes.extend_from_slice(&identity.chain.to_be_bytes());
    bytes.extend_from_slice(&identity.target.to_be_bytes());
}

fn decode_target(bytes: &[u8]) -> EcScopeResult<EcTargetIdentity> {
    let mut reader = Reader(checked_record(bytes, b"ECTG", TARGET_RECORD_BYTES)?);
    reader.target()
}

// A new legitimate ECTG version on the same key, not a legacy-ignored side
// key. Keep decode_target unchanged as the fixed v1 reader.
fn encode_retired_target(request: EcTargetRetirement) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RETIRED_TARGET_RECORD_BYTES);
    bytes.extend_from_slice(b"ECTG");
    bytes.extend_from_slice(&RETIRED_TARGET_VERSION.to_be_bytes());
    encode_target_into(&mut bytes, request.target);
    bytes.extend_from_slice(&request.id);
    checksum(bytes)
}

fn decode_target_record(bytes: &[u8]) -> EcScopeResult<TargetRecord> {
    if bytes.get(4..6) == Some(VERSION.to_be_bytes().as_slice()) {
        return Ok(TargetRecord { identity: decode_target(bytes)?, retirement: None });
    }
    if bytes.len() != RETIRED_TARGET_RECORD_BYTES
        || &bytes[..4] != b"ECTG"
        || bytes[4..6] != RETIRED_TARGET_VERSION.to_be_bytes()
        || bytes[bytes.len()-4..] != crc32c::crc32c(&bytes[..bytes.len()-4]).to_be_bytes()
    {
        return Err(EcScopeError::Corrupt("target retirement version, extent, magic or checksum"));
    }
    let mut reader = Reader(&bytes[6..bytes.len()-4]);
    let request = EcTargetRetirement { target: reader.target()?, id: reader.take()? };
    request.validate()?;
    if !reader.0.is_empty() {
        return Err(EcScopeError::Corrupt("trailing target retirement bytes"));
    }
    Ok(TargetRecord { identity: request.target, retirement: Some(request.id) })
}

fn encode_fence(request: EcScopeRevocation) -> Vec<u8> {
    let mut bytes = record(b"ECRV");
    encode_target_into(&mut bytes, request.binding.target);
    bytes.extend_from_slice(&request.binding.object);
    bytes.push(request.binding.kind as u8);
    bytes.extend_from_slice(&request.binding.scope);
    bytes.extend_from_slice(&request.binding.owner_uid.to_be_bytes());
    bytes.extend_from_slice(&request.binding.client_namespace);
    bytes.extend_from_slice(&request.id);
    bytes.extend_from_slice(&request.endpoint_set_digest);
    checksum(bytes)
}

fn decode_fence(bytes: &[u8]) -> EcScopeResult<EcScopeRevocation> {
    let mut reader = Reader(checked_record(bytes, b"ECRV", FENCE_RECORD_BYTES)?);
    let target = reader.target()?;
    let object = reader.take()?;
    let kind = match reader.take::<1>()?[0] {
        1 => EcScopeKind::ReadPin,
        2 => EcScopeKind::WriteOperation,
        _ => return Err(EcScopeError::Corrupt("unknown EC scope kind")),
    };
    let scope = reader.take()?;
    let owner_uid = u32::from_be_bytes(reader.take()?);
    let client_namespace = reader.take()?;
    let request = EcScopeRevocation {
        binding: EcScopeBinding {
            target,
            object,
            kind,
            scope,
            owner_uid,
            client_namespace,
        },
        id: reader.take()?,
        endpoint_set_digest: reader.take()?,
    };
    request.validate()?;
    if !reader.0.is_empty() {
        return Err(EcScopeError::Corrupt("trailing EC scope record bytes"));
    }
    Ok(request)
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> EcScopeResult<[u8; N]> {
        if self.0.len() < N {
            return Err(EcScopeError::Corrupt("short EC metadata field"));
        }
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into()
            .map_err(|_| EcScopeError::Corrupt("EC field extent"))
    }

    fn target(&mut self) -> EcScopeResult<EcTargetIdentity> {
        let identity = EcTargetIdentity {
            engine: self.take()?,
            incarnation: self.take()?,
            chain: u32::from_be_bytes(self.take()?),
            target: u64::from_be_bytes(self.take()?),
        };
        validate_target_numbers(identity.chain, identity.target)?;
        if identity.engine == [0; 16] || identity.incarnation == [0; 16] {
            return Err(EcScopeError::Corrupt("zero persistent EC target identity"));
        }
        Ok(identity)
    }
}

#[cfg(test)]
#[path = "ec_scope_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ec_target_retirement_tests.rs"]
mod target_retirement_tests;
