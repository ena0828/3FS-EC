//! Bounded immutable staging over the existing chunk allocator and MetaStore.
//!
//! This facade intentionally does not expose legacy update, auto-commit,
//! compaction, or delete operations. Admission/authentication belongs to the
//! enclosing Storage service; opening this local component is not authorization.

use crate::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub const IMMUTABLE_STAGE_ENGINE_DIRECTORY: &str = "engine-ec-v2";
pub const IMMUTABLE_STAGE_ROOT_MARKER: &[u8] = b"3FS_EC_ENGINE_ROOT_V2\n";
pub const IMMUTABLE_STAGE_V1_BLOCKER: &[u8] = b"3FS_EC_ENGINE_V1_BLOCKED_BY_V2\n";

/// Called only with the same exclusive RocksDB handle whose logical keys
/// were classified as an unprovisioned, strictly empty V2 namespace. Before
/// joint provisioning, no group has been allocated: existing cluster files
/// must therefore be ordinary zero-length files. Never walk arbitrary paths.
pub(crate) fn validate_empty_immutable_stage_paths(path: &std::path::Path) -> Result<()> {
    let classes: HashSet<_> = (0..CHUNK_SIZE_NUMBER)
        .map(|index| (CHUNK_SIZE_SMALL * (1u64 << index)).to_string())
        .collect();
    let io =
        |error: std::io::Error| Error::IoError(format!("inspect empty staging namespace: {error}"));
    for entry in std::fs::read_dir(path).map_err(io)? {
        let entry = entry.map_err(io)?;
        let metadata = std::fs::symlink_metadata(entry.path()).map_err(io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::MetaError("non-UTF8 path in empty staging namespace".into()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::MetaError(
                "empty staging namespace contains a non-directory or symlink".into(),
            ));
        }
        if name == "meta" {
            continue;
        }
        if !classes.contains(&name) {
            return Err(Error::MetaError(
                "unknown directory in empty staging namespace".into(),
            ));
        }
        for file in std::fs::read_dir(entry.path()).map_err(io)? {
            let file = file.map_err(io)?;
            let metadata = std::fs::symlink_metadata(file.path()).map_err(io)?;
            let name = file
                .file_name()
                .into_string()
                .map_err(|_| Error::MetaError("non-UTF8 cluster filename".into()))?;
            if name.len() != 2
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
                || !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() != 0
            {
                return Err(Error::MetaError(
                    "unprovisioned stage has unknown or nonempty cluster files".into(),
                ));
            }
        }
    }
    Ok(())
}

pub type ImmutableStageResult<T> = std::result::Result<T, ImmutableStageError>;

#[derive(Debug, PartialEq)]
pub enum ImmutableStageError {
    Storage(Error),
    Invalid(&'static str),
    Conflict,
    Missing,
    NotActive,
    Busy,
    Corrupt(&'static str),
    /// Never authorizes publication or freeing any possibly referenced extent.
    OutcomeUnknown(String),
}

impl From<Error> for ImmutableStageError {
    fn from(error: Error) -> Self {
        match error {
            Error::IoError(_) | Error::RocksDBError(_) => Self::OutcomeUnknown(error.to_string()),
            other => Self::Storage(other),
        }
    }
}

impl std::fmt::Display for ImmutableStageError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ImmutableStageLimits {
    /// Memory cache entries, not a limit on persisted terminal records.
    pub max_cached_records: usize,
    /// Non-evictable reservations, including writes with unknown outcomes.
    pub max_active: usize,
    pub max_concurrent_io: usize,
}

impl Default for ImmutableStageLimits {
    fn default() -> Self {
        Self {
            max_cached_records: 4096,
            max_active: 64,
            max_concurrent_io: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableStageStatus {
    pub stage_id: [u8; 16],
    pub state: ImmutableStageState,
    pub prefix_bytes: u32,
    pub pending_block: bool,
    pub revision: u64,
    /// Query alone is not a durability acknowledgment. Every reopened record
    /// starts unconfirmed until explicit reconciliation succeeds.
    pub needs_reconcile: bool,
}

struct StageSlot {
    record: Option<StageRecord>,
    chunk: Option<ChunkArc>,
    unknown: bool,
}

#[derive(Default)]
struct StageRegistry {
    slots: HashMap<Bytes, Arc<Mutex<StageSlot>>>,
    active: usize,
}

struct StageInner {
    engine: Engine,
    registry: Mutex<StageRegistry>,
    scopes: Arc<crate::ec_scope::EcScopeRegistry>,
    limits: ImmutableStageLimits,
    io_in_flight: AtomicUsize,
    #[cfg(test)]
    fault: Mutex<Option<StageFault>>,
}

#[derive(Clone)]
pub struct ImmutableStagingEngine(Arc<StageInner>);

// The point names also document the only metadata transition boundaries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StageWritePoint {
    Reservation,
    Intent,
    Progress,
    Seal,
    Abort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageOpenPoint {
    AfterEngineOpen,
    AfterJointProvision,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct StageFault {
    point: StageWritePoint,
    after_commit: bool,
}

struct IoPermit<'a>(&'a AtomicUsize);
impl Drop for IoPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Safe, fallible allocation with a 4096-aligned 64 KiB subslice. It never
/// touches the legacy safe_write 64 MiB thread-local buffer.
struct StageBuffer {
    bytes: Vec<u8>,
    start: usize,
}

impl StageBuffer {
    fn new() -> ImmutableStageResult<Self> {
        const ALIGN: usize = 4096;
        let capacity = IMMUTABLE_STAGE_BLOCK_BYTES + ALIGN - 1;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ImmutableStageError::Busy)?;
        bytes.resize(capacity, 0);
        let start = (ALIGN - bytes.as_ptr() as usize % ALIGN) % ALIGN;
        Ok(Self { bytes, start })
    }
}

impl Deref for StageBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.bytes[self.start..self.start + IMMUTABLE_STAGE_BLOCK_BYTES]
    }
}

impl DerefMut for StageBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes[self.start..self.start + IMMUTABLE_STAGE_BLOCK_BYTES]
    }
}

impl ImmutableStagingEngine {
    /// The caller creates and synchronizes the V2 root marker before opening
    /// the engine. No automatic migration or marker overwrite is permitted.
    /// Older EC loaders reject its exact V2 bytes; pre-EC loaders cannot open
    /// the regular file at root/engine as their engine directory.
    pub fn open(config: &EngineConfig, limits: ImmutableStageLimits) -> ImmutableStageResult<Self> {
        Self::open_with_hook(config, limits, |_, _| Ok(()))
    }

    // Private, per-call callback for deterministic startup interruption tests.
    // It is not a global failure switch or a public control-plane API.
    fn open_with_hook(
        config: &EngineConfig,
        limits: ImmutableStageLimits,
        mut hook: impl FnMut(StageOpenPoint, &Engine) -> ImmutableStageResult<()>,
    ) -> ImmutableStageResult<Self> {
        if config.prefix_len >= IMMUTABLE_STAGE_MAX_KEY_BYTES
            || limits.max_cached_records == 0
            || limits.max_cached_records > 65_536
            || limits.max_active == 0
            || limits.max_active > limits.max_cached_records
            || limits.max_active > 1024
            || limits.max_concurrent_io == 0
            || limits.max_concurrent_io > 64
        {
            return Err(ImmutableStageError::Invalid("invalid staging limits"));
        }
        Self::check_root(config)?;
        // Existing engine namespaces may resume a valid empty database under
        // the exclusive preflight token, but must never recreate a lost DB.
        let engine_config = EngineConfig {
            path: config.path.clone(),
            create: config.create && !config.path.exists(),
            prefix_len: config.prefix_len,
        };
        let engine = Engine::open_staging(&engine_config)?;
        hook(StageOpenPoint::AfterEngineOpen, &engine)?;
        // Identity bootstrapping shares this exact MetaStore and must complete
        // before returning any data/admission interface to the caller.
        let scopes = engine.ec_scope_registry().map_err(|error| {
            ImmutableStageError::OutcomeUnknown(format!("EC scope bootstrap: {error}"))
        })?;
        scopes
            .confirm_staging_identity(config.prefix_len)
            .map_err(|error| {
                ImmutableStageError::OutcomeUnknown(format!(
                    "EC staging identity confirmation: {error}"
                ))
            })?;
        hook(StageOpenPoint::AfterJointProvision, &engine)?;
        let mut legacy = engine.meta_store.iterator();
        legacy.seek([MetaKey::WRITING_CHUNK_KEY_PREFIX])?;
        if legacy
            .key()
            .is_some_and(|key| key.first() == Some(&MetaKey::WRITING_CHUNK_KEY_PREFIX))
        {
            return Err(ImmutableStageError::Corrupt(
                "legacy writing records in V2 staging engine",
            ));
        }
        drop(legacy);
        let mut registry = StageRegistry::default();
        let mut positions = HashSet::new();
        engine
            .meta_store
            .iterator()
            .iterate([STAGE_PREFIX], |key, value| {
                let key = &key[1..];
                if key.len() <= config.prefix_len || key.len() > IMMUTABLE_STAGE_MAX_KEY_BYTES {
                    return Err(Error::MetaError("invalid recovered stage key".into()));
                }
                let record = StageRecord::decode(key, value)?;
                let actual = engine.meta_store.get_chunk_meta(key)?;
                let reserved = engine
                    .meta_store
                    .stage_get_exact(&stage_position_key(record.pos))?;
                let chunk = match record.state {
                    ImmutableStageState::Active => {
                        if actual.is_some()
                            || reserved.as_deref() != Some(stage_key(key).as_slice())
                            || !positions.insert(record.pos)
                            || registry.active >= limits.max_active
                        {
                            return Err(Error::MetaError(
                                "inconsistent active stage reservation".into(),
                            ));
                        }
                        Self::check_reservation(&engine, key, &record)?;
                        registry.active += 1;
                        let allocator = engine.allocators.select_by_pos(record.pos)?;
                        Some(Arc::new(allocator.reference(record.metadata(), false)))
                    }
                    ImmutableStageState::Sealed => {
                        if actual != Some(record.metadata())
                            || reserved.is_some()
                            || engine
                                .meta_store
                                .stage_get_exact(MetaKey::pos_to_chunk_key(record.pos).as_ref())?
                                .as_deref()
                                != Some(key)
                        {
                            return Err(Error::MetaError(
                                "inconsistent sealed stage metadata".into(),
                            ));
                        }
                        Self::check_allocation(&engine, record.pos)?;
                        None
                    }
                    ImmutableStageState::Aborted => {
                        if actual.is_some()
                            || reserved.as_deref() == Some(stage_key(key).as_slice())
                        {
                            return Err(Error::MetaError(
                                "inconsistent aborted stage metadata".into(),
                            ));
                        }
                        None
                    }
                };
                // Validate all terminal records, but do not retain them in
                // memory. Only Active reservations must own an allocation.
                if chunk.is_some() {
                    registry.slots.insert(
                        key.into(),
                        Arc::new(Mutex::new(StageSlot {
                            record: Some(record),
                            chunk,
                            unknown: true,
                        })),
                    );
                }
                Ok(())
            })?;
        let mut reservations = 0;
        engine
            .meta_store
            .iterator()
            .iterate([STAGE_POSITION_PREFIX], |key, value| {
                if key.len() != 9
                    || value.first() != Some(&STAGE_PREFIX)
                    || value.len() <= 1 + config.prefix_len
                    || value.len() > 1 + IMMUTABLE_STAGE_MAX_KEY_BYTES
                {
                    return Err(Error::MetaError("invalid stage position index".into()));
                }
                let pos = Position(u64::from_be_bytes(key[1..].try_into().unwrap()));
                let Some(slot) = registry.slots.get(&Bytes::from(&value[1..])) else {
                    return Err(Error::MetaError("orphan stage position index".into()));
                };
                let slot = slot.lock().unwrap();
                let record = slot.record.as_ref().unwrap();
                if record.state != ImmutableStageState::Active || record.pos != pos {
                    return Err(Error::MetaError("mismatched stage position index".into()));
                }
                reservations += 1;
                Ok(())
            })?;
        if reservations != registry.active {
            return Err(ImmutableStageError::Corrupt(
                "stage reservation cardinality mismatch",
            ));
        }
        Ok(Self(Arc::new(StageInner {
            engine,
            registry: Mutex::new(registry),
            scopes,
            limits,
            io_in_flight: AtomicUsize::new(0),
            #[cfg(test)]
            fault: Mutex::new(None),
        })))
    }

    fn check_root(config: &EngineConfig) -> ImmutableStageResult<()> {
        if config.path.file_name().and_then(|name| name.to_str())
            != Some(IMMUTABLE_STAGE_ENGINE_DIRECTORY)
        {
            return Err(ImmutableStageError::Invalid(
                "staging requires the isolated V2 engine path",
            ));
        }
        let parent = config
            .path
            .parent()
            .ok_or(ImmutableStageError::Invalid("missing V2 root"))?;
        let parent_meta = std::fs::symlink_metadata(parent).map_err(Self::io_error)?;
        if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
            return Err(ImmutableStageError::Invalid(
                "V2 root must be a real directory",
            ));
        }
        if let Ok(metadata) = std::fs::symlink_metadata(&config.path) {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ImmutableStageError::Invalid(
                    "V2 engine must be a real directory",
                ));
            }
        }
        if let Ok(metadata) = std::fs::symlink_metadata(config.path.join("meta")) {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ImmutableStageError::Invalid(
                    "V2 metadata store must be a real directory",
                ));
            }
        }
        Self::check_marker(&parent.join("engine"), IMMUTABLE_STAGE_ROOT_MARKER)?;
        Self::check_marker(&parent.join("engine-ec-v1"), IMMUTABLE_STAGE_V1_BLOCKER)?;
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(Self::io_error)?;
        Ok(())
    }

    fn check_marker(path: &std::path::Path, expected: &[u8]) -> ImmutableStageResult<()> {
        let mut marker = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(Self::io_error)?;
        let metadata = marker.metadata().map_err(Self::io_error)?;
        if !metadata.is_file() || metadata.len() != expected.len() as u64 {
            return Err(ImmutableStageError::Invalid("invalid V2 root blocker"));
        }
        let mut bytes = vec![0u8; expected.len()];
        marker.read_exact(&mut bytes).map_err(Self::io_error)?;
        if bytes != expected {
            return Err(ImmutableStageError::Invalid(
                "V2 marker mismatch; migration is forbidden",
            ));
        }
        marker.sync_all().map_err(Self::io_error)?;
        Ok(())
    }

    fn io_error(error: std::io::Error) -> ImmutableStageError {
        ImmutableStageError::Storage(Error::IoError(error.to_string()))
    }

    pub fn scopes(&self) -> &Arc<crate::ec_scope::EcScopeRegistry> {
        &self.0.scopes
    }

    // Internal bridge binding check. Identity is immutable for the lifetime of
    // this key, including terminal tombstones. This performs no sync barrier.
    pub(crate) fn check_fragment_binding(
        &self,
        key: &[u8],
        id: &[u8; 16],
        length: u32,
        checksum: u32,
    ) -> ImmutableStageResult<()> {
        self.check_key(key)?;
        let slot = self.slot(key)?;
        let slot = slot.lock().map_err(|_| ImmutableStageError::Busy)?;
        let record = slot.record.as_ref().ok_or_else(|| {
            ImmutableStageError::OutcomeUnknown("stage reservation not yet confirmed".into())
        })?;
        if record.spec.stage_id != *id
            || record.spec.length != length
            || record.spec.checksum != checksum
        {
            return Err(ImmutableStageError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn committed_size(&self, prefix: &[u8]) -> ImmutableStageResult<u64> {
        if prefix.len() != self.0.engine.prefix_len {
            return Err(ImmutableStageError::Invalid("invalid accounting prefix"));
        }
        Ok(self.0.engine.meta_store.query_used_size(prefix)?)
    }

    fn check_key(&self, key: &[u8]) -> ImmutableStageResult<()> {
        if key.len() <= self.0.engine.prefix_len || key.len() > IMMUTABLE_STAGE_MAX_KEY_BYTES {
            return Err(ImmutableStageError::Invalid("invalid immutable stage key"));
        }
        Ok(())
    }

    fn permit(&self) -> ImmutableStageResult<IoPermit<'_>> {
        self.0
            .io_in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < self.0.limits.max_concurrent_io).then_some(current + 1)
            })
            .map_err(|_| ImmutableStageError::Busy)?;
        Ok(IoPermit(&self.0.io_in_flight))
    }

    fn cache_space(registry: &mut StageRegistry, limit: usize) -> ImmutableStageResult<()> {
        if registry.slots.len() < limit {
            return Ok(());
        }
        // Never wait for a per-key lock while holding the registry lock: a
        // terminal transition takes them in the opposite order. Active and
        // unknown held allocations are never eviction candidates.
        let evict = registry.slots.iter().find_map(|(key, slot)| {
            if Arc::strong_count(slot) != 1 {
                return None;
            }
            let guard = slot.try_lock().ok()?;
            let record = guard.record.as_ref()?;
            if guard.chunk.is_none() && record.state != ImmutableStageState::Active {
                Some(key.clone())
            } else {
                None
            }
        });
        if let Some(key) = evict {
            registry.slots.remove(&key);
            Ok(())
        } else {
            Err(ImmutableStageError::Busy)
        }
    }

    fn lookup_slot(&self, key: &[u8]) -> ImmutableStageResult<Option<Arc<Mutex<StageSlot>>>> {
        self.check_key(key)?;
        if let Some(slot) = self
            .0
            .registry
            .lock()
            .unwrap()
            .slots
            .get(&Bytes::from(key))
            .cloned()
        {
            return Ok(Some(slot));
        }
        let record = self.0.engine.meta_store.stage_record(key)?;
        let mut registry = self.0.registry.lock().unwrap();
        // A concurrent Begin may have installed its holder while the lookup
        // was reading RocksDB. Always prefer that serialized runtime slot.
        if let Some(slot) = registry.slots.get(&Bytes::from(key)) {
            return Ok(Some(slot.clone()));
        }
        let Some(record) = record else {
            return Ok(None);
        };
        if record.state == ImmutableStageState::Active {
            return Err(ImmutableStageError::Corrupt(
                "active stage lost its non-evictable holder",
            ));
        }
        Self::cache_space(&mut registry, self.0.limits.max_cached_records)?;
        let slot = Arc::new(Mutex::new(StageSlot {
            record: Some(record),
            chunk: None,
            unknown: true,
        }));
        registry.slots.insert(key.into(), slot.clone());
        Ok(Some(slot))
    }

    fn slot(&self, key: &[u8]) -> ImmutableStageResult<Arc<Mutex<StageSlot>>> {
        self.lookup_slot(key)?.ok_or(ImmutableStageError::Missing)
    }

    fn record_for<'a>(
        slot: &'a StageSlot,
        stage_id: &[u8; 16],
    ) -> ImmutableStageResult<&'a StageRecord> {
        let record = slot.record.as_ref().ok_or_else(|| {
            ImmutableStageError::OutcomeUnknown("initial reservation is still in progress".into())
        })?;
        if &record.spec.stage_id != stage_id {
            return Err(ImmutableStageError::Conflict);
        }
        Ok(record)
    }

    fn status(slot: &StageSlot) -> ImmutableStageStatus {
        let record = slot.record.as_ref().unwrap();
        ImmutableStageStatus {
            stage_id: record.spec.stage_id,
            state: record.state,
            prefix_bytes: record.prefix_bytes(),
            pending_block: record.pending.is_some(),
            revision: record.revision,
            needs_reconcile: slot.unknown,
        }
    }

    fn actual(&self, key: &[u8], slot: &StageSlot) -> ImmutableStageResult<StageRecord> {
        let expected = slot.record.as_ref().ok_or(ImmutableStageError::Missing)?;
        let actual = self
            .0
            .engine
            .meta_store
            .stage_record(key)?
            .ok_or(ImmutableStageError::Corrupt("stage record disappeared"))?;
        if !actual.same_reservation(expected) || actual.revision < expected.revision {
            return Err(ImmutableStageError::Corrupt("stage reservation changed"));
        }
        Ok(actual)
    }

    fn check_allocation(engine: &Engine, pos: Position) -> Result<()> {
        let bits = engine
            .meta_store
            .stage_get_exact(MetaKey::group_bits_key(pos.group_id()).as_ref())?
            .ok_or_else(|| Error::MetaError("stage allocation bitmap missing".into()))?;
        if !GroupState::from(&bits)?.check(pos.index()) {
            return Err(Error::MetaError("stage allocation is not reserved".into()));
        }
        Ok(())
    }

    fn check_reservation(engine: &Engine, key: &[u8], record: &StageRecord) -> Result<()> {
        Self::check_allocation(engine, record.pos)?;
        if engine
            .meta_store
            .stage_get_exact(MetaKey::pos_to_chunk_key(record.pos).as_ref())?
            .is_some()
            || engine
                .meta_store
                .stage_get_exact(&stage_position_key(record.pos))?
                .as_deref()
                != Some(stage_key(key).as_slice())
        {
            return Err(Error::MetaError(
                "stage extent is committed or belongs to another reservation".into(),
            ));
        }
        Ok(())
    }

    fn write_batch(
        &self,
        batch: rocksdb::WriteBatch,
        point: StageWritePoint,
    ) -> ImmutableStageResult<()> {
        #[cfg(not(test))]
        let _ = point;
        #[cfg(test)]
        let fault = {
            let mut fault = self.0.fault.lock().unwrap();
            if fault.as_ref().is_some_and(|fault| fault.point == point) {
                fault.take()
            } else {
                None
            }
        };
        #[cfg(test)]
        if fault.is_some_and(|fault| !fault.after_commit) {
            return Err(ImmutableStageError::OutcomeUnknown(format!(
                "test rejected {point:?} write"
            )));
        }
        self.0
            .engine
            .meta_store
            .write(batch, true)
            .map_err(|error| ImmutableStageError::OutcomeUnknown(error.to_string()))?;
        #[cfg(test)]
        if fault.is_some_and(|fault| fault.after_commit) {
            return Err(ImmutableStageError::OutcomeUnknown(format!(
                "test lost {point:?} confirmation after real commit"
            )));
        }
        Ok(())
    }

    /// Reserve exactly one physical allocation. Terminal records remain on
    /// disk for idempotency; the bounded cache is not a lifetime object quota.
    pub fn begin(
        &self,
        key: &[u8],
        spec: &ImmutableStageSpec,
    ) -> ImmutableStageResult<ImmutableStageStatus> {
        self.check_key(key)?;
        spec.validate()?;
        let _permit = self.permit()?;
        let existing = self.lookup_slot(key)?;
        let (slot, inserted) = if let Some(slot) = existing {
            (slot, false)
        } else {
            let mut registry = self.0.registry.lock().unwrap();
            if let Some(slot) = registry.slots.get(&Bytes::from(key)) {
                (slot.clone(), false)
            } else {
                if registry.active >= self.0.limits.max_active {
                    return Err(ImmutableStageError::Busy);
                }
                Self::cache_space(&mut registry, self.0.limits.max_cached_records)?;
                let slot = Arc::new(Mutex::new(StageSlot {
                    record: None,
                    chunk: None,
                    unknown: true,
                }));
                registry.slots.insert(key.into(), slot.clone());
                registry.active += 1;
                (slot, true)
            }
        };
        let mut slot_guard = slot.lock().unwrap();
        if !inserted {
            let record = Self::record_for(&slot_guard, &spec.stage_id)?;
            if record.spec != *spec {
                return Err(ImmutableStageError::Conflict);
            }
            // A durable operation ID with different bytes is rejected even
            // after Sealed/Aborted. Query remains explicitly unconfirmed.
            let actual = self.actual(key, &slot_guard)?;
            if actual != *record {
                slot_guard.unknown = true;
            }
            return Ok(Self::status(&slot_guard));
        }
        let engine = &self.0.engine;
        let allocation = (|| {
            if engine.meta_store.get_chunk_meta(key)?.is_some()
                || engine.meta_store.stage_record(key)?.is_some()
            {
                return Err(ImmutableStageError::Conflict);
            }
            Ok(engine.allocators.allocate(Size::from(spec.length), true)?)
        })();
        let chunk = match allocation {
            Ok(chunk) => Arc::new(chunk),
            Err(error) => {
                let mut registry = self.0.registry.lock().unwrap();
                registry.slots.remove(&Bytes::from(key));
                registry.active -= 1;
                return Err(error);
            }
        };
        let record = StageRecord::new(key, spec.clone(), chunk.meta().pos);
        slot_guard.record = Some(record.clone());
        slot_guard.chunk = Some(chunk.clone());
        // Keep the holder even on a failed/unknown reservation acknowledgment.
        // No fragment bytes have been written at this point.
        Engine::sync_immutable_data(&chunk)?;
        engine.sync_immutable_namespace()?;
        let mut batch = RocksDB::new_write_batch();
        MetaStore::stage_reserve(key, &record, &mut batch)?;
        self.write_batch(batch, StageWritePoint::Reservation)?;
        slot_guard.unknown = false;
        Ok(Self::status(&slot_guard))
    }

    /// Read current metadata only. This never converts an unknown result into
    /// a durable acknowledgment or authorizes reclamation.
    pub fn query(
        &self,
        key: &[u8],
        stage_id: &[u8; 16],
    ) -> ImmutableStageResult<ImmutableStageStatus> {
        let slot = self.slot(key)?;
        let mut slot = slot.lock().unwrap();
        Self::record_for(&slot, stage_id)?;
        let actual = self.actual(key, &slot)?;
        if Some(&actual) != slot.record.as_ref() {
            slot.unknown = true;
        }
        let mut status = Self::status(&slot);
        status.state = actual.state;
        status.prefix_bytes = actual.prefix_bytes();
        status.pending_block = actual.pending.is_some();
        status.revision = actual.revision;
        Ok(status)
    }

    /// Strict sequential blocks with exact-tail sizing. A duplicate block is
    /// accepted only after both its stored digest and actual bytes agree.
    pub fn append(
        &self,
        key: &[u8],
        stage_id: &[u8; 16],
        index: usize,
        bytes: &[u8],
    ) -> ImmutableStageResult<ImmutableStageStatus> {
        let _permit = self.permit()?;
        let slot = self.slot(key)?;
        let mut slot = slot.lock().unwrap();
        let record = Self::record_for(&slot, stage_id)?.clone();
        if slot.unknown {
            return Err(ImmutableStageError::OutcomeUnknown(
                "reconcile stage before retry".into(),
            ));
        }
        if record.state != ImmutableStageState::Active {
            return Err(ImmutableStageError::NotActive);
        }
        if index >= record.spec.block_count()
            || bytes.len() != record.spec.block_len(index)
            || index > record.completed as usize
        {
            return Err(ImmutableStageError::Invalid(
                "append must be the exact next block or an exact duplicate",
            ));
        }
        if self.actual(key, &slot)? != record {
            return Err(ImmutableStageError::Corrupt("stage metadata changed"));
        }
        Self::check_reservation(&self.0.engine, key, &record)?;
        let proof = StageBlockProof::of(bytes);
        let chunk = slot
            .chunk
            .as_ref()
            .ok_or(ImmutableStageError::Corrupt(
                "active stage has no allocation",
            ))?
            .clone();
        let offset = (index * IMMUTABLE_STAGE_BLOCK_BYTES) as u32;
        let mut buffer = StageBuffer::new()?;
        if index < record.completed as usize {
            if record.proofs[index] != proof {
                return Err(ImmutableStageError::Conflict);
            }
            chunk.pread(&mut buffer[..bytes.len()], offset)?;
            if &buffer[..bytes.len()] != bytes {
                return Err(ImmutableStageError::Corrupt(
                    "duplicate block differs on disk",
                ));
            }
            return Ok(Self::status(&slot));
        }
        if record.pending.is_some_and(|pending| pending != proof) {
            return Err(ImmutableStageError::Conflict);
        }
        slot.unknown = true;
        let mut next = record;
        if next.pending.is_none() {
            next.pending = Some(proof);
            next.advance_revision()?;
            let mut batch = RocksDB::new_write_batch();
            MetaStore::stage_put_record(key, &next, &mut batch)?;
            self.write_batch(batch, StageWritePoint::Intent)?;
            slot.record = Some(next.clone());
        }
        buffer[..bytes.len()].copy_from_slice(bytes);
        // The short tail is zero padded only to direct-I/O alignment, inside
        // the already reserved allocation. CRC/SHA cover the logical bytes.
        let write_len = bytes.len().next_multiple_of(4096);
        buffer[bytes.len()..write_len].fill(0);
        self.0
            .engine
            .allocators
            .select_by_pos(next.pos)?
            .clusters
            .pwrite(next.pos, &buffer[..write_len], offset)?;
        Engine::sync_immutable_data(&chunk)?;
        next.proofs[index] = proof;
        next.completed += 1;
        next.pending = None;
        next.advance_revision()?;
        let mut batch = RocksDB::new_write_batch();
        MetaStore::stage_put_record(key, &next, &mut batch)?;
        self.write_batch(batch, StageWritePoint::Progress)?;
        slot.record = Some(next);
        slot.unknown = false;
        Ok(Self::status(&slot))
    }

    fn verify_prefix(chunk: &Chunk, record: &StageRecord) -> ImmutableStageResult<u32> {
        let mut buffer = StageBuffer::new()?;
        let mut crc = 0;
        for index in 0..record.completed as usize {
            let len = record.proofs[index].length as usize;
            chunk.pread(
                &mut buffer[..len],
                (index * IMMUTABLE_STAGE_BLOCK_BYTES) as u32,
            )?;
            if StageBlockProof::of(&buffer[..len]) != record.proofs[index] {
                return Err(ImmutableStageError::Corrupt("stage block proof mismatch"));
            }
            crc = crc32c::crc32c_append(crc, &buffer[..len]);
        }
        Ok(crc)
    }

    fn publish_cache(&self, key: &[u8], record: &StageRecord) -> ImmutableStageResult<()> {
        let engine = &self.0.engine;
        let mut entry = engine.meta_cache.entry_by_ref(key);
        let meta = record.metadata();
        if engine.meta_store.get_chunk_meta(key)? != Some(meta.clone()) {
            return Err(ImmutableStageError::Corrupt(
                "sealed metadata is not authoritative",
            ));
        }
        Self::check_allocation(engine, record.pos)?;
        if engine
            .meta_store
            .stage_get_exact(MetaKey::pos_to_chunk_key(record.pos).as_ref())?
            .as_deref()
            != Some(key)
            || engine
                .meta_store
                .stage_get_exact(&stage_position_key(record.pos))?
                .is_some()
        {
            return Err(ImmutableStageError::Corrupt(
                "sealed allocation index differs",
            ));
        }
        if let Some(chunk) = entry.get() {
            if chunk.meta() != &meta {
                return Err(ImmutableStageError::Corrupt(
                    "sealed cache identity differs",
                ));
            }
        } else {
            let chunk = engine
                .allocators
                .select_by_pos(meta.pos)?
                .reference(meta, false);
            entry.insert(Arc::new(chunk));
        }
        Ok(())
    }

    fn finish_terminal(&self, slot: &mut StageSlot) {
        // The reference is released only after a confirmed terminal write or
        // successful reconciliation. There is at most one holder per stage.
        if slot.chunk.take().is_some() {
            self.0.registry.lock().unwrap().active -= 1;
        }
    }

    /// Validate the exact authoritative state and completed prefix, then sync
    /// data, directory reachability, and WAL in that order. Pending data is not
    /// promoted: the sender must resend its bound bytes before progress moves.
    pub fn reconcile(
        &self,
        key: &[u8],
        stage_id: &[u8; 16],
    ) -> ImmutableStageResult<ImmutableStageStatus> {
        let _permit = self.permit()?;
        let slot = self.slot(key)?;
        let mut slot = slot.lock().unwrap();
        Self::record_for(&slot, stage_id)?;
        self.reconcile_locked(key, &mut slot)
    }

    fn reconcile_locked(
        &self,
        key: &[u8],
        slot: &mut StageSlot,
    ) -> ImmutableStageResult<ImmutableStageStatus> {
        slot.unknown = true;
        let actual = self.0.engine.meta_store.stage_record(key)?;
        let record = if let Some(actual) = actual {
            if !actual.same_reservation(slot.record.as_ref().unwrap())
                || actual.revision < slot.record.as_ref().unwrap().revision
            {
                return Err(ImmutableStageError::Corrupt(
                    "reconciliation identity mismatch",
                ));
            }
            actual
        } else {
            let candidate = slot.record.as_ref().unwrap();
            if candidate.revision != 1
                || candidate.completed != 0
                || candidate.pending.is_some()
                || slot.chunk.is_none()
            {
                return Err(ImmutableStageError::Corrupt(
                    "missing durable stage after progress",
                ));
            }
            // A failed initial reservation may not be visible. Reassert this
            // same held position; do not allocate a replacement or release it.
            let owner = self
                .0
                .engine
                .meta_store
                .stage_get_exact(&stage_position_key(candidate.pos))?;
            if self.0.engine.meta_store.get_chunk_meta(key)?.is_some()
                || self
                    .0
                    .engine
                    .meta_store
                    .stage_get_exact(MetaKey::pos_to_chunk_key(candidate.pos).as_ref())?
                    .is_some()
                || owner
                    .as_deref()
                    .is_some_and(|owner| owner != stage_key(key).as_slice())
            {
                return Err(ImmutableStageError::Corrupt(
                    "cannot reassert a conflicting reservation",
                ));
            }
            let chunk = slot.chunk.as_ref().unwrap();
            Engine::sync_immutable_data(chunk)?;
            self.0.engine.sync_immutable_namespace()?;
            let mut batch = RocksDB::new_write_batch();
            MetaStore::stage_reserve(key, candidate, &mut batch)?;
            self.write_batch(batch, StageWritePoint::Reservation)?;
            candidate.clone()
        };
        match record.state {
            ImmutableStageState::Active => {
                if self.0.engine.meta_store.get_chunk_meta(key)?.is_some()
                    || self
                        .0
                        .engine
                        .meta_store
                        .stage_get_exact(&stage_position_key(record.pos))?
                        .as_deref()
                        != Some(stage_key(key).as_slice())
                {
                    return Err(ImmutableStageError::Corrupt(
                        "invalid active reservation during reconciliation",
                    ));
                }
                Self::check_reservation(&self.0.engine, key, &record)?;
                let chunk = slot
                    .chunk
                    .as_ref()
                    .ok_or(ImmutableStageError::Corrupt("lost reserved holder"))?;
                Self::verify_prefix(chunk, &record)?;
                Engine::sync_immutable_data(chunk)?;
            }
            ImmutableStageState::Sealed => {
                if self
                    .0
                    .engine
                    .meta_store
                    .stage_get_exact(&stage_position_key(record.pos))?
                    .is_some()
                {
                    return Err(ImmutableStageError::Corrupt(
                        "sealed object retains a staging index",
                    ));
                }
                self.publish_cache(key, &record)?;
                let chunk = self
                    .0
                    .engine
                    .get_immutable(key)?
                    .ok_or(ImmutableStageError::Missing)?;
                if Self::verify_prefix(&chunk, &record)? != record.spec.checksum {
                    return Err(ImmutableStageError::Corrupt("sealed fragment CRC mismatch"));
                }
                Engine::sync_immutable_data(&chunk)?;
            }
            ImmutableStageState::Aborted => {
                if self.0.engine.meta_store.get_chunk_meta(key)?.is_some()
                    || self
                        .0
                        .engine
                        .meta_store
                        .stage_get_exact(&stage_position_key(record.pos))?
                        .as_deref()
                        == Some(stage_key(key).as_slice())
                {
                    return Err(ImmutableStageError::Corrupt(
                        "aborted state still owns persistent data",
                    ));
                }
            }
        }
        self.0.engine.sync_immutable_namespace()?;
        self.0
            .engine
            .meta_store
            .sync_wal()
            .map_err(|error| ImmutableStageError::OutcomeUnknown(error.to_string()))?;
        slot.record = Some(record);
        slot.unknown = false;
        if slot.record.as_ref().unwrap().state != ImmutableStageState::Active {
            self.finish_terminal(slot);
        }
        Ok(Self::status(&slot))
    }

    /// Atomically install final metadata and its terminal staging record.
    /// add_chunk_mut (including used-size accounting) runs at most once.
    pub fn seal(&self, key: &[u8], stage_id: &[u8; 16]) -> ImmutableStageResult<ChunkMeta> {
        let _permit = self.permit()?;
        let slot = self.slot(key)?;
        let mut slot = slot.lock().unwrap();
        let mut record = Self::record_for(&slot, stage_id)?.clone();
        if slot.unknown {
            if record.state == ImmutableStageState::Sealed && slot.chunk.is_none() {
                // A terminal cache miss is never a new commit. Reconfirm its
                // bytes/barriers here instead of replaying additive accounting.
                self.reconcile_locked(key, &mut slot)?;
                record = slot.record.as_ref().unwrap().clone();
            } else {
                return Err(ImmutableStageError::OutcomeUnknown(
                    "reconcile stage before sealing".into(),
                ));
            }
        }
        if self.actual(key, &slot)? != record {
            return Err(ImmutableStageError::Corrupt("seal metadata changed"));
        }
        if record.state == ImmutableStageState::Sealed {
            self.publish_cache(key, &record)?;
            return Ok(record.metadata());
        }
        if record.state != ImmutableStageState::Active
            || record.prefix_bytes() != record.spec.length
            || record.pending.is_some()
        {
            return Err(ImmutableStageError::NotActive);
        }
        Self::check_reservation(&self.0.engine, key, &record)?;
        let chunk = slot
            .chunk
            .as_ref()
            .ok_or(ImmutableStageError::Corrupt("seal has no reservation"))?
            .clone();
        if Self::verify_prefix(&chunk, &record)? != record.spec.checksum {
            return Err(ImmutableStageError::Corrupt(
                "fragment CRC differs from begin intent",
            ));
        }
        slot.unknown = true;
        Engine::sync_immutable_data(&chunk)?;
        self.0.engine.sync_immutable_namespace()?;
        let engine = &self.0.engine;
        let mut entry = engine.meta_cache.entry_by_ref(key);
        if entry.get().is_some() || engine.meta_store.get_chunk_meta(key)?.is_some() {
            return Err(ImmutableStageError::Corrupt(
                "seal destination already exists",
            ));
        }
        record.state = ImmutableStageState::Sealed;
        record.advance_revision()?;
        let mut batch = RocksDB::new_write_batch();
        engine
            .meta_store
            .add_chunk_mut(key, &record.metadata(), &mut batch)?;
        MetaStore::stage_put_record(key, &record, &mut batch)?;
        batch.delete(stage_position_key(record.pos));
        self.write_batch(batch, StageWritePoint::Seal)?;
        drop(entry);
        self.publish_cache(key, &record)?;
        slot.record = Some(record.clone());
        slot.unknown = false;
        self.finish_terminal(&mut slot);
        Ok(record.metadata())
    }

    /// Internal cancellation after trusted scope admission has been fenced and
    /// all admitted jobs drained. A clock expiry is not such a fence. No public
    /// RPC/physical-delete authorization is provided by this component.
    pub(crate) fn cancel_after_fence(
        &self,
        key: &[u8],
        stage_id: &[u8; 16],
    ) -> ImmutableStageResult<ImmutableStageStatus> {
        let _permit = self.permit()?;
        let slot = self.slot(key)?;
        let mut slot = slot.lock().unwrap();
        let mut record = Self::record_for(&slot, stage_id)?.clone();
        if slot.unknown {
            if record.state == ImmutableStageState::Aborted && slot.chunk.is_none() {
                self.reconcile_locked(key, &mut slot)?;
                record = slot.record.as_ref().unwrap().clone();
            } else {
                return Err(ImmutableStageError::OutcomeUnknown(
                    "reconcile before cancellation".into(),
                ));
            }
        }
        if self.actual(key, &slot)? != record {
            return Err(ImmutableStageError::Corrupt("cancel metadata changed"));
        }
        if record.state == ImmutableStageState::Aborted {
            return Ok(Self::status(&slot));
        }
        if record.state != ImmutableStageState::Active {
            return Err(ImmutableStageError::NotActive);
        }
        Self::check_reservation(&self.0.engine, key, &record)?;
        if self.0.engine.meta_store.get_chunk_meta(key)?.is_some() {
            return Err(ImmutableStageError::Corrupt(
                "cannot cancel readable metadata",
            ));
        }
        slot.unknown = true;
        record.state = ImmutableStageState::Aborted;
        record.pending = None;
        record.advance_revision()?;
        let mut batch = RocksDB::new_write_batch();
        MetaStore::stage_abort(key, &record, &mut batch)?;
        self.write_batch(batch, StageWritePoint::Abort)?;
        slot.record = Some(record);
        slot.unknown = false;
        self.finish_terminal(&mut slot);
        Ok(Self::status(&slot))
    }

    /// Owned, verified block read; the persistent block digest was computed
    /// from bytes received by this engine. This is not remote authorization.
    pub fn read_sealed_block(
        &self,
        key: &[u8],
        stage_id: &[u8; 16],
        index: usize,
    ) -> ImmutableStageResult<Vec<u8>> {
        let _permit = self.permit()?;
        let slot = self.slot(key)?;
        let slot = slot.lock().unwrap();
        let record = Self::record_for(&slot, stage_id)?;
        if record.state != ImmutableStageState::Sealed || index >= record.spec.block_count() {
            return Err(ImmutableStageError::NotActive);
        }
        if self.actual(key, &slot)? != *record {
            return Err(ImmutableStageError::Corrupt("read stage metadata differs"));
        }
        let chunk = self
            .0
            .engine
            .get_immutable(key)?
            .ok_or(ImmutableStageError::Missing)?;
        if chunk.meta() != &record.metadata() {
            return Err(ImmutableStageError::Corrupt("read chunk identity differs"));
        }
        let len = record.spec.block_len(index);
        let mut buffer = StageBuffer::new()?;
        chunk.pread(
            &mut buffer[..len],
            (index * IMMUTABLE_STAGE_BLOCK_BYTES) as u32,
        )?;
        if StageBlockProof::of(&buffer[..len]) != record.proofs[index] {
            return Err(ImmutableStageError::Corrupt(
                "sealed block checksum mismatch",
            ));
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(len)
            .map_err(|_| ImmutableStageError::Busy)?;
        result.extend_from_slice(&buffer[..len]);
        Ok(result)
    }
}

#[cfg(test)]
#[path = "immutable_stage_tests.rs"]
mod tests;
