//! Internal exact GC for known stages. No RPC or authorization is exported.
//! Metadata format 3 and explicit root blockers are mandatory; V2 is unchanged.
use super::*;
use sha2::{Digest, Sha256};

pub(crate) const IMMUTABLE_GC_ROOT_MARKER: &[u8] = b"3FS_EC_ENGINE_ROOT_V3_GC\n";
pub(crate) const IMMUTABLE_GC_V1_BLOCKER: &[u8] = b"3FS_EC_ENGINE_V1_BLOCKED_BY_V3_GC\n";

/// Retained while a metadata result is unknown. Active stages already retain
/// their allocation in StageSlot::chunk; Sealed stages need this extra holder.
/// It is not counted as another Active allocation.
pub(super) struct StageGcPending {
    ledger: EcStageGcRecord,
    before: StageRecord,
    _sealed_holder: Option<ChunkArc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EcStageGcReceipt {
    pub claim_id: [u8; 16],
    pub ledger_sha256: [u8; 32],
    pub terminal_revision: u64,
}

impl ImmutableStagingEngine {
    pub(crate) fn actual_disk_format(&self) -> u16 {
        match self.0.format {
            EcStagingFormat::V2 => 2,
            EcStagingFormat::ExactGc => 3,
        }
    }

    /// Opens a new, explicitly marked GC-capable namespace. This does not
    /// upgrade a V2 store, authorize a claim, or expose a Storage wire method.
    pub(crate) fn open_gc(
        config: &EngineConfig,
        limits: ImmutableStageLimits,
    ) -> ImmutableStageResult<Self> {
        Self::open_format_with_hook(config, limits, EcStagingFormat::ExactGc, |_, _| Ok(()))
    }

    pub(super) fn require_gc(&self, claim: &EcStageGcClaim) -> ImmutableStageResult<()> {
        if self.0.format != EcStagingFormat::ExactGc {
            return Err(ImmutableStageError::Invalid(
                "exact GC requires explicit disk format 3",
            ));
        }
        claim.validate()?;
        let actual = self
            .0
            .scopes
            .load_target(claim.target.chain, claim.target.target)
            .map_err(|error| {
                ImmutableStageError::OutcomeUnknown(format!("GC target confirmation: {error}"))
            })?;
        if actual != claim.target {
            return Err(ImmutableStageError::Conflict);
        }
        Ok(())
    }

    fn check_gc_terminal(
        engine: &Engine,
        key: &[u8],
        ledger: &EcStageGcRecord,
    ) -> Result<StageRecord> {
        let terminal = engine
            .meta_store
            .stage_record(key)?
            .ok_or_else(|| Error::MetaError("GC ledger without stage tombstone".into()))?;
        if !ledger.validates_terminal(key, &terminal)?
            || engine.meta_store.get_chunk_meta(key)?.is_some()
            || engine
                .meta_store
                .stage_get_exact(&stage_position_key(terminal.pos))?
                .as_deref()
                == Some(stage_key(key).as_slice())
            || engine
                .meta_store
                .stage_get_exact(MetaKey::pos_to_chunk_key(terminal.pos).as_ref())?
                .as_deref()
                == Some(key)
        {
            return Err(Error::MetaError(
                "GC ledger contradicts exact stage/index state".into(),
            ));
        }
        // Another allocation may have reused this position. Do not demand an
        // empty bitmap/index, and never release or mutate that later owner.
        Ok(terminal)
    }

    pub(super) fn validate_gc_ledger_on_open(
        engine: &Engine,
        scopes: &crate::ec_scope::EcScopeRegistry,
    ) -> ImmutableStageResult<()> {
        engine
            .meta_store
            .iterator()
            .iterate([STAGE_GC_PREFIX], |key, bytes| {
                let key = &key[1..];
                if key.len() <= engine.prefix_len || key.len() > IMMUTABLE_STAGE_MAX_KEY_BYTES {
                    return Err(Error::MetaError("invalid exact GC key".into()));
                }
                let ledger = EcStageGcRecord::decode(key, bytes)?;
                if ledger.target.engine != scopes.engine_identity() {
                    return Err(Error::MetaError(
                        "GC ledger engine identity mismatch".into(),
                    ));
                }
                let target = scopes
                    .load_target(ledger.target.chain, ledger.target.target)
                    .map_err(|error| Error::MetaError(format!("GC target restore: {error}")))?;
                if target != ledger.target {
                    return Err(Error::MetaError(
                        "GC ledger target incarnation mismatch".into(),
                    ));
                }
                Self::check_gc_terminal(engine, key, &ledger)?;
                Ok(())
            })?;
        // Startup has no pre-crash outstanding in-memory references. Pair
        // confirmation and this WAL barrier precede all data APIs.
        engine.meta_store.sync_wal()?;
        Ok(())
    }

    fn finish_gc_locked(
        &self,
        key: &[u8],
        slot: &mut StageSlot,
        ledger: &EcStageGcRecord,
    ) -> ImmutableStageResult<EcStageGcReceipt> {
        self.finish_gc_locked_with(key, slot, ledger, |store| store.sync_wal())
    }

    fn finish_gc_locked_with(
        &self,
        key: &[u8],
        slot: &mut StageSlot,
        ledger: &EcStageGcRecord,
        sync: impl FnOnce(&MetaStore) -> Result<()>,
    ) -> ImmutableStageResult<EcStageGcReceipt> {
        let terminal = Self::check_gc_terminal(&self.0.engine, key, ledger)?;
        if let Some(pending) = &slot.gc_pending {
            if pending.ledger != *ledger {
                return Err(ImmutableStageError::Conflict);
            }
        }
        // Until this succeeds, no reference is released and no success is
        // returned, even when a failed write is visible through RocksDB cache.
        sync(&self.0.engine.meta_store)?;
        let mut entry = self.0.engine.meta_cache.entry_by_ref(key);
        if let Some(chunk) = entry.get() {
            if chunk.meta().pos != ledger.position
                || chunk.meta().etag.as_slice() != terminal.spec.etag.as_slice()
                || chunk.meta().len != terminal.spec.length
                || chunk.meta().checksum != terminal.spec.checksum
            {
                return Err(ImmutableStageError::Corrupt("GC cached allocation differs"));
            }
        }
        entry.remove();
        drop(entry);
        slot.record = Some(terminal);
        slot.unknown = false;
        // Active's held allocation is counted once. Sealed's pending holder is
        // separate and must not decrement StageRegistry::active.
        self.finish_terminal(slot);
        slot.gc_pending = None;
        Ok(EcStageGcReceipt {
            claim_id: ledger.claim_id,
            ledger_sha256: Sha256::digest(ledger.encode()).into(),
            terminal_revision: ledger.terminal_revision,
        })
    }

    /// Execute a previously authenticated, exact Meta claim. This crate-only
    /// function does not infer authority from claim fields, expiry, or one
    /// scope's Drained state. The future caller must establish all historical
    /// allocation protections are closed before entry. Missing is an error.
    pub(crate) fn collect_known_stage_after_claim(
        &self,
        key: &[u8],
        claim: &EcStageGcClaim,
    ) -> ImmutableStageResult<EcStageGcReceipt> {
        self.check_key(key)?;
        self.require_gc(claim)?;
        if self.0.engine.meta_store.stage_absent_record(key)?.is_some() {
            return Err(ImmutableStageError::Conflict);
        }
        let _permit = self.permit()?;
        let handle = self.slot(key)?;
        let mut slot = handle.lock().map_err(|_| ImmutableStageError::Busy)?;
        if let Some(ledger) = self.0.engine.meta_store.stage_gc_record(key)? {
            if !ledger.matches(key, claim) {
                return Err(ImmutableStageError::Conflict);
            }
            return self.finish_gc_locked(key, &mut slot, &ledger);
        }
        if let Some(pending) = &slot.gc_pending {
            if !pending.ledger.matches(key, claim) {
                return Err(ImmutableStageError::Conflict);
            }
            // An uncertain atomic batch either left the complete ledger or
            // left exactly its pre-state. Mixed state is corruption, not a
            // reason to repeat a decrement or reclaim some other position.
            if self.0.engine.meta_store.stage_record(key)?.as_ref() != Some(&pending.before) {
                return Err(ImmutableStageError::Corrupt(
                    "GC batch has no ledger but changed stage",
                ));
            }
            self.0.engine.meta_store.sync_wal()?;
        } else if slot.unknown {
            self.reconcile_locked(key, &mut slot)?;
        }
        let before = self.actual(key, &slot)?;
        if before.spec != claim.spec || slot.record.as_ref() != Some(&before) {
            return Err(ImmutableStageError::Conflict);
        }
        let engine = &self.0.engine;
        let held = match before.state {
            ImmutableStageState::Active => {
                Self::check_reservation(engine, key, &before)?;
                if slot.chunk.is_none() || engine.meta_store.get_chunk_meta(key)?.is_some() {
                    return Err(ImmutableStageError::Corrupt(
                        "GC Active reservation is not exclusive",
                    ));
                }
                None
            }
            ImmutableStageState::Sealed => {
                self.publish_cache(key, &before)?;
                let chunk = engine
                    .get_immutable(key)?
                    .ok_or(ImmutableStageError::Missing)?;
                if chunk.meta() != &before.metadata() {
                    return Err(ImmutableStageError::Corrupt("GC sealed metadata mismatch"));
                }
                Some(chunk)
            }
            ImmutableStageState::Aborted => {
                if engine.meta_store.get_chunk_meta(key)?.is_some()
                    || engine
                        .meta_store
                        .stage_get_exact(&stage_position_key(before.pos))?
                        .as_deref()
                        == Some(stage_key(key).as_slice())
                    || engine
                        .meta_store
                        .stage_get_exact(MetaKey::pos_to_chunk_key(before.pos).as_ref())?
                        .as_deref()
                        == Some(key)
                {
                    return Err(ImmutableStageError::Corrupt(
                        "GC aborted record still owns storage",
                    ));
                }
                None
            }
        };
        let mut terminal = before.clone();
        terminal.state = ImmutableStageState::Aborted;
        terminal.pending = None;
        terminal.revision = terminal
            .revision
            .checked_add(1)
            .ok_or(ImmutableStageError::Corrupt("GC stage revision overflow"))?;
        let ledger = EcStageGcRecord::new(key, claim, &before, &terminal)?;
        let mut batch = RocksDB::new_write_batch();
        match before.state {
            ImmutableStageState::Active => MetaStore::stage_abort(key, &terminal, &mut batch)?,
            ImmutableStageState::Sealed => {
                // Exactly once: remove_mut releases bitmap and subtracts the
                // committed size. Never also call stage_abort for this state.
                engine
                    .meta_store
                    .remove_mut(key, &before.metadata(), &mut batch)?;
                MetaStore::stage_put_record(key, &terminal, &mut batch)?;
            }
            ImmutableStageState::Aborted => {
                MetaStore::stage_put_record(key, &terminal, &mut batch)?
            }
        }
        batch.put(stage_gc_key(key), ledger.encode());
        slot.gc_pending = Some(StageGcPending {
            ledger: ledger.clone(),
            before,
            _sealed_holder: held,
        });
        slot.unknown = true;
        // Keep the cached reference and both pending/Active holders across any
        // exception or unknown acknowledgment. All data methods share this slot.
        let entry = engine.meta_cache.entry_by_ref(key);
        self.write_batch(batch, StageWritePoint::ExactGc)?;
        drop(entry);
        self.finish_gc_locked(key, &mut slot, &ledger)
    }

    /// Query performs no new deletion. An exact durable ledger plus a fresh
    /// WAL confirmation is required; an absent ledger is never Deleted.
    pub(crate) fn query_known_stage_gc(
        &self,
        key: &[u8],
        claim: &EcStageGcClaim,
    ) -> ImmutableStageResult<EcStageGcReceipt> {
        self.check_key(key)?;
        self.require_gc(claim)?;
        if self.0.engine.meta_store.stage_absent_record(key)?.is_some() {
            return Err(ImmutableStageError::Conflict);
        }
        let _permit = self.permit()?;
        let handle = self.slot(key)?;
        let mut slot = handle.lock().map_err(|_| ImmutableStageError::Busy)?;
        let Some(ledger) = self.0.engine.meta_store.stage_gc_record(key)? else {
            return Err(if slot.gc_pending.is_some() {
                ImmutableStageError::OutcomeUnknown("GC result is not confirmed".into())
            } else {
                ImmutableStageError::Missing
            });
        };
        if !ledger.matches(key, claim) {
            return Err(ImmutableStageError::Conflict);
        }
        self.finish_gc_locked(key, &mut slot, &ledger)
    }
}

#[cfg(test)]
#[path = "immutable_gc_tests.rs"]
mod tests;
