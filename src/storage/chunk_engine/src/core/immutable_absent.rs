//! Confirming absence is a separate, irreversible fact, never Collect(Missing).
use super::*;
use crate::ec_scope::{EcScopeRevocation, EcTargetRetirement};
use sha2::{Digest, Sha256};

pub(crate) struct EcStageAbsentClaim {
    pub gc: EcStageGcClaim,
    pub closure_digest: [u8; 32],
    pub scope: EcScopeRevocation,
    pub retirement: Option<EcTargetRetirement>,
}
pub(crate) struct EcStageAbsentReceipt {
    pub claim_id: [u8; 16],
    pub ledger_sha256: [u8; 32],
    pub record_revision: u64,
}
impl ImmutableStagingEngine {
    // Two real reverse-index scans, bounded together by entries and bytes.
    // Exceeding either budget is Busy, never an absence receipt. Other keys
    // may change; this exact key is closed and serialized by its stage slot.
    fn absent_indexes(engine: &Engine, key: &[u8]) -> ImmutableStageResult<()> {
        let mut count=0usize;
        let mut bytes=0usize;
        for prefix in [STAGE_POSITION_PREFIX, MetaKey::POS_TO_CHUNK_KEY_PREFIX] {
            let mut it=engine.meta_store.iterator();
            it.seek([prefix])?;
            while let Some(k)=it.key().filter(|k| k.first()==Some(&prefix)) {
                let v=it.value().ok_or(ImmutableStageError::Corrupt("missing index value"))?;
                count+=1;
                bytes=bytes.saturating_add(k.len()).saturating_add(v.len());
                if count>65536 || bytes>16*1024*1024 { return Err(ImmutableStageError::Busy); }
                let expected=if prefix==STAGE_POSITION_PREFIX {stage_key(key)} else {key.to_vec()};
                if v==expected.as_slice() {return Err(ImmutableStageError::Conflict);}
                it.next();
            }
            it.status()?;
        }
        Ok(())
    }
    pub(super) fn validate_absence_on_open(engine:&Engine, scopes:&crate::ec_scope::EcScopeRegistry)
        -> ImmutableStageResult<()> {
        engine.meta_store.iterator().iterate([STAGE_ABSENT_PREFIX],|key,bytes| {
            let key=&key[1..];
            let r=EcStageAbsentRecord::decode(key,bytes)?;
            if r.target.engine!=scopes.engine_identity() ||
                scopes.load_target(r.target.chain,r.target.target).map_err(|e|Error::MetaError(format!("absence target: {e}")))?!=r.target ||
                engine.meta_store.stage_record(key)?.is_some() || engine.meta_store.get_chunk_meta(key)?.is_some() ||
                engine.meta_store.stage_gc_record(key)?.is_some() {
                return Err(Error::MetaError("absence ledger contradicts recovered state".into()));
            }
            Ok(())
        })?;
        // Normal staging recovery validates its reservation namespace. Each
        // receipt separately scans BOTH reverse namespaces at confirmation.
        engine.meta_store.sync_wal()?;
        Ok(())
    }
    pub(crate) fn confirm_absent_after_close(&self,key:&[u8],c:&EcStageAbsentClaim,query:bool)
        -> ImmutableStageResult<EcStageAbsentReceipt> {
        self.check_key(key)?;
        self.require_gc(&c.gc)?;
        if c.scope.binding.target!=c.gc.target || c.scope.binding.scope!=c.gc.spec.stage_id ||
            c.scope.binding.kind!=crate::ec_scope::EcScopeKind::WriteOperation {
            return Err(ImmutableStageError::Conflict);
        }
        let _permit=self.permit()?;
        self.scopes().confirm_closed_for_absence(c.scope,c.retirement)
            .map_err(|e|ImmutableStageError::OutcomeUnknown(format!("absence closure: {e}")))?;
        let expected=EcStageAbsentRecord::new(key,&c.gc,c.closure_digest)?;
        // Install/find the very same per-key serialization used by Begin and
        // old GC. No registry lock is held while reading or syncing RocksDB.
        let slot={
            let mut r=self.0.registry.lock().unwrap();
            if let Some(slot)=r.slots.get(&Bytes::from(key)) {slot.clone()} else {
                Self::cache_space(&mut r,self.0.limits.max_cached_records)?;
                let slot=Arc::new(Mutex::new(StageSlot {record:None,chunk:None,unknown:false,gc_pending:None}));
                r.slots.insert(key.into(),slot.clone()); slot
            }
        };
        let mut slot=slot.lock().unwrap();
        let engine=&self.0.engine;
        let prior=engine.meta_store.stage_absent_record(key)?;
        if let Some(r)=&prior {if r!=&expected {return Err(ImmutableStageError::Conflict);}}
        if slot.record.is_some() || slot.chunk.is_some() || slot.gc_pending.is_some() ||
            engine.meta_store.stage_record(key)?.is_some() || engine.meta_store.stage_gc_record(key)?.is_some() ||
            engine.meta_store.get_chunk_meta(key)?.is_some() {return Err(ImmutableStageError::Conflict);}
        if prior.is_none() && slot.unknown {return Err(ImmutableStageError::OutcomeUnknown("absence write unconfirmed".into()));}
        if prior.is_none() && query {return Err(ImmutableStageError::Missing);}
        let entry=engine.meta_cache.entry_by_ref(key);
        if entry.get().is_some() {return Err(ImmutableStageError::Conflict);}
        Self::absent_indexes(engine,key)?;
        // An unknown write remains non-evictable. Query may confirm an exact
        // cache-visible record only after another real WAL barrier succeeds.
        if prior.is_none() {
            slot.unknown=true;
            let mut batch=RocksDB::new_write_batch();
            batch.put(stage_absent_key(key),expected.encode());
            self.write_batch(batch,StageWritePoint::Absent)?;
        }
        engine.meta_store.sync_wal()?;
        slot.unknown=false;
        drop(entry);
        Ok(EcStageAbsentReceipt {claim_id:expected.claim_id,
            ledger_sha256:Sha256::digest(expected.encode()).into(),record_revision:1})
    }
}
