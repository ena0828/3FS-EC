//! Versioned, bounded records for immutable staging in the engine's RocksDB.
//! These records deliberately do not use the legacy writing-chunk log.

use crate::*;
use derse::Serialize;
use sha2::{Digest, Sha256};

pub const IMMUTABLE_STAGE_BLOCK_BYTES: usize = 64 * 1024;
pub const IMMUTABLE_STAGE_MAX_BLOCKS: usize = 16;
pub const IMMUTABLE_STAGE_MAX_BYTES: usize =
    IMMUTABLE_STAGE_BLOCK_BYTES * IMMUTABLE_STAGE_MAX_BLOCKS;
pub const IMMUTABLE_STAGE_MAX_KEY_BYTES: usize = 256;

pub(crate) const STAGE_PREFIX: u8 = 13;
pub(crate) const STAGE_POSITION_PREFIX: u8 = 14;
const RECORD_SIZE: usize = 1024;
const HASH_OFFSET: usize = RECORD_SIZE - 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableStageSpec {
    pub stage_id: [u8; 16],
    pub length: u32,
    /// Standard CRC32C, not the complemented ChecksumInfo value.
    pub checksum: u32,
    pub chain_ver: u32,
    pub last_request_id: u64,
    pub last_client_low: u64,
    pub last_client_high: u64,
    /// Opaque immutable identity, not a content digest or authorization proof.
    pub etag: Vec<u8>,
}

impl ImmutableStageSpec {
    pub fn validate(&self) -> Result<()> {
        if self.stage_id == [0; 16]
            || self.length as usize > IMMUTABLE_STAGE_MAX_BYTES
            || self.etag.is_empty()
            || self.etag.len() > MAX_IMMUTABLE_ETAG_LEN
            || (self.length == 0 && self.checksum != 0)
        {
            return Err(Error::InvalidArg(
                "invalid immutable stage specification".into(),
            ));
        }
        Ok(())
    }

    pub fn block_count(&self) -> usize {
        (self.length as usize).div_ceil(IMMUTABLE_STAGE_BLOCK_BYTES)
    }

    pub(crate) fn block_len(&self, index: usize) -> usize {
        (self.length as usize)
            .saturating_sub(index * IMMUTABLE_STAGE_BLOCK_BYTES)
            .min(IMMUTABLE_STAGE_BLOCK_BYTES)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmutableStageState {
    Active,
    Sealed,
    Aborted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StageBlockProof {
    pub length: u32,
    pub checksum: u32,
    pub sha256: [u8; 32],
}

impl StageBlockProof {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len() as u32,
            checksum: crc32c::crc32c(bytes),
            sha256: Sha256::digest(bytes).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StageRecord {
    pub spec: ImmutableStageSpec,
    pub state: ImmutableStageState,
    pub pos: Position,
    pub timestamp: u64,
    pub revision: u64,
    pub completed: u8,
    pub proofs: [StageBlockProof; IMMUTABLE_STAGE_MAX_BLOCKS],
    /// Durable intent fixes the next block's bytes before any data write.
    pub pending: Option<StageBlockProof>,
    pub key_sha256: [u8; 32],
}

impl StageRecord {
    pub fn new(key: &[u8], spec: ImmutableStageSpec, pos: Position) -> Self {
        Self {
            spec,
            state: ImmutableStageState::Active,
            pos,
            timestamp: ChunkMeta::now(),
            revision: 1,
            completed: 0,
            proofs: [StageBlockProof::default(); IMMUTABLE_STAGE_MAX_BLOCKS],
            pending: None,
            key_sha256: Sha256::digest(key).into(),
        }
    }

    pub fn prefix_bytes(&self) -> u32 {
        self.proofs[..self.completed as usize]
            .iter()
            .map(|proof| proof.length)
            .sum()
    }

    pub fn metadata(&self) -> ChunkMeta {
        ChunkMeta {
            pos: self.pos,
            chain_ver: self.spec.chain_ver,
            chunk_ver: 1,
            len: self.spec.length,
            checksum: self.spec.checksum,
            timestamp: self.timestamp,
            last_request_id: self.spec.last_request_id,
            last_client_low: self.spec.last_client_low,
            last_client_high: self.spec.last_client_high,
            etag: self.spec.etag.as_slice().into(),
            uncommitted: self.state != ImmutableStageState::Sealed,
        }
    }

    pub fn advance_revision(&mut self) -> Result<()> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::MetaError("immutable stage revision exhausted".into()))?;
        Ok(())
    }

    pub fn same_reservation(&self, other: &Self) -> bool {
        self.spec == other.spec
            && self.pos == other.pos
            && self.timestamp == other.timestamp
            && self.key_sha256 == other.key_sha256
    }

    pub fn validate(&self, key: &[u8]) -> Result<()> {
        self.spec.validate()?;
        let key_hash: [u8; 32] = Sha256::digest(key).into();
        let capacity = self.pos.chunk_size();
        if key.is_empty()
            || key.len() > IMMUTABLE_STAGE_MAX_KEY_BYTES
            || self.key_sha256 != key_hash
            || self.revision == 0
            || !capacity.is_power_of_two()
            || capacity < CHUNK_SIZE_SMALL
            || capacity.0 > IMMUTABLE_STAGE_MAX_BYTES as u64
            || capacity.0 < u64::from(self.spec.length)
            || self.completed as usize > self.spec.block_count()
        {
            return Err(Error::MetaError("invalid immutable stage record".into()));
        }
        for (index, proof) in self.proofs.iter().enumerate() {
            if index < self.completed as usize {
                if proof.length as usize != self.spec.block_len(index) {
                    return Err(Error::MetaError("invalid completed stage block".into()));
                }
            } else if *proof != StageBlockProof::default() {
                return Err(Error::MetaError("noncanonical unused stage block".into()));
            }
        }
        if let Some(proof) = self.pending {
            if self.state != ImmutableStageState::Active
                || self.completed as usize >= self.spec.block_count()
                || proof.length as usize != self.spec.block_len(self.completed as usize)
            {
                return Err(Error::MetaError("invalid pending stage block".into()));
            }
        }
        if self.state == ImmutableStageState::Sealed
            && (self.completed as usize != self.spec.block_count() || self.pending.is_some())
        {
            return Err(Error::MetaError("incomplete sealed stage".into()));
        }
        Ok(())
    }

    pub fn encode(&self, key: &[u8]) -> Result<[u8; RECORD_SIZE]> {
        self.validate(key)?;
        let mut out = [0u8; RECORD_SIZE];
        out[..8].copy_from_slice(b"3FSTAGE2");
        out[8] = match self.state {
            ImmutableStageState::Active => 1,
            ImmutableStageState::Sealed => 2,
            ImmutableStageState::Aborted => 3,
        };
        out[9] = self.completed;
        out[10] = u8::from(self.pending.is_some());
        out[11] = self.spec.etag.len() as u8;
        out[12..20].copy_from_slice(&self.revision.to_be_bytes());
        out[20..28].copy_from_slice(&self.pos.0.to_be_bytes());
        out[28..36].copy_from_slice(&self.timestamp.to_be_bytes());
        out[36..40].copy_from_slice(&self.spec.length.to_be_bytes());
        out[40..44].copy_from_slice(&self.spec.checksum.to_be_bytes());
        out[44..48].copy_from_slice(&self.spec.chain_ver.to_be_bytes());
        out[48..56].copy_from_slice(&self.spec.last_request_id.to_be_bytes());
        out[56..64].copy_from_slice(&self.spec.last_client_low.to_be_bytes());
        out[64..72].copy_from_slice(&self.spec.last_client_high.to_be_bytes());
        out[72..88].copy_from_slice(&self.spec.stage_id);
        out[88..88 + self.spec.etag.len()].copy_from_slice(&self.spec.etag);
        out[152..184].copy_from_slice(&self.key_sha256);
        let pending = self.pending.unwrap_or_default();
        for (index, proof) in self
            .proofs
            .iter()
            .chain(std::iter::once(&pending))
            .enumerate()
        {
            let offset = 184 + 40 * index;
            out[offset..offset + 4].copy_from_slice(&proof.length.to_be_bytes());
            out[offset + 4..offset + 8].copy_from_slice(&proof.checksum.to_be_bytes());
            out[offset + 8..offset + 40].copy_from_slice(&proof.sha256);
        }
        let hash = Sha256::digest(&out[..HASH_OFFSET]);
        out[HASH_OFFSET..].copy_from_slice(&hash);
        Ok(out)
    }

    pub fn decode(key: &[u8], bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECORD_SIZE || &bytes[..8] != b"3FSTAGE2" {
            return Err(Error::MetaError(
                "invalid stage record length or format".into(),
            ));
        }
        let hash: [u8; 32] = Sha256::digest(&bytes[..HASH_OFFSET]).into();
        if hash.as_slice() != &bytes[HASH_OFFSET..]
            || bytes[10] > 1
            || bytes[11] == 0
            || bytes[11] as usize > MAX_IMMUTABLE_ETAG_LEN
            || bytes[88 + bytes[11] as usize..152]
                .iter()
                .any(|byte| *byte != 0)
            || bytes[864..HASH_OFFSET].iter().any(|byte| *byte != 0)
        {
            return Err(Error::MetaError(
                "corrupt or noncanonical stage record".into(),
            ));
        }
        // All offsets are fixed and bounded after the exact length check.
        let u32_at = |offset| u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let u64_at = |offset| u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let proof_at = |index| {
            let offset = 184 + 40 * index;
            StageBlockProof {
                length: u32_at(offset),
                checksum: u32_at(offset + 4),
                sha256: bytes[offset + 8..offset + 40].try_into().unwrap(),
            }
        };
        let pending = proof_at(IMMUTABLE_STAGE_MAX_BLOCKS);
        if bytes[10] == 0 && pending != StageBlockProof::default() {
            return Err(Error::MetaError("noncanonical absent stage intent".into()));
        }
        let out = Self {
            spec: ImmutableStageSpec {
                stage_id: bytes[72..88].try_into().unwrap(),
                length: u32_at(36),
                checksum: u32_at(40),
                chain_ver: u32_at(44),
                last_request_id: u64_at(48),
                last_client_low: u64_at(56),
                last_client_high: u64_at(64),
                etag: bytes[88..88 + bytes[11] as usize].to_vec(),
            },
            state: match bytes[8] {
                1 => ImmutableStageState::Active,
                2 => ImmutableStageState::Sealed,
                3 => ImmutableStageState::Aborted,
                _ => return Err(Error::MetaError("unknown stage state".into())),
            },
            pos: Position(u64_at(20)),
            timestamp: u64_at(28),
            revision: u64_at(12),
            completed: bytes[9],
            proofs: std::array::from_fn(proof_at),
            pending: (bytes[10] == 1).then_some(pending),
            key_sha256: bytes[152..184].try_into().unwrap(),
        };
        out.validate(key)?;
        Ok(out)
    }
}

pub(crate) fn stage_key(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + key.len());
    out.push(STAGE_PREFIX);
    out.extend_from_slice(key);
    out
}

pub(crate) fn stage_position_key(pos: Position) -> [u8; 9] {
    let mut out = [STAGE_POSITION_PREFIX; 9];
    out[1..].copy_from_slice(&pos.0.to_be_bytes());
    out
}

impl MetaStore {
    pub(crate) fn stage_get_exact(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut it = self.iterator();
        it.seek(key)?;
        Ok(if it.key() == Some(key) {
            let value = it.value().unwrap_or_default();
            if value.len() > RECORD_SIZE {
                return Err(Error::MetaError(
                    "oversized immutable stage metadata value".into(),
                ));
            }
            Some(value.to_vec())
        } else {
            None
        })
    }

    pub(crate) fn stage_record(&self, key: &[u8]) -> Result<Option<StageRecord>> {
        self.stage_get_exact(&stage_key(key))?
            .map(|bytes| StageRecord::decode(key, &bytes))
            .transpose()
    }

    pub(crate) fn stage_put_record(
        key: &[u8],
        record: &StageRecord,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<()> {
        batch.put(stage_key(key), record.encode(key)?);
        Ok(())
    }

    /// Reserve the allocation without creating a readable chunk or accounting
    /// committed bytes. Repeating this same reservation is idempotent.
    pub(crate) fn stage_reserve(
        key: &[u8],
        record: &StageRecord,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<()> {
        Self::stage_put_record(key, record, batch)?;
        batch.put(stage_position_key(record.pos), stage_key(key));
        let merge: derse::DownwardBytes = MergeState::acquire(record.pos.index())
            .serialize()
            .map_err(Error::SerializationError)?;
        batch.merge(
            MetaKey::group_bits_key(record.pos.group_id()),
            merge.as_slice(),
        );
        Ok(())
    }

    pub(crate) fn stage_abort(
        key: &[u8],
        record: &StageRecord,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<()> {
        Self::stage_put_record(key, record, batch)?;
        batch.delete(stage_position_key(record.pos));
        let merge: derse::DownwardBytes = MergeState::release(record.pos.index())
            .serialize()
            .map_err(Error::SerializationError)?;
        batch.merge(
            MetaKey::group_bits_key(record.pos.group_id()),
            merge.as_slice(),
        );
        Ok(())
    }
}
