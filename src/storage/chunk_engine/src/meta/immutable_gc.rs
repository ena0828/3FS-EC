//! Permanent, exact-key GC ledger for the explicitly gated format-3 engine.
//! A record proves only a local atomic metadata transition, not authorization.
use crate::ec_scope::EcTargetIdentity;
use crate::*;
use sha2::{Digest, Sha256};

pub(crate) const STAGE_GC_PREFIX: u8 = 16;
const RECORD_BYTES: usize = 384;
const HASH_OFFSET: usize = RECORD_BYTES - 32;

/// Internal mapping of a trusted, authenticated Meta claim. None of these
/// caller-supplied fields proves eligibility or authority by itself. The future
/// Storage control layer must verify the full canonical claim, its instance,
/// historical scope drains, and the dedicated GC capability before calling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EcStageGcClaim {
    pub claim_id: [u8; 16],
    pub claim_digest: [u8; 32],
    pub eligibility_digest: [u8; 32],
    pub target: EcTargetIdentity,
    pub spec: ImmutableStageSpec,
}

impl EcStageGcClaim {
    pub(crate) fn validate(&self) -> Result<()> {
        self.spec.validate()?;
        if self.claim_id == [0; 16]
            || self.claim_digest == [0; 32]
            || self.eligibility_digest == [0; 32]
            || self.target.engine == [0; 16]
            || self.target.incarnation == [0; 16]
            || self.target.chain == 0
            || self.target.target == 0
        {
            return Err(Error::InvalidArg("incomplete exact GC claim".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EcStageGcRecord {
    pub claim_id: [u8; 16],
    pub claim_digest: [u8; 32],
    pub eligibility_digest: [u8; 32],
    pub target: EcTargetIdentity,
    pub key_sha256: [u8; 32],
    pub spec_sha256: [u8; 32],
    pub before_sha256: [u8; 32],
    pub terminal_sha256: [u8; 32],
    pub position: Position,
    pub terminal_revision: u64,
    pub before_state: ImmutableStageState,
}

pub(crate) fn stage_gc_key(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + 1);
    out.push(STAGE_GC_PREFIX);
    out.extend_from_slice(key);
    out
}

pub(crate) fn spec_digest(spec: &ImmutableStageSpec) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"3FSGCSPEC1");
    hash.update(spec.stage_id);
    hash.update(spec.length.to_be_bytes());
    hash.update(spec.checksum.to_be_bytes());
    hash.update(spec.chain_ver.to_be_bytes());
    hash.update(spec.last_request_id.to_be_bytes());
    hash.update(spec.last_client_low.to_be_bytes());
    hash.update(spec.last_client_high.to_be_bytes());
    hash.update((spec.etag.len() as u32).to_be_bytes());
    hash.update(&spec.etag);
    hash.finalize().into()
}

impl EcStageGcRecord {
    pub(crate) fn new(
        key: &[u8],
        claim: &EcStageGcClaim,
        before: &StageRecord,
        terminal: &StageRecord,
    ) -> Result<Self> {
        claim.validate()?;
        if before.spec != claim.spec
            || terminal.spec != claim.spec
            || !before.same_reservation(terminal)
            || terminal.state != ImmutableStageState::Aborted
            || terminal.revision
                != before
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| Error::MetaError("GC revision overflow".into()))?
        {
            return Err(Error::MetaError("invalid exact GC transition".into()));
        }
        Ok(Self {
            claim_id: claim.claim_id,
            claim_digest: claim.claim_digest,
            eligibility_digest: claim.eligibility_digest,
            target: claim.target,
            key_sha256: Sha256::digest(key).into(),
            spec_sha256: spec_digest(&claim.spec),
            before_sha256: Sha256::digest(before.encode(key)?).into(),
            terminal_sha256: Sha256::digest(terminal.encode(key)?).into(),
            position: before.pos,
            terminal_revision: terminal.revision,
            before_state: before.state,
        })
    }

    pub(crate) fn matches(&self, key: &[u8], claim: &EcStageGcClaim) -> bool {
        self.claim_id == claim.claim_id
            && self.claim_digest == claim.claim_digest
            && self.eligibility_digest == claim.eligibility_digest
            && self.target == claim.target
            && self.key_sha256 == <[u8; 32]>::from(Sha256::digest(key))
            && self.spec_sha256 == spec_digest(&claim.spec)
    }

    pub(crate) fn validates_terminal(&self, key: &[u8], terminal: &StageRecord) -> Result<bool> {
        Ok(terminal.state == ImmutableStageState::Aborted
            && terminal.pos == self.position
            && terminal.revision == self.terminal_revision
            && spec_digest(&terminal.spec) == self.spec_sha256
            && <[u8; 32]>::from(Sha256::digest(terminal.encode(key)?)) == self.terminal_sha256)
    }

    pub(crate) fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(b"3FSGCLD1");
        bytes[8..24].copy_from_slice(&self.claim_id);
        bytes[24..56].copy_from_slice(&self.claim_digest);
        bytes[56..88].copy_from_slice(&self.eligibility_digest);
        bytes[88..104].copy_from_slice(&self.target.engine);
        bytes[104..120].copy_from_slice(&self.target.incarnation);
        bytes[120..124].copy_from_slice(&self.target.chain.to_be_bytes());
        bytes[124..132].copy_from_slice(&self.target.target.to_be_bytes());
        bytes[132..164].copy_from_slice(&self.key_sha256);
        bytes[164..196].copy_from_slice(&self.spec_sha256);
        bytes[196..228].copy_from_slice(&self.before_sha256);
        bytes[228..260].copy_from_slice(&self.terminal_sha256);
        bytes[260..268].copy_from_slice(&self.position.0.to_be_bytes());
        bytes[268..276].copy_from_slice(&self.terminal_revision.to_be_bytes());
        bytes[276] = match self.before_state {
            ImmutableStageState::Active => 1,
            ImmutableStageState::Sealed => 2,
            ImmutableStageState::Aborted => 3,
        };
        let digest = Sha256::digest(&bytes[..HASH_OFFSET]);
        bytes[HASH_OFFSET..].copy_from_slice(&digest);
        bytes
    }

    pub(crate) fn decode(key: &[u8], bytes: &[u8]) -> Result<Self> {
        let invalid = || Error::MetaError("invalid exact GC ledger".into());
        if key.is_empty()
            || key.len() > IMMUTABLE_STAGE_MAX_KEY_BYTES
            || bytes.len() != RECORD_BYTES
            || &bytes[..8] != b"3FSGCLD1"
            || bytes[277..HASH_OFFSET].iter().any(|b| *b != 0)
            || Sha256::digest(&bytes[..HASH_OFFSET]).as_slice() != &bytes[HASH_OFFSET..]
        {
            return Err(invalid());
        }
        let record = Self {
            claim_id: bytes[8..24].try_into().unwrap(),
            claim_digest: bytes[24..56].try_into().unwrap(),
            eligibility_digest: bytes[56..88].try_into().unwrap(),
            target: EcTargetIdentity {
                engine: bytes[88..104].try_into().unwrap(),
                incarnation: bytes[104..120].try_into().unwrap(),
                chain: u32::from_be_bytes(bytes[120..124].try_into().unwrap()),
                target: u64::from_be_bytes(bytes[124..132].try_into().unwrap()),
            },
            key_sha256: bytes[132..164].try_into().unwrap(),
            spec_sha256: bytes[164..196].try_into().unwrap(),
            before_sha256: bytes[196..228].try_into().unwrap(),
            terminal_sha256: bytes[228..260].try_into().unwrap(),
            position: Position(u64::from_be_bytes(bytes[260..268].try_into().unwrap())),
            terminal_revision: u64::from_be_bytes(bytes[268..276].try_into().unwrap()),
            before_state: match bytes[276] {
                1 => ImmutableStageState::Active,
                2 => ImmutableStageState::Sealed,
                3 => ImmutableStageState::Aborted,
                _ => return Err(invalid()),
            },
        };
        if record.claim_id == [0; 16]
            || record.claim_digest == [0; 32]
            || record.eligibility_digest == [0; 32]
            || record.target.engine == [0; 16]
            || record.target.incarnation == [0; 16]
            || record.target.chain == 0
            || record.target.target == 0
            || record.terminal_revision < 2
            || record.before_sha256 == [0; 32]
            || record.terminal_sha256 == [0; 32]
            || record.spec_sha256 == [0; 32]
            || record.key_sha256 != <[u8; 32]>::from(Sha256::digest(key))
        {
            return Err(invalid());
        }
        Ok(record)
    }
}

impl MetaStore {
    pub(crate) fn stage_gc_record(&self, key: &[u8]) -> Result<Option<EcStageGcRecord>> {
        self.stage_get_exact(&stage_gc_key(key))?
            .map(|bytes| EcStageGcRecord::decode(key, &bytes))
            .transpose()
    }
}
