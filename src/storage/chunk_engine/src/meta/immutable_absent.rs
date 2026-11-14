//! Independent terminal absence ledger. It is neither a stage nor a deletion.
use crate::*;
use sha2::{Digest, Sha256};

pub(crate) const STAGE_ABSENT_PREFIX: u8 = 17;
const SIZE: usize = 268;
pub(crate) fn stage_absent_key(key: &[u8]) -> Vec<u8> {
    let mut out = vec![STAGE_ABSENT_PREFIX];
    out.extend_from_slice(key);
    out
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EcStageAbsentRecord {
    pub claim_id: [u8; 16],
    pub claim_digest: [u8; 32],
    pub eligibility_digest: [u8; 32],
    pub closure_digest: [u8; 32],
    pub target: crate::ec_scope::EcTargetIdentity,
    pub key_digest: [u8; 32],
    pub spec_digest: [u8; 32],
}
impl EcStageAbsentRecord {
    pub fn new(key: &[u8], claim: &EcStageGcClaim, closure: [u8; 32]) -> Result<Self> {
        claim.validate()?;
        if closure == [0; 32] { return Err(Error::MetaError("empty absence closure".into())); }
        Ok(Self { claim_id: claim.claim_id, claim_digest: claim.claim_digest,
            eligibility_digest: claim.eligibility_digest, closure_digest: closure,
            target: claim.target, key_digest: Sha256::digest(key).into(),
            spec_digest: super::immutable_gc::spec_digest(&claim.spec) })
    }
    pub fn encode(&self) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        b[..8].copy_from_slice(b"3FSEABS1");
        b[8..24].copy_from_slice(&self.claim_id);
        b[24..56].copy_from_slice(&self.claim_digest);
        b[56..88].copy_from_slice(&self.eligibility_digest);
        b[88..120].copy_from_slice(&self.closure_digest);
        b[120..136].copy_from_slice(&self.target.engine);
        b[136..152].copy_from_slice(&self.target.incarnation);
        b[152..156].copy_from_slice(&self.target.chain.to_be_bytes());
        b[156..164].copy_from_slice(&self.target.target.to_be_bytes());
        b[164..196].copy_from_slice(&self.key_digest);
        b[196..228].copy_from_slice(&self.spec_digest);
        b[228..236].copy_from_slice(&1u64.to_be_bytes());
        let digest: [u8; 32] = Sha256::digest(&b[..236]).into();
        b[236..].copy_from_slice(&digest);
        b
    }
    pub fn decode(key: &[u8], b: &[u8]) -> Result<Self> {
        let invalid = || Error::MetaError("invalid absence ledger".into());
        if b.len()!=SIZE || &b[..8]!=b"3FSEABS1" || b[228..236]!=1u64.to_be_bytes() ||
            b[236..]!=Sha256::digest(&b[..236])[..] { return Err(invalid()); }
        let r=Self { claim_id:b[8..24].try_into().unwrap(), claim_digest:b[24..56].try_into().unwrap(),
            eligibility_digest:b[56..88].try_into().unwrap(), closure_digest:b[88..120].try_into().unwrap(),
            target:crate::ec_scope::EcTargetIdentity {engine:b[120..136].try_into().unwrap(),
                incarnation:b[136..152].try_into().unwrap(),chain:u32::from_be_bytes(b[152..156].try_into().unwrap()),
                target:u64::from_be_bytes(b[156..164].try_into().unwrap())},
            key_digest:b[164..196].try_into().unwrap(),spec_digest:b[196..228].try_into().unwrap() };
        if r.claim_id==[0;16] || r.claim_digest==[0;32] || r.eligibility_digest==[0;32] ||
            r.closure_digest==[0;32] || r.spec_digest==[0;32] || r.key_digest!=<[u8;32]>::from(Sha256::digest(key)) ||
            r.target.engine==[0;16] || r.target.incarnation==[0;16] || r.target.chain==0 || r.target.target==0 {
            return Err(invalid());
        }
        Ok(r)
    }
}
impl MetaStore {
    pub(crate) fn stage_absent_record(&self, key:&[u8]) -> Result<Option<EcStageAbsentRecord>> {
        self.stage_get_exact(&stage_absent_key(key))?.map(|b|EcStageAbsentRecord::decode(key,&b)).transpose()
    }
}
