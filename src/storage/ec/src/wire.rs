//! Bounded helper frames with explicit little-endian fields and CRC32C.
//!
//! CRC detects accidental corruption, not authentication or malicious replay.
//! Callers must authenticate peers and bind frames to the expected session,
//! helper order, slice sequence and publication state. Control-frame semantics
//! belong to that execution protocol, not this codec.
//!
//! Version 1 header (byte offsets, half-open ranges):
//! 0..8 magic; 8..10 version; 10 kind; 11 reserved (zero);
//! 12..16 variable length; 16..18 target count; 18..20 hop;
//! 20..24 valid length; 24..32 sequence; 32..40 offset;
//! 40..56 job; 56..88 plan digest; 88..104 stripe;
//! 104..112 generation; 112..120 epoch;
//! 120..124 variable-region CRC32C; 124..128 CRC32C of bytes 0..124.
//! The variable region is target_count little-endian u16 IDs followed by payload.
use crate::{error, read::crc32c, Result};

pub const HEADER_LEN: usize = 128;
const MAGIC: &[u8; 8] = b"3FSECW\0\0";
const VERSION: u16 = 1;
const MAX_TARGETS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    pub job: u128,
    pub plan: [u8; 32],
    pub stripe: u128,
    pub generation: u64,
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Slice = 1,
    Finish = 2,
    Ack = 3,
    Failure = 4,
}

impl FrameKind {
    fn parse(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Slice),
            2 => Ok(Self::Finish),
            3 => Ok(Self::Ack),
            4 => Ok(Self::Failure),
            _ => Err(error("unknown frame kind")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub session: SessionId,
    pub sequence: u64,
    pub offset: u64,
    pub valid_len: u32,
    pub hop: u16,
    pub targets: Vec<u16>,
    pub payload: Vec<u8>,
}

// Called only after checking an exact HEADER_LEN header, with constant ranges.
fn field<const N: usize>(header: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&header[offset..offset + N]);
    value
}

fn validate_shape(
    kind: FrameKind,
    valid_len: u32,
    target_count: usize,
    variable_len: usize,
) -> Result<()> {
    if target_count > MAX_TARGETS {
        return Err(error("frame target count exceeds 256"));
    }
    let target_bytes = target_count
        .checked_mul(2)
        .ok_or_else(|| error("frame target byte count overflow"))?;
    if variable_len < target_bytes {
        return Err(error(
            "frame variable region is shorter than its target list",
        ));
    }
    if kind == FrameKind::Slice {
        if valid_len == 0 || target_count == 0 {
            return Err(error(
                "slice requires positive length and at least one target",
            ));
        }
        let length = usize::try_from(valid_len)
            .map_err(|_| error("slice valid length exceeds address space"))?;
        let expected = length
            .checked_mul(target_count)
            .and_then(|bytes| bytes.checked_add(target_bytes))
            .ok_or_else(|| error("slice payload size overflow"))?;
        if variable_len != expected {
            return Err(error(
                "slice payload length differs from length times targets",
            ));
        }
    }
    Ok(())
}

/// Validates an exact fixed header before a network reader allocates its body.
///
/// `max_payload` bounds the entire variable region, including target IDs.
/// The returned size includes HEADER_LEN. This checks the header CRC, fields,
/// count, lengths and Slice shape, but cannot check body CRC or target identity.
/// Call `Frame::decode` on the complete frame after a bounded, timed read.
pub fn encoded_len(header: &[u8], max_payload: usize) -> Result<usize> {
    if header.len() != HEADER_LEN {
        return Err(error("frame header must contain exactly 128 bytes"));
    }
    if &header[..8] != MAGIC {
        return Err(error("invalid frame magic"));
    }
    if u16::from_le_bytes(field(header, 8)) != VERSION {
        return Err(error("unsupported frame version"));
    }
    if header[11] != 0 {
        return Err(error("nonzero frame reserved field"));
    }
    if crc32c(&header[..124]) != u32::from_le_bytes(field(header, 124)) {
        return Err(error("frame header CRC32C mismatch"));
    }
    let kind = FrameKind::parse(header[10])?;
    let variable_len = usize::try_from(u32::from_le_bytes(field(header, 12)))
        .map_err(|_| error("frame variable length exceeds address space"))?;
    if variable_len > max_payload {
        return Err(error("frame variable region exceeds configured limit"));
    }
    let target_count = usize::from(u16::from_le_bytes(field(header, 16)));
    let valid_len = u32::from_le_bytes(field(header, 20));
    validate_shape(kind, valid_len, target_count, variable_len)?;
    HEADER_LEN
        .checked_add(variable_len)
        .ok_or_else(|| error("encoded frame size overflow"))
}

fn reserve(bytes: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes)
        .map_err(|_| error("cannot allocate bounded frame buffer"))?;
    Ok(output)
}

impl Frame {
    /// Encodes one frame after checking lengths, target uniqueness and Slice shape.
    /// Target IDs are u16; their membership in the code's shard set is checked by
    /// the executor. At most 256 IDs are permitted, and their order is preserved.
    pub fn encode(&self, max_payload: usize) -> Result<Vec<u8>> {
        if self.targets.len() > MAX_TARGETS {
            return Err(error("frame target count exceeds 256"));
        }
        let variable_len = self
            .targets
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(self.payload.len()))
            .ok_or_else(|| error("frame variable length overflow"))?;
        if variable_len > max_payload {
            return Err(error("frame variable region exceeds configured limit"));
        }
        let wire_len =
            u32::try_from(variable_len).map_err(|_| error("frame variable length exceeds u32"))?;
        validate_shape(self.kind, self.valid_len, self.targets.len(), variable_len)?;
        for (index, target) in self.targets.iter().enumerate() {
            if self.targets[..index].contains(target) {
                return Err(error("duplicate frame target"));
            }
        }
        let total = HEADER_LEN
            .checked_add(variable_len)
            .ok_or_else(|| error("encoded frame size overflow"))?;
        let mut output = reserve(total)?;
        output.resize(HEADER_LEN, 0);
        for target in &self.targets {
            output.extend_from_slice(&target.to_le_bytes());
        }
        output.extend_from_slice(&self.payload);
        let body_crc = crc32c(&output[HEADER_LEN..]);
        output[..8].copy_from_slice(MAGIC);
        output[8..10].copy_from_slice(&VERSION.to_le_bytes());
        output[10] = self.kind as u8;
        output[12..16].copy_from_slice(&wire_len.to_le_bytes());
        // target count is already bounded by 256, so this narrowing is exact.
        output[16..18].copy_from_slice(&(self.targets.len() as u16).to_le_bytes());
        output[18..20].copy_from_slice(&self.hop.to_le_bytes());
        output[20..24].copy_from_slice(&self.valid_len.to_le_bytes());
        output[24..32].copy_from_slice(&self.sequence.to_le_bytes());
        output[32..40].copy_from_slice(&self.offset.to_le_bytes());
        output[40..56].copy_from_slice(&self.session.job.to_le_bytes());
        output[56..88].copy_from_slice(&self.session.plan);
        output[88..104].copy_from_slice(&self.session.stripe.to_le_bytes());
        output[104..112].copy_from_slice(&self.session.generation.to_le_bytes());
        output[112..120].copy_from_slice(&self.session.epoch.to_le_bytes());
        output[120..124].copy_from_slice(&body_crc.to_le_bytes());
        let header_crc = crc32c(&output[..124]);
        output[124..128].copy_from_slice(&header_crc.to_le_bytes());
        Ok(output)
    }

    /// Decodes exactly one complete frame. Concatenated frames or trailing bytes
    /// are rejected. No body allocation occurs until header limits and exact
    /// input length have been checked; CRCs and duplicate IDs are also checked
    /// before allocating the returned payload.
    pub fn decode(bytes: &[u8], max_payload: usize) -> Result<Self> {
        let header = bytes
            .get(..HEADER_LEN)
            .ok_or_else(|| error("truncated frame header"))?;
        let total = encoded_len(header, max_payload)?;
        if bytes.len() != total {
            return Err(error("frame is truncated or has trailing bytes"));
        }
        let body = &bytes[HEADER_LEN..];
        if crc32c(body) != u32::from_le_bytes(field(header, 120)) {
            return Err(error("frame variable-region CRC32C mismatch"));
        }
        let target_count = usize::from(u16::from_le_bytes(field(header, 16)));
        let mut targets = Vec::with_capacity(target_count);
        for pair in body[..target_count * 2].chunks_exact(2) {
            let target = u16::from_le_bytes([pair[0], pair[1]]);
            if targets.contains(&target) {
                return Err(error("duplicate frame target"));
            }
            targets.push(target);
        }
        let payload_bytes = &body[target_count * 2..];
        let mut payload = reserve(payload_bytes.len())?;
        payload.extend_from_slice(payload_bytes);
        Ok(Self {
            kind: FrameKind::parse(header[10])?,
            session: SessionId {
                job: u128::from_le_bytes(field(header, 40)),
                plan: field(header, 56),
                stripe: u128::from_le_bytes(field(header, 88)),
                generation: u64::from_le_bytes(field(header, 104)),
                epoch: u64::from_le_bytes(field(header, 112)),
            },
            sequence: u64::from_le_bytes(field(header, 24)),
            offset: u64::from_le_bytes(field(header, 32)),
            valid_len: u32::from_le_bytes(field(header, 20)),
            hop: u16::from_le_bytes(field(header, 18)),
            targets,
            payload,
        })
    }
}
