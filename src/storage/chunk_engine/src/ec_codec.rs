//! Bounded owned-output CXX arithmetic bridge. Identity, source integrity,
//! authorization, and durable publication remain the caller's responsibility.
use std::panic::{catch_unwind, UnwindSafe};

use hf3fs_ec::Codec;

use crate::cxx::ffi::{EcCodecFormat, EcCodecInput, EcCodecResult, EcCodecShard};

const K: usize = 10;
const N: usize = 12;
const MAX_SHARD: usize = 1 << 20;
const INVALID: u16 = 3;
const CORRUPT: u16 = 2;
const NO_MEMORY: u16 = 26;
const FOUND_BUG: u16 = 998;
type BridgeResult<T> = Result<T, (u16, String)>;

fn invalid(message: &str) -> (u16, String) {
    (INVALID, message.into())
}

fn codec_error(error: hf3fs_ec::Error) -> (u16, String) {
    (INVALID, error.to_string())
}

fn boundary(
    operation: impl FnOnce() -> BridgeResult<Vec<EcCodecShard>> + UnwindSafe,
) -> EcCodecResult {
    match catch_unwind(operation) {
        Ok(Ok(shards)) => EcCodecResult {
            error_code: 0,
            error: String::new(),
            shards,
        },
        Ok(Err((error_code, error))) => EcCodecResult {
            error_code,
            error,
            shards: Vec::new(),
        },
        Err(_) => EcCodecResult {
            error_code: FOUND_BUG,
            error: "unexpected panic in EC arithmetic bridge".into(),
            shards: Vec::new(),
        },
    }
}

fn codec(format: &EcCodecFormat) -> BridgeResult<Codec> {
    if (
        format.codec_id,
        format.matrix_version,
        format.data_shards,
        format.parity_shards,
        format.field_polynomial,
    ) != (1, 1, 10, 2, 0x11d)
    {
        return Err(invalid(
            "unsupported EC codec, matrix, dimensions or field polynomial",
        ));
    }
    Codec::new(K, N - K).map_err(codec_error)
}

fn shape(logical_length: u64, shard_bytes: u32) -> BridgeResult<usize> {
    let size = shard_bytes as usize;
    if size == 0 || size > MAX_SHARD || logical_length > K as u64 * size as u64 {
        return Err(invalid(
            "EC requires 1..=1MiB shards and logical length <= 10 * shard bytes",
        ));
    }
    Ok(size)
}

fn copy_bytes(bytes: &[u8]) -> BridgeResult<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| (NO_MEMORY, "cannot allocate EC input".into()))?;
    result.extend_from_slice(bytes);
    Ok(result)
}

fn inputs<'a>(
    shards: &'a [EcCodecInput<'a>],
    count: usize,
    size: usize,
) -> BridgeResult<[Option<&'a [u8]>; N]> {
    if shards.len() != count {
        return Err(invalid("incorrect EC input shard count"));
    }
    let mut indexed = [None; N];
    for shard in shards {
        let index = shard.index as usize;
        if index >= N || indexed[index].is_some() || shard.data.len() != size {
            return Err(invalid(
                "EC shard indices must be distinct and in range with exact shard lengths",
            ));
        }
        indexed[index] = Some(shard.data);
    }
    Ok(indexed)
}

fn output(shards: Vec<Vec<u8>>, indices: impl IntoIterator<Item = usize>) -> Vec<EcCodecShard> {
    indices
        .into_iter()
        .zip(shards)
        .map(|(index, data)| EcCodecShard {
            index: index as u16,
            data,
        })
        .collect()
}

fn verify_codeword(
    codec: &Codec,
    shards: &[Vec<u8>],
    logical_length: u64,
    size: usize,
) -> BridgeResult<()> {
    if shards.len() != N || shards.iter().any(|shard| shard.len() != size) {
        return Err((FOUND_BUG, "EC codec returned an inconsistent shape".into()));
    }
    verify_padding(&shards[..K], logical_length, size)?;
    let expected = codec.encode(&shards[..K]).map_err(codec_error)?;
    if expected[K..] != shards[K..] {
        return Err((
            CORRUPT,
            "EC parity differs from the fixed encoding matrix".into(),
        ));
    }
    Ok(())
}

fn verify_padding(shards: &[Vec<u8>], logical_length: u64, size: usize) -> BridgeResult<()> {
    for (index, shard) in shards.iter().enumerate() {
        let valid = logical_length
            .saturating_sub((index * size) as u64)
            .min(size as u64) as usize;
        if shard[valid..].iter().any(|&byte| byte != 0) {
            return Err((CORRUPT, "EC logical tail has nonzero padding".into()));
        }
    }
    Ok(())
}

pub(crate) fn ec_codec_encode(
    format: &EcCodecFormat,
    data: &[u8],
    shard_bytes: u32,
) -> EcCodecResult {
    boundary(|| {
        let size = shape(data.len() as u64, shard_bytes)?;
        let codec = codec(format)?;
        let mut input = Vec::with_capacity(K);
        for index in 0..K {
            let mut shard = Vec::new();
            shard
                .try_reserve_exact(size)
                .map_err(|_| (NO_MEMORY, "cannot allocate EC shard".into()))?;
            shard.resize(size, 0);
            let start = index * size;
            if start < data.len() {
                let count = size.min(data.len() - start);
                shard[..count].copy_from_slice(&data[start..start + count]);
            }
            input.push(shard);
        }
        Ok(output(codec.encode(&input).map_err(codec_error)?, 0..N))
    })
}

pub(crate) fn ec_codec_verify(
    format: &EcCodecFormat,
    shards: &[EcCodecInput<'_>],
    logical_length: u64,
    shard_bytes: u32,
) -> EcCodecResult {
    boundary(|| {
        let size = shape(logical_length, shard_bytes)?;
        let indexed = inputs(shards, N, size)?;
        let codec = codec(format)?;
        // The existing Codec takes owned data shards. Parity inputs remain
        // borrowed; no copy of those two potentially 1MiB inputs is needed.
        let data = indexed[..K]
            .iter()
            .map(|shard| copy_bytes(shard.ok_or_else(|| invalid("missing EC shard"))?))
            .collect::<BridgeResult<Vec<_>>>()?;
        verify_padding(&data, logical_length, size)?;
        let expected = codec.encode(&data).map_err(codec_error)?;
        for index in K..N {
            if Some(expected[index].as_slice()) != indexed[index] {
                return Err((
                    CORRUPT,
                    "EC parity differs from the fixed encoding matrix".into(),
                ));
            }
        }
        Ok(Vec::new())
    })
}

pub(crate) fn ec_codec_recover(
    format: &EcCodecFormat,
    shards: &[EcCodecInput<'_>],
    logical_length: u64,
    shard_bytes: u32,
) -> EcCodecResult {
    boundary(|| {
        let size = shape(logical_length, shard_bytes)?;
        let indexed = inputs(shards, K, size)?;
        let codec = codec(format)?;
        let healthy: Vec<_> = shards.iter().map(|shard| shard.index as usize).collect();
        let targets: Vec<_> = indexed
            .iter()
            .enumerate()
            .filter_map(|(i, shard)| shard.is_none().then_some(i))
            .collect();
        let plan = codec.repair_plan(&healthy, &targets).map_err(codec_error)?;
        let data = shards
            .iter()
            .map(|shard| copy_bytes(shard.data))
            .collect::<BridgeResult<Vec<_>>>()?;
        let recovered = plan.recover_slice(&data).map_err(codec_error)?;
        let mut complete: Vec<Option<Vec<u8>>> = (0..N).map(|_| None).collect();
        for (index, bytes) in healthy
            .into_iter()
            .zip(data)
            .chain(targets.into_iter().zip(recovered))
        {
            complete[index] = Some(bytes);
        }
        let complete = complete
            .into_iter()
            .map(|shard| {
                shard.ok_or_else(|| (FOUND_BUG, "EC reconstruction omitted a shard".into()))
            })
            .collect::<BridgeResult<Vec<_>>>()?;
        verify_codeword(&codec, &complete, logical_length, size)?;
        Ok(output(complete, 0..N))
    })
}

pub(crate) fn ec_codec_contribute(
    format: &EcCodecFormat,
    healthy: &[u16],
    targets: &[u16],
    helper: u16,
    data: &[u8],
) -> EcCodecResult {
    boundary(|| {
        if healthy.len() != K
            || targets.is_empty()
            || targets.len() > N - K
            || data.len() > MAX_SHARD
        {
            return Err(invalid(
                "EC contribution requires ten sources, one or two targets and <=1MiB input",
            ));
        }
        let codec = codec(format)?;
        let healthy: Vec<_> = healthy.iter().map(|&index| index as usize).collect();
        let targets: Vec<_> = targets.iter().map(|&index| index as usize).collect();
        let plan = codec.repair_plan(&healthy, &targets).map_err(codec_error)?;
        let contribution = plan.contribution(helper as usize).map_err(codec_error)?;
        Ok(output(
            contribution.apply(data).map_err(codec_error)?,
            targets,
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format() -> EcCodecFormat {
        EcCodecFormat {
            codec_id: 1,
            matrix_version: 1,
            data_shards: 10,
            parity_shards: 2,
            field_polynomial: 0x11d,
        }
    }

    #[test]
    fn malformed_bridge_requests_return_errors_without_partial_output() {
        let mut bad = format();
        bad.matrix_version = 2;
        for result in [
            ec_codec_encode(&bad, &[], 1),
            ec_codec_encode(&format(), &[], 0),
            ec_codec_recover(&format(), &[], 0, 1),
            ec_codec_contribute(&format(), &[0; 10], &[11], 0, &[1]),
        ] {
            assert_eq!(result.error_code, INVALID);
            assert!(result.shards.is_empty());
        }
    }

    #[test]
    fn codec_bridge_verifies_padding_and_returns_owned_bytes() {
        let result = ec_codec_encode(&format(), b"short tail", 2);
        assert_eq!(result.error_code, 0);
        assert_eq!(result.shards.len(), N);
        let inputs: Vec<_> = result
            .shards
            .iter()
            .map(|shard| EcCodecInput {
                index: shard.index,
                data: &shard.data,
            })
            .collect();
        assert_eq!(ec_codec_verify(&format(), &inputs, 10, 2).error_code, 0);
        let rejected = ec_codec_verify(&format(), &inputs, 9, 2);
        assert_eq!(rejected.error_code, CORRUPT);
        assert!(rejected.shards.is_empty());
    }

    #[test]
    fn raw_bridge_rejects_malformed_sources_without_cpp_validation() {
        let byte = [0u8];
        let mut sources = [EcCodecInput {
            index: 0,
            data: &byte,
        }; N];
        for (index, source) in sources.iter_mut().enumerate() {
            source.index = index as u16;
        }
        assert_eq!(ec_codec_verify(&format(), &sources, 0, 1).error_code, 0);
        sources[1].index = 0;
        for result in [
            ec_codec_verify(&format(), &sources, 0, 1),
            ec_codec_recover(&format(), &sources[..K], 0, 1),
        ] {
            assert_eq!(result.error_code, INVALID);
            assert!(result.shards.is_empty());
        }
        sources[1].index = 12;
        assert_eq!(
            ec_codec_recover(&format(), &sources[..K], 0, 1).error_code,
            INVALID
        );
        sources[1].index = 1;
        sources[1].data = &[];
        assert_eq!(
            ec_codec_recover(&format(), &sources[..K], 0, 1).error_code,
            INVALID
        );
        let oversized = vec![0; MAX_SHARD + 1];
        let rejected = ec_codec_contribute(
            &format(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            &[10],
            0,
            &oversized,
        );
        assert_eq!(rejected.error_code, INVALID);
        assert!(rejected.shards.is_empty());
    }

    #[test]
    fn unexpected_unwind_is_contained_at_bridge_boundary() {
        let result = boundary(|| panic!("injected bridge unwind"));
        assert_eq!(result.error_code, FOUND_BUG);
        assert!(result.shards.is_empty());
    }
}
