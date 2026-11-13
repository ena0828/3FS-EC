//! Bounded owned-output CXX arithmetic bridge. Identity, source integrity,
//! authorization, and durable publication remain the caller's responsibility.
use std::collections::VecDeque;
use std::panic::{catch_unwind, UnwindSafe};
use std::sync::{Arc, Mutex, OnceLock};

use hf3fs_ec::{Backend, Codec, ContributionPlan, RepairPlan};

use crate::cxx::ffi::{EcCodecFormat, EcCodecInput, EcCodecResult, EcCodecShard};

const K: usize = 10;
const N: usize = 12;
const MAX_SHARD: usize = 1 << 20;
const INVALID: u16 = 3;
const CORRUPT: u16 = 2;
const NO_MEMORY: u16 = 26;
const FOUND_BUG: u16 = 998;
#[cfg(not(feature = "isal-backend"))]
const BACKEND: Backend = Backend::Scalar;
#[cfg(feature = "isal-backend")]
const BACKEND: Backend = Backend::Isal;
const REPAIR_CACHE_CAPACITY: usize = 64;
const CONTRIBUTION_CACHE_CAPACITY: usize = 128;
type BridgeResult<T> = Result<T, (u16, String)>;

pub(crate) fn ec_codec_backend() -> &'static str {
    match BACKEND {
        Backend::Scalar => "scalar",
        #[cfg(feature = "isal-backend")]
        Backend::Isal => "isal",
    }
}

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

fn checked_format(format: &EcCodecFormat) -> BridgeResult<[u16; 5]> {
    let fields = [
        format.codec_id,
        format.matrix_version,
        format.data_shards,
        format.parity_shards,
        format.field_polynomial,
    ];
    if fields != [1, 1, 10, 2, 0x11d] {
        return Err(invalid(
            "unsupported EC codec, matrix, dimensions or field polynomial",
        ));
    }
    Ok(fields)
}

fn codec(format: &EcCodecFormat) -> BridgeResult<&'static Codec> {
    checked_format(format)?;
    static CODEC: OnceLock<BridgeResult<Codec>> = OnceLock::new();
    // Only this fixed construction result is shared, never a request result.
    CODEC
        .get_or_init(|| Codec::with_backend(K, N - K, BACKEND).map_err(codec_error))
        .as_ref()
        .map_err(Clone::clone)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlanKey {
    format: [u16; 5],
    backend: Backend,
    healthy: [usize; K],
    targets: [usize; N - K],
    target_count: usize,
}

impl PlanKey {
    fn checked(
        format: &EcCodecFormat,
        healthy: &[usize],
        targets: &[usize],
    ) -> BridgeResult<Self> {
        let format = checked_format(format)?;
        if healthy.len() != K || targets.is_empty() || targets.len() > N - K {
            return Err(invalid(
                "EC plan requires ten sources and one or two targets",
            ));
        }
        let mut seen = [false; N];
        for &index in healthy.iter().chain(targets) {
            if index >= N || seen[index] {
                return Err(invalid(
                    "EC plan indices must be distinct, disjoint and in range",
                ));
            }
            seen[index] = true;
        }
        let mut key = Self {
            format,
            backend: BACKEND,
            healthy: [0; K],
            targets: [0; N - K],
            target_count: targets.len(),
        };
        // Order is semantic: coefficients match the caller's input columns and
        // requested output rows. A bitmap or sorted key would be incorrect.
        key.healthy.copy_from_slice(healthy);
        key.targets[..targets.len()].copy_from_slice(targets);
        Ok(key)
    }

    fn targets(&self) -> &[usize] {
        &self.targets[..self.target_count]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContributionKey {
    plan: PlanKey,
    helper: usize,
}

impl ContributionKey {
    fn checked(plan: PlanKey, helper: usize) -> BridgeResult<Self> {
        if !plan.healthy.contains(&helper) {
            return Err(invalid("EC contribution helper is not a healthy source"));
        }
        Ok(Self { plan, helper })
    }
}

#[derive(Default)]
struct PlanEntries {
    repairs: VecDeque<(PlanKey, Arc<RepairPlan>)>,
    contributions: VecDeque<(ContributionKey, Arc<ContributionPlan>)>,
}

impl PlanEntries {
    fn repair(&mut self, codec: &Codec, key: PlanKey) -> BridgeResult<Arc<RepairPlan>> {
        if let Some((_, plan)) = self.repairs.iter().find(|(stored, _)| *stored == key) {
            return Ok(Arc::clone(plan));
        }
        let plan = Arc::new(
            codec
                .repair_plan(&key.healthy, key.targets())
                .map_err(codec_error)?,
        );
        if self.repairs.len() == REPAIR_CACHE_CAPACITY {
            self.repairs.pop_front();
        }
        self.repairs.push_back((key, Arc::clone(&plan)));
        Ok(plan)
    }
}

// The cache retains at most 64 repair and 128 single-helper plans. FIFO avoids
// unbounded key growth; outstanding calls may retain an evicted Arc until their
// byte operation ends. No payload, validation result, identity or grant is kept.
// The one lock serializes only lookup and small fixed-size coefficient creation,
// preventing concurrent misses from repeating the same inversion. All byte
// operations (including copies, padding and parity checks) run after unlocking.
#[derive(Default)]
struct PlanCache {
    entries: Mutex<PlanEntries>,
}

fn poisoned_cache() -> (u16, String) {
    (FOUND_BUG, "EC arithmetic plan cache is poisoned".into())
}

impl PlanCache {
    fn repair(&self, codec: &Codec, key: PlanKey) -> BridgeResult<Arc<RepairPlan>> {
        self.entries
            .lock()
            .map_err(|_| poisoned_cache())?
            .repair(codec, key)
    }

    fn contribution(
        &self,
        codec: &Codec,
        key: ContributionKey,
    ) -> BridgeResult<Arc<ContributionPlan>> {
        let mut entries = self.entries.lock().map_err(|_| poisoned_cache())?;
        if let Some((_, plan)) = entries
            .contributions
            .iter()
            .find(|(stored, _)| *stored == key)
        {
            return Ok(Arc::clone(plan));
        }
        let repair = entries.repair(codec, key.plan)?;
        let plan = Arc::new(repair.contribution(key.helper).map_err(codec_error)?);
        if entries.contributions.len() == CONTRIBUTION_CACHE_CAPACITY {
            entries.contributions.pop_front();
        }
        entries.contributions.push_back((key, Arc::clone(&plan)));
        Ok(plan)
    }
}

fn plans() -> &'static PlanCache {
    static PLANS: OnceLock<PlanCache> = OnceLock::new();
    PLANS.get_or_init(PlanCache::default)
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
        let key = PlanKey::checked(format, &healthy, &targets)?;
        let plan = plans().repair(codec, key)?;
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
        verify_codeword(codec, &complete, logical_length, size)?;
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
        let healthy: Vec<_> = healthy.iter().map(|&index| index as usize).collect();
        let targets: Vec<_> = targets.iter().map(|&index| index as usize).collect();
        let key = ContributionKey::checked(
            PlanKey::checked(format, &healthy, &targets)?,
            helper as usize,
        )?;
        let contribution = plans().contribution(codec(format)?, key)?;
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
    fn configured_backend_matches_scalar_across_bridge_operations() {
        let selected = codec(&format()).unwrap().backend();
        #[cfg(feature = "isal-backend")]
        {
            assert_eq!(selected, Backend::Isal);
            assert_eq!(ec_codec_backend(), "isal");
        }
        #[cfg(not(feature = "isal-backend"))]
        {
            assert_eq!(selected, Backend::Scalar);
            assert_eq!(ec_codec_backend(), "scalar");
        }
        println!("EC_CODEC_BACKEND={}", ec_codec_backend());
        // Exercise both sides of the existing 64-byte ISA-L threshold, with
        // nonaligned tails, zero padding, reverse input order and two targets.
        let scalar = Codec::new(K, N - K).unwrap();
        for size in [1, 63, 64, 65, 257] {
            let logical: Vec<u8> = (0..K * size - 1).map(|i| (i * 29 + 3) as u8).collect();
            let mut padded = logical.clone();
            padded.resize(K * size, 0);
            let data: Vec<Vec<u8>> = padded.chunks(size).map(|part| part.to_vec()).collect();
            let expected = scalar.encode(&data).unwrap();
            let encoded = ec_codec_encode(&format(), &logical, size as u32);
            assert_eq!(encoded.error_code, 0);
            assert_eq!(encoded.shards.len(), N);
            for (index, shard) in encoded.shards.iter().enumerate() {
                assert_eq!(shard.index as usize, index);
                assert_eq!(shard.data, expected[index]);
            }
            let inputs: Vec<_> = encoded
                .shards
                .iter()
                .map(|shard| EcCodecInput {
                    index: shard.index,
                    data: &shard.data,
                })
                .collect();
            assert_eq!(
                ec_codec_verify(&format(), &inputs, logical.len() as u64, size as u32).error_code,
                0
            );
            let healthy: Vec<u16> = (1..=10).rev().collect();
            let sources: Vec<_> = healthy
                .iter()
                .map(|&index| EcCodecInput {
                    index,
                    data: &expected[index as usize],
                })
                .collect();
            let recovered = ec_codec_recover(&format(), &sources, logical.len() as u64, size as u32);
            assert_eq!(recovered.error_code, 0);
            assert_eq!(recovered.shards.len(), N);
            for (index, shard) in recovered.shards.iter().enumerate() {
                assert_eq!(shard.index as usize, index);
                assert_eq!(shard.data, expected[index]);
            }
            let mut sum = vec![vec![0u8; size]; 2];
            for &helper in &healthy {
                let result = ec_codec_contribute(
                    &format(),
                    &healthy,
                    &[11, 0],
                    helper,
                    &expected[helper as usize],
                );
                assert_eq!(result.error_code, 0);
                assert_eq!(result.shards.len(), 2);
                for (row, shard) in result.shards.iter().enumerate() {
                    assert_eq!(shard.index, [11, 0][row]);
                    assert_eq!(shard.data.len(), size);
                    for (out, &byte) in sum[row].iter_mut().zip(&shard.data) {
                        *out ^= byte;
                    }
                }
            }
            assert_eq!(sum, vec![expected[11].clone(), expected[0].clone()]);
        }
    }

    #[test]
    fn cached_plans_preserve_order_and_actual_helper_identity() {
        fn shared<T: Send + Sync>() {}
        shared::<Codec>();
        shared::<RepairPlan>();
        shared::<ContributionPlan>();

        let codec = codec(&format()).unwrap();
        assert!(std::ptr::eq(codec, super::codec(&format()).unwrap()));
        let cache = PlanCache::default();
        let input: Vec<Vec<u8>> = (0..K)
            .map(|i| (0..65).map(|j| (i * 17 + j) as u8).collect())
            .collect();
        let codeword = codec.encode(&input).unwrap();
        let mut healthy = [11, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let key = PlanKey::checked(&format(), &healthy, &[9, 10]).unwrap();
        healthy.reverse();
        let keys = [
            key,
            PlanKey::checked(&format(), &healthy, &[9, 10]).unwrap(),
            PlanKey::checked(&format(), &key.healthy, &[10, 9]).unwrap(),
            PlanKey::checked(&format(), &healthy, &[10, 9]).unwrap(),
        ];
        let mut retained = Vec::new();
        for key in keys {
            let plan = cache.repair(codec, key).unwrap();
            assert!(Arc::ptr_eq(&plan, &cache.repair(codec, key).unwrap()));
            for other in &retained {
                assert!(!Arc::ptr_eq(other, &plan));
            }
            retained.push(Arc::clone(&plan));
            let sources: Vec<_> = key.healthy.iter().map(|&i| codeword[i].clone()).collect();
            let expected: Vec<_> = key.targets().iter().map(|&i| codeword[i].clone()).collect();
            assert_eq!(plan.recover_slice(&sources).unwrap(), expected);
            let mut combined = vec![vec![0u8; 65]; key.target_count];
            let mut previous = None;
            for helper in key.healthy {
                let contribution_key = ContributionKey::checked(key, helper).unwrap();
                let contribution = cache.contribution(codec, contribution_key).unwrap();
                assert!(Arc::ptr_eq(
                    &contribution,
                    &cache.contribution(codec, contribution_key).unwrap()
                ));
                if let Some(previous) = previous {
                    assert!(!Arc::ptr_eq(&previous, &contribution));
                }
                assert_eq!(contribution.helper(), helper);
                assert_eq!(contribution.targets(), key.targets());
                for (sum, bytes) in combined
                    .iter_mut()
                    .zip(contribution.apply(&codeword[helper]).unwrap())
                {
                    for (sum, byte) in sum.iter_mut().zip(bytes) {
                        *sum ^= byte;
                    }
                }
                // A hit retains no bytes or length. Empty and different input
                // slices still perform this call's arithmetic.
                assert_eq!(
                    contribution.apply(&[]).unwrap(),
                    vec![Vec::<u8>::new(); key.target_count]
                );
                assert_eq!(
                    contribution.apply(&[0; 3]).unwrap(),
                    vec![vec![0; 3]; key.target_count]
                );
                previous = Some(contribution);
            }
            assert_eq!(combined, expected);
        }
        // The unused target slot is zero, which is also a valid shard number.
        // Therefore target_count is essential even when the arrays coincide.
        let healthy = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11];
        let one = PlanKey::checked(&format(), &healthy, &[10]).unwrap();
        let two = PlanKey::checked(&format(), &healthy, &[10, 0]).unwrap();
        let one = cache.repair(codec, one).unwrap();
        let two = cache.repair(codec, two).unwrap();
        assert!(!Arc::ptr_eq(&one, &two));
        let sources: Vec<_> = healthy.iter().map(|&i| codeword[i].clone()).collect();
        assert_eq!(one.recover_slice(&sources).unwrap(), vec![codeword[10].clone()]);
        assert_eq!(
            two.recover_slice(&sources).unwrap(),
            vec![codeword[10].clone(), codeword[0].clone()]
        );
    }

    #[test]
    fn cache_capacity_is_bounded_and_evicted_borrows_remain_valid() {
        let codec = codec(&format()).unwrap();
        let cache = PlanCache::default();
        let key =
            PlanKey::checked(&format(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], &[10, 11]).unwrap();
        let helper = ContributionKey::checked(key, 0).unwrap();
        let old = cache.repair(codec, key).unwrap();
        let old_contribution = cache.contribution(codec, helper).unwrap();
        // 66 missing pairs, both output orders, two actual helpers per pair:
        // enough distinct keys to evict both bounded FIFO caches.
        for a in 0..N {
            for b in a + 1..N {
                let healthy: Vec<_> = (0..N).filter(|&i| i != a && i != b).collect();
                for targets in [[a, b], [b, a]] {
                    let next = PlanKey::checked(&format(), &healthy, &targets).unwrap();
                    for &helper in &healthy[..2] {
                        cache
                            .contribution(codec, ContributionKey::checked(next, helper).unwrap())
                            .unwrap();
                    }
                    let entries = cache.entries.lock().unwrap();
                    assert!(entries.repairs.len() <= REPAIR_CACHE_CAPACITY);
                    assert!(entries.contributions.len() <= CONTRIBUTION_CACHE_CAPACITY);
                }
            }
        }
        assert_eq!(
            cache.entries.lock().unwrap().repairs.len(),
            REPAIR_CACHE_CAPACITY
        );
        assert_eq!(
            cache.entries.lock().unwrap().contributions.len(),
            CONTRIBUTION_CACHE_CAPACITY
        );
        assert!(!Arc::ptr_eq(&old, &cache.repair(codec, key).unwrap()));
        assert!(!Arc::ptr_eq(
            &old_contribution,
            &cache.contribution(codec, helper).unwrap()
        ));
        let data = vec![vec![7; 17]; K];
        assert_eq!(
            old.recover_slice(&data).unwrap(),
            codec
                .repair_plan(&key.healthy, key.targets())
                .unwrap()
                .recover_slice(&data)
                .unwrap()
        );
        assert_eq!(
            old_contribution.apply(&[9; 17]).unwrap(),
            old.contribution(0).unwrap().apply(&[9; 17]).unwrap()
        );
    }

    #[test]
    fn concurrent_same_key_misses_share_one_plan() {
        let codec = codec(&format()).unwrap();
        let cache = Arc::new(PlanCache::default());
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let key =
            PlanKey::checked(&format(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], &[11, 10]).unwrap();
        let helper = ContributionKey::checked(key, 9).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    (
                        cache.repair(codec, key).unwrap(),
                        cache.contribution(codec, helper).unwrap(),
                    )
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        for result in &results[1..] {
            assert!(Arc::ptr_eq(&results[0].0, &result.0));
            assert!(Arc::ptr_eq(&results[0].1, &result.1));
        }
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.repairs.len(), 1);
        assert_eq!(entries.contributions.len(), 1);
    }

    #[test]
    fn warmed_bridge_cache_does_not_bypass_request_validation() {
        let healthy = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(
            ec_codec_contribute(&format(), &healthy, &[10, 11], 0, &[1]).error_code,
            0
        );
        let mut bad_format = format();
        bad_format.field_polynomial = 0x11b;
        let mut duplicate = healthy;
        duplicate[9] = 0;
        let mut out_of_range = healthy;
        out_of_range[9] = 12;
        for result in [
            ec_codec_contribute(&bad_format, &healthy, &[10, 11], 0, &[1]),
            ec_codec_contribute(&format(), &healthy[..9], &[10, 11], 0, &[1]),
            ec_codec_contribute(&format(), &duplicate, &[10, 11], 0, &[1]),
            ec_codec_contribute(&format(), &out_of_range, &[10, 11], 0, &[1]),
            ec_codec_contribute(&format(), &healthy, &[], 0, &[1]),
            ec_codec_contribute(&format(), &healthy, &[10, 10], 0, &[1]),
            ec_codec_contribute(&format(), &healthy, &[9, 10], 0, &[1]),
            ec_codec_contribute(&format(), &healthy, &[10, 12], 0, &[1]),
            ec_codec_contribute(&format(), &healthy, &[10, 11], 10, &[1]),
            ec_codec_contribute(&format(), &healthy, &[10, 11], 12, &[1]),
        ] {
            assert_eq!(result.error_code, INVALID);
            assert!(result.shards.is_empty());
        }

        let mut encoded = ec_codec_encode(&format(), &[1, 2], 1);
        assert_eq!(encoded.error_code, 0);
        for corrupt in [false, true] {
            if corrupt {
                encoded.shards[9].data[0] = 1;
            }
            let input: Vec<_> = encoded.shards[..K]
                .iter()
                .map(|shard| EcCodecInput {
                    index: shard.index,
                    data: &shard.data,
                })
                .collect();
            let result = ec_codec_recover(&format(), &input, 2, 1);
            assert_eq!(result.error_code, if corrupt { CORRUPT } else { 0 });
            if corrupt {
                assert!(result.shards.is_empty());
            }
        }
    }

    #[test]
    fn poisoned_cache_is_an_explicit_internal_error() {
        let cache = PlanCache::default();
        let codec = codec(&format()).unwrap();
        let key =
            PlanKey::checked(&format(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], &[10]).unwrap();
        cache.repair(codec, key).unwrap();
        let failure = catch_unwind(|| {
            let _guard = cache.entries.lock().unwrap();
            panic!("injected cache construction unwind");
        });
        assert!(failure.is_err());
        assert_eq!(cache.repair(codec, key).unwrap_err().0, FOUND_BUG);
        let helper = ContributionKey::checked(key, 0).unwrap();
        assert_eq!(cache.contribution(codec, helper).unwrap_err().0, FOUND_BUG);
    }

    #[test]
    fn unexpected_unwind_is_contained_at_bridge_boundary() {
        let result = boundary(|| panic!("injected bridge unwind"));
        assert_eq!(result.error_code, FOUND_BUG);
        assert!(result.shards.is_empty());
    }
}
