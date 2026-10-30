use hf3fs_ec::{Backend, Codec, RepairPlan};
use std::ops::Range;

fn codecs(k: usize, m: usize) -> Vec<Codec> {
    let scalar = Codec::new(k, m).unwrap();
    #[cfg(feature = "isal-backend")]
    {
        vec![scalar, Codec::with_backend(k, m, Backend::Isal).unwrap()]
    }
    #[cfg(not(feature = "isal-backend"))]
    {
        vec![scalar]
    }
}

// Independent original codeword: polynomial convolution and long division,
// with inverses found by search. No production encode, recover or coefficients
// are used to produce the expected shards.
fn polynomial_product(a: u8, b: u8) -> u8 {
    let mut product = 0u32;
    for bit in 0..8 {
        if b & (1 << bit) != 0 {
            product ^= u32::from(a) << bit;
        }
    }
    for bit in (8..=14).rev() {
        if product & (1 << bit) != 0 {
            product ^= 0x11d << (bit - 8);
        }
    }
    product as u8
}

fn original(k: usize, m: usize, length: usize) -> Vec<Vec<u8>> {
    let mut state = 0x93cf_2a17_6de8_541bu64;
    let mut shards: Vec<Vec<_>> = (0..k)
        .map(|_| {
            (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect()
        })
        .collect();
    for row in k..k + m {
        let mut parity = vec![0; length];
        for (column, input) in shards[..k].iter().enumerate() {
            let coefficient = (1..=255)
                .find(|&candidate| polynomial_product((row ^ column) as u8, candidate) == 1)
                .unwrap();
            for (out, &byte) in parity.iter_mut().zip(input) {
                *out ^= polynomial_product(coefficient, byte);
            }
        }
        shards.push(parity);
    }
    shards
}

fn accumulated(
    plan: &RepairPlan,
    source: &[Vec<u8>],
    range: Range<usize>,
    helper_order: &[usize],
) -> Vec<Vec<u8>> {
    let mut output = vec![vec![0; range.len()]; plan.targets().len()];
    for &helper in helper_order {
        let contribution = plan.contribution(helper).unwrap();
        assert_eq!(contribution.helper(), helper);
        assert_eq!(contribution.healthy(), plan.healthy());
        assert_eq!(contribution.targets(), plan.targets());
        assert_eq!(contribution.backend(), plan.backend());
        let partial = contribution.apply(&source[helper][range.clone()]).unwrap();
        assert_eq!(partial.len(), output.len());
        for (out, part) in output.iter_mut().zip(partial) {
            assert_eq!(part.len(), out.len());
            for (byte, term) in out.iter_mut().zip(part) {
                *byte ^= term;
            }
        }
    }
    output
}

fn check_orders(codec: &Codec, source: &[Vec<u8>], healthy: &[usize], targets: &[usize]) {
    let mut reordered = healthy.to_vec();
    for variant in 0..3 {
        if variant == 1 {
            reordered.reverse();
        } else if variant == 2 {
            reordered.rotate_left(3);
        }
        let plan = codec.repair_plan(&reordered, targets).unwrap();
        // Accumulation order deliberately differs from coefficient column order.
        let mut arrival = reordered.clone();
        arrival.rotate_right(1);
        let expected: Vec<_> = targets.iter().map(|&i| source[i].clone()).collect();
        assert_eq!(
            accumulated(&plan, source, 0..source[0].len(), &arrival),
            expected,
            "helpers={reordered:?} targets={targets:?} backend={:?}",
            codec.backend()
        );
    }
}

#[test]
fn all_single_and_double_erasures_match_independent_original_shards() {
    let source = original(10, 2, 131);
    let before = source.clone();
    for codec in codecs(10, 2) {
        for first in 0..12 {
            let available: Vec<_> = (0..12).filter(|&i| i != first).collect();
            // Single erasures leave 11 candidates: exercise all 11 choices of
            // the unused shard rather than always selecting the lowest 10.
            for &unused in &available {
                let healthy: Vec<_> = available.iter().copied().filter(|&i| i != unused).collect();
                check_orders(&codec, &source, &healthy, &[first]);
            }
            for second in first + 1..12 {
                let healthy: Vec<_> = (0..12).filter(|&i| i != first && i != second).collect();
                check_orders(&codec, &source, &healthy, &[second, first]);
            }
        }
    }
    assert_eq!(source, before);
}

fn permutations(values: &mut [usize], start: usize, output: &mut Vec<Vec<usize>>) {
    if start == values.len() {
        output.push(values.to_vec());
        return;
    }
    for index in start..values.len() {
        values.swap(start, index);
        permutations(values, start + 1, output);
        values.swap(start, index);
    }
}

#[test]
fn every_small_helper_and_arrival_permutation_preserves_target_order() {
    let source = original(4, 2, 67);
    let expected = vec![source[5].clone(), source[0].clone()];
    let mut orders = Vec::new();
    permutations(&mut [1, 2, 3, 4], 0, &mut orders);
    assert_eq!(orders.len(), 24);
    for codec in codecs(4, 2) {
        for healthy in &orders {
            let plan = codec.repair_plan(healthy, &[5, 0]).unwrap();
            for arrival in &orders {
                assert_eq!(accumulated(&plan, &source, 0..67, arrival), expected);
            }
        }
    }
}

#[test]
fn reused_contributions_recover_every_short_tail_and_empty_slice() {
    let source = original(10, 2, 195);
    let before = source.clone();
    let healthy = [11, 3, 10, 4, 9, 5, 8, 6, 7, 2];
    for codec in codecs(10, 2) {
        let plan = codec.repair_plan(&healthy, &[1, 0]).unwrap();
        let contributions: Vec<_> = healthy
            .iter()
            .map(|&helper| plan.contribution(helper).unwrap())
            .collect();
        for length in 0..=193 {
            let mut recovered = vec![vec![0; length]; 2];
            for contribution in contributions.iter().rev() {
                // A nonzero offset exercises borrowed, unaligned source slices.
                let input = &source[contribution.helper()][1..1 + length];
                let partial = contribution.apply(input).unwrap();
                assert_eq!(partial.len(), 2);
                for (row, output) in recovered.iter_mut().zip(partial) {
                    assert_eq!(output.len(), length);
                    for (byte, term) in row.iter_mut().zip(output) {
                        *byte ^= term;
                    }
                }
            }
            assert_eq!(
                recovered,
                vec![
                    source[1][1..1 + length].to_vec(),
                    source[0][1..1 + length].to_vec()
                ],
                "length={length} backend={:?}",
                codec.backend()
            );
        }
    }
    assert_eq!(source, before);
}

#[test]
fn rejects_nonmembers_and_keeps_actual_helper_identity() {
    let codec = Codec::new(10, 2).unwrap();
    let healthy = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    let plan = codec.repair_plan(&healthy, &[0]).unwrap();
    for invalid in [0, 11, 12, usize::MAX] {
        assert!(plan.contribution(invalid).is_err());
    }
    let contribution = plan.contribution(10).unwrap();
    assert_eq!(contribution.helper(), 10);
    assert_eq!(contribution.backend(), Backend::Scalar);
    assert_eq!(contribution.apply(&[]).unwrap(), vec![Vec::<u8>::new()]);
    // Input length belongs to the caller's slice protocol. Every local byte
    // length is valid, including zero; outputs must never silently truncate it.
    for length in [1, 63, 64, 65, 4099] {
        let input = vec![231; length];
        let output = contribution.apply(&input).unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].len(), length);
        assert!(input.iter().all(|&byte| byte == 231));
    }
}

#[cfg(feature = "isal-backend")]
#[test]
fn isal_contributions_match_scalar_for_every_short_length() {
    let source = original(10, 2, 195);
    let healthy = [11, 9, 10, 8, 2, 3, 4, 5, 6, 7];
    let scalar = Codec::new(10, 2)
        .unwrap()
        .repair_plan(&healthy, &[0, 1])
        .unwrap();
    let isal = Codec::with_backend(10, 2, Backend::Isal)
        .unwrap()
        .repair_plan(&healthy, &[0, 1])
        .unwrap();
    for helper in healthy {
        let scalar = scalar.contribution(helper).unwrap();
        let isal = isal.contribution(helper).unwrap();
        assert_eq!(isal.backend(), Backend::Isal);
        for length in 0..=193 {
            let input = &source[helper][1..1 + length];
            assert_eq!(isal.apply(input).unwrap(), scalar.apply(input).unwrap());
        }
    }
}
