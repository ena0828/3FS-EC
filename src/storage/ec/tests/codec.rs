use hf3fs_ec::Codec;

fn codecs(k: usize, m: usize) -> Vec<Codec> {
    let scalar = Codec::new(k, m).unwrap();
    #[cfg(feature = "isal-backend")]
    {
        vec![
            scalar,
            Codec::with_backend(k, m, hf3fs_ec::Backend::Isal).unwrap(),
        ]
    }
    #[cfg(not(feature = "isal-backend"))]
    {
        vec![scalar]
    }
}

// Independent oracle: carryless polynomial convolution followed by long
// division, with inverses found by exhaustive search rather than exponentiation.
fn polynomial_product(a: u8, b: u8) -> u8 {
    let mut value = 0u32;
    for bit in 0..8 {
        if b & (1 << bit) != 0 {
            value ^= (a as u32) << bit;
        }
    }
    for bit in (8..=14).rev() {
        if value & (1 << bit) != 0 {
            value ^= 0x11d << (bit - 8);
        }
    }
    value as u8
}

fn oracle_encode(data: &[Vec<u8>], parity: usize) -> Vec<Vec<u8>> {
    let k = data.len();
    let mut result = data.to_vec();
    for i in k..k + parity {
        let mut output = vec![0; data[0].len()];
        for (j, input) in data.iter().enumerate() {
            let coefficient = (1..=255)
                .find(|&c| polynomial_product((i ^ j) as u8, c) == 1)
                .unwrap();
            for (dest, &src) in output.iter_mut().zip(input) {
                *dest ^= polynomial_product(coefficient, src);
            }
        }
        result.push(output);
    }
    result
}

fn data(k: usize, length: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..length)
                .map(|j| ((i * 73 + j * 31 + j / 251) % 256) as u8)
                .collect()
        })
        .collect()
}

#[test]
fn encoding_matches_independent_polynomial_oracle() {
    for (k, m) in [(1, 1), (4, 2), (10, 2), (6, 4), (255, 1), (1, 255)] {
        for length in [0, 1, 17, 257] {
            let input = data(k, length);
            let expected = oracle_encode(&input, m);
            for codec in codecs(k, m) {
                assert_eq!(codec.encode(&input).unwrap(), expected);
            }
        }
    }
    assert_eq!(
        oracle_encode(&[vec![1], vec![2]], 2),
        vec![vec![1], vec![2], vec![123], vec![245]]
    );
}

#[test]
fn all_66_double_and_12_single_erasures_recover_oracle_shards() {
    let original = oracle_encode(&data(10, 257), 2);
    for codec in codecs(10, 2) {
        for a in 0..12 {
            let mut single: Vec<_> = original.iter().cloned().map(Some).collect();
            single[a] = None;
            codec.reconstruct(&mut single).unwrap();
            assert_eq!(
                single,
                original.iter().cloned().map(Some).collect::<Vec<_>>()
            );
            for b in a + 1..12 {
                let mut damaged: Vec<_> = original.iter().cloned().map(Some).collect();
                damaged[a] = None;
                damaged[b] = None;
                codec.reconstruct(&mut damaged).unwrap();
                assert_eq!(
                    damaged,
                    original.iter().cloned().map(Some).collect::<Vec<_>>(),
                    "erasures {a},{b}"
                );
            }
        }
    }
}

#[test]
fn reconstructs_multiple_parities_empty_shards_and_reordered_helpers() {
    for codec in codecs(4, 3) {
        for length in [0, 1, 31, 1025] {
            let original = oracle_encode(&data(4, length), 3);
            let mut damaged: Vec<_> = original.iter().cloned().map(Some).collect();
            for index in [0, 3, 6] {
                damaged[index] = None;
            }
            codec.reconstruct(&mut damaged).unwrap();
            assert_eq!(
                damaged,
                original.iter().cloned().map(Some).collect::<Vec<_>>()
            );
            let healthy = [5, 4, 2, 1];
            let plan = codec.repair_plan(&healthy, &[6, 3, 0]).unwrap();
            let input: Vec<_> = healthy.iter().map(|&i| original[i].clone()).collect();
            assert_eq!(
                plan.recover_slice(&input).unwrap(),
                [6, 3, 0].map(|i| original[i].clone())
            );
        }
    }
}

#[test]
fn malformed_parameters_and_excessive_erasures_are_rejected_without_mutation() {
    for (k, m) in [(0, 2), (10, 0), (256, 1), (usize::MAX, 1)] {
        assert!(Codec::new(k, m).is_err());
    }
    let codec = Codec::new(4, 2).unwrap();
    assert!(codec.encode(&data(3, 2)).is_err());
    let mut unequal = data(4, 2);
    unequal[1].push(0);
    assert!(codec.encode(&unequal).is_err());
    for (healthy, targets) in [
        (vec![0, 1, 1, 3], vec![4]),
        (vec![0, 1, 2, 3], vec![3]),
        (vec![0, 1, 2, 3], vec![6]),
        (vec![0, 1, 2], vec![3]),
        (vec![0, 1, 2, 3], vec![]),
        (vec![0, 1, 2, 3], vec![4, 4]),
    ] {
        assert!(codec.repair_plan(&healthy, &targets).is_err());
    }
    let mut missing = vec![
        None,
        None,
        None,
        Some(vec![1]),
        Some(vec![2]),
        Some(vec![3]),
    ];
    let before = missing.clone();
    assert!(codec.reconstruct(&mut missing).is_err());
    assert_eq!(missing, before);
    let mut unequal: Vec<_> = data(6, 1).into_iter().map(Some).collect();
    unequal[0] = Some(vec![1, 2]);
    assert!(codec.reconstruct(&mut unequal).is_err());
    assert!(codec.reconstruct(&mut []).is_err());
}
