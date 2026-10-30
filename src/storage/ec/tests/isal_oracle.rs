#![cfg(feature = "isal-oracle")]

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

#[link(name = "isal")]
extern "C" {
    fn gf_gen_cauchy1_matrix(matrix: *mut u8, rows: i32, columns: i32);
    fn ec_init_tables(k: i32, rows: i32, coefficients: *mut u8, tables: *mut u8);
    fn ec_encode_data(
        length: i32,
        k: i32,
        rows: i32,
        tables: *mut u8,
        input: *mut *mut u8,
        output: *mut *mut u8,
    );
}

fn isal_encode(data: &[Vec<u8>], m: usize) -> Vec<Vec<u8>> {
    let k = data.len();
    let logical_len = data[0].len();
    assert!(k > 0 && m > 0 && k + m <= 256);
    assert!(data.iter().all(|shard| shard.len() == logical_len));
    // Deliberately pad the independent oracle's input. Exercise arbitrary
    // logical lengths without relying on architecture-specific short vectors.
    let physical_len = logical_len.max(1).div_ceil(64) * 64;
    assert!(physical_len <= i32::MAX as usize);
    let mut matrix = vec![0; (k + m) * k];
    let mut tables = vec![0; 32 * k * m];
    let mut input = data.to_vec();
    for shard in &mut input {
        shard.resize(physical_len, 0);
    }
    let mut output = vec![vec![0; physical_len]; m];
    let mut input_ptrs: Vec<_> = input.iter_mut().map(Vec::as_mut_ptr).collect();
    let mut output_ptrs: Vec<_> = output.iter_mut().map(Vec::as_mut_ptr).collect();
    // All arrays are sized above; source and destination vectors are disjoint,
    // live for both calls, and the field parameters fit the C API types.
    unsafe {
        gf_gen_cauchy1_matrix(matrix.as_mut_ptr(), (k + m) as i32, k as i32);
        ec_init_tables(
            k as i32,
            m as i32,
            matrix[k * k..].as_mut_ptr(),
            tables.as_mut_ptr(),
        );
        ec_encode_data(
            physical_len as i32,
            k as i32,
            m as i32,
            tables.as_mut_ptr(),
            input_ptrs.as_mut_ptr(),
            output_ptrs.as_mut_ptr(),
        );
    }
    for shard in &mut output {
        shard.truncate(logical_len);
    }
    let mut all = data.to_vec();
    all.extend(output);
    all
}

fn data(k: usize, length: usize) -> Vec<Vec<u8>> {
    let mut state = 0x3f5ec10u64;
    (0..k)
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
        .collect()
}

#[test]
fn encoding_matches_system_isal_for_multiple_codes_and_unaligned_lengths() {
    for (k, m) in [(1, 1), (2, 2), (4, 2), (10, 2), (6, 4), (15, 5)] {
        for length in [0, 1, 15, 16, 31, 32, 63, 64, 65, 257, 4099] {
            let source = data(k, length);
            let expected = isal_encode(&source, m);
            for codec in codecs(k, m) {
                assert_eq!(
                    codec.encode(&source).unwrap(),
                    expected,
                    "k={k} m={m} length={length}"
                );
            }
        }
    }
}

#[test]
fn all_double_erasures_recover_shards_encoded_by_system_isal() {
    let expected = isal_encode(&data(10, 259), 2);
    for codec in codecs(10, 2) {
        for a in 0..12 {
            for b in a + 1..12 {
                let mut damaged: Vec<_> = expected.iter().cloned().map(Some).collect();
                damaged[a] = None;
                damaged[b] = None;
                codec.reconstruct(&mut damaged).unwrap();
                assert_eq!(
                    damaged,
                    expected.iter().cloned().map(Some).collect::<Vec<_>>(),
                    "erasures {a},{b}"
                );
            }
        }
    }
}
