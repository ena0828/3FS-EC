#![cfg(feature = "isal-backend")]
use hf3fs_ec::{
    repair_pipeline, repair_sequential, Backend, Codec, PipelineConfig, Result, ShardStore,
};
use std::sync::Mutex;

fn data(k: usize, length: usize) -> Vec<Vec<u8>> {
    let mut seed = 20261029u64;
    (0..k)
        .map(|_| {
            (0..length)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect()
        })
        .collect()
}

#[test]
fn backend_selection_and_every_short_tail_match_scalar() {
    assert_eq!(Codec::new(10, 2).unwrap().backend(), Backend::Scalar);
    for (k, m) in [(1, 1), (4, 3), (10, 2), (6, 7)] {
        let scalar = Codec::new(k, m).unwrap();
        let isal = Codec::with_backend(k, m, Backend::Isal).unwrap();
        assert_eq!(isal.backend(), Backend::Isal);
        for length in 0..=193 {
            let source = data(k, length);
            let original = scalar.encode(&source).unwrap();
            assert_eq!(isal.encode(&source).unwrap(), original);
            let healthy: Vec<_> = (1..=k).rev().collect();
            let targets: Vec<_> = [0, k + m - 1].into_iter().take(m.min(2)).collect();
            let plan = isal.repair_plan(&healthy, &targets).unwrap();
            assert_eq!(plan.backend(), Backend::Isal);
            let input: Vec<_> = healthy.iter().map(|&i| original[i].clone()).collect();
            let before = input.clone();
            assert_eq!(
                plan.recover_slice(&input).unwrap(),
                targets
                    .iter()
                    .map(|&i| original[i].clone())
                    .collect::<Vec<_>>()
            );
            assert_eq!(input, before, "FFI must not modify input");
        }
    }
    assert!(Codec::with_backend(0, 2, Backend::Isal).is_err());
    let codec = Codec::with_backend(10, 2, Backend::Isal).unwrap();
    assert!(codec.encode(&data(9, 65)).is_err());
    let mut ragged = data(10, 65);
    ragged[1].push(0);
    assert!(codec.encode(&ragged).is_err());
}

struct MemoryStore {
    original: Vec<Vec<u8>>,
    staged: Mutex<Vec<Vec<u8>>>,
}
impl ShardStore for MemoryStore {
    fn read_shard(&self, shard: usize, offset: usize, length: usize) -> Result<Vec<u8>> {
        Ok(self.original[shard][offset..offset + length].to_vec())
    }
    fn write_shard(&self, shard: usize, offset: usize, bytes: &[u8]) -> Result<()> {
        self.staged.lock().unwrap()[shard][offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn commit(&self, targets: &[usize]) -> Result<()> {
        for &target in targets {
            assert_eq!(self.staged.lock().unwrap()[target], self.original[target]);
        }
        Ok(())
    }
}

#[test]
fn two_backends_by_two_strategies_agree_for_all_short_tails() {
    // slice=128 guarantees ISA-L executes full slices; tails cover 0..=63.
    // slice=31 exercises scalar fallback in an explicitly ISA-L-selected plan.
    for tail in 0..64 {
        let length = 128 + tail;
        let original = Codec::new(10, 2)
            .unwrap()
            .encode(&data(10, length))
            .unwrap();
        for slice_len in [31, 128] {
            for backend in [Backend::Scalar, Backend::Isal] {
                let codec = Codec::with_backend(10, 2, backend).unwrap();
                let plan = codec
                    .repair_plan(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], &[0, 11])
                    .unwrap();
                for pipeline in [false, true] {
                    let store = MemoryStore {
                        original: original.clone(),
                        staged: Mutex::new(vec![vec![0; length]; 12]),
                    };
                    let config = PipelineConfig {
                        shard_len: length,
                        slice_len,
                        queue_depth: 1,
                    };
                    let stats = if pipeline {
                        repair_pipeline(&store, &plan, config)
                    } else {
                        repair_sequential(&store, &plan, config)
                    }
                    .unwrap();
                    assert_eq!(stats.read_bytes, length * 10);
                    assert_eq!(stats.written_bytes, length * 2);
                    for target in [0, 11] {
                        assert_eq!(store.staged.lock().unwrap()[target], original[target]);
                    }
                }
            }
        }
    }
}

#[test]
fn shared_prepared_tables_are_reusable_across_threads() {
    let codec = Codec::with_backend(10, 2, Backend::Isal).unwrap();
    let original = Codec::new(10, 2).unwrap().encode(&data(10, 257)).unwrap();
    let plan = codec
        .repair_plan(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], &[0, 11])
        .unwrap();
    let inputs: Vec<_> = plan
        .healthy()
        .iter()
        .map(|&i| original[i].clone())
        .collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    for _ in 0..8 {
                        assert_eq!(
                            plan.recover_slice(&inputs).unwrap(),
                            [original[0].clone(), original[11].clone()]
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
}

#[test]
#[ignore = "run only after competing builds stop; in-memory benchmark preparation"]
fn release_four_cell_measurement_preparation() {
    let length = 64 * 1024;
    let original = Codec::new(10, 2)
        .unwrap()
        .encode(&data(10, length))
        .unwrap();
    let plans: Vec<_> = [Backend::Scalar, Backend::Isal]
        .into_iter()
        .map(|backend| {
            Codec::with_backend(10, 2, backend)
                .unwrap()
                .repair_plan(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], &[0, 11])
                .unwrap()
        })
        .collect();
    // Rotate four cells through all positions. This is a bounded preparation
    // harness, not enough repetitions for a throughput or tail-latency claim.
    for round in 0..4 {
        for position in 0..4 {
            let cell = (round + position) % 4;
            let backend = cell / 2;
            let pipeline = cell % 2 == 1;
            let store = MemoryStore {
                original: original.clone(),
                staged: Mutex::new(vec![vec![0; length]; 12]),
            };
            let config = PipelineConfig {
                shard_len: length,
                slice_len: 4096,
                queue_depth: 2,
            };
            let start = std::time::Instant::now();
            let stats = if pipeline {
                repair_pipeline(&store, &plans[backend], config)
            } else {
                repair_sequential(&store, &plans[backend], config)
            }
            .unwrap();
            let elapsed_ns = start.elapsed().as_nanos();
            println!("{{\"scope\":\"memory-backend-preparation\",\"backend\":\"{}\",\"pipeline\":{},\"round\":{},\"position\":{},\"read_bytes\":{},\"written_bytes\":{},\"elapsed_ns\":{},\"performance_claim\":false}}",
                if backend == 0 { "scalar" } else { "isal" }, pipeline, round, position, stats.read_bytes, stats.written_bytes, elapsed_ns);
        }
    }
}
