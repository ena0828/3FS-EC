use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use hf3fs_ec::{
    repair_pipeline, repair_sequential, Codec, Error, PipelineConfig, RepairPlan, Result,
    ShardStore,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Read,
    ShortRead,
    Write,
    Commit,
    PanicRead,
    PanicWrite,
    Abort,
}

struct Store {
    original: Vec<Vec<u8>>,
    staged: Mutex<Vec<Vec<u8>>>,
    fault: Fault,
    committed: AtomicBool,
    aborted: AtomicBool,
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl ShardStore for Store {
    fn read_shard(&self, shard: usize, offset: usize, length: usize) -> Result<Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if offset >= 7 {
            match self.fault {
                Fault::Read | Fault::Abort => return Err(Error("injected read error".into())),
                Fault::ShortRead => return Ok(vec![0; length - 1]),
                Fault::PanicRead => panic!("injected backend panic"),
                _ => {}
            }
        }
        Ok(self.original[shard][offset..offset + length].to_vec())
    }

    fn write_shard(&self, shard: usize, offset: usize, data: &[u8]) -> Result<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if offset >= 7 {
            match self.fault {
                Fault::Write => return Err(Error("injected write error".into())),
                Fault::PanicWrite => panic!("injected backend panic"),
                _ => {}
            }
        }
        self.staged.lock().unwrap()[shard][offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn commit(&self, targets: &[usize]) -> Result<()> {
        if self.fault == Fault::Commit {
            return Err(Error("injected commit error".into()));
        }
        let staged = self.staged.lock().unwrap();
        for &target in targets {
            if staged[target] != self.original[target] {
                return Err(Error("incorrect staged bytes".into()));
            }
        }
        self.committed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn abort(&self, _targets: &[usize]) -> Result<()> {
        self.aborted.store(true, Ordering::SeqCst);
        if self.fault == Fault::Abort {
            return Err(Error("injected abort error".into()));
        }
        Ok(())
    }
}

fn fixture(length: usize, fault: Fault) -> (Store, RepairPlan) {
    let codec = Codec::new(10, 2).unwrap();
    let data: Vec<Vec<_>> = (0..10)
        .map(|i| {
            (0..length)
                .map(|j| ((i * 101 + j * 29) % 256) as u8)
                .collect()
        })
        .collect();
    let original = codec.encode(&data).unwrap();
    let store = Store {
        original,
        staged: Mutex::new(vec![vec![0; length]; 12]),
        fault,
        committed: AtomicBool::new(false),
        aborted: AtomicBool::new(false),
        reads: AtomicUsize::new(0),
        writes: AtomicUsize::new(0),
    };
    let plan = codec
        .repair_plan(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 11], &[0, 10])
        .unwrap();
    (store, plan)
}

#[test]
fn pipeline_and_sequential_match_across_tail_and_window_boundaries() {
    for length in [0, 1, 6, 7, 8, 31, 1025] {
        for slice_len in [1, 7, 16, 2048] {
            for queue_depth in [1, 2, 4] {
                let config = PipelineConfig {
                    shard_len: length,
                    slice_len,
                    queue_depth,
                };
                let (seq, plan) = fixture(length, Fault::None);
                let (pipe, _) = fixture(length, Fault::None);
                let baseline = repair_sequential(&seq, &plan, config).unwrap();
                let candidate = repair_pipeline(&pipe, &plan, config).unwrap();
                assert_eq!(baseline, candidate);
                assert_eq!(candidate.read_bytes, length * 10);
                assert_eq!(candidate.written_bytes, length * 2);
                assert_eq!(*seq.staged.lock().unwrap(), *pipe.staged.lock().unwrap());
                assert!(pipe.committed.load(Ordering::SeqCst));
                assert!(!pipe.aborted.load(Ordering::SeqCst));
            }
        }
    }
}

#[test]
fn faults_terminate_join_and_abort_with_a_bounded_queue() {
    for fault in [
        Fault::Read,
        Fault::ShortRead,
        Fault::Write,
        Fault::Commit,
        Fault::PanicRead,
        Fault::PanicWrite,
        Fault::Abort,
    ] {
        let (store, plan) = fixture(4099, fault);
        let store = Arc::new(store);
        let owned = Arc::clone(&store);
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = repair_pipeline(
                owned.as_ref(),
                &plan,
                PipelineConfig {
                    shard_len: 4099,
                    slice_len: 7,
                    queue_depth: 1,
                },
            );
            tx.send(result).unwrap();
        });
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("repair failed to terminate");
        assert!(result.is_err());
        if fault == Fault::Abort {
            let message = result.unwrap_err().0;
            assert!(message.contains("injected read error") && message.contains("abort failed"));
        }
        worker.join().unwrap();
        assert!(store.aborted.load(Ordering::SeqCst));
        assert!(!store.committed.load(Ordering::SeqCst));
        let reads_after = store.reads.load(Ordering::SeqCst);
        let writes_after = store.writes.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(reads_after, store.reads.load(Ordering::SeqCst));
        assert_eq!(writes_after, store.writes.load(Ordering::SeqCst));
    }
}

#[test]
fn rejects_resource_errors_before_touching_backend() {
    let (store, plan) = fixture(1, Fault::None);
    for config in [
        PipelineConfig {
            shard_len: 1,
            slice_len: 0,
            queue_depth: 1,
        },
        PipelineConfig {
            shard_len: 1,
            slice_len: 1,
            queue_depth: 0,
        },
        PipelineConfig {
            shard_len: 1,
            slice_len: 1,
            queue_depth: 1025,
        },
        PipelineConfig {
            shard_len: usize::MAX,
            slice_len: 1,
            queue_depth: 1,
        },
        PipelineConfig {
            shard_len: 1024 * 1024,
            slice_len: 1024 * 1024,
            queue_depth: 64,
        },
    ] {
        assert!(repair_pipeline(&store, &plan, config).is_err());
    }
    assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert!(!store.committed.load(Ordering::SeqCst));
}

#[test]
fn a_slow_writer_overlaps_reads_without_unbounded_prefetch() {
    struct GatedStore {
        inner: Store,
        first_write: Mutex<Option<mpsc::Sender<()>>>,
        released: Mutex<bool>,
        gate: Condvar,
    }
    impl ShardStore for GatedStore {
        fn read_shard(&self, shard: usize, offset: usize, length: usize) -> Result<Vec<u8>> {
            self.inner.read_shard(shard, offset, length)
        }
        fn write_shard(&self, shard: usize, offset: usize, data: &[u8]) -> Result<()> {
            if let Some(tx) = self.first_write.lock().unwrap().take() {
                tx.send(()).unwrap();
                let mut released = self.released.lock().unwrap();
                while !*released {
                    released = self.gate.wait(released).unwrap();
                }
            }
            self.inner.write_shard(shard, offset, data)
        }
        fn commit(&self, targets: &[usize]) -> Result<()> {
            self.inner.commit(targets)
        }
        fn abort(&self, targets: &[usize]) -> Result<()> {
            self.inner.abort(targets)
        }
    }
    let (inner, plan) = fixture(7000, Fault::None);
    let (started_tx, started_rx) = mpsc::channel();
    let store = Arc::new(GatedStore {
        inner,
        first_write: Mutex::new(Some(started_tx)),
        released: Mutex::new(false),
        gate: Condvar::new(),
    });
    let owned = Arc::clone(&store);
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        done_tx
            .send(repair_pipeline(
                owned.as_ref(),
                &plan,
                PipelineConfig {
                    shard_len: 7000,
                    slice_len: 7,
                    queue_depth: 1,
                },
            ))
            .unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while store.inner.reads.load(Ordering::SeqCst) < 20 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    let overlapping = store.inner.reads.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(20));
    let prefetched = store.inner.reads.load(Ordering::SeqCst);
    // Release the gate before assertions, so a failed test cannot strand workers.
    *store.released.lock().unwrap() = true;
    store.gate.notify_all();
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert!(
        overlapping >= 20,
        "next slice was not read while writer was blocked"
    );
    assert!(
        prefetched <= 60,
        "prefetch escaped the bounded stage buffers"
    );
    assert!(store.inner.committed.load(Ordering::SeqCst));
}
