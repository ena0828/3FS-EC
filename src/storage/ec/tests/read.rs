use hf3fs_ec::read::*;
use hf3fs_ec::{Codec, Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Behavior {
    Good,
    Error,
    Slow,
    Corrupt,
    Stale,
    WrongOffset,
    Short,
    Panic,
}

struct Reader {
    shards: Vec<Vec<u8>>,
    behavior: Vec<Behavior>,
    active: AtomicUsize,
    peak: AtomicUsize,
    started: Mutex<Vec<usize>>,
}

struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ShardReader for Reader {
    fn read(&self, request: &ReadRequest, control: &ReadControl) -> Result<ReadReply> {
        let count = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let _active = Active(&self.active);
        self.peak.fetch_max(count, Ordering::SeqCst);
        self.started.lock().unwrap().push(request.shard);
        let mut reply = ReadReply {
            request: request.clone(),
            bytes: self.shards[request.shard].clone(),
        };
        match self.behavior[request.shard] {
            Behavior::Good => {}
            Behavior::Error => return Err(Error("injected transport failure".into())),
            Behavior::Slow => loop {
                control.check()?;
                std::thread::sleep(Duration::from_millis(1));
            },
            Behavior::Corrupt => reply.bytes[0] ^= 1,
            Behavior::Stale => reply.request.generation += 1,
            Behavior::WrongOffset => reply.request.offset += 1,
            Behavior::Short => {
                reply.bytes.pop();
            }
            Behavior::Panic => panic!("injected backend panic"),
        }
        Ok(reply)
    }
}

fn fixture() -> (Codec, Reader, Vec<ReadRequest>) {
    let codec = Codec::new(10, 2).unwrap();
    let data: Vec<_> = (0..10)
        .map(|i| (0..193).map(|j| (i * 19 + j * 7) as u8).collect())
        .collect();
    let shards = codec.encode(&data).unwrap();
    let requests = shards
        .iter()
        .enumerate()
        .map(|(shard, bytes)| ReadRequest {
            stripe: 0x123456789abcdef,
            generation: 42,
            shard,
            offset: 8192,
            length: bytes.len(),
            crc32c: crc32c(bytes),
        })
        .collect();
    (
        codec,
        Reader {
            shards,
            behavior: vec![Behavior::Good; 12],
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            started: Mutex::new(Vec::new()),
        },
        requests,
    )
}

fn config() -> ReadConfig {
    ReadConfig {
        required: 10,
        initial: 11,
        max_in_flight: 12,
        hedge_after: Duration::from_millis(5),
        deadline: Instant::now() + Duration::from_secs(3),
        max_buffer_bytes: 1 << 20,
    }
}

#[test]
fn crc32c_matches_standard_check_vector() {
    assert_eq!(crc32c(b"123456789"), 0xe3069283);
    assert_eq!(crc32c(b""), 0);
}

#[test]
fn every_single_and_double_failure_yields_decodable_same_format_quorum() {
    for first in 0..12 {
        for second in first..12 {
            let (codec, mut reader, requests) = fixture();
            reader.behavior[first] = Behavior::Error;
            reader.behavior[second] = Behavior::Error;
            let selection =
                read_quorum(&reader, &requests, config(), &CancellationToken::default()).unwrap();
            assert_eq!(selection.shards.len(), 10);
            assert_eq!(reader.active.load(Ordering::SeqCst), 0);
            let mut received = vec![None; 12];
            for reply in selection.shards {
                assert_ne!(reply.request.shard, first);
                assert_ne!(reply.request.shard, second);
                received[reply.request.shard] = Some(reply.bytes);
            }
            codec.reconstruct(&mut received).unwrap();
            for (actual, expected) in received.into_iter().zip(&reader.shards) {
                assert_eq!(&actual.unwrap(), expected);
            }
        }
    }
}

#[test]
fn corrupt_stale_short_wrong_offset_and_panicking_candidates_do_not_count() {
    for behavior in [
        Behavior::Corrupt,
        Behavior::Stale,
        Behavior::WrongOffset,
        Behavior::Short,
        Behavior::Panic,
    ] {
        let (_, mut reader, requests) = fixture();
        reader.behavior[0] = behavior;
        reader.behavior[1] = Behavior::Error;
        let mut cfg = config();
        cfg.hedge_after = Duration::from_secs(60);
        let selection =
            read_quorum(&reader, &requests, cfg, &CancellationToken::default()).unwrap();
        assert!(selection
            .shards
            .iter()
            .all(|reply| reply.request.shard >= 2));
        // Quorum may precede the second failure response. Losers are reclaimed,
        // but failures observed only during reclamation are not quorum metrics.
        assert!((1..=2).contains(&selection.rejected));
        assert_eq!(selection.failures.len(), selection.rejected);
        assert_eq!(selection.attempted, 12);
        assert_eq!(reader.active.load(Ordering::SeqCst), 0);

        // Force validation of this exact bad candidate before the good one,
        // independently of concurrent response order in the 10+2 case above.
        let mut cfg = config();
        cfg.required = 1;
        cfg.initial = 1;
        cfg.max_in_flight = 1;
        let selected = read_quorum(
            &reader,
            &[requests[0].clone(), requests[2].clone()],
            cfg,
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(selected.rejected, 1);
        assert_eq!(selected.failures[0].0, 0);
        assert_eq!(selected.shards[0].request.shard, 2);
    }
}

#[test]
fn stalled_initial_candidates_trigger_twelfth_and_are_reclaimed() {
    let (_, mut reader, requests) = fixture();
    reader.behavior[0] = Behavior::Slow;
    reader.behavior[1] = Behavior::Slow;
    let selection =
        read_quorum(&reader, &requests, config(), &CancellationToken::default()).unwrap();
    assert_eq!(selection.attempted, 12);
    assert!(selection
        .shards
        .iter()
        .all(|reply| reply.request.shard >= 2));
    assert!(selection.total_elapsed >= selection.quorum_elapsed);
    assert_eq!(reader.active.load(Ordering::SeqCst), 0);
    assert!(reader.peak.load(Ordering::SeqCst) <= 12);
}

#[test]
fn cancellation_and_deadline_reclaim_workers() {
    for external in [true, false] {
        let (_, mut reader, requests) = fixture();
        reader.behavior.fill(Behavior::Slow);
        let token = CancellationToken::default();
        let mut cfg = config();
        cfg.deadline = Instant::now()
            + if external {
                Duration::from_secs(3)
            } else {
                Duration::from_millis(100)
            };
        std::thread::scope(|scope| {
            if external {
                let reader_ref = &reader;
                let token_ref = &token;
                scope.spawn(move || {
                    // Wait for real work, rather than depending on thread-start timing.
                    while reader_ref.active.load(Ordering::SeqCst) == 0
                        && Instant::now() < cfg.deadline
                    {
                        std::thread::yield_now();
                    }
                    token_ref.cancel();
                });
            }
            let err = read_quorum(&reader, &requests, cfg, &token).unwrap_err();
            assert!(
                err.0
                    .contains(if external { "cancelled" } else { "deadline" }),
                "{err}"
            );
        });
        assert_eq!(reader.active.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn insufficient_valid_candidates_fails_without_leaking_workers() {
    let (_, mut reader, requests) = fixture();
    reader.behavior[..3].fill(Behavior::Error);
    assert!(
        read_quorum(&reader, &requests, config(), &CancellationToken::default())
            .unwrap_err()
            .0
            .contains("insufficient")
    );
    assert_eq!(reader.active.load(Ordering::SeqCst), 0);
}

#[test]
fn malformed_requests_and_insufficient_budget_start_no_io() {
    let (_, reader, requests) = fixture();
    for mutation in 0..7 {
        let mut candidates = requests.clone();
        let mut cfg = config();
        match mutation {
            0 => candidates[1].shard = candidates[0].shard,
            1 => candidates[1].generation += 1,
            2 => candidates[1].stripe += 1,
            3 => candidates[1].offset += 1,
            4 => cfg.max_buffer_bytes = 1,
            5 => cfg.required = 0,
            _ => candidates.iter_mut().for_each(|r| r.offset = u64::MAX),
        }
        assert!(read_quorum(&reader, &candidates, cfg, &CancellationToken::default()).is_err());
    }
    assert!(reader.started.lock().unwrap().is_empty());
}

#[test]
fn pre_cancelled_or_expired_request_starts_no_io() {
    let (_, reader, requests) = fixture();
    let token = CancellationToken::default();
    token.cancel();
    assert!(read_quorum(&reader, &requests, config(), &token).is_err());
    let mut cfg = config();
    cfg.deadline = Instant::now();
    assert!(read_quorum(&reader, &requests, cfg, &CancellationToken::default()).is_err());
    assert!(reader.started.lock().unwrap().is_empty());
}

#[test]
fn initial_k_without_hedging_does_not_read_unused_parity() {
    let (_, reader, requests) = fixture();
    let mut cfg = config();
    cfg.initial = 10;
    cfg.max_in_flight = 10;
    cfg.hedge_after = Duration::from_secs(60);
    let selection = read_quorum(&reader, &requests, cfg, &CancellationToken::default()).unwrap();
    assert_eq!(selection.attempted, 10);
    assert!(selection
        .shards
        .iter()
        .all(|reply| reply.request.shard < 10));
}
