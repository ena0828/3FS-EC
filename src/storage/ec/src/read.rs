//! Bounded concurrent selection of validated, same-generation shard slices.
//!
//! The transport must obey `ReadControl` and limit response allocation to the
//! requested length. This module never detaches workers: cancellation is
//! cooperative, and a backend ignoring deadlines can delay return. Metadata
//! and expected CRC32C must come from a trusted, pinned stripe descriptor.
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use crate::{error, Result};

#[derive(Clone, Default, Debug)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
pub struct ReadControl {
    external: CancellationToken,
    finished: CancellationToken,
    deadline: Instant,
}

impl ReadControl {
    pub fn check(&self) -> Result<()> {
        if self.external.is_cancelled() || self.finished.is_cancelled() {
            return Err(error("read cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(error("read deadline exceeded"));
        }
        Ok(())
    }

    /// Remaining operation budget, for socket/queue timeout configuration.
    pub fn remaining(&self) -> Result<Duration> {
        self.check()?;
        Ok(self.deadline.saturating_duration_since(Instant::now()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub stripe: u128,
    pub generation: u64,
    pub shard: usize,
    pub offset: u64,
    pub length: usize,
    pub crc32c: u32,
}

#[derive(Debug)]
pub struct ReadReply {
    pub request: ReadRequest,
    pub bytes: Vec<u8>,
}

pub trait ShardReader: Sync {
    /// Return exactly the requested bytes or an error. Implementations must
    /// check cancellation and deadlines while waiting, not just on entry.
    fn read(&self, request: &ReadRequest, control: &ReadControl) -> Result<ReadReply>;
}

#[derive(Clone, Copy, Debug)]
pub struct ReadConfig {
    pub required: usize,
    pub initial: usize,
    pub max_in_flight: usize,
    /// Launch another candidate after this interval without a valid response.
    /// Known failed candidates are replaced immediately.
    pub hedge_after: Duration,
    pub deadline: Instant,
    /// Payload budget; excludes backend internal buffers and worker stacks.
    pub max_buffer_bytes: usize,
}

impl ReadConfig {
    fn validate(&self, requests: &[ReadRequest]) -> Result<()> {
        if self.required == 0
            || self.required > self.initial
            || self.initial > self.max_in_flight
            || self.max_in_flight > requests.len()
            || requests.len() > 256
        {
            return Err(error(
                "require 1 <= required <= initial <= max_in_flight <= candidates <= 256",
            ));
        }
        let first = &requests[0];
        first
            .offset
            .checked_add(first.length as u64)
            .ok_or_else(|| error("read range overflow"))?;
        let budget = self
            .required
            .checked_add(self.max_in_flight)
            .and_then(|v| v.checked_mul(first.length))
            .ok_or_else(|| error("read buffer budget overflow"))?;
        if budget > self.max_buffer_bytes {
            return Err(error("read payload exceeds configured budget"));
        }
        let mut seen = [false; 256];
        for request in requests {
            if request.shard >= seen.len() || seen[request.shard] {
                return Err(error(
                    "candidate shard identities must be distinct and below 256",
                ));
            }
            seen[request.shard] = true;
            if (
                request.stripe,
                request.generation,
                request.offset,
                request.length,
            ) != (first.stripe, first.generation, first.offset, first.length)
            {
                return Err(error(
                    "candidate requests must describe the same stripe generation and slice",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ReadSelection {
    /// Arrival order, including actual shard identities for decoding coefficients.
    pub shards: Vec<ReadReply>,
    pub attempted: usize,
    /// Invalid/error responses observed before quorum (not cancelled losers).
    pub rejected: usize,
    pub failures: Vec<(usize, crate::Error)>,
    /// Quorum time excludes the subsequent mandatory loser reclamation.
    pub quorum_elapsed: Duration,
    pub total_elapsed: Duration,
}

/// Castagnoli CRC, used to reject accidental corruption, not to authenticate peers.
pub fn crc32c(bytes: &[u8]) -> u32 {
    !crc32c_update(!0u32, bytes)
}

fn crc32c_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    crc
}

fn checked_crc32c(bytes: &[u8], control: &ReadControl) -> Result<u32> {
    control.check()?;
    let mut crc = !0u32;
    for chunk in bytes.chunks(4096) {
        crc = crc32c_update(crc, chunk);
        control.check()?;
    }
    Ok(!crc)
}

fn validate_reply(request: &ReadRequest, reply: &ReadReply, control: &ReadControl) -> Result<()> {
    if reply.request != *request {
        return Err(error("response identity/generation does not match request"));
    }
    if reply.bytes.len() != request.length
        || checked_crc32c(&reply.bytes, control)? != request.crc32c
    {
        return Err(error("response length or CRC32C mismatch"));
    }
    Ok(())
}

/// Select `required` valid responses, replacing failures and hedging stalled reads.
/// For 10+2 use 12 candidates, required=10, initial=11, max_in_flight=12.
/// Pending work is cancelled and joined before returning, including error paths.
pub fn read_quorum(
    reader: &dyn ShardReader,
    requests: &[ReadRequest],
    config: ReadConfig,
    cancellation: &CancellationToken,
) -> Result<ReadSelection> {
    config.validate(requests)?;
    let started = Instant::now();
    let control = ReadControl {
        external: cancellation.clone(),
        finished: CancellationToken::default(),
        deadline: config.deadline,
    };
    control.check()?;
    std::thread::scope(|scope| {
        // One result per worker, so a cancelled worker never waits for a consumer.
        let (tx, rx) = mpsc::sync_channel(config.max_in_flight);
        let mut handles = Vec::with_capacity(requests.len());
        let mut active = 0;
        let mut launched = 0;
        let mut wanted = config.initial;
        let mut rejected = 0;
        let mut failures = Vec::new();
        let mut accepted = Vec::with_capacity(config.required);
        let mut last_progress = Instant::now();
        let result = (|| {
            loop {
                control.check()?;
                while active < wanted && launched < requests.len() {
                    control.check()?;
                    let index = launched;
                    let request = &requests[index];
                    let sender = tx.clone();
                    let worker_control = &control;
                    let handle = std::thread::Builder::new()
                        .name(format!("ec-read-{}", request.shard))
                        .spawn_scoped(scope, move || {
                            let response = catch_unwind(AssertUnwindSafe(|| {
                                worker_control.check()?;
                                reader.read(request, worker_control)
                            }))
                            .unwrap_or_else(|_| Err(error("shard reader panicked")));
                            let _ = sender.send((index, response));
                        })
                        .map_err(|err| error(format!("cannot start read worker: {err}")))?;
                    handles.push(Some(handle));
                    active += 1;
                    launched += 1;
                }
                if accepted.len() + active + requests.len() - launched < config.required {
                    return Err(error(format!(
                        "insufficient valid shards: {} accepted, {rejected} rejected",
                        accepted.len()
                    )));
                }
                let poll = Duration::from_millis(5);
                let hedge_wait = config.hedge_after.saturating_sub(last_progress.elapsed());
                let can_hedge = active < config.max_in_flight && launched < requests.len();
                let wait = if can_hedge {
                    poll.min(hedge_wait)
                } else {
                    poll
                };
                match rx.recv_timeout(wait.min(control.remaining()?)) {
                    Ok((index, response)) => {
                        if handles[index].take().unwrap().join().is_err() {
                            return Err(error("read worker panicked outside backend"));
                        }
                        active -= 1;
                        // Do not count a response that arrives after cancellation/deadline.
                        control.check()?;
                        match response.and_then(|reply| {
                            validate_reply(&requests[index], &reply, &control)?;
                            Ok(reply)
                        }) {
                            Ok(reply) => {
                                control.check()?;
                                accepted.push(reply);
                                last_progress = Instant::now();
                                // A success consumes one desired slot; failure keeps it
                                // open for immediate replacement from the candidate list.
                                wanted = wanted.saturating_sub(1);
                                if accepted.len() == config.required {
                                    return Ok(ReadSelection {
                                        shards: accepted,
                                        attempted: launched,
                                        rejected,
                                        failures,
                                        quorum_elapsed: started.elapsed(),
                                        total_elapsed: Duration::ZERO,
                                    });
                                }
                            }
                            Err(failure) => {
                                rejected += 1;
                                failures.push((requests[index].shard, failure));
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if can_hedge && last_progress.elapsed() >= config.hedge_after {
                            wanted = (active + 1).min(config.max_in_flight);
                            last_progress = Instant::now();
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(error("read workers disconnected"))
                    }
                }
            }
        })();
        control.finished.cancel();
        // Drop the receiver so no sender can block while reclamation joins it.
        drop(rx);
        for handle in handles.into_iter().flatten() {
            let _ = handle.join();
        }
        result.map(|mut selection| {
            selection.total_elapsed = started.elapsed();
            selection
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_crc_handles_chunk_boundaries_and_cancelled_empty_input() {
        let control = ReadControl {
            external: CancellationToken::default(),
            finished: CancellationToken::default(),
            deadline: Instant::now() + Duration::from_secs(3),
        };
        for length in [0, 1, 4095, 4096, 4097, 8193] {
            let bytes: Vec<_> = (0..length).map(|i| (i * 13) as u8).collect();
            assert_eq!(checked_crc32c(&bytes, &control).unwrap(), crc32c(&bytes));
        }
        control.external.cancel();
        assert!(checked_crc32c(&[], &control).is_err());
        assert!(checked_crc32c(&[1; 4097], &control).is_err());
        let expired = ReadControl {
            external: CancellationToken::default(),
            finished: CancellationToken::default(),
            deadline: Instant::now(),
        };
        assert!(checked_crc32c(&[1; 4097], &expired).is_err());
    }
}
