use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;

use crate::{error, RepairPlan, Result};

/// The backend must validate shard identity, generation and integrity.
/// Writes MUST remain staged until commit atomically publishes all targets.
/// abort must never erase already published data. Only one repair may own a
/// backend staging transaction at a time. All calls must return in finite time:
/// cancellation cannot interrupt a blocked backend system call.
pub trait ShardStore: Sync {
    fn read_shard(&self, shard: usize, offset: usize, length: usize) -> Result<Vec<u8>>;
    fn write_shard(&self, shard: usize, offset: usize, data: &[u8]) -> Result<()>;
    fn commit(&self, targets: &[usize]) -> Result<()>;
    fn abort(&self, _targets: &[usize]) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    pub shard_len: usize,
    pub slice_len: usize,
    pub queue_depth: usize,
}

impl PipelineConfig {
    /// Conservative payload budget, excluding backend buffers and thread stacks.
    pub fn estimated_buffer_bytes(&self, plan: &RepairPlan) -> Result<usize> {
        self.queue_depth
            .checked_add(2)
            .and_then(|v| v.checked_mul(plan.healthy().len() + plan.targets().len()))
            .and_then(|v| v.checked_mul(self.slice_len.min(self.shard_len)))
            .ok_or_else(|| error("pipeline buffer size overflow"))
    }

    pub fn validate(&self, plan: &RepairPlan) -> Result<()> {
        if self.slice_len == 0 || self.queue_depth == 0 || self.queue_depth > 1024 {
            return Err(error(
                "slice_len must be positive; queue_depth must be in 1..=1024",
            ));
        }
        if self.estimated_buffer_bytes(plan)? > 256 * 1024 * 1024 {
            return Err(error("pipeline payload budget exceeds 256 MiB"));
        }
        self.shard_len
            .checked_mul(plan.healthy().len() + plan.targets().len())
            .ok_or_else(|| error("pipeline byte accounting overflow"))?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RepairStats {
    pub slices: usize,
    pub read_bytes: usize,
    pub written_bytes: usize,
}

struct Batch {
    offset: usize,
    length: usize,
    shards: Vec<Vec<u8>>,
}

fn backend<T>(call: impl FnOnce() -> Result<T>) -> Result<T> {
    catch_unwind(AssertUnwindSafe(call)).map_err(|_| error("backend panicked"))?
}

fn read_batch(
    store: &dyn ShardStore,
    plan: &RepairPlan,
    offset: usize,
    length: usize,
) -> Result<Batch> {
    let mut shards = Vec::with_capacity(plan.healthy().len());
    for &index in plan.healthy() {
        let bytes = backend(|| store.read_shard(index, offset, length))?;
        if bytes.len() != length {
            return Err(error(format!(
                "short/oversized read for shard {index} at {offset}"
            )));
        }
        shards.push(bytes);
    }
    Ok(Batch {
        offset,
        length,
        shards,
    })
}

fn compute_batch(plan: &RepairPlan, input: Batch) -> Result<Batch> {
    Ok(Batch {
        offset: input.offset,
        length: input.length,
        shards: plan.recover_slice(&input.shards)?,
    })
}

fn write_batch(store: &dyn ShardStore, plan: &RepairPlan, batch: Batch) -> Result<()> {
    for (&target, data) in plan.targets().iter().zip(&batch.shards) {
        backend(|| store.write_shard(target, batch.offset, data))?;
    }
    Ok(())
}

fn stats(config: PipelineConfig, plan: &RepairPlan) -> RepairStats {
    RepairStats {
        slices: config.shard_len / config.slice_len
            + usize::from(config.shard_len % config.slice_len != 0),
        read_bytes: config.shard_len * plan.healthy().len(),
        written_bytes: config.shard_len * plan.targets().len(),
    }
}

fn finish(
    store: &dyn ShardStore,
    plan: &RepairPlan,
    result: Result<RepairStats>,
) -> Result<RepairStats> {
    let result = result.and_then(|stats| {
        backend(|| store.commit(plan.targets()))?;
        Ok(stats)
    });
    match result {
        Ok(stats) => Ok(stats),
        Err(primary) => match backend(|| store.abort(plan.targets())) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(error(format!("{primary}; abort failed: {cleanup}"))),
        },
    }
}

/// Sequential reference path with the same codec and commit contract.
pub fn repair_sequential(
    store: &dyn ShardStore,
    plan: &RepairPlan,
    config: PipelineConfig,
) -> Result<RepairStats> {
    config.validate(plan)?;
    let result = (|| {
        let mut offset = 0;
        while offset < config.shard_len {
            let length = config.slice_len.min(config.shard_len - offset);
            let input = read_batch(store, plan, offset, length)?;
            write_batch(store, plan, compute_batch(plan, input)?)?;
            offset += length;
        }
        Ok(stats(config, plan))
    })();
    finish(store, plan, result)
}

/// Three local stages: reader and computation workers plus the calling writer.
/// Two bounded FIFO channels provide backpressure. Disconnecting the downstream
/// channel propagates cancellation upstream; both workers are joined before
/// commit/abort. This is not a distributed ECPipe implementation.
pub fn repair_pipeline(
    store: &dyn ShardStore,
    plan: &RepairPlan,
    config: PipelineConfig,
) -> Result<RepairStats> {
    config.validate(plan)?;
    let cancelled = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        let (input_tx, input_rx) = sync_channel::<Result<Batch>>(config.queue_depth);
        let (output_tx, output_rx) = sync_channel::<Result<Batch>>(config.queue_depth);
        let cancelled_ref = &cancelled;
        let reader = scope.spawn(move || {
            let mut offset = 0;
            while offset < config.shard_len && !cancelled_ref.load(Ordering::Acquire) {
                let length = config.slice_len.min(config.shard_len - offset);
                let batch = read_batch(store, plan, offset, length);
                let failed = batch.is_err();
                if input_tx.send(batch).is_err() || failed {
                    break;
                }
                offset += length;
            }
        });
        let computer = scope.spawn(move || {
            for input in input_rx {
                if cancelled_ref.load(Ordering::Acquire) {
                    break;
                }
                let output = input.and_then(|batch| compute_batch(plan, batch));
                let failed = output.is_err();
                if output_tx.send(output).is_err() || failed {
                    break;
                }
            }
        });
        let written = (|| {
            let mut offset = 0;
            for output in &output_rx {
                let batch = output?;
                if batch.offset != offset
                    || batch.length != config.slice_len.min(config.shard_len - offset)
                {
                    return Err(error("unexpected pipeline slice order or length"));
                }
                let length = batch.length;
                write_batch(store, plan, batch)?;
                offset += length;
            }
            if offset != config.shard_len {
                return Err(error("pipeline terminated before all slices completed"));
            }
            Ok(stats(config, plan))
        })();
        cancelled.store(true, Ordering::Release);
        drop(output_rx);
        let reader_joined = reader.join();
        let computer_joined = computer.join();
        written.and_then(|stats| {
            if reader_joined.is_err() || computer_joined.is_err() {
                Err(error("pipeline worker panicked"))
            } else {
                Ok(stats)
            }
        })
    });
    finish(store, plan, result)
}
