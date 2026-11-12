//! Empty physical groups only; never relocate, delete a logical fragment, or
//! replay a physical action. A class mutex owns the ticket through sync I/O.
use super::*;
use std::sync::TryLockError;

#[derive(Clone, Copy, Debug)]
pub(crate) struct EmptyGroupTrimLimits {
    pub max_groups: u32,
    pub max_bytes: u64,
    pub keep_empty_groups: u32,
}

impl EmptyGroupTrimLimits {
    pub(crate) fn validate(self) -> ImmutableStageResult<()> {
        if self.max_groups == 0 || self.max_groups > 64
            || self.max_bytes == 0 || self.max_bytes > (64u64 << 30)
            || self.keep_empty_groups > 1024 {
            return Err(ImmutableStageError::Invalid("invalid empty-group trim budget"));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct EmptyGroupTrimReport {
    pub attempted_groups: u32,
    pub charged_bytes: u64,
    pub punch_confirmed_groups: u32,
    pub punch_confirmed_bytes: u64,
    pub withdrawn_preallocation_bytes: u64,
    pub unconfirmed_extent_bytes: u64,
    pub reconciled_groups: u32,
    pub quarantined_groups: u32,
    pub busy_classes: u32,
    pub oversized_classes: u32,
    pub unsupported_groups: u32,
    pub os_errno: i32,
    pub complete: bool,
}

impl Default for EmptyGroupTrimReport {
    fn default() -> Self {
        Self { attempted_groups: 0, charged_bytes: 0,
            punch_confirmed_groups: 0, punch_confirmed_bytes: 0,
            withdrawn_preallocation_bytes: 0, unconfirmed_extent_bytes: 0,
            reconciled_groups: 0, quarantined_groups: 0, busy_classes: 0,
            oversized_classes: 0, unsupported_groups: 0, os_errno: 0, complete: true }
    }
}

// Test implementations inject failures around real MetaStore operations. The
// production implementation always uses the already-owned DB/file handles.
trait TrimIo {
    fn remove_group(&self, group: GroupId) -> Result<()>;
    fn sync_wal(&self) -> Result<()>;
    fn punch(&self, group: GroupId) -> std::io::Result<()>;
    fn sync_data(&self, group: GroupId) -> std::io::Result<()>;
}
struct ActualTrimIo<'a> { meta: &'a MetaStore, clusters: &'a Clusters }
impl TrimIo for ActualTrimIo<'_> {
    fn remove_group(&self, group: GroupId) -> Result<()> { self.meta.remove_group(group) }
    fn sync_wal(&self) -> Result<()> { self.meta.sync_wal() }
    fn punch(&self, group: GroupId) -> std::io::Result<()> { self.clusters.punch_empty_group(group) }
    fn sync_data(&self, group: GroupId) -> std::io::Result<()> { self.clusters.sync_trim(group) }
}

impl Allocator {
    pub(crate) fn trim_empty_group(&self, meta: &MetaStore, limits: EmptyGroupTrimLimits,
                                  report: &mut EmptyGroupTrimReport) -> ImmutableStageResult<()> {
        self.trim_empty_group_with(meta, limits, report, &ActualTrimIo { meta, clusters: &self.clusters })
    }

    fn trim_empty_group_with(&self, meta: &MetaStore, limits: EmptyGroupTrimLimits,
                             report: &mut EmptyGroupTrimReport, io: &impl TrimIo) -> ImmutableStageResult<()> {
        limits.validate()?;
        if report.attempted_groups >= limits.max_groups { return Ok(()); }
        let mut pending = match self.trim_pending.try_lock() {
            Ok(lock) => lock,
            Err(TryLockError::WouldBlock) => { report.busy_classes += 1; return Ok(()); }
            Err(TryLockError::Poisoned(_)) => {
                report.complete = false;
                return Err(ImmutableStageError::OutcomeUnknown("poisoned trim ticket".into()));
            }
        };
        let mut allocator = match self.allocator.try_lock() {
            Ok(lock) => lock,
            Err(TryLockError::WouldBlock) => { report.busy_classes += 1; return Ok(()); }
            Err(TryLockError::Poisoned(_)) => {
                report.complete = false;
                return Err(ImmutableStageError::OutcomeUnknown("poisoned allocator during trim".into()));
            }
        };
        let reconcile_only = pending.is_some();
        let group = if let Some(group) = *pending { group } else {
            let pool = &allocator.group_allocator.allocated_groups;
            if pool.len() <= limits.keep_empty_groups as usize { return Ok(()); }
            *pool.iter().next().unwrap()
        };
        let bytes = group.size().0;
        if bytes > limits.max_bytes.saturating_sub(report.charged_bytes) {
            report.oversized_classes += 1;
            return Ok(());
        }
        if !reconcile_only {
            allocator.group_allocator.allocated_groups.remove(&group);
            *pending = Some(group);
        }
        report.attempted_groups += 1;
        report.charged_bytes += bytes;

        // No waits for foreground work/refcounts while holding this mutex. An
        // occupied slot, any strong Chunk owner or a contradictory durable
        // index is a rejection, not a candidate to force into the empty pool.
        let outcome = (|| {
            if group.chunk_size() != self.clusters.chunk_size
                || allocator.full_groups.contains(&group)
                || allocator.active_groups.get(&group).is_some()
                || allocator.frozen_groups.get(&group).is_some()
                || allocator.active_levels.iter().any(|level| level.contains(&group))
                || allocator.group_allocator.allocated_groups.contains(&group)
                || allocator.group_allocator.unallocated_groups.contains(&group)
                || allocator.counter.allocated_chunks() < GroupState::TOTAL_BITS as u64
                || allocator.counter.reserved_chunks() < GroupState::TOTAL_BITS as u64 {
                return Err(ImmutableStageError::Corrupt("trim ticket conflicts with allocator state"));
            }
            for index in 0..GroupState::TOTAL_BITS {
                let pos = Position::new(group, index as u8);
                if allocator.position_rc.get(&pos).is_some()
                    || meta.stage_get_exact(MetaKey::pos_to_chunk_key(pos).as_ref())?.is_some()
                    || meta.stage_get_exact(&stage_position_key(pos))?.is_some() {
                    return Err(ImmutableStageError::Corrupt("trim group still owns a position"));
                }
            }
            let bitmap = meta.stage_get_exact(MetaKey::group_bits_key(group).as_ref())?;
            if let Some(value) = &bitmap {
                if !GroupState::from(value)?.is_empty() {
                    return Err(ImmutableStageError::Corrupt("trim persistent bitmap is occupied"));
                }
            }
            if reconcile_only {
                // A failed delete may or may not be durable. Re-read plus WAL
                // barrier resolves the bitmap only. NEVER execute old punch.
                io.sync_wal()?;
                if bitmap.is_some() {
                    allocator.group_allocator.finish_allocate_task(AllocateTask::Deallocate(group), false);
                } else {
                    allocator.group_allocator.finish_allocate_task(AllocateTask::Deallocate(group), true);
                    report.withdrawn_preallocation_bytes += bytes;
                    report.unconfirmed_extent_bytes += bytes;
                }
                *pending = None;
                report.reconciled_groups += 1;
                return Ok(());
            }
            if bitmap.is_none() {
                // Slow allocation can reserve physical space before its first
                // metadata batch. Dropping that private Chunk may legitimately
                // leave an empty in-memory group without a bitmap. This is not
                // proof of corruption and does not authorize a punch. Resolve
                // absence durably, withdraw preallocation, and report the
                // physical extent as unconfirmed; future reuse must fallocate.
                io.sync_wal()?;
                allocator.group_allocator.finish_allocate_task(AllocateTask::Deallocate(group), true);
                *pending = None;
                report.withdrawn_preallocation_bytes += bytes;
                report.unconfirmed_extent_bytes += bytes;
                report.reconciled_groups += 1;
                return Ok(());
            }
            // Both sync operations must return successfully before the first
            // physical action. Any error retains the in-memory ticket.
            io.remove_group(group)?;
            io.sync_wal()?;
            let punched = io.punch(group).and_then(|()| io.sync_data(group));
            // Even failed/partial/unsupported punching must pass fallocate on
            // reuse. Never restore this address to the preallocated pool.
            allocator.group_allocator.finish_allocate_task(AllocateTask::Deallocate(group), true);
            *pending = None;
            report.withdrawn_preallocation_bytes += bytes;
            match punched {
                Ok(()) => {
                    report.punch_confirmed_groups += 1;
                    report.punch_confirmed_bytes += bytes;
                    Ok(())
                }
                Err(error) => {
                    report.unconfirmed_extent_bytes += bytes;
                    report.os_errno = error.raw_os_error().unwrap_or(0);
                    if matches!(report.os_errno, libc::EOPNOTSUPP | libc::ENOSYS) {
                        report.unsupported_groups += 1;
                    }
                    Err(ImmutableStageError::OutcomeUnknown(format!("trim {group:?} physical result: {error}")))
                }
            }
        })();
        if outcome.is_err() && pending.is_some() { report.quarantined_groups += 1; }
        outcome
    }
}

#[cfg(test)]
#[path = "empty_group_trim_tests.rs"]
mod tests;
