use super::*;

impl ImmutableStagingEngine {
    // One bounded, synchronous pass across classes. Limits include metadata
    // reconciliation attempts and are shared with every disk by the caller.
    pub(crate) fn trim_empty_groups(&self, limits: EmptyGroupTrimLimits,
                                   report: &mut EmptyGroupTrimReport) -> ImmutableStageResult<()> {
        limits.validate()?;
        if self.0.format != EcStagingFormat::ExactGc {
            return Err(ImmutableStageError::Invalid("empty-group trim requires format 3"));
        }
        let _permit = self.permit()?;
        let count = self.0.engine.allocators.vec.len();
        let first = self.0.trim_cursor.fetch_add(1, Ordering::Relaxed) % count;
        for offset in 0..count {
            if report.attempted_groups >= limits.max_groups { break; }
            let index = (first + offset) % count;
            self.0.engine.allocators.vec[index].trim_empty_group(
                &self.0.engine.meta_store, limits, report)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "immutable_trim_tests.rs"]
mod tests;
