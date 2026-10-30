//! Erasure coding, helper contributions, bounded concurrent shard selection,
//! and a local read/compute/write pipeline.
//!
//! This crate does not implement distributed repair, CRAQ, or stripe metadata.
mod codec;
#[cfg(feature = "isal-backend")]
mod isal;
mod pipeline;
pub mod read;

pub use codec::{Backend, Codec, ContributionPlan, RepairPlan};
pub use pipeline::{repair_pipeline, repair_sequential, PipelineConfig, RepairStats, ShardStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn error(message: impl Into<String>) -> Error {
    Error(message.into())
}
