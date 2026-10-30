//! Erasure coding, helper contributions, bounded concurrent shard selection,
//! a local read/compute/write pipeline, and fixed TCP helper chains.
//!
//! The TCP executor requires trusted, preinstalled plans and a storage adapter.
//! It does not implement native 3FS RPC, CRAQ, or stripe metadata publication.
pub mod chain;
mod codec;
#[cfg(feature = "isal-backend")]
mod isal;
mod pipeline;
pub mod read;
pub mod transport;
pub mod wire;

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
