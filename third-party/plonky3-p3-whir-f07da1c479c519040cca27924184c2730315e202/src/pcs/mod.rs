//! WHIR polynomial commitment scheme: commit, prove, and verify.
//!
//! Local modification: the optional hiding implementation and its dependency
//! graph are gated behind the default-off `zk` feature. See `../../UPSTREAM.md`.

mod adapter;
pub(crate) mod committer;
pub mod proof;
pub mod prover;
pub(crate) mod utils;
pub mod verifier;
#[cfg(feature = "zk")]
pub mod zk;

pub use adapter::WhirProverData;

#[cfg(test)]
mod tests;
