#![deny(unsafe_op_in_unsafe_fn)]

mod affine;
pub mod combination;
pub mod field;
pub mod fri;
#[path = "in-memory.rs"]
pub mod in_memory;
pub mod jobs;
pub mod linear;
#[path = "linear-oracle.rs"]
pub(crate) mod linear_oracle;
#[cfg(test)]
#[path = "linear-tests.rs"]
mod linear_tests;
pub mod oracles;
pub mod rows;
#[path = "setup-prover.rs"]
pub mod setup_prover;
pub mod sums;
pub mod transcript;
pub mod tree;
