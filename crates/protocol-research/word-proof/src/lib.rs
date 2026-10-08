#![deny(unsafe_op_in_unsafe_fn)]

// A test's replayed randomness never reaches the participant module.
#[cfg(all(feature = "test-support", target_arch = "wasm32"))]
compile_error!("The test-support feature replays randomness and never builds for Wasm.");

pub mod affine;
pub mod bridge;
pub mod combination;
pub mod field;
pub mod fri;
pub mod jobs;
pub mod linear;
#[path = "linear-oracle.rs"]
pub mod linear_oracle;
#[cfg(test)]
#[path = "linear-tests.rs"]
mod linear_tests;
#[path = "one-shot.rs"]
pub mod one_shot;
pub mod oracles;
pub mod random;
pub mod rows;
pub mod sums;
pub mod transcript;
pub mod tree;
