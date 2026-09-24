#![deny(unsafe_op_in_unsafe_fn)]
pub mod admission;
pub mod body;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "body-browser.rs"]
mod body_browser;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
mod browser;
pub mod close;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "close-browser.rs"]
mod close_browser;
pub mod columns;
pub mod context;
#[path = "../../word-proof/src/field.rs"]
pub mod field;
#[path = "../../word-proof/src/oracles.rs"]
pub mod oracles;
pub mod parameters;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "prover-browser.rs"]
mod prover_browser;
#[path = "../../word-proof/src/random.rs"]
mod random;
pub mod statement;
pub mod submission;
#[path = "../../word-proof/src/transcript.rs"]
pub mod transcript;
#[path = "../../word-proof/src/tree.rs"]
pub mod tree;
use field::base as arithmetic;
#[path = "../../word-proof/src/combination.rs"]
pub mod combination;
#[path = "../../word-verifier/src/engine.rs"]
mod engine;
#[path = "../../word-proof/src/fri.rs"]
pub mod fri;
#[path = "../../registration-proof/src/linear.rs"]
pub mod linear;
#[path = "../../word-proof/src/linear-oracle.rs"]
pub mod linear_oracle;
#[path = "private-ballot.rs"]
pub mod private_ballot;
mod profile;
pub mod proof;
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal, Verifier};

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
pub fn take_browser_classification() -> Option<body::BallotBodyClassification> {
    body_browser::take_classification()
}

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
pub fn take_browser_close_barrier() -> Option<close::VerifiedCloseBarrier> {
    close_browser::take_barrier()
}
