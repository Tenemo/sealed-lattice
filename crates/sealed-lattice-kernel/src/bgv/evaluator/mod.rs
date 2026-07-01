//! Deterministic packed BGV top-k evaluator.
//!
//! This module owns the leveled BGV-RNS evaluation engine and the encrypted
//! top-k circuit over direct encrypted ballot aggregates: encrypted comparison,
//! rank accumulation, and encrypted target projection. The evaluator produces a
//! target proposal; it does not accept the target, prove the evaluation, or
//! decrypt the result.
//!
//! The development key set and development encryption/decryption helpers exist
//! only to drive and check the evaluator against the plaintext top-k oracle.
//! They are never exported through the public package surface.

#[cfg(not(target_arch = "wasm32"))]
macro_rules! evaluator_parallel_iterator {
    ($parallel:expr, $sequential:expr) => {
        $parallel
    };
}

#[cfg(target_arch = "wasm32")]
macro_rules! evaluator_parallel_iterator {
    ($parallel:expr, $sequential:expr) => {
        $sequential
    };
}

pub(crate) mod prg;

pub(crate) mod circuit;
pub(crate) mod engine;
pub(crate) mod key_switch;
pub(crate) mod records;
pub(crate) mod top_k;
