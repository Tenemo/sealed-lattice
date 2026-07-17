//! Deterministic packed BGV top-k evaluator.
//!
//! This module owns the leveled BGV-RNS evaluation engine and the encrypted
//! top-k circuit over direct encrypted ballot aggregates: encrypted comparison,
//! rank accumulation, and encrypted target projection. The evaluator produces a
//! target ciphertext and replay binding; it does not accept the target, prove
//! the evaluation, or decrypt the result.
//!
//! The development key set drives prototype key synthesis and encryption.
//! Secret-key decryption helpers compile only in tests, where they check the
//! evaluator against a plaintext top-k oracle. None of these helpers is
//! exported through the public package surface.

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

pub(crate) mod candidate_evidence;
pub(crate) mod circuit;
pub(crate) mod engine;
pub(crate) mod key_switch;
pub(crate) mod noise_recurrence;
pub(crate) mod program;
pub(crate) mod records;
pub(crate) mod top_k;
