//! Deterministic packed BGV top-k evaluator.
//!
//! This module owns the leveled BGV-RNS evaluation engine and the encrypted
//! top-k circuit over direct encrypted ballot aggregates: encrypted comparison,
//! rank accumulation, and encrypted target projection. The evaluator produces a
//! target ciphertext and replay binding; it does not accept the target, prove
//! the evaluation, or decrypt the result.
//!
//! Development key synthesis, encryption, and secret-key decryption compile
//! only in tests, where they check production evaluator primitives. None of
//! these helpers is exported through the public package surface.

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

#[cfg(test)]
pub(crate) mod prg;

pub(crate) mod ballot_aggregation;
pub(crate) mod ballot_aggregation_runtime;
pub(crate) mod candidate_evidence;
pub(crate) mod engine;
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(crate) mod fixed_width_crt;
pub(crate) mod key_switch;
pub(crate) mod noise_recurrence;
pub(crate) mod pair_character_product;
pub(crate) mod program;
pub(crate) mod records;
pub(crate) mod replay;
#[cfg(test)]
pub(crate) mod semantic_oracle;
pub(crate) mod top_k;
