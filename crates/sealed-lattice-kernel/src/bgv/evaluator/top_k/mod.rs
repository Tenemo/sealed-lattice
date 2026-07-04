mod ciphertext_helpers;
mod comparison;
mod interpolation;
mod packed_rank;
mod rank_lookup;
mod rotations;
mod score_packing;
mod sparse_target;
pub(crate) use ciphertext_helpers::*;
pub(crate) use comparison::*;
pub(crate) use interpolation::*;
pub(crate) use packed_rank::*;
pub(crate) use rank_lookup::*;
pub(crate) use rotations::*;
pub(crate) use score_packing::*;
pub(crate) use sparse_target::*;
use std::collections::BTreeSet;

use crate::{
    bgv::{
        evaluator::{
            circuit::{
                EvaluatorContext, broadcast_constant_coefficients,
                evaluate_polynomial_with_fixed_baby_step_count_and_deferred_terminal_switch,
                modulus_switch_to, normalize_scaling,
            },
            engine::{
                Ciphertext, add_plaintext_coefficients, ciphertext_add, ciphertext_negate,
                ciphertext_sub, encode_slots_to_coefficients, plaintext_mul, scalar_mul,
                signed_residue,
            },
        },
        modular_arithmetic::{add_mod, integer_square_root_ceil, inverse_mod, mul_mod, sub_mod},
        parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

// The deterministic tie policy: a higher aggregate score ranks first, and equal
// scores are broken by the lower option index.
pub(crate) const TIE_POLICY: &str = "higher-sum-first-then-lower-option-index";
// The frozen evaluator working level for the selected multi-ballot parameters:
// the aggregate is mod-switched to this level before packing, every rotation
// and multiplication happens at or below it, and one relinearization key plus
// the packing/forward rotation keys are generated here (lower levels use the
// same keys through CRT-idempotent truncation).
pub(crate) const SELECTED_EVALUATOR_WORKING_LEVEL: usize = 15;
// Level 15 of 17 leaves headroom for packing plus comparison depth (down to
// level 6) plus rank lookup; baby-step 5 is about sqrt of the rank-lookup
// degree; generator 3 generates the order-N/2 subgroup of odd residues mod 2N.
pub(crate) const DIRECT_COMPARISON_OUTPUT_LEVEL: usize = 6;
// The canonical target ciphertext basis: the direct-comparison output level and
// its data-prime prefix. Setup-time statements (the compact same-secret bridge)
// pin their target-basis binding to this one canonical object.
pub(crate) const CANONICAL_TARGET_CIPHERTEXT_LEVEL: usize = DIRECT_COMPARISON_OUTPUT_LEVEL;
pub(crate) const RANK_LOOKUP_BABY_STEP_COUNT: usize = 5;

pub(crate) fn canonical_target_basis_primes() -> &'static [u64] {
    &crate::bgv::parameters::DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
}

pub(crate) fn canonical_target_basis_value() -> CanonicalResult<serde_json::Value> {
    if CANONICAL_TARGET_CIPHERTEXT_LEVEL >= crate::bgv::parameters::DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical target ciphertext level is outside the selected data basis",
        ));
    }

    Ok(serde_json::json!({
        "objectType": "CanonicalTargetBasis",
        "objectVersion": 1,
        "targetLevel": CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        "targetPrimes": canonical_target_basis_primes(),
    }))
}

pub(crate) fn canonical_target_basis_hash() -> CanonicalResult<String> {
    crate::hashing::derive_canonical_object_hash(&canonical_target_basis_value()?)
}
const PACKED_SCORE_GALOIS_GENERATOR: usize = 3;
const GENERATOR_SUBGROUP_ORDER: usize = POLYNOMIAL_DEGREE / 2;

pub(crate) struct PackedRankEvaluation {
    pub(crate) packed_ranks: Ciphertext,
}

// Encrypted sparse target projection result.
pub(crate) struct EncryptedSparseTarget {
    pub(crate) target_id: Ciphertext,
    pub(crate) target_order: Ciphertext,
}

#[cfg(test)]
mod tests;
