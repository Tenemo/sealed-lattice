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
        profile::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

// The deterministic tie policy: a higher aggregate score ranks first, and equal
// scores are broken by the lower option index.
pub(crate) const TIE_POLICY: &str = "higher-sum-first-then-lower-option-index";
// The frozen evaluator working level for the selected multi-ballot profile:
// the aggregate is mod-switched to this level before packing, every rotation
// and multiplication happens at or below it, and one relinearization key plus
// the packing/forward rotation keys are generated here (lower levels use the
// same keys through CRT-idempotent truncation).
pub(crate) const SELECTED_EVALUATOR_WORKING_LEVEL: usize = 15;
pub(crate) const DIRECT_COMPARISON_OUTPUT_LEVEL: usize = 6;
pub(crate) const RANK_LOOKUP_BABY_STEP_COUNT: usize = 5;
const PACKED_SCORE_GALOIS_GENERATOR: usize = 3;
const GENERATOR_SUBGROUP_ORDER: usize = POLYNOMIAL_DEGREE / 2;

pub(crate) struct PackedRankEvaluation {
    pub(crate) packed_ranks: Ciphertext,
    exact_rank_indicators: Vec<Ciphertext>,
}

// Encrypted sparse target projection result.
pub(crate) struct EncryptedSparseTarget {
    pub(crate) target_id: Ciphertext,
    pub(crate) target_order: Ciphertext,
}

#[cfg(test)]
mod tests;
