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

use serde_json::{Value, json};

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
        profile::{BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
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
// Level 15 of 17 leaves headroom for packing plus comparison depth and target
// release; baby-step 5 is about sqrt of the rank-lookup degree; generator 3
// generates the order-N/2 subgroup of odd residues mod 2N.
pub(crate) const DIRECT_COMPARISON_OUTPUT_LEVEL: usize = 4;
pub(crate) const CANONICAL_TARGET_CIPHERTEXT_LEVEL: usize = DIRECT_COMPARISON_OUTPUT_LEVEL;
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

pub(crate) fn canonical_target_basis_value() -> CanonicalResult<Value> {
    if CANONICAL_TARGET_CIPHERTEXT_LEVEL >= DATA_PRIMES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "canonical target ciphertext level is outside the selected data basis",
        ));
    }

    Ok(json!({
        "objectType": "CanonicalTargetBasis",
        "objectVersion": 1,
        "basisId": BgvBasisKind::Data.basis_id(),
        "targetLevel": CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        "primeOrder": "profile-order-prefix",
        "targetPrimes": canonical_target_basis_primes(),
        "modulusSwitchSchedule": {
            "sourceWorkingLevel": SELECTED_EVALUATOR_WORKING_LEVEL,
            "terminalLevel": CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            "rule": "drop trailing data-basis primes until the terminal target level is reached",
        },
        "scalingNormalization": "normalize ciphertext decrypt scaling to one before target roots are computed",
        "targetCiphertextRule": "target id and target order ciphertexts must both use the canonical target level",
    }))
}

pub(crate) fn canonical_target_basis_hash() -> CanonicalResult<String> {
    derive_protocol_hash("TargetBasisHash", &canonical_target_basis_value()?)
}

pub(crate) fn canonical_target_basis_modulus_bits() -> usize {
    canonical_target_basis_primes()
        .iter()
        .map(|modulus| {
            usize::try_from(u64::BITS - modulus.leading_zeros())
                .expect("modulus bit length fits usize")
        })
        .sum()
}

pub(crate) fn canonicalize_target_ciphertext(
    ciphertext: &Ciphertext,
) -> CanonicalResult<Ciphertext> {
    normalize_scaling(&modulus_switch_to(
        ciphertext,
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    )?)
}

pub(crate) fn validate_canonical_target_ciphertext(
    ciphertext: &Ciphertext,
    label: &str,
) -> CanonicalResult<()> {
    if ciphertext.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} must use the canonical target ciphertext level"),
        ));
    }
    if ciphertext.decrypt_scaling != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} must be normalized to decrypt scaling one"),
        ));
    }
    if ciphertext.primes() != canonical_target_basis_primes() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{label} active primes do not match the canonical target basis"),
        ));
    }

    Ok(())
}

pub(crate) fn canonical_target_basis_primes() -> &'static [u64] {
    &DATA_PRIMES[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
}

#[cfg(test)]
mod tests;
