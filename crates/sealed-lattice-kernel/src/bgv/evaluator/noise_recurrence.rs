//! Conservative instruction-by-instruction error recurrence for the exact BGV
//! evaluator implementation.
//!
//! This module is independent parameter evidence. Its values are never read
//! from ciphertexts and are not serialized into protocol artifacts. The
//! recurrence follows the implemented coefficient-domain operations, including
//! canonical plaintext carries, scaling normalization, exact centered hybrid
//! Q/P key switching, and the exact BGV modulus-switch correction.

use std::sync::Arc;

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};

use crate::{
    bgv::{
        key_switch_topology::{
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK, key_switch_special_basis_modulus_product,
        },
        modular_arithmetic::{inverse_mod, mul_mod},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

use super::top_k::{
    CANONICAL_TARGET_CIPHERTEXT_LEVEL, EvaluatorModulusSchedule, RANK_LOOKUP_BABY_STEP_COUNT,
    SELECTED_EVALUATOR_MODULUS_SCHEDULE, comparison_polynomials, direct_comparison_baby_step_count,
    galois_power, generator_exponent_or_conjugated, generator_inverse_power_basis_for_exponent,
    generator_power_basis_for_exponent, interpolate_coefficients, packed_pair_lower_mask,
    packed_score_slot_selector, packed_score_weighted_selector, scheduled_power_table_products,
};

const CENTERED_PLAINTEXT_BOUND: u64 = PLAINTEXT_MODULUS / 2;
const FRESH_ERROR_COEFFICIENT_BOUND: u64 = 2;
const FRESH_RANDOMIZER_COEFFICIENT_BOUND: u64 = 1;
const MAXIMUM_CANONICAL_PLAINTEXT_LIFT_OFFSET: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvaluationKeyErrorKind {
    Relinearization,
    Galois,
}

fn broadcast_constant_coefficients(value: u64) -> Vec<u64> {
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    coefficients[0] = value % PLAINTEXT_MODULUS;
    coefficients
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymbolicCiphertextBound {
    pub(crate) level: usize,
    pub(crate) decrypt_scaling: u64,
    pub(crate) message_coefficient_bound: BigUint,
    pub(crate) error_coefficient_bound: BigUint,
    pub(crate) component_count: usize,
    pub(crate) collective_secret_coefficient_bound: u64,
    pub(crate) minimum_decryption_margin: BigInt,
    data_primes: Arc<[u64]>,
    key_switch_data_primes_per_block: usize,
    key_switch_special_basis_modulus: Arc<BigUint>,
    #[cfg(test)]
    stochastic_rounding_correction_bound: Option<Arc<BigUint>>,
}

impl SymbolicCiphertextBound {
    #[cfg(test)]
    fn with_stochastic_rounding_correction_bound(
        mut self,
        stochastic_rounding_correction_bound: BigUint,
    ) -> Self {
        self.stochastic_rounding_correction_bound =
            Some(Arc::new(stochastic_rounding_correction_bound));
        self
    }

    pub(crate) fn fresh_direct_ballot(
        collective_secret_coefficient_bound: u64,
    ) -> CanonicalResult<Self> {
        Self::fresh_direct_ballot_with_data_primes(
            collective_secret_coefficient_bound,
            Arc::from(DATA_PRIMES),
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
            Arc::new(key_switch_special_basis_modulus_product()),
        )
    }

    fn fresh_direct_ballot_with_data_primes(
        collective_secret_coefficient_bound: u64,
        data_primes: Arc<[u64]>,
        key_switch_data_primes_per_block: usize,
        key_switch_special_basis_modulus: Arc<BigUint>,
    ) -> CanonicalResult<Self> {
        if collective_secret_coefficient_bound == 0 {
            return Err(invalid_recurrence(
                "collective secret coefficient bound must be positive",
            ));
        }

        // The collective public-key error is the sum of one eta-two error per
        // trustee. For b = t*e_pk - a*s and ciphertext errors e0,e1,
        //
        //   c0 + c1*s = M + t*(e_pk*u + e0 + e1*s + Z),
        //
        // where the runtime's canonical plaintext lift is m = M + t*Z for
        // centered M and Z in {0, 1}.
        //
        // Both e_pk*u and e1*s use the collective coefficient bound.
        let convolution_factor = BigUint::from(POLYNOMIAL_DEGREE)
            * BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND)
            * BigUint::from(FRESH_RANDOMIZER_COEFFICIENT_BOUND)
            * BigUint::from(collective_secret_coefficient_bound);
        let error_coefficient_bound = (&convolution_factor << 1_usize)
            + BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND)
            + BigUint::from(MAXIMUM_CANONICAL_PLAINTEXT_LIFT_OFFSET);
        let mut bound = Self {
            level: data_primes.len() - 1,
            decrypt_scaling: 1,
            message_coefficient_bound: BigUint::from(CENTERED_PLAINTEXT_BOUND),
            error_coefficient_bound,
            component_count: 2,
            collective_secret_coefficient_bound,
            minimum_decryption_margin: BigInt::zero(),
            data_primes,
            key_switch_data_primes_per_block,
            key_switch_special_basis_modulus,
            #[cfg(test)]
            stochastic_rounding_correction_bound: None,
        };
        bound.minimum_decryption_margin = bound.final_decryption_margin();

        Ok(bound)
    }

    pub(crate) fn aggregate_fresh_direct_ballots(
        participant_count: u64,
        ballot_count: usize,
    ) -> CanonicalResult<Self> {
        if ballot_count == 0
            || u64::try_from(ballot_count).map_or(true, |count| count > participant_count)
        {
            return Err(invalid_recurrence(
                "ballot count must be between one and the participant count",
            ));
        }

        Self::aggregate_fresh_direct_ballots_with_data_primes(
            participant_count,
            ballot_count,
            Arc::from(DATA_PRIMES),
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
            Arc::new(key_switch_special_basis_modulus_product()),
        )
    }

    fn aggregate_fresh_direct_ballots_with_data_primes(
        participant_count: u64,
        ballot_count: usize,
        data_primes: Arc<[u64]>,
        key_switch_data_primes_per_block: usize,
        key_switch_special_basis_modulus: Arc<BigUint>,
    ) -> CanonicalResult<Self> {
        if ballot_count == 0
            || u64::try_from(ballot_count).map_or(true, |count| count > participant_count)
        {
            return Err(invalid_recurrence(
                "ballot count must be between one and the participant count",
            ));
        }

        let fresh = Self::fresh_direct_ballot_with_data_primes(
            participant_count,
            data_primes,
            key_switch_data_primes_per_block,
            key_switch_special_basis_modulus,
        )?;
        let mut aggregate = fresh.clone();
        for _ in 1..ballot_count {
            aggregate = aggregate.add(&fresh)?;
        }

        Ok(aggregate)
    }

    pub(crate) fn add(&self, other: &Self) -> CanonicalResult<Self> {
        self.require_same_level_and_scaling(other, "addition")?;
        let unreduced_message_bound =
            &self.message_coefficient_bound + &other.message_coefficient_bound;
        let carry_bound = centered_reduction_carry_bound(&unreduced_message_bound);
        let error_coefficient_bound = &self.error_coefficient_bound
            + &other.error_coefficient_bound
            + (absolute_centered_residue(self.scaling_inverse()?) * carry_bound);

        self.derived(
            self.level,
            self.decrypt_scaling,
            canonical_message_bound(unreduced_message_bound),
            error_coefficient_bound,
            self.component_count.max(other.component_count),
            Some(&other.minimum_decryption_margin),
        )
    }

    pub(crate) fn subtract(&self, other: &Self) -> CanonicalResult<Self> {
        self.add(&other.negate())
    }

    pub(crate) fn negate(&self) -> Self {
        self.clone()
    }

    pub(crate) fn scalar_multiply(&self, scalar: i64) -> CanonicalResult<Self> {
        let centered_scalar = centered_plaintext_residue_i128(scalar);
        self.plaintext_multiply_with_norm(&absolute_i128(centered_scalar))
    }

    pub(crate) fn add_plaintext_coefficients(
        &self,
        plaintext_coefficients: &[u64],
    ) -> CanonicalResult<Self> {
        let (plaintext_infinity_bound, _, canonical_lift_offset_bound) =
            plaintext_polynomial_norms(plaintext_coefficients);
        self.add_plaintext_with_bounds(&plaintext_infinity_bound, &canonical_lift_offset_bound)
    }

    fn add_plaintext_with_bounds(
        &self,
        plaintext_infinity_bound: &BigUint,
        canonical_lift_offset_bound: &BigUint,
    ) -> CanonicalResult<Self> {
        let scaling = centered_residue_i128(self.decrypt_scaling);
        let inverse_scaling = self.scaling_inverse()?;
        let inverse_scaling_centered = centered_residue_i128(inverse_scaling);
        let scaling_product_carry =
            (inverse_scaling_centered * scaling - 1) / i128::from(PLAINTEXT_MODULUS);
        let unreduced_message_bound =
            &self.message_coefficient_bound + (absolute_i128(scaling) * plaintext_infinity_bound);
        let message_carry_bound = centered_reduction_carry_bound(&unreduced_message_bound);
        let error_coefficient_bound = &self.error_coefficient_bound
            + (absolute_i128(inverse_scaling_centered) * message_carry_bound)
            + (absolute_i128(scaling_product_carry) * plaintext_infinity_bound)
            + canonical_lift_offset_bound;

        self.derived(
            self.level,
            self.decrypt_scaling,
            canonical_message_bound(unreduced_message_bound),
            error_coefficient_bound,
            self.component_count,
            None,
        )
    }

    pub(crate) fn plaintext_multiply(
        &self,
        plaintext_coefficients: &[u64],
    ) -> CanonicalResult<Self> {
        let (_, plaintext_l1_norm, _) = plaintext_polynomial_norms(plaintext_coefficients);
        self.plaintext_multiply_with_norm(&plaintext_l1_norm)
    }

    fn plaintext_multiply_with_norm(&self, plaintext_l1_norm: &BigUint) -> CanonicalResult<Self> {
        let unreduced_message_bound = &self.message_coefficient_bound * plaintext_l1_norm;
        let carry_bound = centered_reduction_carry_bound(&unreduced_message_bound);
        let error_coefficient_bound = (&self.error_coefficient_bound * plaintext_l1_norm)
            + (absolute_centered_residue(self.scaling_inverse()?) * carry_bound);

        self.derived(
            self.level,
            self.decrypt_scaling,
            canonical_message_bound(unreduced_message_bound),
            error_coefficient_bound,
            self.component_count,
            None,
        )
    }

    pub(crate) fn normalize_scaling(&self) -> CanonicalResult<Self> {
        if self.decrypt_scaling == 1 {
            return Ok(self.clone());
        }
        let scaling = i128::from(self.decrypt_scaling);
        let inverse_scaling = centered_residue_i128(self.scaling_inverse()?);
        let scaling_product_carry = (scaling * inverse_scaling - 1) / i128::from(PLAINTEXT_MODULUS);
        let error_coefficient_bound = (absolute_i128(scaling) * &self.error_coefficient_bound)
            + (absolute_i128(scaling_product_carry) * &self.message_coefficient_bound);

        self.derived(
            self.level,
            1,
            self.message_coefficient_bound.clone(),
            error_coefficient_bound,
            self.component_count,
            None,
        )
    }

    pub(crate) fn tensor(&self, other: &Self) -> CanonicalResult<Self> {
        if self.level != other.level
            || self.component_count != 2
            || other.component_count != 2
            || self.collective_secret_coefficient_bound != other.collective_secret_coefficient_bound
            || self.data_primes != other.data_primes
            || self.key_switch_data_primes_per_block != other.key_switch_data_primes_per_block
            || self.key_switch_special_basis_modulus != other.key_switch_special_basis_modulus
        {
            return Err(invalid_recurrence(
                "tensor multiplication requires two two-component bounds at one level and secret profile",
            ));
        }

        let ring_degree = BigUint::from(POLYNOMIAL_DEGREE);
        let unreduced_message_bound =
            &ring_degree * &self.message_coefficient_bound * &other.message_coefficient_bound;
        let message_carry_bound = centered_reduction_carry_bound(&unreduced_message_bound);
        let left_inverse_scaling = centered_residue_i128(self.scaling_inverse()?);
        let right_inverse_scaling = centered_residue_i128(other.scaling_inverse()?);
        let output_scaling = mul_mod(
            self.decrypt_scaling,
            other.decrypt_scaling,
            PLAINTEXT_MODULUS,
        )?;
        let output_inverse_scaling =
            centered_residue_i128(inverse_mod(output_scaling, PLAINTEXT_MODULUS)?);
        let multiplier_carry = (left_inverse_scaling * right_inverse_scaling
            - output_inverse_scaling)
            / i128::from(PLAINTEXT_MODULUS);

        let left_message_times_right_error = absolute_i128(left_inverse_scaling)
            * &ring_degree
            * &self.message_coefficient_bound
            * &other.error_coefficient_bound;
        let right_message_times_left_error = absolute_i128(right_inverse_scaling)
            * &ring_degree
            * &other.message_coefficient_bound
            * &self.error_coefficient_bound;
        let error_product = BigUint::from(PLAINTEXT_MODULUS)
            * &ring_degree
            * &self.error_coefficient_bound
            * &other.error_coefficient_bound;
        let output_message_carry = absolute_i128(output_inverse_scaling) * message_carry_bound;
        let inverse_multiplier_carry = absolute_i128(multiplier_carry) * &unreduced_message_bound;
        let error_coefficient_bound = left_message_times_right_error
            + right_message_times_left_error
            + error_product
            + output_message_carry
            + inverse_multiplier_carry;

        self.derived(
            self.level,
            output_scaling,
            canonical_message_bound(unreduced_message_bound),
            error_coefficient_bound,
            3,
            Some(&other.minimum_decryption_margin),
        )
    }

    fn key_switch(&self, evaluation_key_kind: EvaluationKeyErrorKind) -> CanonicalResult<Self> {
        if self.component_count < 2 || self.component_count > 3 {
            return Err(invalid_recurrence(
                "key switching requires a two- or three-component ciphertext bound",
            ));
        }
        #[cfg(test)]
        let key_switch_error_bound = if let Some(stochastic_rounding_correction_bound) =
            &self.stochastic_rounding_correction_bound
        {
            hybrid_key_switch_decomposed_error_bound(
                self.level,
                self.key_switch_data_primes_per_block,
                &self.data_primes,
                &self.key_switch_special_basis_modulus,
                &collective_evaluation_key_error_bound(
                    evaluation_key_kind,
                    self.collective_secret_coefficient_bound,
                ),
            )? + stochastic_rounding_correction_bound.as_ref()
        } else {
            hybrid_key_switch_error_bound(
                self.level,
                self.collective_secret_coefficient_bound,
                self.key_switch_data_primes_per_block,
                &self.data_primes,
                &self.key_switch_special_basis_modulus,
                evaluation_key_kind,
            )?
        };
        #[cfg(not(test))]
        let key_switch_error_bound = hybrid_key_switch_error_bound(
            self.level,
            self.collective_secret_coefficient_bound,
            self.key_switch_data_primes_per_block,
            &self.data_primes,
            &self.key_switch_special_basis_modulus,
            evaluation_key_kind,
        )?;
        let error_coefficient_bound = &self.error_coefficient_bound + key_switch_error_bound;

        self.derived(
            self.level,
            self.decrypt_scaling,
            self.message_coefficient_bound.clone(),
            error_coefficient_bound,
            2,
            None,
        )
    }

    pub(crate) fn modulus_switch(&self) -> CanonicalResult<Self> {
        if self.level == 0 || self.component_count != 2 {
            return Err(invalid_recurrence(
                "modulus switching requires a two-component bound above level zero",
            ));
        }
        let dropped_modulus = self.data_primes[self.level];
        let output_scaling = mul_mod(
            self.decrypt_scaling,
            dropped_modulus % PLAINTEXT_MODULUS,
            PLAINTEXT_MODULUS,
        )?;
        let input_inverse_scaling = centered_residue_i128(self.scaling_inverse()?);
        let output_inverse_scaling =
            centered_residue_i128(inverse_mod(output_scaling, PLAINTEXT_MODULUS)?);
        let scaling_transition_carry = (input_inverse_scaling
            - (i128::from(dropped_modulus) * output_inverse_scaling))
            / i128::from(PLAINTEXT_MODULUS);
        let scaling_transition_bound =
            absolute_i128(scaling_transition_carry) * &self.message_coefficient_bound;
        #[cfg(test)]
        let error_coefficient_bound = if let Some(stochastic_rounding_correction_bound) =
            &self.stochastic_rounding_correction_bound
        {
            divide_with_ceiling(
                &(&self.error_coefficient_bound + &scaling_transition_bound),
                &BigUint::from(dropped_modulus),
            ) + stochastic_rounding_correction_bound.as_ref()
        } else {
            let half_dropped_modulus = BigUint::from(dropped_modulus / 2);
            let secret_l1_bound = BigUint::from(POLYNOMIAL_DEGREE)
                * BigUint::from(self.collective_secret_coefficient_bound);
            let correction_bound = half_dropped_modulus * (BigUint::one() + secret_l1_bound);
            let numerator_bound =
                &self.error_coefficient_bound + correction_bound + &scaling_transition_bound;
            divide_with_ceiling(&numerator_bound, &BigUint::from(dropped_modulus))
        };
        #[cfg(not(test))]
        let error_coefficient_bound = {
            let half_dropped_modulus = BigUint::from(dropped_modulus / 2);
            let secret_l1_bound = BigUint::from(POLYNOMIAL_DEGREE)
                * BigUint::from(self.collective_secret_coefficient_bound);
            let correction_bound = half_dropped_modulus * (BigUint::one() + secret_l1_bound);
            let numerator_bound =
                &self.error_coefficient_bound + correction_bound + scaling_transition_bound;
            divide_with_ceiling(&numerator_bound, &BigUint::from(dropped_modulus))
        };

        self.derived(
            self.level - 1,
            output_scaling,
            self.message_coefficient_bound.clone(),
            error_coefficient_bound,
            2,
            None,
        )
    }

    pub(crate) fn modulus_switch_to(&self, target_level: usize) -> CanonicalResult<Self> {
        let mut current = self.clone();
        while current.level > target_level {
            current = current.modulus_switch()?;
        }

        Ok(current)
    }

    pub(crate) fn multiply_and_switch(&self, other: &Self) -> CanonicalResult<Self> {
        self.multiply_and_switch_by(other, 1)
    }

    pub(crate) fn multiply_and_switch_by(
        &self,
        other: &Self,
        modulus_drop_count: usize,
    ) -> CanonicalResult<Self> {
        let target_level = self.level.min(other.level);
        if modulus_drop_count > target_level {
            return Err(invalid_recurrence(
                "symbolic multiplication received an invalid modulus-drop count",
            ));
        }
        let left = self.modulus_switch_to(target_level)?;
        let right = other.modulus_switch_to(target_level)?;
        left.tensor(&right)?
            .key_switch(EvaluationKeyErrorKind::Relinearization)?
            .modulus_switch_to(target_level - modulus_drop_count)
    }

    pub(crate) fn multiply_without_terminal_switch(&self, other: &Self) -> CanonicalResult<Self> {
        let target_level = self.level.min(other.level);
        let left = self.modulus_switch_to(target_level)?;
        let right = other.modulus_switch_to(target_level)?;
        left.tensor(&right)?
            .key_switch(EvaluationKeyErrorKind::Relinearization)
    }

    pub(crate) fn rotate_once(&self) -> CanonicalResult<Self> {
        self.key_switch(EvaluationKeyErrorKind::Galois)
    }

    pub(crate) fn final_decryption_margin(&self) -> BigInt {
        BigInt::from(active_modulus(self.level, &self.data_primes))
            - BigInt::from(BigUint::from(2_u8) * raw_decryption_bound(self))
    }

    fn scaling_inverse(&self) -> CanonicalResult<u64> {
        inverse_mod(self.decrypt_scaling, PLAINTEXT_MODULUS)
    }

    fn require_same_level_and_scaling(&self, other: &Self, operation: &str) -> CanonicalResult<()> {
        if self.level != other.level
            || self.decrypt_scaling != other.decrypt_scaling
            || self.collective_secret_coefficient_bound != other.collective_secret_coefficient_bound
            || self.data_primes != other.data_primes
            || self.key_switch_data_primes_per_block != other.key_switch_data_primes_per_block
            || self.key_switch_special_basis_modulus != other.key_switch_special_basis_modulus
            || {
                #[cfg(test)]
                {
                    self.stochastic_rounding_correction_bound
                        != other.stochastic_rounding_correction_bound
                }
                #[cfg(not(test))]
                {
                    false
                }
            }
        {
            return Err(invalid_recurrence(format!(
                "symbolic {operation} requires equal levels, scaling, and secret profile"
            )));
        }

        Ok(())
    }

    fn derived(
        &self,
        level: usize,
        decrypt_scaling: u64,
        message_coefficient_bound: BigUint,
        error_coefficient_bound: BigUint,
        component_count: usize,
        other_minimum_decryption_margin: Option<&BigInt>,
    ) -> CanonicalResult<Self> {
        let inherited_minimum_decryption_margin = other_minimum_decryption_margin.map_or_else(
            || self.minimum_decryption_margin.clone(),
            |other_minimum| {
                self.minimum_decryption_margin
                    .clone()
                    .min(other_minimum.clone())
            },
        );
        let mut output = Self {
            level,
            decrypt_scaling,
            message_coefficient_bound,
            error_coefficient_bound,
            component_count,
            collective_secret_coefficient_bound: self.collective_secret_coefficient_bound,
            minimum_decryption_margin: inherited_minimum_decryption_margin,
            data_primes: Arc::clone(&self.data_primes),
            key_switch_data_primes_per_block: self.key_switch_data_primes_per_block,
            key_switch_special_basis_modulus: Arc::clone(&self.key_switch_special_basis_modulus),
            #[cfg(test)]
            stochastic_rounding_correction_bound: self
                .stochastic_rounding_correction_bound
                .as_ref()
                .map(Arc::clone),
        };
        let final_decryption_margin = output.final_decryption_margin();
        output.minimum_decryption_margin = output
            .minimum_decryption_margin
            .clone()
            .min(final_decryption_margin);

        Ok(output)
    }
}

fn hybrid_key_switch_error_bound(
    level: usize,
    collective_secret_coefficient_bound: u64,
    data_primes_per_block: usize,
    data_primes: &[u64],
    special_basis_modulus: &BigUint,
    evaluation_key_kind: EvaluationKeyErrorKind,
) -> CanonicalResult<BigUint> {
    let decomposed_error = hybrid_key_switch_decomposed_error_bound(
        level,
        data_primes_per_block,
        data_primes,
        special_basis_modulus,
        &collective_evaluation_key_error_bound(
            evaluation_key_kind,
            collective_secret_coefficient_bound,
        ),
    )?;
    let ring_degree = BigUint::from(POLYNOMIAL_DEGREE);
    let trustee_bound = BigUint::from(collective_secret_coefficient_bound);
    let component_b_correction = BigUint::one();
    let component_a_secret_correction =
        divide_with_ceiling(&(&ring_degree * trustee_bound), &BigUint::from(2_u8));

    Ok(decomposed_error + component_b_correction + component_a_secret_correction)
}

fn hybrid_key_switch_decomposed_error_bound(
    level: usize,
    data_primes_per_block: usize,
    data_primes: &[u64],
    special_basis_modulus: &BigUint,
    collective_evaluation_key_error_bound: &BigUint,
) -> CanonicalResult<BigUint> {
    if level >= data_primes.len()
        || data_primes_per_block == 0
        || collective_evaluation_key_error_bound.is_zero()
    {
        return Err(invalid_recurrence(
            "hybrid key-switch recurrence received an invalid level, block size, or secret bound",
        ));
    }
    let active_data_primes = &data_primes[..=level];
    let active_block_count = active_data_primes.len().div_ceil(data_primes_per_block);
    let maximum_block_modulus = active_data_primes
        .chunks(data_primes_per_block)
        .map(|block| {
            block
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>()
        })
        .max()
        .expect("active data basis has at least one block");
    let ring_degree = BigUint::from(POLYNOMIAL_DEGREE);
    let decomposed_error_numerator = BigUint::from(active_block_count)
        * &ring_degree
        * maximum_block_modulus
        * collective_evaluation_key_error_bound;
    let twice_special_basis_modulus = BigUint::from(2_u8) * special_basis_modulus;
    let decomposed_error =
        divide_with_ceiling(&decomposed_error_numerator, &twice_special_basis_modulus);
    Ok(decomposed_error)
}

fn collective_evaluation_key_error_bound(
    evaluation_key_kind: EvaluationKeyErrorKind,
    collective_secret_coefficient_bound: u64,
) -> BigUint {
    let twice_trustee_bound =
        BigUint::from(2_u8) * BigUint::from(collective_secret_coefficient_bound);
    match evaluation_key_kind {
        EvaluationKeyErrorKind::Relinearization => {
            BigUint::from(2_u8)
                * BigUint::from(POLYNOMIAL_DEGREE)
                * BigUint::from(collective_secret_coefficient_bound)
                * &twice_trustee_bound
                + twice_trustee_bound
        }
        EvaluationKeyErrorKind::Galois => twice_trustee_bound,
    }
}

fn raw_decryption_bound(bound: &SymbolicCiphertextBound) -> BigUint {
    (absolute_centered_residue(
        bound
            .scaling_inverse()
            .expect("nonzero plaintext scaling is invertible"),
    ) * &bound.message_coefficient_bound)
        + (BigUint::from(PLAINTEXT_MODULUS) * &bound.error_coefficient_bound)
}

fn active_modulus(level: usize, data_primes: &[u64]) -> BigUint {
    data_primes[..=level]
        .iter()
        .map(|prime| BigUint::from(*prime))
        .product()
}

fn plaintext_polynomial_norms(coefficients: &[u64]) -> (BigUint, BigUint, BigUint) {
    let mut infinity_bound = BigUint::zero();
    let mut l1_norm = BigUint::zero();
    let mut canonical_lift_offset_bound = BigUint::zero();
    for coefficient in coefficients {
        let absolute_coefficient = absolute_i128(centered_residue_i128(*coefficient));
        infinity_bound = infinity_bound.max(absolute_coefficient.clone());
        l1_norm += absolute_coefficient;
        if coefficient % PLAINTEXT_MODULUS > CENTERED_PLAINTEXT_BOUND {
            canonical_lift_offset_bound = BigUint::one();
        }
    }

    (infinity_bound, l1_norm, canonical_lift_offset_bound)
}

fn centered_reduction_carry_bound(unreduced_bound: &BigUint) -> BigUint {
    (unreduced_bound + BigUint::from(CENTERED_PLAINTEXT_BOUND)) / BigUint::from(PLAINTEXT_MODULUS)
}

fn canonical_message_bound(unreduced_bound: BigUint) -> BigUint {
    unreduced_bound.min(BigUint::from(CENTERED_PLAINTEXT_BOUND))
}

fn divide_with_ceiling(numerator: &BigUint, denominator: &BigUint) -> BigUint {
    let quotient = numerator / denominator;
    if numerator % denominator == BigUint::zero() {
        quotient
    } else {
        quotient + BigUint::one()
    }
}

fn centered_plaintext_residue_i128(value: i64) -> i128 {
    let modulus = i128::from(PLAINTEXT_MODULUS);
    let residue = ((i128::from(value) % modulus) + modulus) % modulus;
    if residue > i128::from(CENTERED_PLAINTEXT_BOUND) {
        residue - modulus
    } else {
        residue
    }
}

fn centered_residue_i128(value: u64) -> i128 {
    let residue = value % PLAINTEXT_MODULUS;
    if residue > CENTERED_PLAINTEXT_BOUND {
        i128::from(residue) - i128::from(PLAINTEXT_MODULUS)
    } else {
        i128::from(residue)
    }
}

fn absolute_centered_residue(value: u64) -> BigUint {
    absolute_i128(centered_residue_i128(value))
}

fn absolute_i128(value: i128) -> BigUint {
    BigUint::from(value.unsigned_abs())
}

fn invalid_recurrence(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectBallotTargetNoiseBound {
    pub(crate) top_count: usize,
    pub(crate) target_identifier: SymbolicCiphertextBound,
    pub(crate) target_order: SymbolicCiphertextBound,
}

impl DirectBallotTargetNoiseBound {
    pub(crate) fn maximum_error_coefficient_bound(&self) -> &BigUint {
        if self.target_identifier.error_coefficient_bound
            >= self.target_order.error_coefficient_bound
        {
            &self.target_identifier.error_coefficient_bound
        } else {
            &self.target_order.error_coefficient_bound
        }
    }

    pub(crate) fn every_decryption_margin_is_positive(&self) -> bool {
        self.target_identifier
            .minimum_decryption_margin
            .is_positive()
            && self.target_order.minimum_decryption_margin.is_positive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactPlaintextPolynomialNorms {
    infinity_bound: BigUint,
    l1_norm: BigUint,
    canonical_lift_offset_bound: BigUint,
}

impl ExactPlaintextPolynomialNorms {
    fn from_coefficients(coefficients: &[u64]) -> Self {
        let (infinity_bound, l1_norm, canonical_lift_offset_bound) =
            plaintext_polynomial_norms(coefficients);
        Self {
            infinity_bound,
            l1_norm,
            canonical_lift_offset_bound,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedPackedRankPairWindow {
    shift: usize,
    window_offset: usize,
    lower_pair_mask: ExactPlaintextPolynomialNorms,
    window_selector: ExactPlaintextPolynomialNorms,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PreparedTargetProjectionKind {
    RankLookup {
        indicator_polynomial: Vec<u64>,
        order_polynomial: Vec<u64>,
    },
    CompleteList,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedTargetProjection {
    top_count: usize,
    kind: PreparedTargetProjectionKind,
}

/// Prime-order-invariant plaintext work for one exact direct-ballot recurrence.
///
/// Each selector is still generated by the production batch encoder. The
/// prepared representation retains exactly the infinity and L1 norms consumed
/// by the symbolic equations, while avoiding repeated 65,536-coefficient
/// inverse-NTT encodings during an exact topology search.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedDirectBallotTargetNoiseRecurrence {
    option_count: usize,
    score_slot_selector: ExactPlaintextPolynomialNorms,
    comparison_shift_constant: ExactPlaintextPolynomialNorms,
    pairwise_comparison_shift: ExactPlaintextPolynomialNorms,
    greater_or_equal_polynomial: Vec<u64>,
    comparison_baby_step_count: usize,
    pair_windows: Vec<PreparedPackedRankPairWindow>,
    identifier_selector: ExactPlaintextPolynomialNorms,
    option_slot_mask: ExactPlaintextPolynomialNorms,
    target_projections: Vec<PreparedTargetProjection>,
}

impl PreparedDirectBallotTargetNoiseRecurrence {
    fn prepare(option_count: usize, score_domain_maximum: u64) -> CanonicalResult<Self> {
        if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
            return Err(invalid_recurrence(
                "direct-ballot noise recurrence requires a valid packed option window",
            ));
        }
        let pair_count = option_count * option_count.saturating_sub(1) / 2;
        if pair_count > POLYNOMIAL_DEGREE / 2 {
            return Err(invalid_recurrence(
                "packed-rank recurrence exceeds the generator subgroup window",
            ));
        }

        let option_indices = (0..option_count).collect::<Vec<_>>();
        let score_slot_selector = ExactPlaintextPolynomialNorms::from_coefficients(
            &packed_score_slot_selector(&option_indices)?,
        );
        let comparison_shift_constant = ExactPlaintextPolynomialNorms::from_coefficients(
            &broadcast_constant_coefficients(score_domain_maximum),
        );
        let pair_count = option_count
            .checked_mul(option_count.saturating_sub(1))
            .and_then(|product| product.checked_div(2))
            .ok_or_else(|| invalid_recurrence("pairwise comparison lane count overflowed"))?;
        let pairwise_comparison_shift_weights = (0..pair_count)
            .map(|logical_index| (logical_index, score_domain_maximum))
            .collect::<Vec<_>>();
        let pairwise_comparison_shift = ExactPlaintextPolynomialNorms::from_coefficients(
            &packed_score_weighted_selector(&pairwise_comparison_shift_weights)?,
        );
        let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_maximum)?;

        let mut pair_windows = Vec::with_capacity(option_count - 1);
        let mut next_window_offset = 0_usize;
        for shift in 1..option_count {
            let pair_window_size = option_count - shift;
            let window_logical_indices =
                (next_window_offset..(next_window_offset + pair_window_size)).collect::<Vec<_>>();
            pair_windows.push(PreparedPackedRankPairWindow {
                shift,
                window_offset: next_window_offset,
                lower_pair_mask: ExactPlaintextPolynomialNorms::from_coefficients(
                    &packed_pair_lower_mask(option_count, shift)?,
                ),
                window_selector: ExactPlaintextPolynomialNorms::from_coefficients(
                    &packed_score_slot_selector(&window_logical_indices)?,
                ),
            });
            next_window_offset += pair_window_size;
        }

        let identifier_weights = (0..option_count)
            .map(|option_index| {
                (
                    option_index,
                    u64::try_from(option_index + 1).expect("option identifier fits u64"),
                )
            })
            .collect::<Vec<_>>();
        let identifier_selector = ExactPlaintextPolynomialNorms::from_coefficients(
            &packed_score_weighted_selector(&identifier_weights)?,
        );
        let option_slot_mask = score_slot_selector.clone();
        let target_projections = (1..=option_count)
            .map(|top_count| {
                let kind = if top_count == option_count {
                    PreparedTargetProjectionKind::CompleteList
                } else {
                    let indicator_values = (0..option_count)
                        .map(|rank_value| u64::from(rank_value < top_count))
                        .collect::<Vec<_>>();
                    let order_values = (0..option_count)
                        .map(|rank_value| {
                            if rank_value < top_count {
                                u64::try_from(rank_value + 1).expect("rank value fits u64")
                            } else {
                                0
                            }
                        })
                        .collect::<Vec<_>>();
                    PreparedTargetProjectionKind::RankLookup {
                        indicator_polynomial: interpolate_coefficients(&indicator_values)?,
                        order_polynomial: interpolate_coefficients(&order_values)?,
                    }
                };
                Ok(PreparedTargetProjection { top_count, kind })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;

        Ok(Self {
            option_count,
            score_slot_selector,
            comparison_shift_constant,
            pairwise_comparison_shift,
            greater_or_equal_polynomial,
            comparison_baby_step_count: direct_comparison_baby_step_count(score_domain_maximum)?,
            pair_windows,
            identifier_selector,
            option_slot_mask,
            target_projections,
        })
    }
}

/// Evaluate the exact production control flow symbolically for every selected
/// top-count value. Every ballot count uses the one working level frozen by the
/// evaluator program.
pub(crate) fn direct_ballot_target_noise_bounds(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    direct_ballot_target_noise_bounds_with_schedule(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
        &SELECTED_EVALUATOR_MODULUS_SCHEDULE,
    )
}

pub(crate) fn direct_ballot_target_noise_bounds_with_schedule(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
    modulus_schedule: &EvaluatorModulusSchedule,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    direct_ballot_target_noise_bounds_with_schedule_and_data_primes(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
        modulus_schedule,
        &DATA_PRIMES,
    )
}

pub(crate) fn direct_ballot_target_noise_bounds_with_schedule_and_data_primes(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
    modulus_schedule: &EvaluatorModulusSchedule,
    data_primes: &[u64],
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    direct_ballot_target_noise_bounds_with_topology(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
        modulus_schedule,
        data_primes,
        KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
        &SPECIAL_PRIMES,
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn direct_ballot_target_noise_bounds_with_topology(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
    modulus_schedule: &EvaluatorModulusSchedule,
    data_primes: &[u64],
    key_switch_data_primes_per_block: usize,
    special_primes: &[u64],
    target_level: usize,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    if option_count < 2 || option_count * 2 > POLYNOMIAL_DEGREE {
        return Err(invalid_recurrence(
            "direct-ballot noise recurrence requires a valid packed option window",
        ));
    }
    if maximum_score < minimum_score {
        return Err(invalid_recurrence(
            "direct-ballot score maximum must not be below its minimum",
        ));
    }
    let ballot_count_u64 = u64::try_from(ballot_count)
        .map_err(|_| invalid_recurrence("ballot count does not fit u64"))?;
    let score_domain_maximum = (maximum_score - minimum_score)
        .checked_mul(ballot_count_u64)
        .ok_or_else(|| invalid_recurrence("comparison domain overflowed"))?;
    let prepared_recurrence =
        PreparedDirectBallotTargetNoiseRecurrence::prepare(option_count, score_domain_maximum)?;
    direct_ballot_target_noise_bounds_with_prepared_topology(
        participant_count,
        ballot_count,
        modulus_schedule,
        data_primes,
        key_switch_data_primes_per_block,
        special_primes,
        target_level,
        &prepared_recurrence,
    )
}

#[allow(clippy::too_many_arguments)]
fn direct_ballot_target_noise_bounds_with_prepared_topology(
    participant_count: u64,
    ballot_count: usize,
    modulus_schedule: &EvaluatorModulusSchedule,
    data_primes: &[u64],
    key_switch_data_primes_per_block: usize,
    special_primes: &[u64],
    target_level: usize,
    prepared_recurrence: &PreparedDirectBallotTargetNoiseRecurrence,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    let working_level = data_primes
        .len()
        .checked_sub(1)
        .ok_or_else(|| invalid_recurrence("evaluator data basis is empty"))?;
    if target_level >= working_level {
        return Err(invalid_recurrence(
            "evaluator working level is outside the selected data basis",
        ));
    }
    if key_switch_data_primes_per_block == 0 || special_primes.is_empty() {
        return Err(invalid_recurrence(
            "evaluator key-switch topology requires a nonempty block and special basis",
        ));
    }
    if modulus_schedule.total_drop_count() != working_level.saturating_sub(target_level)
        || modulus_schedule.pre_comparison_drop_count + modulus_schedule.comparison_drop_count()
            > working_level.saturating_sub(target_level)
    {
        return Err(invalid_recurrence(
            "evaluator modulus schedule does not consume the exact selected level budget",
        ));
    }

    let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots_with_data_primes(
        participant_count,
        ballot_count,
        Arc::from(data_primes),
        key_switch_data_primes_per_block,
        Arc::new(
            special_primes
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product(),
        ),
    )?;
    let working_aggregate = aggregate.modulus_switch_to(working_level)?;
    // The direct-ballot relation and compiler place ordered pairwise score
    // differences in the encrypted plaintext. Aggregation is therefore the
    // exact linear preparation step; the public comparison-domain shift is
    // still applied after aggregation by the pairwise recurrence below.
    let packed_ranks = symbolic_pairwise_ballot_rank_evaluation_with_prepared_plaintexts(
        &working_aggregate,
        working_level,
        modulus_schedule,
        prepared_recurrence,
    )?;
    let normalized_rank = packed_ranks
        .modulus_switch_to(working_level)?
        .normalize_scaling()?;
    let rank_powers = symbolic_prepare_polynomial_powers(
        &normalized_rank,
        prepared_recurrence.option_count,
        RANK_LOOKUP_BABY_STEP_COUNT,
        working_level,
        &modulus_schedule.rank_depth_drop_counts,
    )?;

    prepared_recurrence
        .target_projections
        .iter()
        .map(|projection| {
            let (target_identifier, target_order) =
                symbolic_sparse_target_projection_with_prepared_plaintexts(
                    &packed_ranks,
                    &rank_powers,
                    target_level,
                    projection,
                    &prepared_recurrence.identifier_selector,
                    &prepared_recurrence.option_slot_mask,
                )?;
            Ok(DirectBallotTargetNoiseBound {
                top_count: projection.top_count,
                target_identifier,
                target_order,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn direct_ballot_target_noise_bounds_with_prepared_topology_and_early_preparation_drop(
    participant_count: u64,
    ballot_count: usize,
    modulus_schedule: &EvaluatorModulusSchedule,
    data_primes: &[u64],
    key_switch_data_primes_per_block: usize,
    special_primes: &[u64],
    target_level: usize,
    prepared_recurrence: &PreparedDirectBallotTargetNoiseRecurrence,
) -> CanonicalResult<Vec<DirectBallotTargetNoiseBound>> {
    let working_level = data_primes
        .len()
        .checked_sub(1)
        .ok_or_else(|| invalid_recurrence("evaluator data basis is empty"))?;
    if target_level >= working_level
        || key_switch_data_primes_per_block == 0
        || special_primes.is_empty()
        || modulus_schedule.total_drop_count() != working_level.saturating_sub(target_level)
    {
        return Err(invalid_recurrence(
            "early-drop evaluator topology does not consume its exact level budget",
        ));
    }
    let preparation_level = working_level
        .checked_sub(modulus_schedule.pre_comparison_drop_count)
        .ok_or_else(|| invalid_recurrence("evaluator preparation drop exceeds its level"))?;
    let active_schedule = EvaluatorModulusSchedule {
        pre_comparison_drop_count: 0,
        comparison_depth_drop_counts: modulus_schedule.comparison_depth_drop_counts,
        rank_depth_drop_counts: modulus_schedule.rank_depth_drop_counts,
    };
    if active_schedule.total_drop_count() != preparation_level.saturating_sub(target_level) {
        return Err(invalid_recurrence(
            "early-drop evaluator polynomial schedule does not consume its active level budget",
        ));
    }

    let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots_with_data_primes(
        participant_count,
        ballot_count,
        Arc::from(data_primes),
        key_switch_data_primes_per_block,
        Arc::new(
            special_primes
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product(),
        ),
    )?;
    let preparation_aggregate = aggregate
        .modulus_switch_to(working_level)?
        .modulus_switch_to(preparation_level)?;
    let packed_scores = symbolic_pack_direct_score_slots_with_prepared_selector(
        &preparation_aggregate,
        prepared_recurrence.option_count,
        &prepared_recurrence.score_slot_selector,
    )?;
    let packed_ranks = symbolic_packed_rank_evaluation_with_prepared_plaintexts(
        &packed_scores,
        preparation_level,
        &active_schedule,
        prepared_recurrence,
    )?;
    let normalized_rank = packed_ranks
        .modulus_switch_to(preparation_level)?
        .normalize_scaling()?;
    let rank_powers = symbolic_prepare_polynomial_powers(
        &normalized_rank,
        prepared_recurrence.option_count,
        RANK_LOOKUP_BABY_STEP_COUNT,
        preparation_level,
        &active_schedule.rank_depth_drop_counts,
    )?;

    prepared_recurrence
        .target_projections
        .iter()
        .map(|projection| {
            let (target_identifier, target_order) =
                symbolic_sparse_target_projection_with_prepared_plaintexts(
                    &packed_ranks,
                    &rank_powers,
                    target_level,
                    projection,
                    &prepared_recurrence.identifier_selector,
                    &prepared_recurrence.option_slot_mask,
                )?;
            Ok(DirectBallotTargetNoiseBound {
                top_count: projection.top_count,
                target_identifier,
                target_order,
            })
        })
        .collect()
}

fn symbolic_pack_direct_score_slots(
    direct_scores: &SymbolicCiphertextBound,
    option_count: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let option_indices = (0..option_count).collect::<Vec<_>>();
    let score_slot_selector = ExactPlaintextPolynomialNorms::from_coefficients(
        &packed_score_slot_selector(&option_indices)?,
    );
    symbolic_pack_direct_score_slots_with_prepared_selector(
        direct_scores,
        option_count,
        &score_slot_selector,
    )
}

fn symbolic_pack_direct_score_slots_with_prepared_selector(
    direct_scores: &SymbolicCiphertextBound,
    option_count: usize,
    score_slot_selector: &ExactPlaintextPolynomialNorms,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let selected_scores = direct_scores
        .normalize_scaling()?
        .plaintext_multiply_with_norm(&score_slot_selector.l1_norm)?;
    let duplicated_scores = symbolic_rotate_inverse(&selected_scores, option_count)?;

    symbolic_sum_aligned(&[selected_scores, duplicated_scores])
}

fn symbolic_packed_rank_evaluation(
    packed_scores: &SymbolicCiphertextBound,
    option_count: usize,
    score_domain_maximum: u64,
    working_level: usize,
    modulus_schedule: &EvaluatorModulusSchedule,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let comparison =
        symbolic_prepare_packed_rank_comparison(packed_scores, option_count, score_domain_maximum)?;
    let refreshed_comparison_inputs = comparison.comparison_inputs.modulus_switch_to(
        comparison
            .comparison_inputs
            .level
            .checked_sub(modulus_schedule.pre_comparison_drop_count)
            .ok_or_else(|| invalid_recurrence("comparison pre-drop exceeds the active level"))?,
    )?;
    let comparison_outputs = symbolic_evaluate_polynomial(
        &refreshed_comparison_inputs,
        &comparison.greater_or_equal_polynomial,
        comparison.baby_step_count,
        working_level,
        &modulus_schedule.comparison_depth_drop_counts,
    )?;
    let comparison_output_level = working_level
        .checked_sub(modulus_schedule.pre_comparison_drop_count)
        .and_then(|level| level.checked_sub(modulus_schedule.comparison_drop_count()))
        .ok_or_else(|| invalid_recurrence("comparison schedule exceeds the active level"))?;
    if comparison_outputs.level != comparison_output_level {
        return Err(invalid_recurrence(
            "comparison polynomial reached a level inconsistent with its depth schedule",
        ));
    }

    symbolic_finish_packed_rank_evaluation(
        &comparison_outputs,
        option_count,
        comparison_output_level,
        &comparison.pair_windows,
    )
}

fn symbolic_packed_rank_evaluation_with_prepared_plaintexts(
    packed_scores: &SymbolicCiphertextBound,
    working_level: usize,
    modulus_schedule: &EvaluatorModulusSchedule,
    prepared_recurrence: &PreparedDirectBallotTargetNoiseRecurrence,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut comparison_input_sum = None;
    for pair_window in &prepared_recurrence.pair_windows {
        let shifted_scores =
            symbolic_rotate_positive(packed_scores, galois_power(pair_window.shift)?)?;
        let difference = packed_scores.subtract(&shifted_scores)?;
        let shifted_difference = difference.normalize_scaling()?.add_plaintext_with_bounds(
            &prepared_recurrence.comparison_shift_constant.infinity_bound,
            &prepared_recurrence
                .comparison_shift_constant
                .canonical_lift_offset_bound,
        )?;
        let lower_pair_inputs = shifted_difference
            .normalize_scaling()?
            .plaintext_multiply_with_norm(&pair_window.lower_pair_mask.l1_norm)?;
        let windowed_inputs = if pair_window.window_offset == 0 {
            lower_pair_inputs
        } else {
            symbolic_rotate_inverse(&lower_pair_inputs, pair_window.window_offset)?
        };
        symbolic_add_to_aligned_sum(&mut comparison_input_sum, windowed_inputs)?;
    }
    let comparison_inputs = comparison_input_sum.ok_or_else(|| {
        invalid_recurrence("packed-rank recurrence produced no comparison inputs")
    })?;
    let refreshed_comparison_inputs = comparison_inputs.modulus_switch_to(
        comparison_inputs
            .level
            .checked_sub(modulus_schedule.pre_comparison_drop_count)
            .ok_or_else(|| invalid_recurrence("comparison pre-drop exceeds the active level"))?,
    )?;
    let comparison_outputs = symbolic_evaluate_polynomial(
        &refreshed_comparison_inputs,
        &prepared_recurrence.greater_or_equal_polynomial,
        prepared_recurrence.comparison_baby_step_count,
        working_level,
        &modulus_schedule.comparison_depth_drop_counts,
    )?;
    let comparison_output_level = working_level
        .checked_sub(modulus_schedule.pre_comparison_drop_count)
        .and_then(|level| level.checked_sub(modulus_schedule.comparison_drop_count()))
        .ok_or_else(|| invalid_recurrence("comparison schedule exceeds the active level"))?;
    if comparison_outputs.level != comparison_output_level {
        return Err(invalid_recurrence(
            "comparison polynomial reached a level inconsistent with its depth schedule",
        ));
    }

    symbolic_finish_packed_rank_evaluation_with_prepared_plaintexts(
        &comparison_outputs,
        comparison_output_level,
        &prepared_recurrence.pair_windows,
    )
}

fn symbolic_pairwise_ballot_rank_evaluation_with_prepared_plaintexts(
    packed_pairwise_differences: &SymbolicCiphertextBound,
    working_level: usize,
    modulus_schedule: &EvaluatorModulusSchedule,
    prepared_recurrence: &PreparedDirectBallotTargetNoiseRecurrence,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let comparison_inputs = packed_pairwise_differences
        .normalize_scaling()?
        .add_plaintext_with_bounds(
            &prepared_recurrence.pairwise_comparison_shift.infinity_bound,
            &prepared_recurrence
                .pairwise_comparison_shift
                .canonical_lift_offset_bound,
        )?;
    let refreshed_comparison_inputs = comparison_inputs.modulus_switch_to(
        comparison_inputs
            .level
            .checked_sub(modulus_schedule.pre_comparison_drop_count)
            .ok_or_else(|| invalid_recurrence("comparison pre-drop exceeds the active level"))?,
    )?;
    let comparison_outputs = symbolic_evaluate_polynomial(
        &refreshed_comparison_inputs,
        &prepared_recurrence.greater_or_equal_polynomial,
        prepared_recurrence.comparison_baby_step_count,
        working_level,
        &modulus_schedule.comparison_depth_drop_counts,
    )?;
    let comparison_output_level = working_level
        .checked_sub(modulus_schedule.pre_comparison_drop_count)
        .and_then(|level| level.checked_sub(modulus_schedule.comparison_drop_count()))
        .ok_or_else(|| invalid_recurrence("comparison schedule exceeds the active level"))?;
    if comparison_outputs.level != comparison_output_level {
        return Err(invalid_recurrence(
            "comparison polynomial reached a level inconsistent with its depth schedule",
        ));
    }

    symbolic_finish_pairwise_ballot_rank_evaluation_with_prepared_plaintexts(
        &comparison_outputs,
        comparison_output_level,
        &prepared_recurrence.pair_windows,
    )
}

#[derive(Clone, Debug)]
struct SymbolicPackedRankComparison {
    comparison_inputs: SymbolicCiphertextBound,
    greater_or_equal_polynomial: Vec<u64>,
    baby_step_count: usize,
    pair_windows: Vec<(usize, usize, usize)>,
}

fn symbolic_prepare_packed_rank_comparison(
    packed_scores: &SymbolicCiphertextBound,
    option_count: usize,
    score_domain_maximum: u64,
) -> CanonicalResult<SymbolicPackedRankComparison> {
    let pair_count = option_count * option_count.saturating_sub(1) / 2;
    if pair_count > POLYNOMIAL_DEGREE / 2 {
        return Err(invalid_recurrence(
            "packed-rank recurrence exceeds the generator subgroup window",
        ));
    }
    let (_, greater_or_equal_polynomial) = comparison_polynomials(score_domain_maximum)?;
    let shift_constant = broadcast_constant_coefficients(score_domain_maximum);
    let mut comparison_input_sum = None;
    let mut pair_windows = Vec::with_capacity(option_count - 1);
    let mut next_window_offset = 0_usize;

    for shift in 1..option_count {
        let pair_window_size = option_count - shift;
        pair_windows.push((shift, next_window_offset, pair_window_size));
        let shifted_scores = symbolic_rotate_positive(packed_scores, galois_power(shift)?)?;
        let difference = packed_scores.subtract(&shifted_scores)?;
        let shifted_difference = difference
            .normalize_scaling()?
            .add_plaintext_coefficients(&shift_constant)?;
        let lower_pair_inputs = shifted_difference
            .normalize_scaling()?
            .plaintext_multiply(&packed_pair_lower_mask(option_count, shift)?)?;
        let windowed_inputs = if next_window_offset == 0 {
            lower_pair_inputs
        } else {
            symbolic_rotate_inverse(&lower_pair_inputs, next_window_offset)?
        };
        symbolic_add_to_aligned_sum(&mut comparison_input_sum, windowed_inputs)?;
        next_window_offset += pair_window_size;
    }

    let comparison_inputs = comparison_input_sum.ok_or_else(|| {
        invalid_recurrence("packed-rank recurrence produced no comparison inputs")
    })?;
    Ok(SymbolicPackedRankComparison {
        comparison_inputs,
        greater_or_equal_polynomial,
        baby_step_count: direct_comparison_baby_step_count(score_domain_maximum)?,
        pair_windows,
    })
}

fn symbolic_finish_packed_rank_evaluation(
    comparison_outputs: &SymbolicCiphertextBound,
    option_count: usize,
    comparison_output_level: usize,
    pair_windows: &[(usize, usize, usize)],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut rank_sum = None;
    for &(shift, window_offset, pair_window_size) in pair_windows {
        let window_logical_indices =
            (window_offset..(window_offset + pair_window_size)).collect::<Vec<_>>();
        let windowed_lower_beats_higher = comparison_outputs
            .normalize_scaling()?
            .plaintext_multiply(&packed_score_slot_selector(&window_logical_indices)?)?;
        let lower_beats_higher = if window_offset == 0 {
            windowed_lower_beats_higher
        } else {
            symbolic_rotate_positive(&windowed_lower_beats_higher, galois_power(window_offset)?)?
        };
        let lower_pair_mask = packed_pair_lower_mask(option_count, shift)?;
        let lower_beats_higher_for_lower_slots = lower_beats_higher
            .normalize_scaling()?
            .plaintext_multiply(&lower_pair_mask)?;
        let higher_beats_lower_for_lower_slots = lower_beats_higher_for_lower_slots
            .normalize_scaling()?
            .negate()
            .add_plaintext_coefficients(&lower_pair_mask)?;
        let lower_beats_higher_for_return =
            lower_beats_higher_for_lower_slots.modulus_switch_to(comparison_output_level)?;
        let lower_beats_higher_at_higher_slot =
            symbolic_rotate_inverse(&lower_beats_higher_for_return, shift)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }

    rank_sum.ok_or_else(|| invalid_recurrence("packed-rank recurrence produced no rank terms"))
}

fn symbolic_finish_packed_rank_evaluation_with_prepared_plaintexts(
    comparison_outputs: &SymbolicCiphertextBound,
    comparison_output_level: usize,
    pair_windows: &[PreparedPackedRankPairWindow],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut rank_sum = None;
    for pair_window in pair_windows {
        let windowed_lower_beats_higher = comparison_outputs
            .normalize_scaling()?
            .plaintext_multiply_with_norm(&pair_window.window_selector.l1_norm)?;
        let lower_beats_higher = if pair_window.window_offset == 0 {
            windowed_lower_beats_higher
        } else {
            symbolic_rotate_positive(
                &windowed_lower_beats_higher,
                galois_power(pair_window.window_offset)?,
            )?
        };
        let lower_beats_higher_for_lower_slots = lower_beats_higher
            .normalize_scaling()?
            .plaintext_multiply_with_norm(&pair_window.lower_pair_mask.l1_norm)?;
        let higher_beats_lower_for_lower_slots = lower_beats_higher_for_lower_slots
            .normalize_scaling()?
            .negate()
            .add_plaintext_with_bounds(
                &pair_window.lower_pair_mask.infinity_bound,
                &pair_window.lower_pair_mask.canonical_lift_offset_bound,
            )?;
        let lower_beats_higher_for_return =
            lower_beats_higher_for_lower_slots.modulus_switch_to(comparison_output_level)?;
        let lower_beats_higher_at_higher_slot =
            symbolic_rotate_inverse(&lower_beats_higher_for_return, pair_window.shift)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }

    rank_sum.ok_or_else(|| invalid_recurrence("packed-rank recurrence produced no rank terms"))
}

fn pairwise_ballot_forward_rotation_hop_count(shift: usize) -> CanonicalResult<usize> {
    if shift >= POLYNOMIAL_DEGREE / 2 {
        return Err(invalid_recurrence(
            "pairwise-ballot forward rotation exceeds the generator subgroup",
        ));
    }
    if shift == 0 {
        return Ok(0);
    }

    // The selected directed basis contains +38, -7, and -1. Every positive
    // pair-window offset first advances by the minimum number of +38 hops and
    // then removes the exact overshoot with -7 and -1. This is the canonical
    // path used by the concrete evaluator compiler and its suite-fixed keys.
    let positive_thirty_eight_hops = shift.div_ceil(38);
    let overshoot = positive_thirty_eight_hops
        .checked_mul(38)
        .and_then(|advanced| advanced.checked_sub(shift))
        .ok_or_else(|| invalid_recurrence("pairwise-ballot forward rotation overflowed"))?;
    Ok(positive_thirty_eight_hops + overshoot / 7 + overshoot % 7)
}

fn pairwise_ballot_inverse_rotation_hop_count(shift: usize) -> CanonicalResult<usize> {
    if shift >= POLYNOMIAL_DEGREE / 2 {
        return Err(invalid_recurrence(
            "pairwise-ballot inverse rotation exceeds the generator subgroup",
        ));
    }
    Ok(shift / 7 + shift % 7)
}

fn symbolic_rotate_pairwise_ballot_forward(
    ciphertext: &SymbolicCiphertextBound,
    shift: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut rotated = ciphertext.clone();
    for _ in 0..pairwise_ballot_forward_rotation_hop_count(shift)? {
        rotated = rotated.rotate_once()?;
    }
    Ok(rotated)
}

fn symbolic_rotate_pairwise_ballot_inverse(
    ciphertext: &SymbolicCiphertextBound,
    shift: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut rotated = ciphertext.clone();
    for _ in 0..pairwise_ballot_inverse_rotation_hop_count(shift)? {
        rotated = rotated.rotate_once()?;
    }
    Ok(rotated)
}

fn symbolic_finish_pairwise_ballot_rank_evaluation(
    comparison_outputs: &SymbolicCiphertextBound,
    option_count: usize,
    comparison_output_level: usize,
    pair_windows: &[(usize, usize, usize)],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut rank_sum = None;
    for &(shift, window_offset, pair_window_size) in pair_windows {
        let window_logical_indices =
            (window_offset..(window_offset + pair_window_size)).collect::<Vec<_>>();
        let windowed_lower_beats_higher = comparison_outputs
            .normalize_scaling()?
            .plaintext_multiply(&packed_score_slot_selector(&window_logical_indices)?)?;
        let lower_beats_higher =
            symbolic_rotate_pairwise_ballot_forward(&windowed_lower_beats_higher, window_offset)?;
        let lower_pair_mask = packed_pair_lower_mask(option_count, shift)?;
        let lower_beats_higher_for_lower_slots = lower_beats_higher.normalize_scaling()?;
        let higher_beats_lower_for_lower_slots = lower_beats_higher_for_lower_slots
            .normalize_scaling()?
            .negate()
            .add_plaintext_coefficients(&lower_pair_mask)?;
        let lower_beats_higher_for_return =
            lower_beats_higher_for_lower_slots.modulus_switch_to(comparison_output_level)?;
        let lower_beats_higher_at_higher_slot =
            symbolic_rotate_pairwise_ballot_inverse(&lower_beats_higher_for_return, shift)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }

    rank_sum.ok_or_else(|| invalid_recurrence("pairwise-ballot recurrence produced no rank terms"))
}

fn symbolic_finish_pairwise_ballot_rank_evaluation_with_prepared_plaintexts(
    comparison_outputs: &SymbolicCiphertextBound,
    comparison_output_level: usize,
    pair_windows: &[PreparedPackedRankPairWindow],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut rank_sum = None;
    for pair_window in pair_windows {
        let windowed_lower_beats_higher = comparison_outputs
            .normalize_scaling()?
            .plaintext_multiply_with_norm(&pair_window.window_selector.l1_norm)?;
        let lower_beats_higher = symbolic_rotate_pairwise_ballot_forward(
            &windowed_lower_beats_higher,
            pair_window.window_offset,
        )?;
        let lower_beats_higher_for_lower_slots = lower_beats_higher.normalize_scaling()?;
        let higher_beats_lower_for_lower_slots = lower_beats_higher_for_lower_slots
            .normalize_scaling()?
            .negate()
            .add_plaintext_with_bounds(
                &pair_window.lower_pair_mask.infinity_bound,
                &pair_window.lower_pair_mask.canonical_lift_offset_bound,
            )?;
        let lower_beats_higher_for_return =
            lower_beats_higher_for_lower_slots.modulus_switch_to(comparison_output_level)?;
        let lower_beats_higher_at_higher_slot = symbolic_rotate_pairwise_ballot_inverse(
            &lower_beats_higher_for_return,
            pair_window.shift,
        )?;
        symbolic_add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }

    rank_sum.ok_or_else(|| invalid_recurrence("pairwise-ballot recurrence produced no rank terms"))
}

fn symbolic_sparse_target_projection(
    packed_ranks: &SymbolicCiphertextBound,
    option_count: usize,
    top_count: usize,
    rank_powers: &SymbolicPolynomialPowers,
    target_level: usize,
) -> CanonicalResult<(SymbolicCiphertextBound, SymbolicCiphertextBound)> {
    let id_weights = (0..option_count)
        .map(|option| {
            (
                option,
                u64::try_from(option + 1).expect("option identifier fits u64"),
            )
        })
        .collect::<Vec<_>>();
    let option_indices = (0..option_count).collect::<Vec<_>>();
    let id_selector = packed_score_weighted_selector(&id_weights)?;
    let option_slot_mask = packed_score_slot_selector(&option_indices)?;

    if top_count == option_count {
        let normalized_ranks = packed_ranks.normalize_scaling()?;
        let encrypted_zero = normalized_ranks.scalar_multiply(0)?;
        let target_identifier = encrypted_zero.add_plaintext_coefficients(&id_selector)?;
        let target_order = normalized_ranks.add_plaintext_coefficients(&option_slot_mask)?;
        return Ok((
            target_identifier.modulus_switch_to(target_level)?,
            target_order.modulus_switch_to(target_level)?,
        ));
    }

    let indicator_values = (0..option_count)
        .map(|rank_value| u64::from(rank_value < top_count))
        .collect::<Vec<_>>();
    let order_values = (0..option_count)
        .map(|rank_value| {
            if rank_value < top_count {
                u64::try_from(rank_value + 1).expect("rank value fits u64")
            } else {
                0
            }
        })
        .collect::<Vec<_>>();
    let indicator = symbolic_rank_lookup(rank_powers, &indicator_values)?;
    let order_value = symbolic_rank_lookup(rank_powers, &order_values)?;

    let target_identifier = indicator
        .normalize_scaling()?
        .plaintext_multiply(&id_selector)?;
    let target_order = order_value
        .normalize_scaling()?
        .plaintext_multiply(&option_slot_mask)?;

    Ok((
        target_identifier.modulus_switch_to(target_level)?,
        target_order.modulus_switch_to(target_level)?,
    ))
}

fn symbolic_sparse_target_projection_with_prepared_plaintexts(
    packed_ranks: &SymbolicCiphertextBound,
    rank_powers: &SymbolicPolynomialPowers,
    target_level: usize,
    projection: &PreparedTargetProjection,
    identifier_selector: &ExactPlaintextPolynomialNorms,
    option_slot_mask: &ExactPlaintextPolynomialNorms,
) -> CanonicalResult<(SymbolicCiphertextBound, SymbolicCiphertextBound)> {
    match &projection.kind {
        PreparedTargetProjectionKind::CompleteList => {
            let normalized_ranks = packed_ranks.normalize_scaling()?;
            let encrypted_zero = normalized_ranks.scalar_multiply(0)?;
            let target_identifier = encrypted_zero.add_plaintext_with_bounds(
                &identifier_selector.infinity_bound,
                &identifier_selector.canonical_lift_offset_bound,
            )?;
            let target_order = normalized_ranks.add_plaintext_with_bounds(
                &option_slot_mask.infinity_bound,
                &option_slot_mask.canonical_lift_offset_bound,
            )?;
            Ok((
                target_identifier.modulus_switch_to(target_level)?,
                target_order.modulus_switch_to(target_level)?,
            ))
        }
        PreparedTargetProjectionKind::RankLookup {
            indicator_polynomial,
            order_polynomial,
        } => {
            let indicator = symbolic_evaluate_polynomial_from_prepared_powers(
                rank_powers,
                indicator_polynomial,
            )?;
            let order_value =
                symbolic_evaluate_polynomial_from_prepared_powers(rank_powers, order_polynomial)?;
            let target_identifier = indicator
                .normalize_scaling()?
                .plaintext_multiply_with_norm(&identifier_selector.l1_norm)?;
            let target_order = order_value
                .normalize_scaling()?
                .plaintext_multiply_with_norm(&option_slot_mask.l1_norm)?;
            Ok((
                target_identifier.modulus_switch_to(target_level)?,
                target_order.modulus_switch_to(target_level)?,
            ))
        }
    }
}

fn symbolic_rank_lookup(
    prepared_powers: &SymbolicPolynomialPowers,
    values: &[u64],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let polynomial = interpolate_coefficients(values)?;
    symbolic_evaluate_polynomial_from_prepared_powers(prepared_powers, &polynomial)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolicPowerBound {
    ciphertext_bound: SymbolicCiphertextBound,
    multiplication_depth: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SymbolicPolynomialPowers {
    working_input: SymbolicCiphertextBound,
    baby_step_count: usize,
    block_count: usize,
    baby_powers: Vec<Option<SymbolicPowerBound>>,
    giant_powers: Vec<Option<SymbolicPowerBound>>,
}

fn symbolic_scheduled_power_product(
    left: &SymbolicPowerBound,
    right: &SymbolicPowerBound,
    depth_drop_counts: &[usize],
) -> CanonicalResult<SymbolicPowerBound> {
    let multiplication_depth = left
        .multiplication_depth
        .max(right.multiplication_depth)
        .checked_add(1)
        .ok_or_else(|| invalid_recurrence("symbolic multiplication depth overflowed"))?;
    let drop_count = *depth_drop_counts
        .get(multiplication_depth - 1)
        .ok_or_else(|| invalid_recurrence("symbolic multiplication exceeded its depth schedule"))?;
    Ok(SymbolicPowerBound {
        ciphertext_bound: left
            .ciphertext_bound
            .multiply_and_switch_by(&right.ciphertext_bound, drop_count)?,
        multiplication_depth,
    })
}

fn symbolic_evaluate_polynomial(
    input: &SymbolicCiphertextBound,
    coefficients: &[u64],
    baby_step_count: usize,
    working_level: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<SymbolicCiphertextBound> {
    if coefficients.is_empty() || baby_step_count < 2 {
        return Err(invalid_recurrence(
            "symbolic polynomial evaluation requires coefficients and at least two baby steps",
        ));
    }
    let degree = coefficients.len() - 1;
    if degree == 0 || degree < baby_step_count {
        return symbolic_evaluate_polynomial_by_power_table(
            input,
            coefficients,
            working_level,
            depth_drop_counts,
        );
    }

    let prepared_powers = symbolic_prepare_polynomial_powers(
        input,
        coefficients.len(),
        baby_step_count,
        working_level,
        depth_drop_counts,
    )?;
    symbolic_evaluate_polynomial_from_prepared_powers(&prepared_powers, coefficients)
}

fn symbolic_prepare_polynomial_powers(
    input: &SymbolicCiphertextBound,
    coefficient_count: usize,
    baby_step_count: usize,
    working_level: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<SymbolicPolynomialPowers> {
    if coefficient_count <= baby_step_count || baby_step_count < 2 {
        return Err(invalid_recurrence(
            "prepared symbolic powers require a nontrivial Paterson-Stockmeyer polynomial",
        ));
    }
    let block_count = coefficient_count.div_ceil(baby_step_count);
    let working_input = input.modulus_switch_to(working_level)?;
    let baby_powers = symbolic_build_power_table(
        SymbolicPowerBound {
            ciphertext_bound: working_input.clone(),
            multiplication_depth: 0,
        },
        baby_step_count,
        depth_drop_counts,
    )?;
    let giant_base = baby_powers[baby_step_count]
        .as_ref()
        .ok_or_else(|| invalid_recurrence("symbolic baby power is missing"))?
        .clone();
    let giant_powers =
        symbolic_build_power_table(giant_base, block_count.saturating_sub(1), depth_drop_counts)?;
    Ok(SymbolicPolynomialPowers {
        working_input,
        baby_step_count,
        block_count,
        baby_powers,
        giant_powers,
    })
}

fn symbolic_evaluate_polynomial_from_prepared_powers(
    prepared_powers: &SymbolicPolynomialPowers,
    coefficients: &[u64],
) -> CanonicalResult<SymbolicCiphertextBound> {
    if coefficients.len().div_ceil(prepared_powers.baby_step_count) != prepared_powers.block_count {
        return Err(invalid_recurrence(
            "symbolic polynomial does not match its prepared power geometry",
        ));
    }
    let mut terms = Vec::new();

    for (block_index, giant_power) in prepared_powers
        .giant_powers
        .iter()
        .enumerate()
        .take(prepared_powers.block_count)
    {
        let start = block_index * prepared_powers.baby_step_count;
        let end = coefficients
            .len()
            .min(start + prepared_powers.baby_step_count);
        let block_coefficients = &coefficients[start..end];
        if block_coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            continue;
        }
        let block_value = symbolic_linear_combination_from_powers(
            &prepared_powers.working_input,
            &prepared_powers.baby_powers,
            block_coefficients,
        )?;
        if block_index == 0 {
            terms.push(block_value);
            continue;
        }
        let giant_power = giant_power
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic giant power is missing"))?;
        if block_coefficients[1..]
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            terms.push(giant_power.ciphertext_bound.scalar_multiply(
                i64::try_from(block_coefficients[0]).expect("plaintext coefficient fits i64"),
            )?);
        } else {
            terms
                .push(block_value.multiply_without_terminal_switch(&giant_power.ciphertext_bound)?);
        }
    }

    if terms.is_empty() {
        return prepared_powers.working_input.scalar_multiply(0);
    }
    symbolic_sum_aligned(&terms)
}

fn symbolic_evaluate_polynomial_by_power_table(
    input: &SymbolicCiphertextBound,
    coefficients: &[u64],
    working_level: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let degree = coefficients.len() - 1;
    let working_input = input.modulus_switch_to(working_level)?;
    let mut powers: Vec<Option<SymbolicPowerBound>> = vec![None; degree + 1];
    if degree >= 1 {
        powers[1] = Some(SymbolicPowerBound {
            ciphertext_bound: working_input.clone(),
            multiplication_depth: 0,
        });
    }
    for power in 2..=degree {
        let low = power / 2;
        let high = power - low;
        let low_power = powers[low]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic low power is missing"))?;
        let high_power = powers[high]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic high power is missing"))?;
        powers[power] = Some(symbolic_scheduled_power_product(
            low_power,
            high_power,
            depth_drop_counts,
        )?);
    }
    symbolic_linear_combination_from_powers(&working_input, &powers, coefficients)
}

fn symbolic_build_power_table(
    base: SymbolicPowerBound,
    highest_power: usize,
    depth_drop_counts: &[usize],
) -> CanonicalResult<Vec<Option<SymbolicPowerBound>>> {
    let base_multiplication_depth = base.multiplication_depth;
    let mut powers = vec![None; highest_power + 1];
    if highest_power >= 1 {
        powers[1] = Some(base);
    }
    for product in scheduled_power_table_products(highest_power, base_multiplication_depth)? {
        let low_power = powers[product.lower_power]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic low power is missing"))?;
        let high_power = powers[product.upper_power]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic high power is missing"))?;
        powers[product.output_power] = Some(symbolic_scheduled_power_product(
            low_power,
            high_power,
            depth_drop_counts,
        )?);
    }

    Ok(powers)
}

fn symbolic_linear_combination_from_powers(
    reference: &SymbolicCiphertextBound,
    powers: &[Option<SymbolicPowerBound>],
    coefficients: &[u64],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let target_level = coefficients
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, coefficient)| **coefficient != 0)
        .filter_map(|(power, _)| {
            powers[power]
                .as_ref()
                .map(|power_bound| power_bound.ciphertext_bound.level)
        })
        .min();
    let anchor_level = target_level.unwrap_or(reference.level);
    let anchor = reference
        .modulus_switch_to(anchor_level)?
        .normalize_scaling()?;
    let mut result = anchor
        .scalar_multiply(0)?
        .add_plaintext_coefficients(&broadcast_constant_coefficients(coefficients[0]))?;
    for power in 1..coefficients.len() {
        if coefficients[power] == 0 {
            continue;
        }
        let power_bound = powers[power]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic polynomial power is missing"))?;
        let leveled = power_bound
            .ciphertext_bound
            .modulus_switch_to(anchor_level)?
            .normalize_scaling()?;
        let scaled = leveled.scalar_multiply(
            i64::try_from(coefficients[power]).expect("plaintext coefficient fits i64"),
        )?;
        result = result.add(&scaled)?;
    }

    Ok(result)
}

fn symbolic_sum_aligned(
    ciphertexts: &[SymbolicCiphertextBound],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let target_level = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.level)
        .min()
        .ok_or_else(|| invalid_recurrence("cannot sum an empty symbolic ciphertext set"))?;
    let mut accumulator = ciphertexts[0]
        .modulus_switch_to(target_level)?
        .normalize_scaling()?;
    for ciphertext in &ciphertexts[1..] {
        let aligned = ciphertext
            .modulus_switch_to(target_level)?
            .normalize_scaling()?;
        accumulator = accumulator.add(&aligned)?;
    }

    Ok(accumulator)
}

fn symbolic_add_to_aligned_sum(
    accumulator: &mut Option<SymbolicCiphertextBound>,
    term: SymbolicCiphertextBound,
) -> CanonicalResult<()> {
    *accumulator = Some(match accumulator.take() {
        Some(current) => symbolic_sum_aligned(&[current, term])?,
        None => term,
    });
    Ok(())
}

fn symbolic_rotate_positive(
    ciphertext: &SymbolicCiphertextBound,
    galois_element: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    if galois_element == 1 {
        return Ok(ciphertext.clone());
    }
    let (requires_conjugation, exponent) = generator_exponent_or_conjugated(galois_element)?;
    let mut rotated = ciphertext.clone();
    if requires_conjugation {
        rotated = rotated.rotate_once()?;
    }
    for _ in generator_power_basis_for_exponent(exponent)? {
        rotated = rotated.rotate_once()?;
    }

    Ok(rotated)
}

fn symbolic_rotate_inverse(
    ciphertext: &SymbolicCiphertextBound,
    shift: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let mut rotated = ciphertext.clone();
    for _ in generator_inverse_power_basis_for_exponent(shift)? {
        rotated = rotated.rotate_once()?;
    }

    Ok(rotated)
}

#[cfg(test)]
mod stochastic_rounding;

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{BTreeMap, BTreeSet},
        fs::{self, OpenOptions},
        io::Write,
        path::{Path, PathBuf},
        sync::{
            Arc, Barrier, Condvar, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
    };

    use num_bigint::{BigInt, BigUint};
    use num_traits::{One, Signed, Zero};
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};

    use super::{
        CANONICAL_TARGET_CIPHERTEXT_LEVEL, DirectBallotTargetNoiseBound, EvaluationKeyErrorKind,
        PreparedDirectBallotTargetNoiseRecurrence, SymbolicCiphertextBound,
        SymbolicPackedRankComparison, SymbolicPolynomialPowers, SymbolicPowerBound,
        collective_evaluation_key_error_bound, direct_ballot_target_noise_bounds,
        direct_ballot_target_noise_bounds_with_prepared_topology,
        direct_ballot_target_noise_bounds_with_prepared_topology_and_early_preparation_drop,
        direct_ballot_target_noise_bounds_with_schedule_and_data_primes,
        direct_comparison_baby_step_count, hybrid_key_switch_decomposed_error_bound,
        symbolic_evaluate_polynomial_from_prepared_powers, symbolic_finish_packed_rank_evaluation,
        symbolic_pack_direct_score_slots, symbolic_packed_rank_evaluation,
        symbolic_prepare_packed_rank_comparison, symbolic_prepare_polynomial_powers,
        symbolic_sparse_target_projection,
    };
    use crate::bgv::{
        evaluator::program::{
            compile_candidate_evaluator_program_measurement,
            compiled_prepared_power_instruction_count, compiled_prepared_power_level_trace,
        },
        evaluator::top_k::{
            COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT, EvaluatorModulusSchedule,
            RANK_LOOKUP_BABY_STEP_COUNT, RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
            SELECTED_EVALUATOR_MODULUS_SCHEDULE, SELECTED_EVALUATOR_WORKING_LEVEL,
            ScheduledMultiplicationLevelTrace, comparison_polynomials,
            prepared_polynomial_power_level_trace, scheduled_power_table_products,
        },
        key_switch_topology::{
            canonical_residue_byte_length, validate_key_switch_special_basis_dominates_data_blocks,
        },
        parameters::{
            DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, SPECIAL_PRIMES,
            root_parameters_for_modulus,
        },
        target_decryption::kllps_release::{
            ensure_factor_four_parameter_conditions,
            ensure_factor_four_parameter_conditions_with_data_primes,
            factor_four_required_flooding_bound,
        },
    };
    use crate::foundation::FOUNDATION_PROFILE;

    #[derive(Debug)]
    struct ScheduleMeasurement {
        schedule: EvaluatorModulusSchedule,
        maximum_error_bound: BigUint,
        minimum_margin: BigInt,
        factor_four_c2_margin: BigInt,
        factor_four_conditions_hold: bool,
    }

    fn measure_schedule(
        schedule: EvaluatorModulusSchedule,
    ) -> crate::encoding::CanonicalResult<ScheduleMeasurement> {
        measure_schedule_with_data_primes(schedule, &DATA_PRIMES)
    }

    fn measure_schedule_with_data_primes(
        schedule: EvaluatorModulusSchedule,
        data_primes: &[u64],
    ) -> crate::encoding::CanonicalResult<ScheduleMeasurement> {
        let bounds = direct_ballot_target_noise_bounds_with_schedule_and_data_primes(
            10,
            10,
            20,
            1,
            10,
            &schedule,
            data_primes,
        )?;
        let maximum_error_bound = bounds
            .iter()
            .map(|bound| bound.maximum_error_coefficient_bound())
            .max()
            .cloned()
            .expect("selected evaluator has target bounds");
        let minimum_margin = bounds
            .iter()
            .flat_map(|bound| {
                [
                    bound.target_identifier.minimum_decryption_margin.clone(),
                    bound.target_order.minimum_decryption_margin.clone(),
                    bound.target_identifier.final_decryption_margin(),
                    bound.target_order.final_decryption_margin(),
                ]
            })
            .min()
            .expect("selected evaluator has decryption margins");
        let factor_four_conditions_hold = factor_four_required_flooding_bound(&maximum_error_bound)
            .and_then(|flooding_bound| {
                ensure_factor_four_parameter_conditions(
                    CANONICAL_TARGET_CIPHERTEXT_LEVEL,
                    &maximum_error_bound,
                    &flooding_bound,
                )
            })
            .is_ok();
        let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)?;
        let target_modulus = data_primes[..=CANONICAL_TARGET_CIPHERTEXT_LEVEL]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let plaintext_modulus = BigUint::from(crate::bgv::parameters::PLAINTEXT_MODULUS);
        let scaled_c2_left = &plaintext_modulus
            * ((&maximum_error_bound << 4_usize)
                + &plaintext_modulus * BigUint::from(5_u8)
                + &flooding_bound * BigUint::from(16_u64 * 44));
        let factor_four_c2_margin =
            BigInt::from(target_modulus << 1_usize) - BigInt::from(scaled_c2_left);
        Ok(ScheduleMeasurement {
            schedule,
            maximum_error_bound,
            minimum_margin,
            factor_four_c2_margin,
            factor_four_conditions_hold,
        })
    }

    const JOINT_SEARCH_MINIMUM_TARGET_LEVEL: usize = CANONICAL_TARGET_CIPHERTEXT_LEVEL;
    const JOINT_SEARCH_MAXIMUM_TARGET_LEVEL: usize = 10;
    const JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT: usize = JOINT_SEARCH_MINIMUM_TARGET_LEVEL + 2;
    const MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH: u64 = u32::MAX as u64 - 4;
    const PROSPECTIVE_DATA_TAIL_PRIMES: [u64; 2] = [23_811_328_966_657, 22_265_138_774_017];
    const TARGET_HEAVY_BLOCK_BALANCED_DATA_PRIMES: [u64; DATA_PRIMES.len()] = [
        16_676_279_703_699_457,
        16_675_970_465_660_929,
        16_675_867_386_314_753,
        16_674_630_434_160_641,
        16_674_115_037_429_761,
        16_673_187_323_314_177,
        618_476_077_057,
        9_586_379_194_369,
        25_975_995_236_353,
        27_109_868_044_289,
        16_653_602_247_540_737,
        16_655_766_913_810_433,
        16_657_106_945_310_721,
        16_657_725_421_387_777,
        7_318_633_578_497,
        8_040_189_001_729,
        8_349_427_040_257,
        16_659_787_008_311_297,
        16_660_714_722_426_881,
        16_661_333_198_503_937,
        16_663_807_102_812_161,
        3_401_618_423_809,
        16_665_662_531_043_329,
        16_667_930_276_659_201,
        16_671_331_895_083_009,
        16_672_259_609_198_593,
    ];
    const THREE_PRE_COMPARISON_DROP_CANDIDATE_DATA_PRIMES: [u64; DATA_PRIMES.len()] = [
        72_056_792_309_563_393,
        72_055_246_119_370_753,
        72_054_318_405_255_169,
        278_520_393_367_553,
        276_458_806_444_033,
        275_737_251_020_801,
        16_676_279_703_699_457,
        16_663_807_102_812_161,
        16_675_867_386_314_753,
        16_674_630_434_160_641,
        16_674_115_037_429_761,
        16_673_187_323_314_177,
        16_672_259_609_198_593,
        16_671_331_895_083_009,
        16_667_930_276_659_201,
        16_675_970_465_660_929,
        3_401_618_423_809,
        16_661_333_198_503_937,
        16_660_714_722_426_881,
        16_659_787_008_311_297,
        16_657_725_421_387_777,
        16_657_106_945_310_721,
        16_655_766_913_810_433,
        16_653_602_247_540_737,
        27_109_868_044_289,
        618_476_077_057,
    ];
    const EARLY_PREPARATION_DROP_BLOCK_BALANCED_DATA_PRIMES: [u64; DATA_PRIMES.len()] = [
        72_056_792_309_563_393,
        72_055_246_119_370_753,
        72_054_318_405_255_169,
        278_520_393_367_553,
        276_458_806_444_033,
        275_737_251_020_801,
        16_671_331_895_083_009,
        16_672_259_609_198_593,
        16_673_187_323_314_177,
        16_674_115_037_429_761,
        16_674_630_434_160_641,
        618_476_077_057,
        16_659_787_008_311_297,
        16_660_714_722_426_881,
        16_661_333_198_503_937,
        16_663_807_102_812_161,
        16_667_930_276_659_201,
        3_401_618_423_809,
        16_653_602_247_540_737,
        16_655_766_913_810_433,
        16_657_106_945_310_721,
        16_657_725_421_387_777,
        27_109_868_044_289,
        16_675_867_386_314_753,
        16_675_970_465_660_929,
        16_676_279_703_699_457,
    ];
    const JOINT_SEARCH_VARIABLE_COUNT: usize = 1
        + COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT
        + RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT;

    fn prospective_data_prime_order_candidates() -> [PrimeOrderCandidate; 3] {
        let mut current = DATA_PRIMES.to_vec();
        current.extend(PROSPECTIVE_DATA_TAIL_PRIMES);
        let mut largest_drop_first = current.clone();
        largest_drop_first[CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1..].sort_unstable();
        let mut smallest_drop_first = current.clone();
        smallest_drop_first[CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1..]
            .sort_unstable_by(|left, right| right.cmp(left));
        [
            PrimeOrderCandidate {
                label: "prospective-current",
                data_primes: current,
            },
            PrimeOrderCandidate {
                label: "prospective-largest-drop-first",
                data_primes: largest_drop_first,
            },
            PrimeOrderCandidate {
                label: "prospective-smallest-drop-first",
                data_primes: smallest_drop_first,
            },
        ]
    }

    fn target_heavy_block_balanced_prime_order() -> PrimeOrderCandidate {
        PrimeOrderCandidate {
            label: "target-heavy-block-balanced",
            data_primes: TARGET_HEAVY_BLOCK_BALANCED_DATA_PRIMES.to_vec(),
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PowerDagSearchState {
        prepared_powers: SymbolicPolynomialPowers,
        packed_ranks: Option<SymbolicCiphertextBound>,
        working_level: usize,
        pre_comparison_drop_count: usize,
        comparison_depth_drop_counts: [usize; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
        rank_depth_drop_counts: [usize; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
        assigned_variable_count: usize,
        consumed_drop_count: usize,
        evaluator_instruction_count: u64,
        active_data_limb_instruction_units: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct AlignedPowerDominanceKey {
        multiplication_depth: usize,
        ciphertext_bound: SymbolicCiphertextBound,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PowerDagSearchStateDominanceKey {
        working_level: usize,
        pre_comparison_drop_count: usize,
        assigned_variable_count: usize,
        consumed_drop_count: usize,
        evaluator_instruction_count: u64,
        active_data_limb_instruction_units: u64,
        working_input: SymbolicCiphertextBound,
        packed_ranks: Option<SymbolicCiphertextBound>,
        baby_powers: Vec<Option<AlignedPowerDominanceKey>>,
        giant_powers: Vec<Option<AlignedPowerDominanceKey>>,
    }

    impl PowerDagSearchStateDominanceKey {
        fn from_state(state: &PowerDagSearchState) -> crate::encoding::CanonicalResult<Self> {
            let comparison_level = state
                .working_level
                .checked_sub(state.consumed_drop_count)
                .ok_or_else(|| {
                    super::invalid_recurrence("search state consumed too many levels")
                })?;
            Ok(Self {
                working_level: state.working_level,
                pre_comparison_drop_count: state.pre_comparison_drop_count,
                assigned_variable_count: state.assigned_variable_count,
                consumed_drop_count: state.consumed_drop_count,
                evaluator_instruction_count: state.evaluator_instruction_count,
                active_data_limb_instruction_units: state.active_data_limb_instruction_units,
                working_input: state
                    .prepared_powers
                    .working_input
                    .modulus_switch_to(comparison_level)?,
                packed_ranks: state
                    .packed_ranks
                    .as_ref()
                    .map(|bound| bound.modulus_switch_to(comparison_level))
                    .transpose()?,
                baby_powers: state
                    .prepared_powers
                    .baby_powers
                    .iter()
                    .map(|power| aligned_power_dominance_key(power, comparison_level))
                    .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?,
                giant_powers: state
                    .prepared_powers
                    .giant_powers
                    .iter()
                    .map(|power| aligned_power_dominance_key(power, comparison_level))
                    .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?,
            })
        }

        fn dominates(&self, other: &Self) -> bool {
            self.working_level == other.working_level
                // At a fixed consumed-drop count, the future recurrence reads
                // only the aligned ciphertext and power bounds below. A larger
                // pre-comparison drop also leaves a no-larger relinearization
                // basis at final measurement, so it is safe to dominate a
                // smaller pre-comparison drop when every operative bound and
                // work measure is no worse.
                && self.pre_comparison_drop_count >= other.pre_comparison_drop_count
                && self.assigned_variable_count == other.assigned_variable_count
                && self.consumed_drop_count == other.consumed_drop_count
                && self.evaluator_instruction_count <= other.evaluator_instruction_count
                && self.active_data_limb_instruction_units
                    <= other.active_data_limb_instruction_units
                && aligned_bound_dominates(&self.working_input, &other.working_input)
                && optional_aligned_bound_dominates(
                    self.packed_ranks.as_ref(),
                    other.packed_ranks.as_ref(),
                )
                && aligned_power_keys_dominate(&self.baby_powers, &other.baby_powers)
                && aligned_power_keys_dominate(&self.giant_powers, &other.giant_powers)
        }

        fn lower_existing_bounds_once(&mut self) -> crate::encoding::CanonicalResult<()> {
            self.working_input = self.working_input.modulus_switch()?;
            if let Some(packed_ranks) = self.packed_ranks.as_mut() {
                *packed_ranks = packed_ranks.modulus_switch()?;
            }
            for power_key in self
                .baby_powers
                .iter_mut()
                .chain(&mut self.giant_powers)
                .filter_map(Option::as_mut)
            {
                power_key.ciphertext_bound = power_key.ciphertext_bound.modulus_switch()?;
            }
            Ok(())
        }

        fn finish_transition_to_state(
            &mut self,
            state: &PowerDagSearchState,
        ) -> crate::encoding::CanonicalResult<()> {
            let comparison_level = state
                .working_level
                .checked_sub(state.consumed_drop_count)
                .ok_or_else(|| {
                    super::invalid_recurrence("search state consumed too many levels")
                })?;
            if self.working_input.level != comparison_level {
                return Err(super::invalid_recurrence(
                    "search dominance key is not aligned to the transitioned level",
                ));
            }
            self.pre_comparison_drop_count = state.pre_comparison_drop_count;
            self.working_level = state.working_level;
            self.assigned_variable_count = state.assigned_variable_count;
            self.consumed_drop_count = state.consumed_drop_count;
            self.evaluator_instruction_count = state.evaluator_instruction_count;
            self.active_data_limb_instruction_units = state.active_data_limb_instruction_units;
            require_optional_aligned_bound_shape(
                self.packed_ranks.as_ref(),
                state.packed_ranks.as_ref(),
                comparison_level,
            )?;
            finish_aligned_power_keys(
                &mut self.baby_powers,
                &state.prepared_powers.baby_powers,
                comparison_level,
            )?;
            finish_aligned_power_keys(
                &mut self.giant_powers,
                &state.prepared_powers.giant_powers,
                comparison_level,
            )?;
            Ok(())
        }
    }

    fn require_optional_aligned_bound_shape(
        existing: Option<&SymbolicCiphertextBound>,
        state_bound: Option<&SymbolicCiphertextBound>,
        comparison_level: usize,
    ) -> crate::encoding::CanonicalResult<()> {
        match (existing, state_bound) {
            (Some(existing), Some(_)) if existing.level == comparison_level => Ok(()),
            (None, None) => Ok(()),
            _ => Err(super::invalid_recurrence(
                "search dominance key changed optional-bound shape",
            )),
        }
    }

    fn finish_aligned_power_keys(
        existing_keys: &mut [Option<AlignedPowerDominanceKey>],
        state_powers: &[Option<SymbolicPowerBound>],
        comparison_level: usize,
    ) -> crate::encoding::CanonicalResult<()> {
        if existing_keys.len() != state_powers.len() {
            return Err(super::invalid_recurrence(
                "search dominance key changed power-table shape",
            ));
        }
        for (existing_key, state_power) in existing_keys.iter_mut().zip(state_powers) {
            match (existing_key.as_mut(), state_power) {
                (Some(existing_key), Some(state_power)) => {
                    if existing_key.multiplication_depth != state_power.multiplication_depth
                        || existing_key.ciphertext_bound.level != comparison_level
                    {
                        return Err(super::invalid_recurrence(
                            "search dominance key changed a retained power",
                        ));
                    }
                }
                (None, Some(state_power)) => {
                    *existing_key = Some(AlignedPowerDominanceKey {
                        multiplication_depth: state_power.multiplication_depth,
                        ciphertext_bound: state_power
                            .ciphertext_bound
                            .modulus_switch_to(comparison_level)?,
                    });
                }
                (None, None) => {}
                (Some(_), None) => {
                    return Err(super::invalid_recurrence(
                        "search dominance key removed a retained power",
                    ));
                }
            }
        }
        Ok(())
    }

    fn aligned_power_dominance_key(
        power: &Option<SymbolicPowerBound>,
        comparison_level: usize,
    ) -> crate::encoding::CanonicalResult<Option<AlignedPowerDominanceKey>> {
        power
            .as_ref()
            .map(|power| {
                Ok(AlignedPowerDominanceKey {
                    multiplication_depth: power.multiplication_depth,
                    ciphertext_bound: power.ciphertext_bound.modulus_switch_to(comparison_level)?,
                })
            })
            .transpose()
    }

    fn aligned_power_keys_dominate(
        left: &[Option<AlignedPowerDominanceKey>],
        right: &[Option<AlignedPowerDominanceKey>],
    ) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(left, right)| match (left, right) {
                    (Some(left), Some(right)) => {
                        left.multiplication_depth == right.multiplication_depth
                            && aligned_bound_dominates(
                                &left.ciphertext_bound,
                                &right.ciphertext_bound,
                            )
                    }
                    (None, None) => true,
                    _ => false,
                })
    }

    fn optional_aligned_bound_dominates(
        left: Option<&SymbolicCiphertextBound>,
        right: Option<&SymbolicCiphertextBound>,
    ) -> bool {
        match (left, right) {
            (Some(left), Some(right)) => aligned_bound_dominates(left, right),
            (None, None) => true,
            _ => false,
        }
    }

    fn aligned_bound_dominates(
        left: &SymbolicCiphertextBound,
        right: &SymbolicCiphertextBound,
    ) -> bool {
        left.level == right.level
            && left.decrypt_scaling == right.decrypt_scaling
            && left.component_count == right.component_count
            && left.collective_secret_coefficient_bound == right.collective_secret_coefficient_bound
            && left.data_primes == right.data_primes
            && left.key_switch_data_primes_per_block == right.key_switch_data_primes_per_block
            && left.key_switch_special_basis_modulus == right.key_switch_special_basis_modulus
            && left.message_coefficient_bound <= right.message_coefficient_bound
            && left.error_coefficient_bound <= right.error_coefficient_bound
            && left.minimum_decryption_margin >= right.minimum_decryption_margin
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct SearchPruningCounts {
        generated_prefix_count: u128,
        resource_rejected_prefix_count: u128,
        negative_margin_prefix_count: u128,
        dominated_prefix_count: u128,
        resource_rejected_complete_schedule_counts: BTreeMap<usize, u128>,
        negative_margin_complete_schedule_counts: BTreeMap<usize, u128>,
        dominated_complete_schedule_counts: BTreeMap<usize, u128>,
        evaluated_complete_schedule_counts: BTreeMap<usize, u128>,
    }

    #[derive(Clone, Copy, Debug)]
    enum SearchPruningReason {
        NegativeMargin,
        Dominated,
    }

    fn initialize_partial_power_dag(
        input: &SymbolicCiphertextBound,
        coefficient_count: usize,
        baby_step_count: usize,
        working_level: usize,
    ) -> crate::encoding::CanonicalResult<SymbolicPolynomialPowers> {
        if coefficient_count <= baby_step_count || baby_step_count < 2 {
            return Err(super::invalid_recurrence(
                "partial power DAG requires a nontrivial Paterson-Stockmeyer polynomial",
            ));
        }
        let block_count = coefficient_count.div_ceil(baby_step_count);
        let working_input = input.modulus_switch_to(working_level)?;
        let mut baby_powers = vec![None; baby_step_count + 1];
        baby_powers[1] = Some(SymbolicPowerBound {
            ciphertext_bound: working_input.clone(),
            multiplication_depth: 0,
        });
        Ok(SymbolicPolynomialPowers {
            working_input,
            baby_step_count,
            block_count,
            baby_powers,
            giant_powers: vec![None; block_count],
        })
    }

    fn extend_partial_power_dag_at_depth(
        prepared_powers: &mut SymbolicPolynomialPowers,
        multiplication_depth: usize,
        modulus_drop_count: usize,
    ) -> crate::encoding::CanonicalResult<(u64, u64)> {
        let mut instruction_count = 0_u64;
        let mut active_data_limb_instruction_units = 0_u64;

        for product in scheduled_power_table_products(prepared_powers.baby_step_count, 0)? {
            if product.multiplication_depth != multiplication_depth
                || prepared_powers.baby_powers[product.output_power].is_some()
            {
                continue;
            }
            let Some(left) = prepared_powers.baby_powers[product.lower_power].clone() else {
                continue;
            };
            let Some(right) = prepared_powers.baby_powers[product.upper_power].clone() else {
                continue;
            };
            let (product_instruction_count, product_limb_units) =
                scheduled_product_work(&left, &right, modulus_drop_count)?;
            prepared_powers.baby_powers[product.output_power] = Some(SymbolicPowerBound {
                ciphertext_bound: left
                    .ciphertext_bound
                    .multiply_and_switch_by(&right.ciphertext_bound, modulus_drop_count)?,
                multiplication_depth: product.multiplication_depth,
            });
            instruction_count = instruction_count
                .checked_add(product_instruction_count)
                .expect("selected evaluator instruction count fits u64");
            active_data_limb_instruction_units = active_data_limb_instruction_units
                .checked_add(product_limb_units)
                .expect("selected evaluator limb work fits u64");
        }

        if prepared_powers
            .giant_powers
            .get(1)
            .is_some_and(Option::is_none)
            && let Some(giant_base) =
                prepared_powers.baby_powers[prepared_powers.baby_step_count].clone()
        {
            prepared_powers.giant_powers[1] = Some(giant_base);
        }
        if let Some(giant_base_multiplication_depth) = prepared_powers
            .giant_powers
            .get(1)
            .and_then(Option::as_ref)
            .map(|power| power.multiplication_depth)
        {
            for product in scheduled_power_table_products(
                prepared_powers.block_count.saturating_sub(1),
                giant_base_multiplication_depth,
            )? {
                if product.multiplication_depth != multiplication_depth
                    || prepared_powers.giant_powers[product.output_power].is_some()
                {
                    continue;
                }
                let Some(left) = prepared_powers.giant_powers[product.lower_power].clone() else {
                    continue;
                };
                let Some(right) = prepared_powers.giant_powers[product.upper_power].clone() else {
                    continue;
                };
                let (product_instruction_count, product_limb_units) =
                    scheduled_product_work(&left, &right, modulus_drop_count)?;
                prepared_powers.giant_powers[product.output_power] = Some(SymbolicPowerBound {
                    ciphertext_bound: left
                        .ciphertext_bound
                        .multiply_and_switch_by(&right.ciphertext_bound, modulus_drop_count)?,
                    multiplication_depth: product.multiplication_depth,
                });
                instruction_count = instruction_count
                    .checked_add(product_instruction_count)
                    .expect("selected evaluator instruction count fits u64");
                active_data_limb_instruction_units = active_data_limb_instruction_units
                    .checked_add(product_limb_units)
                    .expect("selected evaluator limb work fits u64");
            }
        }

        if instruction_count == 0 {
            return Err(super::invalid_recurrence(
                "partial power DAG depth contains no multiplication",
            ));
        }
        Ok((instruction_count, active_data_limb_instruction_units))
    }

    #[derive(Debug)]
    struct PreparedPowerDagDepthBranch {
        modulus_drop_count: usize,
        baby_power_outputs: Vec<(usize, SymbolicPowerBound)>,
        giant_base: Option<SymbolicPowerBound>,
        giant_power_outputs: Vec<(usize, SymbolicPowerBound)>,
        instruction_count: u64,
        active_data_limb_instruction_units: u64,
    }

    fn prepare_power_dag_depth_branches(
        prepared_powers: &SymbolicPolynomialPowers,
        multiplication_depth: usize,
        minimum_modulus_drop_count: usize,
        maximum_modulus_drop_count: usize,
    ) -> crate::encoding::CanonicalResult<Vec<PreparedPowerDagDepthBranch>> {
        if minimum_modulus_drop_count > maximum_modulus_drop_count {
            return Ok(Vec::new());
        }

        let mut zero_drop_powers = prepared_powers.clone();
        let (zero_drop_instruction_count, zero_drop_limb_units) =
            extend_partial_power_dag_at_depth(&mut zero_drop_powers, multiplication_depth, 0)?;
        let mut baby_power_outputs = newly_created_power_outputs(
            &prepared_powers.baby_powers,
            &zero_drop_powers.baby_powers,
            0,
        )?;
        let mut giant_power_outputs = newly_created_power_outputs(
            &prepared_powers.giant_powers,
            &zero_drop_powers.giant_powers,
            2,
        )?;
        let newly_created_product_count = baby_power_outputs.len() + giant_power_outputs.len();
        if newly_created_product_count == 0 {
            return Err(super::invalid_recurrence(
                "prepared power DAG depth contains no multiplication",
            ));
        }

        for _ in 0..minimum_modulus_drop_count {
            switch_prepared_power_outputs_once(&mut baby_power_outputs)?;
            switch_prepared_power_outputs_once(&mut giant_power_outputs)?;
        }

        let assigns_giant_base = prepared_powers
            .giant_powers
            .get(1)
            .is_some_and(Option::is_none)
            && zero_drop_powers
                .giant_powers
                .get(1)
                .is_some_and(Option::is_some);
        let fixed_giant_base = assigns_giant_base
            .then(|| {
                prepared_powers
                    .baby_powers
                    .get(prepared_powers.baby_step_count)
                    .and_then(Option::as_ref)
                    .cloned()
            })
            .flatten();
        let mut branches =
            Vec::with_capacity(maximum_modulus_drop_count - minimum_modulus_drop_count + 1);
        for modulus_drop_count in minimum_modulus_drop_count..=maximum_modulus_drop_count {
            let giant_base = if assigns_giant_base {
                fixed_giant_base.clone().or_else(|| {
                    baby_power_outputs
                        .iter()
                        .find(|(power_index, _)| *power_index == prepared_powers.baby_step_count)
                        .map(|(_, power)| power.clone())
                })
            } else {
                None
            };
            if assigns_giant_base && giant_base.is_none() {
                return Err(super::invalid_recurrence(
                    "prepared power DAG depth omitted the giant-step base",
                ));
            }
            let additional_grouped_switch_instruction_count = u64::from(modulus_drop_count > 1)
                .checked_mul(
                    u64::try_from(newly_created_product_count)
                        .expect("selected evaluator product count fits u64"),
                )
                .expect("selected evaluator instruction count fits u64");
            let additional_limb_units = baby_power_outputs
                .iter()
                .chain(&giant_power_outputs)
                .try_fold(0_u64, |total, (_, output)| {
                    let zero_drop_output_level = output
                        .ciphertext_bound
                        .level
                        .checked_add(modulus_drop_count)
                        .ok_or_else(|| {
                            super::invalid_recurrence("prepared power DAG output level overflowed")
                        })?;
                    (0..modulus_drop_count).try_fold(total, |total, drop_index| {
                        total
                            .checked_add(
                                u64::try_from(zero_drop_output_level - drop_index + 1)
                                    .expect("selected evaluator level fits u64"),
                            )
                            .ok_or_else(|| {
                                super::invalid_recurrence("selected evaluator limb work overflowed")
                            })
                    })
                })?;
            branches.push(PreparedPowerDagDepthBranch {
                modulus_drop_count,
                baby_power_outputs: baby_power_outputs.clone(),
                giant_base,
                giant_power_outputs: giant_power_outputs.clone(),
                instruction_count: zero_drop_instruction_count
                    .checked_add(additional_grouped_switch_instruction_count)
                    .expect("selected evaluator instruction count fits u64"),
                active_data_limb_instruction_units: zero_drop_limb_units
                    .checked_add(additional_limb_units)
                    .expect("selected evaluator limb work fits u64"),
            });
            if modulus_drop_count < maximum_modulus_drop_count {
                switch_prepared_power_outputs_once(&mut baby_power_outputs)?;
                switch_prepared_power_outputs_once(&mut giant_power_outputs)?;
            }
        }
        Ok(branches)
    }

    fn newly_created_power_outputs(
        previous_powers: &[Option<SymbolicPowerBound>],
        zero_drop_powers: &[Option<SymbolicPowerBound>],
        first_product_index: usize,
    ) -> crate::encoding::CanonicalResult<Vec<(usize, SymbolicPowerBound)>> {
        if previous_powers.len() != zero_drop_powers.len() {
            return Err(super::invalid_recurrence(
                "prepared power DAG changed power-table shape",
            ));
        }
        let mut outputs = Vec::new();
        for (power_index, (previous_power, zero_drop_power)) in
            previous_powers.iter().zip(zero_drop_powers).enumerate()
        {
            match (previous_power, zero_drop_power) {
                (Some(previous_power), Some(zero_drop_power))
                    if previous_power == zero_drop_power => {}
                (None, Some(zero_drop_power)) if power_index >= first_product_index => {
                    outputs.push((power_index, zero_drop_power.clone()));
                }
                (None, None) => {}
                (None, Some(_)) => {}
                _ => {
                    return Err(super::invalid_recurrence(
                        "prepared power DAG changed a retained power",
                    ));
                }
            }
        }
        Ok(outputs)
    }

    fn switch_prepared_power_outputs_once(
        outputs: &mut [(usize, SymbolicPowerBound)],
    ) -> crate::encoding::CanonicalResult<()> {
        for (_, output) in outputs {
            output.ciphertext_bound = output.ciphertext_bound.modulus_switch()?;
        }
        Ok(())
    }

    fn apply_prepared_power_dag_depth_branch(
        prepared_powers: &mut SymbolicPolynomialPowers,
        branch: PreparedPowerDagDepthBranch,
    ) -> crate::encoding::CanonicalResult<(u64, u64)> {
        for (power_index, output) in branch.baby_power_outputs {
            let power_slot = prepared_powers
                .baby_powers
                .get_mut(power_index)
                .ok_or_else(|| super::invalid_recurrence("baby-power index overflowed"))?;
            if power_slot.is_some() {
                return Err(super::invalid_recurrence(
                    "prepared branch replaced a retained baby power",
                ));
            }
            *power_slot = Some(output);
        }
        if let Some(giant_base) = branch.giant_base {
            let giant_base_slot = prepared_powers
                .giant_powers
                .get_mut(1)
                .ok_or_else(|| super::invalid_recurrence("giant-power base is missing"))?;
            if giant_base_slot.is_some() {
                return Err(super::invalid_recurrence(
                    "prepared branch replaced the retained giant-power base",
                ));
            }
            *giant_base_slot = Some(giant_base);
        }
        for (power_index, output) in branch.giant_power_outputs {
            let power_slot = prepared_powers
                .giant_powers
                .get_mut(power_index)
                .ok_or_else(|| super::invalid_recurrence("giant-power index overflowed"))?;
            if power_slot.is_some() {
                return Err(super::invalid_recurrence(
                    "prepared branch replaced a retained giant power",
                ));
            }
            *power_slot = Some(output);
        }
        Ok((
            branch.instruction_count,
            branch.active_data_limb_instruction_units,
        ))
    }

    fn scheduled_product_work(
        left: &SymbolicPowerBound,
        right: &SymbolicPowerBound,
        modulus_drop_count: usize,
    ) -> crate::encoding::CanonicalResult<(u64, u64)> {
        let target_level = left
            .ciphertext_bound
            .level
            .min(right.ciphertext_bound.level);
        if modulus_drop_count > target_level {
            return Err(super::invalid_recurrence(
                "partial power DAG drop exceeds the active level",
            ));
        }
        let left_alignment_drop_count = left.ciphertext_bound.level - target_level;
        let right_alignment_drop_count = right.ciphertext_bound.level - target_level;
        let instruction_count = u64::from(left_alignment_drop_count > 0)
            + u64::from(right_alignment_drop_count > 0)
            + u64::from(modulus_drop_count > 1)
            + 1;
        let mut active_data_limb_instruction_units =
            u64::try_from(target_level + 1).expect("selected evaluator level fits u64");
        for level in (target_level + 1..=left.ciphertext_bound.level).rev() {
            active_data_limb_instruction_units = active_data_limb_instruction_units
                .checked_add(u64::try_from(level + 1).expect("selected evaluator level fits u64"))
                .expect("selected evaluator limb work fits u64");
        }
        for level in (target_level + 1..=right.ciphertext_bound.level).rev() {
            active_data_limb_instruction_units = active_data_limb_instruction_units
                .checked_add(u64::try_from(level + 1).expect("selected evaluator level fits u64"))
                .expect("selected evaluator limb work fits u64");
        }
        for drop_index in 0..modulus_drop_count {
            active_data_limb_instruction_units = active_data_limb_instruction_units
                .checked_add(
                    u64::try_from(target_level - drop_index + 1)
                        .expect("selected evaluator level fits u64"),
                )
                .expect("selected evaluator limb work fits u64");
        }
        Ok((instruction_count, active_data_limb_instruction_units))
    }

    fn partial_power_dag_is_complete(prepared_powers: &SymbolicPolynomialPowers) -> bool {
        prepared_powers
            .baby_powers
            .iter()
            .skip(1)
            .all(Option::is_some)
            && prepared_powers
                .giant_powers
                .iter()
                .skip(1)
                .all(Option::is_some)
    }

    fn every_operative_margin_is_positive(state: &PowerDagSearchState) -> bool {
        let bounds = std::iter::once(&state.prepared_powers.working_input)
            .chain(
                state
                    .prepared_powers
                    .baby_powers
                    .iter()
                    .filter_map(Option::as_ref)
                    .map(|power| &power.ciphertext_bound),
            )
            .chain(
                state
                    .prepared_powers
                    .giant_powers
                    .iter()
                    .filter_map(Option::as_ref)
                    .map(|power| &power.ciphertext_bound),
            )
            .chain(state.packed_ranks.iter());
        // `minimum_decryption_margin` is the minimum over the complete ancestry
        // of a bound. Every recurrence operation carries it forward with `min`,
        // so a nonpositive operative margin can never become positive in a
        // descendant. Discarding such a prefix therefore cannot discard an
        // admissible completion, even when later modulus switches improve the
        // current ciphertext's margin.
        bounds
            .into_iter()
            .all(|bound| bound.minimum_decryption_margin.is_positive())
    }

    fn state_dominates(
        left: &PowerDagSearchState,
        right: &PowerDagSearchState,
    ) -> crate::encoding::CanonicalResult<bool> {
        if left.working_level != right.working_level
            || left.pre_comparison_drop_count < right.pre_comparison_drop_count
            || left.assigned_variable_count != right.assigned_variable_count
            || left.consumed_drop_count != right.consumed_drop_count
            || left.evaluator_instruction_count > right.evaluator_instruction_count
            || left.active_data_limb_instruction_units > right.active_data_limb_instruction_units
        {
            return Ok(false);
        }
        let comparison_level = left
            .working_level
            .checked_sub(left.consumed_drop_count)
            .ok_or_else(|| super::invalid_recurrence("search state consumed too many levels"))?;
        if !bound_dominates_after_alignment(
            &left.prepared_powers.working_input,
            &right.prepared_powers.working_input,
            comparison_level,
        )? || !optional_bound_dominates_after_alignment(
            left.packed_ranks.as_ref(),
            right.packed_ranks.as_ref(),
            comparison_level,
        )? || left.prepared_powers.baby_powers.len() != right.prepared_powers.baby_powers.len()
            || left.prepared_powers.giant_powers.len() != right.prepared_powers.giant_powers.len()
        {
            return Ok(false);
        }
        for (left_power, right_power) in left
            .prepared_powers
            .baby_powers
            .iter()
            .chain(&left.prepared_powers.giant_powers)
            .zip(
                right
                    .prepared_powers
                    .baby_powers
                    .iter()
                    .chain(&right.prepared_powers.giant_powers),
            )
        {
            match (left_power, right_power) {
                (Some(left_power), Some(right_power))
                    if left_power.multiplication_depth == right_power.multiplication_depth
                        && bound_dominates_after_alignment(
                            &left_power.ciphertext_bound,
                            &right_power.ciphertext_bound,
                            comparison_level,
                        )? => {}
                (None, None) => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    fn optional_bound_dominates_after_alignment(
        left: Option<&SymbolicCiphertextBound>,
        right: Option<&SymbolicCiphertextBound>,
        target_level: usize,
    ) -> crate::encoding::CanonicalResult<bool> {
        match (left, right) {
            (Some(left), Some(right)) => bound_dominates_after_alignment(left, right, target_level),
            (None, None) => Ok(true),
            _ => Ok(false),
        }
    }

    fn bound_dominates_after_alignment(
        left: &SymbolicCiphertextBound,
        right: &SymbolicCiphertextBound,
        target_level: usize,
    ) -> crate::encoding::CanonicalResult<bool> {
        let left = left.modulus_switch_to(target_level)?;
        let right = right.modulus_switch_to(target_level)?;
        Ok(left.level == right.level
            && left.decrypt_scaling == right.decrypt_scaling
            && left.component_count == right.component_count
            && left.collective_secret_coefficient_bound
                == right.collective_secret_coefficient_bound
            && left.data_primes == right.data_primes
            && left.key_switch_data_primes_per_block == right.key_switch_data_primes_per_block
            && left.key_switch_special_basis_modulus == right.key_switch_special_basis_modulus
            && left.message_coefficient_bound <= right.message_coefficient_bound
            && left.error_coefficient_bound <= right.error_coefficient_bound
            && left.minimum_decryption_margin >= right.minimum_decryption_margin)
    }

    fn weak_composition_count(variable_count: usize, total: usize) -> u128 {
        if variable_count == 0 {
            return u128::from(total == 0);
        }
        binomial_coefficient(total + variable_count - 1, variable_count - 1)
    }

    fn bounded_composition_count(variable_count: usize, total: usize, cap: usize) -> u128 {
        let mut counts = vec![0_u128; total + 1];
        counts[0] = 1;
        for _ in 0..variable_count {
            let previous = counts.clone();
            counts.fill(0);
            for previous_total in 0..=total {
                for value in 0..=cap.min(total - previous_total) {
                    counts[previous_total + value] += previous[previous_total];
                }
            }
        }
        counts[total]
    }

    fn binomial_coefficient(total: usize, selected: usize) -> u128 {
        let selected = selected.min(total - selected);
        (1..=selected).fold(1_u128, |value, offset| {
            value
                .checked_mul(u128::try_from(total - selected + offset).expect("count fits u128"))
                .expect("selected schedule count fits u128")
                / u128::try_from(offset).expect("count fits u128")
        })
    }

    fn joint_search_total_drop_range(
        working_level: usize,
    ) -> crate::encoding::CanonicalResult<std::ops::RangeInclusive<usize>> {
        let maximum_target_level = JOINT_SEARCH_MAXIMUM_TARGET_LEVEL.min(
            working_level
                .checked_sub(1)
                .ok_or_else(|| super::invalid_recurrence("evaluator working level is zero"))?,
        );
        if maximum_target_level < JOINT_SEARCH_MINIMUM_TARGET_LEVEL {
            return Err(super::invalid_recurrence(
                "evaluator working level cannot reach the minimum target basis",
            ));
        }
        Ok((working_level - maximum_target_level)
            ..=(working_level - JOINT_SEARCH_MINIMUM_TARGET_LEVEL))
    }

    fn record_pruned_prefix_completions(
        counts: &mut SearchPruningCounts,
        state: &PowerDagSearchState,
        reason: SearchPruningReason,
    ) {
        let remaining_variable_count = JOINT_SEARCH_VARIABLE_COUNT - state.assigned_variable_count;
        let total_drop_range = joint_search_total_drop_range(state.working_level)
            .expect("retained search states have a valid target-level range");
        for total_drop_count in total_drop_range {
            let Some(remaining_drop_count) =
                total_drop_count.checked_sub(state.consumed_drop_count)
            else {
                continue;
            };
            let completion_count =
                weak_composition_count(remaining_variable_count, remaining_drop_count);
            let completion_counts = match reason {
                SearchPruningReason::NegativeMargin => {
                    &mut counts.negative_margin_complete_schedule_counts
                }
                SearchPruningReason::Dominated => &mut counts.dominated_complete_schedule_counts,
            };
            *completion_counts.entry(total_drop_count).or_default() += completion_count;
        }
    }

    fn insert_nondominated_state(
        states: &mut Vec<PowerDagSearchState>,
        candidate: PowerDagSearchState,
        counts: &mut SearchPruningCounts,
    ) -> crate::encoding::CanonicalResult<()> {
        if record_nonpositive_candidate(&candidate, counts) {
            return Ok(());
        }
        for existing in states.iter() {
            if state_dominates(existing, &candidate)? {
                counts.dominated_prefix_count += 1;
                record_pruned_prefix_completions(
                    counts,
                    &candidate,
                    SearchPruningReason::Dominated,
                );
                return Ok(());
            }
        }
        let mut retained = Vec::with_capacity(states.len() + 1);
        for existing in states.drain(..) {
            if state_dominates(&candidate, &existing)? {
                counts.dominated_prefix_count += 1;
                record_pruned_prefix_completions(counts, &existing, SearchPruningReason::Dominated);
            } else {
                retained.push(existing);
            }
        }
        retained.push(candidate);
        *states = retained;
        Ok(())
    }

    fn record_nonpositive_candidate(
        candidate: &PowerDagSearchState,
        counts: &mut SearchPruningCounts,
    ) -> bool {
        if every_operative_margin_is_positive(candidate) {
            return false;
        }
        counts.negative_margin_prefix_count += 1;
        record_pruned_prefix_completions(counts, candidate, SearchPruningReason::NegativeMargin);
        true
    }

    #[derive(Clone, Debug)]
    struct CachedPowerDagSearchState {
        state: PowerDagSearchState,
        dominance_key: PowerDagSearchStateDominanceKey,
    }

    impl CachedPowerDagSearchState {
        fn from_state(state: PowerDagSearchState) -> crate::encoding::CanonicalResult<Self> {
            let dominance_key = PowerDagSearchStateDominanceKey::from_state(&state)?;
            Ok(Self {
                state,
                dominance_key,
            })
        }

        fn finish_dominance_key_transition(&mut self) -> crate::encoding::CanonicalResult<()> {
            self.dominance_key.finish_transition_to_state(&self.state)
        }
    }

    #[derive(Debug, Default)]
    struct NondominatedSearchFrontier {
        entries: Vec<Option<CachedPowerDagSearchState>>,
        entry_indices_by_instruction_and_limb_units: BTreeMap<u64, BTreeMap<u64, Vec<usize>>>,
    }

    impl NondominatedSearchFrontier {
        fn push_known_nondominated_cached(&mut self, cached_state: CachedPowerDagSearchState) {
            self.push_cached_state(cached_state);
        }

        fn insert(
            &mut self,
            candidate: PowerDagSearchState,
            counts: &mut SearchPruningCounts,
        ) -> crate::encoding::CanonicalResult<()> {
            if record_nonpositive_candidate(&candidate, counts) {
                return Ok(());
            }
            self.insert_positive_cached(CachedPowerDagSearchState::from_state(candidate)?, counts)
        }

        fn insert_cached(
            &mut self,
            candidate: CachedPowerDagSearchState,
            counts: &mut SearchPruningCounts,
        ) -> crate::encoding::CanonicalResult<()> {
            if record_nonpositive_candidate(&candidate.state, counts) {
                return Ok(());
            }
            self.insert_positive_cached(candidate, counts)
        }

        fn insert_positive_cached(
            &mut self,
            candidate: CachedPowerDagSearchState,
            counts: &mut SearchPruningCounts,
        ) -> crate::encoding::CanonicalResult<()> {
            let candidate_instruction_count = candidate.state.evaluator_instruction_count;
            let candidate_limb_units = candidate.state.active_data_limb_instruction_units;
            let existing_dominates_candidate = self
                .entry_indices_by_instruction_and_limb_units
                .range(..=candidate_instruction_count)
                .any(|(_, indices_by_limb_units)| {
                    indices_by_limb_units.range(..=candidate_limb_units).any(
                        |(_, entry_indices)| {
                            entry_indices.iter().any(|entry_index| {
                                self.entries
                                    .get(*entry_index)
                                    .and_then(Option::as_ref)
                                    .is_some_and(|entry| {
                                        entry.dominance_key.dominates(&candidate.dominance_key)
                                    })
                            })
                        },
                    )
                });
            if existing_dominates_candidate {
                counts.dominated_prefix_count += 1;
                record_pruned_prefix_completions(
                    counts,
                    &candidate.state,
                    SearchPruningReason::Dominated,
                );
                return Ok(());
            }

            let mut dominated_entry_indices = self
                .entry_indices_by_instruction_and_limb_units
                .range(candidate_instruction_count..)
                .flat_map(|(_, indices_by_limb_units)| {
                    indices_by_limb_units
                        .range(candidate_limb_units..)
                        .flat_map(|(_, entry_indices)| entry_indices.iter().copied())
                })
                .filter(|entry_index| {
                    self.entries
                        .get(*entry_index)
                        .and_then(Option::as_ref)
                        .is_some_and(|entry| {
                            candidate.dominance_key.dominates(&entry.dominance_key)
                        })
                })
                .collect::<Vec<_>>();
            dominated_entry_indices.sort_unstable();
            for entry_index in dominated_entry_indices {
                let Some(dominated_entry) =
                    self.entries.get_mut(entry_index).and_then(Option::take)
                else {
                    continue;
                };
                self.remove_entry_index(
                    dominated_entry.state.evaluator_instruction_count,
                    dominated_entry.state.active_data_limb_instruction_units,
                    entry_index,
                );
                counts.dominated_prefix_count += 1;
                record_pruned_prefix_completions(
                    counts,
                    &dominated_entry.state,
                    SearchPruningReason::Dominated,
                );
            }

            self.push_cached_state(candidate);
            Ok(())
        }

        fn push_cached_state(&mut self, cached_state: CachedPowerDagSearchState) {
            let entry_index = self.entries.len();
            let instruction_count = cached_state.state.evaluator_instruction_count;
            let limb_units = cached_state.state.active_data_limb_instruction_units;
            self.entries.push(Some(cached_state));
            self.entry_indices_by_instruction_and_limb_units
                .entry(instruction_count)
                .or_default()
                .entry(limb_units)
                .or_default()
                .push(entry_index);
        }

        fn remove_entry_index(
            &mut self,
            instruction_count: u64,
            limb_units: u64,
            entry_index: usize,
        ) {
            let mut remove_instruction_bucket = false;
            if let Some(indices_by_limb_units) = self
                .entry_indices_by_instruction_and_limb_units
                .get_mut(&instruction_count)
            {
                let mut remove_limb_bucket = false;
                if let Some(entry_indices) = indices_by_limb_units.get_mut(&limb_units) {
                    if let Some(index_position) = entry_indices
                        .iter()
                        .position(|candidate_index| *candidate_index == entry_index)
                    {
                        entry_indices.remove(index_position);
                    }
                    remove_limb_bucket = entry_indices.is_empty();
                }
                if remove_limb_bucket {
                    indices_by_limb_units.remove(&limb_units);
                }
                remove_instruction_bucket = indices_by_limb_units.is_empty();
            }
            if remove_instruction_bucket {
                self.entry_indices_by_instruction_and_limb_units
                    .remove(&instruction_count);
            }
        }

        fn into_cached_states(self) -> Vec<CachedPowerDagSearchState> {
            self.entries.into_iter().flatten().collect()
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct JointTopologyCandidate {
        label: &'static str,
        special_prime_count: usize,
        data_primes_per_block: usize,
        security_comparison_allows_finalist: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PrimeOrderCandidate {
        label: &'static str,
        data_primes: Vec<u64>,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct JointSearchMeasurement {
        topology_label: &'static str,
        prime_order_label: &'static str,
        data_prime_count: usize,
        working_level: usize,
        schedule: EvaluatorModulusSchedule,
        target_level: usize,
        relinearization_level: usize,
        maximum_error_bound: BigUint,
        minimum_margin: BigInt,
        factor_four_maximum_error_bound: BigUint,
        factor_four_c2_margin: BigInt,
        factor_four_conditions_hold: bool,
        evaluator_instruction_count: u64,
        active_data_limb_instruction_units: u64,
        participant_source_wire_byte_length: u64,
        final_evaluator_store_wire_byte_length: u64,
        ceremony_evaluator_wire_byte_length: u64,
        target_role_stream_byte_length: u64,
        paired_target_stream_byte_length: u64,
        paired_target_stream_requires_independent_chunks: bool,
        target_ciphertext_resident_byte_length: u64,
        full_qp_log2: f64,
        security_comparison_allows_finalist: bool,
    }

    const JOINT_SEARCH_CHECKPOINT_SCHEMA: &str =
        "sealed-lattice/joint-evaluator-topology-search-checkpoint/v1";
    const JOINT_SEARCH_CHECKPOINT_DIRECTORY_NAME: &str = "selected-evaluator-joint-topology-search";
    const PROSPECTIVE_28_PRIME_P5_B7_CHECKPOINT_SCHEMA: &str =
        "sealed-lattice/prospective-28-prime-p5-b7-search-checkpoint/v1";
    const PROSPECTIVE_28_PRIME_P5_B7_CHECKPOINT_DIRECTORY_NAME: &str =
        "prospective-28-prime-p5-b7-joint-topology-search";
    const TARGET_HEAVY_BLOCK_BALANCED_CHECKPOINT_SCHEMA: &str =
        "sealed-lattice/target-heavy-block-balanced-evaluator-search-checkpoint/v1";
    const TARGET_HEAVY_BLOCK_BALANCED_CHECKPOINT_DIRECTORY_NAME: &str =
        "target-heavy-block-balanced-evaluator-search";
    // Each outer worker owns one complete triple search. Nested Rayon and
    // libtest execution stay serialized; the guarded fresh-prefix probe owns
    // the measured peak check for this cap and its bounded reorder window.
    const JOINT_SEARCH_MAXIMUM_WORKER_COUNT: usize = 16;
    const JOINT_SEARCH_REORDER_WINDOW_MULTIPLIER: usize = 2;
    const JOINT_SEARCH_PARALLEL_PREFIX_PROBE_TRIPLE_COUNT: usize = 16;
    const JOINT_SEARCH_PARALLEL_PREFIX_PROBE_MINIMUM_DATA_PRIME_COUNT: usize = 18;
    const JOINT_SEARCH_PARALLEL_PREFIX_PROBE_MAXIMUM_DATA_PRIME_COUNT: usize = 19;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct JointSearchScheduleCheckpoint {
        pre_comparison_drop_count: usize,
        comparison_depth_drop_counts: [usize; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
        rank_depth_drop_counts: [usize; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
    }

    impl From<EvaluatorModulusSchedule> for JointSearchScheduleCheckpoint {
        fn from(schedule: EvaluatorModulusSchedule) -> Self {
            Self {
                pre_comparison_drop_count: schedule.pre_comparison_drop_count,
                comparison_depth_drop_counts: schedule.comparison_depth_drop_counts,
                rank_depth_drop_counts: schedule.rank_depth_drop_counts,
            }
        }
    }

    impl From<JointSearchScheduleCheckpoint> for EvaluatorModulusSchedule {
        fn from(checkpoint: JointSearchScheduleCheckpoint) -> Self {
            Self {
                pre_comparison_drop_count: checkpoint.pre_comparison_drop_count,
                comparison_depth_drop_counts: checkpoint.comparison_depth_drop_counts,
                rank_depth_drop_counts: checkpoint.rank_depth_drop_counts,
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct JointSearchTripleCheckpoint {
        binding: Value,
        pruning_counts: SearchPruningCounts,
        retained_schedules: Vec<JointSearchScheduleCheckpoint>,
    }

    #[derive(Clone, Debug)]
    struct JointSearchTripleTask {
        topology: JointTopologyCandidate,
        prime_order: PrimeOrderCandidate,
        data_prime_count: usize,
        checkpoint_binding: Value,
        checkpoint_path: Option<PathBuf>,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct JointSearchTripleResult {
        topology: JointTopologyCandidate,
        prime_order: PrimeOrderCandidate,
        data_prime_count: usize,
        checkpoint_binding: Value,
        checkpoint_install_path: Option<PathBuf>,
        pruning_counts: SearchPruningCounts,
        retained_schedules: Vec<JointSearchScheduleCheckpoint>,
        measurements: Vec<JointSearchMeasurement>,
    }

    fn joint_topology_candidates() -> [JointTopologyCandidate; 7] {
        [
            JointTopologyCandidate {
                label: "P6/B6",
                special_prime_count: 6,
                data_primes_per_block: 6,
                security_comparison_allows_finalist: true,
            },
            JointTopologyCandidate {
                label: "P6/B7",
                special_prime_count: 6,
                data_primes_per_block: 7,
                security_comparison_allows_finalist: true,
            },
            JointTopologyCandidate {
                label: "P7/B7",
                special_prime_count: 7,
                data_primes_per_block: 7,
                security_comparison_allows_finalist: false,
            },
            JointTopologyCandidate {
                label: "P8/B9",
                special_prime_count: 8,
                data_primes_per_block: 9,
                security_comparison_allows_finalist: false,
            },
            JointTopologyCandidate {
                label: "P9/B10",
                special_prime_count: 9,
                data_primes_per_block: 10,
                security_comparison_allows_finalist: false,
            },
            JointTopologyCandidate {
                label: "P5/B6-control",
                special_prime_count: 5,
                data_primes_per_block: 6,
                security_comparison_allows_finalist: true,
            },
            JointTopologyCandidate {
                label: "P5/B7-control",
                special_prime_count: 5,
                data_primes_per_block: 7,
                security_comparison_allows_finalist: true,
            },
        ]
    }

    fn prime_order_candidates() -> [PrimeOrderCandidate; 3] {
        let mut largest_drop_first = DATA_PRIMES.to_vec();
        largest_drop_first[CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1..].sort_unstable();
        let mut smallest_drop_first = DATA_PRIMES.to_vec();
        smallest_drop_first[CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1..]
            .sort_unstable_by(|left, right| right.cmp(left));
        [
            PrimeOrderCandidate {
                label: "current",
                data_primes: DATA_PRIMES.to_vec(),
            },
            PrimeOrderCandidate {
                label: "largest-drop-first",
                data_primes: largest_drop_first,
            },
            PrimeOrderCandidate {
                label: "smallest-drop-first",
                data_primes: smallest_drop_first,
            },
        ]
    }

    fn unique_prime_order_candidates_for_count(
        data_prime_count: usize,
    ) -> crate::encoding::CanonicalResult<Vec<PrimeOrderCandidate>> {
        if !(JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT..=DATA_PRIMES.len()).contains(&data_prime_count)
        {
            return Err(super::invalid_recurrence(
                "joint evaluator data-prime count is outside the exact candidate range",
            ));
        }
        let mut unique_candidates = Vec::<PrimeOrderCandidate>::new();
        for candidate in prime_order_candidates() {
            if unique_candidates.iter().any(|existing| {
                existing.data_primes[..data_prime_count]
                    == candidate.data_primes[..data_prime_count]
            }) {
                continue;
            }
            unique_candidates.push(candidate);
        }
        Ok(unique_candidates)
    }

    fn joint_search_checkpoint_binding(
        topology: JointTopologyCandidate,
        prime_order: &PrimeOrderCandidate,
        data_primes: &[u64],
    ) -> Value {
        let topology_catalog = joint_topology_candidates()
            .into_iter()
            .map(|candidate| {
                json!({
                    "label": candidate.label,
                    "specialPrimeCount": candidate.special_prime_count,
                    "dataPrimesPerBlock": candidate.data_primes_per_block,
                    "securityComparisonAllowsFinalist": candidate.security_comparison_allows_finalist,
                })
            })
            .collect::<Vec<_>>();
        let prime_order_catalog = prime_order_candidates()
            .into_iter()
            .map(|candidate| {
                json!({
                    "label": candidate.label,
                    "dataPrimes": &candidate.data_primes,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schema": JOINT_SEARCH_CHECKPOINT_SCHEMA,
            "searchSemanticsVersion": 1,
            "candidateCatalog": {
                "topologies": topology_catalog,
                "primeOrders": prime_order_catalog,
                "dataPrimes": DATA_PRIMES,
                "specialPrimes": SPECIAL_PRIMES,
            },
            "fixedProfile": {
                "participantCount": 10,
                "ballotCount": 10,
                "optionCount": 20,
                "minimumScore": 1,
                "maximumScore": 10,
                "polynomialDegree": POLYNOMIAL_DEGREE,
                "plaintextModulus": PLAINTEXT_MODULUS,
                "minimumTargetLevel": JOINT_SEARCH_MINIMUM_TARGET_LEVEL,
                "maximumTargetLevel": JOINT_SEARCH_MAXIMUM_TARGET_LEVEL,
                "minimumDataPrimeCount": JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT,
                "comparisonDepthCount": COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
                "rankDepthCount": RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
                "searchVariableCount": JOINT_SEARCH_VARIABLE_COUNT,
                "maximumCanonicalStreamByteLength": MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                "maximumCopiedBufferByteLength": FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
            },
            "triple": {
                "topologyLabel": topology.label,
                "specialPrimeCount": topology.special_prime_count,
                "dataPrimesPerBlock": topology.data_primes_per_block,
                "securityComparisonAllowsFinalist": topology.security_comparison_allows_finalist,
                "primeOrderLabel": prime_order.label,
                "dataPrimes": data_primes,
            },
        })
    }

    fn prospective_28_prime_p5_b7_checkpoint_binding(
        topology: JointTopologyCandidate,
        prime_order: &PrimeOrderCandidate,
    ) -> Value {
        let prime_order_catalog = prospective_data_prime_order_candidates();
        let canonical_data_primes = prime_order_catalog[0].data_primes.clone();
        let serialized_prime_orders = prime_order_catalog
            .iter()
            .map(|candidate| {
                json!({
                    "label": candidate.label,
                    "dataPrimes": &candidate.data_primes,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schema": PROSPECTIVE_28_PRIME_P5_B7_CHECKPOINT_SCHEMA,
            "searchSemanticsVersion": 1,
            "candidateCatalog": {
                "topologies": [{
                    "label": topology.label,
                    "specialPrimeCount": topology.special_prime_count,
                    "dataPrimesPerBlock": topology.data_primes_per_block,
                    "securityComparisonAllowsFinalist": topology.security_comparison_allows_finalist,
                }],
                "primeOrders": serialized_prime_orders,
                "canonicalDataPrimes": canonical_data_primes,
                "prospectiveDataTailPrimes": PROSPECTIVE_DATA_TAIL_PRIMES,
                "specialPrimes": &SPECIAL_PRIMES[..topology.special_prime_count],
            },
            "fixedProfile": {
                "participantCount": 10,
                "ballotCount": 10,
                "optionCount": 20,
                "minimumScore": 1,
                "maximumScore": 10,
                "polynomialDegree": POLYNOMIAL_DEGREE,
                "plaintextModulus": PLAINTEXT_MODULUS,
                "minimumTargetLevel": JOINT_SEARCH_MINIMUM_TARGET_LEVEL,
                "maximumTargetLevel": JOINT_SEARCH_MAXIMUM_TARGET_LEVEL,
                "dataPrimeCount": DATA_PRIMES.len() + PROSPECTIVE_DATA_TAIL_PRIMES.len(),
                "comparisonDepthCount": COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
                "rankDepthCount": RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
                "searchVariableCount": JOINT_SEARCH_VARIABLE_COUNT,
                "maximumCanonicalStreamByteLength": MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                "maximumCopiedBufferByteLength": FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
            },
            "triple": {
                "topologyLabel": topology.label,
                "specialPrimeCount": topology.special_prime_count,
                "dataPrimesPerBlock": topology.data_primes_per_block,
                "securityComparisonAllowsFinalist": topology.security_comparison_allows_finalist,
                "primeOrderLabel": prime_order.label,
                "dataPrimes": &prime_order.data_primes,
            },
        })
    }

    fn target_heavy_block_balanced_checkpoint_binding(
        topology: JointTopologyCandidate,
        prime_order: &PrimeOrderCandidate,
    ) -> Value {
        json!({
            "schema": TARGET_HEAVY_BLOCK_BALANCED_CHECKPOINT_SCHEMA,
            "searchSemanticsVersion": 1,
            "primeOrderLabel": prime_order.label,
            "orderedDataPrimes": &prime_order.data_primes,
            "orderedSpecialPrimes": &SPECIAL_PRIMES[..topology.special_prime_count],
            "topology": {
                "label": topology.label,
                "specialPrimeCount": topology.special_prime_count,
                "dataPrimesPerBlock": topology.data_primes_per_block,
                "securityComparisonAllowsFinalist": topology.security_comparison_allows_finalist,
            },
            "fixedProfile": {
                "participantCount": 10,
                "ballotCount": 10,
                "optionCount": 20,
                "minimumScore": 1,
                "maximumScore": 10,
                "polynomialDegree": POLYNOMIAL_DEGREE,
                "plaintextModulus": PLAINTEXT_MODULUS,
                "minimumTargetLevel": JOINT_SEARCH_MINIMUM_TARGET_LEVEL,
                "maximumTargetLevel": JOINT_SEARCH_MAXIMUM_TARGET_LEVEL,
                "comparisonDepthCount": COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
                "rankDepthCount": RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
                "searchVariableCount": JOINT_SEARCH_VARIABLE_COUNT,
                "maximumCanonicalStreamByteLength": MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                "maximumCopiedBufferByteLength": FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
            },
        })
    }

    fn joint_search_checkpoint_file_name(
        topology: JointTopologyCandidate,
        prime_order: &PrimeOrderCandidate,
        data_prime_count: usize,
    ) -> String {
        fn label_slug(label: &str) -> String {
            label
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect()
        }

        format!(
            "data-prime-count-{data_prime_count}-topology-{}-prime-order-{}.json",
            label_slug(topology.label),
            label_slug(prime_order.label),
        )
    }

    fn joint_search_checkpoint_path(
        topology: JointTopologyCandidate,
        prime_order: &PrimeOrderCandidate,
        data_prime_count: usize,
    ) -> crate::encoding::CanonicalResult<Option<PathBuf>> {
        if std::env::var("SEALED_LATTICE_RESUME_TEST_CHECKPOINTS").as_deref() != Ok("1") {
            return Ok(None);
        }
        let checkpoint_root =
            std::env::var_os("SEALED_LATTICE_TEST_CHECKPOINT_ROOT").ok_or_else(|| {
                super::invalid_recurrence(
                    "joint evaluator search checkpoint resume requires a checkpoint root",
                )
            })?;
        Ok(Some(
            PathBuf::from(checkpoint_root)
                .join(JOINT_SEARCH_CHECKPOINT_DIRECTORY_NAME)
                .join(joint_search_checkpoint_file_name(
                    topology,
                    prime_order,
                    data_prime_count,
                )),
        ))
    }

    enum JointSearchCheckpointLocation {
        Disabled,
        Environment,
        IsolatedRoot(PathBuf),
    }

    fn joint_search_triple_tasks(
        data_prime_counts: impl IntoIterator<Item = usize>,
        checkpoint_location: &JointSearchCheckpointLocation,
    ) -> crate::encoding::CanonicalResult<Vec<JointSearchTripleTask>> {
        let mut tasks = Vec::new();
        for data_prime_count in data_prime_counts {
            for topology in joint_topology_candidates() {
                for prime_order in unique_prime_order_candidates_for_count(data_prime_count)? {
                    let checkpoint_binding = joint_search_checkpoint_binding(
                        topology,
                        &prime_order,
                        &prime_order.data_primes[..data_prime_count],
                    );
                    let checkpoint_path = match checkpoint_location {
                        JointSearchCheckpointLocation::Disabled => None,
                        JointSearchCheckpointLocation::Environment => {
                            joint_search_checkpoint_path(topology, &prime_order, data_prime_count)?
                        }
                        JointSearchCheckpointLocation::IsolatedRoot(checkpoint_root) => Some(
                            checkpoint_root
                                .join(JOINT_SEARCH_CHECKPOINT_DIRECTORY_NAME)
                                .join(joint_search_checkpoint_file_name(
                                    topology,
                                    &prime_order,
                                    data_prime_count,
                                )),
                        ),
                    };
                    tasks.push(JointSearchTripleTask {
                        topology,
                        prime_order,
                        data_prime_count,
                        checkpoint_binding,
                        checkpoint_path,
                    });
                }
            }
        }
        Ok(tasks)
    }

    fn prospective_28_prime_p5_b7_search_tasks()
    -> crate::encoding::CanonicalResult<Vec<JointSearchTripleTask>> {
        if std::env::var("SEALED_LATTICE_RESUME_TEST_CHECKPOINTS").as_deref() != Ok("1") {
            return Err(super::invalid_recurrence(
                "prospective evaluator search requires checkpoint resume",
            ));
        }
        let checkpoint_root =
            std::env::var_os("SEALED_LATTICE_TEST_CHECKPOINT_ROOT").ok_or_else(|| {
                super::invalid_recurrence("prospective evaluator search requires a checkpoint root")
            })?;
        let checkpoint_directory = PathBuf::from(checkpoint_root)
            .join(PROSPECTIVE_28_PRIME_P5_B7_CHECKPOINT_DIRECTORY_NAME);
        let topology = joint_topology_candidates()
            .into_iter()
            .find(|candidate| candidate.label == "P5/B7-control")
            .ok_or_else(|| super::invalid_recurrence("prospective P5/B7 topology is absent"))?;
        prospective_data_prime_order_candidates()
            .into_iter()
            .map(|prime_order| {
                let data_prime_count = prime_order.data_primes.len();
                if data_prime_count != DATA_PRIMES.len() + PROSPECTIVE_DATA_TAIL_PRIMES.len() {
                    return Err(super::invalid_recurrence(
                        "prospective evaluator search received the wrong data-prime count",
                    ));
                }
                let checkpoint_binding =
                    prospective_28_prime_p5_b7_checkpoint_binding(topology, &prime_order);
                let checkpoint_path = Some(checkpoint_directory.join(
                    joint_search_checkpoint_file_name(topology, &prime_order, data_prime_count),
                ));
                Ok(JointSearchTripleTask {
                    topology,
                    prime_order,
                    data_prime_count,
                    checkpoint_binding,
                    checkpoint_path,
                })
            })
            .collect()
    }

    fn target_heavy_block_balanced_search_task()
    -> crate::encoding::CanonicalResult<JointSearchTripleTask> {
        if std::env::var("SEALED_LATTICE_RESUME_TEST_CHECKPOINTS").as_deref() != Ok("1") {
            return Err(super::invalid_recurrence(
                "target-heavy evaluator search requires checkpoint resume",
            ));
        }
        let checkpoint_root =
            std::env::var_os("SEALED_LATTICE_TEST_CHECKPOINT_ROOT").ok_or_else(|| {
                super::invalid_recurrence(
                    "target-heavy evaluator search requires a checkpoint root",
                )
            })?;
        let topology = JointTopologyCandidate {
            label: "P6/B7-target-heavy-block-balanced",
            special_prime_count: 6,
            data_primes_per_block: 7,
            security_comparison_allows_finalist: true,
        };
        let prime_order = target_heavy_block_balanced_prime_order();
        let data_prime_count = prime_order.data_primes.len();
        let checkpoint_binding =
            target_heavy_block_balanced_checkpoint_binding(topology, &prime_order);
        let checkpoint_path = Some(
            PathBuf::from(checkpoint_root)
                .join(TARGET_HEAVY_BLOCK_BALANCED_CHECKPOINT_DIRECTORY_NAME)
                .join(joint_search_checkpoint_file_name(
                    topology,
                    &prime_order,
                    data_prime_count,
                )),
        );
        Ok(JointSearchTripleTask {
            topology,
            prime_order,
            data_prime_count,
            checkpoint_binding,
            checkpoint_path,
        })
    }

    fn joint_search_parallel_worker_count(task_count: usize) -> usize {
        if task_count == 0 {
            return 0;
        }
        thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(JOINT_SEARCH_MAXIMUM_WORKER_COUNT)
            .min(task_count)
    }

    fn joint_search_parallel_reorder_window(worker_count: usize, task_count: usize) -> usize {
        worker_count
            .saturating_mul(JOINT_SEARCH_REORDER_WINDOW_MULTIPLIER)
            .min(task_count)
    }

    fn joint_search_parallel_prefix_checkpoint_root() -> crate::encoding::CanonicalResult<PathBuf> {
        let run_directory = std::env::var_os("SEALED_LATTICE_RUN_DIRECTORY").ok_or_else(|| {
            super::invalid_recurrence(
                "joint evaluator parallel-prefix probe requires the guarded runner directory",
            )
        })?;
        Ok(PathBuf::from(run_directory)
            .join("test-checkpoints")
            .join("joint-evaluator-parallel-prefix-probe"))
    }

    fn read_joint_search_checkpoint(
        checkpoint_path: &Path,
        expected_binding: &Value,
    ) -> crate::encoding::CanonicalResult<Option<JointSearchTripleCheckpoint>> {
        if !checkpoint_path.try_exists().map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint existence check failed: {error}"
            ))
        })? {
            return Ok(None);
        }
        let checkpoint_bytes = fs::read(checkpoint_path).map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint read failed: {error}"
            ))
        })?;
        let checkpoint: JointSearchTripleCheckpoint = serde_json::from_slice(&checkpoint_bytes)
            .map_err(|error| {
                super::invalid_recurrence(format!(
                    "joint evaluator search checkpoint decode failed: {error}"
                ))
            })?;
        if checkpoint.binding != *expected_binding {
            return Err(super::invalid_recurrence(
                "joint evaluator search checkpoint binding does not match the exact search catalog",
            ));
        }
        Ok(Some(checkpoint))
    }

    fn write_joint_search_checkpoint(
        checkpoint_path: &Path,
        checkpoint: &JointSearchTripleCheckpoint,
    ) -> crate::encoding::CanonicalResult<()> {
        let parent_directory = checkpoint_path.parent().ok_or_else(|| {
            super::invalid_recurrence("joint evaluator search checkpoint path has no parent")
        })?;
        fs::create_dir_all(parent_directory).map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint directory creation failed: {error}"
            ))
        })?;
        if checkpoint_path.try_exists().map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint existence check failed: {error}"
            ))
        })? {
            return Err(super::invalid_recurrence(
                "joint evaluator search refused to replace an existing checkpoint",
            ));
        }
        let pending_path =
            checkpoint_path.with_extension(format!("json.pending-{}", std::process::id()));
        let checkpoint_bytes = serde_json::to_vec(checkpoint).map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint encode failed: {error}"
            ))
        })?;
        let mut pending_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&pending_path)
            .map_err(|error| {
                super::invalid_recurrence(format!(
                    "joint evaluator search checkpoint staging failed: {error}"
                ))
            })?;
        pending_file.write_all(&checkpoint_bytes).map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint write failed: {error}"
            ))
        })?;
        pending_file.sync_all().map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint sync failed: {error}"
            ))
        })?;
        drop(pending_file);
        fs::rename(&pending_path, checkpoint_path).map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint atomic install failed: {error}"
            ))
        })?;
        Ok(())
    }

    fn component_material_wire_byte_length(
        level: usize,
        data_primes: &[u64],
        special_primes: &[u64],
        data_primes_per_block: usize,
    ) -> crate::encoding::CanonicalResult<u64> {
        let data_prime_count = level + 1;
        let data_block_count = data_prime_count.div_ceil(data_primes_per_block);
        let bytes_per_coefficient = data_primes[..data_prime_count]
            .iter()
            .chain(special_primes)
            .try_fold(0_u64, |total, modulus| {
                total
                    .checked_add(
                        u64::try_from(canonical_residue_byte_length(*modulus)?).map_err(|_| {
                            super::invalid_recurrence("component residue width does not fit u64")
                        })?,
                    )
                    .ok_or_else(|| super::invalid_recurrence("component byte length overflowed"))
            })?;
        u64::try_from(data_block_count)
            .ok()
            .and_then(|block_count| block_count.checked_mul(u64::try_from(POLYNOMIAL_DEGREE).ok()?))
            .and_then(|coefficient_count| coefficient_count.checked_mul(bytes_per_coefficient))
            .ok_or_else(|| super::invalid_recurrence("component byte length overflowed"))
    }

    fn evaluator_material_wire_byte_lengths(
        relinearization_level: usize,
        data_primes: &[u64],
        special_primes: &[u64],
        data_primes_per_block: usize,
    ) -> crate::encoding::CanonicalResult<(u64, u64, u64)> {
        let working_level = data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| super::invalid_recurrence("evaluator data basis is empty"))?;
        let relinearization_component_byte_length = component_material_wire_byte_length(
            relinearization_level,
            data_primes,
            special_primes,
            data_primes_per_block,
        )?;
        let galois_component_byte_length = component_material_wire_byte_length(
            working_level,
            data_primes,
            special_primes,
            data_primes_per_block,
        )?;
        let participant_source_wire_byte_length = relinearization_component_byte_length
            .checked_mul(3)
            .and_then(|byte_length| {
                galois_component_byte_length
                    .checked_mul(4)
                    .and_then(|galois_byte_length| byte_length.checked_add(galois_byte_length))
            })
            .ok_or_else(|| super::invalid_recurrence("source material byte length overflowed"))?;
        let final_evaluator_store_wire_byte_length = relinearization_component_byte_length
            .checked_mul(2)
            .and_then(|byte_length| {
                galois_component_byte_length
                    .checked_mul(4)
                    .and_then(|galois_byte_length| byte_length.checked_add(galois_byte_length))
            })
            .ok_or_else(|| super::invalid_recurrence("final material byte length overflowed"))?;
        let ceremony_evaluator_wire_byte_length = participant_source_wire_byte_length
            .checked_mul(10)
            .and_then(|byte_length| byte_length.checked_add(final_evaluator_store_wire_byte_length))
            .ok_or_else(|| super::invalid_recurrence("ceremony material byte length overflowed"))?;
        Ok((
            participant_source_wire_byte_length,
            final_evaluator_store_wire_byte_length,
            ceremony_evaluator_wire_byte_length,
        ))
    }

    fn topology_pre_comparison_drop_meets_stream_bound(
        topology: JointTopologyCandidate,
        data_primes: &[u64],
        pre_comparison_drop_count: usize,
    ) -> crate::encoding::CanonicalResult<bool> {
        let working_level = data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| super::invalid_recurrence("evaluator data basis is empty"))?;
        let relinearization_level = working_level
            .checked_sub(pre_comparison_drop_count)
            .ok_or_else(|| super::invalid_recurrence("relinearization level underflowed"))?;
        let (_, _, ceremony_evaluator_wire_byte_length) = evaluator_material_wire_byte_lengths(
            relinearization_level,
            data_primes,
            &SPECIAL_PRIMES[..topology.special_prime_count],
            topology.data_primes_per_block,
        )?;
        Ok(ceremony_evaluator_wire_byte_length <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH)
    }

    fn target_stream_byte_lengths(target_level: usize) -> (u64, u64, u64) {
        let target_role_stream_byte_length = u64::try_from(target_level + 1)
            .expect("target level fits u64")
            .checked_mul(
                u64::try_from(POLYNOMIAL_DEGREE)
                    .expect("ring degree fits u64")
                    .checked_mul(8)
                    .and_then(|byte_length| byte_length.checked_add(8))
                    .expect("target limb byte length fits u64"),
            )
            .and_then(|byte_length| byte_length.checked_add(2))
            .expect("target role stream byte length fits u64");
        let paired_target_stream_byte_length = target_role_stream_byte_length
            .checked_mul(2)
            .expect("paired target stream byte length fits u64");
        let target_ciphertext_resident_byte_length = u64::try_from(target_level + 1)
            .expect("target level fits u64")
            .checked_mul(u64::try_from(POLYNOMIAL_DEGREE).expect("ring degree fits u64"))
            .and_then(|coefficient_count| coefficient_count.checked_mul(8))
            .and_then(|component_byte_length| component_byte_length.checked_mul(4))
            .expect("two target ciphertexts fit u64");
        (
            target_role_stream_byte_length,
            paired_target_stream_byte_length,
            target_ciphertext_resident_byte_length,
        )
    }

    fn modulus_log2(moduli: &[u64]) -> f64 {
        moduli.iter().map(|modulus| (*modulus as f64).log2()).sum()
    }

    fn factor_four_maximum_evaluator_error_bound(
        target_level: usize,
        data_primes: &[u64],
    ) -> BigUint {
        let target_modulus = data_primes[..=target_level]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let mut lower = BigUint::zero();
        let mut upper = target_modulus;
        while lower < upper {
            let middle = (&lower + &upper + BigUint::one()) >> 1_usize;
            let accepted = factor_four_required_flooding_bound(&middle)
                .and_then(|flooding_bound| {
                    ensure_factor_four_parameter_conditions_with_data_primes(
                        target_level,
                        &middle,
                        &flooding_bound,
                        data_primes,
                    )
                })
                .is_ok();
            if accepted {
                lower = middle;
            } else {
                upper = middle - BigUint::one();
            }
        }
        lower
    }

    fn prefix_can_reach_selected_target_level(
        working_level: usize,
        assigned_variable_count: usize,
        consumed_drop_count: usize,
    ) -> bool {
        let Ok(total_drop_range) = joint_search_total_drop_range(working_level) else {
            return false;
        };
        consumed_drop_count <= *total_drop_range.end()
            && (assigned_variable_count < JOINT_SEARCH_VARIABLE_COUNT
                || consumed_drop_count >= *total_drop_range.start())
    }

    fn minimum_next_modulus_drop_count(state: &PowerDagSearchState) -> usize {
        if state.assigned_variable_count + 1 == JOINT_SEARCH_VARIABLE_COUNT {
            let minimum_total_drop_count = *joint_search_total_drop_range(state.working_level)
                .expect("retained search states have a valid target-level range")
                .start();
            minimum_total_drop_count.saturating_sub(state.consumed_drop_count)
        } else {
            0
        }
    }

    fn pre_comparison_work(working_level: usize, pre_comparison_drop_count: usize) -> (u64, u64) {
        let instruction_count = u64::from(pre_comparison_drop_count > 0);
        let active_data_limb_instruction_units = (0..pre_comparison_drop_count)
            .map(|drop_index| {
                u64::try_from(working_level - drop_index + 1)
                    .expect("selected evaluator level fits u64")
            })
            .sum();
        (instruction_count, active_data_limb_instruction_units)
    }

    fn prepare_joint_comparison(
        topology: JointTopologyCandidate,
        data_primes: &[u64],
    ) -> crate::encoding::CanonicalResult<SymbolicPackedRankComparison> {
        let special_basis_modulus = SPECIAL_PRIMES[..topology.special_prime_count]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots_with_data_primes(
            10,
            10,
            Arc::from(data_primes),
            topology.data_primes_per_block,
            Arc::new(special_basis_modulus),
        )?;
        let working_level = data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| super::invalid_recurrence("evaluator data basis is empty"))?;
        let working_aggregate = aggregate.modulus_switch_to(working_level)?;
        let packed_scores = symbolic_pack_direct_score_slots(&working_aggregate, 20)?;
        symbolic_prepare_packed_rank_comparison(&packed_scores, 20, 90)
    }

    fn prepare_joint_pairwise_ballot_comparison(
        topology: JointTopologyCandidate,
        data_primes: &[u64],
    ) -> crate::encoding::CanonicalResult<SymbolicPackedRankComparison> {
        let special_basis_modulus = SPECIAL_PRIMES[..topology.special_prime_count]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots_with_data_primes(
            10,
            10,
            Arc::from(data_primes),
            topology.data_primes_per_block,
            Arc::new(special_basis_modulus),
        )?;
        let working_level = data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| super::invalid_recurrence("evaluator data basis is empty"))?;
        let comparison_shift_weights = (0..190)
            .map(|logical_index| (logical_index, 90_u64))
            .collect::<Vec<_>>();
        let comparison_inputs = aggregate
            .modulus_switch_to(working_level)?
            .normalize_scaling()?
            .add_plaintext_coefficients(&super::packed_score_weighted_selector(
                &comparison_shift_weights,
            )?)?;
        let (_, greater_or_equal_polynomial) = comparison_polynomials(90)?;
        let mut pair_windows = Vec::with_capacity(19);
        let mut next_window_offset = 0_usize;
        for shift in 1..20 {
            let pair_window_size = 20 - shift;
            pair_windows.push((shift, next_window_offset, pair_window_size));
            next_window_offset += pair_window_size;
        }
        if next_window_offset != 190 {
            return Err(super::invalid_recurrence(
                "pairwise-ballot comparison did not cover every ordered pair lane",
            ));
        }
        Ok(SymbolicPackedRankComparison {
            comparison_inputs,
            greater_or_equal_polynomial,
            baby_step_count: direct_comparison_baby_step_count(90)?,
            pair_windows,
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PreComparisonFrontierPartition {
        Separate,
        CollapseDominated,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ComparisonSearchResourceFilter {
        CurrentEvaluatorMaterial,
        MeasurePairwiseMaterialAfterComparison,
    }

    fn search_frontier_key(
        partition: PreComparisonFrontierPartition,
        state: &PowerDagSearchState,
    ) -> (usize, usize) {
        let pre_comparison_partition = match partition {
            PreComparisonFrontierPartition::Separate => state.pre_comparison_drop_count,
            PreComparisonFrontierPartition::CollapseDominated => 0,
        };
        (pre_comparison_partition, state.consumed_drop_count)
    }

    fn generate_comparison_search_states(
        topology: JointTopologyCandidate,
        comparison: &SymbolicPackedRankComparison,
        counts: &mut SearchPruningCounts,
    ) -> crate::encoding::CanonicalResult<Vec<CachedPowerDagSearchState>> {
        generate_comparison_search_states_with_partition(
            topology,
            comparison,
            counts,
            PreComparisonFrontierPartition::CollapseDominated,
            ComparisonSearchResourceFilter::CurrentEvaluatorMaterial,
        )
    }

    fn generate_comparison_search_states_with_partition(
        topology: JointTopologyCandidate,
        comparison: &SymbolicPackedRankComparison,
        counts: &mut SearchPruningCounts,
        partition: PreComparisonFrontierPartition,
        resource_filter: ComparisonSearchResourceFilter,
    ) -> crate::encoding::CanonicalResult<Vec<CachedPowerDagSearchState>> {
        let working_level = comparison
            .comparison_inputs
            .data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| super::invalid_recurrence("evaluator data basis is empty"))?;
        let total_drop_range = joint_search_total_drop_range(working_level)?;
        let mut states_by_pre_and_total =
            BTreeMap::<(usize, usize), NondominatedSearchFrontier>::new();
        for pre_comparison_drop_count in 0..=*total_drop_range.end() {
            if resource_filter == ComparisonSearchResourceFilter::CurrentEvaluatorMaterial
                && !topology_pre_comparison_drop_meets_stream_bound(
                    topology,
                    &comparison.comparison_inputs.data_primes,
                    pre_comparison_drop_count,
                )?
            {
                counts.resource_rejected_prefix_count += 1;
                for total_drop_count in total_drop_range.clone() {
                    let Some(remaining_drop_count) =
                        total_drop_count.checked_sub(pre_comparison_drop_count)
                    else {
                        continue;
                    };
                    *counts
                        .resource_rejected_complete_schedule_counts
                        .entry(total_drop_count)
                        .or_default() += weak_composition_count(
                        JOINT_SEARCH_VARIABLE_COUNT - 1,
                        remaining_drop_count,
                    );
                }
                continue;
            }
            let comparison_input_level = working_level
                .checked_sub(pre_comparison_drop_count)
                .ok_or_else(|| super::invalid_recurrence("comparison pre-drop exceeds level"))?;
            let refreshed_comparison_inputs = comparison
                .comparison_inputs
                .modulus_switch_to(comparison_input_level)?;
            let prepared_powers = initialize_partial_power_dag(
                &refreshed_comparison_inputs,
                comparison.greater_or_equal_polynomial.len(),
                comparison.baby_step_count,
                working_level,
            )?;
            let (evaluator_instruction_count, active_data_limb_instruction_units) =
                pre_comparison_work(working_level, pre_comparison_drop_count);
            let state = PowerDagSearchState {
                prepared_powers,
                packed_ranks: None,
                working_level,
                pre_comparison_drop_count,
                comparison_depth_drop_counts: [0; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
                rank_depth_drop_counts: [0; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
                assigned_variable_count: 1,
                consumed_drop_count: pre_comparison_drop_count,
                evaluator_instruction_count,
                active_data_limb_instruction_units,
            };
            counts.generated_prefix_count += 1;
            if prefix_can_reach_selected_target_level(
                state.working_level,
                state.assigned_variable_count,
                state.consumed_drop_count,
            ) {
                states_by_pre_and_total
                    .entry(search_frontier_key(partition, &state))
                    .or_default()
                    .insert(state, counts)?;
            }
        }

        for comparison_depth in 0..COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT {
            let mut next_states_by_pre_and_total =
                BTreeMap::<(usize, usize), NondominatedSearchFrontier>::new();
            for frontier in states_by_pre_and_total.into_values() {
                for cached_state in frontier.into_cached_states() {
                    let maximum_modulus_drop_count =
                        *joint_search_total_drop_range(cached_state.state.working_level)?.end()
                            - cached_state.state.consumed_drop_count;
                    let minimum_modulus_drop_count =
                        minimum_next_modulus_drop_count(&cached_state.state);
                    let prepared_branches = prepare_power_dag_depth_branches(
                        &cached_state.state.prepared_powers,
                        comparison_depth + 1,
                        minimum_modulus_drop_count,
                        maximum_modulus_drop_count,
                    )?;
                    let prepared_branch_count = prepared_branches.len();
                    let CachedPowerDagSearchState {
                        state: parent_state,
                        dominance_key: parent_dominance_key,
                    } = cached_state;
                    let mut reusable_state = Some(parent_state);
                    let mut sibling_dominance_key = Some(parent_dominance_key);
                    for _ in 0..minimum_modulus_drop_count {
                        sibling_dominance_key
                            .as_mut()
                            .expect("comparison siblings retain their dominance cursor")
                            .lower_existing_bounds_once()?;
                    }
                    for (branch_index, prepared_branch) in prepared_branches.into_iter().enumerate()
                    {
                        let modulus_drop_count = prepared_branch.modulus_drop_count;
                        let is_final_branch = branch_index + 1 == prepared_branch_count;
                        let mut candidate_state = if is_final_branch {
                            reusable_state
                                .take()
                                .expect("final branch owns its search state")
                        } else {
                            reusable_state
                                .as_ref()
                                .expect("earlier branches retain their search state")
                                .clone()
                        };
                        candidate_state.assigned_variable_count += 1;
                        candidate_state.consumed_drop_count += modulus_drop_count;
                        if !prefix_can_reach_selected_target_level(
                            candidate_state.working_level,
                            candidate_state.assigned_variable_count,
                            candidate_state.consumed_drop_count,
                        ) {
                            return Err(super::invalid_recurrence(
                                "prepared comparison branch cannot reach a selected target level",
                            ));
                        }
                        candidate_state.comparison_depth_drop_counts[comparison_depth] =
                            modulus_drop_count;
                        let (instruction_count, limb_units) =
                            apply_prepared_power_dag_depth_branch(
                                &mut candidate_state.prepared_powers,
                                prepared_branch,
                            )?;
                        candidate_state.evaluator_instruction_count = candidate_state
                            .evaluator_instruction_count
                            .checked_add(instruction_count)
                            .expect("selected evaluator instruction count fits u64");
                        candidate_state.active_data_limb_instruction_units = candidate_state
                            .active_data_limb_instruction_units
                            .checked_add(limb_units)
                            .expect("selected evaluator limb work fits u64");
                        counts.generated_prefix_count += 1;
                        if !record_nonpositive_candidate(&candidate_state, counts) {
                            let dominance_key = if is_final_branch {
                                sibling_dominance_key
                                    .take()
                                    .expect("final comparison branch owns its dominance key")
                            } else {
                                sibling_dominance_key
                                    .as_ref()
                                    .expect("comparison siblings retain their dominance key")
                                    .clone()
                            };
                            let mut candidate = CachedPowerDagSearchState {
                                state: candidate_state,
                                dominance_key,
                            };
                            candidate.finish_dominance_key_transition()?;
                            next_states_by_pre_and_total
                                .entry(search_frontier_key(partition, &candidate.state))
                                .or_default()
                                .insert_positive_cached(candidate, counts)?;
                        }
                        if !is_final_branch {
                            sibling_dominance_key
                                .as_mut()
                                .expect("comparison siblings retain their dominance cursor")
                                .lower_existing_bounds_once()?;
                        }
                    }
                }
            }
            states_by_pre_and_total = next_states_by_pre_and_total;
        }

        let mut rank_input_states_by_pre_and_total =
            BTreeMap::<(usize, usize), NondominatedSearchFrontier>::new();
        for frontier in states_by_pre_and_total.into_values() {
            for cached_state in frontier.into_cached_states() {
                let mut state = cached_state.state;
                if !partial_power_dag_is_complete(&state.prepared_powers) {
                    return Err(super::invalid_recurrence(
                        "comparison search ended with an incomplete power DAG",
                    ));
                }
                let comparison_outputs = symbolic_evaluate_polynomial_from_prepared_powers(
                    &state.prepared_powers,
                    &comparison.greater_or_equal_polynomial,
                )?;
                let comparison_output_level = state
                    .working_level
                    .checked_sub(state.consumed_drop_count)
                    .ok_or_else(|| {
                        super::invalid_recurrence("comparison search consumed too many levels")
                    })?;
                if comparison_outputs.level != comparison_output_level {
                    return Err(super::invalid_recurrence(
                        "comparison search reached an inconsistent output level",
                    ));
                }
                let packed_ranks = match resource_filter {
                    ComparisonSearchResourceFilter::CurrentEvaluatorMaterial => {
                        symbolic_finish_packed_rank_evaluation(
                            &comparison_outputs,
                            20,
                            comparison_output_level,
                            &comparison.pair_windows,
                        )?
                    }
                    ComparisonSearchResourceFilter::MeasurePairwiseMaterialAfterComparison => {
                        super::symbolic_finish_pairwise_ballot_rank_evaluation(
                            &comparison_outputs,
                            20,
                            comparison_output_level,
                            &comparison.pair_windows,
                        )?
                    }
                };
                let normalized_rank = packed_ranks
                    .modulus_switch_to(state.working_level)?
                    .normalize_scaling()?;
                state.prepared_powers = initialize_partial_power_dag(
                    &normalized_rank,
                    20,
                    RANK_LOOKUP_BABY_STEP_COUNT,
                    state.working_level,
                )?;
                state.packed_ranks = Some(packed_ranks);
                let cached_state = CachedPowerDagSearchState::from_state(state)?;
                rank_input_states_by_pre_and_total
                    .entry(search_frontier_key(partition, &cached_state.state))
                    .or_default()
                    .insert_cached(cached_state, counts)?;
            }
        }
        Ok(rank_input_states_by_pre_and_total
            .into_values()
            .flat_map(NondominatedSearchFrontier::into_cached_states)
            .collect())
    }

    fn generate_complete_rank_search_states(
        comparison_states: Vec<CachedPowerDagSearchState>,
        counts: &mut SearchPruningCounts,
    ) -> crate::encoding::CanonicalResult<Vec<PowerDagSearchState>> {
        generate_complete_rank_search_states_with_partition(
            comparison_states,
            counts,
            PreComparisonFrontierPartition::CollapseDominated,
        )
    }

    fn generate_complete_rank_search_states_with_partition(
        comparison_states: Vec<CachedPowerDagSearchState>,
        counts: &mut SearchPruningCounts,
        partition: PreComparisonFrontierPartition,
    ) -> crate::encoding::CanonicalResult<Vec<PowerDagSearchState>> {
        let mut states_by_pre_and_total =
            BTreeMap::<(usize, usize), NondominatedSearchFrontier>::new();
        for cached_state in comparison_states {
            states_by_pre_and_total
                .entry(search_frontier_key(partition, &cached_state.state))
                .or_default()
                .push_known_nondominated_cached(cached_state);
        }
        for rank_depth in 0..RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT {
            let mut next_states_by_pre_and_total =
                BTreeMap::<(usize, usize), NondominatedSearchFrontier>::new();
            for frontier in states_by_pre_and_total.into_values() {
                for cached_state in frontier.into_cached_states() {
                    let maximum_modulus_drop_count =
                        *joint_search_total_drop_range(cached_state.state.working_level)?.end()
                            - cached_state.state.consumed_drop_count;
                    let minimum_modulus_drop_count =
                        minimum_next_modulus_drop_count(&cached_state.state);
                    let prepared_branches = prepare_power_dag_depth_branches(
                        &cached_state.state.prepared_powers,
                        rank_depth + 1,
                        minimum_modulus_drop_count,
                        maximum_modulus_drop_count,
                    )?;
                    let prepared_branch_count = prepared_branches.len();
                    let CachedPowerDagSearchState {
                        state: parent_state,
                        dominance_key: parent_dominance_key,
                    } = cached_state;
                    let mut reusable_state = Some(parent_state);
                    let mut sibling_dominance_key = Some(parent_dominance_key);
                    for _ in 0..minimum_modulus_drop_count {
                        sibling_dominance_key
                            .as_mut()
                            .expect("rank siblings retain their dominance cursor")
                            .lower_existing_bounds_once()?;
                    }
                    for (branch_index, prepared_branch) in prepared_branches.into_iter().enumerate()
                    {
                        let modulus_drop_count = prepared_branch.modulus_drop_count;
                        let is_final_branch = branch_index + 1 == prepared_branch_count;
                        let mut candidate_state = if is_final_branch {
                            reusable_state
                                .take()
                                .expect("final branch owns its search state")
                        } else {
                            reusable_state
                                .as_ref()
                                .expect("earlier branches retain their search state")
                                .clone()
                        };
                        candidate_state.assigned_variable_count += 1;
                        candidate_state.consumed_drop_count += modulus_drop_count;
                        if !prefix_can_reach_selected_target_level(
                            candidate_state.working_level,
                            candidate_state.assigned_variable_count,
                            candidate_state.consumed_drop_count,
                        ) {
                            return Err(super::invalid_recurrence(
                                "prepared rank branch cannot reach a selected target level",
                            ));
                        }
                        candidate_state.rank_depth_drop_counts[rank_depth] = modulus_drop_count;
                        let (instruction_count, limb_units) =
                            apply_prepared_power_dag_depth_branch(
                                &mut candidate_state.prepared_powers,
                                prepared_branch,
                            )?;
                        candidate_state.evaluator_instruction_count = candidate_state
                            .evaluator_instruction_count
                            .checked_add(instruction_count)
                            .expect("selected evaluator instruction count fits u64");
                        candidate_state.active_data_limb_instruction_units = candidate_state
                            .active_data_limb_instruction_units
                            .checked_add(limb_units)
                            .expect("selected evaluator limb work fits u64");
                        counts.generated_prefix_count += 1;
                        if !record_nonpositive_candidate(&candidate_state, counts) {
                            let dominance_key = if is_final_branch {
                                sibling_dominance_key
                                    .take()
                                    .expect("final rank branch owns its dominance key")
                            } else {
                                sibling_dominance_key
                                    .as_ref()
                                    .expect("rank siblings retain their dominance key")
                                    .clone()
                            };
                            let mut candidate = CachedPowerDagSearchState {
                                state: candidate_state,
                                dominance_key,
                            };
                            candidate.finish_dominance_key_transition()?;
                            next_states_by_pre_and_total
                                .entry(search_frontier_key(partition, &candidate.state))
                                .or_default()
                                .insert_positive_cached(candidate, counts)?;
                        }
                        if !is_final_branch {
                            sibling_dominance_key
                                .as_mut()
                                .expect("rank siblings retain their dominance cursor")
                                .lower_existing_bounds_once()?;
                        }
                    }
                }
            }
            states_by_pre_and_total = next_states_by_pre_and_total;
        }
        Ok(states_by_pre_and_total
            .into_values()
            .flat_map(NondominatedSearchFrontier::into_cached_states)
            .map(|cached_state| cached_state.state)
            .collect())
    }

    fn replay_complete_joint_search_state(
        topology: JointTopologyCandidate,
        comparison: &SymbolicPackedRankComparison,
        schedule: EvaluatorModulusSchedule,
    ) -> crate::encoding::CanonicalResult<PowerDagSearchState> {
        let working_level = comparison
            .comparison_inputs
            .data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| super::invalid_recurrence("evaluator data basis is empty"))?;
        if !joint_search_total_drop_range(working_level)?.contains(&schedule.total_drop_count())
            || !topology_pre_comparison_drop_meets_stream_bound(
                topology,
                &comparison.comparison_inputs.data_primes,
                schedule.pre_comparison_drop_count,
            )?
        {
            return Err(super::invalid_recurrence(
                "checkpointed joint evaluator schedule is outside the exact search range",
            ));
        }
        let comparison_input_level = working_level
            .checked_sub(schedule.pre_comparison_drop_count)
            .ok_or_else(|| super::invalid_recurrence("comparison pre-drop exceeds level"))?;
        let refreshed_comparison_inputs = comparison
            .comparison_inputs
            .modulus_switch_to(comparison_input_level)?;
        let (evaluator_instruction_count, active_data_limb_instruction_units) =
            pre_comparison_work(working_level, schedule.pre_comparison_drop_count);
        let mut state = PowerDagSearchState {
            prepared_powers: initialize_partial_power_dag(
                &refreshed_comparison_inputs,
                comparison.greater_or_equal_polynomial.len(),
                comparison.baby_step_count,
                working_level,
            )?,
            packed_ranks: None,
            working_level,
            pre_comparison_drop_count: schedule.pre_comparison_drop_count,
            comparison_depth_drop_counts: schedule.comparison_depth_drop_counts,
            rank_depth_drop_counts: schedule.rank_depth_drop_counts,
            assigned_variable_count: 1,
            consumed_drop_count: schedule.pre_comparison_drop_count,
            evaluator_instruction_count,
            active_data_limb_instruction_units,
        };
        for (comparison_depth, modulus_drop_count) in schedule
            .comparison_depth_drop_counts
            .into_iter()
            .enumerate()
        {
            state.assigned_variable_count += 1;
            state.consumed_drop_count += modulus_drop_count;
            let (instruction_count, limb_units) = extend_partial_power_dag_at_depth(
                &mut state.prepared_powers,
                comparison_depth + 1,
                modulus_drop_count,
            )?;
            state.evaluator_instruction_count += instruction_count;
            state.active_data_limb_instruction_units += limb_units;
        }
        if !partial_power_dag_is_complete(&state.prepared_powers) {
            return Err(super::invalid_recurrence(
                "checkpointed comparison schedule produced an incomplete power DAG",
            ));
        }
        let comparison_outputs = symbolic_evaluate_polynomial_from_prepared_powers(
            &state.prepared_powers,
            &comparison.greater_or_equal_polynomial,
        )?;
        let comparison_output_level = working_level
            .checked_sub(state.consumed_drop_count)
            .ok_or_else(|| {
                super::invalid_recurrence("comparison schedule consumed too many levels")
            })?;
        let packed_ranks = symbolic_finish_packed_rank_evaluation(
            &comparison_outputs,
            20,
            comparison_output_level,
            &comparison.pair_windows,
        )?;
        let normalized_rank = packed_ranks
            .modulus_switch_to(working_level)?
            .normalize_scaling()?;
        state.prepared_powers = initialize_partial_power_dag(
            &normalized_rank,
            20,
            RANK_LOOKUP_BABY_STEP_COUNT,
            working_level,
        )?;
        state.packed_ranks = Some(packed_ranks);
        for (rank_depth, modulus_drop_count) in
            schedule.rank_depth_drop_counts.into_iter().enumerate()
        {
            state.assigned_variable_count += 1;
            state.consumed_drop_count += modulus_drop_count;
            let (instruction_count, limb_units) = extend_partial_power_dag_at_depth(
                &mut state.prepared_powers,
                rank_depth + 1,
                modulus_drop_count,
            )?;
            state.evaluator_instruction_count += instruction_count;
            state.active_data_limb_instruction_units += limb_units;
        }
        if state.assigned_variable_count != JOINT_SEARCH_VARIABLE_COUNT
            || state.consumed_drop_count != schedule.total_drop_count()
            || !partial_power_dag_is_complete(&state.prepared_powers)
            || !every_operative_margin_is_positive(&state)
        {
            return Err(super::invalid_recurrence(
                "checkpointed joint evaluator schedule does not replay as a retained complete state",
            ));
        }
        Ok(state)
    }

    fn measure_complete_joint_search_state(
        topology: JointTopologyCandidate,
        prime_order: &PrimeOrderCandidate,
        data_primes: &[u64],
        state: &PowerDagSearchState,
        factor_four_maximum_error_bound: &BigUint,
    ) -> crate::encoding::CanonicalResult<JointSearchMeasurement> {
        if state.assigned_variable_count != JOINT_SEARCH_VARIABLE_COUNT
            || !partial_power_dag_is_complete(&state.prepared_powers)
        {
            return Err(super::invalid_recurrence(
                "joint search measurement received an incomplete schedule",
            ));
        }
        let working_level = data_primes
            .len()
            .checked_sub(1)
            .ok_or_else(|| super::invalid_recurrence("evaluator data basis is empty"))?;
        if state.working_level != working_level {
            return Err(super::invalid_recurrence(
                "joint search state does not match its data-prime prefix",
            ));
        }
        let target_level = state
            .working_level
            .checked_sub(state.consumed_drop_count)
            .ok_or_else(|| super::invalid_recurrence("joint search consumed too many levels"))?;
        let packed_ranks = state
            .packed_ranks
            .as_ref()
            .ok_or_else(|| super::invalid_recurrence("joint search is missing packed ranks"))?;
        let target_bounds = (1..=20)
            .map(|top_count| {
                symbolic_sparse_target_projection(
                    packed_ranks,
                    20,
                    top_count,
                    &state.prepared_powers,
                    target_level,
                )
            })
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;
        let maximum_error_bound = target_bounds
            .iter()
            .flat_map(|(target_identifier, target_order)| {
                [
                    &target_identifier.error_coefficient_bound,
                    &target_order.error_coefficient_bound,
                ]
            })
            .max()
            .cloned()
            .expect("selected evaluator has target bounds");
        let minimum_margin = target_bounds
            .iter()
            .flat_map(|(target_identifier, target_order)| {
                [
                    target_identifier.minimum_decryption_margin.clone(),
                    target_order.minimum_decryption_margin.clone(),
                    target_identifier.final_decryption_margin(),
                    target_order.final_decryption_margin(),
                ]
            })
            .min()
            .expect("selected evaluator has target margins");
        let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)?;
        let factor_four_conditions_hold = ensure_factor_four_parameter_conditions_with_data_primes(
            target_level,
            &maximum_error_bound,
            &flooding_bound,
            data_primes,
        )
        .is_ok();
        let target_modulus = data_primes[..=target_level]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
        let scaled_c2_left = &plaintext_modulus
            * ((&maximum_error_bound << 4_usize)
                + &plaintext_modulus * BigUint::from(5_u8)
                + &flooding_bound * BigUint::from(16_u64 * 44));
        let factor_four_c2_margin =
            BigInt::from(target_modulus << 1_usize) - BigInt::from(scaled_c2_left);
        let relinearization_level = state
            .working_level
            .checked_sub(state.pre_comparison_drop_count)
            .ok_or_else(|| super::invalid_recurrence("relinearization level underflowed"))?;
        let special_primes = &SPECIAL_PRIMES[..topology.special_prime_count];
        let (
            participant_source_wire_byte_length,
            final_evaluator_store_wire_byte_length,
            ceremony_evaluator_wire_byte_length,
        ) = evaluator_material_wire_byte_lengths(
            relinearization_level,
            data_primes,
            special_primes,
            topology.data_primes_per_block,
        )?;
        let (
            target_role_stream_byte_length,
            paired_target_stream_byte_length,
            target_ciphertext_resident_byte_length,
        ) = target_stream_byte_lengths(target_level);
        Ok(JointSearchMeasurement {
            topology_label: topology.label,
            prime_order_label: prime_order.label,
            data_prime_count: data_primes.len(),
            working_level,
            schedule: EvaluatorModulusSchedule {
                pre_comparison_drop_count: state.pre_comparison_drop_count,
                comparison_depth_drop_counts: state.comparison_depth_drop_counts,
                rank_depth_drop_counts: state.rank_depth_drop_counts,
            },
            target_level,
            relinearization_level,
            maximum_error_bound,
            minimum_margin,
            factor_four_maximum_error_bound: factor_four_maximum_error_bound.clone(),
            factor_four_c2_margin,
            factor_four_conditions_hold,
            evaluator_instruction_count: state.evaluator_instruction_count,
            active_data_limb_instruction_units: state.active_data_limb_instruction_units,
            participant_source_wire_byte_length,
            final_evaluator_store_wire_byte_length,
            ceremony_evaluator_wire_byte_length,
            target_role_stream_byte_length,
            paired_target_stream_byte_length,
            paired_target_stream_requires_independent_chunks: paired_target_stream_byte_length
                > u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                    .expect("copied-buffer bound fits u64"),
            target_ciphertext_resident_byte_length,
            full_qp_log2: modulus_log2(data_primes) + modulus_log2(special_primes),
            security_comparison_allows_finalist: topology.security_comparison_allows_finalist,
        })
    }

    fn joint_measurement_dominates(
        left: &JointSearchMeasurement,
        right: &JointSearchMeasurement,
    ) -> bool {
        left.maximum_error_bound <= right.maximum_error_bound
            && left.minimum_margin >= right.minimum_margin
            && left.evaluator_instruction_count <= right.evaluator_instruction_count
            && left.active_data_limb_instruction_units <= right.active_data_limb_instruction_units
            && left.ceremony_evaluator_wire_byte_length <= right.ceremony_evaluator_wire_byte_length
            && left.target_role_stream_byte_length <= right.target_role_stream_byte_length
            && left.target_ciphertext_resident_byte_length
                <= right.target_ciphertext_resident_byte_length
            && left.full_qp_log2 <= right.full_qp_log2
            && (left.maximum_error_bound < right.maximum_error_bound
                || left.minimum_margin > right.minimum_margin
                || left.evaluator_instruction_count < right.evaluator_instruction_count
                || left.active_data_limb_instruction_units
                    < right.active_data_limb_instruction_units
                || left.ceremony_evaluator_wire_byte_length
                    < right.ceremony_evaluator_wire_byte_length
                || left.target_role_stream_byte_length < right.target_role_stream_byte_length
                || left.target_ciphertext_resident_byte_length
                    < right.target_ciphertext_resident_byte_length
                || left.full_qp_log2 < right.full_qp_log2)
    }

    fn joint_measurement_is_finalist(measurement: &JointSearchMeasurement) -> bool {
        measurement.minimum_margin.is_positive()
            && measurement.factor_four_conditions_hold
            && measurement.security_comparison_allows_finalist
            && measurement.ceremony_evaluator_wire_byte_length
                <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
            && measurement.target_role_stream_byte_length
                <= u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                    .expect("copied-buffer bound fits u64")
    }

    #[derive(Debug, Default)]
    struct JointMeasurementAccumulator {
        comparison_measurements:
            BTreeMap<(&'static str, &'static str, usize, usize), JointSearchMeasurement>,
        pareto_measurements: Vec<JointSearchMeasurement>,
        finalist_measurement_count: u128,
    }

    impl JointMeasurementAccumulator {
        fn observe(&mut self, measurement: JointSearchMeasurement) {
            let comparison_key = (
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.target_level,
            );
            let replaces_comparison = self
                .comparison_measurements
                .get(&comparison_key)
                .is_none_or(|current| {
                    measurement.maximum_error_bound < current.maximum_error_bound
                        || (measurement.maximum_error_bound == current.maximum_error_bound
                            && measurement.active_data_limb_instruction_units
                                < current.active_data_limb_instruction_units)
                });
            if replaces_comparison {
                self.comparison_measurements
                    .insert(comparison_key, measurement.clone());
            }

            if !joint_measurement_is_finalist(&measurement) {
                return;
            }
            self.finalist_measurement_count += 1;
            if self
                .pareto_measurements
                .iter()
                .any(|existing| joint_measurement_dominates(existing, &measurement))
            {
                return;
            }
            self.pareto_measurements
                .retain(|existing| !joint_measurement_dominates(&measurement, existing));
            self.pareto_measurements.push(measurement);
        }

        fn into_parts(
            self,
        ) -> (
            BTreeMap<(&'static str, &'static str, usize, usize), JointSearchMeasurement>,
            Vec<JointSearchMeasurement>,
            u128,
        ) {
            (
                self.comparison_measurements,
                self.pareto_measurements,
                self.finalist_measurement_count,
            )
        }
    }

    fn first_failed_joint_measurement_constraint(
        measurement: &JointSearchMeasurement,
    ) -> Option<&'static str> {
        if !measurement.minimum_margin.is_positive() {
            return Some("operative-decryption-margin");
        }
        if !measurement.factor_four_conditions_hold {
            return Some("factor-four-release");
        }
        if measurement.ceremony_evaluator_wire_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH {
            return Some("canonical-stream-bound");
        }
        if measurement.target_role_stream_byte_length
            > u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .expect("copied-buffer bound fits u64")
        {
            return Some("independent-target-role-buffer");
        }
        if !measurement.security_comparison_allows_finalist {
            return Some("security-comparison");
        }
        None
    }

    fn print_joint_measurement(label: &str, measurement: &JointSearchMeasurement) {
        println!(
            "{} topology={} primeOrder={} dataPrimeCount={} galoisLevel={} rkgLevel={} kllpsTargetLevel={} pre={} comparison={:?} rank={:?} error={} errorBits={} minimumMargin={} factorFourMaximum={} factorFourC2Margin={} factorFour={} instructions={} activeLimbUnits={} participantSourceBytes={} finalStoreBytes={} ceremonyBytes={} streamBound={} targetRoleBytes={} targetRoleFits={} pairedTargetBytes={} independentRoleChunks={} targetResidentBytes={} fullQpLog2={:.6} securityComparisonFinalist={}",
            label,
            measurement.topology_label,
            measurement.prime_order_label,
            measurement.data_prime_count,
            measurement.working_level,
            measurement.relinearization_level,
            measurement.target_level,
            measurement.schedule.pre_comparison_drop_count,
            measurement.schedule.comparison_depth_drop_counts,
            measurement.schedule.rank_depth_drop_counts,
            measurement.maximum_error_bound,
            measurement.maximum_error_bound.bits(),
            measurement.minimum_margin,
            measurement.factor_four_maximum_error_bound,
            measurement.factor_four_c2_margin,
            measurement.factor_four_conditions_hold,
            measurement.evaluator_instruction_count,
            measurement.active_data_limb_instruction_units,
            measurement.participant_source_wire_byte_length,
            measurement.final_evaluator_store_wire_byte_length,
            measurement.ceremony_evaluator_wire_byte_length,
            measurement.ceremony_evaluator_wire_byte_length <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
            measurement.target_role_stream_byte_length,
            measurement.target_role_stream_byte_length
                <= u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                    .expect("copied-buffer bound fits u64"),
            measurement.paired_target_stream_byte_length,
            measurement.paired_target_stream_requires_independent_chunks,
            measurement.target_ciphertext_resident_byte_length,
            measurement.full_qp_log2,
            measurement.security_comparison_allows_finalist,
        );
    }

    fn schedule_from_search_state(state: &PowerDagSearchState) -> EvaluatorModulusSchedule {
        EvaluatorModulusSchedule {
            pre_comparison_drop_count: state.pre_comparison_drop_count,
            comparison_depth_drop_counts: state.comparison_depth_drop_counts,
            rank_depth_drop_counts: state.rank_depth_drop_counts,
        }
    }

    fn validate_joint_search_classification(
        working_level: usize,
        counts: &SearchPruningCounts,
        retained_schedules: &[JointSearchScheduleCheckpoint],
    ) -> crate::encoding::CanonicalResult<()> {
        if !retained_schedules
            .windows(2)
            .all(|window| window[0] < window[1])
        {
            return Err(super::invalid_recurrence(
                "joint evaluator search checkpoint schedules are not strictly canonical",
            ));
        }
        let expected_evaluated_counts = retained_schedules.iter().fold(
            BTreeMap::<usize, u128>::new(),
            |mut evaluated_counts, schedule| {
                *evaluated_counts
                    .entry(EvaluatorModulusSchedule::from(*schedule).total_drop_count())
                    .or_default() += 1;
                evaluated_counts
            },
        );
        if counts.evaluated_complete_schedule_counts != expected_evaluated_counts {
            return Err(super::invalid_recurrence(
                "joint evaluator search checkpoint evaluated-count map does not match its schedules",
            ));
        }
        let total_drop_range = joint_search_total_drop_range(working_level)?;
        let every_recorded_total_is_selected = [
            &counts.resource_rejected_complete_schedule_counts,
            &counts.negative_margin_complete_schedule_counts,
            &counts.dominated_complete_schedule_counts,
            &counts.evaluated_complete_schedule_counts,
        ]
        .into_iter()
        .flat_map(|count_map| count_map.keys())
        .all(|total_drop_count| total_drop_range.contains(total_drop_count));
        if !every_recorded_total_is_selected {
            return Err(super::invalid_recurrence(
                "joint evaluator search checkpoint contains an out-of-range schedule count",
            ));
        }
        for total_drop_count in total_drop_range {
            let analytical_count =
                weak_composition_count(JOINT_SEARCH_VARIABLE_COUNT, total_drop_count);
            let classified_count = counts
                .resource_rejected_complete_schedule_counts
                .get(&total_drop_count)
                .copied()
                .unwrap_or_default()
                + counts
                    .negative_margin_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default()
                + counts
                    .dominated_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default()
                + counts
                    .evaluated_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default();
            if classified_count != analytical_count {
                return Err(super::invalid_recurrence(format!(
                    "joint evaluator search checkpoint count identity failed for total drop count {total_drop_count}"
                )));
            }
        }
        Ok(())
    }

    fn measure_joint_search_states(
        topology: JointTopologyCandidate,
        prime_order: &PrimeOrderCandidate,
        data_primes: &[u64],
        states: &[PowerDagSearchState],
    ) -> crate::encoding::CanonicalResult<Vec<JointSearchMeasurement>> {
        let mut factor_four_maximum_error_bounds = BTreeMap::new();
        states
            .iter()
            .map(|state| {
                let target_level = state
                    .working_level
                    .checked_sub(state.consumed_drop_count)
                    .ok_or_else(|| {
                        super::invalid_recurrence(
                            "complete joint evaluator search state consumed too many levels",
                        )
                    })?;
                let factor_four_maximum_error_bound = factor_four_maximum_error_bounds
                    .entry(target_level)
                    .or_insert_with(|| {
                        factor_four_maximum_evaluator_error_bound(target_level, data_primes)
                    });
                measure_complete_joint_search_state(
                    topology,
                    prime_order,
                    data_primes,
                    state,
                    factor_four_maximum_error_bound,
                )
            })
            .collect()
    }

    fn execute_bounded_in_canonical_order<Task, Output, Work, Commit>(
        tasks: Vec<Task>,
        requested_worker_count: usize,
        requested_reorder_window: usize,
        work: Work,
        mut commit: Commit,
    ) -> crate::encoding::CanonicalResult<()>
    where
        Task: Send,
        Output: Send,
        Work: Fn(Task) -> crate::encoding::CanonicalResult<Output> + Sync,
        Commit: FnMut(Output) -> crate::encoding::CanonicalResult<()>,
    {
        if tasks.is_empty() {
            return Ok(());
        }
        if requested_worker_count == 0 || requested_reorder_window == 0 {
            return Err(super::invalid_recurrence(
                "bounded canonical executor requires a positive worker count and reorder window",
            ));
        }
        let task_count = tasks.len();
        let worker_count = requested_worker_count.min(task_count);
        let reorder_window = requested_reorder_window.max(worker_count).min(task_count);
        let cancellation_requested = AtomicBool::new(false);
        let (task_sender, task_receiver) = mpsc::channel::<(usize, Task)>();
        let task_receiver = Mutex::new(task_receiver);
        let (result_sender, result_receiver) =
            mpsc::channel::<(usize, crate::encoding::CanonicalResult<Output>)>();

        thread::scope(|scope| {
            for _ in 0..worker_count {
                let task_receiver = &task_receiver;
                let result_sender = result_sender.clone();
                let cancellation_requested = &cancellation_requested;
                let work = &work;
                scope.spawn(move || {
                    loop {
                        let task = task_receiver
                            .lock()
                            .expect("joint search task receiver mutex is not poisoned")
                            .recv();
                        let Ok((task_index, task)) = task else {
                            break;
                        };
                        if cancellation_requested.load(Ordering::Acquire) {
                            break;
                        }
                        let result = work(task);
                        if result.is_err() {
                            cancellation_requested.store(true, Ordering::Release);
                        }
                        if result_sender.send((task_index, result)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(result_sender);

            let mut indexed_tasks = tasks.into_iter().enumerate();
            let mut dispatched_task_count = 0_usize;
            for _ in 0..reorder_window {
                let (task_index, task) = indexed_tasks
                    .next()
                    .expect("reorder window is bounded by the task count");
                task_sender.send((task_index, task)).map_err(|_| {
                    super::invalid_recurrence(
                        "bounded canonical executor lost every worker before dispatch",
                    )
                })?;
                dispatched_task_count += 1;
            }

            let mut next_commit_index = 0_usize;
            let mut pending_results = BTreeMap::new();
            let mut failure_observed = false;
            while next_commit_index < task_count {
                let (task_index, result) = match result_receiver.recv() {
                    Ok(result) => result,
                    Err(_) => {
                        cancellation_requested.store(true, Ordering::Release);
                        return Err(super::invalid_recurrence(
                            "bounded canonical executor lost every worker before completion",
                        ));
                    }
                };
                if result.is_err() {
                    failure_observed = true;
                    cancellation_requested.store(true, Ordering::Release);
                }
                if pending_results.insert(task_index, result).is_some() {
                    cancellation_requested.store(true, Ordering::Release);
                    return Err(super::invalid_recurrence(
                        "bounded canonical executor received a duplicate task result",
                    ));
                }

                while let Some(result) = pending_results.remove(&next_commit_index) {
                    let output = match result {
                        Ok(output) => output,
                        Err(error) => {
                            cancellation_requested.store(true, Ordering::Release);
                            return Err(error);
                        }
                    };
                    if let Err(error) = commit(output) {
                        cancellation_requested.store(true, Ordering::Release);
                        return Err(error);
                    }
                    next_commit_index += 1;
                }

                while !failure_observed
                    && dispatched_task_count < task_count
                    && dispatched_task_count - next_commit_index < reorder_window
                {
                    let (task_index, task) = indexed_tasks
                        .next()
                        .expect("undispatched task count matches the task iterator");
                    if task_sender.send((task_index, task)).is_err() {
                        cancellation_requested.store(true, Ordering::Release);
                        return Err(super::invalid_recurrence(
                            "bounded canonical executor lost every worker during dispatch",
                        ));
                    }
                    dispatched_task_count += 1;
                }
            }

            cancellation_requested.store(true, Ordering::Release);
            drop(task_sender);
            Ok(())
        })
    }

    fn compute_joint_search_triple(
        task: JointSearchTripleTask,
    ) -> crate::encoding::CanonicalResult<JointSearchTripleResult> {
        let JointSearchTripleTask {
            topology,
            prime_order,
            data_prime_count,
            checkpoint_binding,
            checkpoint_path,
        } = task;
        let data_primes = &prime_order.data_primes[..data_prime_count];
        let comparison = prepare_joint_comparison(topology, data_primes)?;

        if let Some(checkpoint_path) = checkpoint_path.as_deref()
            && let Some(checkpoint) =
                read_joint_search_checkpoint(checkpoint_path, &checkpoint_binding)?
        {
            let states = checkpoint
                .retained_schedules
                .iter()
                .map(|schedule| {
                    replay_complete_joint_search_state(
                        topology,
                        &comparison,
                        EvaluatorModulusSchedule::from(*schedule),
                    )
                })
                .collect::<crate::encoding::CanonicalResult<Vec<_>>>()?;
            let measurements =
                measure_joint_search_states(topology, &prime_order, data_primes, &states)?;
            return Ok(JointSearchTripleResult {
                topology,
                prime_order,
                data_prime_count,
                checkpoint_binding,
                checkpoint_install_path: None,
                pruning_counts: checkpoint.pruning_counts,
                retained_schedules: checkpoint.retained_schedules,
                measurements,
            });
        }

        let mut pruning_counts = SearchPruningCounts::default();
        let comparison_states =
            generate_comparison_search_states(topology, &comparison, &mut pruning_counts)?;
        let mut complete_states =
            generate_complete_rank_search_states(comparison_states, &mut pruning_counts)?;
        complete_states.sort_by_key(|state| {
            JointSearchScheduleCheckpoint::from(schedule_from_search_state(state))
        });
        let retained_schedules = complete_states
            .iter()
            .map(|state| {
                *pruning_counts
                    .evaluated_complete_schedule_counts
                    .entry(state.consumed_drop_count)
                    .or_default() += 1;
                JointSearchScheduleCheckpoint::from(schedule_from_search_state(state))
            })
            .collect::<Vec<_>>();
        let measurements =
            measure_joint_search_states(topology, &prime_order, data_primes, &complete_states)?;
        Ok(JointSearchTripleResult {
            topology,
            prime_order,
            data_prime_count,
            checkpoint_binding,
            checkpoint_install_path: checkpoint_path,
            pruning_counts,
            retained_schedules,
            measurements,
        })
    }

    fn joint_search_checkpoint_bytes(
        result: &JointSearchTripleResult,
    ) -> crate::encoding::CanonicalResult<Vec<u8>> {
        serde_json::to_vec(&JointSearchTripleCheckpoint {
            binding: result.checkpoint_binding.clone(),
            pruning_counts: result.pruning_counts.clone(),
            retained_schedules: result.retained_schedules.clone(),
        })
        .map_err(|error| {
            super::invalid_recurrence(format!(
                "joint evaluator search checkpoint encode failed: {error}"
            ))
        })
    }

    fn joint_search_classification_lines(
        result: &JointSearchTripleResult,
    ) -> crate::encoding::CanonicalResult<Vec<String>> {
        let working_level = result.data_prime_count - 1;
        joint_search_total_drop_range(working_level)?
            .map(|total_drop_count| {
                let analytical_count =
                    weak_composition_count(JOINT_SEARCH_VARIABLE_COUNT, total_drop_count);
                let resource_rejected_count = result
                    .pruning_counts
                    .resource_rejected_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default();
                let negative_margin_count = result
                    .pruning_counts
                    .negative_margin_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default();
                let dominated_count = result
                    .pruning_counts
                    .dominated_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default();
                let evaluated_count = result
                    .pruning_counts
                    .evaluated_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default();
                if analytical_count
                    != resource_rejected_count
                        + negative_margin_count
                        + dominated_count
                        + evaluated_count
                {
                    return Err(super::invalid_recurrence(
                        "joint evaluator search output count identity failed",
                    ));
                }
                Ok(format!(
                    "jointSearchCounts topology={} primeOrder={} dataPrimeCount={} workingLevel={} targetLevel={} analytical={} resourceRejected={} negativeMargin={} dominated={} evaluated={} generatedPrefixes={} resourcePrefixes={} negativePrefixes={} dominatedPrefixes={}",
                    result.topology.label,
                    result.prime_order.label,
                    result.data_prime_count,
                    working_level,
                    working_level - total_drop_count,
                    analytical_count,
                    resource_rejected_count,
                    negative_margin_count,
                    dominated_count,
                    evaluated_count,
                    result.pruning_counts.generated_prefix_count,
                    result.pruning_counts.resource_rejected_prefix_count,
                    result.pruning_counts.negative_margin_prefix_count,
                    result.pruning_counts.dominated_prefix_count,
                ))
            })
            .collect()
    }

    fn commit_joint_search_triple(
        mut result: JointSearchTripleResult,
        measurement_accumulator: &mut JointMeasurementAccumulator,
        print_classifications: bool,
    ) -> crate::encoding::CanonicalResult<()> {
        validate_joint_search_classification(
            result.data_prime_count - 1,
            &result.pruning_counts,
            &result.retained_schedules,
        )?;
        let classification_lines = joint_search_classification_lines(&result)?;
        if let Some(checkpoint_path) = result.checkpoint_install_path.as_deref() {
            write_joint_search_checkpoint(
                checkpoint_path,
                &JointSearchTripleCheckpoint {
                    binding: result.checkpoint_binding.clone(),
                    pruning_counts: result.pruning_counts.clone(),
                    retained_schedules: result.retained_schedules.clone(),
                },
            )?;
        }
        for measurement in result.measurements.drain(..) {
            measurement_accumulator.observe(measurement);
        }
        if print_classifications {
            for line in classification_lines {
                println!("{line}");
            }
        }
        Ok(())
    }

    #[test]
    fn prime_order_normalization_preserves_each_distinct_prefix_once() {
        let candidates = prime_order_candidates();
        assert_eq!(candidates[0].label, "current");
        assert_eq!(candidates[2].label, "smallest-drop-first");
        assert_eq!(candidates[0].data_primes, candidates[2].data_primes);
        assert_ne!(candidates[0].data_primes, candidates[1].data_primes);

        for data_prime_count in JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT..=DATA_PRIMES.len() {
            let unique_candidates = unique_prime_order_candidates_for_count(data_prime_count)
                .expect("candidate data-prime count");
            assert_eq!(unique_candidates.len(), 2);
            for candidate in &candidates {
                assert_eq!(
                    unique_candidates
                        .iter()
                        .filter(|unique| {
                            unique.data_primes[..data_prime_count]
                                == candidate.data_primes[..data_prime_count]
                        })
                        .count(),
                    1,
                    "each distinct prefix has exactly one search representative",
                );
            }
            for left_index in 0..unique_candidates.len() {
                for right_index in left_index + 1..unique_candidates.len() {
                    assert_ne!(
                        unique_candidates[left_index].data_primes[..data_prime_count],
                        unique_candidates[right_index].data_primes[..data_prime_count],
                    );
                }
            }
        }
    }

    #[test]
    fn joint_data_prime_candidate_range_covers_every_undominated_prefix() {
        assert_eq!(
            JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT,
            JOINT_SEARCH_MINIMUM_TARGET_LEVEL + 2,
        );
        for rejected_count in 0..JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT {
            assert!(unique_prime_order_candidates_for_count(rejected_count).is_err());
        }
        assert!(unique_prime_order_candidates_for_count(DATA_PRIMES.len() + 1).is_err());

        for data_prime_count in JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT..=DATA_PRIMES.len() {
            let working_level = data_prime_count - 1;
            let total_drop_range = joint_search_total_drop_range(working_level)
                .expect("candidate working level has a target range");
            let target_levels = total_drop_range
                .clone()
                .map(|total_drop_count| working_level - total_drop_count)
                .collect::<Vec<_>>();
            let expected_maximum_target_level =
                JOINT_SEARCH_MAXIMUM_TARGET_LEVEL.min(working_level - 1);
            assert_eq!(
                target_levels,
                (JOINT_SEARCH_MINIMUM_TARGET_LEVEL..=expected_maximum_target_level)
                    .rev()
                    .collect::<Vec<_>>(),
            );

            if data_prime_count < DATA_PRIMES.len() {
                for candidate in prime_order_candidates() {
                    assert!(
                        modulus_log2(&candidate.data_primes[..data_prime_count])
                            < modulus_log2(&candidate.data_primes[..=data_prime_count]),
                        "an unused suffix prime strictly worsens the full basis without changing the evaluator prefix",
                    );
                }
            }
        }

        let minimum_prefix_schedule = EvaluatorModulusSchedule {
            pre_comparison_drop_count: 1,
            comparison_depth_drop_counts: [0; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
            rank_depth_drop_counts: [0; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
        };
        let compiled_minimum_prefix = compile_candidate_evaluator_program_measurement(
            &minimum_prefix_schedule,
            JOINT_SEARCH_MINIMUM_TARGET_LEVEL,
            &DATA_PRIMES[..JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT],
        )
        .expect("minimum candidate prefix compiles at its own working level");
        assert!(compiled_minimum_prefix.minimum_instruction_count > 0);
        assert!(
            compiled_minimum_prefix.minimum_instruction_count
                <= compiled_minimum_prefix.maximum_instruction_count
        );
        assert!(
            compile_candidate_evaluator_program_measurement(
                &minimum_prefix_schedule,
                JOINT_SEARCH_MINIMUM_TARGET_LEVEL,
                &[],
            )
            .is_err(),
        );
        assert!(
            compile_candidate_evaluator_program_measurement(
                &minimum_prefix_schedule,
                JOINT_SEARCH_MINIMUM_TARGET_LEVEL,
                &DATA_PRIMES,
            )
            .is_err(),
            "the candidate compiler must derive its level budget from the supplied prefix",
        );
    }

    #[test]
    fn streamed_measurement_reduction_matches_batch_reference_exactly() {
        let baseline = JointSearchMeasurement {
            topology_label: "P6/B6",
            prime_order_label: "current",
            data_prime_count: DATA_PRIMES.len(),
            working_level: SELECTED_EVALUATOR_WORKING_LEVEL,
            schedule: EvaluatorModulusSchedule {
                pre_comparison_drop_count: 0,
                comparison_depth_drop_counts: [0; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
                rank_depth_drop_counts: [0; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
            },
            target_level: 5,
            relinearization_level: 10,
            maximum_error_bound: BigUint::from(10_u8),
            minimum_margin: BigInt::from(100_u8),
            factor_four_maximum_error_bound: BigUint::from(40_u8),
            factor_four_c2_margin: BigInt::from(100_u8),
            factor_four_conditions_hold: true,
            evaluator_instruction_count: 100,
            active_data_limb_instruction_units: 100,
            participant_source_wire_byte_length: 10,
            final_evaluator_store_wire_byte_length: 10,
            ceremony_evaluator_wire_byte_length: 100,
            target_role_stream_byte_length: 100,
            paired_target_stream_byte_length: 200,
            paired_target_stream_requires_independent_chunks: false,
            target_ciphertext_resident_byte_length: 100,
            full_qp_log2: 100.0,
            security_comparison_allows_finalist: true,
        };
        let mut error_tradeoff = baseline.clone();
        error_tradeoff.schedule.pre_comparison_drop_count = 1;
        error_tradeoff.maximum_error_bound = BigUint::from(9_u8);
        error_tradeoff.minimum_margin = BigInt::from(90_u8);
        error_tradeoff.evaluator_instruction_count = 110;
        error_tradeoff.active_data_limb_instruction_units = 110;

        let mut dominated = baseline.clone();
        dominated.schedule.pre_comparison_drop_count = 2;
        dominated.maximum_error_bound = BigUint::from(11_u8);
        dominated.minimum_margin = BigInt::from(90_u8);
        dominated.evaluator_instruction_count = 120;
        dominated.active_data_limb_instruction_units = 120;

        let mut superior = baseline.clone();
        superior.schedule.pre_comparison_drop_count = 3;
        superior.maximum_error_bound = BigUint::from(8_u8);
        superior.minimum_margin = BigInt::from(120_u8);
        superior.evaluator_instruction_count = 80;
        superior.active_data_limb_instruction_units = 80;
        superior.ceremony_evaluator_wire_byte_length = 80;
        superior.target_role_stream_byte_length = 80;
        superior.target_ciphertext_resident_byte_length = 80;
        superior.full_qp_log2 = 80.0;

        let superior_duplicate = superior.clone();
        let mut instruction_tradeoff = superior.clone();
        instruction_tradeoff.schedule.pre_comparison_drop_count = 4;
        instruction_tradeoff.maximum_error_bound = BigUint::from(7_u8);
        instruction_tradeoff.minimum_margin = BigInt::from(110_u8);
        instruction_tradeoff.evaluator_instruction_count = 90;
        instruction_tradeoff.active_data_limb_instruction_units = 90;

        let mut nonfinal_comparison_winner = instruction_tradeoff.clone();
        nonfinal_comparison_winner
            .schedule
            .pre_comparison_drop_count = 5;
        nonfinal_comparison_winner.maximum_error_bound = BigUint::from(1_u8);
        nonfinal_comparison_winner.factor_four_conditions_hold = false;

        let measurements = vec![
            baseline,
            error_tradeoff,
            dominated,
            superior,
            superior_duplicate,
            instruction_tradeoff,
            nonfinal_comparison_winner,
        ];
        let mut expected_comparison_measurements =
            BTreeMap::<(&'static str, &'static str, usize, usize), JointSearchMeasurement>::new();
        for measurement in &measurements {
            let key = (
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.target_level,
            );
            if expected_comparison_measurements
                .get(&key)
                .is_none_or(|current| {
                    measurement.maximum_error_bound < current.maximum_error_bound
                        || (measurement.maximum_error_bound == current.maximum_error_bound
                            && measurement.active_data_limb_instruction_units
                                < current.active_data_limb_instruction_units)
                })
            {
                expected_comparison_measurements.insert(key, measurement.clone());
            }
        }
        let finalists = measurements
            .iter()
            .filter(|measurement| joint_measurement_is_finalist(measurement))
            .collect::<Vec<_>>();
        let expected_pareto_measurements = finalists
            .iter()
            .enumerate()
            .filter_map(|(measurement_index, measurement)| {
                let is_dominated = finalists.iter().enumerate().any(|(other_index, other)| {
                    other_index != measurement_index
                        && joint_measurement_dominates(*other, *measurement)
                });
                (!is_dominated).then(|| (**measurement).clone())
            })
            .collect::<Vec<_>>();
        let expected_finalist_measurement_count =
            u128::try_from(finalists.len()).expect("small finalist count fits u128");
        drop(finalists);

        let mut accumulator = JointMeasurementAccumulator::default();
        for measurement in measurements {
            accumulator.observe(measurement);
        }
        let (comparison_measurements, pareto_measurements, finalist_measurement_count) =
            accumulator.into_parts();
        assert_eq!(comparison_measurements, expected_comparison_measurements);
        assert_eq!(pareto_measurements, expected_pareto_measurements);
        assert_eq!(
            finalist_measurement_count,
            expected_finalist_measurement_count,
        );
    }

    #[test]
    fn joint_topology_resource_frontier_uses_exact_family_geometries() {
        let expected_minimum_pre_comparison_drop_counts = [8_usize, 3, 5, 0, 0, 8, 0];
        for (topology, expected_minimum) in joint_topology_candidates()
            .into_iter()
            .zip(expected_minimum_pre_comparison_drop_counts)
        {
            let actual_minimum = (0..=SELECTED_EVALUATOR_WORKING_LEVEL)
                .find(|pre_comparison_drop_count| {
                    topology_pre_comparison_drop_meets_stream_bound(
                        topology,
                        &DATA_PRIMES,
                        *pre_comparison_drop_count,
                    )
                    .expect("topology resource accounting")
                })
                .expect("one pre-comparison level meets the stream bound");
            assert_eq!(actual_minimum, expected_minimum, "{}", topology.label);
            if actual_minimum > 0 {
                assert!(
                    !topology_pre_comparison_drop_meets_stream_bound(
                        topology,
                        &DATA_PRIMES,
                        actual_minimum - 1,
                    )
                    .expect("preceding topology resource accounting")
                );
            }
        }

        let p6_b6 = joint_topology_candidates()[0];
        let p6_b7 = joint_topology_candidates()[1];
        let p7_b7 = joint_topology_candidates()[2];
        let p8_b9 = joint_topology_candidates()[3];
        let p9_b10 = joint_topology_candidates()[4];
        assert_eq!(
            component_material_wire_byte_length(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p6_b6.special_prime_count],
                p6_b6.data_primes_per_block,
            )
            .expect("P6/B6 Galois component accounting"),
            72_417_280,
        );
        assert_eq!(
            component_material_wire_byte_length(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p6_b7.special_prime_count],
                p6_b7.data_primes_per_block,
            )
            .expect("P6/B7 Galois component accounting"),
            57_933_824,
        );
        assert_eq!(
            component_material_wire_byte_length(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p7_b7.special_prime_count],
                p7_b7.data_primes_per_block,
            )
            .expect("P7/B7 Galois component accounting"),
            60_030_976,
        );
        assert_eq!(
            component_material_wire_byte_length(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p8_b9.special_prime_count],
                p8_b9.data_primes_per_block,
            )
            .expect("P8/B9 Galois component accounting"),
            46_596_096,
        );
        assert_eq!(
            component_material_wire_byte_length(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p9_b10.special_prime_count],
                p9_b10.data_primes_per_block,
            )
            .expect("P9/B10 Galois component accounting"),
            48_168_960,
        );

        assert_eq!(
            evaluator_material_wire_byte_lengths(
                SELECTED_EVALUATOR_WORKING_LEVEL - 2,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p6_b7.special_prime_count],
                p6_b7.data_primes_per_block,
            )
            .expect("P6/B7 pre-two accounting")
            .2,
            4_302_307_328,
        );
        assert_eq!(
            evaluator_material_wire_byte_lengths(
                SELECTED_EVALUATOR_WORKING_LEVEL - 3,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p6_b7.special_prime_count],
                p6_b7.data_primes_per_block,
            )
            .expect("P6/B7 pre-three accounting")
            .2,
            4_243_587_072,
        );
        assert_eq!(
            evaluator_material_wire_byte_lengths(
                SELECTED_EVALUATOR_WORKING_LEVEL - 8,
                &DATA_PRIMES,
                &SPECIAL_PRIMES[..p6_b6.special_prime_count],
                p6_b6.data_primes_per_block,
            )
            .expect("P6/B6 pre-eight accounting")
            .2,
            4_237_033_472,
        );
    }

    fn symbolic_prepared_power_level_trace(
        prepared_powers: &SymbolicPolynomialPowers,
    ) -> Vec<ScheduledMultiplicationLevelTrace> {
        let mut trace = Vec::new();
        for product in scheduled_power_table_products(prepared_powers.baby_step_count, 0)
            .expect("symbolic baby power schedule")
        {
            let left = prepared_powers.baby_powers[product.lower_power]
                .as_ref()
                .expect("symbolic baby left input");
            let right = prepared_powers.baby_powers[product.upper_power]
                .as_ref()
                .expect("symbolic baby right input");
            let output = prepared_powers.baby_powers[product.output_power]
                .as_ref()
                .expect("symbolic baby output");
            trace.push(ScheduledMultiplicationLevelTrace {
                multiplication_depth: product.multiplication_depth,
                left_input_level: left.ciphertext_bound.level,
                right_input_level: right.ciphertext_bound.level,
                modulus_drop_count: left
                    .ciphertext_bound
                    .level
                    .min(right.ciphertext_bound.level)
                    - output.ciphertext_bound.level,
                output_level: output.ciphertext_bound.level,
            });
        }
        let giant_base_multiplication_depth = prepared_powers.giant_powers[1]
            .as_ref()
            .expect("symbolic giant base")
            .multiplication_depth;
        for product in scheduled_power_table_products(
            prepared_powers.block_count.saturating_sub(1),
            giant_base_multiplication_depth,
        )
        .expect("symbolic giant power schedule")
        {
            let left = prepared_powers.giant_powers[product.lower_power]
                .as_ref()
                .expect("symbolic giant left input");
            let right = prepared_powers.giant_powers[product.upper_power]
                .as_ref()
                .expect("symbolic giant right input");
            let output = prepared_powers.giant_powers[product.output_power]
                .as_ref()
                .expect("symbolic giant output");
            trace.push(ScheduledMultiplicationLevelTrace {
                multiplication_depth: product.multiplication_depth,
                left_input_level: left.ciphertext_bound.level,
                right_input_level: right.ciphertext_bound.level,
                modulus_drop_count: left
                    .ciphertext_bound
                    .level
                    .min(right.ciphertext_bound.level)
                    - output.ciphertext_bound.level,
                output_level: output.ciphertext_bound.level,
            });
        }
        trace
    }

    #[test]
    fn grouped_modulus_switch_instruction_work_matches_the_compiler() {
        let rank_input = SymbolicCiphertextBound::aggregate_fresh_direct_ballots(10, 10)
            .expect("rank instruction-work input");
        let depth_drop_counts = [3_usize, 0, 2, 0, 4];
        let mut prepared_powers = initialize_partial_power_dag(
            &rank_input,
            20,
            RANK_LOOKUP_BABY_STEP_COUNT,
            SELECTED_EVALUATOR_WORKING_LEVEL,
        )
        .expect("rank instruction-work DAG");
        let mut recurrence_instruction_count = 0_u64;
        for (depth_index, modulus_drop_count) in depth_drop_counts.iter().enumerate() {
            let (instruction_count, _) = extend_partial_power_dag_at_depth(
                &mut prepared_powers,
                depth_index + 1,
                *modulus_drop_count,
            )
            .expect("rank instruction-work depth");
            recurrence_instruction_count += instruction_count;
        }
        let compiler_instruction_count = compiled_prepared_power_instruction_count(
            SELECTED_EVALUATOR_WORKING_LEVEL,
            20,
            RANK_LOOKUP_BABY_STEP_COUNT,
            &depth_drop_counts,
        )
        .expect("compiled rank instruction work");
        assert_eq!(
            recurrence_instruction_count,
            u64::try_from(compiler_instruction_count).expect("compiler count fits u64"),
        );
        let compiler_trace = compiled_prepared_power_level_trace(
            SELECTED_EVALUATOR_WORKING_LEVEL,
            20,
            RANK_LOOKUP_BABY_STEP_COUNT,
            &depth_drop_counts,
        )
        .expect("compiled rank instruction trace");
        assert!(
            compiler_trace
                .iter()
                .any(|step| step.modulus_drop_count > 1)
        );
        assert!(
            compiler_trace
                .iter()
                .any(|step| step.modulus_drop_count == 0)
        );
        assert_eq!(
            pre_comparison_work(SELECTED_EVALUATOR_WORKING_LEVEL, 0).0,
            0
        );
        assert_eq!(
            pre_comparison_work(SELECTED_EVALUATOR_WORKING_LEVEL, 7).0,
            1
        );
    }

    #[test]
    fn incremental_modulus_switch_alignment_matches_direct_alignment() {
        let working_bound = SymbolicCiphertextBound::aggregate_fresh_direct_ballots(10, 10)
            .expect("alignment input")
            .modulus_switch_to(SELECTED_EVALUATOR_WORKING_LEVEL)
            .expect("working-level alignment");
        for intermediate_level in
            CANONICAL_TARGET_CIPHERTEXT_LEVEL..=SELECTED_EVALUATOR_WORKING_LEVEL
        {
            let intermediate = working_bound
                .modulus_switch_to(intermediate_level)
                .expect("intermediate alignment");
            for final_level in CANONICAL_TARGET_CIPHERTEXT_LEVEL..=intermediate_level {
                assert_eq!(
                    intermediate
                        .modulus_switch_to(final_level)
                        .expect("incremental final alignment"),
                    working_bound
                        .modulus_switch_to(final_level)
                        .expect("direct final alignment"),
                );
            }
        }
    }

    #[test]
    fn cached_comparison_branches_match_direct_binary_depth_dag_and_rank_reset() {
        let topology = joint_topology_candidates()[1];
        let comparison = prepare_joint_comparison(topology, &DATA_PRIMES)
            .expect("binary comparison preparation");
        let pre_comparison_drop_count = 3;
        let comparison_input_level = SELECTED_EVALUATOR_WORKING_LEVEL - pre_comparison_drop_count;
        let refreshed_comparison_inputs = comparison
            .comparison_inputs
            .modulus_switch_to(comparison_input_level)
            .expect("binary comparison input alignment");
        let (evaluator_instruction_count, active_data_limb_instruction_units) =
            pre_comparison_work(SELECTED_EVALUATOR_WORKING_LEVEL, pre_comparison_drop_count);
        let initial_state = PowerDagSearchState {
            prepared_powers: initialize_partial_power_dag(
                &refreshed_comparison_inputs,
                comparison.greater_or_equal_polynomial.len(),
                comparison.baby_step_count,
                SELECTED_EVALUATOR_WORKING_LEVEL,
            )
            .expect("initial binary comparison power DAG"),
            packed_ranks: None,
            working_level: SELECTED_EVALUATOR_WORKING_LEVEL,
            pre_comparison_drop_count,
            comparison_depth_drop_counts: [0; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
            rank_depth_drop_counts: [0; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
            assigned_variable_count: 1,
            consumed_drop_count: pre_comparison_drop_count,
            evaluator_instruction_count,
            active_data_limb_instruction_units,
        };
        let mut frontier = vec![
            CachedPowerDagSearchState::from_state(initial_state)
                .expect("initial cached binary comparison state"),
        ];

        for comparison_depth in 0..COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT {
            let mut next_frontier = Vec::with_capacity(frontier.len() * 2);
            for cached_state in frontier {
                let reference_parent_state = cached_state.state.clone();
                let prepared_branches = prepare_power_dag_depth_branches(
                    &cached_state.state.prepared_powers,
                    comparison_depth + 1,
                    0,
                    1,
                )
                .expect("prepared binary comparison branches");
                let prepared_branch_count = prepared_branches.len();
                let CachedPowerDagSearchState {
                    state: parent_state,
                    dominance_key: parent_dominance_key,
                } = cached_state;
                let mut reusable_state = Some(parent_state);
                let mut sibling_dominance_key = Some(parent_dominance_key);
                for (branch_index, prepared_branch) in prepared_branches.into_iter().enumerate() {
                    let modulus_drop_count = prepared_branch.modulus_drop_count;
                    let is_final_branch = branch_index + 1 == prepared_branch_count;
                    let mut candidate_state = if is_final_branch {
                        reusable_state
                            .take()
                            .expect("final binary branch owns its state")
                    } else {
                        reusable_state
                            .as_ref()
                            .expect("binary siblings retain their state")
                            .clone()
                    };
                    candidate_state.assigned_variable_count += 1;
                    candidate_state.consumed_drop_count += modulus_drop_count;
                    candidate_state.comparison_depth_drop_counts[comparison_depth] =
                        modulus_drop_count;
                    let (instruction_count, limb_units) = apply_prepared_power_dag_depth_branch(
                        &mut candidate_state.prepared_powers,
                        prepared_branch,
                    )
                    .expect("apply prepared binary comparison branch");
                    candidate_state.evaluator_instruction_count += instruction_count;
                    candidate_state.active_data_limb_instruction_units += limb_units;

                    let mut reference_candidate = reference_parent_state.clone();
                    reference_candidate.assigned_variable_count += 1;
                    reference_candidate.consumed_drop_count += modulus_drop_count;
                    reference_candidate.comparison_depth_drop_counts[comparison_depth] =
                        modulus_drop_count;
                    let (reference_instruction_count, reference_limb_units) =
                        extend_partial_power_dag_at_depth(
                            &mut reference_candidate.prepared_powers,
                            comparison_depth + 1,
                            modulus_drop_count,
                        )
                        .expect("direct binary comparison branch");
                    reference_candidate.evaluator_instruction_count += reference_instruction_count;
                    reference_candidate.active_data_limb_instruction_units += reference_limb_units;
                    assert_eq!(candidate_state, reference_candidate);

                    let dominance_key = if is_final_branch {
                        sibling_dominance_key
                            .take()
                            .expect("final binary branch owns its dominance key")
                    } else {
                        sibling_dominance_key
                            .as_ref()
                            .expect("binary siblings retain their dominance key")
                            .clone()
                    };
                    let mut candidate = CachedPowerDagSearchState {
                        state: candidate_state,
                        dominance_key,
                    };
                    candidate
                        .finish_dominance_key_transition()
                        .expect("incremental binary comparison dominance key");
                    assert_eq!(
                        candidate.dominance_key,
                        PowerDagSearchStateDominanceKey::from_state(&candidate.state)
                            .expect("direct binary comparison dominance key"),
                    );
                    next_frontier.push(candidate);
                    if !is_final_branch {
                        sibling_dominance_key
                            .as_mut()
                            .expect("binary siblings retain their dominance cursor")
                            .lower_existing_bounds_once()
                            .expect("lower binary sibling dominance key");
                    }
                }
            }
            frontier = next_frontier;
        }
        assert_eq!(
            frontier.len(),
            1_usize << COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
        );

        let cached_comparison_state = frontier
            .into_iter()
            .next()
            .expect("binary comparison frontier is nonempty");
        let mut rank_input_state = cached_comparison_state.state;
        let comparison_outputs = symbolic_evaluate_polynomial_from_prepared_powers(
            &rank_input_state.prepared_powers,
            &comparison.greater_or_equal_polynomial,
        )
        .expect("binary comparison outputs");
        let comparison_output_level =
            SELECTED_EVALUATOR_WORKING_LEVEL - rank_input_state.consumed_drop_count;
        let packed_ranks = symbolic_finish_packed_rank_evaluation(
            &comparison_outputs,
            20,
            comparison_output_level,
            &comparison.pair_windows,
        )
        .expect("binary comparison packed ranks");
        let normalized_rank = packed_ranks
            .modulus_switch_to(SELECTED_EVALUATOR_WORKING_LEVEL)
            .expect("binary rank input alignment")
            .normalize_scaling()
            .expect("binary rank input scaling");
        rank_input_state.prepared_powers = initialize_partial_power_dag(
            &normalized_rank,
            20,
            RANK_LOOKUP_BABY_STEP_COUNT,
            SELECTED_EVALUATOR_WORKING_LEVEL,
        )
        .expect("binary rank input power DAG");
        rank_input_state.packed_ranks = Some(packed_ranks);
        let rebuilt_rank_input = CachedPowerDagSearchState::from_state(rank_input_state)
            .expect("rebuilt rank-input dominance key");
        assert_eq!(
            rebuilt_rank_input.dominance_key,
            PowerDagSearchStateDominanceKey::from_state(&rebuilt_rank_input.state)
                .expect("direct rank-input dominance key"),
        );
    }

    #[test]
    fn cached_rank_branches_preserve_exact_frontier_counts_and_pareto_inputs() {
        const DROP_VALUE_COUNT: usize = 3;
        let rank_input = SymbolicCiphertextBound::aggregate_fresh_direct_ballots(10, 10)
            .expect("rank search input");
        let coefficient_count = 20;
        let mut exhaustive_states = Vec::new();
        let allocation_count =
            DROP_VALUE_COUNT.pow(RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT as u32);

        for encoded_allocation in 0..allocation_count {
            let mut remaining_allocation = encoded_allocation;
            let mut depth_drop_counts = [0_usize; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT];
            for drop_count in &mut depth_drop_counts {
                *drop_count = remaining_allocation % DROP_VALUE_COUNT;
                remaining_allocation /= DROP_VALUE_COUNT;
            }
            let mut prepared_powers = initialize_partial_power_dag(
                &rank_input,
                coefficient_count,
                RANK_LOOKUP_BABY_STEP_COUNT,
                SELECTED_EVALUATOR_WORKING_LEVEL,
            )
            .expect("partial rank power DAG");
            let mut evaluator_instruction_count = 0_u64;
            let mut active_data_limb_instruction_units = 0_u64;
            for (depth_index, modulus_drop_count) in depth_drop_counts.iter().enumerate() {
                let (instruction_count, limb_units) = extend_partial_power_dag_at_depth(
                    &mut prepared_powers,
                    depth_index + 1,
                    *modulus_drop_count,
                )
                .expect("partial rank power DAG depth");
                evaluator_instruction_count += instruction_count;
                active_data_limb_instruction_units += limb_units;
            }
            let production_powers = super::symbolic_prepare_polynomial_powers(
                &rank_input,
                coefficient_count,
                RANK_LOOKUP_BABY_STEP_COUNT,
                SELECTED_EVALUATOR_WORKING_LEVEL,
                &depth_drop_counts,
            )
            .expect("production rank power DAG");
            assert_eq!(prepared_powers, production_powers);
            let circuit_trace = prepared_polynomial_power_level_trace(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                coefficient_count,
                RANK_LOOKUP_BABY_STEP_COUNT,
                &depth_drop_counts,
            )
            .expect("circuit rank power trace");
            let compiler_trace = compiled_prepared_power_level_trace(
                SELECTED_EVALUATOR_WORKING_LEVEL,
                coefficient_count,
                RANK_LOOKUP_BABY_STEP_COUNT,
                &depth_drop_counts,
            )
            .expect("compiler rank power trace");
            assert_eq!(
                symbolic_prepared_power_level_trace(&prepared_powers),
                circuit_trace
            );
            assert_eq!(compiler_trace, circuit_trace);
            if encoded_allocation == 0 {
                assert!(circuit_trace.iter().all(|step| {
                    step.modulus_drop_count == 0
                        && step.output_level == step.left_input_level.min(step.right_input_level)
                }));
            }
            exhaustive_states.push(PowerDagSearchState {
                prepared_powers,
                packed_ranks: Some(rank_input.clone()),
                working_level: SELECTED_EVALUATOR_WORKING_LEVEL,
                pre_comparison_drop_count: 0,
                comparison_depth_drop_counts: [0; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
                rank_depth_drop_counts: depth_drop_counts,
                assigned_variable_count: JOINT_SEARCH_VARIABLE_COUNT,
                consumed_drop_count: depth_drop_counts.iter().sum(),
                evaluator_instruction_count,
                active_data_limb_instruction_units,
            });
        }

        let initial_state = PowerDagSearchState {
            prepared_powers: initialize_partial_power_dag(
                &rank_input,
                coefficient_count,
                RANK_LOOKUP_BABY_STEP_COUNT,
                SELECTED_EVALUATOR_WORKING_LEVEL,
            )
            .expect("initial partial rank power DAG"),
            packed_ranks: Some(rank_input),
            working_level: SELECTED_EVALUATOR_WORKING_LEVEL,
            pre_comparison_drop_count: 0,
            comparison_depth_drop_counts: [0; COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
            rank_depth_drop_counts: [0; RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT],
            assigned_variable_count: 1 + COMPARISON_SWITCHED_MULTIPLICATION_DEPTH_COUNT,
            consumed_drop_count: 0,
            evaluator_instruction_count: 0,
            active_data_limb_instruction_units: 0,
        };
        let mut frontier = vec![
            CachedPowerDagSearchState::from_state(initial_state)
                .expect("initial cached rank state"),
        ];
        let mut pruning_counts = SearchPruningCounts::default();
        let mut reference_pruning_counts = SearchPruningCounts::default();
        for depth_index in 0..RANK_SWITCHED_MULTIPLICATION_DEPTH_COUNT {
            let mut next_frontiers = BTreeMap::<usize, NondominatedSearchFrontier>::new();
            let mut reference_next_frontiers = BTreeMap::<usize, Vec<PowerDagSearchState>>::new();
            let pruned_prefix_count_before_depth =
                pruning_counts.negative_margin_prefix_count + pruning_counts.dominated_prefix_count;
            let mut generated_candidate_count = 0_u128;
            for cached_state in frontier {
                let reference_parent_state = cached_state.state.clone();
                let prepared_branches = prepare_power_dag_depth_branches(
                    &cached_state.state.prepared_powers,
                    depth_index + 1,
                    0,
                    DROP_VALUE_COUNT - 1,
                )
                .expect("prepared rank power DAG depth branches");
                let prepared_branch_count = prepared_branches.len();
                let CachedPowerDagSearchState {
                    state: parent_state,
                    dominance_key: parent_dominance_key,
                } = cached_state;
                let mut reusable_state = Some(parent_state);
                let mut sibling_dominance_key = Some(parent_dominance_key);
                for (branch_index, prepared_branch) in prepared_branches.into_iter().enumerate() {
                    let modulus_drop_count = prepared_branch.modulus_drop_count;
                    let is_final_branch = branch_index + 1 == prepared_branch_count;
                    let mut candidate_state = if is_final_branch {
                        reusable_state
                            .take()
                            .expect("final test branch owns its state")
                    } else {
                        reusable_state
                            .as_ref()
                            .expect("test siblings retain their state")
                            .clone()
                    };
                    candidate_state.assigned_variable_count += 1;
                    candidate_state.consumed_drop_count += modulus_drop_count;
                    candidate_state.rank_depth_drop_counts[depth_index] = modulus_drop_count;
                    let (instruction_count, limb_units) = apply_prepared_power_dag_depth_branch(
                        &mut candidate_state.prepared_powers,
                        prepared_branch,
                    )
                    .expect("apply prepared rank power DAG depth branch");
                    candidate_state.evaluator_instruction_count += instruction_count;
                    candidate_state.active_data_limb_instruction_units += limb_units;

                    let mut reference_candidate = reference_parent_state.clone();
                    reference_candidate.assigned_variable_count += 1;
                    reference_candidate.consumed_drop_count += modulus_drop_count;
                    reference_candidate.rank_depth_drop_counts[depth_index] = modulus_drop_count;
                    let (reference_instruction_count, reference_limb_units) =
                        extend_partial_power_dag_at_depth(
                            &mut reference_candidate.prepared_powers,
                            depth_index + 1,
                            modulus_drop_count,
                        )
                        .expect("reference rank power DAG depth");
                    reference_candidate.evaluator_instruction_count += reference_instruction_count;
                    reference_candidate.active_data_limb_instruction_units += reference_limb_units;
                    assert_eq!(candidate_state, reference_candidate);
                    generated_candidate_count += 1;
                    insert_nondominated_state(
                        reference_next_frontiers
                            .entry(reference_candidate.consumed_drop_count)
                            .or_default(),
                        reference_candidate,
                        &mut reference_pruning_counts,
                    )
                    .expect("reference rank frontier insertion");
                    if !record_nonpositive_candidate(&candidate_state, &mut pruning_counts) {
                        let dominance_key = if is_final_branch {
                            sibling_dominance_key
                                .take()
                                .expect("final test branch owns its dominance key")
                        } else {
                            sibling_dominance_key
                                .as_ref()
                                .expect("test siblings retain their dominance key")
                                .clone()
                        };
                        let mut candidate = CachedPowerDagSearchState {
                            state: candidate_state,
                            dominance_key,
                        };
                        candidate
                            .finish_dominance_key_transition()
                            .expect("incremental rank dominance key");
                        assert_eq!(
                            candidate.dominance_key,
                            PowerDagSearchStateDominanceKey::from_state(&candidate.state)
                                .expect("direct rank dominance key"),
                        );
                        next_frontiers
                            .entry(candidate.state.consumed_drop_count)
                            .or_default()
                            .insert_positive_cached(candidate, &mut pruning_counts)
                            .expect("cached rank frontier insertion");
                    }
                    if !is_final_branch {
                        sibling_dominance_key
                            .as_mut()
                            .expect("test siblings retain their dominance cursor")
                            .lower_existing_bounds_once()
                            .expect("lower test sibling dominance key");
                    }
                }
            }
            for cached_frontier in next_frontiers.values() {
                let indexed_entry_count = cached_frontier
                    .entry_indices_by_instruction_and_limb_units
                    .values()
                    .flat_map(BTreeMap::values)
                    .map(Vec::len)
                    .sum::<usize>();
                let retained_entry_count = cached_frontier
                    .entries
                    .iter()
                    .filter(|entry| entry.is_some())
                    .count();
                assert_eq!(indexed_entry_count, retained_entry_count);
            }
            frontier = next_frontiers
                .into_values()
                .flat_map(NondominatedSearchFrontier::into_cached_states)
                .collect();
            let reference_frontier = reference_next_frontiers
                .into_values()
                .flatten()
                .collect::<Vec<_>>();
            assert_eq!(
                frontier
                    .iter()
                    .map(|cached_state| &cached_state.state)
                    .collect::<Vec<_>>(),
                reference_frontier.iter().collect::<Vec<_>>(),
            );
            assert_eq!(pruning_counts, reference_pruning_counts);
            let pruned_prefix_count_after_depth =
                pruning_counts.negative_margin_prefix_count + pruning_counts.dominated_prefix_count;
            assert_eq!(
                generated_candidate_count,
                u128::try_from(frontier.len()).expect("small frontier length fits u128")
                    + pruned_prefix_count_after_depth
                    - pruned_prefix_count_before_depth,
                "every bounded candidate is either retained or exactly accounted as pruned",
            );
        }

        assert!(pruning_counts.dominated_prefix_count > 0);
        for exhaustive_state in &exhaustive_states {
            assert!(frontier.iter().any(|retained_state| {
                state_dominates(&retained_state.state, exhaustive_state)
                    .expect("retained-state dominance")
            }));
        }
        for retained_state in &frontier {
            assert!(!exhaustive_states.iter().any(|exhaustive_state| {
                state_dominates(exhaustive_state, &retained_state.state)
                    .expect("exhaustive-state dominance")
                    && !state_dominates(&retained_state.state, exhaustive_state)
                        .expect("reverse exhaustive-state dominance")
            }));
        }
    }

    #[test]
    fn cross_pre_comparison_dominance_preserves_exhaustive_small_search() {
        let topology = joint_topology_candidates()[0];
        let data_primes = &DATA_PRIMES[..10];
        let comparison =
            prepare_joint_comparison(topology, data_primes).expect("small joint comparison");

        let mut separate_counts = SearchPruningCounts::default();
        let separate_comparison_states = generate_comparison_search_states_with_partition(
            topology,
            &comparison,
            &mut separate_counts,
            PreComparisonFrontierPartition::Separate,
            ComparisonSearchResourceFilter::CurrentEvaluatorMaterial,
        )
        .expect("separate pre-comparison frontier search");
        let mut collapsed_counts = SearchPruningCounts::default();
        let collapsed_comparison_states = generate_comparison_search_states_with_partition(
            topology,
            &comparison,
            &mut collapsed_counts,
            PreComparisonFrontierPartition::CollapseDominated,
            ComparisonSearchResourceFilter::CurrentEvaluatorMaterial,
        )
        .expect("collapsed pre-comparison frontier search");

        for separate_state in &separate_comparison_states {
            assert!(collapsed_comparison_states.iter().any(|collapsed_state| {
                state_dominates(&collapsed_state.state, &separate_state.state)
                    .expect("cross-pre comparison-state dominance")
            }));
        }
        for collapsed_state in &collapsed_comparison_states {
            assert!(
                separate_comparison_states
                    .iter()
                    .any(|separate_state| separate_state.state == collapsed_state.state)
            );
        }

        let separate_complete_states = generate_complete_rank_search_states_with_partition(
            separate_comparison_states,
            &mut separate_counts,
            PreComparisonFrontierPartition::Separate,
        )
        .expect("separate pre-comparison complete search");
        let collapsed_complete_states = generate_complete_rank_search_states_with_partition(
            collapsed_comparison_states,
            &mut collapsed_counts,
            PreComparisonFrontierPartition::CollapseDominated,
        )
        .expect("collapsed pre-comparison complete search");

        for separate_state in &separate_complete_states {
            assert!(collapsed_complete_states.iter().any(|collapsed_state| {
                state_dominates(collapsed_state, separate_state)
                    .expect("cross-pre complete-state dominance")
            }));
        }
        for collapsed_state in &collapsed_complete_states {
            assert!(
                separate_complete_states
                    .iter()
                    .any(|separate_state| separate_state == collapsed_state)
            );
        }

        for state in &separate_complete_states {
            *separate_counts
                .evaluated_complete_schedule_counts
                .entry(state.consumed_drop_count)
                .or_default() += 1;
        }
        for state in &collapsed_complete_states {
            *collapsed_counts
                .evaluated_complete_schedule_counts
                .entry(state.consumed_drop_count)
                .or_default() += 1;
        }
        let working_level = data_primes.len() - 1;
        for total_drop_count in
            joint_search_total_drop_range(working_level).expect("small target-level range")
        {
            let analytical_count =
                weak_composition_count(JOINT_SEARCH_VARIABLE_COUNT, total_drop_count);
            for counts in [&separate_counts, &collapsed_counts] {
                let classified_count = counts
                    .resource_rejected_complete_schedule_counts
                    .get(&total_drop_count)
                    .copied()
                    .unwrap_or_default()
                    + counts
                        .negative_margin_complete_schedule_counts
                        .get(&total_drop_count)
                        .copied()
                        .unwrap_or_default()
                    + counts
                        .dominated_complete_schedule_counts
                        .get(&total_drop_count)
                        .copied()
                        .unwrap_or_default()
                    + counts
                        .evaluated_complete_schedule_counts
                        .get(&total_drop_count)
                        .copied()
                        .unwrap_or_default();
                assert_eq!(classified_count, analytical_count);
            }
        }
        assert!(
            collapsed_counts.generated_prefix_count <= separate_counts.generated_prefix_count,
            "cross-pre dominance must not increase exhaustive prefix generation"
        );
    }

    #[test]
    fn bounded_canonical_executor_commits_in_order_with_bounded_parallel_work() {
        let simultaneous_start = Arc::new(Barrier::new(2));
        let release_first_task = Arc::new((Mutex::new(false), Condvar::new()));
        let active_worker_count = Arc::new(AtomicUsize::new(0));
        let maximum_active_worker_count = Arc::new(AtomicUsize::new(0));
        let completion_order = Arc::new(Mutex::new(Vec::new()));
        let coordinator_thread = thread::current().id();
        let mut committed_outputs = Vec::new();

        let work_simultaneous_start = Arc::clone(&simultaneous_start);
        let work_release_first_task = Arc::clone(&release_first_task);
        let work_active_worker_count = Arc::clone(&active_worker_count);
        let work_maximum_active_worker_count = Arc::clone(&maximum_active_worker_count);
        let work_completion_order = Arc::clone(&completion_order);
        execute_bounded_in_canonical_order(
            (0_usize..8).collect(),
            2,
            4,
            move |task_index| {
                let active_count = work_active_worker_count.fetch_add(1, Ordering::AcqRel) + 1;
                work_maximum_active_worker_count.fetch_max(active_count, Ordering::AcqRel);
                if task_index < 2 {
                    work_simultaneous_start.wait();
                }
                if task_index == 0 {
                    let (released, release_condition) = &*work_release_first_task;
                    let mut released = released
                        .lock()
                        .expect("first-task release mutex is not poisoned");
                    while !*released {
                        released = release_condition
                            .wait(released)
                            .expect("first-task release mutex is not poisoned");
                    }
                }
                work_completion_order
                    .lock()
                    .expect("completion-order mutex is not poisoned")
                    .push(task_index);
                if task_index == 1 {
                    let (released, release_condition) = &*work_release_first_task;
                    *released
                        .lock()
                        .expect("first-task release mutex is not poisoned") = true;
                    release_condition.notify_one();
                }
                work_active_worker_count.fetch_sub(1, Ordering::AcqRel);
                Ok(task_index * task_index)
            },
            |output| {
                assert_eq!(thread::current().id(), coordinator_thread);
                committed_outputs.push(output);
                Ok(())
            },
        )
        .expect("bounded canonical execution");

        assert_eq!(committed_outputs, vec![0, 1, 4, 9, 16, 25, 36, 49]);
        let completion_order = completion_order
            .lock()
            .expect("completion-order mutex is not poisoned");
        let second_task_position = completion_order
            .iter()
            .position(|task_index| *task_index == 1)
            .expect("second task completed");
        let first_task_position = completion_order
            .iter()
            .position(|task_index| *task_index == 0)
            .expect("first task completed");
        assert!(second_task_position < first_task_position);
        assert_eq!(maximum_active_worker_count.load(Ordering::Acquire), 2);
        assert_eq!(active_worker_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn bounded_canonical_executor_returns_indexed_failure_after_joining_workers() {
        let simultaneous_start = Arc::new(Barrier::new(2));
        let release_first_task = Arc::new((Mutex::new(false), Condvar::new()));
        let active_worker_count = Arc::new(AtomicUsize::new(0));
        let mut committed_outputs = Vec::new();

        let work_simultaneous_start = Arc::clone(&simultaneous_start);
        let work_release_first_task = Arc::clone(&release_first_task);
        let work_active_worker_count = Arc::clone(&active_worker_count);
        let error = execute_bounded_in_canonical_order(
            (0_usize..8).collect(),
            2,
            4,
            move |task_index| {
                work_active_worker_count.fetch_add(1, Ordering::AcqRel);
                if task_index < 2 {
                    work_simultaneous_start.wait();
                }
                if task_index == 0 {
                    let (released, release_condition) = &*work_release_first_task;
                    let mut released = released
                        .lock()
                        .expect("first-task release mutex is not poisoned");
                    while !*released {
                        released = release_condition
                            .wait(released)
                            .expect("first-task release mutex is not poisoned");
                    }
                    work_active_worker_count.fetch_sub(1, Ordering::AcqRel);
                    return Ok(task_index);
                }
                if task_index == 1 {
                    let (released, release_condition) = &*work_release_first_task;
                    *released
                        .lock()
                        .expect("first-task release mutex is not poisoned") = true;
                    release_condition.notify_one();
                    work_active_worker_count.fetch_sub(1, Ordering::AcqRel);
                    return Err(super::invalid_recurrence("indexed worker failure"));
                }
                work_active_worker_count.fetch_sub(1, Ordering::AcqRel);
                Ok(task_index)
            },
            |output| {
                committed_outputs.push(output);
                Ok(())
            },
        )
        .expect_err("indexed worker failure is returned");

        assert!(error.to_string().contains("indexed worker failure"));
        assert_eq!(committed_outputs, vec![0]);
        assert_eq!(active_worker_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn joint_search_parallel_executor_matches_serial_exhaustive_minimum_prefix() {
        let tasks = joint_search_triple_tasks(
            JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT..=JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT,
            &JointSearchCheckpointLocation::Disabled,
        )
        .expect("minimum-prefix task catalog");
        assert_eq!(tasks.len(), 14);
        let serial_results = tasks
            .clone()
            .into_iter()
            .map(compute_joint_search_triple)
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("serial exhaustive minimum-prefix search");
        let mut parallel_results = Vec::new();
        execute_bounded_in_canonical_order(tasks, 4, 8, compute_joint_search_triple, |result| {
            validate_joint_search_classification(
                result.data_prime_count - 1,
                &result.pruning_counts,
                &result.retained_schedules,
            )?;
            parallel_results.push(result);
            Ok(())
        })
        .expect("parallel exhaustive minimum-prefix search");

        assert_eq!(parallel_results, serial_results);
        let serial_checkpoint_bytes = serial_results
            .iter()
            .map(joint_search_checkpoint_bytes)
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("serial checkpoint bytes");
        let parallel_checkpoint_bytes = parallel_results
            .iter()
            .map(joint_search_checkpoint_bytes)
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("parallel checkpoint bytes");
        assert_eq!(parallel_checkpoint_bytes, serial_checkpoint_bytes);
        let serial_classifications = serial_results
            .iter()
            .map(joint_search_classification_lines)
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("serial classification output");
        let parallel_classifications = parallel_results
            .iter()
            .map(joint_search_classification_lines)
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("parallel classification output");
        assert_eq!(parallel_classifications, serial_classifications);

        let mut serial_accumulator = JointMeasurementAccumulator::default();
        for result in serial_results {
            commit_joint_search_triple(result, &mut serial_accumulator, false)
                .expect("serial coordinator commit");
        }
        let mut parallel_accumulator = JointMeasurementAccumulator::default();
        for result in parallel_results {
            commit_joint_search_triple(result, &mut parallel_accumulator, false)
                .expect("parallel coordinator commit");
        }
        assert_eq!(
            parallel_accumulator.into_parts(),
            serial_accumulator.into_parts()
        );
    }

    #[test]
    #[ignore = "fresh 16-triple parallel peak probe; run through the guarded measurements runner"]
    fn selected_evaluator_joint_topology_parallel_prefix_reports_guarded_peak() {
        let checkpoint_root = joint_search_parallel_prefix_checkpoint_root()
            .expect("guarded parallel-prefix checkpoint root");
        assert!(
            !checkpoint_root
                .try_exists()
                .expect("parallel-prefix checkpoint root existence check"),
            "parallel-prefix peak probe requires a fresh isolated checkpoint root",
        );
        let mut tasks = joint_search_triple_tasks(
            JOINT_SEARCH_PARALLEL_PREFIX_PROBE_MINIMUM_DATA_PRIME_COUNT
                ..=JOINT_SEARCH_PARALLEL_PREFIX_PROBE_MAXIMUM_DATA_PRIME_COUNT,
            &JointSearchCheckpointLocation::IsolatedRoot(checkpoint_root.clone()),
        )
        .expect("parallel-prefix task catalog");
        tasks.truncate(JOINT_SEARCH_PARALLEL_PREFIX_PROBE_TRIPLE_COUNT);
        assert_eq!(tasks.len(), JOINT_SEARCH_PARALLEL_PREFIX_PROBE_TRIPLE_COUNT);
        assert!(tasks[..14].iter().all(|task| task.data_prime_count == 18),);
        assert!(tasks[14..].iter().all(|task| task.data_prime_count == 19),);
        let worker_count = joint_search_parallel_worker_count(tasks.len());
        assert_eq!(worker_count, JOINT_SEARCH_MAXIMUM_WORKER_COUNT);
        let reorder_window = joint_search_parallel_reorder_window(worker_count, tasks.len());
        let mut measurement_accumulator = JointMeasurementAccumulator::default();
        println!(
            "jointSearchParallelPrefix workers={worker_count} configuredReorderWindow={} effectiveReorderWindow={reorder_window} taskCount={} dataPrimeCounts=18,19 checkpointRoot={}",
            JOINT_SEARCH_MAXIMUM_WORKER_COUNT * JOINT_SEARCH_REORDER_WINDOW_MULTIPLIER,
            tasks.len(),
            checkpoint_root.display(),
        );
        execute_bounded_in_canonical_order(
            tasks,
            worker_count,
            reorder_window,
            compute_joint_search_triple,
            |result| commit_joint_search_triple(result, &mut measurement_accumulator, true),
        )
        .expect("guarded parallel-prefix search");

        let checkpoint_directory = checkpoint_root.join(JOINT_SEARCH_CHECKPOINT_DIRECTORY_NAME);
        let checkpoint_file_count = fs::read_dir(&checkpoint_directory)
            .expect("parallel-prefix checkpoint directory")
            .map(|entry| entry.expect("parallel-prefix checkpoint entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .count();
        assert_eq!(
            checkpoint_file_count,
            JOINT_SEARCH_PARALLEL_PREFIX_PROBE_TRIPLE_COUNT,
        );
        let (comparison_measurements, pareto_measurements, finalist_measurement_count) =
            measurement_accumulator.into_parts();
        println!(
            "jointSearchParallelPrefixComplete checkpoints={checkpoint_file_count} comparisonMeasurements={} paretoMeasurements={} finalistMeasurements={finalist_measurement_count}",
            comparison_measurements.len(),
            pareto_measurements.len(),
        );
    }

    #[test]
    #[ignore = "exact target-heavy block-balanced evaluator search; run through the guarded measurements runner"]
    fn target_heavy_block_balanced_six_special_seven_data_block_search_reports_exact_finalists() {
        let prime_order = target_heavy_block_balanced_prime_order();
        let mut actual_prime_multiset = prime_order.data_primes.clone();
        actual_prime_multiset.sort_unstable();
        let mut canonical_prime_multiset = DATA_PRIMES.to_vec();
        canonical_prime_multiset.sort_unstable();
        assert_eq!(actual_prime_multiset, canonical_prime_multiset);

        let mut descending_data_primes = DATA_PRIMES.to_vec();
        descending_data_primes.sort_unstable_by(|left, right| right.cmp(left));
        assert_eq!(
            &prime_order.data_primes[..6],
            &descending_data_primes[..6],
            "the target prefix must contain the six largest data primes",
        );
        assert_eq!(
            prime_order.data_primes[6],
            *descending_data_primes
                .last()
                .expect("the data basis is nonempty"),
            "the first block must attain the minimum possible product for the fixed target prefix",
        );
        let block_moduli = prime_order
            .data_primes
            .chunks(7)
            .map(|block| {
                block
                    .iter()
                    .map(|prime| BigUint::from(*prime))
                    .product::<BigUint>()
            })
            .collect::<Vec<_>>();
        assert_eq!(block_moduli.len(), 4);
        assert!(
            block_moduli[1..]
                .iter()
                .all(|block_modulus| block_modulus < &block_moduli[0]),
            "every suffix block must stay below the unavoidable first-block modulus",
        );
        let globally_descending_maximum_block_modulus = descending_data_primes
            .chunks(7)
            .map(|block| {
                block
                    .iter()
                    .map(|prime| BigUint::from(*prime))
                    .product::<BigUint>()
            })
            .max()
            .expect("the data basis has one block");
        assert!(block_moduli[0] < globally_descending_maximum_block_modulus);
        let target_modulus = prime_order.data_primes[..6]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let current_target_modulus = DATA_PRIMES[..6]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        assert!(target_modulus > current_target_modulus);

        let task = target_heavy_block_balanced_search_task()
            .expect("target-heavy block-balanced exact search task");
        assert_eq!(task.topology.special_prime_count, 6);
        assert_eq!(task.topology.data_primes_per_block, 7);
        assert_eq!(task.data_prime_count, DATA_PRIMES.len());
        assert_eq!(task.prime_order.data_primes, prime_order.data_primes);
        assert!(
            !topology_pre_comparison_drop_meets_stream_bound(
                task.topology,
                &task.prime_order.data_primes,
                1,
            )
            .expect("preceding evaluator stream accounting"),
        );
        assert!(
            topology_pre_comparison_drop_meets_stream_bound(
                task.topology,
                &task.prime_order.data_primes,
                2,
            )
            .expect("selected evaluator stream accounting"),
        );
        let checkpoint_path = task
            .checkpoint_path
            .as_deref()
            .expect("target-heavy search task has a checkpoint")
            .to_path_buf();
        let checkpoint_directory = checkpoint_path
            .parent()
            .expect("target-heavy checkpoint directory")
            .to_path_buf();
        println!(
            "targetHeavySearchTask topology={} primeOrder={} dataPrimeCount={} checkpoint={}",
            task.topology.label,
            task.prime_order.label,
            task.data_prime_count,
            checkpoint_path.display(),
        );

        let result = compute_joint_search_triple(task)
            .expect("target-heavy block-balanced exact evaluator search");
        let mut measurement_accumulator = JointMeasurementAccumulator::default();
        commit_joint_search_triple(result, &mut measurement_accumulator, true)
            .expect("target-heavy block-balanced exact search result");
        let checkpoint_file_count = fs::read_dir(&checkpoint_directory)
            .expect("target-heavy checkpoint directory")
            .map(|entry| entry.expect("target-heavy checkpoint entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .count();
        assert_eq!(checkpoint_file_count, 1);

        let (comparison_measurements, mut pareto_measurements, finalist_measurement_count) =
            measurement_accumulator.into_parts();
        let print_exact_measurement = |label: &str, measurement: &JointSearchMeasurement| {
            let target_modulus = prime_order.data_primes[..=measurement.target_level]
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>();
            let full_qp_modulus = prime_order
                .data_primes
                .iter()
                .chain(&SPECIAL_PRIMES[..6])
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>();
            print_joint_measurement(label, measurement);
            println!(
                "{label}ExactModuli topology={} primeOrder={} dataPrimeCount={} targetLevel={} targetQ={} fullQp={}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.target_level,
                target_modulus,
                full_qp_modulus,
            );
        };
        for measurement in comparison_measurements.values() {
            print_exact_measurement("targetHeavyComparison", measurement);
        }
        pareto_measurements.sort_by(|left, right| {
            left.target_level
                .cmp(&right.target_level)
                .then_with(|| left.maximum_error_bound.cmp(&right.maximum_error_bound))
                .then_with(|| {
                    left.ceremony_evaluator_wire_byte_length
                        .cmp(&right.ceremony_evaluator_wire_byte_length)
                })
        });
        for measurement in &pareto_measurements {
            assert!(joint_measurement_is_finalist(measurement));
            print_exact_measurement("targetHeavyPareto", measurement);
            let compiled_measurement = compile_candidate_evaluator_program_measurement(
                &measurement.schedule,
                measurement.target_level,
                &prime_order.data_primes,
            )
            .expect("target-heavy Pareto schedule compiles for every top count");
            println!(
                "targetHeavyCompiled topology={} primeOrder={} dataPrimeCount={} targetLevel={} minimumInstructions={} maximumInstructions={}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.target_level,
                compiled_measurement.minimum_instruction_count,
                compiled_measurement.maximum_instruction_count,
            );
            println!(
                "targetHeavyPrimeFamilies topology={} primeOrder={} dataPrimeCount={} galoisLevel={} galoisDataPrimes={:?} rkgLevel={} rkgDataPrimes={:?} kllpsTargetLevel={} kllpsDataPrimes={:?} specialPrimes={:?}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.working_level,
                &prime_order.data_primes,
                measurement.relinearization_level,
                &prime_order.data_primes[..=measurement.relinearization_level],
                measurement.target_level,
                &prime_order.data_primes[..=measurement.target_level],
                &SPECIAL_PRIMES[..6],
            );
        }
        assert!(
            finalist_measurement_count > 0,
            "target-heavy block-balanced exact search found no genuine finalist",
        );
        assert!(!pareto_measurements.is_empty());
    }

    #[test]
    #[ignore = "exact early preparation-drop candidate measurement; remove after selecting the evaluator topology"]
    fn six_special_six_data_block_early_preparation_drop_candidate_reports_exact_bounds() {
        const TARGET_LEVEL: usize = 5;
        let topology = joint_topology_candidates()[0];
        assert_eq!(topology.label, "P6/B6");
        let data_primes = &EARLY_PREPARATION_DROP_BLOCK_BALANCED_DATA_PRIMES;
        let schedules = [
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 3,
                comparison_depth_drop_counts: [1, 1, 1, 1, 1, 1, 2, 1],
                rank_depth_drop_counts: [5, 1, 2, 0, 0],
            },
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 2,
                comparison_depth_drop_counts: [1, 1, 1, 1, 1, 1, 2, 1],
                rank_depth_drop_counts: [5, 1, 2, 1, 0],
            },
        ];
        let prepared_recurrence = PreparedDirectBallotTargetNoiseRecurrence::prepare(20, 90)
            .expect("candidate plaintext recurrence prepares exactly once");
        let mut retained_finalist = false;
        for schedule in schedules {
            assert_eq!(
                schedule.total_drop_count(),
                data_primes.len() - 1 - TARGET_LEVEL
            );
            let bounds =
                direct_ballot_target_noise_bounds_with_prepared_topology_and_early_preparation_drop(
                    10,
                    10,
                    &schedule,
                    data_primes,
                    topology.data_primes_per_block,
                    &SPECIAL_PRIMES[..topology.special_prime_count],
                    TARGET_LEVEL,
                    &prepared_recurrence,
                )
                .expect("early preparation-drop candidate recurrence");
            let maximum_error_bound = bounds
                .iter()
                .map(DirectBallotTargetNoiseBound::maximum_error_coefficient_bound)
                .max()
                .cloned()
                .expect("candidate evaluator has target bounds");
            let minimum_margin = bounds
                .iter()
                .flat_map(|bound| {
                    [
                        bound.target_identifier.minimum_decryption_margin.clone(),
                        bound.target_order.minimum_decryption_margin.clone(),
                        bound.target_identifier.final_decryption_margin(),
                        bound.target_order.final_decryption_margin(),
                    ]
                })
                .min()
                .expect("candidate evaluator has operative margins");
            let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)
                .expect("candidate factor-four flooding bound");
            let factor_four_conditions_hold =
                ensure_factor_four_parameter_conditions_with_data_primes(
                    TARGET_LEVEL,
                    &maximum_error_bound,
                    &flooding_bound,
                    data_primes,
                )
                .is_ok();
            let preparation_level = data_primes.len() - 1 - schedule.pre_comparison_drop_count;
            let component_wire_byte_length = component_material_wire_byte_length(
                preparation_level,
                data_primes,
                &SPECIAL_PRIMES[..topology.special_prime_count],
                topology.data_primes_per_block,
            )
            .expect("early preparation-level component accounting");
            let ceremony_evaluator_wire_byte_length = component_wire_byte_length
                .checked_mul(76)
                .expect("early preparation-level ceremony accounting");
            let finalist = minimum_margin.is_positive()
                && factor_four_conditions_hold
                && ceremony_evaluator_wire_byte_length <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH;
            retained_finalist |= finalist;
            println!(
                "earlyPreparationCandidate topology={} pre={} errorBits={} minimumMarginPositive={} minimumMarginBits={} factorFour={} componentBytes={} ceremonyBytes={} streamBound={} finalist={}",
                topology.label,
                schedule.pre_comparison_drop_count,
                maximum_error_bound.bits(),
                minimum_margin.is_positive(),
                minimum_margin.magnitude().bits(),
                factor_four_conditions_hold,
                component_wire_byte_length,
                ceremony_evaluator_wire_byte_length,
                ceremony_evaluator_wire_byte_length <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                finalist,
            );
        }
        assert!(
            retained_finalist,
            "neither early preparation-drop schedule satisfies every operative bound"
        );
    }

    #[test]
    #[ignore = "exact pairwise-ballot evaluator candidate measurement; remove after selecting the evaluator topology"]
    fn six_special_six_data_block_pairwise_ballot_candidate_reports_exact_bounds() {
        const TARGET_LEVEL: usize = 5;

        #[derive(Debug)]
        struct PairwiseBallotCandidateMeasurement {
            schedule: EvaluatorModulusSchedule,
            maximum_error_bound: BigUint,
            minimum_margin: BigInt,
            factor_four_conditions_hold: bool,
            active_data_limb_instruction_units: u64,
            relinearization_level: usize,
            galois_level: usize,
            participant_source_wire_byte_length: u64,
            final_evaluator_store_wire_byte_length: u64,
            ceremony_evaluator_wire_byte_length: u64,
        }

        let topology = joint_topology_candidates()[0];
        assert_eq!(topology.label, "P6/B6");
        let data_primes = &THREE_PRE_COMPARISON_DROP_CANDIDATE_DATA_PRIMES;
        let comparison = prepare_joint_pairwise_ballot_comparison(topology, data_primes)
            .expect("pairwise-ballot comparison prepares exactly");
        let exact_rotation_hop_count = comparison
            .pair_windows
            .iter()
            .map(|(shift, window_offset, _)| {
                super::pairwise_ballot_forward_rotation_hop_count(*window_offset).and_then(
                    |forward_hops| {
                        super::pairwise_ballot_inverse_rotation_hop_count(*shift)
                            .map(|inverse_hops| forward_hops + inverse_hops)
                    },
                )
            })
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("pairwise-ballot rotation paths are canonical")
            .into_iter()
            .sum::<usize>();
        assert_eq!(exact_rotation_hop_count, 211);
        let mut pruning_counts = SearchPruningCounts::default();
        let comparison_states = generate_comparison_search_states_with_partition(
            topology,
            &comparison,
            &mut pruning_counts,
            PreComparisonFrontierPartition::Separate,
            ComparisonSearchResourceFilter::MeasurePairwiseMaterialAfterComparison,
        )
        .expect("pairwise-ballot comparison schedule frontier");
        let complete_states = generate_complete_rank_search_states_with_partition(
            comparison_states,
            &mut pruning_counts,
            PreComparisonFrontierPartition::Separate,
        )
        .expect("pairwise-ballot rank schedule frontier");
        let candidate_states = complete_states
            .into_iter()
            .filter(|state| state.working_level - state.consumed_drop_count == TARGET_LEVEL)
            .collect::<Vec<_>>();
        assert!(
            !candidate_states.is_empty(),
            "the pairwise-ballot frontier retained no target-level-five schedule",
        );
        let prepared_recurrence = PreparedDirectBallotTargetNoiseRecurrence::prepare(20, 90)
            .expect("candidate plaintext recurrence prepares exactly once");
        let mut measurements = Vec::with_capacity(candidate_states.len());
        for state in candidate_states {
            let schedule = schedule_from_search_state(&state);
            assert_eq!(
                schedule.total_drop_count(),
                data_primes.len() - 1 - TARGET_LEVEL
            );
            let bounds = direct_ballot_target_noise_bounds_with_prepared_topology(
                10,
                10,
                &schedule,
                data_primes,
                topology.data_primes_per_block,
                &SPECIAL_PRIMES[..topology.special_prime_count],
                TARGET_LEVEL,
                &prepared_recurrence,
            )
            .expect("pairwise-ballot candidate recurrence");
            let maximum_error_bound = bounds
                .iter()
                .map(DirectBallotTargetNoiseBound::maximum_error_coefficient_bound)
                .max()
                .cloned()
                .expect("candidate evaluator has target bounds");
            let minimum_margin = bounds
                .iter()
                .flat_map(|bound| {
                    [
                        bound.target_identifier.minimum_decryption_margin.clone(),
                        bound.target_order.minimum_decryption_margin.clone(),
                        bound.target_identifier.final_decryption_margin(),
                        bound.target_order.final_decryption_margin(),
                    ]
                })
                .min()
                .expect("candidate evaluator has operative margins");
            let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)
                .expect("candidate factor-four flooding bound");
            let factor_four_conditions_hold =
                ensure_factor_four_parameter_conditions_with_data_primes(
                    TARGET_LEVEL,
                    &maximum_error_bound,
                    &flooding_bound,
                    data_primes,
                )
                .is_ok();
            let relinearization_level = data_primes.len() - 1 - schedule.pre_comparison_drop_count;
            let galois_level = relinearization_level
                .checked_sub(schedule.comparison_drop_count())
                .expect("comparison drops fit the relinearization level");
            let relinearization_component_byte_length = component_material_wire_byte_length(
                relinearization_level,
                data_primes,
                &SPECIAL_PRIMES[..topology.special_prime_count],
                topology.data_primes_per_block,
            )
            .expect("pairwise-ballot relinearization component accounting");
            let galois_component_byte_length = component_material_wire_byte_length(
                galois_level,
                data_primes,
                &SPECIAL_PRIMES[..topology.special_prime_count],
                topology.data_primes_per_block,
            )
            .expect("pairwise-ballot Galois component accounting");
            let participant_source_wire_byte_length = relinearization_component_byte_length
                .checked_mul(3)
                .and_then(|byte_length| {
                    galois_component_byte_length
                        .checked_mul(3)
                        .and_then(|galois_byte_length| byte_length.checked_add(galois_byte_length))
                })
                .expect("pairwise-ballot participant accounting");
            let final_evaluator_store_wire_byte_length = relinearization_component_byte_length
                .checked_mul(2)
                .and_then(|byte_length| {
                    galois_component_byte_length
                        .checked_mul(3)
                        .and_then(|galois_byte_length| byte_length.checked_add(galois_byte_length))
                })
                .expect("pairwise-ballot final-store accounting");
            let ceremony_evaluator_wire_byte_length = participant_source_wire_byte_length
                .checked_mul(10)
                .and_then(|byte_length| {
                    byte_length.checked_add(final_evaluator_store_wire_byte_length)
                })
                .expect("pairwise-ballot ceremony accounting");
            measurements.push(PairwiseBallotCandidateMeasurement {
                schedule,
                maximum_error_bound,
                minimum_margin,
                factor_four_conditions_hold,
                active_data_limb_instruction_units: state.active_data_limb_instruction_units,
                relinearization_level,
                galois_level,
                participant_source_wire_byte_length,
                final_evaluator_store_wire_byte_length,
                ceremony_evaluator_wire_byte_length,
            });
        }
        measurements.sort_by(|left, right| {
            right
                .factor_four_conditions_hold
                .cmp(&left.factor_four_conditions_hold)
                .then_with(|| right.minimum_margin.cmp(&left.minimum_margin))
                .then_with(|| left.maximum_error_bound.cmp(&right.maximum_error_bound))
                .then_with(|| {
                    left.active_data_limb_instruction_units
                        .cmp(&right.active_data_limb_instruction_units)
                })
                .then_with(|| {
                    JointSearchScheduleCheckpoint::from(left.schedule)
                        .cmp(&JointSearchScheduleCheckpoint::from(right.schedule))
                })
        });
        let finalist_count = measurements
            .iter()
            .filter(|measurement| {
                measurement.minimum_margin.is_positive()
                    && measurement.factor_four_conditions_hold
                    && measurement.ceremony_evaluator_wire_byte_length
                        <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
            })
            .count();
        println!(
            "pairwiseBallotSearch retainedSchedules={} finalists={} generatedPrefixes={} resourceRejectedPrefixes={} negativeMarginPrefixes={} dominatedPrefixes={}",
            measurements.len(),
            finalist_count,
            pruning_counts.generated_prefix_count,
            pruning_counts.resource_rejected_prefix_count,
            pruning_counts.negative_margin_prefix_count,
            pruning_counts.dominated_prefix_count,
        );
        for measurement in measurements.iter().take(20) {
            let finalist = measurement.minimum_margin.is_positive()
                && measurement.factor_four_conditions_hold
                && measurement.ceremony_evaluator_wire_byte_length
                    <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH;
            println!(
                "pairwiseBallotCandidate topology={} pre={} comparison={:?} rank={:?} errorBits={} minimumMarginPositive={} minimumMarginBits={} factorFour={} activeLimbUnits={} rkgLevel={} galoisLevel={} participantBytes={} finalBytes={} ceremonyBytes={} streamBound={} finalist={}",
                topology.label,
                measurement.schedule.pre_comparison_drop_count,
                measurement.schedule.comparison_depth_drop_counts,
                measurement.schedule.rank_depth_drop_counts,
                measurement.maximum_error_bound.bits(),
                measurement.minimum_margin.is_positive(),
                measurement.minimum_margin.magnitude().bits(),
                measurement.factor_four_conditions_hold,
                measurement.active_data_limb_instruction_units,
                measurement.relinearization_level,
                measurement.galois_level,
                measurement.participant_source_wire_byte_length,
                measurement.final_evaluator_store_wire_byte_length,
                measurement.ceremony_evaluator_wire_byte_length,
                measurement.ceremony_evaluator_wire_byte_length
                    <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                finalist,
            );
        }
        assert!(
            finalist_count > 0,
            "the exact pairwise-ballot frontier found no schedule satisfying every operative bound"
        );
    }

    #[test]
    #[ignore = "focused live-order evaluator candidate measurement; remove after selecting the evaluator topology"]
    fn live_data_order_six_special_six_data_block_candidate_reports_exact_bounds() {
        const TARGET_LEVEL: usize = 5;
        const MAXIMUM_TERNARY_VSS_MODULUS_EXCLUSIVE: u64 = 16_677_181_699_666_569;

        let topology = joint_topology_candidates()[0];
        assert_eq!(topology.label, "P6/B6");
        assert_eq!(topology.special_prime_count, 6);
        assert_eq!(topology.data_primes_per_block, 6);
        let data_primes = &DATA_PRIMES;
        let special_primes = &SPECIAL_PRIMES[..topology.special_prime_count];

        assert!(
            data_primes[..=TARGET_LEVEL]
                .iter()
                .all(|modulus| *modulus < MAXIMUM_TERNARY_VSS_MODULUS_EXCLUSIVE),
            "the active target prefix must fit the selected ternary VSS capacity"
        );
        assert_eq!(
            data_primes.iter().copied().collect::<BTreeSet<_>>().len(),
            data_primes.len(),
            "the live data basis must contain no duplicate modulus"
        );
        let two_ring_degree = u64::try_from(POLYNOMIAL_DEGREE)
            .expect("ring degree fits u64")
            .checked_mul(2)
            .expect("twice the ring degree fits u64");
        for modulus in data_primes {
            assert_eq!((modulus - 1) % PLAINTEXT_MODULUS, 0);
            assert_eq!((modulus - 1) % two_ring_degree, 0);
        }
        for modulus in data_primes[..=TARGET_LEVEL].iter().chain(special_primes) {
            assert!(
                root_parameters_for_modulus(*modulus).is_some(),
                "candidate modulus {modulus} has no selected NTT root parameters"
            );
        }
        validate_key_switch_special_basis_dominates_data_blocks(
            data_primes,
            special_primes,
            topology.data_primes_per_block,
        )
        .expect("candidate special basis strictly dominates every active data block");

        let schedule = SELECTED_EVALUATOR_MODULUS_SCHEDULE;
        assert_eq!(
            schedule.total_drop_count(),
            data_primes.len() - 1 - TARGET_LEVEL,
            "the live schedule must consume the exact target-level budget"
        );
        let comparison = prepare_joint_pairwise_ballot_comparison(topology, data_primes)
            .expect("live-order pairwise comparison prepares exactly");
        let exact_rotation_hop_count = comparison
            .pair_windows
            .iter()
            .map(|(shift, window_offset, _)| {
                super::pairwise_ballot_forward_rotation_hop_count(*window_offset).and_then(
                    |forward_hop_count| {
                        super::pairwise_ballot_inverse_rotation_hop_count(*shift)
                            .map(|inverse_hop_count| forward_hop_count + inverse_hop_count)
                    },
                )
            })
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("live-order rotation paths are canonical")
            .into_iter()
            .sum::<usize>();
        assert_eq!(exact_rotation_hop_count, 211);

        let prepared_recurrence = PreparedDirectBallotTargetNoiseRecurrence::prepare(20, 90)
            .expect("live-order plaintext recurrence prepares exactly once");
        let bounds = direct_ballot_target_noise_bounds_with_prepared_topology(
            10,
            10,
            &schedule,
            data_primes,
            topology.data_primes_per_block,
            special_primes,
            TARGET_LEVEL,
            &prepared_recurrence,
        )
        .expect("live-order pairwise recurrence derives exact bounds");
        assert_eq!(bounds.len(), 20);
        let maximum_error_bound = bounds
            .iter()
            .map(DirectBallotTargetNoiseBound::maximum_error_coefficient_bound)
            .max()
            .cloned()
            .expect("live-order evaluator has target bounds");
        let minimum_margin = bounds
            .iter()
            .flat_map(|bound| {
                [
                    bound.target_identifier.minimum_decryption_margin.clone(),
                    bound.target_order.minimum_decryption_margin.clone(),
                    bound.target_identifier.final_decryption_margin(),
                    bound.target_order.final_decryption_margin(),
                ]
            })
            .min()
            .expect("live-order evaluator has operative margins");
        let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)
            .expect("live-order factor-four flooding bound derives");
        let factor_four_conditions_hold = ensure_factor_four_parameter_conditions_with_data_primes(
            TARGET_LEVEL,
            &maximum_error_bound,
            &flooding_bound,
            data_primes,
        )
        .is_ok();

        let relinearization_level = data_primes.len() - 1 - schedule.pre_comparison_drop_count;
        let galois_level = relinearization_level
            .checked_sub(schedule.comparison_drop_count())
            .expect("comparison drops fit the live relinearization level");
        let relinearization_component_byte_length = component_material_wire_byte_length(
            relinearization_level,
            data_primes,
            special_primes,
            topology.data_primes_per_block,
        )
        .expect("live-order relinearization component accounting");
        let galois_component_byte_length = component_material_wire_byte_length(
            galois_level,
            data_primes,
            special_primes,
            topology.data_primes_per_block,
        )
        .expect("live-order Galois component accounting");
        let participant_source_wire_byte_length = relinearization_component_byte_length
            .checked_mul(3)
            .and_then(|relinearization_byte_length| {
                galois_component_byte_length
                    .checked_mul(3)
                    .and_then(|galois_byte_length| {
                        relinearization_byte_length.checked_add(galois_byte_length)
                    })
            })
            .expect("live-order participant source accounting");
        let final_evaluator_store_wire_byte_length = relinearization_component_byte_length
            .checked_mul(2)
            .and_then(|relinearization_byte_length| {
                galois_component_byte_length
                    .checked_mul(3)
                    .and_then(|galois_byte_length| {
                        relinearization_byte_length.checked_add(galois_byte_length)
                    })
            })
            .expect("live-order final store accounting");
        let ceremony_evaluator_wire_byte_length = participant_source_wire_byte_length
            .checked_mul(10)
            .and_then(|source_byte_length| {
                source_byte_length.checked_add(final_evaluator_store_wire_byte_length)
            })
            .expect("live-order ceremony accounting");
        let compiled_measurement =
            compile_candidate_evaluator_program_measurement(&schedule, TARGET_LEVEL, data_primes)
                .expect("live-order evaluator compiler accepts the exact candidate");
        let active_target_modulus = data_primes[..=TARGET_LEVEL]
            .iter()
            .map(|modulus| BigUint::from(*modulus))
            .product::<BigUint>();

        println!(
            "liveOrderP6B6 activeTargetModulus={} activeTargetModulusBits={} maximumError={} maximumErrorBits={} minimumMargin={} minimumMarginPositive={} minimumMarginBits={} factorFour={} rkgLevel={} galoisLevel={} rkgComponentBytes={} galoisComponentBytes={} participantBytes={} finalStoreBytes={} ceremonyBytes={} minimumInstructionCount={} maximumInstructionCount={} rotationHops={}",
            active_target_modulus,
            active_target_modulus.bits(),
            maximum_error_bound,
            maximum_error_bound.bits(),
            minimum_margin,
            minimum_margin.is_positive(),
            minimum_margin.magnitude().bits(),
            factor_four_conditions_hold,
            relinearization_level,
            galois_level,
            relinearization_component_byte_length,
            galois_component_byte_length,
            participant_source_wire_byte_length,
            final_evaluator_store_wire_byte_length,
            ceremony_evaluator_wire_byte_length,
            compiled_measurement.minimum_instruction_count,
            compiled_measurement.maximum_instruction_count,
            exact_rotation_hop_count,
        );
        assert!(minimum_margin.is_positive());
        assert!(factor_four_conditions_hold);
        assert!(ceremony_evaluator_wire_byte_length <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH);
    }

    #[test]
    #[ignore = "focused current-prime schedule diagnosis; run through the guarded measurements runner"]
    fn current_prime_fixed_schedule_screen_reports_first_recurrence_divergence() {
        const TARGET_LEVEL: usize = 5;
        let schedules = [
            ("selected-uniform", SELECTED_EVALUATOR_MODULUS_SCHEDULE),
            (
                "candidate-zero-pre",
                EvaluatorModulusSchedule {
                    pre_comparison_drop_count: 0,
                    comparison_depth_drop_counts: [2, 1, 1, 1, 1, 1, 1, 2],
                    rank_depth_drop_counts: [5, 1, 2, 0, 2],
                },
            ),
            (
                "candidate-two-pre",
                EvaluatorModulusSchedule {
                    pre_comparison_drop_count: 2,
                    comparison_depth_drop_counts: [1, 1, 1, 1, 1, 1, 2, 1],
                    rank_depth_drop_counts: [5, 1, 2, 1, 0],
                },
            ),
        ];
        let topologies = [
            joint_topology_candidates()[4],
            joint_topology_candidates()[0],
        ];
        let prepared_recurrence = PreparedDirectBallotTargetNoiseRecurrence::prepare(20, 90)
            .expect("current-prime plaintext recurrence prepares exactly once");
        for topology in topologies {
            let special_primes = &SPECIAL_PRIMES[..topology.special_prime_count];
            validate_key_switch_special_basis_dominates_data_blocks(
                &DATA_PRIMES,
                special_primes,
                topology.data_primes_per_block,
            )
            .expect("screened special basis dominates every current data block");
            for (schedule_label, schedule) in schedules {
                assert_eq!(
                    schedule.total_drop_count(),
                    DATA_PRIMES.len() - 1 - TARGET_LEVEL
                );
                let bounds = direct_ballot_target_noise_bounds_with_prepared_topology(
                    10,
                    10,
                    &schedule,
                    &DATA_PRIMES,
                    topology.data_primes_per_block,
                    special_primes,
                    TARGET_LEVEL,
                    &prepared_recurrence,
                )
                .expect("current-prime fixed schedule recurrence");
                let maximum_error_bound = bounds
                    .iter()
                    .map(DirectBallotTargetNoiseBound::maximum_error_coefficient_bound)
                    .max()
                    .cloned()
                    .expect("current-prime evaluator has target bounds");
                let minimum_margin = bounds
                    .iter()
                    .flat_map(|bound| {
                        [
                            bound.target_identifier.minimum_decryption_margin.clone(),
                            bound.target_order.minimum_decryption_margin.clone(),
                            bound.target_identifier.final_decryption_margin(),
                            bound.target_order.final_decryption_margin(),
                        ]
                    })
                    .min()
                    .expect("current-prime evaluator has operative margins");
                let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)
                    .expect("current-prime flooding bound");
                let factor_four_conditions_hold =
                    ensure_factor_four_parameter_conditions_with_data_primes(
                        TARGET_LEVEL,
                        &maximum_error_bound,
                        &flooding_bound,
                        &DATA_PRIMES,
                    )
                    .is_ok();
                let target_modulus = DATA_PRIMES[..=TARGET_LEVEL]
                    .iter()
                    .map(|prime| BigUint::from(*prime))
                    .product::<BigUint>();
                let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
                let scaled_c2_left = &plaintext_modulus
                    * ((&maximum_error_bound << 4_usize)
                        + &plaintext_modulus * BigUint::from(5_u8)
                        + &flooding_bound * BigUint::from(16_u64 * 44));
                let factor_four_c2_margin =
                    BigInt::from(&target_modulus << 1_usize) - BigInt::from(scaled_c2_left);
                let relinearization_level =
                    DATA_PRIMES.len() - 1 - schedule.pre_comparison_drop_count;
                let galois_level = relinearization_level
                    .checked_sub(schedule.comparison_drop_count())
                    .expect("comparison drops fit the current working level");
                let relinearization_component_byte_length = component_material_wire_byte_length(
                    relinearization_level,
                    &DATA_PRIMES,
                    special_primes,
                    topology.data_primes_per_block,
                )
                .expect("current-prime RKG component accounting");
                let galois_component_byte_length = component_material_wire_byte_length(
                    galois_level,
                    &DATA_PRIMES,
                    special_primes,
                    topology.data_primes_per_block,
                )
                .expect("current-prime Galois component accounting");
                let participant_source_wire_byte_length = relinearization_component_byte_length
                    .checked_mul(3)
                    .and_then(|rkg_byte_length| {
                        galois_component_byte_length
                            .checked_mul(3)
                            .and_then(|galois_byte_length| {
                                rkg_byte_length.checked_add(galois_byte_length)
                            })
                    })
                    .expect("current-prime participant accounting");
                let final_store_wire_byte_length = relinearization_component_byte_length
                    .checked_mul(2)
                    .and_then(|rkg_byte_length| {
                        galois_component_byte_length
                            .checked_mul(3)
                            .and_then(|galois_byte_length| {
                                rkg_byte_length.checked_add(galois_byte_length)
                            })
                    })
                    .expect("current-prime final-store accounting");
                let ceremony_wire_byte_length = participant_source_wire_byte_length
                    .checked_mul(10)
                    .and_then(|source_byte_length| {
                        source_byte_length.checked_add(final_store_wire_byte_length)
                    })
                    .expect("current-prime ceremony accounting");
                let compiled_measurement = compile_candidate_evaluator_program_measurement(
                    &schedule,
                    TARGET_LEVEL,
                    &DATA_PRIMES,
                )
                .expect("current-prime fixed schedule compiler measurement");
                println!(
                    "currentPrimeScreen topology={} schedule={} pre={} comparison={:?} rank={:?} maximumErrorBits={} minimumMarginPositive={} minimumMarginBits={} factorFourC2Margin={} factorFour={} rkgLevel={} galoisLevel={} rkgComponentBytes={} galoisComponentBytes={} participantBytes={} finalStoreBytes={} ceremonyBytes={} streamBound={} minimumInstructions={} maximumInstructions={}",
                    topology.label,
                    schedule_label,
                    schedule.pre_comparison_drop_count,
                    schedule.comparison_depth_drop_counts,
                    schedule.rank_depth_drop_counts,
                    maximum_error_bound.bits(),
                    minimum_margin.is_positive(),
                    minimum_margin.magnitude().bits(),
                    factor_four_c2_margin,
                    factor_four_conditions_hold,
                    relinearization_level,
                    galois_level,
                    relinearization_component_byte_length,
                    galois_component_byte_length,
                    participant_source_wire_byte_length,
                    final_store_wire_byte_length,
                    ceremony_wire_byte_length,
                    ceremony_wire_byte_length <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                    compiled_measurement.minimum_instruction_count,
                    compiled_measurement.maximum_instruction_count,
                );
                trace_current_prime_recurrence(
                    topology.label,
                    schedule_label,
                    schedule,
                    topology.data_primes_per_block,
                    special_primes,
                    &prepared_recurrence,
                )
                .expect("current-prime operation trace");
            }
        }
    }

    struct CurrentPrimeRecurrenceTrace {
        topology_label: &'static str,
        schedule_label: &'static str,
        operation_ordinal: usize,
        first_nonpositive_margin: Option<String>,
    }

    impl CurrentPrimeRecurrenceTrace {
        fn observe(&mut self, operation: impl Into<String>, bound: &SymbolicCiphertextBound) {
            let operation = operation.into();
            let margin = bound.final_decryption_margin();
            println!(
                "currentPrimeTrace topology={} schedule={} operationOrdinal={} operation={} level={} messageBits={} errorBits={} rawBoundBits={} marginPositive={} marginBits={}",
                self.topology_label,
                self.schedule_label,
                self.operation_ordinal,
                operation,
                bound.level,
                bound.message_coefficient_bound.bits(),
                bound.error_coefficient_bound.bits(),
                super::raw_decryption_bound(bound).bits(),
                margin.is_positive(),
                margin.magnitude().bits(),
            );
            if !margin.is_positive() && self.first_nonpositive_margin.is_none() {
                self.first_nonpositive_margin = Some(operation);
            }
            self.operation_ordinal += 1;
        }
    }

    fn trace_current_prime_prepared_powers(
        phase_label: &str,
        prepared_powers: &SymbolicPolynomialPowers,
        trace: &mut CurrentPrimeRecurrenceTrace,
    ) {
        for product in scheduled_power_table_products(prepared_powers.baby_step_count, 0)
            .expect("current-prime baby power schedule")
        {
            let output = prepared_powers.baby_powers[product.output_power]
                .as_ref()
                .expect("current-prime baby power output");
            trace.observe(
                format!(
                    "{phase_label}-baby-power-{}-depth-{}",
                    product.output_power, product.multiplication_depth
                ),
                &output.ciphertext_bound,
            );
        }
        let giant_base_depth = prepared_powers.baby_powers[prepared_powers.baby_step_count]
            .as_ref()
            .expect("current-prime giant base")
            .multiplication_depth;
        for product in scheduled_power_table_products(
            prepared_powers.block_count.saturating_sub(1),
            giant_base_depth,
        )
        .expect("current-prime giant power schedule")
        {
            let output = prepared_powers.giant_powers[product.output_power]
                .as_ref()
                .expect("current-prime giant power output");
            trace.observe(
                format!(
                    "{phase_label}-giant-power-{}-depth-{}",
                    product.output_power, product.multiplication_depth
                ),
                &output.ciphertext_bound,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn trace_current_prime_recurrence(
        topology_label: &'static str,
        schedule_label: &'static str,
        schedule: EvaluatorModulusSchedule,
        data_primes_per_block: usize,
        special_primes: &[u64],
        prepared_recurrence: &PreparedDirectBallotTargetNoiseRecurrence,
    ) -> crate::encoding::CanonicalResult<()> {
        let special_basis_modulus = special_primes
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let mut trace = CurrentPrimeRecurrenceTrace {
            topology_label,
            schedule_label,
            operation_ordinal: 0,
            first_nonpositive_margin: None,
        };
        let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots_with_data_primes(
            10,
            10,
            Arc::from(DATA_PRIMES),
            data_primes_per_block,
            Arc::new(special_basis_modulus),
        )?;
        trace.observe("aggregate", &aggregate);
        let comparison_inputs = aggregate.normalize_scaling()?.add_plaintext_with_bounds(
            &prepared_recurrence.pairwise_comparison_shift.infinity_bound,
            &prepared_recurrence
                .pairwise_comparison_shift
                .canonical_lift_offset_bound,
        )?;
        trace.observe("comparison-shift", &comparison_inputs);
        let refreshed_comparison_inputs = comparison_inputs.modulus_switch_to(
            comparison_inputs
                .level
                .checked_sub(schedule.pre_comparison_drop_count)
                .expect("current-prime pre-comparison drop fits"),
        )?;
        trace.observe("comparison-pre-drop", &refreshed_comparison_inputs);
        let comparison_powers = symbolic_prepare_polynomial_powers(
            &refreshed_comparison_inputs,
            prepared_recurrence.greater_or_equal_polynomial.len(),
            prepared_recurrence.comparison_baby_step_count,
            DATA_PRIMES.len() - 1,
            &schedule.comparison_depth_drop_counts,
        )?;
        trace_current_prime_prepared_powers("comparison", &comparison_powers, &mut trace);
        let comparison_outputs = symbolic_evaluate_polynomial_from_prepared_powers(
            &comparison_powers,
            &prepared_recurrence.greater_or_equal_polynomial,
        )?;
        trace.observe("comparison-polynomial-fold", &comparison_outputs);
        let comparison_output_level = DATA_PRIMES.len()
            - 1
            - schedule.pre_comparison_drop_count
            - schedule.comparison_drop_count();
        let packed_ranks =
            super::symbolic_finish_pairwise_ballot_rank_evaluation_with_prepared_plaintexts(
                &comparison_outputs,
                comparison_output_level,
                &prepared_recurrence.pair_windows,
            )?;
        trace.observe("pairwise-rank-rotation-fold", &packed_ranks);
        let normalized_rank = packed_ranks
            .modulus_switch_to(DATA_PRIMES.len() - 1)?
            .normalize_scaling()?;
        trace.observe("rank-normalization", &normalized_rank);
        let rank_powers = symbolic_prepare_polynomial_powers(
            &normalized_rank,
            prepared_recurrence.option_count,
            RANK_LOOKUP_BABY_STEP_COUNT,
            DATA_PRIMES.len() - 1,
            &schedule.rank_depth_drop_counts,
        )?;
        trace_current_prime_prepared_powers("rank", &rank_powers, &mut trace);
        for projection in &prepared_recurrence.target_projections {
            let (target_identifier, target_order) =
                super::symbolic_sparse_target_projection_with_prepared_plaintexts(
                    &packed_ranks,
                    &rank_powers,
                    5,
                    projection,
                    &prepared_recurrence.identifier_selector,
                    &prepared_recurrence.option_slot_mask,
                )?;
            trace.observe(
                format!("target-{}-identifier", projection.top_count),
                &target_identifier,
            );
            trace.observe(
                format!("target-{}-order", projection.top_count),
                &target_order,
            );
        }
        println!(
            "currentPrimeFirstDivergence topology={} schedule={} firstNonpositiveMargin={}",
            topology_label,
            schedule_label,
            trace.first_nonpositive_margin.as_deref().unwrap_or("none"),
        );
        Ok(())
    }

    #[test]
    #[ignore = "concrete exact evaluator candidate search; remove after selecting the evaluator topology"]
    fn six_special_seven_data_block_minimum_three_pre_comparison_drop_search_reports_exact_finalists()
     {
        const TARGET_LEVEL: usize = 5;
        const MINIMUM_PRE_COMPARISON_DROP_COUNT: usize = 3;

        #[derive(Debug)]
        struct ExactCandidateMeasurement {
            schedule: EvaluatorModulusSchedule,
            maximum_error_bound: BigUint,
            minimum_margin: BigInt,
            factor_four_c2_margin: BigInt,
            factor_four_conditions_hold: bool,
            evaluator_instruction_count: u64,
            active_data_limb_instruction_units: u64,
            participant_source_wire_byte_length: u64,
            final_evaluator_store_wire_byte_length: u64,
            ceremony_evaluator_wire_byte_length: u64,
        }

        let topology = joint_topology_candidates()[1];
        assert_eq!(topology.label, "P6/B7");
        assert_eq!(topology.special_prime_count, 6);
        assert_eq!(topology.data_primes_per_block, 7);
        assert!(topology.security_comparison_allows_finalist);

        let data_primes = &THREE_PRE_COMPARISON_DROP_CANDIDATE_DATA_PRIMES;
        assert_eq!(data_primes.len(), DATA_PRIMES.len());
        assert_eq!(data_primes.len() - 1 - TARGET_LEVEL, 20);
        assert_eq!(
            data_primes.iter().copied().collect::<BTreeSet<_>>().len(),
            data_primes.len()
        );
        let two_polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE)
            .expect("ring degree fits u64")
            .checked_mul(2)
            .expect("twice the ring degree fits u64");
        for data_prime in data_primes {
            assert_eq!(*data_prime % PLAINTEXT_MODULUS, 1);
            assert_eq!(*data_prime % two_polynomial_degree, 1);
        }
        assert!(
            topology_pre_comparison_drop_meets_stream_bound(
                topology,
                data_primes,
                MINIMUM_PRE_COMPARISON_DROP_COUNT,
            )
            .expect("minimum retained pre-comparison drop has exact stream accounting"),
        );

        let comparison = prepare_joint_comparison(topology, data_primes)
            .expect("candidate comparison recurrence prepares exactly");
        let mut pruning_counts = SearchPruningCounts::default();
        let mut comparison_states =
            generate_comparison_search_states(topology, &comparison, &mut pruning_counts)
                .expect("candidate comparison schedule frontier");
        comparison_states.retain(|cached_state| {
            cached_state.state.pre_comparison_drop_count >= MINIMUM_PRE_COMPARISON_DROP_COUNT
        });
        assert!(
            !comparison_states.is_empty(),
            "the exact comparison frontier retains the required pre-comparison domain",
        );
        let complete_states =
            generate_complete_rank_search_states(comparison_states, &mut pruning_counts)
                .expect("candidate rank schedule frontier");
        let retained_complete_state_count_before_target_filter = complete_states.len();
        let candidate_states = complete_states
            .into_iter()
            .filter(|state| {
                state.pre_comparison_drop_count >= MINIMUM_PRE_COMPARISON_DROP_COUNT
                    && state.working_level - state.consumed_drop_count == TARGET_LEVEL
            })
            .collect::<Vec<_>>();
        assert!(
            !candidate_states.is_empty(),
            "the exact schedule frontier retains target-level-five candidates",
        );
        let retained_target_schedule_count = candidate_states.len();

        let prepared_recurrence = PreparedDirectBallotTargetNoiseRecurrence::prepare(20, 90)
            .expect("candidate plaintext recurrence prepares exactly once");
        let factor_four_maximum_error_bound =
            factor_four_maximum_evaluator_error_bound(TARGET_LEVEL, data_primes);
        let (
            target_role_stream_byte_length,
            paired_target_stream_byte_length,
            target_ciphertext_resident_byte_length,
        ) = target_stream_byte_lengths(TARGET_LEVEL);
        let maximum_copied_buffer_byte_length =
            u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .expect("copied-buffer bound fits u64");
        assert!(target_role_stream_byte_length <= maximum_copied_buffer_byte_length);

        let target_modulus = data_primes[..=TARGET_LEVEL]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
        let mut candidate_measurements = Vec::new();
        for state in candidate_states {
            let schedule = schedule_from_search_state(&state);
            assert_eq!(
                schedule.total_drop_count(),
                data_primes.len() - 1 - TARGET_LEVEL
            );
            let bounds = direct_ballot_target_noise_bounds_with_prepared_topology(
                10,
                10,
                &schedule,
                data_primes,
                topology.data_primes_per_block,
                &SPECIAL_PRIMES[..topology.special_prime_count],
                TARGET_LEVEL,
                &prepared_recurrence,
            )
            .expect("prepared candidate schedule recurrence");
            assert_eq!(
                bounds
                    .iter()
                    .map(|bound| bound.top_count)
                    .collect::<Vec<_>>(),
                (1..=20).collect::<Vec<_>>(),
            );
            let maximum_error_bound = bounds
                .iter()
                .map(DirectBallotTargetNoiseBound::maximum_error_coefficient_bound)
                .max()
                .cloned()
                .expect("candidate evaluator has target bounds");
            let minimum_margin = bounds
                .iter()
                .flat_map(|bound| {
                    [
                        bound.target_identifier.minimum_decryption_margin.clone(),
                        bound.target_order.minimum_decryption_margin.clone(),
                        bound.target_identifier.final_decryption_margin(),
                        bound.target_order.final_decryption_margin(),
                    ]
                })
                .min()
                .expect("candidate evaluator has operative margins");
            let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)
                .expect("candidate factor-four flooding bound");
            let factor_four_conditions_hold =
                ensure_factor_four_parameter_conditions_with_data_primes(
                    TARGET_LEVEL,
                    &maximum_error_bound,
                    &flooding_bound,
                    data_primes,
                )
                .is_ok();
            let scaled_c2_left = &plaintext_modulus
                * ((&maximum_error_bound << 4_usize)
                    + &plaintext_modulus * BigUint::from(5_u8)
                    + &flooding_bound * BigUint::from(16_u64 * 44));
            let factor_four_c2_margin =
                BigInt::from(&target_modulus << 1_usize) - BigInt::from(scaled_c2_left);
            let relinearization_level = state
                .working_level
                .checked_sub(state.pre_comparison_drop_count)
                .expect("retained pre-comparison drop fits the working level");
            let (
                participant_source_wire_byte_length,
                final_evaluator_store_wire_byte_length,
                ceremony_evaluator_wire_byte_length,
            ) = evaluator_material_wire_byte_lengths(
                relinearization_level,
                data_primes,
                &SPECIAL_PRIMES[..topology.special_prime_count],
                topology.data_primes_per_block,
            )
            .expect("candidate evaluator material accounting");

            candidate_measurements.push(ExactCandidateMeasurement {
                schedule,
                maximum_error_bound,
                minimum_margin,
                factor_four_c2_margin,
                factor_four_conditions_hold,
                evaluator_instruction_count: state.evaluator_instruction_count,
                active_data_limb_instruction_units: state.active_data_limb_instruction_units,
                participant_source_wire_byte_length,
                final_evaluator_store_wire_byte_length,
                ceremony_evaluator_wire_byte_length,
            });
        }

        candidate_measurements.sort_by(|left, right| {
            right
                .factor_four_conditions_hold
                .cmp(&left.factor_four_conditions_hold)
                .then_with(|| right.factor_four_c2_margin.cmp(&left.factor_four_c2_margin))
                .then_with(|| right.minimum_margin.cmp(&left.minimum_margin))
                .then_with(|| left.maximum_error_bound.cmp(&right.maximum_error_bound))
                .then_with(|| {
                    left.active_data_limb_instruction_units
                        .cmp(&right.active_data_limb_instruction_units)
                })
                .then_with(|| {
                    JointSearchScheduleCheckpoint::from(left.schedule)
                        .cmp(&JointSearchScheduleCheckpoint::from(right.schedule))
                })
        });
        let finalist_measurement_count = candidate_measurements
            .iter()
            .filter(|measurement| {
                measurement.minimum_margin.is_positive()
                    && measurement.factor_four_conditions_hold
                    && measurement.ceremony_evaluator_wire_byte_length
                        <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
            })
            .count();
        println!(
            "threePreCandidateSearch retainedCompleteSchedules={} retainedTargetSchedules={} finalists={} generatedPrefixes={} resourceRejectedPrefixes={} negativeMarginPrefixes={} dominatedPrefixes={} targetQ={} factorFourMaximum={} targetRoleBytes={} targetRoleBound={} pairedTargetBytes={} targetResidentBytes={} fullQpLog2={:.6}",
            retained_complete_state_count_before_target_filter,
            retained_target_schedule_count,
            finalist_measurement_count,
            pruning_counts.generated_prefix_count,
            pruning_counts.resource_rejected_prefix_count,
            pruning_counts.negative_margin_prefix_count,
            pruning_counts.dominated_prefix_count,
            target_modulus,
            factor_four_maximum_error_bound,
            target_role_stream_byte_length,
            maximum_copied_buffer_byte_length,
            paired_target_stream_byte_length,
            target_ciphertext_resident_byte_length,
            modulus_log2(data_primes)
                + modulus_log2(&SPECIAL_PRIMES[..topology.special_prime_count]),
        );
        for measurement in &candidate_measurements {
            let compiled_measurement = compile_candidate_evaluator_program_measurement(
                &measurement.schedule,
                TARGET_LEVEL,
                data_primes,
            )
            .expect("candidate schedule compiles for every top count");
            let finalist = measurement.minimum_margin.is_positive()
                && measurement.factor_four_conditions_hold
                && measurement.ceremony_evaluator_wire_byte_length
                    <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH;
            println!(
                "threePreCandidateSchedule pre={} comparison={:?} rank={:?} error={} errorBits={} minimumMargin={} factorFourC2Margin={} factorFour={} instructions={} activeLimbUnits={} participantSourceBytes={} finalStoreBytes={} ceremonyBytes={} streamBound={} targetRoleFits={} minimumCompiledInstructions={} maximumCompiledInstructions={} finalist={}",
                measurement.schedule.pre_comparison_drop_count,
                measurement.schedule.comparison_depth_drop_counts,
                measurement.schedule.rank_depth_drop_counts,
                measurement.maximum_error_bound,
                measurement.maximum_error_bound.bits(),
                measurement.minimum_margin,
                measurement.factor_four_c2_margin,
                measurement.factor_four_conditions_hold,
                measurement.evaluator_instruction_count,
                measurement.active_data_limb_instruction_units,
                measurement.participant_source_wire_byte_length,
                measurement.final_evaluator_store_wire_byte_length,
                measurement.ceremony_evaluator_wire_byte_length,
                measurement.ceremony_evaluator_wire_byte_length
                    <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
                target_role_stream_byte_length <= maximum_copied_buffer_byte_length,
                compiled_measurement.minimum_instruction_count,
                compiled_measurement.maximum_instruction_count,
                finalist,
            );
        }
        assert!(
            finalist_measurement_count > 0,
            "the exact supplied candidate search found no schedule satisfying every operative bound",
        );
    }

    #[test]
    #[ignore = "exact fixed-schedule prime-order beam search; run through the guarded measurements runner"]
    fn six_special_seven_data_block_prime_order_beam_search_reports_exact_candidates() {
        #[derive(Clone)]
        struct Candidate {
            data_primes: Vec<u64>,
            maximum_error_bound: BigUint,
            minimum_margin: BigInt,
            target_modulus: BigUint,
            target_modulus_twice: BigUint,
            scaled_c2_left: BigUint,
            factor_four_c2_margin: BigInt,
            factor_four_conditions_hold: bool,
        }

        let schedule = EvaluatorModulusSchedule {
            pre_comparison_drop_count: 2,
            comparison_depth_drop_counts: [1, 1, 1, 1, 1, 1, 2, 1],
            rank_depth_drop_counts: [5, 1, 2, 1, 0],
        };
        assert_eq!(schedule.total_drop_count(), 20);

        let prepared_recurrence = PreparedDirectBallotTargetNoiseRecurrence::prepare(20, 90)
            .expect("fixed-schedule plaintext recurrence prepares exactly");
        let prepared_reference_bounds = direct_ballot_target_noise_bounds_with_prepared_topology(
            10,
            10,
            &schedule,
            &DATA_PRIMES,
            7,
            &SPECIAL_PRIMES[..6],
            5,
            &prepared_recurrence,
        )
        .expect("prepared reference recurrence");
        let special_basis_modulus = SPECIAL_PRIMES[..6]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let unprepared_aggregate =
            SymbolicCiphertextBound::aggregate_fresh_direct_ballots_with_data_primes(
                10,
                10,
                Arc::from(DATA_PRIMES),
                7,
                Arc::new(special_basis_modulus),
            )
            .expect("unprepared reference aggregate");
        let unprepared_working_level = DATA_PRIMES.len() - 1;
        let unprepared_working_aggregate = unprepared_aggregate
            .modulus_switch_to(unprepared_working_level)
            .expect("unprepared reference working aggregate");
        let unprepared_packed_scores =
            symbolic_pack_direct_score_slots(&unprepared_working_aggregate, 20)
                .expect("unprepared reference score packing");
        let unprepared_packed_ranks = symbolic_packed_rank_evaluation(
            &unprepared_packed_scores,
            20,
            90,
            unprepared_working_level,
            &schedule,
        )
        .expect("unprepared reference rank evaluation");
        let unprepared_normalized_rank = unprepared_packed_ranks
            .modulus_switch_to(unprepared_working_level)
            .expect("unprepared reference rank alignment")
            .normalize_scaling()
            .expect("unprepared reference rank normalization");
        let unprepared_rank_powers = symbolic_prepare_polynomial_powers(
            &unprepared_normalized_rank,
            20,
            RANK_LOOKUP_BABY_STEP_COUNT,
            unprepared_working_level,
            &schedule.rank_depth_drop_counts,
        )
        .expect("unprepared reference rank powers");
        let unprepared_reference_bounds = (1..=20)
            .map(|top_count| {
                let (target_identifier, target_order) = symbolic_sparse_target_projection(
                    &unprepared_packed_ranks,
                    20,
                    top_count,
                    &unprepared_rank_powers,
                    5,
                )?;
                Ok(DirectBallotTargetNoiseBound {
                    top_count,
                    target_identifier,
                    target_order,
                })
            })
            .collect::<crate::encoding::CanonicalResult<Vec<_>>>()
            .expect("unprepared reference target projections");
        assert_eq!(prepared_reference_bounds, unprepared_reference_bounds);

        let measured_candidates = RefCell::new(BTreeMap::<Vec<u64>, Candidate>::new());

        let measure = |data_primes: Vec<u64>| {
            if let Some(candidate) = measured_candidates.borrow().get(&data_primes).cloned() {
                return candidate;
            }
            let bounds = direct_ballot_target_noise_bounds_with_prepared_topology(
                10,
                10,
                &schedule,
                &data_primes,
                7,
                &SPECIAL_PRIMES[..6],
                5,
                &prepared_recurrence,
            )
            .expect("fixed-schedule prime-order recurrence");
            let maximum_error_bound = bounds
                .iter()
                .map(|bound| bound.maximum_error_coefficient_bound())
                .max()
                .cloned()
                .expect("fixed evaluator has target bounds");
            let minimum_margin = bounds
                .iter()
                .flat_map(|bound| {
                    [
                        bound.target_identifier.minimum_decryption_margin.clone(),
                        bound.target_order.minimum_decryption_margin.clone(),
                        bound.target_identifier.final_decryption_margin(),
                        bound.target_order.final_decryption_margin(),
                    ]
                })
                .min()
                .expect("fixed evaluator has decryption margins");
            let flooding_bound = factor_four_required_flooding_bound(&maximum_error_bound)
                .expect("fixed evaluator flooding bound");
            let factor_four_conditions_hold =
                ensure_factor_four_parameter_conditions_with_data_primes(
                    5,
                    &maximum_error_bound,
                    &flooding_bound,
                    &data_primes,
                )
                .is_ok();
            let target_modulus = data_primes[..=5]
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>();
            let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
            let scaled_c2_left = &plaintext_modulus
                * ((&maximum_error_bound << 4_usize)
                    + &plaintext_modulus * BigUint::from(5_u8)
                    + &flooding_bound * BigUint::from(16_u64 * 44));
            let target_modulus_twice = &target_modulus << 1_usize;
            let factor_four_c2_margin =
                BigInt::from(target_modulus_twice.clone()) - BigInt::from(scaled_c2_left.clone());
            let candidate = Candidate {
                data_primes,
                maximum_error_bound,
                minimum_margin,
                target_modulus,
                target_modulus_twice,
                scaled_c2_left,
                factor_four_c2_margin,
                factor_four_conditions_hold,
            };
            measured_candidates
                .borrow_mut()
                .insert(candidate.data_primes.clone(), candidate.clone());
            candidate
        };

        let mut largest_drop_first = DATA_PRIMES.to_vec();
        largest_drop_first[6..].sort_unstable();
        let mut smallest_drop_first = DATA_PRIMES.to_vec();
        smallest_drop_first[6..].sort_unstable_by(|left, right| right.cmp(left));
        let initial_orders = [
            DATA_PRIMES.to_vec(),
            largest_drop_first,
            smallest_drop_first,
            TARGET_HEAVY_BLOCK_BALANCED_DATA_PRIMES.to_vec(),
        ];
        let mut beam = initial_orders
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(measure)
            .collect::<Vec<_>>();
        const BEAM_WIDTH: usize = 8;
        const MAXIMUM_ROUND_COUNT: usize = 16;
        for round_ordinal in 0..MAXIMUM_ROUND_COUNT {
            let mut orders = BTreeSet::new();
            for candidate in &beam {
                orders.insert(candidate.data_primes.clone());
                for left_index in 0..candidate.data_primes.len() {
                    for right_index in left_index + 1..candidate.data_primes.len() {
                        let mut neighbor = candidate.data_primes.clone();
                        neighbor.swap(left_index, right_index);
                        orders.insert(neighbor);
                    }
                }
            }
            let mut measured = orders.into_iter().map(measure).collect::<Vec<_>>();
            measured.sort_by(|left, right| {
                right
                    .factor_four_conditions_hold
                    .cmp(&left.factor_four_conditions_hold)
                    .then_with(|| {
                        let left_ratio_cross_product =
                            &left.target_modulus_twice * &right.scaled_c2_left;
                        let right_ratio_cross_product =
                            &right.target_modulus_twice * &left.scaled_c2_left;
                        right_ratio_cross_product.cmp(&left_ratio_cross_product)
                    })
                    .then_with(|| right.factor_four_c2_margin.cmp(&left.factor_four_c2_margin))
                    .then_with(|| right.minimum_margin.cmp(&left.minimum_margin))
                    .then_with(|| left.maximum_error_bound.cmp(&right.maximum_error_bound))
                    .then_with(|| left.data_primes.cmp(&right.data_primes))
            });
            measured.truncate(BEAM_WIDTH);
            beam = measured;
            let best = beam.first().expect("prime-order beam remains nonempty");
            println!(
                "primeOrderBeam round={} errorBits={} minimumMarginPositive={} targetModulusBits={} targetModulusTwiceBits={} scaledC2LeftBits={} factorFourRatio={}/{} factorFourSlack={} factorFour={} measuredOrderCount={} targetPrimes={:?} orderedDataPrimes={:?}",
                round_ordinal + 1,
                best.maximum_error_bound.bits(),
                best.minimum_margin.is_positive(),
                best.target_modulus.bits(),
                best.target_modulus_twice.bits(),
                best.scaled_c2_left.bits(),
                best.target_modulus_twice,
                best.scaled_c2_left,
                best.factor_four_c2_margin,
                best.factor_four_conditions_hold,
                measured_candidates.borrow().len(),
                &best.data_primes[..6],
                &best.data_primes,
            );
            if best.factor_four_conditions_hold && best.minimum_margin.is_positive() {
                break;
            }
        }
        let best = beam.first().expect("prime-order beam produced a candidate");
        assert!(
            best.factor_four_conditions_hold && best.minimum_margin.is_positive(),
            "the exact prime-order beam search found no factor-four candidate"
        );
    }

    #[test]
    #[ignore = "prospective exact 28-prime P5/B7 search; remove after selecting the evaluator topology"]
    fn prospective_28_prime_p5_b7_exhaustive_search_reports_exact_finalists() {
        let two_polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE)
            .expect("ring degree fits u64")
            .checked_mul(2)
            .expect("twice the ring degree fits u64");
        for prime in PROSPECTIVE_DATA_TAIL_PRIMES {
            assert_eq!(prime % PLAINTEXT_MODULUS, 1);
            assert_eq!(prime % two_polynomial_degree, 1);
            assert!(!DATA_PRIMES.contains(&prime));
        }
        assert_ne!(
            PROSPECTIVE_DATA_TAIL_PRIMES[0],
            PROSPECTIVE_DATA_TAIL_PRIMES[1],
        );

        let tasks = prospective_28_prime_p5_b7_search_tasks()
            .expect("prospective P5/B7 exact task catalog");
        assert_eq!(tasks.len(), 3);
        assert_eq!(
            tasks
                .iter()
                .map(|task| task.prime_order.label)
                .collect::<Vec<_>>(),
            vec![
                "prospective-current",
                "prospective-largest-drop-first",
                "prospective-smallest-drop-first",
            ],
        );
        assert!(tasks.iter().all(|task| {
            task.topology.label == "P5/B7-control"
                && task.data_prime_count == DATA_PRIMES.len() + 2
                && task.checkpoint_path.as_ref().is_some_and(|path| {
                    path.to_string_lossy()
                        .contains(PROSPECTIVE_28_PRIME_P5_B7_CHECKPOINT_DIRECTORY_NAME)
                })
        }));
        let prime_orders = tasks
            .iter()
            .map(|task| task.prime_order.clone())
            .collect::<Vec<_>>();
        let checkpoint_directory = tasks[0]
            .checkpoint_path
            .as_deref()
            .and_then(Path::parent)
            .expect("prospective checkpoint directory")
            .to_path_buf();
        assert!(tasks.iter().all(|task| {
            task.checkpoint_path.as_deref().and_then(Path::parent)
                == Some(checkpoint_directory.as_path())
        }));
        for task in &tasks {
            println!(
                "prospectiveSearchTask topology={} primeOrder={} dataPrimeCount={} checkpoint={}",
                task.topology.label,
                task.prime_order.label,
                task.data_prime_count,
                task.checkpoint_path
                    .as_deref()
                    .expect("prospective task has a checkpoint")
                    .display(),
            );
        }

        let worker_count = joint_search_parallel_worker_count(tasks.len());
        let reorder_window = joint_search_parallel_reorder_window(worker_count, tasks.len());
        let mut measurement_accumulator = JointMeasurementAccumulator::default();
        execute_bounded_in_canonical_order(
            tasks,
            worker_count,
            reorder_window,
            compute_joint_search_triple,
            |result| commit_joint_search_triple(result, &mut measurement_accumulator, true),
        )
        .expect("prospective exact P5/B7 search");
        let checkpoint_file_count = fs::read_dir(&checkpoint_directory)
            .expect("prospective checkpoint directory")
            .map(|entry| entry.expect("prospective checkpoint entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .count();
        assert_eq!(checkpoint_file_count, 3);

        let (comparison_measurements, mut pareto_measurements, finalist_measurement_count) =
            measurement_accumulator.into_parts();
        let print_exact_moduli = |label: &str, measurement: &JointSearchMeasurement| {
            let prime_order = prime_orders
                .iter()
                .find(|candidate| candidate.label == measurement.prime_order_label)
                .expect("prospective measurement prime order");
            let data_primes = &prime_order.data_primes[..measurement.data_prime_count];
            let target_modulus = data_primes[..=measurement.target_level]
                .iter()
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>();
            let full_qp_modulus = data_primes
                .iter()
                .chain(&SPECIAL_PRIMES[..5])
                .map(|prime| BigUint::from(*prime))
                .product::<BigUint>();
            print_joint_measurement(label, measurement);
            println!(
                "{label}ExactModuli topology={} primeOrder={} dataPrimeCount={} targetLevel={} targetQ={} fullQp={}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.target_level,
                target_modulus,
                full_qp_modulus,
            );
        };
        for measurement in comparison_measurements.values() {
            print_exact_moduli("prospectiveComparison", measurement);
        }
        pareto_measurements.sort_by(|left, right| {
            left.target_level
                .cmp(&right.target_level)
                .then_with(|| left.prime_order_label.cmp(right.prime_order_label))
                .then_with(|| left.maximum_error_bound.cmp(&right.maximum_error_bound))
                .then_with(|| {
                    left.ceremony_evaluator_wire_byte_length
                        .cmp(&right.ceremony_evaluator_wire_byte_length)
                })
        });
        for measurement in &pareto_measurements {
            assert!(joint_measurement_is_finalist(measurement));
            print_exact_moduli("prospectivePareto", measurement);
            let prime_order = prime_orders
                .iter()
                .find(|candidate| candidate.label == measurement.prime_order_label)
                .expect("prospective Pareto prime order");
            let data_primes = &prime_order.data_primes[..measurement.data_prime_count];
            let compiled_measurement = compile_candidate_evaluator_program_measurement(
                &measurement.schedule,
                measurement.target_level,
                data_primes,
            )
            .expect("prospective Pareto schedule compiles for every top count");
            println!(
                "prospectiveCompiled topology={} primeOrder={} dataPrimeCount={} targetLevel={} minimumInstructions={} maximumInstructions={}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.target_level,
                compiled_measurement.minimum_instruction_count,
                compiled_measurement.maximum_instruction_count,
            );
            println!(
                "prospectivePrimeFamilies topology={} primeOrder={} dataPrimeCount={} galoisLevel={} galoisDataPrimes={:?} rkgLevel={} rkgDataPrimes={:?} kllpsTargetLevel={} kllpsDataPrimes={:?} specialPrimes={:?}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.working_level,
                data_primes,
                measurement.relinearization_level,
                &data_primes[..=measurement.relinearization_level],
                measurement.target_level,
                &data_primes[..=measurement.target_level],
                &SPECIAL_PRIMES[..5],
            );
        }
        assert!(
            finalist_measurement_count > 0,
            "prospective exact search found no genuine finalist",
        );
        assert!(!pareto_measurements.is_empty());
    }

    #[test]
    #[ignore = "exact joint evaluator topology search; run through the guarded measurements runner"]
    fn selected_evaluator_joint_topology_search_reports_exact_pareto() {
        assert_eq!(bounded_composition_count(14, 20, 2), 93_093);
        assert_eq!(bounded_composition_count(14, 20, 3), 24_608_948);
        assert_eq!(bounded_composition_count(14, 20, 4), 149_968_455);

        let mut measurement_accumulator = JointMeasurementAccumulator::default();
        let tasks = joint_search_triple_tasks(
            JOINT_SEARCH_MINIMUM_DATA_PRIME_COUNT..=DATA_PRIMES.len(),
            &JointSearchCheckpointLocation::Environment,
        )
        .expect("joint evaluator search task catalog");
        assert_eq!(tasks.len(), 280);
        let worker_count = joint_search_parallel_worker_count(tasks.len());
        let reorder_window = joint_search_parallel_reorder_window(worker_count, tasks.len());
        assert_eq!(
            reorder_window,
            (worker_count * JOINT_SEARCH_REORDER_WINDOW_MULTIPLIER).min(tasks.len()),
        );
        println!(
            "jointSearchExecutor workers={worker_count} reorderWindow={reorder_window} taskCount={}",
            tasks.len(),
        );
        execute_bounded_in_canonical_order(
            tasks,
            worker_count,
            reorder_window,
            compute_joint_search_triple,
            |result| commit_joint_search_triple(result, &mut measurement_accumulator, true),
        )
        .expect("bounded canonical joint evaluator search");

        let (comparison_measurements, mut pareto_measurements, finalist_measurement_count) =
            measurement_accumulator.into_parts();
        for measurement in comparison_measurements.values() {
            print_joint_measurement("jointComparison", measurement);
            if measurement.topology_label.starts_with("P5/") {
                println!(
                    "p5Control topology={} primeOrder={} dataPrimeCount={} targetLevel={} firstFailedConstraint={}",
                    measurement.topology_label,
                    measurement.prime_order_label,
                    measurement.data_prime_count,
                    measurement.target_level,
                    first_failed_joint_measurement_constraint(measurement).unwrap_or("none"),
                );
            }
        }

        pareto_measurements.sort_by(|left, right| {
            left.data_prime_count
                .cmp(&right.data_prime_count)
                .then_with(|| left.target_level.cmp(&right.target_level))
                .then_with(|| left.maximum_error_bound.cmp(&right.maximum_error_bound))
                .then_with(|| {
                    left.ceremony_evaluator_wire_byte_length
                        .cmp(&right.ceremony_evaluator_wire_byte_length)
                })
        });
        for measurement in &pareto_measurements {
            let prime_order = prime_order_candidates()
                .into_iter()
                .find(|candidate| candidate.label == measurement.prime_order_label)
                .expect("Pareto prime order is registered");
            let data_primes = &prime_order.data_primes[..measurement.data_prime_count];
            let compiled_measurement = compile_candidate_evaluator_program_measurement(
                &measurement.schedule,
                measurement.target_level,
                data_primes,
            )
            .expect("Pareto evaluator schedule compiles for every top count");
            let topology = joint_topology_candidates()
                .into_iter()
                .find(|candidate| candidate.label == measurement.topology_label)
                .expect("Pareto topology is registered");
            print_joint_measurement("jointPareto", measurement);
            println!(
                "jointCompiled topology={} primeOrder={} dataPrimeCount={} targetLevel={} minimumInstructions={} maximumInstructions={}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.target_level,
                compiled_measurement.minimum_instruction_count,
                compiled_measurement.maximum_instruction_count,
            );
            println!(
                "jointPrimeFamilies topology={} primeOrder={} dataPrimeCount={} galoisLevel={} galoisDataPrimes={:?} rkgLevel={} rkgDataPrimes={:?} kllpsTargetLevel={} kllpsDataPrimes={:?} specialPrimes={:?}",
                measurement.topology_label,
                measurement.prime_order_label,
                measurement.data_prime_count,
                measurement.working_level,
                data_primes,
                measurement.relinearization_level,
                &prime_order.data_primes[..=measurement.relinearization_level],
                measurement.target_level,
                &prime_order.data_primes[..=measurement.target_level],
                &SPECIAL_PRIMES[..topology.special_prime_count],
            );
        }
        assert!(finalist_measurement_count > 0);
    }

    #[test]
    #[ignore = "exact evaluator allocation search; run through the guarded measurements runner"]
    fn selected_evaluator_depth_drop_allocation_search_reports_exact_candidates() {
        const COMPARISON_CANDIDATES: [[usize; 8]; 8] = [
            [1, 1, 1, 1, 1, 1, 1, 1],
            [2, 1, 1, 1, 1, 1, 1, 0],
            [2, 2, 1, 1, 1, 1, 0, 0],
            [3, 1, 1, 1, 1, 1, 0, 0],
            [3, 2, 1, 1, 1, 0, 0, 0],
            [4, 1, 1, 1, 1, 0, 0, 0],
            [4, 2, 1, 1, 0, 0, 0, 0],
            [5, 1, 1, 1, 0, 0, 0, 0],
        ];
        const RANK_CANDIDATES: [[usize; 5]; 10] = [
            [2, 2, 2, 2, 2],
            [3, 2, 2, 2, 1],
            [3, 3, 2, 2, 0],
            [4, 3, 2, 1, 0],
            [5, 3, 1, 1, 0],
            [6, 2, 1, 1, 0],
            [6, 3, 1, 0, 0],
            [7, 2, 1, 0, 0],
            [8, 2, 0, 0, 0],
            [10, 0, 0, 0, 0],
        ];
        const EARLY_PRE_SCHEDULES: [EvaluatorModulusSchedule; 7] = [
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 8,
                comparison_depth_drop_counts: [1; 8],
                rank_depth_drop_counts: [4, 0, 0, 0, 0],
            },
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 9,
                comparison_depth_drop_counts: [1; 8],
                rank_depth_drop_counts: [3, 0, 0, 0, 0],
            },
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 10,
                comparison_depth_drop_counts: [1; 8],
                rank_depth_drop_counts: [2, 0, 0, 0, 0],
            },
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 11,
                comparison_depth_drop_counts: [1; 8],
                rank_depth_drop_counts: [1, 0, 0, 0, 0],
            },
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 12,
                comparison_depth_drop_counts: [1; 8],
                rank_depth_drop_counts: [0; 5],
            },
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 10,
                comparison_depth_drop_counts: [2, 1, 1, 1, 1, 1, 1, 0],
                rank_depth_drop_counts: [2, 0, 0, 0, 0],
            },
            EvaluatorModulusSchedule {
                pre_comparison_drop_count: 10,
                comparison_depth_drop_counts: [3, 1, 1, 1, 1, 1, 0, 0],
                rank_depth_drop_counts: [2, 0, 0, 0, 0],
            },
        ];
        let mut measurements = Vec::new();
        let balanced_zero_pre_schedule = EvaluatorModulusSchedule {
            pre_comparison_drop_count: 0,
            comparison_depth_drop_counts: [2, 1, 2, 1, 2, 1, 2, 1],
            rank_depth_drop_counts: [2, 1, 2, 1, 2],
        };
        let mut ascending_tail_data_primes = DATA_PRIMES;
        ascending_tail_data_primes[CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1..].sort_unstable();
        let mut descending_tail_data_primes = DATA_PRIMES;
        descending_tail_data_primes[CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1..]
            .sort_unstable_by(|left, right| right.cmp(left));
        for (prime_order_label, data_primes) in [
            ("current", DATA_PRIMES.as_slice()),
            ("largest-drop-first", ascending_tail_data_primes.as_slice()),
            (
                "smallest-drop-first",
                descending_tail_data_primes.as_slice(),
            ),
        ] {
            let balanced_zero_pre_measurement =
                measure_schedule_with_data_primes(balanced_zero_pre_schedule, data_primes)
                    .expect("balanced zero-pre candidate recurrence");
            println!(
                "primeOrder={} schedule pre={} comparison={:?} rank={:?} errorBits={} minimumMarginPositive={} factorFourC2Margin={} factorFour={}",
                prime_order_label,
                balanced_zero_pre_schedule.pre_comparison_drop_count,
                balanced_zero_pre_schedule.comparison_depth_drop_counts,
                balanced_zero_pre_schedule.rank_depth_drop_counts,
                balanced_zero_pre_measurement.maximum_error_bound.bits(),
                balanced_zero_pre_measurement.minimum_margin > BigInt::from(0_u8),
                balanced_zero_pre_measurement.factor_four_c2_margin,
                balanced_zero_pre_measurement.factor_four_conditions_hold,
            );
            measurements.push(balanced_zero_pre_measurement);
        }
        for (prime_order_label, data_primes) in [
            ("current", DATA_PRIMES.as_slice()),
            ("largest-drop-first", ascending_tail_data_primes.as_slice()),
        ] {
            for schedule in EARLY_PRE_SCHEDULES {
                let measurement = measure_schedule_with_data_primes(schedule, data_primes)
                    .expect("early pre-drop candidate recurrence");
                println!(
                    "primeOrder={} earlyPre schedule pre={} comparison={:?} rank={:?} errorBits={} minimumMarginPositive={} factorFourC2Margin={} factorFour={}",
                    prime_order_label,
                    schedule.pre_comparison_drop_count,
                    schedule.comparison_depth_drop_counts,
                    schedule.rank_depth_drop_counts,
                    measurement.maximum_error_bound.bits(),
                    measurement.minimum_margin > BigInt::from(0_u8),
                    measurement.factor_four_c2_margin,
                    measurement.factor_four_conditions_hold,
                );
                measurements.push(measurement);
            }
        }
        for comparison_depth_drop_counts in COMPARISON_CANDIDATES {
            for rank_depth_drop_counts in RANK_CANDIDATES {
                let schedule = EvaluatorModulusSchedule {
                    pre_comparison_drop_count: 2,
                    comparison_depth_drop_counts,
                    rank_depth_drop_counts,
                };
                if schedule.total_drop_count() != 20 {
                    continue;
                }
                let measurement = measure_schedule(schedule).expect("candidate recurrence");
                println!(
                    "schedule pre={} comparison={:?} rank={:?} errorBits={} minimumMarginPositive={} factorFourC2Margin={} factorFour={}",
                    schedule.pre_comparison_drop_count,
                    schedule.comparison_depth_drop_counts,
                    schedule.rank_depth_drop_counts,
                    measurement.maximum_error_bound.bits(),
                    measurement.minimum_margin > BigInt::from(0_u8),
                    measurement.factor_four_c2_margin,
                    measurement.factor_four_conditions_hold,
                );
                measurements.push(measurement);
            }
        }
        measurements.sort_by(|left, right| {
            left.maximum_error_bound
                .cmp(&right.maximum_error_bound)
                .then_with(|| right.minimum_margin.cmp(&left.minimum_margin))
        });
        let best = measurements.first().expect("search evaluates candidates");
        println!(
            "best schedule pre={} comparison={:?} rank={:?} maximumError={} errorBits={} minimumMarginPositive={} factorFourC2Margin={} factorFour={}",
            best.schedule.pre_comparison_drop_count,
            best.schedule.comparison_depth_drop_counts,
            best.schedule.rank_depth_drop_counts,
            best.maximum_error_bound,
            best.maximum_error_bound.bits(),
            best.minimum_margin > BigInt::from(0_u8),
            best.factor_four_c2_margin,
            best.factor_four_conditions_hold,
        );
    }

    #[test]
    fn collective_fresh_and_aggregate_bounds_include_every_trustee_error() {
        let fresh = SymbolicCiphertextBound::fresh_direct_ballot(10).unwrap();
        assert_eq!(
            fresh.error_coefficient_bound,
            BigUint::from(40_u8) * BigUint::from(POLYNOMIAL_DEGREE) + BigUint::from(3_u8)
        );

        let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots(10, 10).unwrap();
        assert_eq!(
            aggregate.error_coefficient_bound,
            BigUint::from(10_u8) * fresh.error_coefficient_bound + BigUint::from(9_u8)
        );
    }

    #[test]
    fn key_switch_error_uses_the_exact_relinearization_or_galois_key_distribution() {
        let collective_secret_coefficient_bound = 10_u64;
        let special_basis_modulus = SPECIAL_PRIMES[..6]
            .iter()
            .map(|prime| BigUint::from(*prime))
            .product::<BigUint>();
        let relinearization_key_error = collective_evaluation_key_error_bound(
            EvaluationKeyErrorKind::Relinearization,
            collective_secret_coefficient_bound,
        );
        let galois_key_error = collective_evaluation_key_error_bound(
            EvaluationKeyErrorKind::Galois,
            collective_secret_coefficient_bound,
        );
        assert_eq!(relinearization_key_error, BigUint::from(26_214_420_u64));
        assert_eq!(galois_key_error, BigUint::from(20_u8));

        let relinearization_decomposed_error = hybrid_key_switch_decomposed_error_bound(
            DATA_PRIMES.len() - 1,
            7,
            &DATA_PRIMES,
            &special_basis_modulus,
            &relinearization_key_error,
        )
        .expect("P6/B7 relinearization decomposition bound");
        let galois_decomposed_error = hybrid_key_switch_decomposed_error_bound(
            DATA_PRIMES.len() - 1,
            7,
            &DATA_PRIMES,
            &special_basis_modulus,
            &galois_key_error,
        )
        .expect("P6/B7 Galois decomposition bound");
        assert_eq!(
            relinearization_decomposed_error,
            BigUint::from(1_999_741_091_069_u64)
        );
        assert_eq!(galois_decomposed_error, BigUint::from(1_525_681_u64));

        let two_component_bound = SymbolicCiphertextBound::fresh_direct_ballot_with_data_primes(
            collective_secret_coefficient_bound,
            Arc::from(DATA_PRIMES),
            7,
            Arc::new(special_basis_modulus),
        )
        .expect("P6/B7 two-component bound");
        let rotated = two_component_bound
            .rotate_once()
            .expect("Galois key switch bound");
        assert_eq!(
            &rotated.error_coefficient_bound - &two_component_bound.error_coefficient_bound,
            galois_decomposed_error + BigUint::from(327_681_u64)
        );

        let mut three_component_bound = two_component_bound.clone();
        three_component_bound.component_count = 3;
        let relinearized = three_component_bound
            .key_switch(EvaluationKeyErrorKind::Relinearization)
            .expect("relinearization key switch bound");
        assert_eq!(
            &relinearized.error_coefficient_bound - &three_component_bound.error_coefficient_bound,
            relinearization_decomposed_error + BigUint::from(327_681_u64)
        );
    }

    #[test]
    fn canonical_plaintext_lifts_and_scaling_multipliers_are_accounted_exactly() {
        let mut zero_bound = SymbolicCiphertextBound::fresh_direct_ballot(10).unwrap();
        zero_bound.message_coefficient_bound = BigUint::zero();
        zero_bound.error_coefficient_bound = BigUint::zero();

        let small_canonical_plaintext = zero_bound
            .add_plaintext_coefficients(&[1])
            .expect("small canonical plaintext addition");
        assert_eq!(
            small_canonical_plaintext.error_coefficient_bound,
            BigUint::zero()
        );
        let lifted_negative_plaintext = zero_bound
            .add_plaintext_coefficients(&[PLAINTEXT_MODULUS - 1])
            .expect("lifted negative plaintext addition");
        assert_eq!(
            lifted_negative_plaintext.error_coefficient_bound,
            BigUint::one()
        );

        let mut noncentered_scaling_bound = zero_bound;
        noncentered_scaling_bound.decrypt_scaling = PLAINTEXT_MODULUS - 1;
        noncentered_scaling_bound.message_coefficient_bound = BigUint::from(7_u8);
        noncentered_scaling_bound.error_coefficient_bound = BigUint::from(11_u8);
        let normalized = noncentered_scaling_bound
            .normalize_scaling()
            .expect("canonical scaling normalization");
        assert_eq!(normalized.decrypt_scaling, 1);
        assert_eq!(
            normalized.error_coefficient_bound,
            BigUint::from(PLAINTEXT_MODULUS - 1) * BigUint::from(11_u8) + BigUint::from(7_u8)
        );
    }

    #[test]
    fn recurrence_rejects_invalid_ballot_multiplicities() {
        assert!(SymbolicCiphertextBound::aggregate_fresh_direct_ballots(10, 0).is_err());
        assert!(SymbolicCiphertextBound::aggregate_fresh_direct_ballots(10, 11).is_err());
        assert!(SymbolicCiphertextBound::fresh_direct_ballot(0).is_err());
    }

    #[test]
    fn every_top_count_has_an_exact_symbolic_target_bound() {
        let bounds = direct_ballot_target_noise_bounds(10, 10, 20, 1, 10).unwrap();
        for bound in &bounds {
            println!(
                "topCount={} maximumError={} errorBits={} identifierFinalMargin={} orderFinalMargin={} identifierMinimumMargin={} orderMinimumMargin={}",
                bound.top_count,
                bound.maximum_error_coefficient_bound(),
                bound.maximum_error_coefficient_bound().bits(),
                bound.target_identifier.final_decryption_margin(),
                bound.target_order.final_decryption_margin(),
                bound.target_identifier.minimum_decryption_margin,
                bound.target_order.minimum_decryption_margin,
            );
        }
        assert_eq!(bounds.len(), 20);
        assert_eq!(
            bounds
                .iter()
                .map(|bound| bound.top_count)
                .collect::<Vec<_>>(),
            (1..=20).collect::<Vec<_>>()
        );
        let expected_error_bound_bit_lengths = vec![
            5195, 5196, 5196, 5196, 5195, 5195, 5195, 5196, 5196, 5196, 5196, 5196, 5195, 5195,
            5193, 5194, 5195, 5196, 5195, 74,
        ];
        let actual_error_bound_bit_lengths = bounds
            .iter()
            .map(|bound| bound.maximum_error_coefficient_bound().bits())
            .collect::<Vec<_>>();
        assert_eq!(
            actual_error_bound_bit_lengths,
            expected_error_bound_bit_lengths
        );
        for bound in &bounds {
            assert_eq!(bound.target_identifier.component_count, 2);
            assert_eq!(bound.target_order.component_count, 2);
            assert!(bound.maximum_error_coefficient_bound() > &BigUint::from(0_u8));
            assert_eq!(
                bound.every_decryption_margin_is_positive(),
                bound.top_count == 20
            );
            assert_eq!(
                bound.target_identifier.level,
                CANONICAL_TARGET_CIPHERTEXT_LEVEL
            );
            assert_eq!(bound.target_order.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);
        }
    }

    #[test]
    fn one_ballot_all_target_schedule_uses_the_canonical_levels() {
        let bounds = direct_ballot_target_noise_bounds(10, 1, 20, 1, 10)
            .expect("the canonical working level supports the one-ballot schedule");

        assert_eq!(bounds.len(), 20);
        assert_eq!(
            bounds
                .iter()
                .map(|bound| bound.top_count)
                .collect::<Vec<_>>(),
            (1..=20).collect::<Vec<_>>()
        );
        assert!(bounds.iter().all(|bound| {
            bound.target_identifier.level == CANONICAL_TARGET_CIPHERTEXT_LEVEL
                && bound.target_order.level == CANONICAL_TARGET_CIPHERTEXT_LEVEL
        }));
    }
}
