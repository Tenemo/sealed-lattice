//! Conservative instruction-by-instruction error recurrence for the exact BGV
//! evaluator implementation.
//!
//! This module is independent parameter evidence. Its values are never read
//! from ciphertexts and are not serialized into protocol artifacts. The
//! recurrence follows the implemented coefficient-domain operations, including
//! canonical plaintext carries, scaling normalization, exact centered hybrid
//! Q/P key switching, and the exact BGV modulus-switch correction.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};

use crate::{
    bgv::{
        key_switch_topology::{
            KEY_SWITCH_DATA_PRIMES_PER_BLOCK, key_switch_special_basis_modulus_product,
        },
        modular_arithmetic::{inverse_mod, mul_mod},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

use super::{
    circuit::broadcast_constant_coefficients,
    top_k::{
        CANONICAL_TARGET_CIPHERTEXT_LEVEL, DIRECT_COMPARISON_OUTPUT_LEVEL,
        RANK_LOOKUP_BABY_STEP_COUNT, SELECTED_EVALUATOR_WORKING_LEVEL, comparison_polynomials,
        direct_comparison_baby_step_count, galois_power, generator_exponent_or_conjugated,
        generator_inverse_power_basis_for_exponent, generator_power_basis_for_exponent,
        interpolate_coefficients, packed_pair_lower_mask, packed_score_slot_selector,
        packed_score_weighted_selector,
    },
};

const CENTERED_PLAINTEXT_BOUND: u64 = PLAINTEXT_MODULUS / 2;
const FRESH_ERROR_COEFFICIENT_BOUND: u64 = 2;
const FRESH_RANDOMIZER_COEFFICIENT_BOUND: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SymbolicCiphertextBound {
    pub(crate) level: usize,
    pub(crate) decrypt_scaling: u64,
    pub(crate) message_coefficient_bound: BigUint,
    pub(crate) error_coefficient_bound: BigUint,
    pub(crate) component_count: usize,
    pub(crate) collective_secret_coefficient_bound: u64,
    pub(crate) minimum_decryption_margin: BigInt,
}

impl SymbolicCiphertextBound {
    pub(crate) fn fresh_direct_ballot(
        collective_secret_coefficient_bound: u64,
    ) -> CanonicalResult<Self> {
        if collective_secret_coefficient_bound == 0 {
            return Err(invalid_recurrence(
                "collective secret coefficient bound must be positive",
            ));
        }

        // The collective public-key error is the sum of one eta-two error per
        // trustee. For b = t*e_pk - a*s and ciphertext errors e0,e1,
        //
        //   c0 + c1*s = m + t*(e_pk*u + e0 + e1*s).
        //
        // Both e_pk*u and e1*s use the collective coefficient bound.
        let convolution_factor = BigUint::from(POLYNOMIAL_DEGREE)
            * BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND)
            * BigUint::from(FRESH_RANDOMIZER_COEFFICIENT_BOUND)
            * BigUint::from(collective_secret_coefficient_bound);
        let error_coefficient_bound =
            (&convolution_factor << 1_usize) + BigUint::from(FRESH_ERROR_COEFFICIENT_BOUND);
        let mut bound = Self {
            level: DATA_PRIMES.len() - 1,
            decrypt_scaling: 1,
            message_coefficient_bound: BigUint::from(CENTERED_PLAINTEXT_BOUND),
            error_coefficient_bound,
            component_count: 2,
            collective_secret_coefficient_bound,
            minimum_decryption_margin: BigInt::zero(),
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

        let fresh = Self::fresh_direct_ballot(participant_count)?;
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
        let (plaintext_infinity_bound, _) = plaintext_polynomial_norms(plaintext_coefficients);
        let scaling = centered_residue_i128(self.decrypt_scaling);
        let inverse_scaling = self.scaling_inverse()?;
        let inverse_scaling_centered = centered_residue_i128(inverse_scaling);
        let scaling_product_carry =
            (inverse_scaling_centered * scaling - 1) / i128::from(PLAINTEXT_MODULUS);
        let unreduced_message_bound =
            &self.message_coefficient_bound + (absolute_i128(scaling) * &plaintext_infinity_bound);
        let message_carry_bound = centered_reduction_carry_bound(&unreduced_message_bound);
        let error_coefficient_bound = &self.error_coefficient_bound
            + (absolute_i128(inverse_scaling_centered) * message_carry_bound)
            + (absolute_i128(scaling_product_carry) * plaintext_infinity_bound);

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
        let (_, plaintext_l1_norm) = plaintext_polynomial_norms(plaintext_coefficients);
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
        let scaling = centered_residue_i128(self.decrypt_scaling);
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

    pub(crate) fn key_switch(&self) -> CanonicalResult<Self> {
        if self.component_count < 2 || self.component_count > 3 {
            return Err(invalid_recurrence(
                "key switching requires a two- or three-component ciphertext bound",
            ));
        }
        let error_coefficient_bound = &self.error_coefficient_bound
            + hybrid_key_switch_error_bound(
                self.level,
                self.collective_secret_coefficient_bound,
                KEY_SWITCH_DATA_PRIMES_PER_BLOCK,
            )?;

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
        let dropped_modulus = DATA_PRIMES[self.level];
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
        let half_dropped_modulus = BigUint::from(dropped_modulus / 2);
        let secret_l1_bound = BigUint::from(POLYNOMIAL_DEGREE)
            * BigUint::from(self.collective_secret_coefficient_bound);
        let correction_bound = half_dropped_modulus * (BigUint::one() + secret_l1_bound);
        let numerator_bound = &self.error_coefficient_bound
            + correction_bound
            + (absolute_i128(scaling_transition_carry) * &self.message_coefficient_bound);
        let error_coefficient_bound =
            divide_with_ceiling(&numerator_bound, &BigUint::from(dropped_modulus));

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
        let target_level = self.level.min(other.level);
        let left = self.modulus_switch_to(target_level)?;
        let right = other.modulus_switch_to(target_level)?;
        left.tensor(&right)?.key_switch()?.modulus_switch()
    }

    pub(crate) fn multiply_without_terminal_switch(&self, other: &Self) -> CanonicalResult<Self> {
        let target_level = self.level.min(other.level);
        let left = self.modulus_switch_to(target_level)?;
        let right = other.modulus_switch_to(target_level)?;
        left.tensor(&right)?.key_switch()
    }

    pub(crate) fn rotate_once(&self) -> CanonicalResult<Self> {
        self.key_switch()
    }

    pub(crate) fn final_decryption_margin(&self) -> BigInt {
        BigInt::from(active_modulus(self.level))
            - BigInt::from(BigUint::from(2_u8) * raw_decryption_bound(self))
    }

    pub(crate) fn raw_decryption_bound(&self) -> BigUint {
        raw_decryption_bound(self)
    }

    pub(crate) fn active_modulus(&self) -> BigUint {
        active_modulus(self.level)
    }

    fn scaling_inverse(&self) -> CanonicalResult<u64> {
        inverse_mod(self.decrypt_scaling, PLAINTEXT_MODULUS)
    }

    fn require_same_level_and_scaling(&self, other: &Self, operation: &str) -> CanonicalResult<()> {
        if self.level != other.level
            || self.decrypt_scaling != other.decrypt_scaling
            || self.collective_secret_coefficient_bound != other.collective_secret_coefficient_bound
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
) -> CanonicalResult<BigUint> {
    if level >= DATA_PRIMES.len()
        || data_primes_per_block == 0
        || collective_secret_coefficient_bound == 0
    {
        return Err(invalid_recurrence(
            "hybrid key-switch recurrence received an invalid level, block size, or secret bound",
        ));
    }
    let active_data_primes = &DATA_PRIMES[..=level];
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
    let trustee_bound = BigUint::from(collective_secret_coefficient_bound);
    let collective_rkg_error_bound = BigUint::from(2_u8)
        * &ring_degree
        * &trustee_bound
        * (BigUint::from(2_u8) * &trustee_bound)
        + (BigUint::from(2_u8) * &trustee_bound);
    let decomposed_error_numerator = BigUint::from(active_block_count)
        * &ring_degree
        * maximum_block_modulus
        * collective_rkg_error_bound;
    let twice_special_basis_modulus =
        BigUint::from(2_u8) * key_switch_special_basis_modulus_product();
    let decomposed_error =
        divide_with_ceiling(&decomposed_error_numerator, &twice_special_basis_modulus);
    let component_b_correction = BigUint::one();
    let component_a_secret_correction =
        divide_with_ceiling(&(&ring_degree * trustee_bound), &BigUint::from(2_u8));

    Ok(decomposed_error + component_b_correction + component_a_secret_correction)
}

fn raw_decryption_bound(bound: &SymbolicCiphertextBound) -> BigUint {
    (absolute_centered_residue(
        bound
            .scaling_inverse()
            .expect("nonzero plaintext scaling is invertible"),
    ) * &bound.message_coefficient_bound)
        + (BigUint::from(PLAINTEXT_MODULUS) * &bound.error_coefficient_bound)
}

fn active_modulus(level: usize) -> BigUint {
    DATA_PRIMES[..=level]
        .iter()
        .map(|prime| BigUint::from(*prime))
        .product()
}

fn plaintext_polynomial_norms(coefficients: &[u64]) -> (BigUint, BigUint) {
    let mut infinity_bound = BigUint::zero();
    let mut l1_norm = BigUint::zero();
    for coefficient in coefficients {
        let absolute_coefficient = absolute_i128(centered_residue_i128(*coefficient));
        infinity_bound = infinity_bound.max(absolute_coefficient.clone());
        l1_norm += absolute_coefficient;
    }

    (infinity_bound, l1_norm)
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
    direct_ballot_target_noise_bounds_at_working_level(
        participant_count,
        ballot_count,
        option_count,
        minimum_score,
        maximum_score,
        SELECTED_EVALUATOR_WORKING_LEVEL,
    )
}

pub(crate) fn direct_ballot_target_noise_bounds_at_working_level(
    participant_count: u64,
    ballot_count: usize,
    option_count: usize,
    minimum_score: u64,
    maximum_score: u64,
    working_level: usize,
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
    if working_level >= DATA_PRIMES.len() {
        return Err(invalid_recurrence(
            "evaluator working level is outside the selected data basis",
        ));
    }

    let aggregate =
        SymbolicCiphertextBound::aggregate_fresh_direct_ballots(participant_count, ballot_count)?;
    let working_aggregate = aggregate.modulus_switch_to(working_level)?;
    let packed_scores = symbolic_pack_direct_score_slots(&working_aggregate, option_count)?;
    let packed_ranks = symbolic_packed_rank_evaluation(
        &packed_scores,
        option_count,
        score_domain_maximum,
        working_level,
    )?;

    (1..=option_count)
        .map(|top_count| {
            let (target_identifier, target_order) = symbolic_sparse_target_projection(
                &packed_ranks,
                option_count,
                top_count,
                working_level,
            )?;
            Ok(DirectBallotTargetNoiseBound {
                top_count,
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
    let selected_scores = direct_scores
        .normalize_scaling()?
        .plaintext_multiply(&packed_score_slot_selector(&option_indices)?)?;
    let duplicated_scores = symbolic_rotate_inverse(&selected_scores, option_count)?;

    symbolic_sum_aligned(&[selected_scores, duplicated_scores])
}

fn symbolic_packed_rank_evaluation(
    packed_scores: &SymbolicCiphertextBound,
    option_count: usize,
    score_domain_maximum: u64,
    working_level: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
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
    let comparison_input_switch_count = if working_level >= SELECTED_EVALUATOR_WORKING_LEVEL {
        2
    } else {
        1
    };
    let refreshed_comparison_inputs = comparison_inputs.modulus_switch_to(
        comparison_inputs
            .level
            .saturating_sub(comparison_input_switch_count),
    )?;
    let comparison_outputs = symbolic_evaluate_polynomial(
        &refreshed_comparison_inputs,
        &greater_or_equal_polynomial,
        direct_comparison_baby_step_count(score_domain_maximum)?,
        working_level,
    )?;

    let mut rank_sum = None;
    for (shift, window_offset, pair_window_size) in pair_windows {
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
            lower_beats_higher_for_lower_slots.modulus_switch_to(DIRECT_COMPARISON_OUTPUT_LEVEL)?;
        let lower_beats_higher_at_higher_slot =
            symbolic_rotate_inverse(&lower_beats_higher_for_return, shift)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, higher_beats_lower_for_lower_slots)?;
        symbolic_add_to_aligned_sum(&mut rank_sum, lower_beats_higher_at_higher_slot)?;
    }

    rank_sum.ok_or_else(|| invalid_recurrence("packed-rank recurrence produced no rank terms"))
}

fn symbolic_sparse_target_projection(
    packed_ranks: &SymbolicCiphertextBound,
    option_count: usize,
    top_count: usize,
    working_level: usize,
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
            target_identifier.modulus_switch_to(CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
            target_order.modulus_switch_to(CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
        ));
    }

    let normalized_rank = packed_ranks
        .modulus_switch_to(working_level)?
        .normalize_scaling()?;
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
    let indicator = symbolic_rank_lookup(&normalized_rank, &indicator_values, working_level)?;
    let order_value = symbolic_rank_lookup(&normalized_rank, &order_values, working_level)?;

    let target_identifier = indicator
        .normalize_scaling()?
        .plaintext_multiply(&id_selector)?;
    let target_order = order_value
        .normalize_scaling()?
        .plaintext_multiply(&option_slot_mask)?;

    Ok((
        target_identifier.modulus_switch_to(CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
        target_order.modulus_switch_to(CANONICAL_TARGET_CIPHERTEXT_LEVEL)?,
    ))
}

fn symbolic_rank_lookup(
    normalized_rank: &SymbolicCiphertextBound,
    values: &[u64],
    working_level: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let polynomial = interpolate_coefficients(values)?;
    symbolic_evaluate_polynomial(
        normalized_rank,
        &polynomial,
        RANK_LOOKUP_BABY_STEP_COUNT,
        working_level,
    )
}

fn symbolic_evaluate_polynomial(
    input: &SymbolicCiphertextBound,
    coefficients: &[u64],
    baby_step_count: usize,
    working_level: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    if coefficients.is_empty() || baby_step_count < 2 {
        return Err(invalid_recurrence(
            "symbolic polynomial evaluation requires coefficients and at least two baby steps",
        ));
    }
    let degree = coefficients.len() - 1;
    if degree == 0 || degree < baby_step_count {
        return symbolic_evaluate_polynomial_by_power_table(input, coefficients, working_level);
    }

    let block_count = coefficients.len().div_ceil(baby_step_count);
    let working_input = input.modulus_switch_to(working_level)?;
    let baby_powers = symbolic_build_power_table(&working_input, baby_step_count)?;
    let giant_base = baby_powers[baby_step_count]
        .as_ref()
        .ok_or_else(|| invalid_recurrence("symbolic baby power is missing"))?
        .clone();
    let giant_powers = symbolic_build_power_table(&giant_base, block_count.saturating_sub(1))?;
    let mut terms = Vec::new();

    for (block_index, giant_power) in giant_powers.iter().enumerate().take(block_count) {
        let start = block_index * baby_step_count;
        let end = coefficients.len().min(start + baby_step_count);
        let block_coefficients = &coefficients[start..end];
        if block_coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
        {
            continue;
        }
        let block_value = symbolic_linear_combination_from_powers(
            &working_input,
            &baby_powers,
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
            terms.push(giant_power.scalar_multiply(
                i64::try_from(block_coefficients[0]).expect("plaintext coefficient fits i64"),
            )?);
        } else {
            terms.push(block_value.multiply_without_terminal_switch(giant_power)?);
        }
    }

    if terms.is_empty() {
        return symbolic_evaluate_polynomial_by_power_table(input, &[0], working_level);
    }
    symbolic_sum_aligned(&terms)
}

fn symbolic_evaluate_polynomial_by_power_table(
    input: &SymbolicCiphertextBound,
    coefficients: &[u64],
    working_level: usize,
) -> CanonicalResult<SymbolicCiphertextBound> {
    let degree = coefficients.len() - 1;
    let working_input = input.modulus_switch_to(working_level)?;
    let mut powers = vec![None; degree + 1];
    if degree >= 1 {
        powers[1] = Some(working_input.clone());
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
        powers[power] = Some(low_power.multiply_and_switch(high_power)?);
    }
    symbolic_linear_combination_from_powers(&working_input, &powers, coefficients)
}

fn symbolic_build_power_table(
    base: &SymbolicCiphertextBound,
    highest_power: usize,
) -> CanonicalResult<Vec<Option<SymbolicCiphertextBound>>> {
    let mut powers = vec![None; highest_power + 1];
    if highest_power >= 1 {
        powers[1] = Some(base.clone());
    }
    for power in 2..=highest_power {
        let low = power / 2;
        let high = power - low;
        let low_power = powers[low]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic low power is missing"))?;
        let high_power = powers[high]
            .as_ref()
            .ok_or_else(|| invalid_recurrence("symbolic high power is missing"))?;
        powers[power] = Some(low_power.multiply_and_switch(high_power)?);
    }

    Ok(powers)
}

fn symbolic_linear_combination_from_powers(
    reference: &SymbolicCiphertextBound,
    powers: &[Option<SymbolicCiphertextBound>],
    coefficients: &[u64],
) -> CanonicalResult<SymbolicCiphertextBound> {
    let target_level = coefficients
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, coefficient)| **coefficient != 0)
        .filter_map(|(power, _)| powers[power].as_ref().map(|bound| bound.level))
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
mod tests {
    use num_bigint::BigUint;

    use super::{
        CANONICAL_TARGET_CIPHERTEXT_LEVEL, SymbolicCiphertextBound,
        direct_ballot_target_noise_bounds,
    };
    use crate::bgv::parameters::POLYNOMIAL_DEGREE;

    #[test]
    fn collective_fresh_and_aggregate_bounds_include_every_trustee_error() {
        let fresh = SymbolicCiphertextBound::fresh_direct_ballot(10).unwrap();
        assert_eq!(
            fresh.error_coefficient_bound,
            BigUint::from(40_u8) * BigUint::from(POLYNOMIAL_DEGREE) + BigUint::from(2_u8)
        );

        let aggregate = SymbolicCiphertextBound::aggregate_fresh_direct_ballots(10, 10).unwrap();
        assert_eq!(
            aggregate.error_coefficient_bound,
            BigUint::from(10_u8) * fresh.error_coefficient_bound + BigUint::from(9_u8)
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
