use super::*;
use crate::encoding::CanonicalResult;

#[cfg(test)]
use super::{
    parameters::demo_linear_proof_encoding_contract, profile_constants::DEMO_GENERATED_PROFILE,
};
use super::{
    parameters::{LinearProofEncoding, LinearProofProfile, linear_proof_profile_for_encoding},
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    public_parameters::DEFAULT_LINEAR_PROOF_RING_DEGREE,
    quadratic_equation::{LinearProofQuadraticEquation, WeightedLinearProofQuadraticEquation},
    rng::sample_linear_proof_uniform_u64_values,
    sparse_polynomial_matrix::SparsePolynomialMatrix,
};

pub(super) const TBOX_UPSILON_COORDINATES: usize = 1;
pub(super) const TBOX_UNBOUNDED_MESSAGE_LENGTH: usize = 0;
pub(super) const TBOX_APPROXIMATE_NORM_COORDINATES: usize = 16;
#[cfg(test)]
pub(super) const TBOX_EXACT_NORM_DIMENSION: usize = 32;
#[cfg(test)]
pub(super) const TBOX_EXACT_NORM_BOUND_SQUARED: u64 =
    DEMO_GENERATED_PROFILE.exact_norm_bound_squared;
pub(super) const TBOX_EXTENDED_COORDINATES: usize = 33;
pub(crate) const TBOX_QUADRATIC_EVALUATION_MESSAGE_LENGTH: usize = 9;
pub(crate) const TBOX_QUADRATIC_MANY_MESSAGE_LENGTH: usize = 11;
pub(super) const TBOX_QUADRATIC_EVALUATION_REPETITIONS: usize = 4;

// Each constant reserves a contiguous, non-overlapping Fiat-Shamir challenge
// block (beta3, beta4, upsilon, binary, euclidean, z4, z3 in order). The cumulative
// offsets are frozen against the generated LaZer vectors: changing the layout is a
// proof-profile change, not a local patch.
pub(super) const TBOX_BETA3_DOMAIN_OFFSET: u32 = 0;
pub(super) const TBOX_BETA4_DOMAIN_OFFSET: u32 =
    (TBOX_QUADRATIC_EVALUATION_REPETITIONS * (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1)) as u32;
pub(super) const TBOX_UPSILON_DOMAIN_OFFSET: u32 =
    (TBOX_QUADRATIC_EVALUATION_REPETITIONS * 2 * (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1)) as u32;
pub(super) const TBOX_BINARY_DOMAIN_OFFSET: u32 = (TBOX_QUADRATIC_EVALUATION_REPETITIONS
    * (2 * (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) + 1))
    as u32;
pub(super) const TBOX_EUCLIDEAN_DOMAIN_OFFSET: u32 = (TBOX_QUADRATIC_EVALUATION_REPETITIONS
    * (2 * (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) + 2))
    as u32;
pub(super) const TBOX_Z4_RESPONSE_DOMAIN_OFFSET: u32 = (TBOX_QUADRATIC_EVALUATION_REPETITIONS
    * (2 * (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) + 2 + TBOX_UPSILON_COORDINATES))
    as u32;
pub(super) const TBOX_Z3_RESPONSE_DOMAIN_OFFSET: u32 = (TBOX_QUADRATIC_EVALUATION_REPETITIONS
    * (2 * (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) + 2 + TBOX_UPSILON_COORDINATES + 256))
    as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TboxRelationProfile {
    pub(super) proof_ring: PolynomialRing,
    pub(super) coefficient_bit_length: usize,
    pub(super) exact_norm_bound_squared: u64,
    pub(super) euclidean_response_vector_length: usize,
    pub(super) infinity_response_vector_length: usize,
    pub(super) short_response_message_length: usize,
}

impl TboxRelationProfile {
    fn from_proof_encoding(proof_encoding: &LinearProofEncoding) -> CanonicalResult<Self> {
        proof_encoding.validate()?;
        let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
        Self::from_parts(proof_encoding, proof_profile)
    }

    fn from_parts(
        proof_encoding: &LinearProofEncoding,
        proof_profile: LinearProofProfile,
    ) -> CanonicalResult<Self> {
        Ok(Self {
            proof_ring: PolynomialRing::new(
                proof_encoding.ring_degree,
                proof_encoding.coefficient_modulus,
            )?,
            coefficient_bit_length: proof_encoding.full_size_coefficient_bit_length,
            exact_norm_bound_squared: proof_profile.exact_norm_bound_squared,
            euclidean_response_vector_length: proof_encoding.euclidean_response_vector_length,
            infinity_response_vector_length: proof_encoding.infinity_response_vector_length,
            short_response_message_length: proof_encoding.short_response_vector_length,
        })
    }

    pub(super) fn short_message_without_upsilon(self) -> usize {
        self.short_response_message_length - TBOX_UPSILON_COORDINATES
    }

    pub(super) fn extended_coordinates(self) -> usize {
        self.short_response_message_length
    }

    pub(super) fn exact_norm_dimension(self) -> usize {
        self.short_response_message_length - TBOX_UPSILON_COORDINATES
    }

    pub(super) fn approximate_relation_polynomial_count(self) -> usize {
        self.infinity_response_vector_length
    }

    pub(super) fn beta_offset(self) -> usize {
        (self.short_message_without_upsilon()
            + TBOX_UPSILON_COORDINATES
            + TBOX_UNBOUNDED_MESSAGE_LENGTH
            + self.approximate_relation_polynomial_count()
            + self.approximate_relation_polynomial_count())
            * 2
    }

    pub(super) fn upsilon_offset(self) -> usize {
        self.short_message_without_upsilon() * 2
    }

    pub(super) fn y3_offset(self) -> usize {
        (self.short_message_without_upsilon()
            + TBOX_UPSILON_COORDINATES
            + TBOX_UNBOUNDED_MESSAGE_LENGTH)
            * 2
    }

    pub(super) fn y4_offset(self) -> usize {
        (self.short_message_without_upsilon()
            + TBOX_UPSILON_COORDINATES
            + TBOX_UNBOUNDED_MESSAGE_LENGTH
            + self.approximate_relation_polynomial_count())
            * 2
    }

    pub(super) fn quadratic_evaluation_dimension(self) -> usize {
        2 * (self.short_response_message_length + TBOX_QUADRATIC_EVALUATION_MESSAGE_LENGTH)
    }

    pub(super) fn quadratic_many_dimension(self) -> usize {
        2 * (self.short_response_message_length + TBOX_QUADRATIC_MANY_MESSAGE_LENGTH)
    }
}

#[cfg(test)]
pub(super) fn demo_tbox_profile() -> CanonicalResult<TboxRelationProfile> {
    TboxRelationProfile::from_proof_encoding(&demo_linear_proof_encoding_contract())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TboxRelationAccumulatorSet {
    pub(crate) primary_schwartz_zippel_accumulators: Vec<LinearProofQuadraticEquation>,
    pub(crate) secondary_schwartz_zippel_accumulators: Vec<LinearProofQuadraticEquation>,
    pub(crate) extra_beta_norm_equations: Vec<LinearProofQuadraticEquation>,
}

impl TboxRelationAccumulatorSet {
    pub(crate) fn auto_folded_equations(
        &self,
    ) -> CanonicalResult<Vec<LinearProofQuadraticEquation>> {
        if self.primary_schwartz_zippel_accumulators.len()
            != self.secondary_schwartz_zippel_accumulators.len()
        {
            return Err(invalid_tbox_relation(
                "primary and secondary accumulator counts must match",
            ));
        }

        let mut folded_equations = Vec::with_capacity(
            self.primary_schwartz_zippel_accumulators.len() + self.extra_beta_norm_equations.len(),
        );
        for (primary_accumulator, secondary_accumulator) in self
            .primary_schwartz_zippel_accumulators
            .iter()
            .zip(&self.secondary_schwartz_zippel_accumulators)
        {
            folded_equations
                .push(primary_accumulator.schwartz_zippel_auto_fold_with(secondary_accumulator)?);
        }
        folded_equations.extend(self.extra_beta_norm_equations.iter().cloned());

        Ok(folded_equations)
    }
}

#[cfg(test)]
pub(crate) fn initialize_default_tbox_relation_accumulators()
-> CanonicalResult<TboxRelationAccumulatorSet> {
    initialize_tbox_relation_accumulators(demo_tbox_profile()?)
}

pub(super) fn initialize_tbox_relation_accumulators(
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<TboxRelationAccumulatorSet> {
    validate_tbox_shape()?;

    let proof_ring = tbox_profile.proof_ring;
    let equation_dimension = tbox_profile.quadratic_evaluation_dimension();
    // One accumulator per Schwartz-Zippel pair: each pair consumes two of the
    // four repetitions (one primary, one secondary evaluation point).
    let accumulator_count = TBOX_QUADRATIC_EVALUATION_REPETITIONS / 2;
    let primary_schwartz_zippel_accumulators = (0..accumulator_count)
        .map(|_| LinearProofQuadraticEquation::zero(proof_ring, equation_dimension))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secondary_schwartz_zippel_accumulators = (0..accumulator_count)
        .map(|_| LinearProofQuadraticEquation::zero(proof_ring, equation_dimension))
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(TboxRelationAccumulatorSet {
        primary_schwartz_zippel_accumulators,
        secondary_schwartz_zippel_accumulators,
        extra_beta_norm_equations: vec![
            build_beta3_norm_equation(tbox_profile)?,
            build_beta4_norm_equation(tbox_profile)?,
        ],
    })
}

#[cfg(test)]
pub(crate) fn build_default_tbox_prefix_accumulators(
    challenge_seed: &[u8; 32],
) -> CanonicalResult<TboxRelationAccumulatorSet> {
    build_tbox_prefix_accumulators(challenge_seed, &demo_linear_proof_encoding_contract())
}

pub(crate) fn build_tbox_prefix_accumulators(
    challenge_seed: &[u8; 32],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<TboxRelationAccumulatorSet> {
    let tbox_profile = TboxRelationProfile::from_proof_encoding(proof_encoding)?;
    let mut accumulator_set = initialize_tbox_relation_accumulators(tbox_profile)?;
    apply_tbox_beta3_relations(&mut accumulator_set, challenge_seed, tbox_profile)?;
    apply_tbox_beta4_relations(&mut accumulator_set, challenge_seed, tbox_profile)?;
    apply_tbox_upsilon_relation(&mut accumulator_set, challenge_seed, tbox_profile)?;
    ensure_linear_proof_binary_relation_is_not_required()?;
    apply_tbox_l2_relation(&mut accumulator_set, challenge_seed, tbox_profile)?;

    Ok(accumulator_set)
}

#[cfg(test)]
pub(crate) fn apply_default_tbox_beta3_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_tbox_beta3_relations(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

pub(super) fn apply_tbox_beta3_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    let challenge_values = sample_linear_proof_uniform_u64_values(
        (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) * TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        u64::from(TBOX_BETA3_DOMAIN_OFFSET),
    )?;

    for accumulator_pair_index in 0..accumulator_set.primary_schwartz_zippel_accumulators.len() {
        let primary_relation = build_accumulated_beta3_relation(
            &challenge_values,
            accumulator_pair_index,
            0,
            tbox_profile,
        )?;
        accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLinearProofQuadraticEquation {
                    challenge_scalar: 1,
                    equation: &primary_relation,
                }])?;

        let secondary_relation = build_accumulated_beta3_relation(
            &challenge_values,
            accumulator_pair_index,
            1,
            tbox_profile,
        )?;
        accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLinearProofQuadraticEquation {
                    challenge_scalar: 1,
                    equation: &secondary_relation,
                }])?;
    }

    Ok(())
}

fn build_accumulated_beta3_relation(
    challenge_values: &[u64],
    accumulator_pair_index: usize,
    challenge_lane_offset: usize,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    // inverse_two is 1/2 mod q; the half-factor pre-divides each challenge so the
    // later auto-fold (which sums the conjugate pair) is not doubled.
    let inverse_two = proof_ring.modulus().div_ceil(2);
    let beta_offset = tbox_profile.beta_offset();
    let equation_dimension = tbox_profile.quadratic_evaluation_dimension();
    let mut beta_polynomial = vec![0_u64; proof_ring.degree()];

    // challenge_lane_offset 0/1 selects the primary/secondary Schwartz-Zippel
    // evaluation point; the two points are the pair the auto-fold later combines.
    for (coefficient_index, coefficient) in beta_polynomial.iter_mut().enumerate().skip(1) {
        let challenge_index = (coefficient_index - 1) * TBOX_QUADRATIC_EVALUATION_REPETITIONS
            + 2 * accumulator_pair_index
            + challenge_lane_offset;
        *coefficient = multiply_mod(
            inverse_two,
            challenge_values[challenge_index],
            proof_ring.modulus(),
        );
    }

    let entries = if is_zero_polynomial(&beta_polynomial) {
        Vec::new()
    } else {
        vec![
            SparsePolynomialVectorEntry::new(beta_offset, beta_polynomial.clone()),
            SparsePolynomialVectorEntry::new(beta_offset + 1, beta_polynomial),
        ]
    };

    LinearProofQuadraticEquation::new(
        SparsePolynomialMatrix::zero(proof_ring, equation_dimension, equation_dimension)?,
        SparsePolynomialVector::new(proof_ring, equation_dimension, entries)?,
        None,
    )
}

#[cfg(test)]
pub(crate) fn apply_default_tbox_beta4_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_tbox_beta4_relations(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

pub(super) fn apply_tbox_beta4_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    let challenge_values = sample_linear_proof_uniform_u64_values(
        (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) * TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        u64::from(TBOX_BETA4_DOMAIN_OFFSET),
    )?;

    for accumulator_pair_index in 0..accumulator_set.primary_schwartz_zippel_accumulators.len() {
        let primary_relation = build_accumulated_beta4_relation(
            &challenge_values,
            accumulator_pair_index,
            0,
            tbox_profile,
        )?;
        accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLinearProofQuadraticEquation {
                    challenge_scalar: 1,
                    equation: &primary_relation,
                }])?;

        let secondary_relation = build_accumulated_beta4_relation(
            &challenge_values,
            accumulator_pair_index,
            1,
            tbox_profile,
        )?;
        accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLinearProofQuadraticEquation {
                    challenge_scalar: 1,
                    equation: &secondary_relation,
                }])?;
    }

    Ok(())
}

fn build_accumulated_beta4_relation(
    challenge_values: &[u64],
    accumulator_pair_index: usize,
    challenge_lane_offset: usize,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    let inverse_two = proof_ring.modulus().div_ceil(2);
    let beta_offset = tbox_profile.beta_offset();
    let equation_dimension = tbox_profile.quadratic_evaluation_dimension();
    let half_degree = proof_ring.degree() / 2;
    let mut first_polynomial = vec![0_u64; proof_ring.degree()];
    let mut second_polynomial = vec![0_u64; proof_ring.degree()];

    for coefficient_index in 1..proof_ring.degree() {
        let challenge_index = (coefficient_index - 1) * TBOX_QUADRATIC_EVALUATION_REPETITIONS
            + 2 * accumulator_pair_index
            + challenge_lane_offset;
        let coefficient_value = multiply_mod(
            inverse_two,
            challenge_values[challenge_index],
            proof_ring.modulus(),
        );
        let shifted_coefficient_index = if coefficient_index < half_degree {
            coefficient_index + half_degree
        } else {
            coefficient_index - half_degree
        };
        first_polynomial[shifted_coefficient_index] = if coefficient_index < half_degree {
            negate_mod(coefficient_value, proof_ring.modulus())
        } else {
            coefficient_value
        };
        second_polynomial[shifted_coefficient_index] = if coefficient_index < half_degree {
            coefficient_value
        } else {
            negate_mod(coefficient_value, proof_ring.modulus())
        };
    }

    let mut entries = Vec::with_capacity(2);
    if !is_zero_polynomial(&first_polynomial) {
        entries.push(SparsePolynomialVectorEntry::new(
            beta_offset,
            first_polynomial,
        ));
    }
    if !is_zero_polynomial(&second_polynomial) {
        entries.push(SparsePolynomialVectorEntry::new(
            beta_offset + 1,
            second_polynomial,
        ));
    }

    LinearProofQuadraticEquation::new(
        SparsePolynomialMatrix::zero(proof_ring, equation_dimension, equation_dimension)?,
        SparsePolynomialVector::new(proof_ring, equation_dimension, entries)?,
        None,
    )
}

#[cfg(test)]
pub(crate) fn apply_default_tbox_upsilon_relation(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_tbox_upsilon_relation(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

pub(super) fn apply_tbox_upsilon_relation(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    let relation = build_upsilon_binary_relation(tbox_profile)?;
    accumulate_single_linear_proof_partial_relation_by_schwartz_zippel(
        accumulator_set,
        &relation,
        challenge_seed,
        TBOX_UPSILON_DOMAIN_OFFSET,
        tbox_profile.coefficient_bit_length,
    )
}

#[cfg(test)]
pub(crate) fn apply_default_tbox_l2_relation(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_tbox_l2_relation(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

pub(super) fn apply_tbox_l2_relation(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    let relation = build_l2_norm_relation(tbox_profile)?;
    accumulate_single_linear_proof_partial_relation_by_schwartz_zippel(
        accumulator_set,
        &relation,
        challenge_seed,
        TBOX_EUCLIDEAN_DOMAIN_OFFSET,
        tbox_profile.coefficient_bit_length,
    )
}

#[cfg(test)]
pub(crate) fn apply_default_tbox_z4_response_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_tbox_z4_response_relations(
        accumulator_set,
        transformed_statement_matrix,
        transformed_target_vector,
        infinity_response_vector,
        challenge_seed,
        &demo_linear_proof_encoding_contract(),
    )
}

pub(crate) fn apply_tbox_z4_response_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = TboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_linear_proof_z4_inputs(
        transformed_statement_matrix,
        transformed_target_vector,
        infinity_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let automorphic_statement_matrix = transformed_statement_matrix.automorphism()?;
    let challenge_matrix = sample_linear_proof_uniform_matrix(
        TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        TBOX_Z4_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_linear_proof_response_rotation_products(
        challenge_seed,
        &challenge_matrix,
        transformed_statement_matrix.rows(),
        true,
        proof_ring.modulus(),
    )?;
    let shifted_rotation_polynomial_matrix = convert_z4_rotation_products_to_polynomials(
        proof_ring,
        &response_rotation_matrix_products,
        transformed_statement_matrix.rows(),
    )?;
    let statement_products = multiply_rows_by_polynomial_matrix(
        proof_ring,
        &shifted_rotation_polynomial_matrix,
        &automorphic_statement_matrix,
    )?;
    let target_products = dot_rotation_products_with_target(
        proof_ring,
        &response_rotation_matrix_products,
        transformed_target_vector,
    )?;

    for repetition_index in 0..TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_linear_proof_z4_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &statement_products[repetition_index],
            target_products[repetition_index],
        )?;
        accumulate_linear_proof_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) fn apply_tbox_z4_response_relations_sparse(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    transformed_statement_matrix: &SparsePolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = TboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_linear_proof_sparse_z4_inputs(
        transformed_statement_matrix,
        transformed_target_vector,
        infinity_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let automorphic_statement_matrix = transformed_statement_matrix.automorphism()?;
    let challenge_matrix = sample_linear_proof_uniform_matrix(
        TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        TBOX_Z4_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_linear_proof_response_rotation_products(
        challenge_seed,
        &challenge_matrix,
        transformed_statement_matrix.rows(),
        true,
        proof_ring.modulus(),
    )?;
    let shifted_rotation_polynomial_matrix = convert_z4_rotation_products_to_polynomials(
        proof_ring,
        &response_rotation_matrix_products,
        transformed_statement_matrix.rows(),
    )?;
    let statement_products = multiply_rows_by_sparse_polynomial_matrix(
        proof_ring,
        &shifted_rotation_polynomial_matrix,
        &automorphic_statement_matrix,
    )?;
    let target_products = dot_rotation_products_with_target(
        proof_ring,
        &response_rotation_matrix_products,
        transformed_target_vector,
    )?;

    for repetition_index in 0..TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_linear_proof_z4_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &statement_products[repetition_index],
            target_products[repetition_index],
        )?;
        accumulate_linear_proof_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) struct TboxZ4ResponseRelationInputs<'a> {
    pub(crate) transformed_statement_rows: usize,
    pub(crate) transformed_statement_columns: usize,
    pub(crate) transformed_target_vector: &'a PolynomialVector,
    pub(crate) infinity_response_vector: &'a [Vec<i64>],
    pub(crate) challenge_seed: &'a [u8; 32],
    pub(crate) proof_encoding: &'a LinearProofEncoding,
}

pub(crate) fn apply_tbox_z4_response_relations_with_product_builder(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    input: TboxZ4ResponseRelationInputs<'_>,
    build_statement_products: impl FnOnce(
        PolynomialRing,
        &[Vec<Vec<u64>>],
    ) -> CanonicalResult<Vec<Vec<Vec<u64>>>>,
) -> CanonicalResult<()> {
    let tbox_profile = TboxRelationProfile::from_proof_encoding(input.proof_encoding)?;
    validate_statement_shape(
        input.transformed_statement_rows,
        input.transformed_statement_columns,
        tbox_profile,
    )?;
    if input.transformed_target_vector.ring() != tbox_profile.proof_ring
        || input.transformed_target_vector.len() != input.transformed_statement_rows
    {
        return Err(invalid_tbox_relation(
            "z4 response relation target vector does not match the streamed transformed statement",
        ));
    }
    validate_linear_proof_response_vector(
        input.infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let challenge_matrix = sample_linear_proof_uniform_matrix(
        TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        input.challenge_seed,
        TBOX_Z4_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        input.infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_linear_proof_response_rotation_products(
        input.challenge_seed,
        &challenge_matrix,
        input.transformed_statement_rows,
        true,
        proof_ring.modulus(),
    )?;
    let shifted_rotation_polynomial_matrix = convert_z4_rotation_products_to_polynomials(
        proof_ring,
        &response_rotation_matrix_products,
        input.transformed_statement_rows,
    )?;
    let statement_products =
        build_statement_products(proof_ring, &shifted_rotation_polynomial_matrix)?;
    let target_products = dot_rotation_products_with_target(
        proof_ring,
        &response_rotation_matrix_products,
        input.transformed_target_vector,
    )?;

    for repetition_index in 0..TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_linear_proof_z4_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &statement_products[repetition_index],
            target_products[repetition_index],
        )?;
        accumulate_linear_proof_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn apply_default_tbox_z3_response_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_tbox_z3_response_relations(
        accumulator_set,
        transformed_statement_matrix,
        euclidean_response_vector,
        challenge_seed,
        &demo_linear_proof_encoding_contract(),
    )
}

pub(crate) fn apply_tbox_z3_response_relations(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = TboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_linear_proof_z3_inputs(
        transformed_statement_matrix,
        euclidean_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let challenge_matrix = sample_linear_proof_uniform_matrix(
        TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        TBOX_Z3_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_linear_proof_response_rotation_products(
        challenge_seed,
        &challenge_matrix,
        tbox_profile.extended_coordinates(),
        false,
        proof_ring.modulus(),
    )?;
    let rotation_polynomial_matrix = convert_z3_rotation_products_to_polynomials(
        proof_ring,
        &response_rotation_matrix_products,
        tbox_profile.extended_coordinates(),
    )?;

    for repetition_index in 0..TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_linear_proof_z3_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &rotation_polynomial_matrix[repetition_index],
        )?;
        accumulate_linear_proof_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) fn apply_tbox_z3_response_relations_sparse(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    transformed_statement_matrix: &SparsePolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = TboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_linear_proof_sparse_z3_inputs(
        transformed_statement_matrix,
        euclidean_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let challenge_matrix = sample_linear_proof_uniform_matrix(
        TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        TBOX_Z3_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_linear_proof_response_rotation_products(
        challenge_seed,
        &challenge_matrix,
        tbox_profile.extended_coordinates(),
        false,
        proof_ring.modulus(),
    )?;
    let rotation_polynomial_matrix = convert_z3_rotation_products_to_polynomials(
        proof_ring,
        &response_rotation_matrix_products,
        tbox_profile.extended_coordinates(),
    )?;

    for repetition_index in 0..TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_linear_proof_z3_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &rotation_polynomial_matrix[repetition_index],
        )?;
        accumulate_linear_proof_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) fn apply_tbox_z3_response_relations_for_statement_shape(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    transformed_statement_rows: usize,
    transformed_statement_columns: usize,
    euclidean_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = TboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_statement_shape(
        transformed_statement_rows,
        transformed_statement_columns,
        tbox_profile,
    )?;
    validate_linear_proof_response_vector(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let challenge_matrix = sample_linear_proof_uniform_matrix(
        TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        TBOX_Z3_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_linear_proof_response_rotation_products(
        challenge_seed,
        &challenge_matrix,
        tbox_profile.extended_coordinates(),
        false,
        proof_ring.modulus(),
    )?;
    let rotation_polynomial_matrix = convert_z3_rotation_products_to_polynomials(
        proof_ring,
        &response_rotation_matrix_products,
        tbox_profile.extended_coordinates(),
    )?;

    for repetition_index in 0..TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_linear_proof_z3_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &rotation_polynomial_matrix[repetition_index],
        )?;
        accumulate_linear_proof_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}
