use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[cfg(test)]
use super::lazer_demo_public_parameters::LAZER_DEMO_PROOF_COEFFICIENT_BIT_LENGTH;
use super::{
    lazer_demo_public_parameters::{
        LAZER_DEMO_PROOF_COEFFICIENT_MODULUS, LAZER_DEMO_PROOF_RING_DEGREE,
        LAZER_DEMO_TBOX_SHORT_MESSAGE_LENGTH,
    },
    lazer_demo_quadratic::{LazerDemoQuadraticEquation, WeightedLazerDemoQuadraticEquation},
    lazer_demo_rng::sample_lazer_demo_uniform_u64_values,
    linear_proof_parameters::{
        LazerDemoProofEncoding, LazerLinearProofProfile, demo_linear_proof_encoding_contract,
        linear_proof_profile_for_encoding,
    },
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
    sparse_polynomial_vector::{SparsePolynomialVector, SparsePolynomialVectorEntry},
};

const LAZER_DEMO_TBOX_UPSILON_COORDINATES: usize = 1;
const LAZER_DEMO_TBOX_UNBOUNDED_MESSAGE_LENGTH: usize = 0;
const LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES: usize = 16;
const LAZER_DEMO_TBOX_EXACT_NORM_DIMENSION: usize = 32;
#[cfg(test)]
const LAZER_DEMO_TBOX_EXACT_NORM_BOUND_SQUARED: u64 = 2_048;
const LAZER_DEMO_TBOX_EXTENDED_COORDINATES: usize = 33;
pub(crate) const LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_MESSAGE_LENGTH: usize = 9;
pub(crate) const LAZER_DEMO_TBOX_QUADRATIC_MANY_MESSAGE_LENGTH: usize = 11;
const LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS: usize = 4;

const LAZER_DEMO_TBOX_BETA3_DOMAIN_OFFSET: u32 = 0;
const LAZER_DEMO_TBOX_BETA4_DOMAIN_OFFSET: u32 =
    (LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS * (LAZER_DEMO_PROOF_RING_DEGREE - 1)) as u32;
const LAZER_DEMO_TBOX_UPSILON_DOMAIN_OFFSET: u32 = (LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS
    * 2 * (LAZER_DEMO_PROOF_RING_DEGREE - 1))
    as u32;
const LAZER_DEMO_TBOX_BINARY_DOMAIN_OFFSET: u32 = (LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS
    * (2 * (LAZER_DEMO_PROOF_RING_DEGREE - 1) + 1))
    as u32;
const LAZER_DEMO_TBOX_EUCLIDEAN_DOMAIN_OFFSET: u32 =
    (LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS
        * (2 * (LAZER_DEMO_PROOF_RING_DEGREE - 1) + 2)) as u32;
const LAZER_DEMO_TBOX_Z4_RESPONSE_DOMAIN_OFFSET: u32 =
    (LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS
        * (2 * (LAZER_DEMO_PROOF_RING_DEGREE - 1) + 2 + LAZER_DEMO_TBOX_UPSILON_COORDINATES))
        as u32;
const LAZER_DEMO_TBOX_Z3_RESPONSE_DOMAIN_OFFSET: u32 =
    (LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS
        * (2 * (LAZER_DEMO_PROOF_RING_DEGREE - 1) + 2 + LAZER_DEMO_TBOX_UPSILON_COORDINATES + 256))
        as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LazerTboxRelationProfile {
    proof_ring: PolynomialRing,
    coefficient_bit_length: usize,
    exact_norm_bound_squared: u64,
    euclidean_response_vector_length: usize,
    infinity_response_vector_length: usize,
    short_response_message_length: usize,
}

impl LazerTboxRelationProfile {
    fn from_proof_encoding(proof_encoding: &LazerDemoProofEncoding) -> CanonicalResult<Self> {
        proof_encoding.validate()?;
        let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
        Self::from_parts(proof_encoding, proof_profile)
    }

    fn from_parts(
        proof_encoding: &LazerDemoProofEncoding,
        proof_profile: LazerLinearProofProfile,
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

    fn short_message_without_upsilon(self) -> usize {
        self.short_response_message_length - LAZER_DEMO_TBOX_UPSILON_COORDINATES
    }

    fn extended_coordinates(self) -> usize {
        self.short_response_message_length
    }

    fn exact_norm_dimension(self) -> usize {
        self.short_response_message_length - LAZER_DEMO_TBOX_UPSILON_COORDINATES
    }

    fn approximate_relation_polynomial_count(self) -> usize {
        self.infinity_response_vector_length
    }

    fn beta_offset(self) -> usize {
        (self.short_message_without_upsilon()
            + LAZER_DEMO_TBOX_UPSILON_COORDINATES
            + LAZER_DEMO_TBOX_UNBOUNDED_MESSAGE_LENGTH
            + self.approximate_relation_polynomial_count()
            + self.approximate_relation_polynomial_count())
            * 2
    }

    fn upsilon_offset(self) -> usize {
        self.short_message_without_upsilon() * 2
    }

    fn y3_offset(self) -> usize {
        (self.short_message_without_upsilon()
            + LAZER_DEMO_TBOX_UPSILON_COORDINATES
            + LAZER_DEMO_TBOX_UNBOUNDED_MESSAGE_LENGTH)
            * 2
    }

    fn y4_offset(self) -> usize {
        (self.short_message_without_upsilon()
            + LAZER_DEMO_TBOX_UPSILON_COORDINATES
            + LAZER_DEMO_TBOX_UNBOUNDED_MESSAGE_LENGTH
            + self.approximate_relation_polynomial_count())
            * 2
    }

    fn quadratic_evaluation_dimension(self) -> usize {
        2 * (self.short_response_message_length
            + LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_MESSAGE_LENGTH)
    }

    fn quadratic_many_dimension(self) -> usize {
        2 * (self.short_response_message_length + LAZER_DEMO_TBOX_QUADRATIC_MANY_MESSAGE_LENGTH)
    }
}

fn demo_tbox_profile() -> CanonicalResult<LazerTboxRelationProfile> {
    LazerTboxRelationProfile::from_proof_encoding(&demo_linear_proof_encoding_contract())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LazerDemoTboxRelationAccumulatorSet {
    pub(crate) primary_schwartz_zippel_accumulators: Vec<LazerDemoQuadraticEquation>,
    pub(crate) secondary_schwartz_zippel_accumulators: Vec<LazerDemoQuadraticEquation>,
    pub(crate) extra_beta_norm_equations: Vec<LazerDemoQuadraticEquation>,
}

impl LazerDemoTboxRelationAccumulatorSet {
    pub(crate) fn auto_folded_equations(&self) -> CanonicalResult<Vec<LazerDemoQuadraticEquation>> {
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

pub(crate) fn initialize_lazer_demo_tbox_relation_accumulators()
-> CanonicalResult<LazerDemoTboxRelationAccumulatorSet> {
    initialize_lazer_tbox_relation_accumulators(demo_tbox_profile()?)
}

fn initialize_lazer_tbox_relation_accumulators(
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoTboxRelationAccumulatorSet> {
    validate_lazer_demo_tbox_shape()?;

    let proof_ring = tbox_profile.proof_ring;
    let equation_dimension = tbox_profile.quadratic_evaluation_dimension();
    let accumulator_count = LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS / 2;
    let primary_schwartz_zippel_accumulators = (0..accumulator_count)
        .map(|_| LazerDemoQuadraticEquation::zero(proof_ring, equation_dimension))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secondary_schwartz_zippel_accumulators = (0..accumulator_count)
        .map(|_| LazerDemoQuadraticEquation::zero(proof_ring, equation_dimension))
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(LazerDemoTboxRelationAccumulatorSet {
        primary_schwartz_zippel_accumulators,
        secondary_schwartz_zippel_accumulators,
        extra_beta_norm_equations: vec![
            build_lazer_beta3_norm_equation(tbox_profile)?,
            build_lazer_beta4_norm_equation(tbox_profile)?,
        ],
    })
}

pub(crate) fn build_lazer_demo_tbox_prefix_accumulators(
    challenge_seed: &[u8; 32],
) -> CanonicalResult<LazerDemoTboxRelationAccumulatorSet> {
    build_lazer_tbox_prefix_accumulators(challenge_seed, &demo_linear_proof_encoding_contract())
}

pub(crate) fn build_lazer_tbox_prefix_accumulators(
    challenge_seed: &[u8; 32],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<LazerDemoTboxRelationAccumulatorSet> {
    let tbox_profile = LazerTboxRelationProfile::from_proof_encoding(proof_encoding)?;
    let mut accumulator_set = initialize_lazer_tbox_relation_accumulators(tbox_profile)?;
    apply_lazer_tbox_beta3_relations(&mut accumulator_set, challenge_seed, tbox_profile)?;
    apply_lazer_tbox_beta4_relations(&mut accumulator_set, challenge_seed, tbox_profile)?;
    apply_lazer_tbox_upsilon_relation(&mut accumulator_set, challenge_seed, tbox_profile)?;
    ensure_lazer_demo_binary_relation_is_not_required()?;
    apply_lazer_tbox_l2_relation(&mut accumulator_set, challenge_seed, tbox_profile)?;

    Ok(accumulator_set)
}

#[cfg(test)]
pub(crate) fn apply_lazer_demo_tbox_beta3_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_lazer_tbox_beta3_relations(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

fn apply_lazer_tbox_beta3_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    let inverse_two = proof_ring.modulus().div_ceil(2);
    let challenge_values = sample_lazer_demo_uniform_u64_values(
        (LAZER_DEMO_PROOF_RING_DEGREE - 1) * LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        u64::from(LAZER_DEMO_TBOX_BETA3_DOMAIN_OFFSET),
    )?;

    for coefficient_index in 1..LAZER_DEMO_PROOF_RING_DEGREE {
        for accumulator_pair_index in 0..accumulator_set.primary_schwartz_zippel_accumulators.len()
        {
            let primary_challenge_index = (coefficient_index - 1)
                * LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS
                + 2 * accumulator_pair_index;
            let primary_coefficient = multiply_mod(
                inverse_two,
                challenge_values[primary_challenge_index],
                proof_ring.modulus(),
            );
            let primary_relation = build_lazer_beta3_linear_relation(
                coefficient_index,
                primary_coefficient,
                tbox_profile,
            )?;
            accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index] =
                accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index]
                    .accumulate_weighted_partial_equations(&[
                        WeightedLazerDemoQuadraticEquation {
                            challenge_scalar: 1,
                            equation: &primary_relation,
                        },
                    ])?;

            let secondary_challenge_index = primary_challenge_index + 1;
            let secondary_coefficient = multiply_mod(
                inverse_two,
                challenge_values[secondary_challenge_index],
                proof_ring.modulus(),
            );
            let secondary_relation = build_lazer_beta3_linear_relation(
                coefficient_index,
                secondary_coefficient,
                tbox_profile,
            )?;
            accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index] =
                accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index]
                    .accumulate_weighted_partial_equations(&[
                        WeightedLazerDemoQuadraticEquation {
                            challenge_scalar: 1,
                            equation: &secondary_relation,
                        },
                    ])?;
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn apply_lazer_demo_tbox_beta4_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_lazer_tbox_beta4_relations(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

fn apply_lazer_tbox_beta4_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    let inverse_two = proof_ring.modulus().div_ceil(2);
    let challenge_values = sample_lazer_demo_uniform_u64_values(
        (LAZER_DEMO_PROOF_RING_DEGREE - 1) * LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        u64::from(LAZER_DEMO_TBOX_BETA4_DOMAIN_OFFSET),
    )?;

    for coefficient_index in 1..LAZER_DEMO_PROOF_RING_DEGREE {
        for accumulator_pair_index in 0..accumulator_set.primary_schwartz_zippel_accumulators.len()
        {
            let primary_challenge_index = (coefficient_index - 1)
                * LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS
                + 2 * accumulator_pair_index;
            let primary_coefficient = multiply_mod(
                inverse_two,
                challenge_values[primary_challenge_index],
                proof_ring.modulus(),
            );
            let primary_relation = build_lazer_beta4_linear_relation(
                coefficient_index,
                primary_coefficient,
                tbox_profile,
            )?;
            accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index] =
                accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index]
                    .accumulate_weighted_partial_equations(&[
                        WeightedLazerDemoQuadraticEquation {
                            challenge_scalar: 1,
                            equation: &primary_relation,
                        },
                    ])?;

            let secondary_challenge_index = primary_challenge_index + 1;
            let secondary_coefficient = multiply_mod(
                inverse_two,
                challenge_values[secondary_challenge_index],
                proof_ring.modulus(),
            );
            let secondary_relation = build_lazer_beta4_linear_relation(
                coefficient_index,
                secondary_coefficient,
                tbox_profile,
            )?;
            accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index] =
                accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index]
                    .accumulate_weighted_partial_equations(&[
                        WeightedLazerDemoQuadraticEquation {
                            challenge_scalar: 1,
                            equation: &secondary_relation,
                        },
                    ])?;
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn apply_lazer_demo_tbox_upsilon_relation(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_lazer_tbox_upsilon_relation(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

fn apply_lazer_tbox_upsilon_relation(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    let relation = build_lazer_upsilon_binary_relation(tbox_profile)?;
    accumulate_single_lazer_demo_partial_relation_by_schwartz_zippel(
        accumulator_set,
        &relation,
        challenge_seed,
        LAZER_DEMO_TBOX_UPSILON_DOMAIN_OFFSET,
        tbox_profile.coefficient_bit_length,
    )
}

#[cfg(test)]
pub(crate) fn apply_lazer_demo_tbox_l2_relation(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_lazer_tbox_l2_relation(accumulator_set, challenge_seed, demo_tbox_profile()?)
}

fn apply_lazer_tbox_l2_relation(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    challenge_seed: &[u8; 32],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    let relation = build_lazer_l2_norm_relation(tbox_profile)?;
    accumulate_single_lazer_demo_partial_relation_by_schwartz_zippel(
        accumulator_set,
        &relation,
        challenge_seed,
        LAZER_DEMO_TBOX_EUCLIDEAN_DOMAIN_OFFSET,
        tbox_profile.coefficient_bit_length,
    )
}

pub(crate) fn apply_lazer_demo_tbox_z4_response_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_lazer_tbox_z4_response_relations(
        accumulator_set,
        transformed_statement_matrix,
        transformed_target_vector,
        infinity_response_vector,
        challenge_seed,
        &demo_linear_proof_encoding_contract(),
    )
}

pub(crate) fn apply_lazer_tbox_z4_response_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = LazerTboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_lazer_demo_z4_inputs(
        transformed_statement_matrix,
        transformed_target_vector,
        infinity_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let automorphic_statement_matrix = transformed_statement_matrix.automorphism()?;
    let challenge_matrix = sample_lazer_demo_uniform_matrix(
        LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        LAZER_DEMO_TBOX_Z4_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_lazer_demo_response_rotation_products(
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

    for repetition_index in 0..LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_lazer_demo_z4_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &statement_products[repetition_index],
            target_products[repetition_index],
        )?;
        accumulate_lazer_demo_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) fn apply_lazer_tbox_z4_response_relations_sparse(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    transformed_statement_matrix: &SparsePolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = LazerTboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_lazer_demo_sparse_z4_inputs(
        transformed_statement_matrix,
        transformed_target_vector,
        infinity_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let automorphic_statement_matrix = transformed_statement_matrix.automorphism()?;
    let challenge_matrix = sample_lazer_demo_uniform_matrix(
        LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        LAZER_DEMO_TBOX_Z4_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_lazer_demo_response_rotation_products(
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

    for repetition_index in 0..LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_lazer_demo_z4_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &statement_products[repetition_index],
            target_products[repetition_index],
        )?;
        accumulate_lazer_demo_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) fn apply_lazer_demo_tbox_z3_response_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
) -> CanonicalResult<()> {
    apply_lazer_tbox_z3_response_relations(
        accumulator_set,
        transformed_statement_matrix,
        euclidean_response_vector,
        challenge_seed,
        &demo_linear_proof_encoding_contract(),
    )
}

pub(crate) fn apply_lazer_tbox_z3_response_relations(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    transformed_statement_matrix: &PolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = LazerTboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_lazer_demo_z3_inputs(
        transformed_statement_matrix,
        euclidean_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let challenge_matrix = sample_lazer_demo_uniform_matrix(
        LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        LAZER_DEMO_TBOX_Z3_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_lazer_demo_response_rotation_products(
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

    for repetition_index in 0..LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_lazer_demo_z3_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &rotation_polynomial_matrix[repetition_index],
        )?;
        accumulate_lazer_demo_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) fn apply_lazer_tbox_z3_response_relations_sparse(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    transformed_statement_matrix: &SparsePolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    challenge_seed: &[u8; 32],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<()> {
    let tbox_profile = LazerTboxRelationProfile::from_proof_encoding(proof_encoding)?;
    validate_lazer_demo_sparse_z3_inputs(
        transformed_statement_matrix,
        euclidean_response_vector,
        tbox_profile,
    )?;
    let proof_ring = tbox_profile.proof_ring;
    let challenge_matrix = sample_lazer_demo_uniform_matrix(
        LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
        256,
        proof_ring.modulus(),
        tbox_profile.coefficient_bit_length,
        challenge_seed,
        LAZER_DEMO_TBOX_Z3_RESPONSE_DOMAIN_OFFSET,
    )?;
    let flattened_response = flatten_signed_response(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        proof_ring.degree(),
    )?;
    let response_rotation_matrix_products = compute_lazer_demo_response_rotation_products(
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

    for repetition_index in 0..LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS {
        let relation = build_lazer_demo_z3_response_relation(
            tbox_profile,
            proof_ring,
            &challenge_matrix[repetition_index],
            &flattened_response,
            &rotation_polynomial_matrix[repetition_index],
        )?;
        accumulate_lazer_demo_repetition_relation(accumulator_set, repetition_index, &relation)?;
    }

    Ok(())
}

pub(crate) fn validate_lazer_demo_tbox_relation_builder_port() -> CanonicalResult<()> {
    let initial_accumulators = initialize_lazer_demo_tbox_relation_accumulators()?;
    if initial_accumulators
        .primary_schwartz_zippel_accumulators
        .len()
        != 2
        || initial_accumulators
            .secondary_schwartz_zippel_accumulators
            .len()
            != 2
        || initial_accumulators.extra_beta_norm_equations.len() != 2
    {
        return Err(invalid_tbox_relation(
            "initial tbox accumulator shape does not match the LaZer demo profile",
        ));
    }

    let proof_ring = lazer_demo_tbox_proof_ring()?;
    let beta3_relation = build_lazer_demo_beta3_linear_relation(1, 7)?;
    if beta3_relation.linear_terms().entries().len() != 2
        || beta3_relation.linear_terms().entries()[0].position() != lazer_demo_tbox_beta_offset()
        || beta3_relation.linear_terms().entries()[0].coefficients()[1] != 7
        || beta3_relation.constant_term().is_some()
    {
        return Err(invalid_tbox_relation(
            "beta3 relation self-check did not match the LaZer demo layout",
        ));
    }

    let beta4_relation = build_lazer_demo_beta4_linear_relation(1, 7)?;
    if beta4_relation.linear_terms().entries().len() != 2
        || beta4_relation.linear_terms().entries()[0].coefficients()[33] != proof_ring.modulus() - 7
        || beta4_relation.linear_terms().entries()[1].coefficients()[33] != 7
    {
        return Err(invalid_tbox_relation(
            "beta4 relation self-check did not match the LaZer demo layout",
        ));
    }

    let upsilon_relation = build_lazer_demo_upsilon_binary_relation()?;
    if upsilon_relation.quadratic_terms().entries().len() != 1
        || upsilon_relation.linear_terms().entries().len() != 1
        || upsilon_relation.linear_terms().entries()[0]
            .coefficients()
            .iter()
            .any(|coefficient| *coefficient != proof_ring.modulus() - 1)
    {
        return Err(invalid_tbox_relation(
            "upsilon relation self-check did not match the LaZer demo layout",
        ));
    }

    let l2_relation = build_lazer_demo_l2_norm_relation()?;
    if l2_relation.quadratic_terms().entries().len() != LAZER_DEMO_TBOX_EXACT_NORM_DIMENSION
        || l2_relation.linear_terms().entries().len() != 1
        || l2_relation
            .constant_term()
            .is_none_or(|constant_term| constant_term[0] != proof_ring.modulus() - 2_048)
    {
        return Err(invalid_tbox_relation(
            "l2 relation self-check did not match the LaZer demo layout",
        ));
    }

    let challenge_seed = [5_u8; 32];
    let prefixed_accumulators = build_lazer_demo_tbox_prefix_accumulators(&challenge_seed)?;
    let folded_equations = prefixed_accumulators.auto_folded_equations()?;
    if folded_equations.len() != 4
        || folded_equations[0].quadratic_terms().entries().is_empty()
        || folded_equations[0].linear_terms().entries().is_empty()
        || folded_equations[0]
            .constant_term()
            .is_none_or(|constant_term| constant_term.len() != LAZER_DEMO_PROOF_RING_DEGREE)
    {
        return Err(invalid_tbox_relation(
            "prefixed tbox accumulator self-check did not produce folded equations",
        ));
    }

    let zero_statement_matrix = PolynomialMatrix::new(
        proof_ring,
        LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES,
        LAZER_DEMO_TBOX_EXACT_NORM_DIMENSION,
        vec![
            vec![0_u64; LAZER_DEMO_PROOF_RING_DEGREE];
            LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES * LAZER_DEMO_TBOX_EXACT_NORM_DIMENSION
        ],
    )?;
    let zero_target_vector =
        PolynomialVector::zero(proof_ring, LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES)?;
    let zero_response = vec![
        vec![0_i64; LAZER_DEMO_PROOF_RING_DEGREE];
        LAZER_DEMO_PROOF_RING_DEGREE
            / LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES
    ];
    let mut response_accumulators = prefixed_accumulators.clone();
    apply_lazer_demo_tbox_z4_response_relations(
        &mut response_accumulators,
        &zero_statement_matrix,
        &zero_target_vector,
        &zero_response,
        &challenge_seed,
    )?;
    apply_lazer_demo_tbox_z3_response_relations(
        &mut response_accumulators,
        &zero_statement_matrix,
        &zero_response,
        &challenge_seed,
    )?;

    Ok(())
}

fn validate_lazer_demo_z4_inputs(
    transformed_statement_matrix: &PolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    validate_lazer_demo_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    if transformed_target_vector.ring() != transformed_statement_matrix.ring()
        || transformed_target_vector.len() != transformed_statement_matrix.rows()
    {
        return Err(invalid_tbox_relation(
            "z4 response relation target vector does not match the demo transformed statement",
        ));
    }
    validate_lazer_demo_response_vector(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

fn validate_lazer_demo_sparse_z4_inputs(
    transformed_statement_matrix: &SparsePolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    validate_lazer_demo_sparse_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    if transformed_target_vector.ring() != transformed_statement_matrix.ring()
        || transformed_target_vector.len() != transformed_statement_matrix.rows()
    {
        return Err(invalid_tbox_relation(
            "z4 response relation target vector does not match the demo transformed statement",
        ));
    }
    validate_lazer_demo_response_vector(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

fn validate_lazer_demo_z3_inputs(
    transformed_statement_matrix: &PolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    validate_lazer_demo_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    validate_lazer_demo_response_vector(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

fn validate_lazer_demo_sparse_z3_inputs(
    transformed_statement_matrix: &SparsePolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    validate_lazer_demo_sparse_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    validate_lazer_demo_response_vector(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

fn validate_lazer_demo_statement_matrix(
    transformed_statement_matrix: &PolynomialMatrix,
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    if transformed_statement_matrix.ring() != proof_ring
        || transformed_statement_matrix.rows() == 0
        || transformed_statement_matrix.columns() != tbox_profile.exact_norm_dimension()
    {
        return Err(invalid_tbox_relation(
            "response relation statement matrix does not match the demo transformed statement shape",
        ));
    }

    Ok(())
}

fn validate_lazer_demo_sparse_statement_matrix(
    transformed_statement_matrix: &SparsePolynomialMatrix,
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    if transformed_statement_matrix.ring() != proof_ring
        || transformed_statement_matrix.rows() == 0
        || transformed_statement_matrix.columns() != tbox_profile.exact_norm_dimension()
    {
        return Err(invalid_tbox_relation(
            "response relation statement matrix does not match the demo transformed statement shape",
        ));
    }

    Ok(())
}

fn validate_lazer_demo_response_vector(
    response_vector: &[Vec<i64>],
    expected_vector_length: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    if response_vector.len() != expected_vector_length {
        return Err(invalid_tbox_relation(
            "response relation vector length does not match the demo response layout",
        ));
    }
    if response_vector
        .iter()
        .any(|polynomial| polynomial.len() != proof_ring_degree)
    {
        return Err(invalid_tbox_relation(
            "response relation polynomial degree does not match the demo proof ring",
        ));
    }

    Ok(())
}

fn sample_lazer_demo_uniform_matrix(
    row_count: usize,
    column_count: usize,
    modulus: u64,
    modulus_bit_length: usize,
    seed: &[u8; 32],
    matrix_domain_separator: u32,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut rows = Vec::with_capacity(row_count);
    for row_index in 0..row_count {
        let row_domain_separator = compose_lazer_demo_matrix_row_domain(
            matrix_domain_separator,
            row_index
                .checked_mul(column_count)
                .ok_or_else(|| invalid_tbox_relation("matrix sampler row offset overflowed"))?,
        )?;
        rows.push(sample_lazer_demo_uniform_u64_values(
            column_count,
            modulus,
            modulus_bit_length,
            seed,
            row_domain_separator,
        )?);
    }

    Ok(rows)
}

fn compute_lazer_demo_response_rotation_products(
    challenge_seed: &[u8; 32],
    challenge_matrix: &[Vec<u64>],
    column_group_count: usize,
    use_prime_rotation_domain: bool,
    modulus: u64,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let rotation_column_count = column_group_count
        .checked_mul(LAZER_DEMO_PROOF_RING_DEGREE)
        .ok_or_else(|| invalid_tbox_relation("rotation product column count overflowed"))?;
    let mut signed_products =
        vec![vec![0_i128; rotation_column_count]; LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS];

    for response_coordinate_index in 0..256 {
        let row_domain_separator = if use_prime_rotation_domain {
            256 + response_coordinate_index
        } else {
            response_coordinate_index
        };
        let rotation_row = sample_lazer_demo_binary_difference_values(
            rotation_column_count,
            challenge_seed,
            u64::try_from(row_domain_separator)
                .map_err(|_| invalid_tbox_relation("rotation row domain does not fit in u64"))?,
        );
        for repetition_index in 0..LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS {
            let challenge =
                i128::from(challenge_matrix[repetition_index][response_coordinate_index]);
            for (rotation_column_index, rotation_value) in rotation_row.iter().enumerate() {
                if *rotation_value != 0 {
                    signed_products[repetition_index][rotation_column_index] +=
                        challenge * i128::from(*rotation_value);
                }
            }
        }
    }

    signed_products
        .iter()
        .map(|row| {
            row.iter()
                .map(|value| positive_mod_i128(*value, i128::from(modulus)))
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect()
}

fn convert_z4_rotation_products_to_polynomials(
    ring: PolynomialRing,
    response_rotation_matrix_products: &[Vec<u64>],
    approximate_norm_coordinates: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let inverse_two = ring.modulus().div_ceil(2);
    let mut rows = Vec::with_capacity(response_rotation_matrix_products.len());
    for response_rotation_product_row in response_rotation_matrix_products {
        let mut polynomial_row = vec![vec![0_u64; ring.degree()]; approximate_norm_coordinates];
        for approximate_coordinate_index in 0..approximate_norm_coordinates {
            for coefficient_index in 0..ring.degree() {
                let scaled_coefficient = multiply_mod(
                    inverse_two,
                    response_rotation_product_row
                        [approximate_coordinate_index * ring.degree() + coefficient_index],
                    ring.modulus(),
                );
                if coefficient_index < ring.degree() / 2 {
                    polynomial_row[approximate_coordinate_index]
                        [coefficient_index + ring.degree() / 2] = scaled_coefficient;
                } else {
                    polynomial_row[approximate_coordinate_index]
                        [coefficient_index - ring.degree() / 2] =
                        negate_mod(scaled_coefficient, ring.modulus());
                }
            }
        }
        rows.push(polynomial_row);
    }

    Ok(rows)
}

fn convert_z3_rotation_products_to_polynomials(
    ring: PolynomialRing,
    response_rotation_matrix_products: &[Vec<u64>],
    extended_coordinates: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut rows = Vec::with_capacity(response_rotation_matrix_products.len());
    for response_rotation_product_row in response_rotation_matrix_products {
        let mut polynomial_row = Vec::with_capacity(extended_coordinates);
        for extended_coordinate_index in 0..extended_coordinates {
            polynomial_row.push(
                response_rotation_product_row[extended_coordinate_index * ring.degree()
                    ..(extended_coordinate_index + 1) * ring.degree()]
                    .to_vec(),
            );
        }
        rows.push(polynomial_row);
    }

    Ok(rows)
}

fn multiply_rows_by_polynomial_matrix(
    ring: PolynomialRing,
    polynomial_rows: &[Vec<Vec<u64>>],
    matrix: &PolynomialMatrix,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut output_rows = Vec::with_capacity(polynomial_rows.len());
    for polynomial_row in polynomial_rows {
        if polynomial_row.len() != matrix.rows() {
            return Err(invalid_tbox_relation(
                "polynomial row length does not match matrix row count",
            ));
        }
        let mut output_row = Vec::with_capacity(matrix.columns());
        for column_index in 0..matrix.columns() {
            let mut accumulated_polynomial = vec![0_u64; ring.degree()];
            for (row_index, row_polynomial) in polynomial_row.iter().enumerate() {
                let product =
                    ring.mul_negacyclic(row_polynomial, matrix.entry(row_index, column_index)?)?;
                accumulated_polynomial = ring.add(&accumulated_polynomial, &product)?;
            }
            output_row.push(accumulated_polynomial);
        }
        output_rows.push(output_row);
    }

    Ok(output_rows)
}

fn multiply_rows_by_sparse_polynomial_matrix(
    ring: PolynomialRing,
    polynomial_rows: &[Vec<Vec<u64>>],
    matrix: &SparsePolynomialMatrix,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut output_rows = Vec::with_capacity(polynomial_rows.len());
    for polynomial_row in polynomial_rows {
        if polynomial_row.len() != matrix.rows() {
            return Err(invalid_tbox_relation(
                "polynomial row length does not match matrix row count",
            ));
        }
        let mut output_row = vec![vec![0_u64; ring.degree()]; matrix.columns()];
        for entry in matrix.entries() {
            let product =
                ring.mul_negacyclic(&polynomial_row[entry.row_index()], entry.coefficients())?;
            output_row[entry.column_index()] =
                ring.add(&output_row[entry.column_index()], &product)?;
        }
        output_rows.push(output_row);
    }

    Ok(output_rows)
}

fn dot_rotation_products_with_target(
    ring: PolynomialRing,
    response_rotation_matrix_products: &[Vec<u64>],
    transformed_target_vector: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    let flattened_target = transformed_target_vector
        .entries()
        .iter()
        .flat_map(|polynomial| polynomial.iter().copied())
        .collect::<Vec<_>>();
    response_rotation_matrix_products
        .iter()
        .map(|row| dot_canonical_vectors_mod(row, &flattened_target, ring.modulus()))
        .collect()
}

fn build_lazer_demo_z4_response_relation(
    tbox_profile: LazerTboxRelationProfile,
    ring: PolynomialRing,
    challenge_row: &[u64],
    flattened_response: &[i64],
    statement_products: &[Vec<u64>],
    target_product: u64,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    if statement_products.len() < tbox_profile.exact_norm_dimension() {
        return Err(invalid_tbox_relation(
            "statement product row is too short for the z4 response relation",
        ));
    }
    let beta_offset = tbox_profile.beta_offset();
    let inverse_two = ring.modulus().div_ceil(2);
    let mut quadratic_entries = Vec::new();
    for (short_coordinate_index, statement_product) in statement_products
        .iter()
        .enumerate()
        .take(tbox_profile.exact_norm_dimension())
    {
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset,
            ring.neg(statement_product)?,
        );
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset + 1,
            statement_product.clone(),
        );
    }

    let mut linear_entries = Vec::new();
    for approximate_offset_index in 0..tbox_profile.approximate_relation_polynomial_count() {
        push_sparse_vector_entry_if_nonzero(
            &mut linear_entries,
            tbox_profile.y4_offset() + 1 + 2 * approximate_offset_index,
            challenge_polynomial_from_row(ring, challenge_row, approximate_offset_index)?,
        );
    }
    let scaled_target_product = multiply_mod(inverse_two, target_product, ring.modulus());
    push_sparse_vector_entry_if_nonzero(
        &mut linear_entries,
        beta_offset,
        single_coefficient_polynomial(
            ring,
            ring.degree() / 2,
            negate_mod(scaled_target_product, ring.modulus()),
        )?,
    );
    push_sparse_vector_entry_if_nonzero(
        &mut linear_entries,
        beta_offset + 1,
        single_coefficient_polynomial(ring, ring.degree() / 2, scaled_target_product)?,
    );

    LazerDemoQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            tbox_profile.quadratic_evaluation_dimension(),
            quadratic_entries,
        )?,
        SparsePolynomialVector::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            linear_entries,
        )?,
        Some(constant_polynomial(
            ring,
            negate_mod(
                dot_signed_response_with_challenge(
                    flattened_response,
                    challenge_row,
                    ring.modulus(),
                )?,
                ring.modulus(),
            ),
        )),
    )
}

fn build_lazer_demo_z3_response_relation(
    tbox_profile: LazerTboxRelationProfile,
    ring: PolynomialRing,
    challenge_row: &[u64],
    flattened_response: &[i64],
    rotation_polynomial_row: &[Vec<u64>],
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    if rotation_polynomial_row.len() < tbox_profile.extended_coordinates() {
        return Err(invalid_tbox_relation(
            "rotation polynomial row is too short for the z3 response relation",
        ));
    }
    let beta_offset = tbox_profile.beta_offset();
    let inverse_two = ring.modulus().div_ceil(2);
    let mut quadratic_entries = Vec::new();
    for (short_coordinate_index, rotation_polynomial) in rotation_polynomial_row
        .iter()
        .enumerate()
        .take(tbox_profile.exact_norm_dimension())
    {
        let scaled_product = ring.scale(inverse_two, rotation_polynomial)?;
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset,
            scaled_product.clone(),
        );
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset + 1,
            scaled_product,
        );
    }
    let scaled_upsilon_product = ring.scale(
        inverse_two,
        &rotation_polynomial_row[tbox_profile.extended_coordinates() - 1],
    )?;
    push_sparse_matrix_entry_if_nonzero(
        &mut quadratic_entries,
        tbox_profile.upsilon_offset() + 1,
        beta_offset,
        scaled_upsilon_product.clone(),
    );
    push_sparse_matrix_entry_if_nonzero(
        &mut quadratic_entries,
        tbox_profile.upsilon_offset() + 1,
        beta_offset + 1,
        scaled_upsilon_product,
    );

    let mut linear_entries = Vec::new();
    for approximate_offset_index in 0..tbox_profile.approximate_relation_polynomial_count() {
        push_sparse_vector_entry_if_nonzero(
            &mut linear_entries,
            tbox_profile.y3_offset() + 1 + 2 * approximate_offset_index,
            challenge_polynomial_from_row(ring, challenge_row, approximate_offset_index)?,
        );
    }

    LazerDemoQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            tbox_profile.quadratic_evaluation_dimension(),
            quadratic_entries,
        )?,
        SparsePolynomialVector::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            linear_entries,
        )?,
        Some(constant_polynomial(
            ring,
            negate_mod(
                dot_signed_response_with_challenge(
                    flattened_response,
                    challenge_row,
                    ring.modulus(),
                )?,
                ring.modulus(),
            ),
        )),
    )
}

fn accumulate_lazer_demo_repetition_relation(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    repetition_index: usize,
    relation: &LazerDemoQuadraticEquation,
) -> CanonicalResult<()> {
    let weighted_relation = [WeightedLazerDemoQuadraticEquation {
        challenge_scalar: 1,
        equation: relation,
    }];
    if repetition_index.is_multiple_of(2) {
        let accumulator_index = repetition_index / 2;
        accumulator_set.primary_schwartz_zippel_accumulators[accumulator_index] = accumulator_set
            .primary_schwartz_zippel_accumulators[accumulator_index]
            .accumulate_weighted_partial_equations(&weighted_relation)?;
    } else {
        let accumulator_index = repetition_index / 2;
        accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_index] = accumulator_set
            .secondary_schwartz_zippel_accumulators[accumulator_index]
            .accumulate_weighted_partial_equations(&weighted_relation)?;
    }

    Ok(())
}

fn flatten_signed_response(
    response_vector: &[Vec<i64>],
    expected_vector_length: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<Vec<i64>> {
    validate_lazer_demo_response_vector(
        response_vector,
        expected_vector_length,
        proof_ring_degree,
    )?;
    Ok(response_vector
        .iter()
        .flat_map(|polynomial| polynomial.iter().copied())
        .collect())
}

fn challenge_polynomial_from_row(
    ring: PolynomialRing,
    challenge_row: &[u64],
    polynomial_index: usize,
) -> CanonicalResult<Vec<u64>> {
    let start = polynomial_index
        .checked_mul(ring.degree())
        .ok_or_else(|| invalid_tbox_relation("challenge polynomial start overflowed"))?;
    let end = start
        .checked_add(ring.degree())
        .ok_or_else(|| invalid_tbox_relation("challenge polynomial end overflowed"))?;
    if end > challenge_row.len() {
        return Err(invalid_tbox_relation(
            "challenge polynomial index is outside the challenge row",
        ));
    }

    Ok(challenge_row[start..end].to_vec())
}

fn sample_lazer_demo_binary_difference_values(
    value_count: usize,
    seed: &[u8; 32],
    domain_separator: u64,
) -> Vec<i8> {
    let byte_count = (2 * value_count).div_ceil(8);
    let random_bytes = super::lazer_demo_rng::generate_lazer_demo_aes256ctr_stream(
        seed,
        domain_separator,
        byte_count,
    );
    let mut values = vec![0_i8; value_count];
    for (value_index, value) in values.iter_mut().enumerate().take(value_count) {
        let positive_bit = read_bit(&random_bytes, value_index);
        let negative_bit = read_bit(&random_bytes, value_count + value_index);
        *value = positive_bit as i8 - negative_bit as i8;
    }

    values
}

fn read_bit(bytes: &[u8], bit_index: usize) -> u8 {
    (bytes[bit_index / 8] >> (bit_index % 8)) & 1
}

fn dot_signed_response_with_challenge(
    flattened_response: &[i64],
    challenge_row: &[u64],
    modulus: u64,
) -> CanonicalResult<u64> {
    if flattened_response.len() != challenge_row.len() {
        return Err(invalid_tbox_relation(
            "response and challenge lengths do not match for the dot product",
        ));
    }
    let mut accumulated_value = 0_i128;
    for (response_coefficient, challenge_coefficient) in
        flattened_response.iter().zip(challenge_row)
    {
        accumulated_value += i128::from(*response_coefficient) * i128::from(*challenge_coefficient);
        accumulated_value %= i128::from(modulus);
    }

    positive_mod_i128(accumulated_value, i128::from(modulus))
}

fn dot_canonical_vectors_mod(left: &[u64], right: &[u64], modulus: u64) -> CanonicalResult<u64> {
    if left.len() != right.len() {
        return Err(invalid_tbox_relation(
            "canonical vector dot-product lengths do not match",
        ));
    }
    let mut accumulated_value = 0_u128;
    for (left_coefficient, right_coefficient) in left.iter().zip(right) {
        accumulated_value = (accumulated_value
            + u128::from(*left_coefficient) * u128::from(*right_coefficient))
            % u128::from(modulus);
    }

    Ok(accumulated_value as u64)
}

fn push_sparse_matrix_entry_if_nonzero(
    entries: &mut Vec<SparsePolynomialMatrixEntry>,
    row_index: usize,
    column_index: usize,
    polynomial: Vec<u64>,
) {
    if !is_zero_polynomial(&polynomial) {
        entries.push(SparsePolynomialMatrixEntry::new(
            row_index,
            column_index,
            polynomial,
        ));
    }
}

fn push_sparse_vector_entry_if_nonzero(
    entries: &mut Vec<SparsePolynomialVectorEntry>,
    position: usize,
    polynomial: Vec<u64>,
) {
    if !is_zero_polynomial(&polynomial) {
        entries.push(SparsePolynomialVectorEntry::new(position, polynomial));
    }
}

fn compose_lazer_demo_matrix_row_domain(
    matrix_domain_separator: u32,
    row_offset: usize,
) -> CanonicalResult<u64> {
    let row_offset = u32::try_from(row_offset)
        .map_err(|_| invalid_tbox_relation("matrix sampler row offset does not fit in u32"))?;
    Ok((u64::from(matrix_domain_separator) << 32) | u64::from(row_offset))
}

fn accumulate_single_lazer_demo_partial_relation_by_schwartz_zippel(
    accumulator_set: &mut LazerDemoTboxRelationAccumulatorSet,
    relation: &LazerDemoQuadraticEquation,
    challenge_seed: &[u8; 32],
    challenge_domain: u32,
    coefficient_bit_length: usize,
) -> CanonicalResult<()> {
    for accumulator_pair_index in 0..accumulator_set.primary_schwartz_zippel_accumulators.len() {
        let challenge_values = sample_lazer_demo_uniform_u64_values(
            2,
            relation.ring().modulus(),
            coefficient_bit_length,
            challenge_seed,
            u64::from(challenge_domain),
        )?;
        accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLazerDemoQuadraticEquation {
                    challenge_scalar: challenge_values[0],
                    equation: relation,
                }])?;
        accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLazerDemoQuadraticEquation {
                    challenge_scalar: challenge_values[1],
                    equation: relation,
                }])?;
    }

    Ok(())
}

#[cfg(test)]
fn build_lazer_demo_beta3_norm_equation() -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_beta3_norm_equation(demo_tbox_profile()?)
}

fn build_lazer_beta3_norm_equation(
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_beta_norm_equation(false, tbox_profile)
}

#[cfg(test)]
fn build_lazer_demo_beta4_norm_equation() -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_beta4_norm_equation(demo_tbox_profile()?)
}

fn build_lazer_beta4_norm_equation(
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_beta_norm_equation(true, tbox_profile)
}

fn build_lazer_beta_norm_equation(
    negated_diagonal_terms: bool,
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    let inverse_two = proof_ring.modulus().div_ceil(2);
    let inverse_four = inverse_four_modulus(proof_ring.modulus())?;
    let diagonal_coefficient = if negated_diagonal_terms {
        negate_mod(inverse_four, proof_ring.modulus())
    } else {
        inverse_four
    };
    let beta_offset = tbox_profile.beta_offset();
    let equation_dimension = tbox_profile.quadratic_many_dimension();

    LazerDemoQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            proof_ring,
            equation_dimension,
            equation_dimension,
            vec![
                SparsePolynomialMatrixEntry::new(
                    beta_offset,
                    beta_offset,
                    constant_polynomial(proof_ring, diagonal_coefficient),
                ),
                SparsePolynomialMatrixEntry::new(
                    beta_offset,
                    beta_offset + 1,
                    constant_polynomial(proof_ring, inverse_two),
                ),
                SparsePolynomialMatrixEntry::new(
                    beta_offset + 1,
                    beta_offset + 1,
                    constant_polynomial(proof_ring, diagonal_coefficient),
                ),
            ],
        )?,
        SparsePolynomialVector::zero(proof_ring, equation_dimension)?,
        Some(constant_polynomial(proof_ring, proof_ring.modulus() - 1)),
    )
}

fn build_lazer_demo_beta3_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_beta3_linear_relation(coefficient_index, coefficient_value, demo_tbox_profile()?)
}

fn build_lazer_beta3_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    if coefficient_index == 0 || coefficient_index >= proof_ring.degree() {
        return Err(invalid_tbox_relation(
            "beta3 coefficient index must be in one through degree minus one",
        ));
    }
    let beta_offset = tbox_profile.beta_offset();
    let coefficient_polynomial =
        single_coefficient_polynomial(proof_ring, coefficient_index, coefficient_value)?;
    let mut vector_entries = Vec::new();
    if !is_zero_polynomial(&coefficient_polynomial) {
        vector_entries.push(SparsePolynomialVectorEntry::new(
            beta_offset,
            coefficient_polynomial.clone(),
        ));
        vector_entries.push(SparsePolynomialVectorEntry::new(
            beta_offset + 1,
            coefficient_polynomial,
        ));
    }

    LazerDemoQuadraticEquation::new(
        SparsePolynomialMatrix::zero(
            proof_ring,
            tbox_profile.quadratic_evaluation_dimension(),
            tbox_profile.quadratic_evaluation_dimension(),
        )?,
        SparsePolynomialVector::new(
            proof_ring,
            tbox_profile.quadratic_evaluation_dimension(),
            vector_entries,
        )?,
        None,
    )
}

fn build_lazer_demo_beta4_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_beta4_linear_relation(coefficient_index, coefficient_value, demo_tbox_profile()?)
}

fn build_lazer_beta4_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    if coefficient_index == 0 || coefficient_index >= proof_ring.degree() {
        return Err(invalid_tbox_relation(
            "beta4 coefficient index must be in one through degree minus one",
        ));
    }
    let half_degree = proof_ring.degree() / 2;
    let shifted_coefficient_index = if coefficient_index < half_degree {
        coefficient_index + half_degree
    } else {
        coefficient_index - half_degree
    };
    let first_position_coefficient = if coefficient_index < half_degree {
        negate_mod(coefficient_value, proof_ring.modulus())
    } else {
        coefficient_value
    };
    let second_position_coefficient = if coefficient_index < half_degree {
        coefficient_value
    } else {
        negate_mod(coefficient_value, proof_ring.modulus())
    };
    let beta_offset = tbox_profile.beta_offset();
    let first_polynomial = single_coefficient_polynomial(
        proof_ring,
        shifted_coefficient_index,
        first_position_coefficient,
    )?;
    let second_polynomial = single_coefficient_polynomial(
        proof_ring,
        shifted_coefficient_index,
        second_position_coefficient,
    )?;

    let mut vector_entries = Vec::new();
    if !is_zero_polynomial(&first_polynomial) {
        vector_entries.push(SparsePolynomialVectorEntry::new(
            beta_offset,
            first_polynomial,
        ));
    }
    if !is_zero_polynomial(&second_polynomial) {
        vector_entries.push(SparsePolynomialVectorEntry::new(
            beta_offset + 1,
            second_polynomial,
        ));
    }

    LazerDemoQuadraticEquation::new(
        SparsePolynomialMatrix::zero(
            proof_ring,
            tbox_profile.quadratic_evaluation_dimension(),
            tbox_profile.quadratic_evaluation_dimension(),
        )?,
        SparsePolynomialVector::new(
            proof_ring,
            tbox_profile.quadratic_evaluation_dimension(),
            vector_entries,
        )?,
        None,
    )
}

fn build_lazer_demo_upsilon_binary_relation() -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_upsilon_binary_relation(demo_tbox_profile()?)
}

fn build_lazer_upsilon_binary_relation(
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    let upsilon_offset = tbox_profile.upsilon_offset();
    let equation_dimension = tbox_profile.quadratic_evaluation_dimension();

    LazerDemoQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            proof_ring,
            equation_dimension,
            equation_dimension,
            vec![SparsePolynomialMatrixEntry::new(
                upsilon_offset,
                upsilon_offset + 1,
                constant_polynomial(proof_ring, 1),
            )],
        )?,
        SparsePolynomialVector::new(
            proof_ring,
            equation_dimension,
            vec![SparsePolynomialVectorEntry::new(
                upsilon_offset + 1,
                all_coefficients_polynomial(proof_ring, proof_ring.modulus() - 1),
            )],
        )?,
        None,
    )
}

fn build_lazer_demo_l2_norm_relation() -> CanonicalResult<LazerDemoQuadraticEquation> {
    build_lazer_l2_norm_relation(demo_tbox_profile()?)
}

fn build_lazer_l2_norm_relation(
    tbox_profile: LazerTboxRelationProfile,
) -> CanonicalResult<LazerDemoQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    let equation_dimension = tbox_profile.quadratic_evaluation_dimension();
    let mut quadratic_entries = Vec::with_capacity(tbox_profile.exact_norm_dimension());
    for short_coordinate_index in 0..tbox_profile.exact_norm_dimension() {
        quadratic_entries.push(SparsePolynomialMatrixEntry::new(
            2 * short_coordinate_index,
            2 * short_coordinate_index + 1,
            constant_polynomial(proof_ring, 1),
        ));
    }

    LazerDemoQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            proof_ring,
            equation_dimension,
            equation_dimension,
            quadratic_entries,
        )?,
        SparsePolynomialVector::new(
            proof_ring,
            equation_dimension,
            vec![SparsePolynomialVectorEntry::new(
                tbox_profile.upsilon_offset(),
                binary_power_polynomial_automorphism(
                    proof_ring,
                    tbox_profile.exact_norm_bound_squared,
                    tbox_profile.coefficient_bit_length,
                )?,
            )],
        )?,
        Some(constant_polynomial(
            proof_ring,
            proof_ring.modulus() - tbox_profile.exact_norm_bound_squared,
        )),
    )
}

fn ensure_lazer_demo_binary_relation_is_not_required() -> CanonicalResult<()> {
    if LAZER_DEMO_TBOX_BINARY_DOMAIN_OFFSET >= LAZER_DEMO_TBOX_EUCLIDEAN_DOMAIN_OFFSET {
        return Err(invalid_tbox_relation(
            "binary relation domain layout is inconsistent with the demo tbox profile",
        ));
    }

    Ok(())
}

fn inverse_four_modulus(modulus: u64) -> CanonicalResult<u64> {
    if modulus <= 4 || modulus.is_multiple_of(2) {
        return Err(invalid_tbox_relation(
            "modular inverse of four requires an odd modulus greater than four",
        ));
    }

    let modulus_multiplier = if modulus % 4 == 1 { 3_u128 } else { 1_u128 };
    let inverse = modulus_multiplier
        .checked_mul(u128::from(modulus))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid_tbox_relation("modular inverse of four overflowed"))?
        / 4;

    u64::try_from(inverse)
        .map_err(|_| invalid_tbox_relation("modular inverse of four does not fit in u64"))
}

fn validate_lazer_demo_tbox_shape() -> CanonicalResult<()> {
    if LAZER_DEMO_TBOX_SHORT_MESSAGE_LENGTH != 33
        || LAZER_DEMO_TBOX_UPSILON_COORDINATES != 1
        || LAZER_DEMO_TBOX_UNBOUNDED_MESSAGE_LENGTH != 0
        || LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES != 16
        || LAZER_DEMO_TBOX_EXTENDED_COORDINATES != 33
        || LAZER_DEMO_TBOX_QUADRATIC_MANY_MESSAGE_LENGTH != 11
        || LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS != 4
    {
        return Err(invalid_tbox_relation(
            "demo tbox constants no longer match temp/lazer/python/demo/demo_params.h",
        ));
    }

    Ok(())
}

pub(crate) fn lazer_demo_tbox_proof_ring() -> CanonicalResult<PolynomialRing> {
    PolynomialRing::new(
        LAZER_DEMO_PROOF_RING_DEGREE,
        LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
    )
}

fn lazer_demo_tbox_short_message_without_upsilon() -> usize {
    LAZER_DEMO_TBOX_SHORT_MESSAGE_LENGTH - LAZER_DEMO_TBOX_UPSILON_COORDINATES
}

fn lazer_demo_tbox_beta_offset() -> usize {
    let proof_ring_offset_for_approximate_relation =
        LAZER_DEMO_PROOF_RING_DEGREE / LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES;
    let proof_ring_offset_for_extended_relation =
        LAZER_DEMO_PROOF_RING_DEGREE / LAZER_DEMO_TBOX_APPROXIMATE_NORM_COORDINATES;

    (lazer_demo_tbox_short_message_without_upsilon()
        + LAZER_DEMO_TBOX_UPSILON_COORDINATES
        + LAZER_DEMO_TBOX_UNBOUNDED_MESSAGE_LENGTH
        + proof_ring_offset_for_approximate_relation
        + proof_ring_offset_for_extended_relation)
        * 2
}

#[cfg(test)]
fn lazer_demo_tbox_upsilon_offset() -> usize {
    lazer_demo_tbox_short_message_without_upsilon() * 2
}

pub(crate) fn lazer_demo_tbox_quadratic_many_dimension() -> usize {
    2 * (LAZER_DEMO_TBOX_SHORT_MESSAGE_LENGTH + LAZER_DEMO_TBOX_QUADRATIC_MANY_MESSAGE_LENGTH)
}

pub(crate) fn constant_polynomial(ring: PolynomialRing, coefficient: u64) -> Vec<u64> {
    let mut polynomial = vec![0_u64; ring.degree()];
    polynomial[0] = coefficient % ring.modulus();
    polynomial
}

fn all_coefficients_polynomial(ring: PolynomialRing, coefficient: u64) -> Vec<u64> {
    vec![coefficient % ring.modulus(); ring.degree()]
}

fn single_coefficient_polynomial(
    ring: PolynomialRing,
    coefficient_index: usize,
    coefficient: u64,
) -> CanonicalResult<Vec<u64>> {
    if coefficient_index >= ring.degree() {
        return Err(invalid_tbox_relation(
            "single coefficient index is outside the proof ring degree",
        ));
    }
    let mut polynomial = vec![0_u64; ring.degree()];
    polynomial[coefficient_index] = coefficient % ring.modulus();

    Ok(polynomial)
}

fn binary_power_polynomial_automorphism(
    ring: PolynomialRing,
    value: u64,
    coefficient_bit_length: usize,
) -> CanonicalResult<Vec<u64>> {
    let mut polynomial = vec![0_u64; ring.degree()];
    for (bit_index, coefficient) in polynomial
        .iter_mut()
        .enumerate()
        .take(coefficient_bit_length)
    {
        let power_of_two =
            1_u64
                .checked_shl(u32::try_from(bit_index).map_err(|_| {
                    invalid_tbox_relation("binary power bit index does not fit in u32")
                })?)
                .ok_or_else(|| invalid_tbox_relation("binary power coefficient overflowed"))?;
        if power_of_two <= value {
            *coefficient = power_of_two % ring.modulus();
        }
    }

    ring.automorphism(&polynomial)
}

fn is_zero_polynomial(polynomial: &[u64]) -> bool {
    polynomial.iter().all(|coefficient| *coefficient == 0)
}

fn negate_mod(value: u64, modulus: u64) -> u64 {
    if value == 0 { 0 } else { modulus - value }
}

fn multiply_mod(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

fn positive_mod_i128(value: i128, modulus: i128) -> CanonicalResult<u64> {
    if modulus <= 1 {
        return Err(invalid_tbox_relation("modulus must be greater than one"));
    }
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    u64::try_from(reduced)
        .map_err(|_| invalid_tbox_relation("reduced signed value does not fit in u64"))
}

fn invalid_tbox_relation(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        LAZER_DEMO_PROOF_COEFFICIENT_BIT_LENGTH, LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
        LAZER_DEMO_PROOF_RING_DEGREE, LAZER_DEMO_TBOX_BETA3_DOMAIN_OFFSET,
        LAZER_DEMO_TBOX_BETA4_DOMAIN_OFFSET, LAZER_DEMO_TBOX_EUCLIDEAN_DOMAIN_OFFSET,
        LAZER_DEMO_TBOX_EXACT_NORM_BOUND_SQUARED, LAZER_DEMO_TBOX_EXACT_NORM_DIMENSION,
        LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS, LAZER_DEMO_TBOX_UPSILON_DOMAIN_OFFSET,
        apply_lazer_demo_tbox_beta3_relations, apply_lazer_demo_tbox_beta4_relations,
        apply_lazer_demo_tbox_l2_relation, apply_lazer_demo_tbox_upsilon_relation,
        build_lazer_demo_beta3_linear_relation, build_lazer_demo_beta3_norm_equation,
        build_lazer_demo_beta4_linear_relation, build_lazer_demo_beta4_norm_equation,
        build_lazer_demo_l2_norm_relation, build_lazer_demo_tbox_prefix_accumulators,
        build_lazer_demo_upsilon_binary_relation, initialize_lazer_demo_tbox_relation_accumulators,
        inverse_four_modulus, lazer_demo_tbox_beta_offset, lazer_demo_tbox_upsilon_offset,
        multiply_mod, validate_lazer_demo_tbox_relation_builder_port,
    };
    use crate::ballot_privacy::lazer_demo_rng::sample_lazer_demo_uniform_u64_values;

    #[test]
    fn initial_accumulators_include_beta_norm_equations() {
        let accumulators = initialize_lazer_demo_tbox_relation_accumulators()
            .expect("initial accumulators should validate");

        assert_eq!(accumulators.primary_schwartz_zippel_accumulators.len(), 2);
        assert_eq!(accumulators.secondary_schwartz_zippel_accumulators.len(), 2);
        assert_eq!(accumulators.extra_beta_norm_equations.len(), 2);
        assert_eq!(
            accumulators.extra_beta_norm_equations[0]
                .quadratic_terms()
                .entries()
                .len(),
            3
        );
        assert_eq!(
            accumulators.extra_beta_norm_equations[0]
                .constant_term()
                .expect("constant should exist")[0],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS - 1
        );
    }

    #[test]
    fn beta3_linear_relation_uses_expected_beta_coordinates() {
        let relation =
            build_lazer_demo_beta3_linear_relation(1, 9).expect("beta3 relation should validate");

        assert!(relation.quadratic_terms().entries().is_empty());
        assert_eq!(relation.linear_terms().entries().len(), 2);
        assert_eq!(
            relation.linear_terms().entries()[0].position(),
            lazer_demo_tbox_beta_offset()
        );
        assert_eq!(
            relation.linear_terms().entries()[1].position(),
            lazer_demo_tbox_beta_offset() + 1
        );
        assert_eq!(relation.linear_terms().entries()[0].coefficients()[1], 9);
        assert_eq!(relation.linear_terms().entries()[1].coefficients()[1], 9);
        assert!(relation.constant_term().is_none());
    }

    #[test]
    fn beta4_linear_relation_applies_half_degree_shift_and_signs() {
        let lower_half_relation = build_lazer_demo_beta4_linear_relation(1, 9)
            .expect("lower-half beta4 relation should validate");
        let upper_half_relation = build_lazer_demo_beta4_linear_relation(32, 9)
            .expect("upper-half beta4 relation should validate");

        assert_eq!(
            lower_half_relation.linear_terms().entries()[0].coefficients()[33],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS - 9
        );
        assert_eq!(
            lower_half_relation.linear_terms().entries()[1].coefficients()[33],
            9
        );
        assert_eq!(
            upper_half_relation.linear_terms().entries()[0].coefficients()[0],
            9
        );
        assert_eq!(
            upper_half_relation.linear_terms().entries()[1].coefficients()[0],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS - 9
        );
    }

    #[test]
    fn beta_norm_diagonal_uses_modular_inverse_of_four() {
        let proof_ring = super::lazer_demo_tbox_proof_ring().expect("proof ring should validate");
        let inverse_four = inverse_four_modulus(proof_ring.modulus())
            .expect("inverse of four should exist for the demo modulus");
        assert_eq!(inverse_four, 27_021_597_764_223_448);
        assert_eq!(
            ((u128::from(inverse_four) * 4) % u128::from(proof_ring.modulus())) as u64,
            1
        );

        let beta3_norm_equation =
            build_lazer_demo_beta3_norm_equation().expect("beta3 norm equation should build");
        let beta4_norm_equation =
            build_lazer_demo_beta4_norm_equation().expect("beta4 norm equation should build");

        assert_eq!(
            beta3_norm_equation.quadratic_terms().entries()[0].coefficients()[0],
            inverse_four
        );
        assert_eq!(
            beta4_norm_equation.quadratic_terms().entries()[0].coefficients()[0],
            proof_ring.modulus() - inverse_four
        );
    }

    #[test]
    fn beta_accumulators_use_the_same_challenge_layout_as_upstream() {
        let mut accumulators = initialize_lazer_demo_tbox_relation_accumulators()
            .expect("initial accumulators should validate");
        let challenge_seed = [3_u8; 32];

        apply_lazer_demo_tbox_beta3_relations(&mut accumulators, &challenge_seed)
            .expect("beta3 accumulation should succeed");

        let beta3_challenges = sample_lazer_demo_uniform_u64_values(
            (LAZER_DEMO_PROOF_RING_DEGREE - 1) * LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
            LAZER_DEMO_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(LAZER_DEMO_TBOX_BETA3_DOMAIN_OFFSET),
        )
        .expect("challenge sampling should succeed");
        let inverse_two = LAZER_DEMO_PROOF_COEFFICIENT_MODULUS.div_ceil(2);
        let expected_first_primary = multiply_mod(
            inverse_two,
            beta3_challenges[0],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
        );
        let expected_second_primary = multiply_mod(
            inverse_two,
            beta3_challenges[4],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
        );

        assert_eq!(
            accumulators.primary_schwartz_zippel_accumulators[0]
                .linear_terms()
                .entries()[0]
                .coefficients()[1],
            expected_first_primary
        );
        assert_eq!(
            accumulators.primary_schwartz_zippel_accumulators[0]
                .linear_terms()
                .entries()[0]
                .coefficients()[2],
            expected_second_primary
        );

        apply_lazer_demo_tbox_beta4_relations(&mut accumulators, &challenge_seed)
            .expect("beta4 accumulation should succeed");
        let beta4_challenges = sample_lazer_demo_uniform_u64_values(
            (LAZER_DEMO_PROOF_RING_DEGREE - 1) * LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS,
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
            LAZER_DEMO_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(LAZER_DEMO_TBOX_BETA4_DOMAIN_OFFSET),
        )
        .expect("challenge sampling should succeed");
        let expected_beta4_shifted = multiply_mod(
            inverse_two,
            beta4_challenges[0],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
        );
        let expected_beta3_at_shifted_index = multiply_mod(
            inverse_two,
            beta3_challenges[32 * LAZER_DEMO_TBOX_QUADRATIC_EVALUATION_REPETITIONS],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
        );
        let expected_accumulated_shifted_coefficient =
            if expected_beta3_at_shifted_index >= expected_beta4_shifted {
                expected_beta3_at_shifted_index - expected_beta4_shifted
            } else {
                LAZER_DEMO_PROOF_COEFFICIENT_MODULUS + expected_beta3_at_shifted_index
                    - expected_beta4_shifted
            };
        assert_eq!(
            accumulators.primary_schwartz_zippel_accumulators[0]
                .linear_terms()
                .entries()[0]
                .coefficients()[33],
            expected_accumulated_shifted_coefficient
        );
    }

    #[test]
    fn upsilon_and_l2_relations_match_demo_shapes() {
        let upsilon_relation =
            build_lazer_demo_upsilon_binary_relation().expect("upsilon relation should validate");
        let l2_relation = build_lazer_demo_l2_norm_relation().expect("l2 relation should validate");

        assert_eq!(
            upsilon_relation.quadratic_terms().entries()[0].row_index(),
            lazer_demo_tbox_upsilon_offset()
        );
        assert_eq!(
            upsilon_relation.quadratic_terms().entries()[0].column_index(),
            lazer_demo_tbox_upsilon_offset() + 1
        );
        assert_eq!(
            l2_relation.quadratic_terms().entries().len(),
            LAZER_DEMO_TBOX_EXACT_NORM_DIMENSION
        );
        assert_eq!(
            l2_relation.linear_terms().entries()[0].position(),
            lazer_demo_tbox_upsilon_offset()
        );
        assert_eq!(l2_relation.linear_terms().entries()[0].coefficients()[0], 1);
        assert_eq!(
            l2_relation.linear_terms().entries()[0].coefficients()[53],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS - LAZER_DEMO_TBOX_EXACT_NORM_BOUND_SQUARED
        );
        assert_eq!(
            l2_relation.constant_term().expect("constant should exist")[0],
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS - LAZER_DEMO_TBOX_EXACT_NORM_BOUND_SQUARED
        );
    }

    #[test]
    fn upsilon_and_l2_accumulators_use_single_relation_schwartz_zippel_domains() {
        let mut accumulators = initialize_lazer_demo_tbox_relation_accumulators()
            .expect("initial accumulators should validate");
        let challenge_seed = [4_u8; 32];

        apply_lazer_demo_tbox_upsilon_relation(&mut accumulators, &challenge_seed)
            .expect("upsilon accumulation should succeed");
        let upsilon_challenges = sample_lazer_demo_uniform_u64_values(
            2,
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
            LAZER_DEMO_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(LAZER_DEMO_TBOX_UPSILON_DOMAIN_OFFSET),
        )
        .expect("upsilon challenge sampling should succeed");
        assert_eq!(
            accumulators.primary_schwartz_zippel_accumulators[0]
                .quadratic_terms()
                .entries()[0]
                .coefficients()[0],
            upsilon_challenges[0]
        );
        assert_eq!(
            accumulators.primary_schwartz_zippel_accumulators[1]
                .quadratic_terms()
                .entries()[0]
                .coefficients()[0],
            upsilon_challenges[0]
        );

        apply_lazer_demo_tbox_l2_relation(&mut accumulators, &challenge_seed)
            .expect("l2 accumulation should succeed");
        let l2_challenges = sample_lazer_demo_uniform_u64_values(
            2,
            LAZER_DEMO_PROOF_COEFFICIENT_MODULUS,
            LAZER_DEMO_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(LAZER_DEMO_TBOX_EUCLIDEAN_DOMAIN_OFFSET),
        )
        .expect("l2 challenge sampling should succeed");
        assert_eq!(
            accumulators.primary_schwartz_zippel_accumulators[0]
                .constant_term()
                .expect("constant should exist")[0],
            multiply_mod(
                LAZER_DEMO_PROOF_COEFFICIENT_MODULUS - LAZER_DEMO_TBOX_EXACT_NORM_BOUND_SQUARED,
                l2_challenges[0],
                LAZER_DEMO_PROOF_COEFFICIENT_MODULUS
            )
        );
    }

    #[test]
    fn prefix_accumulators_auto_fold_to_quad_many_equation_count() {
        let accumulators = build_lazer_demo_tbox_prefix_accumulators(&[9_u8; 32])
            .expect("prefix accumulators should validate");

        let folded_equations = accumulators
            .auto_folded_equations()
            .expect("auto-fold should succeed");

        assert_eq!(folded_equations.len(), 4);
        assert!(!folded_equations[0].quadratic_terms().entries().is_empty());
        assert!(!folded_equations[0].linear_terms().entries().is_empty());
    }

    #[test]
    fn relation_builder_self_check_passes() {
        validate_lazer_demo_tbox_relation_builder_port()
            .expect("relation builder self-check should pass");
    }
}
