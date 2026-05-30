use super::*;
// Encodes (1/2 (beta + sigma(beta)))^2 = 1, i.e. beta^2 = 1 over the sigma-fixed
// subfield (beta is a sign). Diagonal entries carry 1/4, the off-diagonal 1/2, and
// the constant is q-1 = -1 mod q.
pub(super) fn build_beta_norm_equation(
    negated_diagonal_terms: bool,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
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

    LinearProofQuadraticEquation::new(
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

#[cfg(test)]
pub(super) fn build_default_beta3_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    build_beta3_linear_relation(coefficient_index, coefficient_value, demo_tbox_profile()?)
}

#[cfg(test)]
pub(super) fn build_beta3_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
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

    LinearProofQuadraticEquation::new(
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

#[cfg(test)]
pub(super) fn build_default_beta4_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    build_beta4_linear_relation(coefficient_index, coefficient_value, demo_tbox_profile()?)
}

#[cfg(test)]
pub(super) fn build_beta4_linear_relation(
    coefficient_index: usize,
    coefficient_value: u64,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
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

    LinearProofQuadraticEquation::new(
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

#[cfg(test)]
pub(super) fn build_default_upsilon_binary_relation()
-> CanonicalResult<LinearProofQuadraticEquation> {
    build_upsilon_binary_relation(demo_tbox_profile()?)
}

pub(super) fn build_upsilon_binary_relation(
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    let proof_ring = tbox_profile.proof_ring;
    let upsilon_offset = tbox_profile.upsilon_offset();
    let equation_dimension = tbox_profile.quadratic_evaluation_dimension();

    LinearProofQuadraticEquation::new(
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

#[cfg(test)]
pub(super) fn build_default_l2_norm_relation() -> CanonicalResult<LinearProofQuadraticEquation> {
    build_l2_norm_relation(demo_tbox_profile()?)
}

pub(super) fn build_l2_norm_relation(
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
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

    LinearProofQuadraticEquation::new(
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

pub(super) fn ensure_linear_proof_binary_relation_is_not_required() -> CanonicalResult<()> {
    if TBOX_BINARY_DOMAIN_OFFSET >= TBOX_EUCLIDEAN_DOMAIN_OFFSET {
        return Err(invalid_tbox_relation(
            "binary relation domain layout is inconsistent with the demo tbox profile",
        ));
    }

    Ok(())
}

// Computes 4^{-1} mod q as (k*q + 1)/4. k is chosen so k*q + 1 is divisible by 4:
// k = 3 when q ≡ 1 (mod 4), else k = 1 (q is odd, so q ≡ 3 (mod 4) gives q+1 ≡ 0).
pub(super) fn inverse_four_modulus(modulus: u64) -> CanonicalResult<u64> {
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

// Tripwire: hard-asserts the demo profile shape (33/1/0/16/33/11/4) so the
// demo-derived relation builders cannot be used with a mismatched profile.
pub(super) fn validate_tbox_shape() -> CanonicalResult<()> {
    if TBOX_SHORT_MESSAGE_LENGTH != 33
        || TBOX_UPSILON_COORDINATES != 1
        || TBOX_UNBOUNDED_MESSAGE_LENGTH != 0
        || TBOX_APPROXIMATE_NORM_COORDINATES != 16
        || TBOX_EXTENDED_COORDINATES != 33
        || TBOX_QUADRATIC_MANY_MESSAGE_LENGTH != 11
        || TBOX_QUADRATIC_EVALUATION_REPETITIONS != 4
    {
        return Err(invalid_tbox_relation(
            "default tbox constants no longer match the proof encoding contract",
        ));
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn tbox_proof_ring() -> CanonicalResult<PolynomialRing> {
    PolynomialRing::new(
        DEFAULT_LINEAR_PROOF_RING_DEGREE,
        DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
    )
}

#[cfg(test)]
pub(super) fn tbox_short_message_without_upsilon() -> usize {
    TBOX_SHORT_MESSAGE_LENGTH - TBOX_UPSILON_COORDINATES
}

#[cfg(test)]
pub(super) fn tbox_beta_offset() -> usize {
    let proof_ring_offset_for_approximate_relation =
        DEFAULT_LINEAR_PROOF_RING_DEGREE / TBOX_APPROXIMATE_NORM_COORDINATES;
    let proof_ring_offset_for_extended_relation =
        DEFAULT_LINEAR_PROOF_RING_DEGREE / TBOX_APPROXIMATE_NORM_COORDINATES;

    (tbox_short_message_without_upsilon()
        + TBOX_UPSILON_COORDINATES
        + TBOX_UNBOUNDED_MESSAGE_LENGTH
        + proof_ring_offset_for_approximate_relation
        + proof_ring_offset_for_extended_relation)
        * 2
}

#[cfg(test)]
pub(super) fn tbox_upsilon_offset() -> usize {
    tbox_short_message_without_upsilon() * 2
}

#[cfg(test)]
pub(crate) fn tbox_quadratic_many_dimension() -> usize {
    2 * (TBOX_SHORT_MESSAGE_LENGTH + TBOX_QUADRATIC_MANY_MESSAGE_LENGTH)
}

pub(crate) fn constant_polynomial(ring: PolynomialRing, coefficient: u64) -> Vec<u64> {
    let mut polynomial = vec![0_u64; ring.degree()];
    polynomial[0] = coefficient % ring.modulus();
    polynomial
}

pub(super) fn all_coefficients_polynomial(ring: PolynomialRing, coefficient: u64) -> Vec<u64> {
    vec![coefficient % ring.modulus(); ring.degree()]
}

pub(super) fn single_coefficient_polynomial(
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

// Binary-decomposition gadget for the squared-norm bound: builds Sum 2^i X^i over
// powers 2^i <= value (truncated to coefficient_bit_length), then applies sigma.
pub(super) fn binary_power_polynomial_automorphism(
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

pub(super) fn is_zero_polynomial(polynomial: &[u64]) -> bool {
    polynomial.iter().all(|coefficient| *coefficient == 0)
}

pub(super) fn negate_mod(value: u64, modulus: u64) -> u64 {
    if value == 0 { 0 } else { modulus - value }
}

pub(super) fn multiply_mod(left: u64, right: u64, modulus: u64) -> u64 {
    crate::ballot_privacy::polynomial_ring::mul_mod(left, right, modulus)
}

pub(super) fn positive_mod_i128(value: i128, modulus: i128) -> CanonicalResult<u64> {
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

pub(super) fn invalid_tbox_relation(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS, DEFAULT_LINEAR_PROOF_RING_DEGREE,
        TBOX_BETA3_DOMAIN_OFFSET, TBOX_BETA4_DOMAIN_OFFSET, TBOX_EUCLIDEAN_DOMAIN_OFFSET,
        TBOX_EXACT_NORM_BOUND_SQUARED, TBOX_EXACT_NORM_DIMENSION,
        TBOX_QUADRATIC_EVALUATION_REPETITIONS, TBOX_UPSILON_DOMAIN_OFFSET,
        apply_default_tbox_beta3_relations, apply_default_tbox_beta4_relations,
        apply_default_tbox_l2_relation, apply_default_tbox_upsilon_relation,
        build_default_beta3_linear_relation, build_default_beta3_norm_equation,
        build_default_beta4_linear_relation, build_default_beta4_norm_equation,
        build_default_l2_norm_relation, build_default_tbox_prefix_accumulators,
        build_default_upsilon_binary_relation, initialize_default_tbox_relation_accumulators,
        inverse_four_modulus, multiply_mod, tbox_beta_offset, tbox_upsilon_offset,
        validate_tbox_relation_builder_self_check,
    };
    use crate::ballot_privacy::linear_proof::public_parameters::DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH;
    use crate::ballot_privacy::linear_proof::rng::sample_linear_proof_uniform_u64_values;

    #[test]
    fn initial_accumulators_include_beta_norm_equations() {
        let accumulators = initialize_default_tbox_relation_accumulators()
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
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS - 1
        );
    }

    #[test]
    fn beta3_linear_relation_uses_expected_beta_coordinates() {
        let relation =
            build_default_beta3_linear_relation(1, 9).expect("beta3 relation should validate");

        assert!(relation.quadratic_terms().entries().is_empty());
        assert_eq!(relation.linear_terms().entries().len(), 2);
        assert_eq!(
            relation.linear_terms().entries()[0].position(),
            tbox_beta_offset()
        );
        assert_eq!(
            relation.linear_terms().entries()[1].position(),
            tbox_beta_offset() + 1
        );
        assert_eq!(relation.linear_terms().entries()[0].coefficients()[1], 9);
        assert_eq!(relation.linear_terms().entries()[1].coefficients()[1], 9);
        assert!(relation.constant_term().is_none());
    }

    #[test]
    fn beta4_linear_relation_applies_half_degree_shift_and_signs() {
        let lower_half_relation = build_default_beta4_linear_relation(1, 9)
            .expect("lower-half beta4 relation should validate");
        let upper_half_relation = build_default_beta4_linear_relation(32, 9)
            .expect("upper-half beta4 relation should validate");

        assert_eq!(
            lower_half_relation.linear_terms().entries()[0].coefficients()[33],
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS - 9
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
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS - 9
        );
    }

    #[test]
    fn beta_norm_diagonal_uses_modular_inverse_of_four() {
        let proof_ring = super::tbox_proof_ring().expect("proof ring should validate");
        let inverse_four = inverse_four_modulus(proof_ring.modulus())
            .expect("inverse of four should exist for the demo modulus");
        assert_eq!(inverse_four, 27_021_597_764_223_448);
        assert_eq!(
            ((u128::from(inverse_four) * 4) % u128::from(proof_ring.modulus())) as u64,
            1
        );

        let beta3_norm_equation =
            build_default_beta3_norm_equation().expect("beta3 norm equation should build");
        let beta4_norm_equation =
            build_default_beta4_norm_equation().expect("beta4 norm equation should build");

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
        let mut accumulators = initialize_default_tbox_relation_accumulators()
            .expect("initial accumulators should validate");
        let challenge_seed = [3_u8; 32];

        apply_default_tbox_beta3_relations(&mut accumulators, &challenge_seed)
            .expect("beta3 accumulation should succeed");

        let beta3_challenges = sample_linear_proof_uniform_u64_values(
            (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) * TBOX_QUADRATIC_EVALUATION_REPETITIONS,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(TBOX_BETA3_DOMAIN_OFFSET),
        )
        .expect("challenge sampling should succeed");
        let inverse_two = DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS.div_ceil(2);
        let expected_first_primary = multiply_mod(
            inverse_two,
            beta3_challenges[0],
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
        );
        let expected_second_primary = multiply_mod(
            inverse_two,
            beta3_challenges[4],
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
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

        apply_default_tbox_beta4_relations(&mut accumulators, &challenge_seed)
            .expect("beta4 accumulation should succeed");
        let beta4_challenges = sample_linear_proof_uniform_u64_values(
            (DEFAULT_LINEAR_PROOF_RING_DEGREE - 1) * TBOX_QUADRATIC_EVALUATION_REPETITIONS,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(TBOX_BETA4_DOMAIN_OFFSET),
        )
        .expect("challenge sampling should succeed");
        let expected_beta4_shifted = multiply_mod(
            inverse_two,
            beta4_challenges[0],
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
        );
        let expected_beta3_at_shifted_index = multiply_mod(
            inverse_two,
            beta3_challenges[32 * TBOX_QUADRATIC_EVALUATION_REPETITIONS],
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
        );
        let expected_accumulated_shifted_coefficient =
            if expected_beta3_at_shifted_index >= expected_beta4_shifted {
                expected_beta3_at_shifted_index - expected_beta4_shifted
            } else {
                DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS + expected_beta3_at_shifted_index
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
            build_default_upsilon_binary_relation().expect("upsilon relation should validate");
        let l2_relation = build_default_l2_norm_relation().expect("l2 relation should validate");

        assert_eq!(
            upsilon_relation.quadratic_terms().entries()[0].row_index(),
            tbox_upsilon_offset()
        );
        assert_eq!(
            upsilon_relation.quadratic_terms().entries()[0].column_index(),
            tbox_upsilon_offset() + 1
        );
        assert_eq!(
            l2_relation.quadratic_terms().entries().len(),
            TBOX_EXACT_NORM_DIMENSION
        );
        assert_eq!(
            l2_relation.linear_terms().entries()[0].position(),
            tbox_upsilon_offset()
        );
        assert_eq!(l2_relation.linear_terms().entries()[0].coefficients()[0], 1);
        assert_eq!(
            l2_relation.linear_terms().entries()[0].coefficients()[53],
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS - TBOX_EXACT_NORM_BOUND_SQUARED
        );
        assert_eq!(
            l2_relation.constant_term().expect("constant should exist")[0],
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS - TBOX_EXACT_NORM_BOUND_SQUARED
        );
    }

    #[test]
    fn upsilon_and_l2_accumulators_use_single_relation_schwartz_zippel_domains() {
        let mut accumulators = initialize_default_tbox_relation_accumulators()
            .expect("initial accumulators should validate");
        let challenge_seed = [4_u8; 32];

        apply_default_tbox_upsilon_relation(&mut accumulators, &challenge_seed)
            .expect("upsilon accumulation should succeed");
        let upsilon_challenges = sample_linear_proof_uniform_u64_values(
            2,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(TBOX_UPSILON_DOMAIN_OFFSET),
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

        apply_default_tbox_l2_relation(&mut accumulators, &challenge_seed)
            .expect("l2 accumulation should succeed");
        let l2_challenges = sample_linear_proof_uniform_u64_values(
            2,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS,
            DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH,
            &challenge_seed,
            u64::from(TBOX_EUCLIDEAN_DOMAIN_OFFSET),
        )
        .expect("l2 challenge sampling should succeed");
        assert_eq!(
            accumulators.primary_schwartz_zippel_accumulators[0]
                .constant_term()
                .expect("constant should exist")[0],
            multiply_mod(
                DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS - TBOX_EXACT_NORM_BOUND_SQUARED,
                l2_challenges[0],
                DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS
            )
        );
    }

    #[test]
    fn prefix_accumulators_auto_fold_to_quad_many_equation_count() {
        let accumulators = build_default_tbox_prefix_accumulators(&[9_u8; 32])
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
        validate_tbox_relation_builder_self_check()
            .expect("relation builder self-check should pass");
    }
}
