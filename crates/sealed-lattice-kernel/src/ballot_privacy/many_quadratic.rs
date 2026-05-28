use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[cfg(test)]
use super::linear_proof_public_parameters::DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH;
#[cfg(test)]
use super::tbox_relations::{
    linear_proof_tbox_proof_ring, linear_proof_tbox_quadratic_many_dimension,
};
use super::{
    linear_proof_rng::sample_linear_proof_uniform_u64_values,
    polynomial_ring::PolynomialRing,
    quadratic_equation::LinearProofQuadraticEquation,
    tbox_relations::{
        TBOX_QUADRATIC_EVALUATION_MESSAGE_LENGTH, TBOX_QUADRATIC_MANY_MESSAGE_LENGTH,
        TboxRelationAccumulatorSet, constant_polynomial,
    },
};

const TBOX_HASH_MASK_POLYNOMIALS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManyQuadraticFold {
    pub(crate) folded_equation: LinearProofQuadraticEquation,
    pub(crate) challenge_polynomials: Vec<Vec<u64>>,
}

pub(crate) fn build_many_quadratic_equations(
    accumulator_set: &TboxRelationAccumulatorSet,
    hash_mask_vector: &[Vec<u64>],
) -> CanonicalResult<Vec<LinearProofQuadraticEquation>> {
    let folded_tbox_equations = accumulator_set.auto_folded_equations()?;
    if folded_tbox_equations.len() != 4 {
        return Err(invalid_many_quadratic(
            "tbox accumulator fold must produce two hash-mask equations and two beta norm equations",
        ));
    }
    let proof_ring = folded_tbox_equations[0].ring();
    validate_linear_proof_hash_mask_vector(hash_mask_vector, proof_ring)?;
    let evaluation_dimension = folded_tbox_equations[0].dimension();
    if evaluation_dimension < 2 * TBOX_QUADRATIC_EVALUATION_MESSAGE_LENGTH
        || !evaluation_dimension.is_multiple_of(2)
    {
        return Err(invalid_many_quadratic(
            "tbox accumulator evaluation dimension is not compatible with the many-quadratic layout",
        ));
    }
    let short_response_message_length =
        evaluation_dimension / 2 - TBOX_QUADRATIC_EVALUATION_MESSAGE_LENGTH;
    let many_quadratic_dimension =
        2 * (short_response_message_length + TBOX_QUADRATIC_MANY_MESSAGE_LENGTH);

    let hash_mask_linear_position_base = evaluation_dimension;
    let mut many_quadratic_equations = Vec::with_capacity(folded_tbox_equations.len());
    for hash_mask_index in 0..TBOX_HASH_MASK_POLYNOMIALS {
        let expanded_equation =
            folded_tbox_equations[hash_mask_index].resize_dimension(many_quadratic_dimension)?;
        let linked_equation = expanded_equation
            .sub_constant_polynomial(&hash_mask_vector[hash_mask_index])?
            .add_linear_polynomial_term(
                hash_mask_linear_position_base + 2 * hash_mask_index,
                constant_polynomial(proof_ring, 1),
            )?;
        many_quadratic_equations.push(linked_equation);
    }

    for beta_norm_equation in &folded_tbox_equations[TBOX_HASH_MASK_POLYNOMIALS..] {
        many_quadratic_equations
            .push(beta_norm_equation.resize_dimension(many_quadratic_dimension)?);
    }

    Ok(many_quadratic_equations)
}

#[cfg(test)]
pub(crate) fn fold_default_many_quadratic_equations(
    equations: &[LinearProofQuadraticEquation],
    challenge_seed: &[u8; 32],
) -> CanonicalResult<ManyQuadraticFold> {
    fold_many_quadratic_equations(
        equations,
        challenge_seed,
        DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH,
    )
}

pub(crate) fn fold_many_quadratic_equations(
    equations: &[LinearProofQuadraticEquation],
    challenge_seed: &[u8; 32],
    coefficient_bit_length: usize,
) -> CanonicalResult<ManyQuadraticFold> {
    if equations.is_empty() {
        return Err(invalid_many_quadratic(
            "many-quadratic folding requires at least one equation",
        ));
    }

    let proof_ring = equations[0].ring();
    let expected_dimension = equations[0].dimension();
    let mut folded_equation = LinearProofQuadraticEquation::zero(proof_ring, expected_dimension)?;
    let mut challenge_polynomials = Vec::with_capacity(equations.len());
    for (equation_index, equation) in equations.iter().enumerate() {
        if equation.ring() != proof_ring || equation.dimension() != expected_dimension {
            return Err(invalid_many_quadratic(
                "many-quadratic folding requires equations with matching rings and dimensions",
            ));
        }

        let challenge_polynomial = sample_linear_proof_uniform_u64_values(
            proof_ring.degree(),
            proof_ring.modulus(),
            coefficient_bit_length,
            challenge_seed,
            u64::try_from(equation_index + 1).map_err(|_| {
                invalid_many_quadratic("many-quadratic challenge index does not fit in u64")
            })?,
        )?;
        let scaled_equation = equation.scale_by_polynomial(&challenge_polynomial)?;
        folded_equation = folded_equation.add(&scaled_equation)?;
        challenge_polynomials.push(challenge_polynomial);
    }

    Ok(ManyQuadraticFold {
        folded_equation,
        challenge_polynomials,
    })
}

#[cfg(test)]
pub(crate) fn validate_many_quadratic_self_check() -> CanonicalResult<()> {
    let proof_ring = linear_proof_tbox_proof_ring()?;
    let first_equation = LinearProofQuadraticEquation::zero(
        proof_ring,
        linear_proof_tbox_quadratic_many_dimension(),
    )?
    .add_linear_polynomial_term(0, constant_polynomial(proof_ring, 1))?;
    let second_equation = LinearProofQuadraticEquation::zero(
        proof_ring,
        linear_proof_tbox_quadratic_many_dimension(),
    )?
    .add_linear_polynomial_term(2, constant_polynomial(proof_ring, 5))?;
    let fold =
        fold_default_many_quadratic_equations(&[first_equation, second_equation], &[17_u8; 32])?;

    if fold.challenge_polynomials.len() != 2
        || fold.folded_equation.dimension() != linear_proof_tbox_quadratic_many_dimension()
        || fold.folded_equation.linear_terms().entries().len() != 2
    {
        return Err(invalid_many_quadratic(
            "many-quadratic folding self-check did not produce the expected shape",
        ));
    }
    let first_linear_entry = &fold.folded_equation.linear_terms().entries()[0];
    if first_linear_entry.position() != 0
        || first_linear_entry.coefficients() != fold.challenge_polynomials[0]
    {
        return Err(invalid_many_quadratic(
            "many-quadratic folding self-check did not use the first polyvec_urandom domain",
        ));
    }

    Ok(())
}

fn validate_linear_proof_hash_mask_vector(
    hash_mask_vector: &[Vec<u64>],
    proof_ring: PolynomialRing,
) -> CanonicalResult<()> {
    if hash_mask_vector.len() != TBOX_HASH_MASK_POLYNOMIALS {
        return Err(invalid_many_quadratic(
            "hash-mask vector length must match the demo tbox lambda halves",
        ));
    }
    for hash_mask_polynomial in hash_mask_vector {
        proof_ring.validate_coefficients(hash_mask_polynomial)?;
        // The fixed LaZer-style TBOX profile requires zero at the two
        // automorphism fixed positions used by the current degree-64 proof
        // ring. Generalizing the proof ring shape must revisit this invariant.
        if hash_mask_polynomial[0] != 0 || hash_mask_polynomial[proof_ring.degree() / 2] != 0 {
            return Err(invalid_many_quadratic(
                "hash-mask polynomial constant and half-degree coefficients must be zero",
            ));
        }
    }

    Ok(())
}

fn invalid_many_quadratic(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        build_many_quadratic_equations, fold_default_many_quadratic_equations,
        validate_many_quadratic_self_check,
    };
    use crate::ballot_privacy::{
        polynomial_ring::PolynomialRing,
        tbox_relations::{
            build_default_tbox_prefix_accumulators, linear_proof_tbox_proof_ring,
            linear_proof_tbox_quadratic_many_dimension,
        },
    };

    fn zero_hash_mask_vector() -> Vec<Vec<u64>> {
        let proof_ring = linear_proof_tbox_proof_ring().expect("proof ring should validate");
        vec![vec![0_u64; proof_ring.degree()]; 2]
    }

    #[test]
    fn tbox_equations_expand_to_many_quadratic_dimension_and_bind_hash_mask() {
        let accumulators = build_default_tbox_prefix_accumulators(&[9_u8; 32])
            .expect("prefix accumulators should validate");
        let mut hash_mask_vector = zero_hash_mask_vector();
        hash_mask_vector[0][1] = 7;

        let equations = build_many_quadratic_equations(&accumulators, &hash_mask_vector)
            .expect("many quadratic equations should build");

        assert_eq!(equations.len(), 4);
        assert!(
            equations.iter().all(
                |equation| equation.dimension() == linear_proof_tbox_quadratic_many_dimension()
            )
        );
        assert_eq!(
            equations[0]
                .linear_terms()
                .entries()
                .last()
                .expect("hash-mask linear link should exist")
                .position(),
            84
        );
        assert_eq!(
            equations[0].constant_term().expect("constant should exist")[1],
            equations[0].ring().modulus() - 7
        );
    }

    #[test]
    fn many_quadratic_folding_uses_polyvec_urandom_domains() {
        let accumulators = build_default_tbox_prefix_accumulators(&[11_u8; 32])
            .expect("prefix accumulators should validate");
        let equations = build_many_quadratic_equations(&accumulators, &zero_hash_mask_vector())
            .expect("many quadratic equations should build");

        let first_fold = fold_default_many_quadratic_equations(&equations, &[3_u8; 32])
            .expect("fold should validate");
        let repeated_fold = fold_default_many_quadratic_equations(&equations, &[3_u8; 32])
            .expect("fold should repeat");
        let changed_fold = fold_default_many_quadratic_equations(&equations, &[4_u8; 32])
            .expect("changed seed fold should validate");

        assert_eq!(first_fold, repeated_fold);
        assert_ne!(
            first_fold.challenge_polynomials,
            changed_fold.challenge_polynomials
        );
        assert_eq!(first_fold.challenge_polynomials.len(), equations.len());
        assert!(
            first_fold
                .challenge_polynomials
                .iter()
                .flatten()
                .all(|coefficient| *coefficient < equations[0].ring().modulus())
        );
    }

    #[test]
    fn many_quadratic_builder_rejects_malformed_hash_masks() {
        let accumulators = build_default_tbox_prefix_accumulators(&[9_u8; 32])
            .expect("prefix accumulators should validate");
        let proof_ring =
            PolynomialRing::new(64, 36_028_797_018_964_597).expect("proof ring should validate");
        let mut malformed_hash_mask = vec![vec![0_u64; proof_ring.degree()]; 2];
        malformed_hash_mask[1][proof_ring.degree() / 2] = 1;

        let error = build_many_quadratic_equations(&accumulators, &malformed_hash_mask)
            .expect_err("half-degree hash-mask coefficient should fail");

        assert!(error.message.contains("half-degree"));
    }

    #[test]
    fn many_quadratic_self_check_passes() {
        validate_many_quadratic_self_check().expect("self-check should pass");
    }
}
