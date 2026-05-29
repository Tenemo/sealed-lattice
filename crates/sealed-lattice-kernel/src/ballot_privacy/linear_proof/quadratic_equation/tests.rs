use super::{
    LinearProofQuadraticEquation, WeightedLinearProofQuadraticEquation,
    validate_quadratic_helper_self_check,
};
use crate::ballot_privacy::{
    polynomial_ring::PolynomialRing,
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
    sparse_polynomial_vector::{SparsePolynomialVector, SparsePolynomialVectorEntry},
};

fn sample_equation_pair() -> (LinearProofQuadraticEquation, LinearProofQuadraticEquation) {
    let ring = PolynomialRing::new(4, 17).expect("ring should validate");
    let first_quadratic_terms = SparsePolynomialMatrix::new(
        ring,
        4,
        4,
        vec![
            SparsePolynomialMatrixEntry::new(0, 0, vec![1, 2, 3, 4]),
            SparsePolynomialMatrixEntry::new(0, 1, vec![2, 0, 0, 0]),
            SparsePolynomialMatrixEntry::new(1, 3, vec![3, 0, 0, 0]),
        ],
    )
    .expect("first quadratic terms should validate");
    let first_linear_terms = SparsePolynomialVector::new(
        ring,
        4,
        vec![
            SparsePolynomialVectorEntry::new(0, vec![1, 1, 0, 0]),
            SparsePolynomialVectorEntry::new(3, vec![2, 0, 0, 0]),
        ],
    )
    .expect("first linear terms should validate");
    let first_equation = LinearProofQuadraticEquation::new(
        first_quadratic_terms,
        first_linear_terms,
        Some(vec![1, 2, 0, 0]),
    )
    .expect("first equation should validate");

    let second_quadratic_terms = SparsePolynomialMatrix::new(
        ring,
        4,
        4,
        vec![
            SparsePolynomialMatrixEntry::new(0, 2, vec![4, 0, 0, 0]),
            SparsePolynomialMatrixEntry::new(2, 2, vec![5, 0, 0, 0]),
        ],
    )
    .expect("second quadratic terms should validate");
    let second_linear_terms = SparsePolynomialVector::new(
        ring,
        4,
        vec![
            SparsePolynomialVectorEntry::new(1, vec![3, 0, 0, 0]),
            SparsePolynomialVectorEntry::new(2, vec![0, 4, 0, 0]),
        ],
    )
    .expect("second linear terms should validate");
    let second_equation = LinearProofQuadraticEquation::new(
        second_quadratic_terms,
        second_linear_terms,
        Some(vec![3, 0, 1, 0]),
    )
    .expect("second equation should validate");

    (first_equation, second_equation)
}

#[test]
fn schwartz_zippel_auto_fold_matches_linear_proof_formula_for_sparse_terms() {
    let (first_equation, second_equation) = sample_equation_pair();

    let folded_equation = first_equation
        .schwartz_zippel_auto_fold_with(&second_equation)
        .expect("auto fold should succeed");

    assert_eq!(folded_equation.quadratic_terms().entries().len(), 7);
    assert_eq!(
        folded_equation.quadratic_terms().entries()[0].row_index(),
        0
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[0].column_index(),
        0
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[0].coefficients(),
        &[9, 1, 10, 2]
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[3].row_index(),
        1
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[3].column_index(),
        1
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[3].coefficients(),
        &[9, 15, 7, 16]
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[6].row_index(),
        3
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[6].column_index(),
        3
    );
    assert_eq!(
        folded_equation.quadratic_terms().entries()[6].coefficients(),
        &[0, 0, 11, 0]
    );

    assert_eq!(folded_equation.linear_terms().entries().len(), 4);
    assert_eq!(folded_equation.linear_terms().entries()[0].position(), 0);
    assert_eq!(
        folded_equation.linear_terms().entries()[0].coefficients(),
        &[9, 9, 10, 0]
    );
    assert_eq!(folded_equation.linear_terms().entries()[3].position(), 3);
    assert_eq!(
        folded_equation.linear_terms().entries()[3].coefficients(),
        &[1, 2, 0, 0]
    );
    assert_eq!(
        folded_equation
            .constant_term()
            .expect("constant should exist"),
        &[1, 1, 3, 16]
    );
}

#[test]
fn schwartz_zippel_auto_fold_rejects_mismatched_constant_presence() {
    let (first_equation, mut second_equation) = sample_equation_pair();
    second_equation.constant_term = None;

    let error = first_equation
        .schwartz_zippel_auto_fold_with(&second_equation)
        .expect_err("mismatched constants should fail");

    assert!(error.message.contains("both be present"));
}

#[test]
fn weighted_accumulator_combines_sparse_equations_and_constants() {
    let (first_equation, second_equation) = sample_equation_pair();

    let accumulated_equation = first_equation
        .accumulate_weighted_equations(&[WeightedLinearProofQuadraticEquation {
            challenge_scalar: 3,
            equation: &second_equation,
        }])
        .expect("weighted accumulation should succeed");

    assert_eq!(accumulated_equation.quadratic_terms().entries().len(), 5);
    assert_eq!(
        accumulated_equation.quadratic_terms().entries()[2].row_index(),
        0
    );
    assert_eq!(
        accumulated_equation.quadratic_terms().entries()[2].column_index(),
        2
    );
    assert_eq!(
        accumulated_equation.quadratic_terms().entries()[2].coefficients(),
        &[12, 0, 0, 0]
    );
    assert_eq!(accumulated_equation.linear_terms().entries().len(), 4);
    assert_eq!(
        accumulated_equation.linear_terms().entries()[1].position(),
        1
    );
    assert_eq!(
        accumulated_equation.linear_terms().entries()[1].coefficients(),
        &[9, 0, 0, 0]
    );
    assert_eq!(
        accumulated_equation
            .constant_term()
            .expect("constant should exist"),
        &[10, 2, 3, 0]
    );
}

#[test]
fn weighted_partial_accumulator_can_skip_absent_constants() {
    let (first_equation, mut partial_equation) = sample_equation_pair();
    partial_equation.constant_term = None;

    let accumulated_equation = first_equation
        .accumulate_weighted_partial_equations(&[WeightedLinearProofQuadraticEquation {
            challenge_scalar: 3,
            equation: &partial_equation,
        }])
        .expect("partial accumulation should succeed");

    assert_eq!(accumulated_equation.quadratic_terms().entries().len(), 5);
    assert_eq!(accumulated_equation.linear_terms().entries().len(), 4);
    assert_eq!(
        accumulated_equation
            .constant_term()
            .expect("accumulator constant should remain present"),
        &[1, 2, 0, 0]
    );
}

#[test]
fn unweighted_accumulator_combines_sparse_equations_without_scaling() {
    let (first_equation, second_equation) = sample_equation_pair();

    let accumulated_equation = first_equation
        .accumulate_unweighted_equations(&[&second_equation])
        .expect("unweighted accumulation should succeed");

    assert_eq!(accumulated_equation.quadratic_terms().entries().len(), 5);
    assert_eq!(accumulated_equation.linear_terms().entries().len(), 4);
    assert_eq!(
        accumulated_equation
            .constant_term()
            .expect("constant should exist"),
        &[4, 2, 1, 0]
    );
}

#[test]
fn schwartz_zippel_pair_accumulation_samples_primary_and_secondary_challenges() {
    let (first_equation, second_equation) = sample_equation_pair();
    let ring = PolynomialRing::new(4, 17).expect("ring should validate");
    let primary_accumulator =
        LinearProofQuadraticEquation::zero(ring, 4).expect("primary zero should validate");
    let secondary_accumulator =
        LinearProofQuadraticEquation::zero(ring, 4).expect("secondary zero should validate");
    let challenge_seed = [9_u8; 32];

    let accumulator_pairs = LinearProofQuadraticEquation::accumulate_schwartz_zippel_pair_sets(
        std::slice::from_ref(&primary_accumulator),
        std::slice::from_ref(&secondary_accumulator),
        &[&first_equation, &second_equation],
        &challenge_seed,
        7,
        5,
    )
    .expect("pair accumulation should succeed");
    let repeated_pairs = LinearProofQuadraticEquation::accumulate_schwartz_zippel_pair_sets(
        std::slice::from_ref(&primary_accumulator),
        std::slice::from_ref(&secondary_accumulator),
        &[&first_equation, &second_equation],
        &challenge_seed,
        7,
        5,
    )
    .expect("pair accumulation should be deterministic");

    assert_eq!(accumulator_pairs, repeated_pairs);
    assert_eq!(accumulator_pairs.challenge_scalars_by_pair.len(), 1);
    assert_eq!(accumulator_pairs.challenge_scalars_by_pair[0].len(), 4);
    assert!(
        accumulator_pairs.challenge_scalars_by_pair[0]
            .iter()
            .all(|challenge_scalar| *challenge_scalar < 17)
    );

    let primary_manual = primary_accumulator
        .accumulate_weighted_equations(&[
            WeightedLinearProofQuadraticEquation {
                challenge_scalar: accumulator_pairs.challenge_scalars_by_pair[0][0],
                equation: &first_equation,
            },
            WeightedLinearProofQuadraticEquation {
                challenge_scalar: accumulator_pairs.challenge_scalars_by_pair[0][1],
                equation: &second_equation,
            },
        ])
        .expect("manual primary accumulation should succeed");
    let secondary_manual = secondary_accumulator
        .accumulate_weighted_equations(&[
            WeightedLinearProofQuadraticEquation {
                challenge_scalar: accumulator_pairs.challenge_scalars_by_pair[0][2],
                equation: &first_equation,
            },
            WeightedLinearProofQuadraticEquation {
                challenge_scalar: accumulator_pairs.challenge_scalars_by_pair[0][3],
                equation: &second_equation,
            },
        ])
        .expect("manual secondary accumulation should succeed");

    assert_eq!(accumulator_pairs.primary_accumulators[0], primary_manual);
    assert_eq!(
        accumulator_pairs.secondary_accumulators[0],
        secondary_manual
    );
    assert_ne!(
        accumulator_pairs.primary_accumulators[0],
        accumulator_pairs.secondary_accumulators[0]
    );
}

#[test]
fn schwartz_zippel_pair_accumulation_rejects_empty_input_equation_set() {
    let ring = PolynomialRing::new(4, 17).expect("ring should validate");
    let primary_accumulator =
        LinearProofQuadraticEquation::zero(ring, 4).expect("primary zero should validate");
    let secondary_accumulator =
        LinearProofQuadraticEquation::zero(ring, 4).expect("secondary zero should validate");

    let error = LinearProofQuadraticEquation::accumulate_schwartz_zippel_pair_sets(
        &[primary_accumulator],
        &[secondary_accumulator],
        &[],
        &[0_u8; 32],
        0,
        5,
    )
    .expect_err("empty equation list should fail");

    assert!(error.message.contains("at least one"));
}

#[test]
fn zero_quadratic_equation_has_expected_shape() {
    let ring = PolynomialRing::new(4, 17).expect("ring should validate");

    let equation =
        LinearProofQuadraticEquation::zero(ring, 4).expect("zero equation should validate");

    assert_eq!(equation.quadratic_terms().rows(), 4);
    assert!(equation.quadratic_terms().entries().is_empty());
    assert!(equation.linear_terms().entries().is_empty());
    assert_eq!(
        equation.constant_term().expect("constant should exist"),
        &[0, 0, 0, 0]
    );
}

#[test]
fn equation_resize_and_appended_linear_term_preserve_existing_terms() {
    let (first_equation, _) = sample_equation_pair();

    let resized = first_equation
        .resize_dimension(6)
        .expect("resize should expand equation");
    let updated = resized
        .add_linear_polynomial_term(5, vec![7, 0, 0, 0])
        .expect("linear term append should succeed");

    assert_eq!(updated.dimension(), 6);
    assert_eq!(updated.linear_terms().entries().len(), 3);
    assert_eq!(updated.linear_terms().entries()[2].position(), 5);
    assert_eq!(
        updated.linear_terms().entries()[2].coefficients(),
        &[7, 0, 0, 0]
    );
    assert!(
        first_equation
            .resize_dimension(3)
            .expect_err("shrinking should fail")
            .message
            .contains("cannot shrink")
    );
}

#[test]
fn constant_subtraction_and_polynomial_scaling_follow_ring_arithmetic() {
    let (first_equation, _) = sample_equation_pair();

    let shifted = first_equation
        .sub_constant_polynomial(&[1, 1, 0, 0])
        .expect("constant subtraction should succeed");
    let scaled = shifted
        .scale_by_polynomial(&[3, 4, 0, 0])
        .expect("polynomial scaling should succeed");

    assert_eq!(
        shifted.constant_term().expect("constant should exist"),
        &[0, 1, 0, 0]
    );
    assert_eq!(
        scaled.constant_term().expect("constant should exist"),
        &[0, 3, 4, 0]
    );
    assert_eq!(
        scaled.quadratic_terms().entries()[0].coefficients(),
        &[4, 10, 0, 7]
    );
}

#[test]
fn quadratic_helper_self_check_passes() {
    validate_quadratic_helper_self_check().expect("quadratic helper self-check should pass");
}
