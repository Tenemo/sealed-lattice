use super::integer_lift::{
    integer_lift_component_constraint_programs, integer_lift_component_product_expression,
    integer_lift_full_ring_product_constraint_programs,
};
use super::interpreter::signed_rotation_exponent;
use super::*;

const TEST_BASE_FIELD: u64 = 65_537;

fn check_context() -> RelationPlanCheckContext {
    RelationPlanCheckContext {
        base_field_modulus: TEST_BASE_FIELD,
        challenge_extension_degree: 4,
        evaluation_blowup_factor: 2,
        evaluation_domain_generator: 9,
        evaluation_coset_offset: 3,
        deep_point_count: 2,
        quotient_component_count: 4,
        quotient_component_degree_bound_exclusive: 8_200,
        fri_fold_count: 7,
        final_polynomial_degree_bound_exclusive: 256,
        unique_query_count: 16,
        non_native_theta_repetition_count: 2,
        non_native_alpha_repetition_count: 3,
        maximum_fiat_shamir_candidate_draws_per_output: 128,
        resolved_moduli: vec![
            ResolvedSuiteModulus::new(SuiteModulusReference::data(0), 97),
            ResolvedSuiteModulus::new(SuiteModulusReference::data(1), 193),
            ResolvedSuiteModulus::new(SuiteModulusReference::special(0), 241),
            ResolvedSuiteModulus::new(SuiteModulusReference::plaintext(), 257),
        ],
    }
}

fn committed_material_check_context() -> RelationPlanCheckContext {
    let evaluation_domain_size = 1_024_u64;
    let maximum_two_adic_order = 1_u64 << 32;
    let quotient_component_count = 16_u64;
    let unique_query_count = 1_u64;
    let deep_point_count = 1_u64;
    let relation_input = committed_material_input();
    let rounded_mask_degree = quotient_component_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(relation_input.trace_mask_degree_bound_exclusive))
        .and_then(|degree| degree.checked_add(quotient_component_count - 1))
        .and_then(|degree| degree.checked_div(quotient_component_count))
        .expect("test quotient mask degree derives");
    let quotient_decomposition_stride = relation_input
        .relation_trace_domain_size()
        .expect("test relation trace domain derives")
        .checked_add(rounded_mask_degree)
        .expect("test quotient decomposition stride derives");
    let minimum_telescoping_mask_degree_bound_exclusive = unique_query_count
        .checked_mul(2)
        .and_then(|query_coordinate_count| query_coordinate_count.checked_add(deep_point_count))
        .expect("test telescoping mask degree derives");
    RelationPlanCheckContext {
        base_field_modulus: crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
            as u16,
        evaluation_blowup_factor: 2,
        evaluation_domain_generator: modular_power(
            crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
            maximum_two_adic_order / evaluation_domain_size,
            crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
        ),
        evaluation_coset_offset: 7,
        deep_point_count: u16::try_from(deep_point_count).expect("test deep-point count fits"),
        quotient_component_count: u32::try_from(quotient_component_count)
            .expect("test quotient component count fits"),
        quotient_component_degree_bound_exclusive: quotient_decomposition_stride
            .checked_add(minimum_telescoping_mask_degree_bound_exclusive)
            .expect("test quotient component degree bound derives"),
        fri_fold_count: 6,
        final_polynomial_degree_bound_exclusive: 8,
        unique_query_count: u32::try_from(unique_query_count)
            .expect("test unique-query count fits"),
        non_native_theta_repetition_count: 1,
        non_native_alpha_repetition_count: 1,
        maximum_fiat_shamir_candidate_draws_per_output: 128,
        resolved_moduli: vec![ResolvedSuiteModulus::new(
            SuiteModulusReference::data(0),
            97,
        )],
    }
}

fn trace_zeroifier_check_context() -> RelationPlanCheckContext {
    let mut context = committed_material_check_context();
    context.evaluation_domain_generator = modular_power(
        crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
        (1_u64 << 32) / 256,
        crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
    );
    context
}

fn committed_material_input() -> CommittedMaterialRelationPlanInput {
    let ring_degree = 64_u64;
    CommittedMaterialRelationPlanInput {
        ring_degree,
        evaluation_domain_size: 1_024,
        opening_degree_bound_exclusive: 512,
        material_column_degree_bound_exclusive: 10,
        participant_count: 3,
        threshold: 2,
        sharing_data_modulus_indices: vec![0],
        trace_mask_degree_bound_exclusive: ring_degree / 2,
    }
}

fn bound_constraint(
    constraint_role: u16,
    numerator_postfix_expression: Vec<RelationExpressionInstruction>,
) -> RelationConstraintDescriptor {
    RelationConstraintDescriptor {
        constraint_role,
        role_coordinates: Vec::new(),
        numerator_postfix_expression,
        zeroifier_postfix_expression: full_trace_zeroifier_expression(16),
        enforce_proof_base_field_no_wrap: false,
        ordered_injective_integer_factor_expressions: Vec::new(),
    }
}

fn derive_test_interval(
    target_column_ordinal: u32,
    semantic_cells: &[SemanticCellDescriptor],
    constraints: &[RelationConstraintDescriptor],
) -> Result<SignedIntegerInterval, RelationPlanError> {
    let cells_by_column = semantic_cells
        .iter()
        .map(|cell| (cell.column_ordinal, cell))
        .collect::<BTreeMap<_, _>>();
    derive_semantic_cell_interval(
        target_column_ordinal,
        &cells_by_column,
        constraints,
        16,
        &check_context(),
        &mut BTreeMap::new(),
        &mut BTreeSet::new(),
    )
}

fn integer_power(mut base: BigInt, mut exponent: u64) -> BigInt {
    let mut result = BigInt::one();
    while exponent != 0 {
        if exponent & 1 == 1 {
            result *= &base;
        }
        base = &base * &base;
        exponent >>= 1;
    }
    result
}

fn evaluate_integer_lift_test_expression(
    expression: &[RelationExpressionInstruction],
    row_ordinal: usize,
    trace_domain_size: usize,
    theta: &BigInt,
    columns: &BTreeMap<u32, Vec<BigInt>>,
) -> BigInt {
    let mut stack = Vec::<BigInt>::new();
    for instruction in expression {
        match instruction {
            RelationExpressionInstruction::BaseFieldConstant(value) => {
                stack.push(BigInt::from(*value));
            }
            RelationExpressionInstruction::ColumnValue {
                column_ordinal,
                rotation_is_negative,
                rotation_magnitude,
            } => {
                let signed_rotation = signed_rotation_exponent(
                    *rotation_is_negative,
                    *rotation_magnitude,
                    u64::try_from(trace_domain_size).expect("test trace size fits u64"),
                )
                .expect("valid test rotation");
                let rotated_row = (row_ordinal
                    + usize::try_from(signed_rotation).expect("test rotation fits usize"))
                    % trace_domain_size;
                stack.push(
                    columns[column_ordinal]
                        .get(rotated_row)
                        .expect("test column covers the trace")
                        .clone(),
                );
            }
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role: RelationChallengeRole::NonNativeTheta,
                ..
            } => stack.push(theta.clone()),
            RelationExpressionInstruction::NonnegativePower(exponent) => {
                let base = stack.pop().expect("power has one operand");
                stack.push(integer_power(base, *exponent));
            }
            RelationExpressionInstruction::Addition => {
                let right = stack.pop().expect("addition has a right operand");
                let left = stack.pop().expect("addition has a left operand");
                stack.push(left + right);
            }
            RelationExpressionInstruction::Multiplication => {
                let right = stack.pop().expect("multiplication has a right operand");
                let left = stack.pop().expect("multiplication has a left operand");
                stack.push(left * right);
            }
            RelationExpressionInstruction::Negation => {
                let value = stack.pop().expect("negation has one operand");
                stack.push(-value);
            }
            _ => panic!("unexpected instruction in an integer-lift test expression"),
        }
    }
    assert_eq!(stack.len(), 1);
    stack.pop().expect("one expression result")
}

fn suffix_evaluations(values: &[BigInt], theta: &BigInt) -> Vec<BigInt> {
    let mut suffixes = vec![BigInt::zero(); values.len()];
    let last = values.len() - 1;
    suffixes[last] = values[last].clone();
    for row_ordinal in (0..last).rev() {
        suffixes[row_ordinal] = &values[row_ordinal] + theta * &suffixes[row_ordinal + 1];
    }
    suffixes
}

#[test]
fn trace_subgroup_zeroifier_grammar_accepts_exact_subgroups_and_rejects_other_roots() {
    let context = trace_zeroifier_check_context();
    let trace_domain_size = 16;
    let evaluation_domain_size = 256;
    let trace_generator = modular_power(
        context.evaluation_domain_generator,
        evaluation_domain_size / trace_domain_size,
        context.base_field_modulus,
    );
    let trace_root = modular_power(trace_generator, 5, context.base_field_modulus);

    assert!(zeroifier_roots_are_confined_to_trace_domain(
        &full_trace_zeroifier_expression(trace_domain_size),
        trace_domain_size,
        context.base_field_modulus,
    ));
    assert!(zeroifier_roots_are_confined_to_trace_domain(
        &[
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::BaseFieldConstant(trace_root),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ],
        trace_domain_size,
        context.base_field_modulus,
    ));
    let mut excluded_roots = vec![1, trace_root];
    excluded_roots.sort_unstable();
    assert!(zeroifier_roots_are_confined_to_trace_domain(
        &[RelationExpressionInstruction::TraceDomainExceptRoots {
            trace_domain_size,
            ordered_excluded_roots: excluded_roots,
        }],
        trace_domain_size,
        context.base_field_modulus,
    ));

    assert!(zeroifier_roots_are_confined_to_trace_domain(
        &full_trace_zeroifier_expression(trace_domain_size / 2),
        trace_domain_size,
        context.base_field_modulus,
    ));
    assert!(zeroifier_roots_are_confined_to_trace_domain(
        &full_trace_zeroifier_expression(trace_domain_size / 4),
        trace_domain_size,
        context.base_field_modulus,
    ));
    assert!(!zeroifier_roots_are_confined_to_trace_domain(
        &full_trace_zeroifier_expression(3),
        trace_domain_size,
        context.base_field_modulus,
    ));
    assert!(!zeroifier_roots_are_confined_to_trace_domain(
        &full_trace_zeroifier_expression(0),
        trace_domain_size,
        context.base_field_modulus,
    ));
    let non_trace_root = (2..context.base_field_modulus)
        .find(|candidate| {
            modular_power(*candidate, trace_domain_size, context.base_field_modulus) != 1
        })
        .expect("the base field contains an element outside the trace subgroup");
    assert!(!zeroifier_roots_are_confined_to_trace_domain(
        &[
            RelationExpressionInstruction::EvaluationVariable,
            RelationExpressionInstruction::BaseFieldConstant(non_trace_root),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ],
        trace_domain_size,
        context.base_field_modulus,
    ));
}

#[test]
fn trace_zeroifier_fast_path_refuses_a_colliding_coset() {
    let mut context = trace_zeroifier_check_context();
    context.evaluation_coset_offset = 1;
    let checker = RelationPlanChecker::new(&context);
    assert_eq!(
        checker.check_zeroifier_on_coset(&full_trace_zeroifier_expression(16), 16, 256),
        Err(RelationPlanError::ZeroifierVanishesOnEvaluationCoset),
    );
    assert_eq!(
        checker.check_zeroifier_on_coset(&full_trace_zeroifier_expression(8), 16, 256),
        Err(RelationPlanError::ZeroifierVanishesOnEvaluationCoset),
    );
}

#[test]
fn trace_subgroup_zeroifier_uses_the_exact_large_coset_fast_path() {
    let mut context = trace_zeroifier_check_context();
    let trace_domain_size = 1_u64 << 17;
    let subgroup_size = trace_domain_size / 8;
    let evaluation_domain_size = 1_u64 << 19;
    context.evaluation_domain_generator = modular_power(
        crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
        (1_u64 << 32) / evaluation_domain_size,
        context.base_field_modulus,
    );

    assert_eq!(
        RelationPlanChecker::new(&context).check_zeroifier_on_coset(
            &full_trace_zeroifier_expression(subgroup_size),
            trace_domain_size,
            evaluation_domain_size,
        ),
        Ok(()),
    );
}

#[test]
fn oversized_arbitrary_zeroifier_fails_closed() {
    let mut context = trace_zeroifier_check_context();
    let evaluation_domain_size = MAXIMUM_EXHAUSTIVE_ZEROIFIER_COSET_CHECK_DOMAIN_SIZE * 2;
    context.evaluation_domain_generator = modular_power(
        crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
        (1_u64 << 32) / evaluation_domain_size,
        context.base_field_modulus,
    );
    let non_trace_root = (2..context.base_field_modulus)
        .find(|candidate| modular_power(*candidate, 16, context.base_field_modulus) != 1)
        .expect("the base field contains an element outside the trace subgroup");
    let arbitrary_zeroifier = [
        RelationExpressionInstruction::EvaluationVariable,
        RelationExpressionInstruction::BaseFieldConstant(non_trace_root),
        RelationExpressionInstruction::Negation,
        RelationExpressionInstruction::Addition,
    ];

    assert_eq!(
        RelationPlanChecker::new(&context).check_zeroifier_on_coset(
            &arbitrary_zeroifier,
            16,
            evaluation_domain_size,
        ),
        Err(RelationPlanError::InvalidZeroifier),
    );
}

fn dense_negacyclic_product(left: &[BigInt], right: &[BigInt]) -> Vec<BigInt> {
    assert_eq!(left.len(), right.len());
    let ring_degree = left.len();
    let mut product = vec![BigInt::zero(); ring_degree];
    for (left_ordinal, left_value) in left.iter().enumerate() {
        for (right_ordinal, right_value) in right.iter().enumerate() {
            let unwrapped_ordinal = left_ordinal + right_ordinal;
            let coefficient_ordinal = unwrapped_ordinal % ring_degree;
            let term = left_value * right_value;
            if unwrapped_ordinal >= ring_degree {
                product[coefficient_ordinal] -= term;
            } else {
                product[coefficient_ordinal] += term;
            }
        }
    }
    product
}

fn evaluate_dense_polynomial(coefficients: &[BigInt], point: &BigInt) -> BigInt {
    coefficients.iter().enumerate().fold(
        BigInt::zero(),
        |evaluation, (coefficient_ordinal, coefficient)| {
            evaluation
                + coefficient
                    * integer_power(
                        point.clone(),
                        u64::try_from(coefficient_ordinal)
                            .expect("test coefficient ordinal fits u64"),
                    )
        },
    )
}

fn selected_full_ring_half(
    coefficients: &[BigInt],
    selected_half: RelationIntegerLiftFullRingHalf,
) -> Vec<BigInt> {
    let half_ring_degree = coefficients.len() / 2;
    let start = match selected_half {
        RelationIntegerLiftFullRingHalf::Low => 0,
        RelationIntegerLiftFullRingHalf::High => half_ring_degree,
    };
    coefficients[start..start + half_ring_degree].to_vec()
}

fn dense_oracle_transpose_rows(
    multiplicand: &[BigInt],
    selected_product_half: RelationIntegerLiftFullRingHalf,
    multiplier_half: RelationIntegerLiftFullRingHalf,
    point: &BigInt,
) -> Vec<BigInt> {
    let ring_degree = multiplicand.len();
    let half_ring_degree = ring_degree / 2;
    let multiplier_half_start = match multiplier_half {
        RelationIntegerLiftFullRingHalf::Low => 0,
        RelationIntegerLiftFullRingHalf::High => half_ring_degree,
    };
    (0..half_ring_degree)
        .map(|reversed_row_ordinal| {
            let multiplier_coefficient_ordinal =
                multiplier_half_start + (half_ring_degree - 1 - reversed_row_ordinal);
            let mut multiplier_basis = vec![BigInt::zero(); ring_degree];
            multiplier_basis[multiplier_coefficient_ordinal] = BigInt::one();
            let basis_product = dense_negacyclic_product(multiplicand, &multiplier_basis);
            evaluate_dense_polynomial(
                &selected_full_ring_half(&basis_product, selected_product_half),
                point,
            )
        })
        .collect()
}

const ORACLE_MULTIPLICAND_LOW_COLUMN: u32 = 0;
const ORACLE_MULTIPLICAND_HIGH_COLUMN: u32 = 1;
const ORACLE_MULTIPLIER_LOW_COLUMN: u32 = 2;
const ORACLE_MULTIPLIER_HIGH_COLUMN: u32 = 3;
const ORACLE_REVERSED_MULTIPLIER_LOW_COLUMN: u32 = 4;
const ORACLE_REVERSED_MULTIPLIER_HIGH_COLUMN: u32 = 5;
const ORACLE_MULTIPLICAND_LOW_SUFFIX_COLUMN: u32 = 6;
const ORACLE_MULTIPLICAND_HIGH_SUFFIX_COLUMN: u32 = 7;
const ORACLE_REVERSED_MULTIPLIER_LOW_TRANSPOSE_COLUMN: u32 = 8;
const ORACLE_REVERSED_MULTIPLIER_HIGH_TRANSPOSE_COLUMN: u32 = 9;
const ORACLE_LINEAR_SOURCE_COLUMN: u32 = 10;
const ORACLE_LINEAR_EVALUATION_COLUMN: u32 = 11;
const ORACLE_PRODUCT_ACCUMULATOR_COLUMN: u32 = 12;

struct FullRingIntegerLiftOracleFixture {
    component: RelationIntegerLiftComponentDescriptor,
    columns: BTreeMap<u32, Vec<BigInt>>,
    expected_product_expression_rows: Vec<BigInt>,
    expected_signed_product_half: Vec<BigInt>,
}

fn full_ring_integer_lift_oracle_fixture(
    multiplicand: &[BigInt],
    multiplier: &[BigInt],
    selected_product_half: RelationIntegerLiftFullRingHalf,
    product_is_negative: bool,
    multiplier_low_offset: u64,
    multiplier_high_offset: u64,
    point: &BigInt,
) -> FullRingIntegerLiftOracleFixture {
    assert_eq!(multiplicand.len(), multiplier.len());
    assert_eq!(multiplicand.len(), 4);
    let half_ring_degree = multiplicand.len() / 2;
    let multiplicand_low = multiplicand[..half_ring_degree].to_vec();
    let multiplicand_high = multiplicand[half_ring_degree..].to_vec();
    let multiplier_low = multiplier[..half_ring_degree].to_vec();
    let multiplier_high = multiplier[half_ring_degree..].to_vec();
    let encoded_multiplier_low = multiplier_low
        .iter()
        .map(|coefficient| coefficient + BigInt::from(multiplier_low_offset))
        .collect::<Vec<_>>();
    let encoded_multiplier_high = multiplier_high
        .iter()
        .map(|coefficient| coefficient + BigInt::from(multiplier_high_offset))
        .collect::<Vec<_>>();
    let reversed_multiplier_low = encoded_multiplier_low
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    let reversed_multiplier_high = encoded_multiplier_high
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    let low_multiplier_transpose = dense_oracle_transpose_rows(
        multiplicand,
        selected_product_half,
        RelationIntegerLiftFullRingHalf::Low,
        point,
    );
    let high_multiplier_transpose = dense_oracle_transpose_rows(
        multiplicand,
        selected_product_half,
        RelationIntegerLiftFullRingHalf::High,
        point,
    );

    let dense_product = dense_negacyclic_product(multiplicand, multiplier);
    let mut expected_signed_product_half =
        selected_full_ring_half(&dense_product, selected_product_half);
    if product_is_negative {
        for coefficient in &mut expected_signed_product_half {
            *coefficient = -coefficient.clone();
        }
    }
    let linear_source = expected_signed_product_half
        .iter()
        .map(|coefficient| -coefficient)
        .collect::<Vec<_>>();
    let linear_evaluation = suffix_evaluations(&linear_source, point);

    let product_sign = if product_is_negative {
        -BigInt::one()
    } else {
        BigInt::one()
    };
    let expected_product_expression_rows = (0..half_ring_degree)
        .map(|row_ordinal| {
            let low_multiplier =
                &reversed_multiplier_low[row_ordinal] - BigInt::from(multiplier_low_offset);
            let high_multiplier =
                &reversed_multiplier_high[row_ordinal] - BigInt::from(multiplier_high_offset);
            &product_sign
                * (&low_multiplier_transpose[row_ordinal] * low_multiplier
                    + &high_multiplier_transpose[row_ordinal] * high_multiplier)
        })
        .collect::<Vec<_>>();
    let mut product_accumulator = vec![BigInt::zero(); half_ring_degree];
    for row_ordinal in 0..half_ring_degree - 1 {
        product_accumulator[row_ordinal + 1] =
            &product_accumulator[row_ordinal] + &expected_product_expression_rows[row_ordinal];
    }

    let product_descriptor = RelationIntegerLiftFullRingNegacyclicProductDescriptor {
        negative: product_is_negative,
        selected_half: selected_product_half,
        multiplicand_low_column_ordinal: ORACLE_MULTIPLICAND_LOW_COLUMN,
        multiplicand_high_column_ordinal: ORACLE_MULTIPLICAND_HIGH_COLUMN,
        multiplier_low_column_ordinal: ORACLE_MULTIPLIER_LOW_COLUMN,
        multiplier_high_column_ordinal: ORACLE_MULTIPLIER_HIGH_COLUMN,
        reversed_multiplier_low_column_ordinal: ORACLE_REVERSED_MULTIPLIER_LOW_COLUMN,
        reversed_multiplier_high_column_ordinal: ORACLE_REVERSED_MULTIPLIER_HIGH_COLUMN,
        multiplier_low_offset,
        multiplier_high_offset,
        multiplicand_low_suffix_evaluation_column_ordinal: ORACLE_MULTIPLICAND_LOW_SUFFIX_COLUMN,
        multiplicand_high_suffix_evaluation_column_ordinal: ORACLE_MULTIPLICAND_HIGH_SUFFIX_COLUMN,
        reversed_multiplier_low_transpose_column_ordinal:
            ORACLE_REVERSED_MULTIPLIER_LOW_TRANSPOSE_COLUMN,
        reversed_multiplier_high_transpose_column_ordinal:
            ORACLE_REVERSED_MULTIPLIER_HIGH_TRANSPOSE_COLUMN,
    };
    let component = RelationIntegerLiftComponentDescriptor {
        ordered_linear_terms: vec![RelationIntegerLiftLinearTermDescriptor {
            negative: false,
            column_ordinal: ORACLE_LINEAR_SOURCE_COLUMN,
            column_offset: 0,
            coefficient: RelationIntegerLiftCoefficient::Constant(1),
        }],
        ordered_convolution_products: Vec::new(),
        ordered_full_ring_negacyclic_products: vec![product_descriptor],
        linear_evaluation_column_ordinal: ORACLE_LINEAR_EVALUATION_COLUMN,
        product_accumulator_column_ordinal: ORACLE_PRODUCT_ACCUMULATOR_COLUMN,
    };
    let columns = BTreeMap::from([
        (ORACLE_MULTIPLICAND_LOW_COLUMN, multiplicand_low.clone()),
        (ORACLE_MULTIPLICAND_HIGH_COLUMN, multiplicand_high.clone()),
        (ORACLE_MULTIPLIER_LOW_COLUMN, encoded_multiplier_low),
        (ORACLE_MULTIPLIER_HIGH_COLUMN, encoded_multiplier_high),
        (
            ORACLE_REVERSED_MULTIPLIER_LOW_COLUMN,
            reversed_multiplier_low,
        ),
        (
            ORACLE_REVERSED_MULTIPLIER_HIGH_COLUMN,
            reversed_multiplier_high,
        ),
        (
            ORACLE_MULTIPLICAND_LOW_SUFFIX_COLUMN,
            suffix_evaluations(&multiplicand_low, point),
        ),
        (
            ORACLE_MULTIPLICAND_HIGH_SUFFIX_COLUMN,
            suffix_evaluations(&multiplicand_high, point),
        ),
        (
            ORACLE_REVERSED_MULTIPLIER_LOW_TRANSPOSE_COLUMN,
            low_multiplier_transpose,
        ),
        (
            ORACLE_REVERSED_MULTIPLIER_HIGH_TRANSPOSE_COLUMN,
            high_multiplier_transpose,
        ),
        (ORACLE_LINEAR_SOURCE_COLUMN, linear_source),
        (ORACLE_LINEAR_EVALUATION_COLUMN, linear_evaluation),
        (ORACLE_PRODUCT_ACCUMULATOR_COLUMN, product_accumulator),
    ]);
    FullRingIntegerLiftOracleFixture {
        component,
        columns,
        expected_product_expression_rows,
        expected_signed_product_half,
    }
}

fn assert_full_ring_integer_lift_fixture_satisfies_compiled_identities(
    fixture: &FullRingIntegerLiftOracleFixture,
    point: &BigInt,
    case_description: &str,
) {
    let trace_domain_size = fixture.expected_signed_product_half.len();
    let theta_expression = vec![RelationExpressionInstruction::TranscriptChallenge {
        challenge_role: RelationChallengeRole::NonNativeTheta,
        role_coordinates: vec![0, 0],
    }];
    let product_descriptor = &fixture.component.ordered_full_ring_negacyclic_products[0];
    let product_programs = integer_lift_full_ring_product_constraint_programs(
        product_descriptor,
        &theta_expression,
        u64::try_from(trace_domain_size).expect("test half-ring degree fits u64"),
        Vec::new(),
        Vec::new(),
    )
    .expect("full-ring product constraint programs");
    for program_pair_ordinal in 0..4 {
        assert_eq!(
            evaluate_integer_lift_test_expression(
                &product_programs[program_pair_ordinal * 2].numerator_postfix_expression,
                trace_domain_size - 1,
                trace_domain_size,
                point,
                &fixture.columns,
            ),
            BigInt::zero(),
            "full-ring boundary identity failed for {case_description}, program pair {program_pair_ordinal}",
        );
        for row_ordinal in 0..trace_domain_size - 1 {
            assert_eq!(
                evaluate_integer_lift_test_expression(
                    &product_programs[program_pair_ordinal * 2 + 1].numerator_postfix_expression,
                    row_ordinal,
                    trace_domain_size,
                    point,
                    &fixture.columns,
                ),
                BigInt::zero(),
                "full-ring recurrence identity failed for {case_description}, program pair {program_pair_ordinal}, row {row_ordinal}",
            );
        }
    }

    let product_expression = integer_lift_component_product_expression(&fixture.component)
        .expect("component product expression");
    let interpreted_product_rows = (0..trace_domain_size)
        .map(|row_ordinal| {
            evaluate_integer_lift_test_expression(
                &product_expression,
                row_ordinal,
                trace_domain_size,
                point,
                &fixture.columns,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        interpreted_product_rows, fixture.expected_product_expression_rows,
        "compiled product expression diverged from the dense oracle for {case_description}",
    );
    assert_eq!(
        interpreted_product_rows.iter().sum::<BigInt>(),
        evaluate_dense_polynomial(&fixture.expected_signed_product_half, point),
        "compiled product evaluation diverged from the dense oracle for {case_description}",
    );

    let component_programs = integer_lift_component_constraint_programs(
        &fixture.component,
        SuiteModulusReference::data(0),
        &theta_expression,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        &check_context(),
    )
    .expect("integer-lift component constraint programs");
    for (program_ordinal, enforced_rows) in [
        (0, vec![trace_domain_size - 1]),
        (1, (0..trace_domain_size - 1).collect()),
        (2, vec![0]),
        (3, (0..trace_domain_size - 1).collect()),
        (4, vec![trace_domain_size - 1]),
    ] {
        for row_ordinal in enforced_rows {
            assert_eq!(
                evaluate_integer_lift_test_expression(
                    &component_programs[program_ordinal].numerator_postfix_expression,
                    row_ordinal,
                    trace_domain_size,
                    point,
                    &fixture.columns,
                ),
                BigInt::zero(),
                "integer-lift component identity failed for {case_description}, program {program_ordinal}, row {row_ordinal}",
            );
        }
    }
}

#[test]
fn full_ring_integer_lift_matches_an_exhaustive_degree_four_oracle() {
    let point = BigInt::from(11_u8);
    for multiplicand_ordinal in 0..4 {
        for multiplicand_sign in [-1_i8, 1] {
            let mut multiplicand = vec![BigInt::zero(); 4];
            multiplicand[multiplicand_ordinal] = BigInt::from(multiplicand_sign);
            for multiplier_ordinal in 0..4 {
                for multiplier_sign in [-1_i8, 1] {
                    let mut multiplier = vec![BigInt::zero(); 4];
                    multiplier[multiplier_ordinal] = BigInt::from(multiplier_sign);
                    for selected_product_half in [
                        RelationIntegerLiftFullRingHalf::Low,
                        RelationIntegerLiftFullRingHalf::High,
                    ] {
                        for product_is_negative in [false, true] {
                            for (multiplier_low_offset, multiplier_high_offset) in
                                [(0_u64, 0_u64), (3, 5)]
                            {
                                let case_description = format!(
                                    "multiplicand={multiplicand_sign}*X^{multiplicand_ordinal}, multiplier={multiplier_sign}*X^{multiplier_ordinal}, selected_half={selected_product_half:?}, product_is_negative={product_is_negative}, offsets=({multiplier_low_offset},{multiplier_high_offset})"
                                );
                                let fixture = full_ring_integer_lift_oracle_fixture(
                                    &multiplicand,
                                    &multiplier,
                                    selected_product_half,
                                    product_is_negative,
                                    multiplier_low_offset,
                                    multiplier_high_offset,
                                    &point,
                                );
                                assert_full_ring_integer_lift_fixture_satisfies_compiled_identities(
                                    &fixture,
                                    &point,
                                    &case_description,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn full_ring_integer_lift_rejects_a_locally_valid_detached_product_component() {
    let point = BigInt::from(11_u8);
    let shared_secret = [1, 0, 0, 0].map(BigInt::from);
    let detached_secret = [0, -1, 0, 0].map(BigInt::from);
    let multiplier = [0, 0, 1, 0].map(BigInt::from);
    let shared_fixture = full_ring_integer_lift_oracle_fixture(
        &shared_secret,
        &multiplier,
        RelationIntegerLiftFullRingHalf::High,
        false,
        3,
        5,
        &point,
    );
    let mut detached_fixture = full_ring_integer_lift_oracle_fixture(
        &detached_secret,
        &multiplier,
        RelationIntegerLiftFullRingHalf::High,
        false,
        3,
        5,
        &point,
    );
    assert_full_ring_integer_lift_fixture_satisfies_compiled_identities(
        &shared_fixture,
        &point,
        "honest shared-secret component",
    );
    assert_full_ring_integer_lift_fixture_satisfies_compiled_identities(
        &detached_fixture,
        &point,
        "locally valid detached component",
    );

    detached_fixture.columns.insert(
        ORACLE_MULTIPLICAND_LOW_COLUMN,
        shared_fixture.columns[&ORACLE_MULTIPLICAND_LOW_COLUMN].clone(),
    );
    detached_fixture.columns.insert(
        ORACLE_MULTIPLICAND_HIGH_COLUMN,
        shared_fixture.columns[&ORACLE_MULTIPLICAND_HIGH_COLUMN].clone(),
    );
    let theta_expression = vec![RelationExpressionInstruction::TranscriptChallenge {
        challenge_role: RelationChallengeRole::NonNativeTheta,
        role_coordinates: vec![0, 0],
    }];
    let product_programs = integer_lift_full_ring_product_constraint_programs(
        &detached_fixture
            .component
            .ordered_full_ring_negacyclic_products[0],
        &theta_expression,
        2,
        Vec::new(),
        Vec::new(),
    )
    .expect("full-ring product constraint programs");
    let component_programs = integer_lift_component_constraint_programs(
        &detached_fixture.component,
        SuiteModulusReference::data(0),
        &theta_expression,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        &check_context(),
    )
    .expect("integer-lift component constraint programs");
    for (program_ordinal, row_ordinal) in [(0, 1), (1, 0), (2, 0), (3, 0), (4, 1)] {
        assert_eq!(
            evaluate_integer_lift_test_expression(
                &component_programs[program_ordinal].numerator_postfix_expression,
                row_ordinal,
                2,
                &point,
                &detached_fixture.columns,
            ),
            BigInt::zero(),
            "the detached product remains locally valid before its shared multiplicand binding is enforced",
        );
    }
    let hostile_residuals = product_programs
        .iter()
        .enumerate()
        .map(|(program_ordinal, program)| {
            let row_ordinal = if program_ordinal % 2 == 0 { 1 } else { 0 };
            evaluate_integer_lift_test_expression(
                &program.numerator_postfix_expression,
                row_ordinal,
                2,
                &point,
                &detached_fixture.columns,
            )
        })
        .collect::<Vec<_>>();
    assert!(
        hostile_residuals.iter().any(|residual| !residual.is_zero()),
        "the full-ring identities must bind a locally valid component back to the shared same-secret columns",
    );
}

#[test]
fn production_target_share_negacyclic_product_exceeds_the_exact_no_wrap_bound() {
    let target_modulus = crate::bgv::parameters::DATA_PRIMES[0];
    let canonical_residue_interval =
        SignedIntegerInterval::from_bigints(BigInt::zero(), BigInt::from(target_modulus - 1))
            .expect("the production target modulus defines a valid residue interval");
    let maximum_coefficient_product = integer_lift_maximum_absolute_product(
        &canonical_residue_interval,
        &canonical_residue_interval,
    )
    .expect("the production coefficient product bound fits the exact interval model");
    let full_ring_convolution_bound = BigInt::from(maximum_coefficient_product)
        * BigInt::from(crate::bgv::parameters::POLYNOMIAL_DEGREE);
    let exact_product_interval = SignedIntegerInterval::from_bigints(
        -full_ring_convolution_bound.clone(),
        full_ring_convolution_bound.clone(),
    )
    .expect("the production negacyclic product has a valid exact interval");
    let proof_base_field_modulus = BigInt::from(crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS);

    assert!(
        full_ring_convolution_bound.bits() > proof_base_field_modulus.bits(),
        "the exact full-ring product must not inject into the proof base field before the modular quotient is applied"
    );
    assert!(!exact_product_interval.is_injective_modulo(&proof_base_field_modulus));
}

#[test]
fn full_ring_high_half_low_multiplier_transpose_is_exact_for_dense_small_rings() {
    const MULTIPLICAND_LOW: u32 = 0;
    const MULTIPLICAND_HIGH: u32 = 1;
    const MULTIPLICAND_LOW_SUFFIX: u32 = 6;
    const MULTIPLICAND_HIGH_SUFFIX: u32 = 7;
    const LOW_MULTIPLIER_TRANSPOSE: u32 = 8;
    let theta_expression = vec![RelationExpressionInstruction::TranscriptChallenge {
        challenge_role: RelationChallengeRole::NonNativeTheta,
        role_coordinates: vec![0, 0],
    }];

    for ring_degree in [4_usize, 8] {
        let half_ring_degree = ring_degree / 2;
        let theta = BigInt::from(11_u8);
        let multiplicand_low = (0..half_ring_degree)
            .map(|ordinal| BigInt::from(3 * ordinal + 2))
            .collect::<Vec<_>>();
        let multiplicand_high = (0..half_ring_degree)
            .map(|ordinal| BigInt::from(5 * ordinal + 7))
            .collect::<Vec<_>>();
        let multiplier_low = (0..half_ring_degree)
            .map(|ordinal| BigInt::from(7 * ordinal + 3))
            .collect::<Vec<_>>();
        let low_suffix = suffix_evaluations(&multiplicand_low, &theta);
        let high_suffix = suffix_evaluations(&multiplicand_high, &theta);

        let theta_to_half = integer_power(
            theta.clone(),
            u64::try_from(half_ring_degree).expect("half degree fits u64"),
        );
        let mut low_multiplier_transpose = vec![BigInt::zero(); half_ring_degree];
        low_multiplier_transpose[half_ring_degree - 1] = high_suffix[0].clone();
        for row_ordinal in (0..half_ring_degree - 1).rev() {
            low_multiplier_transpose[row_ordinal] = &theta
                * &low_multiplier_transpose[row_ordinal + 1]
                + &multiplicand_low[row_ordinal + 1]
                - &theta_to_half * &multiplicand_high[row_ordinal + 1];
        }

        let descriptor = RelationIntegerLiftFullRingNegacyclicProductDescriptor {
            negative: false,
            selected_half: RelationIntegerLiftFullRingHalf::High,
            multiplicand_low_column_ordinal: MULTIPLICAND_LOW,
            multiplicand_high_column_ordinal: MULTIPLICAND_HIGH,
            multiplier_low_column_ordinal: 2,
            multiplier_high_column_ordinal: 3,
            reversed_multiplier_low_column_ordinal: 4,
            reversed_multiplier_high_column_ordinal: 5,
            multiplier_low_offset: 0,
            multiplier_high_offset: 0,
            multiplicand_low_suffix_evaluation_column_ordinal: MULTIPLICAND_LOW_SUFFIX,
            multiplicand_high_suffix_evaluation_column_ordinal: MULTIPLICAND_HIGH_SUFFIX,
            reversed_multiplier_low_transpose_column_ordinal: LOW_MULTIPLIER_TRANSPOSE,
            reversed_multiplier_high_transpose_column_ordinal: 9,
        };
        let programs = integer_lift_full_ring_product_constraint_programs(
            &descriptor,
            &theta_expression,
            u64::try_from(half_ring_degree).expect("half degree fits u64"),
            Vec::new(),
            Vec::new(),
        )
        .expect("full-ring product constraint programs");
        let columns = BTreeMap::from([
            (MULTIPLICAND_LOW, multiplicand_low.clone()),
            (MULTIPLICAND_HIGH, multiplicand_high.clone()),
            (MULTIPLICAND_LOW_SUFFIX, low_suffix),
            (MULTIPLICAND_HIGH_SUFFIX, high_suffix),
            (LOW_MULTIPLIER_TRANSPOSE, low_multiplier_transpose.clone()),
        ]);
        assert_eq!(
            evaluate_integer_lift_test_expression(
                &programs[4].numerator_postfix_expression,
                half_ring_degree - 1,
                half_ring_degree,
                &theta,
                &columns,
            ),
            BigInt::zero(),
        );
        for row_ordinal in 0..half_ring_degree - 1 {
            assert_eq!(
                evaluate_integer_lift_test_expression(
                    &programs[5].numerator_postfix_expression,
                    row_ordinal,
                    half_ring_degree,
                    &theta,
                    &columns,
                ),
                BigInt::zero(),
            );
        }

        let mut full_multiplicand = multiplicand_low;
        full_multiplicand.extend(multiplicand_high);
        let mut full_multiplier = multiplier_low.clone();
        full_multiplier.extend(vec![BigInt::zero(); half_ring_degree]);
        let direct_product = dense_negacyclic_product(&full_multiplicand, &full_multiplier);
        let direct_high_evaluation = direct_product[half_ring_degree..].iter().enumerate().fold(
            BigInt::zero(),
            |sum, (ordinal, coefficient)| {
                sum + coefficient
                    * integer_power(
                        theta.clone(),
                        u64::try_from(ordinal).expect("coefficient ordinal fits u64"),
                    )
            },
        );
        let transpose_evaluation = low_multiplier_transpose
            .iter()
            .zip(multiplier_low.iter().rev())
            .fold(BigInt::zero(), |sum, (transpose, multiplier)| {
                sum + transpose * multiplier
            });
        assert_eq!(transpose_evaluation, direct_high_evaluation);
    }
}

#[test]
fn integer_lift_product_accumulator_rejects_a_uniform_additive_shift() {
    const TRACE_DOMAIN_SIZE: usize = 4;
    const SOURCE_COLUMN: u32 = 0;
    const LINEAR_EVALUATION_COLUMN: u32 = 1;
    const PRODUCT_ACCUMULATOR_COLUMN: u32 = 2;

    let component = RelationIntegerLiftComponentDescriptor {
        ordered_linear_terms: vec![RelationIntegerLiftLinearTermDescriptor {
            negative: false,
            column_ordinal: SOURCE_COLUMN,
            column_offset: 0,
            coefficient: RelationIntegerLiftCoefficient::Constant(1),
        }],
        ordered_convolution_products: Vec::new(),
        ordered_full_ring_negacyclic_products: Vec::new(),
        linear_evaluation_column_ordinal: LINEAR_EVALUATION_COLUMN,
        product_accumulator_column_ordinal: PRODUCT_ACCUMULATOR_COLUMN,
    };
    let theta_expression = vec![RelationExpressionInstruction::TranscriptChallenge {
        challenge_role: RelationChallengeRole::NonNativeTheta,
        role_coordinates: vec![0, 0],
    }];
    let point_zero = vec![RelationExpressionInstruction::BaseFieldConstant(101)];
    let programs = integer_lift_component_constraint_programs(
        &component,
        SuiteModulusReference::data(0),
        &theta_expression,
        point_zero.clone(),
        vec![RelationExpressionInstruction::BaseFieldConstant(103)],
        vec![RelationExpressionInstruction::BaseFieldConstant(107)],
        &check_context(),
    )
    .expect("integer-lift component constraint programs");
    assert_eq!(programs.len(), 5);
    assert_eq!(programs[2].zeroifier_postfix_expression, point_zero);

    let theta = BigInt::from(11_u8);
    let base_columns = BTreeMap::from([
        (SOURCE_COLUMN, vec![BigInt::zero(); TRACE_DOMAIN_SIZE]),
        (
            LINEAR_EVALUATION_COLUMN,
            vec![BigInt::zero(); TRACE_DOMAIN_SIZE],
        ),
    ]);
    let evaluate = |program_ordinal: usize, row_ordinal: usize, accumulator_rows: Vec<BigInt>| {
        let mut columns = base_columns.clone();
        columns.insert(PRODUCT_ACCUMULATOR_COLUMN, accumulator_rows);
        evaluate_integer_lift_test_expression(
            &programs[program_ordinal].numerator_postfix_expression,
            row_ordinal,
            TRACE_DOMAIN_SIZE,
            &theta,
            &columns,
        )
    };

    let unshifted = vec![BigInt::zero(); TRACE_DOMAIN_SIZE];
    assert_eq!(
        evaluate(0, TRACE_DOMAIN_SIZE - 1, unshifted.clone()),
        BigInt::zero()
    );
    for row_ordinal in 0..TRACE_DOMAIN_SIZE - 1 {
        assert_eq!(evaluate(1, row_ordinal, unshifted.clone()), BigInt::zero());
        assert_eq!(evaluate(3, row_ordinal, unshifted.clone()), BigInt::zero());
    }
    assert_eq!(evaluate(2, 0, unshifted.clone()), BigInt::zero());
    assert_eq!(
        evaluate(4, TRACE_DOMAIN_SIZE - 1, unshifted),
        BigInt::zero()
    );

    let shifted = vec![BigInt::from(7_u8); TRACE_DOMAIN_SIZE];
    for row_ordinal in 0..TRACE_DOMAIN_SIZE - 1 {
        assert_eq!(evaluate(3, row_ordinal, shifted.clone()), BigInt::zero());
    }
    assert_eq!(
        evaluate(4, TRACE_DOMAIN_SIZE - 1, shifted.clone()),
        BigInt::zero()
    );
    assert_eq!(evaluate(2, 0, shifted), BigInt::from(7_u8));
}

#[test]
fn signed_magnitudes_are_unique_for_arbitrary_width_bounds() {
    let zero_tuple =
        canonical_signed_integer_tuple(&BigInt::zero()).expect("canonical zero signed magnitude");
    assert_eq!(zero_tuple.items[0].canonical_bytes(), &[0]);
    assert!(
        zero_tuple.items[1]
            .variable_value_bytes()
            .expect("zero magnitude bytes")
            .is_empty()
    );
    assert!(
        canonical_unsigned_magnitude_item(&BigUint::zero())
            .expect("canonical zero unsigned magnitude")
            .variable_value_bytes()
            .expect("zero unsigned magnitude bytes")
            .is_empty()
    );
    assert_eq!(signed_integer_from_magnitude(0, &[]), Ok(BigInt::zero()));

    let large_positive = BigInt::one() << 300_u32;
    let large_negative = -large_positive.clone();
    let positive_tuple =
        canonical_signed_integer_tuple(&large_positive).expect("large positive signed magnitude");
    let negative_tuple =
        canonical_signed_integer_tuple(&large_negative).expect("large negative signed magnitude");
    assert_ne!(
        positive_tuple.encode().expect("positive encoding"),
        negative_tuple.encode().expect("negative encoding")
    );
    assert_eq!(
        signed_integer_from_magnitude(0, &large_positive.to_bytes_be().1),
        Ok(large_positive)
    );
    assert_eq!(
        signed_integer_from_magnitude(1, &large_negative.magnitude().to_bytes_be()),
        Ok(large_negative)
    );
    assert_eq!(
        signed_integer_from_magnitude(1, &[]),
        Err(RelationPlanError::InvalidSignedMagnitude)
    );
    assert_eq!(
        signed_integer_from_magnitude(0, &[0, 1]),
        Err(RelationPlanError::InvalidSignedMagnitude)
    );
    assert_eq!(
        signed_integer_from_magnitude(2, &[1]),
        Err(RelationPlanError::InvalidSignedMagnitude)
    );
}

#[test]
fn bound_checker_derives_trinary_and_recomposition_intervals() {
    let constraints = vec![
        bound_constraint(1, trinary_constraint_expression(0)),
        bound_constraint(2, trinary_constraint_expression(1)),
        bound_constraint(
            3,
            radix_recomposition_expression(2, 3, None, &[0, 1], TEST_BASE_FIELD)
                .expect("recomposition expression"),
        ),
    ];
    let semantic_cells = vec![
        SemanticCellDescriptor {
            semantic_cell_ordinal: 0,
            column_ordinal: 0,
            claimed_interval: SignedIntegerInterval::new(0, 2),
            bound_certificate: RelationBoundCertificate::Trinary {
                constraint_ordinal: 0,
            },
        },
        SemanticCellDescriptor {
            semantic_cell_ordinal: 1,
            column_ordinal: 1,
            claimed_interval: SignedIntegerInterval::new(0, 2),
            bound_certificate: RelationBoundCertificate::Trinary {
                constraint_ordinal: 1,
            },
        },
        SemanticCellDescriptor {
            semantic_cell_ordinal: 2,
            column_ordinal: 2,
            claimed_interval: SignedIntegerInterval::new(0, 8),
            bound_certificate: RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal: 2,
                radix: 3,
                ordered_digit_column_ordinals: vec![0, 1],
            },
        },
    ];
    assert_eq!(
        derive_test_interval(2, &semantic_cells, &constraints),
        Ok(SignedIntegerInterval::new(0, 8))
    );
}

#[test]
fn bound_checker_derives_finite_set_and_recomposition_intervals() {
    let ordered_finite_set_values = (0..9).map(BigInt::from).collect::<Vec<_>>();
    let (finite_set_expression, ordered_finite_set_factor_expressions) =
        finite_integer_set_constraint_expressions(0, &ordered_finite_set_values, TEST_BASE_FIELD)
            .expect("finite-set constraint expression");
    let constraints = vec![
        RelationConstraintDescriptor {
            constraint_role: 1,
            role_coordinates: Vec::new(),
            numerator_postfix_expression: finite_set_expression,
            zeroifier_postfix_expression: full_trace_zeroifier_expression(16),
            enforce_proof_base_field_no_wrap: false,
            ordered_injective_integer_factor_expressions: ordered_finite_set_factor_expressions,
        },
        bound_constraint(2, trinary_constraint_expression(1)),
        bound_constraint(
            3,
            radix_recomposition_expression(2, 9, None, &[0, 1], TEST_BASE_FIELD)
                .expect("mixed-radix recomposition expression"),
        ),
    ];
    let semantic_cells = vec![
        SemanticCellDescriptor {
            semantic_cell_ordinal: 0,
            column_ordinal: 0,
            claimed_interval: SignedIntegerInterval::new(0, 8),
            bound_certificate: RelationBoundCertificate::FiniteIntegerSet {
                constraint_ordinal: 0,
                ordered_values: ordered_finite_set_values,
            },
        },
        SemanticCellDescriptor {
            semantic_cell_ordinal: 1,
            column_ordinal: 1,
            claimed_interval: SignedIntegerInterval::new(0, 2),
            bound_certificate: RelationBoundCertificate::Trinary {
                constraint_ordinal: 1,
            },
        },
        SemanticCellDescriptor {
            semantic_cell_ordinal: 2,
            column_ordinal: 2,
            claimed_interval: SignedIntegerInterval::new(0, 26),
            bound_certificate: RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal: 2,
                radix: 9,
                ordered_digit_column_ordinals: vec![0, 1],
            },
        },
    ];
    assert_eq!(
        derive_test_interval(2, &semantic_cells, &constraints),
        Ok(SignedIntegerInterval::new(0, 26))
    );
}

#[test]
fn bound_checker_rejects_a_mixed_digit_outside_the_recomposition_radix() {
    let ordered_values = (0..=9).map(BigInt::from).collect::<Vec<_>>();
    let (finite_set_expression, ordered_factor_expressions) =
        finite_integer_set_constraint_expressions(0, &ordered_values, TEST_BASE_FIELD)
            .expect("finite-set constraint expression");
    let constraints = vec![
        RelationConstraintDescriptor {
            constraint_role: 1,
            role_coordinates: Vec::new(),
            numerator_postfix_expression: finite_set_expression,
            zeroifier_postfix_expression: full_trace_zeroifier_expression(16),
            enforce_proof_base_field_no_wrap: false,
            ordered_injective_integer_factor_expressions: ordered_factor_expressions,
        },
        bound_constraint(
            2,
            radix_recomposition_expression(1, 9, None, &[0], TEST_BASE_FIELD)
                .expect("recomposition expression"),
        ),
    ];
    let semantic_cells = vec![
        SemanticCellDescriptor {
            semantic_cell_ordinal: 0,
            column_ordinal: 0,
            claimed_interval: SignedIntegerInterval::new(0, 9),
            bound_certificate: RelationBoundCertificate::FiniteIntegerSet {
                constraint_ordinal: 0,
                ordered_values,
            },
        },
        SemanticCellDescriptor {
            semantic_cell_ordinal: 1,
            column_ordinal: 1,
            claimed_interval: SignedIntegerInterval::new(0, 9),
            bound_certificate: RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal: 1,
                radix: 9,
                ordered_digit_column_ordinals: vec![0],
            },
        },
    ];
    assert_eq!(
        derive_test_interval(1, &semantic_cells, &constraints),
        Err(RelationPlanError::InvalidBoundCertificate)
    );
}

#[test]
fn bound_checker_rejects_self_attested_or_mismatched_intervals() {
    let unrelated_constraint =
        bound_constraint(1, vec![RelationExpressionInstruction::BaseFieldConstant(0)]);
    let self_attested = SemanticCellDescriptor {
        semantic_cell_ordinal: 0,
        column_ordinal: 0,
        claimed_interval: SignedIntegerInterval::new(0, 2),
        bound_certificate: RelationBoundCertificate::Trinary {
            constraint_ordinal: 0,
        },
    };
    assert_eq!(
        derive_test_interval(0, &[self_attested], &[unrelated_constraint]),
        Err(RelationPlanError::InvalidBoundCertificate)
    );

    let mismatched = SemanticCellDescriptor {
        semantic_cell_ordinal: 0,
        column_ordinal: 0,
        claimed_interval: SignedIntegerInterval::new(0, 1),
        bound_certificate: RelationBoundCertificate::Trinary {
            constraint_ordinal: 0,
        },
    };
    assert_eq!(
        derive_test_interval(
            0,
            &[mismatched],
            &[bound_constraint(1, trinary_constraint_expression(0))],
        ),
        Err(RelationPlanError::InvalidSemanticCell)
    );
}

#[test]
fn generated_committed_material_plans_cover_the_exact_root_directions() {
    let context = committed_material_check_context();
    let input = committed_material_input();
    assert_eq!(
        input
            .relation_trace_domain_size()
            .expect("factor-four relation trace domain"),
        input
            .message_trace_domain_size()
            .expect("message trace domain")
            * committed_material::COMMITTED_MATERIAL_TRACE_PACKING_FACTOR,
    );
    let vss_plan = compile_vss_share_linkage_relation_plan(&input, &context)
        .expect("exact VSS share-linkage relation plan");
    let aggregate_plan = compile_aggregate_threshold_share_relation_plan(&input, &context)
        .expect("exact aggregate-threshold-share relation plan");
    assert_eq!(vss_plan.application_statement_schema_identifier(), 0x2110);
    assert_eq!(
        aggregate_plan.application_statement_schema_identifier(),
        0x2111
    );
    assert_eq!(
        vss_plan
            .encode_canonical_tuple(&vss_plan.canonical_tuple().expect("typed VSS plan tuple"),)
            .expect("encoded typed VSS plan tuple"),
        vss_plan.canonical_bytes().expect("VSS plan bytes")
    );
    assert_eq!(
        aggregate_plan
            .encode_canonical_tuple(
                &aggregate_plan
                    .canonical_tuple()
                    .expect("typed aggregate plan tuple"),
            )
            .expect("encoded typed aggregate plan tuple"),
        aggregate_plan
            .canonical_bytes()
            .expect("aggregate plan bytes")
    );
    assert_ne!(
        vss_plan.canonical_hash().expect("VSS plan hash"),
        aggregate_plan
            .canonical_hash()
            .expect("aggregate plan hash")
    );

    for plan in [&vss_plan, &aggregate_plan] {
        let variant = &plan.variants()[0];
        let expected_base_oracle_columns = variant
            .ordered_columns
            .iter()
            .enumerate()
            .filter(|(_, column)| matches!(column.origin, RelationColumnOrigin::Prover))
            .map(|(column_ordinal, _)| u32::try_from(column_ordinal).expect("column ordinal fits"))
            .collect::<Vec<_>>();
        let proof_created_trees = variant
            .ordered_trees
            .iter()
            .filter_map(|tree| match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } => Some((*proof_tree_role, ordered_column_ordinals.as_slice())),
                RelationTreeDescriptor::BoundPublic { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            proof_created_trees,
            vec![(1, expected_base_oracle_columns.as_slice())],
            "every proof-created committed-material column shares one base-oracle leaf"
        );

        let transcript_schedule = variant
            .common_proof_transcript_schedule(&context)
            .expect("committed-material transcript schedule");
        assert_eq!(
            usize::try_from(transcript_schedule.opening_claim_count())
                .expect("opening-claim count fits"),
            variant.ordered_opening_claims.len(),
            "the one initial FRI polynomial consumes every ordered DEEP claim"
        );
        assert_eq!(
            transcript_schedule.fri_fold_count(),
            context.fri_fold_count,
            "the committed-material proof carries one schedule-fixed fold chain"
        );
    }

    let vss_bound_uses = vss_plan.variants()[0]
        .ordered_trees
        .iter()
        .filter_map(|tree| match tree {
            RelationTreeDescriptor::BoundPublic { root_use, .. } => Some(*root_use),
            RelationTreeDescriptor::ProofCreated { .. } => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(vss_bound_uses, vec![BoundTreeRootUse::Output; 5]);

    let aggregate_bound_uses = aggregate_plan.variants()[0]
        .ordered_trees
        .iter()
        .filter_map(|tree| match tree {
            RelationTreeDescriptor::BoundPublic { root_use, .. } => Some(*root_use),
            RelationTreeDescriptor::ProofCreated { .. } => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        aggregate_bound_uses,
        vec![
            BoundTreeRootUse::Input,
            BoundTreeRootUse::Input,
            BoundTreeRootUse::Input,
            BoundTreeRootUse::Output,
        ]
    );

    let vss_variant = &vss_plan.variants()[0];
    assert_eq!(
        vss_variant
            .ordered_coefficient_local_identity_batches()
            .len(),
        vss_variant.ordered_non_native_moduli.len()
            * usize::from(context.non_native_alpha_repetition_count)
            * 2
    );
    let aggregate_variant = &aggregate_plan.variants()[0];
    assert!(
        aggregate_variant
            .ordered_coefficient_local_identity_batches()
            .is_empty(),
        "a single aggregate residual per half must not sample a dead alpha challenge"
    );
    let aggregate_deterministic_identity_count = aggregate_variant
        .ordered_constraints
        .iter()
        .filter(|constraint| {
            constraint
                .numerator_postfix_expression
                .iter()
                .any(|instruction| {
                    matches!(
                        instruction,
                        RelationExpressionInstruction::NonNativeModulusConstant { .. }
                    )
                })
        })
        .count();
    assert_eq!(
        aggregate_deterministic_identity_count,
        aggregate_variant.ordered_non_native_moduli.len() * 2
    );
    assert!(
        aggregate_variant
            .ordered_constraints
            .iter()
            .all(|constraint| {
                constraint
                    .numerator_postfix_expression
                    .iter()
                    .all(|instruction| {
                        !matches!(
                            instruction,
                            RelationExpressionInstruction::TranscriptChallenge {
                                challenge_role: RelationChallengeRole::NonNativeAlpha
                                    | RelationChallengeRole::NonNativeTheta,
                                ..
                            }
                        )
                    })
            })
    );
}

#[test]
fn relation_plan_checker_rejects_duplicate_tree_column_ownership() {
    let context = committed_material_check_context();
    let mut plan = compile_vss_share_linkage_relation_plan(&committed_material_input(), &context)
        .expect("the exact VSS share-linkage relation plan compiles");
    let duplicated_tree = plan.plan.variants[0]
        .ordered_trees
        .first()
        .expect("the VSS relation owns at least one bound tree")
        .clone();
    plan.plan.variants[0].ordered_trees.push(duplicated_tree);

    assert_eq!(plan.check(&context), Err(RelationPlanError::InvalidRoot));
}

#[test]
fn aggregate_plan_checker_rejects_duplicate_or_randomized_half_residuals() {
    let context = committed_material_check_context();
    let input = committed_material_input();
    let mut duplicated = compile_aggregate_threshold_share_relation_plan(&input, &context)
        .expect("exact aggregate-threshold-share relation plan");
    let deterministic_constraint_ordinals = duplicated.plan.variants[0]
        .ordered_constraints
        .iter()
        .enumerate()
        .filter_map(|(constraint_ordinal, constraint)| {
            constraint
                .numerator_postfix_expression
                .iter()
                .any(|instruction| {
                    matches!(
                        instruction,
                        RelationExpressionInstruction::NonNativeModulusConstant { .. }
                    )
                })
                .then_some(constraint_ordinal)
        })
        .collect::<Vec<_>>();
    let first_residual = duplicated.plan.variants[0].ordered_constraints
        [deterministic_constraint_ordinals[0]]
        .numerator_postfix_expression
        .clone();
    duplicated.plan.variants[0].ordered_constraints[deterministic_constraint_ordinals[1]]
        .numerator_postfix_expression = first_residual;
    assert_eq!(
        duplicated.check(&context),
        Err(RelationPlanError::DuplicateItem)
    );

    let mut randomized = compile_aggregate_threshold_share_relation_plan(&input, &context)
        .expect("exact aggregate-threshold-share relation plan");
    let first_deterministic_constraint = randomized.plan.variants[0]
        .ordered_constraints
        .iter_mut()
        .find(|constraint| {
            constraint
                .numerator_postfix_expression
                .iter()
                .any(|instruction| {
                    matches!(
                        instruction,
                        RelationExpressionInstruction::NonNativeModulusConstant { .. }
                    )
                })
        })
        .expect("aggregate plan has deterministic coefficient-local identities");
    first_deterministic_constraint
        .numerator_postfix_expression
        .insert(
            0,
            RelationExpressionInstruction::TranscriptChallenge {
                challenge_role: RelationChallengeRole::NonNativeAlpha,
                role_coordinates: vec![0, 0, 0],
            },
        );
    first_deterministic_constraint
        .numerator_postfix_expression
        .push(RelationExpressionInstruction::Multiplication);
    assert_eq!(
        randomized.check(&context),
        Err(RelationPlanError::InvalidConstraint)
    );
}

#[test]
fn generated_plan_checker_rejects_rotated_factor_and_opening_catalog_tampering() {
    let context = committed_material_check_context();
    let mut input = committed_material_input();
    // The three-participant fixture's point stride equals the half-ring trace
    // size, so its degree-one monomial actions are unrotated half swaps. A
    // valid five-participant roster has a smaller stride and exercises the
    // nonzero trace-rotation binding this test tampers with.
    input.participant_count = 5;
    input.threshold = 2;
    let mut vss_plan = compile_vss_share_linkage_relation_plan(&input, &context)
        .expect("exact VSS share-linkage relation plan");
    let variant = &mut vss_plan.plan.variants[0];
    let rotated_column = variant
        .ordered_coefficient_local_identity_batches
        .iter_mut()
        .flat_map(|batch| batch.ordered_residuals.iter_mut())
        .flat_map(|residual| residual.residual_postfix_expression.iter_mut())
        .find_map(|instruction| match instruction {
            RelationExpressionInstruction::ColumnValue {
                rotation_magnitude, ..
            } if *rotation_magnitude != 0 => Some(rotation_magnitude),
            _ => None,
        })
        .expect("the exact VSS plan contains a rotated monomial-action column");
    *rotated_column = input
        .relation_trace_domain_size()
        .expect("relation trace domain size");
    assert!(
        vss_plan.check(&context).is_err(),
        "a full-trace rotation cannot remain a checked coefficient-local residual",
    );

    let mut aggregate_plan = compile_aggregate_threshold_share_relation_plan(&input, &context)
        .expect("exact aggregate-threshold-share relation plan");
    aggregate_plan.plan.variants[0].ordered_opening_points.pop();
    assert_eq!(
        aggregate_plan.check(&context),
        Err(RelationPlanError::InvalidOpening)
    );
}

#[test]
fn relation_plan_rejects_semantic_witness_first_committed_after_challenge() {
    let context = committed_material_check_context();
    let input = committed_material_input();
    let mut plan = compile_vss_share_linkage_relation_plan(&input, &context)
        .expect("exact VSS share-linkage relation plan");
    let semantic_prover_columns = plan.plan.variants[0]
        .ordered_semantic_cells
        .iter()
        .filter_map(|cell| {
            matches!(
                plan.plan.variants[0].ordered_columns[cell.column_ordinal as usize].origin,
                RelationColumnOrigin::Prover
            )
            .then_some(cell.column_ordinal)
        })
        .collect::<BTreeSet<_>>();
    let base_tree_role = plan.plan.variants[0]
        .ordered_trees
        .iter_mut()
        .find_map(|tree| match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } if *proof_tree_role == 1
                && ordered_column_ordinals
                    .iter()
                    .any(|column_ordinal| semantic_prover_columns.contains(column_ordinal)) =>
            {
                Some(proof_tree_role)
            }
            _ => None,
        })
        .expect("the secret relation has a base tree containing semantic witness columns");
    *base_tree_role = 2;

    assert_eq!(
        plan.check(&context),
        Err(RelationPlanError::InvalidConstraint),
    );
}
