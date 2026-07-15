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
        non_native_modular_identity_challenge_count: 2,
        maximum_fiat_shamir_candidate_draws_per_output: 128,
        resolved_moduli: vec![
            ResolvedSuiteModulus::new(SuiteModulusReference::data(0), 97),
            ResolvedSuiteModulus::new(SuiteModulusReference::data(1), 193),
            ResolvedSuiteModulus::new(SuiteModulusReference::special(0), 241),
            ResolvedSuiteModulus::new(SuiteModulusReference::plaintext(), 257),
        ],
    }
}

fn compiler_input() -> TrusteeEvaluationKeyPlanInput {
    TrusteeEvaluationKeyPlanInput {
        schedule_position: 3,
        ring_degree: 16,
        trace_domain_size: 16,
        evaluation_domain_size: 32_768,
        opening_degree_bound_exclusive: 12_000,
        data_moduli: vec![97, 193],
        special_moduli: vec![241],
        plaintext_modulus: 257,
        decomposition_blocks: vec![
            TrusteeEvaluationKeyDecompositionBlock {
                data_modulus_indices: vec![0],
            },
            TrusteeEvaluationKeyDecompositionBlock {
                data_modulus_indices: vec![1],
            },
        ],
        commitment_data_modulus_indices: vec![0, 1],
        commitment_module_rank: 1,
        trace_mask_degree_bound_exclusive: 4,
        quotient_mask_degree_bound_exclusive: 18,
        first_mask_purpose: 7,
    }
}

fn committed_material_check_context() -> RelationPlanCheckContext {
    let evaluation_domain_size = 256_u64;
    let maximum_two_adic_order = 1_u64 << 32;
    RelationPlanCheckContext {
        base_field_modulus: crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree:
            crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE as u16,
        evaluation_blowup_factor: 2,
        evaluation_domain_generator: modular_power(
            crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
            maximum_two_adic_order / evaluation_domain_size,
            crate::bgv::proof_suite::PROOF_BASE_FIELD_MODULUS,
        ),
        evaluation_coset_offset: 7,
        deep_point_count: 1,
        quotient_component_count: 4,
        quotient_component_degree_bound_exclusive: 64,
        fri_fold_count: 4,
        final_polynomial_degree_bound_exclusive: 8,
        unique_query_count: 8,
        non_native_modular_identity_challenge_count: 1,
        maximum_fiat_shamir_candidate_draws_per_output: 128,
        resolved_moduli: vec![ResolvedSuiteModulus::new(
            SuiteModulusReference::data(0),
            97,
        )],
    }
}

fn committed_material_input() -> CommittedMaterialRelationPlanInput {
    CommittedMaterialRelationPlanInput {
        ring_degree: 16,
        evaluation_domain_size: 256,
        opening_degree_bound_exclusive: 128,
        material_column_degree_bound_exclusive: 10,
        participant_count: 3,
        threshold: 2,
        sharing_data_modulus_indices: vec![0],
        trace_mask_degree_bound_exclusive: 2,
        first_mask_purpose: 100,
    }
}

#[test]
fn incomplete_negacyclic_lowering_never_emits_an_accepting_plan() {
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&compiler_input(), &check_context()),
        Err(RelationPlanError::MissingExactNegacyclicLowering)
    );
}

#[test]
fn decomposition_blocks_must_cover_the_data_basis_once_in_order() {
    let mut missing_limb = compiler_input();
    missing_limb.decomposition_blocks.pop();
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&missing_limb, &check_context()),
        Err(RelationPlanError::NonCanonicalOrder)
    );

    let mut repeated_limb = compiler_input();
    repeated_limb.decomposition_blocks[1].data_modulus_indices = vec![0, 1];
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&repeated_limb, &check_context()),
        Err(RelationPlanError::NonCanonicalOrder)
    );

    let mut empty_block = compiler_input();
    empty_block.decomposition_blocks[0].data_modulus_indices.clear();
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&empty_block, &check_context()),
        Err(RelationPlanError::NonCanonicalOrder)
    );
}

#[test]
fn commitment_primes_are_one_canonical_subset_of_the_data_basis() {
    let mut repeated_prime = compiler_input();
    repeated_prime.commitment_data_modulus_indices = vec![0, 0];
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&repeated_prime, &check_context()),
        Err(RelationPlanError::NonCanonicalOrder)
    );

    let mut unknown_prime = compiler_input();
    unknown_prime.commitment_data_modulus_indices = vec![2];
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&unknown_prime, &check_context()),
        Err(RelationPlanError::NonCanonicalOrder)
    );
}

#[test]
fn every_data_special_and_plaintext_modulus_is_suite_resolved() {
    let mut wrong_special_modulus = check_context();
    wrong_special_modulus.resolved_moduli[2].modulus = 337;
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&compiler_input(), &wrong_special_modulus),
        Err(RelationPlanError::InvalidModulus)
    );

    let mut unsorted_context = check_context();
    unsorted_context.resolved_moduli.swap(1, 2);
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&compiler_input(), &unsorted_context),
        Err(RelationPlanError::NonCanonicalOrder)
    );
}

#[test]
fn exact_relation_geometry_and_common_opening_rank_are_mandatory() {
    let mut no_special_basis = compiler_input();
    no_special_basis.special_moduli.clear();
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&no_special_basis, &check_context()),
        Err(RelationPlanError::InvalidDomain)
    );

    let mut no_common_opening_rank = compiler_input();
    no_common_opening_rank.commitment_module_rank = 0;
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&no_common_opening_rank, &check_context()),
        Err(RelationPlanError::InvalidDomain)
    );

    let mut mismatched_trace = compiler_input();
    mismatched_trace.trace_domain_size = 8;
    assert_eq!(
        compile_trustee_evaluation_key_relation_plan(&mismatched_trace, &check_context()),
        Err(RelationPlanError::InvalidDomain)
    );
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
        suffixes[row_ordinal] =
            &values[row_ordinal] + theta * &suffixes[row_ordinal + 1];
    }
    suffixes
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
            low_multiplier_transpose[row_ordinal] =
                &theta * &low_multiplier_transpose[row_ordinal + 1]
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
            multiplicand_low_suffix_evaluation_column_ordinal:
                MULTIPLICAND_LOW_SUFFIX,
            multiplicand_high_suffix_evaluation_column_ordinal:
                MULTIPLICAND_HIGH_SUFFIX,
            reversed_multiplier_low_transpose_column_ordinal:
                LOW_MULTIPLIER_TRANSPOSE,
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
        let direct_high_evaluation = direct_product[half_ring_degree..]
            .iter()
            .enumerate()
            .fold(BigInt::zero(), |sum, (ordinal, coefficient)| {
                sum + coefficient
                    * integer_power(
                        theta.clone(),
                        u64::try_from(ordinal).expect("coefficient ordinal fits u64"),
                    )
            });
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
fn signed_magnitudes_are_unique_for_arbitrary_width_bounds() {
    let large_positive = BigInt::one() << 300_u32;
    let large_negative = -large_positive.clone();
    let positive_tuple = canonical_signed_integer_tuple(&large_positive)
        .expect("large positive signed magnitude");
    let negative_tuple = canonical_signed_integer_tuple(&large_negative)
        .expect("large negative signed magnitude");
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
fn bound_checker_rejects_self_attested_or_mismatched_intervals() {
    let unrelated_constraint = bound_constraint(
        1,
        vec![RelationExpressionInstruction::BaseFieldConstant(0)],
    );
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
    let vss_plan = compile_vss_share_linkage_relation_plan(&input, &context)
        .expect("exact VSS share-linkage relation plan");
    let aggregate_plan = compile_aggregate_threshold_share_relation_plan(&input, &context)
        .expect("exact aggregate-threshold-share relation plan");
    assert_eq!(vss_plan.application_statement_schema_identifier(), 0x2110);
    assert_eq!(aggregate_plan.application_statement_schema_identifier(), 0x2111);
    assert_eq!(
        vss_plan
            .encode_canonical_tuple(
                &vss_plan
                    .canonical_tuple()
                    .expect("typed VSS plan tuple"),
            )
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
        aggregate_plan.canonical_hash().expect("aggregate plan hash")
    );

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
            * usize::from(context.non_native_modular_identity_challenge_count)
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
    assert!(aggregate_variant.ordered_constraints.iter().all(|constraint| {
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
    }));
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
    first_deterministic_constraint.numerator_postfix_expression.insert(
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
    let input = committed_material_input();
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
                rotation_magnitude,
                ..
            } if *rotation_magnitude != 0 => Some(rotation_magnitude),
            _ => None,
        })
        .expect("the exact VSS plan contains a rotated monomial-action column");
    *rotated_column = input.trace_domain_size().expect("trace domain size");
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
