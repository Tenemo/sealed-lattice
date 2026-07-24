use super::key_relation::{
    AnchorEquationInputs, AnchorOpeningWitness, AnchorQuotientWitness, BoundPolynomialRootUse,
    BoundedUnsignedColumn, ExactRadixDigitColumnCatalog, KeyRelationGeometry,
    KeyRelationPlanBuilder, KeyVerifierSourceKey, SameSecretRelationPlanInput, ShiftedSmallVector,
    SplitIntegerVector, UpperBoundComparatorWitnessLayout, bdlop_matrix_source,
    statement_root_source,
};
use super::*;

const SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER: u16 =
    crate::foundation::ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
const DEGREE_ZERO_VSS_MATERIAL_ROOTS_FIELD_ORDINAL: u64 = 3;
const ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL: u64 = 4;

pub(crate) struct CompiledSameSecretRelation {
    pub(crate) relation_plan: CompiledRelationPlan,
    pub(crate) source_layout: SameSecretSourceLayout,
}

pub(crate) struct SameSecretSourceLayout {
    pub(super) common_secret: ShiftedSmallVector,
    pub(super) negative_indicator: [u32; 2],
    pub(super) ordered_materials: Box<[SameSecretMaterialSourceLayout]>,
    pub(super) ordered_anchors: Box<[SameSecretAnchorSourceLayout]>,
    pub(super) exact_radix_digits_by_column: ExactRadixDigitColumnCatalog,
}

pub(super) struct SameSecretMaterialSourceLayout {
    pub(super) data_modulus_index: u16,
    pub(super) material: [BoundedUnsignedColumn; 2],
    pub(super) upper_bound_comparators: [UpperBoundComparatorWitnessLayout; 2],
}

pub(super) struct SameSecretAnchorSourceLayout {
    pub(super) data_modulus_index: u16,
    pub(super) opening: AnchorOpeningWitness,
    pub(super) commitments: Box<[SplitIntegerVector]>,
    pub(super) first_matrix: Box<[Box<[SplitIntegerVector]>]>,
    pub(super) second_matrix: Box<[SplitIntegerVector]>,
    pub(super) quotients: AnchorQuotientWitness,
}

pub(crate) fn compile_same_secret_relation_plan(
    input: &SameSecretRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
    compile_same_secret_relation_with_source_layout(input, check_context)
        .map(|compiled| compiled.relation_plan)
}

pub(crate) fn compile_same_secret_relation_with_source_layout(
    input: &SameSecretRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledSameSecretRelation, RelationPlanError> {
    let rank = usize::from(input.commitment_module_rank);
    let mut sources = Vec::new();
    for (root_ordinal, _) in input.sharing_data_modulus_indices.iter().enumerate() {
        sources.push(statement_root_source(
            DEGREE_ZERO_VSS_MATERIAL_ROOTS_FIELD_ORDINAL,
            Some(u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?),
        ));
    }
    for (root_ordinal, data_modulus_index) in input
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        sources.push(statement_root_source(
            ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
            Some(u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?),
        ));
        append_matrix_sources(&mut sources, input.ring_degree, data_modulus_index, rank)?;
    }
    let geometry = KeyRelationGeometry::for_same_secret(input);
    let mut builder = KeyRelationPlanBuilder::new(
        SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        &geometry,
        check_context,
        sources,
    )?;
    let secret = builder.add_shifted_ternary_vector()?;
    let negative_indicator = builder.add_binary_vector()?;
    let mut material_source_layouts = Vec::with_capacity(input.sharing_data_modulus_indices.len());
    for (root_ordinal, data_modulus_index) in input
        .sharing_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        let (material, upper_bound_comparators) = builder.add_committed_material_root(
            &KeyVerifierSourceKey::StatementRoot {
                field_ordinal: DEGREE_ZERO_VSS_MATERIAL_ROOTS_FIELD_ORDINAL,
                list_ordinal: Some(
                    u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ),
            },
            SuiteModulusReference::data(data_modulus_index),
        )?;
        builder.add_material_secret_equality(
            &material,
            &secret,
            &negative_indicator,
            SuiteModulusReference::data(data_modulus_index),
        )?;
        material_source_layouts.push(SameSecretMaterialSourceLayout {
            data_modulus_index,
            material,
            upper_bound_comparators,
        });
    }
    let mut anchor_source_layouts = Vec::with_capacity(input.commitment_data_modulus_indices.len());
    for (root_ordinal, data_modulus_index) in input
        .commitment_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        // Every prime commitment limb owns an independent opening tape. Reusing
        // one short opening across CRT limbs creates a joint-view hiding gap
        // even when each individual commitment is hiding.
        let opening = builder.add_anchor_opening_witness()?;
        let modulus_reference = SuiteModulusReference::data(data_modulus_index);
        let commitments = builder.add_setup_polynomial_root(
            &KeyVerifierSourceKey::StatementRoot {
                field_ordinal: ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL,
                list_ordinal: Some(
                    u64::try_from(root_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                ),
            },
            modulus_reference,
            rank.checked_add(1)
                .ok_or(RelationPlanError::CountOverflow)?,
            BoundPolynomialRootUse::Output,
        )?;
        let (first_matrix, second_matrix) =
            add_matrix_columns(&mut builder, data_modulus_index, rank)?;
        let quotients = builder.add_anchor_quotient_witness()?;
        for challenge_ordinal in 0..check_context.non_native_theta_repetition_count {
            builder.add_anchor_equations(
                modulus_reference,
                challenge_ordinal,
                AnchorEquationInputs::new(
                    &commitments,
                    &first_matrix,
                    &second_matrix,
                    &opening,
                    &secret,
                    &quotients,
                ),
            )?;
        }
        anchor_source_layouts.push(SameSecretAnchorSourceLayout {
            data_modulus_index,
            opening,
            commitments: commitments.into_boxed_slice(),
            first_matrix: first_matrix
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            second_matrix: second_matrix.into_boxed_slice(),
            quotients,
        });
    }
    let exact_radix_digits_by_column = builder
        .exact_radix_digits_by_column()
        .iter()
        .map(|(column_ordinal, digit_column_ordinals)| {
            (
                *column_ordinal,
                digit_column_ordinals.clone().into_boxed_slice(),
            )
        })
        .collect();
    let relation_plan = builder.finish()?;
    Ok(CompiledSameSecretRelation {
        relation_plan,
        source_layout: SameSecretSourceLayout {
            common_secret: secret,
            negative_indicator,
            ordered_materials: material_source_layouts.into_boxed_slice(),
            ordered_anchors: anchor_source_layouts.into_boxed_slice(),
            exact_radix_digits_by_column,
        },
    })
}

pub(super) fn append_matrix_sources(
    sources: &mut Vec<(KeyVerifierSourceKey, RelationVerifierSource)>,
    ring_degree: u64,
    data_modulus_index: u16,
    rank: usize,
) -> Result<(), RelationPlanError> {
    for row_ordinal in 0..rank {
        for column_ordinal in 0..=rank {
            sources.push(bdlop_matrix_source(
                ring_degree,
                data_modulus_index,
                1,
                u16::try_from(row_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
                u16::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
            ));
        }
    }
    for column_ordinal in 0..rank {
        sources.push(bdlop_matrix_source(
            ring_degree,
            data_modulus_index,
            2,
            0,
            u16::try_from(column_ordinal).map_err(|_| RelationPlanError::CountOverflow)?,
        ));
    }
    Ok(())
}

pub(super) fn add_matrix_columns(
    builder: &mut KeyRelationPlanBuilder<'_>,
    data_modulus_index: u16,
    rank: usize,
) -> Result<(Vec<Vec<SplitIntegerVector>>, Vec<SplitIntegerVector>), RelationPlanError> {
    let modulus_reference = SuiteModulusReference::data(data_modulus_index);
    let first_matrix = (0..rank)
        .map(|row_ordinal| {
            (0..=rank)
                .map(|column_ordinal| {
                    builder.add_split_verifier_vector(
                        &KeyVerifierSourceKey::BdlopMatrix {
                            data_modulus_index,
                            matrix_part: 1,
                            row: u16::try_from(row_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                            column: u16::try_from(column_ordinal)
                                .map_err(|_| RelationPlanError::CountOverflow)?,
                        },
                        modulus_reference,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let second_matrix = (0..rank)
        .map(|column_ordinal| {
            builder.add_split_verifier_vector(
                &KeyVerifierSourceKey::BdlopMatrix {
                    data_modulus_index,
                    matrix_part: 2,
                    row: 0,
                    column: u16::try_from(column_ordinal)
                        .map_err(|_| RelationPlanError::CountOverflow)?,
                },
                modulus_reference,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((first_matrix, second_matrix))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::bgv::{
        parameters::DATA_PRIMES,
        proof_suite::{
            PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
            field::{ProofBaseFieldElement, ProofChallengeExtensionElement},
            transcript::CommonProofChallenge,
        },
    };

    pub(in super::super) const TEST_RING_DEGREE: u64 = 256;
    pub(in super::super) const TEST_EVALUATION_DOMAIN_SIZE: u64 = 8_192;
    pub(in super::super) const TEST_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 4_096;

    pub(in super::super) fn check_context(include_plaintext: bool) -> RelationPlanCheckContext {
        let maximum_two_adic_order = 1_u64 << 32;
        let mut resolved_moduli = vec![
            ResolvedSuiteModulus::new(SuiteModulusReference::data(0), DATA_PRIMES[0]),
            ResolvedSuiteModulus::new(SuiteModulusReference::data(1), DATA_PRIMES[1]),
            ResolvedSuiteModulus::new(SuiteModulusReference::data(2), DATA_PRIMES[2]),
        ];
        if include_plaintext {
            resolved_moduli.push(ResolvedSuiteModulus::new(
                SuiteModulusReference::plaintext(),
                257,
            ));
        }
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                maximum_two_adic_order / TEST_EVALUATION_DOMAIN_SIZE,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 1,
            quotient_component_count: 4,
            quotient_component_degree_bound_exclusive: 1_024,
            fri_fold_count: 9,
            final_polynomial_degree_bound_exclusive: 8,
            unique_query_count: 8,
            non_native_theta_repetition_count: 1,
            non_native_alpha_repetition_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli,
        }
    }

    pub(in super::super) fn same_secret_input() -> SameSecretRelationPlanInput {
        SameSecretRelationPlanInput {
            ring_degree: TEST_RING_DEGREE,
            evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: TEST_OPENING_DEGREE_BOUND_EXCLUSIVE,
            material_column_degree_bound_exclusive: 10,
            public_polynomial_column_degree_bound_exclusive: TEST_RING_DEGREE,
            sharing_data_modulus_indices: vec![0, 1],
            commitment_data_modulus_indices: vec![0, 1, 2],
            commitment_module_rank: 1,
        }
    }

    pub(in super::super) fn application_challenges(
        variant: &RelationPlanVariant,
        context: &RelationPlanCheckContext,
    ) -> Vec<RelationApplicationChallengeAssignment> {
        let mut seen_coordinates = std::collections::BTreeSet::new();
        variant
            .derived_challenge_catalog(context)
            .expect("derived challenge catalog")
            .into_iter()
            .filter_map(|descriptor| {
                let challenge = match descriptor.role {
                    RelationChallengeRole::NonNativeTheta => CommonProofChallenge::Theta {
                        modulus_ordinal: u16::try_from(descriptor.role_coordinates[0]).ok()?,
                    },
                    RelationChallengeRole::NonNativeAlpha => CommonProofChallenge::Alpha {
                        modulus_ordinal: u16::try_from(descriptor.role_coordinates[0]).ok()?,
                    },
                    _ => return None,
                };
                let repetition_ordinal = u16::try_from(descriptor.role_coordinates[1]).ok()?;
                if !seen_coordinates.insert((challenge, repetition_ordinal)) {
                    return None;
                }
                Some(
                    RelationApplicationChallengeAssignment::new(challenge, repetition_ordinal, 3)
                        .expect("valid application challenge"),
                )
            })
            .collect()
    }

    #[test]
    fn same_secret_plan_is_checked_and_interpretable() {
        let context = check_context(false);
        let plan = compile_same_secret_relation_plan(&same_secret_input(), &context)
            .expect("same-secret relation plan");
        let variant = plan
            .select_variant(None, None)
            .expect("same-secret plan variant");
        let challenges = application_challenges(variant, &context);
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(context.evaluation_coset_offset)
                .expect("evaluation point"),
        );
        let evaluations = variant
            .evaluate_constraints_at_point(&context, evaluation_point, &challenges, |_, _, _| {
                Ok(ProofChallengeExtensionElement::ZERO)
            })
            .expect("every generated constraint is interpretable");
        assert_eq!(evaluations.len(), variant.ordered_constraints.len());
        assert_eq!(
            variant.evaluate_constraints_at_point(
                &context,
                evaluation_point,
                &challenges[..challenges.len() - 1],
                |_, _, _| Ok(ProofChallengeExtensionElement::ZERO),
            ),
            Err(RelationPlanError::InvalidChallengeCatalog)
        );
        assert!(!variant.ordered_columns.is_empty());
        assert!(!variant.ordered_constraints.is_empty());
        assert_eq!(variant.ordered_trees.len(), 7);
        assert!(proof_tree_width(variant, 1) > proof_tree_width(variant, 2));
    }

    #[test]
    fn same_secret_plan_rejects_noncanonical_and_incomplete_geometry() {
        let context = check_context(false);
        let mut repeated_modulus = same_secret_input();
        repeated_modulus.commitment_data_modulus_indices = vec![0, 0];
        assert_eq!(
            compile_same_secret_relation_plan(&repeated_modulus, &context),
            Err(RelationPlanError::InvalidDomain)
        );
        let mut incomplete_prime_local_profile = same_secret_input();
        incomplete_prime_local_profile.commitment_data_modulus_indices = vec![0, 1];
        assert_eq!(
            compile_same_secret_relation_plan(&incomplete_prime_local_profile, &context),
            Err(RelationPlanError::NonCanonicalOrder)
        );
        let mut unsupported_commitment_rank = same_secret_input();
        unsupported_commitment_rank.commitment_module_rank = 2;
        assert_eq!(
            compile_same_secret_relation_plan(&unsupported_commitment_rank, &context),
            Err(RelationPlanError::InvalidDomain)
        );
    }

    pub(in super::super) fn proof_tree_width(variant: &RelationPlanVariant, role: u16) -> usize {
        variant
            .ordered_trees
            .iter()
            .find_map(|tree| match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } if *proof_tree_role == role => Some(ordered_column_ordinals.len()),
                _ => None,
            })
            .expect("proof-created tree role")
    }

    pub(in super::super) fn assert_integer_lift_phase_ownership(variant: &RelationPlanVariant) {
        let tree_roles = variant
            .ordered_trees
            .iter()
            .filter_map(|tree| match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } => Some(
                    ordered_column_ordinals
                        .iter()
                        .map(|column| (*column, *proof_tree_role)),
                ),
                RelationTreeDescriptor::BoundPublic { .. } => None,
            })
            .flatten()
            .collect::<std::collections::BTreeMap<_, _>>();
        let assert_pre_challenge = |column_ordinal: u32| {
            if matches!(
                variant.ordered_columns[column_ordinal as usize].origin,
                RelationColumnOrigin::Prover
            ) {
                assert_eq!(tree_roles.get(&column_ordinal), Some(&1));
            } else {
                assert_ne!(tree_roles.get(&column_ordinal), Some(&2));
            }
        };
        let assert_auxiliary = |column_ordinal: u32| {
            assert!(matches!(
                variant.ordered_columns[column_ordinal as usize].origin,
                RelationColumnOrigin::Prover
            ));
            assert_eq!(tree_roles.get(&column_ordinal), Some(&2));
        };
        for batch in variant.ordered_integer_lift_batches() {
            for binding in &batch.ordered_reversed_column_bindings {
                assert_pre_challenge(binding.source_column_ordinal);
                assert_pre_challenge(binding.reversed_column_ordinal);
                assert_auxiliary(binding.source_prefix_evaluation_column_ordinal);
                assert_auxiliary(binding.reversed_suffix_evaluation_column_ordinal);
            }
            for component in &batch.ordered_components {
                for term in &component.ordered_linear_terms {
                    assert_pre_challenge(term.column_ordinal);
                }
                for product in &component.ordered_full_ring_negacyclic_products {
                    for column in [
                        product.multiplicand_low_column_ordinal,
                        product.multiplicand_high_column_ordinal,
                        product.multiplier_low_column_ordinal,
                        product.multiplier_high_column_ordinal,
                        product.reversed_multiplier_low_column_ordinal,
                        product.reversed_multiplier_high_column_ordinal,
                    ] {
                        assert_pre_challenge(column);
                    }
                    for column in [
                        product.multiplicand_low_suffix_evaluation_column_ordinal,
                        product.multiplicand_high_suffix_evaluation_column_ordinal,
                        product.reversed_multiplier_low_transpose_column_ordinal,
                        product.reversed_multiplier_high_transpose_column_ordinal,
                    ] {
                        assert_auxiliary(column);
                    }
                }
                assert_auxiliary(component.linear_evaluation_column_ordinal);
                assert_auxiliary(component.product_accumulator_column_ordinal);
            }
        }
    }

    pub(in super::super) fn production_context(
        include_plaintext: bool,
    ) -> RelationPlanCheckContext {
        let application_statement_schema_identifier = if include_plaintext {
            crate::foundation::ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        } else {
            crate::foundation::ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
        };
        crate::bgv::proof_suite::selected_profile::selected_relation_plan_check_context(
            application_statement_schema_identifier,
        )
        .expect("selected ordinary-family relation context")
    }

    #[test]
    fn same_secret_production_profile_closes_the_degree_fixed_point() {
        let context = production_context(false);
        let plan = compile_same_secret_relation_plan(
            &crate::bgv::proof_suite::selected_profile::selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &context,
        )
        .expect("production same-secret relation plan");
        plan.check(&context)
            .expect("checked production same-secret relation plan");
        let variant = plan
            .select_variant(None, None)
            .expect("production same-secret relation variant");
        assert_eq!(variant.ordered_columns.len(), 3_110);
        assert_eq!(variant.ordered_constraints.len(), 4_406);
        assert_eq!(variant.ordered_trees.len(), 13);
        assert_eq!(proof_tree_width(variant, 1), 1_968);
        assert_eq!(proof_tree_width(variant, 2), 1_080);
        assert_eq!(variant.trace_domain_size(), 16_384);
        assert_eq!(variant.evaluation_domain_size(), 65_536);
        assert_eq!(variant.ordered_integer_lift_batches().len(), 15);
        assert_eq!(variant.ordered_opening_claims().len(), 4_217);
    }

    #[test]
    fn same_secret_production_relation_contains_the_exact_nonlinear_geometry() {
        let context = production_context(false);
        let compiled = compile_same_secret_relation_with_source_layout(
            &crate::bgv::proof_suite::selected_profile::selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &context,
        )
        .expect("production same-secret relation plan");
        compiled
            .relation_plan
            .check(&context)
            .expect("checked production same-secret relation plan");
        let variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("production same-secret relation variant");

        let mut numerator_instruction_count = 0_usize;
        let mut numerator_multiplication_count = 0_usize;
        let mut numerator_power_count = 0_usize;
        let mut numerator_power_exponents = std::collections::BTreeMap::<u64, usize>::new();
        let mut numerator_length_counts = std::collections::BTreeMap::<usize, usize>::new();
        let mut zeroifier_instruction_count = 0_usize;
        let mut zeroifier_length_counts = std::collections::BTreeMap::<usize, usize>::new();
        let mut injective_program_count = 0_usize;
        let mut injective_instruction_count = 0_usize;
        let mut constraint_role_counts = std::collections::BTreeMap::<u16, usize>::new();
        let mut numerator_degree_counts = std::collections::BTreeMap::<u64, usize>::new();
        let mut zeroifier_degree_counts = std::collections::BTreeMap::<u64, usize>::new();
        let mut quotient_coefficient_count_counts = std::collections::BTreeMap::<u64, usize>::new();
        let mut referenced_column_count_counts = std::collections::BTreeMap::<usize, usize>::new();
        let mut constraint_columns = Vec::<std::collections::BTreeSet<u32>>::new();

        for constraint in &variant.ordered_constraints {
            *constraint_role_counts
                .entry(constraint.constraint_role)
                .or_default() += 1;
            numerator_instruction_count += constraint.numerator_postfix_expression.len();
            *numerator_length_counts
                .entry(constraint.numerator_postfix_expression.len())
                .or_default() += 1;
            for instruction in &constraint.numerator_postfix_expression {
                match instruction {
                    RelationExpressionInstruction::Multiplication => {
                        numerator_multiplication_count += 1;
                    }
                    RelationExpressionInstruction::NonnegativePower(exponent) => {
                        numerator_power_count += 1;
                        *numerator_power_exponents.entry(*exponent).or_default() += 1;
                    }
                    _ => {}
                }
            }
            zeroifier_instruction_count += constraint.zeroifier_postfix_expression.len();
            *zeroifier_length_counts
                .entry(constraint.zeroifier_postfix_expression.len())
                .or_default() += 1;
            injective_program_count += constraint
                .ordered_injective_integer_factor_expressions
                .len();
            injective_instruction_count += constraint
                .ordered_injective_integer_factor_expressions
                .iter()
                .map(Vec::len)
                .sum::<usize>();
            let numerator_shape = check_expression(
                &constraint.numerator_postfix_expression,
                variant,
                &context,
                false,
            )
            .expect("checked numerator shape");
            let zeroifier_shape = check_expression(
                &constraint.zeroifier_postfix_expression,
                variant,
                &context,
                true,
            )
            .expect("checked zeroifier shape");
            let quotient_coefficient_count = numerator_shape
                .degree
                .checked_sub(zeroifier_shape.degree)
                .map_or(1, |quotient_degree| quotient_degree + 1);
            *numerator_degree_counts
                .entry(numerator_shape.degree)
                .or_default() += 1;
            *zeroifier_degree_counts
                .entry(zeroifier_shape.degree)
                .or_default() += 1;
            *quotient_coefficient_count_counts
                .entry(quotient_coefficient_count)
                .or_default() += 1;
            let referenced_column_count =
                expression_column_ordinals(&constraint.numerator_postfix_expression, variant)
                    .expect("checked referenced columns");
            *referenced_column_count_counts
                .entry(referenced_column_count.len())
                .or_default() += 1;
            constraint_columns.push(referenced_column_count);
        }

        let mut first_constraint_by_column = std::collections::BTreeMap::<u32, usize>::new();
        let mut last_constraint_by_column = std::collections::BTreeMap::<u32, usize>::new();
        for (constraint_ordinal, columns) in constraint_columns.iter().enumerate() {
            for column_ordinal in columns {
                first_constraint_by_column
                    .entry(*column_ordinal)
                    .or_insert(constraint_ordinal);
                last_constraint_by_column.insert(*column_ordinal, constraint_ordinal);
            }
        }
        let evaluation_domain_size = variant.evaluation_domain_size() as u128;
        let extension_limb_count = context.challenge_extension_degree as u128;
        let mut maximum_live_column_count = 0_usize;
        let mut maximum_live_transform_bytes = 0_u128;
        let mut maximum_live_constraint_ordinal = 0_usize;
        for constraint_ordinal in 0..constraint_columns.len() {
            let mut live_column_count = 0_usize;
            let mut live_transform_bytes = 0_u128;
            for (column_ordinal, first_constraint) in &first_constraint_by_column {
                if *first_constraint <= constraint_ordinal
                    && last_constraint_by_column[column_ordinal] >= constraint_ordinal
                {
                    live_column_count += 1;
                    let limb_count =
                        match variant.ordered_columns[*column_ordinal as usize].value_type {
                            RelationColumnValueType::BaseField => 1,
                            RelationColumnValueType::ChallengeExtension => extension_limb_count,
                        };
                    live_transform_bytes += evaluation_domain_size * limb_count * 8;
                }
            }
            if live_transform_bytes > maximum_live_transform_bytes {
                maximum_live_column_count = live_column_count;
                maximum_live_transform_bytes = live_transform_bytes;
                maximum_live_constraint_ordinal = constraint_ordinal;
            }
        }
        let maximum_live_columns_for_order = |order: &[usize]| {
            let mut remaining_use_counts = std::collections::BTreeMap::<u32, usize>::new();
            for columns in &constraint_columns {
                for column_ordinal in columns {
                    *remaining_use_counts.entry(*column_ordinal).or_default() += 1;
                }
            }
            let mut active_columns = std::collections::BTreeSet::<u32>::new();
            let mut maximum_live_columns = 0_usize;
            for constraint_ordinal in order {
                let columns = &constraint_columns[*constraint_ordinal];
                active_columns.extend(columns.iter().copied());
                maximum_live_columns = maximum_live_columns.max(active_columns.len());
                for column_ordinal in columns {
                    let remaining_use_count = remaining_use_counts
                        .get_mut(column_ordinal)
                        .expect("scheduled column has a remaining use");
                    *remaining_use_count -= 1;
                    if *remaining_use_count == 0 {
                        remaining_use_counts.remove(column_ordinal);
                        active_columns.remove(column_ordinal);
                    }
                }
            }
            maximum_live_columns
        };
        let mut lexicographic_constraint_order = (0..constraint_columns.len()).collect::<Vec<_>>();
        lexicographic_constraint_order.sort_by(|left, right| {
            constraint_columns[*left]
                .iter()
                .cmp(constraint_columns[*right].iter())
                .then_with(|| left.cmp(right))
        });
        let lexicographic_maximum_live_columns =
            maximum_live_columns_for_order(&lexicographic_constraint_order);
        let mut constraints_by_column = std::collections::BTreeMap::<u32, Vec<usize>>::new();
        let mut greedy_remaining_use_counts = std::collections::BTreeMap::<u32, usize>::new();
        for (constraint_ordinal, columns) in constraint_columns.iter().enumerate() {
            for column_ordinal in columns {
                constraints_by_column
                    .entry(*column_ordinal)
                    .or_default()
                    .push(constraint_ordinal);
                *greedy_remaining_use_counts
                    .entry(*column_ordinal)
                    .or_default() += 1;
            }
        }
        let mut greedy_unprocessed = vec![true; constraint_columns.len()];
        let mut greedy_active_columns = std::collections::BTreeSet::<u32>::new();
        let mut greedy_constraint_order = Vec::with_capacity(constraint_columns.len());
        while greedy_constraint_order.len() < constraint_columns.len() {
            let mut candidates = std::collections::BTreeSet::<usize>::new();
            for column_ordinal in &greedy_active_columns {
                if let Some(column_constraints) = constraints_by_column.get(column_ordinal) {
                    candidates.extend(
                        column_constraints
                            .iter()
                            .copied()
                            .filter(|constraint_ordinal| greedy_unprocessed[*constraint_ordinal]),
                    );
                }
            }
            if candidates.is_empty() {
                candidates.extend(greedy_unprocessed.iter().enumerate().filter_map(
                    |(constraint_ordinal, unprocessed)| unprocessed.then_some(constraint_ordinal),
                ));
            }
            let next_constraint = candidates
                .into_iter()
                .min_by_key(|constraint_ordinal| {
                    let columns = &constraint_columns[*constraint_ordinal];
                    let new_column_count = columns
                        .iter()
                        .filter(|column_ordinal| !greedy_active_columns.contains(column_ordinal))
                        .count();
                    let retiring_column_count = columns
                        .iter()
                        .filter(|column_ordinal| {
                            greedy_remaining_use_counts.get(column_ordinal) == Some(&1)
                        })
                        .count();
                    (
                        new_column_count,
                        greedy_active_columns.len() + new_column_count - retiring_column_count,
                        std::cmp::Reverse(retiring_column_count),
                        *constraint_ordinal,
                    )
                })
                .expect("an unprocessed constraint remains");
            greedy_unprocessed[next_constraint] = false;
            greedy_constraint_order.push(next_constraint);
            for column_ordinal in &constraint_columns[next_constraint] {
                greedy_active_columns.insert(*column_ordinal);
                let remaining_use_count = greedy_remaining_use_counts
                    .get_mut(column_ordinal)
                    .expect("greedy column has a remaining use");
                *remaining_use_count -= 1;
                if *remaining_use_count == 0 {
                    greedy_remaining_use_counts.remove(column_ordinal);
                    greedy_active_columns.remove(column_ordinal);
                }
            }
        }
        let greedy_maximum_live_columns = maximum_live_columns_for_order(&greedy_constraint_order);

        let mut prover_base_column_count = 0_usize;
        let mut prover_extension_column_count = 0_usize;
        let mut bound_base_column_count = 0_usize;
        let mut bound_extension_column_count = 0_usize;
        let mut verifier_base_column_count = 0_usize;
        let mut verifier_extension_column_count = 0_usize;
        let mut source_degree_bound_counts = std::collections::BTreeMap::<u64, usize>::new();
        let mut total_source_coefficient_count = 0_u128;
        for column in &variant.ordered_columns {
            *source_degree_bound_counts
                .entry(column.source_degree_bound_exclusive())
                .or_default() += 1;
            total_source_coefficient_count += u128::from(column.source_degree_bound_exclusive());
            match (column.origin(), column.value_type()) {
                (RelationColumnOrigin::Prover, RelationColumnValueType::BaseField) => {
                    prover_base_column_count += 1;
                }
                (RelationColumnOrigin::Prover, RelationColumnValueType::ChallengeExtension) => {
                    prover_extension_column_count += 1;
                }
                (RelationColumnOrigin::BoundTree { .. }, RelationColumnValueType::BaseField) => {
                    bound_base_column_count += 1;
                }
                (
                    RelationColumnOrigin::BoundTree { .. },
                    RelationColumnValueType::ChallengeExtension,
                ) => {
                    bound_extension_column_count += 1;
                }
                (
                    RelationColumnOrigin::VerifierSequence { .. },
                    RelationColumnValueType::BaseField,
                ) => {
                    verifier_base_column_count += 1;
                }
                (
                    RelationColumnOrigin::VerifierSequence { .. },
                    RelationColumnValueType::ChallengeExtension,
                ) => {
                    verifier_extension_column_count += 1;
                }
            }
        }

        let mut opening_claim_source_counts = std::collections::BTreeMap::<u16, usize>::new();
        let mut opening_claim_point_counts = std::collections::BTreeMap::<u32, usize>::new();
        let mut opening_claims_per_column = std::collections::BTreeMap::<u32, usize>::new();
        for claim in variant.ordered_opening_claims() {
            *opening_claim_source_counts
                .entry(claim.source_class() as u16)
                .or_default() += 1;
            *opening_claim_point_counts
                .entry(claim.opening_point_ordinal())
                .or_default() += 1;
            if let Some(column_ordinal) = claim.column_ordinal() {
                *opening_claims_per_column.entry(column_ordinal).or_default() += 1;
            }
        }
        let opening_claim_multiplicity_counts = opening_claims_per_column.values().fold(
            std::collections::BTreeMap::<usize, usize>::new(),
            |mut counts, multiplicity| {
                *counts.entry(*multiplicity).or_default() += 1;
                counts
            },
        );
        let mut opening_patterns_by_column = std::collections::BTreeMap::<u32, Vec<u32>>::new();
        for claim in variant
            .ordered_opening_claims()
            .iter()
            .filter(|claim| claim.source_class() == RelationOpeningSourceClass::TreeColumn)
        {
            opening_patterns_by_column
                .entry(claim.column_ordinal().expect("tree claim owns a column"))
                .or_default()
                .push(claim.opening_point_ordinal());
        }
        let opening_pattern_counts = opening_patterns_by_column.values().fold(
            std::collections::BTreeMap::<Vec<u32>, usize>::new(),
            |mut counts, pattern| {
                *counts.entry(pattern.clone()).or_default() += 1;
                counts
            },
        );
        let tree_shapes = variant
            .ordered_trees()
            .iter()
            .map(|tree| match tree {
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                } => format!(
                    "proof-created(role={proof_tree_role},width={})",
                    ordered_column_ordinals.len()
                ),
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    ordered_column_ordinals,
                    ..
                } => format!(
                    "bound(kind={},width={})",
                    *construction_kind as u16,
                    ordered_column_ordinals.len()
                ),
            })
            .collect::<Vec<_>>();

        let full_ring_product_count = variant
            .ordered_integer_lift_batches()
            .iter()
            .flat_map(|batch| &batch.ordered_components)
            .map(|component| component.ordered_full_ring_negacyclic_products.len())
            .sum::<usize>();
        let reversed_column_binding_count = variant
            .ordered_integer_lift_batches()
            .iter()
            .map(|batch| batch.ordered_reversed_column_bindings.len())
            .sum::<usize>();
        let shifted_radix_certificate_count = variant
            .ordered_semantic_cells
            .iter()
            .filter(|cell| {
                matches!(
                    &cell.bound_certificate,
                    RelationBoundCertificate::ShiftedRadixRecomposition { .. }
                )
            })
            .count();
        let input_bound_root_count = variant
            .ordered_trees()
            .iter()
            .filter(|tree| {
                matches!(
                    tree,
                    RelationTreeDescriptor::BoundPublic {
                        root_use: BoundTreeRootUse::Input,
                        ..
                    }
                )
            })
            .count();
        let output_bound_root_count = variant
            .ordered_trees()
            .iter()
            .filter(|tree| {
                matches!(
                    tree,
                    RelationTreeDescriptor::BoundPublic {
                        root_use: BoundTreeRootUse::Output,
                        ..
                    }
                )
            })
            .count();

        assert_eq!(compiled.source_layout.ordered_materials.len(), 8);
        assert_eq!(compiled.source_layout.ordered_anchors.len(), 3);
        for common_secret_column in compiled.source_layout.common_secret.coefficients.halves {
            let reference_count = variant
                .ordered_constraints
                .iter()
                .filter(|constraint| {
                    constraint
                        .numerator_postfix_expression
                        .iter()
                        .any(|instruction| {
                            matches!(
                                instruction,
                                RelationExpressionInstruction::ColumnValue {
                                    column_ordinal,
                                    ..
                                } if *column_ordinal == common_secret_column
                            )
                        })
                })
                .count();
            assert!(
                reference_count
                    >= compiled.source_layout.ordered_materials.len()
                        + compiled.source_layout.ordered_anchors.len(),
                "each common-secret half must participate across all public material and anchor families"
            );
        }
        assert_eq!(numerator_instruction_count, 55_248);
        assert_eq!(numerator_multiplication_count, 8_308);
        assert_eq!(numerator_power_count, 360);
        assert_eq!(
            numerator_power_exponents,
            std::collections::BTreeMap::from([(16_384, 360)])
        );
        assert_eq!(
            numerator_length_counts,
            std::collections::BTreeMap::from([
                (1, 120),
                (3, 90),
                (4, 810),
                (6, 222),
                (9, 480),
                (10, 46),
                (11, 1_634),
                (13, 180),
                (14, 196),
                (15, 16),
                (20, 60),
                (23, 60),
                (24, 60),
                (29, 60),
                (33, 30),
                (35, 60),
                (38, 90),
                (41, 30),
                (42, 60),
                (46, 30),
                (48, 10),
                (52, 2),
                (70, 48),
                (72, 12),
            ])
        );
        assert_eq!(zeroifier_instruction_count, 16_450);
        assert_eq!(
            zeroifier_length_counts,
            std::collections::BTreeMap::from([(1, 1_080), (4, 1_260), (5, 2_066)])
        );
        assert_eq!(injective_program_count, 0);
        assert_eq!(injective_instruction_count, 0);
        assert_eq!(
            constraint_role_counts,
            std::collections::BTreeMap::from([(1, 4_406)])
        );
        assert_eq!(
            numerator_degree_counts,
            std::collections::BTreeMap::from([
                (17_065, 2_246),
                (18_431, 80),
                (34_130, 462),
                (51_195, 1_618),
            ])
        );
        assert_eq!(
            zeroifier_degree_counts,
            std::collections::BTreeMap::from([(1, 1_260), (16_383, 1_080), (16_384, 2_066)])
        );
        assert_eq!(
            quotient_coefficient_count_counts,
            std::collections::BTreeMap::from([
                (682, 146),
                (683, 960),
                (2_048, 80),
                (17_065, 1_140),
                (17_747, 222),
                (17_748, 120),
                (34_130, 120),
                (34_812, 1_618),
            ])
        );
        assert_eq!(
            referenced_column_count_counts,
            std::collections::BTreeMap::from([
                (1, 1_960),
                (2, 1_380),
                (3, 422),
                (4, 152),
                (5, 120),
                (6, 120),
                (9, 60),
                (10, 60),
                (11, 60),
                (12, 10),
                (13, 2),
                (18, 60),
            ])
        );
        assert_eq!(first_constraint_by_column.len(), 3_110);
        assert_eq!(maximum_live_column_count, 117);
        assert_eq!(maximum_live_transform_bytes, 1_962_934_272);
        assert_eq!(maximum_live_constraint_ordinal, 2_015);
        assert_eq!(lexicographic_maximum_live_columns, 361);
        assert_eq!(greedy_maximum_live_columns, 162);
        assert_eq!(prover_base_column_count, 3_048);
        assert_eq!(prover_extension_column_count, 0);
        assert_eq!(bound_base_column_count, 44);
        assert_eq!(bound_extension_column_count, 0);
        assert_eq!(verifier_base_column_count, 18);
        assert_eq!(verifier_extension_column_count, 0);
        assert_eq!(total_source_coefficient_count, 53_098_512);
        assert_eq!(
            source_degree_bound_counts,
            std::collections::BTreeMap::from([(16_384, 30), (17_066, 3_048), (18_432, 32),])
        );
        assert_eq!(variant.ordered_opening_points().len(), 3);
        assert_eq!(variant.ordered_opening_claims().len(), 4_217);
        assert_eq!(
            opening_claim_source_counts,
            std::collections::BTreeMap::from([(1, 4_208), (2, 8), (3, 1)])
        );
        assert_eq!(
            opening_claim_point_counts,
            std::collections::BTreeMap::from([(0, 3_101), (1, 1_056), (2, 60)])
        );
        assert_eq!(
            opening_claim_multiplicity_counts,
            std::collections::BTreeMap::from([(1, 1_976), (2, 1_116)])
        );
        assert_eq!(
            opening_pattern_counts,
            std::collections::BTreeMap::from([
                (vec![0], 1_976),
                (vec![0, 1], 1_056),
                (vec![0, 2], 60),
            ])
        );
        assert_eq!(
            tree_shapes,
            [
                "bound(kind=1,width=4)",
                "bound(kind=1,width=4)",
                "bound(kind=1,width=4)",
                "bound(kind=1,width=4)",
                "bound(kind=1,width=4)",
                "bound(kind=1,width=4)",
                "bound(kind=1,width=4)",
                "bound(kind=1,width=4)",
                "bound(kind=2,width=4)",
                "bound(kind=2,width=4)",
                "bound(kind=2,width=4)",
                "proof-created(role=1,width=1968)",
                "proof-created(role=2,width=1080)",
            ]
        );
        assert_eq!(input_bound_root_count, 8);
        assert_eq!(output_bound_root_count, 3);
        assert!(full_ring_product_count > 0);
        assert!(reversed_column_binding_count > 0);
        assert!(shifted_radix_certificate_count > 0);

        assert_eq!(
            numerator_instruction_count,
            variant
                .ordered_constraints
                .iter()
                .map(|constraint| constraint.numerator_postfix_expression.len())
                .sum::<usize>()
        );
        assert_eq!(
            prover_base_column_count
                + prover_extension_column_count
                + bound_base_column_count
                + bound_extension_column_count
                + verifier_base_column_count
                + verifier_extension_column_count,
            variant.ordered_columns.len()
        );
    }

    #[test]
    fn production_same_secret_source_layout_connects_a_representative_radix_column() {
        let context = production_context(false);
        let compiled = compile_same_secret_relation_with_source_layout(
            &crate::bgv::proof_suite::selected_profile::selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &context,
        )
        .expect("production same-secret relation and source layout");
        let source_layout = compiled.source_layout;
        let target = 1_284_u32;
        let mut target_reference_count = 0_usize;
        for material in &source_layout.ordered_materials {
            for (half_ordinal, _) in material.material.iter().enumerate() {
                let comparator = &material.upper_bound_comparators[half_ordinal];
                if comparator.difference_digits.iter().any(|difference| {
                    difference.target_column_ordinal == target
                        || difference.trit_column_ordinals.contains(&target)
                }) || comparator.borrow_column_ordinals.contains(&target)
                {
                    target_reference_count += 1;
                }
            }
        }
        for anchor in &source_layout.ordered_anchors {
            for secret in anchor.opening.hiding_secrets() {
                if secret.source.coefficients.halves.contains(&target) {
                    target_reference_count += 1;
                }
            }
            for error in anchor.opening.hiding_errors() {
                if error.coefficients.halves.contains(&target) {
                    target_reference_count += 1;
                }
            }
            for commitment in &anchor.commitments {
                if commitment.halves.contains(&target) {
                    target_reference_count += 1;
                }
            }
            for row in &anchor.first_matrix {
                for matrix_entry in row {
                    if matrix_entry.halves.contains(&target) {
                        target_reference_count += 1;
                    }
                }
            }
            for matrix_entry in &anchor.second_matrix {
                if matrix_entry.halves.contains(&target) {
                    target_reference_count += 1;
                }
            }
            for quotient in anchor.quotients.rows() {
                if quotient.contains(&target) {
                    target_reference_count += 1;
                }
            }
        }
        for (source, digits) in &source_layout.exact_radix_digits_by_column {
            if *source == target || digits.contains(&target) {
                target_reference_count += 1;
            }
        }
        let variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("production same-secret relation variant");
        for semantic_cell in &variant.ordered_semantic_cells {
            let certificate_mentions_target = match &semantic_cell.bound_certificate {
                RelationBoundCertificate::UnsignedRadixRecomposition {
                    ordered_digit_column_ordinals,
                    ..
                }
                | RelationBoundCertificate::ShiftedRadixRecomposition {
                    ordered_digit_column_ordinals,
                    ..
                } => ordered_digit_column_ordinals.contains(&target),
                RelationBoundCertificate::CanonicalModulusRecomposition {
                    ordered_digit_column_ordinals,
                    ordered_difference_digit_column_ordinals,
                    ordered_borrow_column_ordinals,
                    ..
                } => {
                    ordered_digit_column_ordinals.contains(&target)
                        || ordered_difference_digit_column_ordinals.contains(&target)
                        || ordered_borrow_column_ordinals.contains(&target)
                }
                _ => false,
            };
            if semantic_cell.column_ordinal == target || certificate_mentions_target {
                target_reference_count += 1;
            }
        }
        for batch in variant.ordered_integer_lift_batches() {
            for component in &batch.ordered_components {
                if component
                    .ordered_linear_terms
                    .iter()
                    .any(|term| term.column_ordinal == target)
                    || component.linear_evaluation_column_ordinal == target
                    || component.product_accumulator_column_ordinal == target
                {
                    target_reference_count += 1;
                }
            }
        }
        assert!(target_reference_count > 0);
        let target_descriptor = variant
            .ordered_columns
            .get(target as usize)
            .expect("representative production radix column");
        assert!(matches!(
            target_descriptor.origin,
            RelationColumnOrigin::Prover
        ));
        assert_eq!(
            target_descriptor.value_type,
            RelationColumnValueType::BaseField
        );
        assert_eq!(target_descriptor.source_degree_bound_exclusive, 17_066);
    }
}
