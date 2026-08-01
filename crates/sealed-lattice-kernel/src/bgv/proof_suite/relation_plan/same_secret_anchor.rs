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
    use std::collections::{BTreeMap, BTreeSet};

    use super::super::key_relation::{
        EXACT_INTEGER_LIFT_RADIX, MATERIAL_DIGIT_RADIX, fixed_radix_digits, integer_column_term,
        integer_constant_term, integer_scaled_column_term, sum_integer_terms,
    };
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
    pub(in super::super) const TEST_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 1_024;

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
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                maximum_two_adic_order / TEST_EVALUATION_DOMAIN_SIZE,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            out_of_domain_point_count: 1,
            quotient_component_count: 4,
            quotient_component_degree_bound_exclusive: 1_024,
            phase_column_query_coordinate_count: 8,
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
            .derived_relation_prefix_challenge_catalog(context)
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
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum SameSecretSemanticCategory {
        CommonSecretTernary,
        NegativeIndicator,
        VssInputMaterialEncodingAndBounds,
        VssToCommonSecretEquality,
        AnchorOpenings,
        AnchorCommitmentOutputs,
        PublicBdlopMatrices,
        ModularQuotientWitnesses,
        IntegerLiftReversalBindings,
        ExactCarryEncodings,
        FullRingProductIdentities,
        ComponentAccumulatorIdentities,
        RelationQuotientComponents,
        BatchMask,
    }

    const SAME_SECRET_SEMANTIC_CATEGORY_COUNTS: &[(
        SameSecretSemanticCategory,
        usize,
        usize,
        usize,
    )] = &[
        (SameSecretSemanticCategory::CommonSecretTernary, 2, 2, 2),
        (SameSecretSemanticCategory::NegativeIndicator, 2, 2, 2),
        (
            SameSecretSemanticCategory::VssInputMaterialEncodingAndBounds,
            944,
            976,
            944,
        ),
        (
            SameSecretSemanticCategory::VssToCommonSecretEquality,
            0,
            16,
            0,
        ),
        (SameSecretSemanticCategory::AnchorOpenings, 18, 18, 18),
        (
            SameSecretSemanticCategory::AnchorCommitmentOutputs,
            276,
            276,
            276,
        ),
        (
            SameSecretSemanticCategory::PublicBdlopMatrices,
            414,
            414,
            432,
        ),
        (
            SameSecretSemanticCategory::ModularQuotientWitnesses,
            216,
            216,
            216,
        ),
        (
            SameSecretSemanticCategory::IntegerLiftReversalBindings,
            132,
            300,
            252,
        ),
        (
            SameSecretSemanticCategory::ExactCarryEncodings,
            146,
            146,
            146,
        ),
        (
            SameSecretSemanticCategory::FullRingProductIdentities,
            540,
            1_080,
            1_080,
        ),
        (
            SameSecretSemanticCategory::ComponentAccumulatorIdentities,
            240,
            600,
            480,
        ),
        (
            SameSecretSemanticCategory::RelationQuotientComponents,
            0,
            0,
            8,
        ),
        (SameSecretSemanticCategory::BatchMask, 0, 0, 1),
    ];

    #[derive(Default)]
    struct SameSecretSemanticOwnership {
        columns: BTreeMap<SameSecretSemanticCategory, BTreeSet<u32>>,
        constraints: BTreeMap<SameSecretSemanticCategory, BTreeSet<u32>>,
        opening_claims: BTreeMap<SameSecretSemanticCategory, BTreeSet<u32>>,
    }

    impl SameSecretSemanticOwnership {
        fn constraint_set_mut(
            &mut self,
            category: SameSecretSemanticCategory,
        ) -> &mut BTreeSet<u32> {
            self.constraints.entry(category).or_default()
        }

        fn opening_claim_set_mut(
            &mut self,
            category: SameSecretSemanticCategory,
        ) -> &mut BTreeSet<u32> {
            self.opening_claims.entry(category).or_default()
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct SameSecretConstraintShape {
        numerator_postfix_expression: Vec<RelationExpressionInstruction>,
        zeroifier_postfix_expression: Vec<RelationExpressionInstruction>,
        enforce_proof_base_field_no_wrap: bool,
    }

    type SameSecretConstraintShapeIndex = BTreeMap<SameSecretConstraintShape, Vec<u32>>;

    fn same_secret_constraint_shape(
        numerator_postfix_expression: &[RelationExpressionInstruction],
        zeroifier_postfix_expression: &[RelationExpressionInstruction],
        enforce_proof_base_field_no_wrap: bool,
    ) -> SameSecretConstraintShape {
        SameSecretConstraintShape {
            numerator_postfix_expression: numerator_postfix_expression.to_vec(),
            zeroifier_postfix_expression: zeroifier_postfix_expression.to_vec(),
            enforce_proof_base_field_no_wrap,
        }
    }

    fn same_secret_constraint_shape_index(
        variant: &RelationPlanVariant,
    ) -> SameSecretConstraintShapeIndex {
        let mut constraint_ordinals_by_shape = SameSecretConstraintShapeIndex::new();
        for (constraint_ordinal, constraint) in variant.ordered_constraints.iter().enumerate() {
            if !constraint
                .ordered_injective_integer_factor_expressions
                .is_empty()
            {
                continue;
            }
            constraint_ordinals_by_shape
                .entry(same_secret_constraint_shape(
                    &constraint.numerator_postfix_expression,
                    &constraint.zeroifier_postfix_expression,
                    constraint.enforce_proof_base_field_no_wrap,
                ))
                .or_default()
                .push(u32::try_from(constraint_ordinal).expect("constraint ordinal fits u32"));
        }
        constraint_ordinals_by_shape
    }

    fn extend_split_integer_vector_columns(
        columns: &mut BTreeSet<u32>,
        vector: SplitIntegerVector,
    ) {
        columns.extend(vector.halves);
    }

    fn bound_certificate_dependency_columns(certificate: &RelationBoundCertificate) -> Vec<u32> {
        match certificate {
            RelationBoundCertificate::UnsignedRadixRecomposition {
                ordered_digit_column_ordinals,
                ..
            }
            | RelationBoundCertificate::ShiftedRadixRecomposition {
                ordered_digit_column_ordinals,
                ..
            } => ordered_digit_column_ordinals.clone(),
            RelationBoundCertificate::CanonicalModulusRecomposition {
                ordered_digit_column_ordinals,
                ordered_difference_digit_column_ordinals,
                ordered_borrow_column_ordinals,
                ..
            } => ordered_digit_column_ordinals
                .iter()
                .chain(ordered_difference_digit_column_ordinals)
                .chain(ordered_borrow_column_ordinals)
                .copied()
                .collect(),
            RelationBoundCertificate::Trinary { .. }
            | RelationBoundCertificate::Binary { .. }
            | RelationBoundCertificate::FiniteIntegerSet { .. } => Vec::new(),
        }
    }

    fn expand_same_secret_column_dependencies(
        variant: &RelationPlanVariant,
        exact_radix_digits_by_column: &ExactRadixDigitColumnCatalog,
        columns: &mut BTreeSet<u32>,
    ) {
        loop {
            let previous_count = columns.len();
            for (source_column_ordinal, exact_digit_column_ordinals) in exact_radix_digits_by_column
            {
                if columns.contains(source_column_ordinal) {
                    columns.extend(exact_digit_column_ordinals.iter().copied());
                }
            }
            for semantic_cell in &variant.ordered_semantic_cells {
                if columns.contains(&semantic_cell.column_ordinal) {
                    columns.extend(bound_certificate_dependency_columns(
                        &semantic_cell.bound_certificate,
                    ));
                }
            }
            if columns.len() == previous_count {
                break;
            }
        }
    }

    fn same_secret_column_ownership(
        variant: &RelationPlanVariant,
        source_layout: &SameSecretSourceLayout,
    ) -> BTreeMap<SameSecretSemanticCategory, BTreeSet<u32>> {
        let mut ownership = BTreeMap::<SameSecretSemanticCategory, BTreeSet<u32>>::new();

        extend_split_integer_vector_columns(
            ownership
                .entry(SameSecretSemanticCategory::CommonSecretTernary)
                .or_default(),
            source_layout.common_secret.coefficients,
        );
        ownership
            .entry(SameSecretSemanticCategory::NegativeIndicator)
            .or_default()
            .extend(source_layout.negative_indicator);

        let material_columns = ownership
            .entry(SameSecretSemanticCategory::VssInputMaterialEncodingAndBounds)
            .or_default();
        for material in &source_layout.ordered_materials {
            for (bounded_material, comparator) in material
                .material
                .iter()
                .zip(&material.upper_bound_comparators)
            {
                material_columns.extend(
                    bounded_material
                        .ordered_digit_column_ordinals()
                        .iter()
                        .copied(),
                );
                for difference_digit in &comparator.difference_digits {
                    material_columns.insert(difference_digit.target_column_ordinal);
                    material_columns.extend(difference_digit.trit_column_ordinals.iter().copied());
                }
                material_columns.extend(comparator.borrow_column_ordinals.iter().copied());
            }
        }

        for anchor in &source_layout.ordered_anchors {
            let opening_columns = ownership
                .entry(SameSecretSemanticCategory::AnchorOpenings)
                .or_default();
            for hiding_secret in anchor.opening.hiding_secrets() {
                extend_split_integer_vector_columns(
                    opening_columns,
                    hiding_secret.source.coefficients,
                );
            }
            for hiding_error in anchor.opening.hiding_errors() {
                extend_split_integer_vector_columns(opening_columns, hiding_error.coefficients);
            }

            let commitment_columns = ownership
                .entry(SameSecretSemanticCategory::AnchorCommitmentOutputs)
                .or_default();
            for commitment in &anchor.commitments {
                extend_split_integer_vector_columns(commitment_columns, *commitment);
            }

            let matrix_columns = ownership
                .entry(SameSecretSemanticCategory::PublicBdlopMatrices)
                .or_default();
            for matrix_row in &anchor.first_matrix {
                for matrix_entry in matrix_row {
                    extend_split_integer_vector_columns(matrix_columns, *matrix_entry);
                }
            }
            for matrix_entry in &anchor.second_matrix {
                extend_split_integer_vector_columns(matrix_columns, *matrix_entry);
            }

            let quotient_columns = ownership
                .entry(SameSecretSemanticCategory::ModularQuotientWitnesses)
                .or_default();
            for quotient_row in anchor.quotients.rows() {
                quotient_columns.extend(*quotient_row);
            }
        }

        let mut reversal_columns = BTreeSet::new();
        let mut full_ring_product_columns = BTreeSet::new();
        let mut component_columns = BTreeSet::new();
        let mut exact_carry_columns = BTreeSet::new();
        for batch in variant.ordered_integer_lift_batches() {
            for binding in &batch.ordered_reversed_column_bindings {
                reversal_columns.extend([
                    binding.reversed_column_ordinal,
                    binding.source_prefix_evaluation_column_ordinal,
                    binding.reversed_suffix_evaluation_column_ordinal,
                ]);
            }
            for component in &batch.ordered_components {
                for product in &component.ordered_full_ring_negacyclic_products {
                    full_ring_product_columns.extend([
                        product.multiplicand_low_suffix_evaluation_column_ordinal,
                        product.multiplicand_high_suffix_evaluation_column_ordinal,
                        product.reversed_multiplier_low_transpose_column_ordinal,
                        product.reversed_multiplier_high_transpose_column_ordinal,
                    ]);
                }
                component_columns.extend([
                    component.linear_evaluation_column_ordinal,
                    component.product_accumulator_column_ordinal,
                ]);
                for term in &component.ordered_linear_terms {
                    if term.negative
                        && term.column_offset == 0
                        && term.coefficient
                            == RelationIntegerLiftCoefficient::Constant(EXACT_INTEGER_LIFT_RADIX)
                    {
                        exact_carry_columns.insert(term.column_ordinal);
                    }
                }
            }
        }
        ownership.insert(
            SameSecretSemanticCategory::IntegerLiftReversalBindings,
            reversal_columns,
        );
        ownership.insert(
            SameSecretSemanticCategory::FullRingProductIdentities,
            full_ring_product_columns,
        );
        ownership.insert(
            SameSecretSemanticCategory::ComponentAccumulatorIdentities,
            component_columns,
        );
        ownership.insert(
            SameSecretSemanticCategory::ExactCarryEncodings,
            exact_carry_columns,
        );

        for columns in ownership.values_mut() {
            expand_same_secret_column_dependencies(
                variant,
                &source_layout.exact_radix_digits_by_column,
                columns,
            );
        }
        ownership
    }

    fn bound_certificate_constraint_ordinals(certificate: &RelationBoundCertificate) -> Vec<u32> {
        match certificate {
            RelationBoundCertificate::Trinary { constraint_ordinal }
            | RelationBoundCertificate::Binary { constraint_ordinal }
            | RelationBoundCertificate::UnsignedRadixRecomposition {
                constraint_ordinal, ..
            }
            | RelationBoundCertificate::ShiftedRadixRecomposition {
                constraint_ordinal, ..
            }
            | RelationBoundCertificate::FiniteIntegerSet {
                constraint_ordinal, ..
            } => vec![*constraint_ordinal],
            RelationBoundCertificate::CanonicalModulusRecomposition {
                recomposition_constraint_ordinal,
                ordered_comparator_constraint_ordinals,
                ..
            } => std::iter::once(*recomposition_constraint_ordinal)
                .chain(ordered_comparator_constraint_ordinals.iter().copied())
                .collect(),
        }
    }

    fn constraint_ordinals_matching_shape<'index>(
        constraint_shape_index: &'index SameSecretConstraintShapeIndex,
        numerator_postfix_expression: &[RelationExpressionInstruction],
        zeroifier_postfix_expression: &[RelationExpressionInstruction],
        enforce_proof_base_field_no_wrap: bool,
    ) -> &'index [u32] {
        let constraint_shape = same_secret_constraint_shape(
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
        );
        constraint_shape_index
            .get(&constraint_shape)
            .map_or(&[][..], Vec::as_slice)
    }

    fn claim_matching_constraint(
        constraint_shape_index: &SameSecretConstraintShapeIndex,
        ownership: &mut SameSecretSemanticOwnership,
        category: SameSecretSemanticCategory,
        numerator_postfix_expression: &[RelationExpressionInstruction],
        zeroifier_postfix_expression: &[RelationExpressionInstruction],
        enforce_proof_base_field_no_wrap: bool,
    ) {
        let matches = constraint_ordinals_matching_shape(
            constraint_shape_index,
            numerator_postfix_expression,
            zeroifier_postfix_expression,
            enforce_proof_base_field_no_wrap,
        );
        assert_eq!(
            matches.len(),
            1,
            "generated {category:?} constraint has unique compiled ownership"
        );
        assert!(
            ownership.constraint_set_mut(category).insert(matches[0]),
            "generated {category:?} constraint is claimed once"
        );
    }

    fn claim_integer_lift_constraint_programs(
        constraint_shape_index: &SameSecretConstraintShapeIndex,
        ownership: &mut SameSecretSemanticOwnership,
        category: SameSecretSemanticCategory,
        programs: impl IntoIterator<
            Item = super::super::integer_lift::RelationIntegerLiftConstraintProgram,
        >,
    ) {
        for program in programs {
            claim_matching_constraint(
                constraint_shape_index,
                ownership,
                category,
                &program.numerator_postfix_expression,
                &program.zeroifier_postfix_expression,
                false,
            );
        }
    }

    fn claim_same_secret_bound_constraints(
        variant: &RelationPlanVariant,
        constraint_shape_index: &SameSecretConstraintShapeIndex,
        source_layout: &SameSecretSourceLayout,
        context: &RelationPlanCheckContext,
        ownership: &mut SameSecretSemanticOwnership,
    ) {
        let column_categories = ownership
            .columns
            .iter()
            .flat_map(|(category, columns)| {
                columns
                    .iter()
                    .copied()
                    .map(|column_ordinal| (column_ordinal, *category))
            })
            .collect::<BTreeMap<_, _>>();
        for semantic_cell in &variant.ordered_semantic_cells {
            let category = *column_categories
                .get(&semantic_cell.column_ordinal)
                .expect("every semantic cell belongs to one semantic category");
            ownership
                .constraint_set_mut(category)
                .extend(bound_certificate_constraint_ordinals(
                    &semantic_cell.bound_certificate,
                ));
        }

        let full_trace_zeroifier = full_trace_zeroifier_expression(variant.trace_domain_size());
        for (target_column_ordinal, exact_digit_column_ordinals) in
            &source_layout.exact_radix_digits_by_column
        {
            let category = *column_categories
                .get(target_column_ordinal)
                .expect("every exact-radix target belongs to one semantic category");
            let expression = radix_recomposition_expression(
                *target_column_ordinal,
                EXACT_INTEGER_LIFT_RADIX,
                None,
                exact_digit_column_ordinals,
                context.base_field_modulus,
            )
            .expect("exact-radix target recomposition expression");
            claim_matching_constraint(
                constraint_shape_index,
                ownership,
                category,
                &expression,
                &full_trace_zeroifier,
                true,
            );
        }

        for material in &source_layout.ordered_materials {
            let maximum_digits = fixed_radix_digits(
                context
                    .resolved_modulus(SuiteModulusReference::data(material.data_modulus_index))
                    .expect("material modulus")
                    - 1,
                2,
                MATERIAL_DIGIT_RADIX,
            )
            .expect("material upper-bound digits");
            for (bounded_material, comparator) in material
                .material
                .iter()
                .zip(&material.upper_bound_comparators)
            {
                let value_columns = bounded_material.ordered_digit_column_ordinals();
                assert_eq!(value_columns.len(), maximum_digits.len());
                assert_eq!(comparator.difference_digits.len(), maximum_digits.len());
                for digit_ordinal in 0..maximum_digits.len() {
                    let mut terms =
                        vec![integer_constant_term(maximum_digits[digit_ordinal], false)];
                    terms.push(integer_column_term(value_columns[digit_ordinal], true));
                    if digit_ordinal > 0 {
                        terms.push(integer_column_term(
                            comparator.borrow_column_ordinals[digit_ordinal - 1],
                            true,
                        ));
                    }
                    if digit_ordinal + 1 < maximum_digits.len() {
                        terms.push(integer_scaled_column_term(
                            comparator.borrow_column_ordinals[digit_ordinal],
                            MATERIAL_DIGIT_RADIX,
                            false,
                        ));
                    }
                    terms.push(integer_column_term(
                        comparator.difference_digits[digit_ordinal].target_column_ordinal,
                        true,
                    ));
                    let expression = sum_integer_terms(terms)
                        .expect("material upper-bound comparator expression");
                    claim_matching_constraint(
                        constraint_shape_index,
                        ownership,
                        SameSecretSemanticCategory::VssInputMaterialEncodingAndBounds,
                        &expression,
                        &full_trace_zeroifier,
                        true,
                    );
                }
            }
        }
    }

    fn same_secret_equality_expression(
        source_layout: &SameSecretSourceLayout,
        material: &SameSecretMaterialSourceLayout,
        half_ordinal: usize,
    ) -> Vec<RelationExpressionInstruction> {
        let material_digits = material.material[half_ordinal].ordered_digit_column_ordinals();
        assert_eq!(material_digits.len(), 2);
        vec![
            unrotated_column_expression(material_digits[0]),
            unrotated_column_expression(material_digits[1]),
            RelationExpressionInstruction::BaseFieldConstant(MATERIAL_DIGIT_RADIX),
            RelationExpressionInstruction::Multiplication,
            RelationExpressionInstruction::Addition,
            unrotated_column_expression(
                source_layout.common_secret.coefficients.halves[half_ordinal],
            ),
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
            RelationExpressionInstruction::BaseFieldConstant(1),
            RelationExpressionInstruction::Addition,
            unrotated_column_expression(source_layout.negative_indicator[half_ordinal]),
            RelationExpressionInstruction::NonNativeModulusConstant {
                modulus_reference: SuiteModulusReference::data(material.data_modulus_index),
                multiplier: 1,
            },
            RelationExpressionInstruction::Multiplication,
            RelationExpressionInstruction::Negation,
            RelationExpressionInstruction::Addition,
        ]
    }

    fn claim_same_secret_equality_constraints(
        variant: &RelationPlanVariant,
        constraint_shape_index: &SameSecretConstraintShapeIndex,
        source_layout: &SameSecretSourceLayout,
        ownership: &mut SameSecretSemanticOwnership,
    ) {
        let full_trace_zeroifier = full_trace_zeroifier_expression(variant.trace_domain_size());
        for material in &source_layout.ordered_materials {
            for half_ordinal in 0..2 {
                let expression =
                    same_secret_equality_expression(source_layout, material, half_ordinal);
                claim_matching_constraint(
                    constraint_shape_index,
                    ownership,
                    SameSecretSemanticCategory::VssToCommonSecretEquality,
                    &expression,
                    &full_trace_zeroifier,
                    true,
                );
            }
        }
    }

    fn claim_same_secret_integer_lift_constraints(
        variant: &RelationPlanVariant,
        constraint_shape_index: &SameSecretConstraintShapeIndex,
        context: &RelationPlanCheckContext,
        ownership: &mut SameSecretSemanticOwnership,
    ) -> (usize, usize, usize) {
        use super::super::integer_lift::{
            integer_lift_component_constraint_programs,
            integer_lift_full_ring_product_constraint_programs, integer_lift_point_zeroifier,
            integer_lift_reversed_column_binding_constraint_programs,
            integer_lift_theta_expression, integer_lift_trace_except_rows_zeroifier,
        };

        let trace_domain_size = variant.trace_domain_size();
        let last_row = trace_domain_size - 1;
        let point_zero = integer_lift_point_zeroifier(
            0,
            trace_domain_size,
            variant.evaluation_domain_size(),
            context,
        )
        .expect("integer-lift zero-row zeroifier");
        let point_last = integer_lift_point_zeroifier(
            last_row,
            trace_domain_size,
            variant.evaluation_domain_size(),
            context,
        )
        .expect("integer-lift last-row zeroifier");
        let except_zero = integer_lift_trace_except_rows_zeroifier(
            &[0],
            trace_domain_size,
            variant.evaluation_domain_size(),
            context,
        )
        .expect("integer-lift except-zero zeroifier");
        let except_last = integer_lift_trace_except_rows_zeroifier(
            &[last_row],
            trace_domain_size,
            variant.evaluation_domain_size(),
            context,
        )
        .expect("integer-lift except-last zeroifier");

        let mut full_ring_product_count = 0_usize;
        let mut generated_full_ring_program_count = 0_usize;
        let mut distinct_full_ring_program_count = 0_usize;
        for batch in variant.ordered_integer_lift_batches() {
            assert!(
                batch
                    .ordered_negacyclic_automorphism_permutations
                    .is_empty()
            );
            let modulus_ordinal = variant
                .non_native_modulus_ordinal(batch.modulus_reference())
                .expect("integer-lift modulus ordinal");
            let theta_expression =
                integer_lift_theta_expression(modulus_ordinal, batch.challenge_ordinal());
            for binding in &batch.ordered_reversed_column_bindings {
                claim_integer_lift_constraint_programs(
                    constraint_shape_index,
                    ownership,
                    SameSecretSemanticCategory::IntegerLiftReversalBindings,
                    integer_lift_reversed_column_binding_constraint_programs(
                        binding,
                        &theta_expression,
                        point_zero.clone(),
                        point_last.clone(),
                        except_zero.clone(),
                        except_last.clone(),
                    ),
                );
            }
            let mut distinct_full_ring_program_shapes = BTreeSet::new();
            for component in &batch.ordered_components {
                assert!(component.ordered_convolution_products.is_empty());
                for product in &component.ordered_full_ring_negacyclic_products {
                    full_ring_product_count += 1;
                    let programs = integer_lift_full_ring_product_constraint_programs(
                        product,
                        &theta_expression,
                        trace_domain_size,
                        point_last.clone(),
                        except_last.clone(),
                    )
                    .expect("full-ring product constraint programs");
                    generated_full_ring_program_count += programs.len();
                    for program in programs {
                        let shape = same_secret_constraint_shape(
                            &program.numerator_postfix_expression,
                            &program.zeroifier_postfix_expression,
                            false,
                        );
                        if distinct_full_ring_program_shapes.insert(shape) {
                            distinct_full_ring_program_count += 1;
                            claim_matching_constraint(
                                constraint_shape_index,
                                ownership,
                                SameSecretSemanticCategory::FullRingProductIdentities,
                                &program.numerator_postfix_expression,
                                &program.zeroifier_postfix_expression,
                                false,
                            );
                        }
                    }
                }
                claim_integer_lift_constraint_programs(
                    constraint_shape_index,
                    ownership,
                    SameSecretSemanticCategory::ComponentAccumulatorIdentities,
                    integer_lift_component_constraint_programs(
                        component,
                        batch.modulus_reference(),
                        &theta_expression,
                        point_zero.clone(),
                        point_last.clone(),
                        except_last.clone(),
                        context,
                    )
                    .expect("component accumulator constraint programs"),
                );
            }
        }
        (
            full_ring_product_count,
            generated_full_ring_program_count,
            distinct_full_ring_program_count,
        )
    }

    fn claim_same_secret_opening_claims(
        variant: &RelationPlanVariant,
        ownership: &mut SameSecretSemanticOwnership,
    ) {
        let column_categories = ownership
            .columns
            .iter()
            .flat_map(|(category, columns)| {
                columns
                    .iter()
                    .copied()
                    .map(|column_ordinal| (column_ordinal, *category))
            })
            .collect::<BTreeMap<_, _>>();
        for (opening_claim_ordinal, claim) in variant.ordered_opening_claims().iter().enumerate() {
            let category = match claim.source_class() {
                RelationOpeningSourceClass::TreeColumn => {
                    let column_ordinal = claim
                        .column_ordinal()
                        .expect("tree-column opening names its column");
                    *column_categories
                        .get(&column_ordinal)
                        .expect("opened tree column has semantic ownership")
                }
                RelationOpeningSourceClass::Quotient => {
                    assert!(claim.column_ordinal().is_none());
                    SameSecretSemanticCategory::RelationQuotientComponents
                }
                RelationOpeningSourceClass::BatchMask => {
                    assert!(claim.column_ordinal().is_none());
                    SameSecretSemanticCategory::BatchMask
                }
            };
            assert!(ownership.opening_claim_set_mut(category).insert(
                u32::try_from(opening_claim_ordinal).expect("opening claim ordinal fits u32")
            ));
        }
    }

    fn assert_exact_semantic_partition(
        ownership: &BTreeMap<SameSecretSemanticCategory, BTreeSet<u32>>,
        total_item_count: usize,
        item_kind: &str,
    ) {
        let mut union = BTreeSet::new();
        for (category, category_items) in ownership {
            assert!(
                union.is_disjoint(category_items),
                "{item_kind} semantic category {category:?} overlaps an earlier category"
            );
            union.extend(category_items);
        }
        let expected_union = (0..total_item_count)
            .map(|ordinal| u32::try_from(ordinal).expect("semantic ordinal fits u32"))
            .collect::<BTreeSet<_>>();
        assert_eq!(union, expected_union, "complete {item_kind} semantic union");
    }

    #[test]
    fn same_secret_production_anchor_descriptors_reuse_the_vss_common_secret_columns() {
        let context = production_context(false);
        let compiled = compile_same_secret_relation_with_source_layout(
            &crate::bgv::proof_suite::selected_profile::selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &context,
        )
        .expect("compiled production same-secret relation and source layout");
        compiled
            .relation_plan
            .check(&context)
            .expect("production same-secret relation plan is valid");
        let variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("production same-secret relation variant");
        let constraint_shape_index = same_secret_constraint_shape_index(variant);
        let common_secret_columns = compiled
            .source_layout
            .common_secret
            .coefficients
            .halves
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(common_secret_columns.len(), 2);
        for common_secret_column in &common_secret_columns {
            assert!(
                compiled
                    .source_layout
                    .exact_radix_digits_by_column
                    .iter()
                    .all(|(source_column, _)| source_column != common_secret_column),
                "shifted common-secret columns remain direct integer-lift terms"
            );
        }

        let full_trace_zeroifier = full_trace_zeroifier_expression(variant.trace_domain_size());
        let mut vss_equality_common_secret_columns = BTreeSet::new();
        for material in &compiled.source_layout.ordered_materials {
            for half_ordinal in 0..2 {
                let equality_expression = same_secret_equality_expression(
                    &compiled.source_layout,
                    material,
                    half_ordinal,
                );
                let matching_constraint_ordinals = constraint_ordinals_matching_shape(
                    &constraint_shape_index,
                    &equality_expression,
                    &full_trace_zeroifier,
                    true,
                );
                assert_eq!(
                    matching_constraint_ordinals.len(),
                    1,
                    "each VSS equality has one compiled constraint"
                );
                let constraint =
                    &variant.ordered_constraints[usize::try_from(matching_constraint_ordinals[0])
                        .expect("constraint ordinal fits usize")];
                let queried_common_secret_columns = constraint
                    .numerator_postfix_expression
                    .iter()
                    .filter_map(|instruction| match instruction {
                        RelationExpressionInstruction::ColumnValue { column_ordinal, .. }
                            if common_secret_columns.contains(column_ordinal) =>
                        {
                            Some(*column_ordinal)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let expected_common_secret_column =
                    compiled.source_layout.common_secret.coefficients.halves[half_ordinal];
                assert_eq!(
                    queried_common_secret_columns,
                    vec![expected_common_secret_column],
                    "VSS equality queries its common-secret half exactly once"
                );
                vss_equality_common_secret_columns.insert(expected_common_secret_column);
            }
        }
        assert_eq!(vss_equality_common_secret_columns, common_secret_columns);

        let mut integer_lift_batches_by_key = BTreeMap::new();
        for batch in variant.ordered_integer_lift_batches() {
            assert!(
                integer_lift_batches_by_key
                    .insert(
                        (batch.modulus_reference(), batch.challenge_ordinal()),
                        batch,
                    )
                    .is_none(),
                "integer-lift batch keys are unique"
            );
        }
        let expected_batch_count = compiled
            .source_layout
            .ordered_anchors
            .len()
            .checked_mul(usize::from(context.non_native_theta_repetition_count))
            .expect("integer-lift batch count fits usize");
        assert_eq!(integer_lift_batches_by_key.len(), expected_batch_count);

        let mut anchor_common_secret_columns = BTreeSet::new();
        for anchor in &compiled.source_layout.ordered_anchors {
            let final_hiding_secret = anchor
                .opening
                .hiding_secrets()
                .last()
                .expect("anchor has its final hiding secret");
            for challenge_ordinal in 0..context.non_native_theta_repetition_count {
                let batch = integer_lift_batches_by_key
                    .get(&(
                        SuiteModulusReference::data(anchor.data_modulus_index),
                        challenge_ordinal,
                    ))
                    .expect("every anchor and theta repetition has an integer-lift batch");
                for half_ordinal in 0..2 {
                    let hiding_secret_column =
                        final_hiding_secret.source.coefficients.halves[half_ordinal];
                    let expected_hiding_secret_term = RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: hiding_secret_column,
                        column_offset: final_hiding_secret.source.offset,
                        coefficient: RelationIntegerLiftCoefficient::Constant(1),
                    };
                    let matching_components = batch
                        .ordered_components
                        .iter()
                        .filter(|component| {
                            component
                                .ordered_linear_terms
                                .contains(&expected_hiding_secret_term)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        matching_components.len(),
                        1,
                        "each anchor half has one final component"
                    );
                    let final_component = matching_components[0];
                    let common_secret_column =
                        compiled.source_layout.common_secret.coefficients.halves[half_ordinal];
                    let expected_common_secret_term = RelationIntegerLiftLinearTermDescriptor {
                        negative: true,
                        column_ordinal: common_secret_column,
                        column_offset: compiled.source_layout.common_secret.offset,
                        coefficient: RelationIntegerLiftCoefficient::Constant(1),
                    };
                    assert!(
                        final_component
                            .ordered_linear_terms
                            .contains(&expected_common_secret_term),
                        "anchor final component uses the corresponding common-secret half"
                    );
                    let shifted_secret_terms = final_component
                        .ordered_linear_terms
                        .iter()
                        .filter(|term| {
                            term.negative
                                && term.column_offset == compiled.source_layout.common_secret.offset
                                && term.coefficient == RelationIntegerLiftCoefficient::Constant(1)
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        shifted_secret_terms.len(),
                        2,
                        "the anchor final component has two shifted secret terms"
                    );
                    let shifted_secret_term_columns = shifted_secret_terms
                        .into_iter()
                        .map(|term| term.column_ordinal)
                        .collect::<BTreeSet<_>>();
                    assert_eq!(
                        shifted_secret_term_columns,
                        BTreeSet::from([hiding_secret_column, common_secret_column]),
                        "the anchor final component has no detached secret term"
                    );
                    anchor_common_secret_columns.insert(common_secret_column);
                }
            }
        }
        assert_eq!(anchor_common_secret_columns, common_secret_columns);
        assert_eq!(
            anchor_common_secret_columns, vss_equality_common_secret_columns,
            "VSS equalities and every anchor batch reuse the same secret columns"
        );
    }

    #[test]
    fn same_secret_production_relation_has_an_exact_generated_semantic_partition() {
        let context = production_context(false);
        let compiled = compile_same_secret_relation_with_source_layout(
            &crate::bgv::proof_suite::selected_profile::selected_same_secret_relation_plan_input()
                .expect("selected same-secret relation input"),
            &context,
        )
        .expect("compiled production same-secret relation and source layout");
        compiled
            .relation_plan
            .check(&context)
            .expect("production same-secret relation plan is valid");
        let variant = compiled
            .relation_plan
            .select_variant(None, None)
            .expect("production same-secret relation variant");
        let constraint_shape_index = same_secret_constraint_shape_index(variant);
        let mut ownership = SameSecretSemanticOwnership {
            columns: same_secret_column_ownership(variant, &compiled.source_layout),
            ..SameSecretSemanticOwnership::default()
        };

        claim_same_secret_bound_constraints(
            variant,
            &constraint_shape_index,
            &compiled.source_layout,
            &context,
            &mut ownership,
        );
        claim_same_secret_equality_constraints(
            variant,
            &constraint_shape_index,
            &compiled.source_layout,
            &mut ownership,
        );
        let full_ring_accounting = claim_same_secret_integer_lift_constraints(
            variant,
            &constraint_shape_index,
            &context,
            &mut ownership,
        );
        assert_eq!(
            full_ring_accounting,
            (180, 1_440, 1_080),
            "shared full-ring witnesses retain every product while compiling each identical constraint once"
        );
        claim_same_secret_opening_claims(variant, &mut ownership);

        for (category, expected_columns, expected_constraints, expected_opening_claims) in
            SAME_SECRET_SEMANTIC_CATEGORY_COUNTS
        {
            assert_eq!(
                ownership.columns.get(category).map_or(0, BTreeSet::len),
                *expected_columns,
                "{category:?} column count"
            );
            assert_eq!(
                ownership.constraints.get(category).map_or(0, BTreeSet::len),
                *expected_constraints,
                "{category:?} constraint count"
            );
            assert_eq!(
                ownership
                    .opening_claims
                    .get(category)
                    .map_or(0, BTreeSet::len),
                *expected_opening_claims,
                "{category:?} opening-claim count"
            );
        }

        assert_exact_semantic_partition(
            &ownership.columns,
            variant.ordered_columns().len(),
            "column",
        );
        assert_exact_semantic_partition(
            &ownership.constraints,
            variant.ordered_constraints.len(),
            "constraint",
        );
        assert_exact_semantic_partition(
            &ownership.opening_claims,
            variant.ordered_opening_claims().len(),
            "opening claim",
        );
    }
}
