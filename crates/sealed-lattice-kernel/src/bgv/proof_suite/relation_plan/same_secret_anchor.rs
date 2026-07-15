use super::key_relation::{
    BoundPolynomialRootUse, KeyRelationGeometry, KeyRelationPlanBuilder, KeyVerifierSourceKey,
    SameSecretRelationPlanInput, SplitIntegerVector, bdlop_matrix_source, statement_root_source,
};
use super::*;

const SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER: u16 = 0x1211;
const DEGREE_ZERO_VSS_MATERIAL_ROOTS_FIELD_ORDINAL: u64 = 3;
const ANCHOR_COMMITMENT_ROOTS_FIELD_ORDINAL: u64 = 4;

pub(crate) fn compile_same_secret_relation_plan(
    input: &SameSecretRelationPlanInput,
    check_context: &RelationPlanCheckContext,
) -> Result<CompiledRelationPlan, RelationPlanError> {
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
    for (root_ordinal, data_modulus_index) in input
        .sharing_data_modulus_indices
        .iter()
        .copied()
        .enumerate()
    {
        let material = builder.add_committed_material_root(
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
    }
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
        for challenge_ordinal in 0..check_context.non_native_modular_identity_challenge_count {
            builder.add_anchor_equations(
                modulus_reference,
                challenge_ordinal,
                &commitments,
                &first_matrix,
                &second_matrix,
                &opening,
                &secret,
                &quotients,
            )?;
        }
    }
    builder.finish()
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
            non_native_modular_identity_challenge_count: 1,
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
            first_mask_purpose: 100,
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
        eprintln!(
            "same-secret columns={} constraints={} trees={} base_width={} auxiliary_width={}",
            variant.ordered_columns.len(),
            variant.ordered_constraints.len(),
            variant.ordered_trees.len(),
            proof_tree_width(variant, 1),
            proof_tree_width(variant, 2),
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
                assert_pre_challenge(component.quotient_column_ordinal);
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
        let evaluation_domain_size = 524_288_u64;
        let mut resolved_moduli = DATA_PRIMES
            .iter()
            .copied()
            .enumerate()
            .map(|(index, modulus)| {
                ResolvedSuiteModulus::new(SuiteModulusReference::data(index as u16), modulus)
            })
            .collect::<Vec<_>>();
        if include_plaintext {
            resolved_moduli.push(ResolvedSuiteModulus::new(
                SuiteModulusReference::plaintext(),
                65_537,
            ));
        }
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_blowup_factor: 8,
            evaluation_domain_generator: modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                (1_u64 << 32) / evaluation_domain_size,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 2,
            quotient_component_count: 8,
            quotient_component_degree_bound_exclusive: 32_768,
            fri_fold_count: 8,
            final_polynomial_degree_bound_exclusive: 256,
            unique_query_count: 168,
            non_native_modular_identity_challenge_count: 7,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli,
        }
    }

    #[test]
    fn same_secret_production_profile_closes_the_degree_fixed_point() {
        let context = production_context(false);
        let plan = compile_same_secret_relation_plan(
            &SameSecretRelationPlanInput {
                ring_degree: 32_768,
                evaluation_domain_size: 524_288,
                opening_degree_bound_exclusive: 65_536,
                material_column_degree_bound_exclusive: 16_384,
                public_polynomial_column_degree_bound_exclusive: 16_384,
                sharing_data_modulus_indices: (0..17).collect(),
                commitment_data_modulus_indices: vec![0, 1, 2],
                commitment_module_rank: 1,
                first_mask_purpose: 100,
            },
            &context,
        )
        .expect("production same-secret relation plan");
        plan.check(&context)
            .expect("checked production same-secret relation plan");
    }
}
