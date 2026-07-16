//! Deterministic construction of the fixed proof-profile artifact.

use crate::bgv::parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, SPECIAL_PRIMES};

#[cfg(test)]
use crate::{
    bgv::{
        evaluator::{
            candidate_evidence::EvaluatorCandidateInput, program::selected_evaluator_program_set,
        },
        key_switch_topology::KeySwitchDecompositionTopology,
        parameters::{LOGICAL_SLOT_GENERATOR, POLYNOMIAL_DEGREE, root_parameters_for_modulus},
        setup::{
            SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
            TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND,
            target_decryption_interpolation_denominator_clearing_factor,
        },
    },
    foundation::FOUNDATION_PROFILE,
};

use super::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR,
    PROOF_EVALUATION_COSET_OFFSET, PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT, RelationPlanCheckContext,
    ResolvedSuiteModulus, SuiteModulusReference,
};

#[cfg(test)]
use super::{
    BallotValidityRelationPlanInput, CollectivePublicKeyAggregatePlanInput,
    CommittedMaterialProfile, CommittedMaterialRelationPlanInput,
    EvaluatorKeyAggregateEntryPlanInput, EvaluatorKeyAggregatePlanInput,
    EvaluatorKeyAggregateVariantInput, FirstProfileRootTopology, GaloisKeyShareRelationPlanInput,
    ProofProfileError, ProofProfileSet, PublicAggregateRelationGeometry,
    PublicKeyShareRelationPlanInput, RelinearizationRoundOneRelationPlanInput,
    RelinearizationRoundTwoRelationPlanInput, RkgRoundOneAggregatePlanInput,
    RkgRoundOneAggregateVariantInput, SameSecretRelationPlanInput, TargetReleaseRelationPlanInput,
    TrusteeEvaluationKeyDecompositionBlock, TrusteeEvaluationKeyRelationGeometry,
    ValidatedRelationPlanArtifact, compile_aggregate_threshold_share_relation_plan,
    compile_ballot_validity_relation_plan, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_galois_key_share_relation_plan,
    compile_public_key_share_relation_plan, compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_two_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_target_release_relation_plan,
    compile_vss_share_linkage_relation_plan, merge_checked_relation_plan_variants,
};

const SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 262_144;
pub(super) const SELECTED_EVALUATION_DOMAIN_SIZE: u64 =
    SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE * PROOF_EVALUATION_BLOWUP_FACTOR as u64;
#[cfg(test)]
const SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE: u64 = 16_384;
const SELECTED_QUOTIENT_COMPONENT_COUNT: u32 = 8;
const SELECTED_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE: u64 = 33_884;
const SELECTED_FRI_FOLD_COUNT: u16 = 10;
#[cfg(test)]
const FIRST_MASK_PURPOSE: u16 = 100;
#[cfg(test)]
const RESERVED_BALLOT_SLOT_RULE: u16 = 1;

pub(crate) fn selected_relation_plan_check_context() -> RelationPlanCheckContext {
    let mut resolved_moduli = DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(modulus_index, modulus)| {
            ResolvedSuiteModulus::new(
                SuiteModulusReference::data(
                    u16::try_from(modulus_index).expect("the selected data basis fits u16"),
                ),
                modulus,
            )
        })
        .collect::<Vec<_>>();
    resolved_moduli.extend(SPECIAL_PRIMES.iter().copied().enumerate().map(
        |(modulus_index, modulus)| {
            ResolvedSuiteModulus::new(
                SuiteModulusReference::special(
                    u16::try_from(modulus_index).expect("the selected special basis fits u16"),
                ),
                modulus,
            )
        },
    ));
    resolved_moduli.push(ResolvedSuiteModulus::new(
        SuiteModulusReference::plaintext(),
        PLAINTEXT_MODULUS,
    ));
    resolved_moduli.extend(DATA_PRIMES[..2].iter().copied().enumerate().map(
        |(modulus_index, modulus)| {
            ResolvedSuiteModulus::new(
                SuiteModulusReference::target(
                    u16::try_from(modulus_index).expect("the selected target basis fits u16"),
                ),
                modulus,
            )
        },
    ));

    RelationPlanCheckContext {
        base_field_modulus: PROOF_BASE_FIELD_MODULUS,
        challenge_extension_degree: u16::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
            .expect("the selected challenge extension degree fits u16"),
        evaluation_blowup_factor: PROOF_EVALUATION_BLOWUP_FACTOR,
        evaluation_domain_generator: modular_power(
            PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
            (1_u64 << 32) / SELECTED_EVALUATION_DOMAIN_SIZE,
            PROOF_BASE_FIELD_MODULUS,
        ),
        evaluation_coset_offset: PROOF_EVALUATION_COSET_OFFSET,
        deep_point_count: PROOF_DEEP_POINT_COUNT,
        quotient_component_count: SELECTED_QUOTIENT_COMPONENT_COUNT,
        quotient_component_degree_bound_exclusive:
            SELECTED_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE,
        fri_fold_count: SELECTED_FRI_FOLD_COUNT,
        final_polynomial_degree_bound_exclusive: PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
        unique_query_count: PROOF_UNIQUE_QUERY_COUNT,
        non_native_modular_identity_challenge_count: PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT,
        maximum_fiat_shamir_candidate_draws_per_output:
            PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
        resolved_moduli,
    }
}

#[cfg(test)]
pub(crate) fn selected_proof_profile_set(
    maximum_ballot_attempts_per_participant: u16,
) -> Result<ProofProfileSet, ProofProfileError> {
    let context = selected_relation_plan_check_context();
    let relation_plans = selected_relation_plans(&context)?;
    ProofProfileSet::new(
        relation_plans,
        FirstProfileRootTopology::selected(maximum_ballot_attempts_per_participant)?,
    )
}

#[cfg(test)]
pub(crate) fn selected_committed_material_profile()
-> Result<CommittedMaterialProfile, ProofProfileError> {
    CommittedMaterialProfile::for_common_proof_evaluation_domain(
        POLYNOMIAL_DEGREE,
        usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
            .map_err(|_| ProofProfileError::CountOverflow)?,
    )
    .map_err(|_| ProofProfileError::InvalidRelationPlan)
}

#[cfg(test)]
pub(crate) fn selected_target_decryption_flooding_bound() -> Result<u64, ProofProfileError> {
    u64::try_from(TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND)
        .map_err(|_| ProofProfileError::InvalidRelationPlan)
}

#[cfg(test)]
fn selected_relation_plans(
    context: &RelationPlanCheckContext,
) -> Result<Vec<ValidatedRelationPlanArtifact>, ProofProfileError> {
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let committed_material_profile = selected_committed_material_profile()?;
    let material_column_degree_bound_exclusive =
        u64::try_from(committed_material_profile.material_column_degree_bound_exclusive())
            .map_err(|_| ProofProfileError::CountOverflow)?;
    let sharing_data_modulus_indices = selected_data_modulus_indices();
    let commitment_data_modulus_indices = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .copied()
        .map(|modulus_index| {
            u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let same_secret = compile_same_secret_relation_plan(
        &SameSecretRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            material_column_degree_bound_exclusive,
            public_polynomial_column_degree_bound_exclusive:
                SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
            sharing_data_modulus_indices: sharing_data_modulus_indices.clone(),
            commitment_data_modulus_indices: commitment_data_modulus_indices.clone(),
            commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
                .map_err(|_| ProofProfileError::CountOverflow)?,
            first_mask_purpose: FIRST_MASK_PURPOSE,
        },
        context,
    )?;
    let public_key_share = compile_public_key_share_relation_plan(
        &PublicKeyShareRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            public_polynomial_column_degree_bound_exclusive:
                SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
            data_modulus_indices: sharing_data_modulus_indices.clone(),
            commitment_data_modulus_indices: commitment_data_modulus_indices.clone(),
            commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
                .map_err(|_| ProofProfileError::CountOverflow)?,
            plaintext_modulus: PLAINTEXT_MODULUS,
            first_mask_purpose: FIRST_MASK_PURPOSE,
        },
        context,
    )?;

    let aggregate_geometry = PublicAggregateRelationGeometry {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        public_polynomial_column_degree_bound_exclusive:
            SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        participant_count: FOUNDATION_PROFILE.participant_count,
    };
    let collective_public_key = compile_collective_public_key_aggregate_relation_plan(
        &CollectivePublicKeyAggregatePlanInput {
            geometry: aggregate_geometry.clone(),
            ordered_component_moduli: split_polynomial_modulus_references(
                &sharing_data_modulus_indices
                    .iter()
                    .copied()
                    .map(SuiteModulusReference::data)
                    .collect::<Vec<_>>(),
            ),
        },
        context,
    )?;

    let trustee_geometry = selected_trustee_evaluation_key_geometry(
        &evaluator_candidate,
        commitment_data_modulus_indices,
    )?;
    let relinearization_round_one = compile_relinearization_round_one_relation_plan(
        &RelinearizationRoundOneRelationPlanInput {
            schedule_position: 0,
            geometry: trustee_geometry.clone(),
        },
        context,
    )?;
    let trustee_root_component_moduli = split_polynomial_modulus_references(
        &ordered_trustee_root_row_modulus_references(&trustee_geometry)?,
    );
    let rkg_round_one_aggregate = compile_rkg_round_one_aggregate_relation_plan(
        &RkgRoundOneAggregatePlanInput {
            geometry: aggregate_geometry.clone(),
            ordered_variants: vec![RkgRoundOneAggregateVariantInput {
                schedule_position: 0,
                ordered_left_component_moduli: trustee_root_component_moduli.clone(),
                ordered_right_component_moduli: trustee_root_component_moduli.clone(),
            }],
        },
        context,
    )?;
    let relinearization_round_two = compile_relinearization_round_two_relation_plan(
        &RelinearizationRoundTwoRelationPlanInput {
            schedule_position: 0,
            geometry: trustee_geometry.clone(),
        },
        context,
    )?;

    let galois_plans = evaluator_candidate
        .galois_key_schedule
        .iter()
        .copied()
        .enumerate()
        .map(|(schedule_position, (galois_element, level))| {
            if level != evaluator_candidate.evaluator_working_level {
                return Err(ProofProfileError::InvalidRelationPlan);
            }
            compile_galois_key_share_relation_plan(
                &GaloisKeyShareRelationPlanInput {
                    schedule_position: u32::try_from(schedule_position)
                        .map_err(|_| ProofProfileError::CountOverflow)?,
                    galois_element: u64::try_from(galois_element)
                        .map_err(|_| ProofProfileError::CountOverflow)?,
                    geometry: trustee_geometry.clone(),
                },
                context,
            )
            .map_err(ProofProfileError::from)
        })
        .collect::<Result<Vec<_>, ProofProfileError>>()?;
    let galois_key_shares = merge_checked_relation_plan_variants(0x1217, galois_plans, context)?;

    let evaluator_variants = selected_evaluator_aggregate_variants(
        &evaluator_candidate,
        &trustee_root_component_moduli,
    )?;
    let evaluator_key_aggregate = compile_evaluator_key_aggregate_relation_plan(
        &EvaluatorKeyAggregatePlanInput {
            geometry: aggregate_geometry,
            ordered_variants: evaluator_variants,
        },
        context,
    )?;

    let ballot_validity = compile_ballot_validity_relation_plan(
        &BallotValidityRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            active_data_modulus_indices: sharing_data_modulus_indices.clone(),
            plaintext_modulus: PLAINTEXT_MODULUS,
            primitive_two_n_root: root_parameters_for_modulus(PLAINTEXT_MODULUS)
                .ok_or(ProofProfileError::InvalidRelationPlan)?
                .negacyclic_root,
            slot_generator: u16::try_from(LOGICAL_SLOT_GENERATOR)
                .map_err(|_| ProofProfileError::CountOverflow)?,
            reserved_slot_rule: RESERVED_BALLOT_SLOT_RULE,
            first_mask_purpose: FIRST_MASK_PURPOSE,
        },
        context,
    )?;

    let denominator_clearing_factor = target_decryption_interpolation_denominator_clearing_factor(
        u64::from(FOUNDATION_PROFILE.participant_count),
    )
    .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let target_release = compile_target_release_relation_plan(
        &TargetReleaseRelationPlanInput {
            ring_degree: selected_ring_degree(),
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
            opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
            material_column_degree_bound_exclusive,
            public_polynomial_column_degree_bound_exclusive: selected_ring_degree(),
            target_modulus_indices: vec![0, 1],
            decryption_scale: 1,
            simulation_scale: PLAINTEXT_MODULUS
                .checked_mul(denominator_clearing_factor)
                .ok_or(ProofProfileError::CountOverflow)?,
            flooding_bound: selected_target_decryption_flooding_bound()?,
            first_mask_purpose: FIRST_MASK_PURPOSE,
        },
        context,
    )?;

    let committed_material_input = CommittedMaterialRelationPlanInput {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        material_column_degree_bound_exclusive,
        participant_count: FOUNDATION_PROFILE.participant_count,
        threshold: FOUNDATION_PROFILE.reconstruction_threshold,
        sharing_data_modulus_indices,
        trace_mask_degree_bound_exclusive: u64::try_from(
            committed_material_profile.masking_polynomial_maximum_degree() + 1,
        )
        .map_err(|_| ProofProfileError::CountOverflow)?,
        first_mask_purpose: FIRST_MASK_PURPOSE,
    };
    let vss_share_linkage =
        compile_vss_share_linkage_relation_plan(&committed_material_input, context)?;
    let aggregate_threshold_share =
        compile_aggregate_threshold_share_relation_plan(&committed_material_input, context)?;

    let compiled_plans = vec![
        same_secret,
        public_key_share,
        collective_public_key,
        relinearization_round_one,
        rkg_round_one_aggregate,
        relinearization_round_two,
        galois_key_shares,
        evaluator_key_aggregate,
        ballot_validity,
        target_release,
        vss_share_linkage,
        aggregate_threshold_share,
    ];
    compiled_plans
        .into_iter()
        .map(|plan| ValidatedRelationPlanArtifact::from_owned_compiled_plan(plan, context))
        .collect()
}

#[cfg(test)]
fn selected_trustee_evaluation_key_geometry(
    evaluator_candidate: &EvaluatorCandidateInput,
    commitment_data_modulus_indices: Vec<u16>,
) -> Result<TrusteeEvaluationKeyRelationGeometry, ProofProfileError> {
    let selected_level = evaluator_candidate
        .relinearization_levels
        .first()
        .copied()
        .filter(|_| evaluator_candidate.relinearization_levels.len() == 1)
        .ok_or(ProofProfileError::InvalidRelationPlan)?;
    if evaluator_candidate
        .galois_key_schedule
        .iter()
        .any(|(_, level)| *level != selected_level)
    {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    let decomposition_topology = KeySwitchDecompositionTopology::for_level(selected_level)
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    let decomposition_blocks = (0..decomposition_topology.data_block_count())
        .map(|block_index| {
            Ok(TrusteeEvaluationKeyDecompositionBlock {
                data_modulus_indices: decomposition_topology
                    .data_block_range(block_index)
                    .map_err(|_| ProofProfileError::InvalidRelationPlan)?
                    .map(|modulus_index| {
                        u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, ProofProfileError>>()?;

    Ok(TrusteeEvaluationKeyRelationGeometry {
        ring_degree: selected_ring_degree(),
        evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
        opening_degree_bound_exclusive: SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE,
        public_polynomial_column_degree_bound_exclusive:
            SELECTED_PUBLIC_POLYNOMIAL_COLUMN_DEGREE_BOUND_EXCLUSIVE,
        data_moduli: evaluator_candidate.data_primes.clone(),
        special_moduli: evaluator_candidate.special_primes.clone(),
        plaintext_modulus: evaluator_candidate.plaintext_modulus,
        decomposition_blocks,
        commitment_data_modulus_indices,
        commitment_module_rank: u16::try_from(SETUP_COMMITMENT_MODULE_RANK)
            .map_err(|_| ProofProfileError::CountOverflow)?,
        first_mask_purpose: FIRST_MASK_PURPOSE,
    })
}

#[cfg(test)]
fn selected_evaluator_aggregate_variants(
    evaluator_candidate: &EvaluatorCandidateInput,
    ordered_runtime_component_moduli: &[SuiteModulusReference],
) -> Result<Vec<EvaluatorKeyAggregateVariantInput>, ProofProfileError> {
    let key_positions = selected_evaluator_program_set()
        .and_then(|program| program.key_positions())
        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
    if key_positions.relinearization_catalog_levels() != evaluator_candidate.relinearization_levels
        || key_positions.galois_catalog_positions().len()
            != evaluator_candidate.galois_key_schedule.len()
        || key_positions
            .galois_catalog_positions()
            .iter()
            .zip(&evaluator_candidate.galois_key_schedule)
            .any(|(position, expected)| {
                (position.galois_element(), position.catalog_level()) != *expected
            })
    {
        return Err(ProofProfileError::InvalidRelationPlan);
    }
    key_positions
        .streams()
        .iter()
        .map(|stream| {
            let mut ordered_entries = stream
                .relinearization_catalog_levels()
                .iter()
                .map(|level| {
                    let schedule_position = key_positions
                        .relinearization_catalog_levels()
                        .binary_search(level)
                        .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
                    Ok(EvaluatorKeyAggregateEntryPlanInput {
                        schedule_position: u32::try_from(schedule_position)
                            .map_err(|_| ProofProfileError::CountOverflow)?,
                        ordered_runtime_component_moduli: ordered_runtime_component_moduli.to_vec(),
                    })
                })
                .collect::<Result<Vec<_>, ProofProfileError>>()?;
            ordered_entries.extend(
                stream
                    .galois_catalog_positions()
                    .iter()
                    .map(|position| {
                        let schedule_position = key_positions
                            .galois_catalog_positions()
                            .binary_search(position)
                            .map_err(|_| ProofProfileError::InvalidRelationPlan)?;
                        Ok(EvaluatorKeyAggregateEntryPlanInput {
                            schedule_position: u32::try_from(schedule_position)
                                .map_err(|_| ProofProfileError::CountOverflow)?,
                            ordered_runtime_component_moduli: ordered_runtime_component_moduli
                                .to_vec(),
                        })
                    })
                    .collect::<Result<Vec<_>, ProofProfileError>>()?,
            );
            ordered_entries
                .into_iter()
                .enumerate()
                .map(|(entry_ordinal, entry)| {
                    Ok(EvaluatorKeyAggregateVariantInput {
                        top_count: stream.top_count(),
                        entry_ordinal: u32::try_from(entry_ordinal)
                            .map_err(|_| ProofProfileError::CountOverflow)?,
                        entry,
                    })
                })
                .collect::<Result<Vec<_>, ProofProfileError>>()
        })
        .collect::<Result<Vec<_>, ProofProfileError>>()
        .map(|variants| variants.into_iter().flatten().collect())
}

#[cfg(test)]
fn ordered_trustee_root_row_modulus_references(
    geometry: &TrusteeEvaluationKeyRelationGeometry,
) -> Result<Vec<SuiteModulusReference>, ProofProfileError> {
    let ordered_moduli = (0..geometry.data_moduli.len())
        .map(|modulus_index| {
            Ok(SuiteModulusReference::data(
                u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)?,
            ))
        })
        .chain((0..geometry.special_moduli.len()).map(|modulus_index| {
            Ok(SuiteModulusReference::special(
                u16::try_from(modulus_index).map_err(|_| ProofProfileError::CountOverflow)?,
            ))
        }))
        .collect::<Result<Vec<_>, ProofProfileError>>()?;
    Ok((0..geometry.decomposition_blocks.len())
        .flat_map(|_| ordered_moduli.iter().copied())
        .collect())
}

#[cfg(test)]
fn split_polynomial_modulus_references(
    ordered_moduli: &[SuiteModulusReference],
) -> Vec<SuiteModulusReference> {
    ordered_moduli
        .iter()
        .copied()
        .flat_map(|modulus_reference| [modulus_reference, modulus_reference])
        .collect()
}

#[cfg(test)]
fn selected_data_modulus_indices() -> Vec<u16> {
    (0..DATA_PRIMES.len())
        .map(|modulus_index| {
            u16::try_from(modulus_index).expect("the selected data basis fits u16")
        })
        .collect()
}

#[cfg(test)]
fn selected_ring_degree() -> u64 {
    u64::try_from(POLYNOMIAL_DEGREE).expect("the selected ring degree fits u64")
}

fn modular_power(base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let modulus_wide = u128::from(modulus);
    let mut result = 1_u128;
    let mut base_wide = u128::from(base) % modulus_wide;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = (result * base_wide) % modulus_wide;
        }
        base_wide = (base_wide * base_wide) % modulus_wide;
        exponent >>= 1;
    }
    u64::try_from(result).expect("the modular result is less than the u64 modulus")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_context_is_the_single_fixed_profile_context() {
        let context = selected_relation_plan_check_context();
        assert_eq!(context.deep_point_count, 1);
        assert_eq!(
            context.evaluation_domain_generator,
            17_654_865_857_378_133_588
        );
        assert_eq!(context.fri_fold_count, 10);
        assert_eq!(
            context.resolved_moduli.len(),
            DATA_PRIMES.len() + SPECIAL_PRIMES.len() + 3
        );

        let persistent_material_profile =
            CommittedMaterialProfile::for_common_proof_evaluation_domain(
                POLYNOMIAL_DEGREE,
                usize::try_from(SELECTED_EVALUATION_DOMAIN_SIZE)
                    .expect("the selected evaluation domain fits usize"),
            )
            .expect("persistent material profile on the consuming domain");
        assert_eq!(
            persistent_material_profile.material_column_degree_bound_exclusive(),
            18_432
        );
        assert_eq!(
            persistent_material_profile.masking_polynomial_maximum_degree(),
            2_047
        );
        assert_eq!(
            persistent_material_profile.committed_polynomial_degree_bound_exclusive(),
            usize::try_from(SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE)
                .expect("the selected opening bound fits usize")
        );
    }

    #[test]
    fn selected_profile_has_the_complete_relation_and_root_inventory() {
        let mut profile = selected_proof_profile_set(3).expect("selected proof profile");
        assert_eq!(
            profile.relation_plans().len(),
            super::super::FIRST_PROFILE_APPLICATION_FAMILIES.len()
        );

        let relation_plan = |schema_identifier| {
            profile
                .relation_plans()
                .iter()
                .find(|artifact| {
                    artifact.application_statement_schema_identifier() == schema_identifier
                })
                .expect("selected relation family")
                .compiled_plan()
        };
        let evaluator_variant_count = relation_plan(0x1218).variants().len();
        let key_positions = selected_evaluator_program_set()
            .and_then(|program| program.key_positions())
            .expect("selected evaluator key positions");
        let expected_evaluator_variant_count = key_positions
            .streams()
            .iter()
            .map(|stream| {
                stream.relinearization_catalog_levels().len()
                    + stream.galois_catalog_positions().len()
            })
            .sum::<usize>();
        assert_eq!(evaluator_variant_count, expected_evaluator_variant_count);

        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let sharing_limb_count = DATA_PRIMES.len();
        let commitment_anchor_count = SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len();
        let round_one_variant_count = relation_plan(0x1214).variants().len();
        let round_one_aggregate_variant_count = relation_plan(0x1215).variants().len();
        let round_two_variant_count = relation_plan(0x1216).variants().len();
        let galois_variant_count = relation_plan(0x1217).variants().len();
        let expected_root_edge_count = participant_count * sharing_limb_count
            + participant_count * participant_count * sharing_limb_count
            + participant_count * 2
            + participant_count * commitment_anchor_count
            + participant_count
                * commitment_anchor_count
                * (round_one_variant_count + round_two_variant_count + galois_variant_count)
            + participant_count
            + round_one_aggregate_variant_count * participant_count * 2
            + round_two_variant_count * participant_count * 4
            + evaluator_variant_count * participant_count;
        assert_eq!(
            profile.root_compatibility_edges().len(),
            expected_root_edge_count
        );
        profile.assert_catalog_mutation_boundaries();
    }
}
