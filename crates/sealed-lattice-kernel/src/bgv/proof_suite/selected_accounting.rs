//! Canonical proof ceilings and runtime limits for the selected suite.

use std::collections::BTreeSet;

#[cfg(test)]
use std::sync::OnceLock;

use crate::foundation::{CanonicalDecodeLimits, Hash512, ProofObjectHeader};

#[cfg(test)]
use crate::{
    bgv::{
        evaluator::program::{EvaluatorProgramKeyPositions, selected_evaluator_program_set},
        evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        serialization::two_component_data_ciphertext_canonical_byte_length_ceiling_at_level,
        target_decryption::{
            kllps_release::{
                KLLPS_PAIRED_TARGET_ROLE_COUNT,
                selected_kllps_target_release_source_provider_memory_accounting,
            },
            selected_target_partial_decryption_stream_byte_length,
        },
    },
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, ProofApplicationSlotCeilings,
        SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
        SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION, selected_evaluator_resource_accounting,
    },
};

use super::body::minimal_frontier_node_count;
#[cfg(test)]
use super::collective_public_key_runtime::{
    CollectivePublicKeyApplicationMemoryAccounting,
    collective_public_key_application_memory_accounting,
};
#[cfg(test)]
use super::external_memory::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
};
#[cfg(test)]
use super::prover::{
    CommonProofExternalMemoryRequirement, CommonProofResidentMemoryConfiguration,
    CommonProofResidentMemoryPhase, CommonProofResidentMemoryPlan,
    GeneratedCommonProofStoragePlanError, common_proof_cap_neutral_resource_requirement,
    common_proof_external_memory_requirement, common_proof_resident_memory_requirement,
    common_proof_source_provider_is_live_during_phase,
};
use super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor,
};
#[cfg(test)]
use super::relation_plan::{
    CollectivePublicKeySourceProviderMemoryAccounting,
    CommittedMaterialSourceProviderMemoryAccounting, CompiledRelationPlan, ProofPrivacyMode,
    RelationMaskKind, aggregate_threshold_share_source_provider_memory_accounting,
    collective_public_key_source_provider_memory_accounting,
    compile_public_key_share_relation_with_source_layout,
    compile_relinearization_round_one_relation_with_source_layout,
    compile_relinearization_round_two_relation_with_source_layout,
    compile_same_secret_relation_with_source_layout,
    galois_key_share_source_provider_memory_accounting,
    public_key_share_source_provider_memory_accounting,
    relinearization_round_one_source_provider_memory_accounting,
    relinearization_round_two_source_provider_memory_accounting,
    same_secret_source_provider_memory_accounting,
    vss_share_linkage_source_provider_memory_accounting,
};
#[cfg(test)]
use super::selected_profile::selected_proof_application_slot_ceilings;
use super::{
    CommonProofByteLengthCeiling, CommonProofRuntimeLimits, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, ProofBodyLayout, ProofLeafVisibility,
    ProofTreeCatalogInput, ProofTreeRole, RelationProofTreeInput, StatementOwnedProofTreeInput,
    build_complete_proof_tree_catalog, canonical_common_proof_byte_length_ceiling,
    proof_query_tree_byte_length, selected_relation_plan_check_context,
};
#[cfg(test)]
use super::{
    CommonProofGenerationCheckpointCustodyRequirement, CommonProofSourceProviderMemoryAccounting,
    CommonProofTranscriptSchedule, KeySwitchComponentMaterialTopology,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_DEEP_POINT_COUNT,
    SelectedApplicationStatementContext, SelectedBallotCiphertextReadbackMemoryAccounting,
    SelectedBallotValidityCarrierBufferAccounting,
    SelectedEvaluatorAggregateSourceProviderMemoryAccounting,
    canonical_selected_application_statement_for_ceiling,
    common_proof_generation_checkpoint_custody_requirement_for_variant,
    common_proof_randomness_purpose_is_assigned,
    evaluator_aggregate_source_provider_memory_accounting,
    selected_ballot_ciphertext_readback_memory_accounting,
    selected_ballot_validity_carrier_buffer_accounting,
    selected_committed_material_relation_plan_input, selected_evaluator_entry_positions,
    selected_galois_key_share_batch_schedule, selected_galois_key_share_relation_plan_input,
    selected_proof_profile_set, selected_public_key_share_relation_plan_input,
    selected_recipient_private_vss_payload_byte_length,
    selected_relinearization_relation_plan_inputs, selected_same_secret_relation_plan_input,
    selected_target_release_relation,
};

#[cfg(test)]
use super::ProofTreeCatalogSource;

struct SelectedProofTransportSizing {
    ceiling: CommonProofByteLengthCeiling,
    #[cfg(test)]
    layout: ProofBodyLayout,
    maximum_prefetched_query_byte_length: u64,
    #[cfg(test)]
    transcript_schedule: CommonProofTranscriptSchedule,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedProofAccountingError {
    CanonicalEncoding,
    InvalidProfile,
    InvalidTreeGeometry,
    CountOverflow,
    AllocationLimitExceeded,
    ProofByteLengthExceeded {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        proof_byte_length: usize,
        maximum_proof_byte_length: usize,
    },
    ResourcePlanning,
}

fn selected_proof_transport_sizing(
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<SelectedProofTransportSizing, SelectedProofAccountingError> {
    selected_proof_transport_sizing_with_proof_byte_length_policy(
        application_statement_schema_identifier,
        canonical_application_statement_bytes,
        variant,
        relation_context,
        true,
    )
}

#[cfg(test)]
fn selected_cap_neutral_proof_transport_sizing(
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<SelectedProofTransportSizing, SelectedProofAccountingError> {
    selected_proof_transport_sizing_with_proof_byte_length_policy(
        application_statement_schema_identifier,
        canonical_application_statement_bytes,
        variant,
        relation_context,
        false,
    )
}

fn selected_proof_transport_sizing_with_proof_byte_length_policy(
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    enforce_proof_byte_length_limit: bool,
) -> Result<SelectedProofTransportSizing, SelectedProofAccountingError> {
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let proof_header_bytes = proof_header
        .encode()
        .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let proof_header_byte_length = proof_header_bytes.len();
    let transcript_schedule = variant
        .common_proof_transcript_schedule(relation_context)
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let relation_trees = selected_relation_tree_inputs(variant)?;
    let catalog = build_complete_proof_tree_catalog(
        ProofTreeCatalogInput {
            suite_identifier: [0; Hash512::BYTE_LENGTH],
            canonical_proof_object_header_bytes: proof_header_bytes,
            application_statement_schema_identifier,
            proof_field_index: 0,
            evaluation_domain_size: variant.evaluation_domain_size(),
            relation_trees,
        },
        &transcript_schedule,
    )
    .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
    let layout = ProofBodyLayout::new(
        catalog,
        &transcript_schedule,
        transcript_schedule.terminal_coefficient_count(),
    )
    .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
    let ceiling = canonical_common_proof_byte_length_ceiling(proof_header_byte_length, &layout)
        .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
    require_selected_query_ceiling_geometry(
        transcript_schedule.unique_query_count(),
        transcript_schedule.query_orbit_count(),
        &layout,
        &ceiling,
    )?;
    if enforce_proof_byte_length_limit {
        require_selected_proof_byte_length(
            application_statement_schema_identifier,
            variant.schedule_position(),
            variant.top_count(),
            ceiling.proof_byte_length(),
        )?;
    }
    let maximum_prefetched_query_byte_length =
        ceiling
            .query_trees()
            .iter()
            .try_fold(0_u64, |maximum, tree| {
                tree.opened_leaf_payload_byte_length()
                    .checked_add(tree.authentication_frontier_digest_byte_length())
                    .ok_or(SelectedProofAccountingError::CountOverflow)
                    .and_then(|byte_length| {
                        u64::try_from(byte_length)
                            .map(|byte_length| maximum.max(byte_length))
                            .map_err(|_| SelectedProofAccountingError::CountOverflow)
                    })
            })?;
    if maximum_prefetched_query_byte_length == 0 {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    Ok(SelectedProofTransportSizing {
        ceiling,
        #[cfg(test)]
        layout,
        maximum_prefetched_query_byte_length,
        #[cfg(test)]
        transcript_schedule,
    })
}

fn selected_runtime_limits_from_sizing(
    transport_sizing: &SelectedProofTransportSizing,
) -> Result<CommonProofRuntimeLimits, SelectedProofAccountingError> {
    CommonProofRuntimeLimits::new(
        transport_sizing.ceiling.proof_byte_length(),
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        transport_sizing.maximum_prefetched_query_byte_length,
    )
    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)
}

pub(crate) fn selected_proof_runtime_limits(
    application_statement_schema_identifier: u16,
    canonical_application_statement_bytes: &[u8],
    variant: &RelationPlanVariant,
) -> Result<CommonProofRuntimeLimits, SelectedProofAccountingError> {
    let relation_context =
        selected_relation_plan_check_context(application_statement_schema_identifier)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let transport_sizing = selected_proof_transport_sizing(
        application_statement_schema_identifier,
        canonical_application_statement_bytes,
        variant,
        &relation_context,
    )?;
    selected_runtime_limits_from_sizing(&transport_sizing)
}

fn require_selected_proof_byte_length(
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    proof_byte_length: usize,
) -> Result<(), SelectedProofAccountingError> {
    if proof_byte_length == 0 || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(SelectedProofAccountingError::ProofByteLengthExceeded {
            application_statement_schema_identifier,
            schedule_position,
            top_count,
            proof_byte_length,
            maximum_proof_byte_length: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
        });
    }
    Ok(())
}

fn selected_relation_tree_inputs(
    variant: &RelationPlanVariant,
) -> Result<Vec<RelationProofTreeInput>, SelectedProofAccountingError> {
    variant
        .ordered_trees()
        .iter()
        .map(|tree| match tree {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } => {
                let leaf_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|column_index| variant.ordered_columns().get(column_index))
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::Prover)
                        })
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                Ok(RelationProofTreeInput::ProofCreated {
                    tree_role: match proof_tree_role {
                        1 => ProofTreeRole::BaseOracle,
                        2 => ProofTreeRole::AuxiliaryOracle,
                        _ => return Err(SelectedProofAccountingError::InvalidProfile),
                    },
                    row_width: u32::try_from(ordered_column_ordinals.len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    leaf_visibility,
                })
            }
            RelationTreeDescriptor::BoundPublic {
                construction_kind,
                ordered_column_ordinals,
                ..
            } => Ok(RelationProofTreeInput::BoundPublic(
                match construction_kind {
                    BoundTreeConstructionKind::CommittedMaterial => {
                        StatementOwnedProofTreeInput::CommittedMaterial {
                            material_context_hash: [0; Hash512::BYTE_LENGTH],
                            expected_root: [0; Hash512::BYTE_LENGTH],
                        }
                    }
                    BoundTreeConstructionKind::SetupPolynomial => {
                        StatementOwnedProofTreeInput::SetupPolynomial {
                            public_polynomial_context_hash: [0; Hash512::BYTE_LENGTH],
                            row_width: u32::try_from(ordered_column_ordinals.len())
                                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                            expected_root: [0; Hash512::BYTE_LENGTH],
                        }
                    }
                },
            )),
        })
        .collect()
}

fn require_selected_query_ceiling_geometry(
    unique_query_count: u32,
    query_orbit_count: u64,
    layout: &ProofBodyLayout,
    ceiling: &CommonProofByteLengthCeiling,
) -> Result<(), SelectedProofAccountingError> {
    let unique_query_count = usize::try_from(unique_query_count)
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let query_representatives =
        selected_query_ceiling_witness(unique_query_count, query_orbit_count)?;
    if layout.catalog().evaluation_domain_size().checked_div(2) != Some(query_orbit_count)
        || ceiling.query_trees().len() != layout.catalog().entries().len()
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    for (catalog_index, tree) in ceiling.query_trees().iter().enumerate() {
        let leaf_count = tree.leaf_count();
        if !leaf_count.is_power_of_two()
            || leaf_count.trailing_zeros() != tree.tree_height()
            || u64::try_from(leaf_count)
                .ok()
                .is_none_or(|count| count > query_orbit_count)
            || tree.maximum_opened_leaf_count() != unique_query_count.min(leaf_count)
            || proof_query_tree_byte_length(layout, catalog_index, &query_representatives)
                .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?
                != tree.byte_length()
        {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
        let leaf_count_u64 =
            u64::try_from(leaf_count).map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let projected_leaf_indexes = query_representatives
            .iter()
            .map(|representative| representative % leaf_count_u64)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if projected_leaf_indexes.len() != tree.opened_leaf_count_at_ceiling()
            || minimal_frontier_node_count(&projected_leaf_indexes, leaf_count)
                .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?
                != tree.authentication_frontier_node_count_at_ceiling()
        {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
    }
    Ok(())
}

/// Constructs one shared query vector that attains every folded-tree frontier
/// maximum for a production schedule.
fn selected_query_ceiling_witness(
    unique_query_count: usize,
    query_orbit_count: u64,
) -> Result<Vec<u64>, SelectedProofAccountingError> {
    if unique_query_count == 0
        || !query_orbit_count.is_power_of_two()
        || u64::try_from(unique_query_count)
            .ok()
            .is_none_or(|count| count > query_orbit_count)
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    let seed_capacity = unique_query_count
        .checked_next_power_of_two()
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let seed_bit_width = seed_capacity.trailing_zeros();
    let query_orbit_bit_width = query_orbit_count.trailing_zeros();
    let mut selected_seeds = Vec::new();
    selected_seeds
        .try_reserve_exact(unique_query_count)
        .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
    if seed_bit_width == 0 {
        selected_seeds.push(0_usize);
    } else {
        selected_seeds.extend((0..seed_capacity).filter(|seed| seed.count_ones() % 2 == 1));
        selected_seeds.extend(
            (0..seed_capacity)
                .filter(|seed| seed.count_ones() % 2 == 0)
                .take(unique_query_count - selected_seeds.len()),
        );
    }
    let mut query_representatives = Vec::new();
    query_representatives
        .try_reserve_exact(unique_query_count)
        .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
    for seed in selected_seeds {
        let seed = u64::try_from(seed).map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let mut representative = 0_u64;
        let mut bit_offset = 0_u32;
        while seed_bit_width != 0 && bit_offset < query_orbit_bit_width {
            let copied_bit_count = seed_bit_width.min(query_orbit_bit_width - bit_offset);
            let copied_bit_mask = 1_u64
                .checked_shl(copied_bit_count)
                .and_then(|value| value.checked_sub(1))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            representative |= (seed & copied_bit_mask) << bit_offset;
            bit_offset = bit_offset
                .checked_add(copied_bit_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        }
        query_representatives.push(representative);
    }
    query_representatives.sort_unstable();
    if query_representatives.len() != unique_query_count
        || !query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || query_representatives
            .last()
            .is_none_or(|representative| *representative >= query_orbit_count)
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    Ok(query_representatives)
}

#[cfg(test)]
mod selected_ballot_resource_cap_tests {
    use super::*;

    #[test]
    #[ignore = "guarded selected proof resource measurement"]
    fn selected_ballot_cap_neutral_external_memory_requirement_reports_raw_geometry() {
        let schema_identifier =
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
        let compilation = super::super::selected_ballot_validity_relation_compilation()
            .expect("the selected ballot relation compiles");
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("the selected ballot relation has one action-selected variant");
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected ballot relation has one common-proof context");
        let statement_context = SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            None,
            None,
        );
        let statement_bytes = canonical_selected_application_statement_for_ceiling(
            schema_identifier,
            statement_context,
        )
        .expect("the selected ballot ceiling statement encodes");
        let transport_sizing = selected_proof_transport_sizing(
            schema_identifier,
            &statement_bytes,
            variant,
            &relation_context,
        )
        .expect("the selected ballot proof transport sizing derives");
        let requirement = common_proof_external_memory_requirement(
            variant,
            &relation_context,
            transport_sizing.layout.catalog(),
            &transport_sizing.transcript_schedule,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        )
        .expect("the cap-neutral selected ballot storage requirement derives");
        let object_count_variance = i64::from(requirement.distinct_physical_object_count())
            - i64::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
                .expect("the object cap fits i64");
        let peak_stored_byte_length_variance = i128::from(requirement.peak_stored_byte_length())
            - i128::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH);

        println!(
            "selected ballot cap-neutral external memory: relation_columns={}, relation_constraints={}, step_count={}, maximum_chunk_byte_length={}, maximum_transaction_payload_byte_length={}, distinct_physical_object_count={}, object_lifecycle_count={}, peak_stored_byte_length={}, total_written_byte_length={}, total_read_byte_length={}, transaction_count={}, maximum_object_count={}, object_count_variance={}, maximum_stored_byte_length={}, peak_stored_byte_length_variance={}",
            variant.ordered_columns().len(),
            variant.ordered_constraint_count(),
            requirement.step_count(),
            requirement.maximum_chunk_byte_length(),
            requirement.maximum_transaction_payload_byte_length(),
            requirement.distinct_physical_object_count(),
            requirement.object_lifecycle_count(),
            requirement.peak_stored_byte_length(),
            requirement.total_written_byte_length(),
            requirement.total_read_byte_length(),
            requirement.transaction_count(),
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
            object_count_variance,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
            peak_stored_byte_length_variance,
        );

        assert_eq!(variant.ordered_columns().len(), 3_250);
        assert_eq!(variant.ordered_constraint_count(), 5_214);
        assert_eq!(requirement.step_count(), 353_501);
        assert_eq!(
            requirement.maximum_chunk_byte_length(),
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
        );
        assert_eq!(
            requirement.maximum_transaction_payload_byte_length(),
            49_152
        );
        assert_eq!(requirement.distinct_physical_object_count(), 36_822);
        assert_eq!(requirement.object_lifecycle_count(), 351_918);
        assert_eq!(requirement.peak_stored_byte_length(), 78_048_140_864);
        assert_eq!(requirement.total_written_byte_length(), 5_900_353_862_872);
        assert_eq!(requirement.total_read_byte_length(), 11_468_451_326_432);
        assert_eq!(requirement.transaction_count(), 77_262_030_541);
        assert_eq!(object_count_variance, 32_726);
        assert_eq!(peak_stored_byte_length_variance, 76_974_399_040);
        assert!(
            usize::try_from(requirement.distinct_physical_object_count())
                .is_ok_and(|count| count > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
        );
        assert!(
            requirement.peak_stored_byte_length()
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        );
    }
}

#[cfg(test)]
pub(crate) use resource_accounting::{
    SelectedCompleteActionMaterialResourceAccounting, SelectedProofExternalMemoryDiagnosticError,
    SelectedProofExternalMemoryDiagnosticRequirement, SelectedProofExternalMemoryDiagnosticRow,
    SelectedProofQueryTreeResourceAccounting, SelectedProofResidentPhaseResourceAccounting,
    derive_selected_complete_action_material_resource_accounting,
    selected_complete_proof_resource_accounting, selected_proof_external_memory_diagnostic_report,
};

#[cfg(test)]
mod resource_accounting {
    use super::*;

    fn selected_proof_component_byte_accounting(
        ceiling: &CommonProofByteLengthCeiling,
    ) -> Result<SelectedProofComponentByteAccounting, SelectedProofAccountingError> {
        let component_byte_lengths = ceiling.component_byte_lengths();
        let accounting = SelectedProofComponentByteAccounting {
            canonical_framing_byte_length_ceiling: u64::try_from(
                component_byte_lengths.canonical_framing(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            relation_commitments_and_openings_byte_length_ceiling: u64::try_from(
                component_byte_lengths.relation_commitments_and_openings(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            quotient_commitments_and_openings_byte_length_ceiling: u64::try_from(
                component_byte_lengths.quotient_commitments_and_openings(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            transcript_opening_claims_byte_length_ceiling: u64::try_from(
                component_byte_lengths.transcript_opening_claims(),
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            fri_byte_length_ceiling: u64::try_from(component_byte_lengths.fri())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        };
        if accounting.proof_byte_length_ceiling()
            != Some(
                u64::try_from(ceiling.proof_byte_length())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            )
        {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
        Ok(accounting)
    }

    fn selected_proof_query_tree_resource_accounting(
        transport_sizing: &SelectedProofTransportSizing,
    ) -> Result<
        (Box<[SelectedProofQueryTreeResourceAccounting]>, u32, u64),
        SelectedProofAccountingError,
    > {
        let catalog_entries = transport_sizing.layout.catalog().entries();
        let query_trees = transport_sizing.ceiling.query_trees();
        if catalog_entries.len() != query_trees.len() {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(query_trees.len())
            .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
        let mut bound_public_tree_count = 0_u32;
        let mut total_materialized_row_width = 0_u64;
        for (entry, tree) in catalog_entries.iter().zip(query_trees) {
            if entry.tree_catalog_index() != tree.tree_catalog_index()
                || entry.source() != tree.source()
            {
                return Err(SelectedProofAccountingError::InvalidTreeGeometry);
            }
            let is_bound_public_tree = entry.bound_root().is_some();
            bound_public_tree_count = bound_public_tree_count
                .checked_add(u32::from(is_bound_public_tree))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            let materialized_row_width = u64::try_from(
                entry
                    .materialized_row_width()
                    .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?,
            )
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            total_materialized_row_width = total_materialized_row_width
                .checked_add(materialized_row_width)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            rows.push(SelectedProofQueryTreeResourceAccounting {
                tree_catalog_index: tree.tree_catalog_index(),
                is_bound_public_tree,
                materialized_row_width,
                leaf_count: u64::try_from(tree.leaf_count())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                minimum_opened_leaf_count: u64::try_from(tree.minimum_opened_leaf_count())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                maximum_opened_leaf_count: u64::try_from(tree.maximum_opened_leaf_count())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                opened_leaf_count_at_ceiling: u64::try_from(tree.opened_leaf_count_at_ceiling())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                authentication_frontier_node_count_at_ceiling: u64::try_from(
                    tree.authentication_frontier_node_count_at_ceiling(),
                )
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                opened_leaf_payload_byte_length_ceiling: u64::try_from(
                    tree.opened_leaf_payload_byte_length(),
                )
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                authentication_frontier_digest_byte_length_ceiling: u64::try_from(
                    tree.authentication_frontier_digest_byte_length(),
                )
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                canonical_framing_byte_length_ceiling: u64::try_from(
                    tree.canonical_framing_byte_length(),
                )
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                byte_length_ceiling: u64::try_from(tree.byte_length())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            });
        }
        Ok((
            rows.into_boxed_slice(),
            bound_public_tree_count,
            total_materialized_row_width,
        ))
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedProofComponentByteAccounting {
        canonical_framing_byte_length_ceiling: u64,
        relation_commitments_and_openings_byte_length_ceiling: u64,
        quotient_commitments_and_openings_byte_length_ceiling: u64,
        transcript_opening_claims_byte_length_ceiling: u64,
        fri_byte_length_ceiling: u64,
    }

    impl SelectedProofComponentByteAccounting {
        pub(crate) const fn canonical_framing_byte_length_ceiling(self) -> u64 {
            self.canonical_framing_byte_length_ceiling
        }

        pub(crate) const fn relation_commitments_and_openings_byte_length_ceiling(self) -> u64 {
            self.relation_commitments_and_openings_byte_length_ceiling
        }

        pub(crate) const fn quotient_commitments_and_openings_byte_length_ceiling(self) -> u64 {
            self.quotient_commitments_and_openings_byte_length_ceiling
        }

        pub(crate) const fn transcript_opening_claims_byte_length_ceiling(self) -> u64 {
            self.transcript_opening_claims_byte_length_ceiling
        }

        pub(crate) const fn fri_byte_length_ceiling(self) -> u64 {
            self.fri_byte_length_ceiling
        }

        pub(crate) fn proof_byte_length_ceiling(self) -> Option<u64> {
            self.canonical_framing_byte_length_ceiling
                .checked_add(self.relation_commitments_and_openings_byte_length_ceiling)
                .and_then(|length| {
                    length.checked_add(self.quotient_commitments_and_openings_byte_length_ceiling)
                })
                .and_then(|length| {
                    length.checked_add(self.transcript_opening_claims_byte_length_ceiling)
                })
                .and_then(|length| length.checked_add(self.fri_byte_length_ceiling))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedProofQueryTreeResourceAccounting {
        tree_catalog_index: u16,
        is_bound_public_tree: bool,
        materialized_row_width: u64,
        leaf_count: u64,
        minimum_opened_leaf_count: u64,
        maximum_opened_leaf_count: u64,
        opened_leaf_count_at_ceiling: u64,
        authentication_frontier_node_count_at_ceiling: u64,
        opened_leaf_payload_byte_length_ceiling: u64,
        authentication_frontier_digest_byte_length_ceiling: u64,
        canonical_framing_byte_length_ceiling: u64,
        byte_length_ceiling: u64,
    }

    impl SelectedProofQueryTreeResourceAccounting {
        pub(crate) const fn tree_catalog_index(self) -> u16 {
            self.tree_catalog_index
        }

        pub(crate) const fn is_bound_public_tree(self) -> bool {
            self.is_bound_public_tree
        }

        pub(crate) const fn materialized_row_width(self) -> u64 {
            self.materialized_row_width
        }

        pub(crate) const fn leaf_count(self) -> u64 {
            self.leaf_count
        }

        pub(crate) const fn minimum_opened_leaf_count(self) -> u64 {
            self.minimum_opened_leaf_count
        }

        pub(crate) const fn maximum_opened_leaf_count(self) -> u64 {
            self.maximum_opened_leaf_count
        }

        pub(crate) const fn opened_leaf_count_at_ceiling(self) -> u64 {
            self.opened_leaf_count_at_ceiling
        }

        pub(crate) const fn authentication_frontier_node_count_at_ceiling(self) -> u64 {
            self.authentication_frontier_node_count_at_ceiling
        }

        pub(crate) const fn opened_leaf_payload_byte_length_ceiling(self) -> u64 {
            self.opened_leaf_payload_byte_length_ceiling
        }

        pub(crate) const fn authentication_frontier_digest_byte_length_ceiling(self) -> u64 {
            self.authentication_frontier_digest_byte_length_ceiling
        }

        pub(crate) const fn canonical_framing_byte_length_ceiling(self) -> u64 {
            self.canonical_framing_byte_length_ceiling
        }

        pub(crate) const fn byte_length_ceiling(self) -> u64 {
            self.byte_length_ceiling
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedProofResidentPhaseResourceAccounting {
        phase: CommonProofResidentMemoryPhase,
        prover_resident_byte_length: u64,
        source_provider_persistent_resident_byte_length: u64,
        source_provider_loading_transient_byte_length: u64,
        application_runtime_persistent_resident_byte_length: u64,
        application_runtime_boundary_overlap_byte_length: u64,
        checkpoint_custody_byte_length: u64,
        combined_wasm_resident_byte_length: u64,
    }

    impl SelectedProofResidentPhaseResourceAccounting {
        pub(crate) const fn phase(self) -> CommonProofResidentMemoryPhase {
            self.phase
        }

        pub(crate) const fn phase_code(self) -> u8 {
            self.phase as u8
        }

        pub(crate) const fn phase_name(self) -> &'static str {
            match self.phase {
                CommonProofResidentMemoryPhase::LoadingSourcePolynomials => {
                    "loading-source-polynomials"
                }
                CommonProofResidentMemoryPhase::ConstructingReversedColumns => {
                    "constructing-reversed-columns"
                }
                CommonProofResidentMemoryPhase::TransformingBaseColumns => {
                    "transforming-base-columns"
                }
                CommonProofResidentMemoryPhase::MaterializingBaseTrees => {
                    "materializing-base-trees"
                }
                CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns => {
                    "deriving-auxiliary-columns"
                }
                CommonProofResidentMemoryPhase::TransformingAuxiliaryColumns => {
                    "transforming-auxiliary-columns"
                }
                CommonProofResidentMemoryPhase::MaterializingAuxiliaryTrees => {
                    "materializing-auxiliary-trees"
                }
                CommonProofResidentMemoryPhase::ConstructingQuotient => "constructing-quotient",
                CommonProofResidentMemoryPhase::MaterializingQuotientTrees => {
                    "materializing-quotient-trees"
                }
                CommonProofResidentMemoryPhase::DerivingOpenings => "deriving-openings",
                CommonProofResidentMemoryPhase::ConstructingInitialFri => {
                    "constructing-initial-fri"
                }
                CommonProofResidentMemoryPhase::FoldingFri => "folding-fri",
                CommonProofResidentMemoryPhase::PreparingQueryOutput => "preparing-query-output",
                CommonProofResidentMemoryPhase::EmittingQueries => "emitting-queries",
            }
        }

        pub(crate) const fn prover_resident_byte_length(self) -> u64 {
            self.prover_resident_byte_length
        }

        pub(crate) const fn source_provider_persistent_resident_byte_length(self) -> u64 {
            self.source_provider_persistent_resident_byte_length
        }

        pub(crate) const fn source_provider_loading_transient_byte_length(self) -> u64 {
            self.source_provider_loading_transient_byte_length
        }

        pub(crate) const fn application_runtime_persistent_resident_byte_length(self) -> u64 {
            self.application_runtime_persistent_resident_byte_length
        }

        pub(crate) const fn application_runtime_boundary_overlap_byte_length(self) -> u64 {
            self.application_runtime_boundary_overlap_byte_length
        }

        pub(crate) const fn checkpoint_custody_byte_length(self) -> u64 {
            self.checkpoint_custody_byte_length
        }

        pub(crate) const fn combined_wasm_resident_byte_length(self) -> u64 {
            self.combined_wasm_resident_byte_length
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SelectedResidentMemoryBounds {
        maximum_combined_wasm_resident_byte_length: u64,
        ordered_phases: Box<[SelectedProofResidentPhaseResourceAccounting]>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SelectedProofVariantResourceBounds {
        maximum_combined_wasm_resident_byte_length: u64,
        resident_phases: Box<[SelectedProofResidentPhaseResourceAccounting]>,
        maximum_prefetched_query_byte_length: u64,
        maximum_external_memory_transaction_payload_byte_length: u64,
        maximum_proof_output_chunk_byte_length_ceiling: u64,
        proof_output_chunk_count_ceiling: u64,
        maximum_copied_buffer_byte_length: u64,
    }

    /// One compiler-derived selected-suite proof variant. This is process-local
    /// accounting, not a serialized proof field or an acceptance claim.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedProofVariantResourceAccounting {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        complete_action_application_multiplicity: u32,
        logical_entry_count: u32,
        evaluation_domain_size: u64,
        opening_degree_bound_exclusive: u64,
        relation_column_count: u32,
        verifier_sequence_relation_column_count: u32,
        bound_tree_relation_column_count: u32,
        prover_relation_column_count: u32,
        relation_constraint_count: u32,
        quotient_decomposition_stride: u64,
        quotient_component_degree_bound_exclusive: u64,
        quotient_component_count: u16,
        fri_fold_count: u16,
        terminal_coefficient_count: u32,
        unique_query_count: u32,
        query_orbit_count: u64,
        canonical_header_byte_length_ceiling: u64,
        body_prefix_byte_length_ceiling: u64,
        query_section_byte_length_ceiling: u64,
        proof_byte_length_ceiling: usize,
        proof_component_byte_accounting: SelectedProofComponentByteAccounting,
        ordered_query_trees: Box<[SelectedProofQueryTreeResourceAccounting]>,
        bound_public_tree_count: u32,
        total_materialized_row_width: u64,
        maximum_combined_wasm_resident_byte_length: u64,
        resident_phases: Box<[SelectedProofResidentPhaseResourceAccounting]>,
        maximum_prefetched_query_byte_length: u64,
        maximum_external_memory_transaction_payload_byte_length: u64,
        maximum_proof_output_chunk_byte_length_ceiling: u64,
        proof_output_chunk_count_ceiling: u64,
        maximum_copied_buffer_byte_length: u64,
    }

    impl SelectedProofVariantResourceAccounting {
        pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
            self.application_statement_schema_identifier
        }

        pub(crate) const fn schedule_position(&self) -> Option<u32> {
            self.schedule_position
        }

        pub(crate) const fn top_count(&self) -> Option<u16> {
            self.top_count
        }

        pub(crate) const fn complete_action_application_multiplicity(&self) -> u32 {
            self.complete_action_application_multiplicity
        }

        pub(crate) const fn logical_entry_count(&self) -> u32 {
            self.logical_entry_count
        }

        pub(crate) const fn evaluation_domain_size(&self) -> u64 {
            self.evaluation_domain_size
        }

        pub(crate) const fn opening_degree_bound_exclusive(&self) -> u64 {
            self.opening_degree_bound_exclusive
        }

        pub(crate) const fn relation_column_count(&self) -> u32 {
            self.relation_column_count
        }

        pub(crate) const fn verifier_sequence_relation_column_count(&self) -> u32 {
            self.verifier_sequence_relation_column_count
        }

        pub(crate) const fn bound_tree_relation_column_count(&self) -> u32 {
            self.bound_tree_relation_column_count
        }

        pub(crate) const fn prover_relation_column_count(&self) -> u32 {
            self.prover_relation_column_count
        }

        pub(crate) const fn relation_constraint_count(&self) -> u32 {
            self.relation_constraint_count
        }

        pub(crate) const fn quotient_decomposition_stride(&self) -> u64 {
            self.quotient_decomposition_stride
        }

        pub(crate) const fn quotient_component_degree_bound_exclusive(&self) -> u64 {
            self.quotient_component_degree_bound_exclusive
        }

        pub(crate) const fn quotient_component_count(&self) -> u16 {
            self.quotient_component_count
        }

        pub(crate) const fn fri_fold_count(&self) -> u16 {
            self.fri_fold_count
        }

        pub(crate) const fn terminal_coefficient_count(&self) -> u32 {
            self.terminal_coefficient_count
        }

        pub(crate) const fn unique_query_count(&self) -> u32 {
            self.unique_query_count
        }

        pub(crate) const fn query_orbit_count(&self) -> u64 {
            self.query_orbit_count
        }

        pub(crate) const fn canonical_header_byte_length_ceiling(&self) -> u64 {
            self.canonical_header_byte_length_ceiling
        }

        pub(crate) const fn body_prefix_byte_length_ceiling(&self) -> u64 {
            self.body_prefix_byte_length_ceiling
        }

        pub(crate) const fn query_section_byte_length_ceiling(&self) -> u64 {
            self.query_section_byte_length_ceiling
        }

        pub(crate) const fn proof_byte_length_ceiling(&self) -> usize {
            self.proof_byte_length_ceiling
        }

        pub(crate) const fn proof_component_byte_accounting(
            &self,
        ) -> SelectedProofComponentByteAccounting {
            self.proof_component_byte_accounting
        }

        pub(crate) fn ordered_query_trees(&self) -> &[SelectedProofQueryTreeResourceAccounting] {
            &self.ordered_query_trees
        }

        pub(crate) const fn bound_public_tree_count(&self) -> u32 {
            self.bound_public_tree_count
        }

        pub(crate) const fn total_materialized_row_width(&self) -> u64 {
            self.total_materialized_row_width
        }

        pub(crate) const fn maximum_combined_wasm_resident_byte_length(&self) -> u64 {
            self.maximum_combined_wasm_resident_byte_length
        }

        pub(crate) fn resident_phases(&self) -> &[SelectedProofResidentPhaseResourceAccounting] {
            &self.resident_phases
        }

        pub(crate) const fn maximum_prefetched_query_byte_length(&self) -> u64 {
            self.maximum_prefetched_query_byte_length
        }

        pub(crate) const fn maximum_external_memory_transaction_payload_byte_length(&self) -> u64 {
            self.maximum_external_memory_transaction_payload_byte_length
        }

        pub(crate) const fn maximum_proof_output_chunk_byte_length_ceiling(&self) -> u64 {
            self.maximum_proof_output_chunk_byte_length_ceiling
        }

        pub(crate) const fn proof_output_chunk_count_ceiling(&self) -> u64 {
            self.proof_output_chunk_count_ceiling
        }

        pub(crate) const fn maximum_copied_buffer_byte_length(&self) -> u64 {
            self.maximum_copied_buffer_byte_length
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SelectedProofExternalMemoryDiagnosticError {
        MissingRelationContext,
        CanonicalApplicationStatement(SelectedProofAccountingError),
        TransportSizing(SelectedProofAccountingError),
        ProofResourceRequirement(GeneratedCommonProofStoragePlanError),
        SourceProviderMemory(SelectedProofAccountingError),
        ApplicationRuntimeMemory(SelectedProofAccountingError),
        CheckpointCustody(SelectedProofAccountingError),
        ResidentMemoryAccounting(SelectedProofAccountingError),
        QueryTreeAccounting(SelectedProofAccountingError),
        RelationGeometry(SelectedProofAccountingError),
        CompleteActionMultiplicity(SelectedProofAccountingError),
        LogicalEntryCount(SelectedProofAccountingError),
        OpeningClaimCount(SelectedProofAccountingError),
    }

    impl SelectedProofExternalMemoryDiagnosticError {
        pub(crate) const fn stage(self) -> &'static str {
            match self {
                Self::MissingRelationContext => "relation-context",
                Self::CanonicalApplicationStatement(_) => "canonical-application-statement",
                Self::TransportSizing(_) => "transport-sizing",
                Self::ProofResourceRequirement(_) => "proof-resource-requirement",
                Self::SourceProviderMemory(_) => "source-provider-memory",
                Self::ApplicationRuntimeMemory(_) => "application-runtime-memory",
                Self::CheckpointCustody(_) => "checkpoint-custody",
                Self::ResidentMemoryAccounting(_) => "resident-memory-accounting",
                Self::QueryTreeAccounting(_) => "query-tree-accounting",
                Self::RelationGeometry(_) => "relation-geometry",
                Self::CompleteActionMultiplicity(_) => "complete-action-multiplicity",
                Self::LogicalEntryCount(_) => "logical-entry-count",
                Self::OpeningClaimCount(_) => "opening-claim-count",
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedProofExternalMemoryDiagnosticRequirement {
        external_memory_requirement: CommonProofExternalMemoryRequirement,
        complete_action_application_multiplicity: u32,
        logical_entry_count: u32,
        opening_claim_count: u32,
        evaluation_domain_size: u64,
        opening_degree_bound_exclusive: u64,
        verifier_sequence_relation_column_count: u32,
        bound_tree_relation_column_count: u32,
        prover_relation_column_count: u32,
        quotient_decomposition_stride: u64,
        quotient_component_degree_bound_exclusive: u64,
        quotient_component_count: u16,
        fri_fold_count: u16,
        terminal_coefficient_count: u32,
        unique_query_count: u32,
        query_orbit_count: u64,
        proof_byte_length_ceiling: usize,
        canonical_header_byte_length_ceiling: u64,
        body_prefix_byte_length_ceiling: u64,
        query_section_byte_length_ceiling: u64,
        proof_component_byte_accounting: SelectedProofComponentByteAccounting,
        ordered_query_trees: Box<[SelectedProofQueryTreeResourceAccounting]>,
        bound_public_tree_count: u32,
        total_materialized_row_width: u64,
        maximum_combined_wasm_resident_byte_length: u64,
        resident_phases: Box<[SelectedProofResidentPhaseResourceAccounting]>,
        maximum_prefetched_query_byte_length: u64,
        maximum_external_memory_transaction_payload_byte_length: u64,
        maximum_proof_output_chunk_byte_length_ceiling: u64,
        proof_output_chunk_count_ceiling: u64,
        maximum_copied_buffer_byte_length: u64,
    }

    impl SelectedProofExternalMemoryDiagnosticRequirement {
        pub(crate) const fn external_memory_requirement(
            &self,
        ) -> CommonProofExternalMemoryRequirement {
            self.external_memory_requirement
        }

        pub(crate) const fn complete_action_application_multiplicity(&self) -> u32 {
            self.complete_action_application_multiplicity
        }

        pub(crate) const fn logical_entry_count(&self) -> u32 {
            self.logical_entry_count
        }

        pub(crate) const fn opening_claim_count(&self) -> u32 {
            self.opening_claim_count
        }

        pub(crate) const fn evaluation_domain_size(&self) -> u64 {
            self.evaluation_domain_size
        }

        pub(crate) const fn opening_degree_bound_exclusive(&self) -> u64 {
            self.opening_degree_bound_exclusive
        }

        pub(crate) const fn verifier_sequence_relation_column_count(&self) -> u32 {
            self.verifier_sequence_relation_column_count
        }

        pub(crate) const fn bound_tree_relation_column_count(&self) -> u32 {
            self.bound_tree_relation_column_count
        }

        pub(crate) const fn prover_relation_column_count(&self) -> u32 {
            self.prover_relation_column_count
        }

        pub(crate) const fn quotient_decomposition_stride(&self) -> u64 {
            self.quotient_decomposition_stride
        }

        pub(crate) const fn quotient_component_degree_bound_exclusive(&self) -> u64 {
            self.quotient_component_degree_bound_exclusive
        }

        pub(crate) const fn quotient_component_count(&self) -> u16 {
            self.quotient_component_count
        }

        pub(crate) const fn fri_fold_count(&self) -> u16 {
            self.fri_fold_count
        }

        pub(crate) const fn terminal_coefficient_count(&self) -> u32 {
            self.terminal_coefficient_count
        }

        pub(crate) const fn unique_query_count(&self) -> u32 {
            self.unique_query_count
        }

        pub(crate) const fn query_orbit_count(&self) -> u64 {
            self.query_orbit_count
        }

        pub(crate) const fn proof_byte_length_ceiling(&self) -> usize {
            self.proof_byte_length_ceiling
        }

        pub(crate) const fn canonical_header_byte_length_ceiling(&self) -> u64 {
            self.canonical_header_byte_length_ceiling
        }

        pub(crate) const fn body_prefix_byte_length_ceiling(&self) -> u64 {
            self.body_prefix_byte_length_ceiling
        }

        pub(crate) const fn query_section_byte_length_ceiling(&self) -> u64 {
            self.query_section_byte_length_ceiling
        }

        pub(crate) const fn proof_component_byte_accounting(
            &self,
        ) -> SelectedProofComponentByteAccounting {
            self.proof_component_byte_accounting
        }

        pub(crate) fn ordered_query_trees(&self) -> &[SelectedProofQueryTreeResourceAccounting] {
            &self.ordered_query_trees
        }

        pub(crate) const fn bound_public_tree_count(&self) -> u32 {
            self.bound_public_tree_count
        }

        pub(crate) const fn total_materialized_row_width(&self) -> u64 {
            self.total_materialized_row_width
        }

        pub(crate) const fn maximum_combined_wasm_resident_byte_length(&self) -> u64 {
            self.maximum_combined_wasm_resident_byte_length
        }

        pub(crate) fn resident_phases(&self) -> &[SelectedProofResidentPhaseResourceAccounting] {
            &self.resident_phases
        }

        pub(crate) const fn maximum_prefetched_query_byte_length(&self) -> u64 {
            self.maximum_prefetched_query_byte_length
        }

        pub(crate) const fn maximum_external_memory_transaction_payload_byte_length(&self) -> u64 {
            self.maximum_external_memory_transaction_payload_byte_length
        }

        pub(crate) const fn maximum_proof_output_chunk_byte_length_ceiling(&self) -> u64 {
            self.maximum_proof_output_chunk_byte_length_ceiling
        }

        pub(crate) const fn proof_output_chunk_count_ceiling(&self) -> u64 {
            self.proof_output_chunk_count_ceiling
        }

        pub(crate) const fn maximum_copied_buffer_byte_length(&self) -> u64 {
            self.maximum_copied_buffer_byte_length
        }
    }

    /// One cap-neutral diagnostic row. This process-local report is neither a
    /// proof field nor an acceptance result; production generation continues
    /// to construct and enforce the capped external-memory plan independently.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedProofExternalMemoryDiagnosticRow {
        application_statement_schema_identifier: u16,
        schedule_position: Option<u32>,
        top_count: Option<u16>,
        relation_column_count: usize,
        relation_constraint_count: usize,
        outcome: Result<
            SelectedProofExternalMemoryDiagnosticRequirement,
            SelectedProofExternalMemoryDiagnosticError,
        >,
    }

    impl SelectedProofExternalMemoryDiagnosticRow {
        pub(crate) const fn application_statement_schema_identifier(&self) -> u16 {
            self.application_statement_schema_identifier
        }

        pub(crate) const fn schedule_position(&self) -> Option<u32> {
            self.schedule_position
        }

        pub(crate) const fn top_count(&self) -> Option<u16> {
            self.top_count
        }

        pub(crate) const fn relation_column_count(&self) -> usize {
            self.relation_column_count
        }

        pub(crate) const fn relation_constraint_count(&self) -> usize {
            self.relation_constraint_count
        }

        pub(crate) fn outcome(
            &self,
        ) -> Result<
            SelectedProofExternalMemoryDiagnosticRequirement,
            SelectedProofExternalMemoryDiagnosticError,
        > {
            self.outcome.clone()
        }
    }

    fn selected_relation_column_origin_counts(
        variant: &RelationPlanVariant,
    ) -> Result<(u32, u32, u32, u32), SelectedProofAccountingError> {
        let relation_column_count = u32::try_from(variant.ordered_columns().len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let mut verifier_sequence_relation_column_count = 0_u32;
        let mut bound_tree_relation_column_count = 0_u32;
        let mut prover_relation_column_count = 0_u32;
        for column in variant.ordered_columns() {
            let target = match column.origin() {
                RelationColumnOrigin::VerifierSequence { .. } => {
                    &mut verifier_sequence_relation_column_count
                }
                RelationColumnOrigin::BoundTree { .. } => &mut bound_tree_relation_column_count,
                RelationColumnOrigin::Prover => &mut prover_relation_column_count,
            };
            *target = target
                .checked_add(1)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        }
        if verifier_sequence_relation_column_count
            .checked_add(bound_tree_relation_column_count)
            .and_then(|count| count.checked_add(prover_relation_column_count))
            != Some(relation_column_count)
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok((
            relation_column_count,
            verifier_sequence_relation_column_count,
            bound_tree_relation_column_count,
            prover_relation_column_count,
        ))
    }

    pub(crate) fn selected_proof_external_memory_diagnostic_report()
    -> Result<Box<[SelectedProofExternalMemoryDiagnosticRow]>, SelectedProofAccountingError> {
        let proof_profile =
            selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let key_positions = selected_evaluator_program_set()
            .and_then(|program| program.key_positions())
            .map_err(|_| SelectedProofAccountingError::InvalidProfile);
        let application_slot_ceilings = selected_proof_application_slot_ceilings()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile);
        let variant_count =
            proof_profile
                .relation_plans()
                .iter()
                .try_fold(0_usize, |count, relation_plan| {
                    count
                        .checked_add(relation_plan.compiled_plan().variants().len())
                        .ok_or(SelectedProofAccountingError::CountOverflow)
                })?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(variant_count)
            .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;

        for relation_plan in proof_profile.relation_plans() {
            let application_statement_schema_identifier =
                relation_plan.application_statement_schema_identifier();
            let relation_context =
                selected_relation_plan_check_context(application_statement_schema_identifier);
            for variant in relation_plan.compiled_plan().variants() {
                let outcome = (|| {
                    let relation_context = relation_context.as_ref().ok_or(
                        SelectedProofExternalMemoryDiagnosticError::MissingRelationContext,
                    )?;
                    let statement_context = SelectedApplicationStatementContext::new(
                        FOUNDATION_PROFILE.protocol_version,
                        [0; Hash512::BYTE_LENGTH],
                        variant.schedule_position(),
                        variant.top_count(),
                    );
                    let canonical_application_statement_bytes =
                        canonical_selected_application_statement_for_ceiling(
                            application_statement_schema_identifier,
                            statement_context,
                        )
                        .map_err(|_| {
                            SelectedProofExternalMemoryDiagnosticError::CanonicalApplicationStatement(
                                SelectedProofAccountingError::CanonicalEncoding,
                            )
                        })?;
                    let transport_sizing = selected_cap_neutral_proof_transport_sizing(
                        application_statement_schema_identifier,
                        &canonical_application_statement_bytes,
                        variant,
                        relation_context,
                    )
                    .map_err(SelectedProofExternalMemoryDiagnosticError::TransportSizing)?;
                    let canonical_header_byte_length =
                        u64::try_from(transport_sizing.ceiling.canonical_header_byte_length())
                            .map_err(|_| {
                                SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                                    SelectedProofAccountingError::CountOverflow,
                                )
                            })?;
                    let cap_neutral_resource_requirement =
                        common_proof_cap_neutral_resource_requirement(
                            variant,
                            relation_context,
                            &transport_sizing.transcript_schedule,
                            transport_sizing.layout.catalog(),
                            CommonProofResidentMemoryConfiguration::new(
                                application_statement_schema_identifier,
                                canonical_header_byte_length,
                                transport_sizing.maximum_prefetched_query_byte_length,
                                u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
                                u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH).map_err(
                                    |_| {
                                        SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                                            SelectedProofAccountingError::CountOverflow,
                                        )
                                    },
                                )?,
                            ),
                        )
                        .map_err(
                            SelectedProofExternalMemoryDiagnosticError::ProofResourceRequirement,
                        )?;
                    let external_memory_requirement =
                        cap_neutral_resource_requirement.external_memory_requirement();
                    let committed_material_source_provider_memory_accounting =
                        selected_committed_material_source_provider_memory_accounting(
                            application_statement_schema_identifier,
                            relation_context,
                            relation_plan.compiled_plan(),
                        )
                        .map_err(
                            SelectedProofExternalMemoryDiagnosticError::SourceProviderMemory,
                        )?;
                    let source_provider_memory_accounting =
                        selected_source_provider_memory_accounting(
                            application_statement_schema_identifier,
                            &canonical_application_statement_bytes,
                            variant,
                            relation_context,
                            committed_material_source_provider_memory_accounting,
                        )
                        .map_err(
                            SelectedProofExternalMemoryDiagnosticError::SourceProviderMemory,
                        )?;
                    let application_runtime_memory_accounting =
                        selected_application_runtime_memory_accounting(
                            application_statement_schema_identifier,
                            &canonical_application_statement_bytes,
                            source_provider_memory_accounting,
                        )
                        .map_err(
                            SelectedProofExternalMemoryDiagnosticError::ApplicationRuntimeMemory,
                        )?;
                    let checkpoint_custody_requirement =
                        common_proof_generation_checkpoint_custody_requirement_for_variant(variant)
                            .map_err(|_| {
                                SelectedProofExternalMemoryDiagnosticError::CheckpointCustody(
                                    SelectedProofAccountingError::ResourcePlanning,
                                )
                            })?;
                    let resident_memory_bounds = derive_selected_resident_memory_bounds(
                        cap_neutral_resource_requirement.resident_memory_requirement(),
                        checkpoint_custody_requirement,
                        transport_sizing.transcript_schedule.fri_fold_count(),
                        source_provider_memory_accounting,
                        application_runtime_memory_accounting,
                        false,
                    )
                    .map_err(
                        SelectedProofExternalMemoryDiagnosticError::ResidentMemoryAccounting,
                    )?;
                    let complete_action_application_multiplicity =
                        selected_complete_action_variant_multiplicity(
                            application_statement_schema_identifier,
                            variant,
                            application_slot_ceilings.as_ref().map_err(|error| {
                                SelectedProofExternalMemoryDiagnosticError::CompleteActionMultiplicity(
                                    *error,
                                )
                            })?,
                            key_positions.as_ref().map_err(|error| {
                                SelectedProofExternalMemoryDiagnosticError::CompleteActionMultiplicity(
                                    *error,
                                )
                            })?,
                        )
                        .map_err(
                            SelectedProofExternalMemoryDiagnosticError::CompleteActionMultiplicity,
                        )?;
                    let logical_entry_count = selected_variant_logical_entry_count(
                        application_statement_schema_identifier,
                        variant,
                    )
                    .map_err(SelectedProofExternalMemoryDiagnosticError::LogicalEntryCount)?;
                    let opening_claim_count = u32::try_from(variant.ordered_opening_claims().len())
                        .map_err(|_| {
                            SelectedProofExternalMemoryDiagnosticError::OpeningClaimCount(
                                SelectedProofAccountingError::CountOverflow,
                            )
                        })?;
                    let (
                        _,
                        verifier_sequence_relation_column_count,
                        bound_tree_relation_column_count,
                        prover_relation_column_count,
                    ) = selected_relation_column_origin_counts(variant)
                        .map_err(SelectedProofExternalMemoryDiagnosticError::RelationGeometry)?;
                    let quotient_decomposition_stride = variant
                        .quotient_decomposition_stride(relation_context)
                        .map_err(|_| {
                            SelectedProofExternalMemoryDiagnosticError::RelationGeometry(
                                SelectedProofAccountingError::InvalidProfile,
                            )
                        })?;
                    let (
                        ordered_query_trees,
                        bound_public_tree_count,
                        total_materialized_row_width,
                    ) = selected_proof_query_tree_resource_accounting(&transport_sizing)
                        .map_err(SelectedProofExternalMemoryDiagnosticError::QueryTreeAccounting)?;
                    let proof_component_byte_accounting =
                        selected_proof_component_byte_accounting(&transport_sizing.ceiling)
                            .map_err(SelectedProofExternalMemoryDiagnosticError::TransportSizing)?;
                    let proof_byte_length_ceiling = transport_sizing.ceiling.proof_byte_length();
                    let proof_byte_length_ceiling_u64 =
                        u64::try_from(proof_byte_length_ceiling).map_err(|_| {
                        SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                            SelectedProofAccountingError::CountOverflow,
                        )
                    })?;
                    let maximum_proof_output_chunk_byte_length_ceiling =
                        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                            .map_err(|_| {
                                SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                                    SelectedProofAccountingError::CountOverflow,
                                )
                            })?
                            .min(proof_byte_length_ceiling_u64);
                    let proof_output_chunk_count_ceiling = proof_byte_length_ceiling_u64.div_ceil(
                        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH).map_err(|_| {
                            SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                                SelectedProofAccountingError::CountOverflow,
                            )
                        })?,
                    );
                    let maximum_copied_buffer_byte_length = [
                        transport_sizing.maximum_prefetched_query_byte_length,
                        external_memory_requirement.maximum_transaction_payload_byte_length(),
                        maximum_proof_output_chunk_byte_length_ceiling,
                        u64::from(checkpoint_custody_requirement.peak_copied_buffer_byte_length()),
                    ]
                    .into_iter()
                    .max()
                    .ok_or(
                        SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                            SelectedProofAccountingError::ResourcePlanning,
                        ),
                    )?;
                    Ok(SelectedProofExternalMemoryDiagnosticRequirement {
                        external_memory_requirement,
                        complete_action_application_multiplicity,
                        logical_entry_count,
                        opening_claim_count,
                        evaluation_domain_size: variant.evaluation_domain_size(),
                        opening_degree_bound_exclusive: variant.opening_degree_bound_exclusive(),
                        verifier_sequence_relation_column_count,
                        bound_tree_relation_column_count,
                        prover_relation_column_count,
                        quotient_decomposition_stride,
                        quotient_component_degree_bound_exclusive: relation_context
                            .quotient_component_degree_bound_exclusive,
                        quotient_component_count: transport_sizing
                            .transcript_schedule
                            .quotient_component_count(),
                        fri_fold_count: transport_sizing.transcript_schedule.fri_fold_count(),
                        terminal_coefficient_count: transport_sizing
                            .transcript_schedule
                            .terminal_coefficient_count(),
                        unique_query_count: transport_sizing
                            .transcript_schedule
                            .unique_query_count(),
                        query_orbit_count: transport_sizing.transcript_schedule.query_orbit_count(),
                        proof_byte_length_ceiling,
                        canonical_header_byte_length_ceiling: canonical_header_byte_length,
                        body_prefix_byte_length_ceiling: u64::try_from(
                            transport_sizing.ceiling.body_prefix_byte_length(),
                        )
                        .map_err(|_| {
                            SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                                SelectedProofAccountingError::CountOverflow,
                            )
                        })?,
                        query_section_byte_length_ceiling: u64::try_from(
                            transport_sizing.ceiling.query_section_byte_length(),
                        )
                        .map_err(|_| {
                            SelectedProofExternalMemoryDiagnosticError::TransportSizing(
                                SelectedProofAccountingError::CountOverflow,
                            )
                        })?,
                        proof_component_byte_accounting,
                        ordered_query_trees,
                        bound_public_tree_count,
                        total_materialized_row_width,
                        maximum_combined_wasm_resident_byte_length: resident_memory_bounds
                            .maximum_combined_wasm_resident_byte_length,
                        resident_phases: resident_memory_bounds.ordered_phases,
                        maximum_prefetched_query_byte_length: transport_sizing
                            .maximum_prefetched_query_byte_length,
                        maximum_external_memory_transaction_payload_byte_length:
                            external_memory_requirement.maximum_transaction_payload_byte_length(),
                        maximum_proof_output_chunk_byte_length_ceiling,
                        proof_output_chunk_count_ceiling,
                        maximum_copied_buffer_byte_length,
                    })
                })();
                rows.push(SelectedProofExternalMemoryDiagnosticRow {
                    application_statement_schema_identifier,
                    schedule_position: variant.schedule_position(),
                    top_count: variant.top_count(),
                    relation_column_count: variant.ordered_columns().len(),
                    relation_constraint_count: variant.ordered_constraint_count(),
                    outcome,
                });
            }
        }
        if rows.len() != variant_count {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok(rows.into_boxed_slice())
    }

    static SELECTED_PROOF_VARIANT_RESOURCE_INVENTORY: OnceLock<
        Result<Box<[SelectedProofVariantResourceAccounting]>, SelectedProofAccountingError>,
    > = OnceLock::new();

    pub(crate) fn selected_proof_variant_resource_inventory()
    -> Result<&'static [SelectedProofVariantResourceAccounting], SelectedProofAccountingError> {
        SELECTED_PROOF_VARIANT_RESOURCE_INVENTORY
            .get_or_init(derive_selected_proof_variant_resource_inventory)
            .as_ref()
            .map(|inventory| inventory.as_ref())
            .map_err(|error| *error)
    }

    fn derive_selected_proof_variant_resource_inventory()
    -> Result<Box<[SelectedProofVariantResourceAccounting]>, SelectedProofAccountingError> {
        let proof_profile =
            selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let key_positions = selected_evaluator_program_set()
            .and_then(|program| program.key_positions())
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let application_slot_ceilings = selected_proof_application_slot_ceilings()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        if key_positions.streams().len() != usize::from(FOUNDATION_PROFILE.option_count) {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }

        let mut compiler_ceilings = Vec::new();
        for relation_plan in proof_profile.relation_plans() {
            let application_statement_schema_identifier =
                relation_plan.application_statement_schema_identifier();
            let relation_context =
                selected_relation_plan_check_context(application_statement_schema_identifier)
                    .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            let committed_material_source_provider_memory_accounting =
                selected_committed_material_source_provider_memory_accounting(
                    application_statement_schema_identifier,
                    &relation_context,
                    relation_plan.compiled_plan(),
                )?;
            if committed_material_source_provider_memory_accounting.is_some_and(|accounting| {
                accounting.preparation_peak_resident_byte_length()
                    > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                    || accounting.construction_peak_resident_byte_length()
                        > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
            }) {
                return Err(SelectedProofAccountingError::ResourcePlanning);
            }

            for variant in relation_plan.compiled_plan().variants() {
                let statement_context = SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0; Hash512::BYTE_LENGTH],
                    variant.schedule_position(),
                    variant.top_count(),
                );
                let canonical_application_statement_bytes =
                    canonical_selected_application_statement_for_ceiling(
                        application_statement_schema_identifier,
                        statement_context,
                    )
                    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
                let transport_sizing = selected_proof_transport_sizing(
                    application_statement_schema_identifier,
                    &canonical_application_statement_bytes,
                    variant,
                    &relation_context,
                )?;
                let resource_bounds = require_selected_variant_resource_bounds(
                    application_statement_schema_identifier,
                    &canonical_application_statement_bytes,
                    variant,
                    &relation_context,
                    &transport_sizing,
                    committed_material_source_provider_memory_accounting,
                )?;
                let complete_action_application_multiplicity =
                    selected_complete_action_variant_multiplicity(
                        application_statement_schema_identifier,
                        variant,
                        &application_slot_ceilings,
                        &key_positions,
                    )?;
                let logical_entry_count = selected_variant_logical_entry_count(
                    application_statement_schema_identifier,
                    variant,
                )?;
                let proof_component_byte_accounting =
                    selected_proof_component_byte_accounting(&transport_sizing.ceiling)?;
                let (ordered_query_trees, bound_public_tree_count, total_materialized_row_width) =
                    selected_proof_query_tree_resource_accounting(&transport_sizing)?;
                let relation_column_count = u32::try_from(variant.ordered_columns().len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                let mut verifier_sequence_relation_column_count = 0_u32;
                let mut bound_tree_relation_column_count = 0_u32;
                let mut prover_relation_column_count = 0_u32;
                for column in variant.ordered_columns() {
                    let target = match column.origin() {
                        RelationColumnOrigin::VerifierSequence { .. } => {
                            &mut verifier_sequence_relation_column_count
                        }
                        RelationColumnOrigin::BoundTree { .. } => {
                            &mut bound_tree_relation_column_count
                        }
                        RelationColumnOrigin::Prover => &mut prover_relation_column_count,
                    };
                    *target = target
                        .checked_add(1)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                }
                if verifier_sequence_relation_column_count
                    .checked_add(bound_tree_relation_column_count)
                    .and_then(|count| count.checked_add(prover_relation_column_count))
                    != Some(relation_column_count)
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                let relation_constraint_count =
                    u32::try_from(variant.ordered_constraint_count())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                let quotient_decomposition_stride = variant
                    .quotient_decomposition_stride(&relation_context)
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let quotient_component_degree_bound_exclusive =
                    relation_context.quotient_component_degree_bound_exclusive;
                let SelectedProofVariantResourceBounds {
                    maximum_combined_wasm_resident_byte_length,
                    resident_phases,
                    maximum_prefetched_query_byte_length,
                    maximum_external_memory_transaction_payload_byte_length,
                    maximum_proof_output_chunk_byte_length_ceiling,
                    proof_output_chunk_count_ceiling,
                    maximum_copied_buffer_byte_length,
                } = resource_bounds;
                compiler_ceilings.push(SelectedProofVariantResourceAccounting {
                    application_statement_schema_identifier,
                    schedule_position: variant.schedule_position(),
                    top_count: variant.top_count(),
                    complete_action_application_multiplicity,
                    logical_entry_count,
                    evaluation_domain_size: variant.evaluation_domain_size(),
                    opening_degree_bound_exclusive: variant.opening_degree_bound_exclusive(),
                    relation_column_count,
                    verifier_sequence_relation_column_count,
                    bound_tree_relation_column_count,
                    prover_relation_column_count,
                    relation_constraint_count,
                    quotient_decomposition_stride,
                    quotient_component_degree_bound_exclusive,
                    quotient_component_count: transport_sizing
                        .transcript_schedule
                        .quotient_component_count(),
                    fri_fold_count: transport_sizing.transcript_schedule.fri_fold_count(),
                    terminal_coefficient_count: transport_sizing
                        .transcript_schedule
                        .terminal_coefficient_count(),
                    unique_query_count: transport_sizing.transcript_schedule.unique_query_count(),
                    query_orbit_count: transport_sizing.transcript_schedule.query_orbit_count(),
                    canonical_header_byte_length_ceiling: u64::try_from(
                        transport_sizing.ceiling.canonical_header_byte_length(),
                    )
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    body_prefix_byte_length_ceiling: u64::try_from(
                        transport_sizing.ceiling.body_prefix_byte_length(),
                    )
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    query_section_byte_length_ceiling: u64::try_from(
                        transport_sizing.ceiling.query_section_byte_length(),
                    )
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    proof_byte_length_ceiling: transport_sizing.ceiling.proof_byte_length(),
                    proof_component_byte_accounting,
                    ordered_query_trees,
                    bound_public_tree_count,
                    total_materialized_row_width,
                    maximum_combined_wasm_resident_byte_length,
                    resident_phases,
                    maximum_prefetched_query_byte_length,
                    maximum_external_memory_transaction_payload_byte_length,
                    maximum_proof_output_chunk_byte_length_ceiling,
                    proof_output_chunk_count_ceiling,
                    maximum_copied_buffer_byte_length,
                });
            }
        }
        require_selected_variant_selector_inventory(
            &compiler_ceilings,
            &key_positions,
            &application_slot_ceilings,
        )?;
        Ok(compiler_ceilings.into_boxed_slice())
    }

    fn require_selected_variant_selector_inventory(
        compiler_ceilings: &[SelectedProofVariantResourceAccounting],
        key_positions: &EvaluatorProgramKeyPositions,
        application_slot_ceilings: &ProofApplicationSlotCeilings,
    ) -> Result<(), SelectedProofAccountingError> {
        require_selected_global_proof_backend_geometry(compiler_ceilings)?;
        let mut observed_selectors =
            std::collections::BTreeMap::<u16, BTreeSet<(Option<u32>, Option<u16>)>>::new();
        for ceiling in compiler_ceilings {
            if !observed_selectors
                .entry(ceiling.application_statement_schema_identifier())
                .or_default()
                .insert((ceiling.schedule_position(), ceiling.top_count()))
            {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
        }

        let unselected = BTreeSet::from([(None, None)]);
        let mut expected_selectors = std::collections::BTreeMap::new();
        for schema_identifier in [
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
    ] {
        expected_selectors.insert(schema_identifier, unselected.clone());
    }

        let relinearization_selectors = (0..key_positions.relinearization_catalog_levels().len())
            .map(|schedule_position| {
                u32::try_from(schedule_position)
                    .map(|schedule_position| (Some(schedule_position), None))
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if relinearization_selectors.is_empty() {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        for schema_identifier in [
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        ] {
            expected_selectors.insert(schema_identifier, relinearization_selectors.clone());
        }

        let galois_selectors = selected_galois_key_share_batch_schedule()
            .into_iter()
            .map(|schedule_position| (Some(schedule_position), None))
            .collect::<BTreeSet<_>>();
        if galois_selectors.is_empty() {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        expected_selectors.insert(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            galois_selectors,
        );

        let evaluator_selectors = key_positions
            .streams()
            .iter()
            .map(|stream| (None, Some(stream.top_count())))
            .collect::<BTreeSet<_>>();
        if evaluator_selectors.len() != usize::from(FOUNDATION_PROFILE.option_count)
            || evaluator_selectors
                != (1..=FOUNDATION_PROFILE.option_count)
                    .map(|top_count| (None, Some(top_count)))
                    .collect::<BTreeSet<_>>()
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        expected_selectors.insert(
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            evaluator_selectors,
        );

        if observed_selectors != expected_selectors {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        require_selected_evaluator_variant_resource_ceiling_equality(compiler_ceilings)?;
        for family in application_slot_ceilings.ordered_family_ceilings() {
            let observed_application_multiplicity = compiler_ceilings
                .iter()
                .filter(|variant| {
                    variant.application_statement_schema_identifier()
                        == family.application_statement_schema_identifier
                })
                .try_fold(0_u32, |total, variant| {
                    total
                        .checked_add(variant.complete_action_application_multiplicity())
                        .ok_or(SelectedProofAccountingError::CountOverflow)
                })?;
            if observed_application_multiplicity != family.application_slot_ceiling {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
        }
        let selected_complete_list_variants = compiler_ceilings
            .iter()
            .filter(|variant| {
                variant.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                && variant.complete_action_application_multiplicity() != 0
            })
            .collect::<Vec<_>>();
        if selected_complete_list_variants.len() != 1
            || selected_complete_list_variants[0].top_count()
                != Some(FOUNDATION_PROFILE.option_count)
            || selected_complete_list_variants[0].complete_action_application_multiplicity() != 1
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok(())
    }

    fn require_selected_evaluator_variant_resource_ceiling_equality(
        compiler_ceilings: &[SelectedProofVariantResourceAccounting],
    ) -> Result<(), SelectedProofAccountingError> {
        let mut observed_top_counts = BTreeSet::new();
        let mut normalized_reference = None;
        for variant in compiler_ceilings.iter().filter(|variant| {
            variant.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        }) {
            let top_count = variant
                .top_count()
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            if variant.schedule_position().is_some() || !observed_top_counts.insert(top_count) {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }

            let mut normalized_variant = variant.clone();
            normalized_variant.schedule_position = None;
            normalized_variant.top_count = None;
            normalized_variant.complete_action_application_multiplicity = 0;
            if let Some(reference) = normalized_reference.as_ref() {
                if reference != &normalized_variant {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
            } else {
                normalized_reference = Some(normalized_variant);
            }
        }

        let expected_top_counts = (1..=FOUNDATION_PROFILE.option_count).collect::<BTreeSet<_>>();
        if normalized_reference.is_none() || observed_top_counts != expected_top_counts {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok(())
    }

    #[cfg(test)]
    fn require_selected_evaluator_diagnostic_variant_ceiling_equality(
        diagnostic_rows: &[SelectedProofExternalMemoryDiagnosticRow],
    ) -> Result<(), SelectedProofAccountingError> {
        let mut observed_top_counts = BTreeSet::new();
        let mut normalized_reference = None;
        for row in diagnostic_rows.iter().cloned().filter(|row| {
            row.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
        }) {
            let top_count = row
                .top_count()
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            if row.schedule_position().is_some() || !observed_top_counts.insert(top_count) {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }

            let mut normalized_requirement = row
                .outcome()
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
            normalized_requirement.complete_action_application_multiplicity = 0;
            let mut normalized_row = row;
            normalized_row.top_count = None;
            normalized_row.outcome = Ok(normalized_requirement);
            if let Some(reference) = normalized_reference.as_ref() {
                if reference != &normalized_row {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
            } else {
                normalized_reference = Some(normalized_row);
            }
        }

        let expected_top_counts = (1..=FOUNDATION_PROFILE.option_count).collect::<BTreeSet<_>>();
        if normalized_reference.is_none() || observed_top_counts != expected_top_counts {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok(())
    }

    fn require_selected_global_proof_backend_geometry(
        compiler_ceilings: &[SelectedProofVariantResourceAccounting],
    ) -> Result<(), SelectedProofAccountingError> {
        const SELECTED_BASE_FIELD_MODULUS: u64 = 18_446_744_069_414_584_321;
        const SELECTED_CHALLENGE_EXTENSION_DEGREE: usize = 5;
        const SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE: u64 = 262_144;
        const SELECTED_EVALUATION_DOMAIN_SIZE: u64 = 2_097_152;
        const SELECTED_DEEP_POINT_COUNT: u16 = 1;
        const SELECTED_FRI_FOLD_COUNT: u16 = 10;
        const SELECTED_TERMINAL_COEFFICIENT_COUNT: u32 = 256;
        const COMMITTED_MATERIAL_QUOTIENT_DECOMPOSITION_STRIDE: u64 = 68_267;
        const PUBLIC_AGGREGATE_QUOTIENT_DECOMPOSITION_STRIDE: u64 = 16_384;
        const COMMITTED_MATERIAL_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE: u64 = 68_652;
        const PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE: u64 = 16_384;
        const OTHER_FAMILY_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE: u64 = 33_884;
        const COMMITTED_MATERIAL_QUERY_COUNT: u32 = 192;
        const OTHER_FAMILY_QUERY_COUNT: u32 = 168;
        const COMMITTED_MATERIAL_QUOTIENT_COMPONENT_COUNT: u16 = 3;
        const PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_COUNT: u16 = 9;
        const OTHER_FAMILY_QUOTIENT_COMPONENT_COUNT: u16 = 8;

        let observed_families = compiler_ceilings
            .iter()
            .map(|variant| variant.application_statement_schema_identifier())
            .collect::<BTreeSet<_>>();
        let expected_families = crate::bgv::proof_suite::FIRST_PROFILE_APPLICATION_FAMILIES
            .into_iter()
            .collect::<BTreeSet<_>>();
        if PROOF_BASE_FIELD_MODULUS != SELECTED_BASE_FIELD_MODULUS
            || PROOF_CHALLENGE_EXTENSION_DEGREE != SELECTED_CHALLENGE_EXTENSION_DEGREE
            || PROOF_DEEP_POINT_COUNT != SELECTED_DEEP_POINT_COUNT
            || observed_families != expected_families
            || observed_families.len()
                != crate::bgv::proof_suite::FIRST_PROFILE_APPLICATION_FAMILIES.len()
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }

        for variant in compiler_ceilings {
            let schema_identifier = variant.application_statement_schema_identifier();
            let is_committed_material = matches!(
            schema_identifier,
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        );
            let is_public_aggregate =
                ProofApplicationSlotCeilings::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS
                    .contains(&schema_identifier);
            let expected_query_count = if is_committed_material {
                COMMITTED_MATERIAL_QUERY_COUNT
            } else {
                OTHER_FAMILY_QUERY_COUNT
            };
            let expected_quotient_component_count = if is_committed_material {
                COMMITTED_MATERIAL_QUOTIENT_COMPONENT_COUNT
            } else if is_public_aggregate {
                PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_COUNT
            } else {
                OTHER_FAMILY_QUOTIENT_COMPONENT_COUNT
            };
            let expected_quotient_component_degree_bound_exclusive = if is_committed_material {
                COMMITTED_MATERIAL_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE
            } else if is_public_aggregate {
                PUBLIC_AGGREGATE_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE
            } else {
                OTHER_FAMILY_QUOTIENT_COMPONENT_DEGREE_BOUND_EXCLUSIVE
            };
            let quotient_decomposition_stride_is_selected = if is_committed_material {
                variant.quotient_decomposition_stride()
                    == COMMITTED_MATERIAL_QUOTIENT_DECOMPOSITION_STRIDE
            } else if is_public_aggregate {
                variant.quotient_decomposition_stride()
                    == PUBLIC_AGGREGATE_QUOTIENT_DECOMPOSITION_STRIDE
            } else {
                variant.quotient_decomposition_stride() > 0
                    && variant.quotient_decomposition_stride()
                        <= expected_quotient_component_degree_bound_exclusive
            };
            if variant.opening_degree_bound_exclusive() != SELECTED_OPENING_DEGREE_BOUND_EXCLUSIVE
                || variant.evaluation_domain_size() != SELECTED_EVALUATION_DOMAIN_SIZE
                || variant.evaluation_domain_size() / variant.opening_degree_bound_exclusive() != 8
                || variant.quotient_component_degree_bound_exclusive()
                    != expected_quotient_component_degree_bound_exclusive
                || !quotient_decomposition_stride_is_selected
                || variant.fri_fold_count() != SELECTED_FRI_FOLD_COUNT
                || variant.terminal_coefficient_count() != SELECTED_TERMINAL_COEFFICIENT_COUNT
                || variant.query_orbit_count() != variant.evaluation_domain_size() / 2
                || variant.unique_query_count() != expected_query_count
                || variant.quotient_component_count() != expected_quotient_component_count
            {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
        }

        let vss = compiler_ceilings
            .iter()
            .find(|variant| {
                variant.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            })
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let aggregate = compiler_ceilings
        .iter()
        .find(|variant| {
            variant.application_statement_schema_identifier()
                == ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER
        })
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        if (
            vss.relation_column_count(),
            vss.verifier_sequence_relation_column_count(),
            vss.bound_tree_relation_column_count(),
            vss.prover_relation_column_count(),
            vss.relation_constraint_count(),
        ) != (3_451, 0, 448, 3_003, 3_767)
            || (
                aggregate.relation_column_count(),
                aggregate.verifier_sequence_relation_column_count(),
                aggregate.bound_tree_relation_column_count(),
                aggregate.prover_relation_column_count(),
                aggregate.relation_constraint_count(),
            ) != (2_528, 0, 352, 2_176, 2_672)
        {
            return Err(SelectedProofAccountingError::InvalidProfile);
        }
        Ok(())
    }

    fn selected_variant_logical_entry_count(
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
    ) -> Result<u32, SelectedProofAccountingError> {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                u32::try_from(
                    selected_galois_key_share_relation_plan_input()
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                        .ordered_entries
                        .len(),
                )
                .map_err(|_| SelectedProofAccountingError::CountOverflow)
                .and_then(|count| {
                    if count == 0 {
                        Err(SelectedProofAccountingError::InvalidProfile)
                    } else {
                        Ok(count)
                    }
                })
            }
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                let top_count = variant
                    .top_count()
                    .ok_or(SelectedProofAccountingError::InvalidProfile)?;
                u32::try_from(
                    selected_evaluator_entry_positions(top_count)
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                        .len(),
                )
                .map_err(|_| SelectedProofAccountingError::CountOverflow)
                .and_then(|count| {
                    if count == 0 {
                        Err(SelectedProofAccountingError::InvalidProfile)
                    } else {
                        Ok(count)
                    }
                })
            }
            _ => Ok(1),
        }
    }

    fn selected_complete_action_variant_multiplicity(
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
        application_slot_ceilings: &ProofApplicationSlotCeilings,
        key_positions: &EvaluatorProgramKeyPositions,
    ) -> Result<u32, SelectedProofAccountingError> {
        let family_slot_count = application_slot_ceilings
            .family_ceiling(application_statement_schema_identifier)
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER =>
            {
                let schedule_count =
                    u32::try_from(key_positions.relinearization_catalog_levels().len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                if schedule_count == 0
                    || variant.schedule_position().is_none()
                    || family_slot_count % schedule_count != 0
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(family_slot_count / schedule_count)
            }
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                let schedule_count =
                    u32::try_from(selected_galois_key_share_batch_schedule().len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                if schedule_count == 0
                    || variant.schedule_position().is_none()
                    || family_slot_count % schedule_count != 0
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(family_slot_count / schedule_count)
            }
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                if variant.schedule_position().is_some() || family_slot_count != 1 {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(u32::from(
                    variant.top_count() == Some(FOUNDATION_PROFILE.option_count),
                ))
            }
            _ => {
                if variant.schedule_position().is_some() || variant.top_count().is_some() {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                Ok(family_slot_count)
            }
        }
    }

    #[derive(Clone, Copy)]
    enum SourceProviderMemoryAccounting {
        BallotValidity(SelectedBallotValidityCarrierBufferAccounting),
        CollectivePublicKey(CollectivePublicKeySourceProviderMemoryAccounting),
        EvaluatorAggregate(SelectedEvaluatorAggregateSourceProviderMemoryAccounting),
        CommittedMaterial(CommittedMaterialSourceProviderMemoryAccounting),
        Common(CommonProofSourceProviderMemoryAccounting),
    }

    impl SourceProviderMemoryAccounting {
        const fn loading_persistent_resident_byte_length(self) -> u64 {
            match self {
                Self::BallotValidity(accounting) => {
                    accounting.provider_loading_persistent_resident_byte_length()
                }
                Self::CollectivePublicKey(accounting) => {
                    accounting.loading_persistent_resident_byte_length()
                }
                Self::EvaluatorAggregate(accounting) => {
                    accounting.loading_persistent_resident_byte_length()
                }
                Self::CommittedMaterial(accounting) => {
                    accounting.loading_persistent_resident_byte_length()
                }
                Self::Common(accounting) => accounting.loading_persistent_resident_byte_length(),
            }
        }

        const fn post_source_finish_persistent_resident_byte_length(self) -> u64 {
            match self {
                Self::BallotValidity(accounting) => {
                    accounting.provider_post_source_finish_persistent_resident_byte_length()
                }
                Self::CollectivePublicKey(accounting) => {
                    accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                }
                Self::EvaluatorAggregate(accounting) => {
                    accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                }
                Self::CommittedMaterial(accounting) => {
                    accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                }
                Self::Common(accounting) => {
                    accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                }
            }
        }

        const fn additional_loading_transient_byte_length(self) -> u64 {
            match self {
                Self::BallotValidity(accounting) => {
                    accounting.provider_additional_loading_transient_byte_length()
                }
                Self::CollectivePublicKey(accounting) => {
                    accounting.additional_loading_source_polynomials_transient_byte_length()
                }
                Self::EvaluatorAggregate(accounting) => {
                    accounting.additional_loading_source_polynomials_transient_byte_length()
                }
                Self::CommittedMaterial(accounting) => {
                    accounting.additional_loading_source_polynomials_transient_byte_length()
                }
                Self::Common(accounting) => accounting.additional_loading_transient_byte_length(),
            }
        }

        const fn maximum_returned_source_polynomial_byte_length(self) -> u64 {
            match self {
                Self::BallotValidity(accounting) => {
                    accounting.transferred_source_polynomial_byte_length()
                }
                Self::CollectivePublicKey(accounting) => {
                    accounting.maximum_returned_source_polynomial_byte_length()
                }
                Self::EvaluatorAggregate(accounting) => {
                    accounting.maximum_returned_source_polynomial_byte_length()
                }
                Self::CommittedMaterial(accounting) => {
                    accounting.maximum_returned_source_polynomial_byte_length()
                }
                Self::Common(accounting) => {
                    accounting.maximum_returned_source_polynomial_byte_length()
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum ApplicationRuntimeMemoryAccounting {
        BallotValidity(SelectedBallotCiphertextReadbackMemoryAccounting),
        CollectivePublicKey(CollectivePublicKeyApplicationMemoryAccounting),
    }

    impl ApplicationRuntimeMemoryAccounting {
        const fn loading_persistent_resident_byte_length(self) -> u64 {
            match self {
                Self::BallotValidity(accounting) => accounting.persistent_resident_byte_length(),
                Self::CollectivePublicKey(accounting) => {
                    accounting.loading_persistent_resident_byte_length()
                }
            }
        }

        const fn post_source_polynomial_finish_persistent_resident_byte_length(self) -> u64 {
            match self {
                Self::BallotValidity(accounting) => accounting.persistent_resident_byte_length(),
                Self::CollectivePublicKey(accounting) => {
                    accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                }
            }
        }

        const fn maximum_boundary_overlap_byte_length(self) -> u64 {
            match self {
                Self::BallotValidity(accounting) => {
                    accounting.maximum_boundary_overlap_byte_length()
                }
                Self::CollectivePublicKey(accounting) => {
                    accounting.maximum_boundary_overlap_byte_length()
                }
            }
        }
    }

    fn selected_source_provider_memory_accounting(
        application_statement_schema_identifier: u16,
        canonical_application_statement_bytes: &[u8],
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        committed_material_source_provider_memory_accounting: Option<
            CommittedMaterialSourceProviderMemoryAccounting,
        >,
    ) -> Result<SourceProviderMemoryAccounting, SelectedProofAccountingError> {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => {
                let relation_input = selected_same_secret_relation_plan_input()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let compiled = compile_same_secret_relation_with_source_layout(
                    &relation_input,
                    relation_context,
                )
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let expected_variant = compiled
                    .relation_plan
                    .select_variant(variant.schedule_position(), variant.top_count())
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                if expected_variant
                    .canonical_hash()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                    != variant
                        .canonical_hash()
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                let provider = same_secret_source_provider_memory_accounting(
                    variant,
                    relation_context,
                    relation_input.ring_degree,
                    &compiled.source_layout,
                    canonical_application_statement_bytes.len(),
                )
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                Ok(SourceProviderMemoryAccounting::Common(provider))
            }
            ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                let relation_input = selected_public_key_share_relation_plan_input()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let compiled = compile_public_key_share_relation_with_source_layout(
                    &relation_input,
                    relation_context,
                )
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let expected_variant = compiled
                    .relation_plan
                    .select_variant(variant.schedule_position(), variant.top_count())
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                if expected_variant
                    .canonical_hash()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                    != variant
                        .canonical_hash()
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                let provider = public_key_share_source_provider_memory_accounting(
                    variant,
                    relation_context,
                    relation_input.ring_degree,
                    &compiled.source_layout,
                    canonical_application_statement_bytes.len(),
                )
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                Ok(SourceProviderMemoryAccounting::Common(provider))
            }
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
                Ok(SourceProviderMemoryAccounting::BallotValidity(
                    selected_ballot_validity_carrier_buffer_accounting()
                        .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
                ))
            }
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                Ok(SourceProviderMemoryAccounting::CollectivePublicKey(
                    collective_public_key_source_provider_memory_accounting(variant)
                        .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
                ))
            }
            ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                Ok(SourceProviderMemoryAccounting::EvaluatorAggregate(
                    evaluator_aggregate_source_provider_memory_accounting(
                        variant,
                        relation_context,
                    )
                    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
                ))
            }
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => {
                let (relation_input, _) = selected_relinearization_relation_plan_inputs()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let compiled = compile_relinearization_round_one_relation_with_source_layout(
                    &relation_input,
                    relation_context,
                )
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let expected_variant = compiled
                    .relation_plan
                    .select_variant(variant.schedule_position(), variant.top_count())
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                if expected_variant
                    .canonical_hash()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                    != variant
                        .canonical_hash()
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                let provider = relinearization_round_one_source_provider_memory_accounting(
                    variant,
                    relation_context,
                    &relation_input.geometry,
                    &compiled.source_layout,
                    canonical_application_statement_bytes.len(),
                )
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                Ok(SourceProviderMemoryAccounting::Common(provider))
            }
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
                let (_, relation_input) = selected_relinearization_relation_plan_inputs()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let compiled = compile_relinearization_round_two_relation_with_source_layout(
                    &relation_input,
                    relation_context,
                )
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let expected_variant = compiled
                    .relation_plan
                    .select_variant(variant.schedule_position(), variant.top_count())
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                if expected_variant
                    .canonical_hash()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                    != variant
                        .canonical_hash()
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                let data_primes_per_block = relation_input
                    .geometry
                    .decomposition_blocks
                    .first()
                    .map(|block| block.data_modulus_indices.len())
                    .filter(|count| *count != 0)
                    .ok_or(SelectedProofAccountingError::InvalidProfile)?;
                let aggregate_topology = KeySwitchComponentMaterialTopology::from_suite_algebra(
                    &relation_input.geometry.data_moduli,
                    &relation_input.geometry.special_moduli,
                    data_primes_per_block,
                    usize::try_from(relation_input.geometry.ring_degree)
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                )
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let accounting = relinearization_round_two_source_provider_memory_accounting(
                    variant,
                    relation_context,
                    &relation_input.geometry,
                    &compiled.source_layout,
                    &aggregate_topology,
                    canonical_application_statement_bytes.len(),
                )
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                let provider = CommonProofSourceProviderMemoryAccounting::new(
                    accounting.loading_persistent_resident_byte_length(),
                    accounting.post_source_polynomial_finish_persistent_resident_byte_length(),
                    accounting.additional_loading_source_polynomials_transient_byte_length(),
                    accounting.maximum_returned_source_polynomial_byte_length(),
                );
                Ok(SourceProviderMemoryAccounting::Common(provider))
            }
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => {
                let committed = committed_material_source_provider_memory_accounting
                    .ok_or(SelectedProofAccountingError::ResourcePlanning)?;
                let provider = CommonProofSourceProviderMemoryAccounting::new(
                    committed.loading_persistent_resident_byte_length(),
                    committed.post_source_polynomial_finish_persistent_resident_byte_length(),
                    committed.additional_loading_source_polynomials_transient_byte_length(),
                    committed.maximum_returned_source_polynomial_byte_length(),
                );
                Ok(SourceProviderMemoryAccounting::Common(provider))
            }
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                Ok(SourceProviderMemoryAccounting::CommittedMaterial(
                    committed_material_source_provider_memory_accounting
                        .ok_or(SelectedProofAccountingError::ResourcePlanning)?,
                ))
            }
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                let relation_input = selected_galois_key_share_relation_plan_input()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let accounting = galois_key_share_source_provider_memory_accounting(
                    &relation_input,
                    variant,
                    relation_context,
                    canonical_application_statement_bytes.len(),
                )
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                let provider = CommonProofSourceProviderMemoryAccounting::new(
                    accounting.loading_persistent_resident_byte_length(),
                    accounting.post_source_polynomial_finish_persistent_resident_byte_length(),
                    accounting.additional_loading_source_polynomials_transient_byte_length(),
                    accounting.maximum_returned_source_polynomial_byte_length(),
                );
                Ok(SourceProviderMemoryAccounting::Common(provider))
            }
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
                let compilation = selected_target_release_relation()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let expected_variant = compilation
                    .relation_plan()
                    .select_variant(variant.schedule_position(), variant.top_count())
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                if expected_variant
                    .canonical_hash()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                    != variant
                        .canonical_hash()
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
                {
                    return Err(SelectedProofAccountingError::InvalidProfile);
                }
                let provider =
                    selected_kllps_target_release_source_provider_memory_accounting()
                        .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                Ok(SourceProviderMemoryAccounting::Common(provider))
            }
            _ => Err(SelectedProofAccountingError::InvalidProfile),
        }
    }

    fn selected_committed_material_source_provider_memory_accounting(
        application_statement_schema_identifier: u16,
        relation_context: &RelationPlanCheckContext,
        compiled_plan: &CompiledRelationPlan,
    ) -> Result<Option<CommittedMaterialSourceProviderMemoryAccounting>, SelectedProofAccountingError>
    {
        match application_statement_schema_identifier {
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
            | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER =>
            {
                let relation_input = selected_committed_material_relation_plan_input()
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                let accounting = if application_statement_schema_identifier
                    == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                {
                    vss_share_linkage_source_provider_memory_accounting(
                        &relation_input,
                        relation_context,
                        compiled_plan,
                    )
                } else {
                    aggregate_threshold_share_source_provider_memory_accounting(
                        &relation_input,
                        relation_context,
                        compiled_plan,
                    )
                }
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                Ok(Some(accounting))
            }
            _ => Ok(None),
        }
    }

    fn selected_application_runtime_memory_accounting(
        application_statement_schema_identifier: u16,
        canonical_application_statement_bytes: &[u8],
        source_provider_memory_accounting: SourceProviderMemoryAccounting,
    ) -> Result<Option<ApplicationRuntimeMemoryAccounting>, SelectedProofAccountingError> {
        match (
            application_statement_schema_identifier,
            source_provider_memory_accounting,
        ) {
            (
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                SourceProviderMemoryAccounting::BallotValidity(carrier_accounting),
            ) => Ok(Some(ApplicationRuntimeMemoryAccounting::BallotValidity(
                selected_ballot_ciphertext_readback_memory_accounting(
                    u64::try_from(canonical_application_statement_bytes.len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    carrier_accounting,
                )?,
            ))),
            (
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                SourceProviderMemoryAccounting::CollectivePublicKey(provider_accounting),
            ) => Ok(Some(ApplicationRuntimeMemoryAccounting::CollectivePublicKey(
                collective_public_key_application_memory_accounting(
                    u64::try_from(canonical_application_statement_bytes.len())
                        .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                    provider_accounting,
                )
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
            ))),
            (ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER, _)
            | (
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                _,
            ) => Err(SelectedProofAccountingError::ResourcePlanning),
            _ => Ok(None),
        }
    }

    fn require_selected_variant_resource_bounds(
        application_statement_schema_identifier: u16,
        canonical_application_statement_bytes: &[u8],
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        transport_sizing: &SelectedProofTransportSizing,
        committed_material_source_provider_memory_accounting: Option<
            CommittedMaterialSourceProviderMemoryAccounting,
        >,
    ) -> Result<SelectedProofVariantResourceBounds, SelectedProofAccountingError> {
        let source_provider_memory_accounting = selected_source_provider_memory_accounting(
            application_statement_schema_identifier,
            canonical_application_statement_bytes,
            variant,
            relation_context,
            committed_material_source_provider_memory_accounting,
        )?;
        let application_runtime_memory_accounting = selected_application_runtime_memory_accounting(
            application_statement_schema_identifier,
            canonical_application_statement_bytes,
            source_provider_memory_accounting,
        )?;
        if let (
            SourceProviderMemoryAccounting::CollectivePublicKey(provider_accounting),
            Some(ApplicationRuntimeMemoryAccounting::CollectivePublicKey(application_accounting)),
        ) = (
            source_provider_memory_accounting,
            application_runtime_memory_accounting,
        ) {
            let preparation_peak_resident_byte_length = provider_accounting
                .preparation_peak_resident_byte_length()
                .checked_add(application_accounting.loading_persistent_resident_byte_length())
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            if preparation_peak_resident_byte_length
                > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
            {
                return Err(SelectedProofAccountingError::ResourcePlanning);
            }
        }

        let checkpoint_custody_requirement =
            common_proof_generation_checkpoint_custody_requirement_for_variant(variant)
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let consumed_mask_count = require_selected_mask_coordinate_inventory(
            application_statement_schema_identifier,
            variant,
        )?;
        let expected_logical_cursor_count = consumed_mask_count
            .checked_add(u32::from(
                variant.proof_privacy_mode() == ProofPrivacyMode::SecretBearing,
            ))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        if checkpoint_custody_requirement
            .cursor_manifest_requirement()
            .logical_cursor_count()
            != expected_logical_cursor_count
            || !checkpoint_custody_requirement.fits_absolute_bounds()
        {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }

        let runtime_limits = selected_runtime_limits_from_sizing(transport_sizing)?;
        let resident_memory_requirement = common_proof_resident_memory_requirement(
            variant,
            relation_context,
            &transport_sizing.transcript_schedule,
            transport_sizing.layout.catalog(),
            CommonProofResidentMemoryConfiguration::new(
                application_statement_schema_identifier,
                u64::try_from(transport_sizing.ceiling.canonical_header_byte_length())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                runtime_limits.prefetched_query_byte_length(),
                u64::from(runtime_limits.external_memory_chunk_byte_length()),
                u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            ),
        )
        .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let resident_memory_bounds = require_selected_resident_memory_bounds(
            &resident_memory_requirement,
            checkpoint_custody_requirement,
            transport_sizing.transcript_schedule.fri_fold_count(),
            source_provider_memory_accounting,
            application_runtime_memory_accounting,
        )?;

        let external_memory_requirement = common_proof_external_memory_requirement(
            variant,
            relation_context,
            transport_sizing.layout.catalog(),
            &transport_sizing.transcript_schedule,
            runtime_limits.external_memory_chunk_byte_length(),
        )
        .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let maximum_copied_buffer_byte_length =
            u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let copied_buffer_requirements = [
            runtime_limits.prefetched_query_byte_length(),
            external_memory_requirement.maximum_transaction_payload_byte_length(),
            u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
            u64::from(checkpoint_custody_requirement.peak_copied_buffer_byte_length()),
        ];
        let maximum_copied_buffer_byte_length_for_variant = copied_buffer_requirements
            .iter()
            .copied()
            .max()
            .ok_or(SelectedProofAccountingError::ResourcePlanning)?;
        let proof_byte_length = u64::try_from(runtime_limits.proof_byte_length())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let maximum_proof_output_chunk_byte_length_ceiling =
            u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
                .min(proof_byte_length);
        let proof_output_chunk_count_ceiling = proof_byte_length.div_ceil(
            u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        );
        if u64::try_from(runtime_limits.proof_byte_length())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?
            > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
            || external_memory_requirement.peak_stored_byte_length()
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
            || usize::try_from(external_memory_requirement.distinct_physical_object_count())
                .ok()
                .is_none_or(|count| count > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
            || external_memory_requirement.distinct_physical_object_count() == 0
            || external_memory_requirement.object_lifecycle_count()
                < external_memory_requirement.distinct_physical_object_count()
            || checkpoint_custody_requirement.restore_workspace_byte_ceiling()
                > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
            || copied_buffer_requirements
                .into_iter()
                .any(|byte_length| byte_length > maximum_copied_buffer_byte_length)
        {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }
        Ok(SelectedProofVariantResourceBounds {
            maximum_combined_wasm_resident_byte_length: resident_memory_bounds
                .maximum_combined_wasm_resident_byte_length,
            resident_phases: resident_memory_bounds.ordered_phases,
            maximum_prefetched_query_byte_length: runtime_limits.prefetched_query_byte_length(),
            maximum_external_memory_transaction_payload_byte_length: external_memory_requirement
                .maximum_transaction_payload_byte_length(),
            maximum_proof_output_chunk_byte_length_ceiling,
            proof_output_chunk_count_ceiling,
            maximum_copied_buffer_byte_length: maximum_copied_buffer_byte_length_for_variant,
        })
    }

    fn require_selected_mask_coordinate_inventory(
        application_statement_schema_identifier: u16,
        variant: &RelationPlanVariant,
    ) -> Result<u32, SelectedProofAccountingError> {
        let mut consumed_coordinates = BTreeSet::new();
        let mut trace_ordinals = BTreeSet::new();
        let mut quotient_ordinals = BTreeSet::new();
        let mut opening_ordinals = BTreeSet::new();
        for mask in variant.ordered_masks() {
            let coordinate = mask.mask_coordinate();
            if !common_proof_randomness_purpose_is_assigned(
                application_statement_schema_identifier,
                coordinate.purpose_class(),
            ) || !consumed_coordinates
                .insert((coordinate.purpose_class(), coordinate.mask_ordinal()))
            {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            let inserted = match mask.mask_kind() {
                RelationMaskKind::Trace => trace_ordinals.insert(coordinate.mask_ordinal()),
                RelationMaskKind::Telescoping => {
                    quotient_ordinals.insert(coordinate.mask_ordinal())
                }
                RelationMaskKind::OpeningBatch => {
                    opening_ordinals.insert(coordinate.mask_ordinal())
                }
            };
            if !inserted {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
        }
        for ordinals in [&trace_ordinals, &quotient_ordinals, &opening_ordinals] {
            let ordinal_count = u32::try_from(ordinals.len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            match ordinal_count {
                0 if ordinals.is_empty() => {}
                count
                    if ordinals.first() == Some(&0)
                        && ordinals.last().and_then(|ordinal| ordinal.checked_add(1))
                            == Some(count) => {}
                _ => return Err(SelectedProofAccountingError::InvalidProfile),
            }
        }
        u32::try_from(consumed_coordinates.len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)
    }

    fn require_selected_resident_memory_bounds(
        resident_memory_requirement: &CommonProofResidentMemoryPlan,
        checkpoint_custody_requirement: CommonProofGenerationCheckpointCustodyRequirement,
        fri_fold_count: u16,
        source_provider_memory_accounting: SourceProviderMemoryAccounting,
        application_runtime_memory_accounting: Option<ApplicationRuntimeMemoryAccounting>,
    ) -> Result<SelectedResidentMemoryBounds, SelectedProofAccountingError> {
        derive_selected_resident_memory_bounds(
            resident_memory_requirement,
            checkpoint_custody_requirement,
            fri_fold_count,
            source_provider_memory_accounting,
            application_runtime_memory_accounting,
            true,
        )
    }

    fn derive_selected_resident_memory_bounds(
        resident_memory_requirement: &CommonProofResidentMemoryPlan,
        checkpoint_custody_requirement: CommonProofGenerationCheckpointCustodyRequirement,
        fri_fold_count: u16,
        source_provider_memory_accounting: SourceProviderMemoryAccounting,
        application_runtime_memory_accounting: Option<ApplicationRuntimeMemoryAccounting>,
        enforce_absolute_resident_bounds: bool,
    ) -> Result<SelectedResidentMemoryBounds, SelectedProofAccountingError> {
        let retained_cursor_state_byte_length = checkpoint_custody_requirement
            .cursor_manifest_requirement()
            .retained_cursor_state_byte_ceiling();
        let boundary_checkpoint_custody_byte_length =
            checkpoint_custody_requirement.boundary_peak_additional_resident_byte_ceiling();
        if boundary_checkpoint_custody_byte_length < retained_cursor_state_byte_length
            || (enforce_absolute_resident_bounds
                && !checkpoint_custody_requirement.fits_absolute_bounds())
            || resident_memory_requirement
                .phases()
                .iter()
                .find(|phase| {
                    phase.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
                })
                .is_none_or(|phase| {
                    phase.relation_polynomial_working_set_byte_length()
                        < source_provider_memory_accounting
                            .maximum_returned_source_polynomial_byte_length()
                })
        {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }

        let mut observed_checkpoint_phase_mask = 0_u8;
        let mut maximum_combined_wasm_resident_byte_length = 0_u64;
        let mut ordered_phases = Vec::new();
        ordered_phases
            .try_reserve_exact(resident_memory_requirement.phases().len())
            .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
        for phase_plan in resident_memory_requirement.phases() {
            let (checkpoint_phase_bit, checkpoint_boundary_count) = match phase_plan.phase() {
                CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns => (1_u8, 1_u16),
                CommonProofResidentMemoryPhase::ConstructingQuotient => (2_u8, 1_u16),
                CommonProofResidentMemoryPhase::DerivingOpenings => (4_u8, 1_u16),
                CommonProofResidentMemoryPhase::ConstructingInitialFri => (8_u8, 1_u16),
                CommonProofResidentMemoryPhase::FoldingFri => {
                    (16_u8, fri_fold_count.saturating_sub(1))
                }
                _ => (0_u8, 0_u16),
            };
            if checkpoint_phase_bit != 0 {
                if observed_checkpoint_phase_mask & checkpoint_phase_bit != 0 {
                    return Err(SelectedProofAccountingError::ResourcePlanning);
                }
                observed_checkpoint_phase_mask |= checkpoint_phase_bit;
            }
            let checkpoint_custody_byte_length = if checkpoint_boundary_count == 0 {
                retained_cursor_state_byte_length
            } else {
                boundary_checkpoint_custody_byte_length
            };
            let (
                source_provider_persistent_resident_byte_length,
                source_provider_loading_transient_byte_length,
            ) = selected_source_provider_phase_memory_byte_lengths(
                phase_plan.phase(),
                source_provider_memory_accounting,
            );
            let application_runtime_persistent_resident_byte_length =
                application_runtime_memory_accounting.map_or(0, |accounting| {
                    if phase_plan.phase()
                        == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
                    {
                        accounting.loading_persistent_resident_byte_length()
                    } else {
                        accounting.post_source_polynomial_finish_persistent_resident_byte_length()
                    }
                });
            let application_runtime_boundary_overlap_byte_length =
                application_runtime_memory_accounting.map_or(0, |accounting| {
                    accounting.maximum_boundary_overlap_byte_length()
                });
            let combined_byte_length = phase_plan
                .total_byte_length()
                .checked_add(source_provider_persistent_resident_byte_length)
                .and_then(|length| {
                    length.checked_add(source_provider_loading_transient_byte_length)
                })
                .and_then(|length| {
                    length.checked_add(application_runtime_persistent_resident_byte_length)
                })
                .and_then(|length| {
                    length.checked_add(application_runtime_boundary_overlap_byte_length)
                })
                .and_then(|length| length.checked_add(checkpoint_custody_byte_length))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            if enforce_absolute_resident_bounds
                && combined_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
            {
                return Err(SelectedProofAccountingError::ResourcePlanning);
            }
            maximum_combined_wasm_resident_byte_length =
                maximum_combined_wasm_resident_byte_length.max(combined_byte_length);
            ordered_phases.push(SelectedProofResidentPhaseResourceAccounting {
                phase: phase_plan.phase(),
                prover_resident_byte_length: phase_plan.total_byte_length(),
                source_provider_persistent_resident_byte_length,
                source_provider_loading_transient_byte_length,
                application_runtime_persistent_resident_byte_length,
                application_runtime_boundary_overlap_byte_length,
                checkpoint_custody_byte_length,
                combined_wasm_resident_byte_length: combined_byte_length,
            });
        }
        if observed_checkpoint_phase_mask != 31
            || ordered_phases.len() != resident_memory_requirement.phases().len()
            || ordered_phases
                .windows(2)
                .any(|pair| pair[0].phase as u8 >= pair[1].phase as u8)
        {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }
        Ok(SelectedResidentMemoryBounds {
            maximum_combined_wasm_resident_byte_length,
            ordered_phases: ordered_phases.into_boxed_slice(),
        })
    }

    fn selected_source_provider_phase_memory_byte_lengths(
        phase: CommonProofResidentMemoryPhase,
        source_provider_memory_accounting: SourceProviderMemoryAccounting,
    ) -> (u64, u64) {
        let persistent_resident_byte_length =
            if common_proof_source_provider_is_live_during_phase(phase) {
                if phase == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
                    source_provider_memory_accounting.loading_persistent_resident_byte_length()
                } else {
                    source_provider_memory_accounting
                        .post_source_finish_persistent_resident_byte_length()
                }
            } else {
                0
            };
        let loading_transient_byte_length =
            if phase == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
                source_provider_memory_accounting.additional_loading_transient_byte_length()
            } else {
                0
            };
        (
            persistent_resident_byte_length,
            loading_transient_byte_length,
        )
    }

    /// One physical proof family in the complete selected action. Variant rows are
    /// compiler alternatives; the physical proof count comes only from the
    /// canonical application-slot topology.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedPhysicalProofFamilyResourceAccounting {
        application_statement_schema_identifier: u16,
        physical_proof_count: u32,
        compiler_variant_count: u32,
        selected_variant_count: u32,
        maximum_logical_entry_count_per_proof: u32,
        complete_action_logical_entry_count: u64,
        maximum_proof_byte_length: u64,
    }

    impl SelectedPhysicalProofFamilyResourceAccounting {
        pub(crate) const fn application_statement_schema_identifier(self) -> u16 {
            self.application_statement_schema_identifier
        }

        pub(crate) const fn physical_proof_count(self) -> u32 {
            self.physical_proof_count
        }

        pub(crate) const fn compiler_variant_count(self) -> u32 {
            self.compiler_variant_count
        }

        pub(crate) const fn selected_variant_count(self) -> u32 {
            self.selected_variant_count
        }

        pub(crate) const fn maximum_logical_entry_count_per_proof(self) -> u32 {
            self.maximum_logical_entry_count_per_proof
        }

        pub(crate) const fn complete_action_logical_entry_count(self) -> u64 {
            self.complete_action_logical_entry_count
        }

        pub(crate) const fn maximum_proof_byte_length(self) -> u64 {
            self.maximum_proof_byte_length
        }
    }

    /// Exact production-derived non-proof material for the same selected action.
    /// Fixed-width streams are exact generated lengths; canonical BGV object
    /// values are codec ceilings because residue varuint lengths depend on the
    /// generated coefficients. Signed-envelope overhead remains owned by the
    /// verified generated-mailbox catalog and is not guessed here. The ballot
    /// corpus covers all selected action slots; it is traffic/storage volume, not
    /// an assertion that all candidate packages are simultaneously live or enter
    /// the evaluator aggregate.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedCompleteActionMaterialResourceAccounting {
        one_dealer_recipient_private_vss_payload_byte_length: u64,
        one_dealer_private_vss_payload_upload_byte_length: u64,
        one_recipient_private_vss_payload_download_byte_length: u64,
        ceremony_private_vss_payload_byte_length: u64,
        evaluator_source_wire_byte_length_per_participant: u64,
        evaluator_source_resident_byte_length_per_participant: u64,
        final_evaluator_key_store_wire_byte_length: u64,
        final_evaluator_key_store_resident_byte_length: u64,
        ceremony_evaluator_setup_wire_byte_length: u64,
        ceremony_evaluator_source_and_final_resident_volume_byte_length: u64,
        one_ballot_ciphertext_stream_byte_length: u64,
        one_ballot_ciphertext_stream_chunk_count: u32,
        complete_action_ballot_candidate_package_corpus_byte_length: u64,
        complete_action_ballot_candidate_package_corpus_chunk_count: u64,
        ballot_prover_material_live_set_peak_byte_length: u64,
        one_target_ciphertext_canonical_byte_length_ceiling: u64,
        paired_target_ciphertext_canonical_byte_length_ceiling: u64,
        one_target_partial_stream_byte_length: u64,
        one_participant_paired_target_partial_stream_byte_length: u64,
        ceremony_paired_target_partial_stream_byte_length: u64,
    }

    impl SelectedCompleteActionMaterialResourceAccounting {
        pub(crate) const fn one_dealer_recipient_private_vss_payload_byte_length(self) -> u64 {
            self.one_dealer_recipient_private_vss_payload_byte_length
        }

        pub(crate) const fn one_dealer_private_vss_payload_upload_byte_length(self) -> u64 {
            self.one_dealer_private_vss_payload_upload_byte_length
        }

        pub(crate) const fn one_recipient_private_vss_payload_download_byte_length(self) -> u64 {
            self.one_recipient_private_vss_payload_download_byte_length
        }

        pub(crate) const fn ceremony_private_vss_payload_byte_length(self) -> u64 {
            self.ceremony_private_vss_payload_byte_length
        }

        pub(crate) const fn evaluator_source_wire_byte_length_per_participant(self) -> u64 {
            self.evaluator_source_wire_byte_length_per_participant
        }

        pub(crate) const fn evaluator_source_resident_byte_length_per_participant(self) -> u64 {
            self.evaluator_source_resident_byte_length_per_participant
        }

        pub(crate) const fn final_evaluator_key_store_wire_byte_length(self) -> u64 {
            self.final_evaluator_key_store_wire_byte_length
        }

        pub(crate) const fn final_evaluator_key_store_resident_byte_length(self) -> u64 {
            self.final_evaluator_key_store_resident_byte_length
        }

        pub(crate) const fn ceremony_evaluator_setup_wire_byte_length(self) -> u64 {
            self.ceremony_evaluator_setup_wire_byte_length
        }

        pub(crate) const fn ceremony_evaluator_source_and_final_resident_volume_byte_length(
            self,
        ) -> u64 {
            self.ceremony_evaluator_source_and_final_resident_volume_byte_length
        }

        pub(crate) const fn one_ballot_ciphertext_stream_byte_length(self) -> u64 {
            self.one_ballot_ciphertext_stream_byte_length
        }

        pub(crate) const fn one_ballot_ciphertext_stream_chunk_count(self) -> u32 {
            self.one_ballot_ciphertext_stream_chunk_count
        }

        pub(crate) const fn complete_action_ballot_candidate_package_corpus_byte_length(
            self,
        ) -> u64 {
            self.complete_action_ballot_candidate_package_corpus_byte_length
        }

        pub(crate) const fn complete_action_ballot_candidate_package_corpus_chunk_count(
            self,
        ) -> u64 {
            self.complete_action_ballot_candidate_package_corpus_chunk_count
        }

        pub(crate) const fn ballot_prover_material_live_set_peak_byte_length(self) -> u64 {
            self.ballot_prover_material_live_set_peak_byte_length
        }

        pub(crate) const fn one_target_ciphertext_canonical_byte_length_ceiling(self) -> u64 {
            self.one_target_ciphertext_canonical_byte_length_ceiling
        }

        pub(crate) const fn paired_target_ciphertext_canonical_byte_length_ceiling(self) -> u64 {
            self.paired_target_ciphertext_canonical_byte_length_ceiling
        }

        pub(crate) const fn one_target_partial_stream_byte_length(self) -> u64 {
            self.one_target_partial_stream_byte_length
        }

        pub(crate) const fn one_participant_paired_target_partial_stream_byte_length(self) -> u64 {
            self.one_participant_paired_target_partial_stream_byte_length
        }

        pub(crate) const fn ceremony_paired_target_partial_stream_byte_length(self) -> u64 {
            self.ceremony_paired_target_partial_stream_byte_length
        }
    }

    pub(crate) fn derive_selected_complete_action_material_resource_accounting()
    -> Result<SelectedCompleteActionMaterialResourceAccounting, SelectedProofAccountingError> {
        let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
        let private_vss_payload_byte_length = selected_recipient_private_vss_payload_byte_length()
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let one_dealer_private_vss_payload_upload_byte_length = private_vss_payload_byte_length
            .checked_mul(participant_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let ceremony_private_vss_payload_byte_length =
            one_dealer_private_vss_payload_upload_byte_length
                .checked_mul(participant_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;

        let evaluator = selected_evaluator_resource_accounting()
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let ballot = selected_ballot_validity_carrier_buffer_accounting()
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
        let complete_action_ballot_candidate_package_corpus_byte_length = ballot
            .canonical_ciphertext_byte_length()
            .checked_mul(u64::from(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let complete_action_ballot_candidate_package_corpus_chunk_count =
            u64::from(ballot.canonical_ciphertext_chunk_count())
                .checked_mul(u64::from(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION))
                .ok_or(SelectedProofAccountingError::CountOverflow)?;

        let one_target_ciphertext_canonical_byte_length_ceiling =
            two_component_data_ciphertext_canonical_byte_length_ceiling_at_level(
                CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            )
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
        let paired_target_role_count = u64::try_from(KLLPS_PAIRED_TARGET_ROLE_COUNT)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let paired_target_ciphertext_canonical_byte_length_ceiling =
            one_target_ciphertext_canonical_byte_length_ceiling
                .checked_mul(paired_target_role_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let one_target_partial_stream_byte_length = u64::try_from(
            selected_target_partial_decryption_stream_byte_length()
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
        )
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let one_participant_paired_target_partial_stream_byte_length =
            one_target_partial_stream_byte_length
                .checked_mul(paired_target_role_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let ceremony_paired_target_partial_stream_byte_length =
            one_participant_paired_target_partial_stream_byte_length
                .checked_mul(participant_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let accounting = SelectedCompleteActionMaterialResourceAccounting {
            one_dealer_recipient_private_vss_payload_byte_length: private_vss_payload_byte_length,
            one_dealer_private_vss_payload_upload_byte_length,
            one_recipient_private_vss_payload_download_byte_length:
                one_dealer_private_vss_payload_upload_byte_length,
            ceremony_private_vss_payload_byte_length,
            evaluator_source_wire_byte_length_per_participant: evaluator
                .source_wire_byte_length_per_participant(),
            evaluator_source_resident_byte_length_per_participant: evaluator
                .source_resident_byte_length_per_participant(),
            final_evaluator_key_store_wire_byte_length: evaluator
                .final_evaluator_key_store_wire_byte_length(),
            final_evaluator_key_store_resident_byte_length: evaluator
                .final_evaluator_key_store_resident_byte_length(),
            ceremony_evaluator_setup_wire_byte_length: evaluator.ceremony_setup_wire_byte_length(),
            ceremony_evaluator_source_and_final_resident_volume_byte_length: evaluator
                .ceremony_source_and_final_resident_volume_byte_length(),
            one_ballot_ciphertext_stream_byte_length: ballot.canonical_ciphertext_byte_length(),
            one_ballot_ciphertext_stream_chunk_count: ballot.canonical_ciphertext_chunk_count(),
            complete_action_ballot_candidate_package_corpus_byte_length,
            complete_action_ballot_candidate_package_corpus_chunk_count,
            ballot_prover_material_live_set_peak_byte_length: ballot
                .provider_buffer_live_set_peak_byte_length(),
            one_target_ciphertext_canonical_byte_length_ceiling,
            paired_target_ciphertext_canonical_byte_length_ceiling,
            one_target_partial_stream_byte_length,
            one_participant_paired_target_partial_stream_byte_length,
            ceremony_paired_target_partial_stream_byte_length,
        };
        if accounting.one_dealer_recipient_private_vss_payload_byte_length == 0
            || accounting.one_ballot_ciphertext_stream_byte_length == 0
            || accounting.one_target_ciphertext_canonical_byte_length_ceiling == 0
            || accounting.one_target_partial_stream_byte_length == 0
        {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }
        Ok(accounting)
    }

    /// Production-derived worst-case proof resources for all physical proof slots
    /// in one complete selected action. It deliberately separates one-browser
    /// peak memory from additive ceremony storage and traffic.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SelectedCompleteProofResourceAccounting {
        ordered_families: Box<[SelectedPhysicalProofFamilyResourceAccounting]>,
        material_resources: SelectedCompleteActionMaterialResourceAccounting,
        physical_proof_count: u32,
        complete_action_logical_entry_count: u64,
        complete_action_proof_byte_ceiling: u64,
        setup_physical_proof_count: u32,
        setup_proof_byte_ceiling: u64,
        ballot_physical_proof_count: u32,
        ballot_proof_byte_ceiling: u64,
        target_release_physical_proof_count: u32,
        target_release_proof_byte_ceiling: u64,
        maximum_one_browser_wasm_resident_byte_length: u64,
    }

    impl SelectedCompleteProofResourceAccounting {
        pub(crate) fn ordered_families(&self) -> &[SelectedPhysicalProofFamilyResourceAccounting] {
            &self.ordered_families
        }

        pub(crate) const fn material_resources(
            &self,
        ) -> SelectedCompleteActionMaterialResourceAccounting {
            self.material_resources
        }

        pub(crate) const fn physical_proof_count(&self) -> u32 {
            self.physical_proof_count
        }

        pub(crate) const fn complete_action_logical_entry_count(&self) -> u64 {
            self.complete_action_logical_entry_count
        }

        pub(crate) const fn complete_action_proof_byte_ceiling(&self) -> u64 {
            self.complete_action_proof_byte_ceiling
        }

        pub(crate) const fn setup_physical_proof_count(&self) -> u32 {
            self.setup_physical_proof_count
        }

        pub(crate) const fn setup_proof_byte_ceiling(&self) -> u64 {
            self.setup_proof_byte_ceiling
        }

        pub(crate) const fn ballot_physical_proof_count(&self) -> u32 {
            self.ballot_physical_proof_count
        }

        pub(crate) const fn ballot_proof_byte_ceiling(&self) -> u64 {
            self.ballot_proof_byte_ceiling
        }

        pub(crate) const fn target_release_physical_proof_count(&self) -> u32 {
            self.target_release_physical_proof_count
        }

        pub(crate) const fn target_release_proof_byte_ceiling(&self) -> u64 {
            self.target_release_proof_byte_ceiling
        }

        pub(crate) const fn maximum_one_browser_wasm_resident_byte_length(&self) -> u64 {
            self.maximum_one_browser_wasm_resident_byte_length
        }
    }

    static SELECTED_COMPLETE_PROOF_RESOURCE_ACCOUNTING: OnceLock<
        Result<SelectedCompleteProofResourceAccounting, SelectedProofAccountingError>,
    > = OnceLock::new();

    pub(crate) fn selected_complete_proof_resource_accounting()
    -> Result<&'static SelectedCompleteProofResourceAccounting, SelectedProofAccountingError> {
        SELECTED_COMPLETE_PROOF_RESOURCE_ACCOUNTING
            .get_or_init(derive_selected_complete_proof_resource_accounting)
            .as_ref()
            .map_err(|error| *error)
    }

    fn derive_selected_complete_proof_resource_accounting()
    -> Result<SelectedCompleteProofResourceAccounting, SelectedProofAccountingError> {
        let variants = selected_proof_variant_resource_inventory()?;
        let material_resources = derive_selected_complete_action_material_resource_accounting()?;
        let slot_ceilings = selected_proof_application_slot_ceilings()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
        let mut ordered_families = Vec::new();
        ordered_families
            .try_reserve_exact(slot_ceilings.ordered_family_ceilings().len())
            .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
        let mut observed_variant_schema_identifiers = BTreeSet::new();
        let mut physical_proof_count = 0_u32;
        let mut complete_action_logical_entry_count = 0_u64;
        let mut complete_action_proof_byte_ceiling = 0_u64;
        let mut setup_physical_proof_count = 0_u32;
        let mut setup_proof_byte_ceiling = 0_u64;
        let mut ballot_physical_proof_count = 0_u32;
        let mut ballot_proof_byte_ceiling = 0_u64;
        let mut target_release_physical_proof_count = 0_u32;
        let mut target_release_proof_byte_ceiling = 0_u64;
        let mut maximum_one_browser_wasm_resident_byte_length = 0_u64;

        for family_ceiling in slot_ceilings.ordered_family_ceilings() {
            let schema_identifier = family_ceiling.application_statement_schema_identifier;
            let family_variants = variants
                .iter()
                .filter(|variant| {
                    variant.application_statement_schema_identifier() == schema_identifier
                })
                .collect::<Vec<_>>();
            if family_variants.is_empty() {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            observed_variant_schema_identifiers.insert(schema_identifier);
            let selected_family_variants = family_variants
                .iter()
                .copied()
                .filter(|variant| variant.complete_action_application_multiplicity() != 0)
                .collect::<Vec<_>>();
            if selected_family_variants.is_empty() {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            let physical_count =
                selected_family_variants
                    .iter()
                    .try_fold(0_u32, |total, variant| {
                        total
                            .checked_add(variant.complete_action_application_multiplicity())
                            .ok_or(SelectedProofAccountingError::CountOverflow)
                    })?;
            if physical_count != family_ceiling.application_slot_ceiling {
                return Err(SelectedProofAccountingError::InvalidProfile);
            }
            let compiler_variant_count = u32::try_from(family_variants.len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let selected_variant_count = u32::try_from(selected_family_variants.len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            let maximum_proof_byte_length = selected_family_variants
                .iter()
                .map(|variant| u64::try_from(variant.proof_byte_length_ceiling()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?
                .into_iter()
                .max()
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            let maximum_wasm_resident_byte_length = selected_family_variants
                .iter()
                .map(|variant| variant.maximum_combined_wasm_resident_byte_length())
                .max()
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            let maximum_logical_entry_count_per_proof = selected_family_variants
                .iter()
                .map(|variant| variant.logical_entry_count())
                .max()
                .filter(|count| *count != 0)
                .ok_or(SelectedProofAccountingError::InvalidProfile)?;
            let family_logical_entry_count =
                selected_family_variants
                    .iter()
                    .try_fold(0_u64, |total, variant| {
                        u64::from(variant.logical_entry_count())
                            .checked_mul(u64::from(
                                variant.complete_action_application_multiplicity(),
                            ))
                            .and_then(|count| total.checked_add(count))
                            .ok_or(SelectedProofAccountingError::CountOverflow)
                    })?;
            let family_proof_byte_ceiling =
                selected_family_variants
                    .iter()
                    .try_fold(0_u64, |total, variant| {
                        let proof_byte_length_ceiling =
                            u64::try_from(variant.proof_byte_length_ceiling())
                                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
                        proof_byte_length_ceiling
                            .checked_mul(u64::from(
                                variant.complete_action_application_multiplicity(),
                            ))
                            .and_then(|length| total.checked_add(length))
                            .ok_or(SelectedProofAccountingError::CountOverflow)
                    })?;
            physical_proof_count = physical_proof_count
                .checked_add(physical_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            complete_action_logical_entry_count = complete_action_logical_entry_count
                .checked_add(family_logical_entry_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            complete_action_proof_byte_ceiling = complete_action_proof_byte_ceiling
                .checked_add(family_proof_byte_ceiling)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            match schema_identifier {
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
                    ballot_physical_proof_count = ballot_physical_proof_count
                        .checked_add(physical_count)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                    ballot_proof_byte_ceiling = ballot_proof_byte_ceiling
                        .checked_add(family_proof_byte_ceiling)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                }
                ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
                    target_release_physical_proof_count = target_release_physical_proof_count
                        .checked_add(physical_count)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                    target_release_proof_byte_ceiling = target_release_proof_byte_ceiling
                        .checked_add(family_proof_byte_ceiling)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                }
                _ => {
                    setup_physical_proof_count = setup_physical_proof_count
                        .checked_add(physical_count)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                    setup_proof_byte_ceiling = setup_proof_byte_ceiling
                        .checked_add(family_proof_byte_ceiling)
                        .ok_or(SelectedProofAccountingError::CountOverflow)?;
                }
            }
            maximum_one_browser_wasm_resident_byte_length =
                maximum_one_browser_wasm_resident_byte_length
                    .max(maximum_wasm_resident_byte_length);
            ordered_families.push(SelectedPhysicalProofFamilyResourceAccounting {
                application_statement_schema_identifier: schema_identifier,
                physical_proof_count: physical_count,
                compiler_variant_count,
                selected_variant_count,
                maximum_logical_entry_count_per_proof,
                complete_action_logical_entry_count: family_logical_entry_count,
                maximum_proof_byte_length,
            });
        }

        let expected_variant_schema_identifiers = variants
            .iter()
            .map(|variant| variant.application_statement_schema_identifier())
            .collect::<BTreeSet<_>>();
        if observed_variant_schema_identifiers != expected_variant_schema_identifiers
            || physical_proof_count != slot_ceilings.total_application_slot_ceiling()
            || setup_physical_proof_count
                .checked_add(ballot_physical_proof_count)
                .and_then(|count| count.checked_add(target_release_physical_proof_count))
                != Some(physical_proof_count)
            || setup_proof_byte_ceiling
                .checked_add(ballot_proof_byte_ceiling)
                .and_then(|length| length.checked_add(target_release_proof_byte_ceiling))
                != Some(complete_action_proof_byte_ceiling)
            || maximum_one_browser_wasm_resident_byte_length
                > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }

        Ok(SelectedCompleteProofResourceAccounting {
            ordered_families: ordered_families.into_boxed_slice(),
            material_resources,
            physical_proof_count,
            complete_action_logical_entry_count,
            complete_action_proof_byte_ceiling,
            setup_physical_proof_count,
            setup_proof_byte_ceiling,
            ballot_physical_proof_count,
            ballot_proof_byte_ceiling,
            target_release_physical_proof_count,
            target_release_proof_byte_ceiling,
            maximum_one_browser_wasm_resident_byte_length,
        })
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::BTreeMap;

        use crate::foundation::{CanonicalItem, CanonicalItemType, CanonicalTuple};

        #[test]
        fn selected_target_share_resident_rows_include_the_production_source_provider() {
            let schema_identifier =
                ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER;
            let relation_context = selected_relation_plan_check_context(schema_identifier)
                .expect("the selected target-share relation has one common-proof context");
            let compilation = selected_target_release_relation()
                .expect("the selected target-share relation compiles");
            let variant = compilation
                .relation_plan()
                .select_variant(None, None)
                .expect("the selected target-share relation has one variant");
            let statement_context = SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0; Hash512::BYTE_LENGTH],
                variant.schedule_position(),
                variant.top_count(),
            );
            let statement_bytes = canonical_selected_application_statement_for_ceiling(
                schema_identifier,
                statement_context,
            )
            .expect("the selected target-share ceiling statement encodes");
            let classified_provider = selected_source_provider_memory_accounting(
                schema_identifier,
                &statement_bytes,
                variant,
                &relation_context,
                None,
            )
            .expect("the selected target-share provider accounting derives");
            let expected_provider =
                selected_kllps_target_release_source_provider_memory_accounting()
                    .expect("the production KLLPS provider accounting derives");
            let SourceProviderMemoryAccounting::Common(classified_provider) = classified_provider
            else {
                panic!("the selected target-share schema must use the common source provider");
            };
            assert_eq!(classified_provider, expected_provider);
            assert!(classified_provider.loading_persistent_resident_byte_length() > 0);
            assert!(
                classified_provider.post_source_polynomial_finish_persistent_resident_byte_length()
                    > 0
            );
            assert!(classified_provider.additional_loading_transient_byte_length() > 0);
            assert!(classified_provider.maximum_returned_source_polynomial_byte_length() > 0);
            assert!(matches!(
                selected_source_provider_memory_accounting(
                    u16::MAX,
                    &statement_bytes,
                    variant,
                    &relation_context,
                    None,
                ),
                Err(SelectedProofAccountingError::InvalidProfile)
            ));

            for phase in [
                CommonProofResidentMemoryPhase::LoadingSourcePolynomials,
                CommonProofResidentMemoryPhase::ConstructingReversedColumns,
                CommonProofResidentMemoryPhase::TransformingBaseColumns,
                CommonProofResidentMemoryPhase::MaterializingBaseTrees,
                CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns,
                CommonProofResidentMemoryPhase::TransformingAuxiliaryColumns,
                CommonProofResidentMemoryPhase::MaterializingAuxiliaryTrees,
                CommonProofResidentMemoryPhase::ConstructingQuotient,
                CommonProofResidentMemoryPhase::MaterializingQuotientTrees,
                CommonProofResidentMemoryPhase::DerivingOpenings,
                CommonProofResidentMemoryPhase::ConstructingInitialFri,
                CommonProofResidentMemoryPhase::FoldingFri,
                CommonProofResidentMemoryPhase::PreparingQueryOutput,
                CommonProofResidentMemoryPhase::EmittingQueries,
            ] {
                let (persistent_byte_length, loading_transient_byte_length) =
                    selected_source_provider_phase_memory_byte_lengths(
                        phase,
                        SourceProviderMemoryAccounting::Common(classified_provider),
                    );
                let expected_persistent_byte_length =
                    if phase == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
                        expected_provider.loading_persistent_resident_byte_length()
                    } else {
                        expected_provider
                            .post_source_polynomial_finish_persistent_resident_byte_length()
                    };
                let expected_loading_transient_byte_length =
                    if phase == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
                        expected_provider.additional_loading_transient_byte_length()
                    } else {
                        0
                    };
                assert_eq!(
                    persistent_byte_length, expected_persistent_byte_length,
                    "the target-share provider persistent bytes must follow phase {phase:?}",
                );
                assert_eq!(
                    loading_transient_byte_length, expected_loading_transient_byte_length,
                    "the target-share provider loading scratch must follow phase {phase:?}",
                );
            }
        }

        #[test]
        #[ignore = "guarded selected proof resource measurement"]
        fn selected_candidate_packed_deep_fri_resource_inventory_derives_every_variant() {
            let inventory = selected_proof_variant_resource_inventory()
                .expect("the selected capped resource inventory derives");
            let proof_profile =
                selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
                    .expect("the selected proof profile derives");
            let expected_selectors = proof_profile
                .relation_plans()
                .iter()
                .flat_map(|relation_plan| {
                    relation_plan
                        .compiled_plan()
                        .variants()
                        .iter()
                        .map(|variant| {
                            (
                                relation_plan.application_statement_schema_identifier(),
                                variant.schedule_position(),
                                variant.top_count(),
                            )
                        })
                })
                .collect::<BTreeSet<_>>();
            let observed_selectors = inventory
                .iter()
                .map(|ceiling| {
                    (
                        ceiling.application_statement_schema_identifier(),
                        ceiling.schedule_position(),
                        ceiling.top_count(),
                    )
                })
                .collect::<BTreeSet<_>>();

            assert_eq!(observed_selectors, expected_selectors);
            assert_eq!(inventory.len(), expected_selectors.len());
            assert!(inventory.iter().all(|ceiling| {
                ceiling.proof_byte_length() > 0
                    && ceiling.proof_byte_length() <= MAXIMUM_COMMON_PROOF_BYTE_LENGTH
                    && u64::try_from(ceiling.proof_byte_length())
                        .is_ok_and(|length| length <= MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH)
            }));
        }

        #[test]
        #[ignore = "guarded selected proof resource measurement"]
        fn selected_candidate_external_memory_diagnostic_reports_every_variant() {
            let diagnostic_rows = selected_proof_external_memory_diagnostic_report()
                .expect("the selected cap-neutral diagnostic inventory derives");
            let proof_profile =
                selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
                    .expect("the selected proof profile derives");
            assert_eq!(
                proof_profile
                    .relation_plans()
                    .iter()
                    .map(|plan| plan.application_statement_schema_identifier())
                    .collect::<Vec<_>>(),
                crate::bgv::proof_suite::FIRST_PROFILE_APPLICATION_FAMILIES,
            );
            let expected_selectors = proof_profile
                .relation_plans()
                .iter()
                .flat_map(|relation_plan| {
                    relation_plan
                        .compiled_plan()
                        .variants()
                        .iter()
                        .map(|variant| {
                            (
                                relation_plan.application_statement_schema_identifier(),
                                variant.schedule_position(),
                                variant.top_count(),
                            )
                        })
                })
                .collect::<Vec<_>>();
            let observed_selectors = diagnostic_rows
                .iter()
                .cloned()
                .map(|row| {
                    (
                        row.application_statement_schema_identifier(),
                        row.schedule_position(),
                        row.top_count(),
                    )
                })
                .collect::<Vec<_>>();

            assert_eq!(observed_selectors, expected_selectors);
            assert_eq!(diagnostic_rows.len(), expected_selectors.len());
            assert_eq!(diagnostic_rows.len(), 31);
            assert_eq!(
                diagnostic_rows
                    .iter()
                    .map(|row| row.application_statement_schema_identifier())
                    .collect::<BTreeSet<_>>(),
                crate::bgv::proof_suite::FIRST_PROFILE_APPLICATION_FAMILIES
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            );

            let family_name = |schema_identifier| {
                match schema_identifier {
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER => {
                    "same-secret"
                }
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "public-key-share"
                }
                ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "collective-public-key-aggregate"
                }
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "relinearization-round-one"
                }
                ProofApplicationSlotCeilings::RKG_ROUND_ONE_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "rkg-round-one-aggregate"
                }
                ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER => {
                    "relinearization-round-two"
                }
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "galois-key-share"
                }
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "evaluator-key-aggregate"
                }
                ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
                    "ballot-validity"
                }
                ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER => {
                    "target-share"
                }
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "vss-share-linkage"
                }
                ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                    "aggregate-threshold-share"
                }
                _ => "unknown",
            }
            };
            let selector = |value: Option<u64>| {
                value.map_or_else(|| "none".to_owned(), |value| value.to_string())
            };
            let mut requirement_count = 0_usize;
            let mut derivation_error_count = 0_usize;
            let mut complete_action_physical_proof_slot_count = 0_u32;
            let mut complete_action_logical_entry_count = 0_u64;
            let mut complete_action_proof_byte_length_ceiling = 0_u128;
            let mut complete_action_total_written_byte_length = 0_u128;
            let mut complete_action_total_read_byte_length = 0_u128;
            let mut complete_action_transaction_count = 0_u128;
            let mut complete_action_distinct_physical_object_count = 0_u128;
            let mut complete_action_object_lifecycle_count = 0_u128;
            let mut selected_maximum_peak_stored_byte_length = 0_u64;
            let mut selected_maximum_distinct_physical_object_count = 0_u32;
            let mut selected_maximum_transaction_payload_byte_length = 0_u64;
            let mut selected_maximum_combined_wasm_resident_byte_length = 0_u64;
            let mut selected_maximum_copied_buffer_byte_length = 0_u64;
            for row in diagnostic_rows.iter().cloned() {
                let schema_identifier = row.application_statement_schema_identifier();
                assert_ne!(family_name(schema_identifier), "unknown");
                match row.outcome() {
                    Ok(diagnostic_requirement) => {
                        requirement_count += 1;
                        let requirement = diagnostic_requirement.external_memory_requirement();
                        let multiplicity =
                            diagnostic_requirement.complete_action_application_multiplicity();
                        complete_action_physical_proof_slot_count =
                            complete_action_physical_proof_slot_count
                                .checked_add(multiplicity)
                                .expect("the selected physical proof-slot total fits u32");
                        complete_action_logical_entry_count = complete_action_logical_entry_count
                            .checked_add(
                                u64::from(multiplicity)
                                    .checked_mul(u64::from(
                                        diagnostic_requirement.logical_entry_count(),
                                    ))
                                    .expect("the selected logical-entry product fits u64"),
                            )
                            .expect("the selected logical-entry total fits u64");
                        complete_action_proof_byte_length_ceiling =
                            complete_action_proof_byte_length_ceiling
                                .checked_add(
                                    u128::from(multiplicity)
                                        * u128::try_from(
                                            diagnostic_requirement.proof_byte_length_ceiling(),
                                        )
                                        .expect("the selected proof byte ceiling fits u128"),
                                )
                                .expect("the complete-action proof byte ceiling fits u128");
                        complete_action_total_written_byte_length =
                            complete_action_total_written_byte_length
                                .checked_add(
                                    u128::from(multiplicity)
                                        * u128::from(requirement.total_written_byte_length()),
                                )
                                .expect("the complete-action write total fits u128");
                        complete_action_total_read_byte_length =
                            complete_action_total_read_byte_length
                                .checked_add(
                                    u128::from(multiplicity)
                                        * u128::from(requirement.total_read_byte_length()),
                                )
                                .expect("the complete-action read total fits u128");
                        complete_action_transaction_count = complete_action_transaction_count
                            .checked_add(
                                u128::from(multiplicity)
                                    * u128::from(requirement.transaction_count()),
                            )
                            .expect("the complete-action transaction total fits u128");
                        complete_action_distinct_physical_object_count =
                            complete_action_distinct_physical_object_count
                                .checked_add(
                                    u128::from(multiplicity)
                                        * u128::from(requirement.distinct_physical_object_count()),
                                )
                                .expect("the complete-action object total fits u128");
                        complete_action_object_lifecycle_count =
                            complete_action_object_lifecycle_count
                                .checked_add(
                                    u128::from(multiplicity)
                                        * u128::from(requirement.object_lifecycle_count()),
                                )
                                .expect("the complete-action lifecycle total fits u128");
                        if multiplicity != 0 {
                            selected_maximum_peak_stored_byte_length =
                                selected_maximum_peak_stored_byte_length
                                    .max(requirement.peak_stored_byte_length());
                            selected_maximum_distinct_physical_object_count =
                                selected_maximum_distinct_physical_object_count
                                    .max(requirement.distinct_physical_object_count());
                            selected_maximum_transaction_payload_byte_length =
                                selected_maximum_transaction_payload_byte_length
                                    .max(requirement.maximum_transaction_payload_byte_length());
                            selected_maximum_combined_wasm_resident_byte_length =
                                selected_maximum_combined_wasm_resident_byte_length.max(
                                    diagnostic_requirement
                                        .maximum_combined_wasm_resident_byte_length(),
                                );
                            selected_maximum_copied_buffer_byte_length =
                                selected_maximum_copied_buffer_byte_length.max(
                                    diagnostic_requirement.maximum_copied_buffer_byte_length(),
                                );
                        }
                        let object_count_variance =
                            i64::from(requirement.distinct_physical_object_count())
                                - i64::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
                                    .expect("the object cap fits i64");
                        let peak_stored_byte_length_variance =
                            i128::from(requirement.peak_stored_byte_length())
                                - i128::from(
                                    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
                                );
                        let proof_components =
                            diagnostic_requirement.proof_component_byte_accounting();
                        let proof_byte_length_ceiling_variance =
                            i128::try_from(diagnostic_requirement.proof_byte_length_ceiling())
                                .expect("the proof byte ceiling fits i128")
                                - i128::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
                                    .expect("the proof cap fits i128");
                        let maximum_combined_wasm_resident_byte_length_variance =
                            i128::from(
                                diagnostic_requirement.maximum_combined_wasm_resident_byte_length(),
                            ) - i128::from(MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH);
                        let maximum_copied_buffer_byte_length =
                            diagnostic_requirement.maximum_copied_buffer_byte_length();
                        let maximum_copied_buffer_byte_length_bound =
                            u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                                .expect("the copied-buffer bound fits u64");
                        let maximum_copied_buffer_byte_length_variance =
                            i128::from(maximum_copied_buffer_byte_length)
                                - i128::from(maximum_copied_buffer_byte_length_bound);
                        assert_eq!(diagnostic_requirement.resident_phases().len(), 14);
                        let mut observed_resident_peak_byte_length = 0_u64;
                        for (phase_index, phase) in diagnostic_requirement
                            .resident_phases()
                            .iter()
                            .copied()
                            .enumerate()
                        {
                            assert_eq!(
                                phase.phase_code(),
                                u8::try_from(phase_index + 1).expect("the phase ordinal fits u8"),
                            );
                            assert_eq!(
                                phase
                                    .prover_resident_byte_length()
                                    .checked_add(
                                        phase.source_provider_persistent_resident_byte_length(),
                                    )
                                    .and_then(|length| {
                                        length.checked_add(
                                            phase
                                                .source_provider_loading_transient_byte_length(),
                                        )
                                    })
                                    .and_then(|length| {
                                        length.checked_add(
                                            phase
                                                .application_runtime_persistent_resident_byte_length(),
                                        )
                                    })
                                    .and_then(|length| {
                                        length.checked_add(
                                            phase
                                                .application_runtime_boundary_overlap_byte_length(),
                                        )
                                    })
                                    .and_then(|length| {
                                        length.checked_add(phase.checkpoint_custody_byte_length())
                                    }),
                                Some(phase.combined_wasm_resident_byte_length()),
                            );
                            observed_resident_peak_byte_length = observed_resident_peak_byte_length
                                .max(phase.combined_wasm_resident_byte_length());
                            let phase_resident_byte_length_variance =
                                i128::from(phase.combined_wasm_resident_byte_length())
                                    - i128::from(MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH);
                            println!(
                                "selected-proof-resident-memory-diagnostic family={} schema_identifier=0x{:04x} schedule_position={} top_count={} phase_code={} phase={} prover_resident_byte_length={} source_provider_persistent_resident_byte_length={} source_provider_loading_transient_byte_length={} application_runtime_persistent_resident_byte_length={} application_runtime_boundary_overlap_byte_length={} checkpoint_custody_byte_length={} combined_wasm_resident_byte_length={} maximum_wasm_resident_byte_length={} combined_wasm_resident_byte_length_variance={} outcome=requirement",
                                family_name(schema_identifier),
                                schema_identifier,
                                selector(row.schedule_position().map(u64::from)),
                                selector(row.top_count().map(u64::from)),
                                phase.phase_code(),
                                phase.phase_name(),
                                phase.prover_resident_byte_length(),
                                phase.source_provider_persistent_resident_byte_length(),
                                phase.source_provider_loading_transient_byte_length(),
                                phase.application_runtime_persistent_resident_byte_length(),
                                phase.application_runtime_boundary_overlap_byte_length(),
                                phase.checkpoint_custody_byte_length(),
                                phase.combined_wasm_resident_byte_length(),
                                MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
                                phase_resident_byte_length_variance,
                            );
                        }
                        assert_eq!(
                            observed_resident_peak_byte_length,
                            diagnostic_requirement.maximum_combined_wasm_resident_byte_length(),
                        );
                        println!(
                            "selected-proof-external-memory-diagnostic family={} schema_identifier=0x{:04x} schedule_position={} top_count={} relation_columns={} verifier_sequence_relation_columns={} bound_tree_relation_columns={} prover_relation_columns={} relation_constraints={} evaluation_domain_size={} opening_degree_bound_exclusive={} quotient_decomposition_stride={} quotient_component_degree_bound_exclusive={} quotient_component_count={} fri_fold_count={} terminal_coefficient_count={} unique_query_count={} query_orbit_count={} complete_action_application_multiplicity={} logical_entry_count={} opening_claim_count={} proof_byte_length_ceiling={} maximum_proof_byte_length={} proof_byte_length_ceiling_variance={} canonical_header_byte_length_ceiling={} body_prefix_byte_length_ceiling={} query_section_byte_length_ceiling={} canonical_framing_byte_length_ceiling={} relation_commitments_and_openings_byte_length_ceiling={} quotient_commitments_and_openings_byte_length_ceiling={} transcript_opening_claims_byte_length_ceiling={} fri_byte_length_ceiling={} proof_tree_count={} bound_public_tree_count={} total_materialized_row_width={} maximum_combined_wasm_resident_byte_length={} maximum_wasm_resident_byte_length={} maximum_combined_wasm_resident_byte_length_variance={} maximum_prefetched_query_byte_length={} maximum_external_memory_transaction_payload_byte_length={} maximum_proof_output_chunk_byte_length_ceiling={} proof_output_chunk_count_ceiling={} maximum_copied_buffer_byte_length={} maximum_copied_buffer_byte_length_bound={} maximum_copied_buffer_byte_length_variance={} outcome=requirement step_count={} maximum_chunk_byte_length={} maximum_transaction_payload_byte_length={} distinct_physical_object_count={} object_lifecycle_count={} peak_stored_byte_length={} total_written_byte_length={} total_read_byte_length={} transaction_count={} maximum_object_count={} object_count_variance={} maximum_stored_byte_length={} peak_stored_byte_length_variance={}",
                            family_name(schema_identifier),
                            schema_identifier,
                            selector(row.schedule_position().map(u64::from)),
                            selector(row.top_count().map(u64::from)),
                            row.relation_column_count(),
                            diagnostic_requirement.verifier_sequence_relation_column_count(),
                            diagnostic_requirement.bound_tree_relation_column_count(),
                            diagnostic_requirement.prover_relation_column_count(),
                            row.relation_constraint_count(),
                            diagnostic_requirement.evaluation_domain_size(),
                            diagnostic_requirement.opening_degree_bound_exclusive(),
                            diagnostic_requirement.quotient_decomposition_stride(),
                            diagnostic_requirement.quotient_component_degree_bound_exclusive(),
                            diagnostic_requirement.quotient_component_count(),
                            diagnostic_requirement.fri_fold_count(),
                            diagnostic_requirement.terminal_coefficient_count(),
                            diagnostic_requirement.unique_query_count(),
                            diagnostic_requirement.query_orbit_count(),
                            diagnostic_requirement.complete_action_application_multiplicity(),
                            diagnostic_requirement.logical_entry_count(),
                            diagnostic_requirement.opening_claim_count(),
                            diagnostic_requirement.proof_byte_length_ceiling(),
                            MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
                            proof_byte_length_ceiling_variance,
                            diagnostic_requirement.canonical_header_byte_length_ceiling(),
                            diagnostic_requirement.body_prefix_byte_length_ceiling(),
                            diagnostic_requirement.query_section_byte_length_ceiling(),
                            proof_components.canonical_framing_byte_length_ceiling(),
                            proof_components
                                .relation_commitments_and_openings_byte_length_ceiling(),
                            proof_components
                                .quotient_commitments_and_openings_byte_length_ceiling(),
                            proof_components.transcript_opening_claims_byte_length_ceiling(),
                            proof_components.fri_byte_length_ceiling(),
                            diagnostic_requirement.ordered_query_trees().len(),
                            diagnostic_requirement.bound_public_tree_count(),
                            diagnostic_requirement.total_materialized_row_width(),
                            diagnostic_requirement.maximum_combined_wasm_resident_byte_length(),
                            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
                            maximum_combined_wasm_resident_byte_length_variance,
                            diagnostic_requirement.maximum_prefetched_query_byte_length(),
                            diagnostic_requirement
                                .maximum_external_memory_transaction_payload_byte_length(),
                            diagnostic_requirement
                                .maximum_proof_output_chunk_byte_length_ceiling(),
                            diagnostic_requirement.proof_output_chunk_count_ceiling(),
                            maximum_copied_buffer_byte_length,
                            maximum_copied_buffer_byte_length_bound,
                            maximum_copied_buffer_byte_length_variance,
                            requirement.step_count(),
                            requirement.maximum_chunk_byte_length(),
                            requirement.maximum_transaction_payload_byte_length(),
                            requirement.distinct_physical_object_count(),
                            requirement.object_lifecycle_count(),
                            requirement.peak_stored_byte_length(),
                            requirement.total_written_byte_length(),
                            requirement.total_read_byte_length(),
                            requirement.transaction_count(),
                            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
                            object_count_variance,
                            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
                            peak_stored_byte_length_variance,
                        );
                    }
                    Err(error) => {
                        derivation_error_count += 1;
                        println!(
                            "selected-proof-external-memory-diagnostic family={} schema_identifier=0x{:04x} schedule_position={} top_count={} relation_columns={} relation_constraints={} outcome=derivation-error error_stage={} error={error:?}",
                            family_name(schema_identifier),
                            schema_identifier,
                            selector(row.schedule_position().map(u64::from)),
                            selector(row.top_count().map(u64::from)),
                            row.relation_column_count(),
                            row.relation_constraint_count(),
                            error.stage(),
                        );
                    }
                }
            }
            assert_eq!(
                requirement_count + derivation_error_count,
                diagnostic_rows.len()
            );
            println!(
                "selected-proof-external-memory-diagnostic-summary family_count={} selector_count={} requirement_count={} derivation_error_count={} complete_action_physical_proof_slot_count={} complete_action_logical_entry_count={} complete_action_proof_byte_length_ceiling={} complete_action_distinct_physical_object_count={} complete_action_object_lifecycle_count={} complete_action_total_written_byte_length={} complete_action_total_read_byte_length={} complete_action_transaction_count={} selected_maximum_distinct_physical_object_count={} selected_maximum_peak_stored_byte_length={} selected_maximum_transaction_payload_byte_length={} selected_maximum_combined_wasm_resident_byte_length={} selected_maximum_copied_buffer_byte_length={}",
                crate::bgv::proof_suite::FIRST_PROFILE_APPLICATION_FAMILIES.len(),
                diagnostic_rows.len(),
                requirement_count,
                derivation_error_count,
                complete_action_physical_proof_slot_count,
                complete_action_logical_entry_count,
                complete_action_proof_byte_length_ceiling,
                complete_action_distinct_physical_object_count,
                complete_action_object_lifecycle_count,
                complete_action_total_written_byte_length,
                complete_action_total_read_byte_length,
                complete_action_transaction_count,
                selected_maximum_distinct_physical_object_count,
                selected_maximum_peak_stored_byte_length,
                selected_maximum_transaction_payload_byte_length,
                selected_maximum_combined_wasm_resident_byte_length,
                selected_maximum_copied_buffer_byte_length,
            );
            assert_eq!(
                derivation_error_count, 0,
                "every selected family and selector must have one complete cap-neutral requirement row",
            );
            assert_eq!(complete_action_physical_proof_slot_count, 103);
            assert_eq!(complete_action_logical_entry_count, 159);
            require_selected_evaluator_diagnostic_variant_ceiling_equality(&diagnostic_rows)
                .expect("all twenty evaluator selectors must have one exact resource ceiling");
            let mut inconsistent_diagnostic_rows = diagnostic_rows.to_vec();
            let inconsistent_evaluator_row = inconsistent_diagnostic_rows
                .iter_mut()
                .find(|row| {
                    row.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                        && row.top_count() == Some(7)
                })
                .expect("the seventh evaluator selector has one diagnostic row");
            inconsistent_evaluator_row.relation_constraint_count = inconsistent_evaluator_row
                .relation_constraint_count
                .checked_add(1)
                .expect("the relation constraint count increments");
            assert_eq!(
                require_selected_evaluator_diagnostic_variant_ceiling_equality(
                    &inconsistent_diagnostic_rows,
                ),
                Err(SelectedProofAccountingError::InvalidProfile),
            );

            for relation_plan in proof_profile.relation_plans() {
                let schema_identifier = relation_plan.application_statement_schema_identifier();
                let relation_context = selected_relation_plan_check_context(schema_identifier)
                    .expect("the selected relation has one common-proof context");
                for variant in relation_plan.compiled_plan().variants() {
                    let statement_context = SelectedApplicationStatementContext::new(
                        FOUNDATION_PROFILE.protocol_version,
                        [0; Hash512::BYTE_LENGTH],
                        variant.schedule_position(),
                        variant.top_count(),
                    );
                    let statement_bytes = canonical_selected_application_statement_for_ceiling(
                        schema_identifier,
                        statement_context,
                    )
                    .expect("the production-derived statement encodes");
                    let sizing = selected_cap_neutral_proof_transport_sizing(
                        schema_identifier,
                        &statement_bytes,
                        variant,
                        &relation_context,
                    )
                    .expect(
                        "the relation variant compiles through the packed common-proof backend",
                    );
                    let nonterminal_fri_tree_count = sizing
                        .layout
                        .catalog()
                        .entries()
                        .iter()
                        .filter(|entry| {
                            matches!(
                                entry.source(),
                                super::ProofTreeCatalogSource::NonterminalFriLayer { .. }
                            )
                        })
                        .count();
                    assert_eq!(
                        nonterminal_fri_tree_count,
                        usize::from(sizing.transcript_schedule.fri_fold_count() - 1),
                        "one packed initial polynomial must feed one complete FRI chain",
                    );
                    assert_eq!(
                        sizing.transcript_schedule.opening_claim_count(),
                        u32::try_from(variant.ordered_opening_claims().len())
                            .expect("the checked opening-claim count fits u32"),
                        "every ordered DEEP claim must enter the one packed initial polynomial",
                    );
                }
            }
        }

        #[test]
        #[ignore = "guarded selected proof resource measurement"]
        fn runtime_limits_match_resource_ceilings_for_every_selected_variant() {
            let inventory = selected_proof_variant_resource_inventory()
                .expect("the selected resource inventory derives");
            let proof_profile =
                selected_proof_profile_set(SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT)
                    .expect("the selected proof profile derives");

            for relation_plan in proof_profile.relation_plans() {
                let schema_identifier = relation_plan.application_statement_schema_identifier();
                for variant in relation_plan.compiled_plan().variants() {
                    let statement_context = SelectedApplicationStatementContext::new(
                        FOUNDATION_PROFILE.protocol_version,
                        [0; Hash512::BYTE_LENGTH],
                        variant.schedule_position(),
                        variant.top_count(),
                    );
                    let statement_bytes = canonical_selected_application_statement_for_ceiling(
                        schema_identifier,
                        statement_context,
                    )
                    .expect("the canonical ceiling statement derives");
                    let runtime_limits =
                        selected_proof_runtime_limits(schema_identifier, &statement_bytes, variant)
                            .expect("selected runtime limits derive");
                    let compiler_ceiling = inventory
                        .iter()
                        .find(|ceiling| {
                            ceiling.application_statement_schema_identifier() == schema_identifier
                                && ceiling.schedule_position() == variant.schedule_position()
                                && ceiling.top_count() == variant.top_count()
                        })
                        .expect("every compiled variant has one ceiling");

                    assert_eq!(
                        runtime_limits.proof_byte_length(),
                        compiler_ceiling.proof_byte_length_ceiling()
                    );
                    assert_eq!(
                        runtime_limits.external_memory_chunk_byte_length(),
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
                    );
                    assert!(runtime_limits.prefetched_query_byte_length() > 0);
                    assert!(
                        runtime_limits.prefetched_query_byte_length()
                            <= u64::try_from(runtime_limits.proof_byte_length())
                                .expect("the proof ceiling fits u64")
                    );
                }
            }
        }

        #[test]
        #[ignore = "guarded selected proof resource measurement"]
        fn exact_variant_rows_reconcile_transport_frontiers_memory_and_copies() {
            let inventory = selected_proof_variant_resource_inventory()
                .expect("the selected resource inventory derives");
            assert!(!inventory.is_empty());

            for variant in inventory {
                let proof_byte_length_ceiling =
                    u64::try_from(variant.proof_byte_length_ceiling())
                        .expect("proof byte ceiling fits u64");
                assert_eq!(
                    variant
                        .proof_component_byte_accounting()
                        .proof_byte_length_ceiling(),
                    Some(proof_byte_length_ceiling)
                );
                assert_eq!(
                    variant
                        .canonical_header_byte_length_ceiling()
                        .checked_add(variant.body_prefix_byte_length_ceiling())
                        .and_then(|length| {
                            length.checked_add(variant.query_section_byte_length_ceiling())
                        }),
                    Some(proof_byte_length_ceiling)
                );

                let mut observed_bound_public_tree_count = 0_u32;
                let mut observed_materialized_row_width = 0_u64;
                let mut query_section_byte_length_ceiling_sum = 0_u64;
                for (tree_index, tree) in variant.ordered_query_trees().iter().enumerate() {
                    observed_bound_public_tree_count += u32::from(tree.is_bound_public_tree());
                    observed_materialized_row_width += tree.materialized_row_width();
                    query_section_byte_length_ceiling_sum += tree.byte_length_ceiling();
                    assert_eq!(
                        tree.authentication_frontier_digest_byte_length_ceiling(),
                        tree.authentication_frontier_node_count_at_ceiling()
                            * u64::try_from(Hash512::BYTE_LENGTH).expect("digest length fits u64")
                    );
                    assert_eq!(
                        tree.opened_leaf_payload_byte_length_ceiling()
                            + tree.authentication_frontier_digest_byte_length_ceiling()
                            + tree.canonical_framing_byte_length_ceiling(),
                        tree.byte_length_ceiling()
                    );
                    assert!(
                        tree.minimum_opened_leaf_count() <= tree.opened_leaf_count_at_ceiling()
                            && tree.opened_leaf_count_at_ceiling()
                                <= tree.maximum_opened_leaf_count()
                            && tree.maximum_opened_leaf_count() <= tree.leaf_count()
                    );
                    assert_eq!(
                        tree.tree_catalog_index(),
                        u16::try_from(tree_index).expect("catalog index fits u16")
                    );
                }
                assert_eq!(
                    observed_bound_public_tree_count,
                    variant.bound_public_tree_count()
                );
                assert_eq!(
                    observed_materialized_row_width,
                    variant.total_materialized_row_width()
                );
                assert_eq!(
                    query_section_byte_length_ceiling_sum,
                    variant.query_section_byte_length_ceiling()
                );

                assert_eq!(variant.resident_phases().len(), 14);
                let mut resident_peak = 0_u64;
                for (phase_index, phase) in variant.resident_phases().iter().enumerate() {
                    assert_eq!(
                        phase.phase() as u8,
                        u8::try_from(phase_index + 1).expect("phase ordinal fits u8")
                    );
                    assert_eq!(
                        phase
                            .prover_resident_byte_length()
                            .checked_add(phase.source_provider_persistent_resident_byte_length())
                            .and_then(|length| {
                                length.checked_add(
                                    phase.source_provider_loading_transient_byte_length(),
                                )
                            })
                            .and_then(|length| {
                                length.checked_add(
                                    phase.application_runtime_persistent_resident_byte_length(),
                                )
                            })
                            .and_then(|length| {
                                length.checked_add(
                                    phase.application_runtime_boundary_overlap_byte_length(),
                                )
                            })
                            .and_then(|length| {
                                length.checked_add(phase.checkpoint_custody_byte_length())
                            }),
                        Some(phase.combined_wasm_resident_byte_length())
                    );
                    resident_peak = resident_peak.max(phase.combined_wasm_resident_byte_length());
                }
                assert_eq!(
                    resident_peak,
                    variant.maximum_combined_wasm_resident_byte_length()
                );

                assert!(
                    variant.maximum_copied_buffer_byte_length()
                        >= variant.maximum_prefetched_query_byte_length()
                        && variant.maximum_copied_buffer_byte_length()
                            >= variant.maximum_external_memory_transaction_payload_byte_length()
                        && variant.maximum_copied_buffer_byte_length()
                            >= variant.maximum_proof_output_chunk_byte_length_ceiling()
                        && variant.maximum_copied_buffer_byte_length()
                            <= u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
                                .expect("copied-buffer bound fits u64")
                );
                let output_chunk_byte_length =
                    u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
                        .expect("output chunk length fits u64");
                assert_eq!(
                    variant.proof_output_chunk_count_ceiling(),
                    proof_byte_length.div_ceil(output_chunk_byte_length)
                );
            }
        }

        #[test]
        #[ignore = "guarded selected proof resource measurement"]
        fn complete_action_accounting_derives_all_physical_proof_slots() {
            let accounting = selected_complete_proof_resource_accounting()
                .expect("the complete selected accounting derives");
            let application_slot_ceilings = selected_proof_application_slot_ceilings()
                .expect("the selected application slot ceilings derive");
            let expected_physical_counts = application_slot_ceilings
                .ordered_family_ceilings()
                .iter()
                .map(|family| {
                    (
                        family.application_statement_schema_identifier,
                        family.application_slot_ceiling,
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let observed_physical_counts = accounting
                .ordered_families()
                .iter()
                .map(|family| {
                    (
                        family.application_statement_schema_identifier(),
                        family.physical_proof_count(),
                    )
                })
                .collect::<BTreeMap<_, _>>();

            assert_eq!(observed_physical_counts, expected_physical_counts);
            assert_eq!(
                accounting.physical_proof_count(),
                application_slot_ceilings.total_application_slot_ceiling()
            );
            let galois_physical_proof_count = application_slot_ceilings
                .family_ceiling(
                    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                )
                .expect("the selected Galois family has an application ceiling");
            let galois_logical_entry_count_per_proof = u64::try_from(
                selected_galois_key_share_relation_plan_input()
                    .expect("the selected Galois relation input derives")
                    .ordered_entries
                    .len(),
            )
            .expect("the Galois logical entry count fits u64");
            let evaluator_physical_proof_count = application_slot_ceilings
            .family_ceiling(
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            .expect("the selected evaluator family has an application ceiling");
            let evaluator_logical_entry_count_per_proof = u64::try_from(
                selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
                    .expect("the selected complete evaluator entry positions derive")
                    .len(),
            )
            .expect("the evaluator logical entry count fits u64");
            let expected_logical_entry_count =
                u64::from(application_slot_ceilings.total_application_slot_ceiling())
                    .checked_add(
                        u64::from(galois_physical_proof_count)
                            .checked_mul(galois_logical_entry_count_per_proof - 1)
                            .expect("the Galois logical entry count fits u64"),
                    )
                    .and_then(|count| {
                        count.checked_add(
                            u64::from(evaluator_physical_proof_count)
                                .checked_mul(evaluator_logical_entry_count_per_proof - 1)?,
                        )
                    })
                    .expect("the complete logical entry count fits u64");
            assert_eq!(
                accounting.complete_action_logical_entry_count(),
                expected_logical_entry_count
            );
            let expected_ballot_physical_proof_count = application_slot_ceilings
                .family_ceiling(
                    ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
                )
                .expect("the selected ballot family has an application ceiling");
            let expected_target_release_physical_proof_count = application_slot_ceilings
                .family_ceiling(
                    ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
                )
                .expect("the selected target release family has an application ceiling");
            let expected_setup_physical_proof_count = application_slot_ceilings
                .total_application_slot_ceiling()
                .checked_sub(expected_ballot_physical_proof_count)
                .and_then(|count| count.checked_sub(expected_target_release_physical_proof_count))
                .expect("the selected setup proof count fits u32");
            assert_eq!(
                accounting.setup_physical_proof_count(),
                expected_setup_physical_proof_count
            );
            assert_eq!(
                accounting.ballot_physical_proof_count(),
                expected_ballot_physical_proof_count
            );
            assert_eq!(
                accounting.target_release_physical_proof_count(),
                expected_target_release_physical_proof_count
            );
            let materials = accounting.material_resources();
            let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
            assert_eq!(
                materials.one_dealer_private_vss_payload_upload_byte_length(),
                materials.one_dealer_recipient_private_vss_payload_byte_length()
                    * participant_count
            );
            assert_eq!(
                materials.one_recipient_private_vss_payload_download_byte_length(),
                materials.one_dealer_private_vss_payload_upload_byte_length()
            );
            assert_eq!(
                materials.ceremony_private_vss_payload_byte_length(),
                materials.one_dealer_private_vss_payload_upload_byte_length() * participant_count
            );
            assert_eq!(
                materials.complete_action_ballot_candidate_package_corpus_byte_length(),
                materials.one_ballot_ciphertext_stream_byte_length()
                    * u64::from(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION)
            );
            assert_eq!(
                materials.complete_action_ballot_candidate_package_corpus_chunk_count(),
                u64::from(materials.one_ballot_ciphertext_stream_chunk_count())
                    * u64::from(SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION)
            );
            assert_eq!(
                (
                    materials.one_ballot_ciphertext_stream_byte_length(),
                    materials.one_ballot_ciphertext_stream_chunk_count(),
                ),
                (12_058_628, 12)
            );
            assert_eq!(
                (
                    materials.complete_action_ballot_candidate_package_corpus_byte_length(),
                    materials.complete_action_ballot_candidate_package_corpus_chunk_count(),
                ),
                (241_172_560, 240)
            );
            let ballot_carrier = selected_ballot_validity_carrier_buffer_accounting()
                .expect("the selected ballot carrier accounting derives");
            assert_eq!(
                (
                    ballot_carrier.decoded_ciphertext_residue_byte_length(),
                    ballot_carrier.provider_bound_public_residue_byte_length(),
                    ballot_carrier.provider_witness_coefficient_byte_length(),
                    ballot_carrier.provider_precomputed_transform_byte_length(),
                    ballot_carrier.provider_value_cache_byte_length(),
                    ballot_carrier.provider_transient_scratch_byte_length(),
                    ballot_carrier.provider_buffer_live_set_peak_byte_length(),
                    ballot_carrier.transferred_source_polynomial_byte_length(),
                    ballot_carrier.maximum_boundary_copied_buffer_byte_length(),
                ),
                (
                    24_117_248, 36_175_872, 3_145_728, 1_048_576, 524_288, 1_048_576, 41_943_040,
                    262_144, 1_048_576,
                )
            );
            assert_eq!(
                materials.paired_target_ciphertext_canonical_byte_length_ceiling(),
                materials.one_target_ciphertext_canonical_byte_length_ceiling() * 2
            );
            assert_eq!(
                materials.one_participant_paired_target_partial_stream_byte_length(),
                materials.one_target_partial_stream_byte_length() * 2
            );
            assert_eq!(
                materials.ceremony_paired_target_partial_stream_byte_length(),
                materials.one_participant_paired_target_partial_stream_byte_length()
                    * participant_count
            );
            assert_eq!(
                (
                    materials.evaluator_source_wire_byte_length_per_participant(),
                    materials.evaluator_source_resident_byte_length_per_participant(),
                    materials.final_evaluator_key_store_wire_byte_length(),
                    materials.final_evaluator_key_store_resident_byte_length(),
                    materials.ceremony_evaluator_setup_wire_byte_length(),
                    materials.ceremony_evaluator_source_and_final_resident_volume_byte_length(),
                ),
                (
                    183_631_872,
                    355_467_712,
                    155_582_464,
                    300_941_312,
                    1_991_901_184,
                    3_855_618_432,
                )
            );
            let evaluator = selected_evaluator_resource_accounting()
                .expect("the selected evaluator material accounting derives");
            for level in evaluator.levels() {
                assert_eq!(
                    level.source_wire_byte_length_per_participant(),
                    level.component_wire_byte_length()
                        * level.source_component_count_per_participant()
                );
                assert_eq!(
                    level.source_resident_byte_length_per_participant(),
                    level.component_resident_byte_length()
                        * level.source_component_count_per_participant()
                );
                assert_eq!(
                    level.final_wire_byte_length(),
                    level.component_wire_byte_length() * level.final_component_count()
                );
                assert_eq!(
                    level.final_resident_byte_length(),
                    level.component_resident_byte_length() * level.final_component_count()
                );
            }
            assert_eq!(
                evaluator
                    .levels()
                    .iter()
                    .map(|level| (
                        level.catalog_level(),
                        level.component_wire_byte_length(),
                        level.component_resident_byte_length(),
                        level.source_component_count_per_participant(),
                        level.final_component_count(),
                    ))
                    .collect::<Vec<_>>(),
                vec![
                    (14, 12_288_000, 23_592_960, 3, 3),
                    (18, 20_873_216, 40_370_176, 3, 3),
                    (22, 28_049_408, 54_525_952, 3, 2),
                ]
            );
            assert_eq!(
                (
                    evaluator.relinearization_position_count(),
                    evaluator.galois_position_count(),
                    evaluator.source_component_count_per_participant(),
                    evaluator.final_component_count(),
                    evaluator.source_public_polynomial_context_hash_count_per_participant(),
                    evaluator
                        .source_public_polynomial_context_hash_resident_byte_length_per_participant(
                        ),
                ),
                (1, 6, 9, 8, 7, 448)
            );
            assert!(materials.ballot_prover_material_live_set_peak_byte_length() > 0);
            assert_eq!(
                accounting
                    .setup_proof_byte_ceiling()
                    .checked_add(accounting.ballot_proof_byte_ceiling())
                    .and_then(|length| {
                        length.checked_add(accounting.target_release_proof_byte_ceiling())
                    }),
                Some(accounting.complete_action_proof_byte_ceiling())
            );
            assert_eq!(
                accounting
                    .ordered_families()
                    .iter()
                    .find(|family| {
                        family.application_statement_schema_identifier()
                            == ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
                    })
                    .expect("the Galois family is present")
                    .maximum_logical_entry_count_per_proof(),
                6
            );
            assert_eq!(
                {
                    let evaluator_family = accounting
                        .ordered_families()
                        .iter()
                        .find(|family| {
                            family.application_statement_schema_identifier()
                                == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                        })
                        .expect("the evaluator family is present");
                    assert_eq!(evaluator_family.compiler_variant_count(), 20);
                    assert_eq!(evaluator_family.selected_variant_count(), 1);
                    assert_eq!(evaluator_family.complete_action_logical_entry_count(), 7);
                    evaluator_family.maximum_logical_entry_count_per_proof()
                },
                7
            );
            let complete_list_variants = selected_proof_variant_resource_inventory()
                .expect("the selected variant inventory derives")
                .iter()
                .filter(|variant| {
                    variant.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                })
                .collect::<Vec<_>>();
            assert_eq!(complete_list_variants.len(), 20);
            assert_eq!(
                complete_list_variants
                    .iter()
                    .filter(|variant| variant.complete_action_application_multiplicity() != 0)
                    .map(|variant| (
                        variant.top_count(),
                        variant.complete_action_application_multiplicity()
                    ))
                    .collect::<Vec<_>>(),
                vec![(Some(FOUNDATION_PROFILE.option_count), 1)]
            );
            assert!(accounting.complete_action_proof_byte_ceiling() > 0);
            assert!(
                accounting.maximum_one_browser_wasm_resident_byte_length()
                    <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
            );
        }

        #[test]
        fn proof_ceiling_rejects_one_byte_above_the_absolute_bound() {
            let proof_byte_length = MAXIMUM_COMMON_PROOF_BYTE_LENGTH
                .checked_add(1)
                .expect("the absolute proof bound can be incremented");
            assert!(matches!(
                require_selected_proof_byte_length(0x1218, None, None, proof_byte_length),
                Err(SelectedProofAccountingError::ProofByteLengthExceeded {
                    proof_byte_length: observed,
                    maximum_proof_byte_length: MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
                    ..
                }) if observed == proof_byte_length
            ));
        }

        #[test]
        #[ignore = "guarded selected proof resource measurement"]
        fn report_one_mixed_galois_batch_against_two_level_shards() {
            use crate::bgv::proof_suite::relation_plan::{
                GaloisKeyShareRelationPlanInput,
                compile_galois_key_share_relation_topology_comparison,
                galois_key_share_topology_comparison_memory_accounting,
            };

            fn statement_bytes(
                batch_schedule_position: u32,
                entries: &[super::super::super::relation_plan::GaloisKeyShareRelationEntryInput],
            ) -> Vec<u8> {
                let anchor_items = (0..3)
                    .map(|_| CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]))
                    .collect::<Vec<_>>();
                let entry_items = entries
                    .iter()
                    .map(|entry| {
                        CanonicalItem::nested_tuple(&CanonicalTuple::new(
                            0x121d,
                            1,
                            vec![
                                CanonicalItem::unsigned32(entry.schedule_position),
                                CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]),
                            ],
                        ))
                        .expect("comparison entry encodes")
                    })
                    .collect::<Vec<_>>();
                CanonicalTuple::new(
                    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    2,
                    vec![
                        CanonicalItem::hash512([0; Hash512::BYTE_LENGTH]),
                        CanonicalItem::participant_identity([0; Hash512::BYTE_LENGTH]),
                        CanonicalItem::unsigned16(0),
                        CanonicalItem::unsigned32(batch_schedule_position),
                        CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &anchor_items)
                            .expect("comparison anchors encode"),
                        CanonicalItem::homogeneous_list(
                            CanonicalItemType::NestedTuple,
                            &entry_items,
                        )
                        .expect("comparison entries encode"),
                    ],
                )
                .encode()
                .expect("comparison statement encodes")
            }

            #[derive(Clone, Copy, Debug)]
            struct Measurement {
                plan_bytes: u64,
                proof_bytes: u64,
                relation_columns: u64,
                relation_constraints: u64,
                retained_source_bytes: u64,
                adapter_retained_bytes: u64,
                loading_persistent_bytes: u64,
                loading_transient_bytes: u64,
                preparation_workspace_bytes: u64,
                preparation_peak_bytes: u64,
            }

            fn measure(
                input: &GaloisKeyShareRelationPlanInput,
                context: &RelationPlanCheckContext,
            ) -> Measurement {
                let compiled =
                    compile_galois_key_share_relation_topology_comparison(input, context)
                        .expect("comparison relation compiles");
                let variant = compiled
                    .relation_plan
                    .select_variant(Some(input.batch_schedule_position), None)
                    .expect("comparison variant");
                let statement =
                    statement_bytes(input.batch_schedule_position, &input.ordered_entries);
                let transport = selected_proof_transport_sizing(
                    ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                    &statement,
                    variant,
                    context,
                )
                .expect("comparison transport sizing");
                let memory = galois_key_share_topology_comparison_memory_accounting(
                    variant,
                    context,
                    &input.geometry,
                    &compiled.source_layout,
                    statement.len(),
                )
                .expect("comparison memory accounting");
                Measurement {
                    plan_bytes: compiled
                        .relation_plan
                        .canonical_byte_length_and_hash()
                        .expect("comparison plan bytes")
                        .0,
                    proof_bytes: u64::try_from(transport.ceiling.proof_byte_length())
                        .expect("proof length fits u64"),
                    relation_columns: u64::try_from(variant.ordered_columns().len())
                        .expect("column count fits u64"),
                    relation_constraints: u64::try_from(variant.ordered_constraint_count())
                        .expect("constraint count fits u64"),
                    retained_source_bytes: memory.retained_original_source_byte_length(),
                    adapter_retained_bytes: memory.adapter_retained_byte_length(),
                    loading_persistent_bytes: memory.loading_persistent_resident_byte_length(),
                    loading_transient_bytes: memory
                        .additional_loading_source_polynomials_transient_byte_length(),
                    preparation_workspace_bytes: memory.preparation_tree_workspace_byte_length(),
                    preparation_peak_bytes: memory.preparation_peak_resident_byte_length(),
                }
            }

            let full_input = selected_galois_key_share_relation_plan_input()
                .expect("selected Galois relation input");
            let context = selected_relation_plan_check_context(
                ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            )
            .expect("selected Galois context");
            let maximum_level = full_input
                .ordered_entries
                .iter()
                .map(|entry| entry.selected_level)
                .max()
                .expect("selected Galois entries");
            let full = measure(&full_input, &context);
            let shards = [
                maximum_level,
                full_input
                    .ordered_entries
                    .iter()
                    .map(|entry| entry.selected_level)
                    .min()
                    .expect("selected Galois entries"),
            ]
            .into_iter()
            .enumerate()
            .map(|(batch_schedule_position, level)| {
                let ordered_entries = full_input
                    .ordered_entries
                    .iter()
                    .filter(|entry| entry.selected_level == level)
                    .cloned()
                    .collect::<Vec<_>>();
                measure(
                    &GaloisKeyShareRelationPlanInput {
                        batch_schedule_position: u32::try_from(batch_schedule_position)
                            .expect("batch position fits u32"),
                        ordered_entries,
                        geometry: full_input
                            .geometry
                            .selected_catalog_prefix(level)
                            .expect("shard geometry"),
                    },
                    &context,
                )
            })
            .collect::<Vec<_>>();
            eprintln!("one mixed batch: {full:?}");
            eprintln!("two level shards: {shards:?}");
            eprintln!(
                "two level shard totals: plan_bytes={}, proof_bytes={}, relation_columns={}, relation_constraints={}, retained_source_bytes={}, adapter_retained_bytes={}, maximum_loading_persistent_bytes={}, maximum_loading_transient_bytes={}, maximum_preparation_workspace_bytes={}, maximum_preparation_peak_bytes={}",
                shards.iter().map(|value| value.plan_bytes).sum::<u64>(),
                shards.iter().map(|value| value.proof_bytes).sum::<u64>(),
                shards
                    .iter()
                    .map(|value| value.relation_columns)
                    .sum::<u64>(),
                shards
                    .iter()
                    .map(|value| value.relation_constraints)
                    .sum::<u64>(),
                shards
                    .iter()
                    .map(|value| value.retained_source_bytes)
                    .sum::<u64>(),
                shards
                    .iter()
                    .map(|value| value.adapter_retained_bytes)
                    .sum::<u64>(),
                shards
                    .iter()
                    .map(|value| value.loading_persistent_bytes)
                    .max()
                    .unwrap(),
                shards
                    .iter()
                    .map(|value| value.loading_transient_bytes)
                    .max()
                    .unwrap(),
                shards
                    .iter()
                    .map(|value| value.preparation_workspace_bytes)
                    .max()
                    .unwrap(),
                shards
                    .iter()
                    .map(|value| value.preparation_peak_bytes)
                    .max()
                    .unwrap(),
            );
        }
    }
}
