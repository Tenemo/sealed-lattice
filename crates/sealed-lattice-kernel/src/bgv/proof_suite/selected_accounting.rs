//! Canonical proof ceilings and runtime limits for the selected suite.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use crate::{
    bgv::evaluator::program::{EvaluatorProgramKeyPositions, selected_evaluator_program_set},
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
        ProofApplicationSlotCeilings, ProofObjectHeader,
        SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
    },
};

use super::body::minimal_frontier_node_count;
use super::external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH;
use super::prover::{
    CommonProofResidentMemoryPhase, CommonProofResidentMemoryPlan,
    common_proof_external_memory_requirement, common_proof_resident_memory_requirement,
    common_proof_source_provider_is_live_during_phase,
};
use super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor,
};
use super::relation_plan::{
    CollectivePublicKeySourceProviderMemoryAccounting,
    CommittedMaterialSourceProviderMemoryAccounting, GaloisKeyShareSourceProviderMemoryAccounting,
    ProofPrivacyMode, RelationMaskKind,
    aggregate_threshold_share_source_provider_memory_accounting,
    collective_public_key_source_provider_memory_accounting,
    galois_key_share_source_provider_memory_accounting,
    vss_share_linkage_source_provider_memory_accounting,
};
use super::selected_profile::selected_proof_application_slot_ceilings;
use super::{
    CollectivePublicKeyApplicationMemoryAccounting,
    CommonProofGenerationCheckpointCustodyRequirement, CommonProofTranscriptSchedule,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    SelectedApplicationStatementContext, SelectedBallotCiphertextReadbackMemoryAccounting,
    SelectedBallotValidityCarrierBufferAccounting,
    SelectedEvaluatorAggregateSourceProviderMemoryAccounting,
    canonical_selected_application_statement_for_ceiling,
    collective_public_key_application_memory_accounting,
    common_proof_generation_checkpoint_custody_requirement_for_variant,
    common_proof_randomness_purpose_is_assigned,
    evaluator_aggregate_source_provider_memory_accounting,
    selected_ballot_ciphertext_readback_memory_accounting,
    selected_ballot_validity_carrier_buffer_accounting,
    selected_committed_material_relation_plan_input, selected_evaluator_entry_positions,
    selected_galois_key_share_batch_schedule, selected_galois_key_share_relation_plan_input,
    selected_proof_profile_set,
};
use super::{
    CommonProofByteLengthCeiling, CommonProofRuntimeLimits, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, ProofBodyLayout, ProofLeafVisibility,
    ProofTreeCatalogInput, ProofTreeRole, RelationProofTreeInput, StatementOwnedProofTreeInput,
    build_complete_proof_tree_catalog, canonical_common_proof_byte_length_ceiling,
    proof_query_tree_byte_length, selected_relation_plan_check_context,
};

struct SelectedProofTransportSizing {
    ceiling: CommonProofByteLengthCeiling,
    layout: ProofBodyLayout,
    maximum_prefetched_query_byte_length: u64,
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
    require_selected_proof_byte_length(
        application_statement_schema_identifier,
        variant.schedule_position(),
        variant.top_count(),
        ceiling.proof_byte_length(),
    )?;
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
        layout,
        maximum_prefetched_query_byte_length,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedProofVariantResourceBounds {
    maximum_combined_wasm_resident_byte_length: u64,
    external_memory_peak_stored_byte_length: u64,
    external_memory_total_written_byte_length: u64,
    external_memory_total_read_byte_length: u64,
    external_memory_transaction_count: u64,
    checkpoint_boundary_peak_resident_byte_length: u64,
}

/// One compiler-derived selected-suite proof variant. This is process-local
/// accounting, not a serialized proof field or an acceptance claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofVariantResourceAccounting {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    proof_byte_length: usize,
    maximum_combined_wasm_resident_byte_length: u64,
    external_memory_peak_stored_byte_length: u64,
    external_memory_total_written_byte_length: u64,
    external_memory_total_read_byte_length: u64,
    external_memory_transaction_count: u64,
    checkpoint_boundary_peak_resident_byte_length: u64,
}

impl SelectedProofVariantResourceAccounting {
    pub(crate) const fn application_statement_schema_identifier(self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn schedule_position(self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn proof_byte_length(self) -> usize {
        self.proof_byte_length
    }

    pub(crate) const fn maximum_combined_wasm_resident_byte_length(self) -> u64 {
        self.maximum_combined_wasm_resident_byte_length
    }

    pub(crate) const fn external_memory_peak_stored_byte_length(self) -> u64 {
        self.external_memory_peak_stored_byte_length
    }

    pub(crate) const fn external_memory_total_written_byte_length(self) -> u64 {
        self.external_memory_total_written_byte_length
    }

    pub(crate) const fn external_memory_total_read_byte_length(self) -> u64 {
        self.external_memory_total_read_byte_length
    }

    pub(crate) const fn external_memory_transaction_count(self) -> u64 {
        self.external_memory_transaction_count
    }

    pub(crate) const fn checkpoint_boundary_peak_resident_byte_length(self) -> u64 {
        self.checkpoint_boundary_peak_resident_byte_length
    }
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
            match application_statement_schema_identifier {
                ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                    let relation_input = selected_committed_material_relation_plan_input()
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
                    let accounting = if application_statement_schema_identifier
                        == ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
                    {
                        vss_share_linkage_source_provider_memory_accounting(
                            &relation_input,
                            &relation_context,
                            relation_plan.compiled_plan(),
                        )
                    } else {
                        aggregate_threshold_share_source_provider_memory_accounting(
                            &relation_input,
                            &relation_context,
                            relation_plan.compiled_plan(),
                        )
                    }
                    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
                    if accounting.preparation_peak_resident_byte_length()
                        > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                        || accounting.construction_peak_resident_byte_length()
                            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                    {
                        return Err(SelectedProofAccountingError::ResourcePlanning);
                    }
                    Some(accounting)
                }
                _ => None,
            };

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
            compiler_ceilings.push(SelectedProofVariantResourceAccounting {
                application_statement_schema_identifier,
                schedule_position: variant.schedule_position(),
                top_count: variant.top_count(),
                proof_byte_length: transport_sizing.ceiling.proof_byte_length(),
                maximum_combined_wasm_resident_byte_length: resource_bounds
                    .maximum_combined_wasm_resident_byte_length,
                external_memory_peak_stored_byte_length: resource_bounds
                    .external_memory_peak_stored_byte_length,
                external_memory_total_written_byte_length: resource_bounds
                    .external_memory_total_written_byte_length,
                external_memory_total_read_byte_length: resource_bounds
                    .external_memory_total_read_byte_length,
                external_memory_transaction_count: resource_bounds
                    .external_memory_transaction_count,
                checkpoint_boundary_peak_resident_byte_length: resource_bounds
                    .checkpoint_boundary_peak_resident_byte_length,
            });
        }
    }
    require_selected_variant_selector_inventory(&compiler_ceilings, &key_positions)?;
    Ok(compiler_ceilings.into_boxed_slice())
}

fn require_selected_variant_selector_inventory(
    compiler_ceilings: &[SelectedProofVariantResourceAccounting],
    key_positions: &EvaluatorProgramKeyPositions,
) -> Result<(), SelectedProofAccountingError> {
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
    Ok(())
}

#[derive(Clone, Copy)]
enum SourceProviderMemoryAccounting {
    BallotValidity(SelectedBallotValidityCarrierBufferAccounting),
    CollectivePublicKey(CollectivePublicKeySourceProviderMemoryAccounting),
    EvaluatorAggregate(SelectedEvaluatorAggregateSourceProviderMemoryAccounting),
    GaloisKeyShare(GaloisKeyShareSourceProviderMemoryAccounting),
    CommittedMaterial(CommittedMaterialSourceProviderMemoryAccounting),
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
            Self::GaloisKeyShare(accounting) => {
                accounting.loading_persistent_resident_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
                accounting.loading_persistent_resident_byte_length()
            }
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
            Self::GaloisKeyShare(accounting) => {
                accounting.post_source_polynomial_finish_persistent_resident_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
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
            Self::GaloisKeyShare(accounting) => {
                accounting.additional_loading_source_polynomials_transient_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
                accounting.additional_loading_source_polynomials_transient_byte_length()
            }
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
            Self::GaloisKeyShare(accounting) => {
                accounting.maximum_returned_source_polynomial_byte_length()
            }
            Self::CommittedMaterial(accounting) => {
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
            Self::BallotValidity(accounting) => accounting.maximum_boundary_overlap_byte_length(),
            Self::CollectivePublicKey(accounting) => {
                accounting.maximum_boundary_overlap_byte_length()
            }
        }
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
    let source_provider_memory_accounting = match application_statement_schema_identifier {
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SourceProviderMemoryAccounting::BallotValidity(
                selected_ballot_validity_carrier_buffer_accounting()
                    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
            ))
        }
        ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SourceProviderMemoryAccounting::CollectivePublicKey(
                collective_public_key_source_provider_memory_accounting(variant)
                    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
            ))
        }
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SourceProviderMemoryAccounting::EvaluatorAggregate(
                evaluator_aggregate_source_provider_memory_accounting(variant, relation_context)
                    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
            ))
        }
        ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER
        | ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            Some(SourceProviderMemoryAccounting::CommittedMaterial(
                committed_material_source_provider_memory_accounting
                    .ok_or(SelectedProofAccountingError::ResourcePlanning)?,
            ))
        }
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
            let relation_input = selected_galois_key_share_relation_plan_input()
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
            Some(SourceProviderMemoryAccounting::GaloisKeyShare(
                galois_key_share_source_provider_memory_accounting(
                    &relation_input,
                    variant,
                    relation_context,
                    canonical_application_statement_bytes.len(),
                )
                .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
            ))
        }
        _ => None,
    };
    let application_runtime_memory_accounting = match (
        application_statement_schema_identifier,
        source_provider_memory_accounting,
    ) {
        (
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            Some(SourceProviderMemoryAccounting::BallotValidity(carrier_accounting)),
        ) => Some(ApplicationRuntimeMemoryAccounting::BallotValidity(
            selected_ballot_ciphertext_readback_memory_accounting(
                u64::try_from(canonical_application_statement_bytes.len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                carrier_accounting,
            )?,
        )),
        (
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            Some(SourceProviderMemoryAccounting::CollectivePublicKey(provider_accounting)),
        ) => Some(ApplicationRuntimeMemoryAccounting::CollectivePublicKey(
            collective_public_key_application_memory_accounting(
                u64::try_from(canonical_application_statement_bytes.len())
                    .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
                provider_accounting,
            )
            .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?,
        )),
        (ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER, _)
        | (
            ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            _,
        ) => return Err(SelectedProofAccountingError::ResourcePlanning),
        _ => None,
    };
    if let (
        Some(SourceProviderMemoryAccounting::CollectivePublicKey(provider_accounting)),
        Some(ApplicationRuntimeMemoryAccounting::CollectivePublicKey(application_accounting)),
    ) = (
        source_provider_memory_accounting,
        application_runtime_memory_accounting,
    ) {
        let preparation_peak_resident_byte_length = provider_accounting
            .preparation_peak_resident_byte_length()
            .checked_add(application_accounting.loading_persistent_resident_byte_length())
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        if preparation_peak_resident_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
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
        application_statement_schema_identifier,
        u64::try_from(transport_sizing.ceiling.canonical_header_byte_length())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
        runtime_limits.prefetched_query_byte_length(),
        u64::from(runtime_limits.external_memory_chunk_byte_length()),
        u64::try_from(MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH)
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?,
    )
    .map_err(|_| SelectedProofAccountingError::ResourcePlanning)?;
    let maximum_combined_wasm_resident_byte_length = require_selected_resident_memory_bounds(
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
    if u64::try_from(runtime_limits.proof_byte_length())
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?
        > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || external_memory_requirement.peak_stored_byte_length()
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        || checkpoint_custody_requirement.restore_workspace_byte_ceiling()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || copied_buffer_requirements
            .into_iter()
            .any(|byte_length| byte_length > maximum_copied_buffer_byte_length)
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }
    Ok(SelectedProofVariantResourceBounds {
        maximum_combined_wasm_resident_byte_length,
        external_memory_peak_stored_byte_length: external_memory_requirement
            .peak_stored_byte_length(),
        external_memory_total_written_byte_length: external_memory_requirement
            .total_written_byte_length(),
        external_memory_total_read_byte_length: external_memory_requirement
            .total_read_byte_length(),
        external_memory_transaction_count: external_memory_requirement.transaction_count(),
        checkpoint_boundary_peak_resident_byte_length: checkpoint_custody_requirement
            .boundary_peak_additional_resident_byte_ceiling(),
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
            RelationMaskKind::Telescoping => quotient_ordinals.insert(coordinate.mask_ordinal()),
            RelationMaskKind::OpeningBatch => opening_ordinals.insert(coordinate.mask_ordinal()),
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
    source_provider_memory_accounting: Option<SourceProviderMemoryAccounting>,
    application_runtime_memory_accounting: Option<ApplicationRuntimeMemoryAccounting>,
) -> Result<u64, SelectedProofAccountingError> {
    let retained_cursor_state_byte_length = checkpoint_custody_requirement
        .cursor_manifest_requirement()
        .retained_cursor_state_byte_ceiling();
    let boundary_checkpoint_custody_byte_length =
        checkpoint_custody_requirement.boundary_peak_additional_resident_byte_ceiling();
    if boundary_checkpoint_custody_byte_length < retained_cursor_state_byte_length
        || !checkpoint_custody_requirement.fits_absolute_bounds()
        || source_provider_memory_accounting.is_some_and(|accounting| {
            resident_memory_requirement
                .phases()
                .iter()
                .find(|phase| {
                    phase.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
                })
                .is_none_or(|phase| {
                    phase.relation_polynomial_working_set_byte_length()
                        < accounting.maximum_returned_source_polynomial_byte_length()
                })
        })
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    let mut observed_checkpoint_phase_mask = 0_u8;
    let mut maximum_combined_wasm_resident_byte_length = 0_u64;
    for phase_plan in resident_memory_requirement.phases() {
        let (checkpoint_phase_bit, checkpoint_boundary_count) = match phase_plan.phase() {
            CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns => (1_u8, 1_u16),
            CommonProofResidentMemoryPhase::ConstructingQuotient => (2_u8, 1_u16),
            CommonProofResidentMemoryPhase::DerivingOpenings => (4_u8, 1_u16),
            CommonProofResidentMemoryPhase::ConstructingInitialFri => (8_u8, 1_u16),
            CommonProofResidentMemoryPhase::FoldingFri => (16_u8, fri_fold_count.saturating_sub(1)),
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
        let source_provider_persistent_resident_byte_length =
            if common_proof_source_provider_is_live_during_phase(phase_plan.phase()) {
                source_provider_memory_accounting.map_or(0, |accounting| {
                    if phase_plan.phase()
                        == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
                    {
                        accounting.loading_persistent_resident_byte_length()
                    } else {
                        accounting.post_source_finish_persistent_resident_byte_length()
                    }
                })
            } else {
                0
            };
        let source_provider_loading_transient_byte_length =
            if phase_plan.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
                source_provider_memory_accounting.map_or(
                    0,
                    SourceProviderMemoryAccounting::additional_loading_transient_byte_length,
                )
            } else {
                0
            };
        let application_runtime_persistent_resident_byte_length =
            application_runtime_memory_accounting.map_or(0, |accounting| {
                if phase_plan.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials {
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
            .and_then(|length| length.checked_add(source_provider_loading_transient_byte_length))
            .and_then(|length| {
                length.checked_add(application_runtime_persistent_resident_byte_length)
            })
            .and_then(|length| length.checked_add(application_runtime_boundary_overlap_byte_length))
            .and_then(|length| length.checked_add(checkpoint_custody_byte_length))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        if combined_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
            return Err(SelectedProofAccountingError::ResourcePlanning);
        }
        maximum_combined_wasm_resident_byte_length =
            maximum_combined_wasm_resident_byte_length.max(combined_byte_length);
    }
    if observed_checkpoint_phase_mask != 31 {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }
    Ok(maximum_combined_wasm_resident_byte_length)
}

/// One physical proof family in the complete selected action. Variant rows are
/// compiler alternatives; the physical proof count comes only from the
/// canonical application-slot topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedPhysicalProofFamilyResourceAccounting {
    application_statement_schema_identifier: u16,
    physical_proof_count: u32,
    compiler_variant_count: u32,
    maximum_logical_entry_count_per_proof: u32,
    maximum_proof_byte_length: u64,
    complete_action_proof_byte_ceiling: u64,
    maximum_wasm_resident_byte_length: u64,
    maximum_external_memory_peak_stored_byte_length: u64,
    complete_action_external_memory_written_byte_length: u64,
    complete_action_external_memory_read_byte_length: u64,
    complete_action_external_memory_transaction_count: u64,
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

    pub(crate) const fn maximum_logical_entry_count_per_proof(self) -> u32 {
        self.maximum_logical_entry_count_per_proof
    }

    pub(crate) const fn maximum_proof_byte_length(self) -> u64 {
        self.maximum_proof_byte_length
    }

    pub(crate) const fn complete_action_proof_byte_ceiling(self) -> u64 {
        self.complete_action_proof_byte_ceiling
    }

    pub(crate) const fn maximum_wasm_resident_byte_length(self) -> u64 {
        self.maximum_wasm_resident_byte_length
    }

    pub(crate) const fn maximum_external_memory_peak_stored_byte_length(self) -> u64 {
        self.maximum_external_memory_peak_stored_byte_length
    }

    pub(crate) const fn complete_action_external_memory_written_byte_length(self) -> u64 {
        self.complete_action_external_memory_written_byte_length
    }

    pub(crate) const fn complete_action_external_memory_read_byte_length(self) -> u64 {
        self.complete_action_external_memory_read_byte_length
    }

    pub(crate) const fn complete_action_external_memory_transaction_count(self) -> u64 {
        self.complete_action_external_memory_transaction_count
    }
}

/// Production-derived worst-case proof resources for all physical proof slots
/// in one complete selected action. It deliberately separates one-browser
/// peak memory from additive ceremony storage and traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedCompleteProofResourceAccounting {
    ordered_families: Box<[SelectedPhysicalProofFamilyResourceAccounting]>,
    physical_proof_count: u32,
    complete_action_proof_byte_ceiling: u64,
    maximum_one_browser_wasm_resident_byte_length: u64,
    maximum_one_proof_external_memory_peak_stored_byte_length: u64,
    complete_action_external_memory_written_byte_length: u64,
    complete_action_external_memory_read_byte_length: u64,
    complete_action_external_memory_transaction_count: u64,
}

impl SelectedCompleteProofResourceAccounting {
    pub(crate) fn ordered_families(&self) -> &[SelectedPhysicalProofFamilyResourceAccounting] {
        &self.ordered_families
    }

    pub(crate) const fn physical_proof_count(&self) -> u32 {
        self.physical_proof_count
    }

    pub(crate) const fn complete_action_proof_byte_ceiling(&self) -> u64 {
        self.complete_action_proof_byte_ceiling
    }

    pub(crate) const fn maximum_one_browser_wasm_resident_byte_length(&self) -> u64 {
        self.maximum_one_browser_wasm_resident_byte_length
    }

    pub(crate) const fn maximum_one_proof_external_memory_peak_stored_byte_length(&self) -> u64 {
        self.maximum_one_proof_external_memory_peak_stored_byte_length
    }

    pub(crate) const fn complete_action_external_memory_written_byte_length(&self) -> u64 {
        self.complete_action_external_memory_written_byte_length
    }

    pub(crate) const fn complete_action_external_memory_read_byte_length(&self) -> u64 {
        self.complete_action_external_memory_read_byte_length
    }

    pub(crate) const fn complete_action_external_memory_transaction_count(&self) -> u64 {
        self.complete_action_external_memory_transaction_count
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
    let slot_ceilings = selected_proof_application_slot_ceilings()
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let galois_logical_entry_count = u32::try_from(
        selected_galois_key_share_relation_plan_input()
            .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
            .ordered_entries
            .len(),
    )
    .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    if galois_logical_entry_count == 0 {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let mut ordered_families = Vec::new();
    ordered_families
        .try_reserve_exact(slot_ceilings.ordered_family_ceilings().len())
        .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
    let mut observed_variant_schema_identifiers = BTreeSet::new();
    let mut physical_proof_count = 0_u32;
    let mut complete_action_proof_byte_ceiling = 0_u64;
    let mut maximum_one_browser_wasm_resident_byte_length = 0_u64;
    let mut maximum_one_proof_external_memory_peak_stored_byte_length = 0_u64;
    let mut complete_action_external_memory_written_byte_length = 0_u64;
    let mut complete_action_external_memory_read_byte_length = 0_u64;
    let mut complete_action_external_memory_transaction_count = 0_u64;

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
        let physical_count = family_ceiling.application_slot_ceiling;
        let compiler_variant_count = u32::try_from(family_variants.len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let maximum_proof_byte_length = family_variants
            .iter()
            .map(|variant| u64::try_from(variant.proof_byte_length()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?
            .into_iter()
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let maximum_wasm_resident_byte_length = family_variants
            .iter()
            .map(|variant| variant.maximum_combined_wasm_resident_byte_length())
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let maximum_external_memory_peak_stored_byte_length = family_variants
            .iter()
            .map(|variant| variant.external_memory_peak_stored_byte_length())
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let maximum_external_memory_written_byte_length = family_variants
            .iter()
            .map(|variant| variant.external_memory_total_written_byte_length())
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let maximum_external_memory_read_byte_length = family_variants
            .iter()
            .map(|variant| variant.external_memory_total_read_byte_length())
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let maximum_external_memory_transaction_count = family_variants
            .iter()
            .map(|variant| variant.external_memory_transaction_count())
            .max()
            .ok_or(SelectedProofAccountingError::InvalidProfile)?;
        let maximum_logical_entry_count_per_proof = match schema_identifier {
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER => {
                galois_logical_entry_count
            }
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER => {
                family_variants
                    .iter()
                    .map(|variant| {
                        variant
                            .top_count()
                            .ok_or(SelectedProofAccountingError::InvalidProfile)
                            .and_then(|top_count| {
                                selected_evaluator_entry_positions(top_count)
                                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)
                            })
                            .and_then(|positions| {
                                u32::try_from(positions.len())
                                    .map_err(|_| SelectedProofAccountingError::CountOverflow)
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .max()
                    .filter(|count| *count != 0)
                    .ok_or(SelectedProofAccountingError::InvalidProfile)?
            }
            _ => 1,
        };
        let physical_count_u64 = u64::from(physical_count);
        let family_proof_byte_ceiling = maximum_proof_byte_length
            .checked_mul(physical_count_u64)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let family_external_written_byte_length = maximum_external_memory_written_byte_length
            .checked_mul(physical_count_u64)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let family_external_read_byte_length = maximum_external_memory_read_byte_length
            .checked_mul(physical_count_u64)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        let family_external_transaction_count = maximum_external_memory_transaction_count
            .checked_mul(physical_count_u64)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;

        physical_proof_count = physical_proof_count
            .checked_add(physical_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        complete_action_proof_byte_ceiling = complete_action_proof_byte_ceiling
            .checked_add(family_proof_byte_ceiling)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        maximum_one_browser_wasm_resident_byte_length =
            maximum_one_browser_wasm_resident_byte_length.max(maximum_wasm_resident_byte_length);
        maximum_one_proof_external_memory_peak_stored_byte_length =
            maximum_one_proof_external_memory_peak_stored_byte_length
                .max(maximum_external_memory_peak_stored_byte_length);
        complete_action_external_memory_written_byte_length =
            complete_action_external_memory_written_byte_length
                .checked_add(family_external_written_byte_length)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        complete_action_external_memory_read_byte_length =
            complete_action_external_memory_read_byte_length
                .checked_add(family_external_read_byte_length)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        complete_action_external_memory_transaction_count =
            complete_action_external_memory_transaction_count
                .checked_add(family_external_transaction_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
        ordered_families.push(SelectedPhysicalProofFamilyResourceAccounting {
            application_statement_schema_identifier: schema_identifier,
            physical_proof_count: physical_count,
            compiler_variant_count,
            maximum_logical_entry_count_per_proof,
            maximum_proof_byte_length,
            complete_action_proof_byte_ceiling: family_proof_byte_ceiling,
            maximum_wasm_resident_byte_length,
            maximum_external_memory_peak_stored_byte_length,
            complete_action_external_memory_written_byte_length:
                family_external_written_byte_length,
            complete_action_external_memory_read_byte_length: family_external_read_byte_length,
            complete_action_external_memory_transaction_count: family_external_transaction_count,
        });
    }

    let expected_variant_schema_identifiers = variants
        .iter()
        .map(|variant| variant.application_statement_schema_identifier())
        .collect::<BTreeSet<_>>();
    if observed_variant_schema_identifiers != expected_variant_schema_identifiers
        || physical_proof_count != slot_ceilings.total_application_slot_ceiling()
        || maximum_one_browser_wasm_resident_byte_length
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(SelectedProofAccountingError::ResourcePlanning);
    }

    Ok(SelectedCompleteProofResourceAccounting {
        ordered_families: ordered_families.into_boxed_slice(),
        physical_proof_count,
        complete_action_proof_byte_ceiling,
        maximum_one_browser_wasm_resident_byte_length,
        maximum_one_proof_external_memory_peak_stored_byte_length,
        complete_action_external_memory_written_byte_length,
        complete_action_external_memory_read_byte_length,
        complete_action_external_memory_transaction_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_inventory_covers_every_selected_relation_plan_variant() {
        let inventory = selected_proof_variant_resource_inventory()
            .expect("the selected resource inventory derives");
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
                    compiler_ceiling.proof_byte_length()
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
    fn complete_action_accounting_derives_all_physical_proof_slots() {
        let accounting = selected_complete_proof_resource_accounting()
            .expect("the complete selected accounting derives");
        let expected_physical_counts = BTreeMap::from([
            (0x2110, 10),
            (0x2111, 10),
            (0x1211, 10),
            (0x1212, 10),
            (0x1213, 1),
            (0x1214, 10),
            (0x1215, 1),
            (0x1216, 10),
            (0x1217, 10),
            (0x1218, 1),
            (0x1302, 20),
            (0x1621, 10),
        ]);
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
        assert_eq!(accounting.physical_proof_count(), 103);
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
            3
        );
        assert_eq!(
            accounting
                .ordered_families()
                .iter()
                .find(|family| {
                    family.application_statement_schema_identifier()
                        == ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER
                })
                .expect("the evaluator family is present")
                .maximum_logical_entry_count_per_proof(),
            4
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
}
