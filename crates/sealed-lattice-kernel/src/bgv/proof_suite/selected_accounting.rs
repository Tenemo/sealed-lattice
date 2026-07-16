//! Exact proof-object accounting for the fixed suite.

use std::collections::BTreeSet;

use crate::{
    bgv::{
        evaluator::{
            candidate_evidence::EvaluatorCandidateInput, program::selected_evaluator_program_set,
        },
        key_switch_topology::KeySwitchDecompositionTopology,
    },
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ProofApplicationSlotCeilings,
        ProofObjectHeader,
    },
};

use super::body::minimal_frontier_node_count;
use super::relation_plan::{
    BoundTreeConstructionKind, RelationColumnOrigin, RelationPlanVariant, RelationTreeDescriptor,
};
use super::selected_profile::SELECTED_EVALUATION_DOMAIN_SIZE;
use super::{
    CommonProofPrivacyMode, CommonProofTranscriptSchedule, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    ProofBodyLayout, ProofLeafVisibility, ProofTreeCatalogInput, ProofTreeRole,
    RelationProofTreeInput, SelectedApplicationStatementContext, StatementOwnedProofTreeInput,
    build_complete_proof_tree_catalog, canonical_common_proof_byte_length_ceiling,
    canonical_selected_application_statement_for_ceiling, proof_query_tree_byte_length,
    selected_evaluator_entry_positions, selected_proof_profile_set,
    selected_relation_plan_check_context,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedProofAccountingError {
    CanonicalEncoding,
    InvalidProfile,
    InvalidTreeGeometry,
    CountOverflow,
    AllocationLimitExceeded,
    ProofByteLengthExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofVariantByteCeiling {
    application_statement_schema_identifier: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    proof_byte_length: u64,
}

impl SelectedProofVariantByteCeiling {
    pub(crate) const fn application_statement_schema_identifier(self) -> u16 {
        self.application_statement_schema_identifier
    }

    pub(crate) const fn schedule_position(self) -> Option<u32> {
        self.schedule_position
    }

    pub(crate) const fn top_count(self) -> Option<u16> {
        self.top_count
    }

    pub(crate) const fn proof_byte_length(self) -> u64 {
        self.proof_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectedProofByteAccounting {
    variant_ceilings: Vec<SelectedProofVariantByteCeiling>,
    action_proof_object_counts: Vec<u32>,
    action_proof_byte_lengths: Vec<u64>,
}

impl SelectedProofByteAccounting {
    pub(crate) fn variant_ceilings(&self) -> &[SelectedProofVariantByteCeiling] {
        &self.variant_ceilings
    }

    pub(crate) fn action_proof_object_counts(&self) -> &[u32] {
        &self.action_proof_object_counts
    }

    pub(crate) fn action_proof_byte_lengths(&self) -> &[u64] {
        &self.action_proof_byte_lengths
    }

    pub(crate) fn maximum_proof_object_count(&self) -> u32 {
        self.action_proof_object_counts
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn maximum_proof_byte_length(&self) -> u64 {
        self.action_proof_byte_lengths
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn maximum_variant_proof_byte_length(&self) -> u64 {
        self.variant_ceilings
            .iter()
            .map(|ceiling| ceiling.proof_byte_length())
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn ballot_proof_byte_length(&self) -> Option<u64> {
        self.variant_ceilings
            .iter()
            .find(|ceiling| ceiling.application_statement_schema_identifier == 0x1302)
            .map(|ceiling| ceiling.proof_byte_length)
    }
}

pub(crate) fn selected_proof_byte_accounting(
    maximum_ballot_attempts_per_participant: u16,
    maximum_candidate_packages_per_action: u32,
) -> Result<SelectedProofByteAccounting, SelectedProofAccountingError> {
    if maximum_ballot_attempts_per_participant == 0
        || maximum_candidate_packages_per_action < u32::from(FOUNDATION_PROFILE.participant_count)
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let evaluator_aggregate = selected_evaluator_aggregate_structural_accounting()?;
    if evaluator_aggregate.proof_byte_length == 0 {
        return Err(SelectedProofAccountingError::ProofByteLengthExceeded);
    }
    let proof_profile = selected_proof_profile_set(maximum_ballot_attempts_per_participant)
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let relation_context = selected_relation_plan_check_context();
    let key_positions = selected_evaluator_program_set()
        .and_then(|program| program.key_positions())
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    if key_positions.streams().len() != usize::from(FOUNDATION_PROFILE.option_count) {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }

    let mut variant_ceilings = Vec::new();
    for relation_plan in proof_profile.relation_plans() {
        for variant in relation_plan.compiled_plan().variants() {
            let application_statement_schema_identifier =
                relation_plan.application_statement_schema_identifier();
            let statement_bytes = canonical_selected_application_statement_for_ceiling(
                application_statement_schema_identifier,
                SelectedApplicationStatementContext::new(
                    FOUNDATION_PROFILE.protocol_version,
                    [0; Hash512::BYTE_LENGTH],
                    variant.schedule_position(),
                    variant.top_count(),
                ),
            )
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
            let proof_header = ProofObjectHeader::from_canonical_application_statement(
                statement_bytes,
                &CanonicalDecodeLimits::default(),
            )
            .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
            let proof_header_bytes = proof_header
                .encode()
                .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
            let transcript_schedule = variant
                .common_proof_transcript_schedule(&relation_context)
                .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
            let relation_trees = selected_relation_tree_inputs(variant)?;
            let catalog = build_complete_proof_tree_catalog(
                ProofTreeCatalogInput {
                    suite_identifier: [0; Hash512::BYTE_LENGTH],
                    canonical_proof_object_header_bytes: proof_header_bytes.clone(),
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
            let ceiling =
                canonical_common_proof_byte_length_ceiling(proof_header_bytes.len(), &layout)
                    .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
            require_selected_query_ceiling_geometry(&layout, &ceiling)?;
            let proof_byte_length = u64::try_from(ceiling.proof_byte_length())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
            if proof_byte_length == 0 {
                return Err(SelectedProofAccountingError::ProofByteLengthExceeded);
            }
            variant_ceilings.push(SelectedProofVariantByteCeiling {
                application_statement_schema_identifier,
                schedule_position: variant.schedule_position(),
                top_count: variant.top_count(),
                proof_byte_length,
            });
        }
    }

    let mut action_proof_object_counts = Vec::new();
    let mut action_proof_byte_lengths = Vec::new();
    for stream_positions in key_positions.streams() {
        let relinearization_count =
            u32::try_from(stream_positions.relinearization_catalog_levels().len())
                .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let galois_count = u32::try_from(stream_positions.galois_catalog_positions().len())
            .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let participant_count = u32::from(FOUNDATION_PROFILE.participant_count);
        let proof_object_count = checked_u32_sum(&[
            participant_count
                .checked_mul(4)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            relinearization_count
                .checked_add(galois_count)
                .and_then(|count| count.checked_add(1))
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            participant_count
                .checked_mul(2)
                .and_then(|count| count.checked_add(1))
                .and_then(|count| count.checked_mul(relinearization_count))
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            participant_count
                .checked_mul(galois_count)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
            maximum_candidate_packages_per_action,
            participant_count,
        ])?;
        action_proof_object_counts.push(proof_object_count);

        let top_count = stream_positions.top_count();
        let mut action_byte_length = 0_u64;
        for family in [0x2110, 0x2111, 0x1211, 0x1212] {
            action_byte_length = checked_add_scaled_ceiling(
                action_byte_length,
                find_variant_ceiling(&variant_ceilings, family, None, None)?,
                u64::from(FOUNDATION_PROFILE.participant_count),
            )?;
        }
        action_byte_length = checked_add_scaled_ceiling(
            action_byte_length,
            find_variant_ceiling(&variant_ceilings, 0x1213, None, None)?,
            1,
        )?;
        let evaluator_entry_count = relinearization_count
            .checked_add(galois_count)
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
        for entry_ordinal in 0..evaluator_entry_count {
            action_byte_length = checked_add_scaled_ceiling(
                action_byte_length,
                find_variant_ceiling(
                    &variant_ceilings,
                    0x1218,
                    Some(entry_ordinal),
                    Some(top_count),
                )?,
                1,
            )?;
        }
        for schedule_position in stream_positions
            .relinearization_catalog_levels()
            .iter()
            .map(|level| {
                key_positions
                    .relinearization_catalog_levels()
                    .binary_search(level)
                    .map_err(|_| SelectedProofAccountingError::InvalidProfile)
                    .and_then(|position| {
                        u32::try_from(position)
                            .map_err(|_| SelectedProofAccountingError::CountOverflow)
                    })
            })
        {
            let schedule_position = schedule_position?;
            for (family, multiplicity) in [
                (0x1214, u64::from(FOUNDATION_PROFILE.participant_count)),
                (0x1215, 1),
                (0x1216, u64::from(FOUNDATION_PROFILE.participant_count)),
            ] {
                action_byte_length = checked_add_scaled_ceiling(
                    action_byte_length,
                    find_variant_ceiling(&variant_ceilings, family, Some(schedule_position), None)?,
                    multiplicity,
                )?;
            }
        }
        for schedule_position in
            stream_positions
                .galois_catalog_positions()
                .iter()
                .map(|position| {
                    key_positions
                        .galois_catalog_positions()
                        .binary_search(position)
                        .map_err(|_| SelectedProofAccountingError::InvalidProfile)
                        .and_then(|position| {
                            u32::try_from(position)
                                .map_err(|_| SelectedProofAccountingError::CountOverflow)
                        })
                })
        {
            action_byte_length = checked_add_scaled_ceiling(
                action_byte_length,
                find_variant_ceiling(&variant_ceilings, 0x1217, Some(schedule_position?), None)?,
                u64::from(FOUNDATION_PROFILE.participant_count),
            )?;
        }
        action_byte_length = checked_add_scaled_ceiling(
            action_byte_length,
            find_variant_ceiling(&variant_ceilings, 0x1302, None, None)?,
            u64::from(maximum_candidate_packages_per_action),
        )?;
        action_byte_length = checked_add_scaled_ceiling(
            action_byte_length,
            find_variant_ceiling(&variant_ceilings, 0x1621, None, None)?,
            u64::from(FOUNDATION_PROFILE.participant_count),
        )?;
        action_proof_byte_lengths.push(action_byte_length);
    }

    Ok(SelectedProofByteAccounting {
        variant_ceilings,
        action_proof_object_counts,
        action_proof_byte_lengths,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedEvaluatorAggregateStructuralAccounting {
    bound_tree_count: u32,
    bound_tree_row_width: u32,
    total_bound_row_width: u32,
    opening_claim_count: u32,
    proof_byte_length: usize,
}

/// Derives the exact selected `0x1218` proof ceiling directly from its fixed
/// aggregate topology and the canonical proof codec. This deliberately avoids
/// compiling the much larger secret-bearing relation catalog: the public
/// aggregate alone is already a decisive, independently checkable cap gate.
fn selected_evaluator_aggregate_structural_accounting()
-> Result<SelectedEvaluatorAggregateStructuralAccounting, SelectedProofAccountingError> {
    let evaluator_candidate = EvaluatorCandidateInput::implemented()
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    let selected_level = evaluator_candidate
        .relinearization_levels
        .first()
        .copied()
        .filter(|_| evaluator_candidate.relinearization_levels.len() == 1)
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    let decomposition_topology = KeySwitchDecompositionTopology::for_level(selected_level)
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;
    if selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
        .map_err(|_| SelectedProofAccountingError::InvalidProfile)?
        .is_empty()
    {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    let entry_count = 1_u32;
    let roots_per_entry = u32::from(FOUNDATION_PROFILE.participant_count)
        .checked_add(1)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let bound_tree_count = entry_count
        .checked_mul(roots_per_entry)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let bound_tree_row_width = u32::try_from(decomposition_topology.data_block_count())
        .ok()
        .and_then(|block_count| {
            u32::try_from(decomposition_topology.extended_limb_count())
                .ok()
                .and_then(|limb_count| block_count.checked_mul(limb_count))
        })
        // Each phase-pair tree row carries both halves of every polynomial.
        .and_then(|row_width| row_width.checked_mul(2))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let total_bound_row_width = bound_tree_count
        .checked_mul(bound_tree_row_width)
        .ok_or(SelectedProofAccountingError::CountOverflow)?;

    let relation_context = selected_relation_plan_check_context();
    let quotient_component_count = u16::try_from(relation_context.quotient_component_count)
        .map_err(|_| SelectedProofAccountingError::CountOverflow)?;
    let opening_claim_count = total_bound_row_width
        .checked_add(u32::from(quotient_component_count))
        .ok_or(SelectedProofAccountingError::CountOverflow)?;
    let transcript_schedule = CommonProofTranscriptSchedule::new(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        1,
        quotient_component_count,
        relation_context.deep_point_count,
        opening_claim_count,
        relation_context.fri_fold_count,
        relation_context.final_polynomial_degree_bound_exclusive,
        relation_context.unique_query_count,
        SELECTED_EVALUATION_DOMAIN_SIZE / 2,
        relation_context.maximum_fiat_shamir_candidate_draws_per_output,
        CommonProofPrivacyMode::PublicOnly,
    )
    .map_err(|_| SelectedProofAccountingError::InvalidProfile)?;

    let statement_bytes = canonical_selected_application_statement_for_ceiling(
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        SelectedApplicationStatementContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0; Hash512::BYTE_LENGTH],
            Some(0),
            Some(FOUNDATION_PROFILE.option_count),
        ),
    )
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let proof_header_bytes = ProofObjectHeader::from_canonical_application_statement(
        statement_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .and_then(|header| header.encode())
    .map_err(|_| SelectedProofAccountingError::CanonicalEncoding)?;
    let relation_trees = (0..bound_tree_count)
        .map(|_| {
            RelationProofTreeInput::BoundPublic(StatementOwnedProofTreeInput::SetupPolynomial {
                public_polynomial_context_hash: [0; Hash512::BYTE_LENGTH],
                row_width: bound_tree_row_width,
                expected_root: [0; Hash512::BYTE_LENGTH],
            })
        })
        .collect();
    let catalog = build_complete_proof_tree_catalog(
        ProofTreeCatalogInput {
            suite_identifier: [0; Hash512::BYTE_LENGTH],
            canonical_proof_object_header_bytes: proof_header_bytes.clone(),
            application_statement_schema_identifier:
                ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            proof_field_index: 0,
            evaluation_domain_size: SELECTED_EVALUATION_DOMAIN_SIZE,
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
    let ceiling = canonical_common_proof_byte_length_ceiling(proof_header_bytes.len(), &layout)
        .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?;
    require_selected_query_ceiling_geometry(&layout, &ceiling)?;

    Ok(SelectedEvaluatorAggregateStructuralAccounting {
        bound_tree_count,
        bound_tree_row_width,
        total_bound_row_width,
        opening_claim_count,
        proof_byte_length: ceiling.proof_byte_length(),
    })
}

fn require_selected_proof_byte_length(
    proof_byte_length: usize,
) -> Result<u64, SelectedProofAccountingError> {
    if proof_byte_length == 0 || proof_byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH {
        return Err(SelectedProofAccountingError::ProofByteLengthExceeded);
    }
    u64::try_from(proof_byte_length).map_err(|_| SelectedProofAccountingError::CountOverflow)
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
    layout: &ProofBodyLayout,
    ceiling: &super::CommonProofByteLengthCeiling,
) -> Result<(), SelectedProofAccountingError> {
    const UNIQUE_QUERY_COUNT: usize = 168;
    const MINIMUM_TREE_HEIGHT: u32 = 11;
    const MAXIMUM_TREE_HEIGHT: u32 = 20;
    let query_representatives = selected_query_ceiling_witness()?;
    require_selected_query_ceiling_witness(&query_representatives)?;
    if layout.catalog().evaluation_domain_size() != 1_u64 << (MAXIMUM_TREE_HEIGHT + 1)
        || ceiling.query_trees().len() != layout.catalog().entries().len()
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    let mut observed_tree_heights = BTreeSet::new();
    for (catalog_index, tree) in ceiling.query_trees().iter().enumerate() {
        let leaf_count = tree.leaf_count();
        let tree_height = tree.tree_height();
        if !(MINIMUM_TREE_HEIGHT..=MAXIMUM_TREE_HEIGHT).contains(&tree_height)
            || leaf_count != 1_usize << tree_height
            || tree.opened_leaf_count_at_ceiling() != UNIQUE_QUERY_COUNT
            || tree.maximum_opened_leaf_count() != UNIQUE_QUERY_COUNT
            || tree.authentication_frontier_node_count_at_ceiling()
                != selected_query_frontier_node_count(tree_height, UNIQUE_QUERY_COUNT)?
            || proof_query_tree_byte_length(layout, catalog_index, &query_representatives)
                .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?
                != tree.byte_length()
        {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
        observed_tree_heights.insert(tree_height);
    }
    if observed_tree_heights != (MINIMUM_TREE_HEIGHT..=MAXIMUM_TREE_HEIGHT).collect::<BTreeSet<_>>()
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    Ok(())
}

/// A single query vector attaining every selected tree maximum. The low twenty
/// bits repeat one eight-bit seed. All odd-parity seeds are retained, while 88
/// even-parity seeds are omitted. Every seven-bit cyclic window therefore has
/// a retained preimage, and every eight-bit cyclic window identifies its seed.
/// Consequently each projected tree occupies `min(2^depth, 168)` nodes at
/// every depth, which is the frontier maximum simultaneously for heights 11
/// through 20.
fn selected_query_ceiling_witness() -> Result<Vec<u64>, SelectedProofAccountingError> {
    const EXCLUDED_EVEN_PARITY_SEED_COUNT: usize = 88;
    const QUERY_COUNT: usize = 168;
    let mut excluded_seed_count = 0_usize;
    let mut query_representatives = Vec::new();
    query_representatives
        .try_reserve_exact(QUERY_COUNT)
        .map_err(|_| SelectedProofAccountingError::AllocationLimitExceeded)?;
    for seed in 0_u64..=u8::MAX.into() {
        if seed.count_ones() % 2 == 0 && excluded_seed_count < EXCLUDED_EVEN_PARITY_SEED_COUNT {
            excluded_seed_count = excluded_seed_count
                .checked_add(1)
                .ok_or(SelectedProofAccountingError::CountOverflow)?;
            continue;
        }
        let repeated_seed = seed | (seed << 8) | ((seed & 0x0f) << 16);
        query_representatives.push(repeated_seed);
    }
    query_representatives.sort_unstable();
    if excluded_seed_count != EXCLUDED_EVEN_PARITY_SEED_COUNT
        || query_representatives.len() != QUERY_COUNT
        || !query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(SelectedProofAccountingError::InvalidTreeGeometry);
    }
    Ok(query_representatives)
}

fn require_selected_query_ceiling_witness(
    query_representatives: &[u64],
) -> Result<(), SelectedProofAccountingError> {
    const QUERY_COUNT: usize = 168;
    for tree_height in 11..=20 {
        let leaf_count = 1_usize << tree_height;
        let leaf_count_u64 =
            u64::try_from(leaf_count).map_err(|_| SelectedProofAccountingError::CountOverflow)?;
        let projected_leaf_indexes = query_representatives
            .iter()
            .map(|representative| representative % leaf_count_u64)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if projected_leaf_indexes.len() != QUERY_COUNT
            || minimal_frontier_node_count(&projected_leaf_indexes, leaf_count)
                .map_err(|_| SelectedProofAccountingError::InvalidTreeGeometry)?
                != selected_query_frontier_node_count(tree_height, QUERY_COUNT)?
        {
            return Err(SelectedProofAccountingError::InvalidTreeGeometry);
        }
    }
    Ok(())
}

fn selected_query_frontier_node_count(
    tree_height: u32,
    query_count: usize,
) -> Result<usize, SelectedProofAccountingError> {
    let mut frontier_count = 0_usize;
    for level in 1..tree_height {
        frontier_count = frontier_count
            .checked_add(query_count.min(1_usize << (tree_height - level)))
            .ok_or(SelectedProofAccountingError::CountOverflow)?;
    }
    frontier_count
        .checked_add(2)
        .and_then(|count| count.checked_sub(query_count))
        .ok_or(SelectedProofAccountingError::CountOverflow)
}

fn find_variant_ceiling(
    ceilings: &[SelectedProofVariantByteCeiling],
    family: u16,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
) -> Result<u64, SelectedProofAccountingError> {
    let mut matching = ceilings.iter().filter(|ceiling| {
        ceiling.application_statement_schema_identifier == family
            && ceiling.schedule_position == schedule_position
            && ceiling.top_count == top_count
    });
    let ceiling = matching
        .next()
        .ok_or(SelectedProofAccountingError::InvalidProfile)?;
    if matching.next().is_some() {
        return Err(SelectedProofAccountingError::InvalidProfile);
    }
    Ok(ceiling.proof_byte_length)
}

fn checked_add_scaled_ceiling(
    current: u64,
    ceiling: u64,
    multiplicity: u64,
) -> Result<u64, SelectedProofAccountingError> {
    current
        .checked_add(
            ceiling
                .checked_mul(multiplicity)
                .ok_or(SelectedProofAccountingError::CountOverflow)?,
        )
        .ok_or(SelectedProofAccountingError::CountOverflow)
}

fn checked_u32_sum(values: &[u32]) -> Result<u32, SelectedProofAccountingError> {
    values.iter().try_fold(0_u32, |sum, value| {
        sum.checked_add(*value)
            .ok_or(SelectedProofAccountingError::CountOverflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::evaluator::top_k::selected_evaluator_rotation_key_schedule;

    #[test]
    fn selected_program_positions_drive_proof_multiplicities() {
        let program = selected_evaluator_program_set().expect("selected program set");
        let positions = program.key_positions().expect("selected key positions");
        assert_eq!(positions.relinearization_catalog_levels(), [16]);
        assert_eq!(positions.galois_catalog_positions().len(), 16);
        assert_eq!(
            positions
                .galois_catalog_positions()
                .iter()
                .map(|position| (position.galois_element(), position.catalog_level()))
                .collect::<Vec<_>>(),
            selected_evaluator_rotation_key_schedule(20).expect("selected rotation schedule")
        );
        assert!(positions.streams().iter().all(|stream| {
            stream.relinearization_catalog_levels().len() == 1
                && stream.galois_catalog_positions().len() == 16
        }));
    }

    #[test]
    fn selected_query_frontiers_match_the_exact_selected_geometry() {
        assert_eq!(selected_query_frontier_node_count(11, 168), Ok(592));
        assert_eq!(selected_query_frontier_node_count(12, 168), Ok(760));
        assert_eq!(selected_query_frontier_node_count(20, 168), Ok(2_104));
    }

    #[test]
    fn selected_proof_byte_ceiling_rejects_one_byte_over_before_accounting() {
        assert_eq!(MAXIMUM_COMMON_PROOF_BYTE_LENGTH, 5_242_880);
        assert_eq!(
            require_selected_proof_byte_length(MAXIMUM_COMMON_PROOF_BYTE_LENGTH),
            Ok(MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64)
        );
        assert_eq!(
            require_selected_proof_byte_length(0),
            Err(SelectedProofAccountingError::ProofByteLengthExceeded)
        );
        assert_eq!(
            require_selected_proof_byte_length(MAXIMUM_COMMON_PROOF_BYTE_LENGTH + 1),
            Err(SelectedProofAccountingError::ProofByteLengthExceeded)
        );
    }

    #[test]
    fn one_selected_query_vector_attains_every_folded_tree_maximum() {
        let query_representatives =
            selected_query_ceiling_witness().expect("selected ceiling witness derives");
        assert_eq!(query_representatives.len(), 168);
        assert!(
            query_representatives
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(query_representatives.last().copied().unwrap() < 1_u64 << 20);

        let retained_seed_parities = query_representatives
            .iter()
            .map(|representative| (representative & 0xff).count_ones() % 2)
            .collect::<Vec<_>>();
        assert_eq!(
            retained_seed_parities
                .iter()
                .filter(|parity| **parity == 1)
                .count(),
            128
        );
        assert_eq!(
            retained_seed_parities
                .iter()
                .filter(|parity| **parity == 0)
                .count(),
            40
        );

        let expected_frontier_counts = [
            592, 760, 928, 1_096, 1_264, 1_432, 1_600, 1_768, 1_936, 2_104,
        ];
        let mut observed_frontier_counts = Vec::new();
        for tree_height in 11..=20 {
            let leaf_count = 1_usize << tree_height;
            let projected_leaf_indexes = query_representatives
                .iter()
                .map(|representative| representative % leaf_count as u64)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(projected_leaf_indexes.len(), 168);
            observed_frontier_counts.push(
                minimal_frontier_node_count(&projected_leaf_indexes, leaf_count)
                    .expect("projected frontier derives"),
            );
        }
        assert_eq!(observed_frontier_counts, expected_frontier_counts);
        assert_eq!(
            require_selected_query_ceiling_witness(&query_representatives),
            Ok(())
        );
    }

    #[test]
    fn selected_evaluator_aggregate_entry_exceeds_the_hard_per_proof_cap() {
        let accounting = selected_evaluator_aggregate_structural_accounting()
            .expect("selected evaluator aggregate structure derives");
        assert_eq!(accounting.bound_tree_count, 11);
        assert_eq!(accounting.bound_tree_row_width, 68);
        assert_eq!(accounting.total_bound_row_width, 748);
        assert_eq!(accounting.opening_claim_count, 756);
        assert!(accounting.opening_claim_count <= u32::from(u16::MAX));
        assert_eq!(accounting.proof_byte_length, 8_108_476);
        assert_eq!(
            require_selected_proof_byte_length(accounting.proof_byte_length),
            Err(SelectedProofAccountingError::ProofByteLengthExceeded)
        );
    }

    #[test]
    #[ignore = "long-running exact-family accounting; run via the guarded measurements runner"]
    fn selected_exact_family_and_action_proof_accounting_reports_browser_ceiling_mismatch() {
        let accounting =
            selected_proof_byte_accounting(3, 20).expect("selected proof accounting derives");
        let mut family_maxima = std::collections::BTreeMap::<u16, u64>::new();
        for ceiling in accounting.variant_ceilings() {
            family_maxima
                .entry(ceiling.application_statement_schema_identifier())
                .and_modify(|maximum| *maximum = (*maximum).max(ceiling.proof_byte_length()))
                .or_insert(ceiling.proof_byte_length());
        }
        let maximum_variant = accounting
            .variant_ceilings()
            .iter()
            .max_by_key(|ceiling| ceiling.proof_byte_length())
            .copied()
            .expect("selected relation catalog is non-empty");
        eprintln!(
            "family_maxima={family_maxima:?}; maximum_variant={:?}; action_counts={:?}; action_bytes={:?}; maximum_object_count={}; maximum_action_bytes={}; ballot_bytes={:?}",
            (
                maximum_variant.application_statement_schema_identifier(),
                maximum_variant.schedule_position(),
                maximum_variant.top_count(),
                maximum_variant.proof_byte_length(),
            ),
            accounting.action_proof_object_counts(),
            accounting.action_proof_byte_lengths(),
            accounting.maximum_proof_object_count(),
            accounting.maximum_proof_byte_length(),
            accounting.ballot_proof_byte_length(),
        );
        assert_eq!(
            family_maxima,
            std::collections::BTreeMap::from([
                (0x1211, 18_729_246),
                (0x1212, 15_576_328),
                (0x1213, 7_088_104),
                (0x1214, 38_883_008),
                (0x1215, 12_732_834),
                (0x1216, 100_039_322),
                (0x1217, 25_963_922),
                (0x1218, 8_108_476),
                (0x1302, 12_388_018),
                (0x1621, 19_998_378),
                (0x2110, 149_419_382),
                (0x2111, 116_451_886),
            ])
        );
        assert_eq!(
            family_maxima
                .values()
                .filter(|byte_length| { **byte_length > MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64 })
                .count(),
            12
        );
        assert_eq!(
            (
                maximum_variant.application_statement_schema_identifier(),
                maximum_variant.schedule_position(),
                maximum_variant.top_count(),
                maximum_variant.proof_byte_length(),
            ),
            (0x2110, None, None, 149_419_382)
        );
        assert_eq!(accounting.action_proof_object_counts(), &[269; 20]);
        assert_eq!(accounting.action_proof_byte_lengths(), &[9_150_628_410; 20]);
        assert_eq!(accounting.maximum_proof_object_count(), 269);
        assert_eq!(accounting.maximum_proof_byte_length(), 9_150_628_410);
        assert_eq!(accounting.maximum_variant_proof_byte_length(), 149_419_382);
        assert_eq!(accounting.ballot_proof_byte_length(), Some(12_388_018));
        assert!(
            accounting.maximum_variant_proof_byte_length()
                > MAXIMUM_COMMON_PROOF_BYTE_LENGTH as u64
        );
        assert!(accounting.maximum_proof_byte_length() > 1_500_000_000);
    }
}
