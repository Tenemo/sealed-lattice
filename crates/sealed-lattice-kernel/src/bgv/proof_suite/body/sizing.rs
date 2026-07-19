use std::collections::BTreeMap;

use super::super::{PROOF_CHALLENGE_EXTENSION_DEGREE, merkle::ProofLeafVisibility};
use super::authentication::minimal_frontier_node_count;
use super::{
    AUTHENTICATION_DIGEST_BYTE_LENGTH, ProofBodyError, ProofBodyLayout, ProofTreeCatalogEntry,
    ProofTreeCatalogSource, ProofTreeConstruction,
};
use crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;

pub(crate) fn proof_query_tree_byte_length(
    layout: &ProofBodyLayout,
    catalog_index: usize,
    sorted_query_representatives: &[u64],
) -> Result<usize, ProofBodyError> {
    layout.validate_query_representatives(sorted_query_representatives)?;
    let entry = layout
        .catalog
        .entries
        .get(catalog_index)
        .ok_or(ProofBodyError::InvalidTreeCatalogIndex)?;
    let opened_leaf_indexes = layout.opened_leaf_indexes(entry, sorted_query_representatives)?;
    let leaf_count = entry_leaf_count(entry, layout.catalog.evaluation_domain_size)?;
    let leaf_byte_length = canonical_leaf_byte_length(entry)?;
    let opening_list_byte_length =
        raw_byte_list_byte_length(opened_leaf_indexes.len(), leaf_byte_length)?;
    let frontier_count = minimal_frontier_node_count(&opened_leaf_indexes, leaf_count)?;
    let frontier_list_byte_length = homogeneous_fixed_width_list_byte_length(
        frontier_count,
        AUTHENTICATION_DIGEST_BYTE_LENGTH,
    )?;

    // Each record has an eight-byte tuple header, an eight-byte u16 item,
    // and a six-byte homogeneous-list item header.  The returned list byte
    // lengths already include their six-byte list headers.
    44_usize
        .checked_add(opening_list_byte_length)
        .and_then(|byte_length| byte_length.checked_add(frontier_list_byte_length))
        .ok_or(ProofBodyError::CountOverflow)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofQueryTreeByteLengthCeiling {
    tree_catalog_index: u16,
    source: ProofTreeCatalogSource,
    tree_height: u32,
    leaf_count: usize,
    canonical_leaf_byte_length: usize,
    minimum_opened_leaf_count: usize,
    maximum_opened_leaf_count: usize,
    opened_leaf_count_at_ceiling: usize,
    authentication_frontier_node_count_at_ceiling: usize,
    opened_leaf_payload_byte_length: usize,
    authentication_frontier_digest_byte_length: usize,
    canonical_framing_byte_length: usize,
    byte_length: usize,
}

impl ProofQueryTreeByteLengthCeiling {
    pub(crate) const fn tree_catalog_index(&self) -> u16 {
        self.tree_catalog_index
    }

    pub(crate) const fn source(&self) -> ProofTreeCatalogSource {
        self.source
    }

    pub(crate) const fn tree_height(&self) -> u32 {
        self.tree_height
    }

    pub(crate) const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    pub(crate) const fn canonical_leaf_byte_length(&self) -> usize {
        self.canonical_leaf_byte_length
    }

    pub(crate) const fn minimum_opened_leaf_count(&self) -> usize {
        self.minimum_opened_leaf_count
    }

    pub(crate) const fn maximum_opened_leaf_count(&self) -> usize {
        self.maximum_opened_leaf_count
    }

    pub(crate) const fn opened_leaf_count_at_ceiling(&self) -> usize {
        self.opened_leaf_count_at_ceiling
    }

    pub(crate) const fn authentication_frontier_node_count_at_ceiling(&self) -> usize {
        self.authentication_frontier_node_count_at_ceiling
    }

    pub(crate) const fn opened_leaf_payload_byte_length(&self) -> usize {
        self.opened_leaf_payload_byte_length
    }

    pub(crate) const fn authentication_frontier_digest_byte_length(&self) -> usize {
        self.authentication_frontier_digest_byte_length
    }

    pub(crate) const fn canonical_framing_byte_length(&self) -> usize {
        self.canonical_framing_byte_length
    }

    pub(crate) const fn byte_length(&self) -> usize {
        self.byte_length
    }
}

/// Disjoint serialized components of one canonical proof ceiling. The
/// categories follow the production transcript order and sum exactly to the
/// complete proof byte length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofComponentByteLengths {
    canonical_framing: usize,
    relation_commitments_and_openings: usize,
    quotient_commitments_and_openings: usize,
    transcript_opening_claims: usize,
    fri: usize,
}

impl CommonProofComponentByteLengths {
    pub(crate) const fn canonical_framing(self) -> usize {
        self.canonical_framing
    }

    pub(crate) const fn relation_commitments_and_openings(self) -> usize {
        self.relation_commitments_and_openings
    }

    pub(crate) const fn quotient_commitments_and_openings(self) -> usize {
        self.quotient_commitments_and_openings
    }

    pub(crate) const fn transcript_opening_claims(self) -> usize {
        self.transcript_opening_claims
    }

    pub(crate) const fn fri(self) -> usize {
        self.fri
    }

    pub(crate) fn proof_byte_length(self) -> Option<usize> {
        self.canonical_framing
            .checked_add(self.relation_commitments_and_openings)
            .and_then(|length| length.checked_add(self.quotient_commitments_and_openings))
            .and_then(|length| length.checked_add(self.transcript_opening_claims))
            .and_then(|length| length.checked_add(self.fri))
    }
}

/// Canonical framing plus the sum of the exact maximum record length for every
/// tree. Each tree maximum is exact for its leaf geometry and query-orbit map.
/// Their sum is always a conservative parser ceiling. A profile may bind it as
/// its exact serialized maximum only after proving that one shared query vector
/// attains every included tree maximum; selected-suite accounting performs that
/// constructive check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofByteLengthCeiling {
    canonical_header_byte_length: usize,
    body_prefix_byte_length: usize,
    query_section_byte_length: usize,
    proof_byte_length: usize,
    component_byte_lengths: CommonProofComponentByteLengths,
    query_trees: Vec<ProofQueryTreeByteLengthCeiling>,
}

impl CommonProofByteLengthCeiling {
    pub(crate) const fn canonical_header_byte_length(&self) -> usize {
        self.canonical_header_byte_length
    }

    pub(crate) const fn body_prefix_byte_length(&self) -> usize {
        self.body_prefix_byte_length
    }

    pub(crate) const fn query_section_byte_length(&self) -> usize {
        self.query_section_byte_length
    }

    pub(crate) const fn proof_byte_length(&self) -> usize {
        self.proof_byte_length
    }

    pub(crate) const fn component_byte_lengths(&self) -> CommonProofComponentByteLengths {
        self.component_byte_lengths
    }

    pub(crate) fn query_trees(&self) -> &[ProofQueryTreeByteLengthCeiling] {
        &self.query_trees
    }

    pub(crate) fn maximum_query_tree_byte_length(&self) -> usize {
        self.query_trees
            .iter()
            .map(ProofQueryTreeByteLengthCeiling::byte_length)
            .max()
            .unwrap_or(0)
    }
}

pub(crate) fn canonical_common_proof_byte_length_ceiling(
    canonical_header_byte_length: usize,
    layout: &ProofBodyLayout,
) -> Result<CommonProofByteLengthCeiling, ProofBodyError> {
    if canonical_header_byte_length == 0 {
        return Err(ProofBodyError::InvalidItemLength);
    }
    let unique_query_count =
        usize::try_from(layout.unique_query_count).map_err(|_| ProofBodyError::CountOverflow)?;
    let query_orbit_count =
        usize::try_from(layout.query_orbit_count).map_err(|_| ProofBodyError::CountOverflow)?;
    if unique_query_count == 0 || unique_query_count > query_orbit_count {
        return Err(ProofBodyError::InvalidCatalog);
    }

    let mut query_trees = Vec::new();
    query_trees
        .try_reserve_exact(layout.catalog.entries.len())
        .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
    let mut query_section_byte_length = 4_usize;
    let mut query_framing_byte_length = 0_usize;
    let mut relation_query_payload_byte_length = 0_usize;
    let mut quotient_query_payload_byte_length = 0_usize;
    let mut fri_query_payload_byte_length = 0_usize;
    let mut frontier_node_count_cache = BTreeMap::<(usize, usize), usize>::new();
    for entry in &layout.catalog.entries {
        let leaf_count = entry_leaf_count(entry, layout.catalog.evaluation_domain_size)?;
        let canonical_leaf_byte_length = canonical_leaf_byte_length(entry)?;
        let query_representatives_per_leaf = match entry.source {
            ProofTreeCatalogSource::NonterminalFriLayer { .. } => query_orbit_count
                .checked_div(leaf_count)
                .filter(|multiplicity| *multiplicity != 0)
                .ok_or(ProofBodyError::InvalidCatalog)?,
            _ if leaf_count == query_orbit_count => 1,
            _ => return Err(ProofBodyError::InvalidCatalog),
        };
        if leaf_count
            .checked_mul(query_representatives_per_leaf)
            .filter(|covered_query_orbits| *covered_query_orbits == query_orbit_count)
            .is_none()
        {
            return Err(ProofBodyError::InvalidCatalog);
        }
        let minimum_opened_leaf_count = unique_query_count
            .checked_add(query_representatives_per_leaf - 1)
            .and_then(|count| count.checked_div(query_representatives_per_leaf))
            .ok_or(ProofBodyError::CountOverflow)?;
        let maximum_opened_leaf_count = unique_query_count.min(leaf_count);
        if minimum_opened_leaf_count == 0 || minimum_opened_leaf_count > maximum_opened_leaf_count {
            return Err(ProofBodyError::InvalidCatalog);
        }

        let mut byte_length_at_ceiling = 0_usize;
        let mut opened_leaf_count_at_ceiling = 0_usize;
        let mut authentication_frontier_node_count_at_ceiling = 0_usize;
        for opened_leaf_count in minimum_opened_leaf_count..=maximum_opened_leaf_count {
            let frontier_node_count = if let Some(cached) = frontier_node_count_cache
                .get(&(leaf_count, opened_leaf_count))
                .copied()
            {
                cached
            } else {
                let derived = maximum_minimal_frontier_node_count(leaf_count, opened_leaf_count)?;
                frontier_node_count_cache.insert((leaf_count, opened_leaf_count), derived);
                derived
            };
            let opening_list_byte_length =
                raw_byte_list_byte_length(opened_leaf_count, canonical_leaf_byte_length)?;
            let frontier_list_byte_length = homogeneous_fixed_width_list_byte_length(
                frontier_node_count,
                AUTHENTICATION_DIGEST_BYTE_LENGTH,
            )?;
            let byte_length = 44_usize
                .checked_add(opening_list_byte_length)
                .and_then(|length| length.checked_add(frontier_list_byte_length))
                .ok_or(ProofBodyError::CountOverflow)?;
            if byte_length > byte_length_at_ceiling {
                byte_length_at_ceiling = byte_length;
                opened_leaf_count_at_ceiling = opened_leaf_count;
                authentication_frontier_node_count_at_ceiling = frontier_node_count;
            }
        }
        query_section_byte_length = query_section_byte_length
            .checked_add(byte_length_at_ceiling)
            .ok_or(ProofBodyError::CountOverflow)?;
        let opened_leaf_payload_byte_length = opened_leaf_count_at_ceiling
            .checked_mul(canonical_leaf_byte_length)
            .ok_or(ProofBodyError::CountOverflow)?;
        let authentication_frontier_digest_byte_length =
            authentication_frontier_node_count_at_ceiling
                .checked_mul(AUTHENTICATION_DIGEST_BYTE_LENGTH)
                .ok_or(ProofBodyError::CountOverflow)?;
        let canonical_framing_byte_length = byte_length_at_ceiling
            .checked_sub(opened_leaf_payload_byte_length)
            .and_then(|length| length.checked_sub(authentication_frontier_digest_byte_length))
            .ok_or(ProofBodyError::CountOverflow)?;
        let query_payload_byte_length = opened_leaf_payload_byte_length
            .checked_add(authentication_frontier_digest_byte_length)
            .ok_or(ProofBodyError::CountOverflow)?;
        query_framing_byte_length = query_framing_byte_length
            .checked_add(canonical_framing_byte_length)
            .ok_or(ProofBodyError::CountOverflow)?;
        match entry.source {
            ProofTreeCatalogSource::RelationProofCreated { .. }
            | ProofTreeCatalogSource::RelationBoundPublic => {
                relation_query_payload_byte_length = relation_query_payload_byte_length
                    .checked_add(query_payload_byte_length)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
            ProofTreeCatalogSource::QuotientComponent { .. } => {
                quotient_query_payload_byte_length = quotient_query_payload_byte_length
                    .checked_add(query_payload_byte_length)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
            ProofTreeCatalogSource::OpeningBatchMask
            | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
                fri_query_payload_byte_length = fri_query_payload_byte_length
                    .checked_add(query_payload_byte_length)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
        }
        query_trees.push(ProofQueryTreeByteLengthCeiling {
            tree_catalog_index: entry.tree_catalog_index,
            source: entry.source,
            tree_height: leaf_count.trailing_zeros(),
            leaf_count,
            canonical_leaf_byte_length,
            minimum_opened_leaf_count,
            maximum_opened_leaf_count,
            opened_leaf_count_at_ceiling,
            authentication_frontier_node_count_at_ceiling,
            opened_leaf_payload_byte_length,
            authentication_frontier_digest_byte_length,
            canonical_framing_byte_length,
            byte_length: byte_length_at_ceiling,
        });
    }
    if query_section_byte_length > u32::MAX as usize {
        return Err(ProofBodyError::CountOverflow);
    }
    let body_prefix_byte_length = proof_body_prefix_byte_length(layout)?;
    let proof_byte_length = canonical_header_byte_length
        .checked_add(body_prefix_byte_length)
        .and_then(|length| length.checked_add(query_section_byte_length))
        .filter(|length| *length <= u32::MAX as usize)
        .ok_or(ProofBodyError::CountOverflow)?;
    let extension_element_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(8)
        .ok_or(ProofBodyError::CountOverflow)?;
    let transcript_opening_claim_payload_byte_length =
        usize::try_from(layout.deep_evaluation_count)
            .map_err(|_| ProofBodyError::CountOverflow)?
            .checked_mul(extension_element_byte_length)
            .ok_or(ProofBodyError::CountOverflow)?;
    let terminal_fri_payload_byte_length = usize::try_from(layout.terminal_coefficient_count)
        .map_err(|_| ProofBodyError::CountOverflow)?
        .checked_mul(extension_element_byte_length)
        .ok_or(ProofBodyError::CountOverflow)?;
    let mut relation_root_byte_length = 0_usize;
    let mut quotient_root_byte_length = 0_usize;
    let mut fri_root_byte_length = 0_usize;
    for entry in &layout.catalog.entries {
        if entry.bound_root.is_some() {
            continue;
        }
        match entry.source {
            ProofTreeCatalogSource::RelationProofCreated { .. } => {
                relation_root_byte_length = relation_root_byte_length
                    .checked_add(AUTHENTICATION_DIGEST_BYTE_LENGTH)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
            ProofTreeCatalogSource::QuotientComponent { .. } => {
                quotient_root_byte_length = quotient_root_byte_length
                    .checked_add(AUTHENTICATION_DIGEST_BYTE_LENGTH)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
            ProofTreeCatalogSource::OpeningBatchMask
            | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
                fri_root_byte_length = fri_root_byte_length
                    .checked_add(AUTHENTICATION_DIGEST_BYTE_LENGTH)
                    .ok_or(ProofBodyError::CountOverflow)?;
            }
            ProofTreeCatalogSource::RelationBoundPublic => {
                return Err(ProofBodyError::InvalidCatalog);
            }
        }
    }
    let component_byte_lengths = CommonProofComponentByteLengths {
        canonical_framing: canonical_header_byte_length
            .checked_add(4)
            .and_then(|length| length.checked_add(query_framing_byte_length))
            .and_then(|length| length.checked_add(12))
            .ok_or(ProofBodyError::CountOverflow)?,
        relation_commitments_and_openings: relation_root_byte_length
            .checked_add(relation_query_payload_byte_length)
            .ok_or(ProofBodyError::CountOverflow)?,
        quotient_commitments_and_openings: quotient_root_byte_length
            .checked_add(quotient_query_payload_byte_length)
            .ok_or(ProofBodyError::CountOverflow)?,
        transcript_opening_claims: transcript_opening_claim_payload_byte_length,
        fri: fri_root_byte_length
            .checked_add(fri_query_payload_byte_length)
            .and_then(|length| length.checked_add(terminal_fri_payload_byte_length))
            .ok_or(ProofBodyError::CountOverflow)?,
    };
    if component_byte_lengths.proof_byte_length() != Some(proof_byte_length) {
        return Err(ProofBodyError::InvalidCatalog);
    }
    Ok(CommonProofByteLengthCeiling {
        canonical_header_byte_length,
        body_prefix_byte_length,
        query_section_byte_length,
        proof_byte_length,
        component_byte_lengths,
        query_trees,
    })
}

pub(in crate::bgv::proof_suite) fn maximum_minimal_frontier_node_count(
    leaf_count: usize,
    selected_leaf_count: usize,
) -> Result<usize, ProofBodyError> {
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || selected_leaf_count == 0
        || selected_leaf_count > leaf_count
    {
        return Err(ProofBodyError::InvalidCatalog);
    }
    let mut previous_depth = vec![0_usize, 0_usize];
    let mut previous_subtree_leaf_count = 1_usize;
    for _ in 0..leaf_count.trailing_zeros() {
        let subtree_leaf_count = previous_subtree_leaf_count
            .checked_mul(2)
            .ok_or(ProofBodyError::CountOverflow)?;
        let maximum_selected_count = selected_leaf_count.min(subtree_leaf_count);
        let mut current_depth = Vec::new();
        current_depth
            .try_reserve_exact(maximum_selected_count + 1)
            .map_err(|_| ProofBodyError::AllocationLimitExceeded)?;
        current_depth.resize(maximum_selected_count + 1, 0);
        for (current_selected_count, current_frontier_count) in current_depth
            .iter_mut()
            .enumerate()
            .take(maximum_selected_count + 1)
            .skip(1)
        {
            let minimum_left_count =
                current_selected_count.saturating_sub(previous_subtree_leaf_count);
            let maximum_left_count = current_selected_count.min(previous_subtree_leaf_count);
            let mut maximum_frontier_count = 0_usize;
            for left_count in minimum_left_count..=maximum_left_count {
                let right_count = current_selected_count - left_count;
                let candidate = previous_depth[left_count]
                    .checked_add(previous_depth[right_count])
                    .and_then(|count| {
                        count.checked_add(usize::from((left_count == 0) != (right_count == 0)))
                    })
                    .ok_or(ProofBodyError::CountOverflow)?;
                maximum_frontier_count = maximum_frontier_count.max(candidate);
            }
            *current_frontier_count = maximum_frontier_count;
        }
        previous_depth = current_depth;
        previous_subtree_leaf_count = subtree_leaf_count;
    }
    previous_depth
        .get(selected_leaf_count)
        .copied()
        .ok_or(ProofBodyError::InvalidCatalog)
}

pub(crate) fn proof_body_prefix_byte_length(
    layout: &ProofBodyLayout,
) -> Result<usize, ProofBodyError> {
    let serialized_root_count = layout
        .catalog
        .entries
        .iter()
        .filter(|entry| entry.bound_root.is_none())
        .count();
    let root_byte_length = serialized_root_count
        .checked_mul(64)
        .ok_or(ProofBodyError::CountOverflow)?;
    let extension_element_byte_length = PROOF_CHALLENGE_EXTENSION_DEGREE
        .checked_mul(8)
        .ok_or(ProofBodyError::CountOverflow)?;
    let deep_byte_length = usize::try_from(layout.deep_evaluation_count)
        .map_err(|_| ProofBodyError::CountOverflow)?
        .checked_mul(extension_element_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    let terminal_byte_length = usize::try_from(layout.terminal_coefficient_count)
        .map_err(|_| ProofBodyError::CountOverflow)?
        .checked_mul(extension_element_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    root_byte_length
        .checked_add(deep_byte_length)
        .and_then(|length| length.checked_add(terminal_byte_length))
        .ok_or(ProofBodyError::CountOverflow)
}

pub(super) fn raw_byte_list_byte_length(
    element_count: usize,
    element_byte_length: usize,
) -> Result<usize, ProofBodyError> {
    let framed_element_length = element_byte_length
        .checked_add(4)
        .ok_or(ProofBodyError::CountOverflow)?;
    let byte_length = element_count
        .checked_mul(framed_element_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    ensure_u32_length(byte_length)
}

pub(super) fn homogeneous_fixed_width_list_byte_length(
    element_count: usize,
    element_byte_length: usize,
) -> Result<usize, ProofBodyError> {
    let byte_length = element_count
        .checked_mul(element_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or(ProofBodyError::CountOverflow)?;
    ensure_u32_length(byte_length)
}

fn ensure_u32_length(byte_length: usize) -> Result<usize, ProofBodyError> {
    u32::try_from(byte_length).map_err(|_| ProofBodyError::CountOverflow)?;
    Ok(byte_length)
}

pub(crate) fn entry_leaf_count(
    entry: &ProofTreeCatalogEntry,
    evaluation_domain_size: u64,
) -> Result<usize, ProofBodyError> {
    match &entry.construction {
        ProofTreeConstruction::Common(_) => entry.leaf_count(),
        ProofTreeConstruction::CommittedMaterial { .. }
        | ProofTreeConstruction::SetupPolynomial { .. } => {
            usize::try_from(evaluation_domain_size / 2).map_err(|_| ProofBodyError::CountOverflow)
        }
    }
}

pub(crate) fn canonical_leaf_byte_length(
    entry: &ProofTreeCatalogEntry,
) -> Result<usize, ProofBodyError> {
    match &entry.construction {
        ProofTreeConstruction::Common(context) => {
            let value_byte_length = match entry.source {
                ProofTreeCatalogSource::RelationProofCreated { .. } => 8_usize,
                ProofTreeCatalogSource::QuotientComponent { .. }
                | ProofTreeCatalogSource::OpeningBatchMask
                | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
                    PROOF_CHALLENGE_EXTENSION_DEGREE
                        .checked_mul(8)
                        .ok_or(ProofBodyError::CountOverflow)?
                }
                ProofTreeCatalogSource::RelationBoundPublic => {
                    return Err(ProofBodyError::InvalidCatalog);
                }
            };
            let row_width =
                usize::try_from(context.row_width()).map_err(|_| ProofBodyError::CountOverflow)?;
            let list_values_byte_length = row_width
                .checked_mul(value_byte_length)
                .and_then(|length| length.checked_mul(2))
                .ok_or(ProofBodyError::CountOverflow)?;
            let salt_item_byte_length =
                if context.leaf_visibility() == ProofLeafVisibility::SecretBearing {
                    6 + COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH
                } else {
                    0
                };
            124_usize
                .checked_add(list_values_byte_length)
                .and_then(|length| length.checked_add(salt_item_byte_length))
                .ok_or(ProofBodyError::CountOverflow)
        }
        ProofTreeConstruction::CommittedMaterial { row_width, .. } => {
            let row_width =
                usize::try_from(*row_width).map_err(|_| ProofBodyError::CountOverflow)?;
            122_usize
                .checked_add(COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH)
                .and_then(|fixed_byte_length| {
                    row_width
                        .checked_mul(16)
                        .and_then(|row_byte_length| fixed_byte_length.checked_add(row_byte_length))
                })
                .ok_or(ProofBodyError::CountOverflow)
        }
        ProofTreeConstruction::SetupPolynomial { row_width, .. } => {
            let row_width =
                usize::try_from(*row_width).map_err(|_| ProofBodyError::CountOverflow)?;
            104_usize
                .checked_add(
                    row_width
                        .checked_mul(16)
                        .ok_or(ProofBodyError::CountOverflow)?,
                )
                .ok_or(ProofBodyError::CountOverflow)
        }
    }
}
