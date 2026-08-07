//! Canonical salted Merkle commitments for compact logical responses.
//!
//! The verifier owns every response, component, and leaf coordinate. Leaves
//! bind that geometry, their canonical field encoding, and one fresh 128-byte
//! salt. Parent hashes bind the response and exact tree coordinate. Compact
//! openings carry no coordinates: the verifier derives the unique minimal
//! frontier from its sorted query indices before reconstructing the root.
//!
//! This module owns canonical hashing, verifier-message query mapping,
//! postorder tree writing and scanning, and transported-opening verification.
//! The selected-size response-value source, external-memory transaction driver,
//! and authenticated restart record remain separate implementation owners.

use super::compact_proof_wire::{
    CompactProofResponseWireGeometry, CompactProofWireError, DecodedCompactProofResponse,
};
use super::compact_transcript::compact_vector_commitment_oracle_identifier;
use super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;
use super::merkle::minimal_frontier_coordinates;
use super::{
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, PROOF_CHALLENGE_EXTENSION_DEGREE,
    ProofBaseFieldElement, ProofChallengeExtensionElement,
};
use crate::foundation::{CanonicalItem, Hash512, hash_foundation_tuple_512};

pub(crate) const COMPACT_RESPONSE_LEAF_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/compact-response/leaf/v1";
pub(crate) const COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN: &str =
    "sealed-lattice/common-proof/compact-response/merkle-node/v1";
pub(crate) const COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum CompactResponseLeafValueKind {
    BaseField = 1,
    ExtensionField = 2,
    Padding = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactResponseQuerySelection {
    Unqueried,
    EveryLeaf,
    VerifierMessageDistinctGroup {
        logical_verifier_move_ordinal: u32,
        distinct_query_group_ordinal: u32,
    },
    VerifierMessageDistinctGroupUnion {
        first_logical_verifier_move_ordinal: u32,
        first_distinct_query_group_ordinal: u32,
        second_logical_verifier_move_ordinal: u32,
        second_distinct_query_group_ordinal: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseComponentGeometry {
    first_leaf_ordinal: u64,
    leaf_count: u64,
    minimum_queried_leaf_count: u64,
    maximum_queried_leaf_count: u64,
    query_selection: CompactResponseQuerySelection,
    value_kind: CompactResponseLeafValueKind,
    field_element_count_per_leaf: u64,
}

impl CompactResponseComponentGeometry {
    pub(crate) const fn new(
        first_leaf_ordinal: u64,
        leaf_count: u64,
        queried_leaf_count: u64,
        query_selection: CompactResponseQuerySelection,
        value_kind: CompactResponseLeafValueKind,
        field_element_count_per_leaf: u64,
    ) -> Self {
        Self::new_with_query_count_range(
            first_leaf_ordinal,
            leaf_count,
            queried_leaf_count,
            queried_leaf_count,
            query_selection,
            value_kind,
            field_element_count_per_leaf,
        )
    }

    pub(crate) const fn new_with_query_count_range(
        first_leaf_ordinal: u64,
        leaf_count: u64,
        minimum_queried_leaf_count: u64,
        maximum_queried_leaf_count: u64,
        query_selection: CompactResponseQuerySelection,
        value_kind: CompactResponseLeafValueKind,
        field_element_count_per_leaf: u64,
    ) -> Self {
        Self {
            first_leaf_ordinal,
            leaf_count,
            minimum_queried_leaf_count,
            maximum_queried_leaf_count,
            query_selection,
            value_kind,
            field_element_count_per_leaf,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseMerkleGeometry {
    response_ordinal: u32,
    vector_commitment_oracle_identifier: u32,
    components: Vec<CompactResponseComponentGeometry>,
    merkle_leaf_count: u64,
    minimum_queried_leaf_count: u64,
    maximum_queried_leaf_count: u64,
}

impl CompactResponseMerkleGeometry {
    pub(crate) fn new(
        response_ordinal: u32,
        components: Vec<CompactResponseComponentGeometry>,
    ) -> Result<Self, CompactResponseMerkleError> {
        if components.is_empty() {
            return Err(CompactResponseMerkleError::InvalidGeometry);
        }
        let mut expected_first_leaf_ordinal = 0_u64;
        let mut minimum_queried_leaf_count = 0_u64;
        let mut maximum_queried_leaf_count = 0_u64;
        let mut saw_padding = false;
        for component in &components {
            if component.first_leaf_ordinal != expected_first_leaf_ordinal
                || component.leaf_count == 0
                || component.minimum_queried_leaf_count > component.maximum_queried_leaf_count
                || component.maximum_queried_leaf_count > component.leaf_count
                || (saw_padding && component.value_kind != CompactResponseLeafValueKind::Padding)
            {
                return Err(CompactResponseMerkleError::InvalidGeometry);
            }
            match component.query_selection {
                CompactResponseQuerySelection::Unqueried => {
                    if component.minimum_queried_leaf_count != 0
                        || component.maximum_queried_leaf_count != 0
                    {
                        return Err(CompactResponseMerkleError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::EveryLeaf => {
                    if component.minimum_queried_leaf_count != component.leaf_count
                        || component.maximum_queried_leaf_count != component.leaf_count
                    {
                        return Err(CompactResponseMerkleError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    ..
                } => {
                    if component.minimum_queried_leaf_count == 0
                        || component.minimum_queried_leaf_count
                            != component.maximum_queried_leaf_count
                        || component.maximum_queried_leaf_count == component.leaf_count
                        || logical_verifier_move_ordinal < response_ordinal
                    {
                        return Err(CompactResponseMerkleError::InvalidGeometry);
                    }
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    second_logical_verifier_move_ordinal,
                    ..
                } => {
                    if component.minimum_queried_leaf_count == 0
                        || first_logical_verifier_move_ordinal < response_ordinal
                        || second_logical_verifier_move_ordinal < response_ordinal
                        || first_logical_verifier_move_ordinal
                            >= second_logical_verifier_move_ordinal
                    {
                        return Err(CompactResponseMerkleError::InvalidGeometry);
                    }
                }
            }
            match component.value_kind {
                CompactResponseLeafValueKind::BaseField
                | CompactResponseLeafValueKind::ExtensionField => {
                    if component.field_element_count_per_leaf == 0 {
                        return Err(CompactResponseMerkleError::InvalidGeometry);
                    }
                }
                CompactResponseLeafValueKind::Padding => {
                    saw_padding = true;
                    if component.query_selection != CompactResponseQuerySelection::Unqueried
                        || component.minimum_queried_leaf_count != 0
                        || component.maximum_queried_leaf_count != 0
                        || component.field_element_count_per_leaf != 0
                    {
                        return Err(CompactResponseMerkleError::InvalidGeometry);
                    }
                }
            }
            expected_first_leaf_ordinal = expected_first_leaf_ordinal
                .checked_add(component.leaf_count)
                .ok_or(CompactResponseMerkleError::CountOverflow)?;
            minimum_queried_leaf_count = minimum_queried_leaf_count
                .checked_add(component.minimum_queried_leaf_count)
                .ok_or(CompactResponseMerkleError::CountOverflow)?;
            maximum_queried_leaf_count = maximum_queried_leaf_count
                .checked_add(component.maximum_queried_leaf_count)
                .ok_or(CompactResponseMerkleError::CountOverflow)?;
        }
        if expected_first_leaf_ordinal == 0
            || !expected_first_leaf_ordinal.is_power_of_two()
            || minimum_queried_leaf_count == 0
        {
            return Err(CompactResponseMerkleError::InvalidGeometry);
        }
        Ok(Self {
            response_ordinal,
            vector_commitment_oracle_identifier: compact_vector_commitment_oracle_identifier(
                response_ordinal,
            )
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            components,
            merkle_leaf_count: expected_first_leaf_ordinal,
            minimum_queried_leaf_count,
            maximum_queried_leaf_count,
        })
    }

    pub(crate) const fn response_ordinal(&self) -> u32 {
        self.response_ordinal
    }

    pub(crate) const fn vector_commitment_oracle_identifier(&self) -> u32 {
        self.vector_commitment_oracle_identifier
    }

    pub(crate) const fn merkle_leaf_count(&self) -> u64 {
        self.merkle_leaf_count
    }

    pub(crate) const fn queried_leaf_count(&self) -> u64 {
        self.maximum_queried_leaf_count
    }

    pub(crate) const fn minimum_queried_leaf_count(&self) -> u64 {
        self.minimum_queried_leaf_count
    }

    pub(crate) const fn maximum_queried_leaf_count(&self) -> u64 {
        self.maximum_queried_leaf_count
    }

    pub(crate) fn validate_wire_geometry(
        &self,
        wire_geometry: &CompactProofResponseWireGeometry,
    ) -> Result<(), CompactResponseMerkleError> {
        let (
            expected_minimum_base_field_element_count,
            expected_maximum_base_field_element_count,
            expected_minimum_extension_field_element_count,
            expected_maximum_extension_field_element_count,
        ) = self.components.iter().try_fold(
            (0_u64, 0_u64, 0_u64, 0_u64),
            |(
                minimum_base_count,
                maximum_base_count,
                minimum_extension_count,
                maximum_extension_count,
            ),
             component| {
                let minimum_queried_element_count = component
                    .minimum_queried_leaf_count
                    .checked_mul(component.field_element_count_per_leaf)
                    .ok_or(CompactResponseMerkleError::CountOverflow)?;
                let maximum_queried_element_count = component
                    .maximum_queried_leaf_count
                    .checked_mul(component.field_element_count_per_leaf)
                    .ok_or(CompactResponseMerkleError::CountOverflow)?;
                match component.value_kind {
                    CompactResponseLeafValueKind::BaseField => Ok((
                        minimum_base_count
                            .checked_add(minimum_queried_element_count)
                            .ok_or(CompactResponseMerkleError::CountOverflow)?,
                        maximum_base_count
                            .checked_add(maximum_queried_element_count)
                            .ok_or(CompactResponseMerkleError::CountOverflow)?,
                        minimum_extension_count,
                        maximum_extension_count,
                    )),
                    CompactResponseLeafValueKind::ExtensionField => Ok((
                        minimum_base_count,
                        maximum_base_count,
                        minimum_extension_count
                            .checked_add(minimum_queried_element_count)
                            .ok_or(CompactResponseMerkleError::CountOverflow)?,
                        maximum_extension_count
                            .checked_add(maximum_queried_element_count)
                            .ok_or(CompactResponseMerkleError::CountOverflow)?,
                    )),
                    CompactResponseLeafValueKind::Padding => Ok((
                        minimum_base_count,
                        maximum_base_count,
                        minimum_extension_count,
                        maximum_extension_count,
                    )),
                }
            },
        )?;
        if wire_geometry.ordinal() != self.response_ordinal
            || wire_geometry.minimum_queried_leaf_count() != self.minimum_queried_leaf_count
            || wire_geometry.maximum_queried_leaf_count() != self.maximum_queried_leaf_count
            || wire_geometry.minimum_queried_base_field_element_count()
                != expected_minimum_base_field_element_count
            || wire_geometry.maximum_queried_base_field_element_count()
                != expected_maximum_base_field_element_count
            || wire_geometry.minimum_queried_extension_field_element_count()
                != expected_minimum_extension_field_element_count
            || wire_geometry.maximum_queried_extension_field_element_count()
                != expected_maximum_extension_field_element_count
        {
            return Err(CompactResponseMerkleError::WireGeometryMismatch);
        }
        Ok(())
    }

    fn leaf_descriptor(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactResponseLeafDescriptor, CompactResponseMerkleError> {
        if leaf_ordinal >= self.merkle_leaf_count {
            return Err(CompactResponseMerkleError::InvalidOpeningIndices);
        }
        for (component_index, component) in self.components.iter().enumerate() {
            let component_end = component
                .first_leaf_ordinal
                .checked_add(component.leaf_count)
                .ok_or(CompactResponseMerkleError::CountOverflow)?;
            if leaf_ordinal < component_end {
                return Ok(CompactResponseLeafDescriptor {
                    component_ordinal: u32::try_from(component_index)
                        .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
                    component_leaf_ordinal: leaf_ordinal - component.first_leaf_ordinal,
                    leaf_ordinal,
                    value_kind: component.value_kind,
                    field_element_count: component.field_element_count_per_leaf,
                });
            }
        }
        Err(CompactResponseMerkleError::InvalidGeometry)
    }

    fn validate_query_leaf_ordinals(
        &self,
        query_leaf_ordinals: &[u64],
    ) -> Result<(), CompactResponseMerkleError> {
        let observed_total_count = u64::try_from(query_leaf_ordinals.len())
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        if !(self.minimum_queried_leaf_count..=self.maximum_queried_leaf_count)
            .contains(&observed_total_count)
            || query_leaf_ordinals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || query_leaf_ordinals
                .last()
                .is_some_and(|leaf_ordinal| *leaf_ordinal >= self.merkle_leaf_count)
        {
            return Err(CompactResponseMerkleError::InvalidOpeningIndices);
        }
        let mut observed_component_query_counts = vec![0_u64; self.components.len()];
        for leaf_ordinal in query_leaf_ordinals {
            let descriptor = self.leaf_descriptor(*leaf_ordinal)?;
            if descriptor.value_kind == CompactResponseLeafValueKind::Padding {
                return Err(CompactResponseMerkleError::InvalidOpeningIndices);
            }
            let component_index = usize::try_from(descriptor.component_ordinal)
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
            observed_component_query_counts[component_index] = observed_component_query_counts
                [component_index]
                .checked_add(1)
                .ok_or(CompactResponseMerkleError::CountOverflow)?;
        }
        if self
            .components
            .iter()
            .zip(observed_component_query_counts)
            .any(|(component, observed)| {
                !(component.minimum_queried_leaf_count..=component.maximum_queried_leaf_count)
                    .contains(&observed)
            })
        {
            return Err(CompactResponseMerkleError::InvalidOpeningIndices);
        }
        Ok(())
    }

    fn validate_query_source_geometry(
        &self,
        wire_geometries: &[CompactProofResponseWireGeometry],
    ) -> Result<(), CompactResponseMerkleError> {
        self.validate_wire_geometry(wire_geometry_for_logical_move(
            wire_geometries,
            self.response_ordinal,
        )?)?;
        for component in &self.components {
            match component.query_selection {
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    distinct_query_group_ordinal,
                } => {
                    let (domain_cardinality, query_count) = query_group_shape(
                        wire_geometries,
                        logical_verifier_move_ordinal,
                        distinct_query_group_ordinal,
                    )?;
                    if domain_cardinality != component.leaf_count
                        || query_count != component.minimum_queried_leaf_count
                        || query_count != component.maximum_queried_leaf_count
                    {
                        return Err(CompactResponseMerkleError::InvalidOpeningIndices);
                    }
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    first_distinct_query_group_ordinal,
                    second_logical_verifier_move_ordinal,
                    second_distinct_query_group_ordinal,
                } => {
                    let (first_domain_cardinality, first_query_count) = query_group_shape(
                        wire_geometries,
                        first_logical_verifier_move_ordinal,
                        first_distinct_query_group_ordinal,
                    )?;
                    let (second_domain_cardinality, second_query_count) = query_group_shape(
                        wire_geometries,
                        second_logical_verifier_move_ordinal,
                        second_distinct_query_group_ordinal,
                    )?;
                    let combined_query_count = first_query_count
                        .checked_add(second_query_count)
                        .ok_or(CompactResponseMerkleError::CountOverflow)?;
                    let minimum_union_count = combined_query_count
                        .saturating_sub(component.leaf_count)
                        .max(first_query_count)
                        .max(second_query_count);
                    let maximum_union_count = combined_query_count.min(component.leaf_count);
                    if first_domain_cardinality != component.leaf_count
                        || second_domain_cardinality != component.leaf_count
                        || component.minimum_queried_leaf_count != minimum_union_count
                        || component.maximum_queried_leaf_count != maximum_union_count
                    {
                        return Err(CompactResponseMerkleError::InvalidOpeningIndices);
                    }
                }
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf => {}
            }
        }
        Ok(())
    }

    pub(crate) fn last_query_verifier_move_ordinal(&self) -> u32 {
        self.components
            .iter()
            .filter_map(|component| match component.query_selection {
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    ..
                } => Some(logical_verifier_move_ordinal),
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    second_logical_verifier_move_ordinal,
                    ..
                } => Some(
                    first_logical_verifier_move_ordinal.max(second_logical_verifier_move_ordinal),
                ),
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf => None,
            })
            .fold(self.response_ordinal, u32::max)
    }

    pub(crate) fn has_verifier_message_queries(&self) -> bool {
        self.components.iter().any(|component| {
            matches!(
                component.query_selection,
                CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. }
                    | CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion { .. }
            )
        })
    }
}

fn wire_geometry_for_logical_move(
    wire_geometries: &[CompactProofResponseWireGeometry],
    logical_verifier_move_ordinal: u32,
) -> Result<&CompactProofResponseWireGeometry, CompactResponseMerkleError> {
    let move_index = usize::try_from(logical_verifier_move_ordinal)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    let wire_geometry = wire_geometries
        .get(move_index)
        .ok_or(CompactResponseMerkleError::InvalidOpeningIndices)?;
    if wire_geometry.ordinal() != logical_verifier_move_ordinal {
        return Err(CompactResponseMerkleError::InvalidOpeningIndices);
    }
    Ok(wire_geometry)
}

fn query_group_shape(
    wire_geometries: &[CompactProofResponseWireGeometry],
    logical_verifier_move_ordinal: u32,
    distinct_query_group_ordinal: u32,
) -> Result<(u64, u64), CompactResponseMerkleError> {
    let source_wire_geometry =
        wire_geometry_for_logical_move(wire_geometries, logical_verifier_move_ordinal)?;
    let group_index = usize::try_from(distinct_query_group_ordinal)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    let group = source_wire_geometry
        .verifier_message_geometry()
        .distinct_query_groups()
        .get(group_index)
        .ok_or(CompactResponseMerkleError::InvalidOpeningIndices)?;
    Ok((group.domain_cardinality(), group.query_count()))
}

/// Canonical global response-leaf coordinates selected by the complete decoded
/// verifier-message registry. Full components are opened deterministically;
/// every proper subset names its verifier move and distinct-query group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseQuerySchedule {
    leaf_ordinals: Vec<u64>,
}

impl CompactResponseQuerySchedule {
    pub(crate) fn validate_geometry(
        merkle_geometry: &CompactResponseMerkleGeometry,
        wire_geometries: &[CompactProofResponseWireGeometry],
    ) -> Result<(), CompactResponseMerkleError> {
        merkle_geometry.validate_query_source_geometry(wire_geometries)
    }

    pub(crate) fn validate_registry(
        merkle_geometries: &[CompactResponseMerkleGeometry],
        wire_geometries: &[CompactProofResponseWireGeometry],
    ) -> Result<(), CompactResponseMerkleError> {
        if merkle_geometries.is_empty() || merkle_geometries.len() != wire_geometries.len() {
            return Err(CompactResponseMerkleError::InvalidGeometry);
        }
        let mut referenced_query_groups = wire_geometries
            .iter()
            .enumerate()
            .map(|(move_index, wire_geometry)| {
                if usize::try_from(wire_geometry.ordinal()).ok() != Some(move_index) {
                    return Err(CompactResponseMerkleError::InvalidGeometry);
                }
                Ok(vec![
                    false;
                    wire_geometry
                        .verifier_message_geometry()
                        .distinct_query_groups()
                        .len()
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (response_index, merkle_geometry) in merkle_geometries.iter().enumerate() {
            if usize::try_from(merkle_geometry.response_ordinal()).ok() != Some(response_index) {
                return Err(CompactResponseMerkleError::InvalidGeometry);
            }
            Self::validate_geometry(merkle_geometry, wire_geometries)?;
            for component in &merkle_geometry.components {
                match component.query_selection {
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal,
                        distinct_query_group_ordinal,
                    } => mark_query_group_referenced(
                        &mut referenced_query_groups,
                        logical_verifier_move_ordinal,
                        distinct_query_group_ordinal,
                    )?,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                        first_logical_verifier_move_ordinal,
                        first_distinct_query_group_ordinal,
                        second_logical_verifier_move_ordinal,
                        second_distinct_query_group_ordinal,
                    } => {
                        mark_query_group_referenced(
                            &mut referenced_query_groups,
                            first_logical_verifier_move_ordinal,
                            first_distinct_query_group_ordinal,
                        )?;
                        mark_query_group_referenced(
                            &mut referenced_query_groups,
                            second_logical_verifier_move_ordinal,
                            second_distinct_query_group_ordinal,
                        )?;
                    }
                    CompactResponseQuerySelection::Unqueried
                    | CompactResponseQuerySelection::EveryLeaf => {}
                }
            }
        }
        if referenced_query_groups
            .iter()
            .flatten()
            .any(|referenced| !referenced)
        {
            return Err(CompactResponseMerkleError::InvalidOpeningIndices);
        }
        Ok(())
    }

    pub(crate) fn derive(
        merkle_geometry: &CompactResponseMerkleGeometry,
        wire_geometries: &[CompactProofResponseWireGeometry],
        verifier_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> Result<Self, CompactResponseMerkleError> {
        Self::validate_geometry(merkle_geometry, wire_geometries)?;
        if verifier_messages.len() != wire_geometries.len() {
            return Err(CompactResponseMerkleError::InvalidOpeningIndices);
        }
        for (wire_geometry, verifier_message) in wire_geometries.iter().zip(verifier_messages) {
            let decoded_query_groups = verifier_message.distinct_query_groups();
            let query_group_geometries = wire_geometry
                .verifier_message_geometry()
                .distinct_query_groups();
            if decoded_query_groups.len() != query_group_geometries.len()
                || decoded_query_groups.iter().zip(query_group_geometries).any(
                    |(decoded_group, group_geometry)| {
                        u64::try_from(decoded_group.len()).ok()
                            != Some(group_geometry.query_count())
                            || decoded_group.windows(2).any(|pair| pair[0] >= pair[1])
                            || decoded_group.last().is_some_and(|ordinal| {
                                *ordinal >= group_geometry.domain_cardinality()
                            })
                    },
                )
            {
                return Err(CompactResponseMerkleError::InvalidOpeningIndices);
            }
        }

        let maximum_queried_leaf_count =
            usize::try_from(merkle_geometry.maximum_queried_leaf_count)
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let mut leaf_ordinals = Vec::new();
        leaf_ordinals
            .try_reserve_exact(maximum_queried_leaf_count)
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        if leaf_ordinals.capacity() != maximum_queried_leaf_count {
            return Err(CompactResponseMerkleError::CountOverflow);
        }

        for component in &merkle_geometry.components {
            if component.query_selection == CompactResponseQuerySelection::Unqueried {
                continue;
            }
            if component.query_selection == CompactResponseQuerySelection::EveryLeaf {
                let component_end = component
                    .first_leaf_ordinal
                    .checked_add(component.leaf_count)
                    .ok_or(CompactResponseMerkleError::CountOverflow)?;
                leaf_ordinals.extend(component.first_leaf_ordinal..component_end);
                continue;
            }

            match component.query_selection {
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    distinct_query_group_ordinal,
                } => {
                    let decoded_group = decoded_query_group(
                        verifier_messages,
                        logical_verifier_move_ordinal,
                        distinct_query_group_ordinal,
                    )?;
                    append_component_query_group(&mut leaf_ordinals, component, decoded_group)?;
                }
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    first_distinct_query_group_ordinal,
                    second_logical_verifier_move_ordinal,
                    second_distinct_query_group_ordinal,
                } => {
                    let first_group = decoded_query_group(
                        verifier_messages,
                        first_logical_verifier_move_ordinal,
                        first_distinct_query_group_ordinal,
                    )?;
                    let second_group = decoded_query_group(
                        verifier_messages,
                        second_logical_verifier_move_ordinal,
                        second_distinct_query_group_ordinal,
                    )?;
                    append_component_query_union(
                        &mut leaf_ordinals,
                        component,
                        first_group,
                        second_group,
                    )?;
                }
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf => {
                    return Err(CompactResponseMerkleError::InvalidGeometry);
                }
            }
        }
        merkle_geometry.validate_query_leaf_ordinals(&leaf_ordinals)?;
        Ok(Self { leaf_ordinals })
    }

    pub(crate) fn as_slice(&self) -> &[u64] {
        &self.leaf_ordinals
    }

    pub(crate) fn owned_heap_byte_length(&self) -> Result<u64, CompactResponseMerkleError> {
        u64::try_from(self.leaf_ordinals.capacity())
            .ok()
            .and_then(|count| {
                u64::try_from(size_of::<u64>())
                    .ok()
                    .and_then(|byte_length| count.checked_mul(byte_length))
            })
            .ok_or(CompactResponseMerkleError::CountOverflow)
    }
}

fn decoded_query_group(
    verifier_messages: &[DecodedFixedUniformVerifierMessage],
    logical_verifier_move_ordinal: u32,
    distinct_query_group_ordinal: u32,
) -> Result<&[u64], CompactResponseMerkleError> {
    let move_index = usize::try_from(logical_verifier_move_ordinal)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    let group_index = usize::try_from(distinct_query_group_ordinal)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    verifier_messages
        .get(move_index)
        .and_then(|message| message.distinct_query_groups().get(group_index))
        .map(Vec::as_slice)
        .ok_or(CompactResponseMerkleError::InvalidOpeningIndices)
}

fn append_component_query_group(
    leaf_ordinals: &mut Vec<u64>,
    component: &CompactResponseComponentGeometry,
    decoded_group: &[u64],
) -> Result<(), CompactResponseMerkleError> {
    if u64::try_from(decoded_group.len()).ok() != Some(component.minimum_queried_leaf_count)
        || component.minimum_queried_leaf_count != component.maximum_queried_leaf_count
        || decoded_group.windows(2).any(|pair| pair[0] >= pair[1])
        || decoded_group
            .last()
            .is_some_and(|ordinal| *ordinal >= component.leaf_count)
    {
        return Err(CompactResponseMerkleError::InvalidOpeningIndices);
    }
    for component_leaf_ordinal in decoded_group {
        leaf_ordinals.push(
            component
                .first_leaf_ordinal
                .checked_add(*component_leaf_ordinal)
                .ok_or(CompactResponseMerkleError::CountOverflow)?,
        );
    }
    Ok(())
}

fn append_component_query_union(
    leaf_ordinals: &mut Vec<u64>,
    component: &CompactResponseComponentGeometry,
    first_group: &[u64],
    second_group: &[u64],
) -> Result<(), CompactResponseMerkleError> {
    if first_group.windows(2).any(|pair| pair[0] >= pair[1])
        || second_group.windows(2).any(|pair| pair[0] >= pair[1])
        || first_group
            .last()
            .is_some_and(|ordinal| *ordinal >= component.leaf_count)
        || second_group
            .last()
            .is_some_and(|ordinal| *ordinal >= component.leaf_count)
    {
        return Err(CompactResponseMerkleError::InvalidOpeningIndices);
    }
    let union_start = leaf_ordinals.len();
    let mut first_offset = 0_usize;
    let mut second_offset = 0_usize;
    while first_offset < first_group.len() || second_offset < second_group.len() {
        let next_component_leaf_ordinal = match (
            first_group.get(first_offset),
            second_group.get(second_offset),
        ) {
            (Some(first), Some(second)) if first < second => {
                first_offset += 1;
                *first
            }
            (Some(first), Some(second)) if second < first => {
                second_offset += 1;
                *second
            }
            (Some(first), Some(_)) => {
                first_offset += 1;
                second_offset += 1;
                *first
            }
            (Some(first), None) => {
                first_offset += 1;
                *first
            }
            (None, Some(second)) => {
                second_offset += 1;
                *second
            }
            (None, None) => break,
        };
        leaf_ordinals.push(
            component
                .first_leaf_ordinal
                .checked_add(next_component_leaf_ordinal)
                .ok_or(CompactResponseMerkleError::CountOverflow)?,
        );
    }
    let union_count = u64::try_from(leaf_ordinals.len() - union_start)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    if !(component.minimum_queried_leaf_count..=component.maximum_queried_leaf_count)
        .contains(&union_count)
    {
        return Err(CompactResponseMerkleError::InvalidOpeningIndices);
    }
    Ok(())
}

fn mark_query_group_referenced(
    referenced_query_groups: &mut [Vec<bool>],
    logical_verifier_move_ordinal: u32,
    distinct_query_group_ordinal: u32,
) -> Result<(), CompactResponseMerkleError> {
    let move_index = usize::try_from(logical_verifier_move_ordinal)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    let group_index = usize::try_from(distinct_query_group_ordinal)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    let referenced = referenced_query_groups
        .get_mut(move_index)
        .and_then(|groups| groups.get_mut(group_index))
        .ok_or(CompactResponseMerkleError::InvalidOpeningIndices)?;
    *referenced = true;
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum CompactResponseLeafValue<'value> {
    BaseField(&'value [ProofBaseFieldElement]),
    ExtensionField(&'value [ProofChallengeExtensionElement]),
    Padding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactResponseLeafDescriptor {
    component_ordinal: u32,
    component_leaf_ordinal: u64,
    leaf_ordinal: u64,
    value_kind: CompactResponseLeafValueKind,
    field_element_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactResponseMerkleError {
    InvalidGeometry,
    CountOverflow,
    CanonicalEncoding,
    WireGeometryMismatch,
    InvalidOpeningIndices,
    WrongLeafValueKind,
    WrongLeafValueCount,
    WrongFrontierLength,
    IncompleteFrontier,
    RootMismatch,
    InvalidWireValue,
    OutputChunkPending,
    OutputChunkUnavailable,
    WriterIncomplete,
    WrongTreeChunk,
    ScannerIncomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponsePostorderWriterHeapGeometry {
    output_chunk_byte_length: u64,
    pending_left_digest_byte_length: u64,
    pending_emitted_digest_byte_length: u64,
    maximum_owned_heap_byte_length: u64,
}

impl CompactResponsePostorderWriterHeapGeometry {
    pub(crate) fn derive(
        geometry: &CompactResponseMerkleGeometry,
    ) -> Result<Self, CompactResponseMerkleError> {
        let tree_depth = u64::from(geometry.merkle_leaf_count.trailing_zeros());
        let digest_byte_length = u64::try_from(Hash512::BYTE_LENGTH)
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let output_chunk_byte_length =
            u64::try_from(COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH)
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let pending_left_digest_byte_length = tree_depth
            .checked_mul(digest_byte_length)
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        let pending_emitted_digest_byte_length = tree_depth
            .checked_add(1)
            .and_then(|count| count.checked_mul(digest_byte_length))
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        let maximum_owned_heap_byte_length = output_chunk_byte_length
            .checked_add(pending_left_digest_byte_length)
            .and_then(|length| length.checked_add(pending_emitted_digest_byte_length))
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        Ok(Self {
            output_chunk_byte_length,
            pending_left_digest_byte_length,
            pending_emitted_digest_byte_length,
            maximum_owned_heap_byte_length,
        })
    }

    pub(crate) const fn output_chunk_byte_length(self) -> u64 {
        self.output_chunk_byte_length
    }

    pub(crate) const fn pending_left_digest_byte_length(self) -> u64 {
        self.pending_left_digest_byte_length
    }

    pub(crate) const fn pending_emitted_digest_byte_length(self) -> u64 {
        self.pending_emitted_digest_byte_length
    }

    pub(crate) const fn maximum_owned_heap_byte_length(self) -> u64 {
        self.maximum_owned_heap_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseFrontierScannerHeapGeometry {
    scan_target_byte_length: u64,
    frontier_digest_byte_length: u64,
    maximum_owned_heap_byte_length: u64,
}

impl CompactResponseFrontierScannerHeapGeometry {
    pub(crate) fn derive(
        maximum_frontier_node_count: u64,
    ) -> Result<Self, CompactResponseMerkleError> {
        let scan_target_element_byte_length = 2_u64
            .checked_mul(
                u64::try_from(size_of::<u64>())
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            )
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        let scan_target_byte_length = maximum_frontier_node_count
            .checked_mul(scan_target_element_byte_length)
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        let frontier_digest_byte_length = maximum_frontier_node_count
            .checked_mul(
                u64::try_from(Hash512::BYTE_LENGTH)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            )
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        let maximum_owned_heap_byte_length = scan_target_byte_length
            .checked_add(frontier_digest_byte_length)
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        Ok(Self {
            scan_target_byte_length,
            frontier_digest_byte_length,
            maximum_owned_heap_byte_length,
        })
    }

    pub(crate) const fn scan_target_byte_length(self) -> u64 {
        self.scan_target_byte_length
    }

    pub(crate) const fn frontier_digest_byte_length(self) -> u64 {
        self.frontier_digest_byte_length
    }

    pub(crate) const fn maximum_owned_heap_byte_length(self) -> u64 {
        self.maximum_owned_heap_byte_length
    }
}

/// Streams one complete response tree in canonical postorder.
///
/// A full output chunk must be durably appended before another leaf is
/// accepted. `acknowledge_output_chunk` is therefore called only after the
/// surrounding external-memory transaction has committed successfully.
pub(crate) struct CompactResponsePostorderMerkleWriter<'geometry> {
    geometry: &'geometry CompactResponseMerkleGeometry,
    pending_left_digests: Vec<[u8; Hash512::BYTE_LENGTH]>,
    occupied_level_mask: u64,
    pending_emitted_digests: Vec<[u8; Hash512::BYTE_LENGTH]>,
    pending_emitted_digest_offset: usize,
    output_chunk: Vec<u8>,
    output_chunk_byte_length: usize,
    absorbed_leaf_count: u64,
    acknowledged_tree_byte_length: u64,
    root: Option<[u8; Hash512::BYTE_LENGTH]>,
}

impl<'geometry> CompactResponsePostorderMerkleWriter<'geometry> {
    pub(crate) fn new(
        geometry: &'geometry CompactResponseMerkleGeometry,
    ) -> Result<Self, CompactResponseMerkleError> {
        Self::new_with_chunk_byte_length(geometry, COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH)
    }

    fn new_with_chunk_byte_length(
        geometry: &'geometry CompactResponseMerkleGeometry,
        output_chunk_byte_length: usize,
    ) -> Result<Self, CompactResponseMerkleError> {
        let tree_depth = usize::try_from(geometry.merkle_leaf_count.trailing_zeros())
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        if tree_depth >= u64::BITS as usize
            || output_chunk_byte_length == 0
            || !output_chunk_byte_length.is_multiple_of(Hash512::BYTE_LENGTH)
        {
            return Err(CompactResponseMerkleError::InvalidGeometry);
        }
        let mut pending_left_digests = Vec::new();
        pending_left_digests
            .try_reserve_exact(tree_depth)
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        pending_left_digests.resize(tree_depth, [0_u8; Hash512::BYTE_LENGTH]);
        let mut pending_emitted_digests = Vec::new();
        pending_emitted_digests
            .try_reserve_exact(
                tree_depth
                    .checked_add(1)
                    .ok_or(CompactResponseMerkleError::CountOverflow)?,
            )
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let mut output_chunk = Vec::new();
        output_chunk
            .try_reserve_exact(output_chunk_byte_length)
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        Ok(Self {
            geometry,
            pending_left_digests,
            occupied_level_mask: 0,
            pending_emitted_digests,
            pending_emitted_digest_offset: 0,
            output_chunk,
            output_chunk_byte_length,
            absorbed_leaf_count: 0,
            acknowledged_tree_byte_length: 0,
            root: None,
        })
    }

    pub(crate) fn absorb_leaf(
        &mut self,
        value: CompactResponseLeafValue<'_>,
        leaf_salt: &[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
    ) -> Result<(), CompactResponseMerkleError> {
        if self.output_chunk().is_some()
            || self.pending_emitted_digest_offset < self.pending_emitted_digests.len()
        {
            return Err(CompactResponseMerkleError::OutputChunkPending);
        }
        if self.absorbed_leaf_count >= self.geometry.merkle_leaf_count || self.root.is_some() {
            return Err(CompactResponseMerkleError::WriterIncomplete);
        }

        let mut current_digest = compact_response_leaf_digest(
            self.geometry,
            self.absorbed_leaf_count,
            value,
            leaf_salt,
        )?;
        self.pending_emitted_digests.clear();
        self.pending_emitted_digest_offset = 0;
        self.pending_emitted_digests.push(current_digest);
        let mut current_node_ordinal = self.absorbed_leaf_count;
        let mut level = 0_usize;
        while level < self.pending_left_digests.len()
            && self.occupied_level_mask & (1_u64 << level) != 0
        {
            current_digest = compact_response_merkle_parent_digest(
                self.geometry,
                u32::try_from(level + 1).map_err(|_| CompactResponseMerkleError::CountOverflow)?,
                (current_node_ordinal >> 1) << 1,
                self.pending_left_digests[level],
                current_digest,
            )?;
            self.pending_emitted_digests.push(current_digest);
            self.occupied_level_mask &= !(1_u64 << level);
            current_node_ordinal >>= 1;
            level += 1;
        }
        self.absorbed_leaf_count = self
            .absorbed_leaf_count
            .checked_add(1)
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        if level == self.pending_left_digests.len() {
            if self.absorbed_leaf_count != self.geometry.merkle_leaf_count
                || self.occupied_level_mask != 0
            {
                return Err(CompactResponseMerkleError::WriterIncomplete);
            }
            self.root = Some(current_digest);
        } else {
            self.pending_left_digests[level] = current_digest;
            self.occupied_level_mask |= 1_u64 << level;
        }
        self.drain_pending_digests()
    }

    pub(crate) fn output_chunk(&self) -> Option<&[u8]> {
        if self.output_chunk.len() == self.output_chunk_byte_length
            || (self.root.is_some()
                && self.pending_emitted_digest_offset == self.pending_emitted_digests.len()
                && !self.output_chunk.is_empty())
        {
            Some(&self.output_chunk)
        } else {
            None
        }
    }

    pub(crate) fn acknowledge_output_chunk(&mut self) -> Result<(), CompactResponseMerkleError> {
        let output_byte_length = self
            .output_chunk()
            .map(<[u8]>::len)
            .ok_or(CompactResponseMerkleError::OutputChunkUnavailable)?;
        self.acknowledged_tree_byte_length = self
            .acknowledged_tree_byte_length
            .checked_add(
                u64::try_from(output_byte_length)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            )
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        self.output_chunk.clear();
        self.drain_pending_digests()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.absorbed_leaf_count == self.geometry.merkle_leaf_count
            && self.occupied_level_mask == 0
            && self.pending_emitted_digest_offset == self.pending_emitted_digests.len()
            && self.output_chunk.is_empty()
            && self.root.is_some()
            && expected_postorder_tree_byte_length(self.geometry)
                .is_ok_and(|expected| expected == self.acknowledged_tree_byte_length)
    }

    pub(crate) fn finish(self) -> Result<[u8; Hash512::BYTE_LENGTH], CompactResponseMerkleError> {
        if !self.is_complete() {
            return Err(CompactResponseMerkleError::WriterIncomplete);
        }
        self.root
            .ok_or(CompactResponseMerkleError::WriterIncomplete)
    }

    fn drain_pending_digests(&mut self) -> Result<(), CompactResponseMerkleError> {
        while self.pending_emitted_digest_offset < self.pending_emitted_digests.len()
            && self.output_chunk.len() < self.output_chunk_byte_length
        {
            self.output_chunk.extend_from_slice(
                &self.pending_emitted_digests[self.pending_emitted_digest_offset],
            );
            self.pending_emitted_digest_offset += 1;
        }
        if self.output_chunk.len() > self.output_chunk_byte_length {
            return Err(CompactResponseMerkleError::CountOverflow);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactResponseFrontierScanTarget {
    postorder_digest_ordinal: u64,
    canonical_frontier_ordinal: u64,
}

/// Extracts a canonical minimal frontier from sequential postorder tree bytes.
pub(crate) struct CompactResponsePostorderFrontierScanner {
    targets: Vec<CompactResponseFrontierScanTarget>,
    frontier: Vec<[u8; Hash512::BYTE_LENGTH]>,
    next_target_offset: usize,
    consumed_tree_byte_length: u64,
    expected_tree_byte_length: u64,
    input_chunk_byte_length: usize,
}

impl CompactResponsePostorderFrontierScanner {
    pub(crate) fn new(
        geometry: &CompactResponseMerkleGeometry,
        query_leaf_ordinals: &[u64],
    ) -> Result<Self, CompactResponseMerkleError> {
        Self::new_with_chunk_byte_length(
            geometry,
            query_leaf_ordinals,
            COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH,
        )
    }

    fn new_with_chunk_byte_length(
        geometry: &CompactResponseMerkleGeometry,
        query_leaf_ordinals: &[u64],
        input_chunk_byte_length: usize,
    ) -> Result<Self, CompactResponseMerkleError> {
        geometry.validate_query_leaf_ordinals(query_leaf_ordinals)?;
        if input_chunk_byte_length == 0
            || !input_chunk_byte_length.is_multiple_of(Hash512::BYTE_LENGTH)
        {
            return Err(CompactResponseMerkleError::InvalidGeometry);
        }
        let leaf_count = usize::try_from(geometry.merkle_leaf_count)
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let coordinates = minimal_frontier_coordinates(query_leaf_ordinals, leaf_count)
            .map_err(|_| CompactResponseMerkleError::InvalidOpeningIndices)?;
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(coordinates.len())
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        for (canonical_frontier_ordinal, (level, node_ordinal)) in
            coordinates.into_iter().enumerate()
        {
            targets.push(CompactResponseFrontierScanTarget {
                postorder_digest_ordinal: compact_response_postorder_digest_ordinal(
                    geometry,
                    level,
                    node_ordinal,
                )?,
                canonical_frontier_ordinal: u64::try_from(canonical_frontier_ordinal)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            });
        }
        targets.sort_unstable_by_key(|target| target.postorder_digest_ordinal);
        if targets
            .windows(2)
            .any(|pair| pair[0].postorder_digest_ordinal >= pair[1].postorder_digest_ordinal)
        {
            return Err(CompactResponseMerkleError::InvalidOpeningIndices);
        }
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(targets.len())
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        frontier.resize(targets.len(), [0_u8; Hash512::BYTE_LENGTH]);
        Ok(Self {
            targets,
            frontier,
            next_target_offset: 0,
            consumed_tree_byte_length: 0,
            expected_tree_byte_length: expected_postorder_tree_byte_length(geometry)?,
            input_chunk_byte_length,
        })
    }

    pub(crate) fn absorb_tree_chunk(
        &mut self,
        tree_chunk: &[u8],
    ) -> Result<(), CompactResponseMerkleError> {
        let remaining_byte_length = self
            .expected_tree_byte_length
            .checked_sub(self.consumed_tree_byte_length)
            .ok_or(CompactResponseMerkleError::WrongTreeChunk)?;
        let expected_chunk_byte_length = usize::try_from(
            remaining_byte_length.min(
                u64::try_from(self.input_chunk_byte_length)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            ),
        )
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        if tree_chunk.len() != expected_chunk_byte_length
            || !tree_chunk.len().is_multiple_of(Hash512::BYTE_LENGTH)
        {
            return Err(CompactResponseMerkleError::WrongTreeChunk);
        }
        let first_digest_ordinal = self.consumed_tree_byte_length
            / u64::try_from(Hash512::BYTE_LENGTH)
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let digest_count = u64::try_from(tree_chunk.len() / Hash512::BYTE_LENGTH)
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let past_last_digest_ordinal = first_digest_ordinal
            .checked_add(digest_count)
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        while let Some(target) = self.targets.get(self.next_target_offset).copied()
            && target.postorder_digest_ordinal < past_last_digest_ordinal
        {
            if target.postorder_digest_ordinal < first_digest_ordinal {
                return Err(CompactResponseMerkleError::ScannerIncomplete);
            }
            let chunk_digest_ordinal =
                usize::try_from(target.postorder_digest_ordinal - first_digest_ordinal)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
            let byte_offset = chunk_digest_ordinal
                .checked_mul(Hash512::BYTE_LENGTH)
                .ok_or(CompactResponseMerkleError::CountOverflow)?;
            let digest: [u8; Hash512::BYTE_LENGTH] = tree_chunk
                .get(byte_offset..byte_offset + Hash512::BYTE_LENGTH)
                .ok_or(CompactResponseMerkleError::WrongTreeChunk)?
                .try_into()
                .map_err(|_| CompactResponseMerkleError::WrongTreeChunk)?;
            self.frontier[usize::try_from(target.canonical_frontier_ordinal)
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?] = digest;
            self.next_target_offset += 1;
        }
        self.consumed_tree_byte_length = self
            .consumed_tree_byte_length
            .checked_add(
                u64::try_from(tree_chunk.len())
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?,
            )
            .ok_or(CompactResponseMerkleError::CountOverflow)?;
        Ok(())
    }

    pub(crate) fn remaining_tree_byte_length(&self) -> Result<u64, CompactResponseMerkleError> {
        self.expected_tree_byte_length
            .checked_sub(self.consumed_tree_byte_length)
            .ok_or(CompactResponseMerkleError::WrongTreeChunk)
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.consumed_tree_byte_length == self.expected_tree_byte_length
            && self.next_target_offset == self.targets.len()
    }

    pub(crate) fn finish(
        self,
    ) -> Result<Vec<[u8; Hash512::BYTE_LENGTH]>, CompactResponseMerkleError> {
        if !self.is_complete() {
            return Err(CompactResponseMerkleError::ScannerIncomplete);
        }
        Ok(self.frontier)
    }
}

pub(crate) fn expected_postorder_tree_byte_length(
    geometry: &CompactResponseMerkleGeometry,
) -> Result<u64, CompactResponseMerkleError> {
    geometry
        .merkle_leaf_count
        .checked_mul(2)
        .and_then(|digest_count| digest_count.checked_sub(1))
        .and_then(|digest_count| {
            digest_count.checked_mul(u64::try_from(Hash512::BYTE_LENGTH).ok()?)
        })
        .ok_or(CompactResponseMerkleError::CountOverflow)
}

fn compact_response_postorder_digest_ordinal(
    geometry: &CompactResponseMerkleGeometry,
    level: u32,
    node_ordinal: u64,
) -> Result<u64, CompactResponseMerkleError> {
    let tree_depth = geometry.merkle_leaf_count.trailing_zeros();
    if level > tree_depth || node_ordinal >= geometry.merkle_leaf_count >> level {
        return Err(CompactResponseMerkleError::InvalidGeometry);
    }
    node_ordinal
        .checked_add(1)
        .and_then(|count| count.checked_shl(level + 1))
        .and_then(|ordinal| ordinal.checked_sub(2))
        .and_then(|ordinal| ordinal.checked_sub(u64::from(node_ordinal.count_ones())))
        .ok_or(CompactResponseMerkleError::CountOverflow)
}

pub(crate) fn compact_response_leaf_digest(
    geometry: &CompactResponseMerkleGeometry,
    leaf_ordinal: u64,
    value: CompactResponseLeafValue<'_>,
    leaf_salt: &[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
) -> Result<[u8; Hash512::BYTE_LENGTH], CompactResponseMerkleError> {
    let descriptor = geometry.leaf_descriptor(leaf_ordinal)?;
    let mut canonical_value_bytes = Vec::new();
    match (descriptor.value_kind, value) {
        (CompactResponseLeafValueKind::BaseField, CompactResponseLeafValue::BaseField(values)) => {
            if u64::try_from(values.len()).ok() != Some(descriptor.field_element_count) {
                return Err(CompactResponseMerkleError::WrongLeafValueCount);
            }
            canonical_value_bytes
                .try_reserve_exact(
                    values
                        .len()
                        .checked_mul(size_of::<u64>())
                        .ok_or(CompactResponseMerkleError::CountOverflow)?,
                )
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
            for value in values {
                canonical_value_bytes.extend_from_slice(&value.canonical().to_le_bytes());
            }
        }
        (
            CompactResponseLeafValueKind::ExtensionField,
            CompactResponseLeafValue::ExtensionField(values),
        ) => {
            if u64::try_from(values.len()).ok() != Some(descriptor.field_element_count) {
                return Err(CompactResponseMerkleError::WrongLeafValueCount);
            }
            canonical_value_bytes
                .try_reserve_exact(
                    values
                        .len()
                        .checked_mul(PROOF_CHALLENGE_EXTENSION_DEGREE)
                        .and_then(|count| count.checked_mul(size_of::<u64>()))
                        .ok_or(CompactResponseMerkleError::CountOverflow)?,
                )
                .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
            for value in values {
                for coordinate in value.canonical_coordinates() {
                    canonical_value_bytes.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
        }
        (CompactResponseLeafValueKind::Padding, CompactResponseLeafValue::Padding) => {}
        _ => return Err(CompactResponseMerkleError::WrongLeafValueKind),
    }

    hash_foundation_tuple_512(
        COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
        &[
            CanonicalItem::unsigned32(geometry.response_ordinal),
            CanonicalItem::unsigned32(geometry.vector_commitment_oracle_identifier),
            CanonicalItem::unsigned32(descriptor.component_ordinal),
            CanonicalItem::unsigned64(descriptor.component_leaf_ordinal),
            CanonicalItem::unsigned64(descriptor.leaf_ordinal),
            CanonicalItem::unsigned16(descriptor.value_kind as u16),
            CanonicalItem::unsigned64(descriptor.field_element_count),
            CanonicalItem::variable_bytes(canonical_value_bytes)
                .map_err(|_| CompactResponseMerkleError::CanonicalEncoding)?,
            CanonicalItem::fixed_bytes(leaf_salt)
                .map_err(|_| CompactResponseMerkleError::CanonicalEncoding)?,
        ],
    )
    .map(Hash512::into_bytes)
    .map_err(|_| CompactResponseMerkleError::CanonicalEncoding)
}

pub(crate) fn compact_response_merkle_parent_digest(
    geometry: &CompactResponseMerkleGeometry,
    parent_level: u32,
    left_child_ordinal: u64,
    left_child_digest: [u8; Hash512::BYTE_LENGTH],
    right_child_digest: [u8; Hash512::BYTE_LENGTH],
) -> Result<[u8; Hash512::BYTE_LENGTH], CompactResponseMerkleError> {
    let tree_depth = geometry.merkle_leaf_count.trailing_zeros();
    if parent_level == 0 || parent_level > tree_depth {
        return Err(CompactResponseMerkleError::InvalidGeometry);
    }
    let child_count = geometry
        .merkle_leaf_count
        .checked_shr(parent_level - 1)
        .ok_or(CompactResponseMerkleError::InvalidGeometry)?;
    if left_child_ordinal & 1 != 0
        || left_child_ordinal
            .checked_add(1)
            .is_none_or(|right_child_ordinal| right_child_ordinal >= child_count)
    {
        return Err(CompactResponseMerkleError::InvalidGeometry);
    }
    hash_foundation_tuple_512(
        COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
        &[
            CanonicalItem::unsigned32(geometry.response_ordinal),
            CanonicalItem::unsigned32(geometry.vector_commitment_oracle_identifier),
            CanonicalItem::unsigned32(parent_level),
            CanonicalItem::unsigned64(left_child_ordinal),
            CanonicalItem::hash512(left_child_digest),
            CanonicalItem::hash512(right_child_digest),
        ],
    )
    .map(Hash512::into_bytes)
    .map_err(|_| CompactResponseMerkleError::CanonicalEncoding)
}

pub(crate) fn verify_decoded_compact_response_opening(
    merkle_geometry: &CompactResponseMerkleGeometry,
    wire_geometry: &CompactProofResponseWireGeometry,
    decoded_response: &DecodedCompactProofResponse,
    canonical_proof_bytes: &[u8],
    query_leaf_ordinals: &[u64],
) -> Result<(), CompactResponseMerkleError> {
    merkle_geometry.validate_wire_geometry(wire_geometry)?;
    merkle_geometry.validate_query_leaf_ordinals(query_leaf_ordinals)?;
    if decoded_response.ordinal() != merkle_geometry.response_ordinal
        || decoded_response.queried_leaf_count() != query_leaf_ordinals.len()
    {
        return Err(CompactResponseMerkleError::WireGeometryMismatch);
    }

    let mut base_field_value_offset = 0_usize;
    let mut extension_field_value_offset = 0_usize;
    let mut opened_leaf_digests = Vec::new();
    opened_leaf_digests
        .try_reserve_exact(query_leaf_ordinals.len())
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    for (query_ordinal, leaf_ordinal) in query_leaf_ordinals.iter().copied().enumerate() {
        let descriptor = merkle_geometry.leaf_descriptor(leaf_ordinal)?;
        let leaf_salt = decoded_response
            .leaf_salt(canonical_proof_bytes, query_ordinal)
            .map_err(map_wire_error)?;
        let digest = match descriptor.value_kind {
            CompactResponseLeafValueKind::BaseField => {
                let value_count = usize::try_from(descriptor.field_element_count)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(value_count)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
                for value_ordinal in base_field_value_offset
                    ..base_field_value_offset
                        .checked_add(value_count)
                        .ok_or(CompactResponseMerkleError::CountOverflow)?
                {
                    values.push(
                        decoded_response
                            .base_field_value(canonical_proof_bytes, value_ordinal)
                            .map_err(map_wire_error)?,
                    );
                }
                base_field_value_offset = base_field_value_offset
                    .checked_add(value_count)
                    .ok_or(CompactResponseMerkleError::CountOverflow)?;
                compact_response_leaf_digest(
                    merkle_geometry,
                    leaf_ordinal,
                    CompactResponseLeafValue::BaseField(&values),
                    &leaf_salt,
                )?
            }
            CompactResponseLeafValueKind::ExtensionField => {
                let value_count = usize::try_from(descriptor.field_element_count)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(value_count)
                    .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
                for value_ordinal in extension_field_value_offset
                    ..extension_field_value_offset
                        .checked_add(value_count)
                        .ok_or(CompactResponseMerkleError::CountOverflow)?
                {
                    values.push(
                        decoded_response
                            .extension_field_value(canonical_proof_bytes, value_ordinal)
                            .map_err(map_wire_error)?,
                    );
                }
                extension_field_value_offset = extension_field_value_offset
                    .checked_add(value_count)
                    .ok_or(CompactResponseMerkleError::CountOverflow)?;
                compact_response_leaf_digest(
                    merkle_geometry,
                    leaf_ordinal,
                    CompactResponseLeafValue::ExtensionField(&values),
                    &leaf_salt,
                )?
            }
            CompactResponseLeafValueKind::Padding => {
                return Err(CompactResponseMerkleError::InvalidOpeningIndices);
            }
        };
        opened_leaf_digests.push((leaf_ordinal, digest));
    }
    if base_field_value_offset != decoded_response.queried_base_field_element_count()
        || extension_field_value_offset != decoded_response.queried_extension_field_element_count()
    {
        return Err(CompactResponseMerkleError::WireGeometryMismatch);
    }

    let mut frontier = Vec::new();
    frontier
        .try_reserve_exact(decoded_response.frontier_node_count())
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    for frontier_ordinal in 0..decoded_response.frontier_node_count() {
        frontier.push(
            decoded_response
                .frontier_node(canonical_proof_bytes, frontier_ordinal)
                .map_err(map_wire_error)?,
        );
    }
    reconstruct_compact_response_root(
        merkle_geometry,
        &opened_leaf_digests,
        &frontier,
        decoded_response.root(),
    )
}

fn reconstruct_compact_response_root(
    geometry: &CompactResponseMerkleGeometry,
    opened_leaf_digests: &[(u64, [u8; Hash512::BYTE_LENGTH])],
    frontier: &[[u8; Hash512::BYTE_LENGTH]],
    expected_root: [u8; Hash512::BYTE_LENGTH],
) -> Result<(), CompactResponseMerkleError> {
    let query_leaf_ordinals = opened_leaf_digests
        .iter()
        .map(|(leaf_ordinal, _)| *leaf_ordinal)
        .collect::<Vec<_>>();
    geometry.validate_query_leaf_ordinals(&query_leaf_ordinals)?;
    let leaf_count = usize::try_from(geometry.merkle_leaf_count)
        .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
    let frontier_coordinates = minimal_frontier_coordinates(&query_leaf_ordinals, leaf_count)
        .map_err(|_| CompactResponseMerkleError::InvalidOpeningIndices)?;
    if frontier.len() != frontier_coordinates.len() {
        return Err(CompactResponseMerkleError::WrongFrontierLength);
    }

    let mut current_nodes = opened_leaf_digests.to_vec();
    let mut frontier_offset = 0_usize;
    for level in 0..geometry.merkle_leaf_count.trailing_zeros() {
        let mut next_nodes = Vec::new();
        next_nodes
            .try_reserve_exact(current_nodes.len().div_ceil(2))
            .map_err(|_| CompactResponseMerkleError::CountOverflow)?;
        let mut current_offset = 0_usize;
        while current_offset < current_nodes.len() {
            let (node_ordinal, node_digest) = current_nodes[current_offset];
            let (left_child_digest, right_child_digest) = if node_ordinal & 1 == 0
                && current_nodes
                    .get(current_offset + 1)
                    .is_some_and(|(next_ordinal, _)| *next_ordinal == node_ordinal + 1)
            {
                let right_digest = current_nodes[current_offset + 1].1;
                current_offset += 2;
                (node_digest, right_digest)
            } else {
                let expected_coordinate = (level, node_ordinal ^ 1);
                if frontier_coordinates.get(frontier_offset).copied() != Some(expected_coordinate) {
                    return Err(CompactResponseMerkleError::IncompleteFrontier);
                }
                let sibling_digest = *frontier
                    .get(frontier_offset)
                    .ok_or(CompactResponseMerkleError::IncompleteFrontier)?;
                frontier_offset += 1;
                current_offset += 1;
                if node_ordinal & 1 == 0 {
                    (node_digest, sibling_digest)
                } else {
                    (sibling_digest, node_digest)
                }
            };
            let parent_ordinal = node_ordinal >> 1;
            if next_nodes
                .last()
                .is_some_and(|(previous_ordinal, _)| *previous_ordinal >= parent_ordinal)
            {
                return Err(CompactResponseMerkleError::IncompleteFrontier);
            }
            next_nodes.push((
                parent_ordinal,
                compact_response_merkle_parent_digest(
                    geometry,
                    level + 1,
                    parent_ordinal << 1,
                    left_child_digest,
                    right_child_digest,
                )?,
            ));
        }
        current_nodes = next_nodes;
    }
    if frontier_offset != frontier.len() || current_nodes.as_slice() != [(0, expected_root)] {
        return Err(CompactResponseMerkleError::RootMismatch);
    }
    Ok(())
}

fn map_wire_error(_: CompactProofWireError) -> CompactResponseMerkleError {
    CompactResponseMerkleError::InvalidWireValue
}

#[cfg(test)]
mod tests {
    use super::super::compact_proof_wire::{
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireInput,
        CompactProofWireGeometry, CompactProofWireInput, PROOF_FIXED_HEADER_BYTE_LENGTH,
        decode_compact_proof_wire, encode_compact_proof_wire,
    };
    use super::super::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageGeometry,
        decode_fixed_uniform_verifier_message, derive_fixed_uniform_verifier_message,
    };
    use super::super::merkle::maximum_minimal_frontier_node_count;
    use super::*;
    use crate::bgv::proof_suite::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;

    #[derive(Clone)]
    enum OwnedLeafValue {
        BaseField(Vec<ProofBaseFieldElement>),
        ExtensionField(Vec<ProofChallengeExtensionElement>),
        Padding,
    }

    impl OwnedLeafValue {
        fn borrowed(&self) -> CompactResponseLeafValue<'_> {
            match self {
                Self::BaseField(values) => CompactResponseLeafValue::BaseField(values),
                Self::ExtensionField(values) => CompactResponseLeafValue::ExtensionField(values),
                Self::Padding => CompactResponseLeafValue::Padding,
            }
        }
    }

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("small canonical base value")
    }

    fn extension(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_canonical_coordinates([
            value,
            value + 1,
            value + 2,
            value + 3,
            value + 4,
        ])
        .expect("small canonical extension value")
    }

    fn response_geometry() -> CompactResponseMerkleGeometry {
        response_geometry_for_ordinal(0)
    }

    fn response_geometry_for_ordinal(response_ordinal: u32) -> CompactResponseMerkleGeometry {
        CompactResponseMerkleGeometry::new(
            response_ordinal,
            vec![
                CompactResponseComponentGeometry::new(
                    0,
                    2,
                    1,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: response_ordinal,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::BaseField,
                    2,
                ),
                CompactResponseComponentGeometry::new(
                    2,
                    4,
                    2,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: response_ordinal,
                        distinct_query_group_ordinal: 1,
                    },
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                ),
                CompactResponseComponentGeometry::new(
                    6,
                    2,
                    0,
                    CompactResponseQuerySelection::Unqueried,
                    CompactResponseLeafValueKind::Padding,
                    0,
                ),
            ],
        )
        .expect("small response Merkle geometry")
    }

    fn leaf_values() -> Vec<OwnedLeafValue> {
        vec![
            OwnedLeafValue::BaseField(vec![base(11), base(13)]),
            OwnedLeafValue::BaseField(vec![base(17), base(19)]),
            OwnedLeafValue::ExtensionField(vec![extension(23)]),
            OwnedLeafValue::ExtensionField(vec![extension(29)]),
            OwnedLeafValue::ExtensionField(vec![extension(31)]),
            OwnedLeafValue::ExtensionField(vec![extension(37)]),
            OwnedLeafValue::Padding,
            OwnedLeafValue::Padding,
        ]
    }

    fn leaf_salts() -> Vec<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]> {
        (0_u8..8)
            .map(|leaf_ordinal| [leaf_ordinal + 1; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH])
            .collect()
    }

    fn build_tree(
        geometry: &CompactResponseMerkleGeometry,
        values: &[OwnedLeafValue],
        salts: &[[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]],
    ) -> Vec<Vec<[u8; Hash512::BYTE_LENGTH]>> {
        let leaves = values
            .iter()
            .zip(salts)
            .enumerate()
            .map(|(leaf_ordinal, (value, salt))| {
                compact_response_leaf_digest(
                    geometry,
                    u64::try_from(leaf_ordinal).unwrap(),
                    value.borrowed(),
                    salt,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let parent_level = u32::try_from(levels.len()).unwrap();
            let parents = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .enumerate()
                .map(|(parent_ordinal, children)| {
                    compact_response_merkle_parent_digest(
                        geometry,
                        parent_level,
                        u64::try_from(parent_ordinal * 2).unwrap(),
                        children[0],
                        children[1],
                    )
                    .unwrap()
                })
                .collect();
            levels.push(parents);
        }
        levels
    }

    fn frontier(
        levels: &[Vec<[u8; Hash512::BYTE_LENGTH]>],
        query_leaf_ordinals: &[u64],
    ) -> Vec<[u8; Hash512::BYTE_LENGTH]> {
        minimal_frontier_coordinates(query_leaf_ordinals, levels[0].len())
            .unwrap()
            .into_iter()
            .map(|(level, node_ordinal)| {
                levels[usize::try_from(level).unwrap()][usize::try_from(node_ordinal).unwrap()]
            })
            .collect()
    }

    fn verifier_message_geometry() -> FixedUniformVerifierMessageGeometry {
        FixedUniformVerifierMessageGeometry::new(
            1,
            0,
            1,
            vec![
                FixedUniformDistinctQueryGeometry::new(2, 1),
                FixedUniformDistinctQueryGeometry::new(4, 2),
            ],
        )
        .expect("small verifier-message geometry")
    }

    fn query_only_message(
        geometry: &FixedUniformVerifierMessageGeometry,
        accepted_queries: &[u64],
    ) -> DecodedFixedUniformVerifierMessage {
        let mut bytes = vec![0_u8; geometry.exact_message_byte_length().unwrap()];
        let candidate_slot_byte_length =
            usize::try_from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT)
                .unwrap()
                .checked_mul(size_of::<u64>())
                .unwrap();
        for (query_ordinal, accepted_query) in accepted_queries.iter().enumerate() {
            let offset = query_ordinal
                .checked_mul(candidate_slot_byte_length)
                .unwrap();
            bytes[offset..offset + size_of::<u64>()].copy_from_slice(&accepted_query.to_le_bytes());
        }
        decode_fixed_uniform_verifier_message(geometry, &bytes)
            .expect("fixed query candidates decode")
    }

    #[test]
    fn shared_component_uses_the_unique_union_and_variable_wire_counts() {
        let no_query_message_geometry =
            FixedUniformVerifierMessageGeometry::new(1, 0, 0, Vec::new())
                .expect("first message has one fixed challenge");
        let query_message_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(8, 3)],
        )
        .expect("later message has one query group");
        let shared_merkle_geometry = CompactResponseMerkleGeometry::new(
            0,
            vec![
                CompactResponseComponentGeometry::new_with_query_count_range(
                    0,
                    8,
                    3,
                    6,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                        first_logical_verifier_move_ordinal: 1,
                        first_distinct_query_group_ordinal: 0,
                        second_logical_verifier_move_ordinal: 2,
                        second_distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                ),
            ],
        )
        .expect("one shared response component");
        let deterministic_merkle_geometry = |response_ordinal| {
            CompactResponseMerkleGeometry::new(
                response_ordinal,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    1,
                    1,
                    CompactResponseQuerySelection::EveryLeaf,
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                )],
            )
            .expect("one deterministic response leaf")
        };
        let maximum_frontier_node_count = (3..=6)
            .map(|opening_count| {
                maximum_minimal_frontier_node_count(8, opening_count)
                    .expect("shared frontier maximum")
            })
            .max()
            .and_then(|count| u64::try_from(count).ok())
            .unwrap();
        let wire_geometries = vec![
            CompactProofResponseWireGeometry::new_with_count_ranges(
                0,
                0,
                0,
                3,
                6,
                3,
                6,
                maximum_frontier_node_count,
                no_query_message_geometry.clone(),
            )
            .expect("variable shared response wire"),
            CompactProofResponseWireGeometry::new(1, 0, 1, 1, 0, query_message_geometry.clone())
                .expect("first query-message response wire"),
            CompactProofResponseWireGeometry::new(2, 0, 1, 1, 0, query_message_geometry.clone())
                .expect("second query-message response wire"),
        ];
        let merkle_geometries = vec![
            shared_merkle_geometry.clone(),
            deterministic_merkle_geometry(1),
            deterministic_merkle_geometry(2),
        ];
        CompactResponseQuerySchedule::validate_registry(&merkle_geometries, &wire_geometries)
            .expect("both shared query sources are owned exactly");

        let verifier_messages = vec![
            derive_fixed_uniform_verifier_message(
                Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]),
                0,
                &no_query_message_geometry,
            )
            .expect("first verifier message"),
            query_only_message(&query_message_geometry, &[1, 3, 5]),
            query_only_message(&query_message_geometry, &[3, 4, 5]),
        ];
        let schedule = CompactResponseQuerySchedule::derive(
            &shared_merkle_geometry,
            &wire_geometries,
            &verifier_messages,
        )
        .expect("shared query union");
        assert_eq!(schedule.as_slice(), [1, 3, 4, 5]);

        let values = (0_u64..8)
            .map(|value| OwnedLeafValue::ExtensionField(vec![extension(41 + value)]))
            .collect::<Vec<_>>();
        let salts = leaf_salts();
        let tree = build_tree(&shared_merkle_geometry, &values, &salts);
        let root = tree.last().unwrap()[0];
        let opened_values = schedule
            .as_slice()
            .iter()
            .map(
                |leaf_ordinal| match &values[usize::try_from(*leaf_ordinal).unwrap()] {
                    OwnedLeafValue::ExtensionField(values) => values[0],
                    _ => unreachable!(),
                },
            )
            .collect::<Vec<_>>();
        let opened_salts = schedule
            .as_slice()
            .iter()
            .map(|leaf_ordinal| salts[usize::try_from(*leaf_ordinal).unwrap()])
            .collect::<Vec<_>>();
        let proof_geometry =
            CompactProofWireGeometry::new(1, vec![wire_geometries[0].clone()]).unwrap();
        let proof_bytes = encode_compact_proof_wire(
            &proof_geometry,
            &CompactProofWireInput::new(vec![CompactProofResponseWireInput::new(
                root,
                [0x45; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
                Vec::new(),
                opened_values,
                opened_salts,
                frontier(&tree, schedule.as_slice()),
            )]),
        )
        .expect("variable shared opening encodes");
        let decoded =
            decode_compact_proof_wire(&proof_geometry, &proof_bytes, proof_bytes.len()).unwrap();
        assert_eq!(
            decoded.responses()[0].queried_extension_field_element_count(),
            4
        );
        assert_eq!(decoded.responses()[0].queried_leaf_count(), 4);
        assert_eq!(
            verify_decoded_compact_response_opening(
                &shared_merkle_geometry,
                &wire_geometries[0],
                &decoded.responses()[0],
                &proof_bytes,
                schedule.as_slice(),
            ),
            Ok(())
        );

        let count_offset = PROOF_FIXED_HEADER_BYTE_LENGTH
            + size_of::<u32>()
            + Hash512::BYTE_LENGTH
            + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
        let mut oversized_count = proof_bytes.clone();
        oversized_count[count_offset + size_of::<u32>()..count_offset + 2 * size_of::<u32>()]
            .copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            decode_compact_proof_wire(&proof_geometry, &oversized_count, oversized_count.len()),
            Err(CompactProofWireError::InvalidGeometry)
        );

        let wrong_schedule = [1, 3, 5];
        assert_eq!(
            verify_decoded_compact_response_opening(
                &shared_merkle_geometry,
                &wire_geometries[0],
                &decoded.responses()[0],
                &proof_bytes,
                &wrong_schedule,
            ),
            Err(CompactResponseMerkleError::WireGeometryMismatch)
        );
    }

    #[test]
    fn later_verifier_message_query_sources_are_explicit_shareable_and_complete() {
        let first_message_geometry = FixedUniformVerifierMessageGeometry::new(1, 0, 0, vec![])
            .expect("first message has no query group");
        let later_message_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(4, 2)],
        )
        .expect("later message owns one query group");
        let first_response_geometry = CompactResponseMerkleGeometry::new(
            0,
            vec![
                CompactResponseComponentGeometry::new(
                    0,
                    4,
                    2,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: 1,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                ),
                CompactResponseComponentGeometry::new(
                    4,
                    4,
                    2,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: 1,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                ),
            ],
        )
        .expect("two components share one later query group");
        let second_response_geometry = CompactResponseMerkleGeometry::new(
            1,
            vec![CompactResponseComponentGeometry::new(
                0,
                1,
                1,
                CompactResponseQuerySelection::EveryLeaf,
                CompactResponseLeafValueKind::ExtensionField,
                1,
            )],
        )
        .expect("one deterministic response leaf");
        let wire_geometries = vec![
            CompactProofResponseWireGeometry::new(
                0,
                0,
                4,
                4,
                u64::try_from(maximum_minimal_frontier_node_count(8, 4).unwrap()).unwrap(),
                first_message_geometry.clone(),
            )
            .expect("first response wire geometry"),
            CompactProofResponseWireGeometry::new(1, 0, 1, 1, 0, later_message_geometry.clone())
                .expect("second response wire geometry"),
        ];
        let merkle_geometries = vec![first_response_geometry, second_response_geometry];
        CompactResponseQuerySchedule::validate_registry(&merkle_geometries, &wire_geometries)
            .expect("the later group is explicitly and completely referenced");

        let verifier_messages = vec![
            derive_fixed_uniform_verifier_message(
                Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
                0,
                &first_message_geometry,
            )
            .expect("first verifier message"),
            derive_fixed_uniform_verifier_message(
                Hash512::from_bytes([0x37; Hash512::BYTE_LENGTH]),
                1,
                &later_message_geometry,
            )
            .expect("later verifier message"),
        ];
        let schedule = CompactResponseQuerySchedule::derive(
            &merkle_geometries[0],
            &wire_geometries,
            &verifier_messages,
        )
        .expect("both components use the later decoded group");
        let local_group = verifier_messages[1].distinct_query_groups()[0].as_slice();
        assert_eq!(
            schedule.as_slice(),
            [
                local_group[0],
                local_group[1],
                local_group[0] + 4,
                local_group[1] + 4
            ]
        );

        let wire_geometries_with_unused_group = vec![
            wire_geometries[0].clone(),
            CompactProofResponseWireGeometry::new(
                1,
                0,
                1,
                1,
                0,
                FixedUniformVerifierMessageGeometry::new(
                    0,
                    0,
                    0,
                    vec![
                        FixedUniformDistinctQueryGeometry::new(4, 2),
                        FixedUniformDistinctQueryGeometry::new(4, 2),
                    ],
                )
                .unwrap(),
            )
            .unwrap(),
        ];
        assert_eq!(
            CompactResponseQuerySchedule::validate_registry(
                &merkle_geometries,
                &wire_geometries_with_unused_group,
            ),
            Err(CompactResponseMerkleError::InvalidOpeningIndices)
        );
        assert_eq!(
            CompactResponseMerkleGeometry::new(
                1,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    4,
                    2,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: 0,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                )],
            ),
            Err(CompactResponseMerkleError::InvalidGeometry)
        );
    }

    fn encoded_opening(
        merkle_geometry: &CompactResponseMerkleGeometry,
        query_leaf_ordinals: &[u64],
        root_mutation: bool,
        base_value_mutation: bool,
        salt_mutation: bool,
        frontier_mutation: bool,
    ) -> (CompactProofWireGeometry, Vec<u8>) {
        let values = leaf_values();
        let salts = leaf_salts();
        let levels = build_tree(merkle_geometry, &values, &salts);
        let mut root = levels.last().unwrap()[0];
        if root_mutation {
            root[0] ^= 1;
        }
        let mut base_values = vec![base(11), base(13)];
        if base_value_mutation {
            base_values[1] = base(37);
        }
        let extension_values = vec![extension(23), extension(31)];
        let mut opened_salts = query_leaf_ordinals
            .iter()
            .map(|leaf_ordinal| salts[usize::try_from(*leaf_ordinal).unwrap()])
            .collect::<Vec<_>>();
        if salt_mutation {
            opened_salts[1][0] ^= 1;
        }
        let mut authentication_frontier = frontier(&levels, query_leaf_ordinals);
        if frontier_mutation {
            authentication_frontier[0][0] ^= 1;
        }
        let maximum_frontier_node_count = maximum_minimal_frontier_node_count(8, 3).unwrap();
        let response_wire_geometry = CompactProofResponseWireGeometry::new(
            merkle_geometry.response_ordinal(),
            2,
            2,
            3,
            u64::try_from(maximum_frontier_node_count).unwrap(),
            verifier_message_geometry(),
        )
        .unwrap();
        let proof_geometry =
            CompactProofWireGeometry::new(1, vec![response_wire_geometry]).unwrap();
        let proof_input = CompactProofWireInput::new(vec![CompactProofResponseWireInput::new(
            root,
            [0x51; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            base_values,
            extension_values,
            opened_salts,
            authentication_frontier,
        )]);
        let proof_bytes = encode_compact_proof_wire(&proof_geometry, &proof_input).unwrap();
        (proof_geometry, proof_bytes)
    }

    #[test]
    fn canonical_response_merkle_opening_round_trips_and_refuses_every_bound_mutation() {
        let geometry = response_geometry();
        let query_leaf_ordinals = [0, 2, 4];
        let (wire_geometry, canonical_proof_bytes) =
            encoded_opening(&geometry, &query_leaf_ordinals, false, false, false, false);
        let decoded = decode_compact_proof_wire(
            &wire_geometry,
            &canonical_proof_bytes,
            canonical_proof_bytes.len(),
        )
        .unwrap();
        assert_eq!(
            verify_decoded_compact_response_opening(
                &geometry,
                &wire_geometry.responses()[0],
                &decoded.responses()[0],
                &canonical_proof_bytes,
                &query_leaf_ordinals,
            ),
            Ok(())
        );

        for (root_mutation, base_value_mutation, salt_mutation, frontier_mutation) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let (mutated_wire_geometry, mutated_bytes) = encoded_opening(
                &geometry,
                &query_leaf_ordinals,
                root_mutation,
                base_value_mutation,
                salt_mutation,
                frontier_mutation,
            );
            let mutated = decode_compact_proof_wire(
                &mutated_wire_geometry,
                &mutated_bytes,
                mutated_bytes.len(),
            )
            .unwrap();
            assert_eq!(
                verify_decoded_compact_response_opening(
                    &geometry,
                    &mutated_wire_geometry.responses()[0],
                    &mutated.responses()[0],
                    &mutated_bytes,
                    &query_leaf_ordinals,
                ),
                Err(CompactResponseMerkleError::RootMismatch)
            );
        }

        for malformed_queries in [&[2, 0, 4][..], &[0, 0, 4], &[0, 2, 6], &[0, 2, 8]] {
            assert_eq!(
                verify_decoded_compact_response_opening(
                    &geometry,
                    &wire_geometry.responses()[0],
                    &decoded.responses()[0],
                    &canonical_proof_bytes,
                    malformed_queries,
                ),
                Err(CompactResponseMerkleError::InvalidOpeningIndices)
            );
        }

        let changed_query_position = [1, 2, 4];
        assert_eq!(
            verify_decoded_compact_response_opening(
                &geometry,
                &wire_geometry.responses()[0],
                &decoded.responses()[0],
                &canonical_proof_bytes,
                &changed_query_position,
            ),
            Err(CompactResponseMerkleError::RootMismatch)
        );
        let changed_response_geometry = response_geometry_for_ordinal(1);
        assert_eq!(
            verify_decoded_compact_response_opening(
                &changed_response_geometry,
                &wire_geometry.responses()[0],
                &decoded.responses()[0],
                &canonical_proof_bytes,
                &query_leaf_ordinals,
            ),
            Err(CompactResponseMerkleError::WireGeometryMismatch)
        );
    }

    #[test]
    fn leaf_and_parent_hashes_bind_types_counts_components_and_coordinates() {
        let geometry = response_geometry();
        let values = leaf_values();
        let salts = leaf_salts();
        let base_digest =
            compact_response_leaf_digest(&geometry, 0, values[0].borrowed(), &salts[0]).unwrap();
        assert_eq!(
            compact_response_leaf_digest(
                &geometry,
                0,
                CompactResponseLeafValue::BaseField(&[base(11)]),
                &salts[0],
            ),
            Err(CompactResponseMerkleError::WrongLeafValueCount)
        );
        assert_eq!(
            compact_response_leaf_digest(
                &geometry,
                0,
                CompactResponseLeafValue::ExtensionField(&[extension(11)]),
                &salts[0],
            ),
            Err(CompactResponseMerkleError::WrongLeafValueKind)
        );
        let second_base_digest =
            compact_response_leaf_digest(&geometry, 1, values[1].borrowed(), &salts[1]).unwrap();
        let parent =
            compact_response_merkle_parent_digest(&geometry, 1, 0, base_digest, second_base_digest)
                .unwrap();
        assert_ne!(
            parent,
            compact_response_merkle_parent_digest(
                &geometry,
                1,
                0,
                second_base_digest,
                base_digest,
            )
            .unwrap()
        );
        let next_response_geometry = response_geometry_for_ordinal(1);
        assert_ne!(
            parent,
            compact_response_merkle_parent_digest(
                &next_response_geometry,
                1,
                0,
                base_digest,
                second_base_digest,
            )
            .unwrap()
        );
        assert_eq!(
            compact_response_merkle_parent_digest(&geometry, 0, 0, base_digest, second_base_digest,),
            Err(CompactResponseMerkleError::InvalidGeometry)
        );
        assert_eq!(
            compact_response_merkle_parent_digest(&geometry, 1, 1, base_digest, second_base_digest,),
            Err(CompactResponseMerkleError::InvalidGeometry)
        );
        assert_ne!(
            COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
            COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN
        );
    }

    #[test]
    fn postorder_writer_and_frontier_scanner_match_the_independent_tree() {
        const TEST_CHUNK_BYTE_LENGTH: usize = 4 * Hash512::BYTE_LENGTH;

        let geometry = response_geometry();
        let values = leaf_values();
        let salts = leaf_salts();
        let independent_levels = build_tree(&geometry, &values, &salts);
        let query_leaf_ordinals = [0, 2, 4];
        let expected_frontier = frontier(&independent_levels, &query_leaf_ordinals);

        let mut writer = CompactResponsePostorderMerkleWriter::new_with_chunk_byte_length(
            &geometry,
            TEST_CHUNK_BYTE_LENGTH,
        )
        .unwrap();
        let mut tree_chunks = Vec::new();
        for (leaf_ordinal, (value, salt)) in values.iter().zip(&salts).enumerate() {
            if leaf_ordinal == 3 {
                assert_eq!(
                    writer.absorb_leaf(value.borrowed(), salt),
                    Err(CompactResponseMerkleError::OutputChunkPending)
                );
            }
            if let Some(chunk) = writer.output_chunk() {
                tree_chunks.push(chunk.to_vec());
                writer.acknowledge_output_chunk().unwrap();
            }
            writer.absorb_leaf(value.borrowed(), salt).unwrap();
        }
        while let Some(chunk) = writer.output_chunk() {
            tree_chunks.push(chunk.to_vec());
            writer.acknowledge_output_chunk().unwrap();
        }
        let root = writer.finish().unwrap();
        assert_eq!(root, independent_levels.last().unwrap()[0]);
        assert_eq!(
            tree_chunks.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![256, 256, 256, 192]
        );

        let tree_bytes = tree_chunks.concat();
        assert_eq!(tree_bytes.len(), 15 * Hash512::BYTE_LENGTH);
        for (level, level_digests) in independent_levels.iter().enumerate() {
            for (node_ordinal, expected_digest) in level_digests.iter().enumerate() {
                let postorder_digest_ordinal = compact_response_postorder_digest_ordinal(
                    &geometry,
                    u32::try_from(level).unwrap(),
                    u64::try_from(node_ordinal).unwrap(),
                )
                .unwrap();
                let byte_offset =
                    usize::try_from(postorder_digest_ordinal).unwrap() * Hash512::BYTE_LENGTH;
                assert_eq!(
                    &tree_bytes[byte_offset..byte_offset + Hash512::BYTE_LENGTH],
                    expected_digest
                );
            }
        }

        let mut scanner = CompactResponsePostorderFrontierScanner::new_with_chunk_byte_length(
            &geometry,
            &query_leaf_ordinals,
            TEST_CHUNK_BYTE_LENGTH,
        )
        .unwrap();
        for chunk in &tree_chunks {
            scanner.absorb_tree_chunk(chunk).unwrap();
        }
        let scanned_frontier = scanner.finish().unwrap();
        assert_eq!(scanned_frontier, expected_frontier);
        let opened_leaf_digests = query_leaf_ordinals
            .iter()
            .map(|leaf_ordinal| {
                (
                    *leaf_ordinal,
                    independent_levels[0][usize::try_from(*leaf_ordinal).unwrap()],
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reconstruct_compact_response_root(
                &geometry,
                &opened_leaf_digests,
                &scanned_frontier,
                root,
            ),
            Ok(())
        );

        let mut truncated_scanner =
            CompactResponsePostorderFrontierScanner::new_with_chunk_byte_length(
                &geometry,
                &query_leaf_ordinals,
                TEST_CHUNK_BYTE_LENGTH,
            )
            .unwrap();
        for chunk in &tree_chunks[..tree_chunks.len() - 1] {
            truncated_scanner.absorb_tree_chunk(chunk).unwrap();
        }
        assert_eq!(
            truncated_scanner.finish(),
            Err(CompactResponseMerkleError::ScannerIncomplete)
        );
        let mut malformed_scanner =
            CompactResponsePostorderFrontierScanner::new_with_chunk_byte_length(
                &geometry,
                &query_leaf_ordinals,
                TEST_CHUNK_BYTE_LENGTH,
            )
            .unwrap();
        assert_eq!(
            malformed_scanner.absorb_tree_chunk(&tree_chunks[0][..255]),
            Err(CompactResponseMerkleError::WrongTreeChunk)
        );

        let mut incomplete_writer =
            CompactResponsePostorderMerkleWriter::new_with_chunk_byte_length(
                &geometry,
                TEST_CHUNK_BYTE_LENGTH,
            )
            .unwrap();
        assert_eq!(
            incomplete_writer.acknowledge_output_chunk(),
            Err(CompactResponseMerkleError::OutputChunkUnavailable)
        );
        incomplete_writer
            .absorb_leaf(values[0].borrowed(), &salts[0])
            .unwrap();
        assert_eq!(
            incomplete_writer.finish(),
            Err(CompactResponseMerkleError::WriterIncomplete)
        );
    }

    #[test]
    fn production_postorder_writer_heap_geometry_is_exact() {
        let geometry = response_geometry();
        let heap = CompactResponsePostorderWriterHeapGeometry::derive(&geometry).unwrap();
        assert_eq!(heap.output_chunk_byte_length(), 1_048_576);
        assert_eq!(heap.pending_left_digest_byte_length(), 192);
        assert_eq!(heap.pending_emitted_digest_byte_length(), 256);
        assert_eq!(heap.maximum_owned_heap_byte_length(), 1_049_024);
        let scanner_heap = CompactResponseFrontierScannerHeapGeometry::derive(4).unwrap();
        assert_eq!(scanner_heap.scan_target_byte_length(), 64);
        assert_eq!(scanner_heap.frontier_digest_byte_length(), 256);
        assert_eq!(scanner_heap.maximum_owned_heap_byte_length(), 320);

        let production_writer = CompactResponsePostorderMerkleWriter::new(&geometry).unwrap();
        assert_eq!(
            production_writer.output_chunk_byte_length,
            COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH
        );
        assert!(production_writer.output_chunk().is_none());

        let production_scanner =
            CompactResponsePostorderFrontierScanner::new(&geometry, &[0, 2, 4]).unwrap();
        assert_eq!(
            production_scanner.input_chunk_byte_length,
            COMPACT_RESPONSE_TREE_STORAGE_CHUNK_BYTE_LENGTH
        );
        assert_eq!(production_scanner.consumed_tree_byte_length, 0);
    }

    #[test]
    fn response_geometry_refuses_gaps_padding_queries_and_wire_count_drift() {
        let valid_components = response_geometry().components;
        let mut gap = valid_components.clone();
        gap[1].first_leaf_ordinal += 1;
        assert_eq!(
            CompactResponseMerkleGeometry::new(0, gap),
            Err(CompactResponseMerkleError::InvalidGeometry)
        );
        let mut queried_padding = valid_components.clone();
        queried_padding[2].maximum_queried_leaf_count = 1;
        assert_eq!(
            CompactResponseMerkleGeometry::new(0, queried_padding),
            Err(CompactResponseMerkleError::InvalidGeometry)
        );
        let geometry = response_geometry();
        let wrong_wire_geometry =
            CompactProofResponseWireGeometry::new(0, 1, 3, 3, 4, verifier_message_geometry())
                .unwrap();
        assert_eq!(
            geometry.validate_wire_geometry(&wrong_wire_geometry),
            Err(CompactResponseMerkleError::WireGeometryMismatch)
        );
    }
}
