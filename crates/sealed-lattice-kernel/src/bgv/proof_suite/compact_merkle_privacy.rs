//! Salted-response Merkle privacy and finite EPRO programming.
//!
//! The production compact proof commits each logical response as one salted
//! vector. The 45 construction commitments name component/query-source ranges in
//! those 82 vectors; they are not a second Merkle layer. This module validates
//! that embedding. Its test-only security game executes a finite,
//! collision-free random-oracle patch over the exact leaf and parent
//! preimages owned by `compact_response_merkle`; it is not a production
//! checkpoint or oracle implementation.

use num_bigint::BigUint;

#[cfg(test)]
use std::collections::BTreeSet;

use super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
use super::compact_masking_coefficient_maps::{
    CompactCommitmentQueryCoordinate, CompactCommitmentQuerySource,
    CompactConstructionCommitmentEmbedding, CompactConstructionCommitmentOwnership,
    CompactMaskingCoefficientMapCertificate, CompactMaskingCoefficientMapError,
    CompactResponseComponentEmbedding, derive_selected_compact_masking_coefficient_map_certificate,
    response_component_source_role,
};
use super::compact_proof_contract::{
    CompactProofContractError, CompactPublicKeyVerifierInputs,
    selected_compact_public_key_proof_contract,
};
use super::compact_response_merkle::{
    CompactResponseMerkleError, CompactResponseMerkleGeometry, CompactResponseQuerySchedule,
    CompactResponseQuerySelection,
};
use super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;
use crate::foundation::Hash512;

#[cfg(test)]
use super::compact_proof_contract::CompactPublicKeyProofContract;
#[cfg(test)]
use super::compact_proof_wire::{
    CompactProofResponseWireGeometry, CompactProofWireGeometry, DecodedCompactProofResponse,
};
#[cfg(test)]
use super::compact_response_merkle::{
    CompactResponseOpenedLeafHashCursor, CompactResponseRootReconstruction,
    CompactResponseRootReconstructionPoll, compact_response_hash_preimage,
};

const SHAKE256_OUTPUT_BIT_LENGTH: u32 = 512;
const BCS16_MERKLE_PRIVACY_DENOMINATOR_POWER: u32 = SHAKE256_OUTPUT_BIT_LENGTH / 4 - 2;
const LEAF_SALT_BIT_LENGTH: u32 =
    (COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH * u8::BITS as usize) as u32;
const SELECTED_RESPONSE_COMMITMENT_COUNT: usize = 82;
const SELECTED_CONSTRUCTION_COMMITMENT_COUNT: usize = 45;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactMerklePrivacyError {
    Contract(CompactProofContractError),
    CoefficientMap(CompactMaskingCoefficientMapError),
    Merkle(CompactResponseMerkleError),
    ArithmeticOverflow,
    InvalidConstructionEmbedding,
    #[cfg(test)]
    WrongResponseOrder,
    #[cfg(test)]
    WrongOpeningBoundary,
    #[cfg(test)]
    MissingResponseRoot,
    #[cfg(test)]
    DuplicateResponseRoot,
    #[cfg(test)]
    RootMismatch,
    #[cfg(test)]
    ConflictingOracleInput,
    #[cfg(test)]
    OracleOutputCollision,
    #[cfg(test)]
    RetiredOracleInput,
    #[cfg(test)]
    RetiredOracleOutput,
    #[cfg(test)]
    WrongCheckpoint,
    #[cfg(test)]
    IncompleteAttempt,
}

impl From<CompactProofContractError> for CompactMerklePrivacyError {
    fn from(error: CompactProofContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<CompactMaskingCoefficientMapError> for CompactMerklePrivacyError {
    fn from(error: CompactMaskingCoefficientMapError) -> Self {
        Self::CoefficientMap(error)
    }
}

impl From<CompactResponseMerkleError> for CompactMerklePrivacyError {
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::Merkle(error)
    }
}

/// Exact rational numerator/denominator-exponent representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMerkleProbabilityBound {
    numerator: BigUint,
    denominator_power: u32,
}

impl CompactMerkleProbabilityBound {
    #[cfg(test)]
    pub(crate) const fn denominator_power(&self) -> u32 {
        self.denominator_power
    }

    #[cfg(test)]
    pub(crate) fn numerator(&self) -> &BigUint {
        &self.numerator
    }
}

/// One recomputed component/query-source binding for an abstract construction
/// commitment. A role-5 component owns one union source containing both arms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactConstructionMerkleBinding {
    pub(crate) commitment_ordinal: u32,
    pub(crate) response_ordinal: u32,
    pub(crate) component_ordinal: u32,
    pub(crate) first_leaf_ordinal: u64,
    pub(crate) leaf_count: u64,
    pub(crate) ownership: CompactConstructionCommitmentOwnership,
    pub(crate) query_source: CompactCommitmentQuerySource,
}

/// Production-derived privacy statement for the complete selected response
/// topology. It contains no producer-supplied status or accounting fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactMerklePrivacyCertificate {
    contract_source_hash: Hash512,
    response_commitment_count: u32,
    committed_leaf_count: u64,
    construction_bindings: Vec<CompactConstructionMerkleBinding>,
    response_component_embeddings: Vec<CompactResponseComponentEmbedding>,
    bcs16_statistical_distance: CompactMerkleProbabilityBound,
    leaf_salt_collision: CompactMerkleProbabilityBound,
}

impl CompactMerklePrivacyCertificate {
    pub(crate) const fn contract_source_hash(&self) -> Hash512 {
        self.contract_source_hash
    }

    pub(crate) const fn response_commitment_count(&self) -> u32 {
        self.response_commitment_count
    }

    #[cfg(test)]
    pub(crate) const fn committed_leaf_count(&self) -> u64 {
        self.committed_leaf_count
    }

    #[cfg(test)]
    pub(crate) fn construction_bindings(&self) -> &[CompactConstructionMerkleBinding] {
        &self.construction_bindings
    }

    #[cfg(test)]
    pub(crate) fn response_component_embedding_count(&self) -> usize {
        self.response_component_embeddings.len()
    }

    /// BCS16 salted-Merkle statistical distance `sum_i n_i / 2^126`
    /// for a 512-bit random oracle and the exact 82 tree sizes.
    #[cfg(test)]
    pub(crate) const fn bcs16_statistical_distance(&self) -> &CompactMerkleProbabilityBound {
        &self.bcs16_statistical_distance
    }

    /// Collision probability for all independently sampled 1024-bit leaf
    /// salts, union-bounded as `choose(total_leaf_count, 2) / 2^1024`.
    #[cfg(test)]
    pub(crate) const fn leaf_salt_collision(&self) -> &CompactMerkleProbabilityBound {
        &self.leaf_salt_collision
    }
}

pub(crate) fn derive_selected_compact_merkle_privacy_certificate()
-> Result<CompactMerklePrivacyCertificate, CompactMerklePrivacyError> {
    let contract = selected_compact_public_key_proof_contract()?;
    let coefficient_map = derive_selected_compact_masking_coefficient_map_certificate()?;
    derive_compact_merkle_privacy_certificate(&contract.verifier_inputs(), &coefficient_map)
}

fn derive_compact_merkle_privacy_certificate(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    coefficient_map: &CompactMaskingCoefficientMapCertificate,
) -> Result<CompactMerklePrivacyCertificate, CompactMerklePrivacyError> {
    coefficient_map.check()?;
    if inputs.response_merkle_geometries.len() != SELECTED_RESPONSE_COMMITMENT_COUNT
        || inputs.response_component_roles.len() != SELECTED_RESPONSE_COMMITMENT_COUNT
        || inputs.response_merkle_geometries.len() != inputs.response_component_roles.len()
        || coefficient_map.construction_commitment_embeddings().len()
            != SELECTED_CONSTRUCTION_COMMITMENT_COUNT
    {
        return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
    }

    let committed_leaf_count =
        inputs
            .response_merkle_geometries
            .iter()
            .try_fold(0_u64, |total, geometry| {
                total
                    .checked_add(geometry.merkle_leaf_count())
                    .ok_or(CompactMerklePrivacyError::ArithmeticOverflow)
            })?;
    validate_response_component_embeddings(
        inputs,
        coefficient_map.response_component_embeddings(),
    )?;
    let construction_bindings = derive_construction_bindings(
        inputs,
        coefficient_map.response_component_embeddings(),
        coefficient_map.construction_commitment_embeddings(),
    )?;
    let salt_collision_numerator = BigUint::from(committed_leaf_count)
        * BigUint::from(committed_leaf_count.saturating_sub(1))
        / BigUint::from(2_u8);
    Ok(CompactMerklePrivacyCertificate {
        contract_source_hash: inputs.canonical_source_hash()?,
        response_commitment_count: u32::try_from(inputs.response_merkle_geometries.len())
            .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?,
        committed_leaf_count,
        construction_bindings,
        response_component_embeddings: coefficient_map.response_component_embeddings().to_vec(),
        bcs16_statistical_distance: CompactMerkleProbabilityBound {
            numerator: BigUint::from(committed_leaf_count),
            denominator_power: BCS16_MERKLE_PRIVACY_DENOMINATOR_POWER,
        },
        leaf_salt_collision: CompactMerkleProbabilityBound {
            numerator: salt_collision_numerator,
            denominator_power: LEAF_SALT_BIT_LENGTH,
        },
    })
}

fn derive_construction_bindings(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    response_embeddings: &[CompactResponseComponentEmbedding],
    construction_embeddings: &[CompactConstructionCommitmentEmbedding],
) -> Result<Vec<CompactConstructionMerkleBinding>, CompactMerklePrivacyError> {
    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(SELECTED_CONSTRUCTION_COMMITMENT_COUNT)
        .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
    for embedding in construction_embeddings {
        bindings.push(construction_binding(
            inputs,
            response_embeddings,
            *embedding,
        )?);
    }
    for (binding_index, binding) in bindings.iter().enumerate() {
        if usize::try_from(binding.commitment_ordinal).ok() != Some(binding_index)
            || bindings[..binding_index].iter().any(|preceding| {
                preceding.response_ordinal == binding.response_ordinal
                    && preceding.component_ordinal == binding.component_ordinal
            })
        {
            return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
        }
    }
    validate_shared_cross_epoch_binding(&bindings)?;
    Ok(bindings)
}

fn validate_response_component_embeddings(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    embeddings: &[CompactResponseComponentEmbedding],
) -> Result<(), CompactMerklePrivacyError> {
    let expected_component_count =
        inputs
            .response_merkle_geometries
            .iter()
            .try_fold(0_usize, |count, geometry| {
                count
                    .checked_add(geometry.components().len())
                    .ok_or(CompactMerklePrivacyError::ArithmeticOverflow)
            })?;
    if embeddings.len() != expected_component_count {
        return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
    }
    let mut embedding_index = 0_usize;
    for (response_index, (geometry, roles)) in inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
        .enumerate()
    {
        for (component_index, (component, role)) in
            geometry.components().iter().zip(roles).enumerate()
        {
            let embedding = embeddings
                .get(embedding_index)
                .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)?;
            if usize::try_from(embedding.outer_response_ordinal).ok() != Some(response_index)
                || usize::try_from(embedding.component_ordinal).ok() != Some(component_index)
                || geometry.response_ordinal() != embedding.outer_response_ordinal
                || *role != embedding.component_role
                || embedding.semantic_role != response_component_source_role(role.role_tag)?
                || component.first_leaf_ordinal() != embedding.first_leaf_ordinal
                || component.leaf_count() != embedding.leaf_count
                || component.minimum_queried_leaf_count() != embedding.minimum_queried_leaf_count
                || component.maximum_queried_leaf_count() != embedding.maximum_queried_leaf_count
                || component.query_selection() != embedding.query_selection
                || component.value_kind() != embedding.value_kind
                || component.field_element_count_per_leaf()
                    != embedding.field_element_count_per_leaf
            {
                return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
            }
            embedding_index = embedding_index
                .checked_add(1)
                .ok_or(CompactMerklePrivacyError::ArithmeticOverflow)?;
        }
    }
    if embedding_index != embeddings.len() {
        return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
    }
    Ok(())
}

fn construction_binding(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    response_embeddings: &[CompactResponseComponentEmbedding],
    embedding: CompactConstructionCommitmentEmbedding,
) -> Result<CompactConstructionMerkleBinding, CompactMerklePrivacyError> {
    let response_index = usize::try_from(embedding.outer_response_ordinal)
        .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
    let component_index = usize::try_from(embedding.component_ordinal)
        .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
    let geometry = inputs
        .response_merkle_geometries
        .get(response_index)
        .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)?;
    let role = inputs
        .response_component_roles
        .get(response_index)
        .and_then(|roles| roles.get(component_index))
        .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)?;
    let component = geometry
        .components()
        .get(component_index)
        .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)?;
    let response_embedding = response_embeddings
        .iter()
        .find(|candidate| {
            candidate.outer_response_ordinal == embedding.outer_response_ordinal
                && candidate.component_ordinal == embedding.component_ordinal
        })
        .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)?;
    let expected_ownership = match role.role_tag {
        5 => CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch,
        1 => CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 1 },
        2..=4 => CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 2 },
        11 | 14..=17 if (1..=2).contains(&role.epoch) => {
            CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: role.epoch }
        }
        _ => return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding),
    };
    if geometry.response_ordinal() != embedding.outer_response_ordinal
        || *role != embedding.component_role
        || response_embedding.component_role != embedding.component_role
        || response_embedding.semantic_role != Some(embedding.semantic_role)
        || embedding.ownership != expected_ownership
        || !query_source_matches_component(embedding.query_source, component.query_selection())
    {
        return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
    }
    Ok(CompactConstructionMerkleBinding {
        commitment_ordinal: embedding.commitment_ordinal,
        response_ordinal: embedding.outer_response_ordinal,
        component_ordinal: embedding.component_ordinal,
        first_leaf_ordinal: component.first_leaf_ordinal(),
        leaf_count: component.leaf_count(),
        ownership: embedding.ownership,
        query_source: embedding.query_source,
    })
}

fn query_source_matches_component(
    source: CompactCommitmentQuerySource,
    selection: CompactResponseQuerySelection,
) -> bool {
    match (source, selection) {
        (
            CompactCommitmentQuerySource::Component,
            CompactResponseQuerySelection::Unqueried
            | CompactResponseQuerySelection::EveryLeaf
            | CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. },
        ) => true,
        (
            CompactCommitmentQuerySource::SharedCrossEpochUnion {
                owned_pre_challenge,
                reused_main,
            },
            CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                first_logical_verifier_move_ordinal,
                first_distinct_query_group_ordinal,
                second_logical_verifier_move_ordinal,
                second_distinct_query_group_ordinal,
            },
        ) => {
            owned_pre_challenge.logical_verifier_move_ordinal == first_logical_verifier_move_ordinal
                && owned_pre_challenge.distinct_query_group_ordinal
                    == first_distinct_query_group_ordinal
                && reused_main.logical_verifier_move_ordinal == second_logical_verifier_move_ordinal
                && reused_main.distinct_query_group_ordinal == second_distinct_query_group_ordinal
        }
        _ => false,
    }
}

fn validate_shared_cross_epoch_binding(
    bindings: &[CompactConstructionMerkleBinding],
) -> Result<(), CompactMerklePrivacyError> {
    let shared = bindings
        .iter()
        .filter(|binding| {
            !matches!(
                binding.query_source,
                CompactCommitmentQuerySource::Component
            )
        })
        .collect::<Vec<_>>();
    if shared.len() != 1
        || shared[0].ownership
            != CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch
        || !matches!(
            shared[0].query_source,
            CompactCommitmentQuerySource::SharedCrossEpochUnion { .. }
        )
    {
        return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
    }
    Ok(())
}

/// Re-derives one opening schedule at the response's exact last-use boundary
/// and verifies every selected component and construction query source against
/// the decoded verifier messages. Callers never supply leaf ordinals.
pub(super) fn derive_and_validate_compact_response_query_schedule(
    certificate: &CompactMerklePrivacyCertificate,
    response_ordinal: u32,
    geometry: &CompactResponseMerkleGeometry,
    wire_geometries: &[super::compact_proof_wire::CompactProofResponseWireGeometry],
    verifier_message_prefix: &[DecodedFixedUniformVerifierMessage],
) -> Result<CompactResponseQuerySchedule, CompactMerklePrivacyError> {
    let query_schedule = CompactResponseQuerySchedule::derive_at_last_query_boundary(
        geometry,
        wire_geometries,
        verifier_message_prefix,
    )?;

    let mut response_embedding_count = 0_usize;
    for embedding in certificate
        .response_component_embeddings
        .iter()
        .filter(|embedding| embedding.outer_response_ordinal == response_ordinal)
    {
        let component_index = usize::try_from(embedding.component_ordinal)
            .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
        let component = geometry
            .components()
            .get(component_index)
            .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)?;
        if usize::try_from(embedding.component_ordinal).ok() != Some(response_embedding_count)
            || component.first_leaf_ordinal() != embedding.first_leaf_ordinal
            || component.leaf_count() != embedding.leaf_count
            || component.minimum_queried_leaf_count() != embedding.minimum_queried_leaf_count
            || component.maximum_queried_leaf_count() != embedding.maximum_queried_leaf_count
            || component.query_selection() != embedding.query_selection
            || component.value_kind() != embedding.value_kind
            || component.field_element_count_per_leaf() != embedding.field_element_count_per_leaf
        {
            return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
        }
        let observed = component_schedule_slice(&query_schedule, component)?;
        if !component_schedule_matches(component, observed, verifier_message_prefix)? {
            return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
        }
        response_embedding_count = response_embedding_count
            .checked_add(1)
            .ok_or(CompactMerklePrivacyError::ArithmeticOverflow)?;
    }
    if response_embedding_count != geometry.components().len() {
        return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
    }

    let mut shared_binding_count = 0_usize;
    for binding in certificate
        .construction_bindings
        .iter()
        .filter(|binding| binding.response_ordinal == response_ordinal)
    {
        let component_index = usize::try_from(binding.component_ordinal)
            .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
        let component = geometry
            .components()
            .get(component_index)
            .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)?;
        if component.first_leaf_ordinal() != binding.first_leaf_ordinal
            || component.leaf_count() != binding.leaf_count
            || !query_source_matches_component(binding.query_source, component.query_selection())
        {
            return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
        }
        if !matches!(
            binding.query_source,
            CompactCommitmentQuerySource::Component
        ) {
            shared_binding_count = shared_binding_count
                .checked_add(1)
                .ok_or(CompactMerklePrivacyError::ArithmeticOverflow)?;
            let observed = component_schedule_slice(&query_schedule, component)?;
            if !query_source_is_present(
                binding.query_source,
                component.first_leaf_ordinal(),
                observed,
                verifier_message_prefix,
            )? {
                return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
            }
        }
    }
    if shared_binding_count > 1 {
        return Err(CompactMerklePrivacyError::InvalidConstructionEmbedding);
    }
    Ok(query_schedule)
}

fn component_schedule_slice<'schedule>(
    query_schedule: &'schedule CompactResponseQuerySchedule,
    component: &super::compact_response_merkle::CompactResponseComponentGeometry,
) -> Result<&'schedule [u64], CompactMerklePrivacyError> {
    let component_end = component
        .first_leaf_ordinal()
        .checked_add(component.leaf_count())
        .ok_or(CompactMerklePrivacyError::ArithmeticOverflow)?;
    let schedule = query_schedule.as_slice();
    let start =
        schedule.partition_point(|leaf_ordinal| *leaf_ordinal < component.first_leaf_ordinal());
    let end = schedule.partition_point(|leaf_ordinal| *leaf_ordinal < component_end);
    Ok(&schedule[start..end])
}

fn component_schedule_matches(
    component: &super::compact_response_merkle::CompactResponseComponentGeometry,
    observed: &[u64],
    verifier_messages: &[DecodedFixedUniformVerifierMessage],
) -> Result<bool, CompactMerklePrivacyError> {
    let first_leaf_ordinal = component.first_leaf_ordinal();
    let matches = match component.query_selection() {
        CompactResponseQuerySelection::Unqueried => observed.is_empty(),
        CompactResponseQuerySelection::EveryLeaf => {
            u64::try_from(observed.len()).ok() == Some(component.leaf_count())
                && observed
                    .iter()
                    .copied()
                    .eq(first_leaf_ordinal..first_leaf_ordinal + component.leaf_count())
        }
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal,
            distinct_query_group_ordinal,
        } => query_group_matches(
            observed,
            first_leaf_ordinal,
            decoded_query_group(
                verifier_messages,
                logical_verifier_move_ordinal,
                distinct_query_group_ordinal,
            )?,
        ),
        CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
            first_logical_verifier_move_ordinal,
            first_distinct_query_group_ordinal,
            second_logical_verifier_move_ordinal,
            second_distinct_query_group_ordinal,
        } => query_group_union_matches(
            observed,
            first_leaf_ordinal,
            decoded_query_group(
                verifier_messages,
                first_logical_verifier_move_ordinal,
                first_distinct_query_group_ordinal,
            )?,
            decoded_query_group(
                verifier_messages,
                second_logical_verifier_move_ordinal,
                second_distinct_query_group_ordinal,
            )?,
        ),
    };
    Ok(matches)
}

fn decoded_query_group(
    verifier_messages: &[DecodedFixedUniformVerifierMessage],
    logical_verifier_move_ordinal: u32,
    distinct_query_group_ordinal: u32,
) -> Result<&[u64], CompactMerklePrivacyError> {
    let move_index = usize::try_from(logical_verifier_move_ordinal)
        .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
    let group_index = usize::try_from(distinct_query_group_ordinal)
        .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
    verifier_messages
        .get(move_index)
        .and_then(|message| message.distinct_query_groups().get(group_index))
        .map(Vec::as_slice)
        .ok_or(CompactMerklePrivacyError::InvalidConstructionEmbedding)
}

fn query_group_matches(observed: &[u64], first_leaf_ordinal: u64, group: &[u64]) -> bool {
    observed.len() == group.len()
        && observed
            .iter()
            .zip(group)
            .all(|(observed, component_leaf)| {
                first_leaf_ordinal.checked_add(*component_leaf) == Some(*observed)
            })
}

fn query_group_union_matches(
    observed: &[u64],
    first_leaf_ordinal: u64,
    first_group: &[u64],
    second_group: &[u64],
) -> bool {
    let mut observed_offset = 0_usize;
    let mut first_offset = 0_usize;
    let mut second_offset = 0_usize;
    while first_offset < first_group.len() || second_offset < second_group.len() {
        let component_leaf_ordinal = match (
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
        let Some(expected) = first_leaf_ordinal.checked_add(component_leaf_ordinal) else {
            return false;
        };
        if observed.get(observed_offset) != Some(&expected) {
            return false;
        }
        observed_offset += 1;
    }
    observed_offset == observed.len()
}

fn query_source_is_present(
    query_source: CompactCommitmentQuerySource,
    first_leaf_ordinal: u64,
    observed_component_schedule: &[u64],
    verifier_messages: &[DecodedFixedUniformVerifierMessage],
) -> Result<bool, CompactMerklePrivacyError> {
    let CompactCommitmentQuerySource::SharedCrossEpochUnion {
        owned_pre_challenge,
        reused_main,
    } = query_source
    else {
        return Ok(true);
    };
    Ok(query_coordinate_is_present(
        owned_pre_challenge,
        first_leaf_ordinal,
        observed_component_schedule,
        verifier_messages,
    )? && query_coordinate_is_present(
        reused_main,
        first_leaf_ordinal,
        observed_component_schedule,
        verifier_messages,
    )?)
}

fn query_coordinate_is_present(
    coordinate: CompactCommitmentQueryCoordinate,
    first_leaf_ordinal: u64,
    observed_component_schedule: &[u64],
    verifier_messages: &[DecodedFixedUniformVerifierMessage],
) -> Result<bool, CompactMerklePrivacyError> {
    let group = decoded_query_group(
        verifier_messages,
        coordinate.logical_verifier_move_ordinal,
        coordinate.distinct_query_group_ordinal,
    )?;
    Ok(!group.is_empty()
        && group.iter().all(|component_leaf_ordinal| {
            first_leaf_ordinal
                .checked_add(*component_leaf_ordinal)
                .is_some_and(|leaf_ordinal| {
                    observed_component_schedule
                        .binary_search(&leaf_ordinal)
                        .is_ok()
                })
        }))
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactEproPatchEntry {
    preimage: Vec<u8>,
    output: [u8; Hash512::BYTE_LENGTH],
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CompactEproPatch {
    entries: Vec<CompactEproPatchEntry>,
}

#[cfg(test)]
impl CompactEproPatch {
    fn evaluate(&self, preimage: &[u8]) -> [u8; Hash512::BYTE_LENGTH] {
        self.entries
            .iter()
            .find(|entry| entry.preimage == preimage)
            .map_or_else(
                || compact_response_hash_preimage(preimage),
                |entry| entry.output,
            )
    }

    fn program(
        &mut self,
        preimage: Vec<u8>,
        output: [u8; Hash512::BYTE_LENGTH],
        retired_preimages: &[Vec<u8>],
        retired_outputs: &[[u8; Hash512::BYTE_LENGTH]],
    ) -> Result<(), CompactMerklePrivacyError> {
        if retired_preimages.contains(&preimage) {
            return Err(CompactMerklePrivacyError::RetiredOracleInput);
        }
        if retired_outputs.contains(&output) {
            return Err(CompactMerklePrivacyError::RetiredOracleOutput);
        }
        if let Some(existing) = self.entries.iter().find(|entry| entry.preimage == preimage) {
            return if existing.output == output {
                Ok(())
            } else {
                Err(CompactMerklePrivacyError::ConflictingOracleInput)
            };
        }
        if self.entries.iter().any(|entry| entry.output == output) {
            return Err(CompactMerklePrivacyError::OracleOutputCollision);
        }
        self.entries
            .push(CompactEproPatchEntry { preimage, output });
        Ok(())
    }
}

#[cfg(test)]
fn stage_patch_entry(
    committed: &CompactEproPatch,
    staged: &mut Vec<CompactEproPatchEntry>,
    preimage: Vec<u8>,
    output: [u8; Hash512::BYTE_LENGTH],
    retired_preimages: &[Vec<u8>],
    retired_outputs: &[[u8; Hash512::BYTE_LENGTH]],
) -> Result<(), CompactMerklePrivacyError> {
    if retired_preimages.contains(&preimage) {
        return Err(CompactMerklePrivacyError::RetiredOracleInput);
    }
    if retired_outputs.contains(&output) {
        return Err(CompactMerklePrivacyError::RetiredOracleOutput);
    }
    if let Some(existing) = committed
        .entries
        .iter()
        .chain(staged.iter())
        .find(|entry| entry.preimage == preimage)
    {
        return if existing.output == output {
            Ok(())
        } else {
            Err(CompactMerklePrivacyError::ConflictingOracleInput)
        };
    }
    if committed
        .entries
        .iter()
        .chain(staged.iter())
        .any(|entry| entry.output == output)
    {
        return Err(CompactMerklePrivacyError::OracleOutputCollision);
    }
    staged.push(CompactEproPatchEntry { preimage, output });
    Ok(())
}

#[cfg(test)]
trait CompactEproIdealOracle {
    fn sample_output(&mut self) -> [u8; Hash512::BYTE_LENGTH];
}

#[cfg(test)]
struct CompactEproResponseOpening<'value> {
    opening_verifier_move_ordinal: u32,
    verifier_message_prefix: &'value [DecodedFixedUniformVerifierMessage],
    decoded_response: &'value DecodedCompactProofResponse,
    canonical_proof_bytes: &'value [u8],
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactEproResponseState {
    root: [u8; Hash512::BYTE_LENGTH],
    patch_start: usize,
    patch_end: Option<usize>,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMerkleEproCheckpoint {
    contract_source_hash: Hash512,
    attempt_identifier: [u8; 32],
    reset_ordinal: u32,
    response_count: usize,
    patch_entry_count: usize,
}

/// Test-only finite EPRO chronology. A response root is published before its
/// same-ordinal verifier message; its opening is programmed atomically only at
/// the last verifier move that queries that response. Failed programming
/// retries leave no entries. A security-game rewind permanently retires the
/// discarded oracle suffix so it cannot be replayed; this deliberately does
/// not model product checkpoint restoration.
#[cfg(test)]
struct CompactMerkleEproSimulation<'contract> {
    proof_wire_geometry: &'contract CompactProofWireGeometry,
    response_merkle_geometries: &'contract [CompactResponseMerkleGeometry],
    privacy_certificate: CompactMerklePrivacyCertificate,
    attempt_identifier: [u8; 32],
    reset_ordinal: u32,
    responses: Vec<CompactEproResponseState>,
    patch: CompactEproPatch,
    retired_preimages: Vec<Vec<u8>>,
    retired_outputs: Vec<[u8; Hash512::BYTE_LENGTH]>,
}

#[cfg(test)]
impl<'contract> CompactMerkleEproSimulation<'contract> {
    fn new(
        contract: &'contract CompactPublicKeyProofContract,
        attempt_identifier: [u8; 32],
    ) -> Result<Self, CompactMerklePrivacyError> {
        let inputs = contract.verifier_inputs();
        let coefficient_map = derive_selected_compact_masking_coefficient_map_certificate()?;
        let privacy_certificate =
            derive_compact_merkle_privacy_certificate(&inputs, &coefficient_map)?;
        Ok(Self {
            proof_wire_geometry: inputs.proof_wire_geometry,
            response_merkle_geometries: inputs.response_merkle_geometries,
            privacy_certificate,
            attempt_identifier,
            reset_ordinal: 0,
            responses: Vec::new(),
            patch: CompactEproPatch::default(),
            retired_preimages: Vec::new(),
            retired_outputs: Vec::new(),
        })
    }

    const fn privacy_certificate(&self) -> &CompactMerklePrivacyCertificate {
        &self.privacy_certificate
    }

    fn publish_response_root(
        &mut self,
        response_ordinal: u32,
        root: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<(), CompactMerklePrivacyError> {
        if usize::try_from(response_ordinal).ok() != Some(self.responses.len())
            || self.responses.len() >= self.response_merkle_geometries.len()
        {
            return Err(CompactMerklePrivacyError::WrongResponseOrder);
        }
        if self.responses.iter().any(|response| response.root == root)
            || self.patch.entries.iter().any(|entry| entry.output == root)
            || self.retired_outputs.contains(&root)
        {
            return Err(CompactMerklePrivacyError::DuplicateResponseRoot);
        }
        self.responses.push(CompactEproResponseState {
            root,
            patch_start: self.patch.entries.len(),
            patch_end: None,
        });
        Ok(())
    }

    fn publish_ideal_response_root(
        &mut self,
        response_ordinal: u32,
        ideal_oracle: &mut impl CompactEproIdealOracle,
    ) -> Result<(), CompactMerklePrivacyError> {
        let root = ideal_oracle.sample_output();
        self.publish_response_root(response_ordinal, root)
    }

    fn program_response_opening(
        &mut self,
        opening: CompactEproResponseOpening<'_>,
        ideal_oracle: &mut impl CompactEproIdealOracle,
    ) -> Result<(), CompactMerklePrivacyError> {
        let response_ordinal = opening.decoded_response.ordinal();
        let response_index = usize::try_from(response_ordinal)
            .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
        let geometry = self
            .response_merkle_geometries
            .get(response_index)
            .ok_or(CompactMerklePrivacyError::WrongResponseOrder)?;
        let response = self
            .responses
            .get(response_index)
            .ok_or(CompactMerklePrivacyError::MissingResponseRoot)?;
        if response.patch_end.is_some() {
            return Err(CompactMerklePrivacyError::DuplicateResponseRoot);
        }
        if opening.opening_verifier_move_ordinal != geometry.last_query_verifier_move_ordinal() {
            return Err(CompactMerklePrivacyError::WrongOpeningBoundary);
        }
        let query_schedule = derive_and_validate_compact_response_query_schedule(
            &self.privacy_certificate,
            response_ordinal,
            geometry,
            self.proof_wire_geometry.responses(),
            opening.verifier_message_prefix,
        )?;
        let mut reserved_outputs = BTreeSet::new();
        for response in &self.responses {
            if !reserved_outputs.insert(response.root) {
                return Err(CompactMerklePrivacyError::DuplicateResponseRoot);
            }
        }
        let mut frontier = Vec::new();
        frontier
            .try_reserve_exact(opening.decoded_response.frontier_node_count())
            .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
        for frontier_ordinal in 0..opening.decoded_response.frontier_node_count() {
            let frontier_digest = opening
                .decoded_response
                .frontier_node(opening.canonical_proof_bytes, frontier_ordinal)
                .map_err(|_| {
                    CompactMerklePrivacyError::Merkle(CompactResponseMerkleError::InvalidWireValue)
                })?;
            if self
                .patch
                .entries
                .iter()
                .any(|entry| entry.output == frontier_digest)
                || self.retired_outputs.contains(&frontier_digest)
                || !reserved_outputs.insert(frontier_digest)
            {
                return Err(CompactMerklePrivacyError::OracleOutputCollision);
            }
            frontier.push(frontier_digest);
        }
        let mut staged_entries = Vec::new();
        let mut leaf_digests = Vec::new();
        leaf_digests
            .try_reserve_exact(query_schedule.as_slice().len())
            .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?;
        let mut leaf_cursor = CompactResponseOpenedLeafHashCursor::new(
            geometry,
            opening.decoded_response,
            opening.canonical_proof_bytes,
            &query_schedule,
        )?;
        while let Some(preimage) = leaf_cursor.next_preimage()? {
            let output = ideal_oracle.sample_output();
            if reserved_outputs.contains(&output) {
                return Err(CompactMerklePrivacyError::OracleOutputCollision);
            }
            stage_patch_entry(
                &self.patch,
                &mut staged_entries,
                preimage,
                output,
                &self.retired_preimages,
                &self.retired_outputs,
            )?;
            leaf_digests.push(output);
        }
        let mut reconstruction = CompactResponseRootReconstruction::new(
            geometry,
            &query_schedule,
            &leaf_digests,
            &frontier,
        )?;
        let root = loop {
            match reconstruction.poll()? {
                CompactResponseRootReconstructionPoll::ParentHash(request) => {
                    let output = if request.is_root() {
                        opening.decoded_response.root()
                    } else {
                        let output = ideal_oracle.sample_output();
                        if reserved_outputs.contains(&output) {
                            return Err(CompactMerklePrivacyError::OracleOutputCollision);
                        }
                        output
                    };
                    stage_patch_entry(
                        &self.patch,
                        &mut staged_entries,
                        request.preimage()?,
                        output,
                        &self.retired_preimages,
                        &self.retired_outputs,
                    )?;
                    reconstruction.absorb_parent_digest(output)?;
                }
                CompactResponseRootReconstructionPoll::Complete(root) => break root,
            }
        };
        if root != response.root || root != opening.decoded_response.root() {
            return Err(CompactMerklePrivacyError::RootMismatch);
        }
        self.patch.entries.extend(staged_entries);
        let patch_end = self.patch.entries.len();
        self.responses[response_index].patch_end = Some(patch_end);
        Ok(())
    }

    fn checkpoint(&self) -> Result<CompactMerkleEproCheckpoint, CompactMerklePrivacyError> {
        if self
            .responses
            .iter()
            .any(|response| response.patch_end.is_none())
        {
            return Err(CompactMerklePrivacyError::WrongOpeningBoundary);
        }
        Ok(CompactMerkleEproCheckpoint {
            contract_source_hash: self.privacy_certificate.contract_source_hash,
            attempt_identifier: self.attempt_identifier,
            reset_ordinal: self.reset_ordinal,
            response_count: self.responses.len(),
            patch_entry_count: self.patch.entries.len(),
        })
    }

    fn reset_to(
        &mut self,
        checkpoint: &CompactMerkleEproCheckpoint,
    ) -> Result<(), CompactMerklePrivacyError> {
        if checkpoint.contract_source_hash != self.privacy_certificate.contract_source_hash
            || checkpoint.attempt_identifier != self.attempt_identifier
            || checkpoint.reset_ordinal != self.reset_ordinal
            || checkpoint.response_count > self.responses.len()
            || checkpoint.patch_entry_count > self.patch.entries.len()
            || self.responses[..checkpoint.response_count]
                .iter()
                .any(|response| {
                    response.patch_end != Some(checkpoint.patch_entry_count)
                        && response
                            .patch_end
                            .is_none_or(|end| end > checkpoint.patch_entry_count)
                })
            || self.responses[checkpoint.response_count..]
                .iter()
                .any(|response| response.patch_start < checkpoint.patch_entry_count)
        {
            return Err(CompactMerklePrivacyError::WrongCheckpoint);
        }
        let discarded = self.patch.entries.split_off(checkpoint.patch_entry_count);
        for entry in discarded {
            self.retired_preimages.push(entry.preimage);
            self.retired_outputs.push(entry.output);
        }
        for response in self.responses.drain(checkpoint.response_count..) {
            self.retired_outputs.push(response.root);
        }
        self.reset_ordinal = self
            .reset_ordinal
            .checked_add(1)
            .ok_or(CompactMerklePrivacyError::ArithmeticOverflow)?;
        Ok(())
    }

    fn finish(self) -> Result<CompactMerkleEproCertificate, CompactMerklePrivacyError> {
        if self.responses.len() != self.response_merkle_geometries.len()
            || self
                .responses
                .iter()
                .any(|response| response.patch_end.is_none())
        {
            return Err(CompactMerklePrivacyError::IncompleteAttempt);
        }
        Ok(CompactMerkleEproCertificate {
            privacy: self.privacy_certificate,
            programmed_query_count: u64::try_from(self.patch.entries.len())
                .map_err(|_| CompactMerklePrivacyError::ArithmeticOverflow)?,
        })
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactMerkleEproCertificate {
    privacy: CompactMerklePrivacyCertificate,
    programmed_query_count: u64,
}

#[cfg(test)]
impl CompactMerkleEproCertificate {
    const fn privacy(&self) -> &CompactMerklePrivacyCertificate {
        &self.privacy
    }

    const fn programmed_query_count(&self) -> u64 {
        self.programmed_query_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_masking_coefficient_maps::CompactMaskingViewRole;
    use crate::bgv::proof_suite::compact_proof_contract::CompactResponseComponentRoleContract;
    use crate::bgv::proof_suite::compact_proof_wire::{
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireInput,
        CompactProofWireInput, decode_compact_proof_wire, encode_compact_proof_wire,
    };
    use crate::bgv::proof_suite::compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValue, CompactResponseLeafValueKind,
        compact_response_leaf_digest, compact_response_merkle_parent_digest,
    };
    use crate::bgv::proof_suite::field::ProofBaseFieldElement;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageGeometry,
        derive_fixed_uniform_verifier_message,
    };
    use crate::hashing::hash_framed_parts_512;

    fn selected_verifier_messages(
        inputs: &CompactPublicKeyVerifierInputs<'_>,
    ) -> Vec<DecodedFixedUniformVerifierMessage> {
        inputs
            .proof_wire_geometry
            .responses()
            .iter()
            .map(|wire_geometry| {
                let mut transcript_state = [0_u8; Hash512::BYTE_LENGTH];
                transcript_state[..4].copy_from_slice(&wire_geometry.ordinal().to_le_bytes());
                derive_fixed_uniform_verifier_message(
                    Hash512::from_bytes(transcript_state),
                    wire_geometry.ordinal(),
                    wire_geometry.verifier_message_geometry(),
                )
                .expect("selected verifier message derives")
            })
            .collect()
    }

    fn small_epro_privacy_certificate(
        geometry: &CompactResponseMerkleGeometry,
    ) -> CompactMerklePrivacyCertificate {
        let component = &geometry.components()[0];
        let committed_leaf_count = geometry.merkle_leaf_count();
        let salt_collision_numerator = BigUint::from(committed_leaf_count)
            * BigUint::from(committed_leaf_count.saturating_sub(1))
            / BigUint::from(2_u8);
        let component_role = CompactResponseComponentRoleContract {
            role_tag: 1,
            epoch: 1,
            batch_ordinal: 0,
            round_ordinal: 0,
        };
        CompactMerklePrivacyCertificate {
            contract_source_hash: Hash512::from_bytes(hash_framed_parts_512(
                "sealed-lattice/test-only/compact-merkle-epro-contract/v1",
                &[b"one response; two base-field leaves; one verifier query"],
            )),
            response_commitment_count: 1,
            committed_leaf_count,
            construction_bindings: vec![CompactConstructionMerkleBinding {
                commitment_ordinal: 0,
                response_ordinal: geometry.response_ordinal(),
                component_ordinal: 0,
                first_leaf_ordinal: component.first_leaf_ordinal(),
                leaf_count: component.leaf_count(),
                ownership: CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 1 },
                query_source: CompactCommitmentQuerySource::Component,
            }],
            response_component_embeddings: vec![CompactResponseComponentEmbedding {
                outer_response_ordinal: geometry.response_ordinal(),
                component_ordinal: 0,
                semantic_role: Some(CompactMaskingViewRole::Source),
                component_role,
                first_leaf_ordinal: component.first_leaf_ordinal(),
                leaf_count: component.leaf_count(),
                minimum_queried_leaf_count: component.minimum_queried_leaf_count(),
                maximum_queried_leaf_count: component.maximum_queried_leaf_count(),
                query_selection: component.query_selection(),
                value_kind: component.value_kind(),
                field_element_count_per_leaf: component.field_element_count_per_leaf(),
            }],
            bcs16_statistical_distance: CompactMerkleProbabilityBound {
                numerator: BigUint::from(committed_leaf_count),
                denominator_power: BCS16_MERKLE_PRIVACY_DENOMINATOR_POWER,
            },
            leaf_salt_collision: CompactMerkleProbabilityBound {
                numerator: salt_collision_numerator,
                denominator_power: LEAF_SALT_BIT_LENGTH,
            },
        }
    }

    #[test]
    fn selected_topology_derives_82_salted_roots_and_45_typed_embeddings() {
        let certificate = derive_selected_compact_merkle_privacy_certificate().unwrap();
        let contract = selected_compact_public_key_proof_contract().unwrap();
        let contract_component_count = contract
            .verifier_inputs()
            .response_merkle_geometries
            .iter()
            .map(|geometry| geometry.components().len())
            .sum::<usize>();
        assert_eq!(certificate.response_commitment_count(), 82);
        assert_eq!(certificate.committed_leaf_count(), 639_270);
        assert_eq!(certificate.construction_bindings().len(), 45);
        assert_eq!(contract_component_count, 161);
        assert_eq!(
            certificate.response_component_embedding_count(),
            contract_component_count
        );
        assert_eq!(
            certificate.bcs16_statistical_distance().numerator(),
            &BigUint::from(639_270_u64)
        );
        assert_eq!(
            certificate.bcs16_statistical_distance().denominator_power(),
            126
        );
        assert_eq!(certificate.leaf_salt_collision().denominator_power(), 1024);
        let shared = certificate
            .construction_bindings()
            .iter()
            .filter(|binding| {
                !matches!(
                    binding.query_source,
                    CompactCommitmentQuerySource::Component
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 1);
        assert_eq!(
            shared[0].ownership,
            CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch
        );
        let CompactCommitmentQuerySource::SharedCrossEpochUnion {
            owned_pre_challenge,
            reused_main,
        } = shared[0].query_source
        else {
            panic!("role-five commitment must own the typed query union");
        };
        assert_ne!(owned_pre_challenge, reused_main);
    }

    fn assert_invalid_response_embedding(
        inputs: &CompactPublicKeyVerifierInputs<'_>,
        embeddings: &[CompactResponseComponentEmbedding],
        mutate: impl FnOnce(&mut CompactResponseComponentEmbedding),
    ) {
        let mut mutated = embeddings.to_vec();
        mutate(&mut mutated[0]);
        assert_eq!(
            validate_response_component_embeddings(inputs, &mutated),
            Err(CompactMerklePrivacyError::InvalidConstructionEmbedding)
        );
    }

    #[test]
    fn response_embedding_refuses_every_bound_field_class() {
        let contract = selected_compact_public_key_proof_contract().unwrap();
        let inputs = contract.verifier_inputs();
        let coefficient_map =
            derive_selected_compact_masking_coefficient_map_certificate().unwrap();
        let embeddings = coefficient_map.response_component_embeddings();
        validate_response_component_embeddings(&inputs, embeddings).unwrap();

        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.outer_response_ordinal += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.component_ordinal += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.semantic_role = Some(CompactMaskingViewRole::Mirror);
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.component_role.role_tag += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.component_role.epoch += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.component_role.batch_ordinal += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.component_role.round_ordinal += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.first_leaf_ordinal += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.leaf_count -= 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.minimum_queried_leaf_count -= 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.maximum_queried_leaf_count += 1;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.query_selection = CompactResponseQuerySelection::Unqueried;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.value_kind =
                super::super::compact_response_merkle::CompactResponseLeafValueKind::Padding;
        });
        assert_invalid_response_embedding(&inputs, embeddings, |embedding| {
            embedding.field_element_count_per_leaf += 1;
        });
    }

    fn assert_invalid_construction_embedding(
        inputs: &CompactPublicKeyVerifierInputs<'_>,
        response_embeddings: &[CompactResponseComponentEmbedding],
        construction_embeddings: &[CompactConstructionCommitmentEmbedding],
        mutate: impl FnOnce(&mut CompactConstructionCommitmentEmbedding),
    ) {
        let mut mutated = construction_embeddings.to_vec();
        mutate(&mut mutated[0]);
        assert_eq!(
            derive_construction_bindings(inputs, response_embeddings, &mutated),
            Err(CompactMerklePrivacyError::InvalidConstructionEmbedding)
        );
    }

    fn assert_invalid_shared_construction_embedding(
        inputs: &CompactPublicKeyVerifierInputs<'_>,
        response_embeddings: &[CompactResponseComponentEmbedding],
        construction_embeddings: &[CompactConstructionCommitmentEmbedding],
        mutate: impl FnOnce(&mut CompactConstructionCommitmentEmbedding),
    ) {
        let mut mutated = construction_embeddings.to_vec();
        let shared = mutated
            .iter_mut()
            .find(|embedding| embedding.component_role.role_tag == 5)
            .expect("selected topology has one shared cross-epoch commitment");
        mutate(shared);
        assert_eq!(
            derive_construction_bindings(inputs, response_embeddings, &mutated),
            Err(CompactMerklePrivacyError::InvalidConstructionEmbedding)
        );
    }

    #[test]
    fn construction_embedding_refuses_every_bound_field_class() {
        let contract = selected_compact_public_key_proof_contract().unwrap();
        let inputs = contract.verifier_inputs();
        let coefficient_map =
            derive_selected_compact_masking_coefficient_map_certificate().unwrap();
        let response_embeddings = coefficient_map.response_component_embeddings();
        let construction_embeddings = coefficient_map.construction_commitment_embeddings();
        derive_construction_bindings(&inputs, response_embeddings, construction_embeddings)
            .unwrap();

        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.commitment_ordinal += 1,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.outer_response_ordinal += 1,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.component_ordinal += 1,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.semantic_role = CompactMaskingViewRole::Mirror,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.component_role.role_tag += 1,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.component_role.epoch += 1,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.component_role.batch_ordinal += 1,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.component_role.round_ordinal += 1,
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| {
                embedding.ownership = match embedding.ownership {
                    CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 1 } => {
                        CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 2 }
                    }
                    CompactConstructionCommitmentOwnership::OwnedByEpoch { .. } => {
                        CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 1 }
                    }
                    CompactConstructionCommitmentOwnership::OwnedByPreChallengeEpochReusedByMainEpoch => {
                        CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 1 }
                    }
                };
            },
        );
        assert_invalid_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| {
                embedding.query_source = CompactCommitmentQuerySource::SharedCrossEpochUnion {
                    owned_pre_challenge: CompactCommitmentQueryCoordinate {
                        logical_verifier_move_ordinal: 0,
                        distinct_query_group_ordinal: 0,
                    },
                    reused_main: CompactCommitmentQueryCoordinate {
                        logical_verifier_move_ordinal: 1,
                        distinct_query_group_ordinal: 0,
                    },
                };
            },
        );
        assert_invalid_shared_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| {
                embedding.ownership =
                    CompactConstructionCommitmentOwnership::OwnedByEpoch { epoch: 1 };
            },
        );
        assert_invalid_shared_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| embedding.query_source = CompactCommitmentQuerySource::Component,
        );
        assert_invalid_shared_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| {
                let CompactCommitmentQuerySource::SharedCrossEpochUnion {
                    owned_pre_challenge,
                    ..
                } = &mut embedding.query_source
                else {
                    panic!("role-five query source must be a union");
                };
                owned_pre_challenge.distinct_query_group_ordinal += 1;
            },
        );
        assert_invalid_shared_construction_embedding(
            &inputs,
            response_embeddings,
            construction_embeddings,
            |embedding| {
                let CompactCommitmentQuerySource::SharedCrossEpochUnion { reused_main, .. } =
                    &mut embedding.query_source
                else {
                    panic!("role-five query source must be a union");
                };
                reused_main.distinct_query_group_ordinal += 1;
            },
        );
    }

    #[test]
    fn finite_patch_rejects_conflicts_collisions_and_retired_values() {
        let mut patch = CompactEproPatch::default();
        patch.program(vec![1], [2; 64], &[], &[]).unwrap();
        assert_eq!(patch.evaluate(&[1]), [2; 64]);
        assert_eq!(
            patch.program(vec![1], [3; 64], &[], &[]),
            Err(CompactMerklePrivacyError::ConflictingOracleInput)
        );
        assert_eq!(
            patch.program(vec![2], [2; 64], &[], &[]),
            Err(CompactMerklePrivacyError::OracleOutputCollision)
        );
        assert_eq!(
            patch.program(vec![3], [4; 64], &[vec![3]], &[]),
            Err(CompactMerklePrivacyError::RetiredOracleInput)
        );
        assert_eq!(
            patch.program(vec![4], [5; 64], &[], &[[5; 64]]),
            Err(CompactMerklePrivacyError::RetiredOracleOutput)
        );
    }

    #[test]
    fn selected_role_five_opening_requires_both_exact_verifier_query_arms() {
        let contract = selected_compact_public_key_proof_contract().unwrap();
        let inputs = contract.verifier_inputs();
        let messages = selected_verifier_messages(&inputs);
        let certificate = derive_selected_compact_merkle_privacy_certificate().unwrap();
        let shared_bindings = certificate
            .construction_bindings
            .iter()
            .enumerate()
            .filter(|(_, binding)| {
                !matches!(
                    binding.query_source,
                    CompactCommitmentQuerySource::Component
                )
            })
            .map(|(index, binding)| (index, *binding))
            .collect::<Vec<_>>();
        assert_eq!(shared_bindings.len(), 1);
        let response_index = usize::try_from(shared_bindings[0].1.response_ordinal).unwrap();
        let geometry = &inputs.response_merkle_geometries[response_index];
        let prefix_length = usize::try_from(
            geometry
                .last_query_verifier_move_ordinal()
                .checked_add(1)
                .unwrap(),
        )
        .unwrap();
        let verifier_message_prefix = &messages[..prefix_length];

        let schedule = derive_and_validate_compact_response_query_schedule(
            &certificate,
            geometry.response_ordinal(),
            geometry,
            inputs.proof_wire_geometry.responses(),
            verifier_message_prefix,
        )
        .expect("both exact role-five arms validate");
        let shared_component = geometry
            .components()
            .get(usize::try_from(shared_bindings[0].1.component_ordinal).unwrap())
            .unwrap();
        let observed = component_schedule_slice(&schedule, shared_component).unwrap();
        let (binding_index, binding) = shared_bindings[0];
        assert!(
            query_source_is_present(
                binding.query_source,
                binding.first_leaf_ordinal,
                observed,
                verifier_message_prefix,
            )
            .unwrap()
        );
        let CompactCommitmentQuerySource::SharedCrossEpochUnion {
            owned_pre_challenge,
            reused_main,
        } = binding.query_source
        else {
            panic!("role-five query source must be a union");
        };
        assert!(
            query_coordinate_is_present(
                owned_pre_challenge,
                binding.first_leaf_ordinal,
                observed,
                verifier_message_prefix,
            )
            .unwrap()
        );
        assert!(
            query_coordinate_is_present(
                reused_main,
                binding.first_leaf_ordinal,
                observed,
                verifier_message_prefix,
            )
            .unwrap()
        );

        for mutate_owned_pre_challenge in [true, false] {
            let mut tampered = certificate.clone();
            let CompactCommitmentQuerySource::SharedCrossEpochUnion {
                owned_pre_challenge,
                reused_main,
            } = &mut tampered.construction_bindings[binding_index].query_source
            else {
                panic!("role-five query source must be a union");
            };
            let coordinate = if mutate_owned_pre_challenge {
                owned_pre_challenge
            } else {
                reused_main
            };
            coordinate.distinct_query_group_ordinal += 1;
            assert_eq!(
                derive_and_validate_compact_response_query_schedule(
                    &tampered,
                    geometry.response_ordinal(),
                    geometry,
                    inputs.proof_wire_geometry.responses(),
                    verifier_message_prefix,
                ),
                Err(CompactMerklePrivacyError::InvalidConstructionEmbedding)
            );
        }
    }

    #[test]
    fn failed_patch_staging_is_atomic_and_a_clean_retry_succeeds() {
        let committed = CompactEproPatch::default();
        let mut failed_staging = Vec::new();
        stage_patch_entry(
            &committed,
            &mut failed_staging,
            vec![0x11],
            [0x21; Hash512::BYTE_LENGTH],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            stage_patch_entry(
                &committed,
                &mut failed_staging,
                vec![0x12],
                [0x21; Hash512::BYTE_LENGTH],
                &[],
                &[],
            ),
            Err(CompactMerklePrivacyError::OracleOutputCollision)
        );
        assert!(committed.entries.is_empty());

        let mut retry_staging = Vec::new();
        stage_patch_entry(
            &committed,
            &mut retry_staging,
            vec![0x11],
            [0x22; Hash512::BYTE_LENGTH],
            &[],
            &[],
        )
        .unwrap();
        stage_patch_entry(
            &committed,
            &mut retry_staging,
            vec![0x12],
            [0x23; Hash512::BYTE_LENGTH],
            &[],
            &[],
        )
        .unwrap();
        let mut committed = committed;
        committed.entries.extend(retry_staging);
        assert_eq!(committed.evaluate(&[0x11]), [0x22; Hash512::BYTE_LENGTH]);
        assert_eq!(committed.evaluate(&[0x12]), [0x23; Hash512::BYTE_LENGTH]);
    }

    #[test]
    fn finite_epro_programs_a_canonical_small_opening_and_finishes() {
        struct ExactLeafOracle(Option<[u8; Hash512::BYTE_LENGTH]>);

        impl CompactEproIdealOracle for ExactLeafOracle {
            fn sample_output(&mut self) -> [u8; Hash512::BYTE_LENGTH] {
                self.0.take().expect("the opening samples one leaf digest")
            }
        }

        let verifier_message_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(2, 1)],
        )
        .expect("one binary query group");
        let response_geometry = CompactResponseMerkleGeometry::new(
            0,
            vec![CompactResponseComponentGeometry::new(
                0,
                2,
                1,
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal: 0,
                    distinct_query_group_ordinal: 0,
                },
                CompactResponseLeafValueKind::BaseField,
                1,
            )],
        )
        .expect("two-leaf response geometry");
        let response_wire_geometry =
            CompactProofResponseWireGeometry::new(0, 1, 0, 1, 1, verifier_message_geometry.clone())
                .expect("one-leaf opening wire geometry");
        let proof_wire_geometry =
            CompactProofWireGeometry::new(vec![response_wire_geometry]).unwrap();
        CompactResponseQuerySchedule::validate_registry(
            std::slice::from_ref(&response_geometry),
            proof_wire_geometry.responses(),
        )
        .expect("the query group is owned exactly once");

        let verifier_message = derive_fixed_uniform_verifier_message(
            Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]),
            0,
            &verifier_message_geometry,
        )
        .expect("small verifier message derives");
        let queried_leaf_ordinal = verifier_message.distinct_query_groups()[0][0];
        let queried_leaf_index = usize::try_from(queried_leaf_ordinal).unwrap();
        let sibling_leaf_index = queried_leaf_index ^ 1;
        let values = [
            ProofBaseFieldElement::from_canonical(11).unwrap(),
            ProofBaseFieldElement::from_canonical(13).unwrap(),
        ];
        let salts = [
            [0x81; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
            [0x82; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
        ];
        let leaf_digests: [[u8; Hash512::BYTE_LENGTH]; 2] = std::array::from_fn(|leaf_index| {
            compact_response_leaf_digest(
                &response_geometry,
                u64::try_from(leaf_index).unwrap(),
                CompactResponseLeafValue::BaseField(std::slice::from_ref(&values[leaf_index])),
                &salts[leaf_index],
            )
            .unwrap()
        });
        let root = compact_response_merkle_parent_digest(
            &response_geometry,
            1,
            0,
            leaf_digests[0],
            leaf_digests[1],
        )
        .unwrap();
        let canonical_proof_bytes = encode_compact_proof_wire(
            &proof_wire_geometry,
            &CompactProofWireInput::new(vec![CompactProofResponseWireInput::new(
                root,
                [0x91; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
                vec![values[queried_leaf_index]],
                Vec::new(),
                vec![salts[queried_leaf_index]],
                vec![leaf_digests[sibling_leaf_index]],
            )]),
        )
        .expect("canonical small opening encodes");
        let decoded_proof =
            decode_compact_proof_wire(&proof_wire_geometry, &canonical_proof_bytes).unwrap();
        let privacy_certificate = small_epro_privacy_certificate(&response_geometry);
        let mut simulation = CompactMerkleEproSimulation {
            proof_wire_geometry: &proof_wire_geometry,
            response_merkle_geometries: std::slice::from_ref(&response_geometry),
            privacy_certificate,
            attempt_identifier: [0xa1; 32],
            reset_ordinal: 0,
            responses: Vec::new(),
            patch: CompactEproPatch::default(),
            retired_preimages: Vec::new(),
            retired_outputs: Vec::new(),
        };
        simulation.publish_response_root(0, root).unwrap();
        let mut ideal_oracle = ExactLeafOracle(Some(leaf_digests[queried_leaf_index]));
        simulation
            .program_response_opening(
                CompactEproResponseOpening {
                    opening_verifier_move_ordinal: 0,
                    verifier_message_prefix: std::slice::from_ref(&verifier_message),
                    decoded_response: &decoded_proof.responses()[0],
                    canonical_proof_bytes: &canonical_proof_bytes,
                },
                &mut ideal_oracle,
            )
            .expect("the finite patch programs the leaf and parent preimages");
        assert!(ideal_oracle.0.is_none());

        let certificate = simulation.finish().expect("the complete attempt finishes");
        assert_eq!(certificate.privacy().response_commitment_count(), 1);
        assert_eq!(certificate.privacy().committed_leaf_count(), 2);
        assert_eq!(certificate.programmed_query_count(), 2);
    }

    #[test]
    fn reset_retires_discarded_roots_and_rejects_stale_or_wrong_attempt_checkpoints() {
        struct FixedOracle([u8; Hash512::BYTE_LENGTH]);

        impl CompactEproIdealOracle for FixedOracle {
            fn sample_output(&mut self) -> [u8; Hash512::BYTE_LENGTH] {
                self.0
            }
        }

        let contract = selected_compact_public_key_proof_contract().unwrap();
        let attempt_identifier = [0x31; 32];
        let mut simulation =
            CompactMerkleEproSimulation::new(&contract, attempt_identifier).unwrap();
        assert_eq!(
            simulation.privacy_certificate().response_commitment_count(),
            82
        );
        let checkpoint = simulation.checkpoint().unwrap();
        let mut wrong_attempt = checkpoint.clone();
        wrong_attempt.attempt_identifier[0] ^= 1;
        assert_eq!(
            simulation.reset_to(&wrong_attempt),
            Err(CompactMerklePrivacyError::WrongCheckpoint)
        );

        let retired_root = [0x41; Hash512::BYTE_LENGTH];
        simulation
            .publish_ideal_response_root(0, &mut FixedOracle(retired_root))
            .unwrap();
        simulation
            .patch
            .program(
                vec![0x51],
                [0x61; Hash512::BYTE_LENGTH],
                &simulation.retired_preimages,
                &simulation.retired_outputs,
            )
            .unwrap();
        simulation
            .patch
            .program(
                vec![0x52],
                [0x62; Hash512::BYTE_LENGTH],
                &simulation.retired_preimages,
                &simulation.retired_outputs,
            )
            .unwrap();
        simulation.responses[0].patch_end = Some(2);
        assert_eq!(simulation.checkpoint().unwrap().patch_entry_count, 2,);
        simulation.reset_to(&checkpoint).unwrap();
        assert!(simulation.responses.is_empty());
        assert_eq!(simulation.patch.entries.len(), 0);
        assert_eq!(simulation.retired_preimages, [vec![0x51], vec![0x52]]);
        assert_eq!(
            simulation.retired_outputs,
            [
                [0x61; Hash512::BYTE_LENGTH],
                [0x62; Hash512::BYTE_LENGTH],
                retired_root,
            ]
        );
        assert_eq!(
            simulation.patch.program(
                vec![0x51],
                [0x63; Hash512::BYTE_LENGTH],
                &simulation.retired_preimages,
                &simulation.retired_outputs,
            ),
            Err(CompactMerklePrivacyError::RetiredOracleInput)
        );
        assert_eq!(
            simulation.patch.program(
                vec![0x53],
                [0x62; Hash512::BYTE_LENGTH],
                &simulation.retired_preimages,
                &simulation.retired_outputs,
            ),
            Err(CompactMerklePrivacyError::RetiredOracleOutput)
        );
        assert_eq!(
            simulation.publish_response_root(0, retired_root),
            Err(CompactMerklePrivacyError::DuplicateResponseRoot)
        );
        assert_eq!(
            simulation.reset_to(&checkpoint),
            Err(CompactMerklePrivacyError::WrongCheckpoint)
        );
        assert_eq!(
            simulation.finish(),
            Err(CompactMerklePrivacyError::IncompleteAttempt)
        );
    }
}
