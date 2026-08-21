//! Frozen verifier-owned contract for the factor-one compact public-key proof.
//!
//! The checked-in bytes are decoded under fixed limits and then rebuilt into
//! the operative wire, transcript, response-Merkle, WHIR, and checkpoint
//! geometries. Proof bytes carry no contract fields: a producer cannot change
//! this record or any acceptance decision.

use super::PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
use super::application_statement::{
    SelectedApplicationStatementError, SelectedPublicKeyShareStatementLayout,
    selected_public_key_share_statement_layout,
};
use super::compact_cfw_geometry::{
    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH,
    CompactCfwCrossEpochVerifierGeometry, CompactCfwVerifierConfiguration,
};
use super::compact_generation_checkpoint::{
    CompactGenerationCheckpointError, CompactResponseCheckpointSchedule,
    compact_checkpoint_binding_domains,
};
use super::compact_proof_wire::{
    COMPACT_PACKING_FACTOR, COMPACT_PROOF_WIRE_MAGIC, COMPACT_PUBLIC_INPUT_WIRE_MAGIC,
    CompactProofResponseWireGeometry, CompactProofWireError, CompactProofWireGeometry,
    CompactPublicInputWireGeometry, compact_public_input_binding_roles,
};
use super::compact_response_merkle::{
    COMPACT_RESPONSE_LEAF_HASH_DOMAIN, COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
    CompactResponseComponentGeometry, CompactResponseLeafValueKind, CompactResponseMerkleError,
    CompactResponseMerkleGeometry, CompactResponseQuerySchedule, CompactResponseQuerySelection,
};
use super::compact_transcript::{
    COMPACT_FIAT_SHAMIR_PREFIX_VERSION, compact_transcript_binding_domains,
};
use super::compact_whir_geometry::CompactWhirVerifierGeometry;
use super::field::PROOF_BASE_FIELD_MODULUS;
use super::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN, FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION,
    FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN, FixedUniformDistinctQueryGeometry,
    FixedUniformVerifierMessageError, FixedUniformVerifierMessageGeometry,
};
use super::relation_plan::{
    CompactPublicKeyRelationCatalog, selected_compact_public_key_relation_catalog,
};
use crate::foundation::{FOUNDATION_PROFILE, Hash512};
use crate::hashing::hash_framed_parts_512;

const CONTRACT_MAGIC: [u8; 8] = *b"SLCPC001";
const CONTRACT_VERSION: u16 = 3;
const EXPECTED_RESPONSE_COUNT: usize = 82;
const EXPECTED_COMMITMENT_COUNT: u32 = 45;
const EXPECTED_DISTINCT_QUERY_GROUP_COUNT: u32 = 26;
const WHIR_EPOCH_COUNT: usize = 2;
const WHIR_FOLD_COUNT_PER_EPOCH: usize = 4;
const EXPECTED_WHIR_FOLD_COUNT: usize = WHIR_EPOCH_COUNT * WHIR_FOLD_COUNT_PER_EPOCH;
const WHIR_ROUND_COUNT: usize = 3;
const WHIR_MAIN_LOG_INVERSE_RATE: u32 = 2;
const WHIR_SUMCHECK_MASK_MESSAGE_LENGTH: u64 = 3;
const WHIR_SUMCHECK_WIRE_EXTENSION_ELEMENT_COUNT: u64 = 2;
const WHIR_AUXILIARY_TARGET_COUNT: u64 = 1;
const WHIR_BASE_MASKED_CLAIM_COUNT: u64 = 1;
const MAXIMUM_CONTRACT_BYTE_LENGTH: usize = 4 * 1024 * 1024;
const MAXIMUM_CONTRACT_LIST_LENGTH: usize = 16_384;
const GENERATED_CONTRACT_SOURCE_HASH_DOMAIN: &str =
    "sealed-lattice/bgv/compact-public-key-proof-contract/source/v1";

/// Generated source is authoritative. The byte-identity test below derives the
/// same record independently from the production relation and proof catalogs.
const GENERATED_CONTRACT_BYTES: &[u8] = include_bytes!("compact_proof_contract.generated.bin");

fn compact_contract_binding_domains() -> [&'static str; 10] {
    let transcript = compact_transcript_binding_domains();
    let checkpoint = compact_checkpoint_binding_domains();
    [
        transcript[0],
        FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN,
        FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN,
        COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
        COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
        transcript[1],
        transcript[2],
        transcript[3],
        checkpoint[0],
        checkpoint[1],
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactPublicKeyProofContract {
    relation: CompactPublicKeyRelationCatalog,
    cfw_configuration: CompactCfwVerifierConfiguration,
    statement_layout: SelectedPublicKeyShareStatementLayout,
    public_input_wire_geometry: CompactPublicInputWireGeometry,
    proof_wire_geometry: CompactProofWireGeometry,
    response_merkle_geometries: Vec<CompactResponseMerkleGeometry>,
    response_component_roles: Vec<Vec<CompactResponseComponentRoleContract>>,
    checkpoint_schedule: CompactResponseCheckpointSchedule,
    verifier_moves: Vec<CompactVerifierMoveContract>,
    whir_epochs: Vec<CompactWhirEpochContract>,
    whir_folds: Vec<CompactWhirFoldContract>,
}

/// One borrowed, already-validated set of inputs for the compact verifier.
/// Keeping the coupled rows behind this aggregate prevents a consumer from
/// pairing wire, Merkle, transcript, WHIR, or checkpoint rows from different
/// contract records.
pub(crate) struct CompactPublicKeyVerifierInputs<'a> {
    pub(crate) relation: &'a CompactPublicKeyRelationCatalog,
    pub(crate) cfw_configuration: CompactCfwVerifierConfiguration,
    pub(crate) statement_layout: SelectedPublicKeyShareStatementLayout,
    pub(crate) public_input_wire_geometry: CompactPublicInputWireGeometry,
    pub(crate) proof_wire_geometry: &'a CompactProofWireGeometry,
    pub(crate) response_merkle_geometries: &'a [CompactResponseMerkleGeometry],
    pub(crate) response_component_roles: &'a [Vec<CompactResponseComponentRoleContract>],
    pub(crate) checkpoint_schedule: &'a CompactResponseCheckpointSchedule,
    pub(crate) verifier_moves: &'a [CompactVerifierMoveContract],
    pub(crate) whir_epochs: &'a [CompactWhirEpochContract],
    pub(crate) whir_folds: &'a [CompactWhirFoldContract],
}

#[cfg(test)]
pub(super) struct CompactProofContractGenerationInput {
    pub(super) relation_schema_digest: [u8; 64],
    pub(super) commitment_count: u32,
    pub(super) distinct_query_group_count: u32,
    pub(super) public_input_wire_geometry: CompactPublicInputWireGeometry,
    pub(super) proof_wire_geometry: CompactProofWireGeometry,
    pub(super) response_merkle_geometries: Vec<CompactResponseMerkleGeometry>,
    pub(super) response_component_roles: Vec<Vec<CompactResponseComponentRoleContract>>,
    pub(super) checkpoint_schedule: CompactResponseCheckpointSchedule,
    pub(super) verifier_moves: Vec<CompactVerifierMoveContractInput>,
    pub(super) whir_epochs: Vec<CompactWhirEpochContractInput>,
    pub(super) whir_folds: Vec<CompactWhirFoldContractInput>,
}

struct CompactProofContractAuthorities {
    relation: CompactPublicKeyRelationCatalog,
    cfw_configuration: CompactCfwVerifierConfiguration,
    whir_geometry: CompactWhirVerifierGeometry,
    statement_layout: SelectedPublicKeyShareStatementLayout,
}

impl CompactProofContractAuthorities {
    fn selected() -> Result<Self, CompactProofContractError> {
        let relation = selected_compact_public_key_relation_catalog()
            .map_err(|_| CompactProofContractError::InvalidRelation)?;
        let cfw_configuration = selected_cfw_configuration(&relation)?;
        let whir_geometry = CompactWhirVerifierGeometry::derive(cfw_configuration)
            .map_err(|_| CompactProofContractError::InvalidWhirRadius)?;
        Ok(Self {
            relation,
            cfw_configuration,
            whir_geometry,
            statement_layout: selected_public_key_share_statement_layout()?,
        })
    }
}

impl CompactPublicKeyProofContract {
    pub(crate) fn decode_selected() -> Result<Self, CompactProofContractError> {
        Self::decode(GENERATED_CONTRACT_BYTES)
    }

    pub(crate) fn verifier_inputs(&self) -> CompactPublicKeyVerifierInputs<'_> {
        CompactPublicKeyVerifierInputs {
            relation: &self.relation,
            cfw_configuration: self.cfw_configuration,
            statement_layout: self.statement_layout,
            public_input_wire_geometry: self.public_input_wire_geometry,
            proof_wire_geometry: &self.proof_wire_geometry,
            response_merkle_geometries: &self.response_merkle_geometries,
            response_component_roles: &self.response_component_roles,
            checkpoint_schedule: &self.checkpoint_schedule,
            verifier_moves: &self.verifier_moves,
            whir_epochs: &self.whir_epochs,
            whir_folds: &self.whir_folds,
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CompactProofContractError> {
        let reader = Self::decode_preamble(bytes)?;
        let authorities = CompactProofContractAuthorities::selected()?;
        Self::decode_after_preamble(bytes, reader, &authorities)
    }

    #[cfg(test)]
    fn decode_with_authorities(
        bytes: &[u8],
        authorities: &CompactProofContractAuthorities,
    ) -> Result<Self, CompactProofContractError> {
        let reader = Self::decode_preamble(bytes)?;
        Self::decode_after_preamble(bytes, reader, authorities)
    }

    fn decode_preamble(bytes: &[u8]) -> Result<Reader<'_>, CompactProofContractError> {
        let mut reader = Reader::new(bytes)?;
        reader.expect_fixed(&CONTRACT_MAGIC)?;
        reader.expect_u16(CONTRACT_VERSION)?;
        reader.expect_u16(FOUNDATION_PROFILE.participant_count)?;
        reader.expect_u16(FOUNDATION_PROFILE.option_count)?;
        reader.expect_u16(COMPACT_PACKING_FACTOR)?;
        Ok(reader)
    }

    fn decode_after_preamble(
        bytes: &[u8],
        mut reader: Reader<'_>,
        authorities: &CompactProofContractAuthorities,
    ) -> Result<Self, CompactProofContractError> {
        let statement_layout = authorities.statement_layout;
        reader.expect_u16(statement_layout.schema_identifier())?;
        reader.expect_u16(statement_layout.schema_version())?;
        reader.expect_u16(statement_layout.field_count())?;
        reader.expect_fixed(&statement_layout.canonical_layout_digest()?)?;
        reader.expect_u32(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT)?;
        reader.expect_u16(COMPACT_FIAT_SHAMIR_PREFIX_VERSION)?;
        reader.expect_u16(FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION)?;
        reader.expect_fixed(&COMPACT_PROOF_WIRE_MAGIC)?;
        reader.expect_fixed(&COMPACT_PUBLIC_INPUT_WIRE_MAGIC)?;
        for role in compact_public_input_binding_roles() {
            reader.expect_u8(role as u8)?;
        }
        for domain in compact_contract_binding_domains() {
            reader.expect_domain(domain)?;
        }

        let relation_schema_digest = reader.read_array()?;
        let relation = &authorities.relation;
        validate_relation_binding(relation, relation_schema_digest)?;
        let cfw_configuration = authorities.cfw_configuration;
        decode_cfw_configuration(&mut reader, cfw_configuration)?;
        let public_input_wire_geometry = CompactPublicInputWireGeometry::new(
            relation.public_input_ring_vector_count(),
            relation.ring_degree(),
        )?;

        let response_count = reader.read_count()?;
        if response_count != EXPECTED_RESPONSE_COUNT {
            return Err(CompactProofContractError::InvalidResponseRegistry);
        }
        let mut response_wire_geometries = Vec::with_capacity(response_count);
        let mut response_merkle_geometries = Vec::with_capacity(response_count);
        let mut response_component_roles = Vec::with_capacity(response_count);
        for response_index in 0..response_count {
            let (wire, merkle, component_roles) = decode_response(&mut reader, response_index)?;
            response_wire_geometries.push(wire);
            response_merkle_geometries.push(merkle);
            response_component_roles.push(component_roles);
        }
        let proof_wire_geometry = CompactProofWireGeometry::new(response_wire_geometries)?;
        CompactResponseQuerySchedule::validate_registry(
            &response_merkle_geometries,
            proof_wire_geometry.responses(),
        )?;

        let move_count = reader.read_count()?;
        if move_count != response_count {
            return Err(CompactProofContractError::InvalidTranscript);
        }
        let mut verifier_moves = Vec::with_capacity(move_count);
        let mut observed_query_group_count = 0_u32;
        for move_index in 0..move_count {
            let verifier_move = decode_verifier_move(&mut reader, move_index)?;
            observed_query_group_count = observed_query_group_count
                .checked_add(
                    u32::try_from(verifier_move.message_geometry.distinct_query_groups().len())
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                )
                .ok_or(CompactProofContractError::LengthOverflow)?;
            if verifier_move.message_geometry
                != *proof_wire_geometry.responses()[move_index].verifier_message_geometry()
            {
                return Err(CompactProofContractError::InvalidTranscript);
            }
            verifier_moves.push(verifier_move);
        }
        if observed_query_group_count != EXPECTED_DISTINCT_QUERY_GROUP_COUNT {
            return Err(CompactProofContractError::InvalidTranscript);
        }
        let whir_epoch_count = reader.read_count()?;
        if whir_epoch_count != WHIR_EPOCH_COUNT {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        let mut whir_epochs = Vec::with_capacity(whir_epoch_count);
        for epoch_index in 0..whir_epoch_count {
            whir_epochs.push(CompactWhirEpochContract::decode(&mut reader, epoch_index)?);
        }
        let expected_whir_epochs = authorities.whir_geometry.epochs();
        for (decoded, expected) in whir_epochs.iter().zip(expected_whir_epochs) {
            if decoded.polynomial_variable_count != expected.polynomial_variable_count()
                || decoded.folding_schedule != expected.folding_schedule()
                || decoded.final_variable_count != expected.final_variable_count()
                || decoded.round_log_inverse_rates != expected.round_log_inverse_rates()
                || decoded.mask_query_count != expected.mask_query_count()
            {
                return Err(CompactProofContractError::InvalidWhirRadius);
            }
        }
        let pre_challenge_cross_epoch_group = whir_epochs[0]
            .external_mask_groups
            .first()
            .ok_or(CompactProofContractError::InvalidWhirRadius)?;
        let main_cross_epoch_group = whir_epochs[1]
            .external_mask_groups
            .get(2)
            .ok_or(CompactProofContractError::InvalidWhirRadius)?;
        let shared_cross_epoch_randomness_length = whir_epochs[0]
            .mask_query_count
            .checked_add(whir_epochs[1].mask_query_count)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        if pre_challenge_cross_epoch_group.role_tag != 1
            || pre_challenge_cross_epoch_group.committed_encoding_source != 1
            || main_cross_epoch_group.role_tag != 1
            || main_cross_epoch_group.committed_encoding_source != 2
            || pre_challenge_cross_epoch_group.width != main_cross_epoch_group.width
            || pre_challenge_cross_epoch_group.message_length
                != main_cross_epoch_group.message_length
            || pre_challenge_cross_epoch_group.randomness_length
                != shared_cross_epoch_randomness_length
            || main_cross_epoch_group.randomness_length != shared_cross_epoch_randomness_length
            || pre_challenge_cross_epoch_group.domain_size != main_cross_epoch_group.domain_size
            || pre_challenge_cross_epoch_group.width
                != authorities.whir_geometry.cross_epoch_mask_width()
            || pre_challenge_cross_epoch_group.message_length
                != authorities.whir_geometry.cross_epoch_mask_message_length()
        {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }

        let whir_fold_count = reader.read_count()?;
        if whir_fold_count != EXPECTED_WHIR_FOLD_COUNT {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        let mut whir_folds = Vec::with_capacity(whir_fold_count);
        for fold_index in 0..whir_fold_count {
            whir_folds.push(decode_whir_fold(&mut reader, fold_index)?);
        }
        for (fold_index, fold) in whir_folds.iter().enumerate() {
            let epoch = &whir_epochs[fold_index / WHIR_FOLD_COUNT_PER_EPOCH];
            let expected_epoch = expected_whir_epochs[fold_index / WHIR_FOLD_COUNT_PER_EPOCH];
            let batch_ordinal = fold_index % WHIR_FOLD_COUNT_PER_EPOCH;
            let folded_variable_count = epoch.folding_schedule[..=batch_ordinal]
                .iter()
                .try_fold(0_u32, |count, folding_factor| {
                    count.checked_add(*folding_factor)
                })
                .ok_or(CompactProofContractError::InvalidWhirRadius)?;
            let remaining_variable_count = epoch
                .polynomial_variable_count
                .checked_sub(folded_variable_count)
                .ok_or(CompactProofContractError::InvalidWhirRadius)?;
            let expected_message_length = 1_u64
                .checked_shl(remaining_variable_count)
                .ok_or(CompactProofContractError::InvalidWhirRadius)?;
            let expected_rate = if batch_ordinal == 0 {
                WHIR_MAIN_LOG_INVERSE_RATE
            } else {
                epoch.round_log_inverse_rates[batch_ordinal - 1]
            };
            if fold.message_length != expected_message_length
                || fold.oracle_width
                    != 1_u64
                        .checked_shl(epoch.folding_schedule[batch_ordinal])
                        .ok_or(CompactProofContractError::InvalidWhirRadius)?
                || fold.block_length
                    != fold
                        .message_length
                        .checked_shl(expected_rate)
                        .ok_or(CompactProofContractError::InvalidWhirRadius)?
                || fold.query_count != expected_epoch.query_counts()[batch_ordinal]
            {
                return Err(CompactProofContractError::InvalidWhirRadius);
            }
        }
        for (epoch_index, epoch) in whir_epochs.iter().enumerate() {
            let folds = &whir_folds[epoch_index * WHIR_FOLD_COUNT_PER_EPOCH
                ..(epoch_index + 1) * WHIR_FOLD_COUNT_PER_EPOCH];
            let sumcheck_mask_message_length = epoch.internal_mask_groups[0].message_length;
            if sumcheck_mask_message_length != WHIR_SUMCHECK_MASK_MESSAGE_LENGTH {
                return Err(CompactProofContractError::InvalidWhirRadius);
            }
            for batch_ordinal in 0..WHIR_FOLD_COUNT_PER_EPOCH {
                if epoch.internal_mask_groups[batch_ordinal * 2].message_length
                    != sumcheck_mask_message_length
                {
                    return Err(CompactProofContractError::InvalidWhirRadius);
                }
            }
            for (round_ordinal, fold) in folds.iter().enumerate().take(WHIR_ROUND_COUNT) {
                if epoch.internal_mask_groups[round_ordinal * 2 + 1].message_length
                    != fold.query_count
                {
                    return Err(CompactProofContractError::InvalidWhirRadius);
                }
            }
        }
        let cfw_geometry = cfw_configuration.geometry();
        let main_external_mask_groups = &whir_epochs[1].external_mask_groups;
        if main_external_mask_groups[0].width
            != u64::try_from(cfw_geometry.inner_mask_count())
                .map_err(|_| CompactProofContractError::LengthOverflow)?
            || main_external_mask_groups[0].message_length
                != u64::try_from(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
                    .map_err(|_| CompactProofContractError::LengthOverflow)?
            || main_external_mask_groups[1].width
                != u64::try_from(cfw_geometry.outer_mask_count())
                    .map_err(|_| CompactProofContractError::LengthOverflow)?
            || main_external_mask_groups[1].message_length
                != u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                    .map_err(|_| CompactProofContractError::LengthOverflow)?
        {
            return Err(CompactProofContractError::InvalidRelation);
        }
        validate_exact_verifier_chronology(
            &verifier_moves,
            cfw_configuration,
            &whir_epochs,
            &whir_folds,
        )?;
        validate_exact_response_registry(
            &response_merkle_geometries,
            &response_component_roles,
            &verifier_moves,
            cfw_configuration,
            &whir_epochs,
            &whir_folds,
        )?;

        let checkpoint_count = reader.read_count()?;
        if checkpoint_count != response_count {
            return Err(CompactProofContractError::InvalidCheckpointSchedule);
        }
        let mut declared_checkpoint_counts = Vec::with_capacity(checkpoint_count);
        for boundary_index in 0..checkpoint_count {
            let boundary_ordinal = reader.read_u32()?;
            if usize::try_from(boundary_ordinal).ok() != Some(boundary_index) {
                return Err(CompactProofContractError::InvalidCheckpointSchedule);
            }
            declared_checkpoint_counts.push(reader.read_u32()?);
        }
        let checkpoint_schedule = CompactResponseCheckpointSchedule::derive(
            &proof_wire_geometry,
            &response_merkle_geometries,
        )?;
        if checkpoint_schedule.completed_proof_response_counts()
            != declared_checkpoint_counts.as_slice()
        {
            return Err(CompactProofContractError::InvalidCheckpointSchedule);
        }

        reader.finish()?;

        let contract = Self {
            relation: relation.clone(),
            cfw_configuration,
            statement_layout,
            public_input_wire_geometry,
            proof_wire_geometry,
            response_merkle_geometries,
            response_component_roles,
            checkpoint_schedule,
            verifier_moves,
            whir_epochs,
            whir_folds,
        };
        if contract.encode()? != bytes {
            return Err(CompactProofContractError::NonCanonicalEncoding);
        }
        Ok(contract)
    }

    fn encode(&self) -> Result<Vec<u8>, CompactProofContractError> {
        self.verifier_inputs().encode()
    }
}

impl CompactPublicKeyVerifierInputs<'_> {
    pub(crate) fn canonical_source_hash(&self) -> Result<Hash512, CompactProofContractError> {
        self.canonical_source_byte_length_and_hash()
            .map(|(_, hash)| hash)
    }

    pub(crate) fn canonical_source_byte_length_and_hash(
        &self,
    ) -> Result<(u64, Hash512), CompactProofContractError> {
        let canonical_bytes = self.encode()?;
        let byte_length = u64::try_from(canonical_bytes.len())
            .map_err(|_| CompactProofContractError::LengthOverflow)?;
        Ok((
            byte_length,
            Hash512::from_bytes(hash_framed_parts_512(
                GENERATED_CONTRACT_SOURCE_HASH_DOMAIN,
                &[canonical_bytes.as_slice()],
            )),
        ))
    }

    fn encode(&self) -> Result<Vec<u8>, CompactProofContractError> {
        if self.public_input_wire_geometry
            != CompactPublicInputWireGeometry::new(
                self.relation.public_input_ring_vector_count(),
                self.relation.ring_degree(),
            )?
        {
            return Err(CompactProofContractError::InvalidRelation);
        }
        let mut writer = Writer::new();
        writer.write_fixed(&CONTRACT_MAGIC);
        writer.write_u16(CONTRACT_VERSION);
        writer.write_u16(FOUNDATION_PROFILE.participant_count);
        writer.write_u16(FOUNDATION_PROFILE.option_count);
        writer.write_u16(COMPACT_PACKING_FACTOR);
        writer.write_u16(self.statement_layout.schema_identifier());
        writer.write_u16(self.statement_layout.schema_version());
        writer.write_u16(self.statement_layout.field_count());
        writer.write_fixed(&self.statement_layout.canonical_layout_digest()?);
        writer.write_u32(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT);
        writer.write_u16(COMPACT_FIAT_SHAMIR_PREFIX_VERSION);
        writer.write_u16(FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION);
        writer.write_fixed(&COMPACT_PROOF_WIRE_MAGIC);
        writer.write_fixed(&COMPACT_PUBLIC_INPUT_WIRE_MAGIC);
        for role in compact_public_input_binding_roles() {
            writer.write_u8(role as u8);
        }
        for domain in compact_contract_binding_domains() {
            writer.write_domain(domain)?;
        }
        writer.write_fixed(
            &self
                .relation
                .canonical_schema_digest()
                .map_err(|_| CompactProofContractError::InvalidRelation)?,
        );
        encode_cfw_configuration(&mut writer, self.cfw_configuration)?;
        writer.write_count(self.proof_wire_geometry.responses().len())?;
        for ((wire, merkle), component_roles) in self
            .proof_wire_geometry
            .responses()
            .iter()
            .zip(self.response_merkle_geometries)
            .zip(self.response_component_roles)
        {
            encode_response(&mut writer, wire, merkle, component_roles)?;
        }
        writer.write_count(self.verifier_moves.len())?;
        for verifier_move in self.verifier_moves {
            verifier_move.encode(&mut writer)?;
        }
        writer.write_count(self.whir_epochs.len())?;
        for epoch in self.whir_epochs {
            epoch.encode(&mut writer)?;
        }
        writer.write_count(self.whir_folds.len())?;
        for fold in self.whir_folds {
            fold.encode(&mut writer);
        }
        writer.write_count(self.checkpoint_schedule.total_response_count())?;
        for (boundary_index, completed_response_count) in self
            .checkpoint_schedule
            .completed_proof_response_counts()
            .iter()
            .copied()
            .enumerate()
        {
            writer.write_u32(
                u32::try_from(boundary_index)
                    .map_err(|_| CompactProofContractError::LengthOverflow)?,
            );
            writer.write_u32(completed_response_count);
        }
        writer.finish()
    }
}

pub(crate) fn selected_compact_public_key_proof_contract()
-> Result<CompactPublicKeyProofContract, CompactProofContractError> {
    CompactPublicKeyProofContract::decode_selected()
}

#[cfg(test)]
pub(super) fn encode_generated_contract_source(
    input: CompactProofContractGenerationInput,
) -> Result<Vec<u8>, CompactProofContractError> {
    let relation = selected_compact_public_key_relation_catalog()
        .map_err(|_| CompactProofContractError::InvalidRelation)?;
    let statement_layout = selected_public_key_share_statement_layout()?;
    let whir_epochs = input
        .whir_epochs
        .into_iter()
        .enumerate()
        .map(|(epoch_index, epoch)| {
            let contract = CompactWhirEpochContract {
                epoch: epoch.epoch,
                polynomial_variable_count: epoch.polynomial_variable_count,
                folding_schedule: epoch.folding_schedule,
                final_variable_count: epoch.final_variable_count,
                round_log_inverse_rates: epoch.round_log_inverse_rates,
                mask_query_count: epoch.mask_query_count,
                internal_mask_groups: epoch
                    .internal_mask_groups
                    .into_iter()
                    .map(compact_whir_mask_group_from_input)
                    .collect(),
                external_mask_groups: epoch
                    .external_mask_groups
                    .into_iter()
                    .map(compact_whir_mask_group_from_input)
                    .collect(),
            };
            contract.validate(epoch_index)?;
            Ok(contract)
        })
        .collect::<Result<Vec<_>, CompactProofContractError>>()?;
    let whir_folds = input
        .whir_folds
        .into_iter()
        .enumerate()
        .map(|(fold_index, fold)| {
            let dimension = fold
                .message_length
                .checked_add(fold.hiding_randomness_length)
                .ok_or(CompactProofContractError::LengthOverflow)?;
            let unique_decoding_radius = fold
                .block_length
                .checked_sub(dimension)
                .and_then(|distance| distance.checked_sub(1))
                .ok_or(CompactProofContractError::InvalidWhirRadius)?
                / 2;
            let contract = CompactWhirFoldContract {
                epoch: fold.epoch,
                batch_ordinal: fold.batch_ordinal,
                message_length: fold.message_length,
                hiding_randomness_length: fold.hiding_randomness_length,
                block_length: fold.block_length,
                oracle_width: fold.oracle_width,
                query_count: fold.query_count,
                unique_decoding_radius,
            };
            contract.validate(fold_index)?;
            Ok(contract)
        })
        .collect::<Result<Vec<_>, CompactProofContractError>>()?;
    let verifier_moves = input
        .verifier_moves
        .into_iter()
        .map(|move_input| CompactVerifierMoveContract {
            ordinal: move_input.ordinal,
            preceding_prover_response_ordinal: move_input.preceding_prover_response_ordinal,
            preceding_commitment_count: move_input.preceding_commitment_count,
            role_coordinates: move_input.role_coordinates,
            message_geometry: move_input.message_geometry,
        })
        .collect();
    let cfw_configuration = selected_cfw_configuration(&relation)?;
    if input.commitment_count != EXPECTED_COMMITMENT_COUNT
        || input.distinct_query_group_count != EXPECTED_DISTINCT_QUERY_GROUP_COUNT
    {
        return Err(CompactProofContractError::InvalidTranscript);
    }
    if input.relation_schema_digest
        != relation
            .canonical_schema_digest()
            .map_err(|_| CompactProofContractError::InvalidRelation)?
    {
        return Err(CompactProofContractError::InvalidRelation);
    }
    let contract = CompactPublicKeyProofContract {
        relation,
        cfw_configuration,
        statement_layout,
        public_input_wire_geometry: input.public_input_wire_geometry,
        proof_wire_geometry: input.proof_wire_geometry,
        response_merkle_geometries: input.response_merkle_geometries,
        response_component_roles: input.response_component_roles,
        checkpoint_schedule: input.checkpoint_schedule,
        verifier_moves,
        whir_epochs,
        whir_folds,
    };
    let bytes = contract.encode()?;
    let decoded = CompactPublicKeyProofContract::decode(&bytes)?;
    if decoded != contract {
        return Err(CompactProofContractError::NonCanonicalEncoding);
    }
    Ok(bytes)
}

#[cfg(test)]
fn compact_whir_mask_group_from_input(
    input: CompactWhirMaskGroupContractInput,
) -> CompactWhirMaskGroupContract {
    CompactWhirMaskGroupContract {
        role_tag: input.role_tag,
        coordinate: input.coordinate,
        width: input.width,
        message_length: input.message_length,
        randomness_length: input.randomness_length,
        domain_size: input.domain_size,
        committed_encoding_source: input.committed_encoding_source,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactVerifierMoveContract {
    pub(crate) ordinal: u32,
    pub(crate) preceding_prover_response_ordinal: u32,
    pub(crate) preceding_commitment_count: u32,
    pub(crate) role_coordinates: Vec<CompactVerifierRoleCoordinate>,
    pub(crate) message_geometry: FixedUniformVerifierMessageGeometry,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompactVerifierMoveContractInput {
    pub(super) ordinal: u32,
    pub(super) preceding_prover_response_ordinal: u32,
    pub(super) preceding_commitment_count: u32,
    pub(super) role_coordinates: Vec<CompactVerifierRoleCoordinate>,
    pub(super) message_geometry: FixedUniformVerifierMessageGeometry,
}

impl CompactVerifierMoveContract {
    fn encode(&self, writer: &mut Writer) -> Result<(), CompactProofContractError> {
        writer.write_u32(self.ordinal);
        writer.write_u32(self.preceding_prover_response_ordinal);
        writer.write_u32(self.preceding_commitment_count);
        writer.write_count(self.role_coordinates.len())?;
        for role in &self.role_coordinates {
            role.encode(writer);
        }
        encode_message_geometry(writer, &self.message_geometry)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactVerifierRoleCoordinate {
    pub(crate) role_tag: u8,
    pub(crate) epoch: u8,
    pub(crate) batch_ordinal: u8,
    pub(crate) round_ordinal: u32,
    pub(crate) extension_output_start: u64,
    pub(crate) extension_output_end: u64,
    pub(crate) base_field_output_start: u64,
    pub(crate) base_field_output_end: u64,
    pub(crate) distinct_query_group_start: u64,
    pub(crate) distinct_query_group_end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseComponentRoleContract {
    pub(crate) role_tag: u8,
    pub(crate) epoch: u8,
    pub(crate) batch_ordinal: u8,
    pub(crate) round_ordinal: u32,
}

#[cfg(test)]
impl CompactResponseComponentRoleContract {
    pub(super) const fn new(
        role_tag: u8,
        epoch: u8,
        batch_ordinal: u8,
        round_ordinal: u32,
    ) -> Self {
        Self {
            role_tag,
            epoch,
            batch_ordinal,
            round_ordinal,
        }
    }
}

#[cfg(test)]
impl CompactVerifierRoleCoordinate {
    pub(super) fn non_epoch(role_tag: u8, round_ordinal: u32, ranges: [[u64; 2]; 3]) -> Self {
        Self {
            role_tag,
            epoch: 0,
            batch_ordinal: 0,
            round_ordinal,
            extension_output_start: ranges[0][0],
            extension_output_end: ranges[0][1],
            base_field_output_start: ranges[1][0],
            base_field_output_end: ranges[1][1],
            distinct_query_group_start: ranges[2][0],
            distinct_query_group_end: ranges[2][1],
        }
    }

    pub(super) fn epoch(
        role_tag: u8,
        epoch: u8,
        batch_ordinal: u8,
        round_ordinal: u32,
        ranges: [[u64; 2]; 3],
    ) -> Self {
        Self {
            role_tag,
            epoch,
            batch_ordinal,
            round_ordinal,
            extension_output_start: ranges[0][0],
            extension_output_end: ranges[0][1],
            base_field_output_start: ranges[1][0],
            base_field_output_end: ranges[1][1],
            distinct_query_group_start: ranges[2][0],
            distinct_query_group_end: ranges[2][1],
        }
    }
}

impl CompactVerifierRoleCoordinate {
    fn encode(self, writer: &mut Writer) {
        writer.write_u8(self.role_tag);
        writer.write_u8(self.epoch);
        writer.write_u8(self.batch_ordinal);
        writer.write_u32(self.round_ordinal);
        writer.write_u64(self.extension_output_start);
        writer.write_u64(self.extension_output_end);
        writer.write_u64(self.base_field_output_start);
        writer.write_u64(self.base_field_output_end);
        writer.write_u64(self.distinct_query_group_start);
        writer.write_u64(self.distinct_query_group_end);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirEpochContract {
    pub(crate) epoch: u8,
    pub(crate) polynomial_variable_count: u32,
    pub(crate) folding_schedule: [u32; WHIR_FOLD_COUNT_PER_EPOCH],
    pub(crate) final_variable_count: u32,
    pub(crate) round_log_inverse_rates: [u32; WHIR_ROUND_COUNT],
    pub(crate) mask_query_count: u64,
    pub(crate) internal_mask_groups: Vec<CompactWhirMaskGroupContract>,
    pub(crate) external_mask_groups: Vec<CompactWhirMaskGroupContract>,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompactWhirEpochContractInput {
    pub(super) epoch: u8,
    pub(super) polynomial_variable_count: u32,
    pub(super) folding_schedule: [u32; WHIR_FOLD_COUNT_PER_EPOCH],
    pub(super) final_variable_count: u32,
    pub(super) round_log_inverse_rates: [u32; WHIR_ROUND_COUNT],
    pub(super) mask_query_count: u64,
    pub(super) internal_mask_groups: Vec<CompactWhirMaskGroupContractInput>,
    pub(super) external_mask_groups: Vec<CompactWhirMaskGroupContractInput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirMaskGroupContract {
    pub(crate) role_tag: u8,
    pub(crate) coordinate: u8,
    pub(crate) width: u64,
    pub(crate) message_length: u64,
    pub(crate) randomness_length: u64,
    pub(crate) domain_size: u64,
    pub(crate) committed_encoding_source: u8,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CompactWhirMaskGroupContractInput {
    pub(super) role_tag: u8,
    pub(super) coordinate: u8,
    pub(super) width: u64,
    pub(super) message_length: u64,
    pub(super) randomness_length: u64,
    pub(super) domain_size: u64,
    pub(super) committed_encoding_source: u8,
}

impl CompactWhirEpochContract {
    fn decode(
        reader: &mut Reader<'_>,
        epoch_index: usize,
    ) -> Result<Self, CompactProofContractError> {
        let epoch = reader.read_u8()?;
        let polynomial_variable_count = reader.read_u32()?;
        let folding_schedule = [
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
            reader.read_u32()?,
        ];
        let final_variable_count = reader.read_u32()?;
        let round_log_inverse_rates = [reader.read_u32()?, reader.read_u32()?, reader.read_u32()?];
        let mask_query_count = reader.read_u64()?;
        let internal_mask_groups = decode_whir_mask_groups(reader)?;
        let external_mask_groups = decode_whir_mask_groups(reader)?;
        let contract = Self {
            epoch,
            polynomial_variable_count,
            folding_schedule,
            final_variable_count,
            round_log_inverse_rates,
            mask_query_count,
            internal_mask_groups,
            external_mask_groups,
        };
        contract.validate(epoch_index)?;
        Ok(contract)
    }

    pub(super) fn validate(&self, epoch_index: usize) -> Result<(), CompactProofContractError> {
        let folded_variable_count = self
            .folding_schedule
            .iter()
            .try_fold(0_u32, |sum, factor| sum.checked_add(*factor))
            .ok_or(CompactProofContractError::InvalidWhirRadius)?;
        if usize::from(self.epoch) != epoch_index + 1
            || self.folding_schedule.contains(&0)
            || folded_variable_count.checked_add(self.final_variable_count)
                != Some(self.polynomial_variable_count)
            || !(1..=6).contains(&self.final_variable_count)
            || self.round_log_inverse_rates.contains(&0)
            || self.mask_query_count == 0
            || self.internal_mask_groups.len() != 7
            || self.external_mask_groups.is_empty()
        {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        let expected_internal_roles = [(4, 0), (5, 0), (4, 1), (5, 1), (4, 2), (5, 2), (4, 3)];
        if self
            .internal_mask_groups
            .iter()
            .zip(expected_internal_roles)
            .any(|(group, (role_tag, coordinate))| {
                group.role_tag != role_tag
                    || group.coordinate != coordinate
                    || group.committed_encoding_source != 1
                    || group.randomness_length != self.mask_query_count
                    || (role_tag == 4
                        && group.width != u64::from(self.folding_schedule[usize::from(coordinate)]))
                    || (role_tag == 5 && group.width != 1)
            })
        {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        let expected_external_roles: &[(u8, u8)] = if epoch_index == 0 {
            &[(1, 1)]
        } else {
            &[(2, 1), (3, 1), (1, 2)]
        };
        if self.external_mask_groups.len() != expected_external_roles.len()
            || self
                .external_mask_groups
                .iter()
                .zip(expected_external_roles)
                .any(|(group, (role_tag, committed_encoding_source))| {
                    group.role_tag != *role_tag
                        || group.coordinate != 0
                        || group.committed_encoding_source != *committed_encoding_source
                        || ((*role_tag == 2 || *role_tag == 3)
                            && group.randomness_length != self.mask_query_count)
                })
        {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        for group in self
            .external_mask_groups
            .iter()
            .chain(&self.internal_mask_groups)
        {
            group.validate()?;
        }
        Ok(())
    }

    fn encode(&self, writer: &mut Writer) -> Result<(), CompactProofContractError> {
        writer.write_u8(self.epoch);
        writer.write_u32(self.polynomial_variable_count);
        for factor in self.folding_schedule {
            writer.write_u32(factor);
        }
        writer.write_u32(self.final_variable_count);
        for rate in self.round_log_inverse_rates {
            writer.write_u32(rate);
        }
        writer.write_u64(self.mask_query_count);
        encode_whir_mask_groups(writer, &self.internal_mask_groups)?;
        encode_whir_mask_groups(writer, &self.external_mask_groups)
    }
}

impl CompactWhirMaskGroupContract {
    fn validate(self) -> Result<(), CompactProofContractError> {
        let populated_message_length = self
            .message_length
            .checked_add(self.randomness_length)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        let expected_domain_size = populated_message_length
            .checked_next_power_of_two()
            .and_then(|value| value.checked_shl(2))
            .ok_or(CompactProofContractError::InvalidWhirRadius)?;
        if self.role_tag == 0
            || self.role_tag > 5
            || self.width == 0
            || self.message_length == 0
            || self.randomness_length == 0
            || self.domain_size != expected_domain_size
            || !(1..=2).contains(&self.committed_encoding_source)
        {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        let role_coordinates_are_valid = match self.role_tag {
            1 => self.coordinate == 0,
            2 | 3 => self.coordinate == 0 && self.committed_encoding_source == 1,
            4 => self.coordinate < 4 && self.committed_encoding_source == 1,
            5 => self.coordinate < 3 && self.committed_encoding_source == 1,
            _ => false,
        };
        if !role_coordinates_are_valid {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        Ok(())
    }

    fn encode(self, writer: &mut Writer) {
        writer.write_u8(self.role_tag);
        writer.write_u8(self.coordinate);
        writer.write_u64(self.width);
        writer.write_u64(self.message_length);
        writer.write_u64(self.randomness_length);
        writer.write_u64(self.domain_size);
        writer.write_u8(self.committed_encoding_source);
    }
}

fn decode_whir_mask_groups(
    reader: &mut Reader<'_>,
) -> Result<Vec<CompactWhirMaskGroupContract>, CompactProofContractError> {
    let count = reader.read_count()?;
    let mut groups = Vec::with_capacity(count);
    for _ in 0..count {
        let group = CompactWhirMaskGroupContract {
            role_tag: reader.read_u8()?,
            coordinate: reader.read_u8()?,
            width: reader.read_u64()?,
            message_length: reader.read_u64()?,
            randomness_length: reader.read_u64()?,
            domain_size: reader.read_u64()?,
            committed_encoding_source: reader.read_u8()?,
        };
        group.validate()?;
        groups.push(group);
    }
    Ok(groups)
}

fn encode_whir_mask_groups(
    writer: &mut Writer,
    groups: &[CompactWhirMaskGroupContract],
) -> Result<(), CompactProofContractError> {
    writer.write_count(groups.len())?;
    for group in groups {
        group.encode(writer);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactWhirFoldContract {
    pub(crate) epoch: u8,
    pub(crate) batch_ordinal: u8,
    pub(crate) message_length: u64,
    pub(crate) hiding_randomness_length: u64,
    pub(crate) block_length: u64,
    pub(crate) oracle_width: u64,
    pub(crate) query_count: u64,
    pub(crate) unique_decoding_radius: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CompactWhirFoldContractInput {
    pub(super) epoch: u8,
    pub(super) batch_ordinal: u8,
    pub(super) message_length: u64,
    pub(super) hiding_randomness_length: u64,
    pub(super) block_length: u64,
    pub(super) oracle_width: u64,
    pub(super) query_count: u64,
}

impl CompactWhirFoldContract {
    pub(super) fn validate(self, fold_index: usize) -> Result<(), CompactProofContractError> {
        if usize::from(self.epoch) != fold_index / WHIR_FOLD_COUNT_PER_EPOCH + 1
            || usize::from(self.batch_ordinal) != fold_index % WHIR_FOLD_COUNT_PER_EPOCH
            || self.message_length == 0
            || self.hiding_randomness_length == 0
            || self.query_count != self.hiding_randomness_length
        {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        let dimension = self
            .message_length
            .checked_add(self.hiding_randomness_length)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        if dimension >= self.block_length {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        let strict_radius = self
            .block_length
            .checked_sub(dimension)
            .and_then(|distance| distance.checked_sub(1))
            .ok_or(CompactProofContractError::InvalidWhirRadius)?
            / 2;
        if self.unique_decoding_radius != strict_radius
            || self
                .unique_decoding_radius
                .checked_mul(2)
                .is_none_or(|twice_radius| twice_radius >= self.block_length - dimension)
        {
            return Err(CompactProofContractError::InvalidWhirRadius);
        }
        Ok(())
    }

    fn encode(self, writer: &mut Writer) {
        writer.write_u8(self.epoch);
        writer.write_u8(self.batch_ordinal);
        writer.write_u64(self.message_length);
        writer.write_u64(self.hiding_randomness_length);
        writer.write_u64(self.block_length);
        writer.write_u64(self.oracle_width);
        writer.write_u64(self.query_count);
        writer.write_u64(self.unique_decoding_radius);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactProofContractError {
    Truncated,
    TrailingBytes,
    LengthOverflow,
    LimitExceeded,
    WrongMagic,
    WrongVersionOrTarget,
    WrongDomain,
    NonCanonicalEncoding,
    InvalidRelation,
    InvalidResponseRegistry,
    InvalidTranscript,
    InvalidWhirRadius,
    InvalidCheckpointSchedule,
    ProofWire(CompactProofWireError),
    ResponseMerkle(CompactResponseMerkleError),
    Checkpoint(CompactGenerationCheckpointError),
    VerifierMessage(FixedUniformVerifierMessageError),
    ApplicationStatement(SelectedApplicationStatementError),
}

impl From<CompactProofWireError> for CompactProofContractError {
    fn from(error: CompactProofWireError) -> Self {
        Self::ProofWire(error)
    }
}

impl From<CompactResponseMerkleError> for CompactProofContractError {
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::ResponseMerkle(error)
    }
}

impl From<CompactGenerationCheckpointError> for CompactProofContractError {
    fn from(error: CompactGenerationCheckpointError) -> Self {
        Self::Checkpoint(error)
    }
}

impl From<FixedUniformVerifierMessageError> for CompactProofContractError {
    fn from(error: FixedUniformVerifierMessageError) -> Self {
        Self::VerifierMessage(error)
    }
}

impl From<SelectedApplicationStatementError> for CompactProofContractError {
    fn from(error: SelectedApplicationStatementError) -> Self {
        Self::ApplicationStatement(error)
    }
}

fn validate_relation_binding(
    relation: &CompactPublicKeyRelationCatalog,
    relation_schema_digest: [u8; 64],
) -> Result<(), CompactProofContractError> {
    if relation
        .canonical_schema_digest()
        .map_err(|_| CompactProofContractError::InvalidRelation)?
        != relation_schema_digest
    {
        return Err(CompactProofContractError::InvalidRelation);
    }
    Ok(())
}

fn selected_cfw_configuration(
    relation: &CompactPublicKeyRelationCatalog,
) -> Result<CompactCfwVerifierConfiguration, CompactProofContractError> {
    let cross_epoch = relation
        .cross_epoch_copy_geometry()
        .map_err(|_| CompactProofContractError::InvalidRelation)?;
    CompactCfwVerifierConfiguration::derive(
        usize::try_from(relation.padded_witness_element_count())
            .map_err(|_| CompactProofContractError::LengthOverflow)?,
        CompactCfwCrossEpochVerifierGeometry {
            copied_ring_vector_count: cross_epoch.copied_ring_vector_count(),
            copied_element_count: cross_epoch.copied_element_count(),
            pre_challenge_message_element_count: cross_epoch.pre_challenge_message_element_count(),
            main_message_element_count: cross_epoch.main_message_element_count(),
            point_coordinate_count: cross_epoch.point_coordinate_count(),
        },
    )
    .map_err(|_| CompactProofContractError::InvalidRelation)
}

fn encode_cfw_configuration(
    writer: &mut Writer,
    configuration: CompactCfwVerifierConfiguration,
) -> Result<(), CompactProofContractError> {
    let geometry = configuration.geometry();
    let cross_epoch = configuration.cross_epoch();
    for value in [
        u64::try_from(geometry.witness_length()),
        u64::try_from(geometry.r1cs_row_count()),
        u64::try_from(geometry.sumcheck_round_count()),
        u64::try_from(geometry.inner_mask_count()),
        u64::try_from(geometry.outer_mask_count()),
        u64::try_from(geometry.generalized_committed_relation_claim_count()),
    ] {
        writer.write_u64(value.map_err(|_| CompactProofContractError::LengthOverflow)?);
    }
    writer.write_u64(cross_epoch.copied_ring_vector_count);
    writer.write_u64(cross_epoch.copied_element_count);
    writer.write_u64(cross_epoch.pre_challenge_message_element_count);
    writer.write_u64(cross_epoch.main_message_element_count);
    writer.write_u32(cross_epoch.point_coordinate_count);
    for role_tag in configuration.matrix_role_tags() {
        writer.write_u8(role_tag);
    }
    writer.write_u64(configuration.inner_mask_message_length());
    writer.write_u64(configuration.inner_mask_application_multiplier());
    for value in configuration.inner_evaluation_at_zero_covector() {
        writer.write_u64(value);
    }
    for value in configuration.inner_evaluation_at_one_covector() {
        writer.write_u64(value);
    }
    for value in configuration.inner_endpoint_targets() {
        writer.write_u64(value);
    }
    writer.write_u64(configuration.outer_mask_message_length());
    writer.write_u64(configuration.outer_revealed_evaluation_count());
    writer.write_u64(configuration.global_committed_relation_claim_count());
    writer.write_u64(configuration.auxiliary_target_count());
    for exponent in configuration.zero_evader_exponents() {
        writer.write_u32(exponent);
    }
    for range in [
        configuration.initial_constraint_combining_range(),
        configuration
            .initial_equality_point_range()
            .map_err(|_| CompactProofContractError::InvalidRelation)?,
    ] {
        writer.write_u64(range[0]);
        writer.write_u64(range[1]);
    }
    writer.write_u64(configuration.per_round_challenge_count());
    for value in configuration.last_round_excluded_canonical_elements() {
        writer.write_u64(value);
    }
    for value in configuration.joint_constraint_range() {
        writer.write_u64(value);
    }
    writer.write_u64(configuration.cross_epoch_preceding_claim_count());
    writer.write_u64(configuration.cross_epoch_mask_message_count());
    writer.write_u64(configuration.cross_epoch_disclosed_scalar_count());
    Ok(())
}

fn decode_cfw_configuration(
    reader: &mut Reader<'_>,
    configuration: CompactCfwVerifierConfiguration,
) -> Result<(), CompactProofContractError> {
    let mut expected = Writer::new();
    encode_cfw_configuration(&mut expected, configuration)?;
    let expected = expected.finish()?;
    let end = reader
        .offset
        .checked_add(expected.len())
        .ok_or(CompactProofContractError::LengthOverflow)?;
    if end > reader.bytes.len() {
        return Err(CompactProofContractError::Truncated);
    }
    if reader.bytes.get(reader.offset..end) != Some(expected.as_slice()) {
        return Err(CompactProofContractError::InvalidRelation);
    }
    reader.offset = end;
    Ok(())
}

fn decode_response(
    reader: &mut Reader<'_>,
    response_index: usize,
) -> Result<
    (
        CompactProofResponseWireGeometry,
        CompactResponseMerkleGeometry,
        Vec<CompactResponseComponentRoleContract>,
    ),
    CompactProofContractError,
> {
    let ordinal = reader.read_u32()?;
    if usize::try_from(ordinal).ok() != Some(response_index) {
        return Err(CompactProofContractError::InvalidResponseRegistry);
    }
    let minimum_base = reader.read_u64()?;
    let maximum_base = reader.read_u64()?;
    let minimum_extension = reader.read_u64()?;
    let maximum_extension = reader.read_u64()?;
    let minimum_leaves = reader.read_u64()?;
    let maximum_leaves = reader.read_u64()?;
    let maximum_frontier = reader.read_u64()?;
    let message_geometry = decode_message_geometry(reader)?;
    let wire = CompactProofResponseWireGeometry::new_with_count_ranges(
        ordinal,
        minimum_base,
        maximum_base,
        minimum_extension,
        maximum_extension,
        minimum_leaves,
        maximum_leaves,
        maximum_frontier,
        message_geometry,
    )?;
    let component_count = reader.read_count()?;
    let mut components = Vec::with_capacity(component_count);
    let mut component_roles = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        let (component, role) = decode_response_component(reader)?;
        components.push(component);
        component_roles.push(role);
    }
    let merkle = CompactResponseMerkleGeometry::new(ordinal, components)?;
    merkle.validate_wire_geometry(&wire)?;
    Ok((wire, merkle, component_roles))
}

fn encode_response(
    writer: &mut Writer,
    wire: &CompactProofResponseWireGeometry,
    merkle: &CompactResponseMerkleGeometry,
    component_roles: &[CompactResponseComponentRoleContract],
) -> Result<(), CompactProofContractError> {
    if component_roles.len() != merkle.components().len() {
        return Err(CompactProofContractError::InvalidResponseRegistry);
    }
    writer.write_u32(wire.ordinal());
    writer.write_u64(wire.minimum_queried_base_field_element_count());
    writer.write_u64(wire.maximum_queried_base_field_element_count());
    writer.write_u64(wire.minimum_queried_extension_field_element_count());
    writer.write_u64(wire.maximum_queried_extension_field_element_count());
    writer.write_u64(wire.minimum_queried_leaf_count());
    writer.write_u64(wire.maximum_queried_leaf_count());
    writer.write_u64(wire.maximum_frontier_node_count());
    encode_message_geometry(writer, wire.verifier_message_geometry())?;
    writer.write_count(merkle.components().len())?;
    for (component, role) in merkle.components().iter().zip(component_roles) {
        encode_response_component(writer, *component, *role);
    }
    Ok(())
}

fn decode_response_component(
    reader: &mut Reader<'_>,
) -> Result<
    (
        CompactResponseComponentGeometry,
        CompactResponseComponentRoleContract,
    ),
    CompactProofContractError,
> {
    let role = CompactResponseComponentRoleContract {
        role_tag: reader.read_u8()?,
        epoch: reader.read_u8()?,
        batch_ordinal: reader.read_u8()?,
        round_ordinal: reader.read_u32()?,
    };
    if role.role_tag == 0 || role.role_tag > 22 || role.epoch > 2 {
        return Err(CompactProofContractError::InvalidResponseRegistry);
    }
    let first_leaf = reader.read_u64()?;
    let leaf_count = reader.read_u64()?;
    let minimum_queried = reader.read_u64()?;
    let maximum_queried = reader.read_u64()?;
    let query_selection = match reader.read_u8()? {
        0 => CompactResponseQuerySelection::Unqueried,
        1 => CompactResponseQuerySelection::EveryLeaf,
        2 => CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal: reader.read_u32()?,
            distinct_query_group_ordinal: reader.read_u32()?,
        },
        3 => CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
            first_logical_verifier_move_ordinal: reader.read_u32()?,
            first_distinct_query_group_ordinal: reader.read_u32()?,
            second_logical_verifier_move_ordinal: reader.read_u32()?,
            second_distinct_query_group_ordinal: reader.read_u32()?,
        },
        _ => return Err(CompactProofContractError::InvalidResponseRegistry),
    };
    let value_kind = match reader.read_u8()? {
        1 => CompactResponseLeafValueKind::BaseField,
        2 => CompactResponseLeafValueKind::ExtensionField,
        3 => CompactResponseLeafValueKind::Padding,
        _ => return Err(CompactProofContractError::InvalidResponseRegistry),
    };
    let field_element_count_per_leaf = reader.read_u64()?;
    Ok((
        CompactResponseComponentGeometry::new_with_query_count_range(
            first_leaf,
            leaf_count,
            minimum_queried,
            maximum_queried,
            query_selection,
            value_kind,
            field_element_count_per_leaf,
        ),
        role,
    ))
}

fn encode_response_component(
    writer: &mut Writer,
    component: CompactResponseComponentGeometry,
    role: CompactResponseComponentRoleContract,
) {
    writer.write_u8(role.role_tag);
    writer.write_u8(role.epoch);
    writer.write_u8(role.batch_ordinal);
    writer.write_u32(role.round_ordinal);
    writer.write_u64(component.first_leaf_ordinal());
    writer.write_u64(component.leaf_count());
    writer.write_u64(component.minimum_queried_leaf_count());
    writer.write_u64(component.maximum_queried_leaf_count());
    match component.query_selection() {
        CompactResponseQuerySelection::Unqueried => writer.write_u8(0),
        CompactResponseQuerySelection::EveryLeaf => writer.write_u8(1),
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal,
            distinct_query_group_ordinal,
        } => {
            writer.write_u8(2);
            writer.write_u32(logical_verifier_move_ordinal);
            writer.write_u32(distinct_query_group_ordinal);
        }
        CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
            first_logical_verifier_move_ordinal,
            first_distinct_query_group_ordinal,
            second_logical_verifier_move_ordinal,
            second_distinct_query_group_ordinal,
        } => {
            writer.write_u8(3);
            writer.write_u32(first_logical_verifier_move_ordinal);
            writer.write_u32(first_distinct_query_group_ordinal);
            writer.write_u32(second_logical_verifier_move_ordinal);
            writer.write_u32(second_distinct_query_group_ordinal);
        }
    }
    writer.write_u8(component.value_kind() as u8);
    writer.write_u64(component.field_element_count_per_leaf());
}

fn decode_verifier_move(
    reader: &mut Reader<'_>,
    move_index: usize,
) -> Result<CompactVerifierMoveContract, CompactProofContractError> {
    let ordinal = reader.read_u32()?;
    let preceding_prover_response_ordinal = reader.read_u32()?;
    let preceding_commitment_count = reader.read_u32()?;
    if usize::try_from(ordinal).ok() != Some(move_index)
        || preceding_prover_response_ordinal == 0
        || preceding_commitment_count == 0
        || preceding_commitment_count > EXPECTED_COMMITMENT_COUNT
    {
        return Err(CompactProofContractError::InvalidTranscript);
    }
    let role_count = reader.read_count()?;
    if role_count == 0 || role_count > 2 {
        return Err(CompactProofContractError::InvalidTranscript);
    }
    let mut role_coordinates = Vec::with_capacity(role_count);
    for _ in 0..role_count {
        let role = CompactVerifierRoleCoordinate {
            role_tag: reader.read_u8()?,
            epoch: reader.read_u8()?,
            batch_ordinal: reader.read_u8()?,
            round_ordinal: reader.read_u32()?,
            extension_output_start: reader.read_u64()?,
            extension_output_end: reader.read_u64()?,
            base_field_output_start: reader.read_u64()?,
            base_field_output_end: reader.read_u64()?,
            distinct_query_group_start: reader.read_u64()?,
            distinct_query_group_end: reader.read_u64()?,
        };
        if role.role_tag == 0 || role.role_tag > 11 || role.epoch > 2 {
            return Err(CompactProofContractError::InvalidTranscript);
        }
        role_coordinates.push(role);
    }
    let message_geometry = decode_message_geometry(reader)?;
    validate_role_coordinate_partition(&role_coordinates, &message_geometry)?;
    Ok(CompactVerifierMoveContract {
        ordinal,
        preceding_prover_response_ordinal,
        preceding_commitment_count,
        role_coordinates,
        message_geometry,
    })
}

pub(super) fn validate_exact_verifier_chronology(
    verifier_moves: &[CompactVerifierMoveContract],
    cfw_configuration: CompactCfwVerifierConfiguration,
    whir_epochs: &[CompactWhirEpochContract],
    whir_folds: &[CompactWhirFoldContract],
) -> Result<(), CompactProofContractError> {
    let [pre_challenge_epoch, main_epoch] = whir_epochs else {
        return Err(CompactProofContractError::InvalidTranscript);
    };
    let pre_challenge_folds: &[CompactWhirFoldContract; WHIR_FOLD_COUNT_PER_EPOCH] = whir_folds
        .get(..WHIR_FOLD_COUNT_PER_EPOCH)
        .and_then(|folds| folds.try_into().ok())
        .ok_or(CompactProofContractError::InvalidTranscript)?;
    let main_folds: &[CompactWhirFoldContract; WHIR_FOLD_COUNT_PER_EPOCH] = whir_folds
        .get(WHIR_FOLD_COUNT_PER_EPOCH..EXPECTED_WHIR_FOLD_COUNT)
        .and_then(|folds| folds.try_into().ok())
        .ok_or(CompactProofContractError::InvalidTranscript)?;
    let mut expected = ExpectedVerifierChronology::new();

    expected.record_response(0)?;
    expected.record_response(1)?;
    expected.record_single_move(
        expected_role(1, 0, 0, 0),
        extension_message_geometry(1, PROOF_BASE_FIELD_MODULUS)?,
    )?;

    expected.record_response(1)?;
    expected.record_response(1)?;
    expected.record_response(2)?;
    expected.record_single_move(
        expected_role(2, 0, 0, 0),
        extension_message_geometry(
            u64::from(cfw_configuration.cross_epoch().point_coordinate_count),
            0,
        )?,
    )?;

    expected.record_response(0)?;
    let cfw_round_count = u32::try_from(cfw_configuration.geometry().sumcheck_round_count())
        .map_err(|_| CompactProofContractError::LengthOverflow)?;
    expected.record_single_move(
        expected_role(3, 0, 0, 0),
        extension_message_geometry(
            u64::from(cfw_round_count)
                .checked_add(1)
                .ok_or(CompactProofContractError::LengthOverflow)?,
            0,
        )?,
    )?;
    for round_ordinal in 0..cfw_round_count {
        expected.record_response(0)?;
        let excluded_extension_prefix_cardinality = if round_ordinal + 1 == cfw_round_count {
            u64::try_from(
                cfw_configuration
                    .last_round_excluded_canonical_elements()
                    .len(),
            )
            .map_err(|_| CompactProofContractError::LengthOverflow)?
        } else {
            0
        };
        expected.record_single_move(
            expected_role(4, 0, 0, round_ordinal),
            extension_message_geometry(
                cfw_configuration.per_round_challenge_count(),
                excluded_extension_prefix_cardinality,
            )?,
        )?;
    }

    expected.record_response(0)?;
    let [joint_start, joint_end] = cfw_configuration.joint_constraint_range();
    let joint_count = joint_end
        .checked_sub(joint_start)
        .ok_or(CompactProofContractError::InvalidTranscript)?;
    let combined_extension_count = joint_count
        .checked_add(1)
        .ok_or(CompactProofContractError::LengthOverflow)?;
    expected.record_move(
        vec![
            expected_role_with_ranges(5, 0, 0, 0, [[0, joint_count], [0, 0], [0, 0]]),
            expected_role_with_ranges(
                6,
                1,
                0,
                0,
                [[joint_count, combined_extension_count], [0, 0], [0, 0]],
            ),
        ],
        extension_message_geometry(combined_extension_count, 0)?,
    )?;

    expected.append_whir_epoch(pre_challenge_epoch, pre_challenge_folds, false)?;
    let pre_challenge_final_groups =
        expected_final_query_groups(pre_challenge_epoch, pre_challenge_folds)?;
    let pre_challenge_final_group_count = u64::try_from(pre_challenge_final_groups.len())
        .map_err(|_| CompactProofContractError::LengthOverflow)?;
    expected.record_move(
        vec![
            expected_role_with_ranges(
                11,
                1,
                0,
                0,
                [[0, 0], [0, 0], [0, pre_challenge_final_group_count]],
            ),
            expected_role_with_ranges(6, 2, 0, 0, [[0, 1], [0, 0], [0, 0]]),
        ],
        FixedUniformVerifierMessageGeometry::new(1, 0, 0, pre_challenge_final_groups)?,
    )?;
    expected.append_whir_epoch(main_epoch, main_folds, true)?;
    expected.finish(verifier_moves)
}

struct ExpectedVerifierChronology {
    moves: Vec<CompactVerifierMoveContract>,
    prover_response_count: u32,
    commitment_count: u32,
}

impl ExpectedVerifierChronology {
    fn new() -> Self {
        Self {
            moves: Vec::with_capacity(EXPECTED_RESPONSE_COUNT),
            prover_response_count: 0,
            commitment_count: 0,
        }
    }

    fn record_response(&mut self, commitment_count: u32) -> Result<(), CompactProofContractError> {
        self.prover_response_count = self
            .prover_response_count
            .checked_add(1)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        self.commitment_count = self
            .commitment_count
            .checked_add(commitment_count)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        Ok(())
    }

    fn record_single_move(
        &mut self,
        role: CompactVerifierRoleCoordinate,
        message_geometry: FixedUniformVerifierMessageGeometry,
    ) -> Result<(), CompactProofContractError> {
        let role = full_message_role(role, &message_geometry)?;
        self.record_move(vec![role], message_geometry)
    }

    fn record_move(
        &mut self,
        role_coordinates: Vec<CompactVerifierRoleCoordinate>,
        message_geometry: FixedUniformVerifierMessageGeometry,
    ) -> Result<(), CompactProofContractError> {
        if self.prover_response_count == 0 {
            return Err(CompactProofContractError::InvalidTranscript);
        }
        self.moves.push(CompactVerifierMoveContract {
            ordinal: u32::try_from(self.moves.len())
                .map_err(|_| CompactProofContractError::LengthOverflow)?,
            preceding_prover_response_ordinal: self.prover_response_count - 1,
            preceding_commitment_count: self.commitment_count,
            role_coordinates,
            message_geometry,
        });
        Ok(())
    }

    fn append_whir_epoch(
        &mut self,
        epoch: &CompactWhirEpochContract,
        folds: &[CompactWhirFoldContract; WHIR_FOLD_COUNT_PER_EPOCH],
        record_final_queries: bool,
    ) -> Result<(), CompactProofContractError> {
        self.record_response(1)?;
        self.record_single_move(
            expected_role(7, epoch.epoch, 0, 0),
            extension_message_geometry(1, 0)?,
        )?;
        self.append_whir_folding_moves(epoch, 0)?;

        for (round_ordinal, fold) in folds.iter().enumerate().take(WHIR_ROUND_COUNT) {
            self.record_response(2)?;
            self.record_single_move(
                expected_role(
                    9,
                    epoch.epoch,
                    0,
                    u32::try_from(round_ordinal)
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                ),
                FixedUniformVerifierMessageGeometry::new(
                    1,
                    0,
                    1,
                    vec![FixedUniformDistinctQueryGeometry::new(
                        fold.block_length,
                        fold.query_count,
                    )],
                )?,
            )?;

            let batch_ordinal = round_ordinal + 1;
            self.record_response(1)?;
            self.record_single_move(
                expected_role(
                    7,
                    epoch.epoch,
                    u8::try_from(batch_ordinal)
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                    0,
                ),
                extension_message_geometry(1, 0)?,
            )?;
            self.append_whir_folding_moves(epoch, batch_ordinal)?;
        }

        let mask_group_count = epoch
            .external_mask_groups
            .len()
            .checked_add(epoch.internal_mask_groups.len())
            .ok_or(CompactProofContractError::LengthOverflow)?;
        self.record_response(
            u32::try_from(mask_group_count)
                .map_err(|_| CompactProofContractError::LengthOverflow)?
                .checked_add(1)
                .ok_or(CompactProofContractError::LengthOverflow)?,
        )?;
        self.record_single_move(
            expected_role(10, epoch.epoch, 0, 0),
            extension_message_geometry(1, 0)?,
        )?;
        self.record_response(0)?;
        if record_final_queries {
            self.record_single_move(
                expected_role(11, epoch.epoch, 0, 0),
                FixedUniformVerifierMessageGeometry::new(
                    0,
                    0,
                    0,
                    expected_final_query_groups(epoch, folds)?,
                )?,
            )?;
        }
        Ok(())
    }

    fn append_whir_folding_moves(
        &mut self,
        epoch: &CompactWhirEpochContract,
        batch_ordinal: usize,
    ) -> Result<(), CompactProofContractError> {
        let fold_count = epoch.folding_schedule[batch_ordinal];
        for round_ordinal in 0..fold_count {
            self.record_response(0)?;
            self.record_single_move(
                expected_role(
                    8,
                    epoch.epoch,
                    u8::try_from(batch_ordinal)
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                    round_ordinal,
                ),
                extension_message_geometry(1, 0)?,
            )?;
        }
        Ok(())
    }

    fn finish(
        self,
        verifier_moves: &[CompactVerifierMoveContract],
    ) -> Result<(), CompactProofContractError> {
        let query_group_count = self.moves.iter().try_fold(0_u32, |count, verifier_move| {
            count
                .checked_add(
                    u32::try_from(verifier_move.message_geometry.distinct_query_groups().len())
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                )
                .ok_or(CompactProofContractError::LengthOverflow)
        })?;
        if self.moves != verifier_moves
            || self.commitment_count != EXPECTED_COMMITMENT_COUNT
            || query_group_count != EXPECTED_DISTINCT_QUERY_GROUP_COUNT
        {
            return Err(CompactProofContractError::InvalidTranscript);
        }
        Ok(())
    }
}

fn extension_message_geometry(
    extension_output_count: u64,
    excluded_extension_prefix_cardinality: u64,
) -> Result<FixedUniformVerifierMessageGeometry, CompactProofContractError> {
    Ok(FixedUniformVerifierMessageGeometry::new(
        extension_output_count,
        excluded_extension_prefix_cardinality,
        0,
        Vec::new(),
    )?)
}

fn expected_final_query_groups(
    epoch: &CompactWhirEpochContract,
    folds: &[CompactWhirFoldContract; WHIR_FOLD_COUNT_PER_EPOCH],
) -> Result<Vec<FixedUniformDistinctQueryGeometry>, CompactProofContractError> {
    let mut groups = Vec::with_capacity(
        1_usize
            .checked_add(epoch.external_mask_groups.len())
            .and_then(|count| count.checked_add(epoch.internal_mask_groups.len()))
            .ok_or(CompactProofContractError::LengthOverflow)?,
    );
    groups.push(FixedUniformDistinctQueryGeometry::new(
        folds[WHIR_FOLD_COUNT_PER_EPOCH - 1].block_length,
        folds[WHIR_FOLD_COUNT_PER_EPOCH - 1].query_count,
    ));
    groups.extend(
        epoch
            .external_mask_groups
            .iter()
            .chain(&epoch.internal_mask_groups)
            .map(|group| {
                FixedUniformDistinctQueryGeometry::new(group.domain_size, epoch.mask_query_count)
            }),
    );
    Ok(groups)
}

const fn expected_role(
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
) -> CompactVerifierRoleCoordinate {
    expected_role_with_ranges(
        role_tag,
        epoch,
        batch_ordinal,
        round_ordinal,
        [[0, 0], [0, 0], [0, 0]],
    )
}

const fn expected_role_with_ranges(
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
    ranges: [[u64; 2]; 3],
) -> CompactVerifierRoleCoordinate {
    CompactVerifierRoleCoordinate {
        role_tag,
        epoch,
        batch_ordinal,
        round_ordinal,
        extension_output_start: ranges[0][0],
        extension_output_end: ranges[0][1],
        base_field_output_start: ranges[1][0],
        base_field_output_end: ranges[1][1],
        distinct_query_group_start: ranges[2][0],
        distinct_query_group_end: ranges[2][1],
    }
}

fn full_message_role(
    role: CompactVerifierRoleCoordinate,
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<CompactVerifierRoleCoordinate, CompactProofContractError> {
    Ok(expected_role_with_ranges(
        role.role_tag,
        role.epoch,
        role.batch_ordinal,
        role.round_ordinal,
        [
            [0, geometry.extension_output_count()],
            [0, geometry.base_field_output_count()],
            [
                0,
                u64::try_from(geometry.distinct_query_groups().len())
                    .map_err(|_| CompactProofContractError::LengthOverflow)?,
            ],
        ],
    ))
}

fn validate_exact_response_registry(
    response_merkle_geometries: &[CompactResponseMerkleGeometry],
    response_component_roles: &[Vec<CompactResponseComponentRoleContract>],
    verifier_moves: &[CompactVerifierMoveContract],
    cfw_configuration: CompactCfwVerifierConfiguration,
    whir_epochs: &[CompactWhirEpochContract],
    whir_folds: &[CompactWhirFoldContract],
) -> Result<(), CompactProofContractError> {
    if response_merkle_geometries.len() != verifier_moves.len()
        || response_component_roles.len() != verifier_moves.len()
    {
        return Err(CompactProofContractError::InvalidResponseRegistry);
    }
    for (response_index, verifier_move) in verifier_moves.iter().enumerate() {
        let response_ordinal =
            u32::try_from(response_index).map_err(|_| CompactProofContractError::LengthOverflow)?;
        let mut expected = ExpectedResponseRegistry::new();
        match verifier_move.role_coordinates.as_slice() {
            [role] if role.role_tag == 1 => {
                let (epoch, folds) = expected_whir_epoch_and_folds(1, whir_epochs, whir_folds)?;
                expected.push_queried_component(
                    response_component_role(1, 0, 0, 0),
                    folds[0].block_length,
                    folds[0].query_count,
                    expected_source_query_selection(verifier_moves, epoch.epoch, 0)?,
                    CompactResponseLeafValueKind::BaseField,
                    folds[0].oracle_width,
                )?;
            }
            [role] if role.role_tag == 2 => {
                let (pre_epoch, _) = expected_whir_epoch_and_folds(1, whir_epochs, whir_folds)?;
                let (main_epoch, main_folds) =
                    expected_whir_epoch_and_folds(2, whir_epochs, whir_folds)?;
                let (cfw_inner_index, cfw_inner) = expected_whir_mask_group(main_epoch, 2, 0)?;
                expected.push_queried_component(
                    response_component_role(2, 0, 0, 0),
                    cfw_inner.domain_size,
                    main_epoch.mask_query_count,
                    expected_final_mask_query_selection(
                        verifier_moves,
                        main_epoch.epoch,
                        cfw_inner_index,
                    )?,
                    CompactResponseLeafValueKind::ExtensionField,
                    cfw_inner.width,
                )?;
                expected.push_queried_component(
                    response_component_role(3, 0, 0, 0),
                    main_folds[0].block_length,
                    main_folds[0].query_count,
                    expected_source_query_selection(verifier_moves, main_epoch.epoch, 0)?,
                    CompactResponseLeafValueKind::ExtensionField,
                    main_folds[0].oracle_width,
                )?;
                let (cfw_outer_index, cfw_outer) = expected_whir_mask_group(main_epoch, 3, 0)?;
                expected.push_queried_component(
                    response_component_role(4, 0, 0, 0),
                    cfw_outer.domain_size,
                    main_epoch.mask_query_count,
                    expected_final_mask_query_selection(
                        verifier_moves,
                        main_epoch.epoch,
                        cfw_outer_index,
                    )?,
                    CompactResponseLeafValueKind::ExtensionField,
                    cfw_outer.width,
                )?;
                let (pre_cross_index, pre_cross) = expected_whir_mask_group(pre_epoch, 1, 0)?;
                let (main_cross_index, main_cross) = expected_whir_mask_group(main_epoch, 1, 0)?;
                if (
                    pre_cross.width,
                    pre_cross.message_length,
                    pre_cross.randomness_length,
                ) != (
                    main_cross.width,
                    main_cross.message_length,
                    main_cross.randomness_length,
                ) || pre_cross.domain_size != main_cross.domain_size
                {
                    return Err(CompactProofContractError::InvalidResponseRegistry);
                }
                let combined_query_count = pre_epoch
                    .mask_query_count
                    .checked_add(main_epoch.mask_query_count)
                    .ok_or(CompactProofContractError::LengthOverflow)?;
                let minimum_union_count = combined_query_count
                    .saturating_sub(pre_cross.domain_size)
                    .max(pre_epoch.mask_query_count)
                    .max(main_epoch.mask_query_count);
                let maximum_union_count = combined_query_count.min(pre_cross.domain_size);
                expected.push_component(
                    response_component_role(5, 0, 0, 0),
                    CompactResponseComponentGeometry::new_with_query_count_range(
                        0,
                        pre_cross.domain_size,
                        minimum_union_count,
                        maximum_union_count,
                        CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                            first_logical_verifier_move_ordinal:
                                expected_final_query_move_ordinal(
                                    verifier_moves,
                                    pre_epoch.epoch,
                                )?,
                            first_distinct_query_group_ordinal: u32::try_from(pre_cross_index)
                                .map_err(|_| CompactProofContractError::LengthOverflow)?
                                .checked_add(1)
                                .ok_or(CompactProofContractError::LengthOverflow)?,
                            second_logical_verifier_move_ordinal:
                                expected_final_query_move_ordinal(
                                    verifier_moves,
                                    main_epoch.epoch,
                                )?,
                            second_distinct_query_group_ordinal: u32::try_from(main_cross_index)
                                .map_err(|_| CompactProofContractError::LengthOverflow)?
                                .checked_add(1)
                                .ok_or(CompactProofContractError::LengthOverflow)?,
                        },
                        CompactResponseLeafValueKind::ExtensionField,
                        pre_cross.width,
                    ),
                )?;
            }
            [role] if role.role_tag == 3 => {
                expected.push_extension_scalars(
                    response_component_role(6, 0, 0, 0),
                    cfw_configuration.cross_epoch_disclosed_scalar_count(),
                )?;
                expected.push_extension_scalars(
                    response_component_role(7, 0, 0, 0),
                    cfw_configuration.auxiliary_target_count(),
                )?;
            }
            [role] if role.role_tag == 4 => {
                expected.push_extension_scalars(
                    response_component_role(8, 0, 0, role.round_ordinal),
                    cfw_configuration.outer_mask_message_length(),
                )?;
            }
            [joint, opening] if joint.role_tag == 5 && opening.role_tag == 6 => {
                expected.push_extension_scalars(
                    response_component_role(9, 0, 0, 0),
                    u64::try_from(cfw_configuration.geometry().outer_mask_count())
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                )?;
                expected.push_extension_scalars(
                    response_component_role(10, 0, 0, 0),
                    u64::try_from(cfw_configuration.matrix_role_tags().len())
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                )?;
            }
            [role] if role.role_tag == 7 => {
                let (epoch, _) =
                    expected_whir_epoch_and_folds(role.epoch, whir_epochs, whir_folds)?;
                let (group_index, group) = expected_whir_mask_group(epoch, 4, role.batch_ordinal)?;
                expected.push_queried_component(
                    response_component_role(11, role.epoch, role.batch_ordinal, 0),
                    group.domain_size,
                    epoch.mask_query_count,
                    expected_final_mask_query_selection(verifier_moves, role.epoch, group_index)?,
                    CompactResponseLeafValueKind::ExtensionField,
                    group.width,
                )?;
                expected.push_extension_scalars(
                    response_component_role(12, role.epoch, role.batch_ordinal, 0),
                    WHIR_AUXILIARY_TARGET_COUNT,
                )?;
            }
            [role] if role.role_tag == 8 => {
                expected.push_extension_scalars(
                    response_component_role(13, role.epoch, role.batch_ordinal, role.round_ordinal),
                    WHIR_SUMCHECK_WIRE_EXTENSION_ELEMENT_COUNT,
                )?;
            }
            [role] if role.role_tag == 9 => {
                let (epoch, folds) =
                    expected_whir_epoch_and_folds(role.epoch, whir_epochs, whir_folds)?;
                let round_index = usize::try_from(role.round_ordinal)
                    .map_err(|_| CompactProofContractError::LengthOverflow)?;
                let next_source_index = round_index
                    .checked_add(1)
                    .ok_or(CompactProofContractError::LengthOverflow)?;
                let next_source = folds
                    .get(next_source_index)
                    .ok_or(CompactProofContractError::InvalidResponseRegistry)?;
                expected.push_queried_component(
                    response_component_role(14, role.epoch, 0, role.round_ordinal),
                    next_source.block_length,
                    next_source.query_count,
                    expected_source_query_selection(verifier_moves, role.epoch, next_source_index)?,
                    CompactResponseLeafValueKind::ExtensionField,
                    next_source.oracle_width,
                )?;
                let (group_index, group) = expected_whir_mask_group(
                    epoch,
                    5,
                    u8::try_from(round_index)
                        .map_err(|_| CompactProofContractError::LengthOverflow)?,
                )?;
                expected.push_queried_component(
                    response_component_role(15, role.epoch, 0, role.round_ordinal),
                    group.domain_size,
                    epoch.mask_query_count,
                    expected_final_mask_query_selection(verifier_moves, role.epoch, group_index)?,
                    CompactResponseLeafValueKind::ExtensionField,
                    group.width,
                )?;
            }
            [role] if role.role_tag == 10 => {
                let (epoch, folds) =
                    expected_whir_epoch_and_folds(role.epoch, whir_epochs, whir_folds)?;
                let final_source = &folds[WHIR_FOLD_COUNT_PER_EPOCH - 1];
                expected.push_queried_component(
                    response_component_role(16, role.epoch, 0, 0),
                    final_source.block_length,
                    final_source.query_count,
                    expected_source_query_selection(verifier_moves, role.epoch, WHIR_ROUND_COUNT)?,
                    CompactResponseLeafValueKind::ExtensionField,
                    1,
                )?;
                for (group_index, group) in epoch
                    .external_mask_groups
                    .iter()
                    .chain(&epoch.internal_mask_groups)
                    .enumerate()
                {
                    expected.push_queried_component(
                        response_component_role(
                            17,
                            role.epoch,
                            u8::try_from(group_index)
                                .map_err(|_| CompactProofContractError::LengthOverflow)?,
                            0,
                        ),
                        group.domain_size,
                        epoch.mask_query_count,
                        expected_final_mask_query_selection(
                            verifier_moves,
                            role.epoch,
                            group_index,
                        )?,
                        CompactResponseLeafValueKind::ExtensionField,
                        group.width,
                    )?;
                }
                expected.push_extension_scalars(
                    response_component_role(18, role.epoch, 0, 0),
                    WHIR_BASE_MASKED_CLAIM_COUNT,
                )?;
            }
            [final_queries, opening] if final_queries.role_tag == 11 && opening.role_tag == 6 => {
                append_expected_blinded_response(
                    &mut expected,
                    final_queries.epoch,
                    whir_epochs,
                    whir_folds,
                )?;
            }
            [role] if role.role_tag == 11 => {
                append_expected_blinded_response(
                    &mut expected,
                    role.epoch,
                    whir_epochs,
                    whir_folds,
                )?;
            }
            _ => return Err(CompactProofContractError::InvalidResponseRegistry),
        }
        let (expected_merkle, expected_roles) = expected.finish(response_ordinal)?;
        if response_merkle_geometries[response_index] != expected_merkle
            || response_component_roles[response_index] != expected_roles
        {
            return Err(CompactProofContractError::InvalidResponseRegistry);
        }
    }
    Ok(())
}

fn append_expected_blinded_response(
    expected: &mut ExpectedResponseRegistry,
    epoch_tag: u8,
    whir_epochs: &[CompactWhirEpochContract],
    whir_folds: &[CompactWhirFoldContract],
) -> Result<(), CompactProofContractError> {
    let (epoch, folds) = expected_whir_epoch_and_folds(epoch_tag, whir_epochs, whir_folds)?;
    let source_message_element_count = 1_u64
        .checked_shl(epoch.final_variable_count)
        .ok_or(CompactProofContractError::LengthOverflow)?;
    expected.push_extension_scalars(
        response_component_role(19, epoch_tag, 0, 0),
        source_message_element_count,
    )?;
    expected.push_extension_scalars(
        response_component_role(20, epoch_tag, 0, 0),
        folds[WHIR_FOLD_COUNT_PER_EPOCH - 1].query_count,
    )?;
    for (group_index, group) in epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .enumerate()
    {
        expected.push_extension_scalars(
            response_component_role(
                21,
                epoch_tag,
                u8::try_from(group_index).map_err(|_| CompactProofContractError::LengthOverflow)?,
                0,
            ),
            group
                .width
                .checked_mul(
                    group
                        .message_length
                        .checked_add(group.randomness_length)
                        .ok_or(CompactProofContractError::LengthOverflow)?,
                )
                .ok_or(CompactProofContractError::LengthOverflow)?,
        )?;
    }
    Ok(())
}

struct ExpectedResponseRegistry {
    components: Vec<CompactResponseComponentGeometry>,
    roles: Vec<CompactResponseComponentRoleContract>,
    meaningful_leaf_count: u64,
}

impl ExpectedResponseRegistry {
    fn new() -> Self {
        Self {
            components: Vec::new(),
            roles: Vec::new(),
            meaningful_leaf_count: 0,
        }
    }

    fn push_extension_scalars(
        &mut self,
        role: CompactResponseComponentRoleContract,
        element_count: u64,
    ) -> Result<(), CompactProofContractError> {
        self.push_component(
            role,
            CompactResponseComponentGeometry::new(
                0,
                element_count,
                element_count,
                CompactResponseQuerySelection::EveryLeaf,
                CompactResponseLeafValueKind::ExtensionField,
                1,
            ),
        )
    }

    fn push_queried_component(
        &mut self,
        role: CompactResponseComponentRoleContract,
        leaf_count: u64,
        query_count: u64,
        query_selection: CompactResponseQuerySelection,
        value_kind: CompactResponseLeafValueKind,
        field_element_count_per_leaf: u64,
    ) -> Result<(), CompactProofContractError> {
        self.push_component(
            role,
            CompactResponseComponentGeometry::new(
                0,
                leaf_count,
                query_count,
                query_selection,
                value_kind,
                field_element_count_per_leaf,
            ),
        )
    }

    fn push_component(
        &mut self,
        role: CompactResponseComponentRoleContract,
        component: CompactResponseComponentGeometry,
    ) -> Result<(), CompactProofContractError> {
        let leaf_count = component.leaf_count();
        self.components.push(
            CompactResponseComponentGeometry::new_with_query_count_range(
                self.meaningful_leaf_count,
                component.leaf_count(),
                component.minimum_queried_leaf_count(),
                component.maximum_queried_leaf_count(),
                component.query_selection(),
                component.value_kind(),
                component.field_element_count_per_leaf(),
            ),
        );
        self.roles.push(role);
        self.meaningful_leaf_count = self
            .meaningful_leaf_count
            .checked_add(leaf_count)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        Ok(())
    }

    fn finish(
        mut self,
        response_ordinal: u32,
    ) -> Result<
        (
            CompactResponseMerkleGeometry,
            Vec<CompactResponseComponentRoleContract>,
        ),
        CompactProofContractError,
    > {
        let merkle_leaf_count = self
            .meaningful_leaf_count
            .checked_next_power_of_two()
            .ok_or(CompactProofContractError::LengthOverflow)?;
        if merkle_leaf_count > self.meaningful_leaf_count {
            self.push_component(
                response_component_role(22, 0, 0, 0),
                CompactResponseComponentGeometry::new(
                    0,
                    merkle_leaf_count - self.meaningful_leaf_count,
                    0,
                    CompactResponseQuerySelection::Unqueried,
                    CompactResponseLeafValueKind::Padding,
                    0,
                ),
            )?;
        }
        Ok((
            CompactResponseMerkleGeometry::new(response_ordinal, self.components)?,
            self.roles,
        ))
    }
}

const fn response_component_role(
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
) -> CompactResponseComponentRoleContract {
    CompactResponseComponentRoleContract {
        role_tag,
        epoch,
        batch_ordinal,
        round_ordinal,
    }
}

fn expected_whir_epoch_and_folds<'a>(
    epoch_tag: u8,
    whir_epochs: &'a [CompactWhirEpochContract],
    whir_folds: &'a [CompactWhirFoldContract],
) -> Result<
    (
        &'a CompactWhirEpochContract,
        &'a [CompactWhirFoldContract; WHIR_FOLD_COUNT_PER_EPOCH],
    ),
    CompactProofContractError,
> {
    let epoch_index = usize::from(
        epoch_tag
            .checked_sub(1)
            .ok_or(CompactProofContractError::InvalidResponseRegistry)?,
    );
    let epoch = whir_epochs
        .get(epoch_index)
        .ok_or(CompactProofContractError::InvalidResponseRegistry)?;
    let first_fold = epoch_index
        .checked_mul(WHIR_FOLD_COUNT_PER_EPOCH)
        .ok_or(CompactProofContractError::LengthOverflow)?;
    let folds = whir_folds
        .get(first_fold..first_fold + WHIR_FOLD_COUNT_PER_EPOCH)
        .and_then(|folds| folds.try_into().ok())
        .ok_or(CompactProofContractError::InvalidResponseRegistry)?;
    Ok((epoch, folds))
}

fn expected_whir_mask_group(
    epoch: &CompactWhirEpochContract,
    role_tag: u8,
    coordinate: u8,
) -> Result<(usize, &CompactWhirMaskGroupContract), CompactProofContractError> {
    let mut matching_group = None;
    for (group_index, group) in epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .enumerate()
    {
        if group.role_tag == role_tag && group.coordinate == coordinate {
            if matching_group.is_some() {
                return Err(CompactProofContractError::InvalidResponseRegistry);
            }
            matching_group = Some((group_index, group));
        }
    }
    matching_group.ok_or(CompactProofContractError::InvalidResponseRegistry)
}

fn expected_verifier_move_ordinal(
    verifier_moves: &[CompactVerifierMoveContract],
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
) -> Result<u32, CompactProofContractError> {
    let mut matching_ordinal = None;
    for verifier_move in verifier_moves {
        if verifier_move.role_coordinates.iter().any(|role| {
            (
                role.role_tag,
                role.epoch,
                role.batch_ordinal,
                role.round_ordinal,
            ) == (role_tag, epoch, batch_ordinal, round_ordinal)
        }) {
            if matching_ordinal.is_some() {
                return Err(CompactProofContractError::InvalidResponseRegistry);
            }
            matching_ordinal = Some(verifier_move.ordinal);
        }
    }
    matching_ordinal.ok_or(CompactProofContractError::InvalidResponseRegistry)
}

fn expected_final_query_move_ordinal(
    verifier_moves: &[CompactVerifierMoveContract],
    epoch: u8,
) -> Result<u32, CompactProofContractError> {
    expected_verifier_move_ordinal(verifier_moves, 11, epoch, 0, 0)
}

fn expected_final_mask_query_selection(
    verifier_moves: &[CompactVerifierMoveContract],
    epoch: u8,
    group_index: usize,
) -> Result<CompactResponseQuerySelection, CompactProofContractError> {
    Ok(
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal: expected_final_query_move_ordinal(
                verifier_moves,
                epoch,
            )?,
            distinct_query_group_ordinal: u32::try_from(group_index)
                .map_err(|_| CompactProofContractError::LengthOverflow)?
                .checked_add(1)
                .ok_or(CompactProofContractError::LengthOverflow)?,
        },
    )
}

fn expected_source_query_selection(
    verifier_moves: &[CompactVerifierMoveContract],
    epoch: u8,
    oracle_ordinal: usize,
) -> Result<CompactResponseQuerySelection, CompactProofContractError> {
    let logical_verifier_move_ordinal = if oracle_ordinal < WHIR_ROUND_COUNT {
        expected_verifier_move_ordinal(
            verifier_moves,
            9,
            epoch,
            0,
            u32::try_from(oracle_ordinal).map_err(|_| CompactProofContractError::LengthOverflow)?,
        )?
    } else if oracle_ordinal == WHIR_ROUND_COUNT {
        expected_final_query_move_ordinal(verifier_moves, epoch)?
    } else {
        return Err(CompactProofContractError::InvalidResponseRegistry);
    };
    Ok(
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal,
            distinct_query_group_ordinal: 0,
        },
    )
}

fn validate_role_coordinate_partition(
    roles: &[CompactVerifierRoleCoordinate],
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<(), CompactProofContractError> {
    let query_group_count = u64::try_from(geometry.distinct_query_groups().len())
        .map_err(|_| CompactProofContractError::LengthOverflow)?;
    for (start, end, total) in roles.iter().flat_map(|role| {
        [
            (
                role.extension_output_start,
                role.extension_output_end,
                geometry.extension_output_count(),
            ),
            (
                role.base_field_output_start,
                role.base_field_output_end,
                geometry.base_field_output_count(),
            ),
            (
                role.distinct_query_group_start,
                role.distinct_query_group_end,
                query_group_count,
            ),
        ]
    }) {
        if start > end || end > total {
            return Err(CompactProofContractError::InvalidTranscript);
        }
    }
    validate_exact_role_partition(roles, geometry.extension_output_count(), |role| {
        (role.extension_output_start, role.extension_output_end)
    })?;
    validate_exact_role_partition(roles, geometry.base_field_output_count(), |role| {
        (role.base_field_output_start, role.base_field_output_end)
    })?;
    validate_exact_role_partition(roles, query_group_count, |role| {
        (
            role.distinct_query_group_start,
            role.distinct_query_group_end,
        )
    })?;
    Ok(())
}

fn validate_exact_role_partition(
    roles: &[CompactVerifierRoleCoordinate],
    total: u64,
    range: impl Fn(&CompactVerifierRoleCoordinate) -> (u64, u64),
) -> Result<(), CompactProofContractError> {
    let mut intervals = [(0_u64, 0_u64); 2];
    let mut interval_count = 0_usize;
    for role in roles {
        let (start, end) = range(role);
        if start != end {
            intervals[interval_count] = (start, end);
            interval_count += 1;
        }
    }
    if interval_count == 2 && intervals[1].0 < intervals[0].0 {
        intervals.swap(0, 1);
    }
    let mut cursor = 0_u64;
    for &(start, end) in &intervals[..interval_count] {
        if start != cursor || end < start || end > total {
            return Err(CompactProofContractError::InvalidTranscript);
        }
        cursor = end;
    }
    if cursor != total {
        return Err(CompactProofContractError::InvalidTranscript);
    }
    Ok(())
}

fn decode_whir_fold(
    reader: &mut Reader<'_>,
    fold_index: usize,
) -> Result<CompactWhirFoldContract, CompactProofContractError> {
    let fold = CompactWhirFoldContract {
        epoch: reader.read_u8()?,
        batch_ordinal: reader.read_u8()?,
        message_length: reader.read_u64()?,
        hiding_randomness_length: reader.read_u64()?,
        block_length: reader.read_u64()?,
        oracle_width: reader.read_u64()?,
        query_count: reader.read_u64()?,
        unique_decoding_radius: reader.read_u64()?,
    };
    fold.validate(fold_index)?;
    Ok(fold)
}

fn decode_message_geometry(
    reader: &mut Reader<'_>,
) -> Result<FixedUniformVerifierMessageGeometry, CompactProofContractError> {
    let extension_output_count = reader.read_u64()?;
    let excluded_extension_prefix_cardinality = reader.read_u64()?;
    let base_field_output_count = reader.read_u64()?;
    let group_count = reader.read_count()?;
    let mut groups = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        groups.push(FixedUniformDistinctQueryGeometry::new(
            reader.read_u64()?,
            reader.read_u64()?,
        ));
    }
    Ok(FixedUniformVerifierMessageGeometry::new(
        extension_output_count,
        excluded_extension_prefix_cardinality,
        base_field_output_count,
        groups,
    )?)
}

fn encode_message_geometry(
    writer: &mut Writer,
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<(), CompactProofContractError> {
    writer.write_u64(geometry.extension_output_count());
    writer.write_u64(geometry.excluded_extension_prefix_cardinality());
    writer.write_u64(geometry.base_field_output_count());
    writer.write_count(geometry.distinct_query_groups().len())?;
    for group in geometry.distinct_query_groups() {
        writer.write_u64(group.domain_cardinality());
        writer.write_u64(group.query_count());
    }
    Ok(())
}

struct Reader<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> Reader<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Result<Self, CompactProofContractError> {
        if bytes.len() > MAXIMUM_CONTRACT_BYTE_LENGTH {
            return Err(CompactProofContractError::LimitExceeded);
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn read_array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], CompactProofContractError> {
        let end = self
            .offset
            .checked_add(LENGTH)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(CompactProofContractError::Truncated)?;
        let mut output = [0; LENGTH];
        output.copy_from_slice(source);
        self.offset = end;
        Ok(output)
    }

    fn read_u8(&mut self) -> Result<u8, CompactProofContractError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, CompactProofContractError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, CompactProofContractError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, CompactProofContractError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_count(&mut self) -> Result<usize, CompactProofContractError> {
        let count = usize::try_from(self.read_u32()?)
            .map_err(|_| CompactProofContractError::LengthOverflow)?;
        if count > MAXIMUM_CONTRACT_LIST_LENGTH {
            return Err(CompactProofContractError::LimitExceeded);
        }
        Ok(count)
    }

    fn expect_fixed(&mut self, expected: &[u8]) -> Result<(), CompactProofContractError> {
        let end = self
            .offset
            .checked_add(expected.len())
            .ok_or(CompactProofContractError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(CompactProofContractError::Truncated);
        }
        if self.bytes.get(self.offset..end) != Some(expected) {
            return Err(CompactProofContractError::WrongMagic);
        }
        self.offset = end;
        Ok(())
    }

    fn expect_u16(&mut self, expected: u16) -> Result<(), CompactProofContractError> {
        if self.read_u16()? != expected {
            return Err(CompactProofContractError::WrongVersionOrTarget);
        }
        Ok(())
    }

    fn expect_u8(&mut self, expected: u8) -> Result<(), CompactProofContractError> {
        if self.read_u8()? != expected {
            return Err(CompactProofContractError::WrongVersionOrTarget);
        }
        Ok(())
    }

    fn expect_u32(&mut self, expected: u32) -> Result<(), CompactProofContractError> {
        if self.read_u32()? != expected {
            return Err(CompactProofContractError::WrongVersionOrTarget);
        }
        Ok(())
    }

    fn expect_domain(&mut self, expected: &str) -> Result<(), CompactProofContractError> {
        let length = usize::from(self.read_u16()?);
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CompactProofContractError::LengthOverflow)?;
        if self.bytes.get(self.offset..end) != Some(expected.as_bytes()) {
            return Err(CompactProofContractError::WrongDomain);
        }
        self.offset = end;
        Ok(())
    }

    fn finish(self) -> Result<(), CompactProofContractError> {
        if self.offset != self.bytes.len() {
            return Err(CompactProofContractError::TrailingBytes);
        }
        Ok(())
    }
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn write_fixed(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.write_fixed(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write_fixed(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write_fixed(&value.to_le_bytes());
    }

    fn write_count(&mut self, value: usize) -> Result<(), CompactProofContractError> {
        if value > MAXIMUM_CONTRACT_LIST_LENGTH {
            return Err(CompactProofContractError::LimitExceeded);
        }
        self.write_u32(
            u32::try_from(value).map_err(|_| CompactProofContractError::LengthOverflow)?,
        );
        Ok(())
    }

    fn write_domain(&mut self, domain: &str) -> Result<(), CompactProofContractError> {
        let length =
            u16::try_from(domain.len()).map_err(|_| CompactProofContractError::LengthOverflow)?;
        self.write_u16(length);
        self.write_fixed(domain.as_bytes());
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, CompactProofContractError> {
        if self.bytes.len() > MAXIMUM_CONTRACT_BYTE_LENGTH {
            return Err(CompactProofContractError::LimitExceeded);
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_factor_one_contract_source_is_byte_identical() {
        let generated =
            super::super::compact_public_key_static_catalog::generated_factor_one_contract_source_bytes();
        assert_eq!(generated, GENERATED_CONTRACT_BYTES);
        let decoded = CompactPublicKeyProofContract::decode_selected()
            .expect("checked-in factor-one contract decodes");
        assert_eq!(decoded.encode().expect("contract re-encodes"), generated);
    }

    #[test]
    fn hostile_contract_framing_and_target_are_refused() {
        assert_eq!(
            CompactPublicKeyProofContract::decode(&CONTRACT_MAGIC[..7]),
            Err(CompactProofContractError::Truncated)
        );
        let mut wrong_magic = CONTRACT_MAGIC;
        wrong_magic[0] ^= 1;
        assert_eq!(
            CompactPublicKeyProofContract::decode(&wrong_magic),
            Err(CompactProofContractError::WrongMagic)
        );
        assert_eq!(
            CompactPublicKeyProofContract::decode(&vec![0; MAXIMUM_CONTRACT_BYTE_LENGTH + 1]),
            Err(CompactProofContractError::LimitExceeded)
        );

        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &GENERATED_CONTRACT_BYTES[..GENERATED_CONTRACT_BYTES.len() - 1],
            ),
            Err(CompactProofContractError::Truncated),
        );
        let mut trailing = GENERATED_CONTRACT_BYTES.to_vec();
        trailing.push(0);
        assert_eq!(
            CompactPublicKeyProofContract::decode(&trailing),
            Err(CompactProofContractError::TrailingBytes),
        );

        for field_offset in [8_usize, 10, 12, 14, 16, 18, 20, 86] {
            let mut wrong_target = GENERATED_CONTRACT_BYTES.to_vec();
            wrong_target[field_offset] ^= 1;
            assert_eq!(
                CompactPublicKeyProofContract::decode(&wrong_target),
                Err(CompactProofContractError::WrongVersionOrTarget),
            );
        }

        let mut reader = generated_contract_header_reader();
        let mut offset = reader.offset;
        for expected_domain in compact_contract_binding_domains() {
            let length = usize::from(u16::from_le_bytes(
                GENERATED_CONTRACT_BYTES[offset..offset + 2]
                    .try_into()
                    .expect("domain length bytes"),
            ));
            assert_eq!(length, expected_domain.len());
            let mut wrong_domain = GENERATED_CONTRACT_BYTES.to_vec();
            wrong_domain[offset + 2] ^= 1;
            assert_eq!(
                CompactPublicKeyProofContract::decode(&wrong_domain),
                Err(CompactProofContractError::WrongDomain),
            );
            let mut wrong_domain_length = GENERATED_CONTRACT_BYTES.to_vec();
            wrong_domain_length[offset..offset + 2]
                .copy_from_slice(&(u16::try_from(length).unwrap() + 1).to_le_bytes());
            assert_eq!(
                CompactPublicKeyProofContract::decode(&wrong_domain_length),
                Err(CompactProofContractError::WrongDomain),
            );
            offset += 2 + length;
            reader
                .expect_domain(expected_domain)
                .expect("generated domain framing decodes");
        }
        assert_eq!(reader.offset, offset);

        let _: [u8; 64] = reader.read_array().expect("relation schema digest decodes");
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected relation catalog derives");
        let cfw_configuration =
            selected_cfw_configuration(&relation).expect("selected CFW configuration derives");
        decode_cfw_configuration(&mut reader, cfw_configuration)
            .expect("generated CFW configuration decodes");
        let response_count_offset = reader.offset;
        let mut missing_response = GENERATED_CONTRACT_BYTES.to_vec();
        missing_response[response_count_offset..response_count_offset + 4].copy_from_slice(
            &(u32::try_from(EXPECTED_RESPONSE_COUNT).expect("response count fits u32") - 1)
                .to_le_bytes(),
        );
        assert_eq!(
            CompactPublicKeyProofContract::decode(&missing_response),
            Err(CompactProofContractError::InvalidResponseRegistry),
        );
        let mut excessive_response_count = GENERATED_CONTRACT_BYTES.to_vec();
        excessive_response_count[response_count_offset..response_count_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            CompactPublicKeyProofContract::decode(&excessive_response_count),
            Err(CompactProofContractError::LimitExceeded),
        );
    }

    #[test]
    fn every_static_contract_binding_is_load_bearing() {
        let mut reader = Reader::new(GENERATED_CONTRACT_BYTES)
            .expect("generated contract stays inside the byte ceiling");
        reader
            .expect_fixed(&CONTRACT_MAGIC)
            .expect("generated contract magic decodes");
        for expected in [
            CONTRACT_VERSION,
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            COMPACT_PACKING_FACTOR,
        ] {
            reader
                .expect_u16(expected)
                .expect("generated target binding decodes");
        }
        let statement_layout = selected_public_key_share_statement_layout()
            .expect("selected statement layout derives");
        for expected in [
            statement_layout.schema_identifier(),
            statement_layout.schema_version(),
            statement_layout.field_count(),
        ] {
            reader
                .expect_u16(expected)
                .expect("generated statement binding decodes");
        }

        let statement_digest_start = reader.offset;
        reader
            .expect_fixed(
                &statement_layout
                    .canonical_layout_digest()
                    .expect("statement layout digest derives"),
            )
            .expect("generated statement digest decodes");
        assert_representative_byte_mutation_is_refused(
            statement_digest_start..reader.offset,
            CompactProofContractError::WrongMagic,
            "statement layout digest",
        );

        reader
            .expect_u32(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT)
            .expect("generated candidate-draw binding decodes");
        let transcript_version_start = reader.offset;
        reader
            .expect_u16(COMPACT_FIAT_SHAMIR_PREFIX_VERSION)
            .expect("generated transcript version decodes");
        assert_each_byte_mutation_is_refused(
            transcript_version_start..reader.offset,
            CompactProofContractError::WrongVersionOrTarget,
            "transcript version",
        );
        let verifier_message_version_start = reader.offset;
        reader
            .expect_u16(FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION)
            .expect("generated verifier-message version decodes");
        assert_each_byte_mutation_is_refused(
            verifier_message_version_start..reader.offset,
            CompactProofContractError::WrongVersionOrTarget,
            "verifier-message version",
        );

        let proof_magic_start = reader.offset;
        reader
            .expect_fixed(&COMPACT_PROOF_WIRE_MAGIC)
            .expect("generated proof magic decodes");
        assert_representative_byte_mutation_is_refused(
            proof_magic_start..reader.offset,
            CompactProofContractError::WrongMagic,
            "proof wire magic",
        );
        let public_input_magic_start = reader.offset;
        reader
            .expect_fixed(&COMPACT_PUBLIC_INPUT_WIRE_MAGIC)
            .expect("generated public-input magic decodes");
        assert_representative_byte_mutation_is_refused(
            public_input_magic_start..reader.offset,
            CompactProofContractError::WrongMagic,
            "public-input wire magic",
        );
        for role in compact_public_input_binding_roles() {
            let role_offset = reader.offset;
            reader
                .expect_u8(role as u8)
                .expect("generated public-input role decodes");
            assert_each_byte_mutation_is_refused(
                role_offset..reader.offset,
                CompactProofContractError::WrongVersionOrTarget,
                "public-input binding role",
            );
        }
        for domain in compact_contract_binding_domains() {
            reader
                .expect_domain(domain)
                .expect("generated contract domain decodes");
        }

        let relation_digest_start = reader.offset;
        reader.offset += 64;
        assert_representative_byte_mutation_is_refused(
            relation_digest_start..reader.offset,
            CompactProofContractError::InvalidRelation,
            "relation schema digest",
        );

        let cfw_start = reader.offset;
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected relation catalog derives");
        let cfw_configuration =
            selected_cfw_configuration(&relation).expect("selected CFW configuration derives");
        decode_cfw_configuration(&mut reader, cfw_configuration)
            .expect("generated CFW configuration decodes");
        assert_representative_byte_mutation_is_refused(
            cfw_start..reader.offset,
            CompactProofContractError::InvalidRelation,
            "CFW verifier configuration",
        );
    }

    #[test]
    fn hostile_verifier_ranges_and_chronology_are_semantically_refused() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("checked-in factor-one contract decodes");

        let mut reversed_range = contract.clone();
        reversed_range.verifier_moves[0].role_coordinates[0].extension_output_start = 1;
        reversed_range.verifier_moves[0].role_coordinates[0].extension_output_end = 0;
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &reversed_range.encode().expect("hostile range encodes")
            ),
            Err(CompactProofContractError::InvalidTranscript),
        );

        let mut overlapping_ranges = contract.clone();
        overlapping_ranges.verifier_moves[26].role_coordinates[1].extension_output_start = 0;
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &overlapping_ranges
                    .encode()
                    .expect("hostile overlapping ranges encode")
            ),
            Err(CompactProofContractError::InvalidTranscript),
        );

        let mut gap_between_ranges = contract.clone();
        gap_between_ranges.verifier_moves[26].role_coordinates[0].extension_output_end = 0;
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &gap_between_ranges
                    .encode()
                    .expect("hostile range gap encodes")
            ),
            Err(CompactProofContractError::InvalidTranscript),
        );

        let mut out_of_bounds_range = contract.clone();
        out_of_bounds_range.verifier_moves[0].role_coordinates[0].extension_output_end = 2;
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &out_of_bounds_range
                    .encode()
                    .expect("hostile out-of-bounds range encodes")
            ),
            Err(CompactProofContractError::InvalidTranscript),
        );

        let mut excessive_role_count = contract.clone();
        let duplicate_role = excessive_role_count.verifier_moves[26].role_coordinates[0];
        excessive_role_count.verifier_moves[26]
            .role_coordinates
            .push(duplicate_role);
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &excessive_role_count
                    .encode()
                    .expect("hostile role count encodes")
            ),
            Err(CompactProofContractError::InvalidTranscript),
        );

        let mut wrong_predecessor = contract.clone();
        wrong_predecessor.verifier_moves[53].preceding_prover_response_ordinal -= 1;
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &wrong_predecessor
                    .encode()
                    .expect("hostile predecessor encodes")
            ),
            Err(CompactProofContractError::InvalidTranscript),
        );

        let mut wrong_commitment_progression = contract;
        wrong_commitment_progression.verifier_moves[52].preceding_commitment_count -= 1;
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &wrong_commitment_progression
                    .encode()
                    .expect("hostile commitment progression encodes")
            ),
            Err(CompactProofContractError::InvalidTranscript),
        );
    }

    #[test]
    fn hostile_response_semantics_are_refused() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("checked-in factor-one contract decodes");

        let mut detached_frontier_ceiling = contract.clone();
        let original_wire = &detached_frontier_ceiling.proof_wire_geometry.responses()[0];
        let replacement_wire = CompactProofResponseWireGeometry::new_with_count_ranges(
            original_wire.ordinal(),
            original_wire.minimum_queried_base_field_element_count(),
            original_wire.maximum_queried_base_field_element_count(),
            original_wire.minimum_queried_extension_field_element_count(),
            original_wire.maximum_queried_extension_field_element_count(),
            original_wire.minimum_queried_leaf_count(),
            original_wire.maximum_queried_leaf_count(),
            original_wire.maximum_frontier_node_count() + 1,
            original_wire.verifier_message_geometry().clone(),
        )
        .expect("hostile frontier ceiling remains structurally framed");
        let mut response_wires = detached_frontier_ceiling
            .proof_wire_geometry
            .responses()
            .to_vec();
        response_wires[0] = replacement_wire;
        detached_frontier_ceiling.proof_wire_geometry =
            CompactProofWireGeometry::new(response_wires)
                .expect("hostile proof geometry remains structurally framed");
        assert_eq!(
            CompactPublicKeyProofContract::decode(
                &detached_frontier_ceiling
                    .encode()
                    .expect("hostile frontier ceiling encodes")
            ),
            Err(CompactProofContractError::ResponseMerkle(
                CompactResponseMerkleError::WireGeometryMismatch,
            )),
        );

        let mut wrong_value_kind = contract.clone();
        replace_response_component(
            &mut wrong_value_kind,
            0,
            0,
            Some(CompactResponseLeafValueKind::ExtensionField),
            None,
        );
        assert!(matches!(
            CompactPublicKeyProofContract::decode(
                &wrong_value_kind
                    .encode()
                    .expect("hostile value kind encodes")
            ),
            Err(CompactProofContractError::ResponseMerkle(_)),
        ));
    }

    #[test]
    fn every_response_semantic_coordinate_is_load_bearing() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("checked-in factor-one contract decodes");

        for (response_index, roles) in contract.response_component_roles.iter().enumerate() {
            for component_index in 0..roles.len() {
                for coordinate in 0..4 {
                    let mut hostile = contract.clone();
                    let role =
                        &mut hostile.response_component_roles[response_index][component_index];
                    match coordinate {
                        0 => {
                            role.role_tag = if role.role_tag == 22 {
                                21
                            } else {
                                role.role_tag + 1
                            }
                        }
                        1 => role.epoch = if role.epoch == 2 { 1 } else { role.epoch + 1 },
                        2 => role.batch_ordinal = role.batch_ordinal.wrapping_add(1),
                        3 => role.round_ordinal = role.round_ordinal.wrapping_add(1),
                        _ => unreachable!(),
                    }
                    assert_contract_mutation_is_refused(
                        hostile,
                        &format!(
                            "response {response_index} component {component_index} role coordinate {coordinate}"
                        ),
                    );
                }
            }
        }

        let query_sources =
            contract
                .response_merkle_geometries
                .iter()
                .enumerate()
                .flat_map(|(response_index, geometry)| {
                    geometry.components().iter().enumerate().map(
                        move |(component_index, component)| {
                            (response_index, component_index, component.query_selection())
                        },
                    )
                })
                .collect::<Vec<_>>();
        let mut mutated_query_source_coordinates = 0_usize;
        let mut mutated_union_source_coordinates = 0_usize;
        for (response_index, component_index, selection) in query_sources {
            let coordinate_count = match selection {
                CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. } => 2,
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion { .. } => 4,
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf => 0,
            };
            for coordinate in 0..coordinate_count {
                let hostile_selection = mutate_query_source_coordinate(
                    selection,
                    u32::try_from(response_index).expect("response index fits u32"),
                    coordinate,
                );
                let mut hostile = contract.clone();
                replace_response_component(
                    &mut hostile,
                    response_index,
                    component_index,
                    None,
                    Some(hostile_selection),
                );
                assert_contract_mutation_is_refused(
                    hostile,
                    &format!(
                        "response {response_index} component {component_index} query-source coordinate {coordinate}"
                    ),
                );
                mutated_query_source_coordinates += 1;
                if coordinate_count == 4 {
                    mutated_union_source_coordinates += 1;
                }
            }
        }
        assert!(mutated_query_source_coordinates > 0);
        assert!(mutated_union_source_coordinates > 0);
    }

    #[test]
    fn every_whir_epoch_mask_and_fold_field_is_load_bearing() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("checked-in factor-one contract decodes");

        for epoch_index in 0..contract.whir_epochs.len() {
            for field in 0..11 {
                let mut hostile = contract.clone();
                let epoch = &mut hostile.whir_epochs[epoch_index];
                match field {
                    0 => epoch.epoch = if epoch.epoch == 2 { 1 } else { 2 },
                    1 => {
                        epoch.polynomial_variable_count =
                            epoch.polynomial_variable_count.wrapping_add(1)
                    }
                    2..=5 => {
                        epoch.folding_schedule[field - 2] =
                            epoch.folding_schedule[field - 2].wrapping_add(1)
                    }
                    6 => epoch.final_variable_count = epoch.final_variable_count.wrapping_add(1),
                    7..=9 => {
                        epoch.round_log_inverse_rates[field - 7] =
                            epoch.round_log_inverse_rates[field - 7].wrapping_add(1)
                    }
                    10 => epoch.mask_query_count = epoch.mask_query_count.wrapping_add(1),
                    _ => unreachable!(),
                }
                assert_contract_mutation_is_refused(
                    hostile,
                    &format!("WHIR epoch {epoch_index} field {field}"),
                );
            }

            for internal in [true, false] {
                let group_count = if internal {
                    contract.whir_epochs[epoch_index].internal_mask_groups.len()
                } else {
                    contract.whir_epochs[epoch_index].external_mask_groups.len()
                };
                for group_index in 0..group_count {
                    for field in 0..7 {
                        let mut hostile = contract.clone();
                        let group = if internal {
                            &mut hostile.whir_epochs[epoch_index].internal_mask_groups[group_index]
                        } else {
                            &mut hostile.whir_epochs[epoch_index].external_mask_groups[group_index]
                        };
                        match field {
                            0 => {
                                group.role_tag = if group.role_tag == 5 {
                                    4
                                } else {
                                    group.role_tag + 1
                                }
                            }
                            1 => group.coordinate = group.coordinate.wrapping_add(1),
                            2 => group.width = group.width.wrapping_add(1),
                            3 => group.message_length = group.message_length.wrapping_add(1),
                            4 => group.randomness_length = group.randomness_length.wrapping_add(1),
                            5 => group.domain_size = group.domain_size.wrapping_add(1),
                            6 => {
                                group.committed_encoding_source =
                                    if group.committed_encoding_source == 1 {
                                        2
                                    } else {
                                        1
                                    }
                            }
                            _ => unreachable!(),
                        }
                        assert_contract_mutation_is_refused(
                            hostile,
                            &format!(
                                "WHIR epoch {epoch_index} {} mask group {group_index} field {field}",
                                if internal { "internal" } else { "external" }
                            ),
                        );
                    }
                }

                let mut missing_group = contract.clone();
                let groups = if internal {
                    &mut missing_group.whir_epochs[epoch_index].internal_mask_groups
                } else {
                    &mut missing_group.whir_epochs[epoch_index].external_mask_groups
                };
                groups.pop();
                assert_contract_mutation_is_refused(
                    missing_group,
                    &format!(
                        "WHIR epoch {epoch_index} {} mask-group list",
                        if internal { "internal" } else { "external" }
                    ),
                );
            }
        }

        for fold_index in 0..contract.whir_folds.len() {
            for field in 0..8 {
                let mut hostile = contract.clone();
                let fold = &mut hostile.whir_folds[fold_index];
                match field {
                    0 => fold.epoch = if fold.epoch == 2 { 1 } else { 2 },
                    1 => fold.batch_ordinal = fold.batch_ordinal.wrapping_add(1),
                    2 => fold.message_length = fold.message_length.wrapping_add(1),
                    3 => {
                        fold.hiding_randomness_length =
                            fold.hiding_randomness_length.wrapping_add(1)
                    }
                    4 => fold.block_length = fold.block_length.wrapping_add(1),
                    5 => fold.oracle_width = fold.oracle_width.wrapping_add(1),
                    6 => fold.query_count = fold.query_count.wrapping_add(1),
                    7 => fold.unique_decoding_radius = fold.unique_decoding_radius.wrapping_add(1),
                    _ => unreachable!(),
                }
                assert_contract_mutation_is_refused(
                    hostile,
                    &format!("WHIR fold {fold_index} field {field}"),
                );
            }
        }
    }

    #[test]
    fn global_registry_lists_are_load_bearing() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("checked-in factor-one contract decodes");

        let mut missing_move = contract.clone();
        missing_move.verifier_moves.pop();
        assert_contract_mutation_is_refused(missing_move, "verifier move list");

        let mut missing_epoch = contract.clone();
        missing_epoch.whir_epochs.pop();
        assert_contract_mutation_is_refused(missing_epoch, "WHIR epoch list");

        let mut missing_fold = contract.clone();
        missing_fold.whir_folds.pop();
        assert_contract_mutation_is_refused(missing_fold, "WHIR fold list");
    }

    #[test]
    fn every_checkpoint_boundary_is_load_bearing() {
        let checkpoint_offset = generated_checkpoint_offset();
        let checkpoint_count = u32::from_le_bytes(
            GENERATED_CONTRACT_BYTES[checkpoint_offset..checkpoint_offset + 4]
                .try_into()
                .expect("checkpoint count bytes"),
        );
        assert_eq!(
            usize::try_from(checkpoint_count).expect("checkpoint count fits usize"),
            EXPECTED_RESPONSE_COUNT,
        );

        let mut wrong_checkpoint_count = GENERATED_CONTRACT_BYTES.to_vec();
        wrong_checkpoint_count[checkpoint_offset..checkpoint_offset + 4]
            .copy_from_slice(&(checkpoint_count - 1).to_le_bytes());
        assert_eq!(
            decode_with_test_authorities(&wrong_checkpoint_count),
            Err(CompactProofContractError::InvalidCheckpointSchedule),
        );

        let boundary_start = checkpoint_offset + 4;
        for boundary_index in 0..EXPECTED_RESPONSE_COUNT {
            for field_offset in [0_usize, 4] {
                let offset = boundary_start + boundary_index * 8 + field_offset;
                let value = u32::from_le_bytes(
                    GENERATED_CONTRACT_BYTES[offset..offset + 4]
                        .try_into()
                        .expect("checkpoint boundary field bytes"),
                );
                let mut hostile = GENERATED_CONTRACT_BYTES.to_vec();
                hostile[offset..offset + 4].copy_from_slice(&value.wrapping_add(1).to_le_bytes());
                assert_eq!(
                    decode_with_test_authorities(&hostile),
                    Err(CompactProofContractError::InvalidCheckpointSchedule),
                    "checkpoint boundary {boundary_index} field {field_offset} was not load-bearing",
                );
            }
        }

        assert_eq!(
            boundary_start + EXPECTED_RESPONSE_COUNT * 8,
            GENERATED_CONTRACT_BYTES.len()
        );
    }

    fn generated_contract_header_reader() -> Reader<'static> {
        let mut reader = Reader::new(GENERATED_CONTRACT_BYTES)
            .expect("generated contract stays inside the byte ceiling");
        reader
            .expect_fixed(&CONTRACT_MAGIC)
            .expect("generated contract magic decodes");
        reader
            .expect_u16(CONTRACT_VERSION)
            .expect("generated contract version decodes");
        reader
            .expect_u16(FOUNDATION_PROFILE.participant_count)
            .expect("generated participant count decodes");
        reader
            .expect_u16(FOUNDATION_PROFILE.option_count)
            .expect("generated option count decodes");
        reader
            .expect_u16(COMPACT_PACKING_FACTOR)
            .expect("generated packing factor decodes");
        let statement_layout = selected_public_key_share_statement_layout()
            .expect("selected statement layout derives");
        reader
            .expect_u16(statement_layout.schema_identifier())
            .expect("generated statement schema decodes");
        reader
            .expect_u16(statement_layout.schema_version())
            .expect("generated statement version decodes");
        reader
            .expect_u16(statement_layout.field_count())
            .expect("generated statement field count decodes");
        reader
            .expect_fixed(
                &statement_layout
                    .canonical_layout_digest()
                    .expect("statement layout digest derives"),
            )
            .expect("generated statement digest decodes");
        reader
            .expect_u32(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT)
            .expect("generated candidate-draw count decodes");
        reader
            .expect_u16(COMPACT_FIAT_SHAMIR_PREFIX_VERSION)
            .expect("generated transcript version decodes");
        reader
            .expect_u16(FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION)
            .expect("generated message version decodes");
        reader
            .expect_fixed(&COMPACT_PROOF_WIRE_MAGIC)
            .expect("generated proof magic decodes");
        reader
            .expect_fixed(&COMPACT_PUBLIC_INPUT_WIRE_MAGIC)
            .expect("generated public-input magic decodes");
        for role in compact_public_input_binding_roles() {
            reader
                .expect_u8(role as u8)
                .expect("generated public-input role decodes");
        }
        reader
    }

    fn generated_checkpoint_offset() -> usize {
        let mut reader = generated_contract_header_reader();
        for domain in compact_contract_binding_domains() {
            reader
                .expect_domain(domain)
                .expect("generated contract domain decodes");
        }
        let _: [u8; 64] = reader.read_array().expect("relation digest decodes");
        let relation = selected_compact_public_key_relation_catalog()
            .expect("selected relation catalog derives");
        let cfw_configuration =
            selected_cfw_configuration(&relation).expect("selected CFW configuration derives");
        decode_cfw_configuration(&mut reader, cfw_configuration)
            .expect("generated CFW configuration decodes");

        let response_count = reader.read_count().expect("response count decodes");
        for response_index in 0..response_count {
            decode_response(&mut reader, response_index).expect("generated response decodes");
        }
        let move_count = reader.read_count().expect("move count decodes");
        for move_index in 0..move_count {
            decode_verifier_move(&mut reader, move_index).expect("generated verifier move decodes");
        }
        let epoch_count = reader.read_count().expect("WHIR epoch count decodes");
        for epoch_index in 0..epoch_count {
            CompactWhirEpochContract::decode(&mut reader, epoch_index)
                .expect("generated WHIR epoch decodes");
        }
        let fold_count = reader.read_count().expect("WHIR fold count decodes");
        for fold_index in 0..fold_count {
            decode_whir_fold(&mut reader, fold_index).expect("generated WHIR fold decodes");
        }
        reader.offset
    }

    fn assert_each_byte_mutation_is_refused(
        offsets: std::ops::Range<usize>,
        expected_error: CompactProofContractError,
        description: &str,
    ) {
        for offset in offsets {
            let mut hostile = GENERATED_CONTRACT_BYTES.to_vec();
            hostile[offset] ^= 1;
            assert_eq!(
                decode_with_test_authorities(&hostile),
                Err(expected_error),
                "{description} byte {offset} was not load-bearing",
            );
        }
    }

    fn assert_representative_byte_mutation_is_refused(
        offsets: std::ops::Range<usize>,
        expected_error: CompactProofContractError,
        description: &str,
    ) {
        let offset = offsets.start;
        assert!(
            offset < offsets.end,
            "{description} mutation range is empty"
        );
        let mut hostile = GENERATED_CONTRACT_BYTES.to_vec();
        hostile[offset] ^= 1;
        assert_eq!(
            decode_with_test_authorities(&hostile),
            Err(expected_error),
            "{description} was not load-bearing",
        );
    }

    fn assert_contract_mutation_is_refused(
        hostile: CompactPublicKeyProofContract,
        description: &str,
    ) {
        let bytes = hostile.encode().expect("hostile contract mutation encodes");
        assert!(
            decode_with_test_authorities(&bytes).is_err(),
            "{description} was not load-bearing",
        );
    }

    fn decode_with_test_authorities(
        bytes: &[u8],
    ) -> Result<CompactPublicKeyProofContract, CompactProofContractError> {
        static SELECTED_AUTHORITIES: std::sync::OnceLock<CompactProofContractAuthorities> =
            std::sync::OnceLock::new();
        let authorities = SELECTED_AUTHORITIES.get_or_init(|| {
            CompactProofContractAuthorities::selected()
                .expect("selected compact proof authorities derive")
        });
        CompactPublicKeyProofContract::decode_with_authorities(bytes, authorities)
    }

    fn mutate_query_source_coordinate(
        selection: CompactResponseQuerySelection,
        response_ordinal: u32,
        coordinate: usize,
    ) -> CompactResponseQuerySelection {
        match selection {
            CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                logical_verifier_move_ordinal,
                distinct_query_group_ordinal,
            } => CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                logical_verifier_move_ordinal: if coordinate == 0 {
                    logical_verifier_move_ordinal
                        .checked_sub(1)
                        .filter(|ordinal| *ordinal >= response_ordinal)
                        .unwrap_or_else(|| logical_verifier_move_ordinal.wrapping_add(1))
                } else {
                    logical_verifier_move_ordinal
                },
                distinct_query_group_ordinal: if coordinate == 1 {
                    distinct_query_group_ordinal.wrapping_add(1)
                } else {
                    distinct_query_group_ordinal
                },
            },
            CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                first_logical_verifier_move_ordinal,
                first_distinct_query_group_ordinal,
                second_logical_verifier_move_ordinal,
                second_distinct_query_group_ordinal,
            } => CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                first_logical_verifier_move_ordinal: if coordinate == 0 {
                    first_logical_verifier_move_ordinal
                        .checked_sub(1)
                        .filter(|ordinal| *ordinal >= response_ordinal)
                        .unwrap_or_else(|| {
                            let ordinal = first_logical_verifier_move_ordinal.wrapping_add(1);
                            assert!(ordinal < second_logical_verifier_move_ordinal);
                            ordinal
                        })
                } else {
                    first_logical_verifier_move_ordinal
                },
                first_distinct_query_group_ordinal: if coordinate == 1 {
                    first_distinct_query_group_ordinal.wrapping_add(1)
                } else {
                    first_distinct_query_group_ordinal
                },
                second_logical_verifier_move_ordinal: if coordinate == 2 {
                    second_logical_verifier_move_ordinal.wrapping_add(1)
                } else {
                    second_logical_verifier_move_ordinal
                },
                second_distinct_query_group_ordinal: if coordinate == 3 {
                    second_distinct_query_group_ordinal.wrapping_add(1)
                } else {
                    second_distinct_query_group_ordinal
                },
            },
            CompactResponseQuerySelection::Unqueried | CompactResponseQuerySelection::EveryLeaf => {
                panic!("query source mutation requires a source-bearing selection")
            }
        }
    }

    fn replace_response_component(
        contract: &mut CompactPublicKeyProofContract,
        response_index: usize,
        component_index: usize,
        value_kind: Option<CompactResponseLeafValueKind>,
        query_selection: Option<CompactResponseQuerySelection>,
    ) {
        let response = &contract.response_merkle_geometries[response_index];
        let original = response.components()[component_index];
        let replacement = CompactResponseComponentGeometry::new_with_query_count_range(
            original.first_leaf_ordinal(),
            original.leaf_count(),
            original.minimum_queried_leaf_count(),
            original.maximum_queried_leaf_count(),
            query_selection.unwrap_or(original.query_selection()),
            value_kind.unwrap_or(original.value_kind()),
            original.field_element_count_per_leaf(),
        );
        let mut components = response.components().to_vec();
        components[component_index] = replacement;
        contract.response_merkle_geometries[response_index] = CompactResponseMerkleGeometry::new(
            u32::try_from(response_index).expect("response index fits u32"),
            components,
        )
        .expect("hostile response remains structurally framed");
    }
}
