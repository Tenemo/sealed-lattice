//! Canonical-byte and verifier-consumer correspondence for compact CFW/WHIR.
//!
//! This owner walks the verifier-owned proof and public-input geometries
//! independently of the encoder. It assigns every fixed or bounded canonical
//! region to its decoder, transcript, Merkle, and protocol consumers; assigns
//! every fixed verifier-message candidate region to one decoded challenge
//! consumer; and checks the complete domain-separated SHAKE256 dependency
//! graph. Counted frontier regions remain parameterized by their canonical
//! counts until bytes exist, while their maxima are reconciled exactly here.

use std::collections::BTreeSet;
use std::ops::Range;

use super::cfw_reduction::CfwReductionCatalog;
use super::response_commitment::{
    PackingResponseCommitmentCatalog, ResponseComponentRole, ResponseVectorLedger,
};
use super::transcript_binding::PackingTranscriptBindingLedger;
use super::transcript_chronology::{
    PackingTranscriptChronology, TranscriptEpoch, VerifierMoveRole,
};
use super::uniform_verifier_randomness::PackingUniformVerifierRandomness;
use super::{
    BASE_FIELD_ELEMENT_BYTE_LENGTH, CompactStaticCatalogError, EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
    MERKLE_DIGEST_BYTE_LENGTH, PRIVATE_LEAF_SALT_BYTE_LENGTH,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, checked_add, checked_product,
};
use crate::bgv::proof_suite::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, COMPACT_PROOF_WIRE_MAGIC,
    COMPACT_PUBLIC_INPUT_WIRE_MAGIC, CompactProofResponseWireGeometry, CompactProofWireGeometry,
    CompactPublicInputWireGeometry, FRONTIER_DICTIONARY_REFERENCE_BYTE_LENGTH,
    PROOF_FIXED_HEADER_BYTE_LENGTH, PUBLIC_INPUT_BINDING_COUNT,
    PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH,
};
use crate::bgv::proof_suite::compact_response_merkle::{
    COMPACT_RESPONSE_LEAF_HASH_DOMAIN, COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
    CompactResponseQuerySchedule, CompactResponseQuerySelection,
};
use crate::bgv::proof_suite::compact_transcript::COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN;
use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN, FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN,
    FixedUniformVerifierMessageGeometry,
};
use crate::foundation::Hash512;

const EXTENSION_CANDIDATE_BYTE_LENGTH: u64 = 64;
const BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH: u64 = 8;
const CANONICAL_COUNT_BYTE_LENGTH: u64 = 4;
const RESPONSE_ORDINAL_BYTE_LENGTH: u64 = 4;
const PACKING_FACTOR_BYTE_LENGTH: u64 = 2;
const RESPONSE_COUNT_BYTE_LENGTH: u64 = 4;

const EXPECTED_FIAT_SHAMIR_PREFIX_DOMAIN: &str =
    "sealed-lattice/proof/compact-fiat-shamir-prefix/v1";
const EXPECTED_FIXED_MESSAGE_SEED_DOMAIN: &str =
    "sealed-lattice/proof/fixed-uniform-verifier-message-seed/v1";
const EXPECTED_FIXED_MESSAGE_BLOCK_DOMAIN: &str =
    "sealed-lattice/proof/fixed-uniform-verifier-message-block/v1";
const EXPECTED_RESPONSE_LEAF_DOMAIN: &str = "sealed-lattice/common-proof/compact-response/leaf/v1";
const EXPECTED_RESPONSE_NODE_DOMAIN: &str =
    "sealed-lattice/common-proof/compact-response/merkle-node/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalByteRegion {
    start: u64,
    end: u64,
}

impl CanonicalByteRegion {
    fn append(cursor: &mut u64, byte_length: u64) -> Result<Self, CompactStaticCatalogError> {
        if byte_length == 0 {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let start = *cursor;
        let end = checked_add(start, byte_length)?;
        *cursor = end;
        Ok(Self { start, end })
    }

    const fn byte_length(&self) -> u64 {
        self.end - self.start
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicInputRegionRole {
    Magic,
    PackingFactor,
    SuiteIdentifier,
    ApplicationStatementHash,
    ManifestHash,
    RelationPlanHash,
    RingVectorCount,
    RingDegree,
    FieldElementCount,
    RelationFieldElements,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanonicalRegionConsumer {
    CanonicalDecoder,
    FiatShamirPrefix,
    ApplicationBinding,
    RelationVerifier,
    ResponseMerkleVerifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicInputByteCorrespondence {
    role: PublicInputRegionRole,
    region: CanonicalByteRegion,
    consumers: Vec<CanonicalRegionConsumer>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofHeaderRegionRole {
    Magic,
    PackingFactor,
    ResponseCount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProofHeaderByteCorrespondence {
    role: ProofHeaderRegionRole,
    region: CanonicalByteRegion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofSection {
    PreChallengeWhir,
    CompactRelation,
    StructuredTransposeSource,
    CfwToWhirHandoff,
    MainWhir,
    Padding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComponentFieldKind {
    BaseField,
    ExtensionField,
    Padding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResponseComponentByteCorrespondence {
    role: ResponseComponentRole,
    section: ProofSection,
    component_ordinal: u32,
    first_leaf_ordinal: u64,
    leaf_count: u64,
    queried_leaf_count: u64,
    query_selection: CompactResponseQuerySelection,
    field_kind: ComponentFieldKind,
    value_region: Option<CanonicalByteRegion>,
    value_region_consumers: Vec<CanonicalRegionConsumer>,
    leaf_salt_region: Option<CanonicalByteRegion>,
    leaf_salt_region_consumers: Vec<CanonicalRegionConsumer>,
    consumer_move_ordinal: Option<u32>,
    consumer_roles: Vec<VerifierMoveRole>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResponseMaximumByteCorrespondence {
    response_ordinal: u32,
    vector_commitment_oracle_identifier: u32,
    maximum_proof_start: u64,
    maximum_proof_end: u64,
    ordinal_region: CanonicalByteRegion,
    ordinal_region_consumers: Vec<CanonicalRegionConsumer>,
    root_region: CanonicalByteRegion,
    root_region_consumers: Vec<CanonicalRegionConsumer>,
    round_salt_region: CanonicalByteRegion,
    round_salt_region_consumers: Vec<CanonicalRegionConsumer>,
    components: Vec<ResponseComponentByteCorrespondence>,
    frontier_dictionary_count_region: CanonicalByteRegion,
    frontier_node_count_region: CanonicalByteRegion,
    maximum_frontier_dictionary_region: Option<CanonicalByteRegion>,
    maximum_frontier_reference_region: Option<CanonicalByteRegion>,
    frontier_region_consumers: Vec<CanonicalRegionConsumer>,
    maximum_frontier_node_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateRegionKind {
    ExtensionOutputs,
    BaseFieldOutputs,
    DistinctQueryGroup { group_ordinal: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FixedMessageCandidateByteCorrespondence {
    kind: CandidateRegionKind,
    region: CanonicalByteRegion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DecodedChallengeConsumer {
    role: VerifierMoveRole,
    extension_output_range: Range<u64>,
    base_field_output_range: Range<u64>,
    distinct_query_group_range: Range<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FixedVerifierMessageCorrespondence {
    logical_move_ordinal: u32,
    prefix_response_count: u32,
    exact_message_byte_length: u64,
    seed_hash_query_count: u64,
    block_hash_query_count: u64,
    candidate_regions: Vec<FixedMessageCandidateByteCorrespondence>,
    decoded_consumers: Vec<DecodedChallengeConsumer>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OracleDomainRole {
    FiatShamirPrefix,
    FixedMessageSeed,
    FixedMessageBlock,
    ResponseLeaf,
    ResponseMerkleNode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OracleDomainCorrespondence {
    role: OracleDomainRole,
    domain: &'static str,
    output_bit_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingEmittedByteCorrespondence {
    public_input_regions: Vec<PublicInputByteCorrespondence>,
    proof_header_regions: Vec<ProofHeaderByteCorrespondence>,
    response_layouts: Vec<ResponseMaximumByteCorrespondence>,
    verifier_messages: Vec<FixedVerifierMessageCorrespondence>,
    oracle_domains: Vec<OracleDomainCorrespondence>,
    exact_public_input_byte_length: u64,
    maximum_proof_byte_length: u64,
    distinct_referenced_query_group_count: u64,
    prefix_hash_query_count: u64,
    fixed_message_seed_and_block_hash_query_count: u64,
    total_concrete_fiat_shamir_hash_query_count: u64,
}

impl PackingEmittedByteCorrespondence {
    pub(super) const fn total_concrete_fiat_shamir_hash_query_count(&self) -> u64 {
        self.total_concrete_fiat_shamir_hash_query_count
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn derive(
        chronology: &PackingTranscriptChronology,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
        response_commitments: &PackingResponseCommitmentCatalog,
        proof_geometry: &CompactProofWireGeometry,
        public_input_geometry: CompactPublicInputWireGeometry,
        transcript_binding: &PackingTranscriptBindingLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let correspondence = Self::derive_without_check(
            chronology,
            uniform_verifier_randomness,
            response_commitments,
            proof_geometry,
            public_input_geometry,
            transcript_binding,
            cfw_reduction,
        )?;
        correspondence.check(
            chronology,
            uniform_verifier_randomness,
            response_commitments,
            proof_geometry,
            public_input_geometry,
            transcript_binding,
            cfw_reduction,
        )?;
        Ok(correspondence)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn check(
        &self,
        chronology: &PackingTranscriptChronology,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
        response_commitments: &PackingResponseCommitmentCatalog,
        proof_geometry: &CompactProofWireGeometry,
        public_input_geometry: CompactPublicInputWireGeometry,
        transcript_binding: &PackingTranscriptBindingLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<(), CompactStaticCatalogError> {
        let expected = Self::derive_without_check(
            chronology,
            uniform_verifier_randomness,
            response_commitments,
            proof_geometry,
            public_input_geometry,
            transcript_binding,
            cfw_reduction,
        )?;
        if self != &expected
            || self.public_input_regions.len() != 10
            || self.proof_header_regions.len() != 3
            || self.response_layouts.len() != proof_geometry.responses().len()
            || self.verifier_messages.len() != chronology.verifier_moves().len()
            || self.oracle_domains.len() != 5
            || self.distinct_referenced_query_group_count != chronology.distinct_query_group_count
            || self.prefix_hash_query_count != chronology.logical_verifier_move_count()?
            || self.fixed_message_seed_and_block_hash_query_count
                != uniform_verifier_randomness.concrete_challenge_stream_hash_query_count()
            || self.total_concrete_fiat_shamir_hash_query_count
                != transcript_binding.total_concrete_fiat_shamir_hash_query_count()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_without_check(
        chronology: &PackingTranscriptChronology,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
        response_commitments: &PackingResponseCommitmentCatalog,
        proof_geometry: &CompactProofWireGeometry,
        public_input_geometry: CompactPublicInputWireGeometry,
        transcript_binding: &PackingTranscriptBindingLedger,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        let public_input_regions = derive_public_input_regions(public_input_geometry)?;
        let proof_header_regions = derive_proof_header_regions()?;
        let response_layouts =
            derive_response_layouts(chronology, response_commitments.responses(), proof_geometry)?;
        let verifier_messages = derive_verifier_message_correspondence(
            chronology,
            uniform_verifier_randomness,
            cfw_reduction,
        )?;
        let oracle_domains = derive_oracle_domains()?;

        let merkle_geometries = response_commitments.production_merkle_geometries()?;
        CompactResponseQuerySchedule::validate_registry(
            &merkle_geometries,
            proof_geometry.responses(),
        )
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;

        let distinct_referenced_query_groups = response_commitments
            .responses()
            .iter()
            .flat_map(|response| &response.components)
            .filter_map(|component| match component.query_selection {
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal,
                    distinct_query_group_ordinal,
                } => Some((logical_verifier_move_ordinal, distinct_query_group_ordinal)),
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf => None,
            })
            .collect::<BTreeSet<_>>();
        let distinct_referenced_query_group_count =
            u64::try_from(distinct_referenced_query_groups.len())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;

        let exact_public_input_byte_length =
            u64::try_from(public_input_geometry.exact_canonical_byte_length())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        let maximum_proof_byte_length =
            u64::try_from(proof_geometry.maximum_canonical_byte_length())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
        if public_input_regions
            .last()
            .is_none_or(|region| region.region.end != exact_public_input_byte_length)
            || response_layouts
                .last()
                .is_none_or(|response| response.maximum_proof_end != maximum_proof_byte_length)
            || response_layouts
                .windows(2)
                .any(|pair| pair[0].maximum_proof_end != pair[1].maximum_proof_start)
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        let prefix_hash_query_count = chronology.logical_verifier_move_count()?;
        let fixed_message_seed_and_block_hash_query_count =
            verifier_messages.iter().try_fold(0_u64, |count, message| {
                checked_add(
                    count,
                    checked_add(
                        message.seed_hash_query_count,
                        message.block_hash_query_count,
                    )?,
                )
            })?;
        let total_concrete_fiat_shamir_hash_query_count = checked_add(
            prefix_hash_query_count,
            fixed_message_seed_and_block_hash_query_count,
        )?;
        if fixed_message_seed_and_block_hash_query_count
            != transcript_binding.fixed_message_seed_and_block_hash_query_count()
            || total_concrete_fiat_shamir_hash_query_count
                != transcript_binding.total_concrete_fiat_shamir_hash_query_count()
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }

        Ok(Self {
            public_input_regions,
            proof_header_regions,
            response_layouts,
            verifier_messages,
            oracle_domains,
            exact_public_input_byte_length,
            maximum_proof_byte_length,
            distinct_referenced_query_group_count,
            prefix_hash_query_count,
            fixed_message_seed_and_block_hash_query_count,
            total_concrete_fiat_shamir_hash_query_count,
        })
    }
}

fn derive_public_input_regions(
    geometry: CompactPublicInputWireGeometry,
) -> Result<Vec<PublicInputByteCorrespondence>, CompactStaticCatalogError> {
    if !matches!(geometry.packing_factor(), 1 | 2 | 4 | 8)
        || geometry.ring_vector_count() == 0
        || geometry.ring_degree() == 0
        || geometry.field_element_count()
            != geometry
                .ring_vector_count()
                .checked_mul(geometry.ring_degree())
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let mut cursor = 0_u64;
    let mut regions = Vec::with_capacity(10);
    let mut append = |role, byte_length, consumers| {
        let region = CanonicalByteRegion::append(&mut cursor, byte_length)?;
        regions.push(PublicInputByteCorrespondence {
            role,
            region,
            consumers,
        });
        Ok::<(), CompactStaticCatalogError>(())
    };
    append(
        PublicInputRegionRole::Magic,
        u64::try_from(COMPACT_PUBLIC_INPUT_WIRE_MAGIC.len())
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        vec![
            CanonicalRegionConsumer::CanonicalDecoder,
            CanonicalRegionConsumer::FiatShamirPrefix,
        ],
    )?;
    append(
        PublicInputRegionRole::PackingFactor,
        PACKING_FACTOR_BYTE_LENGTH,
        vec![
            CanonicalRegionConsumer::CanonicalDecoder,
            CanonicalRegionConsumer::FiatShamirPrefix,
        ],
    )?;
    for role in [
        PublicInputRegionRole::SuiteIdentifier,
        PublicInputRegionRole::ApplicationStatementHash,
        PublicInputRegionRole::ManifestHash,
        PublicInputRegionRole::RelationPlanHash,
    ] {
        append(
            role,
            u64::try_from(Hash512::BYTE_LENGTH)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            vec![
                CanonicalRegionConsumer::CanonicalDecoder,
                CanonicalRegionConsumer::ApplicationBinding,
                CanonicalRegionConsumer::FiatShamirPrefix,
            ],
        )?;
    }
    for role in [
        PublicInputRegionRole::RingVectorCount,
        PublicInputRegionRole::RingDegree,
        PublicInputRegionRole::FieldElementCount,
    ] {
        append(
            role,
            CANONICAL_COUNT_BYTE_LENGTH,
            vec![
                CanonicalRegionConsumer::CanonicalDecoder,
                CanonicalRegionConsumer::RelationVerifier,
                CanonicalRegionConsumer::FiatShamirPrefix,
            ],
        )?;
    }
    append(
        PublicInputRegionRole::RelationFieldElements,
        checked_product(&[
            u64::from(geometry.field_element_count()),
            BASE_FIELD_ELEMENT_BYTE_LENGTH,
        ])?,
        vec![
            CanonicalRegionConsumer::CanonicalDecoder,
            CanonicalRegionConsumer::RelationVerifier,
            CanonicalRegionConsumer::FiatShamirPrefix,
        ],
    )?;
    if PUBLIC_INPUT_BINDING_COUNT != 4
        || cursor
            != u64::try_from(geometry.exact_canonical_byte_length())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
        || cursor
            < u64::try_from(PUBLIC_INPUT_FIXED_HEADER_BYTE_LENGTH)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(regions)
}

fn derive_proof_header_regions()
-> Result<Vec<ProofHeaderByteCorrespondence>, CompactStaticCatalogError> {
    let mut cursor = 0_u64;
    let regions = [
        (
            ProofHeaderRegionRole::Magic,
            u64::try_from(COMPACT_PROOF_WIRE_MAGIC.len())
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        ),
        (
            ProofHeaderRegionRole::PackingFactor,
            PACKING_FACTOR_BYTE_LENGTH,
        ),
        (
            ProofHeaderRegionRole::ResponseCount,
            RESPONSE_COUNT_BYTE_LENGTH,
        ),
    ]
    .into_iter()
    .map(|(role, byte_length)| {
        Ok(ProofHeaderByteCorrespondence {
            role,
            region: CanonicalByteRegion::append(&mut cursor, byte_length)?,
        })
    })
    .collect::<Result<Vec<_>, CompactStaticCatalogError>>()?;
    if cursor
        != u64::try_from(PROOF_FIXED_HEADER_BYTE_LENGTH)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(regions)
}

fn derive_response_layouts(
    chronology: &PackingTranscriptChronology,
    responses: &[ResponseVectorLedger],
    proof_geometry: &CompactProofWireGeometry,
) -> Result<Vec<ResponseMaximumByteCorrespondence>, CompactStaticCatalogError> {
    if responses.len() != proof_geometry.responses().len()
        || responses.len() != chronology.verifier_moves().len()
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let mut maximum_proof_cursor = u64::try_from(PROOF_FIXED_HEADER_BYTE_LENGTH)
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    responses
        .iter()
        .zip(proof_geometry.responses())
        .map(|(response, wire_geometry)| {
            derive_response_layout(
                chronology,
                response,
                wire_geometry,
                &mut maximum_proof_cursor,
            )
        })
        .collect()
}

fn derive_response_layout(
    chronology: &PackingTranscriptChronology,
    response: &ResponseVectorLedger,
    wire_geometry: &CompactProofResponseWireGeometry,
    maximum_proof_cursor: &mut u64,
) -> Result<ResponseMaximumByteCorrespondence, CompactStaticCatalogError> {
    let verifier_move = chronology
        .verifier_moves()
        .get(
            usize::try_from(response.ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        )
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    if wire_geometry.ordinal() != response.ordinal
        || verifier_move.ordinal() != response.ordinal
        || verifier_move.roles() != response.verifier_move_roles
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }

    let maximum_proof_start = *maximum_proof_cursor;
    let mut relative_cursor = 0_u64;
    let ordinal_region =
        CanonicalByteRegion::append(&mut relative_cursor, RESPONSE_ORDINAL_BYTE_LENGTH)?;
    let root_region = CanonicalByteRegion::append(
        &mut relative_cursor,
        u64::try_from(Hash512::BYTE_LENGTH)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    )?;
    let round_salt_region = CanonicalByteRegion::append(
        &mut relative_cursor,
        u64::try_from(COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    )?;

    let base_value_byte_length = checked_product(&[
        wire_geometry.queried_base_field_element_count(),
        BASE_FIELD_ELEMENT_BYTE_LENGTH,
    ])?;
    let extension_value_byte_length = checked_product(&[
        wire_geometry.queried_extension_field_element_count(),
        EXTENSION_FIELD_ELEMENT_BYTE_LENGTH,
    ])?;
    let base_value_start = relative_cursor;
    let extension_value_start = checked_add(base_value_start, base_value_byte_length)?;
    let leaf_salt_start = checked_add(extension_value_start, extension_value_byte_length)?;
    let mut base_value_cursor = base_value_start;
    let mut extension_value_cursor = extension_value_start;
    let mut leaf_salt_cursor = leaf_salt_start;
    let mut component_rows = Vec::with_capacity(response.components.len());
    for (component_ordinal, component) in response.components.iter().enumerate() {
        let field_kind = component_field_kind(component.role);
        let value_byte_length = checked_product(&[
            component.queried_leaf_count,
            component.value_byte_length_per_leaf,
        ])?;
        let value_region = if value_byte_length == 0 {
            None
        } else {
            let cursor = match field_kind {
                ComponentFieldKind::BaseField => &mut base_value_cursor,
                ComponentFieldKind::ExtensionField => &mut extension_value_cursor,
                ComponentFieldKind::Padding => {
                    return Err(CompactStaticCatalogError::InvalidGeometry);
                }
            };
            Some(CanonicalByteRegion::append(cursor, value_byte_length)?)
        };
        let leaf_salt_region = if component.queried_leaf_count == 0 {
            None
        } else {
            Some(CanonicalByteRegion::append(
                &mut leaf_salt_cursor,
                checked_product(&[component.queried_leaf_count, PRIVATE_LEAF_SALT_BYTE_LENGTH])?,
            )?)
        };
        let (consumer_move_ordinal, consumer_roles) =
            component_consumer(chronology, response.ordinal, component.query_selection)?;
        component_rows.push(ResponseComponentByteCorrespondence {
            role: component.role,
            section: proof_section(component.role),
            component_ordinal: u32::try_from(component_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            first_leaf_ordinal: component.first_leaf_ordinal,
            leaf_count: component.leaf_count,
            queried_leaf_count: component.queried_leaf_count,
            query_selection: component.query_selection,
            field_kind,
            value_region,
            value_region_consumers: if value_byte_length == 0 {
                Vec::new()
            } else {
                vec![
                    CanonicalRegionConsumer::CanonicalDecoder,
                    CanonicalRegionConsumer::ResponseMerkleVerifier,
                ]
            },
            leaf_salt_region,
            leaf_salt_region_consumers: if component.queried_leaf_count == 0 {
                Vec::new()
            } else {
                vec![
                    CanonicalRegionConsumer::CanonicalDecoder,
                    CanonicalRegionConsumer::ResponseMerkleVerifier,
                ]
            },
            consumer_move_ordinal,
            consumer_roles,
        });
    }
    let expected_leaf_salt_end = checked_add(
        leaf_salt_start,
        checked_product(&[
            wire_geometry.queried_leaf_count(),
            PRIVATE_LEAF_SALT_BYTE_LENGTH,
        ])?,
    )?;
    if base_value_cursor != extension_value_start
        || extension_value_cursor != leaf_salt_start
        || leaf_salt_cursor != expected_leaf_salt_end
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    relative_cursor = leaf_salt_cursor;
    let frontier_dictionary_count_region =
        CanonicalByteRegion::append(&mut relative_cursor, CANONICAL_COUNT_BYTE_LENGTH)?;
    let frontier_node_count_region =
        CanonicalByteRegion::append(&mut relative_cursor, CANONICAL_COUNT_BYTE_LENGTH)?;
    let maximum_frontier_dictionary_region = optional_region(
        &mut relative_cursor,
        checked_product(&[
            wire_geometry.maximum_frontier_node_count(),
            MERKLE_DIGEST_BYTE_LENGTH,
        ])?,
    )?;
    let maximum_frontier_reference_region = optional_region(
        &mut relative_cursor,
        checked_product(&[
            wire_geometry.maximum_frontier_node_count(),
            u64::try_from(FRONTIER_DICTIONARY_REFERENCE_BYTE_LENGTH)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        ])?,
    )?;
    let production_maximum = u64::try_from(
        wire_geometry
            .maximum_canonical_byte_length()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?,
    )
    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    if relative_cursor != production_maximum {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let maximum_proof_end = checked_add(maximum_proof_start, relative_cursor)?;
    *maximum_proof_cursor = maximum_proof_end;
    Ok(ResponseMaximumByteCorrespondence {
        response_ordinal: response.ordinal,
        vector_commitment_oracle_identifier: response.vector_commitment_oracle_identifier,
        maximum_proof_start,
        maximum_proof_end,
        ordinal_region,
        ordinal_region_consumers: vec![
            CanonicalRegionConsumer::CanonicalDecoder,
            CanonicalRegionConsumer::ResponseMerkleVerifier,
        ],
        root_region,
        root_region_consumers: vec![
            CanonicalRegionConsumer::CanonicalDecoder,
            CanonicalRegionConsumer::FiatShamirPrefix,
            CanonicalRegionConsumer::ResponseMerkleVerifier,
        ],
        round_salt_region,
        round_salt_region_consumers: vec![
            CanonicalRegionConsumer::CanonicalDecoder,
            CanonicalRegionConsumer::FiatShamirPrefix,
        ],
        components: component_rows,
        frontier_dictionary_count_region,
        frontier_node_count_region,
        maximum_frontier_dictionary_region,
        maximum_frontier_reference_region,
        frontier_region_consumers: vec![
            CanonicalRegionConsumer::CanonicalDecoder,
            CanonicalRegionConsumer::ResponseMerkleVerifier,
        ],
        maximum_frontier_node_count: wire_geometry.maximum_frontier_node_count(),
    })
}

fn optional_region(
    cursor: &mut u64,
    byte_length: u64,
) -> Result<Option<CanonicalByteRegion>, CompactStaticCatalogError> {
    if byte_length == 0 {
        Ok(None)
    } else {
        CanonicalByteRegion::append(cursor, byte_length).map(Some)
    }
}

const fn component_field_kind(role: ResponseComponentRole) -> ComponentFieldKind {
    match role {
        ResponseComponentRole::PreChallengeSource => ComponentFieldKind::BaseField,
        ResponseComponentRole::Padding => ComponentFieldKind::Padding,
        _ => ComponentFieldKind::ExtensionField,
    }
}

const fn proof_section(role: ResponseComponentRole) -> ProofSection {
    match role {
        ResponseComponentRole::PreChallengeSource => ProofSection::PreChallengeWhir,
        ResponseComponentRole::MainSource => ProofSection::StructuredTransposeSource,
        ResponseComponentRole::CrossEpochOpeningEvaluations
        | ResponseComponentRole::CfwFinalValues => ProofSection::CfwToWhirHandoff,
        ResponseComponentRole::CfwInnerMasks
        | ResponseComponentRole::CfwOuterMasks
        | ResponseComponentRole::CfwAuxiliaryTarget
        | ResponseComponentRole::CfwSumcheckPolynomial { .. }
        | ResponseComponentRole::CfwOuterEvaluations => ProofSection::CompactRelation,
        ResponseComponentRole::WhirSumcheckMask {
            epoch: TranscriptEpoch::PreChallenge,
            ..
        }
        | ResponseComponentRole::WhirSumcheckAuxiliaryTarget {
            epoch: TranscriptEpoch::PreChallenge,
            ..
        }
        | ResponseComponentRole::WhirSumcheckWire {
            epoch: TranscriptEpoch::PreChallenge,
            ..
        }
        | ResponseComponentRole::WhirNextSource {
            epoch: TranscriptEpoch::PreChallenge,
            ..
        }
        | ResponseComponentRole::WhirCodeSwitchMask {
            epoch: TranscriptEpoch::PreChallenge,
            ..
        }
        | ResponseComponentRole::WhirFreshSourceMask {
            epoch: TranscriptEpoch::PreChallenge,
        }
        | ResponseComponentRole::WhirFreshMaskGroup {
            epoch: TranscriptEpoch::PreChallenge,
            ..
        }
        | ResponseComponentRole::WhirBaseMaskedClaim {
            epoch: TranscriptEpoch::PreChallenge,
        }
        | ResponseComponentRole::WhirBlindedSourceMessage {
            epoch: TranscriptEpoch::PreChallenge,
        }
        | ResponseComponentRole::WhirBlindedSourceRandomness {
            epoch: TranscriptEpoch::PreChallenge,
        }
        | ResponseComponentRole::WhirBlindedMaskGroup {
            epoch: TranscriptEpoch::PreChallenge,
            ..
        } => ProofSection::PreChallengeWhir,
        ResponseComponentRole::WhirSumcheckMask {
            epoch: TranscriptEpoch::Main,
            ..
        }
        | ResponseComponentRole::WhirSumcheckAuxiliaryTarget {
            epoch: TranscriptEpoch::Main,
            ..
        }
        | ResponseComponentRole::WhirSumcheckWire {
            epoch: TranscriptEpoch::Main,
            ..
        }
        | ResponseComponentRole::WhirNextSource {
            epoch: TranscriptEpoch::Main,
            ..
        }
        | ResponseComponentRole::WhirCodeSwitchMask {
            epoch: TranscriptEpoch::Main,
            ..
        }
        | ResponseComponentRole::WhirFreshSourceMask {
            epoch: TranscriptEpoch::Main,
        }
        | ResponseComponentRole::WhirFreshMaskGroup {
            epoch: TranscriptEpoch::Main,
            ..
        }
        | ResponseComponentRole::WhirBaseMaskedClaim {
            epoch: TranscriptEpoch::Main,
        }
        | ResponseComponentRole::WhirBlindedSourceMessage {
            epoch: TranscriptEpoch::Main,
        }
        | ResponseComponentRole::WhirBlindedSourceRandomness {
            epoch: TranscriptEpoch::Main,
        }
        | ResponseComponentRole::WhirBlindedMaskGroup {
            epoch: TranscriptEpoch::Main,
            ..
        } => ProofSection::MainWhir,
        ResponseComponentRole::Padding => ProofSection::Padding,
    }
}

fn component_consumer(
    chronology: &PackingTranscriptChronology,
    response_ordinal: u32,
    query_selection: CompactResponseQuerySelection,
) -> Result<(Option<u32>, Vec<VerifierMoveRole>), CompactStaticCatalogError> {
    let logical_move_ordinal = match query_selection {
        CompactResponseQuerySelection::Unqueried => return Ok((None, Vec::new())),
        CompactResponseQuerySelection::EveryLeaf => response_ordinal,
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal,
            ..
        } => logical_verifier_move_ordinal,
    };
    let verifier_move = chronology
        .verifier_moves()
        .get(
            usize::try_from(logical_move_ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
        )
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let consumer_roles = match query_selection {
        CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. } => {
            let roles = verifier_move
                .roles()
                .iter()
                .copied()
                .filter(|role| {
                    matches!(
                        role,
                        VerifierMoveRole::WhirRoundQueryAndCombination { .. }
                            | VerifierMoveRole::WhirFinalQueries { .. }
                    )
                })
                .collect::<Vec<_>>();
            if roles.len() != 1 {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            roles
        }
        CompactResponseQuerySelection::EveryLeaf => verifier_move.roles().to_vec(),
        CompactResponseQuerySelection::Unqueried => unreachable!(),
    };
    Ok((Some(logical_move_ordinal), consumer_roles))
}

fn derive_verifier_message_correspondence(
    chronology: &PackingTranscriptChronology,
    uniform_verifier_randomness: &PackingUniformVerifierRandomness,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<Vec<FixedVerifierMessageCorrespondence>, CompactStaticCatalogError> {
    if chronology.verifier_moves().len() != uniform_verifier_randomness.move_count() {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    chronology
        .verifier_moves()
        .iter()
        .enumerate()
        .map(|(move_index, verifier_move)| {
            let geometry = uniform_verifier_randomness.fixed_message_geometry(move_index)?;
            derive_verifier_message(
                verifier_move.ordinal(),
                verifier_move.roles(),
                &geometry,
                cfw_reduction,
            )
        })
        .collect()
}

fn derive_verifier_message(
    logical_move_ordinal: u32,
    roles: &[VerifierMoveRole],
    geometry: &FixedUniformVerifierMessageGeometry,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<FixedVerifierMessageCorrespondence, CompactStaticCatalogError> {
    let draw_count = u64::from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT);
    let mut cursor = 0_u64;
    let mut candidate_regions = Vec::new();
    let extension_candidate_byte_length = checked_product(&[
        geometry.extension_output_count(),
        draw_count,
        EXTENSION_CANDIDATE_BYTE_LENGTH,
    ])?;
    if let Some(region) = optional_region(&mut cursor, extension_candidate_byte_length)? {
        candidate_regions.push(FixedMessageCandidateByteCorrespondence {
            kind: CandidateRegionKind::ExtensionOutputs,
            region,
        });
    }
    let base_candidate_byte_length = checked_product(&[
        geometry.base_field_output_count(),
        draw_count,
        BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH,
    ])?;
    if let Some(region) = optional_region(&mut cursor, base_candidate_byte_length)? {
        candidate_regions.push(FixedMessageCandidateByteCorrespondence {
            kind: CandidateRegionKind::BaseFieldOutputs,
            region,
        });
    }
    for (group_ordinal, group) in geometry.distinct_query_groups().iter().enumerate() {
        candidate_regions.push(FixedMessageCandidateByteCorrespondence {
            kind: CandidateRegionKind::DistinctQueryGroup {
                group_ordinal: u32::try_from(group_ordinal)
                    .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
            },
            region: CanonicalByteRegion::append(
                &mut cursor,
                checked_product(&[
                    group.query_count(),
                    draw_count,
                    BASE_OR_QUERY_CANDIDATE_BYTE_LENGTH,
                ])?,
            )?,
        });
    }
    let exact_message_byte_length = geometry
        .exact_message_byte_length_u64()
        .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?;
    if cursor != exact_message_byte_length {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let decoded_consumers = derive_decoded_challenge_consumers(roles, geometry, cfw_reduction)?;
    check_decoded_challenge_consumer_partition(geometry, &decoded_consumers)?;
    let block_hash_query_count = exact_message_byte_length.div_ceil(
        u64::try_from(Hash512::BYTE_LENGTH)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
    );
    if checked_add(1, block_hash_query_count)?
        != geometry
            .concrete_hash_query_count()
            .map_err(|_| CompactStaticCatalogError::InvalidGeometry)?
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(FixedVerifierMessageCorrespondence {
        logical_move_ordinal,
        prefix_response_count: logical_move_ordinal
            .checked_add(1)
            .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?,
        exact_message_byte_length,
        seed_hash_query_count: 1,
        block_hash_query_count,
        candidate_regions,
        decoded_consumers,
    })
}

fn derive_decoded_challenge_consumers(
    roles: &[VerifierMoveRole],
    geometry: &FixedUniformVerifierMessageGeometry,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<Vec<DecodedChallengeConsumer>, CompactStaticCatalogError> {
    let extension_count = geometry.extension_output_count();
    let base_count = geometry.base_field_output_count();
    let group_count = u64::try_from(geometry.distinct_query_groups().len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    match roles {
        [role] => Ok(vec![DecodedChallengeConsumer {
            role: *role,
            extension_output_range: 0..extension_count,
            base_field_output_range: 0..base_count,
            distinct_query_group_range: 0..group_count,
        }]),
        [
            VerifierMoveRole::CfwJointConstraint,
            opening_role @ VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::PreChallenge,
            },
        ] => {
            let joint_count = u64::from(cfw_reduction.joint_constraint_randomness_element_count());
            if extension_count != checked_add(joint_count, 1)?
                || base_count != 0
                || group_count != 0
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            Ok(vec![
                DecodedChallengeConsumer {
                    role: VerifierMoveRole::CfwJointConstraint,
                    extension_output_range: 0..joint_count,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..0,
                },
                DecodedChallengeConsumer {
                    role: *opening_role,
                    extension_output_range: joint_count..extension_count,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..0,
                },
            ])
        }
        [
            final_query_role @ VerifierMoveRole::WhirFinalQueries {
                epoch: TranscriptEpoch::PreChallenge,
            },
            opening_role @ VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::Main,
            },
        ] => {
            if extension_count != 1 || base_count != 0 || group_count == 0 {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            Ok(vec![
                DecodedChallengeConsumer {
                    role: *final_query_role,
                    extension_output_range: 0..0,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..group_count,
                },
                DecodedChallengeConsumer {
                    role: *opening_role,
                    extension_output_range: 0..1,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..0,
                },
            ])
        }
        _ => Err(CompactStaticCatalogError::InvalidGeometry),
    }
}

fn check_decoded_challenge_consumer_partition(
    geometry: &FixedUniformVerifierMessageGeometry,
    consumers: &[DecodedChallengeConsumer],
) -> Result<(), CompactStaticCatalogError> {
    let group_count = u64::try_from(geometry.distinct_query_groups().len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    check_exact_range_partition(
        geometry.extension_output_count(),
        consumers
            .iter()
            .map(|consumer| &consumer.extension_output_range),
    )?;
    check_exact_range_partition(
        geometry.base_field_output_count(),
        consumers
            .iter()
            .map(|consumer| &consumer.base_field_output_range),
    )?;
    check_exact_range_partition(
        group_count,
        consumers
            .iter()
            .map(|consumer| &consumer.distinct_query_group_range),
    )
}

fn check_exact_range_partition<'range>(
    element_count: u64,
    ranges: impl Iterator<Item = &'range Range<u64>>,
) -> Result<(), CompactStaticCatalogError> {
    let element_count_usize = usize::try_from(element_count)
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    let mut coverage = vec![0_u8; element_count_usize];
    for range in ranges {
        if range.start > range.end || range.end > element_count {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        for ordinal in range.clone() {
            let index = usize::try_from(ordinal)
                .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
            coverage[index] = coverage[index]
                .checked_add(1)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        }
    }
    if coverage.iter().any(|count| *count != 1) {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn derive_oracle_domains() -> Result<Vec<OracleDomainCorrespondence>, CompactStaticCatalogError> {
    let specifications = [
        (
            OracleDomainRole::FiatShamirPrefix,
            COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
            EXPECTED_FIAT_SHAMIR_PREFIX_DOMAIN,
        ),
        (
            OracleDomainRole::FixedMessageSeed,
            FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN,
            EXPECTED_FIXED_MESSAGE_SEED_DOMAIN,
        ),
        (
            OracleDomainRole::FixedMessageBlock,
            FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN,
            EXPECTED_FIXED_MESSAGE_BLOCK_DOMAIN,
        ),
        (
            OracleDomainRole::ResponseLeaf,
            COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
            EXPECTED_RESPONSE_LEAF_DOMAIN,
        ),
        (
            OracleDomainRole::ResponseMerkleNode,
            COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
            EXPECTED_RESPONSE_NODE_DOMAIN,
        ),
    ];
    if specifications
        .iter()
        .any(|(_, production, expected)| production != expected || production.is_empty())
        || specifications
            .iter()
            .enumerate()
            .any(|(left_index, (_, left, _))| {
                specifications
                    .iter()
                    .skip(left_index + 1)
                    .any(|(_, right, _)| left == right)
            })
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(specifications
        .into_iter()
        .map(|(role, domain, _)| OracleDomainCorrespondence {
            role,
            domain,
            output_bit_length: 512,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::bgv::proof_suite::compact_proof_wire::{
        CompactProofResponseWireInput, CompactProofWireError, CompactProofWireInput,
        CompactPublicInputBindings, decode_compact_proof_wire, decode_compact_public_input,
        encode_compact_proof_wire, encode_compact_public_input,
    };
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;
    use crate::bgv::proof_suite::compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValue, CompactResponseLeafValueKind,
        CompactResponseMerkleError, CompactResponseMerkleGeometry, compact_response_leaf_digest,
        compact_response_merkle_parent_digest, verify_decoded_compact_response_opening,
    };
    use crate::bgv::proof_suite::compact_transcript::{
        CompactProverTranscript, derive_compact_fiat_shamir_verifier_message,
    };
    use crate::bgv::proof_suite::field::ProofBaseFieldElement;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        DecodedFixedUniformVerifierMessage, FixedUniformDistinctQueryGeometry,
    };
    use crate::bgv::proof_suite::merkle::{
        maximum_minimal_frontier_node_count, minimal_frontier_coordinates,
    };

    type Digest = [u8; Hash512::BYTE_LENGTH];
    type LeafSalt = [u8; PRIVATE_LEAF_SALT_BYTE_LENGTH as usize];

    struct SmallTransportedOpening {
        proof_geometry: CompactProofWireGeometry,
        merkle_geometry: CompactResponseMerkleGeometry,
        public_input_geometry: CompactPublicInputWireGeometry,
        public_input_bindings: CompactPublicInputBindings,
        canonical_public_input_bytes: Vec<u8>,
        canonical_proof_bytes: Vec<u8>,
        prover_verifier_message: DecodedFixedUniformVerifierMessage,
        query_leaf_ordinals: Vec<u64>,
    }

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("small canonical base-field value")
    }

    fn build_small_tree(
        geometry: &CompactResponseMerkleGeometry,
        leaf_values: &[ProofBaseFieldElement],
        leaf_salts: &[LeafSalt],
    ) -> Vec<Vec<Digest>> {
        let leaves = leaf_values
            .iter()
            .zip(leaf_salts)
            .enumerate()
            .map(|(leaf_ordinal, (value, salt))| {
                compact_response_leaf_digest(
                    geometry,
                    u64::try_from(leaf_ordinal).expect("small leaf ordinal"),
                    CompactResponseLeafValue::BaseField(std::slice::from_ref(value)),
                    salt,
                )
                .expect("small canonical response leaf")
            })
            .collect::<Vec<_>>();
        let mut levels = vec![leaves];
        while levels.last().expect("tree level").len() > 1 {
            let parent_level = u32::try_from(levels.len()).expect("small parent level");
            let parents = levels
                .last()
                .expect("tree level")
                .chunks_exact(2)
                .enumerate()
                .map(|(parent_ordinal, children)| {
                    compact_response_merkle_parent_digest(
                        geometry,
                        parent_level,
                        u64::try_from(parent_ordinal * 2).expect("small child ordinal"),
                        children[0],
                        children[1],
                    )
                    .expect("small canonical response parent")
                })
                .collect();
            levels.push(parents);
        }
        levels
    }

    fn small_frontier(levels: &[Vec<Digest>], query_leaf_ordinals: &[u64]) -> Vec<Digest> {
        minimal_frontier_coordinates(query_leaf_ordinals, levels[0].len())
            .expect("small minimal frontier")
            .into_iter()
            .map(|(level, node_ordinal)| {
                levels[usize::try_from(level).expect("small level")]
                    [usize::try_from(node_ordinal).expect("small node ordinal")]
            })
            .collect()
    }

    fn small_transported_opening() -> SmallTransportedOpening {
        let verifier_message_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(8, 3)],
        )
        .expect("small verifier-message geometry");
        let merkle_geometry = CompactResponseMerkleGeometry::new(
            0,
            vec![CompactResponseComponentGeometry::new(
                0,
                8,
                3,
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal: 0,
                    distinct_query_group_ordinal: 0,
                },
                CompactResponseLeafValueKind::BaseField,
                1,
            )],
        )
        .expect("small response Merkle geometry");
        let maximum_frontier_node_count = u64::try_from(
            maximum_minimal_frontier_node_count(8, 3).expect("small frontier ceiling"),
        )
        .expect("small frontier ceiling fits u64");
        let response_wire_geometry = CompactProofResponseWireGeometry::new(
            0,
            3,
            0,
            3,
            maximum_frontier_node_count,
            verifier_message_geometry,
        )
        .expect("small response wire geometry");
        let proof_geometry = CompactProofWireGeometry::new(1, vec![response_wire_geometry])
            .expect("small proof wire geometry");
        CompactResponseQuerySchedule::validate_registry(
            std::slice::from_ref(&merkle_geometry),
            proof_geometry.responses(),
        )
        .expect("small query registry");

        let public_input_geometry =
            CompactPublicInputWireGeometry::new(1, 1, 2).expect("small public-input geometry");
        let public_input_bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x44; Hash512::BYTE_LENGTH]),
        );
        let canonical_public_input_bytes = encode_compact_public_input(
            public_input_geometry,
            public_input_bindings,
            &[base(3), base(5)],
        )
        .expect("small canonical public input");
        let decoded_public_input = decode_compact_public_input(
            public_input_geometry,
            public_input_bindings,
            &canonical_public_input_bytes,
        )
        .expect("small decoded public input");

        let leaf_values = (0_u64..8)
            .map(|ordinal| base(11 + ordinal))
            .collect::<Vec<_>>();
        let leaf_salts = (0_u8..8)
            .map(|ordinal| [ordinal + 1; PRIVATE_LEAF_SALT_BYTE_LENGTH as usize])
            .collect::<Vec<_>>();
        let tree = build_small_tree(&merkle_geometry, &leaf_values, &leaf_salts);
        let root = tree.last().expect("root level")[0];
        let round_salt = [0x5a; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH];
        let mut prover_transcript = CompactProverTranscript::new(
            &proof_geometry,
            &decoded_public_input,
            &canonical_public_input_bytes,
        )
        .expect("small prover transcript");
        prover_transcript
            .record_response_commitment(root, round_salt)
            .expect("small response commitment");
        let prover_verifier_message = prover_transcript
            .derive_verifier_message()
            .expect("live verifier message");
        prover_transcript
            .finish()
            .expect("complete small transcript");
        let query_schedule = CompactResponseQuerySchedule::derive(
            &merkle_geometry,
            proof_geometry.responses(),
            std::slice::from_ref(&prover_verifier_message),
        )
        .expect("live transcript-derived query schedule");
        let query_leaf_ordinals = query_schedule.as_slice().to_vec();
        let opened_values = query_leaf_ordinals
            .iter()
            .map(|ordinal| leaf_values[usize::try_from(*ordinal).expect("small query ordinal")])
            .collect();
        let opened_salts = query_leaf_ordinals
            .iter()
            .map(|ordinal| leaf_salts[usize::try_from(*ordinal).expect("small query ordinal")])
            .collect();
        let frontier = small_frontier(&tree, &query_leaf_ordinals);
        let canonical_proof_bytes = encode_compact_proof_wire(
            &proof_geometry,
            &CompactProofWireInput::new(vec![CompactProofResponseWireInput::new(
                root,
                round_salt,
                opened_values,
                Vec::new(),
                opened_salts,
                frontier,
            )]),
        )
        .expect("small canonical proof");

        SmallTransportedOpening {
            proof_geometry,
            merkle_geometry,
            public_input_geometry,
            public_input_bindings,
            canonical_public_input_bytes,
            canonical_proof_bytes,
            prover_verifier_message,
            query_leaf_ordinals,
        }
    }

    #[test]
    fn every_factor_maps_all_canonical_regions_and_challenge_consumers() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let expected_response_counts = [82, 80, 78, 76];
        let expected_proof_byte_lengths = [26_436_090, 25_518_898, 24_815_706, 24_871_730];
        let expected_hash_query_counts = [181_604, 183_360, 179_548, 183_288];
        for (factor_ordinal, factor) in catalog.factor_catalogs.iter().enumerate() {
            let correspondence = &factor.emitted_byte_correspondence;
            assert_eq!(
                correspondence.response_layouts.len(),
                expected_response_counts[factor_ordinal]
            );
            assert_eq!(
                correspondence.maximum_proof_byte_length,
                expected_proof_byte_lengths[factor_ordinal]
            );
            assert_eq!(correspondence.distinct_referenced_query_group_count, 26);
            assert_eq!(
                correspondence.total_concrete_fiat_shamir_hash_query_count,
                expected_hash_query_counts[factor_ordinal]
            );
            assert!(correspondence.response_layouts.iter().all(|response| {
                response.root_region.byte_length() == Hash512::BYTE_LENGTH as u64
                    && response.round_salt_region.byte_length()
                        == COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH as u64
                    && response.root_region_consumers
                        == [
                            CanonicalRegionConsumer::CanonicalDecoder,
                            CanonicalRegionConsumer::FiatShamirPrefix,
                            CanonicalRegionConsumer::ResponseMerkleVerifier,
                        ]
                    && response.round_salt_region_consumers
                        == [
                            CanonicalRegionConsumer::CanonicalDecoder,
                            CanonicalRegionConsumer::FiatShamirPrefix,
                        ]
                    && response.frontier_region_consumers
                        == [
                            CanonicalRegionConsumer::CanonicalDecoder,
                            CanonicalRegionConsumer::ResponseMerkleVerifier,
                        ]
                    && !response.components.is_empty()
                    && response.components.iter().all(|component| {
                        component.value_region.is_some()
                            == !component.value_region_consumers.is_empty()
                            && component.leaf_salt_region.is_some()
                                == !component.leaf_salt_region_consumers.is_empty()
                    })
            }));
            assert!(correspondence.public_input_regions.iter().all(|region| {
                region
                    .consumers
                    .contains(&CanonicalRegionConsumer::FiatShamirPrefix)
            }));
            assert!(correspondence.verifier_messages.iter().all(|message| {
                message.prefix_response_count == message.logical_move_ordinal + 1
                    && message.seed_hash_query_count == 1
                    && message.block_hash_query_count > 0
                    && !message.candidate_regions.is_empty()
                    && !message.decoded_consumers.is_empty()
            }));
        }
    }

    #[test]
    fn live_transcript_small_geometry_matches_transport_bytes_and_fresh_verification() {
        let fixture = small_transported_opening();
        let decoded_public_input = decode_compact_public_input(
            fixture.public_input_geometry,
            fixture.public_input_bindings,
            &fixture.canonical_public_input_bytes,
        )
        .expect("fresh transported public input");
        let decoded_proof = decode_compact_proof_wire(
            &fixture.proof_geometry,
            &fixture.canonical_proof_bytes,
            fixture.canonical_proof_bytes.len(),
        )
        .expect("fresh transported proof");
        let verifier_message = derive_compact_fiat_shamir_verifier_message(
            &fixture.proof_geometry,
            &decoded_proof,
            &fixture.canonical_proof_bytes,
            &decoded_public_input,
            &fixture.canonical_public_input_bytes,
            0,
        )
        .expect("fresh verifier message from transported bytes");
        assert_eq!(verifier_message, fixture.prover_verifier_message);
        let query_schedule = CompactResponseQuerySchedule::derive(
            &fixture.merkle_geometry,
            fixture.proof_geometry.responses(),
            std::slice::from_ref(&verifier_message),
        )
        .expect("fresh query schedule from transported bytes");
        assert_eq!(query_schedule.as_slice(), fixture.query_leaf_ordinals);
        assert_eq!(
            verify_decoded_compact_response_opening(
                &fixture.merkle_geometry,
                &fixture.proof_geometry.responses()[0],
                &decoded_proof.responses()[0],
                &fixture.canonical_proof_bytes,
                query_schedule.as_slice(),
            ),
            Ok(())
        );

        let response_start = PROOF_FIXED_HEADER_BYTE_LENGTH;
        let root_start = response_start + RESPONSE_ORDINAL_BYTE_LENGTH as usize;
        let round_salt_start = root_start + Hash512::BYTE_LENGTH;
        let base_values_start = round_salt_start + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
        let leaf_salts_start = base_values_start + 3 * BASE_FIELD_ELEMENT_BYTE_LENGTH as usize;
        let frontier_counts_start = leaf_salts_start + 3 * PRIVATE_LEAF_SALT_BYTE_LENGTH as usize;
        let frontier_dictionary_count = u32::from_le_bytes(
            fixture.canonical_proof_bytes
                [frontier_counts_start..frontier_counts_start + size_of::<u32>()]
                .try_into()
                .expect("frontier dictionary count bytes"),
        ) as usize;
        let frontier_node_count = u32::from_le_bytes(
            fixture.canonical_proof_bytes[frontier_counts_start + size_of::<u32>()
                ..frontier_counts_start + 2 * size_of::<u32>()]
                .try_into()
                .expect("frontier node count bytes"),
        ) as usize;
        let exact_proof_end = frontier_counts_start
            + 2 * size_of::<u32>()
            + frontier_dictionary_count * Hash512::BYTE_LENGTH
            + frontier_node_count * FRONTIER_DICTIONARY_REFERENCE_BYTE_LENGTH;
        assert_eq!(exact_proof_end, fixture.canonical_proof_bytes.len());
        assert_eq!(
            &fixture.canonical_proof_bytes[..COMPACT_PROOF_WIRE_MAGIC.len()],
            &COMPACT_PROOF_WIRE_MAGIC
        );
        assert_eq!(
            &fixture.canonical_public_input_bytes[..COMPACT_PUBLIC_INPUT_WIRE_MAGIC.len()],
            &COMPACT_PUBLIC_INPUT_WIRE_MAGIC
        );
        assert_eq!(
            fixture.canonical_public_input_bytes.len(),
            fixture.public_input_geometry.exact_canonical_byte_length()
        );
    }

    #[test]
    fn live_transcript_small_geometry_refuses_bound_section_and_structure_mutations() {
        let fixture = small_transported_opening();
        let decoded_public_input = decode_compact_public_input(
            fixture.public_input_geometry,
            fixture.public_input_bindings,
            &fixture.canonical_public_input_bytes,
        )
        .expect("fresh transported public input");
        let response_start = PROOF_FIXED_HEADER_BYTE_LENGTH;
        let root_start = response_start + RESPONSE_ORDINAL_BYTE_LENGTH as usize;
        let round_salt_start = root_start + Hash512::BYTE_LENGTH;
        let base_values_start = round_salt_start + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
        let leaf_salts_start = base_values_start + 3 * BASE_FIELD_ELEMENT_BYTE_LENGTH as usize;
        let frontier_counts_start = leaf_salts_start + 3 * PRIVATE_LEAF_SALT_BYTE_LENGTH as usize;
        let frontier_dictionary_start = frontier_counts_start + 2 * size_of::<u32>();

        for mutation_offset in [root_start, base_values_start, leaf_salts_start] {
            let mut mutated_proof = fixture.canonical_proof_bytes.clone();
            mutated_proof[mutation_offset] ^= 1;
            let decoded_proof = decode_compact_proof_wire(
                &fixture.proof_geometry,
                &mutated_proof,
                mutated_proof.len(),
            )
            .expect("canonical bound-section mutation");
            let verifier_message = derive_compact_fiat_shamir_verifier_message(
                &fixture.proof_geometry,
                &decoded_proof,
                &mutated_proof,
                &decoded_public_input,
                &fixture.canonical_public_input_bytes,
                0,
            )
            .expect("mutated verifier message");
            let query_schedule = CompactResponseQuerySchedule::derive(
                &fixture.merkle_geometry,
                fixture.proof_geometry.responses(),
                std::slice::from_ref(&verifier_message),
            )
            .expect("mutated query schedule");
            assert!(matches!(
                verify_decoded_compact_response_opening(
                    &fixture.merkle_geometry,
                    &fixture.proof_geometry.responses()[0],
                    &decoded_proof.responses()[0],
                    &mutated_proof,
                    query_schedule.as_slice(),
                ),
                Err(CompactResponseMerkleError::RootMismatch
                    | CompactResponseMerkleError::WrongFrontierLength)
            ));
        }

        let mut round_salt_mutation = fixture.canonical_proof_bytes.clone();
        round_salt_mutation[round_salt_start] ^= 1;
        let decoded_round_salt_mutation = decode_compact_proof_wire(
            &fixture.proof_geometry,
            &round_salt_mutation,
            round_salt_mutation.len(),
        )
        .expect("canonical round-salt mutation");
        let changed_verifier_message = derive_compact_fiat_shamir_verifier_message(
            &fixture.proof_geometry,
            &decoded_round_salt_mutation,
            &round_salt_mutation,
            &decoded_public_input,
            &fixture.canonical_public_input_bytes,
            0,
        )
        .expect("round-salt-mutated verifier message");
        assert_ne!(changed_verifier_message, fixture.prover_verifier_message);
        let changed_query_schedule = CompactResponseQuerySchedule::derive(
            &fixture.merkle_geometry,
            fixture.proof_geometry.responses(),
            std::slice::from_ref(&changed_verifier_message),
        )
        .expect("round-salt-mutated query schedule");
        assert_ne!(
            changed_query_schedule.as_slice(),
            fixture.query_leaf_ordinals
        );
        assert!(matches!(
            verify_decoded_compact_response_opening(
                &fixture.merkle_geometry,
                &fixture.proof_geometry.responses()[0],
                &decoded_round_salt_mutation.responses()[0],
                &round_salt_mutation,
                changed_query_schedule.as_slice(),
            ),
            Err(CompactResponseMerkleError::RootMismatch
                | CompactResponseMerkleError::WrongFrontierLength)
        ));

        let mut frontier_mutation = fixture.canonical_proof_bytes.clone();
        frontier_mutation[frontier_dictionary_start] ^= 1;
        match decode_compact_proof_wire(
            &fixture.proof_geometry,
            &frontier_mutation,
            frontier_mutation.len(),
        ) {
            Ok(decoded_frontier_mutation) => assert_eq!(
                verify_decoded_compact_response_opening(
                    &fixture.merkle_geometry,
                    &fixture.proof_geometry.responses()[0],
                    &decoded_frontier_mutation.responses()[0],
                    &frontier_mutation,
                    &fixture.query_leaf_ordinals,
                ),
                Err(CompactResponseMerkleError::RootMismatch)
            ),
            Err(CompactProofWireError::DuplicateOrUnsortedFrontierDictionary) => {}
            Err(error) => panic!("unexpected frontier mutation refusal: {error:?}"),
        }

        assert_eq!(
            decode_compact_proof_wire(
                &fixture.proof_geometry,
                &fixture.canonical_proof_bytes[..fixture.canonical_proof_bytes.len() - 1],
                fixture.canonical_proof_bytes.len() - 1,
            ),
            Err(CompactProofWireError::Truncated)
        );
        let mut reordered_response = fixture.canonical_proof_bytes.clone();
        reordered_response[response_start..response_start + size_of::<u32>()]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            decode_compact_proof_wire(
                &fixture.proof_geometry,
                &reordered_response,
                reordered_response.len(),
            ),
            Err(CompactProofWireError::WrongResponseOrdinal)
        );
        let mut noncanonical_value = fixture.canonical_proof_bytes.clone();
        noncanonical_value[base_values_start..base_values_start + size_of::<u64>()]
            .copy_from_slice(
                &crate::bgv::proof_suite::field::PROOF_BASE_FIELD_MODULUS.to_le_bytes(),
            );
        assert_eq!(
            decode_compact_proof_wire(
                &fixture.proof_geometry,
                &noncanonical_value,
                noncanonical_value.len(),
            ),
            Err(CompactProofWireError::NonCanonicalBaseFieldElement)
        );

        let mut wrong_binding = fixture.canonical_public_input_bytes.clone();
        wrong_binding
            [COMPACT_PUBLIC_INPUT_WIRE_MAGIC.len() + PACKING_FACTOR_BYTE_LENGTH as usize] ^= 1;
        assert_eq!(
            decode_compact_public_input(
                fixture.public_input_geometry,
                fixture.public_input_bindings,
                &wrong_binding,
            ),
            Err(CompactProofWireError::WrongPublicInputBinding)
        );
        assert_eq!(
            decode_compact_public_input(
                fixture.public_input_geometry,
                fixture.public_input_bindings,
                &fixture.canonical_public_input_bytes
                    [..fixture.canonical_public_input_bytes.len() - 1],
            ),
            Err(CompactProofWireError::Truncated)
        );
        let mut trailing_public_input = fixture.canonical_public_input_bytes.clone();
        trailing_public_input.push(0);
        assert_eq!(
            decode_compact_public_input(
                fixture.public_input_geometry,
                fixture.public_input_bindings,
                &trailing_public_input,
            ),
            Err(CompactProofWireError::TrailingBytes)
        );
    }

    #[test]
    fn correspondence_rejects_a_reassigned_component_consumer() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let factor = &catalog.factor_catalogs[0];
        let mut correspondence = factor.emitted_byte_correspondence.clone();
        let component = correspondence.response_layouts[0]
            .components
            .iter_mut()
            .find(|component| component.consumer_move_ordinal.is_some())
            .expect("the first response has a queried component");
        component.consumer_move_ordinal = Some(
            component
                .consumer_move_ordinal
                .expect("queried component consumer")
                .checked_add(1)
                .expect("small consumer ordinal"),
        );
        assert_eq!(
            correspondence.check(
                &factor.transcript_chronology,
                &factor.uniform_verifier_randomness,
                &factor.response_commitments,
                &factor.proof_wire_geometry,
                factor.public_input_wire_geometry,
                &factor.transcript_binding,
                &catalog.cfw_reduction,
            ),
            Err(CompactStaticCatalogError::InvalidGeometry)
        );
    }
}
