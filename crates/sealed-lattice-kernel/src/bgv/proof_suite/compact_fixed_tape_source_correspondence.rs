//! Independent source correspondence for compact verifier randomness.
//!
//! Every selected logical verifier move is one direct fixed-width SHAKE256
//! answer over the complete canonical transcript prefix and the complete
//! compiler-derived proof geometry. This module reconstructs that preimage and
//! answer independently from the production transcript implementation. The
//! result is development evidence only: it neither equates fixed SHAKE256 with
//! an ideal oracle nor authorizes proof acceptance.

use std::mem::size_of;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::compact_emitted_cdhz::{CompactEmittedCdhzMeasurement, CompactSharedHashGraphCensus};
use super::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, COMPACT_PACKING_FACTOR, CompactProofWireGeometry,
    DecodedCompactProofWire,
};
use super::compact_transcript::{
    COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_DOMAIN, COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_VERSION,
    compact_fiat_shamir_round_verifier_message_answer_prefix,
    materialize_compact_fiat_shamir_verifier_message,
};
use super::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION, FixedUniformVerifierMessageGeometry,
    decode_fixed_uniform_verifier_message,
};
use super::{
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, SourceVerifiedCompactPublicKeyProof,
};
use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalItemType,
    Hash512,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactFixedTapeSourceCorrespondenceError {
    ArithmeticOverflow,
    CanonicalFraming {
        round_ordinal: u32,
    },
    Contract,
    Geometry {
        round_ordinal: u32,
    },
    AnswerPrefixMismatch {
        round_ordinal: u32,
    },
    OutputMismatch {
        round_ordinal: u32,
        first_divergent_byte_offset: u64,
    },
    DecodedMessageMismatch {
        round_ordinal: u32,
    },
    HostileFaultUndetected {
        round_ordinal: u32,
        fault_category: &'static str,
    },
    MeasurementMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFixedTapeRoundSourceCorrespondence {
    pub(crate) round_ordinal: u32,
    pub(crate) verifier_message_answer_prefix: [u8; Hash512::BYTE_LENGTH],
    pub(crate) input_byte_length: u64,
    pub(crate) message_byte_length: u64,
}

/// Compact-only certificate bound to one source-verified canonical byte pair.
/// It inventories every direct verifier-randomness call without claiming a
/// concrete-QROM reduction or minting a verification capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFixedTapeSourceCorrespondence {
    pub(crate) selected_contract_source_hash: Hash512,
    pub(crate) canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) verifier_message_domain: &'static str,
    pub(crate) verifier_message_version: u16,
    pub(crate) geometry_version: u16,
    pub(crate) logical_round_count: u64,
    pub(crate) direct_xof_call_count: u64,
    pub(crate) total_verifier_message_input_byte_length: u64,
    pub(crate) minimum_verifier_message_input_byte_length: u64,
    pub(crate) maximum_verifier_message_input_byte_length: u64,
    pub(crate) total_fixed_tape_byte_length: u64,
    pub(crate) maximum_message_byte_length_per_round: u64,
    pub(crate) rounds: Box<[CompactFixedTapeRoundSourceCorrespondence]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndependentDirectXofTrace {
    verifier_message_answer_prefix: [u8; Hash512::BYTE_LENGTH],
    input_byte_length: u64,
    message_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IndependentDirectXofFault {
    None,
    WrongDomain,
    WrongVersion,
    WrongPackingFactor,
    WrongRoundOrdinal,
    WrongPrefixCount,
    WrongDeclaredWidth,
    WrongResponseCount,
    WrongGeometryField,
    WrongPublicInputLength,
    WrongPublicInputByte,
    WrongCommitmentIdentifier,
    WrongCommitmentRoot,
    WrongRoundSalt,
}

impl IndependentDirectXofFault {
    const HOSTILE: [Self; 13] = [
        Self::WrongDomain,
        Self::WrongVersion,
        Self::WrongPackingFactor,
        Self::WrongRoundOrdinal,
        Self::WrongPrefixCount,
        Self::WrongDeclaredWidth,
        Self::WrongResponseCount,
        Self::WrongGeometryField,
        Self::WrongPublicInputLength,
        Self::WrongPublicInputByte,
        Self::WrongCommitmentIdentifier,
        Self::WrongCommitmentRoot,
        Self::WrongRoundSalt,
    ];

    const fn category(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WrongDomain => "domain",
            Self::WrongVersion => "version",
            Self::WrongPackingFactor => "packing factor",
            Self::WrongRoundOrdinal => "round ordinal",
            Self::WrongPrefixCount => "prefix count",
            Self::WrongDeclaredWidth => "declared width",
            Self::WrongResponseCount => "response count",
            Self::WrongGeometryField => "proof geometry",
            Self::WrongPublicInputLength => "public-input length",
            Self::WrongPublicInputByte => "public-input bytes",
            Self::WrongCommitmentIdentifier => "commitment identifier",
            Self::WrongCommitmentRoot => "commitment root",
            Self::WrongRoundSalt => "round salt",
        }
    }
}

/// Replays every selected call from a terminal that can exist only after
/// canonical transport, full algebraic verification, and independent public-
/// source correspondence have all succeeded.
pub(crate) fn verify_source_verified_compact_fixed_tape_correspondence(
    proof: &SourceVerifiedCompactPublicKeyProof,
    measurement: &CompactEmittedCdhzMeasurement,
) -> Result<CompactFixedTapeSourceCorrespondence, CompactFixedTapeSourceCorrespondenceError> {
    let transport = proof.source_verified_transport();
    let verifier_inputs = transport.verifier_inputs();
    let selected_contract_source_hash = verifier_inputs
        .canonical_source_hash()
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::Contract)?;
    let proof_view = transport.proof_view();
    let public_input_view = transport.public_input_view();
    let measurement_census = &measurement.decoded_actual_byte_census;
    if measurement_census.canonical_proof_binding != transport.canonical_proof_binding()
        || measurement_census.canonical_public_input_binding != public_input_view.binding()
        || verifier_inputs.proof_wire_geometry.responses().len()
            != transport.verifier_messages().len()
        || measurement.rounds.len() != transport.verifier_messages().len()
    {
        return Err(CompactFixedTapeSourceCorrespondenceError::MeasurementMismatch);
    }

    let mut total_verifier_message_input_byte_length = 0_u64;
    let mut minimum_verifier_message_input_byte_length = None;
    let mut maximum_verifier_message_input_byte_length = 0_u64;
    let mut total_fixed_tape_byte_length = 0_u64;
    let mut maximum_message_byte_length_per_round = 0_u64;
    let mut rounds = Vec::new();
    rounds
        .try_reserve_exact(transport.verifier_messages().len())
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;

    for (round_index, ((response_geometry, retained_message), measured_round)) in verifier_inputs
        .proof_wire_geometry
        .responses()
        .iter()
        .zip(transport.verifier_messages())
        .zip(&measurement.rounds)
        .enumerate()
    {
        let round_ordinal = u32::try_from(round_index)
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        if response_geometry.ordinal() != round_ordinal || measured_round.ordinal != round_ordinal {
            return Err(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal });
        }
        let geometry = response_geometry.verifier_message_geometry();
        let independent_message_byte_length = independent_message_byte_length(geometry)?;
        if geometry
            .exact_message_byte_length()
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?
            != independent_message_byte_length
            || measured_round.fiat_shamir_message_byte_length
                != u64::try_from(independent_message_byte_length)
                    .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
            || measured_round.concrete_fiat_shamir_xof_call_count != 1
        {
            return Err(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal });
        }

        let production_answer_prefix = compact_fiat_shamir_round_verifier_message_answer_prefix(
            verifier_inputs.proof_wire_geometry,
            proof_view.decoded(),
            proof_view.canonical_bytes(),
            public_input_view.decoded(),
            public_input_view.canonical_bytes(),
            round_ordinal,
        )
        .map_err(
            |_| CompactFixedTapeSourceCorrespondenceError::AnswerPrefixMismatch { round_ordinal },
        )?;
        let production_message_bytes = materialize_compact_fiat_shamir_verifier_message(
            verifier_inputs.proof_wire_geometry,
            proof_view.decoded(),
            proof_view.canonical_bytes(),
            public_input_view.decoded(),
            public_input_view.canonical_bytes(),
            round_ordinal,
        )
        .map_err(
            |_| CompactFixedTapeSourceCorrespondenceError::OutputMismatch {
                round_ordinal,
                first_divergent_byte_offset: 0,
            },
        )?;
        let independent_trace = independently_materialize_direct_xof(
            verifier_inputs.proof_wire_geometry,
            proof_view.decoded(),
            proof_view.canonical_bytes(),
            public_input_view.canonical_bytes(),
            round_ordinal,
            IndependentDirectXofFault::None,
        )?;
        if production_answer_prefix.into_bytes() != independent_trace.verifier_message_answer_prefix
        {
            return Err(
                CompactFixedTapeSourceCorrespondenceError::AnswerPrefixMismatch { round_ordinal },
            );
        }
        if production_message_bytes != independent_trace.message_bytes {
            return Err(CompactFixedTapeSourceCorrespondenceError::OutputMismatch {
                round_ordinal,
                first_divergent_byte_offset: first_divergent_byte_offset(
                    &production_message_bytes,
                    &independent_trace.message_bytes,
                ),
            });
        }
        let independently_decoded =
            decode_fixed_uniform_verifier_message(geometry, &independent_trace.message_bytes)
                .map_err(
                    |_| CompactFixedTapeSourceCorrespondenceError::DecodedMessageMismatch {
                        round_ordinal,
                    },
                )?;
        if &independently_decoded != retained_message {
            return Err(
                CompactFixedTapeSourceCorrespondenceError::DecodedMessageMismatch { round_ordinal },
            );
        }

        total_verifier_message_input_byte_length = total_verifier_message_input_byte_length
            .checked_add(independent_trace.input_byte_length)
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        minimum_verifier_message_input_byte_length = Some(
            minimum_verifier_message_input_byte_length
                .map_or(independent_trace.input_byte_length, |minimum: u64| {
                    minimum.min(independent_trace.input_byte_length)
                }),
        );
        maximum_verifier_message_input_byte_length =
            maximum_verifier_message_input_byte_length.max(independent_trace.input_byte_length);
        total_fixed_tape_byte_length = total_fixed_tape_byte_length
            .checked_add(
                u64::try_from(independent_trace.message_bytes.len())
                    .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
            )
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        maximum_message_byte_length_per_round = maximum_message_byte_length_per_round.max(
            u64::try_from(independent_trace.message_bytes.len())
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
        );
        rounds.push(CompactFixedTapeRoundSourceCorrespondence {
            round_ordinal,
            verifier_message_answer_prefix: independent_trace.verifier_message_answer_prefix,
            input_byte_length: independent_trace.input_byte_length,
            message_byte_length: u64::try_from(independent_trace.message_bytes.len())
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
        });
    }

    verify_deterministic_hostile_faults(
        verifier_inputs.proof_wire_geometry,
        proof_view.decoded(),
        proof_view.canonical_bytes(),
        public_input_view.canonical_bytes(),
    )?;

    let logical_round_count = u64::try_from(transport.verifier_messages().len())
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let correspondence = CompactFixedTapeSourceCorrespondence {
        selected_contract_source_hash,
        canonical_proof_binding: transport.canonical_proof_binding(),
        canonical_public_input_binding: public_input_view.binding(),
        verifier_message_domain: COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_DOMAIN,
        verifier_message_version: COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_VERSION,
        geometry_version: FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION,
        logical_round_count,
        direct_xof_call_count: logical_round_count,
        total_verifier_message_input_byte_length,
        minimum_verifier_message_input_byte_length: minimum_verifier_message_input_byte_length
            .ok_or(CompactFixedTapeSourceCorrespondenceError::MeasurementMismatch)?,
        maximum_verifier_message_input_byte_length,
        total_fixed_tape_byte_length,
        maximum_message_byte_length_per_round,
        rounds: rounds.into_boxed_slice(),
    };
    correspondence.validate_measurement_hash_graph(&measurement_census.shared_hash_graph)?;
    Ok(correspondence)
}

impl CompactFixedTapeSourceCorrespondence {
    fn validate_measurement_hash_graph(
        &self,
        hash_graph: &CompactSharedHashGraphCensus,
    ) -> Result<(), CompactFixedTapeSourceCorrespondenceError> {
        if hash_graph.fiat_shamir_verifier_message_xof_call_count != self.direct_xof_call_count {
            return Err(CompactFixedTapeSourceCorrespondenceError::MeasurementMismatch);
        }
        Ok(())
    }
}

fn verify_deterministic_hostile_faults(
    proof_geometry: &CompactProofWireGeometry,
    decoded_proof: &DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    canonical_public_input_bytes: &[u8],
) -> Result<(), CompactFixedTapeSourceCorrespondenceError> {
    let round_ordinal = proof_geometry
        .responses()
        .first()
        .ok_or(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal: 0 })?
        .ordinal();
    let expected = independently_materialize_direct_xof(
        proof_geometry,
        decoded_proof,
        canonical_proof_bytes,
        canonical_public_input_bytes,
        round_ordinal,
        IndependentDirectXofFault::None,
    )?;
    for fault in IndependentDirectXofFault::HOSTILE {
        let hostile = independently_materialize_direct_xof(
            proof_geometry,
            decoded_proof,
            canonical_proof_bytes,
            canonical_public_input_bytes,
            round_ordinal,
            fault,
        )?;
        if hostile.message_bytes == expected.message_bytes
            || hostile.verifier_message_answer_prefix == expected.verifier_message_answer_prefix
        {
            return Err(
                CompactFixedTapeSourceCorrespondenceError::HostileFaultUndetected {
                    round_ordinal,
                    fault_category: fault.category(),
                },
            );
        }
    }
    Ok(())
}

fn independently_materialize_direct_xof(
    proof_geometry: &CompactProofWireGeometry,
    decoded_proof: &DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    canonical_public_input_bytes: &[u8],
    round_ordinal: u32,
    fault: IndependentDirectXofFault,
) -> Result<IndependentDirectXofTrace, CompactFixedTapeSourceCorrespondenceError> {
    let response_index = usize::try_from(round_ordinal)
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let response_geometry = proof_geometry
        .responses()
        .get(response_index)
        .ok_or(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?;
    let output_byte_length =
        independent_message_byte_length(response_geometry.verifier_message_geometry())?;
    let prefix_response_count = response_index
        .checked_add(1)
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let prefix_items = independent_verifier_message_prefix_items(
        proof_geometry,
        round_ordinal,
        prefix_response_count,
        output_byte_length,
        fault,
    )?;
    let payload = independent_verifier_message_payload(
        decoded_proof,
        canonical_proof_bytes,
        canonical_public_input_bytes,
        round_ordinal,
        fault,
    )?;
    independent_foundation_variable_bytes_xof(
        if fault == IndependentDirectXofFault::WrongDomain {
            "sealed-lattice/test/wrong-compact-fiat-shamir-verifier-message/v2"
        } else {
            COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_DOMAIN
        },
        &prefix_items,
        &payload,
        output_byte_length,
        round_ordinal,
    )
}

fn independent_verifier_message_prefix_items(
    proof_geometry: &CompactProofWireGeometry,
    round_ordinal: u32,
    prefix_response_count: usize,
    output_byte_length: usize,
    fault: IndependentDirectXofFault,
) -> Result<Vec<CanonicalItem>, CompactFixedTapeSourceCorrespondenceError> {
    let mut items = vec![
        CanonicalItem::unsigned16(if fault == IndependentDirectXofFault::WrongVersion {
            COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_VERSION.wrapping_add(1)
        } else {
            COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_VERSION
        }),
        CanonicalItem::unsigned16(if fault == IndependentDirectXofFault::WrongPackingFactor {
            COMPACT_PACKING_FACTOR.wrapping_add(1)
        } else {
            COMPACT_PACKING_FACTOR
        }),
        CanonicalItem::unsigned32(if fault == IndependentDirectXofFault::WrongRoundOrdinal {
            round_ordinal.wrapping_add(1)
        } else {
            round_ordinal
        }),
        CanonicalItem::unsigned32(
            u32::try_from(prefix_response_count)
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
                .wrapping_add(u32::from(
                    fault == IndependentDirectXofFault::WrongPrefixCount,
                )),
        ),
        CanonicalItem::unsigned64(
            u64::try_from(output_byte_length)
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
                .wrapping_add(u64::from(
                    fault == IndependentDirectXofFault::WrongDeclaredWidth,
                )),
        ),
        CanonicalItem::unsigned32(
            u32::try_from(proof_geometry.responses().len())
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
                .wrapping_add(u32::from(
                    fault == IndependentDirectXofFault::WrongResponseCount,
                )),
        ),
    ];
    for (response_index, response) in proof_geometry.responses().iter().enumerate() {
        items.push(CanonicalItem::unsigned32(response.ordinal()));
        let mut response_counts = [
            response.minimum_queried_base_field_element_count(),
            response.maximum_queried_base_field_element_count(),
            response.minimum_queried_extension_field_element_count(),
            response.maximum_queried_extension_field_element_count(),
            response.minimum_queried_leaf_count(),
            response.maximum_queried_leaf_count(),
            response.maximum_frontier_node_count(),
        ];
        if response_index == 0 && fault == IndependentDirectXofFault::WrongGeometryField {
            response_counts[6] = response_counts[6].wrapping_add(1);
        }
        items.extend(response_counts.map(CanonicalItem::unsigned64));
        let message_geometry = response.verifier_message_geometry();
        items.extend([
            CanonicalItem::unsigned16(FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION),
            CanonicalItem::unsigned32(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT),
            CanonicalItem::unsigned64(Hash512::BYTE_LENGTH as u64),
            CanonicalItem::unsigned64(size_of::<u64>() as u64),
            CanonicalItem::unsigned64(message_geometry.extension_output_count()),
            CanonicalItem::unsigned64(message_geometry.excluded_extension_prefix_cardinality()),
            CanonicalItem::unsigned64(message_geometry.base_field_output_count()),
            CanonicalItem::unsigned64(
                u64::try_from(message_geometry.distinct_query_groups().len())
                    .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
            ),
        ]);
        for group in message_geometry.distinct_query_groups() {
            items.push(CanonicalItem::unsigned64(group.domain_cardinality()));
            items.push(CanonicalItem::unsigned64(group.query_count()));
        }
    }
    Ok(items)
}

fn independent_verifier_message_payload(
    decoded_proof: &DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    canonical_public_input_bytes: &[u8],
    round_ordinal: u32,
    fault: IndependentDirectXofFault,
) -> Result<Vec<u8>, CompactFixedTapeSourceCorrespondenceError> {
    let prefix_response_count = usize::try_from(round_ordinal)
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
        .checked_add(1)
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let responses = decoded_proof
        .responses()
        .get(..prefix_response_count)
        .ok_or(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?;
    let payload_byte_length = size_of::<u64>()
        .checked_add(canonical_public_input_bytes.len())
        .and_then(|length| {
            prefix_response_count
                .checked_mul(
                    size_of::<u32>()
                        + Hash512::BYTE_LENGTH
                        + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH,
                )
                .and_then(|entry_bytes| length.checked_add(entry_bytes))
        })
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_byte_length)
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    payload.extend_from_slice(
        &u64::try_from(canonical_public_input_bytes.len())
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
            .wrapping_add(u64::from(
                fault == IndependentDirectXofFault::WrongPublicInputLength,
            ))
            .to_le_bytes(),
    );
    payload.extend_from_slice(canonical_public_input_bytes);
    if fault == IndependentDirectXofFault::WrongPublicInputByte {
        let public_input_offset = size_of::<u64>();
        let first_public_input_byte = payload
            .get_mut(public_input_offset)
            .ok_or(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?;
        *first_public_input_byte ^= 1;
    }
    for (response_index, response) in responses.iter().enumerate() {
        let response_ordinal = u32::try_from(response_index)
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        let mut identifier = response_ordinal
            .checked_add(1)
            .ok_or(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?;
        let mut root = response.root();
        let mut round_salt = response
            .fiat_shamir_round_salt(canonical_proof_bytes)
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?;
        if response_index == 0 {
            if fault == IndependentDirectXofFault::WrongCommitmentIdentifier {
                identifier = identifier.wrapping_add(1);
            } else if fault == IndependentDirectXofFault::WrongCommitmentRoot {
                root[0] ^= 1;
            } else if fault == IndependentDirectXofFault::WrongRoundSalt {
                round_salt[0] ^= 1;
            }
        }
        payload.extend_from_slice(&identifier.to_le_bytes());
        payload.extend_from_slice(&root);
        payload.extend_from_slice(&round_salt);
    }
    if payload.len() != payload_byte_length {
        return Err(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal });
    }
    Ok(payload)
}

fn independent_message_byte_length(
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<usize, CompactFixedTapeSourceCorrespondenceError> {
    let draw_count = u64::from(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT);
    let extension_byte_length = geometry
        .extension_output_count()
        .checked_mul(draw_count)
        .and_then(|count| count.checked_mul(Hash512::BYTE_LENGTH as u64))
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let base_and_query_output_count = geometry.distinct_query_groups().iter().try_fold(
        geometry.base_field_output_count(),
        |count, group| {
            count
                .checked_add(group.query_count())
                .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)
        },
    )?;
    let base_and_query_byte_length = base_and_query_output_count
        .checked_mul(draw_count)
        .and_then(|count| count.checked_mul(size_of::<u64>() as u64))
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    usize::try_from(
        extension_byte_length
            .checked_add(base_and_query_byte_length)
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
    )
    .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)
}

fn independent_foundation_variable_bytes_xof(
    domain: &str,
    prefix_items: &[CanonicalItem],
    payload: &[u8],
    output_byte_length: usize,
    round_ordinal: u32,
) -> Result<IndependentDirectXofTrace, CompactFixedTapeSourceCorrespondenceError> {
    if output_byte_length < Hash512::BYTE_LENGTH {
        return Err(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal });
    }
    let domain_item = CanonicalItem::nonempty_ascii(domain).map_err(|_| {
        CompactFixedTapeSourceCorrespondenceError::CanonicalFraming { round_ordinal }
    })?;
    let item_count = prefix_items
        .len()
        .checked_add(2)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let payload_byte_length = u32::try_from(payload.len())
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let canonical_payload_byte_length = payload
        .len()
        .checked_add(size_of::<u32>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;

    let schema_identifier_bytes = CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes();
    let schema_version_bytes = CANONICAL_TUPLE_VERSION.to_le_bytes();
    let item_count_bytes = item_count.to_le_bytes();
    let mut input_byte_length = schema_identifier_bytes
        .len()
        .checked_add(schema_version_bytes.len())
        .and_then(|length| length.checked_add(item_count_bytes.len()))
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let mut state = Shake256::default();
    state.update(&schema_identifier_bytes);
    state.update(&schema_version_bytes);
    state.update(&item_count_bytes);
    input_byte_length = input_byte_length
        .checked_add(independently_absorb_canonical_item(
            &mut state,
            &domain_item,
            round_ordinal,
        )?)
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    for item in prefix_items {
        input_byte_length = input_byte_length
            .checked_add(independently_absorb_canonical_item(
                &mut state,
                item,
                round_ordinal,
            )?)
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    }
    let raw_type_bytes = CanonicalItemType::RawBytes.canonical_code().to_le_bytes();
    let canonical_payload_byte_length_bytes = canonical_payload_byte_length.to_le_bytes();
    let payload_byte_length_bytes = payload_byte_length.to_le_bytes();
    state.update(&raw_type_bytes);
    state.update(&canonical_payload_byte_length_bytes);
    state.update(&payload_byte_length_bytes);
    state.update(payload);
    input_byte_length = input_byte_length
        .checked_add(raw_type_bytes.len())
        .and_then(|length| length.checked_add(canonical_payload_byte_length_bytes.len()))
        .and_then(|length| length.checked_add(payload_byte_length_bytes.len()))
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;

    let mut reader = state.finalize_xof();
    let mut message_bytes = vec![0_u8; output_byte_length];
    reader.read(&mut message_bytes);
    let verifier_message_answer_prefix = message_bytes[..Hash512::BYTE_LENGTH]
        .try_into()
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?;
    Ok(IndependentDirectXofTrace {
        verifier_message_answer_prefix,
        input_byte_length: u64::try_from(input_byte_length)
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
        message_bytes,
    })
}

fn independently_absorb_canonical_item(
    state: &mut Shake256,
    item: &CanonicalItem,
    round_ordinal: u32,
) -> Result<usize, CompactFixedTapeSourceCorrespondenceError> {
    let byte_length = u32::try_from(item.canonical_bytes().len()).map_err(|_| {
        CompactFixedTapeSourceCorrespondenceError::CanonicalFraming { round_ordinal }
    })?;
    let type_bytes = item.item_type().canonical_code().to_le_bytes();
    let byte_length_bytes = byte_length.to_le_bytes();
    state.update(&type_bytes);
    state.update(&byte_length_bytes);
    state.update(item.canonical_bytes());
    type_bytes
        .len()
        .checked_add(byte_length_bytes.len())
        .and_then(|length| length.checked_add(item.canonical_bytes().len()))
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)
}

fn first_divergent_byte_offset(left: &[u8], right: &[u8]) -> u64 {
    u64::try_from(
        left.iter()
            .zip(right)
            .position(|(left_byte, right_byte)| left_byte != right_byte)
            .unwrap_or_else(|| left.len().min(right.len())),
    )
    .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{CanonicalDecodeLimits, StreamingFoundationTupleHash512};

    #[test]
    fn selected_contract_direct_xof_inventory_is_compiler_derived() {
        let contract =
            super::super::compact_proof_contract::CompactPublicKeyProofContract::decode_selected()
                .expect("the selected compact contract decodes");
        let mut total_byte_length = 0_u64;
        let mut maximum_message_byte_length = 0_u64;
        let mut minimum_message_bit_length = None;
        for response in contract.verifier_inputs().proof_wire_geometry.responses() {
            let geometry = response.verifier_message_geometry();
            let byte_length = independent_message_byte_length(geometry)
                .expect("the independent byte length derives");
            assert_eq!(
                byte_length,
                geometry
                    .exact_message_byte_length()
                    .expect("the production byte length derives"),
            );
            let byte_length = u64::try_from(byte_length).expect("message byte length fits u64");
            total_byte_length += byte_length;
            maximum_message_byte_length = maximum_message_byte_length.max(byte_length);
            let bit_length = byte_length * u64::from(u8::BITS);
            minimum_message_bit_length = Some(
                minimum_message_bit_length
                    .map_or(bit_length, |minimum: u64| minimum.min(bit_length)),
            );
        }
        let logical_round_count = contract
            .verifier_inputs()
            .proof_wire_geometry
            .responses()
            .len();
        println!(
            "selected compact direct-XOF inventory logical_round_count={logical_round_count} direct_xof_call_count={logical_round_count} total_tape_byte_length={total_byte_length} maximum_message_byte_length_per_round={maximum_message_byte_length} minimum_message_bit_length={}",
            minimum_message_bit_length.expect("the selected contract has rounds"),
        );
        assert_eq!(logical_round_count, 82);
        assert_eq!(total_byte_length, 11_612_160);
        assert_eq!(maximum_message_byte_length, 4_442_112);
        assert_eq!(minimum_message_bit_length, Some(65_536));
    }

    #[test]
    fn independent_direct_xof_accepts_streamed_payload_above_default_item_limits() {
        let oversized_payload = vec![
            0x5a;
            CanonicalDecodeLimits::default()
                .maximum_item_byte_length
                .checked_add(1)
                .expect("the hostile payload length derives")
        ];
        assert!(CanonicalItem::variable_bytes(&oversized_payload).is_err());
        let prefix_items = [CanonicalItem::unsigned16(7), CanonicalItem::unsigned32(11)];
        let independent = independent_foundation_variable_bytes_xof(
            "sealed-lattice/test/oversized-streamed-prefix/v1",
            &prefix_items,
            &oversized_payload,
            257,
            11,
        )
        .expect("the independent direct XOF has no external decoder limit");
        let mut production = StreamingFoundationTupleHash512::new_variable_bytes(
            "sealed-lattice/test/oversized-streamed-prefix/v1",
            &prefix_items,
            oversized_payload.len(),
        )
        .expect("the production streaming hash accepts the declared payload");
        for fragment in oversized_payload.chunks(1_048_576) {
            production
                .absorb(fragment)
                .expect("every bounded payload fragment is accepted");
        }
        let mut production_reader = production
            .finalize_bounded_xof(257)
            .expect("the complete payload yields one bounded XOF answer");
        let mut production_bytes = vec![0_u8; 257];
        production_reader
            .read(&mut production_bytes)
            .expect("the exact output width is readable");
        production_reader
            .finish()
            .expect("the complete output width is consumed");
        assert_eq!(independent.message_bytes, production_bytes);
    }
}
