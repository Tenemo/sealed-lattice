//! Independent source correspondence for the compact fixed-output tape graph.
//!
//! This module replays every selected SHAKE256 transcript-prefix and
//! independently indexed output-block call from the source-verified canonical
//! transport. Matching executable bytes and graph calls is necessary source
//! evidence; the separate domain-extension owner maps this exact graph to its
//! ideal-QRO theorem.

use std::mem::size_of;

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::compact_emitted_cdhz::{CompactEmittedCdhzMeasurement, CompactSharedHashGraphCensus};
use super::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, COMPACT_PACKING_FACTOR,
};
use super::compact_transcript::{
    COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN, COMPACT_FIAT_SHAMIR_PREFIX_VERSION,
    compact_fiat_shamir_round_prefix_digest, compact_vector_commitment_oracle_identifier,
};
use super::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN, FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION,
    FixedUniformVerifierMessageGeometry, decode_fixed_uniform_verifier_message,
    materialize_fixed_uniform_verifier_message,
};
use super::{
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, SourceVerifiedCompactPublicKeyProof,
};
use crate::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalItemType,
    Hash512, canonical_foundation_tuple_hash_preimage,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CompactFixedTapeSourceCorrespondenceError {
    ArithmeticOverflow,
    CanonicalFraming {
        round_ordinal: u32,
        block_ordinal: Option<u64>,
    },
    Contract,
    Geometry {
        round_ordinal: u32,
    },
    PrefixMismatch {
        round_ordinal: u32,
    },
    GraphMismatch {
        round_ordinal: u32,
        first_divergent_block_ordinal: u64,
    },
    DecodedMessageMismatch {
        round_ordinal: u32,
    },
    MeasurementMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactFixedTapeGraphModel {
    TranscriptPrefixThenIndependentBlocks,
    #[cfg(test)]
    PredecessorLinkedBlocks,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFixedTapeRoundSourceCorrespondence {
    pub(crate) round_ordinal: u32,
    pub(crate) transcript_prefix_digest: [u8; Hash512::BYTE_LENGTH],
    pub(crate) message_byte_length: u64,
    pub(crate) output_block_count: u64,
}

/// Compact-only certificate bound to one source-verified canonical byte pair.
/// It inventories the complete selected fixed-output graph without claiming a
/// QROM reduction or minting a verification capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFixedTapeSourceCorrespondence {
    pub(crate) selected_contract_source_hash: Hash512,
    pub(crate) canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) graph_model: CompactFixedTapeGraphModel,
    pub(crate) prefix_domain: &'static str,
    pub(crate) block_domain: &'static str,
    pub(crate) geometry_version: u16,
    pub(crate) fixed_hash_output_bit_length: u16,
    pub(crate) logical_round_count: u64,
    pub(crate) prefix_hash_count: u64,
    pub(crate) output_block_hash_count: u64,
    pub(crate) total_fixed_tape_byte_length: u64,
    pub(crate) maximum_output_block_count_per_round: u64,
    pub(crate) rounds: Box<[CompactFixedTapeRoundSourceCorrespondence]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndependentFixedTapeTrace {
    message_bytes: Vec<u8>,
    output_block_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IndependentFixedTapeFault {
    None,
    WrongBlockDomain,
    WrongDeclaredWidth,
    WrongFirstBlockOrdinal,
    WrongSecondBlockOrdinal,
}

/// Replays the complete selected graph from a terminal that can exist only
/// after canonical transport, full algebraic verification, and independent
/// public-source correspondence have all succeeded.
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

    let mut output_block_hash_count = 0_u64;
    let mut total_fixed_tape_byte_length = 0_u64;
    let mut maximum_output_block_count_per_round = 0_u64;
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
        {
            return Err(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal });
        }

        let production_prefix = compact_fiat_shamir_round_prefix_digest(
            verifier_inputs.proof_wire_geometry,
            proof_view.decoded(),
            proof_view.canonical_bytes(),
            public_input_view.decoded(),
            public_input_view.canonical_bytes(),
            round_ordinal,
        )
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::PrefixMismatch { round_ordinal })?;
        let independent_prefix = independently_recompute_round_prefix(
            proof_view.decoded(),
            proof_view.canonical_bytes(),
            public_input_view.canonical_bytes(),
            round_ordinal,
        )?;
        if production_prefix != independent_prefix {
            return Err(CompactFixedTapeSourceCorrespondenceError::PrefixMismatch {
                round_ordinal,
            });
        }

        let production_message_bytes =
            materialize_fixed_uniform_verifier_message(production_prefix, round_ordinal, geometry)
                .map_err(
                    |_| CompactFixedTapeSourceCorrespondenceError::GraphMismatch {
                        round_ordinal,
                        first_divergent_block_ordinal: 0,
                    },
                )?;
        let independent_trace = independently_materialize_fixed_tape(
            independent_prefix,
            round_ordinal,
            geometry,
            IndependentFixedTapeFault::None,
        )?;
        if production_message_bytes != independent_trace.message_bytes {
            return Err(CompactFixedTapeSourceCorrespondenceError::GraphMismatch {
                round_ordinal,
                first_divergent_block_ordinal: first_divergent_block_ordinal(
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
        let expected_fixed_tape_hash_query_count = independent_trace.output_block_count;
        let expected_round_hash_query_count =
            expected_fixed_tape_hash_query_count
                .checked_add(1)
                .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        if geometry
            .concrete_hash_query_count()
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?
            != expected_fixed_tape_hash_query_count
            || measured_round.concrete_fiat_shamir_hash_query_count
                != expected_round_hash_query_count
        {
            return Err(CompactFixedTapeSourceCorrespondenceError::MeasurementMismatch);
        }
        output_block_hash_count = output_block_hash_count
            .checked_add(independent_trace.output_block_count)
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        total_fixed_tape_byte_length = total_fixed_tape_byte_length
            .checked_add(
                u64::try_from(independent_trace.message_bytes.len())
                    .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
            )
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        maximum_output_block_count_per_round =
            maximum_output_block_count_per_round.max(independent_trace.output_block_count);
        rounds.push(CompactFixedTapeRoundSourceCorrespondence {
            round_ordinal,
            transcript_prefix_digest: independent_prefix.into_bytes(),
            message_byte_length: u64::try_from(independent_trace.message_bytes.len())
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
            output_block_count: independent_trace.output_block_count,
        });
    }

    let logical_round_count = u64::try_from(transport.verifier_messages().len())
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let correspondence = CompactFixedTapeSourceCorrespondence {
        selected_contract_source_hash,
        canonical_proof_binding: transport.canonical_proof_binding(),
        canonical_public_input_binding: public_input_view.binding(),
        graph_model: CompactFixedTapeGraphModel::TranscriptPrefixThenIndependentBlocks,
        prefix_domain: COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
        block_domain: FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN,
        geometry_version: FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION,
        fixed_hash_output_bit_length: u16::try_from(Hash512::BYTE_LENGTH * u8::BITS as usize)
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
        logical_round_count,
        prefix_hash_count: logical_round_count,
        output_block_hash_count,
        total_fixed_tape_byte_length,
        maximum_output_block_count_per_round,
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
        if hash_graph.fiat_shamir_prefix_hash_count != self.prefix_hash_count
            || hash_graph.fixed_message_block_hash_count != self.output_block_hash_count
        {
            return Err(CompactFixedTapeSourceCorrespondenceError::MeasurementMismatch);
        }
        Ok(())
    }
}

fn independently_recompute_round_prefix(
    decoded_proof: &super::compact_proof_wire::DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    canonical_public_input_bytes: &[u8],
    round_ordinal: u32,
) -> Result<Hash512, CompactFixedTapeSourceCorrespondenceError> {
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
            .to_le_bytes(),
    );
    payload.extend_from_slice(canonical_public_input_bytes);
    for (response_index, response) in responses.iter().enumerate() {
        let response_ordinal = u32::try_from(response_index)
            .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        payload.extend_from_slice(
            &compact_vector_commitment_oracle_identifier(response_ordinal)
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal })?
                .to_le_bytes(),
        );
        payload.extend_from_slice(&response.root());
        payload.extend_from_slice(
            &response
                .fiat_shamir_round_salt(canonical_proof_bytes)
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::Geometry {
                    round_ordinal,
                })?,
        );
    }
    if payload.len() != payload_byte_length {
        return Err(CompactFixedTapeSourceCorrespondenceError::Geometry { round_ordinal });
    }
    independent_foundation_variable_bytes_hash512(
        COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
        &[
            CanonicalItem::unsigned16(COMPACT_FIAT_SHAMIR_PREFIX_VERSION),
            CanonicalItem::unsigned16(COMPACT_PACKING_FACTOR),
            CanonicalItem::unsigned32(round_ordinal),
            CanonicalItem::unsigned32(
                u32::try_from(prefix_response_count)
                    .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
            ),
        ],
        &payload,
        round_ordinal,
    )
}

fn independently_materialize_fixed_tape(
    starting_transcript_state: Hash512,
    logical_verifier_move_ordinal: u32,
    geometry: &FixedUniformVerifierMessageGeometry,
    fault: IndependentFixedTapeFault,
) -> Result<IndependentFixedTapeTrace, CompactFixedTapeSourceCorrespondenceError> {
    let output_byte_length = independent_message_byte_length(geometry)?;
    let declared_output_byte_length = if fault == IndependentFixedTapeFault::WrongDeclaredWidth {
        output_byte_length
            .checked_add(1)
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
    } else {
        output_byte_length
    };
    let declared_output_byte_length_u64 = u64::try_from(declared_output_byte_length)
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    let block_domain = if fault == IndependentFixedTapeFault::WrongBlockDomain {
        "sealed-lattice/test/wrong-fixed-uniform-verifier-message-block/v2"
    } else {
        FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN
    };
    let mut fixed_block_items = independent_geometry_items(
        starting_transcript_state,
        logical_verifier_move_ordinal,
        geometry,
    )?;
    fixed_block_items.push(CanonicalItem::unsigned64(declared_output_byte_length_u64));
    let output_block_count = independent_output_block_count(output_byte_length)?;
    let mut message_bytes = Vec::new();
    message_bytes
        .try_reserve_exact(output_byte_length)
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
    for block_ordinal in 0..output_block_count {
        let encoded_block_ordinal = if block_ordinal == 0
            && fault == IndependentFixedTapeFault::WrongFirstBlockOrdinal
        {
            1
        } else if block_ordinal == 1 && fault == IndependentFixedTapeFault::WrongSecondBlockOrdinal
        {
            0
        } else {
            block_ordinal
        };
        let mut block_items = fixed_block_items.clone();
        block_items.push(CanonicalItem::unsigned64(encoded_block_ordinal));
        let block = independent_foundation_hash512(
            block_domain,
            &block_items,
            logical_verifier_move_ordinal,
            Some(block_ordinal),
        )?
        .into_bytes();
        let remaining_byte_length = output_byte_length
            .checked_sub(message_bytes.len())
            .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?;
        message_bytes.extend_from_slice(&block[..remaining_byte_length.min(Hash512::BYTE_LENGTH)]);
    }
    if message_bytes.len() != output_byte_length {
        return Err(CompactFixedTapeSourceCorrespondenceError::Geometry {
            round_ordinal: logical_verifier_move_ordinal,
        });
    }
    Ok(IndependentFixedTapeTrace {
        message_bytes,
        output_block_count,
    })
}

fn independent_geometry_items(
    starting_transcript_state: Hash512,
    logical_verifier_move_ordinal: u32,
    geometry: &FixedUniformVerifierMessageGeometry,
) -> Result<Vec<CanonicalItem>, CompactFixedTapeSourceCorrespondenceError> {
    let mut items = vec![
        CanonicalItem::hash512(starting_transcript_state.into_bytes()),
        CanonicalItem::unsigned16(FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION),
        CanonicalItem::unsigned32(logical_verifier_move_ordinal),
        CanonicalItem::unsigned32(PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT),
        CanonicalItem::unsigned64(Hash512::BYTE_LENGTH as u64),
        CanonicalItem::unsigned64(size_of::<u64>() as u64),
        CanonicalItem::unsigned64(geometry.extension_output_count()),
        CanonicalItem::unsigned64(geometry.excluded_extension_prefix_cardinality()),
        CanonicalItem::unsigned64(geometry.base_field_output_count()),
        CanonicalItem::unsigned64(
            u64::try_from(geometry.distinct_query_groups().len())
                .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?,
        ),
    ];
    for group in geometry.distinct_query_groups() {
        items.push(CanonicalItem::unsigned64(group.domain_cardinality()));
        items.push(CanonicalItem::unsigned64(group.query_count()));
    }
    Ok(items)
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

fn independent_output_block_count(
    output_byte_length: usize,
) -> Result<u64, CompactFixedTapeSourceCorrespondenceError> {
    if output_byte_length == 0 {
        return Err(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow);
    }
    u64::try_from(output_byte_length)
        .map_err(|_| CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)?
        .checked_add(Hash512::BYTE_LENGTH as u64 - 1)
        .and_then(|rounded| rounded.checked_div(Hash512::BYTE_LENGTH as u64))
        .ok_or(CompactFixedTapeSourceCorrespondenceError::ArithmeticOverflow)
}

fn independent_foundation_hash512(
    domain: &str,
    items: &[CanonicalItem],
    round_ordinal: u32,
    block_ordinal: Option<u64>,
) -> Result<Hash512, CompactFixedTapeSourceCorrespondenceError> {
    let preimage = canonical_foundation_tuple_hash_preimage(domain, items).map_err(|_| {
        CompactFixedTapeSourceCorrespondenceError::CanonicalFraming {
            round_ordinal,
            block_ordinal,
        }
    })?;
    let mut state = Shake256::default();
    state.update(&preimage);
    let mut reader = state.finalize_xof();
    let mut output = [0_u8; Hash512::BYTE_LENGTH];
    reader.read(&mut output);
    Ok(Hash512::from_bytes(output))
}

fn independent_foundation_variable_bytes_hash512(
    domain: &str,
    prefix_items: &[CanonicalItem],
    payload: &[u8],
    round_ordinal: u32,
) -> Result<Hash512, CompactFixedTapeSourceCorrespondenceError> {
    let domain_item = CanonicalItem::nonempty_ascii(domain).map_err(|_| {
        CompactFixedTapeSourceCorrespondenceError::CanonicalFraming {
            round_ordinal,
            block_ordinal: None,
        }
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

    let mut state = Shake256::default();
    state.update(&CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
    state.update(&CANONICAL_TUPLE_VERSION.to_le_bytes());
    state.update(&item_count.to_le_bytes());
    independently_absorb_canonical_item(&mut state, &domain_item, round_ordinal)?;
    for item in prefix_items {
        independently_absorb_canonical_item(&mut state, item, round_ordinal)?;
    }
    state.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    state.update(&canonical_payload_byte_length.to_le_bytes());
    state.update(&payload_byte_length.to_le_bytes());
    state.update(payload);

    let mut reader = state.finalize_xof();
    let mut output = [0_u8; Hash512::BYTE_LENGTH];
    reader.read(&mut output);
    Ok(Hash512::from_bytes(output))
}

fn independently_absorb_canonical_item(
    state: &mut Shake256,
    item: &CanonicalItem,
    round_ordinal: u32,
) -> Result<(), CompactFixedTapeSourceCorrespondenceError> {
    let byte_length = u32::try_from(item.canonical_bytes().len()).map_err(|_| {
        CompactFixedTapeSourceCorrespondenceError::CanonicalFraming {
            round_ordinal,
            block_ordinal: None,
        }
    })?;
    state.update(&item.item_type().canonical_code().to_le_bytes());
    state.update(&byte_length.to_le_bytes());
    state.update(item.canonical_bytes());
    Ok(())
}

fn first_divergent_block_ordinal(left: &[u8], right: &[u8]) -> u64 {
    let first_divergent_byte = left
        .iter()
        .zip(right)
        .position(|(left_byte, right_byte)| left_byte != right_byte)
        .unwrap_or_else(|| left.len().min(right.len()));
    u64::try_from(first_divergent_byte / Hash512::BYTE_LENGTH).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::super::fixed_uniform_verifier_message::FixedUniformDistinctQueryGeometry;
    use super::*;
    use crate::foundation::{CanonicalDecodeLimits, StreamingFoundationTupleHash512};

    fn multi_block_geometry() -> FixedUniformVerifierMessageGeometry {
        FixedUniformVerifierMessageGeometry::new(
            2,
            3,
            2,
            vec![FixedUniformDistinctQueryGeometry::new(64, 7)],
        )
        .expect("the hostile fixed-tape geometry is valid")
    }

    #[test]
    fn independent_fixed_tape_replay_detects_every_graph_segment_fault() {
        let geometry = multi_block_geometry();
        let starting_transcript_state = Hash512::from_bytes([0x41; Hash512::BYTE_LENGTH]);
        let production =
            materialize_fixed_uniform_verifier_message(starting_transcript_state, 11, &geometry)
                .expect("the production graph materializes");
        let independent = independently_materialize_fixed_tape(
            starting_transcript_state,
            11,
            &geometry,
            IndependentFixedTapeFault::None,
        )
        .expect("the independent graph materializes");
        assert_eq!(independent.message_bytes, production);
        assert!(independent.output_block_count > 1);

        for fault in [
            IndependentFixedTapeFault::WrongBlockDomain,
            IndependentFixedTapeFault::WrongDeclaredWidth,
            IndependentFixedTapeFault::WrongFirstBlockOrdinal,
        ] {
            let hostile = independently_materialize_fixed_tape(
                starting_transcript_state,
                11,
                &geometry,
                fault,
            )
            .expect("the hostile graph remains executable");
            assert_eq!(
                first_divergent_block_ordinal(&production, &hostile.message_bytes),
                0,
                "the {fault:?} mutation must diverge in the first block",
            );
        }
        let hostile = independently_materialize_fixed_tape(
            starting_transcript_state,
            11,
            &geometry,
            IndependentFixedTapeFault::WrongSecondBlockOrdinal,
        )
        .expect("the second-block ordinal mutation remains executable");
        assert_eq!(
            first_divergent_block_ordinal(&production, &hostile.message_bytes),
            1,
        );

        let wrong_state = independently_materialize_fixed_tape(
            Hash512::from_bytes([0x42; Hash512::BYTE_LENGTH]),
            11,
            &geometry,
            IndependentFixedTapeFault::None,
        )
        .expect("the wrong-state graph remains executable");
        assert_eq!(
            first_divergent_block_ordinal(&production, &wrong_state.message_bytes),
            0,
        );
        let wrong_ordinal = independently_materialize_fixed_tape(
            starting_transcript_state,
            12,
            &geometry,
            IndependentFixedTapeFault::None,
        )
        .expect("the wrong-ordinal graph remains executable");
        assert_eq!(
            first_divergent_block_ordinal(&production, &wrong_ordinal.message_bytes),
            0,
        );
    }

    #[test]
    fn selected_contract_fixed_tape_inventory_is_compiler_derived() {
        let contract =
            super::super::compact_proof_contract::CompactPublicKeyProofContract::decode_selected()
                .expect("the selected compact contract decodes");
        let mut total_byte_length = 0_u64;
        let mut total_block_count = 0_u64;
        let mut maximum_block_count = 0_u64;
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
            let block_count = independent_output_block_count(byte_length)
                .expect("the fixed-output block count derives");
            total_byte_length += u64::try_from(byte_length).unwrap();
            total_block_count += block_count;
            maximum_block_count = maximum_block_count.max(block_count);
            let bit_length = u64::try_from(byte_length).unwrap() * u64::from(u8::BITS);
            minimum_message_bit_length = Some(
                minimum_message_bit_length
                    .map_or(bit_length, |minimum: u64| minimum.min(bit_length)),
            );
        }
        println!(
            "selected compact fixed-tape inventory logical_round_count={} total_tape_byte_length={} output_block_hash_count={} maximum_output_block_count_per_round={} minimum_message_bit_length={}",
            contract
                .verifier_inputs()
                .proof_wire_geometry
                .responses()
                .len(),
            total_byte_length,
            total_block_count,
            maximum_block_count,
            minimum_message_bit_length.expect("the selected contract has rounds"),
        );
        assert_eq!(
            contract
                .verifier_inputs()
                .proof_wire_geometry
                .responses()
                .len(),
            82,
        );
        assert_eq!(minimum_message_bit_length, Some(65_536));
    }

    #[test]
    fn independent_prefix_hash_accepts_the_streamed_payload_above_default_item_limits() {
        let oversized_payload = vec![
            0x5a;
            CanonicalDecodeLimits::default()
                .maximum_item_byte_length
                .checked_add(1)
                .expect("the hostile payload length derives")
        ];
        assert!(CanonicalItem::variable_bytes(&oversized_payload).is_err());
        let prefix_items = [CanonicalItem::unsigned16(7), CanonicalItem::unsigned32(11)];
        let independent = independent_foundation_variable_bytes_hash512(
            "sealed-lattice/test/oversized-streamed-prefix/v1",
            &prefix_items,
            &oversized_payload,
            11,
        )
        .expect("the independent prefix hash has no external decoder limit");
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
        assert_eq!(
            independent,
            production
                .finalize()
                .expect("the production streaming hash consumes the complete payload"),
        );
    }
}
