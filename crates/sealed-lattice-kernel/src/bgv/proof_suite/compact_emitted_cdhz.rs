//! CDHZ/BCS census coordinates and test-only emitted-byte measurement.
//!
//! The generated compact-proof contract owns the verifier geometry. This
//! module retains the census value types used by the theorem arithmetic. Tests
//! can measure those coordinates from an already-verified compact transport;
//! the release transport validates structure and salted openings, while
//! algebraic proof verification and production premise constructors remain
//! unavailable.

use std::mem::size_of;

use super::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
use super::PROOF_CHALLENGE_EXTENSION_DEGREE;
#[cfg(test)]
use super::compact_proof_contract::CompactPublicKeyProofContract;
#[cfg(test)]
use super::compact_proof_wire::PROOF_FIXED_HEADER_BYTE_LENGTH;
#[cfg(test)]
use super::compact_proof_wire::{CompactProofWireError, CompactPublicInputBindings};
#[cfg(test)]
use super::compact_public_key_verifier::{
    CompactPublicKeyTransportError, VerifiedCompactPublicKeyTransport,
    compact_proof_transport_binding, compact_public_input_transport_binding,
    verify_selected_compact_public_key_transport,
};
#[cfg(test)]
use super::compact_response_merkle::{
    COMPACT_RESPONSE_LEAF_HASH_DOMAIN, COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
};
use super::compact_response_merkle::{CompactResponseLeafValueKind, CompactResponseQuerySelection};
#[cfg(test)]
use super::compact_transcript::COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN;
#[cfg(test)]
use super::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN, FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN,
};
use super::merkle::maximum_minimal_frontier_node_count;
#[cfg(test)]
use crate::foundation::Hash512;

const CDHZ_MERKLE_OUTPUT_BIT_LENGTH: u16 = 512;
const CDHZ_MERKLE_LEAF_SALT_BIT_LENGTH: u16 =
    (COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH * 8) as u16;
const NO_IMPLICIT_INSTANCE_TUPLE_SIZE: u64 = 0;
const MULTI_EXTRACT_ORACLE_COUNT: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactEmittedCdhzError {
    #[cfg(test)]
    MissingEmittedProof,
    #[cfg(test)]
    MissingEmittedPublicInput,
    #[cfg(test)]
    Transport(CompactPublicKeyTransportError),
    ArithmeticOverflow,
    InvalidCensus,
}

/// The fixed random-oracle domains used by the emitted BCS transcript and its
/// salted response-vector commitments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzRandomOracleDomains {
    pub(crate) fiat_shamir_prefix: &'static str,
    pub(crate) verifier_message_seed: &'static str,
    pub(crate) verifier_message_block: &'static str,
    pub(crate) merkle_leaf: &'static str,
    pub(crate) merkle_parent: &'static str,
}

/// Oracle-family census for the coordinates over which the CDHZ Appendix A.1
/// specialization partitions adversarial query mass. The emission does not determine an adversary's
/// `wFS`, `wVC`, or `wMultiExtract` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzOracleFamilyCensus {
    pub(crate) fiat_shamir_oracle_count: u64,
    pub(crate) vector_commitment_oracle_count: u64,
    pub(crate) multi_extract_oracle_count: u64,
}

/// Exact Merkle multi-extraction arguments contributed by the emitted proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCdhzMerkleMultiExtractionTerms {
    pub(crate) output_bit_length: u16,
    pub(crate) leaf_salt_bit_length: u16,
    pub(crate) vector_commitment_tuple_size: u64,
    pub(crate) input_implicit_instance_tuple_size: u64,
    pub(crate) output_implicit_instance_tuple_size: u64,
    pub(crate) observed_check_oracle_query_count: u64,
    pub(crate) geometry_check_oracle_query_bound: u64,
    /// CDHZ Appendix A.1 offline query-set bound `qPi` for zero implicit
    /// instance dimensions.
    pub(crate) theorem_offline_query_set_bound: u64,
    /// Theorem 8.3 specialized Merkle `q1` bound for this homogeneous binary
    /// Merkle family: `max_{sum qs_i <= qs} sum_i qs_i * log2(lmax)`.
    pub(crate) theorem_q1_bound: u64,
    /// Theorem 8.3 specialized full-check `q2` bound for this homogeneous
    /// binary Merkle family: `max_i qVC_i(lp_i, lp_i) = lmax`.
    pub(crate) theorem_q2_bound: u64,
    pub(crate) maximum_leaf_value_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactEmittedCdhzRound {
    pub(crate) ordinal: u32,
    pub(crate) proof_vector_symbol_length: u64,
    pub(crate) observed_query_count: u64,
    pub(crate) geometry_query_count_bound: u64,
    pub(crate) observed_frontier_node_count: u64,
    pub(crate) observed_frontier_dictionary_entry_count: u64,
    pub(crate) observed_parent_hash_query_count: u64,
    pub(crate) geometry_parent_hash_query_bound: u64,
    pub(crate) emitted_response_byte_length: u64,
    pub(crate) emitted_answer_byte_length: u64,
    pub(crate) emitted_merkle_opening_byte_length: u64,
    pub(crate) fiat_shamir_message_byte_length: u64,
    pub(crate) concrete_fiat_shamir_hash_query_count: u64,
}

/// Physical calls made by the verifier through the compact construction's
/// one fixed-SHAKE256 graph. The logical Fiat-Shamir message, response
/// opening, and vector-commitment counts remain separate census coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactSharedHashGraphCensus {
    pub(crate) fiat_shamir_prefix_hash_count: u64,
    pub(crate) fixed_message_seed_hash_count: u64,
    pub(crate) fixed_message_block_hash_count: u64,
    pub(crate) opened_leaf_hash_count: u64,
    pub(crate) merkle_parent_hash_count: u64,
    pub(crate) total_hash_count: u64,
}

/// Census bound to the exact canonical proof/public-input pair held by the
/// decoded transport owner. It inventories the transported tuples and every
/// verifier consumer edge without claiming any CFW or WHIR equation holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactDecodedActualByteCensus {
    pub(crate) canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    pub(crate) prover_response_count: u64,
    pub(crate) verifier_message_count: u64,
    pub(crate) distinct_query_group_count: u64,
    pub(crate) distinct_query_group_element_count: u64,
    pub(crate) response_opening_tuple_count: u64,
    pub(crate) response_commitment_root_count: u64,
    pub(crate) internal_relation_commitment_count: u64,
    pub(crate) opened_leaf_count: u64,
    pub(crate) secret_leaf_salt_count: u64,
    pub(crate) round_salt_count: u64,
    pub(crate) frontier_node_count: u64,
    pub(crate) frontier_dictionary_entry_count: u64,
    pub(crate) verifier_response_consumer_edge_count: u64,
    pub(crate) verifier_query_group_consumer_edge_count: u64,
    pub(crate) transcript_public_input_length_absorption_count: u64,
    pub(crate) transcript_public_input_absorption_count: u64,
    pub(crate) transcript_commitment_identifier_absorption_count: u64,
    pub(crate) transcript_commitment_root_absorption_count: u64,
    pub(crate) transcript_round_salt_absorption_count: u64,
    pub(crate) shared_hash_graph: CompactSharedHashGraphCensus,
}

impl CompactEmittedCdhzRound {
    fn observed_vector_commitment_check_query_count(&self) -> Result<u64, CompactEmittedCdhzError> {
        self.observed_query_count
            .checked_add(self.observed_parent_hash_query_count)
            .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)
    }

    fn geometry_vector_commitment_check_query_bound(&self) -> Result<u64, CompactEmittedCdhzError> {
        self.geometry_query_count_bound
            .checked_add(self.geometry_parent_hash_query_bound)
            .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)
    }
}

/// Exact emitted-byte census. This is evidence about one canonical transport,
/// not a semantic, masking, Merkle-privacy, or oracle-assumption certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactEmittedCdhzMeasurement {
    pub(crate) canonical_proof_byte_length: u64,
    pub(crate) canonical_public_input_byte_length: u64,
    pub(crate) explicit_public_input_field_element_count: u64,
    /// Number of transported prover-response commitment roots.
    pub(crate) response_vector_commitment_count: u64,
    /// Emission-specific `sum_i |Q^p_i|`, following IOR Definition 6.4's
    /// proof-query coordinate used by CDHZ Appendix A.1.
    pub(crate) observed_proof_query_count: u64,
    /// CDHZ Appendix A.1 `qPi`, derived from every contract-owned response
    /// query-count range rather than a producer field. The emitted count above
    /// is evidence for this same coordinate; it is not substituted for the
    /// verifier's accepted worst-case bound.
    pub(crate) theorem_proof_query_bound: u64,
    /// CDHZ implicit-input query bound `qy`; zero because this compact contract has no
    /// implicit-instance vector-commitment registry.
    pub(crate) input_implicit_query_bound: u64,
    /// Diagnostic compound-oracle counts. These are not the CDHZ `qV`
    /// under the selected fixed-512-bit SHAKE QRO assumption.
    pub(crate) observed_logical_verifier_oracle_call_count: u64,
    pub(crate) logical_verifier_oracle_call_bound: u64,
    /// CDHZ `qV` after expanding the implementation's shared
    /// fixed-512-bit SHAKE QRO graph into one prefix query, seeded-stream
    /// seed/block queries, and response-Merkle leaf/parent queries.
    pub(crate) observed_nrdx_verifier_q_v: u64,
    pub(crate) nrdx_verifier_q_v_bound: u64,
    /// CDHZ `lmax = max_i lp_i`, in committed response-vector symbols.
    pub(crate) maximum_proof_vector_symbol_length: u64,
    pub(crate) emitted_answer_byte_length: u64,
    pub(crate) emitted_merkle_opening_byte_length: u64,
    pub(crate) decoded_actual_byte_census: CompactDecodedActualByteCensus,
    pub(crate) merkle_multi_extraction: CompactCdhzMerkleMultiExtractionTerms,
    pub(crate) oracle_family_census: CompactCdhzOracleFamilyCensus,
    pub(crate) random_oracle_domains: CompactCdhzRandomOracleDomains,
    pub(crate) rounds: Vec<CompactEmittedCdhzRound>,
}

/// Test-only raw-byte seam. It first verifies the canonical transport and then
/// measures the exact emitted-byte census.
#[cfg(test)]
pub(crate) fn measure_selected_compact_emission_cdhz(
    canonical_proof_bytes: Option<&[u8]>,
    canonical_public_input_bytes: Option<&[u8]>,
    expected_public_input_bindings: CompactPublicInputBindings,
) -> Result<CompactEmittedCdhzMeasurement, CompactEmittedCdhzError> {
    let canonical_proof_bytes =
        canonical_proof_bytes.ok_or(CompactEmittedCdhzError::MissingEmittedProof)?;
    let canonical_public_input_bytes =
        canonical_public_input_bytes.ok_or(CompactEmittedCdhzError::MissingEmittedPublicInput)?;
    let transport = verify_selected_compact_public_key_transport(
        expected_public_input_bindings,
        canonical_proof_bytes.to_vec().into_boxed_slice(),
        canonical_public_input_bytes.to_vec().into_boxed_slice(),
    )
    .map_err(CompactEmittedCdhzError::Transport)?;
    measure_verified_compact_emission_cdhz(&transport)
}

/// Measures one test transport whose schedule and salted openings have already
/// been verified. This remains a byte census rather than an algebraic,
/// masking, or semantic acceptance result.
#[cfg(test)]
pub(crate) fn measure_verified_compact_emission_cdhz(
    transport: &VerifiedCompactPublicKeyTransport,
) -> Result<CompactEmittedCdhzMeasurement, CompactEmittedCdhzError> {
    let verifier_inputs = transport.verifier_inputs();
    let proof = transport.proof_view();
    let public_input = transport.public_input_view();
    let response_count = verifier_inputs.proof_wire_geometry.responses().len();
    if response_count == 0
        || proof.decoded().responses().len() != response_count
        || verifier_inputs.response_merkle_geometries.len() != response_count
        || verifier_inputs.verifier_moves.len() != response_count
        || transport.verifier_messages().len() != response_count
    {
        return Err(CompactEmittedCdhzError::InvalidCensus);
    }

    let mut rounds = Vec::new();
    rounds
        .try_reserve_exact(response_count)
        .map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)?;
    let mut observed_proof_query_count = 0_u64;
    let mut theorem_proof_query_bound = 0_u64;
    let mut observed_merkle_check_query_count = 0_u64;
    let mut observed_merkle_parent_hash_query_count = 0_u64;
    let mut geometry_merkle_check_query_bound = 0_u64;
    let mut concrete_fiat_shamir_hash_query_count = 0_u64;
    let mut fixed_message_hash_query_count = 0_u64;
    let mut maximum_proof_vector_symbol_length = 0_u64;
    let mut maximum_leaf_value_byte_length = 0_u64;
    let mut emitted_answer_byte_length = 0_u64;
    let mut emitted_merkle_opening_byte_length = 0_u64;
    let mut frontier_node_count = 0_u64;
    let mut frontier_dictionary_entry_count = 0_u64;
    let mut verifier_query_group_consumer_edge_count = 0_u64;
    let mut transcript_commitment_absorption_count = 0_u64;

    for response_index in 0..response_count {
        let decoded_response = &proof.decoded().responses()[response_index];
        let wire_geometry = &verifier_inputs.proof_wire_geometry.responses()[response_index];
        let merkle_geometry = &verifier_inputs.response_merkle_geometries[response_index];
        let verifier_move = &verifier_inputs.verifier_moves[response_index];
        if usize::try_from(decoded_response.ordinal()).ok() != Some(response_index)
            || decoded_response.ordinal() != wire_geometry.ordinal()
            || decoded_response.ordinal() != merkle_geometry.response_ordinal()
            || decoded_response.ordinal() != verifier_move.ordinal
            || decoded_response.queried_leaf_count() == 0
        {
            return Err(CompactEmittedCdhzError::InvalidCensus);
        }

        // The transport terminal already derived this response's unique query
        // schedule and verified the exact minimal frontier against it. The
        // census consumes the verified counts and does not retain or rederive
        // all 82 schedules.
        let observed_query_count = u64_from_usize(decoded_response.queried_leaf_count())?;
        let geometry_query_count_bound = wire_geometry.maximum_queried_leaf_count();
        let observed_frontier_node_count = u64_from_usize(decoded_response.frontier_node_count())?;
        let observed_parent_hash_query_count = observed_query_count
            .checked_add(observed_frontier_node_count)
            .and_then(|count| count.checked_sub(1))
            .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?;
        let geometry_parent_hash_query_bound = maximum_parent_hash_query_bound(
            merkle_geometry.merkle_leaf_count(),
            wire_geometry.minimum_queried_leaf_count(),
            wire_geometry.maximum_queried_leaf_count(),
        )?;
        let fiat_shamir_message_byte_length = u64::try_from(
            wire_geometry
                .verifier_message_geometry()
                .exact_message_byte_length()
                .map_err(|_| CompactEmittedCdhzError::InvalidCensus)?,
        )
        .map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)?;
        let round_fixed_message_hash_query_count = wire_geometry
            .verifier_message_geometry()
            .concrete_hash_query_count()
            .map_err(|_| CompactEmittedCdhzError::InvalidCensus)?;
        // `compact_fiat_shamir_round_prefix_digest` is one fixed-output SHAKE
        // query. The fixed-message owner separately counts its seed and every
        // predecessor-linked 512-bit block query. The CDHZ reduction defines
        // qV as verifier query complexity, so the compound logical round is
        // not substituted for this concrete shared-QRO census.
        let round_fiat_shamir_hash_query_count = round_fixed_message_hash_query_count
            .checked_add(1)
            .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?;
        let proof_vector_symbol_length = merkle_geometry.merkle_leaf_count();
        let round = CompactEmittedCdhzRound {
            ordinal: decoded_response.ordinal(),
            proof_vector_symbol_length,
            observed_query_count,
            geometry_query_count_bound,
            observed_frontier_node_count,
            observed_frontier_dictionary_entry_count: u64_from_usize(
                decoded_response.frontier_dictionary_count(),
            )?,
            observed_parent_hash_query_count,
            geometry_parent_hash_query_bound,
            emitted_response_byte_length: u64_from_usize(decoded_response.canonical_byte_length())?,
            emitted_answer_byte_length: u64_from_usize(decoded_response.answer_byte_length())?,
            emitted_merkle_opening_byte_length: u64_from_usize(
                decoded_response.merkle_opening_byte_length(),
            )?,
            fiat_shamir_message_byte_length,
            concrete_fiat_shamir_hash_query_count: round_fiat_shamir_hash_query_count,
        };

        observed_proof_query_count =
            checked_add(observed_proof_query_count, round.observed_query_count)?;
        theorem_proof_query_bound =
            checked_add(theorem_proof_query_bound, round.geometry_query_count_bound)?;
        observed_merkle_check_query_count = checked_add(
            observed_merkle_check_query_count,
            round.observed_vector_commitment_check_query_count()?,
        )?;
        observed_merkle_parent_hash_query_count = checked_add(
            observed_merkle_parent_hash_query_count,
            round.observed_parent_hash_query_count,
        )?;
        geometry_merkle_check_query_bound = checked_add(
            geometry_merkle_check_query_bound,
            round.geometry_vector_commitment_check_query_bound()?,
        )?;
        concrete_fiat_shamir_hash_query_count = checked_add(
            concrete_fiat_shamir_hash_query_count,
            round.concrete_fiat_shamir_hash_query_count,
        )?;
        fixed_message_hash_query_count = checked_add(
            fixed_message_hash_query_count,
            round_fixed_message_hash_query_count,
        )?;
        emitted_answer_byte_length =
            checked_add(emitted_answer_byte_length, round.emitted_answer_byte_length)?;
        emitted_merkle_opening_byte_length = checked_add(
            emitted_merkle_opening_byte_length,
            round.emitted_merkle_opening_byte_length,
        )?;
        maximum_proof_vector_symbol_length =
            maximum_proof_vector_symbol_length.max(proof_vector_symbol_length);
        maximum_leaf_value_byte_length = maximum_leaf_value_byte_length.max(
            maximum_response_leaf_value_byte_length(merkle_geometry.components())?,
        );
        frontier_node_count = checked_add(frontier_node_count, round.observed_frontier_node_count)?;
        frontier_dictionary_entry_count = checked_add(
            frontier_dictionary_entry_count,
            round.observed_frontier_dictionary_entry_count,
        )?;
        verifier_query_group_consumer_edge_count = checked_add(
            verifier_query_group_consumer_edge_count,
            merkle_geometry.components().iter().try_fold(
                0_u64,
                |consumer_edge_count, component| {
                    checked_add(
                        consumer_edge_count,
                        query_selection_consumer_edge_count(component.query_selection()),
                    )
                },
            )?,
        )?;
        transcript_commitment_absorption_count = checked_add(
            transcript_commitment_absorption_count,
            u64::try_from(response_index)
                .map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)?
                .checked_add(1)
                .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?,
        )?;
        rounds.push(round);
    }

    if observed_proof_query_count > theorem_proof_query_bound
        || maximum_proof_vector_symbol_length == 0
        || maximum_leaf_value_byte_length == 0
    {
        return Err(CompactEmittedCdhzError::InvalidCensus);
    }
    let ior_round_count = u64_from_usize(rounds.len())?;
    if fixed_message_hash_query_count < ior_round_count {
        return Err(CompactEmittedCdhzError::InvalidCensus);
    }
    let fixed_message_block_hash_count = fixed_message_hash_query_count
        .checked_sub(ior_round_count)
        .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?;
    let observed_logical_verifier_oracle_call_count =
        checked_add(ior_round_count, observed_merkle_check_query_count)?;
    let logical_verifier_oracle_call_bound =
        checked_add(ior_round_count, geometry_merkle_check_query_bound)?;
    let observed_nrdx_verifier_q_v = checked_add(
        concrete_fiat_shamir_hash_query_count,
        observed_merkle_check_query_count,
    )?;
    let nrdx_verifier_q_v_bound = checked_add(
        concrete_fiat_shamir_hash_query_count,
        geometry_merkle_check_query_bound,
    )?;
    let theorem_q1_bound = theorem_proof_query_bound
        .checked_mul(u64::from(maximum_proof_vector_symbol_length.ilog2()))
        .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?;
    let accounted_proof_byte_length = rounds.iter().try_fold(
        u64_from_usize(PROOF_FIXED_HEADER_BYTE_LENGTH)?,
        |byte_length, round| checked_add(byte_length, round.emitted_response_byte_length),
    )?;
    if accounted_proof_byte_length != u64_from_usize(proof.canonical_bytes().len())? {
        return Err(CompactEmittedCdhzError::InvalidCensus);
    }

    let distinct_query_group_count =
        transport
            .verifier_messages()
            .iter()
            .try_fold(0_u64, |count, message| {
                checked_add(
                    count,
                    u64_from_usize(message.distinct_query_groups().len())?,
                )
            })?;
    let distinct_query_group_element_count =
        transport
            .verifier_messages()
            .iter()
            .try_fold(0_u64, |message_total, message| {
                message
                    .distinct_query_groups()
                    .iter()
                    .try_fold(message_total, |group_total, group| {
                        checked_add(group_total, u64_from_usize(group.len())?)
                    })
            })?;
    let internal_relation_commitment_count = verifier_inputs
        .verifier_moves
        .iter()
        .map(|verifier_move| u64::from(verifier_move.preceding_commitment_count))
        .max()
        .ok_or(CompactEmittedCdhzError::InvalidCensus)?;
    let shared_hash_graph_total = concrete_fiat_shamir_hash_query_count
        .checked_add(observed_merkle_check_query_count)
        .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?;

    let measurement = CompactEmittedCdhzMeasurement {
        canonical_proof_byte_length: u64_from_usize(proof.canonical_bytes().len())?,
        canonical_public_input_byte_length: u64_from_usize(public_input.canonical_bytes().len())?,
        explicit_public_input_field_element_count: u64_from_usize(
            public_input.decoded().field_element_count(),
        )?,
        response_vector_commitment_count: ior_round_count,
        observed_proof_query_count,
        theorem_proof_query_bound,
        input_implicit_query_bound: 0,
        observed_logical_verifier_oracle_call_count,
        logical_verifier_oracle_call_bound,
        observed_nrdx_verifier_q_v,
        nrdx_verifier_q_v_bound,
        maximum_proof_vector_symbol_length,
        emitted_answer_byte_length,
        emitted_merkle_opening_byte_length,
        decoded_actual_byte_census: CompactDecodedActualByteCensus {
            canonical_proof_binding: compact_proof_transport_binding(proof.canonical_bytes()),
            canonical_public_input_binding: compact_public_input_transport_binding(
                public_input.canonical_bytes(),
            ),
            prover_response_count: ior_round_count,
            verifier_message_count: ior_round_count,
            distinct_query_group_count,
            distinct_query_group_element_count,
            response_opening_tuple_count: ior_round_count,
            response_commitment_root_count: ior_round_count,
            internal_relation_commitment_count,
            opened_leaf_count: observed_proof_query_count,
            secret_leaf_salt_count: observed_proof_query_count,
            round_salt_count: ior_round_count,
            frontier_node_count,
            frontier_dictionary_entry_count,
            verifier_response_consumer_edge_count: ior_round_count,
            verifier_query_group_consumer_edge_count,
            transcript_public_input_length_absorption_count: ior_round_count,
            transcript_public_input_absorption_count: ior_round_count,
            transcript_commitment_identifier_absorption_count:
                transcript_commitment_absorption_count,
            transcript_commitment_root_absorption_count: transcript_commitment_absorption_count,
            transcript_round_salt_absorption_count: transcript_commitment_absorption_count,
            shared_hash_graph: CompactSharedHashGraphCensus {
                fiat_shamir_prefix_hash_count: ior_round_count,
                fixed_message_seed_hash_count: ior_round_count,
                fixed_message_block_hash_count,
                opened_leaf_hash_count: observed_proof_query_count,
                merkle_parent_hash_count: observed_merkle_parent_hash_query_count,
                total_hash_count: shared_hash_graph_total,
            },
        },
        merkle_multi_extraction: CompactCdhzMerkleMultiExtractionTerms {
            output_bit_length: CDHZ_MERKLE_OUTPUT_BIT_LENGTH,
            leaf_salt_bit_length: CDHZ_MERKLE_LEAF_SALT_BIT_LENGTH,
            vector_commitment_tuple_size: ior_round_count,
            input_implicit_instance_tuple_size: NO_IMPLICIT_INSTANCE_TUPLE_SIZE,
            output_implicit_instance_tuple_size: NO_IMPLICIT_INSTANCE_TUPLE_SIZE,
            observed_check_oracle_query_count: observed_merkle_check_query_count,
            geometry_check_oracle_query_bound: geometry_merkle_check_query_bound,
            theorem_offline_query_set_bound: theorem_proof_query_bound,
            theorem_q1_bound,
            theorem_q2_bound: maximum_proof_vector_symbol_length,
            maximum_leaf_value_byte_length,
        },
        oracle_family_census: CompactCdhzOracleFamilyCensus {
            fiat_shamir_oracle_count: ior_round_count,
            vector_commitment_oracle_count: ior_round_count,
            multi_extract_oracle_count: MULTI_EXTRACT_ORACLE_COUNT,
        },
        random_oracle_domains: CompactCdhzRandomOracleDomains {
            fiat_shamir_prefix: COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
            verifier_message_seed: FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN,
            verifier_message_block: FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN,
            merkle_leaf: COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
            merkle_parent: COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
        },
        rounds,
    };
    measurement.validate_internal_consistency()?;
    Ok(measurement)
}

impl CompactEmittedCdhzMeasurement {
    pub(super) fn validate_internal_consistency(&self) -> Result<(), CompactEmittedCdhzError> {
        let round_count = u64_from_usize(self.rounds.len())?;
        let observed_frontier_node_count = self.rounds.iter().try_fold(0_u64, |total, round| {
            checked_add(total, round.observed_frontier_node_count)
        })?;
        let observed_frontier_dictionary_entry_count =
            self.rounds.iter().try_fold(0_u64, |total, round| {
                checked_add(total, round.observed_frontier_dictionary_entry_count)
            })?;
        let observed_parent_hash_count = self.rounds.iter().try_fold(0_u64, |total, round| {
            checked_add(total, round.observed_parent_hash_query_count)
        })?;
        let concrete_fiat_shamir_hash_count =
            self.rounds.iter().try_fold(0_u64, |total, round| {
                checked_add(total, round.concrete_fiat_shamir_hash_query_count)
            })?;
        let expected_transcript_commitment_absorption_count = round_count
            .checked_mul(
                round_count
                    .checked_add(1)
                    .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_div(2))
            .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?;
        let census = &self.decoded_actual_byte_census;
        let hash_graph = &census.shared_hash_graph;
        let expected_hash_graph_total = hash_graph
            .fiat_shamir_prefix_hash_count
            .checked_add(hash_graph.fixed_message_seed_hash_count)
            .and_then(|count| count.checked_add(hash_graph.fixed_message_block_hash_count))
            .and_then(|count| count.checked_add(hash_graph.opened_leaf_hash_count))
            .and_then(|count| count.checked_add(hash_graph.merkle_parent_hash_count))
            .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?;
        if round_count == 0
            || census.prover_response_count != round_count
            || census.verifier_message_count != round_count
            || census.response_opening_tuple_count != round_count
            || census.response_commitment_root_count != round_count
            || census.opened_leaf_count != self.observed_proof_query_count
            || census.secret_leaf_salt_count != self.observed_proof_query_count
            || census.round_salt_count != round_count
            || census.frontier_node_count != observed_frontier_node_count
            || census.frontier_dictionary_entry_count != observed_frontier_dictionary_entry_count
            || census.verifier_response_consumer_edge_count != round_count
            || census.transcript_public_input_length_absorption_count != round_count
            || census.transcript_public_input_absorption_count != round_count
            || census.transcript_commitment_identifier_absorption_count
                != expected_transcript_commitment_absorption_count
            || census.transcript_commitment_root_absorption_count
                != expected_transcript_commitment_absorption_count
            || census.transcript_round_salt_absorption_count
                != expected_transcript_commitment_absorption_count
            || hash_graph.fiat_shamir_prefix_hash_count != round_count
            || hash_graph.fixed_message_seed_hash_count != round_count
            || hash_graph.opened_leaf_hash_count != self.observed_proof_query_count
            || hash_graph.merkle_parent_hash_count != observed_parent_hash_count
            || hash_graph
                .fiat_shamir_prefix_hash_count
                .checked_add(hash_graph.fixed_message_seed_hash_count)
                .and_then(|count| count.checked_add(hash_graph.fixed_message_block_hash_count))
                != Some(concrete_fiat_shamir_hash_count)
            || hash_graph.total_hash_count != expected_hash_graph_total
            || hash_graph.total_hash_count != self.observed_nrdx_verifier_q_v
        {
            return Err(CompactEmittedCdhzError::InvalidCensus);
        }
        Ok(())
    }
}

const fn query_selection_consumer_edge_count(selection: CompactResponseQuerySelection) -> u64 {
    match selection {
        CompactResponseQuerySelection::Unqueried | CompactResponseQuerySelection::EveryLeaf => 0,
        CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. } => 1,
        CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion { .. } => 2,
    }
}

fn maximum_parent_hash_query_bound(
    leaf_count: u64,
    minimum_query_count: u64,
    maximum_query_count: u64,
) -> Result<u64, CompactEmittedCdhzError> {
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || minimum_query_count == 0
        || minimum_query_count > maximum_query_count
        || maximum_query_count > leaf_count
    {
        return Err(CompactEmittedCdhzError::InvalidCensus);
    }
    let leaf_count =
        usize::try_from(leaf_count).map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)?;
    let maximum_query_count_usize = usize::try_from(maximum_query_count)
        .map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)?;
    // Adding one opened leaf can reduce a minimal frontier by at most one
    // node. Consequently `q + frontier(q) - 1` is nondecreasing, so the
    // range maximum is attained at the contract's maximum query count.
    let frontier_count = maximum_minimal_frontier_node_count(leaf_count, maximum_query_count_usize)
        .map_err(|_| CompactEmittedCdhzError::InvalidCensus)?;
    maximum_query_count
        .checked_add(u64_from_usize(frontier_count)?)
        .and_then(|count| count.checked_sub(1))
        .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)
}

fn maximum_response_leaf_value_byte_length(
    components: &[super::compact_response_merkle::CompactResponseComponentGeometry],
) -> Result<u64, CompactEmittedCdhzError> {
    components.iter().try_fold(0_u64, |maximum, component| {
        let coordinate_count = match component.value_kind() {
            CompactResponseLeafValueKind::BaseField => component.field_element_count_per_leaf(),
            CompactResponseLeafValueKind::ExtensionField => component
                .field_element_count_per_leaf()
                .checked_mul(
                    u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
                        .map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)?,
                )
                .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)?,
            CompactResponseLeafValueKind::Padding => 0,
        };
        coordinate_count
            .checked_mul(
                u64::try_from(size_of::<u64>())
                    .map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)?,
            )
            .map(|byte_length| maximum.max(byte_length))
            .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)
    })
}

fn checked_add(left: u64, right: u64) -> Result<u64, CompactEmittedCdhzError> {
    left.checked_add(right)
        .ok_or(CompactEmittedCdhzError::ArithmeticOverflow)
}

fn u64_from_usize(value: usize) -> Result<u64, CompactEmittedCdhzError> {
    u64::try_from(value).map_err(|_| CompactEmittedCdhzError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arbitrary_bindings() -> CompactPublicInputBindings {
        CompactPublicInputBindings::new(
            Hash512::from_bytes([1; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([2; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([3; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([4; Hash512::BYTE_LENGTH]),
        )
    }

    fn selected_relation_plan_bindings() -> CompactPublicInputBindings {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("selected compact proof contract");
        CompactPublicInputBindings::new(
            Hash512::from_bytes([1; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([2; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([3; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes(
                contract
                    .verifier_inputs()
                    .relation
                    .relation_plan_variant_hash(),
            ),
        )
    }

    #[test]
    fn absent_producer_outputs_fail_before_contract_arithmetic() {
        assert_eq!(
            measure_selected_compact_emission_cdhz(None, None, arbitrary_bindings()),
            Err(CompactEmittedCdhzError::MissingEmittedProof)
        );
        assert_eq!(
            measure_selected_compact_emission_cdhz(Some(&[]), None, arbitrary_bindings()),
            Err(CompactEmittedCdhzError::MissingEmittedPublicInput)
        );
    }

    #[test]
    fn present_empty_outputs_refuse_wrong_context_before_wire_decoding() {
        assert_eq!(
            measure_selected_compact_emission_cdhz(Some(&[]), Some(&[]), arbitrary_bindings()),
            Err(CompactEmittedCdhzError::Transport(
                CompactPublicKeyTransportError::InvalidResponseRegistry
            ))
        );
    }

    #[test]
    fn present_empty_outputs_with_selected_context_report_proof_wire_truncation() {
        assert!(matches!(
            measure_selected_compact_emission_cdhz(
                Some(&[]),
                Some(&[]),
                selected_relation_plan_bindings()
            ),
            Err(CompactEmittedCdhzError::Transport(
                CompactPublicKeyTransportError::Wire(CompactProofWireError::Truncated)
            ))
        ));
    }

    #[test]
    fn parent_hash_bound_uses_query_range_and_tree_geometry() {
        assert_eq!(maximum_parent_hash_query_bound(8, 3, 3), Ok(6));
        assert_eq!(maximum_parent_hash_query_bound(8, 3, 8), Ok(7));
        assert_eq!(
            maximum_parent_hash_query_bound(8, 0, 1),
            Err(CompactEmittedCdhzError::InvalidCensus)
        );
    }

    #[test]
    fn response_roots_and_internal_commitments_are_distinct_contract_coordinates() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("selected compact proof contract");
        let inputs = contract.verifier_inputs();
        let response_root_count = inputs.proof_wire_geometry.responses().len();
        let response_opening_tuple_count = inputs
            .proof_wire_geometry
            .responses()
            .iter()
            .filter(|response| response.minimum_queried_leaf_count() > 0)
            .count();
        let internal_commitment_count = inputs
            .verifier_moves
            .iter()
            .map(|verifier_move| verifier_move.preceding_commitment_count)
            .max()
            .expect("non-empty verifier chronology");
        let outer_vector_commitment_oracle_count = inputs
            .response_merkle_geometries
            .iter()
            .map(|geometry| geometry.vector_commitment_oracle_identifier())
            .collect::<std::collections::BTreeSet<_>>()
            .len();

        assert_eq!(response_root_count, 82);
        assert_eq!(response_root_count * Hash512::BYTE_LENGTH, 5_248);
        assert_eq!(response_opening_tuple_count, 82);
        assert_eq!(outer_vector_commitment_oracle_count, 82);
        assert_eq!(internal_commitment_count, 45);
        assert_ne!(response_root_count, internal_commitment_count as usize);
    }

    #[test]
    fn selected_contract_freezes_the_cdhz_query_and_length_coordinates() {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("selected compact proof contract");
        let inputs = contract.verifier_inputs();
        let mut q_pi = 0_u64;
        let mut merkle_check_bound = 0_u64;
        let mut concrete_fiat_shamir_calls = 0_u64;
        let mut l_max = 0_u64;
        let mut maximum_leaf_value_byte_length = 0_u64;
        let mut minimum_fiat_shamir_message_bit_length = u64::MAX;
        for (wire, merkle) in inputs
            .proof_wire_geometry
            .responses()
            .iter()
            .zip(inputs.response_merkle_geometries)
        {
            q_pi = checked_add(q_pi, wire.maximum_queried_leaf_count()).unwrap();
            let parent_bound = maximum_parent_hash_query_bound(
                merkle.merkle_leaf_count(),
                wire.minimum_queried_leaf_count(),
                wire.maximum_queried_leaf_count(),
            )
            .unwrap();
            merkle_check_bound = checked_add(
                merkle_check_bound,
                checked_add(wire.maximum_queried_leaf_count(), parent_bound).unwrap(),
            )
            .unwrap();
            concrete_fiat_shamir_calls = checked_add(
                concrete_fiat_shamir_calls,
                wire.verifier_message_geometry()
                    .concrete_hash_query_count()
                    .unwrap()
                    + 1,
            )
            .unwrap();
            minimum_fiat_shamir_message_bit_length = minimum_fiat_shamir_message_bit_length.min(
                u64::try_from(
                    wire.verifier_message_geometry()
                        .exact_message_byte_length()
                        .unwrap(),
                )
                .unwrap()
                    * 8,
            );
            l_max = l_max.max(merkle.merkle_leaf_count());
            maximum_leaf_value_byte_length = maximum_leaf_value_byte_length
                .max(maximum_response_leaf_value_byte_length(merkle.components()).unwrap());
        }

        assert_eq!(q_pi, 79_310);
        assert_eq!(merkle_check_bound, 248_467);
        assert_eq!(concrete_fiat_shamir_calls, 181_604);
        assert_eq!(concrete_fiat_shamir_calls + merkle_check_bound, 430_071);
        assert_eq!(l_max, 262_144);
        assert_eq!(q_pi * u64::from(l_max.ilog2()), 1_427_580);
        assert_eq!(maximum_leaf_value_byte_length, 5_120);
        assert_eq!(minimum_fiat_shamir_message_bit_length, 65_536);
    }
}
