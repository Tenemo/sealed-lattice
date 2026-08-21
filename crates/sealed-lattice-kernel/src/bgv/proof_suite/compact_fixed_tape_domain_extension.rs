//! Ideal-QRO domain-extension correspondence for the compact fixed tape.
//!
//! The selected graph is the simple domain extender
//! `block(prefix(transcript), geometry || blockOrdinal)`. This module binds the
//! complete source replay to that graph and instantiates the explicit
//! inequalities in Zhandry's simple-domain-extender proof conservatively. It
//! does not instantiate SHAKE256 or Keccak as a quantum random oracle, does not
//! establish emitted-byte zero knowledge, and cannot mint a runtime verifier
//! capability.

use std::{collections::BTreeSet, mem::size_of};

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::compact_emitted_cdhz::CompactEmittedCdhzMeasurement;
use super::compact_fixed_tape_source_correspondence::{
    CompactFixedTapeGraphModel, CompactFixedTapeSourceCorrespondence,
};
use super::compact_proof_contract::CompactPublicKeyProofContract;
use super::compact_response_merkle::{
    COMPACT_RESPONSE_LEAF_HASH_DOMAIN, COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
};
use super::compact_transcript::COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN;
use super::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN, FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION,
};
use crate::foundation::{
    CanonicalItem, CanonicalItemType, DECLARED_ADVERSARIAL_QUERY_BUDGET, Hash512,
    canonical_foundation_tuple_hash_preimage,
};

const SIMPLE_DOMAIN_EXTENSION_HOP_COUNT: u8 = 1;
const FIND_INPUT_COMMUTATION_TRACE_DISTANCE_COEFFICIENT: u64 = 24;
const INDISTINGUISHABILITY_COLLISION_HYBRID_COUNT: u64 = 2;
const INDISTINGUISHABILITY_FIND_INPUT_OPERATION_COUNT: u64 = 4;
const INDISTINGUISHABILITY_CONSTRUCTION_QUERY_EXPANSION_FACTOR: u64 = 3;
const CONSISTENCY_COLLISION_HYBRID_COUNT: u64 = 2;
const CONSISTENCY_FIND_INPUT_OPERATION_COUNT: u64 = 2;
const FIXED_HASH_OUTPUT_BIT_LENGTH: u16 = 512;
const DOMAIN_EXTENSION_DENOMINATOR_EXPONENT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactFixedTapeDomainExtensionError {
    ArithmeticOverflow,
    BindingMismatch,
    ContractMismatch,
    DomainMismatch,
    GraphModelMismatch,
    HashCountMismatch,
    InputDomainMismatch,
    OutputWidthMismatch,
    QueryBudgetMismatch,
    RoundGeometry { round_ordinal: u32 },
    TheoremConstantMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFixedTapeDomainExtensionCertificate {
    selected_contract_source_hash: Hash512,
    canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
    logical_round_count: u64,
    output_block_hash_count: u64,
    total_fixed_tape_byte_length: u64,
    total_component_output_byte_length: u64,
    discarded_component_tail_byte_length: u64,
    selected_second_input_count: u64,
    minimum_selected_block_preimage_byte_length: u64,
    maximum_selected_block_preimage_byte_length: u64,
    selected_fixed_register_bit_length: u64,
    adversarial_query_budget: u128,
    theorem_hop_count: u8,
    conservative_loss_coefficient: u64,
    domain_extension_loss_numerator: BigUint,
    domain_extension_loss_denominator: BigUint,
}

impl CompactFixedTapeDomainExtensionCertificate {
    pub(crate) const fn selected_contract_source_hash(&self) -> Hash512 {
        self.selected_contract_source_hash
    }

    pub(crate) const fn canonical_proof_binding(&self) -> &[u8; Hash512::BYTE_LENGTH] {
        &self.canonical_proof_binding
    }

    pub(crate) const fn canonical_public_input_binding(&self) -> &[u8; Hash512::BYTE_LENGTH] {
        &self.canonical_public_input_binding
    }

    pub(crate) const fn logical_round_count(&self) -> u64 {
        self.logical_round_count
    }

    pub(crate) const fn output_block_hash_count(&self) -> u64 {
        self.output_block_hash_count
    }

    pub(crate) const fn total_fixed_tape_byte_length(&self) -> u64 {
        self.total_fixed_tape_byte_length
    }

    pub(crate) const fn total_component_output_byte_length(&self) -> u64 {
        self.total_component_output_byte_length
    }

    pub(crate) const fn discarded_component_tail_byte_length(&self) -> u64 {
        self.discarded_component_tail_byte_length
    }

    pub(crate) const fn selected_second_input_count(&self) -> u64 {
        self.selected_second_input_count
    }

    pub(crate) const fn minimum_selected_block_preimage_byte_length(&self) -> u64 {
        self.minimum_selected_block_preimage_byte_length
    }

    pub(crate) const fn maximum_selected_block_preimage_byte_length(&self) -> u64 {
        self.maximum_selected_block_preimage_byte_length
    }

    pub(crate) const fn selected_fixed_register_bit_length(&self) -> u64 {
        self.selected_fixed_register_bit_length
    }

    pub(crate) const fn adversarial_query_budget(&self) -> u128 {
        self.adversarial_query_budget
    }

    pub(crate) const fn theorem_hop_count(&self) -> u8 {
        self.theorem_hop_count
    }

    pub(crate) const fn conservative_loss_coefficient(&self) -> u64 {
        self.conservative_loss_coefficient
    }

    pub(crate) const fn domain_extension_loss_parts(&self) -> (&BigUint, &BigUint) {
        (
            &self.domain_extension_loss_numerator,
            &self.domain_extension_loss_denominator,
        )
    }
}

#[derive(Clone, Copy)]
struct CompactFixedTapeDomainExtensionParameters {
    adversarial_query_budget: u128,
    theorem_hop_count: u8,
    find_input_commutation_trace_distance_coefficient: u64,
    indistinguishability_collision_hybrid_count: u64,
    indistinguishability_find_input_operation_count: u64,
    indistinguishability_construction_query_expansion_factor: u64,
    consistency_collision_hybrid_count: u64,
    consistency_find_input_operation_count: u64,
    fixed_hash_output_bit_length: u16,
}

impl CompactFixedTapeDomainExtensionParameters {
    const fn selected() -> Self {
        Self {
            adversarial_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            theorem_hop_count: SIMPLE_DOMAIN_EXTENSION_HOP_COUNT,
            find_input_commutation_trace_distance_coefficient:
                FIND_INPUT_COMMUTATION_TRACE_DISTANCE_COEFFICIENT,
            indistinguishability_collision_hybrid_count:
                INDISTINGUISHABILITY_COLLISION_HYBRID_COUNT,
            indistinguishability_find_input_operation_count:
                INDISTINGUISHABILITY_FIND_INPUT_OPERATION_COUNT,
            indistinguishability_construction_query_expansion_factor:
                INDISTINGUISHABILITY_CONSTRUCTION_QUERY_EXPANSION_FACTOR,
            consistency_collision_hybrid_count: CONSISTENCY_COLLISION_HYBRID_COUNT,
            consistency_find_input_operation_count: CONSISTENCY_FIND_INPUT_OPERATION_COUNT,
            fixed_hash_output_bit_length: FIXED_HASH_OUTPUT_BIT_LENGTH,
        }
    }
}

pub(crate) fn derive_source_verified_compact_fixed_tape_domain_extension(
    correspondence: &CompactFixedTapeSourceCorrespondence,
    measurement: &CompactEmittedCdhzMeasurement,
) -> Result<CompactFixedTapeDomainExtensionCertificate, CompactFixedTapeDomainExtensionError> {
    measurement
        .validate_internal_consistency()
        .map_err(|_| CompactFixedTapeDomainExtensionError::BindingMismatch)?;
    let census = &measurement.decoded_actual_byte_census;
    if correspondence.canonical_proof_binding != census.canonical_proof_binding
        || correspondence.canonical_public_input_binding != census.canonical_public_input_binding
        || correspondence.logical_round_count != measurement.response_vector_commitment_count
        || correspondence.prefix_hash_count
            != census.shared_hash_graph.fiat_shamir_prefix_hash_count
        || correspondence.output_block_hash_count
            != census.shared_hash_graph.fixed_message_block_hash_count
        || correspondence.prefix_domain != measurement.random_oracle_domains.fiat_shamir_prefix
        || correspondence.block_domain != measurement.random_oracle_domains.verifier_message_block
    {
        return Err(CompactFixedTapeDomainExtensionError::BindingMismatch);
    }

    derive_compact_fixed_tape_domain_extension(
        correspondence,
        CompactFixedTapeDomainExtensionParameters::selected(),
    )
}

fn derive_compact_fixed_tape_domain_extension(
    correspondence: &CompactFixedTapeSourceCorrespondence,
    parameters: CompactFixedTapeDomainExtensionParameters,
) -> Result<CompactFixedTapeDomainExtensionCertificate, CompactFixedTapeDomainExtensionError> {
    validate_selected_parameters(parameters)?;
    if correspondence.graph_model
        != CompactFixedTapeGraphModel::TranscriptPrefixThenIndependentBlocks
    {
        return Err(CompactFixedTapeDomainExtensionError::GraphModelMismatch);
    }
    if correspondence.prefix_domain != COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN
        || correspondence.block_domain != FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN
        || correspondence.geometry_version != FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION
    {
        return Err(CompactFixedTapeDomainExtensionError::DomainMismatch);
    }
    let domains = [
        correspondence.prefix_domain,
        correspondence.block_domain,
        COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
        COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
    ];
    for (left_index, left) in domains.iter().enumerate() {
        if domains[left_index + 1..].contains(left) {
            return Err(CompactFixedTapeDomainExtensionError::DomainMismatch);
        }
    }
    let domain_separation_probe = [CanonicalItem::unsigned8(0)];
    let domain_preimages = domains
        .iter()
        .map(|domain| canonical_foundation_tuple_hash_preimage(domain, &domain_separation_probe))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CompactFixedTapeDomainExtensionError::DomainMismatch)?;
    for (left_index, left) in domain_preimages.iter().enumerate() {
        if domain_preimages[left_index + 1..]
            .iter()
            .any(|right| left.as_slice() == right.as_slice())
        {
            return Err(CompactFixedTapeDomainExtensionError::DomainMismatch);
        }
    }
    if correspondence.fixed_hash_output_bit_length != FIXED_HASH_OUTPUT_BIT_LENGTH {
        return Err(CompactFixedTapeDomainExtensionError::OutputWidthMismatch);
    }

    let selected_contract = CompactPublicKeyProofContract::decode_selected()
        .map_err(|_| CompactFixedTapeDomainExtensionError::ContractMismatch)?;
    let verifier_inputs = selected_contract.verifier_inputs();
    let selected_contract_source_hash = verifier_inputs
        .canonical_source_hash()
        .map_err(|_| CompactFixedTapeDomainExtensionError::ContractMismatch)?;
    if correspondence.selected_contract_source_hash != selected_contract_source_hash {
        return Err(CompactFixedTapeDomainExtensionError::ContractMismatch);
    }
    let responses = verifier_inputs.proof_wire_geometry.responses();
    if correspondence.rounds.len() != responses.len()
        || u64::try_from(responses.len()).ok() != Some(correspondence.logical_round_count)
        || correspondence.prefix_hash_count != correspondence.logical_round_count
    {
        return Err(CompactFixedTapeDomainExtensionError::HashCountMismatch);
    }

    let mut output_block_hash_count = 0_u64;
    let mut total_fixed_tape_byte_length = 0_u64;
    let mut total_component_output_byte_length = 0_u64;
    let mut maximum_output_block_count_per_round = 0_u64;
    let mut selected_second_input_preimages = BTreeSet::new();
    let mut minimum_selected_block_preimage_byte_length = None;
    let mut maximum_selected_block_preimage_byte_length = 0_u64;
    for (round_index, (round, response)) in correspondence.rounds.iter().zip(responses).enumerate()
    {
        let round_ordinal = u32::try_from(round_index)
            .map_err(|_| CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
        let geometry = response.verifier_message_geometry();
        let message_byte_length = geometry
            .exact_message_byte_length_u64()
            .map_err(|_| CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal })?;
        let output_block_count = message_byte_length
            .checked_add(Hash512::BYTE_LENGTH as u64 - 1)
            .and_then(|rounded| rounded.checked_div(Hash512::BYTE_LENGTH as u64))
            .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
        if round.round_ordinal != round_ordinal
            || response.ordinal() != round_ordinal
            || round.message_byte_length != message_byte_length
            || round.output_block_count != output_block_count
        {
            return Err(CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal });
        }

        let geometry_items = geometry
            .canonical_hash_prefix_items(
                Hash512::from_bytes(round.transcript_prefix_digest),
                round_ordinal,
            )
            .map_err(|_| CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal })?;
        if geometry_items.len()
            != 10_usize
                .checked_add(
                    geometry
                        .distinct_query_groups()
                        .len()
                        .checked_mul(2)
                        .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?,
                )
                .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?
            || geometry_items.first().map(|item| item.item_type())
                != Some(CanonicalItemType::Hash512)
            || geometry_items.get(1).map(|item| item.item_type())
                != Some(CanonicalItemType::Unsigned16)
            || geometry_items.get(2).map(|item| item.item_type())
                != Some(CanonicalItemType::Unsigned32)
            || geometry_items.get(3).map(|item| item.item_type())
                != Some(CanonicalItemType::Unsigned32)
            || geometry_items[4..]
                .iter()
                .any(|item| item.item_type() != CanonicalItemType::Unsigned64)
        {
            return Err(CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal });
        }
        let mut first_block_items = geometry_items;
        first_block_items.push(CanonicalItem::unsigned64(message_byte_length));
        first_block_items.push(CanonicalItem::unsigned64(0));
        if first_block_items[first_block_items.len() - 2..]
            .iter()
            .any(|item| item.item_type() != CanonicalItemType::Unsigned64)
            || canonical_foundation_tuple_hash_preimage(
                correspondence.block_domain,
                &first_block_items,
            )
            .is_err()
        {
            return Err(CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal });
        }

        // The theorem's second input is a finite selected catalog. Replacing
        // the first item by one common 512-bit value isolates that catalog from
        // the first-oracle output. Canonical framing must then remain injective
        // across every selected (round, block) slot. Any finite adversary
        // circuit embeds the resulting variable-length raw inputs into one
        // fixed register as `u32(length) || bytes || zero-padding`.
        let mut selected_second_input_items = geometry
            .canonical_hash_prefix_items(
                Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
                round_ordinal,
            )
            .map_err(|_| CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal })?;
        selected_second_input_items.push(CanonicalItem::unsigned64(message_byte_length));
        selected_second_input_items.push(CanonicalItem::unsigned64(0));

        let mut covered_message_byte_length = 0_u64;
        for block_ordinal in 0..output_block_count {
            let component_start = block_ordinal
                .checked_mul(Hash512::BYTE_LENGTH as u64)
                .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
            if component_start != covered_message_byte_length {
                return Err(CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal });
            }
            let remaining_byte_length = message_byte_length
                .checked_sub(component_start)
                .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
            covered_message_byte_length = covered_message_byte_length
                .checked_add(remaining_byte_length.min(Hash512::BYTE_LENGTH as u64))
                .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;

            let block_ordinal_item = selected_second_input_items
                .last_mut()
                .ok_or(CompactFixedTapeDomainExtensionError::InputDomainMismatch)?;
            *block_ordinal_item = CanonicalItem::unsigned64(block_ordinal);
            let canonical_preimage = canonical_foundation_tuple_hash_preimage(
                correspondence.block_domain,
                &selected_second_input_items,
            )
            .map_err(|_| CompactFixedTapeDomainExtensionError::InputDomainMismatch)?;
            let preimage_byte_length = u64::try_from(canonical_preimage.len())
                .map_err(|_| CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
            minimum_selected_block_preimage_byte_length = Some(
                minimum_selected_block_preimage_byte_length
                    .map_or(preimage_byte_length, |minimum: u64| {
                        minimum.min(preimage_byte_length)
                    }),
            );
            maximum_selected_block_preimage_byte_length =
                maximum_selected_block_preimage_byte_length.max(preimage_byte_length);
            if !selected_second_input_preimages.insert(canonical_preimage.as_slice().to_vec()) {
                return Err(CompactFixedTapeDomainExtensionError::InputDomainMismatch);
            }
        }
        if covered_message_byte_length != message_byte_length {
            return Err(CompactFixedTapeDomainExtensionError::RoundGeometry { round_ordinal });
        }

        output_block_hash_count = output_block_hash_count
            .checked_add(output_block_count)
            .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
        total_fixed_tape_byte_length = total_fixed_tape_byte_length
            .checked_add(message_byte_length)
            .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
        total_component_output_byte_length = total_component_output_byte_length
            .checked_add(
                output_block_count
                    .checked_mul(Hash512::BYTE_LENGTH as u64)
                    .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?,
            )
            .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
        maximum_output_block_count_per_round =
            maximum_output_block_count_per_round.max(output_block_count);
    }
    if output_block_hash_count != correspondence.output_block_hash_count
        || total_fixed_tape_byte_length != correspondence.total_fixed_tape_byte_length
        || maximum_output_block_count_per_round
            != correspondence.maximum_output_block_count_per_round
    {
        return Err(CompactFixedTapeDomainExtensionError::HashCountMismatch);
    }
    let selected_second_input_count = u64::try_from(selected_second_input_preimages.len())
        .map_err(|_| CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
    if selected_second_input_count != output_block_hash_count {
        return Err(CompactFixedTapeDomainExtensionError::InputDomainMismatch);
    }
    let minimum_selected_block_preimage_byte_length =
        minimum_selected_block_preimage_byte_length
            .ok_or(CompactFixedTapeDomainExtensionError::InputDomainMismatch)?;
    let selected_fixed_register_bit_length = maximum_selected_block_preimage_byte_length
        .checked_add(size_of::<u32>() as u64)
        .and_then(|byte_length| byte_length.checked_mul(u64::from(u8::BITS)))
        .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;

    let (
        conservative_loss_coefficient,
        domain_extension_loss_numerator,
        domain_extension_loss_denominator,
    ) = derive_domain_extension_loss(parameters)?;

    Ok(CompactFixedTapeDomainExtensionCertificate {
        selected_contract_source_hash,
        canonical_proof_binding: correspondence.canonical_proof_binding,
        canonical_public_input_binding: correspondence.canonical_public_input_binding,
        logical_round_count: correspondence.logical_round_count,
        output_block_hash_count,
        total_fixed_tape_byte_length,
        total_component_output_byte_length,
        discarded_component_tail_byte_length: total_component_output_byte_length
            .checked_sub(total_fixed_tape_byte_length)
            .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?,
        selected_second_input_count,
        minimum_selected_block_preimage_byte_length,
        maximum_selected_block_preimage_byte_length,
        selected_fixed_register_bit_length,
        adversarial_query_budget: parameters.adversarial_query_budget,
        theorem_hop_count: parameters.theorem_hop_count,
        conservative_loss_coefficient,
        domain_extension_loss_numerator,
        domain_extension_loss_denominator,
    })
}

pub(crate) fn selected_compact_fixed_tape_domain_extension_loss_for_arithmetic_fixture()
-> Result<(BigUint, BigUint), CompactFixedTapeDomainExtensionError> {
    let (_, numerator, denominator) =
        derive_domain_extension_loss(CompactFixedTapeDomainExtensionParameters::selected())?;
    Ok((numerator, denominator))
}

fn validate_selected_parameters(
    parameters: CompactFixedTapeDomainExtensionParameters,
) -> Result<(), CompactFixedTapeDomainExtensionError> {
    if parameters.adversarial_query_budget != DECLARED_ADVERSARIAL_QUERY_BUDGET {
        return Err(CompactFixedTapeDomainExtensionError::QueryBudgetMismatch);
    }
    if parameters.theorem_hop_count != SIMPLE_DOMAIN_EXTENSION_HOP_COUNT
        || parameters.find_input_commutation_trace_distance_coefficient
            != FIND_INPUT_COMMUTATION_TRACE_DISTANCE_COEFFICIENT
        || parameters.indistinguishability_collision_hybrid_count
            != INDISTINGUISHABILITY_COLLISION_HYBRID_COUNT
        || parameters.indistinguishability_find_input_operation_count
            != INDISTINGUISHABILITY_FIND_INPUT_OPERATION_COUNT
        || parameters.indistinguishability_construction_query_expansion_factor
            != INDISTINGUISHABILITY_CONSTRUCTION_QUERY_EXPANSION_FACTOR
        || parameters.consistency_collision_hybrid_count != CONSISTENCY_COLLISION_HYBRID_COUNT
        || parameters.consistency_find_input_operation_count
            != CONSISTENCY_FIND_INPUT_OPERATION_COUNT
    {
        return Err(CompactFixedTapeDomainExtensionError::TheoremConstantMismatch);
    }
    if parameters.fixed_hash_output_bit_length != FIXED_HASH_OUTPUT_BIT_LENGTH {
        return Err(CompactFixedTapeDomainExtensionError::OutputWidthMismatch);
    }
    Ok(())
}

fn conservative_simple_domain_extension_loss_coefficient(
    parameters: CompactFixedTapeDomainExtensionParameters,
) -> Result<u64, CompactFixedTapeDomainExtensionError> {
    // Zhandry's Appendix B.5 makes each FindInput/StdDecomp interchange at
    // most `24 / sqrt(2^512)` apart. Lemma 11 performs at most four such
    // interchanges per query, while Lemma 14 performs two. Each of the two
    // collision-abort hybrids in both directions is at most
    // `sum_{i=0}^q sqrt(i / 2^512)`, conservatively bounded by
    // `q^2 / sqrt(2^512)` for `q >= 1`. Thus Lemma 8 contributes coefficient
    // `4 * 24 + 2 = 98` and Lemma 13 contributes `2 * 24 + 2 = 50`.
    // Lemma 6 constructs its Lemma-8 distinguisher by answering each domain-
    // extender query with two first-oracle calls and one second-oracle call,
    // so its query bound expands by three and the quadratic coefficient by
    // nine. The complete one-hop coefficient is therefore
    // `98 * 3^2 + 50 = 932`. This transcribes the explicit proof operations
    // conservatively instead of treating the paper's printed big-O notation
    // as a concrete constant.
    let direct_indistinguishability = parameters
        .indistinguishability_find_input_operation_count
        .checked_mul(parameters.find_input_commutation_trace_distance_coefficient)
        .and_then(|value| value.checked_add(parameters.indistinguishability_collision_hybrid_count))
        .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
    let transformed_indistinguishability = direct_indistinguishability
        .checked_mul(
            parameters
                .indistinguishability_construction_query_expansion_factor
                .checked_pow(2)
                .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?,
        )
        .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
    let direct_consistency = parameters
        .consistency_find_input_operation_count
        .checked_mul(parameters.find_input_commutation_trace_distance_coefficient)
        .and_then(|value| value.checked_add(parameters.consistency_collision_hybrid_count))
        .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)?;
    transformed_indistinguishability
        .checked_add(direct_consistency)
        .ok_or(CompactFixedTapeDomainExtensionError::ArithmeticOverflow)
}

fn derive_domain_extension_loss(
    parameters: CompactFixedTapeDomainExtensionParameters,
) -> Result<(u64, BigUint, BigUint), CompactFixedTapeDomainExtensionError> {
    validate_selected_parameters(parameters)?;
    let coefficient = conservative_simple_domain_extension_loss_coefficient(parameters)?;
    let unreduced_numerator =
        BigUint::from(coefficient) * BigUint::from(parameters.adversarial_query_budget).pow(2);
    let unreduced_denominator = BigUint::one() << DOMAIN_EXTENSION_DENOMINATOR_EXPONENT;
    let divisor =
        greatest_common_divisor(unreduced_numerator.clone(), unreduced_denominator.clone());
    let numerator = unreduced_numerator / &divisor;
    let denominator = unreduced_denominator / divisor;
    if numerator.is_zero() || numerator >= denominator {
        return Err(CompactFixedTapeDomainExtensionError::TheoremConstantMismatch);
    }
    Ok((coefficient, numerator, denominator))
}

fn greatest_common_divisor(mut left: BigUint, mut right: BigUint) -> BigUint {
    while !right.is_zero() {
        let remainder = left % &right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::super::compact_fixed_tape_source_correspondence::CompactFixedTapeRoundSourceCorrespondence;
    use super::*;

    fn selected_structure_correspondence() -> CompactFixedTapeSourceCorrespondence {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .expect("the selected compact contract decodes");
        let verifier_inputs = contract.verifier_inputs();
        let mut total_fixed_tape_byte_length = 0_u64;
        let mut output_block_hash_count = 0_u64;
        let mut maximum_output_block_count_per_round = 0_u64;
        let rounds = verifier_inputs
            .proof_wire_geometry
            .responses()
            .iter()
            .map(|response| {
                let message_byte_length = response
                    .verifier_message_geometry()
                    .exact_message_byte_length_u64()
                    .expect("selected message width derives");
                let output_block_count = message_byte_length.div_ceil(Hash512::BYTE_LENGTH as u64);
                total_fixed_tape_byte_length += message_byte_length;
                output_block_hash_count += output_block_count;
                maximum_output_block_count_per_round =
                    maximum_output_block_count_per_round.max(output_block_count);
                CompactFixedTapeRoundSourceCorrespondence {
                    round_ordinal: response.ordinal(),
                    transcript_prefix_digest: [response.ordinal() as u8; Hash512::BYTE_LENGTH],
                    message_byte_length,
                    output_block_count,
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let logical_round_count = u64::try_from(rounds.len()).unwrap();
        CompactFixedTapeSourceCorrespondence {
            selected_contract_source_hash: verifier_inputs
                .canonical_source_hash()
                .expect("selected contract source hash derives"),
            canonical_proof_binding: [0x31; Hash512::BYTE_LENGTH],
            canonical_public_input_binding: [0x32; Hash512::BYTE_LENGTH],
            graph_model: CompactFixedTapeGraphModel::TranscriptPrefixThenIndependentBlocks,
            prefix_domain: COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
            block_domain: FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN,
            geometry_version: FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION,
            fixed_hash_output_bit_length: FIXED_HASH_OUTPUT_BIT_LENGTH,
            logical_round_count,
            prefix_hash_count: logical_round_count,
            output_block_hash_count,
            total_fixed_tape_byte_length,
            maximum_output_block_count_per_round,
            rounds,
        }
    }

    #[test]
    fn selected_graph_maps_to_one_simple_domain_extension_with_exact_loss() {
        let correspondence = selected_structure_correspondence();
        let certificate = derive_compact_fixed_tape_domain_extension(
            &correspondence,
            CompactFixedTapeDomainExtensionParameters::selected(),
        )
        .expect("the selected graph matches the simple-domain-extender proof");
        assert_eq!(certificate.logical_round_count(), 82);
        assert_eq!(certificate.output_block_hash_count(), 181_440);
        assert_eq!(certificate.total_fixed_tape_byte_length(), 11_612_160);
        assert_eq!(certificate.theorem_hop_count(), 1);
        assert_eq!(certificate.conservative_loss_coefficient(), 932);
        assert_eq!(certificate.adversarial_query_budget(), (1_u128 << 80) - 1);
        assert_eq!(certificate.selected_second_input_count(), 181_440);
        assert_eq!(
            certificate.minimum_selected_block_preimage_byte_length(),
            288
        );
        assert_eq!(
            certificate.maximum_selected_block_preimage_byte_length(),
            596
        );
        assert_eq!(certificate.selected_fixed_register_bit_length(), 4_800);
        assert_eq!(
            certificate.total_component_output_byte_length()
                - certificate.discarded_component_tail_byte_length(),
            certificate.total_fixed_tape_byte_length(),
        );
        let (numerator, denominator) = certificate.domain_extension_loss_parts();
        assert_eq!(
            numerator,
            &(BigUint::from(233_u16) * BigUint::from((1_u128 << 80) - 1).pow(2))
        );
        assert_eq!(denominator, &(BigUint::one() << 254_usize));
    }

    #[test]
    fn every_graph_and_theorem_coordinate_is_load_bearing() {
        let selected = selected_structure_correspondence();
        let mutations: [fn(&mut CompactFixedTapeSourceCorrespondence); 11] = [
            |value| value.graph_model = CompactFixedTapeGraphModel::PredecessorLinkedBlocks,
            |value| value.prefix_domain = value.block_domain,
            |value| value.block_domain = COMPACT_RESPONSE_LEAF_HASH_DOMAIN,
            |value| value.geometry_version = value.geometry_version.wrapping_add(1),
            |value| value.fixed_hash_output_bit_length -= 1,
            |value| value.selected_contract_source_hash = Hash512::from_bytes([0x55; 64]),
            |value| value.prefix_hash_count -= 1,
            |value| value.output_block_hash_count -= 1,
            |value| value.total_fixed_tape_byte_length -= 1,
            |value| value.rounds[0].message_byte_length -= 1,
            |value| value.rounds[1].round_ordinal = 0,
        ];
        for mutate in mutations {
            let mut hostile = selected.clone();
            mutate(&mut hostile);
            assert!(
                derive_compact_fixed_tape_domain_extension(
                    &hostile,
                    CompactFixedTapeDomainExtensionParameters::selected(),
                )
                .is_err(),
            );
        }

        let parameter_mutations: [fn(&mut CompactFixedTapeDomainExtensionParameters); 9] = [
            |value| value.adversarial_query_budget -= 1,
            |value| value.theorem_hop_count += 1,
            |value| value.find_input_commutation_trace_distance_coefficient -= 1,
            |value| value.indistinguishability_collision_hybrid_count -= 1,
            |value| value.indistinguishability_find_input_operation_count -= 1,
            |value| value.indistinguishability_construction_query_expansion_factor -= 1,
            |value| value.consistency_collision_hybrid_count -= 1,
            |value| value.consistency_find_input_operation_count -= 1,
            |value| value.fixed_hash_output_bit_length -= 1,
        ];
        for mutate in parameter_mutations {
            let mut hostile = CompactFixedTapeDomainExtensionParameters::selected();
            mutate(&mut hostile);
            assert!(derive_compact_fixed_tape_domain_extension(&selected, hostile).is_err());
        }
    }
}
