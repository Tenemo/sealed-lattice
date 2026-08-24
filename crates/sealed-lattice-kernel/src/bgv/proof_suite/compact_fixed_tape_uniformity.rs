//! Direct verifier-randomness boundary for the compact Fiat-Shamir transcript.
//!
//! CDHZ models each verifier move as one independently sampled uniform bit
//! string whose width may depend on the round. The selected compact transcript
//! now makes exactly one fixed-width XOF call for each such `rnd_i` interface.
//! A source-verified correspondence certificate can therefore mint this test-
//! only ideal-QRO premise without a domain-extension hop. Bounded rejection
//! contributes its separate exact exhaustion term. The concrete shared
//! Keccak/SHAKE/KMAC reduction remains open and is not implied here.

use num_bigint::BigUint;
use num_traits::{CheckedSub, One, Zero};

use super::compact_emitted_cdhz::CompactEmittedCdhzMeasurement;
use super::compact_fixed_tape_source_correspondence::CompactFixedTapeSourceCorrespondence;
use super::compact_proof_contract::CompactPublicKeyProofContract;
use super::compact_response_merkle::{
    COMPACT_RESPONSE_LEAF_HASH_DOMAIN, COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
};
use super::compact_transcript::{
    COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_DOMAIN, COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_VERSION,
};
use super::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION, FixedUniformVerifierMessageGeometry,
};
use super::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
};
use crate::foundation::Hash512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactFixedTapeUniformityError {
    InvalidSelectedGeometry,
    ArithmeticOverflow,
    BindingMismatch,
    MeasurementMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactFixedTapeExactLoss {
    numerator: BigUint,
    denominator: BigUint,
}

impl CompactFixedTapeExactLoss {
    fn try_new(
        numerator: BigUint,
        denominator: BigUint,
    ) -> Result<Self, CompactFixedTapeUniformityError> {
        if denominator.is_zero() {
            return Err(CompactFixedTapeUniformityError::InvalidSelectedGeometry);
        }
        let divisor = greatest_common_divisor(numerator.clone(), denominator.clone());
        Ok(Self {
            numerator: numerator / &divisor,
            denominator: denominator / divisor,
        })
    }
}

/// Opaque test-only authority that maps every source-verified direct round-XOF
/// answer to the independent uniform verifier tape assumed by CDHZ Appendix
/// A.1 in the ideal-QRO model.
///
/// This remains development evidence and cannot authorize proof verification
/// or concrete SHAKE security reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFixedTapeUniformityPremise {
    round_geometries: Box<[FixedUniformVerifierMessageGeometry]>,
    minimum_uniform_message_bit_length: u64,
    source_verified_binding: Option<CompactFixedTapeSourceVerifiedBinding>,
    sampler_exhaustion_loss: CompactFixedTapeExactLoss,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactFixedTapeSourceVerifiedBinding {
    selected_contract_source_hash: Hash512,
    canonical_proof_binding: [u8; Hash512::BYTE_LENGTH],
    canonical_public_input_binding: [u8; Hash512::BYTE_LENGTH],
}

impl CompactFixedTapeUniformityPremise {
    pub(super) fn round_count(&self) -> usize {
        self.round_geometries.len()
    }

    /// CDHZ `r_min`: the minimum raw uniform verifier-message width before
    /// deterministic rejection decoding.
    pub(super) const fn minimum_uniform_message_bit_length(&self) -> u64 {
        self.minimum_uniform_message_bit_length
    }

    pub(super) const fn sampler_exhaustion_loss_parts(&self) -> (&BigUint, &BigUint) {
        (
            &self.sampler_exhaustion_loss.numerator,
            &self.sampler_exhaustion_loss.denominator,
        )
    }

    /// Recomputes every emitted round width and direct XOF-call count from the
    /// privately retained selected geometries. No measurement field can mint
    /// or strengthen this premise.
    pub(crate) fn validate_measurement(
        &self,
        measurement: &CompactEmittedCdhzMeasurement,
    ) -> Result<(), CompactFixedTapeUniformityError> {
        let round_count = self.round_geometries.len();
        if self
            .source_verified_binding
            .as_ref()
            .is_some_and(|binding| {
                CompactPublicKeyProofContract::decode_selected()
                    .ok()
                    .and_then(|contract| contract.verifier_inputs().canonical_source_hash().ok())
                    != Some(binding.selected_contract_source_hash)
                    || binding.canonical_proof_binding
                        != measurement
                            .decoded_actual_byte_census
                            .canonical_proof_binding
                    || binding.canonical_public_input_binding
                        != measurement
                            .decoded_actual_byte_census
                            .canonical_public_input_binding
            })
        {
            return Err(CompactFixedTapeUniformityError::MeasurementMismatch);
        }
        if measurement.rounds.len() != round_count
            || u64::try_from(round_count).ok() != Some(measurement.response_vector_commitment_count)
            || u64::try_from(round_count).ok()
                != Some(measurement.oracle_family_census.fiat_shamir_oracle_count)
            || measurement
                .random_oracle_domains
                .fiat_shamir_verifier_message
                != COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_DOMAIN
            || measurement.random_oracle_domains.merkle_leaf != COMPACT_RESPONSE_LEAF_HASH_DOMAIN
            || measurement.random_oracle_domains.merkle_parent
                != COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN
        {
            return Err(CompactFixedTapeUniformityError::MeasurementMismatch);
        }

        let mut minimum_bit_length = None;
        for (round_index, (geometry, round)) in self
            .round_geometries
            .iter()
            .zip(&measurement.rounds)
            .enumerate()
        {
            let expected_ordinal = u32::try_from(round_index)
                .map_err(|_| CompactFixedTapeUniformityError::ArithmeticOverflow)?;
            let expected_byte_length = geometry
                .exact_message_byte_length_u64()
                .map_err(|_| CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;
            let expected_bit_length = expected_byte_length
                .checked_mul(u64::from(u8::BITS))
                .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)?;
            if round.ordinal != expected_ordinal
                || round.fiat_shamir_message_byte_length != expected_byte_length
                || round.concrete_fiat_shamir_xof_call_count != 1
            {
                return Err(CompactFixedTapeUniformityError::MeasurementMismatch);
            }
            minimum_bit_length = Some(
                minimum_bit_length.map_or(expected_bit_length, |minimum: u64| {
                    minimum.min(expected_bit_length)
                }),
            );
        }
        if minimum_bit_length != Some(self.minimum_uniform_message_bit_length) {
            return Err(CompactFixedTapeUniformityError::MeasurementMismatch);
        }
        Ok(())
    }

    pub(crate) fn from_source_verified_correspondence(
        correspondence: &CompactFixedTapeSourceCorrespondence,
    ) -> Result<Self, CompactFixedTapeUniformityError> {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .map_err(|_| CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;
        let verifier_inputs = contract.verifier_inputs();
        if verifier_inputs
            .canonical_source_hash()
            .map_err(|_| CompactFixedTapeUniformityError::InvalidSelectedGeometry)?
            != correspondence.selected_contract_source_hash
            || correspondence.verifier_message_domain != COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_DOMAIN
            || correspondence.verifier_message_version
                != COMPACT_FIAT_SHAMIR_VERIFIER_MESSAGE_VERSION
            || correspondence.geometry_version != FIXED_UNIFORM_VERIFIER_MESSAGE_GEOMETRY_VERSION
            || correspondence.logical_round_count != correspondence.direct_xof_call_count
            || u64::try_from(verifier_inputs.proof_wire_geometry.responses().len()).ok()
                != Some(correspondence.logical_round_count)
            || correspondence.rounds.len() != verifier_inputs.proof_wire_geometry.responses().len()
        {
            return Err(CompactFixedTapeUniformityError::BindingMismatch);
        }
        for (response, round) in verifier_inputs
            .proof_wire_geometry
            .responses()
            .iter()
            .zip(&correspondence.rounds)
        {
            if response.ordinal() != round.round_ordinal
                || response
                    .verifier_message_geometry()
                    .exact_message_byte_length_u64()
                    .ok()
                    != Some(round.message_byte_length)
                || round.input_byte_length == 0
            {
                return Err(CompactFixedTapeUniformityError::BindingMismatch);
            }
        }
        let round_geometries = verifier_inputs
            .proof_wire_geometry
            .responses()
            .iter()
            .map(|response| response.verifier_message_geometry().clone())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self::from_selected_geometries(
            round_geometries,
            Some(CompactFixedTapeSourceVerifiedBinding {
                selected_contract_source_hash: correspondence.selected_contract_source_hash,
                canonical_proof_binding: correspondence.canonical_proof_binding,
                canonical_public_input_binding: correspondence.canonical_public_input_binding,
            }),
        )
    }

    /// Conditional-arithmetic fixture only. It has no source-verified byte
    /// binding and must never authorize proof verification or production
    /// security reporting.
    pub(super) fn assume_for_appendix_arithmetic_test()
    -> Result<Self, CompactFixedTapeUniformityError> {
        let contract = CompactPublicKeyProofContract::decode_selected()
            .map_err(|_| CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;
        let inputs = contract.verifier_inputs();
        if inputs.proof_wire_geometry.responses().is_empty()
            || inputs
                .proof_wire_geometry
                .responses()
                .iter()
                .enumerate()
                .any(|(index, response)| usize::try_from(response.ordinal()).ok() != Some(index))
        {
            return Err(CompactFixedTapeUniformityError::InvalidSelectedGeometry);
        }
        let round_geometries = inputs
            .proof_wire_geometry
            .responses()
            .iter()
            .map(|response| response.verifier_message_geometry().clone())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self::from_selected_geometries(round_geometries, None)
    }

    fn from_selected_geometries(
        round_geometries: Box<[FixedUniformVerifierMessageGeometry]>,
        source_verified_binding: Option<CompactFixedTapeSourceVerifiedBinding>,
    ) -> Result<Self, CompactFixedTapeUniformityError> {
        let minimum_uniform_message_bit_length = round_geometries
            .iter()
            .map(|geometry| {
                geometry
                    .exact_message_byte_length_u64()
                    .map_err(|_| CompactFixedTapeUniformityError::InvalidSelectedGeometry)?
                    .checked_mul(u64::from(u8::BITS))
                    .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min()
            .ok_or(CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;
        let sampler_exhaustion_loss = derive_sampler_exhaustion_loss(&round_geometries)?;
        Ok(Self {
            round_geometries,
            minimum_uniform_message_bit_length,
            source_verified_binding,
            sampler_exhaustion_loss,
        })
    }
}

/// Exact union-bound ceiling for every terminal fixed-slot exhaustion event.
/// Conditional on avoiding these events, the decoder maps uniform candidates
/// equidistributively to canonical field elements and ordered distinct query
/// choices.
fn derive_sampler_exhaustion_loss(
    geometries: &[FixedUniformVerifierMessageGeometry],
) -> Result<CompactFixedTapeExactLoss, CompactFixedTapeUniformityError> {
    let draw_count = PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT;
    let draw_count_usize = usize::try_from(draw_count)
        .map_err(|_| CompactFixedTapeUniformityError::ArithmeticOverflow)?;
    let extension_candidate_bit_length = Hash512::BYTE_LENGTH
        .checked_mul(u8::BITS as usize)
        .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)?;
    let common_denominator_exponent = extension_candidate_bit_length
        .checked_mul(draw_count_usize)
        .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)?;
    let common_denominator = BigUint::one() << common_denominator_exponent;
    let extension_candidate_space = BigUint::one() << extension_candidate_bit_length;
    let extension_cardinality =
        BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(PROOF_CHALLENGE_EXTENSION_DEGREE as u32);
    let base_candidate_bit_length = usize::try_from(u64::BITS)
        .map_err(|_| CompactFixedTapeUniformityError::ArithmeticOverflow)?;
    let base_candidate_space = BigUint::one() << base_candidate_bit_length;
    let base_rejected_count = base_candidate_space
        .checked_sub(&BigUint::from(PROOF_BASE_FIELD_MODULUS))
        .ok_or(CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;
    let base_denominator_exponent = base_candidate_bit_length
        .checked_mul(draw_count_usize)
        .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)?;
    let base_scale_exponent = common_denominator_exponent
        .checked_sub(base_denominator_exponent)
        .ok_or(CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;

    let mut numerator = BigUint::zero();
    for geometry in geometries {
        let extension_output_count = geometry.extension_output_count();
        if extension_output_count > 0 {
            let allowed_cardinality = extension_cardinality
                .checked_sub(&BigUint::from(
                    geometry.excluded_extension_prefix_cardinality(),
                ))
                .ok_or(CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;
            if allowed_cardinality <= BigUint::one() {
                return Err(CompactFixedTapeUniformityError::InvalidSelectedGeometry);
            }
            let rejected_count = &extension_candidate_space % &allowed_cardinality;
            numerator += BigUint::from(extension_output_count) * rejected_count.pow(draw_count);
        }

        let base_output_count = geometry.base_field_output_count();
        if base_output_count > 0 {
            numerator += (BigUint::from(base_output_count) * base_rejected_count.pow(draw_count))
                << base_scale_exponent;
        }

        for group in geometry.distinct_query_groups() {
            let domain_cardinality = group.domain_cardinality();
            if !domain_cardinality.is_power_of_two() || group.query_count() > domain_cardinality {
                return Err(CompactFixedTapeUniformityError::InvalidSelectedGeometry);
            }
            let group_denominator_exponent = usize::try_from(domain_cardinality.ilog2())
                .map_err(|_| CompactFixedTapeUniformityError::ArithmeticOverflow)?
                .checked_mul(draw_count_usize)
                .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)?;
            let group_scale_exponent = common_denominator_exponent
                .checked_sub(group_denominator_exponent)
                .ok_or(CompactFixedTapeUniformityError::InvalidSelectedGeometry)?;
            for accepted_count in 1..group.query_count() {
                numerator += BigUint::from(accepted_count).pow(draw_count) << group_scale_exponent;
            }
        }
    }
    CompactFixedTapeExactLoss::try_new(numerator, common_denominator)
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
    use super::*;

    #[test]
    fn conditional_arithmetic_fixture_uses_the_selected_direct_tape_geometry() {
        let premise = CompactFixedTapeUniformityPremise::assume_for_appendix_arithmetic_test()
            .expect("selected conditional fixed-tape arithmetic fixture");
        assert_eq!(premise.round_count(), 82);
        assert_eq!(premise.minimum_uniform_message_bit_length(), 65_536);
        let (exhaustion_numerator, exhaustion_denominator) =
            premise.sampler_exhaustion_loss_parts();
        assert!(!exhaustion_numerator.is_zero());
        assert!(exhaustion_numerator < exhaustion_denominator);
    }
}
