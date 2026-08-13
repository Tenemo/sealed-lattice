//! Fixed-tape uniformity boundary for the compact Fiat-Shamir transcript.
//!
//! CDHZ models each verifier move as one independently sampled uniform bit
//! string. Production instead obtains that string from many predecessor-linked
//! 512-bit calls to the shared SHAKE256 oracle. Canonical framing and bounded
//! rejection establish the corresponding classical distribution, but they do
//! not establish a quantum domain-extension reduction for that shared-oracle
//! graph. Consequently this module deliberately provides no production
//! constructor for [`CompactFixedTapeUniformityPremise`]. Appendix A.1 must
//! fail closed until a matching QROM theorem can mint this opaque premise and
//! its theorem-specific distinguishing loss is added to the Appendix ledger.

use num_bigint::BigUint;

use super::compact_emitted_cdhz::CompactEmittedCdhzMeasurement;
use super::compact_response_merkle::{
    COMPACT_RESPONSE_LEAF_HASH_DOMAIN, COMPACT_RESPONSE_MERKLE_NODE_HASH_DOMAIN,
};
use super::compact_transcript::COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN;
use super::fixed_uniform_verifier_message::{
    FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN, FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN,
    FixedUniformVerifierMessageGeometry,
};

#[cfg(test)]
use super::compact_proof_contract::CompactPublicKeyProofContract;
#[cfg(test)]
use super::{
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
};
#[cfg(test)]
use crate::foundation::Hash512;
#[cfg(test)]
use num_traits::{CheckedSub, One, Zero};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactFixedTapeUniformityError {
    InvalidSelectedGeometry,
    ArithmeticOverflow,
    MeasurementMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompactFixedTapeExactLoss {
    numerator: BigUint,
    denominator: BigUint,
}

#[cfg(test)]
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

/// Opaque authority required to replace every fixed SHAKE seed-and-block graph
/// by the independent uniform verifier tapes assumed by CDHZ Appendix A.1.
///
/// The fields are private and there is intentionally no production
/// constructor. The exact classical framing and rejection arithmetic are
/// necessary but insufficient: a constructor additionally needs a quantum
/// domain-extension reduction for the predecessor-chained graph in the same
/// shared oracle used by Fiat-Shamir and the response commitments. A future
/// constructor and its theorem-specific loss must be added together; the two
/// retained losses below are only exact classical sublosses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactFixedTapeUniformityPremise {
    round_geometries: Box<[FixedUniformVerifierMessageGeometry]>,
    minimum_uniform_message_bit_length: u64,
    seed_collision_loss: CompactFixedTapeExactLoss,
    sampler_exhaustion_loss: CompactFixedTapeExactLoss,
}

impl CompactFixedTapeUniformityPremise {
    pub(super) fn round_count(&self) -> usize {
        self.round_geometries.len()
    }

    /// CDHZ `r_min`: the minimum raw uniform verifier-message width, before
    /// deterministic rejection decoding.
    pub(super) const fn minimum_uniform_message_bit_length(&self) -> u64 {
        self.minimum_uniform_message_bit_length
    }

    pub(super) const fn seed_collision_loss_parts(&self) -> (&BigUint, &BigUint) {
        (
            &self.seed_collision_loss.numerator,
            &self.seed_collision_loss.denominator,
        )
    }

    pub(super) const fn sampler_exhaustion_loss_parts(&self) -> (&BigUint, &BigUint) {
        (
            &self.sampler_exhaustion_loss.numerator,
            &self.sampler_exhaustion_loss.denominator,
        )
    }

    /// Recomputes the emitted round widths and fixed hash-call counts from the
    /// privately retained selected geometries. No measurement field can mint
    /// or strengthen this premise.
    pub(super) fn validate_measurement(
        &self,
        measurement: &CompactEmittedCdhzMeasurement,
    ) -> Result<(), CompactFixedTapeUniformityError> {
        let round_count = self.round_geometries.len();
        if measurement.rounds.len() != round_count
            || u64::try_from(round_count).ok() != Some(measurement.response_vector_commitment_count)
            || u64::try_from(round_count).ok()
                != Some(measurement.oracle_family_census.fiat_shamir_oracle_count)
            || measurement.random_oracle_domains.fiat_shamir_prefix
                != COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN
            || measurement.random_oracle_domains.verifier_message_seed
                != FIXED_UNIFORM_VERIFIER_MESSAGE_SEED_DOMAIN
            || measurement.random_oracle_domains.verifier_message_block
                != FIXED_UNIFORM_VERIFIER_MESSAGE_BLOCK_DOMAIN
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
            let expected_hash_query_count = geometry
                .concrete_hash_query_count()
                .map_err(|_| CompactFixedTapeUniformityError::InvalidSelectedGeometry)?
                .checked_add(1)
                .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)?;
            if round.ordinal != expected_ordinal
                || round.fiat_shamir_message_byte_length != expected_byte_length
                || round.concrete_fiat_shamir_hash_query_count != expected_hash_query_count
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

    /// Conditional-arithmetic fixture only. This explicitly assumes the
    /// missing shared-QRO domain-extension reduction; it must never authorize
    /// proof verification or production security reporting.
    #[cfg(test)]
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
        Self::assume_from_selected_geometries_for_appendix_arithmetic_test(round_geometries)
    }

    #[cfg(test)]
    fn assume_from_selected_geometries_for_appendix_arithmetic_test(
        round_geometries: Box<[FixedUniformVerifierMessageGeometry]>,
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
        let seed_collision_loss = derive_seed_collision_loss(round_geometries.len())?;
        let sampler_exhaustion_loss = derive_sampler_exhaustion_loss(&round_geometries)?;
        Ok(Self {
            round_geometries,
            minimum_uniform_message_bit_length,
            seed_collision_loss,
            sampler_exhaustion_loss,
        })
    }
}

#[cfg(test)]
fn derive_seed_collision_loss(
    round_count: usize,
) -> Result<CompactFixedTapeExactLoss, CompactFixedTapeUniformityError> {
    let round_count = u64::try_from(round_count)
        .map_err(|_| CompactFixedTapeUniformityError::ArithmeticOverflow)?;
    let pair_count = round_count
        .checked_mul(round_count.saturating_sub(1))
        .and_then(|product| product.checked_div(2))
        .ok_or(CompactFixedTapeUniformityError::ArithmeticOverflow)?;
    CompactFixedTapeExactLoss::try_new(
        BigUint::from(pair_count),
        BigUint::one() << (Hash512::BYTE_LENGTH * u8::BITS as usize),
    )
}

/// Exact union-bound ceiling for every terminal fixed-slot exhaustion event.
/// Conditional on avoiding these events, the decoder maps uniform candidates
/// equidistributively to canonical field elements and ordered distinct query
/// choices. This is classical evidence only and cannot construct the opaque
/// QROM premise above.
#[cfg(test)]
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

#[cfg(test)]
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
    fn conditional_arithmetic_fixture_uses_the_selected_raw_tape_geometry() {
        let premise = CompactFixedTapeUniformityPremise::assume_for_appendix_arithmetic_test()
            .expect("selected conditional fixed-tape arithmetic fixture");
        assert_eq!(premise.round_count(), 82);
        assert_eq!(premise.minimum_uniform_message_bit_length(), 65_536);
        let (seed_collision_numerator, seed_collision_denominator) =
            premise.seed_collision_loss_parts();
        assert_eq!(seed_collision_numerator, &BigUint::from(3_321_u16));
        assert_eq!(
            seed_collision_denominator,
            &(BigUint::one() << (Hash512::BYTE_LENGTH * u8::BITS as usize))
        );
        let (exhaustion_numerator, exhaustion_denominator) =
            premise.sampler_exhaustion_loss_parts();
        assert!(!exhaustion_numerator.is_zero());
        assert!(exhaustion_numerator < exhaustion_denominator);
    }
}
