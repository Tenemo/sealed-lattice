//! Fixed-bit verifier messages for the compact public-key BCS reduction.
//!
//! CDHZ state restoration samples one uniformly random bit string per logical
//! verifier move. The production challenge types are obtained by deterministic
//! bounded rejection from that complete string. Extension outputs use 512-bit
//! candidates, base-field outputs and power-of-two query positions use 64-bit
//! candidates, and every logical output owns the suite-wide fixed draw count.
//! The static construction requires exhaustion to reject. Conditional on
//! acceptance, its fixed-slot rejection maps give every canonical field value
//! and every sorted distinct-query set the same number of raw-message
//! preimages. The production decoder and direct SHAKE256 XOF schedule own the
//! concrete geometry used by this independent ledger.

use num_bigint::BigUint;
use num_traits::{CheckedSub, One};

use super::transcript_chronology::{
    DistinctQueryGeometry, ExactChallengeSpace, PackingTranscriptChronology,
};
use super::{
    CompactStaticCatalogError, GOLDILOCKS_BASE_FIELD_MODULUS,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, checked_add, checked_product,
};
use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
    FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageError,
    FixedUniformVerifierMessageGeometry,
};

const EXTENSION_CANDIDATE_BIT_LENGTH: u64 = 512;
const BASE_OR_QUERY_CANDIDATE_BIT_LENGTH: u64 = 64;
const QUINTIC_EXTENSION_DEGREE: u32 = 5;

/// Exact symbolic union-bound input
///
/// `output_count * (rejected_candidate_count_per_draw / 2^candidate_bit_length)
///     ^ candidate_draw_ceiling`.
///
/// Retaining the exact formula inputs avoids constructing a several-thousand-
/// bit rational merely to compare the result with a binary security floor.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactBoundedFieldRejectionFormula {
    output_count: u64,
    allowed_output_cardinality: BigUint,
    candidate_bit_length: u64,
    rejected_candidate_count_per_draw: BigUint,
    candidate_draw_ceiling: u32,
    exhaustion_security_bit_floor: u64,
}

impl ExactBoundedFieldRejectionFormula {
    fn derive(
        output_count: u64,
        allowed_output_cardinality: BigUint,
        candidate_bit_length: u64,
    ) -> Result<Self, CompactStaticCatalogError> {
        if output_count == 0
            || allowed_output_cardinality <= BigUint::one()
            || candidate_bit_length == 0
        {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let candidate_space = BigUint::one() << candidate_bit_length;
        if allowed_output_cardinality >= candidate_space {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let rejected_candidate_count_per_draw = &candidate_space % &allowed_output_cardinality;
        let exhaustion_security_bit_floor = rejection_exhaustion_security_bit_floor(
            candidate_bit_length,
            rejected_candidate_count_per_draw.bits(),
            output_count,
        )?;
        Ok(Self {
            output_count,
            allowed_output_cardinality,
            candidate_bit_length,
            rejected_candidate_count_per_draw,
            candidate_draw_ceiling: PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            exhaustion_security_bit_floor,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UniformVerifierMoveLedger {
    ordinal: u32,
    fixed_message_geometry: FixedUniformVerifierMessageGeometry,
    extension_rejection_formula: Option<ExactBoundedFieldRejectionFormula>,
    base_field_rejection_formula: Option<ExactBoundedFieldRejectionFormula>,
    fixed_candidate_slot_count: u64,
    uniform_message_byte_length: u64,
    uniform_message_bit_length: u64,
    direct_challenge_stream_xof_call_count: u64,
    field_sampling_exhaustion_security_bit_floor: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PackingUniformVerifierRandomness {
    moves: Vec<UniformVerifierMoveLedger>,
    total_fixed_candidate_slot_count: u64,
    total_uniform_message_byte_length: u64,
    minimum_uniform_verifier_message_bit_length: u64,
    direct_challenge_stream_xof_call_count: u64,
    field_sampling_exhaustion_security_bit_floor_per_attempt: u64,
}

impl PackingUniformVerifierRandomness {
    pub(super) fn derive(
        chronology: &PackingTranscriptChronology,
    ) -> Result<Self, CompactStaticCatalogError> {
        let moves = chronology
            .verifier_moves
            .iter()
            .map(|verifier_move| derive_move(verifier_move.ordinal, &verifier_move.challenge_space))
            .collect::<Result<Vec<_>, _>>()?;
        derive_catalog(moves)
    }

    pub(super) fn fixed_message_geometry(
        &self,
        move_ordinal: usize,
    ) -> Result<FixedUniformVerifierMessageGeometry, CompactStaticCatalogError> {
        let move_ledger = self
            .moves
            .get(move_ordinal)
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        if usize::try_from(move_ledger.ordinal).ok() != Some(move_ordinal) {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        Ok(move_ledger.fixed_message_geometry.clone())
    }

    pub(super) const fn move_count(&self) -> usize {
        self.moves.len()
    }
}

fn derive_move(
    ordinal: u32,
    challenge_space: &ExactChallengeSpace,
) -> Result<UniformVerifierMoveLedger, CompactStaticCatalogError> {
    let fixed_message_geometry = production_message_geometry(challenge_space)?;
    let extension_output_count = fixed_message_geometry.extension_output_count();
    let excluded_extension_prefix_cardinality =
        fixed_message_geometry.excluded_extension_prefix_cardinality();
    let base_field_output_count = fixed_message_geometry.base_field_output_count();
    let distinct_query_groups = challenge_space.distinct_query_groups().to_vec();
    if fixed_message_geometry.distinct_query_groups().len() != distinct_query_groups.len()
        || fixed_message_geometry
            .distinct_query_groups()
            .iter()
            .zip(&distinct_query_groups)
            .any(|(production, independent)| {
                production.domain_cardinality() != independent.domain_cardinality
                    || production.query_count() != independent.query_count
            })
    {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    let fixed_candidate_slot_count = fixed_message_geometry
        .fixed_candidate_slot_count()
        .map_err(map_production_message_error)?;
    let uniform_message_byte_length = fixed_message_geometry
        .exact_message_byte_length_u64()
        .map_err(map_production_message_error)?;
    let direct_challenge_stream_xof_call_count = fixed_message_geometry
        .concrete_xof_call_count()
        .map_err(map_production_message_error)?;

    let extension_rejection_formula = if extension_output_count == 0 {
        None
    } else {
        let extension_field_order =
            BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS).pow(QUINTIC_EXTENSION_DEGREE);
        let allowed_extension_cardinality = extension_field_order
            .checked_sub(&BigUint::from(excluded_extension_prefix_cardinality))
            .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
        Some(ExactBoundedFieldRejectionFormula::derive(
            extension_output_count,
            allowed_extension_cardinality,
            EXTENSION_CANDIDATE_BIT_LENGTH,
        )?)
    };
    let base_field_rejection_formula = if base_field_output_count == 0 {
        None
    } else {
        Some(ExactBoundedFieldRejectionFormula::derive(
            base_field_output_count,
            BigUint::from(GOLDILOCKS_BASE_FIELD_MODULUS),
            BASE_OR_QUERY_CANDIDATE_BIT_LENGTH,
        )?)
    };
    let field_sampling_exhaustion_security_bit_floor =
        combined_field_sampling_exhaustion_security_bit_floor(
            extension_rejection_formula.as_ref(),
            base_field_rejection_formula.as_ref(),
        )?;

    Ok(UniformVerifierMoveLedger {
        ordinal,
        fixed_message_geometry,
        extension_rejection_formula,
        base_field_rejection_formula,
        fixed_candidate_slot_count,
        uniform_message_byte_length,
        uniform_message_bit_length: checked_product(&[
            uniform_message_byte_length,
            u64::from(u8::BITS),
        ])?,
        direct_challenge_stream_xof_call_count,
        field_sampling_exhaustion_security_bit_floor,
    })
}

fn derive_catalog(
    moves: Vec<UniformVerifierMoveLedger>,
) -> Result<PackingUniformVerifierRandomness, CompactStaticCatalogError> {
    let total_fixed_candidate_slot_count = moves.iter().try_fold(0_u64, |count, move_ledger| {
        checked_add(count, move_ledger.fixed_candidate_slot_count)
    })?;
    let total_uniform_message_byte_length =
        moves.iter().try_fold(0_u64, |count, move_ledger| {
            checked_add(count, move_ledger.uniform_message_byte_length)
        })?;
    let minimum_uniform_verifier_message_bit_length = moves
        .iter()
        .map(|move_ledger| move_ledger.uniform_message_bit_length)
        .min()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    let direct_challenge_stream_xof_call_count =
        moves.iter().try_fold(0_u64, |count, move_ledger| {
            checked_add(count, move_ledger.direct_challenge_stream_xof_call_count)
        })?;
    let field_sampling_move_count = moves
        .iter()
        .filter(|move_ledger| {
            move_ledger.extension_rejection_formula.is_some()
                || move_ledger.base_field_rejection_formula.is_some()
        })
        .count();
    let field_sampling_exhaustion_security_bit_floor_per_attempt = moves
        .iter()
        .map(|move_ledger| move_ledger.field_sampling_exhaustion_security_bit_floor)
        .min()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
        .checked_sub(ceil_log2_nonzero(field_sampling_move_count)?)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
    Ok(PackingUniformVerifierRandomness {
        moves,
        total_fixed_candidate_slot_count,
        total_uniform_message_byte_length,
        minimum_uniform_verifier_message_bit_length,
        direct_challenge_stream_xof_call_count,
        field_sampling_exhaustion_security_bit_floor_per_attempt,
    })
}

fn production_message_geometry(
    challenge_space: &ExactChallengeSpace,
) -> Result<FixedUniformVerifierMessageGeometry, CompactStaticCatalogError> {
    let (extension_output_count, excluded_extension_prefix_cardinality, base_field_output_count) =
        match challenge_space {
            ExactChallengeSpace::ExtensionVector {
                element_count,
                excluded_element_count,
            } => (u64::from(*element_count), *excluded_element_count, 0),
            ExactChallengeSpace::BaseElementExtensionVectorAndDistinctQueries {
                extension_element_count,
                ..
            } => (u64::from(*extension_element_count), 0, 1),
            ExactChallengeSpace::ExtensionVectorAndDistinctQueries {
                extension_element_count,
                ..
            } => (u64::from(*extension_element_count), 0, 0),
            ExactChallengeSpace::DistinctQueries { .. } => (0, 0, 0),
        };
    let distinct_query_groups = challenge_space
        .distinct_query_groups()
        .iter()
        .map(|group| {
            FixedUniformDistinctQueryGeometry::new(group.domain_cardinality, group.query_count)
        })
        .collect();
    FixedUniformVerifierMessageGeometry::new(
        extension_output_count,
        excluded_extension_prefix_cardinality,
        base_field_output_count,
        distinct_query_groups,
    )
    .map_err(map_production_message_error)
}

fn map_production_message_error(
    error: FixedUniformVerifierMessageError,
) -> CompactStaticCatalogError {
    match error {
        FixedUniformVerifierMessageError::LengthOverflow => {
            CompactStaticCatalogError::ArithmeticOverflow
        }
        _ => CompactStaticCatalogError::InvalidGeometry,
    }
}

fn combined_field_sampling_exhaustion_security_bit_floor(
    extension_rejection_formula: Option<&ExactBoundedFieldRejectionFormula>,
    base_field_rejection_formula: Option<&ExactBoundedFieldRejectionFormula>,
) -> Result<u64, CompactStaticCatalogError> {
    let component_floors = [extension_rejection_formula, base_field_rejection_formula]
        .into_iter()
        .flatten()
        .map(|formula| formula.exhaustion_security_bit_floor)
        .collect::<Vec<_>>();
    if component_floors.is_empty() {
        return Ok(u64::MAX);
    }
    let component_count = component_floors.len();
    component_floors
        .into_iter()
        .min()
        .ok_or(CompactStaticCatalogError::InvalidGeometry)?
        .checked_sub(ceil_log2_nonzero(component_count)?)
        .ok_or(CompactStaticCatalogError::InvalidGeometry)
}

fn rejection_exhaustion_security_bit_floor(
    candidate_bit_length: u64,
    rejected_candidate_bit_length: u64,
    output_count: u64,
) -> Result<u64, CompactStaticCatalogError> {
    if rejected_candidate_bit_length == 0 {
        return Ok(u64::MAX);
    }
    candidate_bit_length
        .checked_sub(rejected_candidate_bit_length)
        .and_then(|per_draw_floor| {
            per_draw_floor.checked_mul(u64::from(
                PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
            ))
        })
        .and_then(|all_draws_floor| {
            all_draws_floor.checked_sub(u64::from(output_count.next_power_of_two().ilog2()))
        })
        .ok_or(CompactStaticCatalogError::InvalidGeometry)
}

fn ceil_log2_nonzero(value: usize) -> Result<u64, CompactStaticCatalogError> {
    if value == 0 {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(u64::from(value.next_power_of_two().ilog2()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::compact_public_key_static_catalog::CompactPublicKeyStaticCatalog;

    #[derive(Debug, PartialEq, Eq)]
    struct UniformRandomnessSnapshot {
        total_fixed_candidate_slot_count: u64,
        total_uniform_message_byte_length: u64,
        direct_challenge_stream_xof_call_count: u64,
        field_sampling_exhaustion_security_bit_floor_per_attempt: u64,
    }

    #[test]
    fn every_logical_move_has_one_fixed_uniform_bit_string() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        let randomness = &selected.uniform_verifier_randomness;
        assert_eq!(
            randomness.moves.len(),
            selected.transcript_chronology.verifier_moves.len()
        );
        assert_eq!(
            randomness.minimum_uniform_verifier_message_bit_length,
            65_536
        );
        assert!(randomness.total_fixed_candidate_slot_count > 0);
        assert!(randomness.total_uniform_message_byte_length > 0);
        assert_eq!(
            randomness.direct_challenge_stream_xof_call_count,
            u64::try_from(randomness.moves.len()).expect("move count fits u64"),
        );
        assert!(randomness.field_sampling_exhaustion_security_bit_floor_per_attempt >= 4_000);
        assert_eq!(
            UniformRandomnessSnapshot {
                total_fixed_candidate_slot_count: selected
                    .uniform_verifier_randomness
                    .total_fixed_candidate_slot_count,
                total_uniform_message_byte_length: selected
                    .uniform_verifier_randomness
                    .total_uniform_message_byte_length,
                direct_challenge_stream_xof_call_count: selected
                    .uniform_verifier_randomness
                    .direct_challenge_stream_xof_call_count,
                field_sampling_exhaustion_security_bit_floor_per_attempt: selected
                    .uniform_verifier_randomness
                    .field_sampling_exhaustion_security_bit_floor_per_attempt,
            },
            UniformRandomnessSnapshot {
                total_fixed_candidate_slot_count: 1_339_520,
                total_uniform_message_byte_length: 11_612_160,
                direct_challenge_stream_xof_call_count: 82,
                field_sampling_exhaustion_security_bit_floor_per_attempt: 4_088,
            }
        );
    }

    #[test]
    fn sorted_distinct_queries_use_subset_cardinality() {
        let geometry = DistinctQueryGeometry {
            domain_cardinality: 8,
            query_count: 3,
        };
        assert_eq!(geometry.cardinality(), Ok(BigUint::from(56_u8)));
    }
}
