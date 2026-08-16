//! Canonical Reed-Solomon domain shared by release replay and semantic tests.

use super::field::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, ProofBaseFieldElement,
    ProofChallengeExtensionElement,
};

const GOLDILOCKS_TWO_ADICITY: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompactReedSolomonDomainError {
    ArithmeticOverflow,
    InvalidGeometry,
}

pub(super) fn validate_canonical_reed_solomon_domain_geometry(
    message_length: usize,
    hiding_randomness_length: usize,
    block_length: usize,
    interleaving_width: usize,
) -> Result<(), CompactReedSolomonDomainError> {
    let dimension = message_length
        .checked_add(hiding_randomness_length)
        .ok_or(CompactReedSolomonDomainError::ArithmeticOverflow)?;
    let block_length_exceeds_field_two_adicity = u64::try_from(block_length)
        .map(|length| length > (1_u64 << GOLDILOCKS_TWO_ADICITY))
        .unwrap_or(true);
    if message_length == 0
        || hiding_randomness_length == 0
        || interleaving_width == 0
        || !block_length.is_power_of_two()
        || block_length_exceeds_field_two_adicity
        || dimension >= block_length
    {
        return Err(CompactReedSolomonDomainError::InvalidGeometry);
    }
    Ok(())
}

pub(super) fn canonical_reed_solomon_domain_evaluation_points(
    message_length: usize,
    hiding_randomness_length: usize,
    block_length: usize,
    interleaving_width: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, CompactReedSolomonDomainError> {
    validate_canonical_reed_solomon_domain_geometry(
        message_length,
        hiding_randomness_length,
        block_length,
        interleaving_width,
    )?;
    let logarithmic_block_length = block_length.ilog2();
    let maximum_generator = ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR)
            .map_err(|_| CompactReedSolomonDomainError::InvalidGeometry)?,
    );
    let root_exponent = 1_u64
        .checked_shl(GOLDILOCKS_TWO_ADICITY - logarithmic_block_length)
        .ok_or(CompactReedSolomonDomainError::InvalidGeometry)?;
    let root = maximum_generator.power(root_exponent);
    let mut evaluation_points = Vec::new();
    evaluation_points
        .try_reserve_exact(block_length)
        .map_err(|_| CompactReedSolomonDomainError::ArithmeticOverflow)?;
    let mut point = ProofChallengeExtensionElement::ONE;
    for _ in 0..block_length {
        evaluation_points.push(point);
        point = point.multiply(root);
    }
    if point != ProofChallengeExtensionElement::ONE
        || (block_length > 1
            && evaluation_points[block_length / 2] == ProofChallengeExtensionElement::ONE)
    {
        return Err(CompactReedSolomonDomainError::InvalidGeometry);
    }
    Ok(evaluation_points)
}
