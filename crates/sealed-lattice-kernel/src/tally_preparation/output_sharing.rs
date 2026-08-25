use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    encoding::{CanonicalReader, append_bytes, append_varuint},
    foundation::MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
};

use super::{BinaryFieldElement256, TallyPreparationError};

pub(crate) const DEGREE_THREE_RECONSTRUCTION_THRESHOLD: usize = 4;
pub(super) const DEGREE_THREE_MASK_SHARE_ARTIFACT_MAGIC: &[u8] =
    b"sealed-lattice/degree-three-mask-share";
pub(super) const DEGREE_THREE_MASK_SHARE_ARTIFACT_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DegreeThreeMaskPolynomial {
    coefficients: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
}

impl DegreeThreeMaskPolynomial {
    pub(crate) const fn new(
        secret: BinaryFieldElement256,
        random_coefficients: [BinaryFieldElement256; 3],
    ) -> Self {
        Self {
            coefficients: [
                secret,
                random_coefficients[0],
                random_coefficients[1],
                random_coefficients[2],
            ],
        }
    }

    pub(crate) fn evaluate(self, evaluation_point: BinaryFieldElement256) -> BinaryFieldElement256 {
        self.coefficients.iter().rev().copied().fold(
            BinaryFieldElement256::ZERO,
            |evaluated_value, coefficient| {
                evaluated_value.multiply(evaluation_point).add(coefficient)
            },
        )
    }

    pub(crate) fn share(
        self,
        participant_count: u16,
        roster_position: u16,
    ) -> Result<DegreeThreeMaskShare, TallyPreparationError> {
        let evaluation_point = canonical_evaluation_point(participant_count, roster_position)?;
        DegreeThreeMaskShare::new(
            participant_count,
            roster_position,
            evaluation_point,
            self.evaluate(evaluation_point),
        )
    }

    pub(crate) fn shares(
        self,
        participant_count: u16,
    ) -> Result<Vec<DegreeThreeMaskShare>, TallyPreparationError> {
        validate_participant_count(participant_count)?;
        (0..participant_count)
            .map(|roster_position| self.share(participant_count, roster_position))
            .collect()
    }

    pub(crate) fn zeroize(&mut self) {
        self.coefficients.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DegreeThreeMaskShare {
    participant_count: u16,
    roster_position: u16,
    evaluation_point: BinaryFieldElement256,
    value: BinaryFieldElement256,
}

impl DegreeThreeMaskShare {
    pub(crate) fn new(
        participant_count: u16,
        roster_position: u16,
        evaluation_point: BinaryFieldElement256,
        value: BinaryFieldElement256,
    ) -> Result<Self, TallyPreparationError> {
        let expected_evaluation_point =
            canonical_evaluation_point(participant_count, roster_position)?;
        if evaluation_point.is_zero() {
            return Err(TallyPreparationError::ZeroEvaluationPoint);
        }
        if evaluation_point
            .ct_eq(&expected_evaluation_point)
            .unwrap_u8()
            != 1
        {
            return Err(TallyPreparationError::EvaluationPointMismatch { roster_position });
        }

        Ok(Self {
            participant_count,
            roster_position,
            evaluation_point,
            value,
        })
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn roster_position(self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn evaluation_point(self) -> BinaryFieldElement256 {
        self.evaluation_point
    }

    pub(crate) const fn value(self) -> BinaryFieldElement256 {
        self.value
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            DEGREE_THREE_MASK_SHARE_ARTIFACT_MAGIC.len()
                + (2 * BinaryFieldElement256::CANONICAL_BYTE_LENGTH)
                + 8,
        );
        append_bytes(&mut bytes, DEGREE_THREE_MASK_SHARE_ARTIFACT_MAGIC);
        append_varuint(&mut bytes, DEGREE_THREE_MASK_SHARE_ARTIFACT_VERSION);
        append_varuint(&mut bytes, u64::from(self.participant_count));
        append_varuint(&mut bytes, u64::from(self.roster_position));
        append_bytes(&mut bytes, &self.evaluation_point.canonical_bytes());
        append_bytes(&mut bytes, &self.value.canonical_bytes());
        bytes
    }
}

pub(crate) fn decode_canonical_degree_three_mask_share(
    bytes: &[u8],
) -> Result<DegreeThreeMaskShare, TallyPreparationError> {
    let mut reader = CanonicalReader::new(bytes);
    if reader.read_bytes()?.as_slice() != DEGREE_THREE_MASK_SHARE_ARTIFACT_MAGIC {
        return Err(TallyPreparationError::ShareArtifactMagicMismatch);
    }
    let version = reader.read_varuint()?;
    if version != DEGREE_THREE_MASK_SHARE_ARTIFACT_VERSION {
        return Err(TallyPreparationError::UnsupportedShareArtifactVersion { version });
    }
    let participant_count = read_u16(&mut reader)?;
    let roster_position = read_u16(&mut reader)?;
    let evaluation_point = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
    let value = BinaryFieldElement256::from_canonical_bytes(&reader.read_bytes()?)?;
    if !reader.is_finished() {
        return Err(TallyPreparationError::TrailingShareArtifactBytes);
    }

    DegreeThreeMaskShare::new(participant_count, roster_position, evaluation_point, value)
}

/// Reconstructs the constant term and verifies every supplied point beyond the
/// four-point interpolation basis.
///
/// Exactly four distinct points always define one degree-at-most-three
/// polynomial, so inconsistency is detectable only when an additional point
/// is supplied or another authenticated relation constrains the polynomial.
pub(crate) fn reconstruct_degree_three_mask(
    expected_participant_count: u16,
    shares: &[DegreeThreeMaskShare],
) -> Result<BinaryFieldElement256, TallyPreparationError> {
    validate_participant_count(expected_participant_count)?;
    if shares.len() < DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
        return Err(TallyPreparationError::InsufficientShares {
            required: DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
            actual: shares.len(),
        });
    }
    if shares.len() > usize::from(expected_participant_count) {
        return Err(TallyPreparationError::ExcessShares {
            participant_count: expected_participant_count,
            actual: shares.len(),
        });
    }

    let mut canonical_shares = shares.to_vec();
    canonical_shares.sort_unstable_by_key(|share| share.roster_position);
    for share in &canonical_shares {
        if share.participant_count != expected_participant_count {
            return Err(TallyPreparationError::ParticipantCountMismatch);
        }
        let expected_evaluation_point =
            canonical_evaluation_point(expected_participant_count, share.roster_position)?;
        if share
            .evaluation_point
            .ct_eq(&expected_evaluation_point)
            .unwrap_u8()
            != 1
        {
            return Err(TallyPreparationError::EvaluationPointMismatch {
                roster_position: share.roster_position,
            });
        }
    }
    for adjacent_shares in canonical_shares.windows(2) {
        if adjacent_shares[0].roster_position == adjacent_shares[1].roster_position {
            return Err(TallyPreparationError::DuplicateSharePosition {
                roster_position: adjacent_shares[0].roster_position,
            });
        }
    }

    let interpolation_basis: [DegreeThreeMaskShare; DEGREE_THREE_RECONSTRUCTION_THRESHOLD] =
        canonical_shares[..DEGREE_THREE_RECONSTRUCTION_THRESHOLD]
            .try_into()
            .expect("the reconstruction threshold was checked before selecting the basis");
    let basis = LagrangeInterpolationBasis::new(interpolation_basis)?;
    for share in &canonical_shares[DEGREE_THREE_RECONSTRUCTION_THRESHOLD..] {
        let expected_value = basis.evaluate(share.evaluation_point);
        if expected_value.ct_eq(&share.value).unwrap_u8() != 1 {
            return Err(TallyPreparationError::InconsistentShare {
                roster_position: share.roster_position,
            });
        }
    }

    Ok(basis.evaluate(BinaryFieldElement256::ZERO))
}

pub(crate) fn canonical_evaluation_point(
    participant_count: u16,
    roster_position: u16,
) -> Result<BinaryFieldElement256, TallyPreparationError> {
    validate_participant_count(participant_count)?;
    if roster_position >= participant_count {
        return Err(TallyPreparationError::RosterPositionOutOfRange {
            roster_position,
            participant_count,
        });
    }
    let one_based_position = roster_position
        .checked_add(1)
        .ok_or(TallyPreparationError::IntegerConversion)?;
    Ok(BinaryFieldElement256::from_low_polynomial_u16(
        one_based_position,
    ))
}

fn validate_participant_count(participant_count: u16) -> Result<(), TallyPreparationError> {
    if usize::from(participant_count) < DEGREE_THREE_RECONSTRUCTION_THRESHOLD
        || participant_count > MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        return Err(TallyPreparationError::ParticipantCountOutOfRange { participant_count });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct LagrangeInterpolationBasis {
    shares: [DegreeThreeMaskShare; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
    inverse_denominators: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
}

impl LagrangeInterpolationBasis {
    fn new(
        shares: [DegreeThreeMaskShare; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
    ) -> Result<Self, TallyPreparationError> {
        let denominators = core::array::from_fn(|selected_share_position| {
            shares
                .iter()
                .enumerate()
                .filter(|(other_share_position, _share)| {
                    *other_share_position != selected_share_position
                })
                .map(|(_other_share_position, share)| {
                    shares[selected_share_position]
                        .evaluation_point
                        .add(share.evaluation_point)
                })
                .fold(BinaryFieldElement256::ONE, |product, factor| {
                    product.multiply(factor)
                })
        });
        let inverse_denominators = batch_invert_four(denominators)?;

        Ok(Self {
            shares,
            inverse_denominators,
        })
    }

    fn evaluate(self, evaluation_point: BinaryFieldElement256) -> BinaryFieldElement256 {
        self.shares.iter().enumerate().fold(
            BinaryFieldElement256::ZERO,
            |interpolated_value, (selected_share_position, selected_share)| {
                let numerator = self
                    .shares
                    .iter()
                    .enumerate()
                    .filter(|(other_share_position, _share)| {
                        *other_share_position != selected_share_position
                    })
                    .map(|(_other_share_position, share)| {
                        evaluation_point.add(share.evaluation_point)
                    })
                    .fold(BinaryFieldElement256::ONE, |product, factor| {
                        product.multiply(factor)
                    });
                let interpolation_coefficient =
                    numerator.multiply(self.inverse_denominators[selected_share_position]);
                interpolated_value.add(selected_share.value.multiply(interpolation_coefficient))
            },
        )
    }
}

pub(super) fn batch_invert_four(
    values: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
) -> Result<[BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD], TallyPreparationError> {
    let mut prefix_products = [BinaryFieldElement256::ONE; DEGREE_THREE_RECONSTRUCTION_THRESHOLD];
    for value_position in 1..DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
        prefix_products[value_position] =
            prefix_products[value_position - 1].multiply(values[value_position - 1]);
    }

    let complete_product = prefix_products[DEGREE_THREE_RECONSTRUCTION_THRESHOLD - 1]
        .multiply(values[DEGREE_THREE_RECONSTRUCTION_THRESHOLD - 1]);
    let mut inverse_suffix = complete_product.multiplicative_inverse()?;
    let mut inverse_values = [BinaryFieldElement256::ZERO; DEGREE_THREE_RECONSTRUCTION_THRESHOLD];
    for value_position in (0..DEGREE_THREE_RECONSTRUCTION_THRESHOLD).rev() {
        inverse_values[value_position] = prefix_products[value_position].multiply(inverse_suffix);
        inverse_suffix = inverse_suffix.multiply(values[value_position]);
    }
    Ok(inverse_values)
}

fn read_u16(reader: &mut CanonicalReader<'_>) -> Result<u16, TallyPreparationError> {
    u16::try_from(reader.read_varuint()?).map_err(|_| TallyPreparationError::IntegerConversion)
}
