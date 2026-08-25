use subtle::ConstantTimeEq;

use crate::foundation::derive_foundation_roster_parameters;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::{
        DEGREE_THREE_RECONSTRUCTION_THRESHOLD, DegreeThreeMaskShare, batch_invert_four,
        canonical_evaluation_point,
    },
};

/// Precomputed fixed-basis checker for a participant's authenticated-key
/// fields.
///
/// Construction derives both interpolation coefficient vectors once. Each
/// subsequent field check performs no allocation or inversion. This object
/// carries no transcript provenance and cannot authorize release by itself.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticatedKeyFieldLocalChecker {
    participant_count: u16,
    participant_position: u16,
    constant_term_coefficients: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
    local_point_coefficients:
        Option<[BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedKeyFieldLocalCheckWork {
    pub(crate) coefficient_vector_count: u64,
    pub(crate) coefficient_precomputation_field_multiplication_count: u64,
    pub(crate) coefficient_precomputation_field_addition_count: u64,
    pub(crate) coefficient_precomputation_field_inversion_count: u64,
    pub(crate) field_multiplication_count_per_checked_field: u64,
    pub(crate) field_addition_count_per_checked_field: u64,
    pub(crate) constant_time_comparison_count_per_checked_field: u64,
}

impl AuthenticatedKeyFieldLocalChecker {
    pub(crate) fn new(
        participant_count: u16,
        participant_position: u16,
    ) -> Result<Self, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::ParticipantCountOutOfRange { participant_count })?;
        if usize::from(roster_parameters.reconstruction_threshold)
            != DEGREE_THREE_RECONSTRUCTION_THRESHOLD
        {
            return Err(
                TallyPreparationError::AuthenticatedKeyReleaseProfileMismatch {
                    participant_count,
                    derived_reconstruction_threshold: roster_parameters.reconstruction_threshold,
                    supported_reconstruction_threshold: u16::try_from(
                        DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
                    )
                    .map_err(|_| TallyPreparationError::IntegerConversion)?,
                },
            );
        }
        let local_evaluation_point =
            canonical_evaluation_point(participant_count, participant_position)?;
        Ok(Self {
            participant_count,
            participant_position,
            constant_term_coefficients: fixed_basis_interpolation_coefficients(
                participant_count,
                BinaryFieldElement256::ZERO,
            )?,
            local_point_coefficients: (usize::from(participant_position)
                >= DEGREE_THREE_RECONSTRUCTION_THRESHOLD)
                .then(|| {
                    fixed_basis_interpolation_coefficients(
                        participant_count,
                        local_evaluation_point,
                    )
                })
                .transpose()?,
        })
    }

    pub(crate) fn reconstruct_locally_checked_field(
        self,
        published_basis_values: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
        local_value: BinaryFieldElement256,
    ) -> Result<BinaryFieldElement256, TallyPreparationError> {
        let local_value_is_consistent = match self.local_point_coefficients {
            Some(local_point_coefficients) => {
                interpolate_fixed_basis_values(published_basis_values, local_point_coefficients)
                    .ct_eq(&local_value)
                    .unwrap_u8()
                    == 1
            }
            None => {
                published_basis_values[usize::from(self.participant_position)]
                    .ct_eq(&local_value)
                    .unwrap_u8()
                    == 1
            }
        };
        if !local_value_is_consistent {
            return Err(TallyPreparationError::InconsistentShare {
                roster_position: self.participant_position,
            });
        }
        Ok(interpolate_fixed_basis_values(
            published_basis_values,
            self.constant_term_coefficients,
        ))
    }

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn participant_position(self) -> u16 {
        self.participant_position
    }

    pub(crate) const fn constant_term_coefficients(
        self,
    ) -> [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD] {
        self.constant_term_coefficients
    }

    pub(crate) const fn local_point_coefficients(
        self,
    ) -> Option<[BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD]> {
        self.local_point_coefficients
    }

    pub(crate) const fn exact_work(self) -> AuthenticatedKeyFieldLocalCheckWork {
        let coefficient_vector_count = if self.local_point_coefficients.is_some() {
            2
        } else {
            1
        };
        // One coefficient vector uses twelve denominator products, twelve
        // batch-inversion multiplications, twelve numerator products, four
        // final coefficient multiplications, twenty-four point additions, and
        // one field inversion. Interpolating one field uses four
        // multiply-and-add steps per coefficient vector.
        AuthenticatedKeyFieldLocalCheckWork {
            coefficient_vector_count,
            coefficient_precomputation_field_multiplication_count: 40 * coefficient_vector_count,
            coefficient_precomputation_field_addition_count: 24 * coefficient_vector_count,
            coefficient_precomputation_field_inversion_count: coefficient_vector_count,
            field_multiplication_count_per_checked_field: 4 * coefficient_vector_count,
            field_addition_count_per_checked_field: 4 * coefficient_vector_count,
            constant_time_comparison_count_per_checked_field: 1,
        }
    }
}

/// Reconstructs one public authenticated-opening key field and checks it
/// against one participant's private preparation share.
///
/// The public interpolation basis is fixed to roster positions zero through
/// three. A participant in that basis compares the published value directly
/// with its private share. Every other participant supplies a fifth point,
/// which must lie on the uniquely interpolated degree-three polynomial.
///
/// This is only the field-level algebra used before an all-ten release
/// acknowledgement. It verifies no encoding, signature, predecessor root,
/// record coordinate, stream completeness, state, or malicious-MPC source and
/// cannot mint any protocol capability.
pub(crate) fn reconstruct_locally_checked_authenticated_key_field(
    expected_participant_count: u16,
    published_basis_shares: &[DegreeThreeMaskShare],
    local_share: DegreeThreeMaskShare,
) -> Result<BinaryFieldElement256, TallyPreparationError> {
    let checker = AuthenticatedKeyFieldLocalChecker::new(
        expected_participant_count,
        local_share.roster_position(),
    )?;
    if published_basis_shares.len() != DEGREE_THREE_RECONSTRUCTION_THRESHOLD {
        return Err(
            TallyPreparationError::AuthenticatedKeyReleaseBasisCountMismatch {
                expected: DEGREE_THREE_RECONSTRUCTION_THRESHOLD,
                actual: published_basis_shares.len(),
            },
        );
    }
    if local_share.participant_count() != expected_participant_count {
        return Err(TallyPreparationError::ParticipantCountMismatch);
    }
    let mut published_basis_values =
        [BinaryFieldElement256::ZERO; DEGREE_THREE_RECONSTRUCTION_THRESHOLD];
    for (basis_position, share) in published_basis_shares.iter().copied().enumerate() {
        let expected_roster_position =
            u16::try_from(basis_position).map_err(|_| TallyPreparationError::IntegerConversion)?;
        if share.roster_position() != expected_roster_position {
            return Err(
                TallyPreparationError::AuthenticatedKeyReleaseBasisPositionMismatch {
                    basis_position,
                    expected_roster_position,
                    actual_roster_position: share.roster_position(),
                },
            );
        }
        if share.participant_count() != expected_participant_count {
            return Err(TallyPreparationError::ParticipantCountMismatch);
        }
        published_basis_values[basis_position] = share.value();
    }
    checker.reconstruct_locally_checked_field(published_basis_values, local_share.value())
}

fn fixed_basis_interpolation_coefficients(
    participant_count: u16,
    evaluation_point: BinaryFieldElement256,
) -> Result<[BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD], TallyPreparationError> {
    let mut basis_points = [BinaryFieldElement256::ZERO; DEGREE_THREE_RECONSTRUCTION_THRESHOLD];
    for (basis_position, basis_point) in basis_points.iter_mut().enumerate() {
        *basis_point = canonical_evaluation_point(
            participant_count,
            u16::try_from(basis_position).map_err(|_| TallyPreparationError::IntegerConversion)?,
        )?;
    }
    let denominators = core::array::from_fn(|selected_position| {
        basis_points
            .iter()
            .enumerate()
            .filter(|(other_position, _point)| *other_position != selected_position)
            .map(|(_other_position, point)| basis_points[selected_position].add(*point))
            .fold(BinaryFieldElement256::ONE, |product, factor| {
                product.multiply(factor)
            })
    });
    let inverse_denominators = batch_invert_four(denominators)?;
    Ok(core::array::from_fn(|selected_position| {
        let numerator = basis_points
            .iter()
            .enumerate()
            .filter(|(other_position, _point)| *other_position != selected_position)
            .map(|(_other_position, point)| evaluation_point.add(*point))
            .fold(BinaryFieldElement256::ONE, |product, factor| {
                product.multiply(factor)
            });
        numerator.multiply(inverse_denominators[selected_position])
    }))
}

fn interpolate_fixed_basis_values(
    values: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
    coefficients: [BinaryFieldElement256; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
) -> BinaryFieldElement256 {
    values
        .into_iter()
        .zip(coefficients)
        .fold(BinaryFieldElement256::ZERO, |sum, (value, coefficient)| {
            sum.add(value.multiply(coefficient))
        })
}
