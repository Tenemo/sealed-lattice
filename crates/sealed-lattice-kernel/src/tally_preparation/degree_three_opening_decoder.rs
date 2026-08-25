use subtle::ConstantTimeEq;

use crate::foundation::derive_foundation_roster_parameters;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::{
        DEGREE_THREE_RECONSTRUCTION_THRESHOLD, DegreeThreeMaskShare, batch_invert_four,
        canonical_evaluation_point,
    },
    replicated_random_sharing::{BinaryFieldPolynomial, CanonicalPolynomialConsistencyVerifier},
};

/// Algebraic result of decoding a complete, externally authenticated opening.
///
/// This value is not a workflow capability. The caller must verify canonical
/// encoding, signatures, context, predecessor roots, and authenticated-share
/// provenance before supplying shares to this decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedDegreeThreeOpening {
    constant_term: BinaryFieldElement256,
    corrected_roster_positions: Vec<u16>,
}

impl DecodedDegreeThreeOpening {
    pub(crate) const fn constant_term(&self) -> BinaryFieldElement256 {
        self.constant_term
    }

    pub(crate) fn corrected_roster_positions(&self) -> &[u16] {
        &self.corrected_roster_positions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DegreeThreeOpeningDecoding {
    Pending {
        required_share_count: usize,
        received_share_count: usize,
    },
    Decoded(DecodedDegreeThreeOpening),
}

/// Canonical Reed-Solomon decoder for a degree-at-most-three Shamir opening.
///
/// A complete roster is required. Missing signed messages remain pending and
/// are never reclassified as absent shares. For a supported roster, the
/// minimum code distance exceeds twice the roster-derived active-fault bound,
/// so at most that many inconsistent points have one unique decoded
/// polynomial.
#[derive(Debug, Clone)]
pub(crate) struct DegreeThreeOpeningDecoder {
    participant_count: u16,
    maximum_inconsistent_share_count: usize,
    fast_path_consistency_verifier: CanonicalPolynomialConsistencyVerifier,
}

impl DegreeThreeOpeningDecoder {
    pub(crate) fn new(participant_count: u16) -> Result<Self, TallyPreparationError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).ok_or(
            TallyPreparationError::DegreeThreeOpeningProfileMismatch {
                participant_count,
                reconstruction_threshold: 0,
            },
        )?;
        let reconstruction_threshold = usize::from(roster_parameters.reconstruction_threshold);
        let maximum_inconsistent_share_count = usize::from(roster_parameters.active_fault_bound);
        let required_codeword_length = DEGREE_THREE_RECONSTRUCTION_THRESHOLD
            .checked_add(
                maximum_inconsistent_share_count
                    .checked_mul(2)
                    .ok_or(TallyPreparationError::ArithmeticOverflow)?,
            )
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if reconstruction_threshold != DEGREE_THREE_RECONSTRUCTION_THRESHOLD
            || usize::from(participant_count) < required_codeword_length
        {
            return Err(TallyPreparationError::DegreeThreeOpeningProfileMismatch {
                participant_count,
                reconstruction_threshold,
            });
        }
        Ok(Self {
            participant_count,
            maximum_inconsistent_share_count,
            fast_path_consistency_verifier: CanonicalPolynomialConsistencyVerifier::new(
                participant_count,
                DEGREE_THREE_RECONSTRUCTION_THRESHOLD - 1,
            )?,
        })
    }

    pub(crate) fn decode(
        &self,
        shares: &[DegreeThreeMaskShare],
    ) -> Result<DegreeThreeOpeningDecoding, TallyPreparationError> {
        if shares.len() > usize::from(self.participant_count) {
            return Err(TallyPreparationError::ExcessShares {
                participant_count: self.participant_count,
                actual: shares.len(),
            });
        }

        let mut canonical_shares = shares.to_vec();
        canonical_shares.sort_unstable_by_key(|share| share.roster_position());
        validate_supplied_shares(self.participant_count, &canonical_shares)?;
        if canonical_shares.len() < usize::from(self.participant_count) {
            return Ok(DegreeThreeOpeningDecoding::Pending {
                required_share_count: usize::from(self.participant_count),
                received_share_count: canonical_shares.len(),
            });
        }

        for (expected_roster_position, share) in canonical_shares.iter().enumerate() {
            if share.roster_position()
                != u16::try_from(expected_roster_position)
                    .map_err(|_| TallyPreparationError::IntegerConversion)?
            {
                return Err(TallyPreparationError::DegreeThreeOpeningDecodingFailure {
                    maximum_inconsistent_share_count: self.maximum_inconsistent_share_count,
                });
            }
        }

        let canonical_values = canonical_shares
            .iter()
            .map(|share| share.value())
            .collect::<Vec<_>>();
        if let Some(polynomial) = self
            .fast_path_consistency_verifier
            .interpolate_and_verify(&canonical_values)?
        {
            return Ok(DegreeThreeOpeningDecoding::Decoded(
                DecodedDegreeThreeOpening {
                    constant_term: polynomial.evaluate(BinaryFieldElement256::ZERO),
                    corrected_roster_positions: Vec::new(),
                },
            ));
        }

        for first_basis_position in 0..canonical_shares.len() - 3 {
            for second_basis_position in first_basis_position + 1..canonical_shares.len() - 2 {
                for third_basis_position in second_basis_position + 1..canonical_shares.len() - 1 {
                    for fourth_basis_position in third_basis_position + 1..canonical_shares.len() {
                        let polynomial = interpolate_degree_three([
                            canonical_shares[first_basis_position],
                            canonical_shares[second_basis_position],
                            canonical_shares[third_basis_position],
                            canonical_shares[fourth_basis_position],
                        ])?;
                        let corrected_roster_positions = canonical_shares
                            .iter()
                            .filter_map(|share| {
                                let expected_value = polynomial.evaluate(share.evaluation_point());
                                (expected_value.ct_eq(&share.value()).unwrap_u8() != 1)
                                    .then_some(share.roster_position())
                            })
                            .collect::<Vec<_>>();
                        if corrected_roster_positions.len() <= self.maximum_inconsistent_share_count
                        {
                            return Ok(DegreeThreeOpeningDecoding::Decoded(
                                DecodedDegreeThreeOpening {
                                    constant_term: polynomial.evaluate(BinaryFieldElement256::ZERO),
                                    corrected_roster_positions,
                                },
                            ));
                        }
                    }
                }
            }
        }

        Err(TallyPreparationError::DegreeThreeOpeningDecodingFailure {
            maximum_inconsistent_share_count: self.maximum_inconsistent_share_count,
        })
    }
}

fn validate_supplied_shares(
    participant_count: u16,
    canonical_shares: &[DegreeThreeMaskShare],
) -> Result<(), TallyPreparationError> {
    for share in canonical_shares {
        if share.participant_count() != participant_count {
            return Err(TallyPreparationError::ParticipantCountMismatch);
        }
        let expected_evaluation_point =
            canonical_evaluation_point(participant_count, share.roster_position())?;
        if share
            .evaluation_point()
            .ct_eq(&expected_evaluation_point)
            .unwrap_u8()
            != 1
        {
            return Err(TallyPreparationError::EvaluationPointMismatch {
                roster_position: share.roster_position(),
            });
        }
    }
    for adjacent_shares in canonical_shares.windows(2) {
        if adjacent_shares[0].roster_position() == adjacent_shares[1].roster_position() {
            return Err(TallyPreparationError::DuplicateSharePosition {
                roster_position: adjacent_shares[0].roster_position(),
            });
        }
    }
    Ok(())
}

fn interpolate_degree_three(
    shares: [DegreeThreeMaskShare; DEGREE_THREE_RECONSTRUCTION_THRESHOLD],
) -> Result<BinaryFieldPolynomial, TallyPreparationError> {
    let denominators = core::array::from_fn(|selected_share_position| {
        let selected_share = shares[selected_share_position];
        shares
            .iter()
            .enumerate()
            .filter(|(other_share_position, _share)| {
                *other_share_position != selected_share_position
            })
            .map(|(_other_share_position, other_share)| {
                selected_share
                    .evaluation_point()
                    .add(other_share.evaluation_point())
            })
            .fold(BinaryFieldElement256::ONE, |product, factor| {
                product.multiply(factor)
            })
    });
    let mut numerators = Vec::with_capacity(DEGREE_THREE_RECONSTRUCTION_THRESHOLD);
    for selected_share_position in 0..shares.len() {
        let mut numerator = BinaryFieldPolynomial::one();
        for (other_share_position, other_share) in shares.iter().enumerate() {
            if other_share_position == selected_share_position {
                continue;
            }
            numerator = numerator.multiply(&BinaryFieldPolynomial::new(vec![
                other_share.evaluation_point(),
                BinaryFieldElement256::ONE,
            ]));
        }
        numerators.push(numerator);
    }
    let inverse_denominators = batch_invert_four(denominators)?;
    Ok(numerators.iter().enumerate().fold(
        BinaryFieldPolynomial::zero(),
        |polynomial, (selected_share_position, numerator)| {
            polynomial.add(
                &numerator.scale(
                    shares[selected_share_position]
                        .value()
                        .multiply(inverse_denominators[selected_share_position]),
                ),
            )
        },
    ))
}
