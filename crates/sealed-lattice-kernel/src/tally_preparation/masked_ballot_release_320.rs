use core::fmt;

use crate::{foundation::derive_foundation_roster_parameters, tally_circuit::CompiledTallyCircuit};

use super::{
    TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bundle_320::{MaskedBallotBundle320, MaskedBallotBundleError320},
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
};

/// Failure of the algebraic masked-ballot release candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotReleaseError320 {
    UnsupportedRoster {
        participant_count: u16,
    },
    CircuitParticipantCountMismatch {
        circuit_participant_count: u16,
        release_participant_count: u16,
    },
    ShareParticipantCountMismatch {
        expected: u16,
        actual: u16,
    },
    ShareEvaluationPointMismatch {
        roster_position: u16,
    },
    DuplicateRosterPosition {
        roster_position: u16,
    },
    ExcessShareCount {
        participant_count: u16,
        actual: usize,
    },
    Undecodable {
        maximum_inconsistent_share_count: usize,
    },
    ArithmeticOverflow,
    Field(TallyPreparationError),
    Bundle(MaskedBallotBundleError320),
}

impl fmt::Display for MaskedBallotReleaseError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRoster { participant_count } => write!(
                formatter,
                "participant count {participant_count} does not admit masked-ballot release decoding"
            ),
            Self::CircuitParticipantCountMismatch {
                circuit_participant_count,
                release_participant_count,
            } => write!(
                formatter,
                "circuit participant count {circuit_participant_count} does not match release participant count {release_participant_count}"
            ),
            Self::ShareParticipantCountMismatch { expected, actual } => write!(
                formatter,
                "masked-ballot release share participant count {actual} does not match expected count {expected}"
            ),
            Self::ShareEvaluationPointMismatch { roster_position } => write!(
                formatter,
                "masked-ballot release share at roster position {roster_position} uses the wrong evaluation point"
            ),
            Self::DuplicateRosterPosition { roster_position } => write!(
                formatter,
                "masked-ballot release repeats roster position {roster_position}"
            ),
            Self::ExcessShareCount {
                participant_count,
                actual,
            } => write!(
                formatter,
                "masked-ballot release has {actual} shares for a {participant_count}-participant roster"
            ),
            Self::Undecodable {
                maximum_inconsistent_share_count,
            } => write!(
                formatter,
                "masked-ballot release is not within {maximum_inconsistent_share_count} inconsistent positions of one admitted codeword"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("masked-ballot release arithmetic overflow")
            }
            Self::Field(error) => error.fmt(formatter),
            Self::Bundle(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MaskedBallotReleaseError320 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Field(error) => Some(error),
            Self::Bundle(error) => Some(error),
            Self::UnsupportedRoster { .. }
            | Self::CircuitParticipantCountMismatch { .. }
            | Self::ShareParticipantCountMismatch { .. }
            | Self::ShareEvaluationPointMismatch { .. }
            | Self::DuplicateRosterPosition { .. }
            | Self::ExcessShareCount { .. }
            | Self::Undecodable { .. }
            | Self::ArithmeticOverflow => None,
        }
    }
}

impl From<TallyPreparationError> for MaskedBallotReleaseError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Field(error)
    }
}

impl From<MaskedBallotBundleError320> for MaskedBallotReleaseError320 {
    fn from(error: MaskedBallotBundleError320) -> Self {
        Self::Bundle(error)
    }
}

/// One externally authenticated roster coordinate supplied to the release
/// decoder.
///
/// This value deliberately contains no signature, root, selected-set, state,
/// or source claim. A future positive verifier must establish all of those
/// predicates before constructing the algebraic input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotReleaseCoordinate320 {
    participant_count: u16,
    roster_position: u16,
    evaluation_point: BinaryFieldElement320,
    value: BinaryFieldElement320,
}

impl MaskedBallotReleaseCoordinate320 {
    pub(crate) fn new(
        participant_count: u16,
        roster_position: u16,
        value: BinaryFieldElement320,
    ) -> Result<Self, MaskedBallotReleaseError320> {
        let evaluation_point = canonical_evaluation_point_320(participant_count, roster_position)?;
        Ok(Self {
            participant_count,
            roster_position,
            evaluation_point,
            value,
        })
    }

    pub(crate) fn from_parts(
        participant_count: u16,
        roster_position: u16,
        evaluation_point: BinaryFieldElement320,
        value: BinaryFieldElement320,
    ) -> Result<Self, MaskedBallotReleaseError320> {
        let expected_evaluation_point =
            canonical_evaluation_point_320(participant_count, roster_position)?;
        if evaluation_point != expected_evaluation_point {
            return Err(MaskedBallotReleaseError320::ShareEvaluationPointMismatch {
                roster_position,
            });
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

    pub(crate) const fn evaluation_point(self) -> BinaryFieldElement320 {
        self.evaluation_point
    }

    pub(crate) const fn value(self) -> BinaryFieldElement320 {
        self.value
    }
}

/// The algebraic result of a complete, externally authenticated release.
///
/// This is not a workflow capability. In particular, the corrected-position
/// diagnostic cannot authorize a release, a selected ballot set, or an
/// activation transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedMaskedBallotRelease320 {
    bundle: MaskedBallotBundle320,
    inconsistent_roster_positions: Vec<u16>,
}

impl DecodedMaskedBallotRelease320 {
    pub(crate) const fn bundle(&self) -> &MaskedBallotBundle320 {
        &self.bundle
    }

    pub(crate) fn inconsistent_roster_positions(&self) -> &[u16] {
        &self.inconsistent_roster_positions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotReleaseDecoding320 {
    Pending {
        required_share_count: usize,
        received_share_count: usize,
    },
    Decoded(DecodedMaskedBallotRelease320),
}

/// Roster-derived Reed-Solomon decoder for the direct ballot candidate.
///
/// The current candidate waits for one authenticated coordinate at every
/// roster position. Once the vector is complete, the decoder accepts only a
/// polynomial of degree below the roster-derived reconstruction threshold
/// that disagrees at no more than the active-fault bound. The code-distance
/// check in `new` makes that polynomial unique whenever it exists.
#[derive(Debug, Clone)]
pub(crate) struct MaskedBallotReleaseDecoder320 {
    participant_count: u16,
    reconstruction_threshold: usize,
    maximum_inconsistent_share_count: usize,
    maximum_interpolation_candidate_count: u64,
}

impl MaskedBallotReleaseDecoder320 {
    pub(crate) fn new(participant_count: u16) -> Result<Self, MaskedBallotReleaseError320> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(MaskedBallotReleaseError320::UnsupportedRoster { participant_count })?;
        let reconstruction_threshold = usize::from(roster_parameters.reconstruction_threshold);
        let maximum_inconsistent_share_count = usize::from(roster_parameters.active_fault_bound);
        let participant_count_usize = usize::from(participant_count);
        let minimum_code_distance = participant_count_usize
            .checked_sub(reconstruction_threshold)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(MaskedBallotReleaseError320::ArithmeticOverflow)?;
        let twice_fault_bound = maximum_inconsistent_share_count
            .checked_mul(2)
            .ok_or(MaskedBallotReleaseError320::ArithmeticOverflow)?;
        if reconstruction_threshold == 0 || minimum_code_distance <= twice_fault_bound {
            return Err(MaskedBallotReleaseError320::UnsupportedRoster { participant_count });
        }
        let maximum_interpolation_candidate_count = binomial_coefficient(
            u64::from(participant_count),
            u64::try_from(reconstruction_threshold)
                .map_err(|_| MaskedBallotReleaseError320::ArithmeticOverflow)?,
        )?;
        Ok(Self {
            participant_count,
            reconstruction_threshold,
            maximum_inconsistent_share_count,
            maximum_interpolation_candidate_count,
        })
    }

    pub(crate) const fn required_share_count(&self) -> usize {
        self.participant_count as usize
    }

    pub(crate) const fn reconstruction_threshold(&self) -> usize {
        self.reconstruction_threshold
    }

    pub(crate) const fn maximum_inconsistent_share_count(&self) -> usize {
        self.maximum_inconsistent_share_count
    }

    pub(crate) const fn codeword_byte_length(&self) -> usize {
        self.required_share_count() * BinaryFieldElement320::CANONICAL_BYTE_LENGTH
    }

    pub(crate) const fn maximum_interpolation_candidate_count(&self) -> u64 {
        self.maximum_interpolation_candidate_count
    }

    pub(crate) fn decode(
        &self,
        circuit: &CompiledTallyCircuit,
        shares: &[MaskedBallotReleaseCoordinate320],
    ) -> Result<MaskedBallotReleaseDecoding320, MaskedBallotReleaseError320> {
        let circuit_participant_count = circuit.profile().participant_count();
        if circuit_participant_count != self.participant_count {
            return Err(
                MaskedBallotReleaseError320::CircuitParticipantCountMismatch {
                    circuit_participant_count,
                    release_participant_count: self.participant_count,
                },
            );
        }
        if shares.len() > self.required_share_count() {
            return Err(MaskedBallotReleaseError320::ExcessShareCount {
                participant_count: self.participant_count,
                actual: shares.len(),
            });
        }

        let mut canonical_shares = shares.to_vec();
        canonical_shares.sort_unstable_by_key(|share| share.roster_position());
        self.validate_shares(&canonical_shares)?;
        if canonical_shares.len() < self.required_share_count() {
            return Ok(MaskedBallotReleaseDecoding320::Pending {
                required_share_count: self.required_share_count(),
                received_share_count: canonical_shares.len(),
            });
        }

        let minimum_matching_share_count = self
            .required_share_count()
            .checked_sub(self.maximum_inconsistent_share_count)
            .ok_or(MaskedBallotReleaseError320::ArithmeticOverflow)?;
        let mut basis_positions = (0..self.reconstruction_threshold).collect::<Vec<_>>();
        loop {
            let basis_shares = basis_positions
                .iter()
                .map(|position| canonical_shares[*position])
                .collect::<Vec<_>>();
            let polynomial = interpolate_polynomial(&basis_shares)?;
            let inconsistent_roster_positions = canonical_shares
                .iter()
                .filter_map(|share| {
                    (polynomial.evaluate(share.evaluation_point()) != share.value())
                        .then_some(share.roster_position())
                })
                .collect::<Vec<_>>();
            if canonical_shares.len() - inconsistent_roster_positions.len()
                >= minimum_matching_share_count
            {
                let bundle = MaskedBallotBundle320::from_field_element(
                    circuit,
                    polynomial.evaluate(BinaryFieldElement320::ZERO),
                )?;
                return Ok(MaskedBallotReleaseDecoding320::Decoded(
                    DecodedMaskedBallotRelease320 {
                        bundle,
                        inconsistent_roster_positions,
                    },
                ));
            }
            if !advance_combination(&mut basis_positions, canonical_shares.len()) {
                break;
            }
        }

        Err(MaskedBallotReleaseError320::Undecodable {
            maximum_inconsistent_share_count: self.maximum_inconsistent_share_count,
        })
    }

    fn validate_shares(
        &self,
        shares: &[MaskedBallotReleaseCoordinate320],
    ) -> Result<(), MaskedBallotReleaseError320> {
        for share in shares {
            if share.participant_count() != self.participant_count {
                return Err(MaskedBallotReleaseError320::ShareParticipantCountMismatch {
                    expected: self.participant_count,
                    actual: share.participant_count(),
                });
            }
            let expected_evaluation_point =
                canonical_evaluation_point_320(self.participant_count, share.roster_position())?;
            if share.evaluation_point() != expected_evaluation_point {
                return Err(MaskedBallotReleaseError320::ShareEvaluationPointMismatch {
                    roster_position: share.roster_position(),
                });
            }
        }
        for adjacent_shares in shares.windows(2) {
            if adjacent_shares[0].roster_position() == adjacent_shares[1].roster_position() {
                return Err(MaskedBallotReleaseError320::DuplicateRosterPosition {
                    roster_position: adjacent_shares[0].roster_position(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct InterpolatedPolynomial320 {
    coefficients: Vec<BinaryFieldElement320>,
}

impl InterpolatedPolynomial320 {
    fn evaluate(&self, point: BinaryFieldElement320) -> BinaryFieldElement320 {
        self.coefficients
            .iter()
            .rev()
            .copied()
            .fold(BinaryFieldElement320::ZERO, |value, coefficient| {
                value.multiply(point).add(coefficient)
            })
    }
}

fn interpolate_polynomial(
    shares: &[MaskedBallotReleaseCoordinate320],
) -> Result<InterpolatedPolynomial320, MaskedBallotReleaseError320> {
    let mut denominators = Vec::with_capacity(shares.len());
    for (selected_position, selected_share) in shares.iter().enumerate() {
        let denominator = shares
            .iter()
            .enumerate()
            .filter(|(other_position, _share)| *other_position != selected_position)
            .map(|(_other_position, other_share)| {
                selected_share
                    .evaluation_point()
                    .add(other_share.evaluation_point())
            })
            .fold(BinaryFieldElement320::ONE, |product, difference| {
                product.multiply(difference)
            });
        denominators.push(denominator);
    }
    let inverse_denominators = batch_invert_nonzero(&denominators)?;

    let mut coefficients = vec![BinaryFieldElement320::ZERO; shares.len()];
    for (selected_position, selected_share) in shares.iter().enumerate() {
        let mut basis_coefficients = vec![BinaryFieldElement320::ONE];
        for (other_position, other_share) in shares.iter().enumerate() {
            if other_position == selected_position {
                continue;
            }
            basis_coefficients =
                multiply_by_x_plus_constant(&basis_coefficients, other_share.evaluation_point());
        }
        let scale = selected_share
            .value()
            .multiply(inverse_denominators[selected_position]);
        for (coefficient, basis_coefficient) in coefficients.iter_mut().zip(basis_coefficients) {
            *coefficient = coefficient.add(basis_coefficient.multiply(scale));
        }
    }
    Ok(InterpolatedPolynomial320 { coefficients })
}

fn multiply_by_x_plus_constant(
    coefficients: &[BinaryFieldElement320],
    constant: BinaryFieldElement320,
) -> Vec<BinaryFieldElement320> {
    let mut product = vec![BinaryFieldElement320::ZERO; coefficients.len() + 1];
    for (position, coefficient) in coefficients.iter().copied().enumerate() {
        product[position] = product[position].add(coefficient.multiply(constant));
        product[position + 1] = product[position + 1].add(coefficient);
    }
    product
}

fn batch_invert_nonzero(
    values: &[BinaryFieldElement320],
) -> Result<Vec<BinaryFieldElement320>, MaskedBallotReleaseError320> {
    let mut prefix_products = Vec::with_capacity(values.len());
    let mut product = BinaryFieldElement320::ONE;
    for value in values {
        prefix_products.push(product);
        product = product.multiply(*value);
    }
    let mut inverse_product = product.multiplicative_inverse()?;
    let mut inverse_values = vec![BinaryFieldElement320::ZERO; values.len()];
    for position in (0..values.len()).rev() {
        inverse_values[position] = inverse_product.multiply(prefix_products[position]);
        inverse_product = inverse_product.multiply(values[position]);
    }
    Ok(inverse_values)
}

fn advance_combination(positions: &mut [usize], item_count: usize) -> bool {
    let selection_count = positions.len();
    for pivot in (0..selection_count).rev() {
        let maximum_position = item_count - selection_count + pivot;
        if positions[pivot] == maximum_position {
            continue;
        }
        positions[pivot] += 1;
        for position in pivot + 1..selection_count {
            positions[position] = positions[position - 1] + 1;
        }
        return true;
    }
    false
}

fn binomial_coefficient(
    item_count: u64,
    selection_count: u64,
) -> Result<u64, MaskedBallotReleaseError320> {
    let smaller_selection_count = selection_count.min(
        item_count
            .checked_sub(selection_count)
            .ok_or(MaskedBallotReleaseError320::ArithmeticOverflow)?,
    );
    let mut coefficient = 1_u64;
    for selected_position in 0..smaller_selection_count {
        coefficient = coefficient
            .checked_mul(item_count - selected_position)
            .ok_or(MaskedBallotReleaseError320::ArithmeticOverflow)?
            / (selected_position + 1);
    }
    Ok(coefficient)
}
