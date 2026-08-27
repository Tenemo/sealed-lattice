use core::fmt;
use zeroize::Zeroize;

use crate::{foundation::derive_foundation_roster_parameters, tally_circuit::CompiledTallyCircuit};

use super::{
    TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bundle_320::{MaskedBallotBundle320, MaskedBallotBundleError320},
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
};

/// Failure of the challenge-free symmetric-bivariate masked-ballot candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotBivariateSharingError320 {
    UnsupportedRoster {
        participant_count: u16,
    },
    CircuitParticipantCountMismatch {
        circuit_participant_count: u16,
        sharing_participant_count: u16,
    },
    RandomCoefficientCountMismatch {
        expected: usize,
        actual: usize,
    },
    RowParticipantCountMismatch {
        expected: u16,
        actual: u16,
    },
    RowEvaluationPointMismatch {
        roster_position: u16,
    },
    RowCrosspointCountMismatch {
        roster_position: u16,
        expected: usize,
        actual: usize,
    },
    RowCrosspointRosterPositionMismatch {
        roster_position: u16,
        crosspoint_position: usize,
        expected_peer_roster_position: u16,
        actual_peer_roster_position: u16,
    },
    RowCrosspointEvaluationPointMismatch {
        roster_position: u16,
        peer_roster_position: u16,
    },
    DuplicateRowRosterPosition {
        roster_position: u16,
    },
    ExcessRowCount {
        participant_count: u16,
        actual: usize,
    },
    NoConsistentRowSet {
        minimum_consistent_row_count: usize,
    },
    ArithmeticOverflow,
    Field(TallyPreparationError),
    Bundle(MaskedBallotBundleError320),
}

impl fmt::Display for MaskedBallotBivariateSharingError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRoster { participant_count } => write!(
                formatter,
                "participant count {participant_count} does not admit symmetric-bivariate masked-ballot sharing"
            ),
            Self::CircuitParticipantCountMismatch {
                circuit_participant_count,
                sharing_participant_count,
            } => write!(
                formatter,
                "circuit participant count {circuit_participant_count} does not match sharing participant count {sharing_participant_count}"
            ),
            Self::RandomCoefficientCountMismatch { expected, actual } => write!(
                formatter,
                "symmetric-bivariate masked-ballot sharing needs {expected} random coefficients but received {actual}"
            ),
            Self::RowParticipantCountMismatch { expected, actual } => write!(
                formatter,
                "masked-ballot row participant count {actual} does not match expected count {expected}"
            ),
            Self::RowEvaluationPointMismatch { roster_position } => write!(
                formatter,
                "masked-ballot row at roster position {roster_position} uses the wrong evaluation point"
            ),
            Self::RowCrosspointCountMismatch {
                roster_position,
                expected,
                actual,
            } => write!(
                formatter,
                "masked-ballot row at roster position {roster_position} has {actual} crosspoints instead of {expected}"
            ),
            Self::RowCrosspointRosterPositionMismatch {
                roster_position,
                crosspoint_position,
                expected_peer_roster_position,
                actual_peer_roster_position,
            } => write!(
                formatter,
                "masked-ballot row at roster position {roster_position} crosspoint {crosspoint_position} names peer {actual_peer_roster_position} instead of {expected_peer_roster_position}"
            ),
            Self::RowCrosspointEvaluationPointMismatch {
                roster_position,
                peer_roster_position,
            } => write!(
                formatter,
                "masked-ballot row at roster position {roster_position} uses the wrong evaluation point for peer {peer_roster_position}"
            ),
            Self::DuplicateRowRosterPosition { roster_position } => write!(
                formatter,
                "masked-ballot release repeats roster position {roster_position}"
            ),
            Self::ExcessRowCount {
                participant_count,
                actual,
            } => write!(
                formatter,
                "masked-ballot release has {actual} rows for a {participant_count}-participant roster"
            ),
            Self::NoConsistentRowSet {
                minimum_consistent_row_count,
            } => write!(
                formatter,
                "complete masked-ballot release contains no mutually consistent set of {minimum_consistent_row_count} rows"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("masked-ballot bivariate-sharing arithmetic overflow")
            }
            Self::Field(error) => error.fmt(formatter),
            Self::Bundle(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MaskedBallotBivariateSharingError320 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Field(error) => Some(error),
            Self::Bundle(error) => Some(error),
            Self::UnsupportedRoster { .. }
            | Self::CircuitParticipantCountMismatch { .. }
            | Self::RandomCoefficientCountMismatch { .. }
            | Self::RowParticipantCountMismatch { .. }
            | Self::RowEvaluationPointMismatch { .. }
            | Self::RowCrosspointCountMismatch { .. }
            | Self::RowCrosspointRosterPositionMismatch { .. }
            | Self::RowCrosspointEvaluationPointMismatch { .. }
            | Self::DuplicateRowRosterPosition { .. }
            | Self::ExcessRowCount { .. }
            | Self::NoConsistentRowSet { .. }
            | Self::ArithmeticOverflow => None,
        }
    }
}

impl From<TallyPreparationError> for MaskedBallotBivariateSharingError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Field(error)
    }
}

impl From<MaskedBallotBundleError320> for MaskedBallotBivariateSharingError320 {
    fn from(error: MaskedBallotBundleError320) -> Self {
        Self::Bundle(error)
    }
}

/// One symmetric bivariate polynomial whose value at `(0, 0)` is the masked
/// ballot bundle.
///
/// The upper-triangular coefficients other than `(0, 0)` are independently
/// sampled by the caller. This scalar candidate authenticates no randomness,
/// root, author, holder, receipt, or state transition.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotSymmetricBivariatePolynomial320 {
    participant_count: u16,
    coefficient_matrix: Vec<Vec<BinaryFieldElement320>>,
}

impl fmt::Debug for MaskedBallotSymmetricBivariatePolynomial320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotSymmetricBivariatePolynomial320")
            .field("participant_count", &self.participant_count)
            .field("coefficient_matrix", &"[redacted]")
            .finish()
    }
}

impl Drop for MaskedBallotSymmetricBivariatePolynomial320 {
    fn drop(&mut self) {
        self.coefficient_matrix.zeroize();
    }
}

impl MaskedBallotSymmetricBivariatePolynomial320 {
    pub(crate) fn from_bundle_and_random_coefficients(
        participant_count: u16,
        bundle: &MaskedBallotBundle320,
        random_upper_triangle_coefficients: &[BinaryFieldElement320],
    ) -> Result<Self, MaskedBallotBivariateSharingError320> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(MaskedBallotBivariateSharingError320::UnsupportedRoster { participant_count })?;
        let coefficient_count_per_axis = usize::from(roster_parameters.reconstruction_threshold);
        let upper_triangle_coefficient_count = coefficient_count_per_axis
            .checked_mul(
                coefficient_count_per_axis
                    .checked_add(1)
                    .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?,
            )
            .and_then(|product| product.checked_div(2))
            .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?;
        let expected_random_coefficient_count = upper_triangle_coefficient_count
            .checked_sub(1)
            .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?;
        if random_upper_triangle_coefficients.len() != expected_random_coefficient_count {
            return Err(
                MaskedBallotBivariateSharingError320::RandomCoefficientCountMismatch {
                    expected: expected_random_coefficient_count,
                    actual: random_upper_triangle_coefficients.len(),
                },
            );
        }

        let mut coefficient_matrix =
            vec![
                vec![BinaryFieldElement320::ZERO; coefficient_count_per_axis];
                coefficient_count_per_axis
            ];
        coefficient_matrix[0][0] = bundle.field_element();
        let mut random_coefficients = random_upper_triangle_coefficients.iter().copied();
        for first_exponent in 0..coefficient_count_per_axis {
            for second_exponent in first_exponent..coefficient_count_per_axis {
                if first_exponent == 0 && second_exponent == 0 {
                    continue;
                }
                let coefficient = random_coefficients
                    .next()
                    .expect("the exact coefficient count was checked above");
                coefficient_matrix[first_exponent][second_exponent] = coefficient;
                coefficient_matrix[second_exponent][first_exponent] = coefficient;
            }
        }
        debug_assert!(random_coefficients.next().is_none());

        Ok(Self {
            participant_count,
            coefficient_matrix,
        })
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) fn coefficient_count_per_axis(&self) -> usize {
        self.coefficient_matrix.len()
    }

    pub(crate) fn random_coefficient_count(&self) -> usize {
        self.coefficient_count_per_axis()
            .checked_mul(self.coefficient_count_per_axis() + 1)
            .and_then(|product| product.checked_div(2))
            .and_then(|count| count.checked_sub(1))
            .expect("a validated roster has a nonempty coefficient matrix")
    }

    pub(crate) fn evaluate(
        &self,
        first_point: BinaryFieldElement320,
        second_point: BinaryFieldElement320,
    ) -> BinaryFieldElement320 {
        self.coefficient_matrix.iter().rev().fold(
            BinaryFieldElement320::ZERO,
            |first_axis_value, row| {
                let second_axis_value = row
                    .iter()
                    .rev()
                    .copied()
                    .fold(BinaryFieldElement320::ZERO, |value, coefficient| {
                        value.multiply(second_point).add(coefficient)
                    });
                first_axis_value
                    .multiply(first_point)
                    .add(second_axis_value)
            },
        )
    }

    pub(crate) fn row(
        &self,
        roster_position: u16,
    ) -> Result<MaskedBallotBivariateRow320, MaskedBallotBivariateSharingError320> {
        let evaluation_point =
            canonical_evaluation_point_320(self.participant_count, roster_position)?;
        let secret_axis_value = self.evaluate(evaluation_point, BinaryFieldElement320::ZERO);
        let crosspoints = (0..self.participant_count)
            .filter(|peer_roster_position| *peer_roster_position != roster_position)
            .map(|peer_roster_position| {
                let peer_evaluation_point =
                    canonical_evaluation_point_320(self.participant_count, peer_roster_position)?;
                Ok(MaskedBallotBivariateCrosspoint320 {
                    peer_roster_position,
                    peer_evaluation_point,
                    value: self.evaluate(evaluation_point, peer_evaluation_point),
                })
            })
            .collect::<Result<Vec<_>, TallyPreparationError>>()?;
        MaskedBallotBivariateRow320::from_parts(
            self.participant_count,
            roster_position,
            evaluation_point,
            secret_axis_value,
            crosspoints,
        )
    }

    #[cfg(test)]
    pub(crate) fn coefficient_matrix(&self) -> &[Vec<BinaryFieldElement320>] {
        &self.coefficient_matrix
    }

    #[cfg(test)]
    pub(crate) fn from_symmetric_coefficient_matrix(
        participant_count: u16,
        coefficient_matrix: Vec<Vec<BinaryFieldElement320>>,
    ) -> Result<Self, MaskedBallotBivariateSharingError320> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(MaskedBallotBivariateSharingError320::UnsupportedRoster { participant_count })?;
        let expected_coefficient_count = usize::from(roster_parameters.reconstruction_threshold);
        if coefficient_matrix.len() != expected_coefficient_count
            || coefficient_matrix
                .iter()
                .any(|row| row.len() != expected_coefficient_count)
        {
            return Err(
                MaskedBallotBivariateSharingError320::RandomCoefficientCountMismatch {
                    expected: expected_coefficient_count
                        .checked_mul(expected_coefficient_count + 1)
                        .and_then(|product| product.checked_div(2))
                        .and_then(|count| count.checked_sub(1))
                        .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?,
                    actual: coefficient_matrix.iter().map(Vec::len).sum(),
                },
            );
        }
        for first_exponent in 0..expected_coefficient_count {
            for second_exponent in 0..expected_coefficient_count {
                if coefficient_matrix[first_exponent][second_exponent]
                    != coefficient_matrix[second_exponent][first_exponent]
                {
                    return Err(MaskedBallotBivariateSharingError320::NoConsistentRowSet {
                        minimum_consistent_row_count: expected_coefficient_count,
                    });
                }
            }
        }
        Ok(Self {
            participant_count,
            coefficient_matrix,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateCrosspoint320 {
    peer_roster_position: u16,
    peer_evaluation_point: BinaryFieldElement320,
    value: BinaryFieldElement320,
}

impl fmt::Debug for MaskedBallotBivariateCrosspoint320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateCrosspoint320")
            .field("peer_roster_position", &self.peer_roster_position)
            .field("peer_evaluation_point", &self.peer_evaluation_point)
            .field("value", &"[redacted]")
            .finish()
    }
}

impl Zeroize for MaskedBallotBivariateCrosspoint320 {
    fn zeroize(&mut self) {
        self.peer_roster_position.zeroize();
        self.peer_evaluation_point.zeroize();
        self.value.zeroize();
    }
}

impl MaskedBallotBivariateCrosspoint320 {
    pub(crate) fn from_parts(
        peer_roster_position: u16,
        peer_evaluation_point: BinaryFieldElement320,
        value: BinaryFieldElement320,
    ) -> Self {
        Self {
            peer_roster_position,
            peer_evaluation_point,
            value,
        }
    }

    pub(crate) const fn peer_roster_position(self) -> u16 {
        self.peer_roster_position
    }

    pub(crate) const fn peer_evaluation_point(self) -> BinaryFieldElement320 {
        self.peer_evaluation_point
    }

    pub(crate) const fn value(self) -> BinaryFieldElement320 {
        self.value
    }
}

/// The algebraic row that one root-bound holder checks before acknowledging
/// custody and may later open after selected-set verification.
///
/// The row consists of the value at the secret axis and one shared
/// crosspoint for every other roster position. A future source verifier must
/// establish that every value is the exact independently salted opening under
/// one author-bound root before constructing this type.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct MaskedBallotBivariateRow320 {
    participant_count: u16,
    roster_position: u16,
    evaluation_point: BinaryFieldElement320,
    secret_axis_value: BinaryFieldElement320,
    crosspoints: Vec<MaskedBallotBivariateCrosspoint320>,
}

impl fmt::Debug for MaskedBallotBivariateRow320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaskedBallotBivariateRow320")
            .field("participant_count", &self.participant_count)
            .field("roster_position", &self.roster_position)
            .field("evaluation_point", &self.evaluation_point)
            .field("secret_axis_value", &"[redacted]")
            .field("crosspoint_count", &self.crosspoints.len())
            .finish()
    }
}

impl Drop for MaskedBallotBivariateRow320 {
    fn drop(&mut self) {
        self.participant_count.zeroize();
        self.roster_position.zeroize();
        self.evaluation_point.zeroize();
        self.secret_axis_value.zeroize();
        self.crosspoints.zeroize();
    }
}

impl MaskedBallotBivariateRow320 {
    pub(crate) fn from_parts(
        participant_count: u16,
        roster_position: u16,
        evaluation_point: BinaryFieldElement320,
        secret_axis_value: BinaryFieldElement320,
        crosspoints: Vec<MaskedBallotBivariateCrosspoint320>,
    ) -> Result<Self, MaskedBallotBivariateSharingError320> {
        derive_foundation_roster_parameters(participant_count)
            .ok_or(MaskedBallotBivariateSharingError320::UnsupportedRoster { participant_count })?;
        let expected_evaluation_point =
            canonical_evaluation_point_320(participant_count, roster_position)?;
        if evaluation_point != expected_evaluation_point {
            return Err(
                MaskedBallotBivariateSharingError320::RowEvaluationPointMismatch {
                    roster_position,
                },
            );
        }
        let expected_crosspoint_count = usize::from(participant_count)
            .checked_sub(1)
            .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?;
        if crosspoints.len() != expected_crosspoint_count {
            return Err(
                MaskedBallotBivariateSharingError320::RowCrosspointCountMismatch {
                    roster_position,
                    expected: expected_crosspoint_count,
                    actual: crosspoints.len(),
                },
            );
        }
        let expected_peer_positions =
            (0..participant_count).filter(|position| *position != roster_position);
        for (crosspoint_position, (crosspoint, expected_peer_roster_position)) in
            crosspoints.iter().zip(expected_peer_positions).enumerate()
        {
            if crosspoint.peer_roster_position() != expected_peer_roster_position {
                return Err(
                    MaskedBallotBivariateSharingError320::RowCrosspointRosterPositionMismatch {
                        roster_position,
                        crosspoint_position,
                        expected_peer_roster_position,
                        actual_peer_roster_position: crosspoint.peer_roster_position(),
                    },
                );
            }
            let expected_peer_evaluation_point =
                canonical_evaluation_point_320(participant_count, expected_peer_roster_position)?;
            if crosspoint.peer_evaluation_point() != expected_peer_evaluation_point {
                return Err(
                    MaskedBallotBivariateSharingError320::RowCrosspointEvaluationPointMismatch {
                        roster_position,
                        peer_roster_position: expected_peer_roster_position,
                    },
                );
            }
        }
        Ok(Self {
            participant_count,
            roster_position,
            evaluation_point,
            secret_axis_value,
            crosspoints,
        })
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) const fn evaluation_point(&self) -> BinaryFieldElement320 {
        self.evaluation_point
    }

    pub(crate) const fn secret_axis_value(&self) -> BinaryFieldElement320 {
        self.secret_axis_value
    }

    pub(crate) fn crosspoints(&self) -> &[MaskedBallotBivariateCrosspoint320] {
        &self.crosspoints
    }

    fn crosspoint_value(&self, peer_roster_position: u16) -> Option<BinaryFieldElement320> {
        self.crosspoints
            .iter()
            .find(|crosspoint| crosspoint.peer_roster_position() == peer_roster_position)
            .map(|crosspoint| crosspoint.value())
    }

    fn interpolation_points(&self) -> Vec<FieldInterpolationPoint320> {
        let mut points = Vec::with_capacity(self.crosspoints.len() + 1);
        points.push(FieldInterpolationPoint320 {
            evaluation_point: BinaryFieldElement320::ZERO,
            value: self.secret_axis_value,
        });
        points.extend(
            self.crosspoints
                .iter()
                .map(|crosspoint| FieldInterpolationPoint320 {
                    evaluation_point: crosspoint.peer_evaluation_point(),
                    value: crosspoint.value(),
                }),
        );
        points
    }

    pub(crate) fn is_locally_degree_bounded(&self, reconstruction_threshold: usize) -> bool {
        let points = self.interpolation_points();
        if reconstruction_threshold == 0 || reconstruction_threshold > points.len() {
            return false;
        }
        let Ok(polynomial) = interpolate_polynomial(&points[..reconstruction_threshold]) else {
            return false;
        };
        points
            .iter()
            .all(|point| polynomial.evaluate(point.evaluation_point) == point.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedMaskedBallotBivariateRelease320 {
    bundle: MaskedBallotBundle320,
    supporting_roster_positions: Vec<u16>,
}

impl DecodedMaskedBallotBivariateRelease320 {
    pub(crate) const fn bundle(&self) -> &MaskedBallotBundle320 {
        &self.bundle
    }

    pub(crate) fn supporting_roster_positions(&self) -> &[u16] {
        &self.supporting_roster_positions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MaskedBallotBivariateReleaseDecoding320 {
    Pending {
        minimum_consistent_row_count: usize,
        received_row_count: usize,
    },
    Decoded(DecodedMaskedBallotBivariateRelease320),
}

/// Challenge-free release decoder for the symmetric-bivariate direct ballot
/// candidate.
///
/// A complete receipt terminal implies that at least `n - f(n)` honest
/// holders checked their exact root-bound rows. Those rows are locally
/// degree-bounded and share one value at every pair coordinate. The decoder
/// can therefore accept as soon as it sees one mutually consistent set of
/// `n - f(n)` released rows; corrupt holders may remain silent. This algebraic
/// result still grants no selected-set, release, activation, or state
/// capability.
#[derive(Debug, Clone)]
pub(crate) struct MaskedBallotBivariateReleaseDecoder320 {
    participant_count: u16,
    reconstruction_threshold: usize,
    minimum_consistent_row_count: usize,
    maximum_row_subset_count: u64,
}

impl MaskedBallotBivariateReleaseDecoder320 {
    pub(crate) fn new(
        participant_count: u16,
    ) -> Result<Self, MaskedBallotBivariateSharingError320> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(MaskedBallotBivariateSharingError320::UnsupportedRoster { participant_count })?;
        let reconstruction_threshold = usize::from(roster_parameters.reconstruction_threshold);
        let minimum_consistent_row_count = usize::from(participant_count)
            .checked_sub(usize::from(roster_parameters.active_fault_bound))
            .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?;
        let minimum_intersection_count = minimum_consistent_row_count
            .checked_mul(2)
            .and_then(|twice_count| twice_count.checked_sub(usize::from(participant_count)))
            .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?;
        if reconstruction_threshold == 0
            || minimum_consistent_row_count < reconstruction_threshold
            || minimum_intersection_count < reconstruction_threshold
        {
            return Err(MaskedBallotBivariateSharingError320::UnsupportedRoster {
                participant_count,
            });
        }
        let maximum_row_subset_count = binomial_coefficient(
            u64::from(participant_count),
            u64::try_from(minimum_consistent_row_count)
                .map_err(|_| MaskedBallotBivariateSharingError320::ArithmeticOverflow)?,
        )?;
        Ok(Self {
            participant_count,
            reconstruction_threshold,
            minimum_consistent_row_count,
            maximum_row_subset_count,
        })
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn reconstruction_threshold(&self) -> usize {
        self.reconstruction_threshold
    }

    pub(crate) const fn minimum_consistent_row_count(&self) -> usize {
        self.minimum_consistent_row_count
    }

    pub(crate) const fn maximum_row_subset_count(&self) -> u64 {
        self.maximum_row_subset_count
    }

    pub(crate) fn committed_field_value_count(&self) -> usize {
        let participant_count = usize::from(self.participant_count);
        participant_count
            .checked_mul(
                participant_count
                    .checked_sub(1)
                    .expect("an admitted roster is nonempty"),
            )
            .and_then(|ordered_pair_count| ordered_pair_count.checked_div(2))
            .and_then(|unordered_pair_count| unordered_pair_count.checked_add(participant_count))
            .expect("the admitted roster field-value count fits usize")
    }

    pub(crate) fn field_values_per_holder(&self) -> usize {
        usize::from(self.participant_count)
    }

    pub(crate) fn decode(
        &self,
        circuit: &CompiledTallyCircuit,
        rows: &[MaskedBallotBivariateRow320],
    ) -> Result<MaskedBallotBivariateReleaseDecoding320, MaskedBallotBivariateSharingError320> {
        let circuit_participant_count = circuit.profile().participant_count();
        if circuit_participant_count != self.participant_count {
            return Err(
                MaskedBallotBivariateSharingError320::CircuitParticipantCountMismatch {
                    circuit_participant_count,
                    sharing_participant_count: self.participant_count,
                },
            );
        }
        if rows.len() > usize::from(self.participant_count) {
            return Err(MaskedBallotBivariateSharingError320::ExcessRowCount {
                participant_count: self.participant_count,
                actual: rows.len(),
            });
        }

        let mut canonical_rows = rows.to_vec();
        canonical_rows.sort_unstable_by_key(|row| row.roster_position());
        self.validate_row_inventory(&canonical_rows)?;
        if canonical_rows.len() < self.minimum_consistent_row_count {
            return Ok(MaskedBallotBivariateReleaseDecoding320::Pending {
                minimum_consistent_row_count: self.minimum_consistent_row_count,
                received_row_count: canonical_rows.len(),
            });
        }

        let locally_valid_row_positions = canonical_rows
            .iter()
            .enumerate()
            .filter_map(|(position, row)| {
                row.is_locally_degree_bounded(self.reconstruction_threshold)
                    .then_some(position)
            })
            .collect::<Vec<_>>();
        if locally_valid_row_positions.len() >= self.minimum_consistent_row_count {
            let mut subset_positions = (0..self.minimum_consistent_row_count).collect::<Vec<_>>();
            loop {
                let selected_rows = subset_positions
                    .iter()
                    .map(|subset_position| {
                        &canonical_rows[locally_valid_row_positions[*subset_position]]
                    })
                    .collect::<Vec<_>>();
                if rows_are_pairwise_consistent(&selected_rows) {
                    let secret_axis_points = selected_rows
                        .iter()
                        .map(|row| FieldInterpolationPoint320 {
                            evaluation_point: row.evaluation_point(),
                            value: row.secret_axis_value(),
                        })
                        .collect::<Vec<_>>();
                    let polynomial = interpolate_polynomial(
                        &secret_axis_points[..self.reconstruction_threshold],
                    )?;
                    if secret_axis_points
                        .iter()
                        .all(|point| polynomial.evaluate(point.evaluation_point) == point.value)
                    {
                        let bundle = MaskedBallotBundle320::from_field_element(
                            circuit,
                            polynomial.evaluate(BinaryFieldElement320::ZERO),
                        )?;
                        let supporting_roster_positions = selected_rows
                            .iter()
                            .map(|row| row.roster_position())
                            .collect::<Vec<_>>();
                        // Any two subsets of this size intersect in at least
                        // `reconstruction_threshold` rows, as checked in
                        // `new`. Their degree-bounded secret-axis polynomials
                        // therefore agree. The first accepted subset already
                        // determines the only possible reconstructed bundle.
                        return Ok(MaskedBallotBivariateReleaseDecoding320::Decoded(
                            DecodedMaskedBallotBivariateRelease320 {
                                bundle,
                                supporting_roster_positions,
                            },
                        ));
                    }
                }
                if !advance_combination(&mut subset_positions, locally_valid_row_positions.len()) {
                    break;
                }
            }
        }

        if canonical_rows.len() < usize::from(self.participant_count) {
            return Ok(MaskedBallotBivariateReleaseDecoding320::Pending {
                minimum_consistent_row_count: self.minimum_consistent_row_count,
                received_row_count: canonical_rows.len(),
            });
        }
        Err(MaskedBallotBivariateSharingError320::NoConsistentRowSet {
            minimum_consistent_row_count: self.minimum_consistent_row_count,
        })
    }

    fn validate_row_inventory(
        &self,
        rows: &[MaskedBallotBivariateRow320],
    ) -> Result<(), MaskedBallotBivariateSharingError320> {
        for row in rows {
            if row.participant_count() != self.participant_count {
                return Err(
                    MaskedBallotBivariateSharingError320::RowParticipantCountMismatch {
                        expected: self.participant_count,
                        actual: row.participant_count(),
                    },
                );
            }
            let expected_evaluation_point =
                canonical_evaluation_point_320(self.participant_count, row.roster_position())?;
            if row.evaluation_point() != expected_evaluation_point {
                return Err(
                    MaskedBallotBivariateSharingError320::RowEvaluationPointMismatch {
                        roster_position: row.roster_position(),
                    },
                );
            }
        }
        for adjacent_rows in rows.windows(2) {
            if adjacent_rows[0].roster_position() == adjacent_rows[1].roster_position() {
                return Err(
                    MaskedBallotBivariateSharingError320::DuplicateRowRosterPosition {
                        roster_position: adjacent_rows[0].roster_position(),
                    },
                );
            }
        }
        Ok(())
    }
}

fn rows_are_pairwise_consistent(rows: &[&MaskedBallotBivariateRow320]) -> bool {
    for first_position in 0..rows.len() {
        for second_position in first_position + 1..rows.len() {
            let first_row = rows[first_position];
            let second_row = rows[second_position];
            if first_row.crosspoint_value(second_row.roster_position())
                != second_row.crosspoint_value(first_row.roster_position())
            {
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Clone, Copy)]
struct FieldInterpolationPoint320 {
    evaluation_point: BinaryFieldElement320,
    value: BinaryFieldElement320,
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
    points: &[FieldInterpolationPoint320],
) -> Result<InterpolatedPolynomial320, MaskedBallotBivariateSharingError320> {
    let mut denominators = Vec::with_capacity(points.len());
    for (selected_position, selected_point) in points.iter().enumerate() {
        let denominator = points
            .iter()
            .enumerate()
            .filter(|(other_position, _point)| *other_position != selected_position)
            .map(|(_other_position, other_point)| {
                selected_point
                    .evaluation_point
                    .add(other_point.evaluation_point)
            })
            .fold(BinaryFieldElement320::ONE, |product, difference| {
                product.multiply(difference)
            });
        denominators.push(denominator);
    }
    let inverse_denominators = batch_invert_nonzero(&denominators)?;

    let mut coefficients = vec![BinaryFieldElement320::ZERO; points.len()];
    for (selected_position, selected_point) in points.iter().enumerate() {
        let mut basis_coefficients = vec![BinaryFieldElement320::ONE];
        for (other_position, other_point) in points.iter().enumerate() {
            if other_position == selected_position {
                continue;
            }
            basis_coefficients =
                multiply_by_x_plus_constant(&basis_coefficients, other_point.evaluation_point);
        }
        let scale = selected_point
            .value
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
) -> Result<Vec<BinaryFieldElement320>, MaskedBallotBivariateSharingError320> {
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
) -> Result<u64, MaskedBallotBivariateSharingError320> {
    let smaller_selection_count = selection_count.min(
        item_count
            .checked_sub(selection_count)
            .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?,
    );
    let mut coefficient = 1_u64;
    for selected_position in 0..smaller_selection_count {
        coefficient = coefficient
            .checked_mul(item_count - selected_position)
            .ok_or(MaskedBallotBivariateSharingError320::ArithmeticOverflow)?
            / (selected_position + 1);
    }
    Ok(coefficient)
}
