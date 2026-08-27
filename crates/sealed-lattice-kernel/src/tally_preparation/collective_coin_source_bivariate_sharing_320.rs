use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::foundation::derive_foundation_roster_parameters;

use super::{
    TallyPreparationError,
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_320::canonical_evaluation_point_320,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH, SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH,
    },
    pseudorandom_zero_sharing_seed_master_join_320::LocallyJoinedPseudorandomZeroSharingSeedMasters320,
};

const COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT: usize = 3;
const COMMITMENT_SALT_PREFIX_BYTE_LENGTH: usize = BinaryFieldElement320::CANONICAL_BYTE_LENGTH;
const COMMITMENT_SALT_SUFFIX_BYTE_LENGTH: usize =
    SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH - COMMITMENT_SALT_PREFIX_BYTE_LENGTH;

/// The three field elements that carry one collective-coin source and its
/// independently retained commitment salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CollectiveCoinSourceComponent320 {
    Source,
    CommitmentSaltPrefix,
    CommitmentSaltSuffix,
}

impl CollectiveCoinSourceComponent320 {
    pub(super) const ALL: [Self; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT] = [
        Self::Source,
        Self::CommitmentSaltPrefix,
        Self::CommitmentSaltSuffix,
    ];

    pub(super) const fn position(self) -> usize {
        match self {
            Self::Source => 0,
            Self::CommitmentSaltPrefix => 1,
            Self::CommitmentSaltSuffix => 2,
        }
    }
}

impl fmt::Display for CollectiveCoinSourceComponent320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source => "source",
            Self::CommitmentSaltPrefix => "commitment-salt prefix",
            Self::CommitmentSaltSuffix => "commitment-salt suffix",
        })
    }
}

/// Failure of the algebraic collective-coin source-and-salt sharing slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectiveCoinSourceBivariateSharingError320 {
    UnsupportedRoster {
        participant_count: u16,
    },
    ContributorPositionOutOfRange {
        contributor_position: u16,
        participant_count: u16,
    },
    RandomCoefficientCountMismatch {
        expected: usize,
        actual: usize,
    },
    RowParticipantCountMismatch {
        expected: u16,
        actual: u16,
    },
    RowContributorPositionMismatch {
        expected: u16,
        actual: u16,
    },
    RowEvaluationPointMismatch {
        holder_position: u16,
    },
    RowCrosspointCountMismatch {
        holder_position: u16,
        expected: usize,
        actual: usize,
    },
    RowCrosspointHolderPositionMismatch {
        holder_position: u16,
        crosspoint_position: usize,
        expected_peer_holder_position: u16,
        actual_peer_holder_position: u16,
    },
    RowCrosspointEvaluationPointMismatch {
        holder_position: u16,
        peer_holder_position: u16,
    },
    DuplicateHolderPosition {
        holder_position: u16,
    },
    ExcessRowCount {
        participant_count: u16,
        actual: usize,
    },
    RowDegreeExceeded {
        holder_position: u16,
        component: CollectiveCoinSourceComponent320,
    },
    CrosspointMismatch {
        first_holder_position: u16,
        second_holder_position: u16,
        component: CollectiveCoinSourceComponent320,
    },
    SecretAxisMismatch {
        holder_position: u16,
        component: CollectiveCoinSourceComponent320,
    },
    NonzeroCommitmentSaltPadding,
    #[cfg(test)]
    InvalidTestCoefficientMatrix,
    ArithmeticOverflow,
    Field(TallyPreparationError),
}

impl fmt::Display for CollectiveCoinSourceBivariateSharingError320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRoster { participant_count } => write!(
                formatter,
                "participant count {participant_count} does not admit collective-coin bivariate sharing"
            ),
            Self::ContributorPositionOutOfRange {
                contributor_position,
                participant_count,
            } => write!(
                formatter,
                "collective-coin contributor position {contributor_position} is outside the {participant_count}-participant roster"
            ),
            Self::RandomCoefficientCountMismatch { expected, actual } => write!(
                formatter,
                "collective-coin bivariate sharing needs {expected} random coefficients but received {actual}"
            ),
            Self::RowParticipantCountMismatch { expected, actual } => write!(
                formatter,
                "collective-coin row participant count {actual} does not match expected count {expected}"
            ),
            Self::RowContributorPositionMismatch { expected, actual } => write!(
                formatter,
                "collective-coin row contributor position {actual} does not match expected position {expected}"
            ),
            Self::RowEvaluationPointMismatch { holder_position } => write!(
                formatter,
                "collective-coin row for holder {holder_position} uses the wrong evaluation point"
            ),
            Self::RowCrosspointCountMismatch {
                holder_position,
                expected,
                actual,
            } => write!(
                formatter,
                "collective-coin row for holder {holder_position} has {actual} crosspoints instead of {expected}"
            ),
            Self::RowCrosspointHolderPositionMismatch {
                holder_position,
                crosspoint_position,
                expected_peer_holder_position,
                actual_peer_holder_position,
            } => write!(
                formatter,
                "collective-coin row for holder {holder_position} crosspoint {crosspoint_position} names peer {actual_peer_holder_position} instead of {expected_peer_holder_position}"
            ),
            Self::RowCrosspointEvaluationPointMismatch {
                holder_position,
                peer_holder_position,
            } => write!(
                formatter,
                "collective-coin row for holder {holder_position} uses the wrong evaluation point for peer {peer_holder_position}"
            ),
            Self::DuplicateHolderPosition { holder_position } => write!(
                formatter,
                "collective-coin release repeats holder position {holder_position}"
            ),
            Self::ExcessRowCount {
                participant_count,
                actual,
            } => write!(
                formatter,
                "collective-coin release has {actual} rows for a {participant_count}-participant roster"
            ),
            Self::RowDegreeExceeded {
                holder_position,
                component,
            } => write!(
                formatter,
                "collective-coin row for holder {holder_position} exceeds the admitted degree in the {component} component"
            ),
            Self::CrosspointMismatch {
                first_holder_position,
                second_holder_position,
                component,
            } => write!(
                formatter,
                "collective-coin rows for holders {first_holder_position} and {second_holder_position} disagree at their reciprocal crosspoint in the {component} component"
            ),
            Self::SecretAxisMismatch {
                holder_position,
                component,
            } => write!(
                formatter,
                "collective-coin row for holder {holder_position} does not lie on the reconstructed secret axis in the {component} component"
            ),
            Self::NonzeroCommitmentSaltPadding => formatter
                .write_str("collective-coin commitment-salt suffix has nonzero canonical padding"),
            #[cfg(test)]
            Self::InvalidTestCoefficientMatrix => formatter.write_str(
                "collective-coin test coefficient matrix has the wrong shape or is not symmetric",
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("collective-coin bivariate-sharing arithmetic overflow")
            }
            Self::Field(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CollectiveCoinSourceBivariateSharingError320 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Field(error) => Some(error),
            Self::UnsupportedRoster { .. }
            | Self::ContributorPositionOutOfRange { .. }
            | Self::RandomCoefficientCountMismatch { .. }
            | Self::RowParticipantCountMismatch { .. }
            | Self::RowContributorPositionMismatch { .. }
            | Self::RowEvaluationPointMismatch { .. }
            | Self::RowCrosspointCountMismatch { .. }
            | Self::RowCrosspointHolderPositionMismatch { .. }
            | Self::RowCrosspointEvaluationPointMismatch { .. }
            | Self::DuplicateHolderPosition { .. }
            | Self::ExcessRowCount { .. }
            | Self::RowDegreeExceeded { .. }
            | Self::CrosspointMismatch { .. }
            | Self::SecretAxisMismatch { .. }
            | Self::NonzeroCommitmentSaltPadding
            | Self::ArithmeticOverflow => None,
            #[cfg(test)]
            Self::InvalidTestCoefficientMatrix => None,
        }
    }
}

impl From<TallyPreparationError> for CollectiveCoinSourceBivariateSharingError320 {
    fn from(error: TallyPreparationError) -> Self {
        Self::Field(error)
    }
}

/// Three independently randomized symmetric bivariate polynomials carrying
/// the retained 40-byte source and 64-byte commitment salt.
///
/// Random coefficients are supplied in component order: source, salt prefix,
/// then padded salt suffix. Within each component they follow upper-triangle
/// exponent order, excluding the constant at `(0, 0)`. This algebraic owner
/// emits no canonical carrier, root, receipt, opening authorization, burn, or
/// continuation capability.
pub(crate) struct CollectiveCoinSourceSymmetricBivariatePolynomial320 {
    participant_count: u16,
    contributor_position: u16,
    coefficient_matrices: [Vec<Vec<BinaryFieldElement320>>; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
}

impl fmt::Debug for CollectiveCoinSourceSymmetricBivariatePolynomial320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceSymmetricBivariatePolynomial320")
            .field("participant_count", &self.participant_count)
            .field("contributor_position", &self.contributor_position)
            .field("coefficient_matrices", &"[redacted]")
            .finish()
    }
}

impl Drop for CollectiveCoinSourceSymmetricBivariatePolynomial320 {
    fn drop(&mut self) {
        for coefficient_matrix in &mut self.coefficient_matrices {
            coefficient_matrix.zeroize();
        }
    }
}

impl CollectiveCoinSourceSymmetricBivariatePolynomial320 {
    /// Consumes the source and salt retained by the positively joined
    /// seed-master owner together with caller-transferred fresh random
    /// coefficients. The transferred coefficient buffer is erased on every
    /// return path. Successful construction still supplies algebraic shares
    /// only and does not authorize their delivery or opening.
    pub(crate) fn from_joined_seed_masters_and_random_coefficients(
        joined_seed_masters: &LocallyJoinedPseudorandomZeroSharingSeedMasters320,
        random_upper_triangle_coefficients: Vec<BinaryFieldElement320>,
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        let random_upper_triangle_coefficients = Zeroizing::new(random_upper_triangle_coefficients);
        let participant_count = joined_seed_masters
            .preparation_context()
            .participant_count();
        let contributor_position = joined_seed_masters.participant_position();
        let collective_coin_source = joined_seed_masters.collective_coin_source();
        Self::from_source_and_salt(
            participant_count,
            contributor_position,
            collective_coin_source.source(),
            collective_coin_source.commitment_salt(),
            &random_upper_triangle_coefficients,
        )
    }

    fn from_source_and_salt(
        participant_count: u16,
        contributor_position: u16,
        source: &[u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
        commitment_salt: &[u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
        random_upper_triangle_coefficients: &[BinaryFieldElement320],
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        let mut salt_suffix_bytes =
            Zeroizing::new([0_u8; BinaryFieldElement320::CANONICAL_BYTE_LENGTH]);
        salt_suffix_bytes[..COMMITMENT_SALT_SUFFIX_BYTE_LENGTH]
            .copy_from_slice(&commitment_salt[COMMITMENT_SALT_PREFIX_BYTE_LENGTH..]);
        let component_secrets = [
            BinaryFieldElement320::from_canonical_bytes(source)?,
            BinaryFieldElement320::from_canonical_bytes(
                &commitment_salt[..COMMITMENT_SALT_PREFIX_BYTE_LENGTH],
            )?,
            BinaryFieldElement320::from_canonical_bytes(salt_suffix_bytes.as_ref())?,
        ];
        Self::from_component_secrets(
            participant_count,
            contributor_position,
            component_secrets,
            random_upper_triangle_coefficients,
        )
    }

    fn from_component_secrets(
        participant_count: u16,
        contributor_position: u16,
        component_secrets: [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
        random_upper_triangle_coefficients: &[BinaryFieldElement320],
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        let mut component_secrets = Zeroizing::new(component_secrets);
        let roster_parameters = derive_foundation_roster_parameters(participant_count).ok_or(
            CollectiveCoinSourceBivariateSharingError320::UnsupportedRoster { participant_count },
        )?;
        if contributor_position >= participant_count {
            component_secrets.zeroize();
            return Err(
                CollectiveCoinSourceBivariateSharingError320::ContributorPositionOutOfRange {
                    contributor_position,
                    participant_count,
                },
            );
        }
        let coefficient_count_per_axis = usize::from(roster_parameters.reconstruction_threshold);
        let random_coefficient_count_per_component =
            random_coefficient_count_per_component(coefficient_count_per_axis)?;
        let expected_random_coefficient_count = random_coefficient_count_per_component
            .checked_mul(COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT)
            .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)?;
        if random_upper_triangle_coefficients.len() != expected_random_coefficient_count {
            component_secrets.zeroize();
            return Err(
                CollectiveCoinSourceBivariateSharingError320::RandomCoefficientCountMismatch {
                    expected: expected_random_coefficient_count,
                    actual: random_upper_triangle_coefficients.len(),
                },
            );
        }

        let mut coefficient_matrices: [Vec<Vec<BinaryFieldElement320>>;
            COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT] = core::array::from_fn(|_| {
            vec![
                vec![BinaryFieldElement320::ZERO; coefficient_count_per_axis];
                coefficient_count_per_axis
            ]
        });
        for component in CollectiveCoinSourceComponent320::ALL {
            let component_position = component.position();
            let coefficient_offset = component_position
                .checked_mul(random_coefficient_count_per_component)
                .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)?;
            let random_coefficients = random_upper_triangle_coefficients
                [coefficient_offset..coefficient_offset + random_coefficient_count_per_component]
                .iter()
                .copied();
            fill_symmetric_coefficient_matrix(
                &mut coefficient_matrices[component_position],
                component_secrets[component_position],
                random_coefficients,
            );
        }
        component_secrets.zeroize();

        Ok(Self {
            participant_count,
            contributor_position,
            coefficient_matrices,
        })
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn contributor_position(&self) -> u16 {
        self.contributor_position
    }

    pub(crate) fn coefficient_count_per_axis(&self) -> usize {
        self.coefficient_matrices[0].len()
    }

    pub(crate) fn random_coefficient_count(&self) -> usize {
        random_coefficient_count_per_component(self.coefficient_count_per_axis())
            .and_then(|count| {
                count
                    .checked_mul(COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT)
                    .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)
            })
            .expect("a validated roster has a bounded coefficient count")
    }

    pub(crate) fn evaluate(
        &self,
        component: CollectiveCoinSourceComponent320,
        first_point: BinaryFieldElement320,
        second_point: BinaryFieldElement320,
    ) -> BinaryFieldElement320 {
        evaluate_coefficient_matrix(
            &self.coefficient_matrices[component.position()],
            first_point,
            second_point,
        )
    }

    pub(crate) fn row(
        &self,
        holder_position: u16,
    ) -> Result<CollectiveCoinSourceBivariateRow320, CollectiveCoinSourceBivariateSharingError320>
    {
        let evaluation_point =
            canonical_evaluation_point_320(self.participant_count, holder_position)?;
        let secret_axis_values = core::array::from_fn(|component_position| {
            let component = CollectiveCoinSourceComponent320::ALL[component_position];
            self.evaluate(component, evaluation_point, BinaryFieldElement320::ZERO)
        });
        let crosspoints = (0..self.participant_count)
            .filter(|peer_holder_position| *peer_holder_position != holder_position)
            .map(|peer_holder_position| {
                let peer_evaluation_point =
                    canonical_evaluation_point_320(self.participant_count, peer_holder_position)?;
                let component_values = core::array::from_fn(|component_position| {
                    let component = CollectiveCoinSourceComponent320::ALL[component_position];
                    self.evaluate(component, evaluation_point, peer_evaluation_point)
                });
                Ok(CollectiveCoinSourceBivariateCrosspoint320 {
                    peer_holder_position,
                    peer_evaluation_point,
                    component_values,
                })
            })
            .collect::<Result<Vec<_>, TallyPreparationError>>()?;
        CollectiveCoinSourceBivariateRow320::from_parts(
            self.participant_count,
            self.contributor_position,
            holder_position,
            evaluation_point,
            secret_axis_values,
            crosspoints,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_source_and_salt_for_test(
        participant_count: u16,
        contributor_position: u16,
        source: &[u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
        commitment_salt: &[u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
        random_upper_triangle_coefficients: &[BinaryFieldElement320],
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        Self::from_source_and_salt(
            participant_count,
            contributor_position,
            source,
            commitment_salt,
            random_upper_triangle_coefficients,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_component_secrets_for_test(
        participant_count: u16,
        contributor_position: u16,
        component_secrets: [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
        random_upper_triangle_coefficients: &[BinaryFieldElement320],
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        Self::from_component_secrets(
            participant_count,
            contributor_position,
            component_secrets,
            random_upper_triangle_coefficients,
        )
    }

    #[cfg(test)]
    pub(crate) fn coefficient_matrices(
        &self,
    ) -> &[Vec<Vec<BinaryFieldElement320>>; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT] {
        &self.coefficient_matrices
    }

    #[cfg(test)]
    pub(crate) fn from_coefficient_matrices_for_test(
        participant_count: u16,
        contributor_position: u16,
        coefficient_matrices: [Vec<Vec<BinaryFieldElement320>>;
            COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).ok_or(
            CollectiveCoinSourceBivariateSharingError320::UnsupportedRoster { participant_count },
        )?;
        if contributor_position >= participant_count {
            return Err(
                CollectiveCoinSourceBivariateSharingError320::ContributorPositionOutOfRange {
                    contributor_position,
                    participant_count,
                },
            );
        }
        let expected_coefficient_count = usize::from(roster_parameters.reconstruction_threshold);
        for coefficient_matrix in &coefficient_matrices {
            if coefficient_matrix.len() != expected_coefficient_count
                || coefficient_matrix
                    .iter()
                    .any(|row| row.len() != expected_coefficient_count)
            {
                return Err(
                    CollectiveCoinSourceBivariateSharingError320::InvalidTestCoefficientMatrix,
                );
            }
            for first_exponent in 0..expected_coefficient_count {
                for second_exponent in 0..expected_coefficient_count {
                    if coefficient_matrix[first_exponent][second_exponent]
                        != coefficient_matrix[second_exponent][first_exponent]
                    {
                        return Err(
                            CollectiveCoinSourceBivariateSharingError320::InvalidTestCoefficientMatrix,
                        );
                    }
                }
            }
        }
        Ok(Self {
            participant_count,
            contributor_position,
            coefficient_matrices,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceBivariateCrosspoint320 {
    peer_holder_position: u16,
    peer_evaluation_point: BinaryFieldElement320,
    component_values: [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
}

impl fmt::Debug for CollectiveCoinSourceBivariateCrosspoint320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceBivariateCrosspoint320")
            .field("peer_holder_position", &self.peer_holder_position)
            .field("peer_evaluation_point", &self.peer_evaluation_point)
            .field("component_values", &"[redacted]")
            .finish()
    }
}

impl Zeroize for CollectiveCoinSourceBivariateCrosspoint320 {
    fn zeroize(&mut self) {
        self.peer_holder_position.zeroize();
        self.peer_evaluation_point.zeroize();
        self.component_values.zeroize();
    }
}

impl CollectiveCoinSourceBivariateCrosspoint320 {
    pub(crate) const fn from_parts(
        peer_holder_position: u16,
        peer_evaluation_point: BinaryFieldElement320,
        component_values: [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
    ) -> Self {
        Self {
            peer_holder_position,
            peer_evaluation_point,
            component_values,
        }
    }

    pub(crate) const fn peer_holder_position(self) -> u16 {
        self.peer_holder_position
    }

    pub(crate) const fn peer_evaluation_point(self) -> BinaryFieldElement320 {
        self.peer_evaluation_point
    }

    pub(crate) const fn component_value(
        self,
        component: CollectiveCoinSourceComponent320,
    ) -> BinaryFieldElement320 {
        self.component_values[component.position()]
    }

    pub(crate) const fn component_values(
        self,
    ) -> [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT] {
        self.component_values
    }
}

/// One holder row for the source and both commitment-salt components.
///
/// A future source-correspondence verifier must construct this type only from
/// exact root-bound openings after local degree and reciprocal crosspoint
/// delivery checks. Raw construction alone authenticates no source or holder.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CollectiveCoinSourceBivariateRow320 {
    participant_count: u16,
    contributor_position: u16,
    holder_position: u16,
    evaluation_point: BinaryFieldElement320,
    secret_axis_values: [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
    crosspoints: Vec<CollectiveCoinSourceBivariateCrosspoint320>,
}

impl fmt::Debug for CollectiveCoinSourceBivariateRow320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CollectiveCoinSourceBivariateRow320")
            .field("participant_count", &self.participant_count)
            .field("contributor_position", &self.contributor_position)
            .field("holder_position", &self.holder_position)
            .field("evaluation_point", &self.evaluation_point)
            .field("secret_axis_values", &"[redacted]")
            .field("crosspoint_count", &self.crosspoints.len())
            .finish()
    }
}

impl Drop for CollectiveCoinSourceBivariateRow320 {
    fn drop(&mut self) {
        self.participant_count.zeroize();
        self.contributor_position.zeroize();
        self.holder_position.zeroize();
        self.evaluation_point.zeroize();
        self.secret_axis_values.zeroize();
        self.crosspoints.zeroize();
    }
}

impl CollectiveCoinSourceBivariateRow320 {
    pub(crate) fn from_parts(
        participant_count: u16,
        contributor_position: u16,
        holder_position: u16,
        evaluation_point: BinaryFieldElement320,
        secret_axis_values: [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
        crosspoints: Vec<CollectiveCoinSourceBivariateCrosspoint320>,
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        let mut secret_axis_values = Zeroizing::new(secret_axis_values);
        let mut crosspoints = Zeroizing::new(crosspoints);
        derive_foundation_roster_parameters(participant_count).ok_or(
            CollectiveCoinSourceBivariateSharingError320::UnsupportedRoster { participant_count },
        )?;
        if contributor_position >= participant_count {
            return Err(
                CollectiveCoinSourceBivariateSharingError320::ContributorPositionOutOfRange {
                    contributor_position,
                    participant_count,
                },
            );
        }
        let expected_evaluation_point =
            canonical_evaluation_point_320(participant_count, holder_position)?;
        if evaluation_point != expected_evaluation_point {
            return Err(
                CollectiveCoinSourceBivariateSharingError320::RowEvaluationPointMismatch {
                    holder_position,
                },
            );
        }
        let expected_crosspoint_count = usize::from(participant_count)
            .checked_sub(1)
            .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)?;
        if crosspoints.len() != expected_crosspoint_count {
            return Err(
                CollectiveCoinSourceBivariateSharingError320::RowCrosspointCountMismatch {
                    holder_position,
                    expected: expected_crosspoint_count,
                    actual: crosspoints.len(),
                },
            );
        }
        let expected_peer_positions =
            (0..participant_count).filter(|position| *position != holder_position);
        for (crosspoint_position, (crosspoint, expected_peer_holder_position)) in
            crosspoints.iter().zip(expected_peer_positions).enumerate()
        {
            if crosspoint.peer_holder_position() != expected_peer_holder_position {
                return Err(
                    CollectiveCoinSourceBivariateSharingError320::RowCrosspointHolderPositionMismatch {
                        holder_position,
                        crosspoint_position,
                        expected_peer_holder_position,
                        actual_peer_holder_position: crosspoint.peer_holder_position(),
                    },
                );
            }
            let expected_peer_evaluation_point =
                canonical_evaluation_point_320(participant_count, expected_peer_holder_position)?;
            if crosspoint.peer_evaluation_point() != expected_peer_evaluation_point {
                return Err(
                    CollectiveCoinSourceBivariateSharingError320::RowCrosspointEvaluationPointMismatch {
                        holder_position,
                        peer_holder_position: expected_peer_holder_position,
                    },
                );
            }
        }
        Ok(Self {
            participant_count,
            contributor_position,
            holder_position,
            evaluation_point,
            secret_axis_values: core::mem::replace(
                &mut *secret_axis_values,
                [BinaryFieldElement320::ZERO; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT],
            ),
            crosspoints: core::mem::take(&mut *crosspoints),
        })
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn contributor_position(&self) -> u16 {
        self.contributor_position
    }

    pub(crate) const fn holder_position(&self) -> u16 {
        self.holder_position
    }

    pub(crate) const fn evaluation_point(&self) -> BinaryFieldElement320 {
        self.evaluation_point
    }

    pub(crate) const fn secret_axis_value(
        &self,
        component: CollectiveCoinSourceComponent320,
    ) -> BinaryFieldElement320 {
        self.secret_axis_values[component.position()]
    }

    pub(crate) const fn secret_axis_values(
        &self,
    ) -> [BinaryFieldElement320; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT] {
        self.secret_axis_values
    }

    pub(crate) fn crosspoints(&self) -> &[CollectiveCoinSourceBivariateCrosspoint320] {
        &self.crosspoints
    }

    fn crosspoint_value(
        &self,
        peer_holder_position: u16,
        component: CollectiveCoinSourceComponent320,
    ) -> Option<BinaryFieldElement320> {
        self.crosspoints
            .iter()
            .find(|crosspoint| crosspoint.peer_holder_position() == peer_holder_position)
            .map(|crosspoint| crosspoint.component_value(component))
    }

    fn interpolation_points(
        &self,
        component: CollectiveCoinSourceComponent320,
    ) -> Vec<FieldInterpolationPoint320> {
        let mut points = Vec::with_capacity(self.crosspoints.len() + 1);
        points.push(FieldInterpolationPoint320 {
            evaluation_point: BinaryFieldElement320::ZERO,
            value: self.secret_axis_value(component),
        });
        points.extend(
            self.crosspoints
                .iter()
                .map(|crosspoint| FieldInterpolationPoint320 {
                    evaluation_point: crosspoint.peer_evaluation_point(),
                    value: crosspoint.component_value(component),
                }),
        );
        points
    }

    pub(super) fn is_locally_degree_bounded(
        &self,
        component: CollectiveCoinSourceComponent320,
        reconstruction_threshold: usize,
    ) -> bool {
        let points = self.interpolation_points(component);
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

/// Reconstructed source and commitment salt with no challenge or continuation
/// authority.
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct DecodedCollectiveCoinSourceBivariateRelease320 {
    source: [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
    commitment_salt: [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    supporting_holder_positions: Vec<u16>,
}

impl fmt::Debug for DecodedCollectiveCoinSourceBivariateRelease320 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedCollectiveCoinSourceBivariateRelease320")
            .field("source", &"[redacted]")
            .field("commitment_salt", &"[redacted]")
            .field(
                "supporting_holder_positions",
                &self.supporting_holder_positions,
            )
            .finish()
    }
}

impl Drop for DecodedCollectiveCoinSourceBivariateRelease320 {
    fn drop(&mut self) {
        self.source.zeroize();
        self.commitment_salt.zeroize();
        self.supporting_holder_positions.zeroize();
    }
}

impl DecodedCollectiveCoinSourceBivariateRelease320 {
    pub(crate) const fn source(&self) -> &[u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH] {
        &self.source
    }

    pub(crate) const fn commitment_salt(
        &self,
    ) -> &[u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH] {
        &self.commitment_salt
    }

    pub(crate) fn supporting_holder_positions(&self) -> &[u16] {
        &self.supporting_holder_positions
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) enum CollectiveCoinSourceBivariateReleaseDecoding320 {
    Pending {
        minimum_consistent_row_count: usize,
        received_row_count: usize,
    },
    Decoded(DecodedCollectiveCoinSourceBivariateRelease320),
}

/// Strict algebraic decoder for one contributor's source-and-salt release.
///
/// The decoder accepts only `n - t` or more mutually consistent rows. It
/// checks every supplied row and never drops, diagnoses for correction, or
/// continues around an inconsistent value. A future protocol owner must feed
/// only positively authenticated root-bound rows and map every error to the
/// single action burn; missing rows remain pending. This type itself grants no
/// challenge-opening or preparation capability.
#[derive(Debug, Clone)]
pub(crate) struct CollectiveCoinSourceBivariateReleaseDecoder320 {
    participant_count: u16,
    contributor_position: u16,
    reconstruction_threshold: usize,
    minimum_consistent_row_count: usize,
}

impl CollectiveCoinSourceBivariateReleaseDecoder320 {
    pub(crate) fn new(
        participant_count: u16,
        contributor_position: u16,
    ) -> Result<Self, CollectiveCoinSourceBivariateSharingError320> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).ok_or(
            CollectiveCoinSourceBivariateSharingError320::UnsupportedRoster { participant_count },
        )?;
        if contributor_position >= participant_count {
            return Err(
                CollectiveCoinSourceBivariateSharingError320::ContributorPositionOutOfRange {
                    contributor_position,
                    participant_count,
                },
            );
        }
        let reconstruction_threshold = usize::from(roster_parameters.reconstruction_threshold);
        let minimum_consistent_row_count = usize::from(participant_count)
            .checked_sub(usize::from(roster_parameters.active_fault_bound))
            .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)?;
        let minimum_intersection_count = minimum_consistent_row_count
            .checked_mul(2)
            .and_then(|twice_count| twice_count.checked_sub(usize::from(participant_count)))
            .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)?;
        if reconstruction_threshold == 0
            || minimum_consistent_row_count < reconstruction_threshold
            || minimum_intersection_count < reconstruction_threshold
        {
            return Err(
                CollectiveCoinSourceBivariateSharingError320::UnsupportedRoster {
                    participant_count,
                },
            );
        }
        Ok(Self {
            participant_count,
            contributor_position,
            reconstruction_threshold,
            minimum_consistent_row_count,
        })
    }

    pub(crate) const fn participant_count(&self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn contributor_position(&self) -> u16 {
        self.contributor_position
    }

    pub(crate) const fn reconstruction_threshold(&self) -> usize {
        self.reconstruction_threshold
    }

    pub(crate) const fn minimum_consistent_row_count(&self) -> usize {
        self.minimum_consistent_row_count
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
            .and_then(|field_values| {
                field_values.checked_mul(COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT)
            })
            .expect("the admitted roster field-value count fits usize")
    }

    pub(crate) fn field_values_per_holder(&self) -> usize {
        usize::from(self.participant_count)
            .checked_mul(COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT)
            .expect("the admitted holder field-value count fits usize")
    }

    pub(crate) fn decode(
        &self,
        rows: &[CollectiveCoinSourceBivariateRow320],
    ) -> Result<
        CollectiveCoinSourceBivariateReleaseDecoding320,
        CollectiveCoinSourceBivariateSharingError320,
    > {
        if rows.len() > usize::from(self.participant_count) {
            return Err(
                CollectiveCoinSourceBivariateSharingError320::ExcessRowCount {
                    participant_count: self.participant_count,
                    actual: rows.len(),
                },
            );
        }

        let mut canonical_rows = rows.to_vec();
        canonical_rows.sort_unstable_by_key(|row| row.holder_position());
        self.validate_row_inventory(&canonical_rows)?;
        self.validate_all_supplied_rows(&canonical_rows)?;
        if canonical_rows.len() < self.minimum_consistent_row_count {
            return Ok(CollectiveCoinSourceBivariateReleaseDecoding320::Pending {
                minimum_consistent_row_count: self.minimum_consistent_row_count,
                received_row_count: canonical_rows.len(),
            });
        }

        let mut component_secrets =
            Zeroizing::new([BinaryFieldElement320::ZERO; COLLECTIVE_COIN_SOURCE_COMPONENT_COUNT]);
        for component in CollectiveCoinSourceComponent320::ALL {
            let secret_axis_points = canonical_rows
                .iter()
                .map(|row| FieldInterpolationPoint320 {
                    evaluation_point: row.evaluation_point(),
                    value: row.secret_axis_value(component),
                })
                .collect::<Vec<_>>();
            let polynomial =
                interpolate_polynomial(&secret_axis_points[..self.reconstruction_threshold])?;
            for (row, point) in canonical_rows.iter().zip(&secret_axis_points) {
                if polynomial.evaluate(point.evaluation_point) != point.value {
                    component_secrets.zeroize();
                    return Err(
                        CollectiveCoinSourceBivariateSharingError320::SecretAxisMismatch {
                            holder_position: row.holder_position(),
                            component,
                        },
                    );
                }
            }
            component_secrets[component.position()] =
                polynomial.evaluate(BinaryFieldElement320::ZERO);
        }

        let mut source = Zeroizing::new(
            component_secrets[CollectiveCoinSourceComponent320::Source.position()]
                .canonical_bytes(),
        );
        let salt_prefix = Zeroizing::new(
            component_secrets[CollectiveCoinSourceComponent320::CommitmentSaltPrefix.position()]
                .canonical_bytes(),
        );
        let salt_suffix = Zeroizing::new(
            component_secrets[CollectiveCoinSourceComponent320::CommitmentSaltSuffix.position()]
                .canonical_bytes(),
        );
        if salt_suffix[COMMITMENT_SALT_SUFFIX_BYTE_LENGTH..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(CollectiveCoinSourceBivariateSharingError320::NonzeroCommitmentSaltPadding);
        }
        let mut commitment_salt =
            Zeroizing::new([0_u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH]);
        commitment_salt[..COMMITMENT_SALT_PREFIX_BYTE_LENGTH].copy_from_slice(salt_prefix.as_ref());
        commitment_salt[COMMITMENT_SALT_PREFIX_BYTE_LENGTH..]
            .copy_from_slice(&salt_suffix[..COMMITMENT_SALT_SUFFIX_BYTE_LENGTH]);

        Ok(CollectiveCoinSourceBivariateReleaseDecoding320::Decoded(
            DecodedCollectiveCoinSourceBivariateRelease320 {
                source: core::mem::replace(
                    &mut *source,
                    [0_u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
                ),
                commitment_salt: core::mem::replace(
                    &mut *commitment_salt,
                    [0_u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
                ),
                supporting_holder_positions: canonical_rows
                    .iter()
                    .map(|row| row.holder_position())
                    .collect(),
            },
        ))
    }

    fn validate_row_inventory(
        &self,
        rows: &[CollectiveCoinSourceBivariateRow320],
    ) -> Result<(), CollectiveCoinSourceBivariateSharingError320> {
        for row in rows {
            if row.participant_count() != self.participant_count {
                return Err(
                    CollectiveCoinSourceBivariateSharingError320::RowParticipantCountMismatch {
                        expected: self.participant_count,
                        actual: row.participant_count(),
                    },
                );
            }
            if row.contributor_position() != self.contributor_position {
                return Err(
                    CollectiveCoinSourceBivariateSharingError320::RowContributorPositionMismatch {
                        expected: self.contributor_position,
                        actual: row.contributor_position(),
                    },
                );
            }
            let expected_evaluation_point =
                canonical_evaluation_point_320(self.participant_count, row.holder_position())?;
            if row.evaluation_point() != expected_evaluation_point {
                return Err(
                    CollectiveCoinSourceBivariateSharingError320::RowEvaluationPointMismatch {
                        holder_position: row.holder_position(),
                    },
                );
            }
        }
        for adjacent_rows in rows.windows(2) {
            if adjacent_rows[0].holder_position() == adjacent_rows[1].holder_position() {
                return Err(
                    CollectiveCoinSourceBivariateSharingError320::DuplicateHolderPosition {
                        holder_position: adjacent_rows[0].holder_position(),
                    },
                );
            }
        }
        Ok(())
    }

    fn validate_all_supplied_rows(
        &self,
        rows: &[CollectiveCoinSourceBivariateRow320],
    ) -> Result<(), CollectiveCoinSourceBivariateSharingError320> {
        for row in rows {
            for component in CollectiveCoinSourceComponent320::ALL {
                if !row.is_locally_degree_bounded(component, self.reconstruction_threshold) {
                    return Err(
                        CollectiveCoinSourceBivariateSharingError320::RowDegreeExceeded {
                            holder_position: row.holder_position(),
                            component,
                        },
                    );
                }
            }
        }
        for first_row_position in 0..rows.len() {
            for second_row_position in first_row_position + 1..rows.len() {
                let first_row = &rows[first_row_position];
                let second_row = &rows[second_row_position];
                for component in CollectiveCoinSourceComponent320::ALL {
                    if first_row.crosspoint_value(second_row.holder_position(), component)
                        != second_row.crosspoint_value(first_row.holder_position(), component)
                    {
                        return Err(
                            CollectiveCoinSourceBivariateSharingError320::CrosspointMismatch {
                                first_holder_position: first_row.holder_position(),
                                second_holder_position: second_row.holder_position(),
                                component,
                            },
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct FieldInterpolationPoint320 {
    evaluation_point: BinaryFieldElement320,
    value: BinaryFieldElement320,
}

#[derive(Debug)]
struct InterpolatedPolynomial320 {
    coefficients: Vec<BinaryFieldElement320>,
}

impl Drop for InterpolatedPolynomial320 {
    fn drop(&mut self) {
        self.coefficients.zeroize();
    }
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
) -> Result<InterpolatedPolynomial320, CollectiveCoinSourceBivariateSharingError320> {
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
) -> Result<Vec<BinaryFieldElement320>, CollectiveCoinSourceBivariateSharingError320> {
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

fn random_coefficient_count_per_component(
    coefficient_count_per_axis: usize,
) -> Result<usize, CollectiveCoinSourceBivariateSharingError320> {
    coefficient_count_per_axis
        .checked_mul(
            coefficient_count_per_axis
                .checked_add(1)
                .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)?,
        )
        .and_then(|product| product.checked_div(2))
        .and_then(|count| count.checked_sub(1))
        .ok_or(CollectiveCoinSourceBivariateSharingError320::ArithmeticOverflow)
}

fn fill_symmetric_coefficient_matrix(
    coefficient_matrix: &mut [Vec<BinaryFieldElement320>],
    constant: BinaryFieldElement320,
    mut random_coefficients: impl Iterator<Item = BinaryFieldElement320>,
) {
    coefficient_matrix[0][0] = constant;
    for first_exponent in 0..coefficient_matrix.len() {
        for second_exponent in first_exponent..coefficient_matrix.len() {
            if first_exponent == 0 && second_exponent == 0 {
                continue;
            }
            let coefficient = random_coefficients
                .next()
                .expect("the exact random coefficient count was checked by the caller");
            coefficient_matrix[first_exponent][second_exponent] = coefficient;
            coefficient_matrix[second_exponent][first_exponent] = coefficient;
        }
    }
    debug_assert!(random_coefficients.next().is_none());
}

fn evaluate_coefficient_matrix(
    coefficient_matrix: &[Vec<BinaryFieldElement320>],
    first_point: BinaryFieldElement320,
    second_point: BinaryFieldElement320,
) -> BinaryFieldElement320 {
    coefficient_matrix
        .iter()
        .rev()
        .fold(BinaryFieldElement320::ZERO, |first_axis_value, row| {
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
        })
}
