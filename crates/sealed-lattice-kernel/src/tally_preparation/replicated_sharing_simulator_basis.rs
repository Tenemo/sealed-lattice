use crate::foundation::derive_foundation_roster_parameters;

use super::{
    BinaryFieldElement256, TallyPreparationError,
    output_sharing::canonical_evaluation_point,
    replicated_random_sharing::{BinaryFieldPolynomial, ReplicatedRandomSharingSubset},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReplicatedSharingSimulatorBasisError {
    Preparation(TallyPreparationError),
    CorruptPositionCountMismatch {
        expected: usize,
        actual: usize,
    },
    CorruptPositionsNotCanonical,
    DifferenceDegreeOutOfRange {
        maximum_degree: usize,
        actual_degree: usize,
    },
    DifferenceVisibleAtCorruptPosition {
        roster_position: u16,
    },
    DifferenceDecompositionFailure,
}

impl From<TallyPreparationError> for ReplicatedSharingSimulatorBasisError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicatedSharingHiddenComponents {
    random_sharing_component: BinaryFieldElement256,
    zero_sharing_components: Box<[BinaryFieldElement256]>,
}

impl ReplicatedSharingHiddenComponents {
    pub(crate) fn new(
        random_sharing_component: BinaryFieldElement256,
        zero_sharing_components: Vec<BinaryFieldElement256>,
    ) -> Self {
        Self {
            random_sharing_component,
            zero_sharing_components: zero_sharing_components.into_boxed_slice(),
        }
    }

    pub(crate) const fn random_sharing_component(&self) -> BinaryFieldElement256 {
        self.random_sharing_component
    }

    pub(crate) fn zero_sharing_components(&self) -> &[BinaryFieldElement256] {
        &self.zero_sharing_components
    }
}

/// Exact hidden-component basis used by the ideal replicated-sharing
/// simulator for one maximum-size static corruption set.
///
/// This is an unactivated proof model. It neither expands a real keyed stream
/// nor authenticates an opening. Its purpose is to establish mechanically that
/// the one all-honest random-sharing output and the roster-derived number of
/// all-honest zero-sharing outputs are a bijective basis of every bounded-
/// degree polynomial difference invisible at the corrupt evaluation points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicatedSharingSimulatorBasis {
    participant_count: u16,
    corrupt_positions: Box<[u16]>,
    maximum_opening_degree: usize,
    random_sharing_basis: BinaryFieldPolynomial,
    zero_sharing_bases: Box<[BinaryFieldPolynomial]>,
}

impl ReplicatedSharingSimulatorBasis {
    pub(crate) fn new(
        participant_count: u16,
        corrupt_positions: &[u16],
    ) -> Result<Self, ReplicatedSharingSimulatorBasisError> {
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        let active_fault_bound = usize::from(roster_parameters.active_fault_bound);
        if corrupt_positions.len() != active_fault_bound {
            return Err(
                ReplicatedSharingSimulatorBasisError::CorruptPositionCountMismatch {
                    expected: active_fault_bound,
                    actual: corrupt_positions.len(),
                },
            );
        }
        if corrupt_positions
            .windows(2)
            .any(|positions| positions[0] >= positions[1])
        {
            return Err(ReplicatedSharingSimulatorBasisError::CorruptPositionsNotCanonical);
        }

        let all_honest_subset = ReplicatedRandomSharingSubset::from_excluded_positions(
            participant_count,
            corrupt_positions,
        )?;
        let random_sharing_basis =
            all_honest_subset.random_sharing_polynomial(BinaryFieldElement256::ONE)?;
        let zero_sharing_bases = (0..active_fault_bound)
            .map(|basis_position| {
                let mut components = vec![BinaryFieldElement256::ZERO; active_fault_bound];
                components[basis_position] = BinaryFieldElement256::ONE;
                all_honest_subset.zero_sharing_polynomial(&components)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        let maximum_opening_degree = active_fault_bound
            .checked_mul(2)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;

        Ok(Self {
            participant_count,
            corrupt_positions: corrupt_positions.into(),
            maximum_opening_degree,
            random_sharing_basis,
            zero_sharing_bases,
        })
    }

    pub(crate) const fn maximum_opening_degree(&self) -> usize {
        self.maximum_opening_degree
    }

    pub(crate) fn random_sharing_basis(&self) -> &BinaryFieldPolynomial {
        &self.random_sharing_basis
    }

    pub(crate) fn zero_sharing_bases(&self) -> &[BinaryFieldPolynomial] {
        &self.zero_sharing_bases
    }

    pub(crate) fn reassemble(
        &self,
        hidden_components: &ReplicatedSharingHiddenComponents,
    ) -> Result<BinaryFieldPolynomial, ReplicatedSharingSimulatorBasisError> {
        if hidden_components.zero_sharing_components.len() != self.zero_sharing_bases.len() {
            return Err(ReplicatedSharingSimulatorBasisError::DifferenceDecompositionFailure);
        }
        Ok(self
            .zero_sharing_bases
            .iter()
            .zip(hidden_components.zero_sharing_components.iter())
            .fold(
                self.random_sharing_basis
                    .scale(hidden_components.random_sharing_component),
                |difference, (basis, component)| difference.add(&basis.scale(*component)),
            ))
    }

    pub(crate) fn decompose(
        &self,
        difference: &BinaryFieldPolynomial,
    ) -> Result<ReplicatedSharingHiddenComponents, ReplicatedSharingSimulatorBasisError> {
        if difference.degree() > self.maximum_opening_degree {
            return Err(
                ReplicatedSharingSimulatorBasisError::DifferenceDegreeOutOfRange {
                    maximum_degree: self.maximum_opening_degree,
                    actual_degree: difference.degree(),
                },
            );
        }
        for roster_position in &self.corrupt_positions {
            let evaluation_point =
                canonical_evaluation_point(self.participant_count, *roster_position)?;
            if !difference.evaluate(evaluation_point).is_zero() {
                return Err(
                    ReplicatedSharingSimulatorBasisError::DifferenceVisibleAtCorruptPosition {
                        roster_position: *roster_position,
                    },
                );
            }
        }

        let random_sharing_component = difference.evaluate(BinaryFieldElement256::ZERO);
        let mut remainder =
            difference.add(&self.random_sharing_basis.scale(random_sharing_component));
        let mut zero_sharing_components =
            vec![BinaryFieldElement256::ZERO; self.zero_sharing_bases.len()];

        for basis_position in (0..self.zero_sharing_bases.len()).rev() {
            let basis = &self.zero_sharing_bases[basis_position];
            let leading_degree = basis.degree();
            let leading_coefficient = basis.coefficient(leading_degree);
            let component = remainder
                .coefficient(leading_degree)
                .multiply(leading_coefficient.multiplicative_inverse()?);
            zero_sharing_components[basis_position] = component;
            remainder = remainder.add(&basis.scale(component));
        }

        if (0..=self.maximum_opening_degree).any(|degree| !remainder.coefficient(degree).is_zero())
        {
            return Err(ReplicatedSharingSimulatorBasisError::DifferenceDecompositionFailure);
        }

        Ok(ReplicatedSharingHiddenComponents {
            random_sharing_component,
            zero_sharing_components: zero_sharing_components.into_boxed_slice(),
        })
    }
}
