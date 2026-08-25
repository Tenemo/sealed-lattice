use crate::{foundation::Hash512, tally_circuit::CompiledTallyCircuit};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    output_sharing::canonical_evaluation_point,
    preparation_multiplication_catalog::PreparationMultiplicationCatalog,
    replicated_beaver_opening::{TripleReductionOpeningCoordinate, TripleReductionOpeningError},
    replicated_random_sharing::BinaryFieldPolynomial,
    replicated_sharing_simulator_basis::{
        ReplicatedSharingHiddenComponents, ReplicatedSharingSimulatorBasis,
        ReplicatedSharingSimulatorBasisError,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicatedBeaverSimulatorPolynomialRole {
    LeftOperandSharing,
    RightOperandSharing,
    ReductionMaskSharing,
    ZeroSharing,
    SampledPublicOpening,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReplicatedBeaverSimulatorError {
    Preparation(TallyPreparationError),
    Opening(TripleReductionOpeningError),
    SimulatorBasis(ReplicatedSharingSimulatorBasisError),
    CoordinateParticipantCountMismatch {
        expected: u16,
        actual: u16,
    },
    CoordinateMaximumDegreeMismatch {
        expected: usize,
        actual: usize,
    },
    PolynomialDegreeOutOfRange {
        role: ReplicatedBeaverSimulatorPolynomialRole,
        maximum_degree: usize,
        actual_degree: usize,
    },
    ZeroSharingConstantNotZero,
    RetargetingInvariantFailure,
    MultiplicationCatalogExhausted,
}

impl From<TallyPreparationError> for ReplicatedBeaverSimulatorError {
    fn from(error: TallyPreparationError) -> Self {
        Self::Preparation(error)
    }
}

impl From<TripleReductionOpeningError> for ReplicatedBeaverSimulatorError {
    fn from(error: TripleReductionOpeningError) -> Self {
        Self::Opening(error)
    }
}

impl From<ReplicatedSharingSimulatorBasisError> for ReplicatedBeaverSimulatorError {
    fn from(error: ReplicatedSharingSimulatorBasisError) -> Self {
        Self::SimulatorBasis(error)
    }
}

/// One ideal-stream triple-opening witness before simulator retargeting.
///
/// This proof-model input carries polynomials, not authenticated protocol
/// bytes. Its constructor checks only the degree and zero-constant conditions
/// used by the algebraic simulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicatedBeaverTripleOpeningWitness {
    left_operand_sharing: BinaryFieldPolynomial,
    right_operand_sharing: BinaryFieldPolynomial,
    reduction_mask_sharing: BinaryFieldPolynomial,
    zero_sharing: BinaryFieldPolynomial,
}

impl ReplicatedBeaverTripleOpeningWitness {
    pub(crate) fn new(
        maximum_sharing_degree: usize,
        left_operand_sharing: BinaryFieldPolynomial,
        right_operand_sharing: BinaryFieldPolynomial,
        reduction_mask_sharing: BinaryFieldPolynomial,
        zero_sharing: BinaryFieldPolynomial,
    ) -> Result<Self, ReplicatedBeaverSimulatorError> {
        let witness = Self {
            left_operand_sharing,
            right_operand_sharing,
            reduction_mask_sharing,
            zero_sharing,
        };
        witness.validate(maximum_sharing_degree)?;
        Ok(witness)
    }

    pub(crate) fn public_opening_polynomial(&self) -> BinaryFieldPolynomial {
        self.left_operand_sharing
            .multiply(&self.right_operand_sharing)
            .add(&self.reduction_mask_sharing)
            .add(&self.zero_sharing)
    }

    fn validate(
        &self,
        maximum_sharing_degree: usize,
    ) -> Result<(), ReplicatedBeaverSimulatorError> {
        validate_degree(
            &self.left_operand_sharing,
            maximum_sharing_degree,
            ReplicatedBeaverSimulatorPolynomialRole::LeftOperandSharing,
        )?;
        validate_degree(
            &self.right_operand_sharing,
            maximum_sharing_degree,
            ReplicatedBeaverSimulatorPolynomialRole::RightOperandSharing,
        )?;
        validate_degree(
            &self.reduction_mask_sharing,
            maximum_sharing_degree,
            ReplicatedBeaverSimulatorPolynomialRole::ReductionMaskSharing,
        )?;
        let maximum_opening_degree = maximum_sharing_degree
            .checked_mul(2)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        validate_degree(
            &self.zero_sharing,
            maximum_opening_degree,
            ReplicatedBeaverSimulatorPolynomialRole::ZeroSharing,
        )?;
        if !self
            .zero_sharing
            .evaluate(BinaryFieldElement256::ZERO)
            .is_zero()
        {
            return Err(ReplicatedBeaverSimulatorError::ZeroSharingConstantNotZero);
        }
        Ok(())
    }
}

/// Exact accepted-path result of one ideal-stream simulator retargeting.
///
/// Private fields keep this algebra record from being caller-fabricated. It is
/// not a signed message, preparation capsule, or workflow capability. The
/// hidden components are additive changes to the all-honest ideal outputs;
/// they are not fixed-SHAKE programming instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetargetedReplicatedBeaverTripleOpening {
    coordinate_identity: Hash512,
    hidden_component_adjustments: ReplicatedSharingHiddenComponents,
    sampled_public_opening: BinaryFieldPolynomial,
    programmed_reduction_mask_sharing: BinaryFieldPolynomial,
    programmed_zero_sharing: BinaryFieldPolynomial,
    output_sharing: BinaryFieldPolynomial,
}

impl RetargetedReplicatedBeaverTripleOpening {
    pub(crate) const fn coordinate_identity(&self) -> Hash512 {
        self.coordinate_identity
    }

    pub(crate) fn hidden_component_adjustments(&self) -> &ReplicatedSharingHiddenComponents {
        &self.hidden_component_adjustments
    }

    pub(crate) fn sampled_public_opening(&self) -> &BinaryFieldPolynomial {
        &self.sampled_public_opening
    }

    pub(crate) fn programmed_reduction_mask_sharing(&self) -> &BinaryFieldPolynomial {
        &self.programmed_reduction_mask_sharing
    }

    pub(crate) fn programmed_zero_sharing(&self) -> &BinaryFieldPolynomial {
        &self.programmed_zero_sharing
    }

    pub(crate) fn output_sharing(&self) -> &BinaryFieldPolynomial {
        &self.output_sharing
    }
}

/// Algebraic ideal-stream simulator for one fixed static corruption set.
///
/// Retargeting preserves every corrupt evaluation and changes only the exact
/// all-honest kernel components established by
/// `ReplicatedSharingSimulatorBasis`. It proves no real-stream replacement,
/// transcript simulation, authentication, or fixed-function security.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplicatedBeaverTripleOpeningSimulator {
    participant_count: u16,
    maximum_sharing_degree: usize,
    corrupt_positions: Box<[u16]>,
    basis: ReplicatedSharingSimulatorBasis,
}

impl ReplicatedBeaverTripleOpeningSimulator {
    pub(crate) fn new(
        participant_count: u16,
        corrupt_positions: &[u16],
    ) -> Result<Self, ReplicatedBeaverSimulatorError> {
        let basis = ReplicatedSharingSimulatorBasis::new(participant_count, corrupt_positions)?;
        let maximum_sharing_degree = basis
            .maximum_opening_degree()
            .checked_div(2)
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        Ok(Self {
            participant_count,
            maximum_sharing_degree,
            corrupt_positions: corrupt_positions.into(),
            basis,
        })
    }

    pub(crate) const fn maximum_sharing_degree(&self) -> usize {
        self.maximum_sharing_degree
    }

    pub(crate) fn retarget(
        &self,
        coordinate: TripleReductionOpeningCoordinate,
        witness: &ReplicatedBeaverTripleOpeningWitness,
        sampled_public_opening: BinaryFieldPolynomial,
    ) -> Result<RetargetedReplicatedBeaverTripleOpening, ReplicatedBeaverSimulatorError> {
        witness.validate(self.maximum_sharing_degree)?;
        if coordinate.participant_count() != self.participant_count {
            return Err(
                ReplicatedBeaverSimulatorError::CoordinateParticipantCountMismatch {
                    expected: self.participant_count,
                    actual: coordinate.participant_count(),
                },
            );
        }
        if coordinate.maximum_degree() != self.basis.maximum_opening_degree() {
            return Err(
                ReplicatedBeaverSimulatorError::CoordinateMaximumDegreeMismatch {
                    expected: self.basis.maximum_opening_degree(),
                    actual: coordinate.maximum_degree(),
                },
            );
        }
        validate_degree(
            &sampled_public_opening,
            self.basis.maximum_opening_degree(),
            ReplicatedBeaverSimulatorPolynomialRole::SampledPublicOpening,
        )?;

        let original_public_opening = witness.public_opening_polynomial();
        let opening_difference = original_public_opening.add(&sampled_public_opening);
        let hidden_component_adjustments = self.basis.decompose(&opening_difference)?;
        let reduction_mask_adjustment = self
            .basis
            .random_sharing_basis()
            .scale(hidden_component_adjustments.random_sharing_component());
        let zero_sharing_adjustment = self
            .basis
            .zero_sharing_bases()
            .iter()
            .zip(hidden_component_adjustments.zero_sharing_components())
            .fold(
                BinaryFieldPolynomial::zero(),
                |adjustment, (basis, component)| adjustment.add(&basis.scale(*component)),
            );
        let programmed_reduction_mask_sharing = witness
            .reduction_mask_sharing
            .add(&reduction_mask_adjustment);
        let programmed_zero_sharing = witness.zero_sharing.add(&zero_sharing_adjustment);
        let reconstructed_public_opening = witness
            .left_operand_sharing
            .multiply(&witness.right_operand_sharing)
            .add(&programmed_reduction_mask_sharing)
            .add(&programmed_zero_sharing);
        if reconstructed_public_opening != sampled_public_opening
            || self.basis.reassemble(&hidden_component_adjustments)? != opening_difference
        {
            return Err(ReplicatedBeaverSimulatorError::RetargetingInvariantFailure);
        }

        for roster_position in &self.corrupt_positions {
            let evaluation_point =
                canonical_evaluation_point(self.participant_count, *roster_position)?;
            if programmed_reduction_mask_sharing.evaluate(evaluation_point)
                != witness.reduction_mask_sharing.evaluate(evaluation_point)
                || programmed_zero_sharing.evaluate(evaluation_point)
                    != witness.zero_sharing.evaluate(evaluation_point)
            {
                return Err(ReplicatedBeaverSimulatorError::RetargetingInvariantFailure);
            }
        }

        let opened_constant = sampled_public_opening.evaluate(BinaryFieldElement256::ZERO);
        let output_sharing = programmed_reduction_mask_sharing
            .add(&BinaryFieldPolynomial::constant(opened_constant));
        let expected_product = witness
            .left_operand_sharing
            .evaluate(BinaryFieldElement256::ZERO)
            .multiply(
                witness
                    .right_operand_sharing
                    .evaluate(BinaryFieldElement256::ZERO),
            );
        if output_sharing.evaluate(BinaryFieldElement256::ZERO) != expected_product {
            return Err(ReplicatedBeaverSimulatorError::RetargetingInvariantFailure);
        }

        Ok(RetargetedReplicatedBeaverTripleOpening {
            coordinate_identity: coordinate.identity(),
            hidden_component_adjustments,
            sampled_public_opening,
            programmed_reduction_mask_sharing,
            programmed_zero_sharing,
            output_sharing,
        })
    }
}

/// Canonical-order wrapper used to exercise sequential simulator composition.
///
/// The wrapper derives each coordinate from one cached production catalog and
/// advances only after a successful algebraic retargeting. It does not model a
/// protocol retry or burn transition.
pub(crate) struct ReplicatedBeaverSimulationSequence {
    context: TallyPreparationContext,
    multiplication_catalog: PreparationMultiplicationCatalog,
    predecessor_root: Hash512,
    next_multiplication_ordinal: u64,
    simulator: ReplicatedBeaverTripleOpeningSimulator,
}

impl ReplicatedBeaverSimulationSequence {
    pub(crate) fn new(
        context: TallyPreparationContext,
        circuit: &CompiledTallyCircuit,
        predecessor_root: Hash512,
        corrupt_positions: &[u16],
    ) -> Result<Self, ReplicatedBeaverSimulatorError> {
        Ok(Self {
            context,
            multiplication_catalog: PreparationMultiplicationCatalog::derive(context, circuit)?,
            predecessor_root,
            next_multiplication_ordinal: 0,
            simulator: ReplicatedBeaverTripleOpeningSimulator::new(
                context.participant_count(),
                corrupt_positions,
            )?,
        })
    }

    pub(crate) const fn next_multiplication_ordinal(&self) -> u64 {
        self.next_multiplication_ordinal
    }

    pub(crate) fn retarget_next(
        &mut self,
        witness: &ReplicatedBeaverTripleOpeningWitness,
        sampled_public_opening: BinaryFieldPolynomial,
    ) -> Result<RetargetedReplicatedBeaverTripleOpening, ReplicatedBeaverSimulatorError> {
        if self.next_multiplication_ordinal >= self.multiplication_catalog.operation_count() {
            return Err(ReplicatedBeaverSimulatorError::MultiplicationCatalogExhausted);
        }
        let coordinate = TripleReductionOpeningCoordinate::derive_from_catalog(
            self.context,
            &self.multiplication_catalog,
            self.predecessor_root,
            self.next_multiplication_ordinal,
        )?;
        let result = self
            .simulator
            .retarget(coordinate, witness, sampled_public_opening)?;
        self.next_multiplication_ordinal = self
            .next_multiplication_ordinal
            .checked_add(1)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        Ok(result)
    }
}

fn validate_degree(
    polynomial: &BinaryFieldPolynomial,
    maximum_degree: usize,
    role: ReplicatedBeaverSimulatorPolynomialRole,
) -> Result<(), ReplicatedBeaverSimulatorError> {
    if polynomial.degree() > maximum_degree {
        return Err(ReplicatedBeaverSimulatorError::PolynomialDegreeOutOfRange {
            role,
            maximum_degree,
            actual_degree: polynomial.degree(),
        });
    }
    Ok(())
}
