//! Pure compiler and semantic evaluator for the unactivated direct-MPC candidate.
//!
//! This module derives the completion-profile arithmetic graph and preliminary
//! resource model. It does not mint a protocol capability or authorize dispatch.

use core::fmt;

use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    foundation::{FOUNDATION_PROFILE, derive_foundation_roster_parameters},
    tally_circuit::{
        TallyCircuitError, TallyCircuitProfile, TallyEvaluationInput, bit_width_for_maximum_value,
        foundation_score_bounds,
    },
};

use super::direct_mpc_prime_field::{
    DIRECT_MPC_PRIME_FIELD_MODULUS, DirectMpcPrimeFieldElement, DirectMpcPrimeFieldError,
    interpolate_consecutive_prime_field_values,
};

pub(crate) const DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH: u64 = 32;
pub(crate) const DIRECT_MPC_SCORE_BIT_COUNT: usize = 4;
pub(crate) const DIRECT_MPC_VALIDATION_REPETITION_COUNT: usize = 8;
pub(crate) const DIRECT_MPC_SUBSET_SEED_BYTE_LENGTH: u64 = 40;
pub(crate) const DIRECT_MPC_VALIDATION_COLLECTIVE_COIN_BYTE_LENGTH: usize = 40;
pub(crate) const DIRECT_MPC_VALIDATION_PREDECESSOR_ROOT_BYTE_LENGTH: usize = 64;
pub(crate) const DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH: usize = 2
    * DIRECT_MPC_VALIDATION_PREDECESSOR_ROOT_BYTE_LENGTH
    + DIRECT_MPC_VALIDATION_COLLECTIVE_COIN_BYTE_LENGTH;

const VALIDATION_CHALLENGE_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/direct-mpc-validation-challenge/v1";

pub(crate) type DirectMpcWireIndex = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcCandidateError {
    TallyCircuit(TallyCircuitError),
    PrimeField(DirectMpcPrimeFieldError),
    CompletionProfileRequired {
        participant_count: u16,
        option_count: u16,
    },
    InvalidWireReference {
        wire: DirectMpcWireIndex,
        available_wire_count: usize,
    },
    WireIndexOverflow,
    ArithmeticOverflow,
    InputFieldCountMismatch {
        expected: usize,
        actual: usize,
    },
    ValidationChallengeContextByteLength {
        expected: usize,
        actual: usize,
    },
    ScoreBitnessCheckFailed,
    NonBooleanAcceptedAuthorship {
        participant_position: usize,
        value: u32,
    },
    OrderedOptionPositionOutOfRange {
        output_position: usize,
        value: u32,
        option_count: usize,
    },
    DuplicateOrderedOptionPosition {
        value: u32,
    },
    InteractionGraphMismatch,
}

impl fmt::Display for DirectMpcCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TallyCircuit(error) => write!(formatter, "tally circuit error: {error}"),
            Self::PrimeField(error) => write!(formatter, "direct MPC field error: {error}"),
            Self::CompletionProfileRequired {
                participant_count,
                option_count,
            } => write!(
                formatter,
                "direct MPC candidate requires the completion participant and option counts; received {participant_count} participants and {option_count} options"
            ),
            Self::InvalidWireReference {
                wire,
                available_wire_count,
            } => write!(
                formatter,
                "direct MPC wire {wire} is unavailable with {available_wire_count} preceding wires"
            ),
            Self::WireIndexOverflow => formatter.write_str("direct MPC wire index overflow"),
            Self::ArithmeticOverflow => formatter.write_str("direct MPC arithmetic overflow"),
            Self::InputFieldCountMismatch { expected, actual } => write!(
                formatter,
                "direct MPC evaluator received {actual} input fields; expected {expected}"
            ),
            Self::ValidationChallengeContextByteLength { expected, actual } => write!(
                formatter,
                "direct MPC validation challenge context has {actual} bytes; expected {expected}"
            ),
            Self::ScoreBitnessCheckFailed => {
                formatter.write_str("direct MPC score-bit validation failed")
            }
            Self::NonBooleanAcceptedAuthorship {
                participant_position,
                value,
            } => write!(
                formatter,
                "direct MPC accepted-authorship value {value} for participant {participant_position} is not Boolean"
            ),
            Self::OrderedOptionPositionOutOfRange {
                output_position,
                value,
                option_count,
            } => write!(
                formatter,
                "direct MPC output {output_position} contains option position {value}; expected a value below {option_count}"
            ),
            Self::DuplicateOrderedOptionPosition { value } => write!(
                formatter,
                "direct MPC output repeats option position {value}"
            ),
            Self::InteractionGraphMismatch => {
                formatter.write_str("direct MPC interaction graph is internally inconsistent")
            }
        }
    }
}

impl std::error::Error for DirectMpcCandidateError {}

impl From<TallyCircuitError> for DirectMpcCandidateError {
    fn from(error: TallyCircuitError) -> Self {
        Self::TallyCircuit(error)
    }
}

impl From<DirectMpcPrimeFieldError> for DirectMpcCandidateError {
    fn from(error: DirectMpcPrimeFieldError) -> Self {
        Self::PrimeField(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DirectMpcPhase {
    BallotValidation,
    TallyEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcInputRole {
    PublicBallotPresence {
        participant_position: u16,
    },
    PrivateScoreBit {
        participant_position: u16,
        option_position: u16,
        bit_position: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectMpcScoreValidityStep {
    LowBitProduct,
    LowThreeBitsAreZero,
    HighScoreIsValid,
    SelectHighOrLowRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcOperationRole {
    ScoreBitMinusOne {
        participant_position: u16,
        option_position: u16,
        bit_position: u16,
    },
    ScoreBitnessConstraint {
        participant_position: u16,
        option_position: u16,
        bit_position: u16,
    },
    ScoreValidity {
        participant_position: u16,
        option_position: u16,
        step: DirectMpcScoreValidityStep,
    },
    BallotValidityProduct {
        participant_position: u16,
        reduction_level: u16,
        pair_position: u16,
    },
    AcceptedBallotAuthorship {
        participant_position: u16,
    },
    EffectiveScore {
        participant_position: u16,
        option_position: u16,
    },
    AggregateScore {
        option_position: u16,
    },
    ShiftedPairDifference {
        lower_option_position: u16,
        higher_option_position: u16,
    },
    ComparisonPower {
        lower_option_position: u16,
        higher_option_position: u16,
        exponent: u16,
    },
    LowerOptionOutranksHigher {
        lower_option_position: u16,
        higher_option_position: u16,
    },
    OptionRank {
        option_position: u16,
    },
    RankPower {
        option_position: u16,
        exponent: u16,
    },
    OrderedOptionPosition {
        output_position: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectMpcArithmeticOperation {
    Affine {
        constant: DirectMpcPrimeFieldElement,
        terms: Box<[(DirectMpcWireIndex, DirectMpcPrimeFieldElement)]>,
    },
    Multiply {
        left_wire: DirectMpcWireIndex,
        right_wire: DirectMpcWireIndex,
    },
    MultiplyByPublic {
        value_wire: DirectMpcWireIndex,
        public_wire: DirectMpcWireIndex,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcOperationRecord {
    pub(crate) output_wire: DirectMpcWireIndex,
    pub(crate) phase: DirectMpcPhase,
    pub(crate) phase_depth: u16,
    pub(crate) multiplication_ordinal: Option<u32>,
    pub(crate) role: DirectMpcOperationRole,
    pub(crate) operation: DirectMpcArithmeticOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcInputWireRecord {
    pub(crate) wire: DirectMpcWireIndex,
    pub(crate) role: DirectMpcInputRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcCandidateGeometry {
    pub(crate) input_field_count: usize,
    pub(crate) public_input_field_count: usize,
    pub(crate) private_score_bit_field_count: usize,
    pub(crate) affine_operation_count: usize,
    pub(crate) public_scale_operation_count: usize,
    pub(crate) validation_multiplication_layer_counts: Box<[u64]>,
    pub(crate) evaluation_multiplication_layer_counts: Box<[u64]>,
    pub(crate) beaver_triple_count: u64,
    pub(crate) score_bitness_constraint_count: u64,
    pub(crate) comparison_pair_count: u64,
    pub(crate) comparison_polynomial_degree: u16,
    pub(crate) rank_polynomial_degree: u16,
    pub(crate) total_wire_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledDirectMpcCandidate {
    profile: TallyCircuitProfile,
    input_wires: Box<[DirectMpcInputWireRecord]>,
    operations: Box<[DirectMpcOperationRecord]>,
    score_bitness_constraint_wires: Box<[DirectMpcWireIndex]>,
    accepted_ballot_authorship_wires: Box<[DirectMpcWireIndex]>,
    ordered_option_position_wires: Box<[DirectMpcWireIndex]>,
    geometry: DirectMpcCandidateGeometry,
}

impl CompiledDirectMpcCandidate {
    pub(crate) const fn profile(&self) -> TallyCircuitProfile {
        self.profile
    }

    pub(crate) fn input_wires(&self) -> &[DirectMpcInputWireRecord] {
        &self.input_wires
    }

    pub(crate) fn operations(&self) -> &[DirectMpcOperationRecord] {
        &self.operations
    }

    pub(crate) fn score_bitness_constraint_wires(&self) -> &[DirectMpcWireIndex] {
        &self.score_bitness_constraint_wires
    }

    pub(crate) fn accepted_ballot_authorship_wires(&self) -> &[DirectMpcWireIndex] {
        &self.accepted_ballot_authorship_wires
    }

    pub(crate) fn ordered_option_position_wires(&self) -> &[DirectMpcWireIndex] {
        &self.ordered_option_position_wires
    }

    pub(crate) fn geometry(&self) -> &DirectMpcCandidateGeometry {
        &self.geometry
    }

    pub(crate) fn evaluate(
        &self,
        input: &TallyEvaluationInput,
        validation_challenge_context: &[u8],
    ) -> Result<DirectMpcCandidateEvaluationOutcome, DirectMpcCandidateError> {
        let input_fields = self.encode_tally_input(input)?;
        self.evaluate_input_fields(&input_fields, validation_challenge_context)
    }

    pub(crate) fn encode_tally_input(
        &self,
        input: &TallyEvaluationInput,
    ) -> Result<Vec<DirectMpcPrimeFieldElement>, DirectMpcCandidateError> {
        let participant_count = usize::from(self.profile.participant_count());
        let option_count = usize::from(self.profile.option_count());
        if input.participant_ballots().len() != participant_count {
            return Err(TallyCircuitError::InputParticipantCountMismatch {
                expected: participant_count,
                actual: input.participant_ballots().len(),
            }
            .into());
        }

        let mut input_fields = Vec::with_capacity(self.geometry.input_field_count);
        for (participant_position, ballot) in input.participant_ballots().iter().enumerate() {
            if ballot.score_encodings().len() != option_count {
                return Err(TallyCircuitError::InputOptionCountMismatch {
                    participant_position,
                    expected: option_count,
                    actual: ballot.score_encodings().len(),
                }
                .into());
            }
            input_fields.push(if ballot.is_present() {
                DirectMpcPrimeFieldElement::ONE
            } else {
                DirectMpcPrimeFieldElement::ZERO
            });
            for (option_position, score_encoding) in
                ballot.score_encodings().iter().copied().enumerate()
            {
                if usize::from(score_encoding) >= 1 << DIRECT_MPC_SCORE_BIT_COUNT {
                    return Err(TallyCircuitError::ScoreEncodingOutOfRange {
                        participant_position,
                        option_position,
                        score_encoding,
                    }
                    .into());
                }
                for bit_position in 0..DIRECT_MPC_SCORE_BIT_COUNT {
                    input_fields.push(if (score_encoding >> bit_position) & 1 == 1 {
                        DirectMpcPrimeFieldElement::ONE
                    } else {
                        DirectMpcPrimeFieldElement::ZERO
                    });
                }
            }
        }
        Ok(input_fields)
    }

    pub(crate) fn evaluate_input_fields(
        &self,
        input_fields: &[DirectMpcPrimeFieldElement],
        validation_challenge_context: &[u8],
    ) -> Result<DirectMpcCandidateEvaluationOutcome, DirectMpcCandidateError> {
        let wire_values = self.evaluate_wire_values(input_fields)?;
        self.verify_bitness_checks(&wire_values, validation_challenge_context)?;

        let mut accepted_ballot_authorship =
            Vec::with_capacity(self.accepted_ballot_authorship_wires.len());
        for (participant_position, wire) in self
            .accepted_ballot_authorship_wires
            .iter()
            .copied()
            .enumerate()
        {
            let value = wire_value(&wire_values, wire)?;
            accepted_ballot_authorship.push(match value.canonical_u32() {
                0 => false,
                1 => true,
                value => {
                    return Err(DirectMpcCandidateError::NonBooleanAcceptedAuthorship {
                        participant_position,
                        value,
                    });
                }
            });
        }

        let ordered_option_positions = if accepted_ballot_authorship.iter().any(|value| *value) {
            let option_count = usize::from(self.profile.option_count());
            let mut observed = vec![false; option_count];
            let mut positions = Vec::with_capacity(self.ordered_option_position_wires.len());
            for (output_position, wire) in self
                .ordered_option_position_wires
                .iter()
                .copied()
                .enumerate()
            {
                let value = wire_value(&wire_values, wire)?.canonical_u32();
                let position = usize::try_from(value)
                    .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?;
                if position >= option_count {
                    return Err(DirectMpcCandidateError::OrderedOptionPositionOutOfRange {
                        output_position,
                        value,
                        option_count,
                    });
                }
                if observed[position] {
                    return Err(DirectMpcCandidateError::DuplicateOrderedOptionPosition { value });
                }
                observed[position] = true;
                positions.push(
                    u16::try_from(position)
                        .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?,
                );
            }
            Some(positions)
        } else {
            None
        };

        Ok(DirectMpcCandidateEvaluationOutcome {
            accepted_ballot_authorship,
            ordered_option_positions,
        })
    }

    fn evaluate_wire_values(
        &self,
        input_fields: &[DirectMpcPrimeFieldElement],
    ) -> Result<Vec<DirectMpcPrimeFieldElement>, DirectMpcCandidateError> {
        if input_fields.len() != self.geometry.input_field_count {
            return Err(DirectMpcCandidateError::InputFieldCountMismatch {
                expected: self.geometry.input_field_count,
                actual: input_fields.len(),
            });
        }
        let mut wire_values = input_fields.to_vec();
        wire_values.reserve(self.operations.len());
        for operation_record in self.operations.iter() {
            let output =
                match &operation_record.operation {
                    DirectMpcArithmeticOperation::Affine { constant, terms } => terms
                        .iter()
                        .try_fold(*constant, |value, (wire, coefficient)| {
                            Ok::<_, DirectMpcCandidateError>(
                                value.add(wire_value(&wire_values, *wire)?.multiply(*coefficient)),
                            )
                        })?,
                    DirectMpcArithmeticOperation::Multiply {
                        left_wire,
                        right_wire,
                    } => wire_value(&wire_values, *left_wire)?
                        .multiply(wire_value(&wire_values, *right_wire)?),
                    DirectMpcArithmeticOperation::MultiplyByPublic {
                        value_wire,
                        public_wire,
                    } => wire_value(&wire_values, *value_wire)?
                        .multiply(wire_value(&wire_values, *public_wire)?),
                };
            if usize::try_from(operation_record.output_wire)
                .map_err(|_| DirectMpcCandidateError::WireIndexOverflow)?
                != wire_values.len()
            {
                return Err(DirectMpcCandidateError::InteractionGraphMismatch);
            }
            wire_values.push(output);
        }
        Ok(wire_values)
    }

    fn verify_bitness_checks(
        &self,
        wire_values: &[DirectMpcPrimeFieldElement],
        validation_challenge_context: &[u8],
    ) -> Result<(), DirectMpcCandidateError> {
        let coefficient_count = self
            .score_bitness_constraint_wires
            .len()
            .checked_mul(DIRECT_MPC_VALIDATION_REPETITION_COUNT)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let coefficients = derive_validation_coefficients(
            self.profile,
            validation_challenge_context,
            coefficient_count,
        )?;
        for repetition_position in 0..DIRECT_MPC_VALIDATION_REPETITION_COUNT {
            let first_coefficient = repetition_position
                .checked_mul(self.score_bitness_constraint_wires.len())
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
            let check = self
                .score_bitness_constraint_wires
                .iter()
                .copied()
                .zip(
                    coefficients[first_coefficient
                        ..first_coefficient + self.score_bitness_constraint_wires.len()]
                        .iter()
                        .copied(),
                )
                .try_fold(
                    DirectMpcPrimeFieldElement::ZERO,
                    |sum, (wire, coefficient)| {
                        Ok::<_, DirectMpcCandidateError>(
                            sum.add(wire_value(wire_values, wire)?.multiply(coefficient)),
                        )
                    },
                )?;
            if check != DirectMpcPrimeFieldElement::ZERO {
                return Err(DirectMpcCandidateError::ScoreBitnessCheckFailed);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcCandidateEvaluationOutcome {
    accepted_ballot_authorship: Vec<bool>,
    ordered_option_positions: Option<Vec<u16>>,
}

impl DirectMpcCandidateEvaluationOutcome {
    pub(crate) fn accepted_ballot_authorship(&self) -> &[bool] {
        &self.accepted_ballot_authorship
    }

    pub(crate) fn ordered_option_positions(&self) -> Option<&[u16]> {
        self.ordered_option_positions.as_deref()
    }
}

pub(crate) fn compile_direct_mpc_candidate(
    profile: TallyCircuitProfile,
) -> Result<CompiledDirectMpcCandidate, DirectMpcCandidateError> {
    let (minimum_score, maximum_score) = foundation_score_bounds()?;
    if profile.participant_count() != FOUNDATION_PROFILE.participant_count
        || profile.option_count() != FOUNDATION_PROFILE.option_count
    {
        return Err(DirectMpcCandidateError::CompletionProfileRequired {
            participant_count: profile.participant_count(),
            option_count: profile.option_count(),
        });
    }
    if minimum_score != 1
        || maximum_score != 10
        || bit_width_for_maximum_value(usize::from(maximum_score)) != DIRECT_MPC_SCORE_BIT_COUNT
    {
        return Err(TallyCircuitError::UnsupportedFoundationScoreRange {
            minimum_score,
            maximum_score,
        }
        .into());
    }

    let participant_count = usize::from(profile.participant_count());
    let option_count = usize::from(profile.option_count());
    let top_count = usize::from(profile.top_count());
    let maximum_aggregate_score = participant_count
        .checked_mul(usize::from(maximum_score))
        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
    let comparison_domain_maximum = maximum_aggregate_score
        .checked_mul(2)
        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
    if comparison_domain_maximum >= DIRECT_MPC_PRIME_FIELD_MODULUS as usize {
        return Err(DirectMpcCandidateError::ArithmeticOverflow);
    }

    let (input_wires, ballot_presence_wires, score_bit_wires) =
        derive_direct_mpc_input_wires(participant_count, option_count)?;
    let mut builder = DirectMpcCircuitBuilder::new(input_wires.len())?;
    let mut score_bitness_constraint_wires =
        Vec::with_capacity(participant_count * option_count * DIRECT_MPC_SCORE_BIT_COUNT);
    let mut accepted_ballot_authorship_wires = Vec::with_capacity(participant_count);

    for participant_position in 0..participant_count {
        let mut score_validity_wires = Vec::with_capacity(option_count);
        for option_position in 0..option_count {
            let bits = &score_bit_wires[participant_position][option_position];
            for (bit_position, bit_wire) in bits.iter().copied().enumerate() {
                let bit_minus_one = builder.append_affine(
                    DirectMpcPhase::BallotValidation,
                    DirectMpcPrimeFieldElement::ONE.negate(),
                    [(bit_wire, DirectMpcPrimeFieldElement::ONE)],
                    DirectMpcOperationRole::ScoreBitMinusOne {
                        participant_position: to_u16(participant_position)?,
                        option_position: to_u16(option_position)?,
                        bit_position: to_u16(bit_position)?,
                    },
                )?;
                score_bitness_constraint_wires.push(builder.append_multiply(
                    DirectMpcPhase::BallotValidation,
                    bit_wire,
                    bit_minus_one,
                    DirectMpcOperationRole::ScoreBitnessConstraint {
                        participant_position: to_u16(participant_position)?,
                        option_position: to_u16(option_position)?,
                        bit_position: to_u16(bit_position)?,
                    },
                )?);
            }

            let low_bit_product = builder.append_multiply(
                DirectMpcPhase::BallotValidation,
                bits[0],
                bits[1],
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::LowBitProduct,
                },
            )?;
            let low_two_bits_are_zero = builder.append_affine(
                DirectMpcPhase::BallotValidation,
                DirectMpcPrimeFieldElement::ONE,
                [
                    (bits[0], DirectMpcPrimeFieldElement::ONE.negate()),
                    (bits[1], DirectMpcPrimeFieldElement::ONE.negate()),
                    (low_bit_product, DirectMpcPrimeFieldElement::ONE),
                ],
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::LowThreeBitsAreZero,
                },
            )?;
            let bit_two_is_zero = builder.append_affine(
                DirectMpcPhase::BallotValidation,
                DirectMpcPrimeFieldElement::ONE,
                [(bits[2], DirectMpcPrimeFieldElement::ONE.negate())],
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::LowThreeBitsAreZero,
                },
            )?;
            let all_low_bits_are_zero = builder.append_multiply(
                DirectMpcPhase::BallotValidation,
                low_two_bits_are_zero,
                bit_two_is_zero,
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::LowThreeBitsAreZero,
                },
            )?;
            let low_score_is_valid = builder.append_affine(
                DirectMpcPhase::BallotValidation,
                DirectMpcPrimeFieldElement::ONE,
                [(
                    all_low_bits_are_zero,
                    DirectMpcPrimeFieldElement::ONE.negate(),
                )],
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::LowThreeBitsAreZero,
                },
            )?;
            let low_bit_product_is_zero = builder.append_affine(
                DirectMpcPhase::BallotValidation,
                DirectMpcPrimeFieldElement::ONE,
                [(low_bit_product, DirectMpcPrimeFieldElement::ONE.negate())],
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::HighScoreIsValid,
                },
            )?;
            let high_score_is_valid = builder.append_multiply(
                DirectMpcPhase::BallotValidation,
                bit_two_is_zero,
                low_bit_product_is_zero,
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::HighScoreIsValid,
                },
            )?;
            let high_minus_low = builder.append_affine(
                DirectMpcPhase::BallotValidation,
                DirectMpcPrimeFieldElement::ZERO,
                [
                    (high_score_is_valid, DirectMpcPrimeFieldElement::ONE),
                    (low_score_is_valid, DirectMpcPrimeFieldElement::ONE.negate()),
                ],
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::SelectHighOrLowRange,
                },
            )?;
            let selected_high_difference = builder.append_multiply(
                DirectMpcPhase::BallotValidation,
                bits[3],
                high_minus_low,
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::SelectHighOrLowRange,
                },
            )?;
            score_validity_wires.push(builder.append_affine(
                DirectMpcPhase::BallotValidation,
                DirectMpcPrimeFieldElement::ZERO,
                [
                    (low_score_is_valid, DirectMpcPrimeFieldElement::ONE),
                    (selected_high_difference, DirectMpcPrimeFieldElement::ONE),
                ],
                DirectMpcOperationRole::ScoreValidity {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                    step: DirectMpcScoreValidityStep::SelectHighOrLowRange,
                },
            )?);
        }

        let ballot_is_valid = append_ballot_validity_product(
            &mut builder,
            to_u16(participant_position)?,
            score_validity_wires,
        )?;
        accepted_ballot_authorship_wires.push(builder.append_public_scale(
            DirectMpcPhase::BallotValidation,
            ballot_is_valid,
            ballot_presence_wires[participant_position],
            DirectMpcOperationRole::AcceptedBallotAuthorship {
                participant_position: to_u16(participant_position)?,
            },
        )?);
    }

    let mut aggregate_score_wires = Vec::with_capacity(option_count);
    for option_position in 0..option_count {
        let mut effective_score_wires = Vec::with_capacity(participant_count);
        for participant_position in 0..participant_count {
            let score_wire = builder.append_affine(
                DirectMpcPhase::TallyEvaluation,
                DirectMpcPrimeFieldElement::ZERO,
                score_bit_wires[participant_position][option_position]
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(bit_position, wire)| {
                        (
                            wire,
                            DirectMpcPrimeFieldElement::from_u64_reduced(1_u64 << bit_position),
                        )
                    }),
                DirectMpcOperationRole::EffectiveScore {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                },
            )?;
            effective_score_wires.push(builder.append_public_scale(
                DirectMpcPhase::TallyEvaluation,
                score_wire,
                accepted_ballot_authorship_wires[participant_position],
                DirectMpcOperationRole::EffectiveScore {
                    participant_position: to_u16(participant_position)?,
                    option_position: to_u16(option_position)?,
                },
            )?);
        }
        aggregate_score_wires.push(
            builder.append_affine(
                DirectMpcPhase::TallyEvaluation,
                DirectMpcPrimeFieldElement::ZERO,
                effective_score_wires
                    .into_iter()
                    .map(|wire| (wire, DirectMpcPrimeFieldElement::ONE)),
                DirectMpcOperationRole::AggregateScore {
                    option_position: to_u16(option_position)?,
                },
            )?,
        );
    }

    let comparison_values = (0..=comparison_domain_maximum)
        .map(|shifted_difference| {
            if shifted_difference >= maximum_aggregate_score {
                DirectMpcPrimeFieldElement::ONE
            } else {
                DirectMpcPrimeFieldElement::ZERO
            }
        })
        .collect::<Vec<_>>();
    let comparison_coefficients = interpolate_consecutive_prime_field_values(&comparison_values)?;
    let mut comparison_wires = vec![vec![None; option_count]; option_count];
    for lower_option_position in 0..option_count {
        for higher_option_position in lower_option_position + 1..option_count {
            let shifted_difference_wire = builder.append_affine(
                DirectMpcPhase::TallyEvaluation,
                DirectMpcPrimeFieldElement::from_u64_reduced(maximum_aggregate_score as u64),
                [
                    (
                        aggregate_score_wires[lower_option_position],
                        DirectMpcPrimeFieldElement::ONE,
                    ),
                    (
                        aggregate_score_wires[higher_option_position],
                        DirectMpcPrimeFieldElement::ONE.negate(),
                    ),
                ],
                DirectMpcOperationRole::ShiftedPairDifference {
                    lower_option_position: to_u16(lower_option_position)?,
                    higher_option_position: to_u16(higher_option_position)?,
                },
            )?;
            let powers = append_power_sequence(
                &mut builder,
                DirectMpcPhase::TallyEvaluation,
                shifted_difference_wire,
                comparison_domain_maximum,
                |exponent| DirectMpcOperationRole::ComparisonPower {
                    lower_option_position: to_u16(lower_option_position)
                        .expect("validated option position fits u16"),
                    higher_option_position: to_u16(higher_option_position)
                        .expect("validated option position fits u16"),
                    exponent: to_u16(exponent).expect("comparison exponent fits u16"),
                },
            )?;
            comparison_wires[lower_option_position][higher_option_position] = Some(
                builder.append_affine(
                    DirectMpcPhase::TallyEvaluation,
                    comparison_coefficients[0],
                    powers
                        .iter()
                        .copied()
                        .enumerate()
                        .map(|(position, wire)| (wire, comparison_coefficients[position + 1])),
                    DirectMpcOperationRole::LowerOptionOutranksHigher {
                        lower_option_position: to_u16(lower_option_position)?,
                        higher_option_position: to_u16(higher_option_position)?,
                    },
                )?,
            );
        }
    }

    let mut rank_wires = Vec::with_capacity(option_count);
    for option_position in 0..option_count {
        let constant = option_count
            .checked_sub(option_position + 1)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let mut terms = Vec::with_capacity(option_count - 1);
        for other_option_position in 0..option_count {
            if other_option_position < option_position {
                terms.push((
                    comparison_wires[other_option_position][option_position]
                        .ok_or(DirectMpcCandidateError::InteractionGraphMismatch)?,
                    DirectMpcPrimeFieldElement::ONE,
                ));
            } else if other_option_position > option_position {
                terms.push((
                    comparison_wires[option_position][other_option_position]
                        .ok_or(DirectMpcCandidateError::InteractionGraphMismatch)?,
                    DirectMpcPrimeFieldElement::ONE.negate(),
                ));
            }
        }
        rank_wires.push(builder.append_affine(
            DirectMpcPhase::TallyEvaluation,
            DirectMpcPrimeFieldElement::from_u64_reduced(constant as u64),
            terms,
            DirectMpcOperationRole::OptionRank {
                option_position: to_u16(option_position)?,
            },
        )?);
    }

    let mut rank_powers = Vec::with_capacity(option_count);
    for (option_position, rank_wire) in rank_wires.iter().copied().enumerate() {
        rank_powers.push(append_power_sequence(
            &mut builder,
            DirectMpcPhase::TallyEvaluation,
            rank_wire,
            option_count - 1,
            |exponent| DirectMpcOperationRole::RankPower {
                option_position: to_u16(option_position)
                    .expect("validated option position fits u16"),
                exponent: to_u16(exponent).expect("rank exponent fits u16"),
            },
        )?);
    }

    let mut ordered_option_position_wires = Vec::with_capacity(top_count);
    for output_position in 0..top_count {
        let equality_values = (0..option_count)
            .map(|rank| {
                if rank == output_position {
                    DirectMpcPrimeFieldElement::ONE
                } else {
                    DirectMpcPrimeFieldElement::ZERO
                }
            })
            .collect::<Vec<_>>();
        let equality_coefficients = interpolate_consecutive_prime_field_values(&equality_values)?;
        let mut constant = DirectMpcPrimeFieldElement::ZERO;
        let mut terms = Vec::with_capacity(option_count * (option_count - 1));
        for (option_position, option_rank_powers) in rank_powers.iter().enumerate() {
            let option_coefficient =
                DirectMpcPrimeFieldElement::from_u64_reduced(option_position as u64);
            constant = constant.add(equality_coefficients[0].multiply(option_coefficient));
            for (power_position, wire) in option_rank_powers.iter().copied().enumerate() {
                let coefficient =
                    equality_coefficients[power_position + 1].multiply(option_coefficient);
                if coefficient != DirectMpcPrimeFieldElement::ZERO {
                    terms.push((wire, coefficient));
                }
            }
        }
        ordered_option_position_wires.push(builder.append_affine(
            DirectMpcPhase::TallyEvaluation,
            constant,
            terms,
            DirectMpcOperationRole::OrderedOptionPosition {
                output_position: to_u16(output_position)?,
            },
        )?);
    }

    let geometry = builder.geometry(
        input_wires.len(),
        participant_count,
        score_bitness_constraint_wires.len(),
        option_count,
        comparison_domain_maximum,
    )?;
    Ok(CompiledDirectMpcCandidate {
        profile,
        input_wires: input_wires.into_boxed_slice(),
        operations: builder.operations.into_boxed_slice(),
        score_bitness_constraint_wires: score_bitness_constraint_wires.into_boxed_slice(),
        accepted_ballot_authorship_wires: accepted_ballot_authorship_wires.into_boxed_slice(),
        ordered_option_position_wires: ordered_option_position_wires.into_boxed_slice(),
        geometry,
    })
}

type DirectMpcScoreBitWires = Vec<Vec<Vec<DirectMpcWireIndex>>>;

fn derive_direct_mpc_input_wires(
    participant_count: usize,
    option_count: usize,
) -> Result<
    (
        Vec<DirectMpcInputWireRecord>,
        Vec<DirectMpcWireIndex>,
        DirectMpcScoreBitWires,
    ),
    DirectMpcCandidateError,
> {
    let input_field_count = participant_count
        .checked_mul(
            1_usize
                .checked_add(
                    option_count
                        .checked_mul(DIRECT_MPC_SCORE_BIT_COUNT)
                        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
                )
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
        )
        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
    let mut input_wires = Vec::with_capacity(input_field_count);
    let mut ballot_presence_wires = Vec::with_capacity(participant_count);
    let mut score_bit_wires = Vec::with_capacity(participant_count);
    for participant_position in 0..participant_count {
        let presence_wire = wire_index(input_wires.len())?;
        input_wires.push(DirectMpcInputWireRecord {
            wire: presence_wire,
            role: DirectMpcInputRole::PublicBallotPresence {
                participant_position: to_u16(participant_position)?,
            },
        });
        ballot_presence_wires.push(presence_wire);

        let mut participant_score_wires = Vec::with_capacity(option_count);
        for option_position in 0..option_count {
            let mut option_score_wires = Vec::with_capacity(DIRECT_MPC_SCORE_BIT_COUNT);
            for bit_position in 0..DIRECT_MPC_SCORE_BIT_COUNT {
                let wire = wire_index(input_wires.len())?;
                input_wires.push(DirectMpcInputWireRecord {
                    wire,
                    role: DirectMpcInputRole::PrivateScoreBit {
                        participant_position: to_u16(participant_position)?,
                        option_position: to_u16(option_position)?,
                        bit_position: to_u16(bit_position)?,
                    },
                });
                option_score_wires.push(wire);
            }
            participant_score_wires.push(option_score_wires);
        }
        score_bit_wires.push(participant_score_wires);
    }
    Ok((input_wires, ballot_presence_wires, score_bit_wires))
}

fn append_ballot_validity_product(
    builder: &mut DirectMpcCircuitBuilder,
    participant_position: u16,
    mut wires: Vec<DirectMpcWireIndex>,
) -> Result<DirectMpcWireIndex, DirectMpcCandidateError> {
    let mut reduction_level = 0_u16;
    while wires.len() > 1 {
        reduction_level = reduction_level
            .checked_add(1)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let mut reduced = Vec::with_capacity(wires.len().div_ceil(2));
        for (pair_position, pair) in wires.chunks(2).enumerate() {
            if pair.len() == 2 {
                reduced.push(builder.append_multiply(
                    DirectMpcPhase::BallotValidation,
                    pair[0],
                    pair[1],
                    DirectMpcOperationRole::BallotValidityProduct {
                        participant_position,
                        reduction_level,
                        pair_position: to_u16(pair_position)?,
                    },
                )?);
            } else {
                reduced.push(pair[0]);
            }
        }
        wires = reduced;
    }
    wires
        .into_iter()
        .next()
        .ok_or(DirectMpcCandidateError::InteractionGraphMismatch)
}

fn append_power_sequence(
    builder: &mut DirectMpcCircuitBuilder,
    phase: DirectMpcPhase,
    base_wire: DirectMpcWireIndex,
    maximum_exponent: usize,
    mut role_for_exponent: impl FnMut(usize) -> DirectMpcOperationRole,
) -> Result<Vec<DirectMpcWireIndex>, DirectMpcCandidateError> {
    let mut powers = Vec::with_capacity(maximum_exponent);
    powers.push(base_wire);
    for exponent in 2..=maximum_exponent {
        let left_exponent = exponent / 2;
        let right_exponent = exponent - left_exponent;
        let left_wire = powers[left_exponent - 1];
        let right_wire = powers[right_exponent - 1];
        powers.push(builder.append_multiply(
            phase,
            left_wire,
            right_wire,
            role_for_exponent(exponent),
        )?);
    }
    Ok(powers)
}

pub(super) fn derive_validation_coefficients(
    profile: TallyCircuitProfile,
    validation_challenge_context: &[u8],
    coefficient_count: usize,
) -> Result<Vec<DirectMpcPrimeFieldElement>, DirectMpcCandidateError> {
    if validation_challenge_context.len() != DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH {
        return Err(
            DirectMpcCandidateError::ValidationChallengeContextByteLength {
                expected: DIRECT_MPC_VALIDATION_CHALLENGE_CONTEXT_BYTE_LENGTH,
                actual: validation_challenge_context.len(),
            },
        );
    }
    let output_byte_length = coefficient_count
        .checked_mul(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH as usize)
        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
    let mut xof = CShake256::from_core(CShake256Core::new_with_function_name(
        b"sealed-lattice",
        VALIDATION_CHALLENGE_CUSTOMIZATION,
    ));
    xof.update(&profile.participant_count().to_le_bytes());
    xof.update(&profile.option_count().to_le_bytes());
    xof.update(&profile.top_count().to_le_bytes());
    // The fixed-width layout is preparation-terminal root, ballot-source-terminal
    // root, then the preparation-committed collective coin opening.
    xof.update(validation_challenge_context);
    let mut bytes = vec![0_u8; output_byte_length];
    xof.finalize_xof().read(&mut bytes);
    Ok(bytes
        .chunks_exact(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH as usize)
        .map(reduce_little_endian_field_sample)
        .collect())
}

pub(super) fn reduce_little_endian_field_sample(sample: &[u8]) -> DirectMpcPrimeFieldElement {
    let reduced_value = sample.iter().rev().fold(0_u64, |accumulated, byte| {
        (accumulated * 256 + u64::from(*byte)) % u64::from(DIRECT_MPC_PRIME_FIELD_MODULUS)
    });
    DirectMpcPrimeFieldElement::from_u64_reduced(reduced_value)
}

#[derive(Clone, Copy)]
struct DirectMpcWireMetadata {
    phase: Option<DirectMpcPhase>,
    phase_depth: u16,
}

struct DirectMpcCircuitBuilder {
    input_field_count: usize,
    operations: Vec<DirectMpcOperationRecord>,
    wire_metadata: Vec<DirectMpcWireMetadata>,
    multiplication_count: u32,
    validation_layer_counts: Vec<u64>,
    evaluation_layer_counts: Vec<u64>,
    affine_operation_count: usize,
    public_scale_operation_count: usize,
}

impl DirectMpcCircuitBuilder {
    fn new(input_field_count: usize) -> Result<Self, DirectMpcCandidateError> {
        wire_index(input_field_count)?;
        Ok(Self {
            input_field_count,
            operations: Vec::new(),
            wire_metadata: vec![
                DirectMpcWireMetadata {
                    phase: None,
                    phase_depth: 0,
                };
                input_field_count
            ],
            multiplication_count: 0,
            validation_layer_counts: Vec::new(),
            evaluation_layer_counts: Vec::new(),
            affine_operation_count: 0,
            public_scale_operation_count: 0,
        })
    }

    fn append_affine(
        &mut self,
        phase: DirectMpcPhase,
        constant: DirectMpcPrimeFieldElement,
        terms: impl IntoIterator<Item = (DirectMpcWireIndex, DirectMpcPrimeFieldElement)>,
        role: DirectMpcOperationRole,
    ) -> Result<DirectMpcWireIndex, DirectMpcCandidateError> {
        let terms = terms.into_iter().collect::<Vec<_>>().into_boxed_slice();
        let phase_depth = terms.iter().try_fold(0_u16, |depth, (wire, _)| {
            Ok::<_, DirectMpcCandidateError>(depth.max(self.phase_depth(*wire, phase)?))
        })?;
        self.affine_operation_count = self
            .affine_operation_count
            .checked_add(1)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        self.append_operation(
            phase,
            phase_depth,
            None,
            role,
            DirectMpcArithmeticOperation::Affine { constant, terms },
        )
    }

    fn append_public_scale(
        &mut self,
        phase: DirectMpcPhase,
        value_wire: DirectMpcWireIndex,
        public_wire: DirectMpcWireIndex,
        role: DirectMpcOperationRole,
    ) -> Result<DirectMpcWireIndex, DirectMpcCandidateError> {
        let phase_depth = self
            .phase_depth(value_wire, phase)?
            .max(self.phase_depth(public_wire, phase)?);
        self.public_scale_operation_count = self
            .public_scale_operation_count
            .checked_add(1)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        self.append_operation(
            phase,
            phase_depth,
            None,
            role,
            DirectMpcArithmeticOperation::MultiplyByPublic {
                value_wire,
                public_wire,
            },
        )
    }

    fn append_multiply(
        &mut self,
        phase: DirectMpcPhase,
        left_wire: DirectMpcWireIndex,
        right_wire: DirectMpcWireIndex,
        role: DirectMpcOperationRole,
    ) -> Result<DirectMpcWireIndex, DirectMpcCandidateError> {
        let phase_depth = self
            .phase_depth(left_wire, phase)?
            .max(self.phase_depth(right_wire, phase)?)
            .checked_add(1)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let multiplication_ordinal = self.multiplication_count;
        self.multiplication_count = self
            .multiplication_count
            .checked_add(1)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let layer_counts = match phase {
            DirectMpcPhase::BallotValidation => &mut self.validation_layer_counts,
            DirectMpcPhase::TallyEvaluation => &mut self.evaluation_layer_counts,
        };
        let layer_position = usize::from(
            phase_depth
                .checked_sub(1)
                .ok_or(DirectMpcCandidateError::InteractionGraphMismatch)?,
        );
        if layer_counts.len() <= layer_position {
            layer_counts.resize(layer_position + 1, 0);
        }
        layer_counts[layer_position] = layer_counts[layer_position]
            .checked_add(1)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        self.append_operation(
            phase,
            phase_depth,
            Some(multiplication_ordinal),
            role,
            DirectMpcArithmeticOperation::Multiply {
                left_wire,
                right_wire,
            },
        )
    }

    fn append_operation(
        &mut self,
        phase: DirectMpcPhase,
        phase_depth: u16,
        multiplication_ordinal: Option<u32>,
        role: DirectMpcOperationRole,
        operation: DirectMpcArithmeticOperation,
    ) -> Result<DirectMpcWireIndex, DirectMpcCandidateError> {
        let output_wire = wire_index(self.wire_metadata.len())?;
        self.operations.push(DirectMpcOperationRecord {
            output_wire,
            phase,
            phase_depth,
            multiplication_ordinal,
            role,
            operation,
        });
        self.wire_metadata.push(DirectMpcWireMetadata {
            phase: Some(phase),
            phase_depth,
        });
        Ok(output_wire)
    }

    fn phase_depth(
        &self,
        wire: DirectMpcWireIndex,
        phase: DirectMpcPhase,
    ) -> Result<u16, DirectMpcCandidateError> {
        let wire_position =
            usize::try_from(wire).map_err(|_| DirectMpcCandidateError::WireIndexOverflow)?;
        let metadata = self.wire_metadata.get(wire_position).ok_or(
            DirectMpcCandidateError::InvalidWireReference {
                wire,
                available_wire_count: self.wire_metadata.len(),
            },
        )?;
        match metadata.phase {
            None => Ok(0),
            Some(wire_phase) if wire_phase == phase => Ok(metadata.phase_depth),
            Some(wire_phase) if wire_phase < phase => Ok(0),
            Some(_) => Err(DirectMpcCandidateError::InteractionGraphMismatch),
        }
    }

    fn geometry(
        &self,
        input_field_count: usize,
        participant_count: usize,
        score_bitness_constraint_count: usize,
        option_count: usize,
        comparison_polynomial_degree: usize,
    ) -> Result<DirectMpcCandidateGeometry, DirectMpcCandidateError> {
        if input_field_count != self.input_field_count {
            return Err(DirectMpcCandidateError::InteractionGraphMismatch);
        }
        let private_score_bit_field_count = participant_count
            .checked_mul(option_count)
            .and_then(|value| value.checked_mul(DIRECT_MPC_SCORE_BIT_COUNT))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let comparison_pair_count = option_count
            .checked_mul(option_count.saturating_sub(1))
            .and_then(|value| value.checked_div(2))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        Ok(DirectMpcCandidateGeometry {
            input_field_count,
            public_input_field_count: participant_count,
            private_score_bit_field_count,
            affine_operation_count: self.affine_operation_count,
            public_scale_operation_count: self.public_scale_operation_count,
            validation_multiplication_layer_counts: self
                .validation_layer_counts
                .clone()
                .into_boxed_slice(),
            evaluation_multiplication_layer_counts: self
                .evaluation_layer_counts
                .clone()
                .into_boxed_slice(),
            beaver_triple_count: u64::from(self.multiplication_count),
            score_bitness_constraint_count: u64::try_from(score_bitness_constraint_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?,
            comparison_pair_count: u64::try_from(comparison_pair_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?,
            comparison_polynomial_degree: to_u16(comparison_polynomial_degree)?,
            rank_polynomial_degree: to_u16(option_count.saturating_sub(1))?,
            total_wire_count: self.wire_metadata.len(),
        })
    }
}

fn wire_value(
    wire_values: &[DirectMpcPrimeFieldElement],
    wire: DirectMpcWireIndex,
) -> Result<DirectMpcPrimeFieldElement, DirectMpcCandidateError> {
    let position = usize::try_from(wire).map_err(|_| DirectMpcCandidateError::WireIndexOverflow)?;
    wire_values
        .get(position)
        .copied()
        .ok_or(DirectMpcCandidateError::InvalidWireReference {
            wire,
            available_wire_count: wire_values.len(),
        })
}

fn wire_index(value: usize) -> Result<DirectMpcWireIndex, DirectMpcCandidateError> {
    DirectMpcWireIndex::try_from(value).map_err(|_| DirectMpcCandidateError::WireIndexOverflow)
}

fn to_u16(value: usize) -> Result<u16, DirectMpcCandidateError> {
    u16::try_from(value).map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectMpcRoundKind {
    SeedCatalogCommitments,
    SeedMailboxDeliveries,
    SeedMailboxReceipts,
    TriplePreparationOpenings,
    BallotDeclarations,
    BallotDeclarationsAndSourceDeliveries,
    BallotSourceReceiptsAndConsistencyOpenings,
    BallotSourceTerminalAndChallengeOpenings,
    ValidationMultiplicationOpenings {
        layer: u16,
        multiplication_count: u64,
    },
    ValidationOutputOpenings,
    SelectedSetAuthorization,
    TargetFinality,
    EvaluationMultiplicationOpenings {
        layer: u16,
        multiplication_count: u64,
    },
    ResultOpenings,
    ResultWitnesses,
    NoResultWitnesses,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMpcInteractionRound {
    pub(crate) ordinal: u16,
    pub(crate) kind: DirectMpcRoundKind,
    pub(crate) required_participant_visit_count: u16,
    pub(crate) public_message_count: u64,
    pub(crate) private_message_count: u64,
    pub(crate) public_field_element_count: u64,
    pub(crate) requires_durable_checkpoint_before_emit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcInteractionGraph {
    pub(crate) success_rounds: Box<[DirectMpcInteractionRound]>,
    pub(crate) all_abstention_rounds: Box<[DirectMpcInteractionRound]>,
    pub(crate) success_maximum_sequential_visit_count: u64,
    pub(crate) success_minimum_visit_count_with_boundary_overlap: u64,
    pub(crate) all_abstention_maximum_sequential_visit_count: u64,
    pub(crate) all_abstention_minimum_visit_count_with_boundary_overlap: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectMpcFaultClass {
    MissingRequiredMessage,
    UnauthenticatedMalformedMessage,
    AuthenticatedAlgebraicInconsistency,
    ForkedAuthenticatedTranscript,
    ReplayAfterTerminal,
    RollbackDetected,
    ParticipantStateLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectMpcFaultDisposition {
    Pending,
    TerminalBurn,
    RefusedConsumedState,
    ParticipantRetiredAndPending,
}

pub(crate) const DIRECT_MPC_FAULT_DISPOSITIONS: &[(
    DirectMpcFaultClass,
    DirectMpcFaultDisposition,
)] = &[
    (
        DirectMpcFaultClass::MissingRequiredMessage,
        DirectMpcFaultDisposition::Pending,
    ),
    (
        DirectMpcFaultClass::UnauthenticatedMalformedMessage,
        DirectMpcFaultDisposition::Pending,
    ),
    (
        DirectMpcFaultClass::AuthenticatedAlgebraicInconsistency,
        DirectMpcFaultDisposition::TerminalBurn,
    ),
    (
        DirectMpcFaultClass::ForkedAuthenticatedTranscript,
        DirectMpcFaultDisposition::TerminalBurn,
    ),
    (
        DirectMpcFaultClass::ReplayAfterTerminal,
        DirectMpcFaultDisposition::RefusedConsumedState,
    ),
    (
        DirectMpcFaultClass::RollbackDetected,
        DirectMpcFaultDisposition::ParticipantRetiredAndPending,
    ),
    (
        DirectMpcFaultClass::ParticipantStateLost,
        DirectMpcFaultDisposition::ParticipantRetiredAndPending,
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectMpcCandidateResourceModel {
    pub(crate) participant_count: u64,
    pub(crate) active_fault_bound: u64,
    pub(crate) reconstruction_threshold: u64,
    pub(crate) selected_set_quorum: u64,
    pub(crate) finality_quorum: u64,
    pub(crate) state_witness_quorum: u64,
    pub(crate) field_canonical_byte_length: u64,
    pub(crate) field_sample_byte_length: u64,
    pub(crate) beaver_triple_count: u64,
    pub(crate) random_degree_three_sharing_count: u64,
    pub(crate) random_degree_six_zero_sharing_count: u64,
    pub(crate) source_consistency_mask_count: u64,
    pub(crate) validation_challenge_coefficient_count: u64,
    pub(crate) affine_operation_count: u64,
    pub(crate) affine_term_count: u64,
    pub(crate) public_scale_operation_count: u64,
    pub(crate) total_wire_count: u64,
    pub(crate) authorized_subset_count: u64,
    pub(crate) authorized_subset_size: u64,
    pub(crate) authorized_subset_count_per_participant: u64,
    pub(crate) subset_seed_contribution_count: u64,
    pub(crate) private_subset_seed_contribution_delivery_count: u64,
    pub(crate) seed_mailbox_message_count: u64,
    pub(crate) ballot_source_mailbox_message_count: u64,
    pub(crate) private_ballot_share_field_element_count: u64,
    pub(crate) persistent_ballot_share_field_count_per_participant: u64,
    pub(crate) ordinary_prss_field_output_count_per_participant: u64,
    pub(crate) zero_prss_field_output_count_per_participant: u64,
    pub(crate) total_prss_field_output_count_per_participant: u64,
    pub(crate) total_prss_source_byte_length_per_participant: u64,
    pub(crate) prss_kmacxof256_query_count_per_participant: u64,
    pub(crate) prss_work_checkpoint_count_per_participant: u64,
    pub(crate) validation_xof_field_output_count_per_participant: u64,
    pub(crate) maximum_prss_xof_output_allocation_byte_length: u64,
    pub(crate) maximum_prss_accumulator_allocation_byte_length: u64,
    pub(crate) persistent_secret_field_count_per_participant: u64,
    pub(crate) persistent_secret_field_byte_length_per_participant: u64,
    pub(crate) joined_subset_master_byte_length_per_participant: u64,
    pub(crate) public_raw_field_element_count: u64,
    pub(crate) public_raw_field_byte_length: u64,
    pub(crate) public_signed_message_count: u64,
    pub(crate) private_signed_message_count: u64,
    pub(crate) total_signature_generation_count: u64,
    pub(crate) private_kem_encapsulation_count: u64,
    pub(crate) private_aead_seal_count: u64,
}

impl CompiledDirectMpcCandidate {
    pub(crate) fn interaction_graph(
        &self,
    ) -> Result<DirectMpcInteractionGraph, DirectMpcCandidateError> {
        let participant_count = self.profile.participant_count();
        let roster_parameters = derive_foundation_roster_parameters(participant_count)
            .ok_or(DirectMpcCandidateError::InteractionGraphMismatch)?;
        let selected_set_quorum = roster_parameters.candidate_view_quorum;
        let finality_quorum = roster_parameters.finality_quorum;
        let state_witness_quorum = roster_parameters.state_witness_quorum;
        let participant_count_u64 = u64::from(participant_count);
        let private_mailbox_count = participant_count_u64
            .checked_mul(participant_count_u64.saturating_sub(1))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let mut success_rounds = Vec::new();
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::SeedCatalogCommitments,
            participant_count,
            participant_count_u64,
            0,
            0,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::SeedMailboxDeliveries,
            participant_count,
            0,
            private_mailbox_count,
            0,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::SeedMailboxReceipts,
            participant_count,
            participant_count_u64,
            0,
            0,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::TriplePreparationOpenings,
            participant_count,
            participant_count_u64,
            0,
            self.geometry
                .beaver_triple_count
                .checked_mul(participant_count_u64)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::BallotDeclarationsAndSourceDeliveries,
            participant_count,
            participant_count_u64,
            private_mailbox_count,
            0,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::BallotSourceReceiptsAndConsistencyOpenings,
            participant_count,
            participant_count_u64,
            0,
            u64::try_from(self.geometry.private_score_bit_field_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?
                .checked_mul(participant_count_u64)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::BallotSourceTerminalAndChallengeOpenings,
            participant_count,
            participant_count_u64,
            0,
            0,
        )?;
        for (layer_position, multiplication_count) in self
            .geometry
            .validation_multiplication_layer_counts
            .iter()
            .copied()
            .enumerate()
        {
            append_interaction_round(
                &mut success_rounds,
                DirectMpcRoundKind::ValidationMultiplicationOpenings {
                    layer: to_u16(layer_position + 1)?,
                    multiplication_count,
                },
                participant_count,
                participant_count_u64,
                0,
                multiplication_count
                    .checked_mul(2)
                    .and_then(|value| value.checked_mul(participant_count_u64))
                    .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            )?;
        }
        let validation_output_field_count_per_participant = u64::try_from(
            self.accepted_ballot_authorship_wires.len() + DIRECT_MPC_VALIDATION_REPETITION_COUNT,
        )
        .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::ValidationOutputOpenings,
            participant_count,
            participant_count_u64,
            0,
            validation_output_field_count_per_participant
                .checked_mul(participant_count_u64)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::SelectedSetAuthorization,
            selected_set_quorum,
            u64::from(selected_set_quorum),
            0,
            0,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::TargetFinality,
            finality_quorum,
            u64::from(finality_quorum),
            0,
            0,
        )?;
        for (layer_position, multiplication_count) in self
            .geometry
            .evaluation_multiplication_layer_counts
            .iter()
            .copied()
            .enumerate()
        {
            append_interaction_round(
                &mut success_rounds,
                DirectMpcRoundKind::EvaluationMultiplicationOpenings {
                    layer: to_u16(layer_position + 1)?,
                    multiplication_count,
                },
                participant_count,
                participant_count_u64,
                0,
                multiplication_count
                    .checked_mul(2)
                    .and_then(|value| value.checked_mul(participant_count_u64))
                    .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            )?;
        }
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::ResultOpenings,
            participant_count,
            participant_count_u64,
            0,
            u64::try_from(self.ordered_option_position_wires.len())
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?
                .checked_mul(participant_count_u64)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
        )?;
        append_interaction_round(
            &mut success_rounds,
            DirectMpcRoundKind::ResultWitnesses,
            state_witness_quorum,
            u64::from(state_witness_quorum),
            0,
            0,
        )?;

        let mut all_abstention_rounds = success_rounds[..4].to_vec();
        append_interaction_round(
            &mut all_abstention_rounds,
            DirectMpcRoundKind::BallotDeclarations,
            participant_count,
            participant_count_u64,
            0,
            0,
        )?;
        append_interaction_round(
            &mut all_abstention_rounds,
            DirectMpcRoundKind::NoResultWitnesses,
            state_witness_quorum,
            u64::from(state_witness_quorum),
            0,
            0,
        )?;
        let (
            success_maximum_sequential_visit_count,
            success_minimum_visit_count_with_boundary_overlap,
        ) = interaction_visit_bounds(&success_rounds)?;
        let (
            all_abstention_maximum_sequential_visit_count,
            all_abstention_minimum_visit_count_with_boundary_overlap,
        ) = interaction_visit_bounds(&all_abstention_rounds)?;
        Ok(DirectMpcInteractionGraph {
            success_rounds: success_rounds.into_boxed_slice(),
            all_abstention_rounds: all_abstention_rounds.into_boxed_slice(),
            success_maximum_sequential_visit_count,
            success_minimum_visit_count_with_boundary_overlap,
            all_abstention_maximum_sequential_visit_count,
            all_abstention_minimum_visit_count_with_boundary_overlap,
        })
    }

    pub(crate) fn resource_model(
        &self,
    ) -> Result<DirectMpcCandidateResourceModel, DirectMpcCandidateError> {
        let participant_count = u64::from(self.profile.participant_count());
        let roster_parameters =
            derive_foundation_roster_parameters(self.profile.participant_count())
                .ok_or(DirectMpcCandidateError::InteractionGraphMismatch)?;
        let active_fault_bound = u64::from(roster_parameters.active_fault_bound);
        let reconstruction_threshold = u64::from(roster_parameters.reconstruction_threshold);
        let selected_set_quorum = u64::from(roster_parameters.candidate_view_quorum);
        let finality_quorum = u64::from(roster_parameters.finality_quorum);
        let state_witness_quorum = u64::from(roster_parameters.state_witness_quorum);
        let authorized_subset_count =
            checked_binomial_coefficient(participant_count, active_fault_bound)?;
        let authorized_subset_count_per_participant = checked_binomial_coefficient(
            participant_count
                .checked_sub(1)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            active_fault_bound,
        )?;
        let authorized_subset_size = participant_count
            .checked_sub(active_fault_bound)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let source_consistency_mask_count =
            u64::try_from(self.geometry.private_score_bit_field_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?;
        let random_degree_three_sharing_count = self
            .geometry
            .beaver_triple_count
            .checked_mul(3)
            .and_then(|value| value.checked_add(source_consistency_mask_count))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let random_degree_six_zero_sharing_count = self.geometry.beaver_triple_count;
        let ordinary_prss_field_output_count_per_participant = random_degree_three_sharing_count
            .checked_mul(authorized_subset_count_per_participant)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let zero_prss_field_output_count_per_participant = random_degree_six_zero_sharing_count
            .checked_mul(authorized_subset_count_per_participant)
            .and_then(|value| value.checked_mul(active_fault_bound))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let total_prss_field_output_count_per_participant =
            ordinary_prss_field_output_count_per_participant
                .checked_add(zero_prss_field_output_count_per_participant)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let total_prss_source_byte_length_per_participant =
            total_prss_field_output_count_per_participant
                .checked_mul(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let fields_per_chunk = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?
            / DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH;
        let ordinary_chunk_count =
            ceiling_divide(random_degree_three_sharing_count, fields_per_chunk)?;
        let zero_chunk_count =
            ceiling_divide(random_degree_six_zero_sharing_count, fields_per_chunk)?;
        let prss_kmacxof256_query_count_per_participant = authorized_subset_count_per_participant
            .checked_mul(ordinary_chunk_count)
            .and_then(|ordinary| {
                authorized_subset_count_per_participant
                    .checked_mul(active_fault_bound)
                    .and_then(|streams| streams.checked_mul(zero_chunk_count))
                    .and_then(|zero| ordinary.checked_add(zero))
            })
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let validation_challenge_coefficient_count = source_consistency_mask_count
            .checked_mul(DIRECT_MPC_VALIDATION_REPETITION_COUNT as u64)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let affine_term_count = self.operations.iter().try_fold(0_u64, |sum, record| {
            let term_count = match &record.operation {
                DirectMpcArithmeticOperation::Affine { terms, .. } => u64::try_from(terms.len())
                    .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?,
                DirectMpcArithmeticOperation::Multiply { .. }
                | DirectMpcArithmeticOperation::MultiplyByPublic { .. } => 0,
            };
            sum.checked_add(term_count)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)
        })?;
        let persistent_ballot_share_field_count_per_participant =
            u64::try_from(self.geometry.private_score_bit_field_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?;
        let persistent_secret_field_count_per_participant = self
            .geometry
            .beaver_triple_count
            .checked_mul(3)
            .and_then(|value| value.checked_add(source_consistency_mask_count))
            .and_then(|value| {
                value.checked_add(persistent_ballot_share_field_count_per_participant)
            })
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let field_canonical_byte_length = DirectMpcPrimeFieldElement::CANONICAL_BYTE_LENGTH as u64;
        let interaction_graph = self.interaction_graph()?;
        let public_raw_field_element_count =
            interaction_graph
                .success_rounds
                .iter()
                .try_fold(0_u64, |sum, round| {
                    sum.checked_add(round.public_field_element_count)
                        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)
                })?;
        let public_signed_message_count =
            interaction_graph
                .success_rounds
                .iter()
                .try_fold(0_u64, |sum, round| {
                    sum.checked_add(round.public_message_count)
                        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)
                })?;
        let private_signed_message_count =
            interaction_graph
                .success_rounds
                .iter()
                .try_fold(0_u64, |sum, round| {
                    sum.checked_add(round.private_message_count)
                        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)
                })?;
        let seed_mailbox_message_count = participant_count
            .checked_mul(participant_count.saturating_sub(1))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let ballot_source_mailbox_message_count = seed_mailbox_message_count;
        let subset_seed_contribution_count = authorized_subset_count
            .checked_mul(authorized_subset_size)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let private_subset_seed_contribution_delivery_count = subset_seed_contribution_count
            .checked_mul(authorized_subset_size.saturating_sub(1))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        let private_ballot_share_field_element_count = source_consistency_mask_count
            .checked_mul(participant_count.saturating_sub(1))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?;
        Ok(DirectMpcCandidateResourceModel {
            participant_count,
            active_fault_bound,
            reconstruction_threshold,
            selected_set_quorum,
            finality_quorum,
            state_witness_quorum,
            field_canonical_byte_length,
            field_sample_byte_length: DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH,
            beaver_triple_count: self.geometry.beaver_triple_count,
            random_degree_three_sharing_count,
            random_degree_six_zero_sharing_count,
            source_consistency_mask_count,
            validation_challenge_coefficient_count,
            affine_operation_count: u64::try_from(self.geometry.affine_operation_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?,
            affine_term_count,
            public_scale_operation_count: u64::try_from(self.geometry.public_scale_operation_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?,
            total_wire_count: u64::try_from(self.geometry.total_wire_count)
                .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?,
            authorized_subset_count,
            authorized_subset_size,
            authorized_subset_count_per_participant,
            subset_seed_contribution_count,
            private_subset_seed_contribution_delivery_count,
            seed_mailbox_message_count,
            ballot_source_mailbox_message_count,
            private_ballot_share_field_element_count,
            persistent_ballot_share_field_count_per_participant,
            ordinary_prss_field_output_count_per_participant,
            zero_prss_field_output_count_per_participant,
            total_prss_field_output_count_per_participant,
            total_prss_source_byte_length_per_participant,
            prss_kmacxof256_query_count_per_participant,
            prss_work_checkpoint_count_per_participant: prss_kmacxof256_query_count_per_participant,
            validation_xof_field_output_count_per_participant:
                validation_challenge_coefficient_count,
            maximum_prss_xof_output_allocation_byte_length: random_degree_three_sharing_count
                .max(random_degree_six_zero_sharing_count)
                .checked_mul(DIRECT_MPC_FIELD_SAMPLE_BYTE_LENGTH)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            maximum_prss_accumulator_allocation_byte_length: random_degree_three_sharing_count
                .max(random_degree_six_zero_sharing_count)
                .checked_mul(field_canonical_byte_length)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            persistent_secret_field_count_per_participant,
            persistent_secret_field_byte_length_per_participant:
                persistent_secret_field_count_per_participant
                    .checked_mul(field_canonical_byte_length)
                    .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            joined_subset_master_byte_length_per_participant:
                authorized_subset_count_per_participant
                    .checked_mul(DIRECT_MPC_SUBSET_SEED_BYTE_LENGTH)
                    .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            public_raw_field_element_count,
            public_raw_field_byte_length: public_raw_field_element_count
                .checked_mul(field_canonical_byte_length)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            public_signed_message_count,
            private_signed_message_count,
            total_signature_generation_count: public_signed_message_count
                .checked_add(private_signed_message_count)
                .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?,
            private_kem_encapsulation_count: private_signed_message_count,
            private_aead_seal_count: private_signed_message_count,
        })
    }
}

fn append_interaction_round(
    rounds: &mut Vec<DirectMpcInteractionRound>,
    kind: DirectMpcRoundKind,
    required_participant_visit_count: u16,
    public_message_count: u64,
    private_message_count: u64,
    public_field_element_count: u64,
) -> Result<(), DirectMpcCandidateError> {
    let ordinal =
        u16::try_from(rounds.len() + 1).map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?;
    rounds.push(DirectMpcInteractionRound {
        ordinal,
        kind,
        required_participant_visit_count,
        public_message_count,
        private_message_count,
        public_field_element_count,
        requires_durable_checkpoint_before_emit: true,
    });
    Ok(())
}

fn interaction_visit_bounds(
    rounds: &[DirectMpcInteractionRound],
) -> Result<(u64, u64), DirectMpcCandidateError> {
    let maximum = rounds.iter().try_fold(0_u64, |sum, round| {
        sum.checked_add(u64::from(round.required_participant_visit_count))
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)
    })?;
    let overlap_count = u64::try_from(rounds.len().saturating_sub(1))
        .map_err(|_| DirectMpcCandidateError::ArithmeticOverflow)?;
    let minimum = maximum
        .checked_sub(overlap_count)
        .ok_or(DirectMpcCandidateError::InteractionGraphMismatch)?;
    Ok((maximum, minimum))
}

fn ceiling_divide(dividend: u64, divisor: u64) -> Result<u64, DirectMpcCandidateError> {
    if divisor == 0 {
        return Err(DirectMpcCandidateError::ArithmeticOverflow);
    }
    dividend
        .checked_add(divisor - 1)
        .and_then(|value| value.checked_div(divisor))
        .ok_or(DirectMpcCandidateError::ArithmeticOverflow)
}

fn checked_binomial_coefficient(
    total_count: u64,
    selected_count: u64,
) -> Result<u64, DirectMpcCandidateError> {
    if selected_count > total_count {
        return Err(DirectMpcCandidateError::ArithmeticOverflow);
    }
    let selected_count = selected_count.min(total_count - selected_count);
    let mut result = 1_u64;
    for factor_position in 0..selected_count {
        result = result
            .checked_mul(total_count - factor_position)
            .ok_or(DirectMpcCandidateError::ArithmeticOverflow)?
            / (factor_position + 1);
    }
    Ok(result)
}
