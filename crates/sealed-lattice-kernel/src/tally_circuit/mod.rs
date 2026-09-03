//! Development-only deterministic tally compiler and independent evaluator.

pub(crate) mod compiler;
#[cfg(test)]
pub(crate) mod direct_evaluator;
#[cfg(test)]
mod interpreter;
#[cfg(test)]
mod tests;

use core::fmt;

use crate::foundation::{
    FOUNDATION_MAXIMUM_SCORE, FOUNDATION_MINIMUM_SCORE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
    MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
    MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
};

pub(crate) type WireIndex = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TallyCircuitProfile {
    participant_count: u16,
    option_count: u16,
    top_count: u16,
}

impl TallyCircuitProfile {
    pub(crate) fn new(
        participant_count: u16,
        option_count: u16,
        top_count: u16,
    ) -> Result<Self, TallyCircuitError> {
        if !(MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT)
            .contains(&participant_count)
        {
            return Err(TallyCircuitError::ParticipantCountOutOfRange { participant_count });
        }
        if !(MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT)
            .contains(&option_count)
        {
            return Err(TallyCircuitError::OptionCountOutOfRange { option_count });
        }
        if !(1..=option_count).contains(&top_count) {
            return Err(TallyCircuitError::TopCountOutOfRange {
                top_count,
                option_count,
            });
        }

        Ok(Self {
            participant_count,
            option_count,
            top_count,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BooleanOperation {
    Constant(bool),
    ExclusiveOr {
        left_wire: WireIndex,
        right_wire: WireIndex,
    },
    Conjunction {
        left_wire: WireIndex,
        right_wire: WireIndex,
    },
    Negation {
        input_wire: WireIndex,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledTallyCircuit {
    profile: TallyCircuitProfile,
    input_bit_count: usize,
    score_bit_width: usize,
    operations: Vec<BooleanOperation>,
    participant_selected_wires: Vec<WireIndex>,
    nonempty_output_wire: WireIndex,
    ordered_option_position_wires: Vec<Vec<WireIndex>>,
}

impl CompiledTallyCircuit {
    pub(crate) const fn input_bit_count(&self) -> usize {
        self.input_bit_count
    }

    pub(crate) fn operations(&self) -> &[BooleanOperation] {
        &self.operations
    }

    pub(crate) fn output_wires(&self) -> Vec<WireIndex> {
        let output_bit_count = self
            .participant_selected_wires
            .len()
            .saturating_add(1)
            .saturating_add(
                self.ordered_option_position_wires
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>(),
            );
        let mut output_wires = Vec::with_capacity(output_bit_count);
        output_wires.extend_from_slice(&self.participant_selected_wires);
        output_wires.push(self.nonempty_output_wire);
        output_wires.extend(
            self.ordered_option_position_wires
                .iter()
                .flat_map(|position_wires| position_wires.iter().copied()),
        );
        output_wires
    }
}

pub(crate) fn encode_compiled_tally_circuit(
    circuit: &CompiledTallyCircuit,
) -> Result<Vec<u8>, TallyCircuitError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        &u64::try_from(circuit.input_bit_count())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u64::try_from(circuit.operations().len())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for operation in circuit.operations() {
        match operation {
            BooleanOperation::Constant(value) => {
                bytes.push(1);
                bytes.push(u8::from(*value));
            }
            BooleanOperation::ExclusiveOr {
                left_wire,
                right_wire,
            } => {
                bytes.push(2);
                bytes.extend_from_slice(&left_wire.to_le_bytes());
                bytes.extend_from_slice(&right_wire.to_le_bytes());
            }
            BooleanOperation::Conjunction {
                left_wire,
                right_wire,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(&left_wire.to_le_bytes());
                bytes.extend_from_slice(&right_wire.to_le_bytes());
            }
            BooleanOperation::Negation { input_wire } => {
                bytes.push(4);
                bytes.extend_from_slice(&input_wire.to_le_bytes());
            }
        }
    }
    let output_wires = circuit.output_wires();
    bytes.extend_from_slice(
        &u64::try_from(output_wires.len())
            .map_err(|_| TallyCircuitError::ArithmeticOverflow)?
            .to_le_bytes(),
    );
    for output_wire in output_wires {
        bytes.extend_from_slice(&output_wire.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TallyEvaluationInput {
    participant_ballots: Vec<TallyBallotInput>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TallyBallotInput {
    is_present: bool,
    score_encodings: Vec<u8>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TallyEvaluationOutcome {
    accepted_ballot_authorship: Vec<bool>,
    ordered_option_positions: Vec<u16>,
    has_selected_ballot: bool,
}

#[cfg(test)]
impl TallyEvaluationOutcome {
    /// Returns the only tally value that may advance toward release.
    ///
    /// Empty selection refuses without returning circuit output positions.
    /// Ballot validity is never an output.
    pub(crate) fn accepted_ordered_option_positions(&self) -> Option<&[u16]> {
        self.has_selected_ballot
            .then_some(self.ordered_option_positions.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TallyCircuitError {
    ParticipantCountOutOfRange {
        participant_count: u16,
    },
    OptionCountOutOfRange {
        option_count: u16,
    },
    TopCountOutOfRange {
        top_count: u16,
        option_count: u16,
    },
    ArithmeticOverflow,
    WireIndexOverflow,
    #[cfg(test)]
    InputParticipantCountMismatch {
        expected: usize,
        actual: usize,
    },
    #[cfg(test)]
    InputOptionCountMismatch {
        participant_position: usize,
        expected: usize,
        actual: usize,
    },
    #[cfg(test)]
    ScoreEncodingOutOfRange {
        participant_position: usize,
        option_position: usize,
        score_encoding: u8,
    },
    #[cfg(test)]
    InputBitCountMismatch {
        expected: usize,
        actual: usize,
    },
    InvalidWireReference {
        wire: WireIndex,
        available_wire_count: usize,
    },
}

impl fmt::Display for TallyCircuitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParticipantCountOutOfRange { participant_count } => write!(
                formatter,
                "participant count {participant_count} is outside the configurable range"
            ),
            Self::OptionCountOutOfRange { option_count } => write!(
                formatter,
                "option count {option_count} is outside the configurable range"
            ),
            Self::TopCountOutOfRange {
                top_count,
                option_count,
            } => write!(
                formatter,
                "top count {top_count} is outside 1..={option_count}"
            ),
            Self::ArithmeticOverflow => formatter.write_str("tally circuit arithmetic overflow"),
            Self::WireIndexOverflow => formatter.write_str("tally circuit wire index overflow"),
            #[cfg(test)]
            Self::InputParticipantCountMismatch { expected, actual } => write!(
                formatter,
                "expected {expected} participant inputs, received {actual}"
            ),
            #[cfg(test)]
            Self::InputOptionCountMismatch {
                participant_position,
                expected,
                actual,
            } => write!(
                formatter,
                "participant {participant_position} has {actual} score encodings; expected {expected}"
            ),
            #[cfg(test)]
            Self::ScoreEncodingOutOfRange {
                participant_position,
                option_position,
                score_encoding,
            } => write!(
                formatter,
                "score encoding {score_encoding} at participant {participant_position}, option {option_position} exceeds the circuit input width"
            ),
            #[cfg(test)]
            Self::InputBitCountMismatch { expected, actual } => write!(
                formatter,
                "expected {expected} circuit input bits, received {actual}"
            ),
            Self::InvalidWireReference {
                wire,
                available_wire_count,
            } => write!(
                formatter,
                "wire {wire} is unavailable with {available_wire_count} preceding wires"
            ),
        }
    }
}

impl std::error::Error for TallyCircuitError {}

pub(crate) const fn foundation_score_bounds() -> (u16, u16) {
    (FOUNDATION_MINIMUM_SCORE, FOUNDATION_MAXIMUM_SCORE)
}

pub(crate) fn bit_width_for_maximum_value(maximum_value: usize) -> usize {
    usize::BITS as usize - maximum_value.leading_zeros() as usize
}
