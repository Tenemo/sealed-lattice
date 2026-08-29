//! Unactivated deterministic Boolean tally circuit.
//!
//! This module owns a candidate circuit artifact and independent development
//! semantics. It does not mint a suite, proof, verification result, workflow
//! capability, or public result.

mod codec;
mod compiler;
mod direct_evaluator;
mod interpreter;
mod output_rekeyed;

#[cfg(test)]
pub(crate) use direct_evaluator::evaluate_tally_directly;
pub(crate) use output_rekeyed::OutputRekeyedTallyCircuit;

#[cfg(test)]
mod output_rekeyed_tests;
#[cfg(test)]
mod tests;

use core::fmt;

use crate::{
    encoding::CanonicalError,
    foundation::{
        FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
};

pub(crate) const TALLY_CIRCUIT_ARTIFACT_MAGIC: &[u8] = b"sealed-lattice/tally-circuit-artifact";
pub(crate) const TALLY_CIRCUIT_COMPILER_IDENTITY_DOMAIN: &str =
    "sealed-lattice/tally-circuit-compiler-identity/v3";
pub(crate) const TALLY_DIRECT_EVALUATOR_IDENTITY_DOMAIN: &str =
    "sealed-lattice/tally-direct-evaluator-identity/v2";
pub(crate) const TALLY_CIRCUIT_IDENTITY_DOMAIN: &str = "sealed-lattice/tally-circuit-identity/v3";

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

    pub(crate) const fn participant_count(self) -> u16 {
        self.participant_count
    }

    pub(crate) const fn option_count(self) -> u16 {
        self.option_count
    }

    pub(crate) const fn top_count(self) -> u16 {
        self.top_count
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

impl BooleanOperation {
    pub(crate) fn referenced_wires(&self) -> impl Iterator<Item = WireIndex> + '_ {
        let wires = match self {
            Self::Constant(_) => [None, None],
            Self::ExclusiveOr {
                left_wire,
                right_wire,
            }
            | Self::Conjunction {
                left_wire,
                right_wire,
            } => [Some(*left_wire), Some(*right_wire)],
            Self::Negation { input_wire } => [Some(*input_wire), None],
        };
        wires.into_iter().flatten()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TallyCircuitGeometry {
    pub(crate) input_bit_count: usize,
    pub(crate) ballot_presence_input_bit_count: usize,
    pub(crate) private_score_input_bit_count: usize,
    pub(crate) score_bit_width: usize,
    pub(crate) aggregate_score_bit_width: usize,
    pub(crate) option_position_bit_width: usize,
    pub(crate) constant_operation_count: usize,
    pub(crate) conjunction_gate_count: usize,
    pub(crate) exclusive_or_gate_count: usize,
    pub(crate) negation_gate_count: usize,
    pub(crate) total_wire_count: usize,
    pub(crate) fresh_input_and_conjunction_output_wire_count: usize,
    pub(crate) folded_conjunction_count: usize,
    pub(crate) folded_exclusive_or_count: usize,
    pub(crate) folded_negation_count: usize,
    pub(crate) duplicate_input_conjunction_count: usize,
    pub(crate) public_output_bit_count: usize,
    pub(crate) private_result_bit_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledTallyCircuit {
    profile: TallyCircuitProfile,
    geometry: TallyCircuitGeometry,
    operations: Vec<BooleanOperation>,
    ballot_presence_wires: Vec<WireIndex>,
    ballot_score_wires: Vec<Vec<Vec<WireIndex>>>,
    nonempty_output_wire: WireIndex,
    ordered_option_position_wires: Vec<Vec<WireIndex>>,
}

impl CompiledTallyCircuit {
    pub(crate) fn compile(profile: TallyCircuitProfile) -> Result<Self, TallyCircuitError> {
        compiler::compile_tally_circuit(profile)
    }

    pub(crate) fn compiler_identity() -> Result<[u8; 64], TallyCircuitError> {
        compiler::tally_circuit_compiler_identity()
    }

    pub(crate) const fn profile(&self) -> TallyCircuitProfile {
        self.profile
    }

    pub(crate) const fn geometry(&self) -> TallyCircuitGeometry {
        self.geometry
    }

    pub(crate) fn operations(&self) -> &[BooleanOperation] {
        &self.operations
    }

    pub(crate) fn ballot_presence_wires(&self) -> &[WireIndex] {
        &self.ballot_presence_wires
    }

    pub(crate) fn ballot_score_wires(&self) -> &[Vec<Vec<WireIndex>>] {
        &self.ballot_score_wires
    }

    pub(crate) fn private_score_input_wires(&self) -> impl Iterator<Item = WireIndex> + '_ {
        self.ballot_score_wires.iter().flatten().flatten().copied()
    }

    pub(crate) const fn nonempty_output_wire(&self) -> WireIndex {
        self.nonempty_output_wire
    }

    pub(crate) fn ordered_option_position_wires(&self) -> &[Vec<WireIndex>] {
        &self.ordered_option_position_wires
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, TallyCircuitError> {
        codec::encode_canonical_tally_circuit(self)
    }

    pub(crate) fn circuit_identity(&self) -> Result<[u8; 64], TallyCircuitError> {
        let canonical_bytes = self.canonical_bytes()?;
        Ok(crate::hashing::hash_framed_parts_512(
            TALLY_CIRCUIT_IDENTITY_DOMAIN,
            &[&canonical_bytes],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TallyEvaluationInput {
    participant_ballots: Vec<TallyBallotInput>,
}

impl TallyEvaluationInput {
    pub(crate) fn new(participant_ballots: Vec<TallyBallotInput>) -> Self {
        Self {
            participant_ballots,
        }
    }

    pub(crate) fn participant_ballots(&self) -> &[TallyBallotInput] {
        &self.participant_ballots
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TallyBallotInput {
    is_present: bool,
    score_encodings: Vec<u8>,
}

impl TallyBallotInput {
    pub(crate) fn new(is_present: bool, score_encodings: Vec<u8>) -> Self {
        Self {
            is_present,
            score_encodings,
        }
    }

    pub(crate) const fn is_present(&self) -> bool {
        self.is_present
    }

    pub(crate) fn score_encodings(&self) -> &[u8] {
        &self.score_encodings
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TallyEvaluationOutcome {
    ordered_option_positions: Vec<u16>,
    has_selected_ballot: bool,
}

impl TallyEvaluationOutcome {
    pub(crate) fn ordered_option_positions(&self) -> &[u16] {
        &self.ordered_option_positions
    }

    pub(crate) const fn has_selected_ballot(&self) -> bool {
        self.has_selected_ballot
    }

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
    UnsupportedFoundationScoreRange {
        minimum_score: u16,
        maximum_score: u16,
    },
    ArithmeticOverflow,
    WireIndexOverflow,
    InputParticipantCountMismatch {
        expected: usize,
        actual: usize,
    },
    InputParticipantPositionOutOfRange {
        participant_position: usize,
        participant_count: usize,
    },
    InputOptionCountMismatch {
        participant_position: usize,
        expected: usize,
        actual: usize,
    },
    ScoreEncodingOutOfRange {
        participant_position: usize,
        option_position: usize,
        score_encoding: u8,
    },
    InputBitCountMismatch {
        expected: usize,
        actual: usize,
    },
    InvalidWireReference {
        wire: WireIndex,
        available_wire_count: usize,
    },
    InvalidOutputWire {
        wire: WireIndex,
        total_wire_count: usize,
    },
    ArtifactTooLarge {
        byte_length: usize,
        maximum_byte_length: usize,
    },
    UnsupportedArtifactVersion {
        version: u64,
    },
    ArtifactMagicMismatch,
    CompilerIdentityMismatch,
    DirectEvaluatorIdentityMismatch,
    NonCanonicalSourceEncoding,
    CircuitMismatch,
    CanonicalEncoding(CanonicalError),
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
            Self::UnsupportedFoundationScoreRange {
                minimum_score,
                maximum_score,
            } => write!(
                formatter,
                "foundation score range {minimum_score}..={maximum_score} is not implemented by this compiler version"
            ),
            Self::ArithmeticOverflow => formatter.write_str("tally circuit arithmetic overflow"),
            Self::WireIndexOverflow => formatter.write_str("tally circuit wire index overflow"),
            Self::InputParticipantCountMismatch { expected, actual } => write!(
                formatter,
                "expected {expected} participant inputs, received {actual}"
            ),
            Self::InputParticipantPositionOutOfRange {
                participant_position,
                participant_count,
            } => write!(
                formatter,
                "participant input position {participant_position} is outside {participant_count} participants"
            ),
            Self::InputOptionCountMismatch {
                participant_position,
                expected,
                actual,
            } => write!(
                formatter,
                "participant {participant_position} has {actual} score encodings; expected {expected}"
            ),
            Self::ScoreEncodingOutOfRange {
                participant_position,
                option_position,
                score_encoding,
            } => write!(
                formatter,
                "score encoding {score_encoding} at participant {participant_position}, option {option_position} exceeds the circuit input width"
            ),
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
            Self::InvalidOutputWire {
                wire,
                total_wire_count,
            } => write!(
                formatter,
                "output wire {wire} is outside {total_wire_count} total wires"
            ),
            Self::ArtifactTooLarge {
                byte_length,
                maximum_byte_length,
            } => write!(
                formatter,
                "tally circuit artifact has {byte_length} bytes; maximum is {maximum_byte_length}"
            ),
            Self::UnsupportedArtifactVersion { version } => {
                write!(
                    formatter,
                    "unsupported tally circuit artifact version {version}"
                )
            }
            Self::ArtifactMagicMismatch => {
                formatter.write_str("tally circuit artifact magic does not match")
            }
            Self::CompilerIdentityMismatch => {
                formatter.write_str("tally circuit compiler identity does not match")
            }
            Self::DirectEvaluatorIdentityMismatch => {
                formatter.write_str("tally direct evaluator identity does not match")
            }
            Self::NonCanonicalSourceEncoding => formatter.write_str(
                "tally circuit source identity requires canonical UTF-8 with LF line endings",
            ),
            Self::CircuitMismatch => formatter.write_str(
                "tally circuit artifact is not the canonical compiler output for its profile",
            ),
            Self::CanonicalEncoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TallyCircuitError {}

impl From<CanonicalError> for TallyCircuitError {
    fn from(error: CanonicalError) -> Self {
        Self::CanonicalEncoding(error)
    }
}

pub(crate) fn foundation_score_bounds() -> Result<(u16, u16), TallyCircuitError> {
    if FOUNDATION_PROFILE.minimum_score != 1 || FOUNDATION_PROFILE.maximum_score != 10 {
        return Err(TallyCircuitError::UnsupportedFoundationScoreRange {
            minimum_score: FOUNDATION_PROFILE.minimum_score,
            maximum_score: FOUNDATION_PROFILE.maximum_score,
        });
    }
    Ok((
        FOUNDATION_PROFILE.minimum_score,
        FOUNDATION_PROFILE.maximum_score,
    ))
}

pub(crate) fn bit_width_for_maximum_value(maximum_value: usize) -> usize {
    usize::BITS as usize - maximum_value.leading_zeros() as usize
}
