//! Unactivated preparation functionality for the deterministic tally circuit.
//!
//! This module currently owns only the independently checked binary field and
//! degree-three mask sharing used by the candidate preparation functionality.
//! It does not select a preparation protocol, mint a capability, or activate a
//! suite.

mod binary_field;
mod output_sharing;

#[cfg(test)]
mod tests;

use core::fmt;

use crate::encoding::CanonicalError;

pub(crate) use binary_field::BinaryFieldElement256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TallyPreparationError {
    FieldElementByteLength {
        expected: usize,
        actual: usize,
    },
    ZeroHasNoMultiplicativeInverse,
    ParticipantCountOutOfRange {
        participant_count: u16,
    },
    RosterPositionOutOfRange {
        roster_position: u16,
        participant_count: u16,
    },
    ZeroEvaluationPoint,
    EvaluationPointMismatch {
        roster_position: u16,
    },
    ParticipantCountMismatch,
    InsufficientShares {
        required: usize,
        actual: usize,
    },
    ExcessShares {
        participant_count: u16,
        actual: usize,
    },
    DuplicateSharePosition {
        roster_position: u16,
    },
    InconsistentShare {
        roster_position: u16,
    },
    ShareArtifactMagicMismatch,
    UnsupportedShareArtifactVersion {
        version: u64,
    },
    TrailingShareArtifactBytes,
    IntegerConversion,
    CanonicalEncoding(CanonicalError),
}

impl fmt::Display for TallyPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldElementByteLength { expected, actual } => write!(
                formatter,
                "binary field element has {actual} bytes; expected {expected}"
            ),
            Self::ZeroHasNoMultiplicativeInverse => {
                formatter.write_str("zero has no multiplicative inverse")
            }
            Self::ParticipantCountOutOfRange { participant_count } => write!(
                formatter,
                "participant count {participant_count} cannot support degree-three mask sharing"
            ),
            Self::RosterPositionOutOfRange {
                roster_position,
                participant_count,
            } => write!(
                formatter,
                "roster position {roster_position} is outside participant count {participant_count}"
            ),
            Self::ZeroEvaluationPoint => {
                formatter.write_str("a Shamir evaluation point must be nonzero")
            }
            Self::EvaluationPointMismatch { roster_position } => write!(
                formatter,
                "the Shamir evaluation point does not match roster position {roster_position}"
            ),
            Self::ParticipantCountMismatch => {
                formatter.write_str("mask shares bind different participant counts")
            }
            Self::InsufficientShares { required, actual } => write!(
                formatter,
                "received {actual} mask shares; at least {required} are required"
            ),
            Self::ExcessShares {
                participant_count,
                actual,
            } => write!(
                formatter,
                "received {actual} mask shares for {participant_count} participants"
            ),
            Self::DuplicateSharePosition { roster_position } => write!(
                formatter,
                "mask shares repeat roster position {roster_position}"
            ),
            Self::InconsistentShare { roster_position } => write!(
                formatter,
                "mask share at roster position {roster_position} is inconsistent with the degree-three polynomial"
            ),
            Self::ShareArtifactMagicMismatch => {
                formatter.write_str("degree-three mask share artifact magic does not match")
            }
            Self::UnsupportedShareArtifactVersion { version } => write!(
                formatter,
                "unsupported degree-three mask share artifact version {version}"
            ),
            Self::TrailingShareArtifactBytes => {
                formatter.write_str("degree-three mask share artifact has trailing bytes")
            }
            Self::IntegerConversion => {
                formatter.write_str("tally preparation integer conversion failed")
            }
            Self::CanonicalEncoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TallyPreparationError {}

impl From<CanonicalError> for TallyPreparationError {
    fn from(error: CanonicalError) -> Self {
        Self::CanonicalEncoding(error)
    }
}
