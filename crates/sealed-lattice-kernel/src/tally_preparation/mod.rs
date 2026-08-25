//! Unactivated preparation functionality for the deterministic tally circuit.
//!
//! This module currently owns only the independently checked binary field and
//! degree-three mask sharing used by the candidate preparation functionality.
//! It does not select a preparation protocol, mint a capability, or activate a
//! suite.

mod adaptive_oracle_repair;
mod amortized_binary_mpc_communication_floor;
mod authenticated_opening;
mod binary_field;
mod binary_field_multiplication_circuit;
mod binary_linear_circuit;
mod binary_ring_packed_mpc_evaluation_floor;
mod context;
mod fixed_roster_beaver_mpc_resource_floor;
mod fixed_roster_linear_mpc_communication_floor;
mod garbled_resource_model;
mod garbling;
mod garbling_alternative_resource_model;
mod geometry;
mod label_encoding;
mod malicious_mpc_communication_floor;
mod output_sharing;
mod preparation_arithmetic_graph;
mod random_state;
mod random_tape;
mod replicated_key_ceremony;
mod replicated_key_ceremony_resource_model;
mod replicated_random_sharing;
mod tower_field_multiplication_circuit;

#[cfg(test)]
mod adaptive_oracle_repair_tests;
#[cfg(test)]
mod amortized_binary_mpc_communication_floor_tests;
#[cfg(test)]
mod authenticated_opening_tests;
#[cfg(test)]
mod binary_field_multiplication_circuit_tests;
#[cfg(test)]
mod binary_linear_circuit_tests;
#[cfg(test)]
mod binary_ring_packed_mpc_evaluation_floor_tests;
#[cfg(test)]
mod fixed_roster_beaver_mpc_resource_floor_tests;
#[cfg(test)]
mod fixed_roster_linear_mpc_communication_floor_tests;
#[cfg(test)]
mod garbled_resource_model_tests;
#[cfg(test)]
mod garbling_alternative_resource_model_tests;
#[cfg(test)]
mod garbling_tests;
#[cfg(test)]
mod label_encoding_tests;
#[cfg(test)]
mod malicious_mpc_communication_floor_tests;
#[cfg(test)]
mod preparation_arithmetic_graph_tests;
#[cfg(test)]
mod randomness_tests;
#[cfg(test)]
mod replicated_key_ceremony_resource_model_tests;
#[cfg(test)]
mod replicated_key_ceremony_tests;
#[cfg(test)]
mod replicated_random_sharing_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tower_field_multiplication_circuit_tests;

use core::fmt;

use crate::tally_circuit::TallyCircuitError;
use crate::{encoding::CanonicalError, foundation::CanonicalCodecError};

pub(crate) use binary_field::BinaryFieldElement256;
pub(crate) use context::TallyPreparationContext;
pub(crate) use geometry::TallyPreparationGeometry;
#[cfg(test)]
pub(crate) use random_state::parse_tally_preparation_random_state;
#[cfg(test)]
pub(crate) use random_tape::{ExplicitJointRandomTape, SeededJointRandomTape};
pub(crate) use random_tape::{
    SEEDED_RANDOM_TAPE_BLOCK_BYTE_LENGTH, TallyPreparationRandomTapeSource,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TallyPreparationError {
    AuthenticatedShareContextEmpty,
    AuthenticatedShareCoordinateEmpty,
    AuthenticatedShareValueLimbCount {
        actual: usize,
    },
    AuthenticatedShareVerificationKeyLimbCountMismatch {
        expected: usize,
        actual: usize,
    },
    SubmittedParticipantCountOutOfRange {
        submitted_participant_count: u64,
        participant_count: u64,
    },
    AuthenticatedShareCommitmentByteLength {
        expected: usize,
        actual: usize,
    },
    AuthenticatedShareSaltByteLength {
        expected: usize,
        actual: usize,
    },
    AuthenticatedShareCommitmentMismatch,
    AuthenticatedShareTagMismatch,
    AuthenticatedShareOpeningMagicMismatch,
    UnsupportedAuthenticatedShareOpeningVersion {
        version: u64,
    },
    TrailingAuthenticatedShareOpeningBytes,
    AuthenticatedShareVerificationKeyMagicMismatch,
    UnsupportedAuthenticatedShareVerificationKeyVersion {
        version: u64,
    },
    TrailingAuthenticatedShareVerificationKeyBytes,
    ReplicatedKeyArtifactMagicMismatch {
        artifact: &'static str,
    },
    UnsupportedReplicatedKeyArtifactVersion {
        artifact: &'static str,
        version: u64,
    },
    TrailingReplicatedKeyArtifactBytes {
        artifact: &'static str,
    },
    ReplicatedKeyFieldByteLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    ReplicatedKeyCoordinateMismatch,
    ReplicatedKeyPurposeOutOfRange,
    ReplicatedKeyContributorNotMember {
        contributor_position: u16,
    },
    ReplicatedKeyRecipientNotMember {
        recipient_position: u16,
    },
    ReplicatedKeySelfDelivery,
    ReplicatedKeyCommitmentMismatch,
    ReplicatedKeyInventoryMismatch,
    ReplicatedKeyAcknowledgementMismatch,
    AffineLabelPointBitMismatch,
    AffineLabelCommitmentsEqual {
        component_position: usize,
    },
    GarblingContributorPositionOutOfRange {
        contributor_position: u16,
        participant_count: u16,
    },
    GarblingInputPointBitMismatch {
        component_position: u16,
        input_side: &'static str,
    },
    GarblingOutputBasePointBitNonzero,
    GarblingLabelCommitmentMembershipMismatch {
        component_position: usize,
    },
    GarblingComponentPointBitMismatch {
        component_position: usize,
    },
    GarblingAuthenticatedRowValueNotBit,
    GarblingAuthenticatedRowBitMismatch,
    FieldElementByteLength {
        expected: usize,
        actual: usize,
    },
    LabelBodyByteLength {
        expected: usize,
        actual: usize,
    },
    WireLabelByteLength {
        expected: usize,
        actual: usize,
    },
    LabelBodyPaddingNonzero,
    NonCanonicalPointBit {
        value: u8,
    },
    GarblingOutputComponentCountMismatch {
        expected: usize,
        actual: usize,
    },
    GarblingOutputByteLength {
        expected: usize,
        actual: usize,
    },
    GarblingOutputPaddingNonzero,
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
    LabelShareArtifactMagicMismatch,
    UnsupportedLabelShareArtifactVersion {
        version: u64,
    },
    TrailingLabelShareArtifactBytes,
    GeometryMismatch,
    ArithmeticOverflow,
    WireIndexOutOfRange {
        wire_index: u32,
        wire_count: usize,
    },
    RandomTapeParticipantCountMismatch {
        expected: usize,
        actual: usize,
    },
    RandomTapeByteLengthMismatch {
        participant_position: usize,
        expected: usize,
        actual: usize,
    },
    RandomSeedCountMismatch {
        expected: usize,
        actual: usize,
    },
    RandomSourceByteLengthMismatch {
        expected: usize,
        actual: usize,
    },
    RandomTapeExhausted,
    RandomTapeNotFullyConsumed {
        expected: usize,
        consumed: usize,
    },
    IntegerConversion,
    TallyCircuit(TallyCircuitError),
    CanonicalEncoding(CanonicalError),
    FoundationCanonicalEncoding(CanonicalCodecError),
}

impl fmt::Display for TallyPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticatedShareContextEmpty => {
                formatter.write_str("authenticated share context must not be empty")
            }
            Self::AuthenticatedShareCoordinateEmpty => {
                formatter.write_str("authenticated share coordinate must not be empty")
            }
            Self::AuthenticatedShareValueLimbCount { actual } => write!(
                formatter,
                "authenticated share value has {actual} limbs; expected one or three"
            ),
            Self::AuthenticatedShareVerificationKeyLimbCountMismatch { expected, actual } => {
                write!(
                    formatter,
                    "authenticated share verification key has {actual} coefficients; expected {expected}"
                )
            }
            Self::SubmittedParticipantCountOutOfRange {
                submitted_participant_count,
                participant_count,
            } => write!(
                formatter,
                "received candidate packages from {submitted_participant_count} participants for a roster of {participant_count}"
            ),
            Self::AuthenticatedShareCommitmentByteLength { expected, actual } => write!(
                formatter,
                "authenticated share commitment has {actual} bytes; expected {expected}"
            ),
            Self::AuthenticatedShareSaltByteLength { expected, actual } => write!(
                formatter,
                "authenticated share salt has {actual} bytes; expected {expected}"
            ),
            Self::AuthenticatedShareCommitmentMismatch => {
                formatter.write_str("authenticated share commitment does not match")
            }
            Self::AuthenticatedShareTagMismatch => {
                formatter.write_str("authenticated share tag does not match")
            }
            Self::AuthenticatedShareOpeningMagicMismatch => {
                formatter.write_str("authenticated share opening artifact magic does not match")
            }
            Self::UnsupportedAuthenticatedShareOpeningVersion { version } => write!(
                formatter,
                "unsupported authenticated share opening artifact version {version}"
            ),
            Self::TrailingAuthenticatedShareOpeningBytes => {
                formatter.write_str("authenticated share opening artifact has trailing bytes")
            }
            Self::AuthenticatedShareVerificationKeyMagicMismatch => formatter
                .write_str("authenticated share verification key artifact magic does not match"),
            Self::UnsupportedAuthenticatedShareVerificationKeyVersion { version } => write!(
                formatter,
                "unsupported authenticated share verification key artifact version {version}"
            ),
            Self::TrailingAuthenticatedShareVerificationKeyBytes => formatter
                .write_str("authenticated share verification key artifact has trailing bytes"),
            Self::ReplicatedKeyArtifactMagicMismatch { artifact } => {
                write!(formatter, "replicated-key {artifact} magic does not match")
            }
            Self::UnsupportedReplicatedKeyArtifactVersion { artifact, version } => write!(
                formatter,
                "unsupported replicated-key {artifact} version {version}"
            ),
            Self::TrailingReplicatedKeyArtifactBytes { artifact } => write!(
                formatter,
                "replicated-key {artifact} artifact has trailing bytes"
            ),
            Self::ReplicatedKeyFieldByteLength {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "replicated-key {field} has {actual} bytes; expected {expected}"
            ),
            Self::ReplicatedKeyCoordinateMismatch => {
                formatter.write_str("replicated-key coordinate does not match")
            }
            Self::ReplicatedKeyPurposeOutOfRange => {
                formatter.write_str("replicated-key purpose is outside the roster geometry")
            }
            Self::ReplicatedKeyContributorNotMember {
                contributor_position,
            } => write!(
                formatter,
                "replicated-key contributor {contributor_position} is not a member of the authorized subset"
            ),
            Self::ReplicatedKeyRecipientNotMember { recipient_position } => write!(
                formatter,
                "replicated-key recipient {recipient_position} is not a member of the authorized subset"
            ),
            Self::ReplicatedKeySelfDelivery => formatter
                .write_str("replicated-key component delivery cannot target its contributor"),
            Self::ReplicatedKeyCommitmentMismatch => {
                formatter.write_str("replicated-key component commitment does not match")
            }
            Self::ReplicatedKeyInventoryMismatch => {
                formatter.write_str("replicated-key inventory does not match the canonical roster")
            }
            Self::ReplicatedKeyAcknowledgementMismatch => {
                formatter.write_str("replicated-key delivery acknowledgement does not match")
            }
            Self::AffineLabelPointBitMismatch => formatter
                .write_str("affine label alternatives must have canonical zero and one point bits"),
            Self::AffineLabelCommitmentsEqual { component_position } => write!(
                formatter,
                "affine label commitments are equal at component {component_position}"
            ),
            Self::GarblingContributorPositionOutOfRange {
                contributor_position,
                participant_count,
            } => write!(
                formatter,
                "garbling contributor position {contributor_position} is outside participant count {participant_count}"
            ),
            Self::GarblingInputPointBitMismatch {
                component_position,
                input_side,
            } => write!(
                formatter,
                "garbling {input_side} input label at component {component_position} has the wrong point bit"
            ),
            Self::GarblingOutputBasePointBitNonzero => {
                formatter.write_str("garbling output base label has a nonzero point bit")
            }
            Self::GarblingLabelCommitmentMembershipMismatch { component_position } => write!(
                formatter,
                "garbling output component {component_position} does not have exactly one matching affine label commitment"
            ),
            Self::GarblingComponentPointBitMismatch { component_position } => write!(
                formatter,
                "garbling output component {component_position} has an inconsistent point bit"
            ),
            Self::GarblingAuthenticatedRowValueNotBit => {
                formatter.write_str("authenticated garbling row value is not a canonical bit")
            }
            Self::GarblingAuthenticatedRowBitMismatch => formatter.write_str(
                "authenticated garbling row bit does not match the evaluated output point bit",
            ),
            Self::FieldElementByteLength { expected, actual } => write!(
                formatter,
                "binary field element has {actual} bytes; expected {expected}"
            ),
            Self::LabelBodyByteLength { expected, actual } => write!(
                formatter,
                "label body has {actual} bytes; expected {expected}"
            ),
            Self::WireLabelByteLength { expected, actual } => write!(
                formatter,
                "wire label has {actual} bytes; expected {expected}"
            ),
            Self::LabelBodyPaddingNonzero => formatter.write_str(
                "the reconstructed label body has nonzero high padding in its third field limb",
            ),
            Self::NonCanonicalPointBit { value } => {
                write!(formatter, "point bit encoding {value} is not zero or one")
            }
            Self::GarblingOutputComponentCountMismatch { expected, actual } => write!(
                formatter,
                "garbling output has {actual} label components; expected {expected}"
            ),
            Self::GarblingOutputByteLength { expected, actual } => write!(
                formatter,
                "garbling output has {actual} bytes; expected {expected}"
            ),
            Self::GarblingOutputPaddingNonzero => formatter
                .write_str("garbling output has nonzero unused high bits in its final byte"),
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
            Self::LabelShareArtifactMagicMismatch => {
                formatter.write_str("degree-three label share artifact magic does not match")
            }
            Self::UnsupportedLabelShareArtifactVersion { version } => write!(
                formatter,
                "unsupported degree-three label share artifact version {version}"
            ),
            Self::TrailingLabelShareArtifactBytes => {
                formatter.write_str("degree-three label share artifact has trailing bytes")
            }
            Self::GeometryMismatch => formatter
                .write_str("tally preparation geometry does not match the compiled circuit"),
            Self::ArithmeticOverflow => {
                formatter.write_str("tally preparation arithmetic overflow")
            }
            Self::WireIndexOutOfRange {
                wire_index,
                wire_count,
            } => write!(
                formatter,
                "wire {wire_index} is outside the preparation wire count {wire_count}"
            ),
            Self::RandomTapeParticipantCountMismatch { expected, actual } => write!(
                formatter,
                "received {actual} explicit random tapes; expected {expected}"
            ),
            Self::RandomTapeByteLengthMismatch {
                participant_position,
                expected,
                actual,
            } => write!(
                formatter,
                "explicit random tape for participant {participant_position} has {actual} bytes; expected {expected}"
            ),
            Self::RandomSeedCountMismatch { expected, actual } => write!(
                formatter,
                "received {actual} random tape seeds; expected {expected}"
            ),
            Self::RandomSourceByteLengthMismatch { expected, actual } => write!(
                formatter,
                "random source exposes {actual} bytes; preparation geometry requires {expected}"
            ),
            Self::RandomTapeExhausted => {
                formatter.write_str("random tape ended before the requested output")
            }
            Self::RandomTapeNotFullyConsumed { expected, consumed } => write!(
                formatter,
                "random tape consumed {consumed} of {expected} required bytes"
            ),
            Self::IntegerConversion => {
                formatter.write_str("tally preparation integer conversion failed")
            }
            Self::TallyCircuit(error) => error.fmt(formatter),
            Self::CanonicalEncoding(error) => error.fmt(formatter),
            Self::FoundationCanonicalEncoding(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TallyPreparationError {}

impl From<CanonicalError> for TallyPreparationError {
    fn from(error: CanonicalError) -> Self {
        Self::CanonicalEncoding(error)
    }
}

impl From<TallyCircuitError> for TallyPreparationError {
    fn from(error: TallyCircuitError) -> Self {
        Self::TallyCircuit(error)
    }
}

impl From<CanonicalCodecError> for TallyPreparationError {
    fn from(error: CanonicalCodecError) -> Self {
        Self::FoundationCanonicalEncoding(error)
    }
}
