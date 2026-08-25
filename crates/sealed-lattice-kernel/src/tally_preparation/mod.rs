//! Unactivated preparation functionality for the deterministic tally circuit.
//!
//! This module currently owns only the independently checked binary field and
//! degree-three mask sharing used by the candidate preparation functionality.
//! It does not select a preparation protocol, mint a capability, or activate a
//! suite.

mod adaptive_oracle_repair;
mod amortized_binary_mpc_communication_floor;
mod authenticated_key_release;
mod authenticated_key_release_resource_floor;
mod authenticated_key_share_vector;
mod authenticated_key_share_vector_codeword_check;
mod authenticated_key_share_vector_codeword_check_resource_floor;
mod authenticated_key_share_vector_codeword_manifest;
mod authenticated_key_share_vector_local_check;
mod authenticated_key_share_vector_local_check_resource_floor;
mod authenticated_key_share_vector_manifest;
mod authenticated_opening;
mod binary_field;
mod binary_field_multiplication_circuit;
mod binary_linear_circuit;
mod binary_ring_packed_mpc_evaluation_floor;
mod context;
mod degree_three_opening_decoder;
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
mod preparation_holder_record_catalog;
mod preparation_multiplication_catalog;
mod random_state;
mod random_tape;
mod replicated_key_ceremony;
mod replicated_key_ceremony_resource_model;
mod replicated_random_bit_catalog;
mod replicated_random_bit_resource_model;
mod replicated_random_bit_sharing;
mod replicated_random_bit_stream;
mod replicated_random_sharing;
mod replicated_sharing_field_stream;
mod replicated_sharing_simulator_basis;
mod replicated_sharing_stream_resource_model;
mod tower_field_multiplication_circuit;

#[cfg(test)]
mod adaptive_oracle_repair_tests;
#[cfg(test)]
mod amortized_binary_mpc_communication_floor_tests;
#[cfg(test)]
mod authenticated_key_release_resource_floor_tests;
#[cfg(test)]
mod authenticated_key_release_tests;
#[cfg(test)]
mod authenticated_key_share_vector_codeword_check_resource_floor_tests;
#[cfg(test)]
mod authenticated_key_share_vector_codeword_check_tests;
#[cfg(test)]
mod authenticated_key_share_vector_codeword_manifest_tests;
#[cfg(test)]
mod authenticated_key_share_vector_local_check_resource_floor_tests;
#[cfg(test)]
mod authenticated_key_share_vector_local_check_tests;
#[cfg(test)]
mod authenticated_key_share_vector_manifest_tests;
#[cfg(test)]
mod authenticated_key_share_vector_tests;
#[cfg(test)]
mod authenticated_opening_tests;
#[cfg(test)]
mod binary_field_multiplication_circuit_tests;
#[cfg(test)]
mod binary_linear_circuit_tests;
#[cfg(test)]
mod binary_ring_packed_mpc_evaluation_floor_tests;
#[cfg(test)]
mod degree_three_opening_decoder_tests;
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
mod preparation_holder_record_catalog_tests;
#[cfg(test)]
mod preparation_multiplication_catalog_tests;
#[cfg(test)]
mod randomness_tests;
#[cfg(test)]
mod replicated_key_ceremony_resource_model_tests;
#[cfg(test)]
mod replicated_key_ceremony_tests;
#[cfg(test)]
mod replicated_random_bit_resource_model_tests;
#[cfg(test)]
mod replicated_random_bit_tests;
#[cfg(test)]
mod replicated_random_sharing_tests;
#[cfg(test)]
mod replicated_sharing_field_stream_tests;
#[cfg(test)]
mod replicated_sharing_simulator_basis_tests;
#[cfg(test)]
mod replicated_sharing_stream_resource_model_tests;
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
    ReplicatedSharingFieldPurposeMismatch,
    ReplicatedSharingFieldCountZero,
    ReplicatedSharingFieldChunkOutOfRange {
        chunk_index: u64,
        chunk_count: u64,
    },
    ReplicatedSharingFieldPositionOutOfRange {
        position_within_chunk: u64,
        field_count: u64,
    },
    ReplicatedRandomBitCountZero,
    ReplicatedRandomBitChunkOutOfRange {
        chunk_index: u64,
        chunk_count: u64,
    },
    ReplicatedRandomBitPositionOutOfRange {
        position_within_chunk: u64,
        bit_count: u64,
    },
    ReplicatedRandomBitIndexOutOfRange {
        bit_index: u64,
        total_bit_count: u64,
    },
    ReplicatedRandomBitCoordinateMismatch,
    ReplicatedRandomBitKeyPurposeMismatch,
    ReplicatedRandomBitComponentCountMismatch {
        expected: usize,
        actual: usize,
    },
    ReplicatedRandomBitComponentNonCanonical {
        component_position: usize,
        value: u8,
    },
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
    DegreeThreeOpeningProfileMismatch {
        participant_count: u16,
        reconstruction_threshold: usize,
    },
    DegreeThreeOpeningDecodingFailure {
        maximum_inconsistent_share_count: usize,
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
    PreparationContextCircuitMismatch,
    PreparationMultiplicationIndexOutOfRange {
        operation_index: u64,
        operation_count: u64,
    },
    PreparationHolderRecordIndexOutOfRange {
        record_index: u64,
        record_count: u64,
    },
    AuthenticatedKeyReleaseBasisCountMismatch {
        expected: usize,
        actual: usize,
    },
    AuthenticatedKeyReleaseBasisPositionMismatch {
        basis_position: usize,
        expected_roster_position: u16,
        actual_roster_position: u16,
    },
    AuthenticatedKeyReleaseProfileMismatch {
        participant_count: u16,
        derived_reconstruction_threshold: u16,
        supported_reconstruction_threshold: u16,
    },
    AuthenticatedKeyShareVectorArtifactMagicMismatch,
    UnsupportedAuthenticatedKeyShareVectorArtifactVersion {
        version: u64,
    },
    TrailingAuthenticatedKeyShareVectorArtifactBytes,
    AuthenticatedKeyShareVectorHashByteLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    AuthenticatedKeyShareVectorDescriptorByteLengthOutOfRange {
        actual: usize,
        maximum: usize,
    },
    AuthenticatedKeyShareVectorSourceMismatch,
    AuthenticatedKeyShareVectorSenderPositionOutOfRange {
        sender_position: u16,
        participant_count: u16,
    },
    AuthenticatedKeyShareVectorGeometryMismatch,
    AuthenticatedKeyShareVectorChunkOutOfRange {
        chunk_index: u64,
        chunk_count: u64,
    },
    AuthenticatedKeyShareVectorPayloadByteLengthMismatch {
        expected: u64,
        actual: u64,
    },
    AuthenticatedKeyShareVectorPayloadDigestMismatch,
    AuthenticatedKeyShareVectorIncomplete {
        expected_chunk_count: u64,
        actual_chunk_count: u64,
    },
    AuthenticatedKeyShareVectorFieldPositionOutOfRange {
        position_within_chunk: u64,
        field_count: u64,
    },
    AuthenticatedKeyShareVectorManifestMagicMismatch,
    UnsupportedAuthenticatedKeyShareVectorManifestVersion {
        version: u64,
    },
    TrailingAuthenticatedKeyShareVectorManifestBytes,
    AuthenticatedKeyShareVectorManifestDescriptorCountMismatch {
        expected: usize,
        actual: usize,
    },
    AuthenticatedKeyShareVectorManifestMismatch,
    AuthenticatedKeyShareVectorCodewordManifestMagicMismatch,
    UnsupportedAuthenticatedKeyShareVectorCodewordManifestVersion {
        version: u64,
    },
    TrailingAuthenticatedKeyShareVectorCodewordManifestBytes,
    AuthenticatedKeyShareVectorCodewordManifestDescriptorCountMismatch {
        expected: usize,
        actual: usize,
    },
    AuthenticatedKeyShareVectorCodewordManifestMismatch,
    AuthenticatedKeyShareVectorAcknowledgementMagicMismatch,
    UnsupportedAuthenticatedKeyShareVectorAcknowledgementVersion {
        version: u64,
    },
    TrailingAuthenticatedKeyShareVectorAcknowledgementBytes,
    AuthenticatedKeyShareVectorAcknowledgementMismatch,
    AuthenticatedKeyShareVectorAcknowledgementCountMismatch {
        expected: usize,
        actual: usize,
    },
    AuthenticatedKeyShareVectorControlByteLengthOutOfRange {
        actual: usize,
        maximum: usize,
    },
    AuthenticatedKeyShareVectorLocalDescriptorMismatch,
    AuthenticatedKeyShareVectorLocalCheckAlreadyComplete,
    AuthenticatedKeyShareVectorLocalPayloadPresenceMismatch {
        basis_position: u16,
        expected: bool,
        actual: bool,
    },
    AuthenticatedKeyShareVectorLocalPayloadOutOfSequence {
        absorbed_basis_count: usize,
    },
    AuthenticatedKeyShareVectorLocalCheckFailed,
    AuthenticatedKeyShareVectorLocalCheckIncomplete {
        expected_chunk_count: u64,
        checked_chunk_count: u64,
        expected_field_count: u64,
        checked_field_count: u64,
        absorbed_basis_count: usize,
    },
    AuthenticatedKeyShareVectorCodewordCheckAlreadyComplete,
    AuthenticatedKeyShareVectorCodewordChunkAwaitingFinalization,
    AuthenticatedKeyShareVectorCodewordChunkIncomplete {
        expected_sender_count: u16,
        absorbed_sender_count: u16,
    },
    AuthenticatedKeyShareVectorCodewordCheckFailed,
    AuthenticatedKeyShareVectorCodewordCheckIncomplete {
        expected_chunk_count: u64,
        checked_chunk_count: u64,
        expected_field_count: u64,
        checked_field_count: u64,
        absorbed_sender_count: u16,
    },
    NonCanonicalPreparationSourceEncoding,
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
            Self::ReplicatedSharingFieldPurposeMismatch => formatter
                .write_str("replicated-sharing field stream purpose does not match its key"),
            Self::ReplicatedSharingFieldCountZero => {
                formatter.write_str("replicated-sharing field stream must contain a field element")
            }
            Self::ReplicatedSharingFieldChunkOutOfRange {
                chunk_index,
                chunk_count,
            } => write!(
                formatter,
                "replicated-sharing field chunk {chunk_index} is outside chunk count {chunk_count}"
            ),
            Self::ReplicatedSharingFieldPositionOutOfRange {
                position_within_chunk,
                field_count,
            } => write!(
                formatter,
                "replicated-sharing field position {position_within_chunk} is outside chunk field count {field_count}"
            ),
            Self::ReplicatedRandomBitCountZero => {
                formatter.write_str("replicated random-bit stream must contain a bit")
            }
            Self::ReplicatedRandomBitChunkOutOfRange {
                chunk_index,
                chunk_count,
            } => write!(
                formatter,
                "replicated random-bit chunk {chunk_index} is outside chunk count {chunk_count}"
            ),
            Self::ReplicatedRandomBitPositionOutOfRange {
                position_within_chunk,
                bit_count,
            } => write!(
                formatter,
                "replicated random-bit position {position_within_chunk} is outside chunk bit count {bit_count}"
            ),
            Self::ReplicatedRandomBitIndexOutOfRange {
                bit_index,
                total_bit_count,
            } => write!(
                formatter,
                "replicated random-bit index {bit_index} is outside catalog bit count {total_bit_count}"
            ),
            Self::ReplicatedRandomBitCoordinateMismatch => {
                formatter.write_str("replicated random-bit coordinate is outside its catalog")
            }
            Self::ReplicatedRandomBitKeyPurposeMismatch => {
                formatter.write_str("replicated random-bit stream requires a random-sharing key")
            }
            Self::ReplicatedRandomBitComponentCountMismatch { expected, actual } => write!(
                formatter,
                "replicated random-bit share received {actual} subset components; expected {expected}"
            ),
            Self::ReplicatedRandomBitComponentNonCanonical {
                component_position,
                value,
            } => write!(
                formatter,
                "replicated random-bit component {component_position} has non-bit value {value}"
            ),
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
            Self::DegreeThreeOpeningProfileMismatch {
                participant_count,
                reconstruction_threshold,
            } => write!(
                formatter,
                "participant count {participant_count} has reconstruction threshold {reconstruction_threshold} and cannot uniquely correct its active-fault bound for a degree-three opening"
            ),
            Self::DegreeThreeOpeningDecodingFailure {
                maximum_inconsistent_share_count,
            } => write!(
                formatter,
                "degree-three opening does not have a polynomial within {maximum_inconsistent_share_count} inconsistent shares"
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
            Self::PreparationContextCircuitMismatch => formatter
                .write_str("preparation context does not match the compiled tally circuit"),
            Self::PreparationMultiplicationIndexOutOfRange {
                operation_index,
                operation_count,
            } => write!(
                formatter,
                "preparation multiplication index {operation_index} is outside operation count {operation_count}"
            ),
            Self::PreparationHolderRecordIndexOutOfRange {
                record_index,
                record_count,
            } => write!(
                formatter,
                "preparation holder-record index {record_index} is outside record count {record_count}"
            ),
            Self::AuthenticatedKeyReleaseBasisCountMismatch { expected, actual } => write!(
                formatter,
                "authenticated-key release received {actual} basis shares; expected {expected}"
            ),
            Self::AuthenticatedKeyReleaseBasisPositionMismatch {
                basis_position,
                expected_roster_position,
                actual_roster_position,
            } => write!(
                formatter,
                "authenticated-key release basis position {basis_position} contains roster position {actual_roster_position}; expected {expected_roster_position}"
            ),
            Self::AuthenticatedKeyReleaseProfileMismatch {
                participant_count,
                derived_reconstruction_threshold,
                supported_reconstruction_threshold,
            } => write!(
                formatter,
                "authenticated-key release participant count {participant_count} derives reconstruction threshold {derived_reconstruction_threshold}; the degree-three checker requires {supported_reconstruction_threshold}"
            ),
            Self::AuthenticatedKeyShareVectorArtifactMagicMismatch => formatter
                .write_str("authenticated-key share-vector descriptor magic does not match"),
            Self::UnsupportedAuthenticatedKeyShareVectorArtifactVersion { version } => write!(
                formatter,
                "unsupported authenticated-key share-vector artifact version {version}"
            ),
            Self::TrailingAuthenticatedKeyShareVectorArtifactBytes => formatter
                .write_str("authenticated-key share-vector descriptor has trailing bytes"),
            Self::AuthenticatedKeyShareVectorHashByteLength {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "authenticated-key share-vector {field} has {actual} bytes; expected {expected}"
            ),
            Self::AuthenticatedKeyShareVectorDescriptorByteLengthOutOfRange {
                actual,
                maximum,
            } => write!(
                formatter,
                "authenticated-key share-vector descriptor has {actual} bytes; maximum is {maximum}"
            ),
            Self::AuthenticatedKeyShareVectorSourceMismatch => formatter
                .write_str("authenticated-key share-vector source binding does not match"),
            Self::AuthenticatedKeyShareVectorSenderPositionOutOfRange {
                sender_position,
                participant_count,
            } => write!(
                formatter,
                "authenticated-key share-vector sender {sender_position} is outside participant count {participant_count}"
            ),
            Self::AuthenticatedKeyShareVectorGeometryMismatch => formatter
                .write_str("authenticated-key share-vector geometry does not match"),
            Self::AuthenticatedKeyShareVectorChunkOutOfRange {
                chunk_index,
                chunk_count,
            } => write!(
                formatter,
                "authenticated-key share-vector chunk {chunk_index} is outside chunk count {chunk_count}"
            ),
            Self::AuthenticatedKeyShareVectorPayloadByteLengthMismatch { expected, actual } => {
                write!(
                    formatter,
                    "authenticated-key share-vector payload has {actual} bytes; expected {expected}"
                )
            }
            Self::AuthenticatedKeyShareVectorPayloadDigestMismatch => formatter
                .write_str("authenticated-key share-vector payload digest does not match"),
            Self::AuthenticatedKeyShareVectorIncomplete {
                expected_chunk_count,
                actual_chunk_count,
            } => write!(
                formatter,
                "authenticated-key share-vector has {actual_chunk_count} payload chunks; expected {expected_chunk_count}"
            ),
            Self::AuthenticatedKeyShareVectorFieldPositionOutOfRange {
                position_within_chunk,
                field_count,
            } => write!(
                formatter,
                "authenticated-key share-vector field position {position_within_chunk} is outside chunk field count {field_count}"
            ),
            Self::AuthenticatedKeyShareVectorManifestMagicMismatch => formatter
                .write_str("authenticated-key share-vector manifest magic does not match"),
            Self::UnsupportedAuthenticatedKeyShareVectorManifestVersion { version } => write!(
                formatter,
                "unsupported authenticated-key share-vector manifest version {version}"
            ),
            Self::TrailingAuthenticatedKeyShareVectorManifestBytes => formatter
                .write_str("authenticated-key share-vector manifest has trailing bytes"),
            Self::AuthenticatedKeyShareVectorManifestDescriptorCountMismatch {
                expected,
                actual,
            } => write!(
                formatter,
                "authenticated-key share-vector manifest has {actual} descriptors; expected {expected}"
            ),
            Self::AuthenticatedKeyShareVectorManifestMismatch => formatter
                .write_str("authenticated-key share-vector manifest does not match"),
            Self::AuthenticatedKeyShareVectorCodewordManifestMagicMismatch => formatter
                .write_str("authenticated-key share-vector codeword manifest magic does not match"),
            Self::UnsupportedAuthenticatedKeyShareVectorCodewordManifestVersion { version } => {
                write!(
                    formatter,
                    "unsupported authenticated-key share-vector codeword manifest version {version}"
                )
            }
            Self::TrailingAuthenticatedKeyShareVectorCodewordManifestBytes => formatter
                .write_str("authenticated-key share-vector codeword manifest has trailing bytes"),
            Self::AuthenticatedKeyShareVectorCodewordManifestDescriptorCountMismatch {
                expected,
                actual,
            } => write!(
                formatter,
                "authenticated-key share-vector codeword manifest has {actual} descriptors; expected {expected}"
            ),
            Self::AuthenticatedKeyShareVectorCodewordManifestMismatch => formatter
                .write_str("authenticated-key share-vector codeword manifest does not match"),
            Self::AuthenticatedKeyShareVectorAcknowledgementMagicMismatch => formatter
                .write_str("authenticated-key share-vector acknowledgement magic does not match"),
            Self::UnsupportedAuthenticatedKeyShareVectorAcknowledgementVersion { version } => {
                write!(
                    formatter,
                    "unsupported authenticated-key share-vector acknowledgement version {version}"
                )
            }
            Self::TrailingAuthenticatedKeyShareVectorAcknowledgementBytes => formatter
                .write_str("authenticated-key share-vector acknowledgement has trailing bytes"),
            Self::AuthenticatedKeyShareVectorAcknowledgementMismatch => formatter
                .write_str("authenticated-key share-vector acknowledgement does not match"),
            Self::AuthenticatedKeyShareVectorAcknowledgementCountMismatch { expected, actual } => {
                write!(
                    formatter,
                    "authenticated-key share-vector acknowledgement set has {actual} entries; expected {expected}"
                )
            }
            Self::AuthenticatedKeyShareVectorControlByteLengthOutOfRange { actual, maximum } => {
                write!(
                    formatter,
                    "authenticated-key share-vector control body has {actual} bytes; maximum is {maximum}"
                )
            }
            Self::AuthenticatedKeyShareVectorLocalDescriptorMismatch => formatter.write_str(
                "authenticated-key local share-vector descriptor does not match the participant",
            ),
            Self::AuthenticatedKeyShareVectorLocalCheckAlreadyComplete => formatter
                .write_str("authenticated-key local share-vector check is already complete"),
            Self::AuthenticatedKeyShareVectorLocalPayloadPresenceMismatch {
                basis_position,
                expected,
                actual,
            } => write!(
                formatter,
                "authenticated-key basis position {basis_position} local-payload presence is {actual}; expected {expected}"
            ),
            Self::AuthenticatedKeyShareVectorLocalPayloadOutOfSequence {
                absorbed_basis_count,
            } => write!(
                formatter,
                "authenticated-key local payload is out of sequence after {absorbed_basis_count} basis chunks"
            ),
            Self::AuthenticatedKeyShareVectorLocalCheckFailed => formatter
                .write_str("authenticated-key local share-vector check has already failed"),
            Self::AuthenticatedKeyShareVectorLocalCheckIncomplete {
                expected_chunk_count,
                checked_chunk_count,
                expected_field_count,
                checked_field_count,
                absorbed_basis_count,
            } => write!(
                formatter,
                "authenticated-key local share-vector check covered {checked_chunk_count} of {expected_chunk_count} chunks and {checked_field_count} of {expected_field_count} fields, with {absorbed_basis_count} basis chunks pending"
            ),
            Self::AuthenticatedKeyShareVectorCodewordCheckAlreadyComplete => formatter
                .write_str("authenticated-key share-vector codeword check is already complete"),
            Self::AuthenticatedKeyShareVectorCodewordChunkAwaitingFinalization => formatter
                .write_str("authenticated-key share-vector codeword chunk is awaiting finalization"),
            Self::AuthenticatedKeyShareVectorCodewordChunkIncomplete {
                expected_sender_count,
                absorbed_sender_count,
            } => write!(
                formatter,
                "authenticated-key share-vector codeword chunk has {absorbed_sender_count} senders; expected {expected_sender_count}"
            ),
            Self::AuthenticatedKeyShareVectorCodewordCheckFailed => formatter
                .write_str("authenticated-key share-vector codeword check has already failed"),
            Self::AuthenticatedKeyShareVectorCodewordCheckIncomplete {
                expected_chunk_count,
                checked_chunk_count,
                expected_field_count,
                checked_field_count,
                absorbed_sender_count,
            } => write!(
                formatter,
                "authenticated-key share-vector codeword check covered {checked_chunk_count} of {expected_chunk_count} chunks and {checked_field_count} of {expected_field_count} fields, with {absorbed_sender_count} sender payloads pending"
            ),
            Self::NonCanonicalPreparationSourceEncoding => formatter.write_str(
                "preparation compiler source identity requires canonical UTF-8 with LF line endings",
            ),
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
