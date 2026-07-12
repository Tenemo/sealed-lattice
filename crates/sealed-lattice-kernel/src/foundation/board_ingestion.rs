use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::{
    CanonicalCodecError, CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem,
    CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE, FoundationObjectType, Hash512,
    OBJECT_ENVELOPE_SCHEMA_IDENTIFIER, ObjectEnvelope, ParticipantIdentity, RefusalReason, Roster,
    SIGNED_CARRIER_SCHEMA_IDENTIFIER, SignedCarrier, StateCapabilityKind, StateOutputIntentPayload,
    StateRecoveryTransitionPayload, StateReservationIntentPayload, StateWitnessVoteKind,
    StateWitnessVotePayload, StorageRootCommitmentPayload, VerificationResult, derive_state_key,
    derive_state_recovery_producer_sequence, derive_state_witness_vote_sequence, hash512,
};

const FOUNDATION_PAYLOAD_VERSION: u16 = 1;

const PUBLIC_RANDOMNESS_COMMITMENT_SCHEMA_IDENTIFIER: u16 = 0x1201;
const PUBLIC_RANDOMNESS_REVEAL_SCHEMA_IDENTIFIER: u16 = 0x1202;
const PRIVATE_SHARE_ACCEPTANCE_SCHEMA_IDENTIFIER: u16 = 0x1203;
const COMPLAINT_SCHEMA_IDENTIFIER: u16 = 0x1204;
const PUBLIC_RANDOMNESS_LOCK_SCHEMA_IDENTIFIER: u16 = 0x1206;
const SETUP_INTENT_SCHEMA_IDENTIFIER: u16 = 0x1200;
const PUBLIC_SETUP_RECORD_SCHEMA_IDENTIFIER: u16 = 0x2100;
const BALLOT_PACKAGE_SCHEMA_IDENTIFIER: u16 = 0x1301;
const BALLOT_CANDIDATE_LIST_SCHEMA_IDENTIFIER: u16 = 0x1400;
const AGGREGATE_SCHEMA_IDENTIFIER: u16 = 0x1404;
const EVALUATOR_REPLAY_SCHEMA_IDENTIFIER: u16 = 0x1502;
const FINALITY_SIGNATURE_SCHEMA_IDENTIFIER: u16 = 0x1601;
const TARGET_DECRYPTION_SHARE_SCHEMA_IDENTIFIER: u16 = 0x1620;

const DEFAULT_MAXIMUM_FOUNDATION_CARRIER_COUNT: usize = 4_096;
const DEFAULT_MAXIMUM_RETAINED_FOUNDATION_CARRIER_BYTE_LENGTH: usize = 64 * 1024 * 1024;
const DEFAULT_MAXIMUM_UNRESOLVED_FOUNDATION_DEPENDENCY_COUNT: usize = 16_384;
const HARD_MAXIMUM_FOUNDATION_CARRIER_COUNT: usize = 65_536;
const HARD_MAXIMUM_RETAINED_FOUNDATION_CARRIER_BYTE_LENGTH: usize = 128 * 1024 * 1024;
const HARD_MAXIMUM_UNRESOLVED_FOUNDATION_DEPENDENCY_COUNT: usize = 65_536;

const EMPTY_ITEMS: &[CanonicalItemType] = &[];
const HASH_AND_HASH_LIST_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::Hash512,
    CanonicalItemType::HomogeneousList,
];
const PARTICIPANT_HASH_AND_BYTES_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::ParticipantIdentity,
    CanonicalItemType::Hash512,
    CanonicalItemType::RawBytes,
];
const HASH_HASH_LIST_AND_BYTES_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::Hash512,
    CanonicalItemType::HomogeneousList,
    CanonicalItemType::RawBytes,
];
const PARTICIPANT_HASH_AND_REASON_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::ParticipantIdentity,
    CanonicalItemType::Hash512,
    CanonicalItemType::Unsigned16,
];
const PUBLIC_SETUP_RECORD_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::Unsigned16,
    CanonicalItemType::HomogeneousList,
    CanonicalItemType::HomogeneousList,
    CanonicalItemType::HomogeneousList,
    CanonicalItemType::RawBytes,
];
const TWO_BYTES_ITEMS: &[CanonicalItemType] =
    &[CanonicalItemType::RawBytes, CanonicalItemType::RawBytes];
const HASH_AND_LIST_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::Hash512,
    CanonicalItemType::HomogeneousList,
];
const AGGREGATE_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::Hash512,
    CanonicalItemType::Hash512,
    CanonicalItemType::HomogeneousList,
    CanonicalItemType::RawBytes,
];
const EVALUATOR_REPLAY_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::Hash512,
    CanonicalItemType::Hash512,
    CanonicalItemType::RawBytes,
    CanonicalItemType::RawBytes,
];
const ONE_HASH_ITEM: &[CanonicalItemType] = &[CanonicalItemType::Hash512];
const STATE_RESERVATION_ITEMS: &[CanonicalItemType] =
    &[CanonicalItemType::Unsigned16, CanonicalItemType::Hash512];
const TWO_HASH_ITEMS: &[CanonicalItemType] =
    &[CanonicalItemType::Hash512, CanonicalItemType::Hash512];
const STATE_RECOVERY_ITEMS: &[CanonicalItemType] =
    &[CanonicalItemType::Unsigned16, CanonicalItemType::Optional];
const TARGET_DECRYPTION_SHARE_ITEMS: &[CanonicalItemType] = &[
    CanonicalItemType::Hash512,
    CanonicalItemType::Hash512,
    CanonicalItemType::RawBytes,
    CanonicalItemType::RawBytes,
    CanonicalItemType::RawBytes,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundationCarrierKind {
    SignedByRosterParticipant,
    UnsignedDeterministic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FoundationExternalPrerequisiteKind {
    PublicSetupSeed,
    SetupSourceAnchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundationPrerequisiteRule {
    None,
    RosterOrderedObjects {
        object_type: FoundationObjectType,
    },
    OneObject {
        object_type: FoundationObjectType,
    },
    OneExternal {
        prerequisite_kind: FoundationExternalPrerequisiteKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundationProducerSequenceRule {
    Any,
    Zero,
    RecoveryEpochPlusOne,
    DerivedStateWitnessVote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundationRecoveryRule {
    None,
    CurrentSubjectState,
    RecoveryTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundationProducerSlotRule {
    ProducerSequence,
    PublicRandomnessRevealSource,
    DeterministicActionObject,
    FixedStateCapability(StateCapabilityKind),
    StateReservationCapability,
    StateOutputReservation,
    StateWitnessIntent,
    StateRecoveryCapability,
    OnePerProducer,
}

/// The additional verifier that must run after canonical carrier ingestion.
///
/// This is a verifier-routing rule, not an outcome embedded in an artifact.
/// The ingestion engine never promotes one of these requirements into protocol
/// acceptance on the producer's assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundationObjectVerificationRequirement {
    CanonicalCarrierAuthentication,
    PublicRandomnessRelation,
    CommonProof,
    DeterministicRecomputation,
    StateAuthorization,
    StorageRootBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationEnvelopePolicy {
    pub object_type: FoundationObjectType,
    pub carrier_kind: FoundationCarrierKind,
    pub signature_purpose: Option<&'static str>,
    pub prerequisite_rule: FoundationPrerequisiteRule,
    pub producer_sequence_rule: FoundationProducerSequenceRule,
    pub recovery_rule: FoundationRecoveryRule,
    pub producer_slot_rule: FoundationProducerSlotRule,
    pub payload_schema_identifier: u16,
    pub payload_schema_version: u16,
    pub payload_item_types: &'static [CanonicalItemType],
    pub verification_requirement: FoundationObjectVerificationRequirement,
}

pub const FOUNDATION_ENVELOPE_POLICIES: [FoundationEnvelopePolicy; 18] = [
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::PublicRandomnessCommitment,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("public-randomness-commitment"),
        prerequisite_rule: FoundationPrerequisiteRule::RosterOrderedObjects {
            object_type: FoundationObjectType::SetupIntent,
        },
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::ProducerSequence,
        payload_schema_identifier: PUBLIC_RANDOMNESS_COMMITMENT_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: HASH_AND_HASH_LIST_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::PublicRandomnessRelation,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::PublicRandomnessReveal,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("public-randomness-reveal"),
        prerequisite_rule: FoundationPrerequisiteRule::RosterOrderedObjects {
            object_type: FoundationObjectType::PublicRandomnessLock,
        },
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::PublicRandomnessRevealSource,
        payload_schema_identifier: PUBLIC_RANDOMNESS_REVEAL_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: PARTICIPANT_HASH_AND_BYTES_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::PublicRandomnessRelation,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::PublicRandomnessLock,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("public-randomness-lock"),
        prerequisite_rule: FoundationPrerequisiteRule::RosterOrderedObjects {
            object_type: FoundationObjectType::PublicRandomnessCommitment,
        },
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::ProducerSequence,
        payload_schema_identifier: PUBLIC_RANDOMNESS_LOCK_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: EMPTY_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::PublicRandomnessRelation,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::SetupIntent,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("setup-intent"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::ProducerSequence,
        payload_schema_identifier: SETUP_INTENT_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: EMPTY_ITEMS,
        verification_requirement:
            FoundationObjectVerificationRequirement::CanonicalCarrierAuthentication,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::PrivateShareAcceptance,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("private-share-acceptance"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::ProducerSequence,
        payload_schema_identifier: PRIVATE_SHARE_ACCEPTANCE_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: HASH_HASH_LIST_AND_BYTES_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::CommonProof,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::Complaint,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("setup-complaint"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::ProducerSequence,
        payload_schema_identifier: COMPLAINT_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: PARTICIPANT_HASH_AND_REASON_ITEMS,
        verification_requirement:
            FoundationObjectVerificationRequirement::CanonicalCarrierAuthentication,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::PublicSetupRecord,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("dealer-public-setup"),
        prerequisite_rule: FoundationPrerequisiteRule::OneExternal {
            prerequisite_kind: FoundationExternalPrerequisiteKind::PublicSetupSeed,
        },
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::ProducerSequence,
        payload_schema_identifier: PUBLIC_SETUP_RECORD_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: PUBLIC_SETUP_RECORD_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::CommonProof,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::BallotPackage,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("direct-ballot"),
        prerequisite_rule: FoundationPrerequisiteRule::OneExternal {
            prerequisite_kind: FoundationExternalPrerequisiteKind::SetupSourceAnchor,
        },
        producer_sequence_rule: FoundationProducerSequenceRule::Any,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::ProducerSequence,
        payload_schema_identifier: BALLOT_PACKAGE_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: TWO_BYTES_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::CommonProof,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::BallotCandidateList,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("ballot-candidate-list"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::CurrentSubjectState,
        producer_slot_rule: FoundationProducerSlotRule::FixedStateCapability(
            StateCapabilityKind::BallotCandidateList,
        ),
        payload_schema_identifier: BALLOT_CANDIDATE_LIST_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: HASH_AND_LIST_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::StateAuthorization,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::Aggregate,
        carrier_kind: FoundationCarrierKind::UnsignedDeterministic,
        signature_purpose: None,
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::DeterministicActionObject,
        payload_schema_identifier: AGGREGATE_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: AGGREGATE_ITEMS,
        verification_requirement:
            FoundationObjectVerificationRequirement::DeterministicRecomputation,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::EvaluatorReplay,
        carrier_kind: FoundationCarrierKind::UnsignedDeterministic,
        signature_purpose: None,
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::DeterministicActionObject,
        payload_schema_identifier: EVALUATOR_REPLAY_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: EVALUATOR_REPLAY_ITEMS,
        verification_requirement:
            FoundationObjectVerificationRequirement::DeterministicRecomputation,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::FinalitySignature,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("target-finality"),
        prerequisite_rule: FoundationPrerequisiteRule::OneObject {
            object_type: FoundationObjectType::EvaluatorReplay,
        },
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::CurrentSubjectState,
        producer_slot_rule: FoundationProducerSlotRule::FixedStateCapability(
            StateCapabilityKind::FinalitySignature,
        ),
        payload_schema_identifier: FINALITY_SIGNATURE_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: ONE_HASH_ITEM,
        verification_requirement: FoundationObjectVerificationRequirement::StateAuthorization,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::StateReservation,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("state-reservation-intent"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::CurrentSubjectState,
        producer_slot_rule: FoundationProducerSlotRule::StateReservationCapability,
        payload_schema_identifier: super::STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: STATE_RESERVATION_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::StateAuthorization,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::StateOutputIntent,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("state-output-intent"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::CurrentSubjectState,
        producer_slot_rule: FoundationProducerSlotRule::StateOutputReservation,
        payload_schema_identifier: super::STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: TWO_HASH_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::StateAuthorization,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::StateWitnessVote,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("state-witness-vote"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::DerivedStateWitnessVote,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::StateWitnessIntent,
        payload_schema_identifier: super::STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: ONE_HASH_ITEM,
        verification_requirement: FoundationObjectVerificationRequirement::StateAuthorization,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::RecoveryTransition,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("state-recovery-transition"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::RecoveryEpochPlusOne,
        recovery_rule: FoundationRecoveryRule::RecoveryTransition,
        producer_slot_rule: FoundationProducerSlotRule::StateRecoveryCapability,
        payload_schema_identifier: super::STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: STATE_RECOVERY_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::StateAuthorization,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::TargetDecryptionShare,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("target-release-output"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::CurrentSubjectState,
        producer_slot_rule: FoundationProducerSlotRule::FixedStateCapability(
            StateCapabilityKind::TargetRelease,
        ),
        payload_schema_identifier: TARGET_DECRYPTION_SHARE_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: TARGET_DECRYPTION_SHARE_ITEMS,
        verification_requirement: FoundationObjectVerificationRequirement::CommonProof,
    },
    FoundationEnvelopePolicy {
        object_type: FoundationObjectType::StorageRootCommitment,
        carrier_kind: FoundationCarrierKind::SignedByRosterParticipant,
        signature_purpose: Some("storage-root-commitment"),
        prerequisite_rule: FoundationPrerequisiteRule::None,
        producer_sequence_rule: FoundationProducerSequenceRule::Zero,
        recovery_rule: FoundationRecoveryRule::None,
        producer_slot_rule: FoundationProducerSlotRule::OnePerProducer,
        payload_schema_identifier: super::STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
        payload_schema_version: FOUNDATION_PAYLOAD_VERSION,
        payload_item_types: ONE_HASH_ITEM,
        verification_requirement: FoundationObjectVerificationRequirement::StorageRootBinding,
    },
];

pub const fn foundation_envelope_policy(
    object_type: FoundationObjectType,
) -> &'static FoundationEnvelopePolicy {
    match object_type {
        FoundationObjectType::PublicRandomnessCommitment => &FOUNDATION_ENVELOPE_POLICIES[0],
        FoundationObjectType::PublicRandomnessReveal => &FOUNDATION_ENVELOPE_POLICIES[1],
        FoundationObjectType::PublicRandomnessLock => &FOUNDATION_ENVELOPE_POLICIES[2],
        FoundationObjectType::SetupIntent => &FOUNDATION_ENVELOPE_POLICIES[3],
        FoundationObjectType::PrivateShareAcceptance => &FOUNDATION_ENVELOPE_POLICIES[4],
        FoundationObjectType::Complaint => &FOUNDATION_ENVELOPE_POLICIES[5],
        FoundationObjectType::PublicSetupRecord => &FOUNDATION_ENVELOPE_POLICIES[6],
        FoundationObjectType::BallotPackage => &FOUNDATION_ENVELOPE_POLICIES[7],
        FoundationObjectType::BallotCandidateList => &FOUNDATION_ENVELOPE_POLICIES[8],
        FoundationObjectType::Aggregate => &FOUNDATION_ENVELOPE_POLICIES[9],
        FoundationObjectType::EvaluatorReplay => &FOUNDATION_ENVELOPE_POLICIES[10],
        FoundationObjectType::FinalitySignature => &FOUNDATION_ENVELOPE_POLICIES[11],
        FoundationObjectType::StateReservation => &FOUNDATION_ENVELOPE_POLICIES[12],
        FoundationObjectType::StateOutputIntent => &FOUNDATION_ENVELOPE_POLICIES[13],
        FoundationObjectType::StateWitnessVote => &FOUNDATION_ENVELOPE_POLICIES[14],
        FoundationObjectType::RecoveryTransition => &FOUNDATION_ENVELOPE_POLICIES[15],
        FoundationObjectType::TargetDecryptionShare => &FOUNDATION_ENVELOPE_POLICIES[16],
        FoundationObjectType::StorageRootCommitment => &FOUNDATION_ENVELOPE_POLICIES[17],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationBoardIngestionLimits {
    maximum_carrier_byte_length: usize,
    maximum_carrier_count: usize,
    maximum_retained_carrier_byte_length: usize,
    maximum_unresolved_dependency_count: usize,
}

impl Default for FoundationBoardIngestionLimits {
    fn default() -> Self {
        Self {
            maximum_carrier_byte_length: FOUNDATION_PROFILE.maximum_copied_buffer_byte_length,
            maximum_carrier_count: DEFAULT_MAXIMUM_FOUNDATION_CARRIER_COUNT,
            maximum_retained_carrier_byte_length:
                DEFAULT_MAXIMUM_RETAINED_FOUNDATION_CARRIER_BYTE_LENGTH,
            maximum_unresolved_dependency_count:
                DEFAULT_MAXIMUM_UNRESOLVED_FOUNDATION_DEPENDENCY_COUNT,
        }
    }
}

impl FoundationBoardIngestionLimits {
    pub fn try_new(
        maximum_carrier_byte_length: usize,
        maximum_carrier_count: usize,
        maximum_retained_carrier_byte_length: usize,
        maximum_unresolved_dependency_count: usize,
    ) -> Result<Self, RefusalReason> {
        if maximum_carrier_byte_length == 0
            || maximum_carrier_byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || maximum_carrier_count == 0
            || maximum_carrier_count > HARD_MAXIMUM_FOUNDATION_CARRIER_COUNT
            || maximum_retained_carrier_byte_length < maximum_carrier_byte_length
            || maximum_retained_carrier_byte_length
                > HARD_MAXIMUM_RETAINED_FOUNDATION_CARRIER_BYTE_LENGTH
            || maximum_unresolved_dependency_count == 0
            || maximum_unresolved_dependency_count
                > HARD_MAXIMUM_UNRESOLVED_FOUNDATION_DEPENDENCY_COUNT
        {
            return Err(RefusalReason::OutsideSupportedProfile);
        }
        Ok(Self {
            maximum_carrier_byte_length,
            maximum_carrier_count,
            maximum_retained_carrier_byte_length,
            maximum_unresolved_dependency_count,
        })
    }

    pub const fn maximum_carrier_byte_length(self) -> usize {
        self.maximum_carrier_byte_length
    }

    pub const fn maximum_carrier_count(self) -> usize {
        self.maximum_carrier_count
    }

    pub const fn maximum_retained_carrier_byte_length(self) -> usize {
        self.maximum_retained_carrier_byte_length
    }

    pub const fn maximum_unresolved_dependency_count(self) -> usize {
        self.maximum_unresolved_dependency_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundationExternalPrerequisite {
    pub prerequisite_kind: FoundationExternalPrerequisiteKind,
    pub object_hash: Hash512,
}

pub struct FoundationBoardIngestionContext<'roster, 'prerequisite> {
    pub suite_id: Hash512,
    pub ceremony_context_hash: Hash512,
    pub action_context_hash: Hash512,
    pub roster: &'roster Roster,
    pub external_prerequisites: &'prerequisite [FoundationExternalPrerequisite],
    pub limits: FoundationBoardIngestionLimits,
}

pub struct AuthenticatedCanonicalFoundationCarrier<'carrier> {
    object_hash: Hash512,
    policy: &'static FoundationEnvelopePolicy,
    envelope: &'carrier ObjectEnvelope,
    canonical_carrier_bytes: &'carrier [u8],
}

impl AuthenticatedCanonicalFoundationCarrier<'_> {
    pub const fn object_hash(&self) -> Hash512 {
        self.object_hash
    }

    pub const fn policy(&self) -> &'static FoundationEnvelopePolicy {
        self.policy
    }

    pub const fn envelope(&self) -> &ObjectEnvelope {
        self.envelope
    }

    pub const fn canonical_carrier_bytes(&self) -> &[u8] {
        self.canonical_carrier_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DependencyKey {
    Object([u8; Hash512::BYTE_LENGTH]),
    External(FoundationExternalPrerequisiteKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CarrierDependencyState {
    Waiting { missing_dependency_count: usize },
    Ready,
    Refused(RefusalReason),
}

impl CarrierDependencyState {
    const fn missing_dependency_count(self) -> usize {
        match self {
            Self::Waiting {
                missing_dependency_count,
            } => missing_dependency_count,
            Self::Ready | Self::Refused(_) => 0,
        }
    }
}

struct StoredCarrier {
    canonical_carrier_bytes: Vec<u8>,
    envelope: ObjectEnvelope,
    dependencies: BTreeSet<DependencyKey>,
    producer_slot: Option<[u8; Hash512::BYTE_LENGTH]>,
    dependency_state: CarrierDependencyState,
}

struct CandidateEvaluation {
    dependencies: BTreeSet<DependencyKey>,
    producer_slot: Option<[u8; Hash512::BYTE_LENGTH]>,
    dependency_state: CarrierDependencyState,
}

pub struct FoundationBoardIngestor {
    suite_id: Hash512,
    ceremony_context_hash: Hash512,
    action_context_hash: Hash512,
    roster: Roster,
    roster_identities: Vec<ParticipantIdentity>,
    canonical_decode_limits: CanonicalDecodeLimits,
    limits: FoundationBoardIngestionLimits,
    external_prerequisites:
        BTreeMap<FoundationExternalPrerequisiteKind, [u8; Hash512::BYTE_LENGTH]>,
    carriers: BTreeMap<[u8; Hash512::BYTE_LENGTH], StoredCarrier>,
    dependents: BTreeMap<DependencyKey, BTreeSet<[u8; Hash512::BYTE_LENGTH]>>,
    producer_slots: BTreeMap<[u8; Hash512::BYTE_LENGTH], BTreeSet<[u8; Hash512::BYTE_LENGTH]>>,
    retained_carrier_byte_length: usize,
    unresolved_dependency_count: usize,
}

impl FoundationBoardIngestor {
    pub fn new(context: FoundationBoardIngestionContext<'_, '_>) -> VerificationResult<Self> {
        let mut roster_identities = Vec::with_capacity(context.roster.entries.len());
        for roster_entry in &context.roster.entries {
            let participant_identity = match roster_entry.participant_identity() {
                Ok(participant_identity) => participant_identity,
                Err(error) => return VerificationResult::refused(error.refusal_reason),
            };
            roster_identities.push(participant_identity);
        }

        let mut external_prerequisites = BTreeMap::new();
        for prerequisite in context.external_prerequisites {
            let prerequisite_hash = prerequisite.object_hash.into_bytes();
            if let Some(existing_hash) =
                external_prerequisites.insert(prerequisite.prerequisite_kind, prerequisite_hash)
                && existing_hash != prerequisite_hash
            {
                return VerificationResult::refused(RefusalReason::Equivocation);
            }
        }

        let maximum_carrier_byte_length = context.limits.maximum_carrier_byte_length;
        let canonical_decode_limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: maximum_carrier_byte_length,
            maximum_item_byte_length: maximum_carrier_byte_length,
            maximum_cumulative_work_byte_length: maximum_carrier_byte_length.saturating_mul(4),
            maximum_cumulative_allocation_byte_length: maximum_carrier_byte_length
                .saturating_mul(3),
            ..CanonicalDecodeLimits::default()
        };

        VerificationResult::valid(Self {
            suite_id: context.suite_id,
            ceremony_context_hash: context.ceremony_context_hash,
            action_context_hash: context.action_context_hash,
            roster: context.roster.clone(),
            roster_identities,
            canonical_decode_limits,
            limits: context.limits,
            external_prerequisites,
            carriers: BTreeMap::new(),
            dependents: BTreeMap::new(),
            producer_slots: BTreeMap::new(),
            retained_carrier_byte_length: 0,
            unresolved_dependency_count: 0,
        })
    }

    /// Ingests only canonical carrier bytes. Relay metadata is deliberately not
    /// an input and cannot affect any hash, slot, prerequisite, or result.
    ///
    /// A valid return establishes canonical encoding, the closed envelope
    /// policy, an external-roster signature where required, complete carrier
    /// prerequisites, and absence of known equivocation. It is returned only
    /// for families whose registry entry requires no additional relation,
    /// proof, state, or storage verifier.
    pub fn ingest_canonical_carrier(
        &mut self,
        canonical_carrier_bytes: &[u8],
    ) -> VerificationResult<AuthenticatedCanonicalFoundationCarrier<'_>> {
        if canonical_carrier_bytes.is_empty() {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }
        if canonical_carrier_bytes.len() > self.limits.maximum_carrier_byte_length {
            return VerificationResult::refused(RefusalReason::OutsideSupportedProfile);
        }

        let envelope = match self.parse_and_authenticate_carrier(canonical_carrier_bytes) {
            Ok(envelope) => envelope,
            Err(refusal_reason) => return VerificationResult::refused(refusal_reason),
        };
        let object_hash = match envelope.object_hash() {
            Ok(object_hash) => object_hash,
            Err(error) => return VerificationResult::refused(error.refusal_reason),
        };
        let object_hash_bytes = object_hash.into_bytes();

        if let Some(existing) = self.carriers.get(&object_hash_bytes) {
            if existing.canonical_carrier_bytes != canonical_carrier_bytes {
                self.mark_equivocation(&[object_hash_bytes]);
                let mut reevaluation_queue = VecDeque::new();
                self.enqueue_dependents(
                    DependencyKey::Object(object_hash_bytes),
                    &mut reevaluation_queue,
                );
                self.reevaluate_queued_carriers(&mut reevaluation_queue);
                return VerificationResult::refused(RefusalReason::Equivocation);
            }
            return self.protocol_result(object_hash_bytes);
        }

        if self.carriers.len() >= self.limits.maximum_carrier_count {
            return VerificationResult::refused(RefusalReason::OutsideSupportedProfile);
        }
        let Some(updated_retained_byte_length) = self
            .retained_carrier_byte_length
            .checked_add(canonical_carrier_bytes.len())
        else {
            return VerificationResult::refused(RefusalReason::OutsideSupportedProfile);
        };
        if updated_retained_byte_length > self.limits.maximum_retained_carrier_byte_length {
            return VerificationResult::refused(RefusalReason::OutsideSupportedProfile);
        }

        let provisional = StoredCarrier {
            canonical_carrier_bytes: canonical_carrier_bytes.to_vec(),
            envelope,
            dependencies: BTreeSet::new(),
            producer_slot: None,
            dependency_state: CarrierDependencyState::Waiting {
                missing_dependency_count: 0,
            },
        };
        let evaluation = match self.evaluate_carrier(&provisional) {
            Ok(evaluation) => evaluation,
            Err(refusal_reason) => return VerificationResult::refused(refusal_reason),
        };
        let prospective_unresolved_count = self
            .unresolved_dependency_count
            .saturating_add(evaluation.dependency_state.missing_dependency_count());
        if prospective_unresolved_count > self.limits.maximum_unresolved_dependency_count {
            return VerificationResult::refused(RefusalReason::OutsideSupportedProfile);
        }

        let stored_carrier = StoredCarrier {
            dependencies: evaluation.dependencies,
            producer_slot: evaluation.producer_slot,
            dependency_state: evaluation.dependency_state,
            ..provisional
        };
        self.retained_carrier_byte_length = updated_retained_byte_length;
        self.unresolved_dependency_count = prospective_unresolved_count;
        self.carriers.insert(object_hash_bytes, stored_carrier);
        self.index_dependencies(object_hash_bytes);
        let equivocated_hashes = self.index_producer_slot(object_hash_bytes);

        let mut reevaluation_queue = VecDeque::new();
        for equivocated_hash in equivocated_hashes {
            self.enqueue_dependents(
                DependencyKey::Object(equivocated_hash),
                &mut reevaluation_queue,
            );
        }
        self.enqueue_dependents(
            DependencyKey::Object(object_hash_bytes),
            &mut reevaluation_queue,
        );
        self.reevaluate_queued_carriers(&mut reevaluation_queue);
        self.protocol_result(object_hash_bytes)
    }

    /// Returns a carrier candidate only after its canonical envelope, external
    /// roster signature, closed family rules, producer slot, and complete
    /// carrier prerequisite chain have been checked. This method intentionally
    /// does not claim family-specific proof or relation acceptance.
    pub fn authenticated_carrier_with_present_prerequisites(
        &self,
        object_hash: Hash512,
    ) -> VerificationResult<AuthenticatedCanonicalFoundationCarrier<'_>> {
        self.authenticated_carrier_result(object_hash.into_bytes())
    }

    pub fn register_external_prerequisite(
        &mut self,
        prerequisite: FoundationExternalPrerequisite,
    ) -> VerificationResult<()> {
        let prerequisite_hash = prerequisite.object_hash.into_bytes();
        if let Some(existing_hash) = self
            .external_prerequisites
            .get(&prerequisite.prerequisite_kind)
        {
            return if *existing_hash == prerequisite_hash {
                VerificationResult::valid(())
            } else {
                VerificationResult::refused(RefusalReason::Equivocation)
            };
        }
        self.external_prerequisites
            .insert(prerequisite.prerequisite_kind, prerequisite_hash);

        let mut reevaluation_queue = VecDeque::new();
        self.enqueue_dependents(
            DependencyKey::External(prerequisite.prerequisite_kind),
            &mut reevaluation_queue,
        );
        self.reevaluate_queued_carriers(&mut reevaluation_queue);
        VerificationResult::valid(())
    }

    pub fn require_complete_carrier_dependency_graph(&self) -> VerificationResult<()> {
        if self.unresolved_dependency_count != 0 {
            return VerificationResult::refused(RefusalReason::MissingPrerequisite);
        }
        for carrier in self.carriers.values() {
            if let CarrierDependencyState::Refused(refusal_reason) = carrier.dependency_state {
                return VerificationResult::refused(refusal_reason);
            }
        }
        VerificationResult::valid(())
    }

    pub fn stored_carrier_count(&self) -> usize {
        self.carriers.len()
    }

    pub const fn retained_carrier_byte_length(&self) -> usize {
        self.retained_carrier_byte_length
    }

    pub const fn unresolved_dependency_count(&self) -> usize {
        self.unresolved_dependency_count
    }

    fn parse_and_authenticate_carrier(
        &self,
        canonical_carrier_bytes: &[u8],
    ) -> Result<ObjectEnvelope, RefusalReason> {
        let outer_tuple =
            CanonicalTuple::decode(canonical_carrier_bytes, &self.canonical_decode_limits)
                .map_err(map_codec_error)?;
        let (envelope, carrier_kind) = match outer_tuple.schema_identifier {
            SIGNED_CARRIER_SCHEMA_IDENTIFIER => {
                let carrier =
                    SignedCarrier::decode(canonical_carrier_bytes, &self.canonical_decode_limits)
                        .map_err(|error| error.refusal_reason)?;
                carrier.verify_signature(&self.roster).into_result()?;
                (
                    carrier.envelope,
                    FoundationCarrierKind::SignedByRosterParticipant,
                )
            }
            OBJECT_ENVELOPE_SCHEMA_IDENTIFIER => (
                ObjectEnvelope::decode(canonical_carrier_bytes, &self.canonical_decode_limits)
                    .map_err(|error| error.refusal_reason)?,
                FoundationCarrierKind::UnsignedDeterministic,
            ),
            _ => return Err(RefusalReason::WrongTypeOrLength),
        };
        let policy = foundation_envelope_policy(envelope.object_type);
        if policy.carrier_kind != carrier_kind {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.validate_envelope_context_and_shape(&envelope, policy)?;
        let payload_tuple = self.validate_payload(&envelope, policy)?;
        self.validate_family_payload_bindings(&envelope, &payload_tuple)?;
        Ok(envelope)
    }

    fn validate_envelope_context_and_shape(
        &self,
        envelope: &ObjectEnvelope,
        policy: &FoundationEnvelopePolicy,
    ) -> Result<(), RefusalReason> {
        if envelope.suite_id != self.suite_id {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        if envelope.ceremony_context_hash != self.ceremony_context_hash
            || envelope.action_context_hash != self.action_context_hash
        {
            return Err(RefusalReason::WrongContext);
        }
        match policy.carrier_kind {
            FoundationCarrierKind::SignedByRosterParticipant => {
                let producer = envelope
                    .producer_participant_id
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                if !self.roster_identities.contains(&producer) {
                    return Err(RefusalReason::WrongContext);
                }
            }
            FoundationCarrierKind::UnsignedDeterministic => {
                if envelope.producer_participant_id.is_some() {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
        }
        match policy.recovery_rule {
            FoundationRecoveryRule::None => {
                if envelope.recovery_epoch != 0 || envelope.recovery_transition_hash.is_some() {
                    return Err(RefusalReason::WrongContext);
                }
            }
            FoundationRecoveryRule::CurrentSubjectState
            | FoundationRecoveryRule::RecoveryTransition => {
                if (envelope.recovery_epoch == 0) != envelope.recovery_transition_hash.is_none() {
                    return Err(RefusalReason::WrongContext);
                }
            }
        }
        match policy.producer_sequence_rule {
            FoundationProducerSequenceRule::Any
            | FoundationProducerSequenceRule::DerivedStateWitnessVote => {}
            FoundationProducerSequenceRule::Zero => {
                if envelope.producer_sequence != 0 {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
            FoundationProducerSequenceRule::RecoveryEpochPlusOne => {
                let expected_sequence =
                    derive_state_recovery_producer_sequence(envelope.recovery_epoch)
                        .map_err(|error| error.refusal_reason)?;
                if envelope.producer_sequence != expected_sequence {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
        }
        Ok(())
    }

    fn validate_payload(
        &self,
        envelope: &ObjectEnvelope,
        policy: &FoundationEnvelopePolicy,
    ) -> Result<CanonicalTuple, RefusalReason> {
        let tuple = CanonicalTuple::decode(&envelope.payload_bytes, &self.canonical_decode_limits)
            .map_err(map_codec_error)?;
        if tuple.schema_identifier != policy.payload_schema_identifier
            || tuple.schema_version != policy.payload_schema_version
            || tuple.items.len() != policy.payload_item_types.len()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        for (item, expected_type) in tuple.items.iter().zip(policy.payload_item_types) {
            if item.item_type() != *expected_type {
                return Err(RefusalReason::WrongTypeOrLength);
            }
        }
        Ok(tuple)
    }

    fn validate_family_payload_bindings(
        &self,
        envelope: &ObjectEnvelope,
        payload_tuple: &CanonicalTuple,
    ) -> Result<(), RefusalReason> {
        match envelope.object_type {
            FoundationObjectType::PublicRandomnessCommitment => {
                require_homogeneous_list_count_and_type(
                    &payload_tuple.items[1],
                    usize::from(FOUNDATION_PROFILE.participant_count),
                    CanonicalItemType::Hash512,
                )?;
            }
            FoundationObjectType::PublicRandomnessReveal => {
                let source_participant_id = read_participant_identity(&payload_tuple.items[0])?;
                if !self.roster_identities.contains(&source_participant_id)
                    || payload_tuple.items[2].canonical_bytes().len() != Hash512::BYTE_LENGTH
                {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
            FoundationObjectType::Complaint => {
                let accused_participant_id = read_participant_identity(&payload_tuple.items[0])?;
                if !self.roster_identities.contains(&accused_participant_id) {
                    return Err(RefusalReason::WrongContext);
                }
                let refusal_reason =
                    RefusalReason::try_from_canonical_code(read_u16(&payload_tuple.items[2])?)
                        .map_err(|_| RefusalReason::MalformedEncoding)?;
                if !matches!(
                    refusal_reason,
                    RefusalReason::MalformedEncoding
                        | RefusalReason::InvalidSignature
                        | RefusalReason::WrongContext
                        | RefusalReason::WrongHashOrRoot
                        | RefusalReason::InvalidProof
                        | RefusalReason::InvalidArithmeticRelation
                ) {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
            FoundationObjectType::PublicSetupRecord => {
                let dealer_roster_position = usize::from(read_u16(&payload_tuple.items[0])?);
                let expected_producer = self
                    .roster_identities
                    .get(dealer_roster_position)
                    .ok_or(RefusalReason::WrongTypeOrLength)?;
                if envelope.producer_participant_id.as_ref() != Some(expected_producer) {
                    return Err(RefusalReason::WrongContext);
                }
                require_homogeneous_list_count_and_type(
                    &payload_tuple.items[3],
                    usize::from(FOUNDATION_PROFILE.participant_count),
                    CanonicalItemType::Hash512,
                )?;
            }
            FoundationObjectType::Aggregate => {
                require_homogeneous_list_count_and_type(
                    &payload_tuple.items[2],
                    usize::from(FOUNDATION_PROFILE.participant_count),
                    CanonicalItemType::Hash512,
                )?;
            }
            FoundationObjectType::StateReservation => {
                StateReservationIntentPayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
            }
            FoundationObjectType::StateOutputIntent => {
                StateOutputIntentPayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
            }
            FoundationObjectType::StateWitnessVote => {
                StateWitnessVotePayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
            }
            FoundationObjectType::RecoveryTransition => {
                StateRecoveryTransitionPayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
            }
            FoundationObjectType::StorageRootCommitment => {
                StorageRootCommitmentPayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
            }
            FoundationObjectType::PublicRandomnessLock
            | FoundationObjectType::SetupIntent
            | FoundationObjectType::PrivateShareAcceptance
            | FoundationObjectType::BallotPackage
            | FoundationObjectType::BallotCandidateList
            | FoundationObjectType::EvaluatorReplay
            | FoundationObjectType::FinalitySignature
            | FoundationObjectType::TargetDecryptionShare => {}
        }
        Ok(())
    }

    fn evaluate_carrier(
        &self,
        carrier: &StoredCarrier,
    ) -> Result<CandidateEvaluation, RefusalReason> {
        let policy = foundation_envelope_policy(carrier.envelope.object_type);
        let mut dependencies = BTreeSet::new();
        let mut missing_dependency_count = 0usize;
        self.evaluate_envelope_prerequisites(
            &carrier.envelope,
            policy.prerequisite_rule,
            &mut dependencies,
            &mut missing_dependency_count,
        )?;
        let producer_slot = self.derive_producer_slot(
            &carrier.envelope,
            policy.producer_slot_rule,
            &mut dependencies,
            &mut missing_dependency_count,
        )?;
        let dependency_state = if missing_dependency_count == 0 {
            CarrierDependencyState::Ready
        } else {
            CarrierDependencyState::Waiting {
                missing_dependency_count,
            }
        };
        Ok(CandidateEvaluation {
            dependencies,
            producer_slot,
            dependency_state,
        })
    }

    fn evaluate_envelope_prerequisites(
        &self,
        envelope: &ObjectEnvelope,
        rule: FoundationPrerequisiteRule,
        dependencies: &mut BTreeSet<DependencyKey>,
        missing_dependency_count: &mut usize,
    ) -> Result<(), RefusalReason> {
        match rule {
            FoundationPrerequisiteRule::None => {
                if !envelope.ordered_prerequisite_hashes.is_empty() {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
            FoundationPrerequisiteRule::OneObject { object_type } => {
                let [prerequisite_hash] = envelope.ordered_prerequisite_hashes.as_slice() else {
                    return Err(RefusalReason::WrongTypeOrLength);
                };
                self.evaluate_object_dependency(
                    *prerequisite_hash,
                    Some((object_type, None)),
                    dependencies,
                    missing_dependency_count,
                )?;
            }
            FoundationPrerequisiteRule::OneExternal { prerequisite_kind } => {
                let [prerequisite_hash] = envelope.ordered_prerequisite_hashes.as_slice() else {
                    return Err(RefusalReason::WrongTypeOrLength);
                };
                let dependency = DependencyKey::External(prerequisite_kind);
                dependencies.insert(dependency);
                match self.external_prerequisites.get(&prerequisite_kind) {
                    Some(expected_hash) if expected_hash == prerequisite_hash.as_bytes() => {}
                    Some(_) => return Err(RefusalReason::WrongHashOrRoot),
                    None => *missing_dependency_count = missing_dependency_count.saturating_add(1),
                }
            }
            FoundationPrerequisiteRule::RosterOrderedObjects { object_type } => {
                if envelope.ordered_prerequisite_hashes.len() != self.roster_identities.len() {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                let mut distinct_hashes = BTreeSet::new();
                for (roster_position, prerequisite_hash) in envelope
                    .ordered_prerequisite_hashes
                    .iter()
                    .copied()
                    .enumerate()
                {
                    if !distinct_hashes.insert(prerequisite_hash.into_bytes()) {
                        return Err(RefusalReason::WrongHashOrRoot);
                    }
                    self.evaluate_object_dependency(
                        prerequisite_hash,
                        Some((object_type, Some(self.roster_identities[roster_position]))),
                        dependencies,
                        missing_dependency_count,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn evaluate_object_dependency(
        &self,
        object_hash: Hash512,
        expected: Option<(FoundationObjectType, Option<ParticipantIdentity>)>,
        dependencies: &mut BTreeSet<DependencyKey>,
        missing_dependency_count: &mut usize,
    ) -> Result<Option<&StoredCarrier>, RefusalReason> {
        let object_hash_bytes = object_hash.into_bytes();
        dependencies.insert(DependencyKey::Object(object_hash_bytes));
        let Some(dependency) = self.carriers.get(&object_hash_bytes) else {
            *missing_dependency_count = missing_dependency_count.saturating_add(1);
            return Ok(None);
        };
        if let CarrierDependencyState::Refused(_) = dependency.dependency_state {
            *missing_dependency_count = missing_dependency_count.saturating_add(1);
            return Ok(Some(dependency));
        }
        if let CarrierDependencyState::Waiting { .. } = dependency.dependency_state {
            *missing_dependency_count = missing_dependency_count.saturating_add(1);
        }
        if let Some((expected_type, expected_producer)) = expected {
            if dependency.envelope.object_type != expected_type {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            if let Some(expected_producer) = expected_producer
                && dependency.envelope.producer_participant_id != Some(expected_producer)
            {
                return Err(RefusalReason::WrongContext);
            }
        }
        Ok(Some(dependency))
    }

    fn derive_producer_slot(
        &self,
        envelope: &ObjectEnvelope,
        rule: FoundationProducerSlotRule,
        dependencies: &mut BTreeSet<DependencyKey>,
        missing_dependency_count: &mut usize,
    ) -> Result<Option<[u8; Hash512::BYTE_LENGTH]>, RefusalReason> {
        let producer = envelope.producer_participant_id;
        let mut slot_items = vec![
            CanonicalItem::hash512(envelope.suite_id.into_bytes()),
            CanonicalItem::hash512(envelope.ceremony_context_hash.into_bytes()),
            CanonicalItem::hash512(envelope.action_context_hash.into_bytes()),
            CanonicalItem::unsigned16(envelope.object_type.canonical_code()),
        ];
        if let Some(producer) = producer {
            slot_items.push(CanonicalItem::participant_identity(producer.into_bytes()));
        }

        match rule {
            FoundationProducerSlotRule::ProducerSequence => {
                slot_items.push(CanonicalItem::unsigned64(envelope.producer_sequence));
            }
            FoundationProducerSlotRule::PublicRandomnessRevealSource => {
                let payload =
                    CanonicalTuple::decode(&envelope.payload_bytes, &self.canonical_decode_limits)
                        .map_err(map_codec_error)?;
                let source_participant_id = read_participant_identity(&payload.items[0])?;
                slot_items.push(CanonicalItem::participant_identity(
                    source_participant_id.into_bytes(),
                ));
            }
            FoundationProducerSlotRule::DeterministicActionObject
            | FoundationProducerSlotRule::OnePerProducer => {}
            FoundationProducerSlotRule::FixedStateCapability(capability_kind) => {
                slot_items.push(CanonicalItem::unsigned16(capability_kind.canonical_code()));
                slot_items.push(CanonicalItem::unsigned64(envelope.recovery_epoch));
            }
            FoundationProducerSlotRule::StateReservationCapability => {
                let payload = StateReservationIntentPayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                let state_key =
                    self.derive_envelope_state_key(envelope, payload.capability_kind)?;
                slot_items.push(CanonicalItem::hash512(state_key.into_bytes()));
                slot_items.push(CanonicalItem::unsigned64(envelope.recovery_epoch));
            }
            FoundationProducerSlotRule::StateRecoveryCapability => {
                let payload = StateRecoveryTransitionPayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                let state_key =
                    self.derive_envelope_state_key(envelope, payload.capability_kind)?;
                slot_items.push(CanonicalItem::hash512(state_key.into_bytes()));
                slot_items.push(CanonicalItem::unsigned64(envelope.recovery_epoch));
            }
            FoundationProducerSlotRule::StateOutputReservation => {
                let payload = StateOutputIntentPayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                let Some(reservation) = self.evaluate_object_dependency(
                    payload.reservation_intent_object_hash,
                    Some((FoundationObjectType::StateReservation, None)),
                    dependencies,
                    missing_dependency_count,
                )?
                else {
                    return Ok(None);
                };
                let reservation_payload = StateReservationIntentPayload::decode(
                    &reservation.envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                self.require_matching_state_subject(envelope, &reservation.envelope)?;
                let state_key =
                    self.derive_envelope_state_key(envelope, reservation_payload.capability_kind)?;
                slot_items.push(CanonicalItem::hash512(state_key.into_bytes()));
                slot_items.push(CanonicalItem::unsigned64(envelope.recovery_epoch));
            }
            FoundationProducerSlotRule::StateWitnessIntent => {
                let vote_payload = StateWitnessVotePayload::decode(
                    &envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                let Some(intent) = self.evaluate_object_dependency(
                    vote_payload.intent_object_hash,
                    None,
                    dependencies,
                    missing_dependency_count,
                )?
                else {
                    return Ok(None);
                };
                let Some(state_binding) = self.resolve_state_intent_binding(
                    intent,
                    dependencies,
                    missing_dependency_count,
                )?
                else {
                    return Ok(None);
                };
                let expected_sequence = derive_state_witness_vote_sequence(
                    state_binding.vote_kind,
                    state_binding.subject_epoch,
                )
                .map_err(|error| error.refusal_reason)?;
                if envelope.producer_sequence != expected_sequence {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                slot_items.push(CanonicalItem::participant_identity(
                    state_binding.subject_participant_id.into_bytes(),
                ));
                slot_items.push(CanonicalItem::hash512(state_binding.state_key.into_bytes()));
                slot_items.push(CanonicalItem::unsigned64(expected_sequence));
            }
        }

        hash512("sealed-lattice/foundation/producer-slot/v1", &slot_items)
            .map(|hash| Some(hash.into_bytes()))
            .map_err(map_codec_error)
    }

    fn resolve_state_intent_binding(
        &self,
        intent: &StoredCarrier,
        dependencies: &mut BTreeSet<DependencyKey>,
        missing_dependency_count: &mut usize,
    ) -> Result<Option<StateIntentSlotBinding>, RefusalReason> {
        let subject_participant_id = intent
            .envelope
            .producer_participant_id
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        match intent.envelope.object_type {
            FoundationObjectType::StateReservation => {
                let payload = StateReservationIntentPayload::decode(
                    &intent.envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                Ok(Some(StateIntentSlotBinding {
                    subject_participant_id,
                    state_key: self
                        .derive_envelope_state_key(&intent.envelope, payload.capability_kind)?,
                    subject_epoch: intent.envelope.recovery_epoch,
                    vote_kind: StateWitnessVoteKind::Reservation,
                }))
            }
            FoundationObjectType::StateOutputIntent => {
                let payload = StateOutputIntentPayload::decode(
                    &intent.envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                let Some(reservation) = self.evaluate_object_dependency(
                    payload.reservation_intent_object_hash,
                    Some((FoundationObjectType::StateReservation, None)),
                    dependencies,
                    missing_dependency_count,
                )?
                else {
                    return Ok(None);
                };
                self.require_matching_state_subject(&intent.envelope, &reservation.envelope)?;
                let reservation_payload = StateReservationIntentPayload::decode(
                    &reservation.envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                Ok(Some(StateIntentSlotBinding {
                    subject_participant_id,
                    state_key: self.derive_envelope_state_key(
                        &intent.envelope,
                        reservation_payload.capability_kind,
                    )?,
                    subject_epoch: intent.envelope.recovery_epoch,
                    vote_kind: StateWitnessVoteKind::Output,
                }))
            }
            FoundationObjectType::RecoveryTransition => {
                let payload = StateRecoveryTransitionPayload::decode(
                    &intent.envelope.payload_bytes,
                    &self.canonical_decode_limits,
                )
                .map_err(|error| error.refusal_reason)?;
                let subject_epoch =
                    derive_state_recovery_producer_sequence(intent.envelope.recovery_epoch)
                        .map_err(|error| error.refusal_reason)?;
                Ok(Some(StateIntentSlotBinding {
                    subject_participant_id,
                    state_key: self
                        .derive_envelope_state_key(&intent.envelope, payload.capability_kind)?,
                    subject_epoch,
                    vote_kind: StateWitnessVoteKind::Recovery,
                }))
            }
            _ => Err(RefusalReason::WrongTypeOrLength),
        }
    }

    fn derive_envelope_state_key(
        &self,
        envelope: &ObjectEnvelope,
        capability_kind: StateCapabilityKind,
    ) -> Result<Hash512, RefusalReason> {
        derive_state_key(
            envelope.suite_id,
            envelope.ceremony_context_hash,
            envelope.action_context_hash,
            envelope
                .producer_participant_id
                .ok_or(RefusalReason::WrongTypeOrLength)?,
            capability_kind,
        )
        .map_err(|error| error.refusal_reason)
    }

    fn require_matching_state_subject(
        &self,
        object: &ObjectEnvelope,
        reservation: &ObjectEnvelope,
    ) -> Result<(), RefusalReason> {
        if object.suite_id != reservation.suite_id
            || object.ceremony_context_hash != reservation.ceremony_context_hash
            || object.action_context_hash != reservation.action_context_hash
            || object.producer_participant_id != reservation.producer_participant_id
            || object.recovery_epoch != reservation.recovery_epoch
            || object.recovery_transition_hash != reservation.recovery_transition_hash
        {
            return Err(RefusalReason::WrongContext);
        }
        Ok(())
    }

    fn index_dependencies(&mut self, object_hash: [u8; Hash512::BYTE_LENGTH]) {
        let dependencies = self
            .carriers
            .get(&object_hash)
            .map(|carrier| carrier.dependencies.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for dependency in dependencies {
            self.dependents
                .entry(dependency)
                .or_default()
                .insert(object_hash);
        }
    }

    fn index_producer_slot(
        &mut self,
        object_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> Vec<[u8; Hash512::BYTE_LENGTH]> {
        let Some(producer_slot) = self
            .carriers
            .get(&object_hash)
            .and_then(|carrier| carrier.producer_slot)
        else {
            return Vec::new();
        };
        let conflicting_hashes = {
            let slot_members = self.producer_slots.entry(producer_slot).or_default();
            slot_members.insert(object_hash);
            if slot_members.len() > 1 {
                Some(slot_members.iter().copied().collect::<Vec<_>>())
            } else {
                None
            }
        };
        if let Some(conflicting_hashes) = conflicting_hashes {
            self.mark_equivocation(&conflicting_hashes);
            conflicting_hashes
        } else {
            Vec::new()
        }
    }

    fn mark_equivocation(&mut self, object_hashes: &[[u8; Hash512::BYTE_LENGTH]]) {
        for object_hash in object_hashes {
            if let Some(carrier) = self.carriers.get_mut(object_hash) {
                self.unresolved_dependency_count = self
                    .unresolved_dependency_count
                    .saturating_sub(carrier.dependency_state.missing_dependency_count());
                carrier.dependency_state =
                    CarrierDependencyState::Refused(RefusalReason::Equivocation);
            }
        }
    }

    fn enqueue_dependents(
        &self,
        dependency: DependencyKey,
        queue: &mut VecDeque<[u8; Hash512::BYTE_LENGTH]>,
    ) {
        if let Some(dependents) = self.dependents.get(&dependency) {
            queue.extend(dependents.iter().copied());
        }
    }

    fn reevaluate_queued_carriers(&mut self, queue: &mut VecDeque<[u8; Hash512::BYTE_LENGTH]>) {
        let mut queued = queue.iter().copied().collect::<BTreeSet<_>>();
        while let Some(object_hash) = queue.pop_front() {
            queued.remove(&object_hash);
            let Some(carrier) = self.carriers.get(&object_hash) else {
                continue;
            };
            if matches!(carrier.dependency_state, CarrierDependencyState::Refused(_)) {
                continue;
            }
            let old_state = carrier.dependency_state;
            let old_slot = carrier.producer_slot;
            let evaluation = self.evaluate_carrier(carrier);
            let (new_dependencies, new_slot, mut new_state) = match evaluation {
                Ok(evaluation) => (
                    evaluation.dependencies,
                    evaluation.producer_slot,
                    evaluation.dependency_state,
                ),
                Err(refusal_reason) => (
                    BTreeSet::new(),
                    old_slot,
                    CarrierDependencyState::Refused(refusal_reason),
                ),
            };
            let old_missing_count = old_state.missing_dependency_count();
            let new_missing_count = new_state.missing_dependency_count();
            let prospective_unresolved_count = self
                .unresolved_dependency_count
                .saturating_sub(old_missing_count)
                .saturating_add(new_missing_count);
            if prospective_unresolved_count > self.limits.maximum_unresolved_dependency_count {
                new_state = CarrierDependencyState::Refused(RefusalReason::OutsideSupportedProfile);
                self.unresolved_dependency_count = self
                    .unresolved_dependency_count
                    .saturating_sub(old_missing_count);
            } else {
                self.unresolved_dependency_count = prospective_unresolved_count;
            }

            if let Some(carrier) = self.carriers.get_mut(&object_hash) {
                carrier.dependencies.extend(new_dependencies);
                carrier.producer_slot = new_slot.or(old_slot);
                carrier.dependency_state = new_state;
            }
            self.index_dependencies(object_hash);
            if old_slot.is_none() && new_slot.is_some() {
                let equivocated_hashes = self.index_producer_slot(object_hash);
                for equivocated_hash in equivocated_hashes {
                    let dependent_key = DependencyKey::Object(equivocated_hash);
                    if let Some(dependents) = self.dependents.get(&dependent_key) {
                        for dependent in dependents {
                            if queued.insert(*dependent) {
                                queue.push_back(*dependent);
                            }
                        }
                    }
                }
            }
            if old_state != new_state {
                let dependent_key = DependencyKey::Object(object_hash);
                if let Some(dependents) = self.dependents.get(&dependent_key) {
                    for dependent in dependents {
                        if queued.insert(*dependent) {
                            queue.push_back(*dependent);
                        }
                    }
                }
            }
        }
    }

    fn protocol_result(
        &self,
        object_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> VerificationResult<AuthenticatedCanonicalFoundationCarrier<'_>> {
        let authenticated = match self.authenticated_carrier_result(object_hash).into_result() {
            Ok(authenticated) => authenticated,
            Err(refusal_reason) => return VerificationResult::refused(refusal_reason),
        };
        match authenticated.policy.verification_requirement {
            FoundationObjectVerificationRequirement::CanonicalCarrierAuthentication => {
                VerificationResult::valid(authenticated)
            }
            // Carrier authentication cannot determine any relation, state, or
            // storage result. Until the fixed follow-on verifier is composed,
            // report the missing verifier prerequisite rather than inventing a
            // cryptographic refusal for work that was never performed.
            FoundationObjectVerificationRequirement::PublicRandomnessRelation
            | FoundationObjectVerificationRequirement::CommonProof
            | FoundationObjectVerificationRequirement::DeterministicRecomputation
            | FoundationObjectVerificationRequirement::StateAuthorization
            | FoundationObjectVerificationRequirement::StorageRootBinding => {
                VerificationResult::refused(RefusalReason::MissingPrerequisite)
            }
        }
    }

    fn authenticated_carrier_result(
        &self,
        object_hash: [u8; Hash512::BYTE_LENGTH],
    ) -> VerificationResult<AuthenticatedCanonicalFoundationCarrier<'_>> {
        let Some(carrier) = self.carriers.get(&object_hash) else {
            return VerificationResult::refused(RefusalReason::MissingPrerequisite);
        };
        match carrier.dependency_state {
            CarrierDependencyState::Ready => {
                VerificationResult::valid(AuthenticatedCanonicalFoundationCarrier {
                    object_hash: Hash512::from_bytes(object_hash),
                    policy: foundation_envelope_policy(carrier.envelope.object_type),
                    envelope: &carrier.envelope,
                    canonical_carrier_bytes: &carrier.canonical_carrier_bytes,
                })
            }
            CarrierDependencyState::Waiting { .. } => {
                VerificationResult::refused(RefusalReason::MissingPrerequisite)
            }
            CarrierDependencyState::Refused(refusal_reason) => {
                VerificationResult::refused(refusal_reason)
            }
        }
    }
}

struct StateIntentSlotBinding {
    subject_participant_id: ParticipantIdentity,
    state_key: Hash512,
    subject_epoch: u64,
    vote_kind: StateWitnessVoteKind,
}

fn map_codec_error(error: CanonicalCodecError) -> RefusalReason {
    if error.kind == CanonicalCodecErrorKind::LimitExceeded {
        RefusalReason::OutsideSupportedProfile
    } else {
        RefusalReason::MalformedEncoding
    }
}

fn read_u16(item: &CanonicalItem) -> Result<u16, RefusalReason> {
    let bytes: [u8; 2] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_participant_identity(item: &CanonicalItem) -> Result<ParticipantIdentity, RefusalReason> {
    let bytes: [u8; ParticipantIdentity::BYTE_LENGTH] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| RefusalReason::WrongTypeOrLength)?;
    Ok(ParticipantIdentity::from_bytes(bytes))
}

fn require_homogeneous_list_count_and_type(
    item: &CanonicalItem,
    expected_count: usize,
    expected_element_type: CanonicalItemType,
) -> Result<(), RefusalReason> {
    let bytes = item.canonical_bytes();
    if bytes.len() < 6 {
        return Err(RefusalReason::MalformedEncoding);
    }
    let element_type =
        CanonicalItemType::from_canonical_code(u16::from_le_bytes([bytes[0], bytes[1]]))
            .ok_or(RefusalReason::MalformedEncoding)?;
    let count = usize::try_from(u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    if element_type != expected_element_type || count != expected_count {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fips204::{
        ml_dsa_65,
        traits::{KeyGen, SerDes, Signer},
    };

    use super::*;
    use crate::foundation::{RosterEntry, derive_participant_identity, signature_message};

    const OBJECT_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/object-signature/v1";

    struct TestFixture {
        suite_id: Hash512,
        ceremony_context_hash: Hash512,
        action_context_hash: Hash512,
        roster: Roster,
        roster_hash: Hash512,
        participant_identities: Vec<ParticipantIdentity>,
        signing_keys: Vec<ml_dsa_65::PrivateKey>,
    }

    impl TestFixture {
        fn new() -> Self {
            let mut roster_entries =
                Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            let mut signing_keys =
                Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
            for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                let mut signing_seed = [0u8; 32];
                signing_seed[0] = u8::try_from(roster_position + 1)
                    .expect("test roster position fits in one byte");
                signing_seed[31] =
                    u8::try_from(FOUNDATION_PROFILE.participant_count - roster_position)
                        .expect("test reverse roster position fits in one byte");
                let (verification_key, signing_key) =
                    ml_dsa_65::KG::keygen_from_seed(&signing_seed);
                let mut mailbox_encapsulation_key = [0u8; 1_184];
                mailbox_encapsulation_key[1_152] = u8::try_from(roster_position + 1)
                    .expect("test roster position fits in one byte");
                roster_entries.push(RosterEntry {
                    roster_position,
                    signing_verification_key: verification_key.into_bytes(),
                    mailbox_encapsulation_key,
                });
                signing_keys.push(signing_key);
            }
            let roster = Roster::new(roster_entries).expect("test roster is canonical");
            let roster_hash = roster.roster_hash().expect("test roster hash derives");
            let participant_identities = roster
                .entries
                .iter()
                .map(|entry| {
                    entry
                        .participant_identity()
                        .expect("test participant identity derives")
                })
                .collect();
            Self {
                suite_id: Hash512::from_bytes([0x11; 64]),
                ceremony_context_hash: Hash512::from_bytes([0x22; 64]),
                action_context_hash: Hash512::from_bytes([0x33; 64]),
                roster,
                roster_hash,
                participant_identities,
                signing_keys,
            }
        }

        fn ingestor(
            &self,
            external_prerequisites: &[FoundationExternalPrerequisite],
        ) -> FoundationBoardIngestor {
            self.ingestor_with_limits(
                external_prerequisites,
                FoundationBoardIngestionLimits::default(),
            )
        }

        fn ingestor_with_limits(
            &self,
            external_prerequisites: &[FoundationExternalPrerequisite],
            limits: FoundationBoardIngestionLimits,
        ) -> FoundationBoardIngestor {
            FoundationBoardIngestor::new(FoundationBoardIngestionContext {
                suite_id: self.suite_id,
                ceremony_context_hash: self.ceremony_context_hash,
                action_context_hash: self.action_context_hash,
                roster: &self.roster,
                external_prerequisites,
                limits,
            })
            .into_result()
            .expect("test board ingestor constructs")
        }

        fn envelope(
            &self,
            object_type: FoundationObjectType,
            producer_roster_position: Option<usize>,
            producer_sequence: u64,
            ordered_prerequisite_hashes: Vec<Hash512>,
            payload_bytes: Vec<u8>,
        ) -> ObjectEnvelope {
            self.envelope_at_recovery_epoch(
                object_type,
                producer_roster_position,
                producer_sequence,
                0,
                None,
                ordered_prerequisite_hashes,
                payload_bytes,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn envelope_at_recovery_epoch(
            &self,
            object_type: FoundationObjectType,
            producer_roster_position: Option<usize>,
            producer_sequence: u64,
            recovery_epoch: u64,
            recovery_transition_hash: Option<Hash512>,
            ordered_prerequisite_hashes: Vec<Hash512>,
            payload_bytes: Vec<u8>,
        ) -> ObjectEnvelope {
            ObjectEnvelope {
                suite_id: self.suite_id,
                object_type,
                ceremony_context_hash: self.ceremony_context_hash,
                action_context_hash: self.action_context_hash,
                recovery_epoch,
                recovery_transition_hash,
                producer_participant_id: producer_roster_position
                    .map(|position| self.participant_identities[position]),
                producer_sequence,
                ordered_prerequisite_hashes,
                payload_bytes,
            }
        }

        fn signed_carrier(
            &self,
            producer_roster_position: usize,
            envelope: ObjectEnvelope,
            signature_seed_byte: u8,
        ) -> Vec<u8> {
            self.signed_carrier_with_key(
                &self.signing_keys[producer_roster_position],
                envelope,
                signature_seed_byte,
            )
        }

        fn signed_carrier_with_key(
            &self,
            signing_key: &ml_dsa_65::PrivateKey,
            envelope: ObjectEnvelope,
            signature_seed_byte: u8,
        ) -> Vec<u8> {
            let message = signature_message(&envelope, self.roster_hash)
                .expect("test signature message derives");
            let signature = signing_key
                .try_sign_with_seed(
                    &[signature_seed_byte; 32],
                    message.as_bytes(),
                    OBJECT_SIGNATURE_CONTEXT,
                )
                .expect("test signature generates");
            SignedCarrier {
                envelope,
                signature,
            }
            .encode()
            .expect("test signed carrier encodes")
        }

        fn setup_intents(&self) -> Vec<(Hash512, Vec<u8>)> {
            (0..self.participant_identities.len())
                .map(|roster_position| {
                    let envelope = self.envelope(
                        FoundationObjectType::SetupIntent,
                        Some(roster_position),
                        0,
                        Vec::new(),
                        empty_payload(SETUP_INTENT_SCHEMA_IDENTIFIER),
                    );
                    let object_hash = envelope.object_hash().expect("test object hash derives");
                    let carrier = self.signed_carrier(
                        roster_position,
                        envelope,
                        u8::try_from(roster_position + 1)
                            .expect("test roster position fits in one byte"),
                    );
                    (object_hash, carrier)
                })
                .collect()
        }
    }

    fn empty_payload(schema_identifier: u16) -> Vec<u8> {
        CanonicalTuple::new(schema_identifier, FOUNDATION_PAYLOAD_VERSION, Vec::new())
            .encode()
            .expect("test empty payload encodes")
    }

    fn hash_list(values: &[Hash512]) -> CanonicalItem {
        let items = values
            .iter()
            .map(|value| CanonicalItem::hash512(value.into_bytes()))
            .collect::<Vec<_>>();
        CanonicalItem::homogeneous_list(CanonicalItemType::Hash512, &items)
            .expect("test hash list encodes")
    }

    fn payload(schema_identifier: u16, items: Vec<CanonicalItem>) -> Vec<u8> {
        CanonicalTuple::new(schema_identifier, FOUNDATION_PAYLOAD_VERSION, items)
            .encode()
            .expect("test payload encodes")
    }

    fn assert_refused<Value>(
        result: VerificationResult<Value>,
        expected_refusal_reason: RefusalReason,
    ) {
        match result {
            VerificationResult::Refused { refusal_reason } => {
                assert_eq!(refusal_reason, expected_refusal_reason);
            }
            VerificationResult::Valid { .. } => {
                panic!("verification unexpectedly succeeded");
            }
        }
    }

    #[test]
    fn registry_is_closed_and_is_the_only_signature_purpose_map() {
        assert_eq!(
            FOUNDATION_ENVELOPE_POLICIES.len(),
            FoundationObjectType::ALL.len()
        );
        let mut assigned_codes = BTreeSet::new();
        for (object_type, policy) in FoundationObjectType::ALL
            .into_iter()
            .zip(FOUNDATION_ENVELOPE_POLICIES)
        {
            assert_eq!(policy.object_type, object_type);
            assert_eq!(policy.payload_schema_version, FOUNDATION_PAYLOAD_VERSION);
            assert_eq!(foundation_envelope_policy(object_type), &policy);
            assert!(assigned_codes.insert(object_type.canonical_code()));
            match policy.carrier_kind {
                FoundationCarrierKind::SignedByRosterParticipant => {
                    assert!(policy.signature_purpose.is_some());
                }
                FoundationCarrierKind::UnsignedDeterministic => {
                    assert!(policy.signature_purpose.is_none());
                    assert!(matches!(
                        object_type,
                        FoundationObjectType::Aggregate | FoundationObjectType::EvaluatorReplay
                    ));
                }
            }
        }
    }

    #[test]
    fn unordered_prerequisites_resolve_and_identical_retransmission_is_idempotent() {
        let fixture = TestFixture::new();
        let setup_intents = fixture.setup_intents();
        let ordered_intent_hashes = setup_intents
            .iter()
            .map(|(object_hash, _)| *object_hash)
            .collect::<Vec<_>>();
        let commitment_payload = payload(
            PUBLIC_RANDOMNESS_COMMITMENT_SCHEMA_IDENTIFIER,
            vec![
                CanonicalItem::hash512([0x41; 64]),
                hash_list(&vec![
                    Hash512::from_bytes([0x52; 64]);
                    usize::from(FOUNDATION_PROFILE.participant_count)
                ]),
            ],
        );
        let commitment_envelope = fixture.envelope(
            FoundationObjectType::PublicRandomnessCommitment,
            Some(0),
            0,
            ordered_intent_hashes.clone(),
            commitment_payload.clone(),
        );
        let commitment_hash = commitment_envelope
            .object_hash()
            .expect("test commitment hash derives");
        let commitment_carrier = fixture.signed_carrier(0, commitment_envelope, 0x71);

        let mut ingestor = fixture.ingestor(&[]);
        assert_refused(
            ingestor.ingest_canonical_carrier(&commitment_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert_refused(
            ingestor.authenticated_carrier_with_present_prerequisites(commitment_hash),
            RefusalReason::MissingPrerequisite,
        );

        for (_, carrier) in setup_intents.iter().rev() {
            assert!(ingestor.ingest_canonical_carrier(carrier).is_valid());
        }
        let authenticated_commitment = ingestor
            .authenticated_carrier_with_present_prerequisites(commitment_hash)
            .into_result()
            .expect("all commitment prerequisites are present");
        assert_eq!(
            authenticated_commitment.policy().verification_requirement,
            FoundationObjectVerificationRequirement::PublicRandomnessRelation
        );
        assert_eq!(
            authenticated_commitment.canonical_carrier_bytes(),
            commitment_carrier
        );
        assert_eq!(ingestor.unresolved_dependency_count(), 0);
        assert_eq!(
            ingestor.require_complete_carrier_dependency_graph(),
            VerificationResult::valid(())
        );

        let stored_count = ingestor.stored_carrier_count();
        let retained_bytes = ingestor.retained_carrier_byte_length();
        assert_refused(
            ingestor.ingest_canonical_carrier(&commitment_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert_eq!(ingestor.stored_carrier_count(), stored_count);
        assert_eq!(ingestor.retained_carrier_byte_length(), retained_bytes);

        let mut wrong_order_ingestor = fixture.ingestor(&[]);
        for (_, carrier) in &setup_intents {
            assert!(
                wrong_order_ingestor
                    .ingest_canonical_carrier(carrier)
                    .is_valid()
            );
        }
        let wrong_order_envelope = fixture.envelope(
            FoundationObjectType::PublicRandomnessCommitment,
            Some(0),
            0,
            ordered_intent_hashes.into_iter().rev().collect(),
            commitment_payload,
        );
        let wrong_order_carrier = fixture.signed_carrier(0, wrong_order_envelope, 0x72);
        assert_refused(
            wrong_order_ingestor.ingest_canonical_carrier(&wrong_order_carrier),
            RefusalReason::WrongContext,
        );
    }

    #[test]
    fn malformed_context_key_and_carrier_kind_inputs_fail_closed() {
        let fixture = TestFixture::new();
        let setup_envelope = fixture.envelope(
            FoundationObjectType::SetupIntent,
            Some(0),
            0,
            Vec::new(),
            empty_payload(SETUP_INTENT_SCHEMA_IDENTIFIER),
        );
        let mut valid_carrier = fixture.signed_carrier(0, setup_envelope.clone(), 0x31);

        let mut ingestor = fixture.ingestor(&[]);
        let signature_byte_index = valid_carrier.len() - 1;
        valid_carrier[signature_byte_index] ^= 1;
        assert_refused(
            ingestor.ingest_canonical_carrier(&valid_carrier),
            RefusalReason::InvalidSignature,
        );

        let mut wrong_context_envelope = setup_envelope.clone();
        wrong_context_envelope.action_context_hash = Hash512::from_bytes([0x99; 64]);
        let wrong_context_carrier = fixture.signed_carrier(0, wrong_context_envelope, 0x32);
        assert_refused(
            ingestor.ingest_canonical_carrier(&wrong_context_carrier),
            RefusalReason::WrongContext,
        );

        let unsigned_signed_family = setup_envelope
            .encode()
            .expect("test unsigned envelope encodes");
        assert_refused(
            ingestor.ingest_canonical_carrier(&unsigned_signed_family),
            RefusalReason::WrongTypeOrLength,
        );

        let aggregate_payload = payload(
            AGGREGATE_SCHEMA_IDENTIFIER,
            vec![
                CanonicalItem::hash512([1; 64]),
                CanonicalItem::hash512([2; 64]),
                hash_list(&vec![
                    Hash512::from_bytes([3; 64]);
                    usize::from(FOUNDATION_PROFILE.participant_count)
                ]),
                CanonicalItem::variable_bytes([]).expect("test descriptor bytes encode"),
            ],
        );
        let signed_unsigned_family = SignedCarrier {
            envelope: fixture.envelope(
                FoundationObjectType::Aggregate,
                Some(0),
                0,
                Vec::new(),
                aggregate_payload,
            ),
            signature: [0; super::super::ML_DSA_65_SIGNATURE_BYTE_LENGTH],
        }
        .encode()
        .expect("test wrong carrier kind encodes");
        assert_refused(
            ingestor.ingest_canonical_carrier(&signed_unsigned_family),
            RefusalReason::WrongTypeOrLength,
        );

        let (unrelated_verification_key, unrelated_signing_key) =
            ml_dsa_65::KG::keygen_from_seed(&[0xe7; 32]);
        let unrelated_participant_id =
            derive_participant_identity(&unrelated_verification_key.into_bytes())
                .expect("test unrelated participant identity derives");
        let mut self_nominated_envelope = setup_envelope.clone();
        self_nominated_envelope.producer_participant_id = Some(unrelated_participant_id);
        let self_nominated_carrier =
            fixture.signed_carrier_with_key(&unrelated_signing_key, self_nominated_envelope, 0x33);
        assert_refused(
            ingestor.ingest_canonical_carrier(&self_nominated_carrier),
            RefusalReason::WrongContext,
        );

        let canonical_envelope = setup_envelope.encode().expect("test envelope encodes");
        let mut unknown_family_envelope = canonical_envelope.clone();
        let mut item_offset = 8usize;
        for _ in 0..3 {
            let item_byte_length = u32::from_le_bytes(
                unknown_family_envelope[item_offset + 2..item_offset + 6]
                    .try_into()
                    .expect("test item length bytes"),
            ) as usize;
            item_offset += 6 + item_byte_length;
        }
        unknown_family_envelope[item_offset + 6..item_offset + 8]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        assert_refused(
            ingestor.ingest_canonical_carrier(&unknown_family_envelope),
            RefusalReason::MalformedEncoding,
        );

        let mut truncated = canonical_envelope;
        truncated.pop();
        assert_refused(
            ingestor.ingest_canonical_carrier(&truncated),
            RefusalReason::MalformedEncoding,
        );
    }

    #[test]
    fn same_slot_equivocation_is_order_independent_and_poisoned_for_all_members() {
        let fixture = TestFixture::new();
        let complaint_payload = |accused_hash_byte: u8| {
            payload(
                COMPLAINT_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::participant_identity(
                        fixture.participant_identities[1].into_bytes(),
                    ),
                    CanonicalItem::hash512([accused_hash_byte; 64]),
                    CanonicalItem::unsigned16(RefusalReason::InvalidSignature.canonical_code()),
                ],
            )
        };
        let first_envelope = fixture.envelope(
            FoundationObjectType::Complaint,
            Some(0),
            7,
            Vec::new(),
            complaint_payload(0x41),
        );
        let first_hash = first_envelope
            .object_hash()
            .expect("first complaint hash derives");
        let first_carrier = fixture.signed_carrier(0, first_envelope, 0x51);
        let second_envelope = fixture.envelope(
            FoundationObjectType::Complaint,
            Some(0),
            7,
            Vec::new(),
            complaint_payload(0x42),
        );
        let second_hash = second_envelope
            .object_hash()
            .expect("second complaint hash derives");
        let second_carrier = fixture.signed_carrier(0, second_envelope, 0x52);

        for (first, second) in [
            (&first_carrier, &second_carrier),
            (&second_carrier, &first_carrier),
        ] {
            let mut ingestor = fixture.ingestor(&[]);
            assert!(ingestor.ingest_canonical_carrier(first).is_valid());
            assert_refused(
                ingestor.ingest_canonical_carrier(second),
                RefusalReason::Equivocation,
            );
            assert_refused(
                ingestor.authenticated_carrier_with_present_prerequisites(first_hash),
                RefusalReason::Equivocation,
            );
            assert_refused(
                ingestor.authenticated_carrier_with_present_prerequisites(second_hash),
                RefusalReason::Equivocation,
            );
        }

        let same_envelope = fixture.envelope(
            FoundationObjectType::SetupIntent,
            Some(2),
            0,
            Vec::new(),
            empty_payload(SETUP_INTENT_SCHEMA_IDENTIFIER),
        );
        let same_hash = same_envelope
            .object_hash()
            .expect("same envelope hash derives");
        let first_randomized_signature = fixture.signed_carrier(2, same_envelope.clone(), 0x61);
        let second_randomized_signature = fixture.signed_carrier(2, same_envelope, 0x62);
        let mut ingestor = fixture.ingestor(&[]);
        assert!(
            ingestor
                .ingest_canonical_carrier(&first_randomized_signature)
                .is_valid()
        );
        assert_refused(
            ingestor.ingest_canonical_carrier(&second_randomized_signature),
            RefusalReason::Equivocation,
        );
        assert_eq!(ingestor.stored_carrier_count(), 1);
        assert_refused(
            ingestor.authenticated_carrier_with_present_prerequisites(same_hash),
            RefusalReason::Equivocation,
        );

        let unresolved_locks = (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                let mut hash_bytes = [0x77; 64];
                hash_bytes[0] = u8::try_from(roster_position)
                    .expect("the test roster position fits in one byte");
                Hash512::from_bytes(hash_bytes)
            })
            .collect::<Vec<_>>();
        let reveal_payload = |contribution_hash_byte: u8| {
            payload(
                PUBLIC_RANDOMNESS_REVEAL_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::participant_identity(
                        fixture.participant_identities[3].into_bytes(),
                    ),
                    CanonicalItem::hash512([contribution_hash_byte; 64]),
                    CanonicalItem::fixed_bytes([0x88; 64]).expect("test recovery share encodes"),
                ],
            )
        };
        let first_reveal = fixture.signed_carrier(
            4,
            fixture.envelope(
                FoundationObjectType::PublicRandomnessReveal,
                Some(4),
                0,
                unresolved_locks.clone(),
                reveal_payload(0x91),
            ),
            0x63,
        );
        let second_reveal = fixture.signed_carrier(
            4,
            fixture.envelope(
                FoundationObjectType::PublicRandomnessReveal,
                Some(4),
                9,
                unresolved_locks,
                reveal_payload(0x92),
            ),
            0x64,
        );
        let mut reveal_ingestor = fixture.ingestor(&[]);
        assert_refused(
            reveal_ingestor.ingest_canonical_carrier(&first_reveal),
            RefusalReason::MissingPrerequisite,
        );
        assert_refused(
            reveal_ingestor.ingest_canonical_carrier(&second_reveal),
            RefusalReason::Equivocation,
        );
    }

    #[test]
    fn proof_deterministic_state_and_storage_families_do_not_gain_acceptance_from_ingestion() {
        let fixture = TestFixture::new();
        let verified_setup_source_hash = Hash512::from_bytes([0xa1; 64]);
        let external_prerequisites = [FoundationExternalPrerequisite {
            prerequisite_kind: FoundationExternalPrerequisiteKind::SetupSourceAnchor,
            object_hash: verified_setup_source_hash,
        }];
        let mut ingestor = fixture.ingestor(&external_prerequisites);

        let ballot_envelope = fixture.envelope(
            FoundationObjectType::BallotPackage,
            Some(0),
            0,
            vec![verified_setup_source_hash],
            payload(
                BALLOT_PACKAGE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::variable_bytes([]).expect("test ciphertext descriptor encodes"),
                    CanonicalItem::variable_bytes([]).expect("test proof descriptor encodes"),
                ],
            ),
        );
        let ballot_hash = ballot_envelope
            .object_hash()
            .expect("test ballot hash derives");
        let ballot_carrier = fixture.signed_carrier(0, ballot_envelope, 0x81);
        assert_refused(
            ingestor.ingest_canonical_carrier(&ballot_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert!(
            ingestor
                .authenticated_carrier_with_present_prerequisites(ballot_hash)
                .is_valid()
        );

        let aggregate_envelope = fixture.envelope(
            FoundationObjectType::Aggregate,
            None,
            0,
            Vec::new(),
            payload(
                AGGREGATE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::hash512([1; 64]),
                    CanonicalItem::hash512([2; 64]),
                    hash_list(&vec![
                        Hash512::from_bytes([3; 64]);
                        usize::from(FOUNDATION_PROFILE.participant_count)
                    ]),
                    CanonicalItem::variable_bytes([]).expect("test aggregate descriptor encodes"),
                ],
            ),
        );
        let aggregate_hash = aggregate_envelope
            .object_hash()
            .expect("test aggregate hash derives");
        assert_refused(
            ingestor.ingest_canonical_carrier(
                &aggregate_envelope
                    .encode()
                    .expect("test aggregate envelope encodes"),
            ),
            RefusalReason::MissingPrerequisite,
        );
        assert!(
            ingestor
                .authenticated_carrier_with_present_prerequisites(aggregate_hash)
                .is_valid()
        );

        let reservation_envelope = fixture.envelope(
            FoundationObjectType::StateReservation,
            Some(0),
            0,
            Vec::new(),
            StateReservationIntentPayload {
                capability_kind: StateCapabilityKind::FinalitySignature,
                authorization_hash: Hash512::from_bytes([0xb1; 64]),
            }
            .encode()
            .expect("test reservation payload encodes"),
        );
        let reservation_hash = reservation_envelope
            .object_hash()
            .expect("test reservation hash derives");
        let reservation_carrier = fixture.signed_carrier(0, reservation_envelope, 0x82);
        assert_refused(
            ingestor.ingest_canonical_carrier(&reservation_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert!(
            ingestor
                .authenticated_carrier_with_present_prerequisites(reservation_hash)
                .is_valid()
        );

        let storage_envelope = fixture.envelope(
            FoundationObjectType::StorageRootCommitment,
            Some(0),
            0,
            Vec::new(),
            StorageRootCommitmentPayload::new(Hash512::from_bytes([0xc1; 64]))
                .encode()
                .expect("test storage-root payload encodes"),
        );
        let storage_hash = storage_envelope
            .object_hash()
            .expect("test storage-root hash derives");
        let storage_carrier = fixture.signed_carrier(0, storage_envelope, 0x83);
        assert_refused(
            ingestor.ingest_canonical_carrier(&storage_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert!(
            ingestor
                .authenticated_carrier_with_present_prerequisites(storage_hash)
                .is_valid()
        );

        let target_envelope = fixture.envelope(
            FoundationObjectType::TargetDecryptionShare,
            Some(1),
            0,
            Vec::new(),
            payload(
                TARGET_DECRYPTION_SHARE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::hash512([0xd1; 64]),
                    CanonicalItem::hash512([0xd2; 64]),
                    CanonicalItem::variable_bytes([]).expect("test target-id descriptor encodes"),
                    CanonicalItem::variable_bytes([])
                        .expect("test target-order descriptor encodes"),
                    CanonicalItem::variable_bytes([]).expect("test proof descriptor encodes"),
                ],
            ),
        );
        let target_hash = target_envelope
            .object_hash()
            .expect("test target-release hash derives");
        let target_carrier = fixture.signed_carrier(1, target_envelope, 0x84);
        assert_refused(
            ingestor.ingest_canonical_carrier(&target_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert!(
            ingestor
                .authenticated_carrier_with_present_prerequisites(target_hash)
                .is_valid()
        );
    }

    #[test]
    fn state_derived_slots_wait_for_references_and_detect_conflicting_outputs() {
        let fixture = TestFixture::new();
        let reservation_envelope = fixture.envelope(
            FoundationObjectType::StateReservation,
            Some(0),
            0,
            Vec::new(),
            StateReservationIntentPayload {
                capability_kind: StateCapabilityKind::BallotCandidateList,
                authorization_hash: Hash512::from_bytes([0xe1; 64]),
            }
            .encode()
            .expect("test reservation payload encodes"),
        );
        let reservation_hash = reservation_envelope
            .object_hash()
            .expect("test reservation hash derives");
        let reservation_carrier = fixture.signed_carrier(0, reservation_envelope, 0x91);

        let output_envelope = |exact_output_hash_byte: u8| {
            fixture.envelope(
                FoundationObjectType::StateOutputIntent,
                Some(0),
                0,
                Vec::new(),
                StateOutputIntentPayload {
                    reservation_intent_object_hash: reservation_hash,
                    exact_output_hash: Hash512::from_bytes([exact_output_hash_byte; 64]),
                }
                .encode()
                .expect("test output payload encodes"),
            )
        };
        let first_output_envelope = output_envelope(0xe2);
        let first_output_hash = first_output_envelope
            .object_hash()
            .expect("test first output hash derives");
        let first_output_carrier = fixture.signed_carrier(0, first_output_envelope, 0x92);

        let mut ingestor = fixture.ingestor(&[]);
        assert_refused(
            ingestor.ingest_canonical_carrier(&first_output_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert_eq!(ingestor.unresolved_dependency_count(), 1);
        assert_refused(
            ingestor.ingest_canonical_carrier(&reservation_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert_eq!(ingestor.unresolved_dependency_count(), 0);
        assert!(
            ingestor
                .authenticated_carrier_with_present_prerequisites(first_output_hash)
                .is_valid()
        );

        let second_output_envelope = output_envelope(0xe3);
        let second_output_hash = second_output_envelope
            .object_hash()
            .expect("test second output hash derives");
        let second_output_carrier = fixture.signed_carrier(0, second_output_envelope, 0x93);
        assert_refused(
            ingestor.ingest_canonical_carrier(&second_output_carrier),
            RefusalReason::Equivocation,
        );
        assert_refused(
            ingestor.authenticated_carrier_with_present_prerequisites(first_output_hash),
            RefusalReason::Equivocation,
        );
        assert_refused(
            ingestor.authenticated_carrier_with_present_prerequisites(second_output_hash),
            RefusalReason::Equivocation,
        );
    }

    #[test]
    fn external_anchor_and_resource_limits_are_fail_closed_and_non_consuming() {
        let fixture = TestFixture::new();
        let expected_setup_hash = Hash512::from_bytes([0xf1; 64]);
        let ballot_envelope = fixture.envelope(
            FoundationObjectType::BallotPackage,
            Some(0),
            0,
            vec![expected_setup_hash],
            payload(
                BALLOT_PACKAGE_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::variable_bytes([]).expect("test ciphertext descriptor encodes"),
                    CanonicalItem::variable_bytes([]).expect("test proof descriptor encodes"),
                ],
            ),
        );
        let ballot_hash = ballot_envelope
            .object_hash()
            .expect("test ballot hash derives");
        let ballot_carrier = fixture.signed_carrier(0, ballot_envelope, 0xa1);
        let mut missing_anchor_ingestor = fixture.ingestor(&[]);
        assert_refused(
            missing_anchor_ingestor.ingest_canonical_carrier(&ballot_carrier),
            RefusalReason::MissingPrerequisite,
        );
        assert_eq!(missing_anchor_ingestor.unresolved_dependency_count(), 1);
        assert_eq!(
            missing_anchor_ingestor.register_external_prerequisite(
                FoundationExternalPrerequisite {
                    prerequisite_kind: FoundationExternalPrerequisiteKind::SetupSourceAnchor,
                    object_hash: Hash512::from_bytes([0xf2; 64]),
                },
            ),
            VerificationResult::valid(())
        );
        assert_refused(
            missing_anchor_ingestor.authenticated_carrier_with_present_prerequisites(ballot_hash),
            RefusalReason::WrongHashOrRoot,
        );
        assert_refused(
            missing_anchor_ingestor.register_external_prerequisite(
                FoundationExternalPrerequisite {
                    prerequisite_kind: FoundationExternalPrerequisiteKind::SetupSourceAnchor,
                    object_hash: expected_setup_hash,
                },
            ),
            RefusalReason::Equivocation,
        );

        let setup_intents = fixture.setup_intents();
        let first_setup_carrier = &setup_intents[0].1;
        let one_carrier_limits = FoundationBoardIngestionLimits::try_new(
            first_setup_carrier.len(),
            1,
            first_setup_carrier.len(),
            16,
        )
        .expect("test one-carrier limits are valid");
        let mut one_carrier_ingestor = fixture.ingestor_with_limits(&[], one_carrier_limits);
        assert!(
            one_carrier_ingestor
                .ingest_canonical_carrier(first_setup_carrier)
                .is_valid()
        );
        assert_refused(
            one_carrier_ingestor.ingest_canonical_carrier(&setup_intents[1].1),
            RefusalReason::OutsideSupportedProfile,
        );
        assert_eq!(one_carrier_ingestor.stored_carrier_count(), 1);

        let ordered_intent_hashes = setup_intents
            .iter()
            .map(|(object_hash, _)| *object_hash)
            .collect::<Vec<_>>();
        let commitment_envelope = fixture.envelope(
            FoundationObjectType::PublicRandomnessCommitment,
            Some(0),
            0,
            ordered_intent_hashes,
            payload(
                PUBLIC_RANDOMNESS_COMMITMENT_SCHEMA_IDENTIFIER,
                vec![
                    CanonicalItem::hash512([0xfa; 64]),
                    hash_list(&vec![
                        Hash512::from_bytes([0xfb; 64]);
                        usize::from(FOUNDATION_PROFILE.participant_count)
                    ]),
                ],
            ),
        );
        let commitment_carrier = fixture.signed_carrier(0, commitment_envelope, 0xa2);
        let dependency_limit = FoundationBoardIngestionLimits::try_new(
            commitment_carrier.len(),
            2,
            commitment_carrier.len() * 2,
            1,
        )
        .expect("test dependency limits are valid");
        let mut dependency_limited_ingestor = fixture.ingestor_with_limits(&[], dependency_limit);
        assert_refused(
            dependency_limited_ingestor.ingest_canonical_carrier(&commitment_carrier),
            RefusalReason::OutsideSupportedProfile,
        );
        assert_eq!(dependency_limited_ingestor.stored_carrier_count(), 0);
        assert_eq!(dependency_limited_ingestor.unresolved_dependency_count(), 0);

        let undersized_limit = FoundationBoardIngestionLimits::try_new(
            first_setup_carrier.len() - 1,
            2,
            first_setup_carrier.len(),
            2,
        )
        .expect("test undersized carrier limit is itself valid");
        let mut byte_limited_ingestor = fixture.ingestor_with_limits(&[], undersized_limit);
        assert_refused(
            byte_limited_ingestor.ingest_canonical_carrier(first_setup_carrier),
            RefusalReason::OutsideSupportedProfile,
        );
        assert_eq!(byte_limited_ingestor.stored_carrier_count(), 0);
    }
}
