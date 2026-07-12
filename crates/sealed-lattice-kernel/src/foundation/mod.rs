//! Canonical foundation data shared by protocol verification paths.
//!
//! This module owns the deterministic tuple framing, Unicode ingress rules,
//! domain-separated hashes, fixed profile identifiers, and verifier result
//! vocabulary. Higher-level protocol modules remain responsible for proving
//! and verifying their schema-specific arithmetic relations.

mod board_ingestion;
mod board_ingestion_runtime;
mod canonical_stream;
mod canonical_stream_runtime;
mod canonical_tuple;
mod cryptographic_counters;
mod hash;
mod local_encrypted_storage;
mod local_storage_runtime;
mod mailbox;
mod participant_identity;
mod private_randomness;
mod proof_attempts;
mod proof_commitments;
mod proof_profiles;
mod proof_transcript;
mod refusal;
mod runtime_schemas;
mod schema_object;
mod schemas;
mod state;
mod state_runtime;
mod suite_record;
mod text;

pub use board_ingestion::{
    AuthenticatedCanonicalFoundationCarrier, FOUNDATION_ENVELOPE_POLICIES,
    FoundationBoardIngestionContext, FoundationBoardIngestionLimits, FoundationBoardIngestor,
    FoundationCarrierKind, FoundationEnvelopePolicy, FoundationExternalPrerequisite,
    FoundationExternalPrerequisiteKind, FoundationObjectVerificationRequirement,
    FoundationPrerequisiteRule, FoundationProducerSequenceRule, FoundationProducerSlotRule,
    FoundationRecoveryRule, foundation_envelope_policy,
};
pub(crate) use board_ingestion_runtime::{
    FOUNDATION_BOARD_CANDIDATE_HASH_BYTE_LENGTH, FOUNDATION_BOARD_SESSION_CAPABILITY_BYTE_LENGTH,
    begin_foundation_board_session, cancel_foundation_board_session,
    ingest_foundation_board_carrier, require_complete_foundation_board_carrier_graph,
};
pub use canonical_stream::{
    CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter,
    MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, derive_canonical_stream_descriptor,
};
pub(crate) use canonical_stream_runtime::{
    CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH, CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE,
    CANONICAL_STREAM_RUNTIME_INVALID_SESSION, CanonicalStreamRuntimeBegin,
    absorb_canonical_stream_chunk, begin_canonical_stream_verifier, begin_canonical_stream_writer,
    cancel_canonical_stream, finish_canonical_stream_verifier, finish_canonical_stream_writer,
};
pub use canonical_tuple::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple,
};
pub use cryptographic_counters::{
    CryptographicCounterSnapshot, CryptographicInterfaceCounters,
    MAXIMUM_AUTHENTICATED_MAILBOX_OPENINGS_PER_CEREMONY,
    MAXIMUM_DEVICE_WRAPPING_OPENS_PER_CEREMONY, MAXIMUM_LOCAL_RECORD_OPENS_PER_CEREMONY,
    MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTES_PER_CEREMONY, MAXIMUM_MAILBOX_ENCAPSULATIONS_PER_CEREMONY,
    MAXIMUM_MAILBOX_PLAINTEXT_BYTES_PER_CEREMONY,
    MAXIMUM_OBJECT_SIGNATURE_GENERATIONS_PER_CEREMONY,
    MAXIMUM_OBJECT_SIGNATURE_VERIFICATIONS_PER_CEREMONY, MAXIMUM_PROOF_VERIFICATIONS_PER_CEREMONY,
};
pub use hash::{Hash512, hash512};
pub use local_encrypted_storage::{
    ACTION_STORAGE_ROOT_BYTE_LENGTH, ActionStorageRoot, AuthenticatedLocalRecordEnvelope,
    CanonicalLocalStorageRecoveryIngress, DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, DeviceWrappedStorageRoot,
    DeviceWrappingAssociatedData, LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_AUTHENTICATOR_BYTE_LENGTH, LOCAL_RECORD_AUTHENTICATOR_INPUT_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER, LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_NONCE_BYTE_LENGTH, LOCAL_RECORD_TAG_BYTE_LENGTH, LocalRecordAssociatedData,
    LocalRecordEnvelope, LocalRecordExpectation, LocalRecordIdentifier, LocalRecordKeyInput,
    LocalRecordPlaintext, LocalRecordType, LocalStorageBinding, LocalStorageOperationError,
    LocalStorageRecoveryValue, STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER, StorageRootCommitmentPayload,
};
pub(crate) use local_storage_runtime::run_local_storage_root_command;
pub use mailbox::{
    AES_256_KEY_BYTE_LENGTH, AES_GCM_NONCE_BYTE_LENGTH, AES_GCM_TAG_BYTE_LENGTH,
    AuthenticatedMailboxEnvelope, MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
    ML_DSA_65_SIGNATURE_BYTE_LENGTH, ML_DSA_65_SIGNING_KEY_BYTE_LENGTH,
    ML_KEM_768_CIPHERTEXT_BYTE_LENGTH, ML_KEM_768_DECAPSULATION_KEY_BYTE_LENGTH,
    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH, MailboxAssociatedData, MailboxBindingExpectation,
    MailboxDecapsulationKey, MailboxKeyScheduleInput, MailboxPayloadType, MailboxSealingRandomness,
    MailboxSigningKey, PreparedMailboxOpening, SealedMailboxPayload, SignedMailboxEnvelope,
    kem_ciphertext_hash, seal_mailbox_payload,
};
pub use participant_identity::{
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, ParticipantIdentityParseError,
    derive_participant_identity,
};
pub use private_randomness::{
    ActionPrivateRandomness, EntropySourceError, FallibleEntropySource, PrivateRandomAttempt,
    PrivateRandomDomain, PrivateRandomStreamContext, PrivateRandomnessActionBinding,
    PrivateRandomnessError, PrivateRandomnessResumeSnapshot, SuiteSamplingPurpose,
    TargetFloodingRole, VerifiableSecretSharingExpansionRole,
};
pub use proof_attempts::{
    EphemeralProofAttemptTracker, ProofApplicationSlot, ProofAttemptProfile,
    ProofAttemptReservationDisposition, ProofAttemptStartDisposition, ProofFamily,
    ProofFamilyByteCeiling,
};
pub use proof_commitments::{
    CommonProofTreeOpeningVerification, PROOF_AUTHENTICATION_FRONTIER_SCHEMA_IDENTIFIER,
    PROOF_AUTHENTICATION_NODE_SCHEMA_IDENTIFIER, PROOF_MERKLE_NODE_SCHEMA_IDENTIFIER,
    PROOF_MERKLE_TREE_CONTEXT_SCHEMA_IDENTIFIER, PROOF_ORACLE_PHASE_PAIR_LEAF_SCHEMA_IDENTIFIER,
    PROOF_QUERY_OPENING_RECORD_SCHEMA_IDENTIFIER, ProofAuthenticationFrontier,
    ProofAuthenticationNode, ProofLeafVisibility, ProofMerkleNode, ProofMerkleTreeContext,
    ProofMerkleTreeRole, ProofOraclePhasePairLeaf, ProofQueryOpeningRecord, ProofTreeValue,
    ProofTreeValueKind, ProofTreeValueProfile, derive_proof_header_hash,
    verify_common_proof_tree_opening,
};
pub use proof_profiles::{
    PROOF_FAMILY_PROFILE_SCHEMA_IDENTIFIER, PROOF_FIELD_PROFILE_SCHEMA_IDENTIFIER,
    PROOF_FIELD_SCHEDULE_SCHEMA_IDENTIFIER, PROOF_PROFILE_MAXIMUM_CHALLENGE_EXTENSION_DEGREE,
    PROOF_PROFILE_SET_MAXIMUM_BYTE_LENGTH, PROOF_PROFILE_SET_SCHEMA_IDENTIFIER, ProofFamilyProfile,
    ProofFieldProfile, ProofFieldSchedule, ProofProfileSet,
};
pub use proof_transcript::{
    CanonicalProofTranscript, ProofChallengeTag, ProofRoundTag, ProofTranscriptError,
};
pub use refusal::{RefusalReason, VerificationResult};
pub use runtime_schemas::{
    CHECKPOINT_BOUNDARY_PROFILE_SCHEMA_IDENTIFIER, CHECKPOINT_MANIFEST_SCHEMA_IDENTIFIER,
    CHECKPOINT_RANDOM_USE_PROFILE_SCHEMA_IDENTIFIER, CheckpointBoundaryProfile, CheckpointManifest,
    CheckpointRandomUseProfile, MOBILE_RUNTIME_PROFILE_SCHEMA_IDENTIFIER, MobileRuntimeProfile,
    RANDOM_CURSOR_SCHEMA_IDENTIFIER, RUNTIME_ASSET_REFERENCE_SCHEMA_IDENTIFIER,
    RUNTIME_BUILD_MANIFEST_SCHEMA_IDENTIFIER, RUNTIME_OPERATION_PROFILE_SCHEMA_IDENTIFIER,
    RandomCursor, RuntimeAssetReference, RuntimeAssetRole, RuntimeBuildManifest,
    RuntimeOperationProfile,
};
pub(crate) use schema_object::{
    FoundationSchemaObjectValidationError, validate_foundation_schema_object,
};
pub use schemas::{
    ACTION_DEFINITION_SCHEMA_IDENTIFIER, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER, ActionDefinition,
    ArtifactKind, ArtifactReference, BOARD_POLICY_SCHEMA_IDENTIFIER, BoardPolicy,
    DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER, DistributionKind, DistributionRecord,
    FOUNDATION_PROFILE, FoundationObjectType, FoundationProfile, FoundationSchemaError,
    FoundationSchemaIdentifier, MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER, MANIFEST_SCHEMA_IDENTIFIER, Manifest,
    OBJECT_ENVELOPE_SCHEMA_IDENTIFIER, OPTION_DEFINITION_SCHEMA_IDENTIFIER, ObjectEnvelope,
    OptionDefinition, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
    PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER, ProofObjectHeader, ROSTER_ENTRY_SCHEMA_IDENTIFIER,
    ROSTER_SCHEMA_IDENTIFIER, Roster, RosterEntry, SIGNED_CARRIER_SCHEMA_IDENTIFIER,
    SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER,
    SUITE_RECORD_SCHEMA_IDENTIFIER, SignedCarrier, StreamDescriptor, action_context_hash,
    ceremony_context_hash, signature_message,
};
pub use state::{
    EphemeralStateWitnessVoteReplayIndex, PreservedStateIntent,
    STATE_CERTIFICATE_SCHEMA_IDENTIFIER, STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
    STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER, STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER,
    STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER, StateCapabilityKind, StateCertificate, StateError,
    StateOutputIntentPayload, StateOutputVerificationInput, StateRecoveryTransitionPayload,
    StateRecoveryVerificationInput, StateReservationIntentPayload,
    StateReservationVerificationInput, StateVerifier, StateWitnessLock, StateWitnessVoteKind,
    StateWitnessVotePayload, StateWitnessVoteReplayDisposition, StateWitnessVoteReplayKey,
    VerifiedStateOutput, VerifiedStateRecovery, VerifiedStateReservation,
    derive_state_exact_output_hash, derive_state_key, derive_state_recovery_producer_sequence,
    derive_state_witness_vote_sequence, verify_state_witness_lock_preservation,
};
pub(crate) use state_runtime::{
    STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, begin_state_verifier_session,
    cancel_state_verifier_session, release_verified_state_object, verify_state_output,
    verify_state_recovery, verify_state_reservation,
};
pub use suite_record::{SUITE_RECORD_MAXIMUM_BYTE_LENGTH, SuiteRecord};
pub use text::{DisplayTextError, StabilizedDisplayText};
