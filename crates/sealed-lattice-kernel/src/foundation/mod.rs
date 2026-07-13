//! Canonical foundation data shared by protocol verification paths.
//!
//! This module owns the deterministic tuple framing, Unicode ingress rules,
//! domain-separated hashes, fixed profile identifiers, and verifier result
//! vocabulary. Higher-level protocol modules remain responsible for proving
//! and verifying their schema-specific arithmetic relations.

mod canonical_stream;
mod canonical_stream_runtime;
mod canonical_tuple;
mod hash;
mod local_encrypted_storage;
mod local_storage_runtime;
mod participant_identity;
mod refusal;
mod schemas;
mod state;
mod state_runtime;
mod text;

pub(crate) use canonical_stream::VerifiedCanonicalStreamSummary;
pub use canonical_stream::{
    CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter,
    MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, derive_canonical_stream_descriptor,
};
pub(crate) use canonical_stream_runtime::{
    CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH, CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE,
    CANONICAL_STREAM_RUNTIME_INVALID_SESSION, CanonicalStreamRuntimeBegin,
    absorb_canonical_stream_chunk, begin_canonical_stream_verifier, begin_canonical_stream_writer,
    cancel_canonical_stream, finish_canonical_stream_verifier,
    finish_canonical_stream_verifier_with_summary, finish_canonical_stream_writer,
};
pub use canonical_tuple::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple,
};
pub use hash::{Hash512, hash512};
pub use local_encrypted_storage::{
    ACTION_STORAGE_ROOT_BYTE_LENGTH, ActionStorageRoot, CanonicalLocalStorageRecoveryIngress,
    DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH, DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH,
    DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, DeviceWrappedStorageRoot,
    DeviceWrappingAssociatedData, LocalStorageBinding, LocalStorageRecoveryValue,
    STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER,
    STORAGE_ROOT_RECOVERY_VALUE_SCHEMA_IDENTIFIER, StorageRootCommitmentPayload,
};
pub(crate) use local_storage_runtime::run_local_storage_root_command;
pub use participant_identity::{
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, ParticipantIdentityParseError,
    derive_participant_identity,
};
pub use refusal::{RefusalReason, VerificationResult};
pub use schemas::{
    ACTION_DEFINITION_SCHEMA_IDENTIFIER, ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER, ActionDefinition,
    ArtifactKind, ArtifactReference, BOARD_POLICY_SCHEMA_IDENTIFIER, BoardPolicy,
    DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER, DistributionKind, DistributionRecord,
    FOUNDATION_PROFILE, FoundationObjectType, FoundationProfile, FoundationSchemaError,
    MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
    MANIFEST_SCHEMA_IDENTIFIER, Manifest, OBJECT_ENVELOPE_SCHEMA_IDENTIFIER,
    OPTION_DEFINITION_SCHEMA_IDENTIFIER, ObjectEnvelope, OptionDefinition,
    PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
    ProofObjectHeader, ROSTER_ENTRY_SCHEMA_IDENTIFIER, ROSTER_SCHEMA_IDENTIFIER, Roster,
    RosterEntry, SIGNED_CARRIER_SCHEMA_IDENTIFIER, SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER,
    STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER, SUITE_RECORD_SCHEMA_IDENTIFIER, SignedCarrier,
    StreamDescriptor, action_context_hash, ceremony_context_hash, signature_message,
};
pub use state::{
    EphemeralStateWitnessVoteReplayIndex, PreservedStateIntent,
    STATE_CERTIFICATE_SCHEMA_IDENTIFIER, STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
    STATE_RECOVERY_TRANSITION_SCHEMA_IDENTIFIER, STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER,
    STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER, StateCapabilityKind, StateCertificate,
    StateDurableBinding, StateError, StateOutputIntentPayload,
    StateRecoveryIntentVerificationInput, StateRecoveryTransitionPayload,
    StateRecoveryVerificationInput, StateReservationIntentPayload,
    StateReservationIntentVerificationInput, StateReservationVerificationInput, StateVerifier,
    StateWitnessLock, StateWitnessVoteKind, StateWitnessVotePayload,
    StateWitnessVoteReplayDisposition, StateWitnessVoteReplayKey, VerifiedStateOutput,
    VerifiedStateOutputIntent, VerifiedStateRecovery, VerifiedStateRecoveryIntent,
    VerifiedStateReservation, VerifiedStateReservationIntent, derive_state_exact_output_hash,
    derive_state_key, derive_state_recovery_producer_sequence, derive_state_witness_vote_sequence,
    verify_state_witness_lock_preservation,
};
pub(crate) use state_runtime::{
    STATE_DURABLE_BINDING_BYTE_LENGTH, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
    begin_state_verifier_session, cancel_state_verifier_session, certify_verified_state_intent,
    describe_verified_state_object, finish_state_output_intent_verification,
    finish_state_output_verification, release_verified_state_object, verify_state_recovery,
    verify_state_recovery_intent, verify_state_reservation, verify_state_reservation_intent,
};
pub use text::{DisplayTextError, StabilizedDisplayText};
