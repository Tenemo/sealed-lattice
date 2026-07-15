//! Canonical foundation data shared by protocol verification paths.

mod authenticated_mailbox;
mod board_ingestion;
mod board_ingestion_ffi;
mod board_ingestion_runtime;
mod canonical_stream;
mod canonical_stream_runtime;
mod canonical_tuple;
mod finality;
mod finality_runtime;
mod hash;
mod local_encrypted_storage;
mod local_storage_runtime;
mod mailbox_gcm;
mod mailbox_gcm_runtime;
mod namespace_freshness;
mod namespace_freshness_runtime;
mod participant_identity;
mod private_randomness;
mod private_randomness_runtime;
mod proof_application;
mod refusal;
mod schemas;
mod state;
mod state_runtime;
mod text;

pub use authenticated_mailbox::{
    MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
    MAILBOX_GCM_TAG_BYTE_LENGTH, MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH,
    MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH, MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
    MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH, MailboxAssociatedData, MailboxKeyScheduleInput,
    MailboxPayloadType, SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER, SignedMailboxEnvelope,
    derive_setup_mailbox_slot_hash,
};
pub use board_ingestion::{
    CanonicalBoardError, CanonicalBoardLimits, CanonicalBoardVerifier, VerifiedTranscriptBatch,
    VerifiedTranscriptObject,
};
pub(crate) use canonical_stream::VerifiedCanonicalStreamSummary;
pub use canonical_stream::{
    CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter,
    MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, derive_canonical_stream_descriptor,
};
pub(crate) use canonical_stream_runtime::{
    CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE, CANONICAL_STREAM_RUNTIME_INVALID_SESSION,
    CanonicalStreamRuntimeBegin, absorb_canonical_stream_chunk, begin_canonical_stream_verifier,
    begin_canonical_stream_writer, cancel_canonical_stream, finish_canonical_stream_verifier,
    finish_canonical_stream_verifier_with_summary, finish_canonical_stream_writer,
};
pub use canonical_tuple::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, IncrementalCanonicalTupleDecoder,
};
pub use finality::{
    FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER, FINALITY_SIGNATURE_PAYLOAD_SCHEMA_IDENTIFIER,
    FINALITY_SIGNER_INPUT_SCHEMA_IDENTIFIER, FINALITY_STATEMENT_SCHEMA_IDENTIFIER,
    FinalityCertificate, FinalitySignaturePayload, FinalitySignerInput, FinalityStatement,
    FinalityVerificationInput, FinalityVerifier, VerifiedEvaluatorReplay, VerifiedFinality,
};
pub(crate) use finality_runtime::{
    FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VERIFIED_FINALITY_DESCRIPTION_BYTE_LENGTH,
    begin_finality_verifier_session, cancel_finality_verifier_session, describe_verified_finality,
    release_verified_finality, verify_finality,
};
pub use hash::{Hash512, hash_foundation_tuple_512};
pub(crate) use hash::{
    StreamingFoundationHashError, StreamingFoundationTupleHash512, fill_foundation_tuple_xof,
};
pub use local_encrypted_storage::{
    ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER, ACTION_STORAGE_ROOT_BYTE_LENGTH,
    ActionStorageDerivationInput, ActionStorageRoot, DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH,
    DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER, DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH,
    DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, DeviceWrappedStorageRoot,
    DeviceWrappingAssociatedData, LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER, LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_NONCE_BYTE_LENGTH, LOCAL_RECORD_TAG_BYTE_LENGTH, LocalRecordAssociatedData,
    LocalRecordEnvelope, LocalRecordIdentifierInput, LocalRecordKeyInput, LocalRecordSealInput,
    LocalRecordType, LocalStorageBinding, MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH,
    STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER, StorageRootCommitmentPayload,
    derive_local_record_envelope_hash, derive_local_record_identifier,
};
pub(crate) use local_storage_runtime::run_local_storage_root_command;
pub(crate) use mailbox_gcm::{MAILBOX_GCM_KEY_BYTE_LENGTH, MAILBOX_GCM_NONCE_BYTE_LENGTH};
pub(crate) use mailbox_gcm_runtime::{
    authenticate_mailbox_gcm_chunk, begin_mailbox_gcm_encryptor, begin_mailbox_gcm_verifier,
    cancel_mailbox_gcm, decrypt_mailbox_gcm_chunk, encrypt_mailbox_gcm_chunk,
    finish_mailbox_gcm_authentication, finish_mailbox_gcm_decryptor, finish_mailbox_gcm_encryptor,
};
pub use namespace_freshness::{
    NAMESPACE_FRESHNESS_CHECKPOINT_SCHEMA_IDENTIFIER, NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER,
    NamespaceFreshnessCheckpoint, NamespaceFreshnessVerifier, NamespaceFreshnessVote,
    SIGNED_NAMESPACE_FRESHNESS_VOTE_SCHEMA_IDENTIFIER, SignedNamespaceFreshnessVote,
    VerifiedNamespaceFreshnessCertificate, VerifiedNamespaceFreshnessCheckpoint,
};
pub(crate) use namespace_freshness_runtime::run_namespace_freshness_command;
pub use participant_identity::{
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, ParticipantIdentityParseError,
    derive_participant_identity,
};
pub use private_randomness::{
    ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER, ACTION_RANDOMNESS_ROOT_BYTE_LENGTH,
    ActionPrivateRandomness, ActionRandomnessDerivationInput, ActionRandomnessRoot,
    ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, OrdinaryProofCoinInput,
    PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, PRIVATE_PROOF_SALT_PURPOSE,
    PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER,
    PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH, PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH,
    PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER, PersistentProofCoinInput, PrivateRandomBlockInput,
    PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    PrivateRandomnessStream, ProofApplicationSlot, RANDOM_CURSOR_SCHEMA_IDENTIFIER,
    SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_IDENTIFIER,
    SetupStructuredCommitmentOpeningContext,
};
pub(crate) use private_randomness_runtime::run_action_randomness_command;
pub use proof_application::{
    PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER, PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
    ProofApplicationBinding, ProofApplicationSlotCeilings, ProofFamilyApplicationCeiling,
    ProofObjectHeader,
};
pub use refusal::{RefusalReason, VerificationResult};
pub use schemas::{
    FOUNDATION_PROFILE, FoundationObjectType, FoundationProfile, FoundationSchemaError,
    ML_DSA_65_SIGNATURE_BYTE_LENGTH, ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH,
    OBJECT_ENVELOPE_SCHEMA_IDENTIFIER, ObjectEnvelope, ROSTER_ENTRY_SCHEMA_IDENTIFIER,
    ROSTER_SCHEMA_IDENTIFIER, Roster, RosterEntry, SIGNED_CARRIER_SCHEMA_IDENTIFIER,
    STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER, SignedCarrier, StreamDescriptor, signature_message,
};
pub use state::{
    STATE_CERTIFICATE_SCHEMA_IDENTIFIER, STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
    STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER, STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
    StateCapabilityKind, StateCertificate, StateDurableBinding, StateError, StateOutputIntentPayload,
    StateReservationIntentPayload,
    StateReservationIntentVerificationInput, StateReservationVerificationInput, StateVerifier,
    StateWitnessVoteKind, StateWitnessVotePayload, VerifiedStateOutput, VerifiedStateOutputIntent,
    VerifiedStateReservation, VerifiedStateReservationIntent, derive_state_exact_output_hash,
    derive_state_key, derive_state_witness_vote_sequence,
};
pub(crate) use state_runtime::{
    STATE_DURABLE_BINDING_BYTE_LENGTH, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
    begin_state_verifier_session, cancel_state_verifier_session, certify_verified_state_intent,
    certify_verified_state_intent_from_unordered_vote_carriers, describe_verified_state_object,
    finish_state_output_intent_verification, finish_state_output_verification,
    release_verified_state_object, verify_state_reservation, verify_state_reservation_intent,
};
pub use text::{DisplayTextError, StabilizedDisplayText};
