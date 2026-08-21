//! Canonical foundation data shared by protocol verification paths.

/// Maximum adversarial random-oracle query count used by the classical and
/// quantum reduction ledgers.
///
/// Every proof-family ledger uses the same `2^80 - 1` budget rather than
/// selecting a family-local value. This is distinct from verifier proof-query
/// complexity such as `qPi`.
pub(crate) const DECLARED_ADVERSARIAL_QUERY_BUDGET: u128 = (1_u128 << 80) - 1;

mod authenticated_mailbox;
mod ballot_candidates;
mod board_ingestion;
mod board_ingestion_ffi;
mod board_ingestion_runtime;
mod canonical_stream;
mod canonical_stream_runtime;
#[cfg(test)]
pub(crate) mod canonical_transport_accounting;
mod canonical_tuple;
mod ceremony;
mod finality;
mod finality_runtime;
mod hash;
mod local_encrypted_storage;
mod local_storage_runtime;
mod mailbox_gcm;
mod mailbox_gcm_runtime;
mod participant_identity;
mod prepared_signed_carrier;
mod private_randomness;
mod private_randomness_runtime;
mod proof_application;
mod refusal;
mod roster_runtime;
mod runtime_input;
mod schemas;
mod selected_suite;
mod setup_transcript_runtime;
mod state;
mod state_runtime;
mod suite;
mod suite_artifact_preflight;
#[cfg(test)]
mod suite_artifacts;
mod text;

pub use authenticated_mailbox::{
    MAILBOX_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, MAILBOX_ENVELOPE_ATTEMPT_IDENTIFIER_BYTE_LENGTH,
    MAILBOX_GCM_TAG_BYTE_LENGTH, MAILBOX_HKDF_EXTRACT_SALT_BYTE_LENGTH,
    MAILBOX_KEM_CIPHERTEXT_BYTE_LENGTH, MAILBOX_KEY_SCHEDULE_INPUT_SCHEMA_IDENTIFIER,
    MAILBOX_SOURCE_SIGNATURE_BYTE_LENGTH, MailboxAssociatedData, MailboxKeyScheduleInput,
    RECIPIENT_PRIVATE_VSS_SHARE_MAILBOX_PAYLOAD_TYPE, SIGNED_MAILBOX_ENVELOPE_SCHEMA_IDENTIFIER,
    SignedMailboxEnvelope, derive_setup_mailbox_slot_hash,
};
pub use ballot_candidates::{
    AuthenticatedBallotCandidateList, AuthenticatedBallotCandidatePackage,
    AuthenticatedBallotCandidateView, BALLOT_CANDIDATE_LIST_PAYLOAD_SCHEMA_IDENTIFIER,
    BALLOT_CANDIDATE_VIEW_INPUT_SCHEMA_IDENTIFIER, BALLOT_CANDIDATE_VIEW_SCHEMA_IDENTIFIER,
    BallotCandidateView, BallotCandidateViewInput, CANDIDATE_ENTRY_SCHEMA_IDENTIFIER,
    CANDIDATE_LIST_INPUT_SCHEMA_IDENTIFIER, CandidateEntry, CandidateListInput,
};
pub(crate) use ballot_candidates::{
    BallotCandidateAuthenticationContext, BallotCandidateListPayload,
    authenticate_ballot_candidate_view,
};
pub use board_ingestion::{
    CanonicalBoardError, CanonicalBoardLimits, CanonicalBoardVerifier, VerifiedTranscriptBatch,
    VerifiedTranscriptObject,
};
pub(crate) use board_ingestion_runtime::{
    BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VerifiedBallotPackageApplicationPayload,
    VerifiedBoardApplicationSource, VerifiedSetupComplaintResolutionReservationHandle,
    consume_verified_setup_complaint_resolution, reserve_verified_setup_complaint_resolution,
    resolve_verified_action_top_count, resolve_verified_board_application_sources,
    resolve_verified_transcript_objects, restore_verified_setup_complaint_resolution,
    with_reserved_verified_setup_complaint_resolution,
};
pub use canonical_stream::{
    CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter,
    MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH, derive_canonical_stream_descriptor,
};
pub(crate) use canonical_stream::{
    CanonicalStreamReadbackVerifier, VerifiedCanonicalStreamSummary,
    canonical_target_release_output_payload,
};
#[cfg(test)]
pub(crate) use canonical_stream::{
    TargetReleaseOutputBundleByteLengths,
    canonical_target_release_output_bundle_byte_lengths_for_accounting,
};
pub(crate) use canonical_stream_runtime::{
    CanonicalStreamRuntimeBegin, absorb_canonical_stream_chunk, begin_canonical_stream_verifier,
    begin_canonical_stream_writer, cancel_canonical_stream, finish_canonical_stream_verifier,
    finish_canonical_stream_verifier_with_summary, finish_canonical_stream_writer,
};
pub use canonical_tuple::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalCodecError,
    CanonicalCodecErrorKind, CanonicalDecodeLimits, CanonicalItem, CanonicalItemType,
    CanonicalTuple, IncrementalCanonicalTupleDecoder,
};
pub use ceremony::{
    ACTION_DEFINITION_SCHEMA_IDENTIFIER, ActionContext, ActionDefinition,
    BOARD_POLICY_SCHEMA_IDENTIFIER, BoardPolicy, CeremonyContext, MANIFEST_SCHEMA_IDENTIFIER,
    Manifest, OPTION_DEFINITION_SCHEMA_IDENTIFIER, OptionDefinition,
};
pub(crate) use finality::VerifiedEvaluatorReplayRelationOutput;
pub use finality::{
    FINALITY_CERTIFICATE_SCHEMA_IDENTIFIER, FINALITY_SIGNATURE_PAYLOAD_SCHEMA_IDENTIFIER,
    FINALITY_SIGNER_INPUT_SCHEMA_IDENTIFIER, FINALITY_STATEMENT_SCHEMA_IDENTIFIER,
    FinalityCertificate, FinalitySignaturePayload, FinalitySignerInput, FinalityStatement,
    FinalityVerificationInput, FinalityVerifier, VerifiedEvaluatorReplay, VerifiedFinality,
};
pub(crate) use finality_runtime::{
    FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VERIFIED_FINALITY_DESCRIPTION_BYTE_LENGTH,
    begin_finality_verifier_session, cancel_finality_verifier_session, describe_verified_finality,
    release_verified_evaluator_replay, release_verified_finality, retain_verified_evaluator_replay,
    verify_finality, with_verified_finality,
};
pub(crate) use hash::{
    FoundationTupleHash512BlockReader, StreamingFoundationHashError,
    StreamingFoundationTupleHash512, foundation_tuple_hash512_seeded_stream_query_count,
};
pub use hash::{Hash512, hash_foundation_tuple_512};
#[cfg(test)]
pub(crate) use hash::{
    canonical_foundation_tuple_hash_preimage, foundation_tuple_hash512_block_count,
};
#[cfg(feature = "primitive-measurement-evidence")]
pub(crate) use local_encrypted_storage::measure_common_proof_scratch_record_codec;
pub use local_encrypted_storage::{
    ACTION_STORAGE_DERIVATION_INPUT_SCHEMA_IDENTIFIER, ACTION_STORAGE_ROOT_BYTE_LENGTH,
    ActionStorageDerivationInput, ActionStorageRoot, CommonProofExternalMemoryRecordKind,
    DEVICE_WRAPPED_STORAGE_ROOT_NONCE_BYTE_LENGTH, DEVICE_WRAPPED_STORAGE_ROOT_SCHEMA_IDENTIFIER,
    DEVICE_WRAPPED_STORAGE_ROOT_TAG_BYTE_LENGTH, DEVICE_WRAPPING_ASSOCIATED_DATA_SCHEMA_IDENTIFIER,
    DeviceWrappedStorageRoot, DeviceWrappingAssociatedData,
    LOCAL_RECORD_ASSOCIATED_DATA_SCHEMA_IDENTIFIER, LOCAL_RECORD_ENVELOPE_SCHEMA_IDENTIFIER,
    LOCAL_RECORD_KEY_INPUT_SCHEMA_IDENTIFIER, LOCAL_RECORD_NONCE_BYTE_LENGTH,
    LOCAL_RECORD_TAG_BYTE_LENGTH, LocalRecordAssociatedData, LocalRecordEnvelope,
    LocalRecordIdentifierInput, LocalRecordKeyInput, LocalRecordSealInput, LocalRecordType,
    LocalStorageBinding, MAXIMUM_LOCAL_RECORD_PLAINTEXT_BYTE_LENGTH,
    STORAGE_ROOT_COMMITMENT_PAYLOAD_SCHEMA_IDENTIFIER, StorageRootCommitmentPayload,
    derive_local_record_envelope_hash, derive_local_record_identifier,
};
pub(crate) use local_storage_runtime::{
    BrowserWorkerAuthenticatedStorageHeadSource, BrowserWorkerAuthenticatedStorageTransitionSource,
    LOCAL_STORAGE_ROOT_CAPABILITY_BYTE_LENGTH,
    MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
    MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
    resolve_browser_worker_authenticated_storage_head_source,
    resolve_browser_worker_authenticated_storage_transition_source, run_local_storage_root_command,
};
pub(crate) use mailbox_gcm::{MAILBOX_GCM_KEY_BYTE_LENGTH, MAILBOX_GCM_NONCE_BYTE_LENGTH};
pub(crate) use mailbox_gcm_runtime::{
    authenticate_mailbox_gcm_chunk, begin_mailbox_gcm_encryptor, begin_mailbox_gcm_verifier,
    cancel_mailbox_gcm, consume_authenticated_mailbox_plaintext_capability,
    decrypt_mailbox_gcm_chunk, encrypt_mailbox_gcm_chunk, finish_mailbox_gcm_authentication,
    finish_mailbox_gcm_decryptor, finish_mailbox_gcm_encryptor,
};
pub use participant_identity::{
    ML_DSA_65_VERIFICATION_KEY_BYTE_LENGTH, ParticipantIdentity, derive_participant_identity,
};
pub(crate) use prepared_signed_carrier::{
    PreparedSignedCarrierDescription, cancel_prepared_signed_carrier,
    finish_prepared_signed_carrier, prepared_signed_carrier_byte_length,
    retain_prepared_signed_carrier,
};
pub(crate) use private_randomness::PersistentProofWitnessCoinBinding;
#[cfg(test)]
pub(crate) use private_randomness::generator_hybrid::{
    MaskGeneratorHonestAbortEvent, MaskGeneratorHybridAssumption, MaskGeneratorHybridHop,
    MaskGeneratorHybridLoss, action_root_expansion_summary, deployed_mask_generator_hybrid,
    quantum_mask_generator_hybrid,
};
#[cfg(all(test, feature = "theorem-evidence"))]
pub(crate) use private_randomness::generator_hybrid::{
    deployed_private_stream_hybrid, quantum_private_stream_hybrid,
};
pub use private_randomness::{
    ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER, ACTION_RANDOMNESS_ROOT_BYTE_LENGTH,
    ActionPrivateRandomness, ActionRandomnessDerivationInput, ActionRandomnessRoot,
    ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, OrdinaryProofCoinInput,
    PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER, PRIVATE_PROOF_SALT_PURPOSE,
    PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER, PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_VERSION,
    PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH, PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH,
    PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER, PersistentProofCoinInput, PrivateRandomBlockInput,
    PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
    PrivateRandomnessStream, ProofApplicationSlot, RANDOM_CURSOR_SCHEMA_IDENTIFIER,
    SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_IDENTIFIER,
    SetupStructuredCommitmentOpeningContext,
};
pub(crate) use private_randomness::{
    ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION, ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH,
    PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION, PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION,
    PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION, PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH,
    PROOF_COIN_KEY_BYTE_LENGTH,
};
pub(crate) use private_randomness_runtime::{
    ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT, ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE,
    AuthenticatedCheckpointContinuationSource, PreparedActionProofAttemptSource,
    PreparedPublicOnlyProofAttemptSource, WitnessBoundPreparedActionProofAttemptSource,
    bind_prepared_action_proof_attempt_to_canonical_witness,
    resolve_prepared_action_proof_attempt_source, resolve_prepared_ordinary_proof_attempt_source,
    resolve_prepared_public_only_proof_attempt_source,
    resolve_setup_action_randomness_reservation_source,
    retain_action_private_randomness_for_exact_family, run_action_randomness_command,
};
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) use private_randomness_runtime::{
    prepare_exact_same_secret_evidence_attempt,
    prepare_exact_same_secret_evidence_attempt_from_authenticated_checkpoint,
};
pub use proof_application::{
    PROOF_APPLICATION_BINDING_SCHEMA_IDENTIFIER, PROOF_OBJECT_HEADER_SCHEMA_IDENTIFIER,
    PROOF_OBJECT_HEADER_SCHEMA_VERSION, ProofApplicationBinding, ProofApplicationSlotCeilings,
    ProofFamilyApplicationCeiling, ProofFamilyApplicationInventory,
    ProofFamilyApplicationInventoryEntry, ProofObjectHeader,
};
pub use refusal::{RefusalReason, VerificationResult};
pub(crate) use schemas::{
    AggregatePayload, BallotPackagePayload, PrivateShareAcceptancePayload,
    encode_aggregate_carrier, encode_evaluator_replay_carrier,
};
pub use schemas::{
    FOUNDATION_PROFILE, FoundationObjectType, FoundationProfile, FoundationRosterParameters,
    FoundationSchemaError, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
    MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
    MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, ML_DSA_65_SIGNATURE_BYTE_LENGTH,
    ML_KEM_768_ENCAPSULATION_KEY_BYTE_LENGTH, OBJECT_ENVELOPE_SCHEMA_IDENTIFIER, ObjectEnvelope,
    ROSTER_ENTRY_SCHEMA_IDENTIFIER, ROSTER_SCHEMA_IDENTIFIER, Roster, RosterEntry,
    SIGNED_CARRIER_SCHEMA_IDENTIFIER, STREAM_DESCRIPTOR_SCHEMA_IDENTIFIER, SignedCarrier,
    StreamDescriptor, derive_foundation_roster_parameters, signature_message,
};
pub(crate) use selected_suite::{
    SELECTED_MAXIMUM_BALLOT_ATTEMPTS_PER_PARTICIPANT,
    SELECTED_MAXIMUM_CANDIDATE_PACKAGES_PER_ACTION,
    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
};
pub(crate) use selected_suite::{
    SELECTED_MAXIMUM_PUBLIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
    selected_evaluator_resource_accounting,
};
pub(crate) use selected_suite::{SelectedSuiteCapability, select_suite_record};
#[cfg(test)]
pub(crate) use selected_suite::{
    derive_unactivated_selected_suite_candidate_record_from_relation_plans,
    selected_maximum_proof_objects_per_action, selected_suite_capability_for_tests,
};
pub(crate) use setup_transcript_runtime::derive_public_randomness_contribution_commitment;
pub(crate) use state::PreparedStateReservationIntent;
pub use state::{
    STATE_CERTIFICATE_SCHEMA_IDENTIFIER, STATE_OUTPUT_INTENT_SCHEMA_IDENTIFIER,
    STATE_RESERVATION_INTENT_SCHEMA_IDENTIFIER, STATE_WITNESS_VOTE_SCHEMA_IDENTIFIER,
    StateCapabilityKind, StateCertificate, StateDurableBinding, StateError,
    StateOutputIntentPayload, StateReservationIntentPayload,
    StateReservationIntentVerificationInput, StateReservationVerificationInput, StateVerifier,
    StateWitnessVoteKind, StateWitnessVotePayload, VerifiedStateOutput, VerifiedStateOutputIntent,
    VerifiedStateReservation, VerifiedStateReservationIntent, derive_state_exact_output_hash,
    derive_state_key, derive_state_witness_vote_sequence,
};
pub(crate) use state_runtime::{
    STATE_DURABLE_BINDING_BYTE_LENGTH, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
    VerifiedStateReservationRuntimeBinding, begin_state_verifier_session,
    cancel_state_verifier_session, certify_verified_state_intent,
    certify_verified_state_intent_from_unordered_vote_carriers,
    commit_accepted_setup_state_reservations, describe_verified_state_object,
    finish_state_output_intent_verification, finish_state_output_verification,
    release_verified_state_object, run_state_producer_command, verified_state_reservation_binding,
    verify_state_reservation, verify_state_reservation_intent, with_verified_state_reservation,
    with_verified_state_reservation_and_output,
};
pub(crate) use suite::selected_sharing_data_prime_coordinates;
pub(crate) use suite::selected_target_data_prime_coordinates;
pub use suite::{
    ARTIFACT_REFERENCE_SCHEMA_IDENTIFIER, ArtifactKind, ArtifactReference,
    DISTRIBUTION_RECORD_SCHEMA_IDENTIFIER, DistributionKind, DistributionPurpose,
    DistributionRecord, SUITE_RECORD_SCHEMA_IDENTIFIER, SuiteCountLimits, SuiteRecord,
};
pub(crate) use suite_artifact_preflight::verify_canonical_suite_artifact;
pub use text::{DisplayTextError, StabilizedDisplayText};
