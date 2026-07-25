//! Shared proof primitives and deterministic transcript-domain bindings.

/// Secret salt width for every secret-bearing common-proof Merkle leaf.
///
/// The 512-bit ideal-XOF commitment uses twice the output width, as required
/// by the statistical-hiding Merkle construction used by the proof theorem.
pub(crate) const COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH: usize = 128;

mod aggregate_threshold_share_runtime;
mod application_statement;
mod ballot_validity_runtime;
mod body;
mod collective_public_key_runtime;
mod committed_material;
mod component_material_stream;
mod component_public_polynomial_runtime;
mod decoder;
mod domain;
mod evaluator_aggregate;
mod evaluator_aggregate_runtime;
mod evaluator_aggregate_source;
mod evaluator_source_material;
mod external_memory;
mod external_polynomial;
mod field;
mod fri;
mod galois_key_share_runtime;
mod galois_source_material;
mod merkle;
mod opening;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod phase_liveness_accounting;
mod polynomial;
mod profile;
mod prover;
mod recipient_vss_payload;
mod relation_plan;
mod relinearization_aggregate_runtime;
mod relinearization_runtime;
mod relinearization_source_material;
mod relinearization_verification_runtime;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod resource_accounting_evidence;
mod row_code_whir;
mod runtime;
mod runtime_ffi;
mod selected_accounting;
#[cfg(test)]
mod selected_material_transport_accounting;
mod selected_profile;
mod setup_generation_runtime;
mod setup_key_relation_runtime;
mod setup_public_polynomial;
mod target_release_runtime;
mod transcript;
mod verifier;
mod vss_share_linkage_runtime;
mod zero_knowledge;

pub(crate) use aggregate_threshold_share_runtime::{
    AggregateThresholdShareGenerationMode, AggregateThresholdShareRuntimeError,
    absorb_authenticated_recipient_vss_payload, aggregate_threshold_share_runtime_error_status,
    begin_aggregate_threshold_share_recipient_authority,
    bind_generated_aggregate_threshold_share_proof_to_board,
    discard_aggregate_threshold_share_generation_board_binding_source,
    discard_aggregate_threshold_share_recipient_authority,
    discard_aggregate_threshold_share_verification_terminal_source,
    finish_aggregate_threshold_share_verification, prepare_aggregate_threshold_share_generation,
    prepare_aggregate_threshold_share_verification,
};
pub(in crate::bgv) use aggregate_threshold_share_runtime::{
    consume_verified_accepted_setup_vss_qualification,
    restore_verified_accepted_setup_vss_qualification,
    with_verified_accepted_setup_vss_package_sources,
    with_verified_accepted_setup_vss_public_randomness,
};
#[cfg(test)]
pub(crate) use ballot_validity_runtime::{
    SelectedBallotCiphertextReadbackMemoryAccounting,
    selected_ballot_ciphertext_readback_memory_accounting,
};
pub(crate) use ballot_validity_runtime::{
    VerifiedBallotCiphertextPolynomial, VerifiedBallotValidityOutput,
    consume_verified_ballot_validity_output, with_verified_ballot_validity_output,
};
#[cfg(test)]
pub(crate) use body::decode_proof_body_prefix;
pub(crate) use body::{CommonProofByteLengthCeiling, canonical_common_proof_byte_length_ceiling};
pub(crate) use body::{
    CompleteProofTreeCatalog, DecodedProofBodyPrefix, DecodedProofPhasePairLeaf, ProofBodyError,
    ProofBodyLayout, ProofTreeCatalogEntry, ProofTreeCatalogInput, ProofTreeCatalogSource,
    ProofTreeOpening, RelationProofTreeInput, StatementOwnedProofTreeInput,
    build_complete_proof_tree_catalog, decode_proof_body_prefix_owned,
    decode_proof_query_section_header_at, decode_proof_query_tree_at,
    proof_body_prefix_byte_length, proof_query_tree_byte_length,
};
pub(crate) use committed_material::CommittedMaterialTree;
pub(crate) use committed_material::{
    AuthenticatedCompactCommittedMaterialSource, CommittedMaterialContext,
    CommittedMaterialProfile, CommittedMaterialRole,
    CommittedMaterialSharedAllocationMemoryAccounting, CompactCommittedMaterialSource,
    authenticated_committed_material_shared_allocation_byte_lengths,
};
#[cfg(test)]
pub(crate) use committed_material::{CommittedMaterialError, CommittedMaterialTreeInput};
pub(crate) use component_material_stream::{
    ComponentMaterialOwnershipBinding, KeySwitchComponentMaterialTopology,
    KeySwitchComponentTraceColumn, VerifiedKeySwitchComponentMaterial,
    VerifiedKeySwitchComponentMaterialStream,
};
pub(crate) use component_public_polynomial_runtime::{
    ComponentPublicPolynomialRuntimeError,
    DescriptorAuthenticatedKeySwitchComponentPublicPolynomialStream,
    KeySwitchComponentPublicPolynomialStream, RecomputedKeySwitchComponentTree,
};
pub(crate) use decoder::{ProofByteSource, ProofDecodeError};
pub(crate) use domain::common_proof_randomness_purpose_is_assigned;
pub(crate) use evaluator_aggregate::{
    EvaluatorKeyStorePhysicalRole, SelectedEvaluatorAggregatePlanError,
    SelectedEvaluatorStoreConstruction, SelectedEvaluatorStoreConstructionOutput,
    SelectedEvaluatorStoreOutputChunk, SelectedEvaluatorStoreSource,
    SelectedEvaluatorStoreSourceCatalog, SelectedEvaluatorStoreSourceReadRequest,
    VerifiedEvaluatorKeyStoreAuxiliaryMaterial, VerifiedEvaluatorKeyStoreMaterial,
    VerifiedEvaluatorKeyStoreMaterialStream, selected_evaluator_aggregate_relation_plan,
};
pub(crate) use evaluator_aggregate_source::SelectedEvaluatorAggregateSourcePolynomialProvider;
#[cfg(test)]
pub(crate) use evaluator_aggregate_source::{
    SelectedEvaluatorAggregateSourceProviderMemoryAccounting,
    evaluator_aggregate_source_provider_memory_accounting,
};
#[cfg(test)]
pub(crate) use external_memory::ProofExternalMemoryPlan;
#[cfg(test)]
pub(crate) use external_memory::ProofExternalMemoryTransactionOperation;
pub(crate) use external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryProtection, ProofExternalMemoryTransactionAdapterError,
    ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
    ProofExternalMemoryTransactionRequest, ProofExternalMemoryUsage,
};
pub(crate) use field::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofFieldError,
};
#[cfg(test)]
pub(crate) use field::{
    PROOF_CHALLENGE_EXTENSION_POLYNOMIAL_COEFFICIENTS, validate_proof_field_profile,
};
pub(crate) use fri::{
    OpenedFriLayerPair, ProofFriError, ProofFriQueryState, ProofFriQueryVerifier,
};
pub(crate) use galois_source_material::{
    VerifiedGaloisSourceMaterialBatch, VerifiedGaloisSourceMaterialBatchPreflight,
};
pub(crate) use merkle::{
    ProofLeafVisibility, ProofMerkleError, ProofMerkleTreeContext, ProofOraclePhasePairLeaf,
    ProofTreeRole, ProofTreeValue,
};
pub(crate) use opening::{
    ProofOpeningClaimEvaluation, ProofOpeningError, evaluate_normalized_opening_claim_pair,
};
pub(crate) use polynomial::{
    ProofEvaluationDomain, ProofPolynomialError, divide_extension_polynomial_by_linear_in_place,
    evaluate_extension_at, extension_polynomial_degree, fold_extension_evaluations_in_place,
};
#[cfg(test)]
pub(crate) use profile::FIRST_PROFILE_APPLICATION_FAMILIES;
#[cfg(test)]
pub(crate) use profile::ProofProfileSet;
pub(crate) use profile::{
    COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT, PROOF_DEEP_POINT_COUNT,
    PROOF_EVALUATION_BLOWUP_FACTOR, PROOF_EVALUATION_COSET_OFFSET,
    PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT, PROOF_NON_NATIVE_ALPHA_REPETITION_COUNT,
    PROOF_NON_NATIVE_THETA_REPETITION_COUNT, PROOF_UNIQUE_QUERY_COUNT, ProofProfileError,
    ValidatedRelationPlanArtifact,
};
#[cfg(test)]
pub(crate) use prover::{
    BoundedCommonProofByteSink, CommonProofResidentMemoryPhase, PublicOnlyCommonProofCoinSource,
    ResidentCommonProofSourcePolynomialProvider, canonical_proof_object_header_bytes,
    common_proof_private_coin_coordinate_derivation_context_hash,
    construct_composed_quotient_polynomial,
    construct_constraint_stream_composed_quotient_polynomial,
    construct_pre_challenge_relation_columns, encode_common_proof_checkpoint_cursor_manifest,
    generate_common_proof,
};
pub(crate) use prover::{
    CheckpointableCommonProofPrivateCoinSource, CommonProofAuthenticatedSourceReadRequest,
    CommonProofBoundTreeLeafSaltRequest, CommonProofByteSink,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofGenerationStateMachine,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinCoordinateCapacity,
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceProviderMemoryAccounting,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PrivateRandomnessCommonProofCoinError,
    PrivateRandomnessCommonProofCoinSource, ProvidedCommonProofSourcePolynomial, apply_trace_mask,
};
#[cfg(test)]
pub(crate) use prover::{
    CommonProofAuxiliaryColumnSynthesisCursor, CommonProofPreChallengeSourceCursor,
    CommonProofPreChallengeSourcePoll, CommonProofQuotientComponentCursor,
    construct_opening_batch_mask, construct_reversed_relation_column,
};
#[cfg(test)]
pub(crate) use prover::{
    CommonProofCheckpointCursorManifestError, CommonProofCheckpointCursorManifestRequirement,
    common_proof_checkpoint_cursor_manifest_requirement_for_variant,
};
#[cfg(test)]
pub(crate) use recipient_vss_payload::selected_recipient_private_vss_payload_byte_length;
pub(crate) use recipient_vss_payload::{
    DecodedRecipientShareLimb, RecipientPrivateVssPayloadError, RecipientShareLimbInput,
    canonical_recipient_private_vss_payload, decode_recipient_private_vss_payload,
};
pub(crate) use relation_plan::{
    BallotValidityAcceptedSetupBinding, BallotValidityAdapterError,
    BallotValidityBoundPublicMaterial, BallotValidityCiphertextReadback,
    BallotValidityCiphertextStreamDecoder, BallotValidityGenerationPreparationError,
    BallotValidityPreparedProofAttempt, BallotValidityRelationPlanInput,
    BallotValidityVerifiedColumnEvaluator, BoundTreeConstructionKind, BoundTreeRootUse,
    CollectivePublicKeyAggregatePlanInput, CollectivePublicKeySetupPolynomialSource,
    CollectivePublicKeySourcePolynomialProvider, CommittedMaterialRelationPlanInput,
    CommittedMaterialSourcePolynomialAdapter, CompiledBallotValidityRelation, CompiledRelationPlan,
    CompiledTargetReleaseRelation, DeepCompositionVerificationInput,
    EvaluatorKeyAggregateEntryPlanInput, EvaluatorKeyAggregatePlanInput,
    EvaluatorKeyAggregateVariantInput, GaloisKeyShareRelationEntryInput,
    GaloisKeyShareRelationPlanInput, GaloisKeyShareSourcePolynomialAdapter,
    PublicAggregateRelationGeometry, PublicKeyShareRelationPlanInput,
    RelationApplicationChallengeAssignment, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, RelationTreeDescriptor, RelinearizationRoundOneRelationPlanInput,
    RelinearizationRoundOneSourcePolynomialAdapter,
    RelinearizationRoundTwoAuthenticatedAggregateSourcePlan,
    RelinearizationRoundTwoRelationPlanInput, RelinearizationRoundTwoSourcePolynomialAdapter,
    ResolvedSuiteModulus, RkgRoundOneAggregatePlanInput, RkgRoundOneAggregateVariantInput,
    SameSecretRelationPlanInput, SetupKeyRelationSourcePolynomialAdapter, SuiteModulusReference,
    TargetReleaseModulusWitness, TargetReleaseRelationPlanInput, TargetReleaseRoleWitness,
    TargetReleaseSourcePolynomialAdapter, TargetReleaseVerifiedColumnEvaluator,
    TargetReleaseWitnessError, TargetReleaseWitnessSource,
    TargetReleaseWitnessSourceMemoryAccounting, TrusteeEvaluationKeyRelationGeometry,
    VerifiedKeyRelationColumnEvaluator, VerifiedTargetReleaseModulusInput,
    VerifiedTargetReleaseProof, apply_negacyclic_automorphism,
    compile_aggregate_threshold_share_relation_plan, compile_ballot_validity_relation,
    compile_ballot_validity_relation_plan, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_galois_key_share_relation_plan,
    compile_galois_key_share_relation_with_source_layout, compile_public_key_share_relation_plan,
    compile_public_key_share_relation_with_source_layout,
    compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_one_relation_with_source_layout,
    compile_relinearization_round_two_relation_plan,
    compile_relinearization_round_two_relation_with_source_layout,
    compile_rkg_round_one_aggregate_relation_plan, compile_same_secret_relation_plan,
    compile_same_secret_relation_with_source_layout, compile_target_release_relation,
    compile_vss_share_linkage_relation_plan, galois_relation_tree_inputs,
    public_key_share_relation_tree_inputs, relinearization_round_one_relation_tree_inputs,
    relinearization_round_two_relation_tree_inputs, same_secret_relation_tree_inputs,
    selected_galois_key_share_batch_schedule,
};
#[cfg(test)]
pub(crate) use relation_plan::{
    SelectedBallotValidityCarrierBufferAccounting,
    selected_ballot_validity_carrier_buffer_accounting,
    target_release_source_provider_memory_accounting_for_source,
};
pub(crate) use relinearization_source_material::{
    VerifiedRelinearizationAggregateMaterial, VerifiedRelinearizationAggregateMaterialPreflight,
    VerifiedRelinearizationRoundOneSourceMaterial,
    VerifiedRelinearizationRoundOneSourceMaterialPreflight, VerifiedRelinearizationSourceMaterial,
    VerifiedRelinearizationSourceMaterialPreflight,
};
pub(in crate::bgv) use row_code_whir::VerifiedSameSecretLowDegreePrerequisite;
pub(crate) use runtime::{
    AuthenticatedCommonProofGenerationCheckpoint, BorrowedVerifiedCommonProofCapability,
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, CommonProofGenerationAuthorization,
    CommonProofGenerationExternalMemoryAccounting, CommonProofGenerationOperationHandle,
    CommonProofGenerationPreparationError, CommonProofGenerationSources,
    CommonProofGenerationWorkerError, CommonProofGenerationWorkerPoll,
    CommonProofRelationPlanCapability, CommonProofRelationPlanCapabilityError,
    CommonProofRuntimeError, CommonProofRuntimeLimits, CommonProofRuntimeRegistry,
    CommonProofSelectedSuiteCapabilityHandle, CommonProofUpstreamInputRegistry,
    CommonProofVerificationOperationHandle, CommonProofVerificationWorkerError,
    CommonProofVerificationWorkerPoll, ConsumedVerifiedCommonProofCapability,
    DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH, ExpectedCommonProofPackageBindings,
    GeneratedCommonProofCapabilityHandle, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    PendingCommonProofAuthorizationHandle, PreparedCommonProofGeneration,
    PreparedCommonProofVerification, VerifiedCommonProofCapabilityHandle,
    VerifiedCommonProofStatementSource, durable_authorization_frame_digest,
};
#[cfg(test)]
pub(crate) use runtime::{
    CommonProofApplicationBinding, CommonProofVerificationBinding, ResidentCommonProofByteSource,
    ResidentCommonProofInputChunk,
};
#[cfg(test)]
pub(crate) use runtime::{
    CommonProofGenerationAttemptStart, CommonProofGenerationCheckpointCustodyRequirement,
    CommonProofGenerationCumulativeWorkRule, CommonProofGenerationResumePrefixExecution,
    CommonProofGenerationResumeStateRestoration, common_proof_generation_attempt_topology,
    common_proof_generation_checkpoint_custody_requirement_for_variant,
};
pub(crate) use runtime_ffi::bind_generated_common_proof_to_verified_statement_source;
pub(crate) use runtime_ffi::bind_generated_common_proofs_to_verified_statement_sources;
pub(crate) use runtime_ffi::consume_verified_common_proof_with_family_terminal;
pub(crate) use runtime_ffi::preflight_and_consume_verified_common_proof_with_family_terminal;
pub(crate) use runtime_ffi::preflight_generated_common_proof_pending_package;
pub(crate) use runtime_ffi::preflight_generated_common_proof_pending_statement;
pub(crate) use runtime_ffi::preflight_verified_common_proof_pending_package;
pub(crate) use runtime_ffi::retain_common_proof_verification_family_adapter_from_upstream;
pub(crate) use runtime_ffi::retire_generated_common_proof_capabilities;
pub(crate) use runtime_ffi::runtime_error_status;
#[cfg(test)]
pub(crate) use selected_accounting::selected_complete_proof_resource_accounting;
pub(crate) use selected_accounting::{SelectedProofAccountingError, selected_proof_runtime_limits};
#[cfg(test)]
pub(crate) use selected_profile::selected_proof_profile_set;
#[cfg(test)]
pub(crate) use selected_profile::selected_target_decryption_flooding_bound;
pub(crate) use selected_profile::{
    selected_ballot_validity_relation_compilation, selected_committed_material_profile,
    selected_committed_material_relation_plan_input, selected_galois_key_share_relation_plan_input,
    selected_public_key_share_relation_plan_input, selected_relation_plan_check_context,
    selected_relation_plans, selected_relinearization_relation_plan_inputs,
    selected_same_secret_relation_plan_input, selected_target_release_relation,
};
pub(crate) use setup_generation_runtime::{
    begin_setup_generation_authority, cancel_setup_generation_public_key_share_body_by_identifier,
    cancel_setup_generation_recipient_payload,
    open_setup_generation_public_key_share_body_by_identifier,
    open_setup_generation_recipient_payload,
    read_setup_generation_public_key_share_body_by_identifier,
    read_setup_generation_recipient_payload, release_setup_generation_authority_by_identifier,
    setup_generation_public_key_share_body_byte_length_by_identifier,
    setup_generation_public_key_share_source_byte_length_by_identifier,
    setup_generation_recipient_payload_byte_length,
    setup_generation_recipient_payload_source_byte_length,
    setup_generation_recipient_payload_source_recipient_roster_position,
};
pub(crate) use setup_public_polynomial::{
    SetupPublicPolynomialContext, SetupPublicPolynomialError, SetupPublicPolynomialLeafByteBuilder,
    SetupPublicPolynomialLeafHashArena, SetupPublicPolynomialRootBuilder,
    SetupPublicPolynomialRootRole, SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput,
    WASM_SETUP_PUBLIC_POLYNOMIAL_LEAF_HASH_STATE_BYTE_LENGTH,
    setup_public_polynomial_wasm_compact_root_memory_plan,
};
#[cfg(test)]
pub(crate) use target_release_runtime::target_release_checkpoint_lineage_identifier_byte_length;
pub(crate) use transcript::{
    CommonProofChallenge, CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber,
    CommonProofTranscript, CommonProofTranscriptSchedule, TranscriptError,
    sample_relation_application_challenges,
};
#[cfg(test)]
pub(crate) use verifier::CommonProofVerificationInput;
#[cfg(test)]
pub(crate) use verifier::verify_common_proof;
pub(crate) use verifier::{
    CommonProofRequiredByteRange, CommonProofVerificationPoll,
    CommonProofVerificationResidentMemoryAccounting, CommonProofVerificationStateMachine,
    CommonProofVerifierError, PollableCommonProofVerificationInput, VerifiedCommonProof,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedEvaluatorKeyStore, VerifiedEvaluatorKeyStorePreflight,
    VerifiedEvaluatorRuntimeRoot, VerifiedRelationColumnEvaluator,
    VerifiedRelationColumnEvaluatorMemoryAccounting, VerifiedRowCodeWhirProofFacts,
    VerifiedStatementOwnedTree, VerifiedStreamedProofTreeTerminal,
    VerifiedStreamedProofTreeTerminalPreflight, verified_application_statement_hash,
};
pub(in crate::bgv) use vss_share_linkage_runtime::consume_ordered_verified_vss_share_linkage_terminals;
pub(in crate::bgv) use vss_share_linkage_runtime::with_verified_vss_share_linkage_terminal;
pub(crate) use zero_knowledge::validate_zero_knowledge_mask_image;

#[cfg(test)]
mod tests;
pub(crate) use application_statement::{
    SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, SelectedVssShareLinkageStatement,
    canonical_selected_aggregate_threshold_share_statement,
    canonical_selected_ballot_validity_statement,
    canonical_selected_collective_public_key_aggregate_statement,
    canonical_selected_galois_key_share_statement, canonical_selected_public_key_share_statement,
    canonical_selected_relinearization_round_one_aggregate_statement,
    canonical_selected_relinearization_round_one_statement,
    canonical_selected_relinearization_round_two_statement,
    canonical_selected_same_secret_statement, canonical_selected_target_share_statement,
    canonical_selected_vss_share_linkage_statement,
    decode_selected_aggregate_threshold_share_statement, decode_selected_application_statement,
    decode_selected_ballot_validity_statement,
    decode_selected_collective_public_key_aggregate_statement,
    decode_selected_galois_key_share_statement, decode_selected_public_key_share_statement,
    decode_selected_relinearization_round_one_aggregate_statement,
    decode_selected_relinearization_round_one_statement, decode_selected_same_secret_statement,
    decode_selected_vss_share_linkage_statement, selected_evaluator_aggregate_entry_roots,
    selected_evaluator_aggregate_entry_roots_in_order, selected_evaluator_entry_positions,
    selected_evaluator_galois_entry_positions, selected_evaluator_relinearization_entry_positions,
};
#[cfg(test)]
pub(crate) use application_statement::{
    SelectedEvaluatorAggregateEntryInput, canonical_selected_application_statement_for_ceiling,
    canonical_selected_evaluator_aggregate_statement,
};
