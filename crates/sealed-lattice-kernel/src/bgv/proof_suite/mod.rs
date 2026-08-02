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
mod galois_key_share_runtime;
mod galois_source_material;
mod merkle;
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
    cancel_aggregate_threshold_share_private_share_acceptance_carrier,
    discard_aggregate_threshold_share_generation_board_binding_source,
    discard_aggregate_threshold_share_recipient_authority,
    discard_aggregate_threshold_share_verification_terminal_source,
    finish_aggregate_threshold_share_private_share_acceptance_carrier,
    finish_aggregate_threshold_share_verification, prepare_aggregate_threshold_share_generation,
    prepare_aggregate_threshold_share_private_share_acceptance_carrier,
    prepare_aggregate_threshold_share_verification,
};
pub(in crate::bgv) use aggregate_threshold_share_runtime::{
    consume_verified_accepted_setup_vss_qualification,
    restore_verified_accepted_setup_vss_qualification,
    with_verified_accepted_setup_vss_package_sources,
    with_verified_accepted_setup_vss_public_randomness,
};
pub(crate) use ballot_validity_runtime::{
    VerifiedBallotCiphertextPolynomial, VerifiedBallotValidityOutput,
    consume_verified_ballot_validity_output, with_verified_ballot_validity_output,
};
pub(crate) use body::{
    ProofBodyError, ProofTreeCatalogEntry, RelationProofTreeInput, StatementOwnedProofTreeInput,
    build_relation_bound_public_tree_catalog_entries,
};
pub(crate) use committed_material::CommittedMaterialTree;
#[cfg(test)]
pub(crate) use committed_material::CommittedMaterialTreeInput;
pub(crate) use committed_material::{
    AuthenticatedCompactCommittedMaterialSource, CommittedMaterialContext,
    CommittedMaterialProfile, CommittedMaterialRole,
    CommittedMaterialSharedAllocationMemoryAccounting, CompactCommittedMaterialSource,
    authenticated_committed_material_shared_allocation_byte_lengths,
};
#[cfg(all(test, feature = "theorem-evidence"))]
pub(crate) use committed_material::{
    CommittedMaterialPrivateDerivationDescription,
    committed_material_private_derivation_description,
};
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
pub(crate) use external_memory::ProofExternalMemoryObjectPlan;
#[cfg(test)]
pub(crate) use external_memory::ProofExternalMemoryPlan;
#[cfg(test)]
pub(crate) use external_memory::ProofExternalMemoryTransactionOperation;
pub(crate) use external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryProtection,
    ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionRecorder,
    ProofExternalMemoryTransactionReplay, ProofExternalMemoryTransactionRequest,
    ProofExternalMemoryUsage,
};
#[cfg(test)]
pub(crate) use field::validate_proof_field_profile;
pub(crate) use field::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofFieldError,
};
pub(crate) use galois_source_material::{
    VerifiedGaloisSourceMaterialBatch, VerifiedGaloisSourceMaterialBatchPreflight,
};
pub(crate) use merkle::{ProofLeafVisibility, ProofTreeRole, ProofTreeValue};
pub(crate) use polynomial::{ProofEvaluationDomain, ProofPolynomialError, evaluate_extension_at};
#[cfg(test)]
pub(crate) use profile::FIRST_PROFILE_APPLICATION_FAMILIES;
#[cfg(test)]
pub(crate) use profile::ProofProfileSet;
pub(crate) use profile::{
    PROOF_EVALUATION_COSET_OFFSET, PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_ALPHA_REPETITION_COUNT, PROOF_NON_NATIVE_THETA_REPETITION_COUNT,
    PROOF_OUT_OF_DOMAIN_POINT_COUNT, ProofProfileError, ValidatedRelationPlanArtifact,
    verify_canonical_proof_profile_set,
};
#[cfg(all(test, feature = "theorem-evidence"))]
pub(crate) use profile::{
    SelectedSameSecretPersistentMaskImageAccounting,
    selected_same_secret_persistent_mask_image_accounting,
};
#[cfg(test)]
pub(crate) use prover::common_proof_checkpoint_cursor_manifest_requirement_for_variant;
#[cfg(test)]
pub(crate) use prover::{
    AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
};
pub(crate) use prover::{
    CheckpointableCommonProofPrivateCoinSource, CommonProofAuthenticatedSourceReadRequest,
    CommonProofBoundTreeLeafSaltRequest, CommonProofByteSink,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofPrivateCoinCoordinate,
    CommonProofPrivateCoinCoordinateCapacity, CommonProofPrivateCoinSource, CommonProofProverError,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialReplayIdentity,
    CommonProofSourcePolynomialRequest, CommonProofSourcePolynomialRequestContext,
    CommonProofSourceProviderMemoryAccounting, CommonProofSourceReplayIdentityCatalog,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PrivateRandomnessCommonProofCoinError,
    PrivateRandomnessCommonProofCoinSource, ProvidedCommonProofSourcePolynomial, apply_trace_mask,
    canonical_proof_object_header_bytes, construct_opening_batch_mask,
};
#[cfg(test)]
pub(crate) use prover::{
    CommonProofAuxiliaryColumnSynthesisCursor, CommonProofPreChallengeSourceCursor,
    CommonProofPreChallengeSourcePoll, CommonProofQuotientComponentCursor,
    construct_reversed_relation_column,
};
#[cfg(test)]
pub(crate) use prover::{
    CommonProofPrivateCoinSamplingCatalog, CommonProofPrivateCoinSamplingOperation,
    RecordingCommonProofPrivateCoinSource,
    common_proof_private_coin_coordinate_derivation_context_hash,
    construct_pre_challenge_relation_columns, encode_common_proof_checkpoint_cursor_manifest,
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
    CompiledTargetReleaseRelation, EvaluatorKeyAggregateEntryPlanInput,
    EvaluatorKeyAggregatePlanInput, EvaluatorKeyAggregateVariantInput,
    GaloisKeyShareRelationEntryInput, GaloisKeyShareRelationPlanInput,
    GaloisKeyShareSourcePolynomialAdapter, OutOfDomainCompositionVerificationInput,
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
pub(in crate::bgv) use row_code_whir::exact_same_secret_verification_runtime_limits;
pub(in crate::bgv::proof_suite) use row_code_whir::{
    ExactSameSecretAuthenticatedTranscriptPrefixRequest, PreparedExactSameSecretTranscriptPrefix,
};
#[cfg(test)]
pub(crate) use runtime::MAXIMUM_COMMON_PROOF_GENERATION_CURSOR_MANIFEST_BYTE_LENGTH;
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
pub(crate) use setup_key_relation_runtime::{
    consume_reserved_setup_key_relation_generation_statement_source,
    require_reserved_setup_key_relation_generation_statement_source,
    reserve_setup_key_relation_generation_statement_source,
    restore_setup_key_relation_generation_statement_source,
};
pub(crate) use setup_public_polynomial::{
    SetupPublicPolynomialContext, SetupPublicPolynomialError, SetupPublicPolynomialRootBuilder,
    SetupPublicPolynomialRootRole, SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput,
    setup_public_polynomial_wasm_compact_root_memory_plan,
};
#[cfg(test)]
pub(crate) use target_release_runtime::target_release_checkpoint_lineage_identifier_byte_length;
#[cfg(test)]
pub(crate) use transcript::CommonProofChallenge;
pub(crate) use transcript::{CommonProofTranscript, sample_relation_application_challenges};
pub(crate) use verifier::{
    CommonProofRequiredByteRange, CommonProofVerifierError,
    IncrementalExpectedProofObjectHeaderComparator, VerifiedCommonProof,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedEvaluatorKeyStore, VerifiedEvaluatorKeyStorePreflight,
    VerifiedEvaluatorRuntimeRoot, VerifiedRelationColumnEvaluator,
    VerifiedRelationColumnEvaluatorMemoryAccounting, VerifiedRowCodeWhirProofFacts,
    VerifiedStatementOwnedTree, VerifiedStreamedProofTreeTerminal,
    VerifiedStreamedProofTreeTerminalPreflight, decode_application_statement,
    derive_relation_tree_inputs, validate_evaluator_auxiliary_root_linkage,
    verified_application_statement_hash, verify_out_of_domain_composition_with_verified_sequences,
};
pub(in crate::bgv) use vss_share_linkage_runtime::consume_ordered_verified_vss_share_linkage_terminals;
pub(in crate::bgv) use vss_share_linkage_runtime::{
    attach_verified_vss_low_degree_evidence_to_same_secret_generation,
    consume_attached_verified_vss_low_degree_evidence, consume_verified_vss_low_degree_evidence,
    detach_verified_vss_low_degree_evidence_from_same_secret_generation,
    with_attached_verified_vss_low_degree_evidence,
};
pub(crate) use zero_knowledge::validate_zero_knowledge_mask_image;
#[cfg(all(test, feature = "theorem-evidence"))]
pub(in crate::bgv::proof_suite) use zero_knowledge::{
    ConstructionMaskDependency, ConstructionMaskResumeRule, ConstructionMaskSourceAuthority,
    ConstructionMaskSourceDescriptor, ConstructionMaskSourceIdentifier,
    ConstructionMaskSourceLifetime, ConstructionMaskingCertificate,
    ConstructionMaskingCorrespondence, ConstructionMaskingPhase, ConstructionMaskingRankKind,
    ConstructionMaskingRankRequirement, ConstructionMaskingRankVerification,
    ConstructionSecretViewAlgebra, ConstructionSecretViewDescriptor,
    ConstructionSecretViewIdentifier, TraceMaskObservationCoordinateCatalog,
    TraceMaskSurjectivityCertificate, checked_construction_masking_correspondence_for_parameters,
    checked_zero_knowledge_mask_image_for_parameters,
};

#[cfg(test)]
pub(crate) use application_statement::canonical_selected_application_statement_for_ceiling;
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
    decode_selected_vss_share_linkage_statement, selected_evaluator_aggregate_entry_roots_in_order,
    selected_evaluator_entry_positions, selected_evaluator_galois_entry_positions,
    selected_evaluator_relinearization_entry_positions,
};
