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
mod oracle_ledger;
mod polynomial;
mod profile;
mod prover;
mod qrom_soundness;
mod recipient_vss_payload;
mod relation_plan;
mod relinearization_source_material;
mod runtime;
mod runtime_ffi;
mod sampler_availability;
mod selected_accounting;
mod selected_profile;
mod setup_generation_runtime;
mod setup_public_polynomial;
mod transcript;
mod verifier;
mod vss_share_linkage_runtime;
mod zero_knowledge;

pub(crate) use aggregate_threshold_share_runtime::{
    AggregateThresholdShareGenerationMode, AggregateThresholdShareRuntimeError,
    absorb_authenticated_recipient_vss_payload,
    aggregate_threshold_share_private_randomness_kmac_input_accounting,
    aggregate_threshold_share_runtime_error_status,
    begin_aggregate_threshold_share_recipient_authority,
    bind_generated_aggregate_threshold_share_proof_to_board,
    consume_verified_accepted_setup_vss_qualification,
    discard_aggregate_threshold_share_generation_board_binding_source,
    discard_aggregate_threshold_share_recipient_authority,
    discard_aggregate_threshold_share_verification_terminal_source,
    finish_aggregate_threshold_share_verification, prepare_aggregate_threshold_share_generation,
    prepare_aggregate_threshold_share_verification,
    require_verified_recipient_vss_mailbox_envelope,
    require_verified_vss_dealer_terminals_match_public_randomness,
    restore_verified_accepted_setup_vss_qualification,
    with_verified_accepted_setup_vss_public_randomness,
};
pub(crate) use ballot_validity_runtime::{
    SelectedBallotCiphertextReadbackMemoryAccounting, VerifiedBallotCiphertextPolynomial,
    VerifiedBallotValidityOutput, consume_verified_ballot_validity_output,
    selected_ballot_ciphertext_readback_memory_accounting, with_verified_ballot_validity_output,
};
pub(crate) use body::{
    CommonProofByteLengthCeiling, DecodedProofBody, PendingProofBodyQueries,
    ProofQueryTreeByteLengthCeiling, canonical_common_proof_byte_length_ceiling,
};
pub(crate) use body::{
    CompleteProofTreeCatalog, DecodedProofBodyPrefix, DecodedProofPhasePairLeaf, ProofBodyError,
    ProofBodyLayout, ProofTreeCatalogEntry, ProofTreeCatalogInput, ProofTreeCatalogSource,
    ProofTreeOpening, RelationProofTreeInput, StatementOwnedProofTreeInput,
    build_complete_proof_tree_catalog, decode_proof_body_prefix, decode_proof_body_prefix_owned,
    decode_proof_query_section_header_at, decode_proof_query_tree_at,
    proof_body_prefix_byte_length, proof_query_tree_byte_length,
};
pub(crate) use committed_material::CommittedMaterialTree;
pub(crate) use committed_material::{
    AuthenticatedCompactCommittedMaterialSource, CommittedMaterialContext, CommittedMaterialError,
    CommittedMaterialProfile, CommittedMaterialRole, CommittedMaterialTreeInput,
    CompactCommittedMaterialSource, maximum_committed_material_inner_derivation_count,
    maximum_committed_material_kmac_input_accounting,
};
pub(crate) use component_material_stream::{
    ComponentMaterialOwnershipBinding, KeySwitchComponentMaterialTopology,
    KeySwitchComponentTraceColumn, KeySwitchComponentTraceHalf, VerifiedKeySwitchComponentMaterial,
    VerifiedKeySwitchComponentMaterialStream,
};
pub(crate) use component_public_polynomial_runtime::{
    ComponentPublicPolynomialRuntimeError, DescriptorAuthenticatedKeySwitchComponentTree,
    DescriptorAuthenticatedKeySwitchComponentPublicPolynomialStream,
    KeySwitchComponentPublicPolynomialStream, RecomputedKeySwitchComponentTree,
};
pub(crate) use decoder::{BoundedProofDecoder, ProofByteSource, ProofDecodeError};
pub(crate) use domain::{
    common_proof_randomness_purpose_is_assigned, common_proof_transcript_domain_id,
};
pub(crate) use evaluator_aggregate::{
    EvaluatorKeyStorePhysicalRole, SelectedEvaluatorAggregatePlanError,
    SelectedEvaluatorStoreConstruction, SelectedEvaluatorStoreConstructionOutput,
    SelectedEvaluatorStoreOutputChunk, SelectedEvaluatorStoreSource,
    SelectedEvaluatorStoreSourceCatalog, SelectedEvaluatorStoreSourceReadRequest,
    VerifiedEvaluatorKeyStoreAuxiliaryMaterial, VerifiedEvaluatorKeyStoreComponentMaterial,
    VerifiedEvaluatorKeyStoreMaterial, VerifiedEvaluatorKeyStoreMaterialStream,
    selected_evaluator_aggregate_relation_plan,
};
pub(crate) use evaluator_aggregate_source::{
    SelectedEvaluatorAggregateSourcePolynomialProvider,
    SelectedEvaluatorAggregateSourceProviderMemoryAccounting,
    evaluator_aggregate_source_provider_memory_accounting,
};
pub(crate) use external_memory::{
    ProofCancellation, ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryProtection, ProofExternalMemoryTransactionAdapterError,
    ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
    ProofExternalMemoryTransactionRequest,
};
#[cfg(test)]
pub(crate) use external_memory::{
    ProofExternalMemoryPlan, ProofExternalMemoryTransactionOperation, ProofExternalMemoryUsage,
};
pub(crate) use field::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, PROOF_CHALLENGE_EXTENSION_POLYNOMIAL_COEFFICIENTS,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofFieldError,
    validate_proof_field_profile,
};
pub(crate) use fri::{
    OpenedFriLayerPair, ProofFriError, ProofFriQueryState, ProofFriQueryVerifier,
};
pub(crate) use galois_source_material::{
    GaloisSourceComponentPreflightBinding, VerifiedGaloisSourceComponent,
    VerifiedGaloisSourceMaterialBatch, VerifiedGaloisSourceMaterialBatchPreflight,
};
pub(crate) use galois_key_share_runtime::{
    PendingGeneratedGaloisSource, restore_pending_generated_galois_source,
    take_pending_generated_galois_source,
};
#[cfg(test)]
pub(crate) use merkle::{CanonicalProofMerkleTree, verify_authentication_frontier};
pub(crate) use merkle::{
    ProofLeafVisibility, ProofMerkleError, ProofMerkleTreeContext, ProofOraclePhasePairLeaf,
    ProofTreeRole, ProofTreeValue, leaf_hash as canonical_merkle_leaf_hash,
    node_hash as canonical_merkle_node_hash,
};
#[cfg(test)]
pub(crate) use opening::evaluate_initial_fri_pair;
pub(crate) use opening::{
    ProofOpeningClaimEvaluation, ProofOpeningError, evaluate_normalized_opening_claim_pair,
};
pub(crate) use oracle_ledger::{
    BCS_MERKLE_STATISTICAL_PRIVACY_DENOMINATOR_EXPONENT, VerifierHashEquationLedger,
    VerifierHashEquationLedgerError, VerifierQueryTreeHashEquationLedger,
    verifier_hash_equation_ledger,
};
#[cfg(test)]
pub(crate) use polynomial::divide_extension_polynomial_by_linear;
pub(crate) use polynomial::{
    ProofEvaluationDomain, ProofPolynomialError, divide_extension_polynomial_by_linear_in_place,
    evaluate_extension_at, extension_polynomial_degree, fold_extension_evaluations,
    fold_extension_evaluations_in_place,
};
pub(crate) use profile::{
    COMMITTED_MATERIAL_PROOF_EVALUATION_BLOWUP_FACTOR, COMMITTED_MATERIAL_PROOF_UNIQUE_QUERY_COUNT,
    PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR, PROOF_EVALUATION_COSET_OFFSET,
    PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT, ProofProfileError,
    ValidatedRelationPlanArtifact,
};
pub(crate) use profile::{
    EvaluatorKeyAggregateEntryTopology, EvaluatorKeyShareSourceKind,
    FIRST_PROFILE_APPLICATION_FAMILIES, FirstProfileRootTopology, ProofFamilyProfile,
    ProofFieldProfile, ProofProfileSet, RelationRootCompatibilityEdge,
    RelationRootConstructionKind, RelationRootEndpoint,
};
pub(crate) use prover::{
    BoundedCommonProofByteSink, BoundedCommonProofByteSinkError,
    CheckpointableCommonProofPrivateCoinSource, CommonProofAuthenticatedSourceReadRequest,
    CommonProofBoundTreeLeafSaltRequest, CommonProofByteSink,
    CommonProofCheckpointCursorManifestError, CommonProofCheckpointCursorManifestRequirement,
    CommonProofColumnEvaluations, CommonProofEncodingError,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofGenerationStateMachine,
    CommonProofMerkleMaterializer, CommonProofMerkleMaterializerProgress,
    CommonProofMerkleStoragePlan, CommonProofOpeningGeometry, CommonProofOpeningPrefetchProgress,
    CommonProofOpeningPrefetcher, CommonProofPreChallengeRelationColumns,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinCoordinateCapacity,
    CommonProofPrivateCoinError, CommonProofPrivateCoinSource,
    CommonProofPrivateRandomnessAccountingError, CommonProofProverError,
    CommonProofResidentInfrastructurePayloadAccounting, CommonProofResidentMemoryPhase,
    CommonProofResidentMemoryPhasePlan, CommonProofResidentMemoryPlan, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialProviderPoll,
    CommonProofSourcePolynomialReplayIdentity, CommonProofSourcePolynomialRequest,
    CommonProofSourcePolynomialRequestContext, CommonProofTranscriptQuerySink,
    CommonProofTranscriptQuerySinkError, CommonProofTreeStorageError,
    MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHECKPOINT_CURSOR_MANIFEST_RUN_COUNT,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PrefetchedCommonProofOpeningArtifact,
    PrivateRandomnessCommonProofCoinError, PrivateRandomnessCommonProofCoinSource,
    ProvidedCommonProofSourcePolynomial, StoredCommonProofMerkleTree, apply_trace_mask,
    canonical_common_proof_query_section_header, canonical_proof_object_header_bytes,
    common_proof_checkpoint_cursor_manifest_requirement,
    common_proof_checkpoint_cursor_manifest_requirement_for_variant,
    common_proof_merkle_storage_plan, common_proof_private_coin_coordinate_derivation_context_hash,
    common_proof_private_randomness_kmac_input_accounting, common_proof_query_section_byte_length,
    construct_fri_terminal_coefficients, construct_initial_fri_polynomial,
    construct_next_fri_layer, construct_opening_batch_mask,
    construct_post_challenge_relation_columns, construct_pre_challenge_relation_columns,
    encode_common_proof_checkpoint_cursor_manifest, encode_common_proof_query_tree_fragment,
    evaluate_common_proof_tree_columns, evaluate_ordered_deep_openings,
    evaluate_pre_challenge_common_proof_tree_columns, sample_private_base_polynomial,
    sample_private_extension_polynomial, write_common_proof_prefix,
};
#[cfg(test)]
pub(crate) use prover::{
    ResidentCommonProofSourcePolynomialProvider, construct_composed_quotient_polynomial,
    construct_constraint_stream_composed_quotient_polynomial, construct_quotient_components,
    decompose_composed_quotient, generate_common_proof,
};
pub(crate) use qrom_soundness::{
    SelectedActionApplicationSoundnessAccounting, SelectedApplicationSoundnessAccounting,
    SelectedApplicationSoundnessAccountingError,
    SelectedApplicationSoundnessVariantAccounting, SelectedExactProbabilityBound,
    require_selected_application_soundness_bounds,
};
pub(crate) use recipient_vss_payload::{
    DecodedRecipientPrivateVssPayload, DecodedRecipientShareLimb, RecipientPrivateVssPayloadError,
    RecipientShareLimbInput, canonical_recipient_private_vss_payload,
    decode_recipient_private_vss_payload, selected_recipient_private_vss_payload_byte_length,
};
pub(crate) use relation_plan::{
    ApplicationExtractionError, ApplicationExtractionInput, ApplicationRootBinding,
    BallotValidityAcceptedSetupBinding, BallotValidityAdapterError,
    BallotValidityAuthenticatedCiphertext, BallotValidityBoundPublicMaterial,
    BallotValidityCiphertextReadback, BallotValidityCiphertextStreamDecoder,
    BallotValidityColumnTransform, BallotValidityEncryptionAttemptWitness,
    BallotValidityGeneratedCiphertext, BallotValidityGenerationPreparationError,
    BallotValidityPreparedProofAttempt, BallotValidityRelationPlanInput,
    BallotValiditySourceColumnRecipe, BallotValiditySourcePlan,
    BallotValiditySourcePolynomialAdapter, BallotValidityVerifiedColumnEvaluator,
    BallotValidityWitnessValueSource, BoundTreeConstructionKind, CheckedApplicationExtractionPlan,
    CollectivePublicKeyAggregatePlanInput, CommittedMaterialRelationPlanInput,
    CommittedMaterialRootTraceRows, CommittedMaterialSourcePolynomialAdapter,
    CommittedMaterialTraceWitnessProvider, CompiledBallotValidityRelation, CompiledRelationPlan,
    CompiledTargetReleaseRelation, EvaluatorKeyAggregateEntryPlanInput,
    EvaluatorKeyAggregatePlanInput, EvaluatorKeyAggregateVariantInput, ExtractedApplicationWitness,
    ExtractedLowDegreeApplicationTree, ExtractedSemanticColumn, GaloisKeyShareRelationEntryInput,
    GaloisKeyShareRelationPlanInput, GaloisKeyShareSourcePolynomialAdapter,
    PackedCommonWitnessClass, PackedCommonWitnessJoin, PublicAggregateRelationGeometry,
    PublicKeyShareRelationPlanInput, RelationApplicationChallengeAssignment,
    RelationApplicationChallengeBadSetCoordinate, RelationApplicationChallengeBadSetGroup,
    RelationApplicationDeepAllowedSetRootBound, RelationApplicationRoundByRoundTransitionCatalog,
    RelationChallengeDescriptor, RelationChallengeEpochCatalog,
    RelationChallengeEpochPrecedingMessage, RelationChallengeModulusSelector,
    RelationChallengeRole, RelationChallengeSampling, RelationColumnOrigin,
    RelationConstraintEvaluation, RelationPlanCheckContext, RelationPlanError, RelationPlanVariant,
    RelationTreeDescriptor, RelinearizationRoundOneRelationPlanInput,
    RelinearizationRoundTwoRelationPlanInput, ResolvedRelationChallengeSampling,
    ResolvedSuiteModulus, RkgRoundOneAggregatePlanInput, RkgRoundOneAggregateVariantInput,
    SameSecretRelationPlanInput, SelectedBallotValidityCarrierBufferAccounting,
    SuiteModulusReference, TargetReleaseCapabilityError, TargetReleaseModulusWitness,
    TargetReleaseRelationPlanInput, TargetReleaseRoleWitness, TargetReleaseSourcePolynomialAdapter,
    TargetReleaseVerifiedColumnEvaluator, TargetReleaseWitness, TargetReleaseWitnessError,
    TargetReleaseWitnessSource, TrusteeEvaluationKeyDecompositionBlock,
    TrusteeEvaluationKeyRelationGeometry, VerifiedTargetReleaseModulusInput,
    VerifiedKeyRelationColumnEvaluator, VerifiedTargetReleaseProof,
    apply_negacyclic_automorphism,
    ballot_encryption_private_randomness_kmac_input_accounting,
    compile_aggregate_threshold_share_relation_plan, compile_ballot_validity_relation,
    compile_ballot_validity_relation_plan, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_galois_key_share_relation_plan,
    compile_galois_key_share_relation_with_source_layout, compile_public_key_share_relation_plan,
    compile_public_key_share_relation_with_source_layout,
    compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_two_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_same_secret_relation_with_source_layout,
    compile_target_release_relation,
    compile_target_release_relation_plan, compile_vss_share_linkage_relation_plan,
    derive_aggregate_threshold_share_trace_witness_provider,
    derive_owned_aggregate_threshold_share_trace_witness_provider,
    derive_owned_vss_share_linkage_trace_witness_provider,
    derive_vss_share_linkage_trace_witness_provider, galois_relation_tree_inputs,
    merge_checked_relation_plan_variants, proof_created_relation_tree_inputs_from_checked_variant,
    selected_ballot_validity_carrier_buffer_accounting, selected_galois_key_share_batch_schedule,
};
pub(crate) use relinearization_source_material::{
    VerifiedRelinearizationAggregateMaterial, VerifiedRelinearizationRoundOneSourceMaterial,
    VerifiedRelinearizationSourceMaterial, selected_relinearization_source_position,
};
pub(crate) use runtime::{
    AuthenticatedCommonProofGenerationCheckpoint, BorrowedVerifiedCommonProofCapability,
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, CommonProofApplicationBinding,
    CommonProofApplicationInputCapabilityHandle,
    CommonProofAuthenticatedLedgerHeadCapabilityHandle,
    CommonProofAuthenticatedLedgerTransitionCapabilityHandle,
    CommonProofEvaluatorAuxiliaryRootCapabilityHandle, CommonProofGenerationAuthorization,
    CommonProofGenerationCheckpointCustodyRequirement, CommonProofGenerationOperationHandle,
    CommonProofGenerationPreparationError, CommonProofGenerationSourceError,
    CommonProofGenerationSources, CommonProofGenerationWorkerError,
    CommonProofGenerationWorkerPoll, CommonProofPreverificationApplicationSourceHandle,
    CommonProofRelationPlanCapability, CommonProofRelationPlanCapabilityError,
    CommonProofRuntimeCancellation, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofRuntimeRegistry, CommonProofSelectedSuiteCapabilityHandle,
    CommonProofStorageTransactionRuntime, CommonProofUpstreamInputRegistry,
    CommonProofVerificationBinding,
    CommonProofVerificationOperationHandle, CommonProofVerificationWorkerError,
    CommonProofVerificationWorkerPoll, CommonProofVerifiedColumnEvaluatorCapabilityHandle,
    ConsumedCommonProofVerificationInputs, ConsumedVerifiedCommonProofCapability,
    DURABLE_AUTHORIZATION_FRAME_BYTE_LENGTH, GeneratedCommonProofCapabilityHandle,
    MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS, PendingCommonProofAuthorizationHandle,
    PollableCommonProofByteSink, PollableCommonProofByteSinkError,
    PreparedCommonProofAuthorization, PreparedCommonProofGeneration,
    PreparedCommonProofVerification, VerifiedCommonProofCapabilityHandle,
    VerifiedCommonProofStatementSource,
    common_proof_generation_checkpoint_custody_requirement_for_variant,
    durable_authorization_frame_digest,
};
#[cfg(test)]
pub(crate) use runtime::{ResidentCommonProofByteSource, ResidentCommonProofInputChunk};
pub(crate) use runtime_ffi::consume_verified_common_proof_with_family_terminal;
pub(crate) use runtime_ffi::bind_generated_common_proof_to_verified_statement_source;
pub(crate) use runtime_ffi::bind_generated_common_proofs_to_verified_statement_sources;
pub(crate) use runtime_ffi::preflight_and_consume_verified_common_proof_with_family_terminal;
pub(crate) use runtime_ffi::preflight_generated_common_proof_pending_statement;
pub(crate) use runtime_ffi::release_generated_common_proof_capability;
pub(crate) use runtime_ffi::retire_generated_common_proof_capabilities;
pub(crate) use runtime_ffi::retain_common_proof_verification_family_adapter_from_upstream;
pub(crate) use runtime_ffi::runtime_error_status;
pub(crate) use runtime_ffi::with_common_proof_selected_suite;
pub(crate) use sampler_availability::{
    CommonProofDeepSamplerAvailabilityAccounting,
    CommonProofExtensionSamplerAvailabilityAccounting,
    CommonProofProductSamplerAvailabilityAccounting,
    CommonProofQueryVectorSamplerAvailabilityAccounting,
    CommonProofSamplerAvailabilityAccounting, CommonProofSamplerAvailabilityAccountingError,
    CommonProofSamplerExhaustionProbabilityBound, SelectedActionSamplerAvailabilityAccounting,
    SelectedProofSamplerAvailabilityVariantAccounting,
    selected_complete_action_sampler_availability_accounting,
};
pub(crate) use selected_accounting::{
    SelectedCompleteActionByteAccounting, SelectedCompleteActionByteAccountingInput,
    SelectedCompleteActionCorpusOwner, SelectedCompleteActionCorpusOwnerByteAccounting,
    SelectedProofAccountingError, SelectedProofByteAccounting,
    selected_complete_action_byte_accounting, selected_proof_byte_accounting,
    selected_proof_runtime_limits,
};
#[cfg(test)]
pub(crate) use selected_accounting::selected_complete_action_byte_accounting_diagnostic_json;
pub(crate) use selected_profile::{
    SelectedRelationApplicationRoundByRoundNumericalBounds,
    SelectedRelationApplicationRoundByRoundTheoremInput, SelectedRoundByRoundProbabilityBound,
    selected_ballot_validity_relation_compilation, selected_committed_material_profile,
    selected_committed_material_relation_plan_input, selected_galois_key_share_relation_plan_input,
    selected_multiplicity_weighted_round_by_round_error_bound, selected_proof_profile_set,
    selected_public_key_share_relation_plan_input,
    selected_relation_application_round_by_round_theorem_inputs,
    selected_relation_plan_check_context, selected_relation_plans,
    selected_same_secret_relation_plan_input,
    selected_target_decryption_flooding_bound,
};
pub(crate) use setup_generation_runtime::{
    begin_setup_generation_authority, cancel_setup_generation_recipient_payload,
    open_setup_generation_recipient_payload, read_setup_generation_recipient_payload,
    release_setup_generation_authority_by_identifier,
    setup_generation_recipient_payload_byte_length,
    setup_generation_recipient_payload_source_byte_length,
    setup_generation_recipient_payload_source_recipient_roster_position,
};
pub(crate) use setup_public_polynomial::{
    SetupPublicPolynomialContext, SetupPublicPolynomialError, SetupPublicPolynomialRootRole,
    SetupPublicPolynomialTree, SetupPublicPolynomialTreeInput,
};
pub(crate) use transcript::{
    CanonicalProofTranscript, CanonicalTranscriptEngine, CommonProofApplicationChallengeGroup,
    CommonProofApplicationChallengeSamplerAccounting, CommonProofChallenge, CommonProofPrivacyMode,
    CommonProofQueryOpeningAbsorber, CommonProofRound, CommonProofTranscript,
    CommonProofTranscriptSchedule, TranscriptError,
};
#[cfg(test)]
pub(crate) use verifier::verify_common_proof;
pub(crate) use verifier::{
    CommonProofRequiredByteRange, CommonProofVerificationInput, CommonProofVerificationPoll,
    CommonProofVerificationStateMachine, CommonProofVerifierError,
    PollableCommonProofVerificationInput, VerifiedCommonProof, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedEvaluatorKeyStore, VerifiedEvaluatorRuntimeRoot, VerifiedRelationColumnEvaluator,
    VerifiedStatementOwnedTree, VerifiedStreamedProofTreeTerminal,
    VerifiedStreamedProofTreeTerminalPreflight,
    verified_application_statement_hash,
};
pub(crate) use vss_share_linkage_runtime::{
    consume_ordered_verified_vss_share_linkage_terminals,
    consume_verified_vss_share_linkage_terminal,
};
pub(crate) use zero_knowledge::validate_zero_knowledge_mask_image;

#[cfg(test)]
mod tests;
pub(crate) use application_statement::{
    SelectedAggregateThresholdShareStatement, SelectedApplicationStatementContext,
    SelectedBallotValidityStatement, SelectedCollectivePublicKeyAggregateStatement,
    SelectedEvaluatorAggregateEntryInput, SelectedEvaluatorAggregateEntryRoots,
    SelectedEvaluatorEntryKind, SelectedEvaluatorEntryPosition, SelectedGaloisKeyShareStatement,
    SelectedPublicKeyShareStatement, SelectedRelinearizationRoundOneAggregateStatement,
    SelectedRelinearizationRoundOneStatement, SelectedSameSecretStatement,
    SelectedVssShareLinkageStatement, canonical_selected_aggregate_threshold_share_statement,
    canonical_selected_application_statement_for_ceiling,
    canonical_selected_ballot_validity_statement, canonical_selected_evaluator_aggregate_statement,
    canonical_selected_collective_public_key_aggregate_statement,
    canonical_selected_galois_key_share_statement, canonical_selected_public_key_share_statement,
    canonical_selected_relinearization_round_one_aggregate_statement,
    canonical_selected_relinearization_round_one_statement,
    canonical_selected_same_secret_statement, canonical_selected_target_share_statement,
    canonical_selected_vss_share_linkage_statement,
    decode_selected_aggregate_threshold_share_statement, decode_selected_application_statement,
    decode_selected_ballot_validity_statement,
    decode_selected_collective_public_key_aggregate_statement,
    decode_selected_galois_key_share_statement, decode_selected_public_key_share_statement,
    decode_selected_relinearization_round_one_aggregate_statement,
    decode_selected_relinearization_round_one_statement, decode_selected_same_secret_statement,
    decode_selected_vss_share_linkage_statement, selected_evaluator_aggregate_entry_roots,
    selected_evaluator_aggregate_entry_roots_in_order, selected_evaluator_entry_position,
    selected_evaluator_entry_positions, selected_evaluator_galois_entry_positions,
    selected_evaluator_relinearization_entry_positions,
    selected_galois_key_share_contribution_roots,
};
