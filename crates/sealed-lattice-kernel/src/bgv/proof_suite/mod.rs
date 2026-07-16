//! Shared proof primitives and deterministic transcript-domain bindings.

mod application_statement;
mod body;
mod committed_material;
mod component_material_stream;
mod decoder;
mod domain;
mod external_memory;
mod external_polynomial;
mod field;
mod fri;
mod merkle;
mod opening;
mod polynomial;
mod profile;
mod prover;
mod relation_plan;
mod runtime;
mod runtime_ffi;
#[cfg(test)]
mod selected_accounting;
mod selected_profile;
mod setup_public_polynomial;
mod transcript;
mod verifier;
mod zero_knowledge;

#[cfg(test)]
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
#[cfg(test)]
pub(crate) use committed_material::{
    CommittedMaterialBoundOpeningProvider, CommittedMaterialError, CommittedMaterialProfile,
    CommittedMaterialTreeInput,
};
pub(crate) use decoder::{BoundedProofDecoder, ProofByteSource, ProofDecodeError};
pub(crate) use domain::{
    common_proof_randomness_purpose_is_assigned, common_proof_transcript_domain_id,
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
#[cfg(test)]
pub(crate) use merkle::{
    CanonicalProofMerkleTree, ProofAuthenticationNode, verify_authentication_frontier,
};
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
#[cfg(test)]
pub(crate) use polynomial::divide_extension_polynomial_by_linear;
pub(crate) use polynomial::{
    ProofEvaluationDomain, ProofPolynomialError, divide_extension_polynomial_by_linear_in_place,
    evaluate_extension_at, extension_polynomial_degree, fold_extension_evaluations,
    fold_extension_evaluations_in_place,
};
#[cfg(test)]
pub(crate) use profile::{
    EvaluatorKeyAggregateEntryTopology, EvaluatorKeyShareSourceKind,
    FIRST_PROFILE_APPLICATION_FAMILIES, FirstProfileRootTopology, ProofFamilyProfile,
    ProofFieldProfile, ProofProfileSet, RelationRootCompatibilityEdge,
    RelationRootConstructionKind, RelationRootEndpoint,
};
pub(crate) use profile::{
    PROOF_DEEP_POINT_COUNT, PROOF_EVALUATION_BLOWUP_FACTOR, PROOF_EVALUATION_COSET_OFFSET,
    PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT, ProofProfileError,
    ValidatedRelationPlanArtifact,
};
pub(crate) use prover::{
    BoundedCommonProofByteSink, BoundedCommonProofByteSinkError,
    CheckpointableCommonProofPrivateCoinSource, CommonProofBoundOpeningProvider,
    CommonProofByteSink, CommonProofColumnEvaluations, CommonProofEncodingError,
    CommonProofGenerationCheckpointBoundary, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofGenerationStateMachine,
    CommonProofMerkleMaterializer, CommonProofMerkleMaterializerProgress,
    CommonProofMerkleStoragePlan, CommonProofOpeningArtifact, CommonProofOpeningGeometry,
    CommonProofOpeningPrefetchProgress, CommonProofOpeningPrefetcher,
    CommonProofPreChallengeRelationColumns, CommonProofPrivateCoinError,
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofResidentMemoryPhase,
    CommonProofResidentMemoryPhasePlan, CommonProofResidentMemoryPlan, CommonProofSourcePolynomial,
    CommonProofTranscriptQuerySink, CommonProofTranscriptQuerySinkError,
    CommonProofTreeStorageError, MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
    PrefetchedCommonProofOpeningArtifact, PrivateRandomnessCommonProofCoinError,
    PrivateRandomnessCommonProofCoinSource, StoredCommonProofMerkleTree,
    StoredCommonProofOpeningArtifact, apply_trace_mask,
    canonical_common_proof_query_section_header, canonical_proof_object_header_bytes,
    common_proof_merkle_storage_plan, common_proof_query_section_byte_length,
    construct_fri_terminal_coefficients, construct_initial_fri_polynomial,
    construct_next_fri_layer, construct_opening_batch_mask,
    construct_post_challenge_relation_columns, construct_pre_challenge_relation_columns,
    encode_common_proof_query_tree_fragment, evaluate_common_proof_tree_columns,
    evaluate_ordered_deep_openings, evaluate_pre_challenge_common_proof_tree_columns,
    sample_private_base_polynomial, sample_private_extension_polynomial, write_common_proof_prefix,
};
#[cfg(test)]
pub(crate) use prover::{
    construct_composed_quotient_polynomial, construct_quotient_components,
    decompose_composed_quotient, generate_common_proof,
};
pub(crate) use relation_plan::{
    BallotValidityRelationPlanInput, CollectivePublicKeyAggregatePlanInput,
    CommittedMaterialRelationPlanInput, CompiledRelationPlan, CompiledTargetReleaseRelation,
    EvaluatorKeyAggregateEntryPlanInput, EvaluatorKeyAggregatePlanInput,
    EvaluatorKeyAggregateVariantInput, GaloisKeyShareRelationPlanInput,
    PublicAggregateRelationGeometry, PublicKeyShareRelationPlanInput,
    RelationApplicationChallengeAssignment, RelationChallengeDescriptor,
    RelationChallengeEpochCatalog, RelationChallengeEpochPrecedingMessage,
    RelationChallengeModulusSelector, RelationChallengeRole, RelationChallengeSampling,
    RelationConstraintEvaluation, RelationPlanCheckContext, RelationPlanError, RelationPlanVariant,
    RelinearizationRoundOneRelationPlanInput, RelinearizationRoundTwoRelationPlanInput,
    ResolvedRelationChallengeSampling, ResolvedSuiteModulus, RkgRoundOneAggregatePlanInput,
    RkgRoundOneAggregateVariantInput, SameSecretRelationPlanInput, SuiteModulusReference,
    TargetReleaseCapabilityError, TargetReleaseModulusWitness, TargetReleaseRelationPlanInput,
    TargetReleaseRoleWitness, TargetReleaseVerifiedColumnEvaluator, TargetReleaseWitness,
    TargetReleaseWitnessError, TrusteeEvaluationKeyDecompositionBlock,
    TrusteeEvaluationKeyRelationGeometry, VerifiedTargetReleaseModulusInput,
    VerifiedTargetReleaseProof, compile_aggregate_threshold_share_relation_plan,
    compile_ballot_validity_relation_plan, compile_collective_public_key_aggregate_relation_plan,
    compile_evaluator_key_aggregate_relation_plan, compile_galois_key_share_relation_plan,
    compile_public_key_share_relation_plan, compile_relinearization_round_one_relation_plan,
    compile_relinearization_round_two_relation_plan, compile_rkg_round_one_aggregate_relation_plan,
    compile_same_secret_relation_plan, compile_target_release_relation,
    compile_target_release_relation_plan, compile_vss_share_linkage_relation_plan,
    merge_checked_relation_plan_variants,
};
pub(crate) use runtime::{
    COMMON_PROOF_CHECKPOINT_STATE_BYTE_LENGTH, CommonProofApplicationBinding,
    CommonProofApplicationInputCapabilityHandle,
    CommonProofAuthenticatedLedgerHeadCapabilityHandle,
    CommonProofAuthenticatedLedgerTransitionCapabilityHandle,
    CommonProofEvaluatorAuxiliaryRootCapabilityHandle, CommonProofGenerationOperationHandle,
    CommonProofGenerationPreparationError, CommonProofGenerationSourceError,
    CommonProofGenerationSources, CommonProofGenerationWorkerError,
    CommonProofGenerationWorkerPoll, CommonProofPreverificationApplicationSourceHandle,
    CommonProofRelationPlanCapability, CommonProofRelationPlanCapabilityError,
    CommonProofRuntimeCancellation, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofRuntimeRegistry, CommonProofSelectedSuiteCapabilityHandle,
    CommonProofStatementTreeCapabilityHandle, CommonProofStorageTransactionRuntime,
    CommonProofUpstreamInputRegistry, CommonProofVerificationBinding,
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
    VerifiedCommonProofStatementSource, durable_authorization_frame_digest,
};
#[cfg(test)]
pub(crate) use runtime::{ResidentCommonProofByteSource, ResidentCommonProofInputChunk};
#[cfg(test)]
pub(crate) use selected_accounting::{
    SelectedProofAccountingError, SelectedProofByteAccounting, SelectedProofVariantByteCeiling,
    selected_proof_byte_accounting,
};
pub(crate) use selected_profile::selected_relation_plan_check_context;
#[cfg(test)]
pub(crate) use selected_profile::{
    selected_committed_material_profile, selected_proof_profile_set,
    selected_target_decryption_flooding_bound,
};
pub(crate) use setup_public_polynomial::{
    SetupPublicPolynomialBoundOpeningProvider, SetupPublicPolynomialContext,
    SetupPublicPolynomialError, SetupPublicPolynomialRootRole, SetupPublicPolynomialTree,
    SetupPublicPolynomialTreeInput,
};
pub(crate) use transcript::{
    CanonicalProofTranscript, CanonicalTranscriptEngine, CommonProofApplicationChallengeGroup,
    CommonProofChallenge, CommonProofPrivacyMode, CommonProofQueryOpeningAbsorber,
    CommonProofRound, CommonProofTranscript, CommonProofTranscriptSchedule, TranscriptError,
};
#[cfg(test)]
pub(crate) use verifier::verify_common_proof;
pub(crate) use verifier::{
    CommonProofRequiredByteRange, CommonProofVerificationInput, CommonProofVerificationPoll,
    CommonProofVerificationStateMachine, CommonProofVerifierError,
    PollableCommonProofVerificationInput, VerifiedCommonProof, VerifiedEvaluatorAggregateEntry,
    VerifiedEvaluatorAuxiliaryRoot, VerifiedEvaluatorKeyStore, VerifiedRelationColumnEvaluator,
    VerifiedStatementOwnedTree, verified_application_statement_hash,
};
pub(crate) use zero_knowledge::validate_zero_knowledge_mask_image;

#[cfg(test)]
mod tests;
pub(crate) use application_statement::{
    SelectedApplicationStatementContext, SelectedEvaluatorAggregateEntryInput,
    SelectedEvaluatorAggregateEntryRoots, SelectedEvaluatorEntryKind,
    SelectedEvaluatorEntryPosition, canonical_selected_application_statement_for_ceiling,
    canonical_selected_evaluator_aggregate_statement, decode_selected_application_statement,
    selected_evaluator_aggregate_entry_roots, selected_evaluator_entry_position,
    selected_evaluator_entry_positions,
};
