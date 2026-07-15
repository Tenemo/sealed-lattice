//! Shared proof primitives and deterministic transcript-domain bindings.

mod body;
mod committed_material;
mod decoder;
mod domain;
mod external_memory;
mod field;
mod fri;
mod merkle;
mod opening;
mod polynomial;
mod profile;
mod prover;
mod relation_plan;
mod runtime;
mod selected_profile;
mod setup_public_polynomial;
mod transcript;
mod verifier;
mod zero_knowledge;

pub(crate) use body::{
    CompleteProofTreeCatalog, DecodedProofBody, DecodedProofBodyPrefix,
    DecodedProofPhasePairLeaf, PendingProofBodyQueries, ProofBodyError, ProofBodyLayout,
    ProofTreeCatalogEntry, ProofTreeCatalogInput, ProofTreeCatalogSource, ProofTreeOpening,
    RelationProofTreeInput, StatementOwnedProofTreeInput, build_complete_proof_tree_catalog,
    decode_proof_body_prefix, decode_proof_body_prefix_owned,
    decode_proof_query_section_header_at, decode_proof_query_tree_at,
    proof_body_prefix_byte_length,
};
pub(crate) use committed_material::{
    CommittedMaterialBoundOpeningProvider, CommittedMaterialError, CommittedMaterialProfile,
    CommittedMaterialTree, CommittedMaterialTreeInput,
};
pub(crate) use decoder::{BoundedProofDecoder, ProofByteSource, ProofDecodeError};
pub(crate) use domain::{
    common_proof_randomness_purpose_is_assigned, common_proof_transcript_domain_id,
};
pub(crate) use external_memory::{
    ProofCancellation, ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
    ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionOperation,
    ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
    ProofExternalMemoryTransactionRequest, ProofExternalMemoryUsage,
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
pub(crate) use merkle::{
    CanonicalProofMerkleTree, ProofAuthenticationNode, ProofLeafVisibility, ProofMerkleError,
    ProofMerkleTreeContext, ProofOraclePhasePairLeaf, ProofTreeRole, ProofTreeValue,
    leaf_hash as canonical_merkle_leaf_hash, node_hash as canonical_merkle_node_hash,
    verify_authentication_frontier,
};
pub(crate) use opening::{
    ProofOpeningClaimEvaluation, ProofOpeningError, evaluate_initial_fri_pair,
    evaluate_normalized_opening_claim_pair,
};
pub(crate) use polynomial::{
    ProofEvaluationDomain, ProofPolynomialError, divide_extension_polynomial_by_linear,
    evaluate_extension_at, extension_polynomial_degree, fold_extension_evaluations,
};
pub(crate) use profile::{
    EvaluatorKeyAggregateEntryTopology, EvaluatorKeyShareSourceKind,
    FIRST_PROFILE_APPLICATION_FAMILIES, FirstProfileRootTopology, PROOF_DEEP_POINT_COUNT,
    PROOF_EVALUATION_BLOWUP_FACTOR, PROOF_EVALUATION_COSET_OFFSET,
    PROOF_FINAL_POLYNOMIAL_DEGREE_BOUND_EXCLUSIVE,
    PROOF_MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT,
    PROOF_NON_NATIVE_IDENTITY_CHALLENGE_COUNT, PROOF_UNIQUE_QUERY_COUNT, ProofFamilyProfile,
    ProofFieldProfile, ProofProfileError, ProofProfileSet, RelationRootCompatibilityEdge,
    RelationRootConstructionKind, RelationRootEndpoint, ValidatedRelationPlanArtifact,
};
pub(crate) use prover::{
    BoundedCommonProofByteSink, BoundedCommonProofByteSinkError, CommonProofBoundOpeningProvider,
    CommonProofByteSink, CommonProofColumnEvaluations, CommonProofEncodingError,
    CommonProofGenerationError, CommonProofGenerationInput, CommonProofMerkleMaterializer,
    CommonProofMerkleMaterializerProgress, CommonProofMerkleStoragePlan,
    CommonProofOpeningArtifact, CommonProofOpeningGeometry, CommonProofOpeningPrefetchProgress,
    CommonProofOpeningPrefetcher, CommonProofPreChallengeRelationColumns,
    CommonProofPrivateCoinError, CommonProofPrivateCoinSource, CommonProofProverError,
    CommonProofQuerySectionWriter, CommonProofSourcePolynomial, CommonProofTranscriptQuerySink,
    CommonProofTranscriptQuerySinkError, CommonProofTreeStorageError,
    PrefetchedCommonProofOpeningArtifact, PrivateRandomnessCommonProofCoinError,
    PrivateRandomnessCommonProofCoinSource, StoredCommonProofMerkleTree,
    StoredCommonProofOpeningArtifact, apply_trace_mask,
    canonical_common_proof_query_section_header, canonical_proof_object_header_bytes,
    common_proof_merkle_storage_plan, common_proof_phase_pair_values,
    common_proof_query_section_byte_length, construct_composed_quotient_polynomial,
    construct_fri_terminal_coefficients, construct_initial_fri_polynomial,
    construct_next_fri_layer, construct_opening_batch_mask,
    construct_post_challenge_relation_columns, construct_pre_challenge_relation_columns,
    construct_quotient_components, decompose_composed_quotient,
    encode_common_proof_query_tree_fragment, evaluate_common_proof_tree_columns,
    evaluate_ordered_deep_openings, evaluate_pre_challenge_common_proof_tree_columns,
    generate_common_proof, materialize_common_proof_merkle_tree, sample_private_base_polynomial,
    sample_private_extension_polynomial, write_common_proof_prefix,
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
    CommonProofAttemptBinding, CommonProofOperationHandle, CommonProofOperationKind,
    CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeCancellation,
    CommonProofRuntimeError, CommonProofRuntimeLimits, CommonProofRuntimeRegistry,
    CommonProofRuntimeVerificationError, CommonProofStorageTransactionRuntime,
    MAXIMUM_COMMON_PROOF_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_RESIDENT_COMMON_PROOF_INPUT_CHUNKS, PollableCommonProofByteSink,
    PollableCommonProofByteSinkError, ResidentCommonProofByteSource,
    ResidentCommonProofInputChunk, VerifiedCommonProofCapabilityHandle,
};
pub(crate) use selected_profile::{
    selected_proof_profile_set, selected_relation_plan_check_context,
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
pub(crate) use verifier::{
    CommonProofRequiredByteRange, CommonProofVerificationInput, CommonProofVerificationPoll,
    CommonProofVerificationStateMachine, CommonProofVerifierError,
    PollableCommonProofVerificationInput, VerifiedCommonProof, VerifiedRelationColumnEvaluator,
    VerifiedStatementOwnedTree, verify_common_proof,
};
pub(crate) use zero_knowledge::validate_zero_knowledge_mask_image;

#[cfg(test)]
mod tests;
