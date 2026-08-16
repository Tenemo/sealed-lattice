//! Pollable production materialization for the compact public-key family.
//!
//! This state owns the authenticated assignment loader, encodes and retains the
//! pre-challenge source before the lookup challenge, accepts that challenge
//! only through the exact compact transcript authority, performs the bounded
//! batch inversion, prepares the production structured-row source, drives the
//! external-memory CFW reduction, and advances the first WHIR epoch through
//! its initial masked sumcheck and first code switch. It does not yet execute
//! either complete WHIR epoch and therefore cannot emit a proof or mint a
//! workflow capability.

use std::rc::Rc;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use rand::{Rng, RngExt};

#[cfg(test)]
use crate::bgv::proof_suite::external_memory::ProofExternalMemoryUsage;
use crate::bgv::proof_suite::{
    ProofBaseFieldElement,
    compact_cfw::{
        COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwError,
        CompactCfwGeometry, CompactCfwMaskMaterial, CompactCfwMaskedCrossEpochClaims,
        CompactCfwPrefixEvaluationError, CompactCfwPrefixEvaluationState, CompactChallengeField,
        compact_cfw_final_challenge_is_allowed, compact_challenge_from_production,
        compact_challenge_to_production,
    },
    compact_cfw_external_prover::{
        CompactCfwExternalProverExecutionError, CompactCfwExternalProverFinishError,
        CompactCfwExternalProverOutput, CompactCfwExternalProverSetupError,
        CompactCfwExternalProverState,
    },
    compact_generation_randomness::{
        COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH, CompactGenerationAttemptRandomness,
        CompactGenerationRandomnessCursorError, CompactGenerationRandomnessError,
    },
    compact_masking_coefficient_maps::{
        CompactMaskingCoefficientMapCertificate, CompactMaskingCoefficientMapError,
        derive_compact_masking_coefficient_map_certificate,
    },
    compact_masking_entropy::{
        CompactMaskingEntropyError, verify_selected_compact_cfw_finish_masking,
        verify_selected_compact_cfw_round_masking,
        verify_selected_compact_cross_epoch_masking_prefix,
        verify_selected_compact_whir_source_query_masking,
        verify_selected_compact_whir_sumcheck_auxiliary_masking,
        verify_selected_compact_whir_sumcheck_round_masking,
    },
    compact_masking_kmac::{CompactMaskingKmacError, derive_selected_compact_masking_kmac_bridge},
    compact_masking_prefix::CompactMaskingAttemptIdentity,
    compact_masking_public_covector::{
        CompactFactorOnePublicCovectorAuthority, CompactFactorOnePublicCovectorError,
    },
    compact_proof_contract::{
        CompactProofContractError, CompactPublicKeyVerifierInputs,
        CompactResponseComponentRoleContract, CompactWhirEpochContract, CompactWhirFoldContract,
        CompactWhirMaskGroupContract, selected_compact_public_key_proof_contract,
    },
    compact_proof_wire::{
        CompactProofWireGeometry, CompactPublicInputBindings, DecodedCompactPublicInput,
    },
    compact_response_generation::{
        CompactOwnedResponseLeaf, CompactResponseGenerationError, CompactResponseGenerationPoll,
        CompactResponseGenerationPollError, CompactResponseGenerationState,
        CompactVerifierMessageAuthority,
    },
    compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValueKind,
        CompactResponseMerkleGeometry,
    },
    compact_whir::{
        CompactWhirCodeSwitchPreparationPoll, CompactWhirCodeSwitchRelationPreparation,
        CompactWhirCodeSwitchRelationPreparationPoll, CompactWhirCodeSwitchState,
        CompactWhirEncodedInitialOracle, CompactWhirEncodedMaskGroup, CompactWhirError,
        CompactWhirInitialSumcheckPoll, CompactWhirInitialSumcheckState,
        CompactWhirPreChallengeRelationPreparation, CompactWhirPreChallengeRelationPreparationPoll,
        CompactWhirPreChallengeRelationPreparationStep, CompactWhirRecomputableExtensionError,
        CompactWhirRecomputableExtensionInitialOracle, CompactWhirRecomputableExtensionPoll,
        compact_whir_configuration_from_contract, compact_whir_mask_group_shape,
        fold_compact_whir_query_major_source_openings,
    },
    external_memory::ProofExternalMemory,
    fixed_uniform_verifier_message::{
        DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageGeometry,
    },
    prover::{
        CommonProofGenerationCheckpointBoundary, CommonProofPrivateCoinSource,
        CommonProofProverError,
    },
};
use crate::foundation::Hash512;
use crate::hashing::hash_framed_parts_512;

use super::{
    CompactPublicKeyRelationCatalog, PreparedCompactPublicKeyAssignmentSources,
    PreparedCompactPublicKeyBaseAssignment,
    authenticated_assignment::{
        CompactAuthenticatedAssignmentPoll, CompactLookupInverseMaterializationPoll,
        CompactLookupInverseMaterializer, CompactPublicKeyAssignment,
        CompactPublicKeyBaseAssignment,
    },
    structured_r1cs::{
        CompactStructuredR1csRowSource, CompactStructuredR1csRowSourcePreparation,
        CompactStructuredR1csRowSourcePreparationPoll,
        CompactStructuredR1csRowSourcePreparationStep,
    },
};

type SelectedCompactPublicKeyAssignment = Rc<CompactPublicKeyAssignment>;
type SelectedCompactPublicKeyRowSource =
    CompactStructuredR1csRowSource<SelectedCompactPublicKeyAssignment>;
type SelectedCompactPublicKeyRowSourcePreparation =
    CompactStructuredR1csRowSourcePreparation<SelectedCompactPublicKeyAssignment>;

const COMPACT_PUBLIC_KEY_PRIVATE_COIN_BINDING_DOMAIN: &str =
    "sealed-lattice/compact-public-key/private-coin-binding/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyFamilyMaterializationError {
    WrongPhase,
    InvalidWorkBudget,
    InvalidVerifierMessage,
    InvalidPreChallengeSource,
    AllocationLimitExceeded,
    Whir(CompactWhirError),
    Prover(CommonProofProverError),
}

impl From<CommonProofProverError> for CompactPublicKeyFamilyMaterializationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CompactWhirError> for CompactPublicKeyFamilyMaterializationError {
    fn from(error: CompactWhirError) -> Self {
        Self::Whir(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyPreChallengeEncodingError<PrivateCoinError> {
    Materialization(CompactPublicKeyFamilyMaterializationError),
    PrivateCoin(PrivateCoinError),
    Randomness(CompactGenerationRandomnessError),
}

impl<PrivateCoinError> From<CompactPublicKeyFamilyMaterializationError>
    for CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>
{
    fn from(error: CompactPublicKeyFamilyMaterializationError) -> Self {
        Self::Materialization(error)
    }
}

impl<PrivateCoinError> From<CommonProofProverError>
    for CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>
{
    fn from(error: CommonProofProverError) -> Self {
        Self::Materialization(error.into())
    }
}

impl<PrivateCoinError> From<CompactWhirError>
    for CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>
{
    fn from(error: CompactWhirError) -> Self {
        Self::Materialization(error.into())
    }
}

impl<PrivateCoinError> From<CompactGenerationRandomnessError>
    for CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>
{
    fn from(error: CompactGenerationRandomnessError) -> Self {
        Self::Randomness(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyFamilyMaterializationPoll {
    AuthenticatedSourceReadRequired,
    SourceLoaded {
        column_ordinal: u32,
    },
    SourcesComplete,
    PreChallengeEncodingRequired,
    LookupVerifierMessageRequired,
    LookupInverseArithmeticStepCompleted {
        processed_element_count: u64,
    },
    StructuredRowSourceStepCompleted {
        step: CompactStructuredR1csRowSourcePreparationStep,
        completed_work_unit_count: u64,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyGenerationPoll {
    AuthenticatedSourceReadRequired,
    SourceLoaded {
        column_ordinal: u32,
    },
    SourcesComplete,
    PreChallengeSourceEncoded,
    ResponseLeafSupplied {
        leaf_ordinal: u64,
    },
    OpenedResponseLeafSupplied {
        leaf_ordinal: u64,
    },
    ResponseArithmeticStepCompleted,
    ResponseStorageTransactionCompleted,
    PreChallengeCheckpointReady,
    LookupInverseArithmeticStepCompleted {
        processed_element_count: u64,
    },
    StructuredRowSourceStepCompleted {
        step: CompactStructuredR1csRowSourcePreparationStep,
        completed_work_unit_count: u64,
    },
    FamilyMaterializationComplete,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyGenerationError<PrivateCoinError, StorageError> {
    FamilyMaterialization(CompactPublicKeyFamilyMaterializationError),
    PreChallengeEncoding(CompactPublicKeyPreChallengeEncodingError<PrivateCoinError>),
    ResponseGeneration(CompactResponseGenerationError),
    ResponsePoll(CompactResponseGenerationPollError<StorageError>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyGenerationInitializationError {
    FamilyMaterialization(CompactPublicKeyFamilyMaterializationError),
    ResponseGeneration(CompactResponseGenerationError),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyMainEpochPreparationError {
    WrongPhase,
    InvalidGeometry,
    AllocationLimitExceeded,
    Materialization(CompactPublicKeyFamilyMaterializationError),
    Contract(CompactProofContractError),
    Cfw(CompactCfwError),
    CfwProverSetup(CompactCfwExternalProverSetupError),
    MaskingCoefficientMap(CompactMaskingCoefficientMapError),
    MaskingEntropy(CompactMaskingEntropyError),
    CfwRoundMasking {
        round_ordinal: u32,
        error: CompactMaskingEntropyError,
    },
    CfwFinishMasking(CompactMaskingEntropyError),
    WhirSumcheckAuxiliaryMasking(CompactMaskingEntropyError),
    WhirSumcheckRoundMasking {
        round_ordinal: u32,
        error: CompactMaskingEntropyError,
    },
    WhirSourceQueryMasking {
        source_ordinal: u8,
        error: CompactMaskingEntropyError,
    },
    MaskingKmac(CompactMaskingKmacError),
    MaskingPublicCovector(CompactFactorOnePublicCovectorError),
    Randomness(CompactGenerationRandomnessError),
    Whir(CompactWhirError),
    Prover(CommonProofProverError),
}

impl From<CompactPublicKeyFamilyMaterializationError>
    for CompactPublicKeyMainEpochPreparationError
{
    fn from(error: CompactPublicKeyFamilyMaterializationError) -> Self {
        Self::Materialization(error)
    }
}

impl From<CompactProofContractError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactProofContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<CompactCfwError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl From<CompactCfwExternalProverSetupError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactCfwExternalProverSetupError) -> Self {
        Self::CfwProverSetup(error)
    }
}

impl From<CompactMaskingCoefficientMapError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactMaskingCoefficientMapError) -> Self {
        Self::MaskingCoefficientMap(error)
    }
}

impl From<CompactMaskingEntropyError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactMaskingEntropyError) -> Self {
        Self::MaskingEntropy(error)
    }
}

impl From<CompactMaskingKmacError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactMaskingKmacError) -> Self {
        Self::MaskingKmac(error)
    }
}

impl From<CompactFactorOnePublicCovectorError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactFactorOnePublicCovectorError) -> Self {
        Self::MaskingPublicCovector(error)
    }
}

impl From<CompactGenerationRandomnessError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactGenerationRandomnessError) -> Self {
        Self::Randomness(error)
    }
}

impl From<CompactWhirError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactWhirError) -> Self {
        Self::Whir(error)
    }
}

impl From<CommonProofProverError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyMainEpochPollError<
    ResponseStorageError,
    CfwStorageError = ResponseStorageError,
> {
    Preparation(CompactPublicKeyMainEpochPreparationError),
    CfwExecution(CompactCfwExternalProverExecutionError<CfwStorageError>),
    CfwFinish(CompactCfwExternalProverFinishError),
    ResponseGeneration(CompactResponseGenerationError),
    ResponsePoll(CompactResponseGenerationPollError<ResponseStorageError>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyMainEpochPoll {
    MainSourceArithmeticStepCompleted {
        processed_work_unit_count: u64,
    },
    CrossEpochEvaluationStepCompleted {
        processed_work_unit_count: u64,
        evaluated_source_element_count: u64,
    },
    ResponseLeafSupplied {
        leaf_ordinal: u64,
    },
    OpenedResponseLeafSupplied {
        response_ordinal: u32,
        leaf_ordinal: u64,
    },
    ResponseArithmeticStepCompleted,
    ResponseStorageTransactionCompleted,
    CfwRoundPolynomialStepCompleted {
        round_ordinal: u32,
        polynomial_ready: bool,
    },
    CfwBoundRoundStepCompleted {
        round_ordinal: u32,
        round_complete: bool,
    },
    CfwRoundResponseCheckpointReady {
        round_ordinal: u32,
    },
    CfwFinalResponseCheckpointReady,
    PreChallengeWhirRelationStepCompleted {
        step: CompactWhirPreChallengeRelationPreparationStep,
        processed_work_unit_count: u64,
    },
    PreChallengeWhirSumcheckPrepared {
        batch_ordinal: u8,
    },
    PreChallengeWhirRoundPolynomialStepCompleted {
        batch_ordinal: u8,
        round_ordinal: u32,
        polynomial_ready: bool,
    },
    PreChallengeWhirBoundRoundStepCompleted {
        batch_ordinal: u8,
        round_ordinal: u32,
        round_complete: bool,
    },
    PreChallengeWhirWeightScalingStepCompleted {
        batch_ordinal: u8,
        scaling_complete: bool,
    },
    PreChallengeWhirAuxiliaryResponseCheckpointReady {
        batch_ordinal: u8,
    },
    PreChallengeWhirRoundResponseCheckpointReady {
        batch_ordinal: u8,
        round_ordinal: u32,
    },
    PreChallengeWhirSumcheckComplete {
        batch_ordinal: u8,
    },
    PreChallengeWhirCodeSwitchRandomnessStepCompleted {
        processed_work_unit_count: u64,
        fold_complete: bool,
    },
    PreChallengeWhirCodeSwitchPrepared,
    PreChallengeWhirCodeSwitchSourceStepCompleted {
        processed_work_unit_count: u64,
    },
    PreChallengeWhirFirstCodeSwitchResponseCheckpointReady,
    PreChallengeWhirCodeSwitchRelationStepCompleted {
        processed_work_unit_count: u64,
        relation_complete: bool,
    },
    PostLookupCheckpointReady,
    CrossEpochCheckpointReady,
}

struct CompactPublicKeyFamilyMetadata {
    relation: Rc<CompactPublicKeyRelationCatalog>,
    public_input_bindings: CompactPublicInputBindings,
    canonical_public_input_bytes: Vec<u8>,
    decoded_public_input: DecodedCompactPublicInput,
    proof_wire_geometry: CompactProofWireGeometry,
    response_merkle_geometries: Vec<CompactResponseMerkleGeometry>,
    compact_construction_identity_hash: [u8; Hash512::BYTE_LENGTH],
    checkpoint_schedule_digest: Hash512,
    source_replay_binding: [u8; Hash512::BYTE_LENGTH],
    pre_challenge: CompactPublicKeyPreChallengeMaterial,
}

impl CompactPublicKeyFamilyMetadata {
    fn from_prepared_assignment(
        prepared: PreparedCompactPublicKeyBaseAssignment,
        pre_challenge: CompactPublicKeyPreChallengeMaterial,
    ) -> (Self, CompactPublicKeyBaseAssignment) {
        let PreparedCompactPublicKeyBaseAssignment {
            relation,
            base_assignment,
            public_input_bindings,
            canonical_public_input_bytes,
            decoded_public_input,
            proof_wire_geometry,
            response_merkle_geometries,
            compact_construction_identity_hash,
            checkpoint_schedule_digest,
        } = prepared;
        let source_replay_binding = base_assignment.source_replay_binding();
        (
            Self {
                relation: Rc::new(relation),
                public_input_bindings,
                canonical_public_input_bytes,
                decoded_public_input,
                proof_wire_geometry,
                response_merkle_geometries,
                compact_construction_identity_hash,
                checkpoint_schedule_digest,
                source_replay_binding,
                pre_challenge,
            },
            base_assignment,
        )
    }
}

enum CompactPublicKeyFamilyMaterializationPhase {
    LoadingSources(Box<PreparedCompactPublicKeyAssignmentSources>),
    AwaitingPreChallengeEncoding(PreparedCompactPublicKeyBaseAssignment),
    AwaitingLookupVerifierMessage {
        prepared: PreparedCompactPublicKeyBaseAssignment,
        pre_challenge: CompactPublicKeyPreChallengeMaterial,
    },
    MaterializingLookupInverses {
        metadata: CompactPublicKeyFamilyMetadata,
        materializer: CompactLookupInverseMaterializer,
    },
    PreparingStructuredRowSource {
        metadata: CompactPublicKeyFamilyMetadata,
        preparation: Box<SelectedCompactPublicKeyRowSourcePreparation>,
    },
    Ready(Option<CompactPublicKeyFamilyMaterial>),
    Cancelled,
    Transitioning,
}

pub(crate) struct CompactPublicKeyFamilyMaterializationState {
    phase: CompactPublicKeyFamilyMaterializationPhase,
}

/// Owns the selected public-key family through its first authenticated compact
/// response boundary. The retained response state and family material continue
/// into CFW and the main WHIR epoch; this state cannot emit a proof by itself.
pub(crate) struct CompactPublicKeyGenerationState {
    family_materialization_state: CompactPublicKeyFamilyMaterializationState,
    response_generation_state: Option<CompactResponseGenerationState>,
    proof_attempt_identifier: [u8; 32],
}

#[derive(Clone, Copy)]
pub(crate) struct CompactPublicKeyPreLookupMaterialView<'state> {
    public_input_bindings: CompactPublicInputBindings,
    canonical_public_input_bytes: &'state [u8],
    decoded_public_input: &'state DecodedCompactPublicInput,
    proof_wire_geometry: &'state CompactProofWireGeometry,
    response_merkle_geometries: &'state [CompactResponseMerkleGeometry],
    compact_construction_identity_hash: [u8; Hash512::BYTE_LENGTH],
    checkpoint_schedule_digest: Hash512,
    source_replay_binding: [u8; Hash512::BYTE_LENGTH],
}

pub(crate) struct CompactPublicKeyFamilyMaterial {
    metadata: CompactPublicKeyFamilyMetadata,
    row_source: SelectedCompactPublicKeyRowSource,
}

pub(crate) struct CompactPublicKeyPreChallengeMaterial {
    encoded_oracle: CompactWhirEncodedInitialOracle,
    randomness: CompactGenerationAttemptRandomness,
    response_leaf_count: u64,
}

pub(crate) struct PreparedCompactPublicKeyMainEpoch {
    family_material: CompactPublicKeyFamilyMaterial,
    response_generation_state: CompactResponseGenerationState,
    post_lookup_material: Option<CompactPublicKeyPostLookupMaterial>,
}

struct CompactPublicKeyPostLookupMaterial {
    masking_coefficient_maps: CompactMaskingCoefficientMapCertificate,
    masking_attempt_identity: Option<CompactMaskingAttemptIdentity>,
    cfw_geometry: CompactCfwGeometry,
    cfw_mask_material: CompactCfwMaskMaterial,
    cfw_auxiliary_target: CompactChallengeField,
    inner_mask_encoding_randomness: Vec<Vec<CompactChallengeField>>,
    inner_mask_oracle: CompactWhirEncodedMaskGroup,
    main_source_oracle: CompactWhirRecomputableExtensionInitialOracle,
    outer_mask_encoding_randomness: Vec<Vec<CompactChallengeField>>,
    outer_mask_oracle: CompactWhirEncodedMaskGroup,
    cross_epoch_masks: [CompactChallengeField; 2],
    cross_epoch_mask_encoding_randomness: Vec<Vec<CompactChallengeField>>,
    cross_epoch_mask_oracle: CompactWhirEncodedMaskGroup,
    response_leaf_count: u64,
    cross_epoch_masking_transcript_cursor: Option<Box<[u8]>>,
    cross_epoch_point: Option<Vec<CompactChallengeField>>,
    cross_epoch_evaluation_state: Option<CompactCfwPrefixEvaluationState>,
    cross_epoch_claims: Option<CompactCfwMaskedCrossEpochClaims>,
    cross_epoch_response_leaf_count: u64,
    cfw_external_prover: Option<CompactCfwExternalProverState>,
    pending_cfw_round_polynomial:
        Option<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
    pending_cfw_bound_challenge: Option<CompactChallengeField>,
    cfw_outer_masking_outputs: Vec<CompactChallengeField>,
    cfw_bound_round_advance_required: bool,
    cfw_external_output: Option<CompactCfwExternalProverOutput>,
    pre_challenge_whir_relation_preparation: Option<CompactWhirPreChallengeRelationPreparation>,
    pre_challenge_whir_sumcheck_batches: Vec<CompactPublicKeyWhirSumcheckBatch>,
    pre_challenge_whir_first_code_switch: Option<CompactWhirCodeSwitchState>,
    pre_challenge_whir_first_code_switch_response_leaf_count: u64,
    pre_challenge_whir_first_source_query_masking_verified: bool,
    pre_challenge_whir_first_code_switch_relation_preparation:
        Option<CompactWhirCodeSwitchRelationPreparation>,
}

struct CompactPublicKeyWhirSumcheckBatch {
    batch_ordinal: u8,
    initial_response_ordinal: u32,
    state: CompactWhirInitialSumcheckState,
    response_leaf_count: u64,
    masking_outputs: Vec<CompactChallengeField>,
    combination_challenge_bound: bool,
    round_masking_verified: bool,
    bound_round_advance_required: bool,
}

impl CompactPublicKeyWhirSumcheckBatch {
    fn new(
        batch_ordinal: u8,
        initial_response_ordinal: u32,
        state: CompactWhirInitialSumcheckState,
        response_leaf_count: u64,
    ) -> Result<Self, CompactPublicKeyMainEpochPreparationError> {
        if response_leaf_count == 0 {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let output_capacity = state
            .mask_messages()
            .len()
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let mut masking_outputs = Vec::new();
        masking_outputs
            .try_reserve_exact(output_capacity)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        masking_outputs.push(state.auxiliary_target());
        Ok(Self {
            batch_ordinal,
            initial_response_ordinal,
            state,
            response_leaf_count,
            masking_outputs,
            combination_challenge_bound: false,
            round_masking_verified: false,
            bound_round_advance_required: false,
        })
    }
}

enum CompactPublicKeyPostLookupResponseLeafPoll {
    ArithmeticStepCompleted { processed_work_unit_count: u64 },
    LeafReady(CompactOwnedResponseLeaf),
}

enum CompactPublicKeyCrossEpochResponseLeafPoll {
    ArithmeticStepCompleted {
        processed_work_unit_count: u64,
        evaluated_source_element_count: u64,
    },
    LeafReady(CompactOwnedResponseLeaf),
}

enum CompactPublicKeyCodeSwitchResponseLeafPoll {
    ArithmeticStepCompleted { processed_work_unit_count: u64 },
    LeafReady(CompactOwnedResponseLeaf),
}

impl CompactPublicKeyGenerationState {
    pub(crate) fn new(
        sources: PreparedCompactPublicKeyAssignmentSources,
        proof_attempt_identifier: [u8; 32],
    ) -> Self {
        Self {
            family_materialization_state: CompactPublicKeyFamilyMaterializationState::new(sources),
            response_generation_state: None,
            proof_attempt_identifier,
        }
    }

    pub(crate) fn checkpoint_boundary(&self) -> Option<CommonProofGenerationCheckpointBoundary> {
        self.response_generation_state
            .as_ref()?
            .checkpoint_boundary()
            .cloned()
    }

    pub(crate) fn pre_lookup_material(&self) -> Option<CompactPublicKeyPreLookupMaterialView<'_>> {
        self.family_materialization_state.pre_lookup_material()
    }

    pub(crate) fn poll_source_loading(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyGenerationPoll, CompactPublicKeyGenerationInitializationError> {
        match self
            .family_materialization_state
            .poll(maximum_work_unit_count)
            .map_err(CompactPublicKeyGenerationInitializationError::FamilyMaterialization)?
        {
            CompactPublicKeyFamilyMaterializationPoll::AuthenticatedSourceReadRequired => {
                Ok(CompactPublicKeyGenerationPoll::AuthenticatedSourceReadRequired)
            }
            CompactPublicKeyFamilyMaterializationPoll::SourceLoaded { column_ordinal } => {
                Ok(CompactPublicKeyGenerationPoll::SourceLoaded { column_ordinal })
            }
            CompactPublicKeyFamilyMaterializationPoll::SourcesComplete => {
                self.initialize_response_generation_state()
                    .map_err(CompactPublicKeyGenerationInitializationError::ResponseGeneration)?;
                Ok(CompactPublicKeyGenerationPoll::SourcesComplete)
            }
            _ => Err(
                CompactPublicKeyGenerationInitializationError::FamilyMaterialization(
                    CompactPublicKeyFamilyMaterializationError::WrongPhase,
                ),
            ),
        }
    }

    pub(crate) fn restore_authenticated_checkpoint_transcript_cursor(
        &mut self,
        canonical_cursor_bytes: &[u8],
        expected_cursor_digest: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<(), CompactResponseGenerationError> {
        self.response_generation_state
            .as_mut()
            .ok_or(CompactResponseGenerationError::WrongPhase)?
            .restore_authenticated_checkpoint_transcript_cursor(
                canonical_cursor_bytes,
                expected_cursor_digest,
            )
    }

    pub(crate) fn canonical_randomness_checkpoint_cursor_bytes(
        &self,
    ) -> Option<[u8; COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH]> {
        Some(
            self.family_materialization_state
                .pre_challenge_material()?
                .canonical_randomness_checkpoint_cursor_bytes(),
        )
    }

    pub(crate) fn validate_authenticated_randomness_checkpoint_cursor(
        &self,
        canonical_cursor_bytes: &[u8],
    ) -> Result<(), CompactGenerationRandomnessCursorError> {
        self.family_materialization_state
            .pre_challenge_material()
            .ok_or(CompactGenerationRandomnessCursorError::WrongLiveCursor)?
            .randomness
            .validate_checkpoint_cursor_bytes(canonical_cursor_bytes)
    }

    pub(crate) fn poll<Coins, Storage>(
        &mut self,
        maximum_work_unit_count: u64,
        private_coins: &mut Coins,
        storage: &mut Storage,
    ) -> Result<
        CompactPublicKeyGenerationPoll,
        CompactPublicKeyGenerationError<Coins::Error, Storage::Error>,
    >
    where
        Coins: CommonProofPrivateCoinSource,
        Storage: ProofExternalMemory,
    {
        let family_poll = self
            .family_materialization_state
            .poll(maximum_work_unit_count)
            .map_err(CompactPublicKeyGenerationError::FamilyMaterialization)?;
        match family_poll {
            CompactPublicKeyFamilyMaterializationPoll::AuthenticatedSourceReadRequired => {
                Ok(CompactPublicKeyGenerationPoll::AuthenticatedSourceReadRequired)
            }
            CompactPublicKeyFamilyMaterializationPoll::SourceLoaded { column_ordinal } => {
                Ok(CompactPublicKeyGenerationPoll::SourceLoaded { column_ordinal })
            }
            CompactPublicKeyFamilyMaterializationPoll::SourcesComplete => {
                self.initialize_response_generation_state()
                    .map_err(CompactPublicKeyGenerationError::ResponseGeneration)?;
                Ok(CompactPublicKeyGenerationPoll::SourcesComplete)
            }
            CompactPublicKeyFamilyMaterializationPoll::PreChallengeEncodingRequired => {
                self.family_materialization_state
                    .encode_pre_challenge_source(private_coins, self.proof_attempt_identifier)
                    .map_err(CompactPublicKeyGenerationError::PreChallengeEncoding)?;
                Ok(CompactPublicKeyGenerationPoll::PreChallengeSourceEncoded)
            }
            CompactPublicKeyFamilyMaterializationPoll::LookupVerifierMessageRequired => {
                self.poll_pre_challenge_response(storage)
            }
            CompactPublicKeyFamilyMaterializationPoll::LookupInverseArithmeticStepCompleted {
                processed_element_count,
            } => Ok(
                CompactPublicKeyGenerationPoll::LookupInverseArithmeticStepCompleted {
                    processed_element_count,
                },
            ),
            CompactPublicKeyFamilyMaterializationPoll::StructuredRowSourceStepCompleted {
                step,
                completed_work_unit_count,
            } => Ok(
                CompactPublicKeyGenerationPoll::StructuredRowSourceStepCompleted {
                    step,
                    completed_work_unit_count,
                },
            ),
            CompactPublicKeyFamilyMaterializationPoll::Complete => {
                Ok(CompactPublicKeyGenerationPoll::FamilyMaterializationComplete)
            }
        }
    }

    pub(crate) fn finish(
        self,
    ) -> Result<PreparedCompactPublicKeyMainEpoch, CompactPublicKeyFamilyMaterializationError> {
        let response_generation_state = self
            .response_generation_state
            .filter(|state| state.checkpoint_boundary().is_some())
            .ok_or(CompactPublicKeyFamilyMaterializationError::WrongPhase)?;
        Ok(PreparedCompactPublicKeyMainEpoch {
            family_material: self.family_materialization_state.finish()?,
            response_generation_state,
            post_lookup_material: None,
        })
    }

    fn initialize_response_generation_state(
        &mut self,
    ) -> Result<(), CompactResponseGenerationError> {
        if self.response_generation_state.is_some() {
            return Err(CompactResponseGenerationError::WrongPhase);
        }
        let pre_lookup_material = self
            .family_materialization_state
            .pre_lookup_material()
            .ok_or(CompactResponseGenerationError::WrongPhase)?;
        let response_generation_state = CompactResponseGenerationState::new(
            pre_lookup_material.proof_wire_geometry(),
            pre_lookup_material.response_merkle_geometries(),
            pre_lookup_material.decoded_public_input(),
            pre_lookup_material.canonical_public_input_bytes(),
        )?;
        self.response_generation_state = Some(response_generation_state);
        Ok(())
    }

    fn poll_pre_challenge_response<PrivateCoinError, Storage>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CompactPublicKeyGenerationPoll,
        CompactPublicKeyGenerationError<PrivateCoinError, Storage::Error>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let Self {
            family_materialization_state,
            response_generation_state,
            ..
        } = self;
        let pre_challenge_material = family_materialization_state
            .pre_challenge_material()
            .ok_or(CompactPublicKeyGenerationError::FamilyMaterialization(
                CompactPublicKeyFamilyMaterializationError::WrongPhase,
            ))?;
        let response_generation_state = response_generation_state.as_mut().ok_or(
            CompactPublicKeyGenerationError::ResponseGeneration(
                CompactResponseGenerationError::WrongPhase,
            ),
        )?;
        match response_generation_state
            .poll(storage)
            .map_err(CompactPublicKeyGenerationError::ResponsePoll)?
        {
            CompactResponseGenerationPoll::ResponseRequired {
                response_ordinal: 0,
            } => {
                response_generation_state
                    .begin_response(pre_challenge_material.fiat_shamir_round_salt())
                    .map_err(CompactPublicKeyGenerationError::ResponseGeneration)?;
                Ok(CompactPublicKeyGenerationPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal: 0,
                leaf_ordinal,
            } => {
                let leaf = pre_challenge_material
                    .response_leaf(leaf_ordinal)
                    .map_err(CompactPublicKeyGenerationError::FamilyMaterialization)?;
                let leaf_salt = pre_challenge_material.response_leaf_salt(leaf_ordinal, &leaf);
                response_generation_state
                    .supply_next_response_leaf(&leaf, &leaf_salt)
                    .map_err(CompactPublicKeyGenerationError::ResponseGeneration)?;
                Ok(CompactPublicKeyGenerationPoll::ResponseLeafSupplied { leaf_ordinal })
            }
            CompactResponseGenerationPoll::OpenedLeafRequired {
                response_ordinal: 0,
                leaf_ordinal,
            } => {
                let leaf = pre_challenge_material
                    .response_leaf(leaf_ordinal)
                    .map_err(CompactPublicKeyGenerationError::FamilyMaterialization)?;
                let leaf_salt = pre_challenge_material.response_leaf_salt(leaf_ordinal, &leaf);
                response_generation_state
                    .supply_next_opened_leaf(&leaf, leaf_salt)
                    .map_err(CompactPublicKeyGenerationError::ResponseGeneration)?;
                Ok(CompactPublicKeyGenerationPoll::OpenedResponseLeafSupplied { leaf_ordinal })
            }
            CompactResponseGenerationPoll::ArithmeticStepCompleted => {
                Ok(CompactPublicKeyGenerationPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::StorageTransactionCompleted => {
                Ok(CompactPublicKeyGenerationPoll::ResponseStorageTransactionCompleted)
            }
            CompactResponseGenerationPoll::CheckpointCursorRequired => {
                let canonical_randomness_cursor =
                    pre_challenge_material.canonical_randomness_checkpoint_cursor_bytes();
                response_generation_state
                    .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                    .map_err(CompactPublicKeyGenerationError::ResponseGeneration)?;
                let lookup_message_authority = response_generation_state
                    .verifier_message_authority(0)
                    .ok_or(CompactPublicKeyGenerationError::ResponseGeneration(
                        CompactResponseGenerationError::WrongPhase,
                    ))?;
                family_materialization_state
                    .supply_lookup_verifier_message(lookup_message_authority)
                    .map_err(CompactPublicKeyGenerationError::FamilyMaterialization)?;
                Ok(CompactPublicKeyGenerationPoll::PreChallengeCheckpointReady)
            }
            CompactResponseGenerationPoll::ResponseRequired { .. }
            | CompactResponseGenerationPoll::ResponseLeafRequired { .. }
            | CompactResponseGenerationPoll::OpenedLeafRequired { .. }
            | CompactResponseGenerationPoll::Complete => {
                Err(CompactPublicKeyGenerationError::ResponseGeneration(
                    CompactResponseGenerationError::WrongPhase,
                ))
            }
        }
    }
}

impl CompactPublicKeyFamilyMaterializationState {
    pub(crate) fn new(sources: PreparedCompactPublicKeyAssignmentSources) -> Self {
        Self {
            phase: CompactPublicKeyFamilyMaterializationPhase::LoadingSources(Box::new(sources)),
        }
    }

    pub(crate) fn pre_lookup_material(&self) -> Option<CompactPublicKeyPreLookupMaterialView<'_>> {
        let prepared = match &self.phase {
            CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(prepared)
            | CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                prepared,
                ..
            } => prepared,
            _ => return None,
        };
        Some(CompactPublicKeyPreLookupMaterialView {
            public_input_bindings: prepared.public_input_bindings,
            canonical_public_input_bytes: &prepared.canonical_public_input_bytes,
            decoded_public_input: &prepared.decoded_public_input,
            proof_wire_geometry: &prepared.proof_wire_geometry,
            response_merkle_geometries: &prepared.response_merkle_geometries,
            compact_construction_identity_hash: prepared.compact_construction_identity_hash,
            checkpoint_schedule_digest: prepared.checkpoint_schedule_digest,
            source_replay_binding: prepared.base_assignment.source_replay_binding(),
        })
    }

    pub(crate) fn pre_challenge_material(&self) -> Option<&CompactPublicKeyPreChallengeMaterial> {
        match &self.phase {
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                pre_challenge,
                ..
            } => Some(pre_challenge),
            CompactPublicKeyFamilyMaterializationPhase::MaterializingLookupInverses {
                metadata,
                ..
            }
            | CompactPublicKeyFamilyMaterializationPhase::PreparingStructuredRowSource {
                metadata,
                ..
            } => Some(&metadata.pre_challenge),
            CompactPublicKeyFamilyMaterializationPhase::Ready(Some(material)) => {
                Some(&material.metadata.pre_challenge)
            }
            _ => None,
        }
    }

    pub(crate) fn encode_pre_challenge_source<Coins: CommonProofPrivateCoinSource>(
        &mut self,
        private_coins: &mut Coins,
        proof_attempt_identifier: [u8; 32],
    ) -> Result<(), CompactPublicKeyPreChallengeEncodingError<Coins::Error>> {
        let CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(prepared) =
            core::mem::replace(
                &mut self.phase,
                CompactPublicKeyFamilyMaterializationPhase::Transitioning,
            )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase.into());
        };
        let result =
            prepare_pre_challenge_material(&prepared, private_coins, proof_attempt_identifier);
        match result {
            Ok(pre_challenge) => {
                self.phase =
                    CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                        prepared,
                        pre_challenge,
                    };
                Ok(())
            }
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                Err(error)
            }
        }
    }

    pub(crate) fn supply_lookup_verifier_message(
        &mut self,
        authority: CompactVerifierMessageAuthority<'_>,
    ) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let prepared = match &self.phase {
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
                prepared,
                ..
            } => prepared,
            _ => return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase),
        };
        if authority.logical_verifier_move_ordinal() != 0
            || authority.proof_wire_geometry() != &prepared.proof_wire_geometry
            || authority.canonical_public_input_bytes()
                != prepared.canonical_public_input_bytes.as_slice()
        {
            return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
        }
        let lookup_message_geometry = prepared
            .proof_wire_geometry
            .responses()
            .first()
            .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage)?
            .verifier_message_geometry();
        let lookup_challenge =
            lookup_challenge_from_verifier_message(lookup_message_geometry, authority.message())?;

        let CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage {
            prepared,
            pre_challenge,
        } = core::mem::replace(
            &mut self.phase,
            CompactPublicKeyFamilyMaterializationPhase::Transitioning,
        )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        let (metadata, base_assignment) =
            CompactPublicKeyFamilyMetadata::from_prepared_assignment(prepared, pre_challenge);
        let materializer =
            match base_assignment.begin_lookup_inverse_materialization(lookup_challenge) {
                Ok(materializer) => materializer,
                Err(error) => {
                    self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                    return Err(error.into());
                }
            };
        self.phase = CompactPublicKeyFamilyMaterializationPhase::MaterializingLookupInverses {
            metadata,
            materializer,
        };
        Ok(())
    }

    pub(crate) fn poll(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyFamilyMaterializationPoll, CompactPublicKeyFamilyMaterializationError>
    {
        if maximum_work_unit_count == 0 {
            return Err(CompactPublicKeyFamilyMaterializationError::InvalidWorkBudget);
        }
        match &mut self.phase {
            CompactPublicKeyFamilyMaterializationPhase::LoadingSources(sources) => {
                match sources.poll_source_loading()? {
                    CompactAuthenticatedAssignmentPoll::AuthenticatedSourceReadRequired => Ok(
                        CompactPublicKeyFamilyMaterializationPoll::AuthenticatedSourceReadRequired,
                    ),
                    CompactAuthenticatedAssignmentPoll::SourceLoaded { column_ordinal } => Ok(
                        CompactPublicKeyFamilyMaterializationPoll::SourceLoaded { column_ordinal },
                    ),
                    CompactAuthenticatedAssignmentPoll::Complete => {
                        self.finish_source_loading()?;
                        Ok(CompactPublicKeyFamilyMaterializationPoll::SourcesComplete)
                    }
                }
            }
            CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(_) => {
                Ok(CompactPublicKeyFamilyMaterializationPoll::PreChallengeEncodingRequired)
            }
            CompactPublicKeyFamilyMaterializationPhase::AwaitingLookupVerifierMessage { .. } => {
                Ok(CompactPublicKeyFamilyMaterializationPoll::LookupVerifierMessageRequired)
            }
            CompactPublicKeyFamilyMaterializationPhase::MaterializingLookupInverses {
                materializer,
                ..
            } => match materializer.advance(maximum_work_unit_count)? {
                CompactLookupInverseMaterializationPoll::ArithmeticStepCompleted {
                    processed_element_count,
                } => Ok(
                    CompactPublicKeyFamilyMaterializationPoll::LookupInverseArithmeticStepCompleted {
                        processed_element_count,
                    },
                ),
                CompactLookupInverseMaterializationPoll::Complete => {
                    self.finish_lookup_materialization()?;
                    self.poll(maximum_work_unit_count)
                }
            },
            CompactPublicKeyFamilyMaterializationPhase::PreparingStructuredRowSource {
                preparation,
                ..
            } => match preparation.advance(maximum_work_unit_count)? {
                CompactStructuredR1csRowSourcePreparationPoll::StepCompleted {
                    step,
                    completed_work_unit_count,
                } => Ok(
                    CompactPublicKeyFamilyMaterializationPoll::StructuredRowSourceStepCompleted {
                        step,
                        completed_work_unit_count,
                    },
                ),
                CompactStructuredR1csRowSourcePreparationPoll::Complete(row_source) => {
                    self.finish_structured_row_source(row_source)?;
                    Ok(CompactPublicKeyFamilyMaterializationPoll::Complete)
                }
            },
            CompactPublicKeyFamilyMaterializationPhase::Ready(_) => {
                Ok(CompactPublicKeyFamilyMaterializationPoll::Complete)
            }
            CompactPublicKeyFamilyMaterializationPhase::Cancelled
            | CompactPublicKeyFamilyMaterializationPhase::Transitioning => {
                Err(CompactPublicKeyFamilyMaterializationError::WrongPhase)
            }
        }
    }

    pub(crate) fn finish(
        mut self,
    ) -> Result<CompactPublicKeyFamilyMaterial, CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::Ready(material) = &mut self.phase else {
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        material
            .take()
            .ok_or(CompactPublicKeyFamilyMaterializationError::WrongPhase)
    }

    fn finish_source_loading(&mut self) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::LoadingSources(sources) =
            core::mem::replace(
                &mut self.phase,
                CompactPublicKeyFamilyMaterializationPhase::Transitioning,
            )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        match (*sources).finish_source_loading() {
            Ok(prepared) => {
                self.phase =
                    CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(
                        prepared,
                    );
                Ok(())
            }
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                Err(error.into())
            }
        }
    }

    fn finish_lookup_materialization(
        &mut self,
    ) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::MaterializingLookupInverses {
            metadata,
            materializer,
        } = core::mem::replace(
            &mut self.phase,
            CompactPublicKeyFamilyMaterializationPhase::Transitioning,
        )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        let assignment = match materializer.finish() {
            Ok(assignment) => Rc::new(assignment),
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                return Err(error.into());
            }
        };
        let preparation = match CompactStructuredR1csRowSourcePreparation::new(
            Rc::clone(&metadata.relation),
            assignment,
        ) {
            Ok(preparation) => preparation,
            Err(error) => {
                self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
                return Err(error.into());
            }
        };
        self.phase = CompactPublicKeyFamilyMaterializationPhase::PreparingStructuredRowSource {
            metadata,
            preparation: Box::new(preparation),
        };
        Ok(())
    }

    fn finish_structured_row_source(
        &mut self,
        row_source: Box<SelectedCompactPublicKeyRowSource>,
    ) -> Result<(), CompactPublicKeyFamilyMaterializationError> {
        let CompactPublicKeyFamilyMaterializationPhase::PreparingStructuredRowSource {
            metadata,
            ..
        } = core::mem::replace(
            &mut self.phase,
            CompactPublicKeyFamilyMaterializationPhase::Transitioning,
        )
        else {
            self.phase = CompactPublicKeyFamilyMaterializationPhase::Cancelled;
            return Err(CompactPublicKeyFamilyMaterializationError::WrongPhase);
        };
        self.phase = CompactPublicKeyFamilyMaterializationPhase::Ready(Some(
            CompactPublicKeyFamilyMaterial {
                metadata,
                row_source: *row_source,
            },
        ));
        Ok(())
    }
}

impl CompactPublicKeyPreLookupMaterialView<'_> {
    pub(crate) const fn public_input_bindings(&self) -> CompactPublicInputBindings {
        self.public_input_bindings
    }

    pub(crate) const fn canonical_public_input_bytes(&self) -> &[u8] {
        self.canonical_public_input_bytes
    }

    pub(crate) const fn decoded_public_input(&self) -> &DecodedCompactPublicInput {
        self.decoded_public_input
    }

    pub(crate) const fn proof_wire_geometry(&self) -> &CompactProofWireGeometry {
        self.proof_wire_geometry
    }

    pub(crate) const fn response_merkle_geometries(&self) -> &[CompactResponseMerkleGeometry] {
        self.response_merkle_geometries
    }

    pub(crate) const fn compact_construction_identity_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.compact_construction_identity_hash
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        self.checkpoint_schedule_digest
    }

    pub(crate) const fn source_replay_binding(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.source_replay_binding
    }

    pub(crate) fn private_coin_derivation_binding_hash(&self) -> Hash512 {
        Hash512::from_bytes(hash_framed_parts_512(
            COMPACT_PUBLIC_KEY_PRIVATE_COIN_BINDING_DOMAIN,
            &[
                &self.compact_construction_identity_hash,
                self.canonical_public_input_bytes,
                &self.source_replay_binding,
            ],
        ))
    }
}

impl CompactPublicKeyFamilyMaterial {
    pub(crate) fn relation(&self) -> &CompactPublicKeyRelationCatalog {
        &self.metadata.relation
    }

    pub(crate) const fn public_input_bindings(&self) -> CompactPublicInputBindings {
        self.metadata.public_input_bindings
    }

    pub(crate) fn canonical_public_input_bytes(&self) -> &[u8] {
        &self.metadata.canonical_public_input_bytes
    }

    pub(crate) const fn decoded_public_input(&self) -> &DecodedCompactPublicInput {
        &self.metadata.decoded_public_input
    }

    pub(crate) const fn proof_wire_geometry(&self) -> &CompactProofWireGeometry {
        &self.metadata.proof_wire_geometry
    }

    pub(crate) fn response_merkle_geometries(&self) -> &[CompactResponseMerkleGeometry] {
        &self.metadata.response_merkle_geometries
    }

    pub(crate) const fn compact_construction_identity_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.metadata.compact_construction_identity_hash
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        self.metadata.checkpoint_schedule_digest
    }

    pub(crate) const fn source_replay_binding(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.metadata.source_replay_binding
    }

    pub(crate) const fn pre_challenge_material(&self) -> &CompactPublicKeyPreChallengeMaterial {
        &self.metadata.pre_challenge
    }

    pub(crate) const fn witness_length(&self) -> u64 {
        self.row_source.witness_length()
    }

    pub(crate) const fn row_count(&self) -> u64 {
        self.row_source.row_count()
    }

    pub(super) const fn row_source(&self) -> &SelectedCompactPublicKeyRowSource {
        &self.row_source
    }
}

impl CompactPublicKeyPreChallengeMaterial {
    pub(crate) const fn proof_attempt_identifier(&self) -> [u8; 32] {
        self.randomness.proof_attempt_identifier()
    }

    pub(crate) fn fiat_shamir_round_salt(
        &self,
    ) -> [u8; crate::bgv::proof_suite::compact_proof_wire::COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH]
    {
        self.randomness.fiat_shamir_round_salt(0)
    }

    pub(crate) fn response_leaf(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyFamilyMaterializationError> {
        if leaf_ordinal >= self.response_leaf_count {
            return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource);
        }
        let row = self
            .encoded_oracle
            .encoded_row(usize::try_from(leaf_ordinal).map_err(|_| {
                CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource
            })?)
            .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(row.len())
            .map_err(|_| CompactPublicKeyFamilyMaterializationError::AllocationLimitExceeded)?;
        values.extend(row.iter().map(|value| {
            ProofBaseFieldElement::from_canonical(value.as_canonical_u64())
                .expect("a Goldilocks value is a canonical production base-field value")
        }));
        Ok(CompactOwnedResponseLeaf::base_field(values))
    }

    pub(crate) fn response_leaf_salt(
        &self,
        leaf_ordinal: u64,
        leaf: &CompactOwnedResponseLeaf,
    ) -> [u8; crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH] {
        self.randomness
            .private_leaf_salt(0, self.response_leaf_count, leaf_ordinal, leaf)
    }

    fn source_query_outputs(
        &self,
        query_positions: &[u64],
    ) -> Result<Vec<CompactChallengeField>, CompactPublicKeyFamilyMaterializationError> {
        let first_position = *query_positions
            .first()
            .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
        let first_row = self
            .encoded_oracle
            .encoded_row(usize::try_from(first_position).map_err(|_| {
                CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource
            })?)
            .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
        let output_count = query_positions
            .len()
            .checked_mul(first_row.len())
            .ok_or(CompactPublicKeyFamilyMaterializationError::AllocationLimitExceeded)?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(output_count)
            .map_err(|_| CompactPublicKeyFamilyMaterializationError::AllocationLimitExceeded)?;
        for position in query_positions {
            let row = self
                .encoded_oracle
                .encoded_row(usize::try_from(*position).map_err(|_| {
                    CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource
                })?)
                .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
            if row.len() != first_row.len() {
                return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource);
            }
            outputs.extend(row.iter().copied().map(CompactChallengeField::from));
        }
        Ok(outputs)
    }

    pub(crate) fn canonical_randomness_checkpoint_cursor_bytes(
        &self,
    ) -> [u8; COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH] {
        self.randomness.canonical_checkpoint_cursor_bytes()
    }
}

impl PreparedCompactPublicKeyMainEpoch {
    pub(crate) const fn family_material(&self) -> &CompactPublicKeyFamilyMaterial {
        &self.family_material
    }

    pub(crate) fn prepare_post_lookup_response(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        if self.post_lookup_material.is_some() {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let masking_coefficient_maps = validate_production_masking_inputs(&self.family_material)?;
        self.post_lookup_material = Some(prepare_post_lookup_material(
            &mut self.family_material,
            masking_coefficient_maps,
        )?);
        Ok(())
    }

    pub(crate) fn poll_post_lookup_response<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let post_lookup_material = post_lookup_material.as_mut().ok_or(
            CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ),
        )?;
        match response_generation_state
            .poll(storage)
            .map_err(CompactPublicKeyMainEpochPollError::ResponsePoll)?
        {
            CompactResponseGenerationPoll::ResponseRequired { response_ordinal }
                if matches!(response_ordinal, 1 | 2) =>
            {
                response_generation_state
                    .begin_response(
                        family_material
                            .metadata
                            .pre_challenge
                            .randomness
                            .fiat_shamir_round_salt(response_ordinal),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal: 1,
                leaf_ordinal,
            } => {
                let leaf = match post_lookup_material
                    .poll_response_leaf(
                        leaf_ordinal,
                        maximum_work_unit_count,
                        &family_material.row_source,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                {
                    CompactPublicKeyPostLookupResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    } => {
                        return Ok(
                            CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted {
                                processed_work_unit_count,
                            },
                        );
                    }
                    CompactPublicKeyPostLookupResponseLeafPoll::LeafReady(leaf) => leaf,
                };
                let leaf_salt = family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .private_leaf_salt(
                        1,
                        post_lookup_material.response_leaf_count,
                        leaf_ordinal,
                        &leaf,
                    );
                response_generation_state
                    .supply_next_response_leaf(&leaf, &leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                post_lookup_material
                    .mark_response_leaf_supplied(leaf_ordinal)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                Ok(CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal })
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal: 2,
                leaf_ordinal,
            } => {
                let leaf = match post_lookup_material
                    .poll_cross_epoch_response_leaf(
                        leaf_ordinal,
                        maximum_work_unit_count,
                        family_material,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                {
                    CompactPublicKeyCrossEpochResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                        evaluated_source_element_count,
                    } => {
                        return Ok(
                            CompactPublicKeyMainEpochPoll::CrossEpochEvaluationStepCompleted {
                                processed_work_unit_count,
                                evaluated_source_element_count,
                            },
                        );
                    }
                    CompactPublicKeyCrossEpochResponseLeafPoll::LeafReady(leaf) => leaf,
                };
                let masking_attempt_identity = if leaf_ordinal == 0 {
                    Some(
                        post_lookup_material
                            .verify_cross_epoch_masking_prefix(
                                family_material,
                                response_generation_state.verifier_messages(),
                                response_generation_state.canonical_proof_prefix_bytes(),
                            )
                            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?,
                    )
                } else if post_lookup_material.masking_attempt_identity.is_none() {
                    return Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ));
                } else {
                    None
                };
                let leaf_salt = family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .private_leaf_salt(
                        2,
                        post_lookup_material.cross_epoch_response_leaf_count,
                        leaf_ordinal,
                        &leaf,
                    );
                response_generation_state
                    .supply_next_response_leaf(&leaf, &leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                if leaf_ordinal == 0 {
                    post_lookup_material.masking_attempt_identity = masking_attempt_identity;
                }
                Ok(CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal })
            }
            CompactResponseGenerationPoll::OpenedLeafRequired {
                response_ordinal,
                leaf_ordinal,
            } => {
                let (leaf, leaf_salt) = match response_ordinal {
                    0 => {
                        let material = family_material.pre_challenge_material();
                        let leaf = material.response_leaf(leaf_ordinal).map_err(|error| {
                            CompactPublicKeyMainEpochPollError::Preparation(
                                CompactPublicKeyMainEpochPreparationError::Materialization(error),
                            )
                        })?;
                        let leaf_salt = material.response_leaf_salt(leaf_ordinal, &leaf);
                        (leaf, leaf_salt)
                    }
                    1 => {
                        let opening_query_leaf_ordinals = response_generation_state
                            .current_opening_query_leaf_ordinals(response_ordinal)
                            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                                CompactPublicKeyMainEpochPreparationError::WrongPhase,
                            ))?;
                        let leaf = match post_lookup_material
                            .poll_opened_response_leaf(
                                leaf_ordinal,
                                maximum_work_unit_count,
                                &family_material.row_source,
                                opening_query_leaf_ordinals,
                            )
                            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                        {
                            CompactPublicKeyPostLookupResponseLeafPoll::ArithmeticStepCompleted {
                                processed_work_unit_count,
                            } => {
                                return Ok(
                                    CompactPublicKeyMainEpochPoll::MainSourceArithmeticStepCompleted {
                                        processed_work_unit_count,
                                    },
                                );
                            }
                            CompactPublicKeyPostLookupResponseLeafPoll::LeafReady(leaf) => leaf,
                        };
                        let leaf_salt = family_material
                            .metadata
                            .pre_challenge
                            .randomness
                            .private_leaf_salt(
                                1,
                                post_lookup_material.response_leaf_count,
                                leaf_ordinal,
                                &leaf,
                            );
                        (leaf, leaf_salt)
                    }
                    2 => {
                        let leaf = post_lookup_material
                            .cross_epoch_response_leaf(leaf_ordinal)
                            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                        let leaf_salt = family_material
                            .metadata
                            .pre_challenge
                            .randomness
                            .private_leaf_salt(
                                2,
                                post_lookup_material.cross_epoch_response_leaf_count,
                                leaf_ordinal,
                                &leaf,
                            );
                        (leaf, leaf_salt)
                    }
                    _ => {
                        return Err(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ));
                    }
                };
                response_generation_state
                    .supply_next_opened_leaf(&leaf, leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                if response_ordinal == 1 {
                    post_lookup_material
                        .mark_response_leaf_supplied(leaf_ordinal)
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                }
                Ok(CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                })
            }
            CompactResponseGenerationPoll::ArithmeticStepCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::StorageTransactionCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted)
            }
            CompactResponseGenerationPoll::CheckpointCursorRequired => {
                let completed_cross_epoch_response = response_generation_state
                    .verifier_message_authority(2)
                    .is_some();
                let canonical_randomness_cursor = family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .canonical_checkpoint_cursor_bytes();
                response_generation_state
                    .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                if completed_cross_epoch_response {
                    let authority = response_generation_state
                        .verifier_message_authority(2)
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?;
                    post_lookup_material
                        .prepare_initial_cfw_prover(family_material, authority.message())
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    Ok(CompactPublicKeyMainEpochPoll::CrossEpochCheckpointReady)
                } else {
                    let authority = response_generation_state
                        .verifier_message_authority(1)
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?;
                    let cross_epoch_point = cross_epoch_point_from_verifier_message(
                        family_material,
                        authority.message(),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    let canonical_transcript_cursor_bytes = response_generation_state
                        .checkpoint_boundary()
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?
                        .canonical_transcript_cursor_bytes();
                    post_lookup_material
                        .prepare_cross_epoch_evaluation(
                            family_material,
                            cross_epoch_point,
                            canonical_transcript_cursor_bytes,
                        )
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    Ok(CompactPublicKeyMainEpochPoll::PostLookupCheckpointReady)
                }
            }
            CompactResponseGenerationPoll::ResponseRequired { .. }
            | CompactResponseGenerationPoll::ResponseLeafRequired { .. }
            | CompactResponseGenerationPoll::Complete => {
                Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn cfw_mask_material(&self) -> Option<&CompactCfwMaskMaterial> {
        Some(&self.post_lookup_material.as_ref()?.cfw_mask_material)
    }

    #[cfg(test)]
    pub(crate) fn cfw_auxiliary_target(&self) -> Option<CompactChallengeField> {
        Some(self.post_lookup_material.as_ref()?.cfw_auxiliary_target)
    }

    #[cfg(test)]
    pub(crate) fn cross_epoch_point(&self) -> Option<&[CompactChallengeField]> {
        self.post_lookup_material
            .as_ref()?
            .cross_epoch_point
            .as_deref()
    }

    #[cfg(test)]
    pub(crate) fn cross_epoch_disclosed_values(&self) -> Option<[CompactChallengeField; 3]> {
        Some(
            self.post_lookup_material
                .as_ref()?
                .cross_epoch_claims
                .as_ref()?
                .disclosed_values(),
        )
    }

    #[cfg(test)]
    pub(crate) fn cross_epoch_masking_prefix_verified(&self) -> bool {
        self.post_lookup_material
            .as_ref()
            .is_some_and(|material| material.masking_attempt_identity.is_some())
    }

    #[cfg(test)]
    pub(crate) fn cfw_prover_auxiliary_target(&self) -> Option<CompactChallengeField> {
        Some(
            self.post_lookup_material
                .as_ref()?
                .cfw_external_prover
                .as_ref()?
                .auxiliary_target(),
        )
    }

    #[cfg(test)]
    pub(crate) fn completed_cfw_round_count(&self) -> Option<usize> {
        self.post_lookup_material
            .as_ref()?
            .completed_cfw_round_count()
            .ok()
    }

    #[cfg(test)]
    pub(crate) fn cfw_finish_masking_verified(&self) -> bool {
        self.post_lookup_material
            .as_ref()
            .is_some_and(|material| material.cfw_external_output.is_some())
    }

    #[cfg(test)]
    pub(crate) fn cfw_external_memory_usage(&self) -> Option<ProofExternalMemoryUsage> {
        Some(
            self.post_lookup_material
                .as_ref()?
                .cfw_external_output
                .as_ref()?
                .usage(),
        )
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_sumcheck_complete(&self, batch_ordinal: u8) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| {
                material
                    .pre_challenge_whir_sumcheck_batches
                    .get(usize::from(batch_ordinal))
            })
            .is_some_and(|batch| batch.batch_ordinal == batch_ordinal && batch.state.is_complete())
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_sumcheck_output_count(
        &self,
        batch_ordinal: u8,
    ) -> Option<usize> {
        Some(
            self.post_lookup_material
                .as_ref()?
                .pre_challenge_whir_sumcheck_batches
                .get(usize::from(batch_ordinal))?
                .masking_outputs
                .len(),
        )
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_residual_length(&self, batch_ordinal: u8) -> Option<usize> {
        self.post_lookup_material
            .as_ref()?
            .pre_challenge_whir_sumcheck_batches
            .get(usize::from(batch_ordinal))?
            .state
            .residual_source()
            .ok()
            .map(<[CompactChallengeField]>::len)
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_first_code_switch_ready(&self) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| material.pre_challenge_whir_first_code_switch.as_ref())
            .is_some_and(|state| state.switch_mask_oracle().is_ok())
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_first_code_switch_bound(&self) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| material.pre_challenge_whir_first_code_switch.as_ref())
            .is_some_and(CompactWhirCodeSwitchState::verifier_move_is_bound)
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_first_source_query_masking_verified(&self) -> bool {
        self.post_lookup_material
            .as_ref()
            .is_some_and(|material| material.pre_challenge_whir_first_source_query_masking_verified)
    }

    pub(crate) fn poll_cfw<
        ResponseStorage: ProofExternalMemory,
        CfwStorage: ProofExternalMemory,
    >(
        &mut self,
        response_storage: &mut ResponseStorage,
        cfw_storage: &mut CfwStorage,
    ) -> Result<
        CompactPublicKeyMainEpochPoll,
        CompactPublicKeyMainEpochPollError<ResponseStorage::Error, CfwStorage::Error>,
    > {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material.as_mut().ok_or(
            CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ),
        )?;
        let cfw_round_count = material.cfw_geometry.sumcheck_round_count();

        if material.cfw_bound_round_advance_required {
            let completed_round_count = material
                .completed_cfw_round_count()
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let round_index = completed_round_count.checked_sub(1).ok_or(
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ),
            )?;
            let round_complete = material
                .cfw_external_prover
                .as_mut()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?
                .advance_bound_round(&family_material.row_source, cfw_storage)
                .map_err(CompactPublicKeyMainEpochPollError::CfwExecution)?;
            if round_complete {
                material.cfw_bound_round_advance_required = false;
                if completed_round_count == cfw_round_count {
                    let external_prover = material.cfw_external_prover.take().ok_or(
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ),
                    )?;
                    let output = external_prover
                        .finish()
                        .map_err(CompactPublicKeyMainEpochPollError::CfwFinish)?;
                    material
                        .verify_cfw_finish_masking(
                            response_generation_state.verifier_messages(),
                            &output,
                        )
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    material.cfw_external_output = Some(output);
                }
            }
            return Ok(CompactPublicKeyMainEpochPoll::CfwBoundRoundStepCompleted {
                round_ordinal: u32::try_from(round_index).map_err(|_| {
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    )
                })?,
                round_complete,
            });
        }

        if material.cfw_external_output.is_none() && material.pending_cfw_round_polynomial.is_none()
        {
            let round_index = material
                .completed_cfw_round_count()
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            if round_index >= cfw_round_count {
                return Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ));
            }
            let round_polynomial = material
                .cfw_external_prover
                .as_mut()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?
                .advance_round_polynomial(&family_material.row_source, cfw_storage)
                .map_err(CompactPublicKeyMainEpochPollError::CfwExecution)?;
            let polynomial_ready = round_polynomial.is_some();
            if let Some(round_polynomial) = round_polynomial {
                material
                    .verify_cfw_round_masking(
                        response_generation_state.verifier_messages(),
                        &round_polynomial,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                material.pending_cfw_round_polynomial = Some(round_polynomial);
            }
            return Ok(
                CompactPublicKeyMainEpochPoll::CfwRoundPolynomialStepCompleted {
                    round_ordinal: u32::try_from(round_index).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?,
                    polynomial_ready,
                },
            );
        }

        let expected_response_ordinal = material
            .expected_cfw_response_ordinal()
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
        match response_generation_state
            .poll(response_storage)
            .map_err(CompactPublicKeyMainEpochPollError::ResponsePoll)?
        {
            CompactResponseGenerationPoll::ResponseRequired { response_ordinal }
                if response_ordinal == expected_response_ordinal =>
            {
                response_generation_state
                    .begin_response(
                        family_material
                            .pre_challenge_material()
                            .randomness
                            .fiat_shamir_round_salt(response_ordinal),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal,
                leaf_ordinal,
            } if response_ordinal == expected_response_ordinal => {
                let leaf = material
                    .cfw_response_leaf(response_ordinal, leaf_ordinal)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let response_leaf_count = family_material
                    .response_merkle_geometries()
                    .get(usize::try_from(response_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    ))?
                    .merkle_leaf_count();
                let leaf_salt = family_material
                    .pre_challenge_material()
                    .randomness
                    .private_leaf_salt(response_ordinal, response_leaf_count, leaf_ordinal, &leaf);
                response_generation_state
                    .supply_next_response_leaf(&leaf, &leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal })
            }
            CompactResponseGenerationPoll::OpenedLeafRequired {
                response_ordinal,
                leaf_ordinal,
            } => {
                let leaf = compact_public_key_response_leaf(
                    family_material,
                    material,
                    response_ordinal,
                    leaf_ordinal,
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let response_leaf_count = family_material
                    .response_merkle_geometries()
                    .get(usize::try_from(response_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    ))?
                    .merkle_leaf_count();
                let leaf_salt = family_material
                    .pre_challenge_material()
                    .randomness
                    .private_leaf_salt(response_ordinal, response_leaf_count, leaf_ordinal, &leaf);
                response_generation_state
                    .supply_next_opened_leaf(&leaf, leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal,
                    leaf_ordinal,
                })
            }
            CompactResponseGenerationPoll::ArithmeticStepCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::StorageTransactionCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted)
            }
            CompactResponseGenerationPoll::CheckpointCursorRequired => {
                let completed_response_ordinal = u32::try_from(
                    response_generation_state
                        .verifier_messages()
                        .len()
                        .checked_sub(1)
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?,
                )
                .map_err(|_| {
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    )
                })?;
                if completed_response_ordinal != expected_response_ordinal {
                    return Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ));
                }
                if material.cfw_external_output.is_some() {
                    let canonical_randomness_cursor = family_material
                        .pre_challenge_material()
                        .randomness
                        .canonical_checkpoint_cursor_bytes();
                    response_generation_state
                        .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                        .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                    return Ok(CompactPublicKeyMainEpochPoll::CfwFinalResponseCheckpointReady);
                }

                let round_index = material
                    .completed_cfw_round_count()
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let round_ordinal = u32::try_from(round_index).map_err(|_| {
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    )
                })?;
                let round_challenge = {
                    let authority = response_generation_state
                        .verifier_message_authority(completed_response_ordinal)
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?;
                    cfw_round_challenge_from_verifier_message(
                        family_material,
                        round_ordinal,
                        authority.message(),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                };
                match material.pending_cfw_bound_challenge {
                    Some(bound_challenge) if bound_challenge == round_challenge => {}
                    Some(_) => {
                        return Err(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ));
                    }
                    None => {
                        material
                            .cfw_external_prover
                            .as_mut()
                            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                                CompactPublicKeyMainEpochPreparationError::WrongPhase,
                            ))?
                            .bind_round_challenge(round_challenge)
                            .map_err(|error| {
                                CompactPublicKeyMainEpochPollError::Preparation(error.into())
                            })?;
                        material.pending_cfw_bound_challenge = Some(round_challenge);
                    }
                }
                let canonical_randomness_cursor = family_material
                    .pre_challenge_material()
                    .randomness
                    .canonical_checkpoint_cursor_bytes();
                response_generation_state
                    .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                let round_polynomial = material.pending_cfw_round_polynomial.take().ok_or(
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ),
                )?;
                material
                    .cfw_outer_masking_outputs
                    .extend_from_slice(&round_polynomial);
                material.pending_cfw_bound_challenge = None;
                material.cfw_bound_round_advance_required = true;
                Ok(
                    CompactPublicKeyMainEpochPoll::CfwRoundResponseCheckpointReady {
                        round_ordinal,
                    },
                )
            }
            CompactResponseGenerationPoll::ResponseRequired { .. }
            | CompactResponseGenerationPoll::ResponseLeafRequired { .. }
            | CompactResponseGenerationPoll::Complete => {
                Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))
            }
        }
    }

    pub(crate) fn prepare_pre_challenge_whir_initial_sumcheck(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if material.cfw_external_output.is_none()
            || material.pre_challenge_whir_relation_preparation.is_some()
            || !material.pre_challenge_whir_sumcheck_batches.is_empty()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let expected_message_count = material
            .cfw_geometry
            .sumcheck_round_count()
            .checked_add(4)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if response_generation_state.verifier_messages().len() != expected_message_count
            || response_generation_state.checkpoint_boundary().is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let contract = selected_compact_public_key_proof_contract()?;
        let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        let opening_batching_challenge = unique_completed_extension_role_challenge(
            &contract.verifier_inputs(),
            response_generation_state.verifier_messages(),
            6,
            pre_challenge_epoch.epoch,
            0,
            0,
        )?;
        let point = material
            .cross_epoch_point
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .clone();
        let [
            masked_pre_challenge_evaluation,
            masked_main_evaluation,
            mask_difference,
        ] = material
            .cross_epoch_claims
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .disclosed_values();
        if family_material
            .metadata
            .pre_challenge
            .encoded_oracle
            .encoding_randomness()
            .is_empty()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let source = family_material
            .metadata
            .pre_challenge
            .encoded_oracle
            .take_source_message()?;
        material.pre_challenge_whir_relation_preparation =
            Some(CompactWhirPreChallengeRelationPreparation::new(
                source,
                point,
                masked_pre_challenge_evaluation,
                masked_main_evaluation,
                mask_difference,
                material.cross_epoch_masks[0],
                material.cross_epoch_masks[1],
                opening_batching_challenge,
            )?);
        Ok(())
    }

    pub(crate) fn poll_pre_challenge_whir_sumcheck<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material.as_mut().ok_or(
            CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ),
        )?;

        if let Some(preparation) = material.pre_challenge_whir_relation_preparation.as_mut() {
            match preparation
                .poll(maximum_work_unit_count)
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
            {
                CompactWhirPreChallengeRelationPreparationPoll::StepCompleted {
                    step,
                    processed_work_unit_count,
                } => {
                    return Ok(
                        CompactPublicKeyMainEpochPoll::PreChallengeWhirRelationStepCompleted {
                            step,
                            processed_work_unit_count,
                        },
                    );
                }
                CompactWhirPreChallengeRelationPreparationPoll::Complete => {}
            }
            let preparation = material
                .pre_challenge_whir_relation_preparation
                .take()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?;
            let relation = preparation
                .finish()
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let contract = selected_compact_public_key_proof_contract()
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs else {
                return Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                ));
            };
            let configuration = compact_whir_configuration_from_contract(pre_challenge_epoch)
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let mask_group = unique_internal_mask_group(pre_challenge_epoch, 4, 0)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let initial_sumcheck = CompactWhirInitialSumcheckState::new(
                relation,
                &configuration,
                0,
                mask_group,
                family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .whir_random_source_mut(),
            )
            .map_err(CompactPublicKeyMainEpochPreparationError::from)
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            family_material
                .metadata
                .pre_challenge
                .randomness
                .ensure_field_sampling_valid()
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let response_ordinal = material
                .pre_challenge_whir_initial_response_ordinal()
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let response_index = usize::try_from(response_ordinal).map_err(|_| {
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                )
            })?;
            let response_geometry = family_material
                .response_merkle_geometries()
                .get(response_index)
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                ))?;
            let response_roles = contract
                .verifier_inputs()
                .response_component_roles
                .get(response_index)
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                ))?;
            validate_whir_sumcheck_response_geometry(
                response_geometry,
                response_roles,
                pre_challenge_epoch.epoch,
                0,
                initial_sumcheck.mask_oracle(),
            )
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            verify_selected_compact_whir_sumcheck_auxiliary_masking(
                contract.verifier_inputs(),
                &material.masking_coefficient_maps,
                material.masking_attempt_identity.ok_or(
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ),
                )?,
                response_generation_state.verifier_messages(),
                pre_challenge_epoch.epoch,
                0,
                initial_sumcheck.auxiliary_target(),
            )
            .map_err(|error| {
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WhirSumcheckAuxiliaryMasking(error),
                )
            })?;
            material.pre_challenge_whir_sumcheck_batches.push(
                CompactPublicKeyWhirSumcheckBatch::new(
                    0,
                    response_ordinal,
                    initial_sumcheck,
                    response_geometry.merkle_leaf_count(),
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?,
            );
            return Ok(
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared {
                    batch_ordinal: 0,
                },
            );
        }

        let active_batch_ordinal = material
            .pre_challenge_whir_sumcheck_batches
            .last()
            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ))?
            .batch_ordinal;
        if material
            .pre_challenge_whir_sumcheck_batches
            .last()
            .is_some_and(|batch| batch.bound_round_advance_required)
        {
            let sumcheck_poll = material
                .pre_challenge_whir_sumcheck_batches
                .last_mut()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?
                .state
                .poll(maximum_work_unit_count)
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            return match sumcheck_poll {
                CompactWhirInitialSumcheckPoll::BoundRoundStepCompleted {
                    round_ordinal,
                    round_complete,
                    ..
                } => {
                    let active_batch = material
                        .pre_challenge_whir_sumcheck_batches
                        .last_mut()
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?;
                    if round_complete
                        && active_batch.state.round_challenges().len()
                            < active_batch.state.mask_messages().len()
                    {
                        active_batch.bound_round_advance_required = false;
                    }
                    Ok(
                        CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                            batch_ordinal: active_batch_ordinal,
                            round_ordinal,
                            round_complete,
                        },
                    )
                }
                CompactWhirInitialSumcheckPoll::WeightScalingStepCompleted {
                    scaling_complete,
                    ..
                } => {
                    if scaling_complete {
                        material
                            .pre_challenge_whir_sumcheck_batches
                            .last_mut()
                            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                                CompactPublicKeyMainEpochPreparationError::WrongPhase,
                            ))?
                            .bound_round_advance_required = false;
                        material
                            .validate_pre_challenge_whir_sumcheck_completion(
                                response_generation_state.verifier_messages(),
                                material
                                    .pre_challenge_whir_sumcheck_batches
                                    .len()
                                    .checked_sub(1)
                                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                                    ))?,
                            )
                            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                        Ok(
                            CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete {
                                batch_ordinal: active_batch_ordinal,
                            },
                        )
                    } else {
                        Ok(
                            CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                                batch_ordinal: active_batch_ordinal,
                                scaling_complete,
                            },
                        )
                    }
                }
                CompactWhirInitialSumcheckPoll::RoundPolynomialStepCompleted { .. } => {
                    Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ))
                }
            };
        }

        if material
            .pre_challenge_whir_sumcheck_batches
            .last()
            .is_some_and(|batch| batch.combination_challenge_bound)
            && material
                .pre_challenge_whir_sumcheck_batches
                .last()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?
                .state
                .pending_round_wire()
                .is_err()
        {
            let sumcheck = &mut material
                .pre_challenge_whir_sumcheck_batches
                .last_mut()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?
                .state;
            return match sumcheck
                .poll(maximum_work_unit_count)
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
            {
                CompactWhirInitialSumcheckPoll::RoundPolynomialStepCompleted {
                    round_ordinal,
                    polynomial_ready,
                    ..
                } => Ok(
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                        batch_ordinal: active_batch_ordinal,
                        round_ordinal,
                        polynomial_ready,
                    },
                ),
                _ => Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                )),
            };
        }

        let response_ordinal = material
            .expected_pre_challenge_whir_response_ordinal()
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
        let initial_response_ordinal = material
            .pre_challenge_whir_sumcheck_initial_response_ordinal(active_batch_ordinal)
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
        if response_ordinal != initial_response_ordinal
            && !material
                .pre_challenge_whir_sumcheck_batches
                .last()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?
                .round_masking_verified
        {
            let contract = selected_compact_public_key_proof_contract()
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs else {
                return Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                ));
            };
            let active_batch = material.pre_challenge_whir_sumcheck_batches.last().ok_or(
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ),
            )?;
            let round_index = active_batch.state.round_challenges().len();
            let round_ordinal = u32::try_from(round_index).map_err(|_| {
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                )
            })?;
            let round_wire = active_batch
                .state
                .pending_round_wire()
                .map_err(|error| CompactPublicKeyMainEpochPollError::Preparation(error.into()))?;
            verify_selected_compact_whir_sumcheck_round_masking(
                contract.verifier_inputs(),
                &material.masking_coefficient_maps,
                material.masking_attempt_identity.ok_or(
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ),
                )?,
                response_generation_state.verifier_messages(),
                pre_challenge_epoch.epoch,
                active_batch_ordinal,
                round_ordinal,
                &active_batch.masking_outputs,
                round_wire,
            )
            .map_err(|error| {
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WhirSumcheckRoundMasking {
                        round_ordinal,
                        error,
                    },
                )
            })?;
            material
                .pre_challenge_whir_sumcheck_batches
                .last_mut()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?
                .round_masking_verified = true;
        }

        match response_generation_state
            .poll(response_storage)
            .map_err(CompactPublicKeyMainEpochPollError::ResponsePoll)?
        {
            CompactResponseGenerationPoll::ResponseRequired {
                response_ordinal: required_response_ordinal,
            } if required_response_ordinal == response_ordinal => {
                response_generation_state
                    .begin_response(
                        family_material
                            .pre_challenge_material()
                            .randomness
                            .fiat_shamir_round_salt(response_ordinal),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal: required_response_ordinal,
                leaf_ordinal,
            } if required_response_ordinal == response_ordinal => {
                let leaf = material
                    .pre_challenge_whir_response_leaf(response_ordinal, leaf_ordinal)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let response_leaf_count = family_material
                    .response_merkle_geometries()
                    .get(usize::try_from(response_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    ))?
                    .merkle_leaf_count();
                let leaf_salt = family_material
                    .pre_challenge_material()
                    .randomness
                    .private_leaf_salt(response_ordinal, response_leaf_count, leaf_ordinal, &leaf);
                response_generation_state
                    .supply_next_response_leaf(&leaf, &leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal })
            }
            CompactResponseGenerationPoll::OpenedLeafRequired {
                response_ordinal: opened_response_ordinal,
                leaf_ordinal,
            } => {
                let leaf = compact_public_key_response_leaf(
                    family_material,
                    material,
                    opened_response_ordinal,
                    leaf_ordinal,
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let response_leaf_count = family_material
                    .response_merkle_geometries()
                    .get(usize::try_from(opened_response_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    ))?
                    .merkle_leaf_count();
                let leaf_salt = family_material
                    .pre_challenge_material()
                    .randomness
                    .private_leaf_salt(
                        opened_response_ordinal,
                        response_leaf_count,
                        leaf_ordinal,
                        &leaf,
                    );
                response_generation_state
                    .supply_next_opened_leaf(&leaf, leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal: opened_response_ordinal,
                    leaf_ordinal,
                })
            }
            CompactResponseGenerationPoll::ArithmeticStepCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::StorageTransactionCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted)
            }
            CompactResponseGenerationPoll::CheckpointCursorRequired => {
                let _authority = response_generation_state
                    .verifier_message_authority(response_ordinal)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ))?;
                let contract = selected_compact_public_key_proof_contract()
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs
                else {
                    return Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    ));
                };
                let canonical_randomness_cursor = family_material
                    .pre_challenge_material()
                    .randomness
                    .canonical_checkpoint_cursor_bytes();
                if response_ordinal == initial_response_ordinal {
                    let challenge = unique_completed_extension_role_challenge(
                        &contract.verifier_inputs(),
                        response_generation_state.verifier_messages(),
                        7,
                        pre_challenge_epoch.epoch,
                        active_batch_ordinal,
                        0,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    let active_batch = material
                        .pre_challenge_whir_sumcheck_batches
                        .last_mut()
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?;
                    active_batch
                        .state
                        .bind_combination_challenge(challenge)
                        .map_err(CompactPublicKeyMainEpochPreparationError::from)
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    response_generation_state
                        .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                        .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                    active_batch.combination_challenge_bound = true;
                    Ok(CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                        batch_ordinal: active_batch_ordinal,
                    })
                } else {
                    let active_batch = material
                        .pre_challenge_whir_sumcheck_batches
                        .last_mut()
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?;
                    let round_index = active_batch.state.round_challenges().len();
                    let round_ordinal = u32::try_from(round_index).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?;
                    let challenge = unique_completed_extension_role_challenge(
                        &contract.verifier_inputs(),
                        response_generation_state.verifier_messages(),
                        8,
                        pre_challenge_epoch.epoch,
                        active_batch_ordinal,
                        round_ordinal,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    let round_wire = active_batch
                        .state
                        .pending_round_wire()
                        .map_err(CompactPublicKeyMainEpochPreparationError::from)
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                        .to_vec();
                    active_batch
                        .state
                        .bind_round_challenge(challenge)
                        .map_err(CompactPublicKeyMainEpochPreparationError::from)
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    response_generation_state
                        .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                        .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                    active_batch.masking_outputs.extend_from_slice(&round_wire);
                    active_batch.round_masking_verified = false;
                    active_batch.bound_round_advance_required = true;
                    Ok(
                        CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                            batch_ordinal: active_batch_ordinal,
                            round_ordinal,
                        },
                    )
                }
            }
            CompactResponseGenerationPoll::ResponseRequired { .. }
            | CompactResponseGenerationPoll::ResponseLeafRequired { .. }
            | CompactResponseGenerationPoll::Complete => {
                Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))
            }
        }
    }

    pub(crate) fn prepare_pre_challenge_whir_first_code_switch(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let initial_sumcheck_batch = material
            .pre_challenge_whir_sumcheck_batches
            .first()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if material.pre_challenge_whir_first_code_switch.is_some()
            || material.pre_challenge_whir_first_code_switch_response_leaf_count != 0
            || material.pre_challenge_whir_first_source_query_masking_verified
            || material.pre_challenge_whir_sumcheck_batches.len() != 1
            || initial_sumcheck_batch.batch_ordinal != 0
            || initial_sumcheck_batch.bound_round_advance_required
            || initial_sumcheck_batch.round_masking_verified
            || !initial_sumcheck_batch.combination_challenge_bound
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        material.validate_pre_challenge_whir_sumcheck_completion(
            response_generation_state.verifier_messages(),
            0,
        )?;
        let response_ordinal = material.pre_challenge_whir_first_code_switch_response_ordinal()?;
        if response_generation_state.verifier_messages().len()
            != usize::try_from(response_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            || response_generation_state.checkpoint_boundary().is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }

        let contract = selected_compact_public_key_proof_contract()?;
        let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        let previous_source_contract =
            unique_whir_fold_contract(&contract.verifier_inputs(), pre_challenge_epoch.epoch, 0)?;
        let next_source_contract =
            unique_whir_fold_contract(&contract.verifier_inputs(), pre_challenge_epoch.epoch, 1)?;
        let switch_mask_contract = unique_internal_mask_group(pre_challenge_epoch, 5, 0)?;
        let (source_evaluations, folding_challenges) = {
            let initial_sumcheck = &mut material
                .pre_challenge_whir_sumcheck_batches
                .first_mut()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            let folding_challenges = initial_sumcheck.state.round_challenges().to_vec();
            let source_evaluations = initial_sumcheck.state.take_residual_source()?;
            (source_evaluations, folding_challenges)
        };
        let previous_encoding_randomness = family_material
            .metadata
            .pre_challenge
            .encoded_oracle
            .take_encoding_randomness()?;
        let code_switch = CompactWhirCodeSwitchState::new(
            source_evaluations,
            previous_encoding_randomness,
            &folding_challenges,
            previous_source_contract,
            next_source_contract,
            switch_mask_contract,
            family_material
                .metadata
                .pre_challenge
                .randomness
                .whir_random_source_mut(),
        )?;
        family_material
            .metadata
            .pre_challenge
            .randomness
            .ensure_field_sampling_valid()?;
        material.pre_challenge_whir_first_code_switch = Some(code_switch);
        Ok(())
    }

    pub(crate) fn poll_pre_challenge_whir_first_code_switch<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material.as_mut().ok_or(
            CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ),
        )?;
        let response_ordinal = material
            .pre_challenge_whir_first_code_switch_response_ordinal()
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;

        if material.pre_challenge_whir_first_code_switch_response_leaf_count == 0 {
            let code_switch = material
                .pre_challenge_whir_first_code_switch
                .as_mut()
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?;
            match code_switch
                .poll_preparation(maximum_work_unit_count)
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
            {
                CompactWhirCodeSwitchPreparationPoll::RandomnessFoldStepCompleted {
                    processed_work_unit_count,
                    fold_complete,
                } => {
                    return Ok(
                        CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted {
                            processed_work_unit_count,
                            fold_complete,
                        },
                    );
                }
                CompactWhirCodeSwitchPreparationPoll::Complete => {}
            }
            let contract = selected_compact_public_key_proof_contract()
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs else {
                return Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                ));
            };
            let response_index = usize::try_from(response_ordinal).map_err(|_| {
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                )
            })?;
            let response_geometry = family_material
                .response_merkle_geometries()
                .get(response_index)
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                ))?;
            let response_roles = contract
                .verifier_inputs()
                .response_component_roles
                .get(response_index)
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                ))?;
            validate_whir_code_switch_response_geometry(
                response_geometry,
                response_roles,
                pre_challenge_epoch.epoch,
                0,
                code_switch.source_oracle(),
                code_switch
                    .switch_mask_oracle()
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?,
            )
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            material.pre_challenge_whir_first_code_switch_response_leaf_count =
                response_geometry.merkle_leaf_count();
            return Ok(CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared);
        }

        match response_generation_state
            .poll(response_storage)
            .map_err(CompactPublicKeyMainEpochPollError::ResponsePoll)?
        {
            CompactResponseGenerationPoll::ResponseRequired {
                response_ordinal: required_response_ordinal,
            } if required_response_ordinal == response_ordinal => {
                response_generation_state
                    .begin_response(
                        family_material
                            .pre_challenge_material()
                            .randomness
                            .fiat_shamir_round_salt(response_ordinal),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal: required_response_ordinal,
                leaf_ordinal,
            } if required_response_ordinal == response_ordinal => {
                match material
                    .poll_first_code_switch_response_leaf(
                        leaf_ordinal,
                        maximum_work_unit_count,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                {
                    CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    } => Ok(
                        CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted {
                            processed_work_unit_count,
                        },
                    ),
                    CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(leaf) => {
                        let response_leaf_count = material
                            .pre_challenge_whir_first_code_switch_response_leaf_count;
                        let leaf_salt = family_material
                            .pre_challenge_material()
                            .randomness
                            .private_leaf_salt(
                                response_ordinal,
                                response_leaf_count,
                                leaf_ordinal,
                                &leaf,
                            );
                        response_generation_state
                            .supply_next_response_leaf(&leaf, &leaf_salt)
                            .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                        material
                            .mark_first_code_switch_response_leaf_supplied(leaf_ordinal)
                            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                        Ok(CompactPublicKeyMainEpochPoll::ResponseLeafSupplied {
                            leaf_ordinal,
                        })
                    }
                }
            }
            CompactResponseGenerationPoll::OpenedLeafRequired {
                response_ordinal: opened_response_ordinal,
                leaf_ordinal,
            } => {
                if !material.pre_challenge_whir_first_source_query_masking_verified {
                    let contract = selected_compact_public_key_proof_contract()
                        .map_err(CompactPublicKeyMainEpochPreparationError::from)
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs
                    else {
                        return Err(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        ));
                    };
                    let (combination_challenge, query_positions) =
                        completed_code_switch_verifier_move(
                            &contract.verifier_inputs(),
                            response_generation_state.verifier_messages(),
                            pre_challenge_epoch.epoch,
                            0,
                        )
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    let query_outputs = family_material
                        .pre_challenge_material()
                        .source_query_outputs(query_positions)
                        .map_err(CompactPublicKeyMainEpochPreparationError::from)
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    verify_selected_compact_whir_source_query_masking(
                        contract.verifier_inputs(),
                        &material.masking_coefficient_maps,
                        material.masking_attempt_identity.ok_or(
                            CompactPublicKeyMainEpochPollError::Preparation(
                                CompactPublicKeyMainEpochPreparationError::WrongPhase,
                            ),
                        )?,
                        response_generation_state.verifier_messages(),
                        pre_challenge_epoch.epoch,
                        0,
                        &query_outputs,
                    )
                    .map_err(|error| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WhirSourceQueryMasking {
                                source_ordinal: 0,
                                error,
                            },
                        )
                    })?;
                    let folding_challenges = material
                        .pre_challenge_whir_sumcheck_batches
                        .first()
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?
                        .state
                        .round_challenges()
                        .to_vec();
                    let folded_source_openings = fold_compact_whir_query_major_source_openings(
                        &query_outputs,
                        query_positions.len(),
                        &folding_challenges,
                    )
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    material
                        .pre_challenge_whir_first_code_switch
                        .as_mut()
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?
                        .bind_verifier_move(
                            query_positions,
                            combination_challenge,
                            folded_source_openings,
                        )
                        .map_err(CompactPublicKeyMainEpochPreparationError::from)
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    material.pre_challenge_whir_first_source_query_masking_verified = true;
                }
                let leaf = compact_public_key_response_leaf(
                    family_material,
                    material,
                    opened_response_ordinal,
                    leaf_ordinal,
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let response_leaf_count = family_material
                    .response_merkle_geometries()
                    .get(usize::try_from(opened_response_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    ))?
                    .merkle_leaf_count();
                let leaf_salt = family_material
                    .pre_challenge_material()
                    .randomness
                    .private_leaf_salt(
                        opened_response_ordinal,
                        response_leaf_count,
                        leaf_ordinal,
                        &leaf,
                    );
                response_generation_state
                    .supply_next_opened_leaf(&leaf, leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(CompactPublicKeyMainEpochPoll::OpenedResponseLeafSupplied {
                    response_ordinal: opened_response_ordinal,
                    leaf_ordinal,
                })
            }
            CompactResponseGenerationPoll::ArithmeticStepCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseArithmeticStepCompleted)
            }
            CompactResponseGenerationPoll::StorageTransactionCompleted => {
                Ok(CompactPublicKeyMainEpochPoll::ResponseStorageTransactionCompleted)
            }
            CompactResponseGenerationPoll::CheckpointCursorRequired => {
                if !material.pre_challenge_whir_first_source_query_masking_verified {
                    return Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ));
                }
                let _authority = response_generation_state
                    .verifier_message_authority(response_ordinal)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ))?;
                if !material
                    .pre_challenge_whir_first_code_switch
                    .as_ref()
                    .is_some_and(CompactWhirCodeSwitchState::verifier_move_is_bound)
                {
                    return Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ));
                }
                let canonical_randomness_cursor = family_material
                    .pre_challenge_material()
                    .randomness
                    .canonical_checkpoint_cursor_bytes();
                response_generation_state
                    .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirFirstCodeSwitchResponseCheckpointReady,
                )
            }
            CompactResponseGenerationPoll::ResponseRequired { .. }
            | CompactResponseGenerationPoll::ResponseLeafRequired { .. }
            | CompactResponseGenerationPoll::Complete => {
                Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))
            }
        }
    }

    pub(crate) fn prepare_pre_challenge_whir_second_sumcheck(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let Self {
            response_generation_state,
            post_lookup_material,
            ..
        } = self;
        let material = post_lookup_material
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let code_switch_response_ordinal =
            material.pre_challenge_whir_first_code_switch_response_ordinal()?;
        if material
            .pre_challenge_whir_first_code_switch_relation_preparation
            .is_some()
            || material.pre_challenge_whir_sumcheck_batches.len() != 1
            || !material.pre_challenge_whir_first_source_query_masking_verified
            || response_generation_state.verifier_messages().len()
                != usize::try_from(code_switch_response_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
                    .checked_add(1)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            || response_generation_state.checkpoint_boundary().is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let initial_sumcheck = &mut material
            .pre_challenge_whir_sumcheck_batches
            .first_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let source_claim = initial_sumcheck.state.residual_source_claim()?;
        let preceding_mask_claim = initial_sumcheck.state.residual_mask_claim()?;
        let target = initial_sumcheck.state.residual_target()?;
        let source_covector = initial_sumcheck.state.take_residual_covector()?;
        let code_switch_inputs = material
            .pre_challenge_whir_first_code_switch
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .take_relation_inputs()?;
        material.pre_challenge_whir_first_code_switch_relation_preparation =
            Some(CompactWhirCodeSwitchRelationPreparation::new(
                code_switch_inputs,
                source_covector,
                source_claim,
                preceding_mask_claim,
                target,
            )?);
        Ok(())
    }

    pub(crate) fn poll_pre_challenge_whir_second_sumcheck_preparation(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPreparationError> {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if material.pre_challenge_whir_sumcheck_batches.len() != 1 {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let relation_preparation = material
            .pre_challenge_whir_first_code_switch_relation_preparation
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        match relation_preparation.poll(maximum_work_unit_count)? {
            CompactWhirCodeSwitchRelationPreparationPoll::QueryRelationStepCompleted {
                processed_work_unit_count,
                relation_complete,
            } => Ok(
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted {
                    processed_work_unit_count,
                    relation_complete,
                },
            ),
            CompactWhirCodeSwitchRelationPreparationPoll::Complete => {
                let relation = material
                    .pre_challenge_whir_first_code_switch_relation_preparation
                    .take()
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                    .finish()?;
                let contract = selected_compact_public_key_proof_contract()?;
                let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs
                else {
                    return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
                };
                let configuration = compact_whir_configuration_from_contract(pre_challenge_epoch)?;
                let mask_group = unique_internal_mask_group(pre_challenge_epoch, 4, 1)?;
                let sumcheck = CompactWhirInitialSumcheckState::new(
                    relation,
                    &configuration,
                    1,
                    mask_group,
                    family_material
                        .metadata
                        .pre_challenge
                        .randomness
                        .whir_random_source_mut(),
                )?;
                family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .ensure_field_sampling_valid()?;
                let response_ordinal =
                    material.pre_challenge_whir_sumcheck_initial_response_ordinal(1)?;
                let response_index = usize::try_from(response_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                let response_geometry = family_material
                    .response_merkle_geometries()
                    .get(response_index)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                let response_roles = contract
                    .verifier_inputs()
                    .response_component_roles
                    .get(response_index)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                validate_whir_sumcheck_response_geometry(
                    response_geometry,
                    response_roles,
                    pre_challenge_epoch.epoch,
                    1,
                    sumcheck.mask_oracle(),
                )?;
                verify_selected_compact_whir_sumcheck_auxiliary_masking(
                    contract.verifier_inputs(),
                    &material.masking_coefficient_maps,
                    material
                        .masking_attempt_identity
                        .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
                    response_generation_state.verifier_messages(),
                    pre_challenge_epoch.epoch,
                    1,
                    sumcheck.auxiliary_target(),
                )
                .map_err(CompactPublicKeyMainEpochPreparationError::WhirSumcheckAuxiliaryMasking)?;
                material.pre_challenge_whir_sumcheck_batches.push(
                    CompactPublicKeyWhirSumcheckBatch::new(
                        1,
                        response_ordinal,
                        sumcheck,
                        response_geometry.merkle_leaf_count(),
                    )?,
                );
                Ok(
                    CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared {
                        batch_ordinal: 1,
                    },
                )
            }
        }
    }

    pub(crate) fn main_source_encoding_complete(&self) -> bool {
        self.post_lookup_material
            .as_ref()
            .is_some_and(|material| material.main_source_oracle.is_complete())
    }

    pub(crate) fn canonical_randomness_checkpoint_cursor_bytes(
        &self,
    ) -> [u8; COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH] {
        self.family_material
            .metadata
            .pre_challenge
            .randomness
            .canonical_checkpoint_cursor_bytes()
    }

    pub(crate) fn validate_authenticated_randomness_checkpoint_cursor(
        &self,
        canonical_cursor_bytes: &[u8],
    ) -> Result<(), CompactGenerationRandomnessCursorError> {
        self.family_material
            .metadata
            .pre_challenge
            .randomness
            .validate_checkpoint_cursor_bytes(canonical_cursor_bytes)
    }

    pub(crate) fn checkpoint_boundary(&self) -> Option<&CommonProofGenerationCheckpointBoundary> {
        self.response_generation_state.checkpoint_boundary()
    }

    pub(crate) fn cancel_response_custody<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactResponseGenerationPollError<Storage::Error>> {
        self.response_generation_state.cancel(storage)
    }
}

fn validate_production_masking_inputs(
    family_material: &CompactPublicKeyFamilyMaterial,
) -> Result<CompactMaskingCoefficientMapCertificate, CompactPublicKeyMainEpochPreparationError> {
    let contract = selected_compact_public_key_proof_contract()?;
    let verifier_inputs = contract.verifier_inputs();
    let contract_source_hash = verifier_inputs.canonical_source_hash()?.into_bytes();
    if verifier_inputs.relation != family_material.relation()
        || contract_source_hash != family_material.compact_construction_identity_hash()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    if derive_selected_compact_masking_kmac_bridge()?.into_bytes() != contract_source_hash {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let coefficient_maps =
        derive_compact_masking_coefficient_map_certificate(contract.verifier_inputs())?;
    let _public_covector_authority =
        CompactFactorOnePublicCovectorAuthority::from_canonical_public_input(
            contract.verifier_inputs(),
            family_material.public_input_bindings(),
            family_material.canonical_public_input_bytes(),
            family_material.decoded_public_input(),
        )?;
    Ok(coefficient_maps)
}

impl CompactPublicKeyPostLookupMaterial {
    fn verify_cross_epoch_masking_prefix(
        &self,
        family_material: &CompactPublicKeyFamilyMaterial,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        canonical_exposed_proof_prefix: &[u8],
    ) -> Result<CompactMaskingAttemptIdentity, CompactPublicKeyMainEpochPreparationError> {
        if self.masking_attempt_identity.is_some() {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let cross_epoch_disclosures = self
            .cross_epoch_claims
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .disclosed_values();
        let contract = selected_compact_public_key_proof_contract()?;
        Ok(verify_selected_compact_cross_epoch_masking_prefix(
            contract.verifier_inputs(),
            &self.masking_coefficient_maps,
            family_material
                .pre_challenge_material()
                .proof_attempt_identifier(),
            family_material.canonical_public_input_bytes(),
            canonical_exposed_proof_prefix,
            self.cross_epoch_masking_transcript_cursor
                .as_deref()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
            completed_messages,
            cross_epoch_disclosures,
            self.cfw_auxiliary_target,
        )?)
    }

    fn prepare_cross_epoch_evaluation(
        &mut self,
        family_material: &CompactPublicKeyFamilyMaterial,
        point: Vec<CompactChallengeField>,
        canonical_transcript_cursor_bytes: &[u8],
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        if self.cross_epoch_point.is_some()
            || self.cross_epoch_masking_transcript_cursor.is_some()
            || self.cross_epoch_evaluation_state.is_some()
            || self.cross_epoch_claims.is_some()
            || self.cfw_external_prover.is_some()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let copy_geometry = family_material
            .relation()
            .cross_epoch_copy_geometry()
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let copied_source_element_count = usize::try_from(copy_geometry.copied_element_count())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let expected_point_coordinate_count =
            usize::try_from(copy_geometry.point_coordinate_count())
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if point.len() != expected_point_coordinate_count
            || family_material.witness_length() != copy_geometry.main_message_element_count()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        if canonical_transcript_cursor_bytes.is_empty() {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let mut retained_transcript_cursor = Vec::new();
        retained_transcript_cursor
            .try_reserve_exact(canonical_transcript_cursor_bytes.len())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        retained_transcript_cursor.extend_from_slice(canonical_transcript_cursor_bytes);
        let evaluation_state =
            CompactCfwPrefixEvaluationState::new(&point, copied_source_element_count)?;
        self.cross_epoch_masking_transcript_cursor =
            Some(retained_transcript_cursor.into_boxed_slice());
        self.cross_epoch_point = Some(point);
        self.cross_epoch_evaluation_state = Some(evaluation_state);
        Ok(())
    }

    fn poll_cross_epoch_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
        family_material: &CompactPublicKeyFamilyMaterial,
    ) -> Result<CompactPublicKeyCrossEpochResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        if self.cross_epoch_response_leaf_count != 4 || leaf_ordinal >= 4 {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        if self.cross_epoch_claims.is_none() {
            if leaf_ordinal != 0 {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            let evaluation_state = self
                .cross_epoch_evaluation_state
                .as_mut()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            if !evaluation_state.is_complete() {
                let progress = evaluation_state
                    .poll(maximum_work_unit_count, |source_ordinal| {
                        family_material
                            .row_source
                            .witness_value(source_ordinal)
                            .map(compact_challenge_from_production)
                    })
                    .map_err(|error| match error {
                        CompactCfwPrefixEvaluationError::Cfw(error) => {
                            CompactPublicKeyMainEpochPreparationError::Cfw(error)
                        }
                        CompactCfwPrefixEvaluationError::Source(error) => {
                            CompactPublicKeyMainEpochPreparationError::Prover(error)
                        }
                    })?;
                return Ok(
                    CompactPublicKeyCrossEpochResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count: progress.processed_work_unit_count(),
                        evaluated_source_element_count: progress.evaluated_source_element_count(),
                    },
                );
            }
            let copy_geometry = family_material
                .relation()
                .cross_epoch_copy_geometry()
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            let claims = CompactCfwMaskedCrossEpochClaims::from_copied_source_evaluation(
                self.cross_epoch_point
                    .as_ref()
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                    .clone(),
                usize::try_from(copy_geometry.copied_element_count())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                evaluation_state.evaluation()?,
                self.cross_epoch_masks[0],
                self.cross_epoch_masks[1],
            )?;
            self.cross_epoch_claims = Some(claims);
        }
        Ok(CompactPublicKeyCrossEpochResponseLeafPoll::LeafReady(
            self.cross_epoch_response_leaf(leaf_ordinal)?,
        ))
    }

    fn cross_epoch_response_leaf(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        if self.cross_epoch_response_leaf_count != 4
            || leaf_ordinal >= self.cross_epoch_response_leaf_count
            || self.cross_epoch_claims.is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        if leaf_ordinal == 3 {
            return encoded_extension_values_response_leaf(Some(&[self.cfw_auxiliary_target]));
        }
        let values = self
            .cross_epoch_claims
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .disclosed_values();
        let value = values[usize::try_from(leaf_ordinal)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?];
        encoded_extension_values_response_leaf(Some(&[value]))
    }

    fn prepare_initial_cfw_prover(
        &mut self,
        family_material: &CompactPublicKeyFamilyMaterial,
        message: &DecodedFixedUniformVerifierMessage,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        if self.masking_attempt_identity.is_none()
            || self.cfw_external_prover.is_some()
            || self.pending_cfw_round_polynomial.is_some()
            || self.pending_cfw_bound_challenge.is_some()
            || !self.cfw_outer_masking_outputs.is_empty()
            || self.cfw_bound_round_advance_required
            || self.cfw_external_output.is_some()
            || self.cross_epoch_claims.is_none()
            || self
                .cross_epoch_evaluation_state
                .as_ref()
                .is_none_or(|state| !state.is_complete())
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let (constraint_combining_challenge, equality_point) =
            initial_cfw_challenges_from_verifier_message(family_material, message)?;
        let prover = CompactCfwExternalProverState::prepare(
            &family_material.row_source,
            self.cfw_mask_material.clone(),
            constraint_combining_challenge,
            equality_point,
        )?;
        if prover.auxiliary_target() != self.cfw_auxiliary_target {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let outer_output_capacity = self
            .cfw_geometry
            .sumcheck_round_count()
            .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
            .and_then(|count| count.checked_add(1))
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        self.cfw_outer_masking_outputs
            .try_reserve_exact(outer_output_capacity)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        self.cfw_outer_masking_outputs
            .push(self.cfw_auxiliary_target);
        self.cfw_external_prover = Some(prover);
        Ok(())
    }

    fn completed_cfw_round_count(
        &self,
    ) -> Result<usize, CompactPublicKeyMainEpochPreparationError> {
        let remaining_output_count = self
            .cfw_outer_masking_outputs
            .len()
            .checked_sub(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if self.cfw_outer_masking_outputs.first().copied() != Some(self.cfw_auxiliary_target)
            || !remaining_output_count.is_multiple_of(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
        {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let completed_round_count = remaining_output_count / COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH;
        if completed_round_count > self.cfw_geometry.sumcheck_round_count() {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        Ok(completed_round_count)
    }

    fn expected_cfw_response_ordinal(
        &self,
    ) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        let response_index = if self.cfw_external_output.is_some() {
            if self.cfw_external_prover.is_some()
                || self.pending_cfw_round_polynomial.is_some()
                || self.cfw_bound_round_advance_required
                || self.completed_cfw_round_count()? != self.cfw_geometry.sumcheck_round_count()
            {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            self.cfw_geometry.sumcheck_round_count().checked_add(3)
        } else {
            if self.pending_cfw_round_polynomial.is_none() || self.cfw_external_prover.is_none() {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            self.completed_cfw_round_count()?.checked_add(3)
        }
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        u32::try_from(response_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
    }

    fn verify_cfw_round_masking(
        &self,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        round_polynomial: &[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        if self.pending_cfw_round_polynomial.is_some()
            || self.cfw_external_output.is_some()
            || self.cfw_bound_round_advance_required
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let round_index = self.completed_cfw_round_count()?;
        let contract = selected_compact_public_key_proof_contract()?;
        let round_ordinal = u32::try_from(round_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        verify_selected_compact_cfw_round_masking(
            contract.verifier_inputs(),
            &self.masking_coefficient_maps,
            self.masking_attempt_identity
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
            completed_messages,
            &self.cfw_outer_masking_outputs,
            round_ordinal,
            round_polynomial,
        )
        .map_err(
            |error| CompactPublicKeyMainEpochPreparationError::CfwRoundMasking {
                round_ordinal,
                error,
            },
        )?;
        Ok(())
    }

    fn verify_cfw_finish_masking(
        &self,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        external_output: &CompactCfwExternalProverOutput,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        if self.cfw_external_prover.is_some()
            || self.pending_cfw_round_polynomial.is_some()
            || self.cfw_bound_round_advance_required
            || self.cfw_external_output.is_some()
            || self.completed_cfw_round_count()? != self.cfw_geometry.sumcheck_round_count()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let finish = external_output.finish();
        verify_selected_compact_cfw_finish_masking(
            selected_compact_public_key_proof_contract()?.verifier_inputs(),
            &self.masking_coefficient_maps,
            self.masking_attempt_identity
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
            completed_messages,
            &self.cfw_outer_masking_outputs,
            finish.outer_evaluations(),
            &finish.final_values(),
        )
        .map_err(CompactPublicKeyMainEpochPreparationError::CfwFinishMasking)?;
        Ok(())
    }

    fn cfw_response_leaf(
        &self,
        response_ordinal: u32,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        let round_count = self.cfw_geometry.sumcheck_round_count();
        let final_response_ordinal = u32::try_from(
            round_count
                .checked_add(3)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if response_ordinal < 3 || response_ordinal > final_response_ordinal {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        if response_ordinal < final_response_ordinal {
            let round_index = usize::try_from(response_ordinal - 3)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            let value_index = usize::try_from(leaf_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            if value_index >= COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            let completed_round_count = self.completed_cfw_round_count()?;
            let value = if round_index < completed_round_count {
                let output_index = round_index
                    .checked_mul(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                    .and_then(|index| index.checked_add(value_index + 1))
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                *self
                    .cfw_outer_masking_outputs
                    .get(output_index)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            } else if round_index == completed_round_count {
                *self
                    .pending_cfw_round_polynomial
                    .as_ref()
                    .and_then(|polynomial| polynomial.get(value_index))
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            } else {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            };
            return encoded_extension_values_response_leaf(Some(core::slice::from_ref(&value)));
        }

        let finish = self
            .cfw_external_output
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .finish();
        let value_index = usize::try_from(leaf_ordinal)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let value = if value_index < round_count {
            Some(finish.outer_evaluations()[value_index])
        } else if value_index < round_count + COMPACT_CFW_MATRIX_COUNT {
            Some(finish.final_values()[value_index - round_count])
        } else {
            None
        };
        match value {
            Some(value) => {
                encoded_extension_values_response_leaf(Some(core::slice::from_ref(&value)))
            }
            None => Ok(CompactOwnedResponseLeaf::padding()),
        }
    }

    fn pre_challenge_whir_initial_response_ordinal(
        &self,
    ) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        let ordinal = self
            .cfw_geometry
            .sumcheck_round_count()
            .checked_add(4)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        u32::try_from(ordinal)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
    }

    fn pre_challenge_whir_sumcheck_initial_response_ordinal(
        &self,
        batch_ordinal: u8,
    ) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        if let Some(batch) = self
            .pre_challenge_whir_sumcheck_batches
            .get(usize::from(batch_ordinal))
        {
            if batch.batch_ordinal != batch_ordinal {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            return Ok(batch.initial_response_ordinal);
        }
        if batch_ordinal == 0 {
            return self.pre_challenge_whir_initial_response_ordinal();
        }
        let contract = selected_compact_public_key_proof_contract()?;
        let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        unique_response_ordinal_for_component_role(
            &contract.verifier_inputs(),
            11,
            pre_challenge_epoch.epoch,
            batch_ordinal,
            0,
        )
    }

    fn pre_challenge_whir_first_code_switch_response_ordinal(
        &self,
    ) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        let initial_batch = self
            .pre_challenge_whir_sumcheck_batches
            .first()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        initial_batch
            .initial_response_ordinal
            .checked_add(
                u32::try_from(initial_batch.state.mask_messages().len())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
                    .checked_add(1)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
    }

    fn expected_pre_challenge_whir_response_ordinal(
        &self,
    ) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        let batch = self
            .pre_challenge_whir_sumcheck_batches
            .last()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if batch.response_leaf_count == 0 || batch.bound_round_advance_required {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let initial_ordinal = batch.initial_response_ordinal;
        if !batch.combination_challenge_bound {
            if batch.masking_outputs.len() != 1 || batch.round_masking_verified {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            return Ok(initial_ordinal);
        }
        let round_index = batch.state.round_challenges().len();
        if round_index >= batch.state.mask_messages().len()
            || batch.state.pending_round_wire().is_err()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let offset = u32::try_from(round_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            .checked_add(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        initial_ordinal
            .checked_add(offset)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
    }

    fn validate_pre_challenge_whir_sumcheck_completion(
        &self,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        batch_index: usize,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let contract = selected_compact_public_key_proof_contract()?;
        let [pre_challenge_epoch, _main_epoch] = contract.verifier_inputs().whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        let batch = self
            .pre_challenge_whir_sumcheck_batches
            .get(batch_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let expected_batch_ordinal = u8::try_from(batch_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if batch.batch_ordinal != expected_batch_ordinal {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let folding_factor = usize::try_from(
            *pre_challenge_epoch
                .folding_schedule
                .get(batch_index)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let source_length = whir_sumcheck_source_length(
            &contract.verifier_inputs(),
            pre_challenge_epoch,
            batch.batch_ordinal,
        )?;
        let expected_residual_length = source_length
            .checked_shr(
                u32::try_from(folding_factor)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let mask_group = unique_internal_mask_group(pre_challenge_epoch, 4, batch.batch_ordinal)?;
        let input_binding_challenge = if batch.batch_ordinal == 0 {
            unique_completed_extension_role_challenge(
                &contract.verifier_inputs(),
                completed_messages,
                6,
                pre_challenge_epoch.epoch,
                0,
                0,
            )?
        } else {
            completed_code_switch_verifier_move(
                &contract.verifier_inputs(),
                completed_messages,
                pre_challenge_epoch.epoch,
                u32::from(batch.batch_ordinal - 1),
            )?
            .0
        };
        let combination_challenge = unique_completed_extension_role_challenge(
            &contract.verifier_inputs(),
            completed_messages,
            7,
            pre_challenge_epoch.epoch,
            batch.batch_ordinal,
            0,
        )?;
        let expected_initial_preceding_mask_claim = (batch.batch_ordinal == 0).then(|| {
            combination_challenge
                * self.cross_epoch_masks[0]
                * CompactChallengeField::TWO
                    .inverse()
                    .exp_u64(folding_factor as u64)
        });
        let residual_source_claim = batch.state.residual_source_claim()?;
        let recomputed_residual_source_claim = batch
            .state
            .residual_source()?
            .iter()
            .copied()
            .zip(batch.state.residual_covector()?)
            .map(|(source_value, weight)| source_value * *weight)
            .sum::<CompactChallengeField>();
        let masking_outputs_are_exact = batch.masking_outputs.len() == 1 + 2 * folding_factor
            && batch.masking_outputs.first().copied() == Some(batch.state.auxiliary_target())
            && (0..folding_factor).all(|round_index| {
                let output_start = 1 + 2 * round_index;
                batch.state.round_wire(round_index)
                    == batch.masking_outputs.get(output_start..output_start + 2)
            });
        let initial_batch_claims_are_exact = if batch.batch_ordinal == 0 {
            batch.state.masked_target()
                == self
                    .cross_epoch_claims
                    .as_ref()
                    .map(CompactCfwMaskedCrossEpochClaims::disclosed_values)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?[0]
                && Some(batch.state.residual_preceding_mask_claim()?)
                    == expected_initial_preceding_mask_claim
        } else {
            true
        };
        if !batch.state.is_complete()
            || !batch.combination_challenge_bound
            || batch.round_masking_verified
            || batch.bound_round_advance_required
            || batch.state.opening_batching_challenge() != input_binding_challenge
            || batch.state.residual_source()?.len() != expected_residual_length
            || batch.state.residual_covector()?.len() != expected_residual_length
            || batch.state.round_challenges().len() != folding_factor
            || batch.state.mask_messages().len() != folding_factor
            || batch.state.mask_encoding_randomness().len() != folding_factor
            || batch.state.mask_encoding_randomness().iter().any(|values| {
                u64::try_from(values.len()).ok() != Some(mask_group.randomness_length)
            })
            || !masking_outputs_are_exact
            || !initial_batch_claims_are_exact
            || residual_source_claim != recomputed_residual_source_claim
        {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok(())
    }

    fn pre_challenge_whir_response_leaf(
        &self,
        response_ordinal: u32,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        for batch in &self.pre_challenge_whir_sumcheck_batches {
            let initial_ordinal = batch.initial_response_ordinal;
            let round_count = u32::try_from(batch.state.mask_messages().len())
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            let final_ordinal = initial_ordinal
                .checked_add(round_count)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            if !(initial_ordinal..=final_ordinal).contains(&response_ordinal) {
                continue;
            }
            if response_ordinal == initial_ordinal {
                if leaf_ordinal >= batch.response_leaf_count {
                    return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
                }
                let mask_height =
                    u64::try_from(batch.state.mask_oracle().encoded_matrix().height())
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                if leaf_ordinal < mask_height {
                    return encoded_extension_response_leaf(
                        batch.state.mask_oracle(),
                        leaf_ordinal,
                    );
                }
                if leaf_ordinal == mask_height {
                    let auxiliary_target = batch.state.auxiliary_target();
                    return encoded_extension_values_response_leaf(Some(core::slice::from_ref(
                        &auxiliary_target,
                    )));
                }
                return Ok(CompactOwnedResponseLeaf::padding());
            }
            let round_index = usize::try_from(response_ordinal - initial_ordinal - 1)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            let contract = selected_compact_public_key_proof_contract()?;
            let response_geometry = contract
                .verifier_inputs()
                .response_merkle_geometries
                .get(
                    usize::try_from(response_ordinal)
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                )
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            if leaf_ordinal >= response_geometry.merkle_leaf_count() {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            let Some(value) = batch.state.round_wire(round_index).and_then(|wire| {
                usize::try_from(leaf_ordinal)
                    .ok()
                    .and_then(|index| wire.get(index))
            }) else {
                return Ok(CompactOwnedResponseLeaf::padding());
            };
            return encoded_extension_values_response_leaf(Some(core::slice::from_ref(value)));
        }
        if response_ordinal == self.pre_challenge_whir_first_code_switch_response_ordinal()? {
            return self.first_code_switch_response_leaf(leaf_ordinal);
        }
        Err(CompactPublicKeyMainEpochPreparationError::WrongPhase)
    }

    fn first_code_switch_component_boundaries(
        &self,
    ) -> Result<[u64; 2], CompactPublicKeyMainEpochPreparationError> {
        let code_switch = self
            .pre_challenge_whir_first_code_switch
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let source_end = u64::try_from(code_switch.source_oracle().encoded_height())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let mask_end = source_end
            .checked_add(
                u64::try_from(code_switch.switch_mask_oracle()?.encoded_matrix().height())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if mask_end > self.pre_challenge_whir_first_code_switch_response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok([source_end, mask_end])
    }

    fn poll_first_code_switch_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyCodeSwitchResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let [source_end, _mask_end] = self.first_code_switch_component_boundaries()?;
        if leaf_ordinal >= self.pre_challenge_whir_first_code_switch_response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        if leaf_ordinal >= source_end {
            return Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                self.first_code_switch_response_leaf(leaf_ordinal)?,
            ));
        }
        let code_switch = self
            .pre_challenge_whir_first_code_switch
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        match code_switch.poll_source_oracle(maximum_work_unit_count)? {
            CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                processed_work_unit_count,
            } => Ok(
                CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                let row = code_switch
                    .source_row(usize::try_from(leaf_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                    })?)?;
                Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                    encoded_extension_values_response_leaf(Some(row))?,
                ))
            }
        }
    }

    fn mark_first_code_switch_response_leaf_supplied(
        &mut self,
        leaf_ordinal: u64,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let [source_end, _mask_end] = self.first_code_switch_component_boundaries()?;
        if leaf_ordinal < source_end {
            self.pre_challenge_whir_first_code_switch
                .as_mut()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                .mark_source_row_supplied(
                    usize::try_from(leaf_ordinal)
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                )?;
        }
        Ok(())
    }

    fn first_code_switch_response_leaf(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        if leaf_ordinal >= self.pre_challenge_whir_first_code_switch_response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let [source_end, mask_end] = self.first_code_switch_component_boundaries()?;
        let code_switch = self
            .pre_challenge_whir_first_code_switch
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if leaf_ordinal < source_end {
            return encoded_extension_values_response_leaf(Some(
                code_switch
                    .source_row(usize::try_from(leaf_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                    })?)?,
            ));
        }
        if leaf_ordinal < mask_end {
            return encoded_extension_response_leaf(
                code_switch.switch_mask_oracle()?,
                leaf_ordinal - source_end,
            );
        }
        Ok(CompactOwnedResponseLeaf::padding())
    }

    fn component_leaf_boundaries(
        &self,
    ) -> Result<[u64; 4], CompactPublicKeyMainEpochPreparationError> {
        let inner_mask_end = u64::try_from(self.inner_mask_oracle.encoded_matrix().height())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let main_source_end = inner_mask_end
            .checked_add(
                u64::try_from(self.main_source_oracle.encoded_height())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let outer_mask_end = main_source_end
            .checked_add(
                u64::try_from(self.outer_mask_oracle.encoded_matrix().height())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let cross_epoch_mask_end = outer_mask_end
            .checked_add(
                u64::try_from(self.cross_epoch_mask_oracle.encoded_matrix().height())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if cross_epoch_mask_end > self.response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok([
            inner_mask_end,
            main_source_end,
            outer_mask_end,
            cross_epoch_mask_end,
        ])
    }

    fn poll_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
        row_source: &SelectedCompactPublicKeyRowSource,
    ) -> Result<CompactPublicKeyPostLookupResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let [inner_mask_end, main_source_end, ..] = self.component_leaf_boundaries()?;
        if (inner_mask_end..main_source_end).contains(&leaf_ordinal) {
            let main_source_row = leaf_ordinal - inner_mask_end;
            match self
                .main_source_oracle
                .poll(maximum_work_unit_count, |source_ordinal| {
                    row_source
                        .witness_value(source_ordinal)
                        .map(compact_challenge_from_production)
                })
                .map_err(|error| match error {
                    CompactWhirRecomputableExtensionError::Whir(error) => {
                        CompactPublicKeyMainEpochPreparationError::Whir(error)
                    }
                    CompactWhirRecomputableExtensionError::Source(error) => {
                        CompactPublicKeyMainEpochPreparationError::Prover(error)
                    }
                })? {
                CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                } => Ok(
                    CompactPublicKeyPostLookupResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    },
                ),
                CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                    let row = self
                        .main_source_oracle
                        .response_row(usize::try_from(main_source_row).map_err(|_| {
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                        })?)
                        .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
                    Ok(CompactPublicKeyPostLookupResponseLeafPoll::LeafReady(
                        encoded_extension_values_response_leaf(Some(row))?,
                    ))
                }
            }
        } else {
            Ok(CompactPublicKeyPostLookupResponseLeafPoll::LeafReady(
                self.response_leaf(leaf_ordinal)?,
            ))
        }
    }

    fn mark_response_leaf_supplied(
        &mut self,
        leaf_ordinal: u64,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let [inner_mask_end, main_source_end, ..] = self.component_leaf_boundaries()?;
        if (inner_mask_end..main_source_end).contains(&leaf_ordinal) {
            self.main_source_oracle
                .mark_response_row_supplied(
                    usize::try_from(leaf_ordinal - inner_mask_end)
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                )
                .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
        }
        Ok(())
    }

    fn poll_opened_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
        row_source: &SelectedCompactPublicKeyRowSource,
        opening_query_leaf_ordinals: &[u64],
    ) -> Result<CompactPublicKeyPostLookupResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let [inner_mask_end, main_source_end, ..] = self.component_leaf_boundaries()?;
        if !(inner_mask_end..main_source_end).contains(&leaf_ordinal) {
            return Ok(CompactPublicKeyPostLookupResponseLeafPoll::LeafReady(
                self.response_leaf(leaf_ordinal)?,
            ));
        }
        let main_source_row = usize::try_from(leaf_ordinal - inner_mask_end)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if self.main_source_oracle.can_begin_opening_replay() {
            let opening_rows = main_source_opening_rows_from_query_schedule(
                inner_mask_end,
                main_source_end,
                opening_query_leaf_ordinals,
            )?;
            if opening_rows.first().copied() != Some(main_source_row) {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            self.main_source_oracle
                .begin_opening_replay(&opening_rows)
                .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
        }
        match self
            .main_source_oracle
            .poll(maximum_work_unit_count, |source_ordinal| {
                row_source
                    .witness_value(source_ordinal)
                    .map(compact_challenge_from_production)
            })
            .map_err(|error| match error {
                CompactWhirRecomputableExtensionError::Whir(error) => {
                    CompactPublicKeyMainEpochPreparationError::Whir(error)
                }
                CompactWhirRecomputableExtensionError::Source(error) => {
                    CompactPublicKeyMainEpochPreparationError::Prover(error)
                }
            })? {
            CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                processed_work_unit_count,
            } => Ok(
                CompactPublicKeyPostLookupResponseLeafPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                let row = self
                    .main_source_oracle
                    .response_row(main_source_row)
                    .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
                Ok(CompactPublicKeyPostLookupResponseLeafPoll::LeafReady(
                    encoded_extension_values_response_leaf(Some(row))?,
                ))
            }
        }
    }

    fn response_leaf(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        if leaf_ordinal >= self.response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let [
            inner_mask_end,
            main_source_end,
            outer_mask_end,
            cross_epoch_mask_end,
        ] = self.component_leaf_boundaries()?;
        if leaf_ordinal < inner_mask_end {
            return encoded_extension_response_leaf(&self.inner_mask_oracle, leaf_ordinal);
        }
        if leaf_ordinal < main_source_end {
            let row = self
                .main_source_oracle
                .response_row(
                    usize::try_from(leaf_ordinal - inner_mask_end)
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                )
                .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
            return encoded_extension_values_response_leaf(Some(row));
        }
        if leaf_ordinal < outer_mask_end {
            return encoded_extension_response_leaf(
                &self.outer_mask_oracle,
                leaf_ordinal - main_source_end,
            );
        }
        if leaf_ordinal < cross_epoch_mask_end {
            return encoded_extension_response_leaf(
                &self.cross_epoch_mask_oracle,
                leaf_ordinal - outer_mask_end,
            );
        }
        Ok(CompactOwnedResponseLeaf::padding())
    }
}

fn main_source_opening_rows_from_query_schedule(
    main_source_first_leaf_ordinal: u64,
    main_source_end_leaf_ordinal: u64,
    query_leaf_ordinals: &[u64],
) -> Result<Vec<usize>, CompactPublicKeyMainEpochPreparationError> {
    if main_source_first_leaf_ordinal >= main_source_end_leaf_ordinal
        || query_leaf_ordinals.is_empty()
        || query_leaf_ordinals
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let mut opening_rows = Vec::new();
    opening_rows
        .try_reserve_exact(query_leaf_ordinals.len())
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
    for leaf_ordinal in query_leaf_ordinals.iter().copied() {
        if (main_source_first_leaf_ordinal..main_source_end_leaf_ordinal).contains(&leaf_ordinal) {
            opening_rows.push(
                usize::try_from(leaf_ordinal - main_source_first_leaf_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            );
        }
    }
    if opening_rows.is_empty() {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(opening_rows)
}

fn prepare_post_lookup_material(
    family_material: &mut CompactPublicKeyFamilyMaterial,
    masking_coefficient_maps: CompactMaskingCoefficientMapCertificate,
) -> Result<CompactPublicKeyPostLookupMaterial, CompactPublicKeyMainEpochPreparationError> {
    let contract = selected_compact_public_key_proof_contract()?;
    let verifier_inputs = contract.verifier_inputs();
    let [pre_challenge_epoch, main_epoch] = verifier_inputs.whir_epochs else {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    };
    let main_configuration = compact_whir_configuration_from_contract(main_epoch)?;
    let witness_length = usize::try_from(family_material.witness_length())
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if 1_usize.checked_shl(
        u32::try_from(main_configuration.num_variables)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
    ) != Some(witness_length)
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let cfw_geometry = CompactCfwGeometry::derive(witness_length).map_err(CompactCfwError::from)?;
    let inner_mask_contract = unique_external_mask_group(main_epoch, 2)?;
    let outer_mask_contract = unique_external_mask_group(main_epoch, 3)?;
    let pre_challenge_cross_epoch_contract = unique_external_mask_group(pre_challenge_epoch, 1)?;
    let main_cross_epoch_contract = unique_external_mask_group(main_epoch, 1)?;
    validate_shared_cross_epoch_contracts(
        pre_challenge_cross_epoch_contract,
        main_cross_epoch_contract,
    )?;
    let inner_mask_shape = compact_whir_mask_group_shape(inner_mask_contract)?;
    let outer_mask_shape = compact_whir_mask_group_shape(outer_mask_contract)?;
    let cross_epoch_mask_shape = compact_whir_mask_group_shape(pre_challenge_cross_epoch_contract)?;

    let randomness = &mut family_material.metadata.pre_challenge.randomness;
    let cfw_mask_material = {
        let random_source = randomness.whir_random_source_mut();
        CompactCfwMaskMaterial::sample(cfw_geometry, || random_source.random())?
    };
    randomness.ensure_field_sampling_valid()?;
    let cfw_auxiliary_target = cfw_mask_material.auxiliary_target(cfw_geometry)?;
    let inner_mask_messages = copy_mask_messages(cfw_mask_material.inner_masks())?;
    let inner_mask_encoding_randomness = sample_mask_encoding_randomness(
        randomness.whir_random_source_mut(),
        inner_mask_shape.width,
        inner_mask_shape.shape.randomness_len,
    )?;
    randomness.ensure_field_sampling_valid()?;
    let inner_mask_oracle = CompactWhirEncodedMaskGroup::encode(
        inner_mask_shape,
        &inner_mask_messages,
        &inner_mask_encoding_randomness,
    )?;
    let main_source_oracle = CompactWhirRecomputableExtensionInitialOracle::sample(
        &main_configuration,
        randomness.whir_random_source_mut(),
    )?;
    randomness.ensure_field_sampling_valid()?;
    if main_source_oracle.source_element_count() != witness_length {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let outer_mask_messages = copy_mask_messages(cfw_mask_material.outer_masks())?;
    let outer_mask_encoding_randomness = sample_mask_encoding_randomness(
        randomness.whir_random_source_mut(),
        outer_mask_shape.width,
        outer_mask_shape.shape.randomness_len,
    )?;
    randomness.ensure_field_sampling_valid()?;
    let outer_mask_oracle = CompactWhirEncodedMaskGroup::encode(
        outer_mask_shape,
        &outer_mask_messages,
        &outer_mask_encoding_randomness,
    )?;
    let cross_epoch_masks = {
        let random_source = randomness.whir_random_source_mut();
        [random_source.random(), random_source.random()]
    };
    randomness.ensure_field_sampling_valid()?;
    let cross_epoch_mask_messages = vec![vec![cross_epoch_masks[0]], vec![cross_epoch_masks[1]]];
    let cross_epoch_mask_encoding_randomness = sample_mask_encoding_randomness(
        randomness.whir_random_source_mut(),
        cross_epoch_mask_shape.width,
        cross_epoch_mask_shape.shape.randomness_len,
    )?;
    randomness.ensure_field_sampling_valid()?;
    let cross_epoch_mask_oracle = CompactWhirEncodedMaskGroup::encode(
        cross_epoch_mask_shape,
        &cross_epoch_mask_messages,
        &cross_epoch_mask_encoding_randomness,
    )?;

    let response_geometry = family_material
        .response_merkle_geometries()
        .get(1)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let response_roles = verifier_inputs
        .response_component_roles
        .get(1)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    validate_post_lookup_response_geometry(
        response_geometry,
        response_roles,
        &inner_mask_oracle,
        &main_source_oracle,
        &outer_mask_oracle,
        &cross_epoch_mask_oracle,
    )?;
    let cross_epoch_response_geometry = family_material
        .response_merkle_geometries()
        .get(2)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let cross_epoch_response_roles = verifier_inputs
        .response_component_roles
        .get(2)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    validate_cross_epoch_response_geometry(
        cross_epoch_response_geometry,
        cross_epoch_response_roles,
        verifier_inputs
            .cfw_configuration
            .cross_epoch_disclosed_scalar_count(),
        verifier_inputs.cfw_configuration.auxiliary_target_count(),
    )?;
    let material = CompactPublicKeyPostLookupMaterial {
        masking_coefficient_maps,
        masking_attempt_identity: None,
        cfw_geometry,
        cfw_mask_material,
        cfw_auxiliary_target,
        inner_mask_encoding_randomness,
        inner_mask_oracle,
        main_source_oracle,
        outer_mask_encoding_randomness,
        outer_mask_oracle,
        cross_epoch_masks,
        cross_epoch_mask_encoding_randomness,
        cross_epoch_mask_oracle,
        response_leaf_count: response_geometry.merkle_leaf_count(),
        cross_epoch_masking_transcript_cursor: None,
        cross_epoch_point: None,
        cross_epoch_evaluation_state: None,
        cross_epoch_claims: None,
        cross_epoch_response_leaf_count: cross_epoch_response_geometry.merkle_leaf_count(),
        cfw_external_prover: None,
        pending_cfw_round_polynomial: None,
        pending_cfw_bound_challenge: None,
        cfw_outer_masking_outputs: Vec::new(),
        cfw_bound_round_advance_required: false,
        cfw_external_output: None,
        pre_challenge_whir_relation_preparation: None,
        pre_challenge_whir_sumcheck_batches: Vec::new(),
        pre_challenge_whir_first_code_switch: None,
        pre_challenge_whir_first_code_switch_response_leaf_count: 0,
        pre_challenge_whir_first_source_query_masking_verified: false,
        pre_challenge_whir_first_code_switch_relation_preparation: None,
    };
    validate_retained_post_lookup_material(
        &material,
        inner_mask_shape,
        outer_mask_shape,
        cross_epoch_mask_shape,
    )?;
    Ok(material)
}

fn unique_external_mask_group(
    epoch: &CompactWhirEpochContract,
    role_tag: u8,
) -> Result<CompactWhirMaskGroupContract, CompactPublicKeyMainEpochPreparationError> {
    let mut matching_groups = epoch
        .external_mask_groups
        .iter()
        .copied()
        .filter(|group| group.role_tag == role_tag);
    let group = matching_groups
        .next()
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if matching_groups.next().is_some() {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(group)
}

fn unique_internal_mask_group(
    epoch: &CompactWhirEpochContract,
    role_tag: u8,
    coordinate: u8,
) -> Result<CompactWhirMaskGroupContract, CompactPublicKeyMainEpochPreparationError> {
    let mut matching_groups = epoch
        .internal_mask_groups
        .iter()
        .copied()
        .filter(|group| group.role_tag == role_tag && group.coordinate == coordinate);
    let group = matching_groups
        .next()
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if matching_groups.next().is_some() {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(group)
}

fn unique_whir_fold_contract(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    epoch: u8,
    batch_ordinal: u8,
) -> Result<CompactWhirFoldContract, CompactPublicKeyMainEpochPreparationError> {
    let mut matching_folds = inputs
        .whir_folds
        .iter()
        .copied()
        .filter(|fold| fold.epoch == epoch && fold.batch_ordinal == batch_ordinal);
    let fold = matching_folds
        .next()
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if matching_folds.next().is_some() {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(fold)
}

fn whir_sumcheck_source_length(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    epoch: &CompactWhirEpochContract,
    batch_ordinal: u8,
) -> Result<usize, CompactPublicKeyMainEpochPreparationError> {
    if batch_ordinal == 0 {
        return 1_usize
            .checked_shl(epoch.polynomial_variable_count)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let source_contract = unique_whir_fold_contract(inputs, epoch.epoch, batch_ordinal)?;
    usize::try_from(
        source_contract
            .message_length
            .checked_mul(source_contract.oracle_width)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
    )
    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
}

fn validate_shared_cross_epoch_contracts(
    pre_challenge: CompactWhirMaskGroupContract,
    main: CompactWhirMaskGroupContract,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if pre_challenge.role_tag != 1
        || main.role_tag != 1
        || pre_challenge.coordinate != 0
        || main.coordinate != 0
        || pre_challenge.width != main.width
        || pre_challenge.message_length != main.message_length
        || pre_challenge.randomness_length != main.randomness_length
        || pre_challenge.domain_size != main.domain_size
        || pre_challenge.committed_encoding_source != 1
        || main.committed_encoding_source != 2
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn copy_mask_messages<const MESSAGE_LENGTH: usize>(
    masks: &[[CompactChallengeField; MESSAGE_LENGTH]],
) -> Result<Vec<Vec<CompactChallengeField>>, CompactPublicKeyMainEpochPreparationError> {
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(masks.len())
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
    for mask in masks {
        let mut message = Vec::new();
        message
            .try_reserve_exact(MESSAGE_LENGTH)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        message.extend_from_slice(mask);
        messages.push(message);
    }
    Ok(messages)
}

fn sample_mask_encoding_randomness(
    random_source: &mut impl Rng,
    mask_count: usize,
    randomness_length: usize,
) -> Result<Vec<Vec<CompactChallengeField>>, CompactPublicKeyMainEpochPreparationError> {
    let mut groups = Vec::new();
    groups
        .try_reserve_exact(mask_count)
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
    for _mask_ordinal in 0..mask_count {
        let mut values = Vec::new();
        values
            .try_reserve_exact(randomness_length)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        for _randomness_ordinal in 0..randomness_length {
            values.push(random_source.random());
        }
        groups.push(values);
    }
    Ok(groups)
}

fn validate_post_lookup_response_geometry(
    response: &CompactResponseMerkleGeometry,
    roles: &[crate::bgv::proof_suite::compact_proof_contract::CompactResponseComponentRoleContract],
    inner_masks: &CompactWhirEncodedMaskGroup,
    main_source: &CompactWhirRecomputableExtensionInitialOracle,
    outer_masks: &CompactWhirEncodedMaskGroup,
    cross_epoch_masks: &CompactWhirEncodedMaskGroup,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    let components = response.components();
    let expected_role_tags = [2_u8, 3, 4, 5, 22];
    if response.response_ordinal() != 1
        || components.len() != expected_role_tags.len()
        || roles.len() != expected_role_tags.len()
        || roles
            .iter()
            .zip(expected_role_tags)
            .any(|(role, expected_tag)| {
                role.role_tag != expected_tag
                    || role.epoch != 0
                    || role.batch_ordinal != 0
                    || role.round_ordinal != 0
            })
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    validate_extension_component(&components[0], inner_masks.encoded_matrix())?;
    validate_extension_component_dimensions(
        &components[1],
        main_source.encoded_height(),
        main_source.width(),
    )?;
    validate_extension_component(&components[2], outer_masks.encoded_matrix())?;
    validate_extension_component(&components[3], cross_epoch_masks.encoded_matrix())?;
    if components[4].value_kind() != CompactResponseLeafValueKind::Padding
        || components[4].field_element_count_per_leaf() != 0
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn validate_cross_epoch_response_geometry(
    response: &CompactResponseMerkleGeometry,
    roles: &[crate::bgv::proof_suite::compact_proof_contract::CompactResponseComponentRoleContract],
    cross_epoch_disclosed_scalar_count: u64,
    auxiliary_target_count: u64,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    let components = response.components();
    if response.response_ordinal() != 2
        || response.merkle_leaf_count() != 4
        || components.len() != 2
        || roles.len() != 2
        || (
            roles[0].role_tag,
            roles[0].epoch,
            roles[0].batch_ordinal,
            roles[0].round_ordinal,
        ) != (6, 0, 0, 0)
        || (
            roles[1].role_tag,
            roles[1].epoch,
            roles[1].batch_ordinal,
            roles[1].round_ordinal,
        ) != (7, 0, 0, 0)
        || cross_epoch_disclosed_scalar_count != 3
        || auxiliary_target_count != 1
        || components.iter().any(|component| {
            component.value_kind() != CompactResponseLeafValueKind::ExtensionField
                || component.field_element_count_per_leaf() != 1
        })
        || components[0].first_leaf_ordinal() != 0
        || components[0].leaf_count() != cross_epoch_disclosed_scalar_count
        || components[1].first_leaf_ordinal() != cross_epoch_disclosed_scalar_count
        || components[1].leaf_count() != auxiliary_target_count
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn validate_extension_component(
    component: &CompactResponseComponentGeometry,
    matrix: &impl Matrix<CompactChallengeField>,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if component.value_kind() != CompactResponseLeafValueKind::ExtensionField
        || usize::try_from(component.leaf_count()).ok() != Some(matrix.height())
        || usize::try_from(component.field_element_count_per_leaf()).ok() != Some(matrix.width())
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn validate_extension_component_dimensions(
    component: &CompactResponseComponentGeometry,
    height: usize,
    width: usize,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if component.value_kind() != CompactResponseLeafValueKind::ExtensionField
        || usize::try_from(component.leaf_count()).ok() != Some(height)
        || usize::try_from(component.field_element_count_per_leaf()).ok() != Some(width)
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn validate_whir_sumcheck_response_geometry(
    geometry: &CompactResponseMerkleGeometry,
    roles: &[CompactResponseComponentRoleContract],
    epoch: u8,
    batch_ordinal: u8,
    mask_oracle: &CompactWhirEncodedMaskGroup,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    let [mask_component, auxiliary_component, padding_component] = geometry.components() else {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    };
    let [mask_role, auxiliary_role, padding_role] = roles else {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    };
    if (mask_role.role_tag, mask_role.epoch, mask_role.batch_ordinal) != (11, epoch, batch_ordinal)
        || (
            auxiliary_role.role_tag,
            auxiliary_role.epoch,
            auxiliary_role.batch_ordinal,
        ) != (12, epoch, batch_ordinal)
        || mask_role.round_ordinal != 0
        || auxiliary_role.round_ordinal != 0
        || (
            padding_role.role_tag,
            padding_role.epoch,
            padding_role.batch_ordinal,
            padding_role.round_ordinal,
        ) != (22, 0, 0, 0)
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    validate_extension_component_dimensions(
        mask_component,
        mask_oracle.encoded_matrix().height(),
        mask_oracle.encoded_matrix().width(),
    )?;
    validate_extension_component_dimensions(auxiliary_component, 1, 1)?;
    let populated_leaf_count = mask_component
        .leaf_count()
        .checked_add(auxiliary_component.leaf_count())
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if padding_component.value_kind() != CompactResponseLeafValueKind::Padding
        || padding_component.field_element_count_per_leaf() != 0
        || padding_component.first_leaf_ordinal() != populated_leaf_count
        || populated_leaf_count.checked_add(padding_component.leaf_count())
            != Some(geometry.merkle_leaf_count())
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn validate_whir_code_switch_response_geometry(
    geometry: &CompactResponseMerkleGeometry,
    roles: &[CompactResponseComponentRoleContract],
    epoch: u8,
    round_ordinal: u32,
    source_oracle: &CompactWhirRecomputableExtensionInitialOracle,
    switch_mask_oracle: &CompactWhirEncodedMaskGroup,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    let [source_component, mask_component, padding_component] = geometry.components() else {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    };
    let [source_role, mask_role, padding_role] = roles else {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    };
    if (
        source_role.role_tag,
        source_role.epoch,
        source_role.batch_ordinal,
        source_role.round_ordinal,
    ) != (14, epoch, 0, round_ordinal)
        || (
            mask_role.role_tag,
            mask_role.epoch,
            mask_role.batch_ordinal,
            mask_role.round_ordinal,
        ) != (15, epoch, 0, round_ordinal)
        || (
            padding_role.role_tag,
            padding_role.epoch,
            padding_role.batch_ordinal,
            padding_role.round_ordinal,
        ) != (22, 0, 0, 0)
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    validate_extension_component_dimensions(
        source_component,
        source_oracle.encoded_height(),
        source_oracle.width(),
    )?;
    validate_extension_component(mask_component, switch_mask_oracle.encoded_matrix())?;
    let populated_leaf_count = source_component
        .leaf_count()
        .checked_add(mask_component.leaf_count())
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if source_component.first_leaf_ordinal() != 0
        || mask_component.first_leaf_ordinal() != source_component.leaf_count()
        || padding_component.value_kind() != CompactResponseLeafValueKind::Padding
        || padding_component.field_element_count_per_leaf() != 0
        || padding_component.first_leaf_ordinal() != populated_leaf_count
        || populated_leaf_count.checked_add(padding_component.leaf_count())
            != Some(geometry.merkle_leaf_count())
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn validate_retained_post_lookup_material(
    material: &CompactPublicKeyPostLookupMaterial,
    inner_mask_shape: p3_whir::pcs::zk::MaskGroupShape,
    outer_mask_shape: p3_whir::pcs::zk::MaskGroupShape,
    cross_epoch_mask_shape: p3_whir::pcs::zk::MaskGroupShape,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if material
        .cfw_mask_material
        .auxiliary_target(material.cfw_geometry)?
        != material.cfw_auxiliary_target
        || material.main_source_oracle.encoding_randomness().is_empty()
        || material.inner_mask_encoding_randomness.len() != inner_mask_shape.width
        || material
            .inner_mask_encoding_randomness
            .iter()
            .any(|values| values.len() != inner_mask_shape.shape.randomness_len)
        || material.outer_mask_encoding_randomness.len() != outer_mask_shape.width
        || material
            .outer_mask_encoding_randomness
            .iter()
            .any(|values| values.len() != outer_mask_shape.shape.randomness_len)
        || material.cross_epoch_masks.len() != cross_epoch_mask_shape.width
        || material.cross_epoch_mask_encoding_randomness.len() != cross_epoch_mask_shape.width
        || material
            .cross_epoch_mask_encoding_randomness
            .iter()
            .any(|values| values.len() != cross_epoch_mask_shape.shape.randomness_len)
        || material.cross_epoch_response_leaf_count != 4
        || material.masking_attempt_identity.is_some()
        || material.cross_epoch_masking_transcript_cursor.is_some()
        || material.cross_epoch_point.is_some()
        || material.cross_epoch_evaluation_state.is_some()
        || material.cross_epoch_claims.is_some()
        || material.cfw_external_prover.is_some()
        || material.pending_cfw_round_polynomial.is_some()
        || material.pending_cfw_bound_challenge.is_some()
        || !material.cfw_outer_masking_outputs.is_empty()
        || material.cfw_bound_round_advance_required
        || material.cfw_external_output.is_some()
        || material.pre_challenge_whir_relation_preparation.is_some()
        || !material.pre_challenge_whir_sumcheck_batches.is_empty()
        || material.pre_challenge_whir_first_code_switch.is_some()
        || material.pre_challenge_whir_first_code_switch_response_leaf_count != 0
        || material.pre_challenge_whir_first_source_query_masking_verified
        || material
            .pre_challenge_whir_first_code_switch_relation_preparation
            .is_some()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn compact_public_key_response_leaf(
    family_material: &CompactPublicKeyFamilyMaterial,
    post_lookup_material: &CompactPublicKeyPostLookupMaterial,
    response_ordinal: u32,
    leaf_ordinal: u64,
) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
    let initial_whir_response_ordinal =
        post_lookup_material.pre_challenge_whir_initial_response_ordinal()?;
    match response_ordinal {
        0 => Ok(family_material
            .pre_challenge_material()
            .response_leaf(leaf_ordinal)?),
        1 => post_lookup_material.response_leaf(leaf_ordinal),
        2 => post_lookup_material.cross_epoch_response_leaf(leaf_ordinal),
        response_ordinal if response_ordinal < initial_whir_response_ordinal => {
            post_lookup_material.cfw_response_leaf(response_ordinal, leaf_ordinal)
        }
        _ => post_lookup_material.pre_challenge_whir_response_leaf(response_ordinal, leaf_ordinal),
    }
}

fn encoded_extension_response_leaf(
    oracle: &CompactWhirEncodedMaskGroup,
    leaf_ordinal: u64,
) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
    encoded_extension_values_response_leaf(
        oracle.encoded_row(
            usize::try_from(leaf_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        ),
    )
}

fn encoded_extension_values_response_leaf(
    row: Option<&[CompactChallengeField]>,
) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
    let row = row.ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(row.len())
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
    for value in row {
        values.push(compact_challenge_to_production(*value)?);
    }
    Ok(CompactOwnedResponseLeaf::extension_field(values))
}

fn completed_code_switch_verifier_move<'message>(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    messages: &'message [DecodedFixedUniformVerifierMessage],
    epoch: u8,
    round_ordinal: u32,
) -> Result<(CompactChallengeField, &'message [u64]), CompactPublicKeyMainEpochPreparationError> {
    validate_completed_verifier_messages(inputs, messages)?;
    let mut result = None;
    for (move_contract, message) in inputs.verifier_moves.iter().zip(messages) {
        for role in &move_contract.role_coordinates {
            if (
                role.role_tag,
                role.epoch,
                role.batch_ordinal,
                role.round_ordinal,
            ) != (9, epoch, 0, round_ordinal)
            {
                continue;
            }
            if result.is_some()
                || (
                    role.extension_output_start,
                    role.extension_output_end,
                    role.base_field_output_start,
                    role.base_field_output_end,
                    role.distinct_query_group_start,
                    role.distinct_query_group_end,
                ) != (0, 1, 0, 1, 0, 1)
                || message.extension_elements().len() != 1
                || message.base_field_elements().len() != 1
                || message.distinct_query_groups().len() != 1
            {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            result = Some((
                compact_challenge_from_production(message.extension_elements()[0]),
                message.distinct_query_groups()[0].as_slice(),
            ));
        }
    }
    result.ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
}

fn unique_response_ordinal_for_component_role(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
    let mut response_ordinal = None;
    for (response_index, roles) in inputs.response_component_roles.iter().enumerate() {
        let matching_role_count = roles
            .iter()
            .filter(|role| {
                (
                    role.role_tag,
                    role.epoch,
                    role.batch_ordinal,
                    role.round_ordinal,
                ) == (role_tag, epoch, batch_ordinal, round_ordinal)
            })
            .count();
        if matching_role_count == 0 {
            continue;
        }
        if matching_role_count != 1 || response_ordinal.is_some() {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        response_ordinal = Some(
            u32::try_from(response_index)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        );
    }
    response_ordinal.ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
}

fn unique_completed_extension_role_challenge(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    messages: &[DecodedFixedUniformVerifierMessage],
    role_tag: u8,
    epoch: u8,
    batch_ordinal: u8,
    round_ordinal: u32,
) -> Result<CompactChallengeField, CompactPublicKeyMainEpochPreparationError> {
    validate_completed_verifier_messages(inputs, messages)?;
    let mut challenge = None;
    for (move_contract, message) in inputs.verifier_moves.iter().zip(messages) {
        for role in &move_contract.role_coordinates {
            if (
                role.role_tag,
                role.epoch,
                role.batch_ordinal,
                role.round_ordinal,
            ) != (role_tag, epoch, batch_ordinal, round_ordinal)
            {
                continue;
            }
            if challenge.is_some()
                || role.extension_output_end
                    != role
                        .extension_output_start
                        .checked_add(1)
                        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
                || role.base_field_output_start != role.base_field_output_end
                || role.distinct_query_group_start != role.distinct_query_group_end
            {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            let challenge_index = usize::try_from(role.extension_output_start)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            challenge = Some(compact_challenge_from_production(
                *message
                    .extension_elements()
                    .get(challenge_index)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            ));
        }
    }
    challenge.ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
}

fn validate_completed_verifier_messages(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    messages: &[DecodedFixedUniformVerifierMessage],
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if messages.is_empty()
        || messages.len() > inputs.verifier_moves.len()
        || inputs
            .verifier_moves
            .iter()
            .zip(messages)
            .any(|(move_contract, message)| {
                u64::try_from(message.extension_elements().len()).ok()
                    != Some(move_contract.message_geometry.extension_output_count())
                    || u64::try_from(message.base_field_elements().len()).ok()
                        != Some(move_contract.message_geometry.base_field_output_count())
                    || message.distinct_query_groups().len()
                        != move_contract.message_geometry.distinct_query_groups().len()
                    || message
                        .distinct_query_groups()
                        .iter()
                        .zip(move_contract.message_geometry.distinct_query_groups())
                        .any(|(positions, geometry)| {
                            u64::try_from(positions.len()).ok() != Some(geometry.query_count())
                                || positions
                                    .iter()
                                    .any(|position| *position >= geometry.domain_cardinality())
                                || positions.windows(2).any(|pair| pair[0] >= pair[1])
                        })
            })
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn cross_epoch_point_from_verifier_message(
    family_material: &CompactPublicKeyFamilyMaterial,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<Vec<CompactChallengeField>, CompactPublicKeyMainEpochPreparationError> {
    let message_geometry = family_material
        .proof_wire_geometry()
        .responses()
        .get(1)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
        .verifier_message_geometry();
    let expected_point_coordinate_count = u64::from(
        family_material
            .relation()
            .cross_epoch_copy_geometry()
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            .point_coordinate_count(),
    );
    if message_geometry.extension_output_count() != expected_point_coordinate_count
        || message_geometry.base_field_output_count() != 0
        || !message_geometry.distinct_query_groups().is_empty()
        || u64::try_from(message.extension_elements().len()).ok()
            != Some(expected_point_coordinate_count)
        || !message.base_field_elements().is_empty()
        || !message.distinct_query_groups().is_empty()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let mut point = Vec::new();
    point
        .try_reserve_exact(message.extension_elements().len())
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
    point.extend(
        message
            .extension_elements()
            .iter()
            .copied()
            .map(compact_challenge_from_production),
    );
    Ok(point)
}

fn initial_cfw_challenges_from_verifier_message(
    family_material: &CompactPublicKeyFamilyMaterial,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<
    (CompactChallengeField, Vec<CompactChallengeField>),
    CompactPublicKeyMainEpochPreparationError,
> {
    let message_geometry = family_material
        .proof_wire_geometry()
        .responses()
        .get(2)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
        .verifier_message_geometry();
    let cfw_geometry = CompactCfwGeometry::derive(
        usize::try_from(family_material.witness_length())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
    )
    .map_err(CompactCfwError::from)?;
    let expected_extension_element_count = u64::try_from(cfw_geometry.sumcheck_round_count())
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
        .checked_add(1)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if message_geometry.extension_output_count() != expected_extension_element_count
        || message_geometry.base_field_output_count() != 0
        || !message_geometry.distinct_query_groups().is_empty()
        || u64::try_from(message.extension_elements().len()).ok()
            != Some(expected_extension_element_count)
        || !message.base_field_elements().is_empty()
        || !message.distinct_query_groups().is_empty()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let (constraint_combining_challenge, equality_point) = message
        .extension_elements()
        .split_first()
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let mut compact_equality_point = Vec::new();
    compact_equality_point
        .try_reserve_exact(equality_point.len())
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
    compact_equality_point.extend(
        equality_point
            .iter()
            .copied()
            .map(compact_challenge_from_production),
    );
    Ok((
        compact_challenge_from_production(*constraint_combining_challenge),
        compact_equality_point,
    ))
}

fn cfw_round_challenge_from_verifier_message(
    family_material: &CompactPublicKeyFamilyMaterial,
    round_ordinal: u32,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<CompactChallengeField, CompactPublicKeyMainEpochPreparationError> {
    let cfw_geometry = CompactCfwGeometry::derive(
        usize::try_from(family_material.witness_length())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
    )
    .map_err(CompactCfwError::from)?;
    let round_index = usize::try_from(round_ordinal)
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if round_index >= cfw_geometry.sumcheck_round_count() {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let response_index = round_index
        .checked_add(3)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let message_geometry = family_material
        .proof_wire_geometry()
        .responses()
        .get(response_index)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
        .verifier_message_geometry();
    if message_geometry.extension_output_count() != 1
        || message_geometry.base_field_output_count() != 0
        || !message_geometry.distinct_query_groups().is_empty()
        || message.extension_elements().len() != 1
        || !message.base_field_elements().is_empty()
        || !message.distinct_query_groups().is_empty()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let challenge = compact_challenge_from_production(message.extension_elements()[0]);
    if round_index + 1 == cfw_geometry.sumcheck_round_count()
        && !compact_cfw_final_challenge_is_allowed(challenge)
    {
        return Err(CompactPublicKeyMainEpochPreparationError::Cfw(
            CompactCfwError::InvalidFinalChallenge,
        ));
    }
    Ok(challenge)
}

fn prepare_pre_challenge_material<Coins: CommonProofPrivateCoinSource>(
    prepared: &PreparedCompactPublicKeyBaseAssignment,
    private_coins: &mut Coins,
    proof_attempt_identifier: [u8; 32],
) -> Result<
    CompactPublicKeyPreChallengeMaterial,
    CompactPublicKeyPreChallengeEncodingError<Coins::Error>,
> {
    let contract = selected_compact_public_key_proof_contract()
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    let verifier_inputs = contract.verifier_inputs();
    let [pre_challenge_epoch, _main_epoch] = verifier_inputs.whir_epochs else {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    };
    let configuration = compact_whir_configuration_from_contract(pre_challenge_epoch)?;
    let cross_epoch_copy = prepared
        .relation
        .cross_epoch_copy_geometry()
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    let copied_element_count = usize::try_from(cross_epoch_copy.copied_element_count())
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    let message_element_count =
        usize::try_from(cross_epoch_copy.pre_challenge_message_element_count())
            .map_err(|_| CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?;
    if !message_element_count.is_power_of_two()
        || configuration.num_variables != message_element_count.ilog2() as usize
        || copied_element_count == 0
        || copied_element_count > message_element_count
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    }
    let mut source = Vec::new();
    source
        .try_reserve_exact(message_element_count)
        .map_err(|_| CompactPublicKeyFamilyMaterializationError::AllocationLimitExceeded)?;
    for element_ordinal in 0..copied_element_count {
        let value = prepared.base_assignment.witness_base_value(
            u64::try_from(element_ordinal).map_err(|_| {
                CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource
            })?,
        )?;
        source.push(Goldilocks::from_u64(value.canonical()));
    }
    source.resize(message_element_count, Goldilocks::ZERO);

    let [source_response_component] = prepared
        .response_merkle_geometries
        .first()
        .ok_or(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource)?
        .components()
    else {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    };
    if source_response_component.value_kind() != CompactResponseLeafValueKind::BaseField {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    }

    let mut randomness = CompactGenerationAttemptRandomness::from_private_coins(
        private_coins,
        proof_attempt_identifier,
    )
    .map_err(CompactPublicKeyPreChallengeEncodingError::PrivateCoin)?;
    let encoded_oracle = CompactWhirEncodedInitialOracle::encode(
        &configuration,
        source,
        randomness.whir_random_source_mut(),
    )?;
    randomness.ensure_field_sampling_valid()?;
    let matrix = encoded_oracle.encoded_matrix();
    if u64::try_from(matrix.height()) != Ok(source_response_component.leaf_count())
        || u64::try_from(matrix.width())
            != Ok(source_response_component.field_element_count_per_leaf())
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidPreChallengeSource.into());
    }
    Ok(CompactPublicKeyPreChallengeMaterial {
        encoded_oracle,
        randomness,
        response_leaf_count: source_response_component.leaf_count(),
    })
}

fn lookup_challenge_from_verifier_message(
    expected_geometry: &FixedUniformVerifierMessageGeometry,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<
    crate::bgv::proof_suite::ProofChallengeExtensionElement,
    CompactPublicKeyFamilyMaterializationError,
> {
    if expected_geometry.extension_output_count() != 1
        || expected_geometry.base_field_output_count() != 0
        || !expected_geometry.distinct_query_groups().is_empty()
        || !message.base_field_elements().is_empty()
        || !message.distinct_query_groups().is_empty()
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
    }
    let [lookup_challenge] = message.extension_elements() else {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
    };
    if lookup_challenge.canonical_coordinates()[1..]
        .iter()
        .all(|coordinate| *coordinate == 0)
    {
        return Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage);
    }
    Ok(*lookup_challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, derive_fixed_uniform_verifier_message,
    };

    #[test]
    fn selected_cross_epoch_response_uses_scalar_leaves_from_the_compiler() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let response = &inputs.response_merkle_geometries[2];
        let roles = &inputs.response_component_roles[2];
        validate_cross_epoch_response_geometry(
            response,
            roles,
            inputs
                .cfw_configuration
                .cross_epoch_disclosed_scalar_count(),
            inputs.cfw_configuration.auxiliary_target_count(),
        )
        .expect("compiler-owned cross-epoch response geometry validates");
        assert_eq!(response.merkle_leaf_count(), 4);
        assert_eq!(
            response
                .components()
                .iter()
                .map(CompactResponseComponentGeometry::leaf_count)
                .collect::<Vec<_>>(),
            vec![3, 1]
        );
        assert!(response.components().iter().all(|component| {
            component.field_element_count_per_leaf() == 1
                && component.value_kind() == CompactResponseLeafValueKind::ExtensionField
                && component.query_selection()
                    == crate::bgv::proof_suite::compact_response_merkle::CompactResponseQuerySelection::EveryLeaf
        }));
        let verifier_message_geometry =
            inputs.proof_wire_geometry.responses()[2].verifier_message_geometry();
        assert_eq!(
            verifier_message_geometry.extension_output_count(),
            u64::try_from(inputs.cfw_configuration.geometry().sumcheck_round_count())
                .expect("selected CFW round count fits the proof wire")
                + 1
        );
        assert_eq!(verifier_message_geometry.base_field_output_count(), 0);
        assert!(verifier_message_geometry.distinct_query_groups().is_empty());
    }

    #[test]
    fn selected_whir_sumcheck_responses_preserve_compiler_padding() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("selected compact contract has both WHIR epochs")
        };
        for batch_index in 0..pre_challenge_epoch.folding_schedule.len() {
            let batch_ordinal = u8::try_from(batch_index).expect("WHIR batch ordinal fits u8");
            let mask_group = unique_internal_mask_group(pre_challenge_epoch, 4, batch_ordinal)
                .expect("selected WHIR mask group is unique");
            let mask_shape = compact_whir_mask_group_shape(mask_group)
                .expect("selected WHIR mask shape derives");
            let messages = vec![
                vec![CompactChallengeField::ZERO; mask_shape.shape.message_len];
                mask_shape.width
            ];
            let randomness = vec![
                vec![CompactChallengeField::ZERO; mask_shape.shape.randomness_len];
                mask_shape.width
            ];
            let mask_oracle =
                CompactWhirEncodedMaskGroup::encode(mask_shape, &messages, &randomness)
                    .expect("selected WHIR mask oracle encodes");
            let response_index = inputs
                .response_component_roles
                .iter()
                .position(|roles| {
                    roles.iter().any(|role| {
                        (
                            role.role_tag,
                            role.epoch,
                            role.batch_ordinal,
                            role.round_ordinal,
                        ) == (11, pre_challenge_epoch.epoch, batch_ordinal, 0)
                    })
                })
                .expect("selected response registry contains each WHIR mask response");
            assert_eq!(
                unique_response_ordinal_for_component_role(
                    &inputs,
                    11,
                    pre_challenge_epoch.epoch,
                    batch_ordinal,
                    0,
                )
                .expect("each selected WHIR mask owns one response"),
                u32::try_from(response_index).expect("selected response index fits u32")
            );
            let response = &inputs.response_merkle_geometries[response_index];
            validate_whir_sumcheck_response_geometry(
                response,
                &inputs.response_component_roles[response_index],
                pre_challenge_epoch.epoch,
                batch_ordinal,
                &mask_oracle,
            )
            .expect("compiler-owned WHIR response geometry validates");

            let [mask_component, auxiliary_component, padding_component] = response.components()
            else {
                panic!("selected WHIR response has mask, auxiliary, and padding components")
            };
            assert_eq!(
                mask_component.leaf_count(),
                u64::try_from(mask_oracle.encoded_matrix().height()).unwrap()
            );
            assert_eq!(auxiliary_component.leaf_count(), 1);
            assert!(padding_component.leaf_count() > 0);
            assert_eq!(
                mask_component.leaf_count()
                    + auxiliary_component.leaf_count()
                    + padding_component.leaf_count(),
                response.merkle_leaf_count()
            );
        }
    }

    #[test]
    fn selected_whir_sumcheck_source_lengths_use_the_correct_domain_owner() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("selected compact contract has both WHIR epochs")
        };
        for (batch_index, folding_factor) in pre_challenge_epoch
            .folding_schedule
            .iter()
            .copied()
            .enumerate()
        {
            let batch_ordinal = u8::try_from(batch_index).expect("WHIR batch ordinal fits u8");
            let source_length =
                whir_sumcheck_source_length(&inputs, pre_challenge_epoch, batch_ordinal)
                    .expect("selected WHIR sumcheck source length derives");
            if batch_ordinal == 0 {
                assert_eq!(
                    source_length,
                    1_usize << pre_challenge_epoch.polynomial_variable_count
                );
            } else {
                let source_contract =
                    unique_whir_fold_contract(&inputs, pre_challenge_epoch.epoch, batch_ordinal)
                        .expect("selected WHIR source contract is unique");
                assert_eq!(
                    u64::try_from(source_length).unwrap(),
                    source_contract.message_length * source_contract.oracle_width
                );
            }
            assert!(
                source_length
                    .checked_shr(folding_factor)
                    .is_some_and(|residual_length| residual_length > 0)
            );
        }
    }

    #[test]
    fn selected_initial_whir_challenges_are_read_from_their_exact_compiler_roles() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("selected compact contract has both WHIR epochs")
        };
        let messages = inputs
            .verifier_moves
            .iter()
            .enumerate()
            .map(|(move_index, move_contract)| {
                derive_fixed_uniform_verifier_message(
                    Hash512::from_bytes([u8::try_from(move_index + 1).unwrap(); 64]),
                    u32::try_from(move_index).unwrap(),
                    &move_contract.message_geometry,
                )
                .expect("selected verifier message derives")
            })
            .collect::<Vec<_>>();
        let mut checked_role_count = 0_usize;
        for (move_index, move_contract) in inputs.verifier_moves.iter().enumerate() {
            for role in move_contract.role_coordinates.iter().filter(|role| {
                role.epoch == pre_challenge_epoch.epoch
                    && role.batch_ordinal == 0
                    && matches!(role.role_tag, 7 | 8)
            }) {
                let challenge = unique_completed_extension_role_challenge(
                    &inputs,
                    &messages[..=move_index],
                    role.role_tag,
                    role.epoch,
                    role.batch_ordinal,
                    role.round_ordinal,
                )
                .expect("the exact completed compiler role supplies its challenge");
                assert_eq!(
                    challenge,
                    compact_challenge_from_production(
                        messages[move_index].extension_elements()
                            [usize::try_from(role.extension_output_start).unwrap()]
                    )
                );
                if move_index > 0 {
                    assert_eq!(
                        unique_completed_extension_role_challenge(
                            &inputs,
                            &messages[..move_index],
                            role.role_tag,
                            role.epoch,
                            role.batch_ordinal,
                            role.round_ordinal,
                        ),
                        Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
                    );
                }
                checked_role_count += 1;
            }
        }
        assert_eq!(
            checked_role_count,
            usize::try_from(pre_challenge_epoch.folding_schedule[0]).unwrap() + 1
        );
    }

    #[test]
    fn selected_code_switch_challenges_are_read_from_their_exact_mixed_output_roles() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("selected compact contract has both WHIR epochs")
        };
        let messages = inputs
            .verifier_moves
            .iter()
            .enumerate()
            .map(|(move_index, move_contract)| {
                derive_fixed_uniform_verifier_message(
                    Hash512::from_bytes([u8::try_from(move_index + 1).unwrap(); 64]),
                    u32::try_from(move_index).unwrap(),
                    &move_contract.message_geometry,
                )
                .expect("selected verifier message derives")
            })
            .collect::<Vec<_>>();
        let mut checked_role_count = 0_usize;
        for (move_index, move_contract) in inputs.verifier_moves.iter().enumerate() {
            for role in move_contract
                .role_coordinates
                .iter()
                .filter(|role| role.role_tag == 9 && role.epoch == pre_challenge_epoch.epoch)
            {
                let (challenge, query_positions) = completed_code_switch_verifier_move(
                    &inputs,
                    &messages[..=move_index],
                    role.epoch,
                    role.round_ordinal,
                )
                .expect("the exact completed code-switch role supplies its outputs");
                assert_eq!(
                    challenge,
                    compact_challenge_from_production(
                        messages[move_index].extension_elements()
                            [usize::try_from(role.extension_output_start).unwrap()]
                    )
                );
                assert_eq!(
                    query_positions,
                    messages[move_index].distinct_query_groups()
                        [usize::try_from(role.distinct_query_group_start).unwrap()]
                );
                if move_index > 0 {
                    assert_eq!(
                        completed_code_switch_verifier_move(
                            &inputs,
                            &messages[..move_index],
                            role.epoch,
                            role.round_ordinal,
                        ),
                        Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
                    );
                }
                checked_role_count += 1;
            }
        }
        assert_eq!(
            checked_role_count,
            pre_challenge_epoch.folding_schedule.len() - 1
        );
    }

    #[test]
    fn lookup_challenge_requires_the_exact_first_message_shape() {
        let contract = crate::bgv::proof_suite::compact_proof_contract::selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let geometry = contract.verifier_inputs().proof_wire_geometry.responses()[0]
            .verifier_message_geometry();
        let message = derive_fixed_uniform_verifier_message(
            Hash512::from_bytes([0x31; Hash512::BYTE_LENGTH]),
            0,
            geometry,
        )
        .expect("the exact lookup message derives");
        let challenge = lookup_challenge_from_verifier_message(geometry, &message)
            .expect("the exact first-message shape supplies the lookup challenge");
        assert!(
            challenge.canonical_coordinates()[1..]
                .iter()
                .any(|coordinate| *coordinate != 0)
        );

        for wrong_geometry in [
            FixedUniformVerifierMessageGeometry::new(2, 0, 0, Vec::new())
                .expect("two-extension geometry"),
            FixedUniformVerifierMessageGeometry::new(1, 0, 1, Vec::new())
                .expect("unexpected base-field geometry"),
            FixedUniformVerifierMessageGeometry::new(
                1,
                0,
                0,
                vec![FixedUniformDistinctQueryGeometry::new(16, 2)],
            )
            .expect("unexpected query geometry"),
        ] {
            let wrong_message = derive_fixed_uniform_verifier_message(
                Hash512::from_bytes([0x32; Hash512::BYTE_LENGTH]),
                0,
                &wrong_geometry,
            )
            .expect("the alternate typed message derives");
            assert_eq!(
                lookup_challenge_from_verifier_message(geometry, &wrong_message),
                Err(CompactPublicKeyFamilyMaterializationError::InvalidVerifierMessage)
            );
        }
    }

    #[test]
    fn verifier_derived_opening_schedule_selects_exact_main_source_rows() {
        assert_eq!(
            main_source_opening_rows_from_query_schedule(4, 12, &[1, 4, 7, 11, 12, 20])
                .expect("the canonical schedule selects its main-source coordinates"),
            vec![0, 3, 7]
        );
        for invalid_schedule in [
            Vec::new(),
            vec![1, 4, 4, 11],
            vec![7, 4],
            vec![0, 1, 12, 13],
        ] {
            assert_eq!(
                main_source_opening_rows_from_query_schedule(4, 12, &invalid_schedule),
                Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
            );
        }
        assert_eq!(
            main_source_opening_rows_from_query_schedule(12, 12, &[12]),
            Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
        );
    }
}
