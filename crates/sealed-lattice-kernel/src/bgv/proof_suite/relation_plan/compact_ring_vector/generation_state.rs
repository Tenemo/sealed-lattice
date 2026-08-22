//! Pollable production materialization for the compact public-key family.
//!
//! This state owns the authenticated assignment loader, encodes and retains the
//! pre-challenge source before the lookup challenge, accepts that challenge
//! only through the exact compact transcript authority, performs the bounded
//! batch inversion, prepares the production structured-row source, drives the
//! external-memory CFW reduction, and advances both WHIR epochs through every
//! masked sumcheck, code switch, base response, and final-query masking gate.
//! It does not yet finalize a complete proof or run algebraic verification and
//! therefore cannot mint a workflow capability.

use std::rc::Rc;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use rand::{Rng, RngExt};

use crate::bgv::proof_suite::external_memory::ProofExternalMemoryUsage;
use crate::bgv::proof_suite::{
    ProofBaseFieldElement,
    compact_cfw::{
        COMPACT_CFW_MATRIX_COUNT, COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwError,
        CompactCfwGeometry, CompactCfwMaskMaterial, CompactCfwMaskedCrossEpochClaims,
        CompactCfwPrefixEvaluationError, CompactCfwPrefixEvaluationState,
        CompactCfwPublicMainCovectorCombination, CompactCfwPublicMainCovectorContinuation,
        CompactChallengeField, compact_cfw_final_challenge_is_allowed,
        compact_challenge_from_production, compact_challenge_to_production,
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
        CompactMaskingEntropyError, CompactMaskingQueryLeaf, CompactVerifiedBaseMaskingPrefix,
        CompactVerifiedBaseRevealMasking, CompactVerifiedWhirBaseCovector,
        CompactWhirSumcheckBatchCoordinate, begin_selected_compact_whir_base_covector_derivation,
        finish_selected_compact_whir_base_covector_derivation,
        verify_selected_compact_cfw_finish_masking, verify_selected_compact_cfw_round_masking,
        verify_selected_compact_cross_epoch_masking_prefix,
        verify_selected_compact_whir_base_final_query_masking,
        verify_selected_compact_whir_base_reveal_masking,
        verify_selected_compact_whir_source_query_masking,
        verify_selected_compact_whir_sumcheck_auxiliary_masking,
        verify_selected_compact_whir_sumcheck_round_masking,
    },
    compact_masking_kmac::{CompactMaskingKmacError, derive_selected_compact_masking_kmac_bridge},
    compact_masking_prefix::CompactMaskingAttemptIdentity,
    compact_masking_public_covector::{
        CompactFactorOneCarriedCovector, CompactFactorOnePublicCovectorAuthority,
        CompactFactorOnePublicCovectorDerivation, CompactFactorOnePublicCovectorError,
        CompactFactorOnePublicCovectorPoll,
    },
    compact_proof_contract::{
        CompactProofContractError, CompactPublicKeyProofContract, CompactPublicKeyVerifierInputs,
        CompactResponseComponentRoleContract, CompactWhirEpochContract, CompactWhirFoldContract,
        CompactWhirMaskGroupContract, selected_compact_public_key_proof_contract,
    },
    compact_proof_wire::{
        CompactProofWireGeometry, CompactPublicInputBindings, DecodedCompactPublicInput,
    },
    compact_response_generation::{
        CompactOwnedResponseLeaf, CompactResponseGenerationError, CompactResponseGenerationOutput,
        CompactResponseGenerationPoll, CompactResponseGenerationPollError,
        CompactResponseGenerationState, CompactVerifierMessageAuthority,
    },
    compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValueKind,
        CompactResponseMerkleGeometry, CompactResponseQuerySelection,
    },
    compact_whir::{
        CompactWhirBaseCaseState, CompactWhirBaseMaskInput, CompactWhirBaseRelation,
        CompactWhirCodeSwitchPreparationPoll, CompactWhirCodeSwitchRelationPreparation,
        CompactWhirCodeSwitchRelationPreparationPoll, CompactWhirCodeSwitchState,
        CompactWhirEncodedInitialOracle, CompactWhirEncodedMaskGroup, CompactWhirError,
        CompactWhirInitialSumcheckPoll, CompactWhirInitialSumcheckSourceReplayError,
        CompactWhirInitialSumcheckState, CompactWhirMainRelationPreparation,
        CompactWhirMainRelationPreparationError, CompactWhirMainRelationPreparationPoll,
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

#[cfg(test)]
use super::authenticated_assignment::InjectedCompactPublicKeyWitnessEquationFault;
use super::{
    CompactPublicKeyRelationCatalog, PreparedCompactPublicKeyAssignmentSources,
    PreparedCompactPublicKeyBaseAssignment,
    authenticated_assignment::{
        CompactAuthenticatedAssignmentPoll, CompactLookupInverseMaterializationPoll,
        CompactLookupInverseMaterializer, CompactPublicKeyAssignment,
        CompactPublicKeyBaseAssignment,
    },
    structured_r1cs::{
        CompactStructuredAssignmentTransposeSource, CompactStructuredR1csRowSource,
        CompactStructuredR1csRowSourcePreparation, CompactStructuredR1csRowSourcePreparationPoll,
        CompactStructuredR1csRowSourcePreparationStep, CompactStructuredWitnessCovectorAccumulator,
        CompactStructuredWitnessCovectorAccumulatorPoll,
        CompactStructuredWitnessCovectorAccumulatorStep,
    },
};

type SelectedCompactPublicKeyAssignment = Rc<CompactPublicKeyAssignment>;
type SelectedCompactPublicKeyRowSource =
    CompactStructuredR1csRowSource<SelectedCompactPublicKeyAssignment>;
type SelectedCompactPublicKeyRowSourcePreparation =
    CompactStructuredR1csRowSourcePreparation<SelectedCompactPublicKeyAssignment>;
type SelectedCompactPublicKeyTransposeSource =
    CompactStructuredAssignmentTransposeSource<SelectedCompactPublicKeyAssignment>;
type SelectedCompactPublicKeyCovectorAccumulator =
    CompactStructuredWitnessCovectorAccumulator<SelectedCompactPublicKeyTransposeSource>;

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
    WhirBaseFreshMasking(CompactMaskingEntropyError),
    MaskingKmac(CompactMaskingKmacError),
    MaskingPublicCovector(CompactFactorOnePublicCovectorError),
    Randomness(CompactGenerationRandomnessError),
    Whir(CompactWhirError),
    Prover(CommonProofProverError),
    ResponseGeneration(CompactResponseGenerationError),
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

impl From<CompactResponseGenerationError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactResponseGenerationError) -> Self {
        Self::ResponseGeneration(error)
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
        round_ordinal: u8,
        processed_work_unit_count: u64,
        fold_complete: bool,
    },
    PreChallengeWhirCodeSwitchPrepared {
        round_ordinal: u8,
    },
    PreChallengeWhirCodeSwitchSourceStepCompleted {
        round_ordinal: u8,
        processed_work_unit_count: u64,
    },
    PreChallengeWhirCodeSwitchResponseCheckpointReady {
        round_ordinal: u8,
    },
    PreChallengeWhirCodeSwitchRelationStepCompleted {
        round_ordinal: u8,
        processed_work_unit_count: u64,
        relation_complete: bool,
    },
    PreChallengeWhirBaseCovectorStepCompleted {
        completed_work_unit_count: u64,
    },
    PreChallengeWhirBaseCovectorsPrepared,
    PreChallengeWhirBaseFreshSourceStepCompleted {
        processed_work_unit_count: u64,
    },
    PreChallengeWhirBasePrepared,
    PreChallengeWhirBaseFreshResponseCheckpointReady,
    PreChallengeWhirBaseBlindedResponsePrepared,
    PreChallengeWhirBaseFinalQueryStepCompleted {
        processed_work_unit_count: u64,
    },
    PreChallengeWhirBaseBlindedResponseCheckpointReady,
    MainWhirCovectorStepCompleted {
        step: CompactStructuredWitnessCovectorAccumulatorStep,
        completed_work_unit_count: u64,
    },
    MainWhirCovectorsPrepared,
    MainWhirRelationSourceStepCompleted {
        processed_work_unit_count: u64,
        relation_complete: bool,
    },
    MainWhirSumcheckPrepared {
        batch_ordinal: u8,
    },
    MainWhirRoundPolynomialStepCompleted {
        batch_ordinal: u8,
        round_ordinal: u32,
        polynomial_ready: bool,
    },
    MainWhirBoundRoundStepCompleted {
        batch_ordinal: u8,
        round_ordinal: u32,
        round_complete: bool,
    },
    MainWhirWeightScalingStepCompleted {
        batch_ordinal: u8,
        scaling_complete: bool,
    },
    MainWhirAuxiliaryResponseCheckpointReady {
        batch_ordinal: u8,
    },
    MainWhirRoundResponseCheckpointReady {
        batch_ordinal: u8,
        round_ordinal: u32,
    },
    MainWhirSumcheckComplete {
        batch_ordinal: u8,
    },
    MainWhirCodeSwitchRandomnessStepCompleted {
        round_ordinal: u8,
        processed_work_unit_count: u64,
        fold_complete: bool,
    },
    MainWhirCodeSwitchPrepared {
        round_ordinal: u8,
    },
    MainWhirCodeSwitchSourceStepCompleted {
        round_ordinal: u8,
        processed_work_unit_count: u64,
    },
    MainWhirCodeSwitchResponseCheckpointReady {
        round_ordinal: u8,
    },
    MainWhirCodeSwitchRelationStepCompleted {
        round_ordinal: u8,
        processed_work_unit_count: u64,
        relation_complete: bool,
    },
    MainWhirBaseFreshSourceStepCompleted {
        processed_work_unit_count: u64,
    },
    MainWhirBaseCovectorStepCompleted {
        completed_work_unit_count: u64,
    },
    MainWhirBaseCovectorsPrepared,
    MainWhirBasePrepared,
    MainWhirBaseFreshResponseCheckpointReady,
    MainWhirBaseBlindedResponsePrepared,
    MainWhirBaseFinalQueryStepCompleted {
        processed_work_unit_count: u64,
    },
    MainWhirBaseBlindedResponseCheckpointReady,
    PostLookupCheckpointReady,
    CrossEpochCheckpointReady,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactPublicKeyWhirEpoch {
    PreChallenge,
    Main,
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
    #[cfg(test)]
    test_only_cfw_masking_inconsistency_round_ordinals: Vec<u32>,
    pre_challenge_whir_relation_preparation: Option<CompactWhirPreChallengeRelationPreparation>,
    pre_challenge_whir_sumcheck_batches: Vec<CompactPublicKeyWhirSumcheckBatch>,
    pre_challenge_whir_code_switches: Vec<CompactPublicKeyWhirCodeSwitch>,
    pre_challenge_whir_base_case: Option<CompactPublicKeyWhirBaseCase>,
    verified_pre_challenge_whir_base_masking_prefix: Option<CompactVerifiedBaseMaskingPrefix>,
    main_whir_covector_accumulator: Option<SelectedCompactPublicKeyCovectorAccumulator>,
    main_whir_covector_continuation: Option<CompactCfwPublicMainCovectorContinuation>,
    main_whir_relation_preparation: Option<CompactWhirMainRelationPreparation>,
    main_whir_sumcheck_batches: Vec<CompactPublicKeyWhirSumcheckBatch>,
    main_whir_code_switches: Vec<CompactPublicKeyWhirCodeSwitch>,
    whir_base_covector_derivation: Option<CompactPublicKeyWhirBaseCovectorDerivation>,
    main_whir_base_case: Option<CompactPublicKeyWhirBaseCase>,
    main_source_queries: Option<CompactPublicKeyRetainedSourceQueries>,
}

struct CompactPublicKeyWhirBaseCovectorDerivation {
    epoch_owner: CompactPublicKeyWhirEpoch,
    derivation: Option<CompactFactorOnePublicCovectorDerivation>,
    authorization: Option<Box<CompactFactorOneCarriedCovector>>,
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

    fn final_response_ordinal(&self) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        self.initial_response_ordinal
            .checked_add(
                u32::try_from(self.state.mask_messages().len())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
    }

    fn owns_response_ordinal(
        &self,
        response_ordinal: u32,
    ) -> Result<bool, CompactPublicKeyMainEpochPreparationError> {
        Ok(
            (self.initial_response_ordinal..=self.final_response_ordinal()?)
                .contains(&response_ordinal),
        )
    }

    fn expected_response_ordinal(&self) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        if self.response_leaf_count == 0 || self.bound_round_advance_required {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        if !self.combination_challenge_bound {
            if self.masking_outputs.len() != 1 || self.round_masking_verified {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            return Ok(self.initial_response_ordinal);
        }
        let round_index = self.state.round_challenges().len();
        if round_index >= self.state.mask_messages().len()
            || self.state.pending_round_wire().is_err()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let offset = u32::try_from(round_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            .checked_add(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        self.initial_response_ordinal
            .checked_add(offset)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
    }

    fn response_leaf(
        &self,
        response_merkle_geometries: &[CompactResponseMerkleGeometry],
        response_ordinal: u32,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        if !self.owns_response_ordinal(response_ordinal)? {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        if response_ordinal == self.initial_response_ordinal {
            if leaf_ordinal >= self.response_leaf_count {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            let mask_height = u64::try_from(self.state.mask_oracle().encoded_matrix().height())
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            if leaf_ordinal < mask_height {
                return encoded_extension_response_leaf(self.state.mask_oracle(), leaf_ordinal);
            }
            if leaf_ordinal == mask_height {
                let auxiliary_target = self.state.auxiliary_target();
                return encoded_extension_values_response_leaf(Some(core::slice::from_ref(
                    &auxiliary_target,
                )));
            }
            return Ok(CompactOwnedResponseLeaf::padding());
        }
        let round_index = usize::try_from(
            response_ordinal
                .checked_sub(self.initial_response_ordinal)
                .and_then(|offset| offset.checked_sub(1))
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let response_geometry = response_merkle_geometries
            .get(
                usize::try_from(response_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .filter(|geometry| geometry.response_ordinal() == response_ordinal)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if leaf_ordinal >= response_geometry.merkle_leaf_count() {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let Some(value) = self.state.round_wire(round_index).and_then(|wire| {
            usize::try_from(leaf_ordinal)
                .ok()
                .and_then(|index| wire.get(index))
        }) else {
            return Ok(CompactOwnedResponseLeaf::padding());
        };
        encoded_extension_values_response_leaf(Some(core::slice::from_ref(value)))
    }
}

impl CompactPublicKeyWhirEpoch {
    fn contract<'contract>(
        self,
        inputs: &CompactPublicKeyVerifierInputs<'contract>,
    ) -> Result<&'contract CompactWhirEpochContract, CompactPublicKeyMainEpochPreparationError>
    {
        let [pre_challenge_epoch, main_epoch] = inputs.whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        Ok(match self {
            Self::PreChallenge => pre_challenge_epoch,
            Self::Main => main_epoch,
        })
    }

    fn round_polynomial_poll(
        self,
        batch_ordinal: u8,
        round_ordinal: u32,
        polynomial_ready: bool,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundPolynomialStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    polynomial_ready,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirRoundPolynomialStepCompleted {
                batch_ordinal,
                round_ordinal,
                polynomial_ready,
            },
        }
    }

    fn bound_round_poll(
        self,
        batch_ordinal: u8,
        round_ordinal: u32,
        round_complete: bool,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBoundRoundStepCompleted {
                    batch_ordinal,
                    round_ordinal,
                    round_complete,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBoundRoundStepCompleted {
                batch_ordinal,
                round_ordinal,
                round_complete,
            },
        }
    }

    fn weight_scaling_poll(
        self,
        batch_ordinal: u8,
        scaling_complete: bool,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirWeightScalingStepCompleted {
                    batch_ordinal,
                    scaling_complete,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirWeightScalingStepCompleted {
                batch_ordinal,
                scaling_complete,
            },
        }
    }

    fn auxiliary_checkpoint_poll(self, batch_ordinal: u8) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirAuxiliaryResponseCheckpointReady {
                    batch_ordinal,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirAuxiliaryResponseCheckpointReady {
                batch_ordinal,
            },
        }
    }

    fn round_checkpoint_poll(
        self,
        batch_ordinal: u8,
        round_ordinal: u32,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirRoundResponseCheckpointReady {
                    batch_ordinal,
                    round_ordinal,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirRoundResponseCheckpointReady {
                batch_ordinal,
                round_ordinal,
            },
        }
    }

    fn sumcheck_complete_poll(self, batch_ordinal: u8) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckComplete { batch_ordinal }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirSumcheckComplete { batch_ordinal },
        }
    }

    fn code_switch_randomness_poll(
        self,
        round_ordinal: u8,
        processed_work_unit_count: u64,
        fold_complete: bool,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRandomnessStepCompleted {
                    round_ordinal,
                    processed_work_unit_count,
                    fold_complete,
                }
            }
            Self::Main => {
                CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRandomnessStepCompleted {
                    round_ordinal,
                    processed_work_unit_count,
                    fold_complete,
                }
            }
        }
    }

    fn code_switch_prepared_poll(self, round_ordinal: u8) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchPrepared { round_ordinal }
            }
            Self::Main => {
                CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchPrepared { round_ordinal }
            }
        }
    }

    fn code_switch_source_poll(
        self,
        round_ordinal: u8,
        processed_work_unit_count: u64,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchSourceStepCompleted {
                    round_ordinal,
                    processed_work_unit_count,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchSourceStepCompleted {
                round_ordinal,
                processed_work_unit_count,
            },
        }
    }

    fn code_switch_checkpoint_poll(self, round_ordinal: u8) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchResponseCheckpointReady {
                    round_ordinal,
                }
            }
            Self::Main => {
                CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchResponseCheckpointReady {
                    round_ordinal,
                }
            }
        }
    }

    fn code_switch_relation_poll(
        self,
        round_ordinal: u8,
        processed_work_unit_count: u64,
        relation_complete: bool,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirCodeSwitchRelationStepCompleted {
                    round_ordinal,
                    processed_work_unit_count,
                    relation_complete,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirCodeSwitchRelationStepCompleted {
                round_ordinal,
                processed_work_unit_count,
                relation_complete,
            },
        }
    }

    fn sumcheck_prepared_poll(self, batch_ordinal: u8) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirSumcheckPrepared { batch_ordinal }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared { batch_ordinal },
        }
    }

    fn base_fresh_source_poll(
        self,
        processed_work_unit_count: u64,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshSourceStepCompleted {
                    processed_work_unit_count,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBaseFreshSourceStepCompleted {
                processed_work_unit_count,
            },
        }
    }

    fn base_covector_step_poll(
        self,
        completed_work_unit_count: u64,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorStepCompleted {
                    completed_work_unit_count,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorStepCompleted {
                completed_work_unit_count,
            },
        }
    }

    fn base_covectors_prepared_poll(self) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseCovectorsPrepared
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBaseCovectorsPrepared,
        }
    }

    fn base_prepared_poll(self) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => CompactPublicKeyMainEpochPoll::PreChallengeWhirBasePrepared,
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBasePrepared,
        }
    }

    fn base_fresh_checkpoint_poll(self) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFreshResponseCheckpointReady
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBaseFreshResponseCheckpointReady,
        }
    }

    fn base_blinded_prepared_poll(self) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponsePrepared
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponsePrepared,
        }
    }

    fn base_final_query_poll(
        self,
        processed_work_unit_count: u64,
    ) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseFinalQueryStepCompleted {
                    processed_work_unit_count,
                }
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBaseFinalQueryStepCompleted {
                processed_work_unit_count,
            },
        }
    }

    fn base_blinded_checkpoint_poll(self) -> CompactPublicKeyMainEpochPoll {
        match self {
            Self::PreChallenge => {
                CompactPublicKeyMainEpochPoll::PreChallengeWhirBaseBlindedResponseCheckpointReady
            }
            Self::Main => CompactPublicKeyMainEpochPoll::MainWhirBaseBlindedResponseCheckpointReady,
        }
    }
}

struct CompactPublicKeyRetainedSourceQueries {
    positions: Vec<u64>,
    outputs: Vec<CompactChallengeField>,
    width: usize,
}

impl CompactPublicKeyRetainedSourceQueries {
    fn new(
        positions: &[u64],
        width: usize,
    ) -> Result<Self, CompactPublicKeyMainEpochPreparationError> {
        if positions.is_empty() || positions.windows(2).any(|pair| pair[0] >= pair[1]) || width == 0
        {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let mut copied_positions = Vec::new();
        copied_positions
            .try_reserve_exact(positions.len())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        copied_positions.extend_from_slice(positions);
        let output_count = positions
            .len()
            .checked_mul(width)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(output_count)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        Ok(Self {
            positions: copied_positions,
            outputs,
            width,
        })
    }

    fn positions(&self) -> &[u64] {
        &self.positions
    }

    fn outputs(&self) -> &[CompactChallengeField] {
        &self.outputs
    }

    fn next_position(&self) -> Result<Option<u64>, CompactPublicKeyMainEpochPreparationError> {
        if !self.outputs.len().is_multiple_of(self.width) {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok(self.positions.get(self.outputs.len() / self.width).copied())
    }

    fn append_row(
        &mut self,
        position: u64,
        row: &[CompactChallengeField],
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        if self.next_position()? != Some(position) || row.len() != self.width {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        self.outputs.extend_from_slice(row);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.outputs.len() == self.positions.len().saturating_mul(self.width)
    }

    fn row(
        &self,
        position: u64,
    ) -> Result<&[CompactChallengeField], CompactPublicKeyMainEpochPreparationError> {
        if !self.is_complete() {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let query_index = self
            .positions
            .binary_search(&position)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let first_value = query_index
            .checked_mul(self.width)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let end_value = first_value
            .checked_add(self.width)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        self.outputs
            .get(first_value..end_value)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
    }
}

impl Drop for CompactPublicKeyRetainedSourceQueries {
    fn drop(&mut self) {
        self.outputs.fill(CompactChallengeField::ZERO);
    }
}

struct CompactPublicKeyWhirCodeSwitch {
    round_ordinal: u8,
    response_ordinal: u32,
    state: CompactWhirCodeSwitchState,
    response_leaf_count: u64,
    source_query_masking_verified: bool,
    retained_source_queries: Option<CompactPublicKeyRetainedSourceQueries>,
    relation_preparation: Option<CompactWhirCodeSwitchRelationPreparation>,
}

impl CompactPublicKeyWhirCodeSwitch {
    fn new(round_ordinal: u8, response_ordinal: u32, state: CompactWhirCodeSwitchState) -> Self {
        Self {
            round_ordinal,
            response_ordinal,
            state,
            response_leaf_count: 0,
            source_query_masking_verified: false,
            retained_source_queries: None,
            relation_preparation: None,
        }
    }

    fn component_boundaries(&self) -> Result<[u64; 2], CompactPublicKeyMainEpochPreparationError> {
        let source_end = u64::try_from(self.state.source_oracle().encoded_height())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let mask_end = source_end
            .checked_add(
                u64::try_from(self.state.switch_mask_oracle()?.encoded_matrix().height())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if self.response_leaf_count == 0 || mask_end > self.response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok([source_end, mask_end])
    }

    fn poll_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyCodeSwitchResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let [source_end, _mask_end] = self.component_boundaries()?;
        if leaf_ordinal >= self.response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        if leaf_ordinal >= source_end {
            return Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                self.response_leaf(leaf_ordinal)?,
            ));
        }
        match self.state.poll_source_oracle(maximum_work_unit_count)? {
            CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                processed_work_unit_count,
            } => Ok(
                CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                let row = self
                    .state
                    .source_row(usize::try_from(leaf_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                    })?)?;
                Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                    encoded_extension_values_response_leaf(Some(row))?,
                ))
            }
        }
    }

    fn mark_response_leaf_supplied(
        &mut self,
        leaf_ordinal: u64,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let [source_end, _mask_end] = self.component_boundaries()?;
        if leaf_ordinal < source_end {
            self.state.mark_source_row_supplied(
                usize::try_from(leaf_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )?;
        }
        Ok(())
    }

    fn poll_opened_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
        opening_query_leaf_ordinals: &[u64],
    ) -> Result<CompactPublicKeyCodeSwitchResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let [source_end, _mask_end] = self.component_boundaries()?;
        if leaf_ordinal >= source_end {
            return Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                self.response_leaf(leaf_ordinal)?,
            ));
        }
        let source_row = usize::try_from(leaf_ordinal)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if self.state.can_begin_source_opening_replay() {
            let opening_rows = main_source_opening_rows_from_query_schedule(
                0,
                source_end,
                opening_query_leaf_ordinals,
            )?;
            if opening_rows.first().copied() != Some(source_row) {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            self.state.begin_source_opening_replay(&opening_rows)?;
        }
        match self.state.poll_source_oracle(maximum_work_unit_count)? {
            CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                processed_work_unit_count,
            } => Ok(
                CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                    encoded_extension_values_response_leaf(Some(
                        self.state.source_row(source_row)?,
                    ))?,
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
        let [source_end, mask_end] = self.component_boundaries()?;
        if leaf_ordinal < source_end {
            let row_ordinal = usize::try_from(leaf_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            let row = if self.state.source_opening_replay_complete() {
                self.retained_source_row(leaf_ordinal)?
            } else {
                self.state.source_row(row_ordinal)?
            };
            return encoded_extension_values_response_leaf(Some(row));
        }
        if leaf_ordinal < mask_end {
            return encoded_extension_response_leaf(
                self.state.switch_mask_oracle()?,
                leaf_ordinal - source_end,
            );
        }
        Ok(CompactOwnedResponseLeaf::padding())
    }

    fn retained_source_row(
        &self,
        leaf_ordinal: u64,
    ) -> Result<&[CompactChallengeField], CompactPublicKeyMainEpochPreparationError> {
        self.retained_source_queries
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .row(leaf_ordinal)
    }
}

struct CompactPublicKeyWhirBaseCase {
    fresh_response_ordinal: u32,
    blinded_response_ordinal: u32,
    state: CompactWhirBaseCaseState,
    fresh_response_leaf_count: u64,
    blinded_response_leaf_count: u64,
    fresh_claim_masking_verified: bool,
    verified_blinded_response_masking: Option<CompactVerifiedBaseRevealMasking>,
    final_query_leaves: Vec<CompactMaskingQueryLeaf>,
    verified_final_query_masking: Option<CompactVerifiedBaseMaskingPrefix>,
}

impl CompactPublicKeyWhirBaseCase {
    fn fresh_component_boundaries(
        &self,
    ) -> Result<Vec<u64>, CompactPublicKeyMainEpochPreparationError> {
        let mut boundaries = Vec::new();
        boundaries
            .try_reserve_exact(
                self.state
                    .fresh_mask_group_count()
                    .checked_add(2)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        let mut end = u64::try_from(self.state.fresh_source_oracle().encoded_height())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        boundaries.push(end);
        for group_ordinal in 0..self.state.fresh_mask_group_count() {
            let group = self
                .state
                .fresh_mask_oracle(group_ordinal)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            end = end
                .checked_add(
                    u64::try_from(group.encoded_matrix().height())
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                )
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            boundaries.push(end);
        }
        end = end
            .checked_add(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        boundaries.push(end);
        if end > self.fresh_response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok(boundaries)
    }

    fn poll_fresh_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyCodeSwitchResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let source_end = *self
            .fresh_component_boundaries()?
            .first()
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if leaf_ordinal >= self.fresh_response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        if leaf_ordinal >= source_end {
            return Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                self.fresh_response_leaf(leaf_ordinal)?,
            ));
        }
        match self
            .state
            .poll_fresh_source_oracle(maximum_work_unit_count)?
        {
            CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                processed_work_unit_count,
            } => Ok(
                CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                let row = self
                    .state
                    .fresh_source_row(usize::try_from(leaf_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                    })?)?;
                Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                    encoded_extension_values_response_leaf(Some(row))?,
                ))
            }
        }
    }

    fn mark_fresh_response_leaf_supplied(
        &mut self,
        leaf_ordinal: u64,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let source_end = *self
            .fresh_component_boundaries()?
            .first()
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if leaf_ordinal < source_end {
            self.state.mark_fresh_source_row_supplied(
                usize::try_from(leaf_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )?;
        }
        Ok(())
    }

    fn poll_opened_fresh_response_leaf(
        &mut self,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
        opening_query_leaf_ordinals: &[u64],
    ) -> Result<CompactPublicKeyCodeSwitchResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let source_end = *self
            .fresh_component_boundaries()?
            .first()
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if leaf_ordinal >= source_end {
            return Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                self.fresh_response_leaf(leaf_ordinal)?,
            ));
        }
        let source_row = usize::try_from(leaf_ordinal)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if self.state.fresh_source_oracle().can_begin_opening_replay() {
            let opening_rows = main_source_opening_rows_from_query_schedule(
                0,
                source_end,
                opening_query_leaf_ordinals,
            )?;
            if opening_rows.first().copied() != Some(source_row) {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            self.state
                .begin_fresh_source_opening_replay(&opening_rows)?;
        }
        match self
            .state
            .poll_fresh_source_oracle(maximum_work_unit_count)?
        {
            CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                processed_work_unit_count,
            } => Ok(
                CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
                    encoded_extension_values_response_leaf(Some(
                        self.state.fresh_source_row(source_row)?,
                    ))?,
                ))
            }
        }
    }

    fn fresh_response_leaf(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        if leaf_ordinal >= self.fresh_response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let boundaries = self.fresh_component_boundaries()?;
        let source_end = boundaries[0];
        if leaf_ordinal < source_end {
            return encoded_extension_values_response_leaf(Some(
                self.state
                    .fresh_source_row(usize::try_from(leaf_ordinal).map_err(|_| {
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                    })?)?,
            ));
        }
        let mut component_start = source_end;
        for group_ordinal in 0..self.state.fresh_mask_group_count() {
            let component_end = boundaries[group_ordinal + 1];
            if leaf_ordinal < component_end {
                return encoded_extension_response_leaf(
                    self.state
                        .fresh_mask_oracle(group_ordinal)
                        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                    leaf_ordinal - component_start,
                );
            }
            component_start = component_end;
        }
        let claim_end = *boundaries
            .last()
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if leaf_ordinal < claim_end {
            return encoded_extension_values_response_leaf(Some(core::slice::from_ref(
                &self.state.fresh_claim(),
            )));
        }
        Ok(CompactOwnedResponseLeaf::padding())
    }

    fn blinded_response_leaf(
        &self,
        leaf_ordinal: u64,
    ) -> Result<CompactOwnedResponseLeaf, CompactPublicKeyMainEpochPreparationError> {
        if leaf_ordinal >= self.blinded_response_leaf_count {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let values = self.state.blinded_response_values()?;
        match usize::try_from(leaf_ordinal)
            .ok()
            .and_then(|leaf_index| values.get(leaf_index))
        {
            Some(value) => {
                encoded_extension_values_response_leaf(Some(core::slice::from_ref(value)))
            }
            None => Ok(CompactOwnedResponseLeaf::padding()),
        }
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

enum CompactPublicKeyCodeSwitchQueryEvaluationPoll {
    StepCompleted { processed_work_unit_count: u64 },
    Complete,
}

impl CompactPublicKeyGenerationState {
    pub(crate) fn new(sources: PreparedCompactPublicKeyAssignmentSources) -> Self {
        Self {
            family_materialization_state: CompactPublicKeyFamilyMaterializationState::new(sources),
            response_generation_state: None,
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

    #[cfg(test)]
    pub(crate) fn inject_first_shifted_eta_two_product_equation_fault(
        &mut self,
    ) -> Result<InjectedCompactPublicKeyWitnessEquationFault, CommonProofProverError> {
        self.family_materialization_state
            .inject_first_shifted_eta_two_product_equation_fault()
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
                    .encode_pre_challenge_source(private_coins)
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

    #[cfg(test)]
    fn inject_first_shifted_eta_two_product_equation_fault(
        &mut self,
    ) -> Result<InjectedCompactPublicKeyWitnessEquationFault, CommonProofProverError> {
        let CompactPublicKeyFamilyMaterializationPhase::AwaitingPreChallengeEncoding(prepared) =
            &mut self.phase
        else {
            return Err(CommonProofProverError::InvalidInput);
        };
        prepared
            .base_assignment
            .inject_first_shifted_eta_two_product_equation_fault(&prepared.relation)
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
        let result = prepare_pre_challenge_material(&prepared, private_coins);
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
    pub(crate) fn prepare_test_only_initial_cfw_sumcheck_inconsistency_transcript(
        &mut self,
    ) -> Result<(), CompactCfwError> {
        self.post_lookup_material
            .as_mut()
            .and_then(|material| material.cfw_external_prover.as_mut())
            .ok_or(CompactCfwError::WrongProverPhase)?
            .prepare_test_only_initial_sumcheck_inconsistency_transcript()
    }

    #[cfg(test)]
    pub(crate) fn test_only_initial_cfw_sumcheck_inconsistency_accepted(&self) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| material.cfw_external_prover.as_ref())
            .is_some_and(|prover| prover.test_only_initial_sumcheck_inconsistency_accepted())
    }

    #[cfg(test)]
    pub(crate) fn test_only_cfw_masking_inconsistency_round_ordinals(&self) -> Option<&[u32]> {
        Some(
            &self
                .post_lookup_material
                .as_ref()?
                .test_only_cfw_masking_inconsistency_round_ordinals,
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
    pub(crate) fn main_whir_sumcheck_complete(&self, batch_ordinal: u8) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| {
                material
                    .main_whir_sumcheck_batches
                    .get(usize::from(batch_ordinal))
            })
            .is_some_and(|batch| batch.batch_ordinal == batch_ordinal && batch.state.is_complete())
    }

    #[cfg(test)]
    pub(crate) fn main_whir_sumcheck_output_count(&self, batch_ordinal: u8) -> Option<usize> {
        Some(
            self.post_lookup_material
                .as_ref()?
                .main_whir_sumcheck_batches
                .get(usize::from(batch_ordinal))?
                .masking_outputs
                .len(),
        )
    }

    #[cfg(test)]
    pub(crate) fn main_whir_residual_length(&self, batch_ordinal: u8) -> Option<usize> {
        self.post_lookup_material
            .as_ref()?
            .main_whir_sumcheck_batches
            .get(usize::from(batch_ordinal))?
            .state
            .residual_source()
            .ok()
            .map(<[CompactChallengeField]>::len)
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_code_switch_ready(&self, round_ordinal: u8) -> bool {
        self.whir_code_switch_ready(CompactPublicKeyWhirEpoch::PreChallenge, round_ordinal)
    }

    #[cfg(test)]
    pub(crate) fn main_whir_code_switch_ready(&self, round_ordinal: u8) -> bool {
        self.whir_code_switch_ready(CompactPublicKeyWhirEpoch::Main, round_ordinal)
    }

    #[cfg(test)]
    fn whir_code_switch_ready(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        round_ordinal: u8,
    ) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| {
                material
                    .whir_code_switches(epoch_owner)
                    .get(usize::from(round_ordinal))
            })
            .is_some_and(|code_switch| {
                code_switch.round_ordinal == round_ordinal
                    && code_switch.state.switch_mask_oracle().is_ok()
            })
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_code_switch_bound(&self, round_ordinal: u8) -> bool {
        self.whir_code_switch_bound(CompactPublicKeyWhirEpoch::PreChallenge, round_ordinal)
    }

    #[cfg(test)]
    pub(crate) fn main_whir_code_switch_bound(&self, round_ordinal: u8) -> bool {
        self.whir_code_switch_bound(CompactPublicKeyWhirEpoch::Main, round_ordinal)
    }

    #[cfg(test)]
    fn whir_code_switch_bound(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        round_ordinal: u8,
    ) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| {
                material
                    .whir_code_switches(epoch_owner)
                    .get(usize::from(round_ordinal))
            })
            .is_some_and(|code_switch| {
                code_switch.round_ordinal == round_ordinal
                    && code_switch.state.verifier_move_is_bound()
            })
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_source_query_masking_verified(
        &self,
        source_ordinal: u8,
    ) -> bool {
        self.whir_source_query_masking_verified(
            CompactPublicKeyWhirEpoch::PreChallenge,
            source_ordinal,
        )
    }

    #[cfg(test)]
    pub(crate) fn main_whir_source_query_masking_verified(&self, source_ordinal: u8) -> bool {
        self.whir_source_query_masking_verified(CompactPublicKeyWhirEpoch::Main, source_ordinal)
    }

    #[cfg(test)]
    pub(crate) fn main_source_query_replay_released(&self) -> bool {
        self.post_lookup_material.as_ref().is_some_and(|material| {
            material.main_source_oracle.opening_replay_complete()
                && material.main_source_oracle.encoding_randomness().is_empty()
                && material
                    .main_source_queries
                    .as_ref()
                    .is_some_and(CompactPublicKeyRetainedSourceQueries::is_complete)
        })
    }

    #[cfg(test)]
    pub(crate) fn main_source_retained_query_count(&self) -> Option<usize> {
        Some(
            self.post_lookup_material
                .as_ref()?
                .main_source_queries
                .as_ref()?
                .positions()
                .len(),
        )
    }

    #[cfg(test)]
    fn whir_source_query_masking_verified(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        source_ordinal: u8,
    ) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| {
                material
                    .whir_code_switches(epoch_owner)
                    .get(usize::from(source_ordinal))
            })
            .is_some_and(|code_switch| {
                code_switch.round_ordinal == source_ordinal
                    && code_switch.source_query_masking_verified
            })
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_base_fresh_claim_masking_verified(&self) -> bool {
        self.whir_base_fresh_claim_masking_verified(CompactPublicKeyWhirEpoch::PreChallenge)
    }

    #[cfg(test)]
    pub(crate) fn main_whir_base_fresh_claim_masking_verified(&self) -> bool {
        self.whir_base_fresh_claim_masking_verified(CompactPublicKeyWhirEpoch::Main)
    }

    #[cfg(test)]
    fn whir_base_fresh_claim_masking_verified(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
    ) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| material.whir_base_case(epoch_owner))
            .is_some_and(|base_case| base_case.fresh_claim_masking_verified)
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_base_blinded_response_ready(&self) -> bool {
        self.whir_base_blinded_response_ready(CompactPublicKeyWhirEpoch::PreChallenge)
    }

    #[cfg(test)]
    pub(crate) fn main_whir_base_blinded_response_ready(&self) -> bool {
        self.whir_base_blinded_response_ready(CompactPublicKeyWhirEpoch::Main)
    }

    #[cfg(test)]
    fn whir_base_blinded_response_ready(&self, epoch_owner: CompactPublicKeyWhirEpoch) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| material.whir_base_case(epoch_owner))
            .is_some_and(|base_case| base_case.state.blinded_response_values().is_ok())
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_base_blinded_response_masking_verified(&self) -> bool {
        self.whir_base_blinded_response_masking_verified(CompactPublicKeyWhirEpoch::PreChallenge)
    }

    #[cfg(test)]
    pub(crate) fn main_whir_base_blinded_response_masking_verified(&self) -> bool {
        self.whir_base_blinded_response_masking_verified(CompactPublicKeyWhirEpoch::Main)
    }

    #[cfg(test)]
    fn whir_base_blinded_response_masking_verified(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
    ) -> bool {
        self.post_lookup_material
            .as_ref()
            .and_then(|material| material.whir_base_case(epoch_owner))
            .is_some_and(|base_case| base_case.verified_blinded_response_masking.is_some())
    }

    #[cfg(test)]
    pub(crate) fn pre_challenge_whir_base_final_query_masking_verified(&self) -> bool {
        self.whir_base_final_query_masking_verified(CompactPublicKeyWhirEpoch::PreChallenge)
    }

    #[cfg(test)]
    pub(crate) fn main_whir_base_final_query_masking_verified(&self) -> bool {
        self.whir_base_final_query_masking_verified(CompactPublicKeyWhirEpoch::Main)
    }

    #[cfg(test)]
    fn whir_base_final_query_masking_verified(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
    ) -> bool {
        self.post_lookup_material
            .as_ref()
            .is_some_and(|material| match epoch_owner {
                CompactPublicKeyWhirEpoch::PreChallenge => material
                    .verified_pre_challenge_whir_base_masking_prefix
                    .is_some(),
                CompactPublicKeyWhirEpoch::Main => material
                    .main_whir_base_case
                    .as_ref()
                    .is_some_and(|base_case| base_case.verified_final_query_masking.is_some()),
            })
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
                let masking_verification = material.verify_cfw_round_masking(
                    response_generation_state.verifier_messages(),
                    &round_polynomial,
                );
                #[cfg(test)]
                if let Err(error) = masking_verification {
                    let round_ordinal = u32::try_from(round_index).map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?;
                    let masking_round_is_new = material
                        .test_only_cfw_masking_inconsistency_round_ordinals
                        .last()
                        .is_none_or(|last_round_ordinal| *last_round_ordinal < round_ordinal);
                    let test_only_dishonest_polynomial = masking_round_is_new
                        && material.cfw_external_prover.as_ref().is_some_and(|prover| {
                            prover.test_only_initial_sumcheck_inconsistency_accepted()
                        })
                        && matches!(
                            &error,
                            CompactPublicKeyMainEpochPreparationError::CfwRoundMasking {
                                round_ordinal: error_round_ordinal,
                                error: CompactMaskingEntropyError::InvalidCoefficientMap,
                            } if *error_round_ordinal == round_ordinal
                        );
                    if test_only_dishonest_polynomial {
                        material
                            .test_only_cfw_masking_inconsistency_round_ordinals
                            .push(round_ordinal);
                    } else {
                        return Err(CompactPublicKeyMainEpochPollError::Preparation(error));
                    }
                }
                #[cfg(not(test))]
                masking_verification.map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
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
            let initial_sumcheck = {
                let mut random_source = family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .whir_random_adapter();
                CompactWhirInitialSumcheckState::new(
                    relation,
                    &configuration,
                    0,
                    mask_group,
                    &mut random_source,
                )
            }
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
                None,
                CompactWhirSumcheckBatchCoordinate::new(pre_challenge_epoch.epoch, 0),
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

        poll_compact_public_key_whir_sumcheck(
            family_material,
            response_generation_state,
            material,
            CompactPublicKeyWhirEpoch::PreChallenge,
            maximum_work_unit_count,
            response_storage,
        )
    }

    pub(crate) fn prepare_pre_challenge_whir_code_switch(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        self.prepare_whir_code_switch(CompactPublicKeyWhirEpoch::PreChallenge)
    }

    pub(crate) fn prepare_main_whir_code_switch(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        self.prepare_whir_code_switch(CompactPublicKeyWhirEpoch::Main)
    }

    fn prepare_whir_code_switch(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let round_index = material.whir_code_switches(epoch_owner).len();
        let round_ordinal = u8::try_from(round_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let preceding_sumcheck_batch = material
            .whir_sumcheck_batches(epoch_owner)
            .get(round_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if material.whir_sumcheck_batches(epoch_owner).len() != round_index + 1
            || preceding_sumcheck_batch.batch_ordinal != round_ordinal
            || preceding_sumcheck_batch.bound_round_advance_required
            || preceding_sumcheck_batch.round_masking_verified
            || !preceding_sumcheck_batch.combination_challenge_bound
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        material.validate_whir_sumcheck_completion_for_epoch(
            epoch_owner,
            response_generation_state.verifier_messages(),
            round_index,
        )?;
        let response_ordinal =
            material.whir_code_switch_response_ordinal(epoch_owner, round_ordinal)?;
        if response_generation_state.verifier_messages().len()
            != usize::try_from(response_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            || response_generation_state.checkpoint_boundary().is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }

        let contract = selected_compact_public_key_proof_contract()?;
        let epoch = epoch_owner.contract(&contract.verifier_inputs())?;
        let previous_source_contract =
            unique_whir_fold_contract(&contract.verifier_inputs(), epoch.epoch, round_ordinal)?;
        let next_batch_ordinal = round_ordinal
            .checked_add(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let next_source_contract = unique_whir_fold_contract(
            &contract.verifier_inputs(),
            epoch.epoch,
            next_batch_ordinal,
        )?;
        let switch_mask_contract = unique_internal_mask_group(epoch, 5, round_ordinal)?;
        let (source_evaluations, folding_challenges) = {
            let preceding_sumcheck = &mut material
                .whir_sumcheck_batches_mut(epoch_owner)
                .get_mut(round_index)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            let folding_challenges = preceding_sumcheck.state.round_challenges().to_vec();
            let source_evaluations = preceding_sumcheck.state.take_residual_source()?;
            (source_evaluations, folding_challenges)
        };
        let code_switch_state = if round_ordinal == 0 {
            match epoch_owner {
                CompactPublicKeyWhirEpoch::PreChallenge => {
                    let previous_encoding_randomness = family_material
                        .metadata
                        .pre_challenge
                        .encoded_oracle
                        .take_encoding_randomness()?;
                    let mut random_source = family_material
                        .metadata
                        .pre_challenge
                        .randomness
                        .whir_random_adapter();
                    CompactWhirCodeSwitchState::new_from_base_source(
                        source_evaluations,
                        previous_encoding_randomness,
                        &folding_challenges,
                        previous_source_contract,
                        next_source_contract,
                        switch_mask_contract,
                        &mut random_source,
                    )?
                }
                CompactPublicKeyWhirEpoch::Main => {
                    if material.main_source_queries.is_some()
                        || !material.main_source_oracle.can_begin_opening_replay()
                    {
                        return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
                    }
                    let previous_encoding_randomness =
                        material.main_source_oracle.encoding_randomness().to_vec();
                    let mut random_source = family_material
                        .metadata
                        .pre_challenge
                        .randomness
                        .whir_random_adapter();
                    CompactWhirCodeSwitchState::new_from_extension_source(
                        source_evaluations,
                        previous_encoding_randomness,
                        &folding_challenges,
                        previous_source_contract,
                        next_source_contract,
                        switch_mask_contract,
                        &mut random_source,
                    )?
                }
            }
        } else {
            let previous_code_switch = material
                .whir_code_switches(epoch_owner)
                .get(round_index - 1)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            if previous_code_switch.round_ordinal != round_ordinal - 1
                || !previous_code_switch.source_query_masking_verified
            {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            let previous_randomness = previous_code_switch.state.source_encoding_randomness();
            let mut copied_previous_randomness = Vec::new();
            copied_previous_randomness
                .try_reserve_exact(previous_randomness.len())
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
            copied_previous_randomness.extend_from_slice(previous_randomness);
            let mut random_source = family_material
                .metadata
                .pre_challenge
                .randomness
                .whir_random_adapter();
            CompactWhirCodeSwitchState::new_from_extension_source(
                source_evaluations,
                copied_previous_randomness,
                &folding_challenges,
                previous_source_contract,
                next_source_contract,
                switch_mask_contract,
                &mut random_source,
            )?
        };
        family_material
            .metadata
            .pre_challenge
            .randomness
            .ensure_field_sampling_valid()?;
        material
            .whir_code_switches_mut(epoch_owner)
            .push(CompactPublicKeyWhirCodeSwitch::new(
                round_ordinal,
                response_ordinal,
                code_switch_state,
            ));
        Ok(())
    }

    pub(crate) fn poll_pre_challenge_whir_code_switch<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        self.poll_whir_code_switch(
            CompactPublicKeyWhirEpoch::PreChallenge,
            maximum_work_unit_count,
            response_storage,
        )
    }

    pub(crate) fn poll_main_whir_code_switch<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        self.poll_whir_code_switch(
            CompactPublicKeyWhirEpoch::Main,
            maximum_work_unit_count,
            response_storage,
        )
    }

    fn poll_whir_code_switch<Storage: ProofExternalMemory>(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
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
        let code_switch_index = material
            .whir_code_switches(epoch_owner)
            .len()
            .checked_sub(1)
            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ))?;
        let round_ordinal = u8::try_from(code_switch_index).map_err(|_| {
            CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
            )
        })?;
        let response_ordinal = material
            .whir_code_switches(epoch_owner)
            .get(code_switch_index)
            .filter(|code_switch| code_switch.round_ordinal == round_ordinal)
            .map(|code_switch| code_switch.response_ordinal)
            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ))?;

        if material.whir_code_switches(epoch_owner)[code_switch_index].response_leaf_count == 0 {
            let code_switch = material
                .whir_code_switches_mut(epoch_owner)
                .get_mut(code_switch_index)
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?;
            match code_switch
                .state
                .poll_preparation(maximum_work_unit_count)
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
            {
                CompactWhirCodeSwitchPreparationPoll::RandomnessFoldStepCompleted {
                    processed_work_unit_count,
                    fold_complete,
                } => {
                    return Ok(epoch_owner.code_switch_randomness_poll(
                        round_ordinal,
                        processed_work_unit_count,
                        fold_complete,
                    ));
                }
                CompactWhirCodeSwitchPreparationPoll::Complete => {}
            }
            let contract = selected_compact_public_key_proof_contract()
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let epoch = epoch_owner
                .contract(&contract.verifier_inputs())
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
            validate_whir_code_switch_response_geometry(
                response_geometry,
                response_roles,
                epoch.epoch,
                u32::from(round_ordinal),
                code_switch.state.source_oracle(),
                code_switch
                    .state
                    .switch_mask_oracle()
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?,
            )
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            code_switch.response_leaf_count = response_geometry.merkle_leaf_count();
            return Ok(epoch_owner.code_switch_prepared_poll(round_ordinal));
        }

        if (epoch_owner == CompactPublicKeyWhirEpoch::Main || round_ordinal > 0)
            && response_generation_state.verifier_messages().len()
                == usize::try_from(response_ordinal)
                    .map_err(|_| {
                        CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                        )
                    })?
                    .checked_add(1)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::InvalidGeometry,
                    ))?
        {
            match material
                .poll_code_switch_source_query_evaluation(
                    epoch_owner,
                    round_ordinal,
                    maximum_work_unit_count,
                    &family_material.row_source,
                    response_generation_state.verifier_messages(),
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
            {
                CompactPublicKeyCodeSwitchQueryEvaluationPoll::StepCompleted {
                    processed_work_unit_count,
                } => {
                    return Ok(epoch_owner
                        .code_switch_source_poll(round_ordinal, processed_work_unit_count));
                }
                CompactPublicKeyCodeSwitchQueryEvaluationPoll::Complete => {}
            }
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
                    .poll_code_switch_response_leaf(
                        epoch_owner,
                        round_ordinal,
                        leaf_ordinal,
                        maximum_work_unit_count,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                {
                    CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    } => Ok(epoch_owner
                        .code_switch_source_poll(round_ordinal, processed_work_unit_count)),
                    CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(leaf) => {
                        let response_leaf_count = material
                            .whir_code_switches(epoch_owner)
                            .get(code_switch_index)
                            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                                CompactPublicKeyMainEpochPreparationError::WrongPhase,
                            ))?
                            .response_leaf_count;
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
                            .mark_code_switch_response_leaf_supplied(
                                epoch_owner,
                                round_ordinal,
                                leaf_ordinal,
                            )
                            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                        Ok(CompactPublicKeyMainEpochPoll::ResponseLeafSupplied { leaf_ordinal })
                    }
                }
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
                material
                    .bind_code_switch_verifier_move(
                        epoch_owner,
                        family_material,
                        response_generation_state.verifier_messages(),
                        round_ordinal,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let _authority = response_generation_state
                    .verifier_message_authority(response_ordinal)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ))?;
                if !material
                    .whir_code_switches(epoch_owner)
                    .get(code_switch_index)
                    .is_some_and(|code_switch| {
                        code_switch.source_query_masking_verified
                            && code_switch.state.verifier_move_is_bound()
                    })
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
                Ok(epoch_owner.code_switch_checkpoint_poll(round_ordinal))
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

    pub(crate) fn prepare_pre_challenge_whir_next_sumcheck(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        self.prepare_whir_next_sumcheck(CompactPublicKeyWhirEpoch::PreChallenge)
    }

    pub(crate) fn prepare_main_whir_next_sumcheck(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        self.prepare_whir_next_sumcheck(CompactPublicKeyWhirEpoch::Main)
    }

    fn prepare_whir_next_sumcheck(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let Self {
            response_generation_state,
            post_lookup_material,
            ..
        } = self;
        let material = post_lookup_material
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let code_switch_index = material
            .whir_code_switches(epoch_owner)
            .len()
            .checked_sub(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let round_ordinal = u8::try_from(code_switch_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let code_switch = material
            .whir_code_switches(epoch_owner)
            .get(code_switch_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let code_switch_response_ordinal = code_switch.response_ordinal;
        if code_switch.round_ordinal != round_ordinal
            || code_switch.relation_preparation.is_some()
            || material.whir_sumcheck_batches(epoch_owner).len() != code_switch_index + 1
            || !code_switch.source_query_masking_verified
            || !code_switch.state.verifier_move_is_bound()
            || response_generation_state.verifier_messages().len()
                != usize::try_from(code_switch_response_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
                    .checked_add(1)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
            || response_generation_state.checkpoint_boundary().is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let preceding_sumcheck = &mut material
            .whir_sumcheck_batches_mut(epoch_owner)
            .get_mut(code_switch_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let source_claim = preceding_sumcheck.state.residual_source_claim()?;
        let preceding_mask_claim = preceding_sumcheck.state.residual_mask_claim()?;
        let target = preceding_sumcheck.state.residual_target()?;
        let source_covector = preceding_sumcheck.state.take_residual_covector()?;
        let code_switch_inputs = material
            .whir_code_switches_mut(epoch_owner)
            .get_mut(code_switch_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .state
            .take_relation_inputs()?;
        material.whir_code_switches_mut(epoch_owner)[code_switch_index].relation_preparation =
            Some(CompactWhirCodeSwitchRelationPreparation::new(
                code_switch_inputs,
                source_covector,
                source_claim,
                preceding_mask_claim,
                target,
            )?);
        Ok(())
    }

    pub(crate) fn poll_pre_challenge_whir_next_sumcheck_preparation(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPreparationError> {
        self.poll_whir_next_sumcheck_preparation(
            CompactPublicKeyWhirEpoch::PreChallenge,
            maximum_work_unit_count,
        )
    }

    pub(crate) fn poll_main_whir_next_sumcheck_preparation(
        &mut self,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPreparationError> {
        self.poll_whir_next_sumcheck_preparation(
            CompactPublicKeyWhirEpoch::Main,
            maximum_work_unit_count,
        )
    }

    fn poll_whir_next_sumcheck_preparation(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
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
        let code_switch_index = material
            .whir_code_switches(epoch_owner)
            .len()
            .checked_sub(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let round_ordinal = u8::try_from(code_switch_index)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let next_batch_ordinal = round_ordinal
            .checked_add(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if material.whir_sumcheck_batches(epoch_owner).len() != code_switch_index + 1 {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let relation_preparation = material
            .whir_code_switches_mut(epoch_owner)
            .get_mut(code_switch_index)
            .filter(|code_switch| code_switch.round_ordinal == round_ordinal)
            .and_then(|code_switch| code_switch.relation_preparation.as_mut())
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        match relation_preparation.poll(maximum_work_unit_count)? {
            CompactWhirCodeSwitchRelationPreparationPoll::QueryRelationStepCompleted {
                processed_work_unit_count,
                relation_complete,
            } => Ok(epoch_owner.code_switch_relation_poll(
                round_ordinal,
                processed_work_unit_count,
                relation_complete,
            )),
            CompactWhirCodeSwitchRelationPreparationPoll::Complete => {
                let relation = material
                    .whir_code_switches_mut(epoch_owner)
                    .get_mut(code_switch_index)
                    .and_then(|code_switch| code_switch.relation_preparation.take())
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                    .finish()?;
                let contract = selected_compact_public_key_proof_contract()?;
                let epoch = epoch_owner.contract(&contract.verifier_inputs())?;
                let configuration = compact_whir_configuration_from_contract(epoch)?;
                let mask_group = unique_internal_mask_group(epoch, 4, next_batch_ordinal)?;
                let sumcheck = {
                    let mut random_source = family_material
                        .metadata
                        .pre_challenge
                        .randomness
                        .whir_random_adapter();
                    CompactWhirInitialSumcheckState::new(
                        relation,
                        &configuration,
                        usize::from(next_batch_ordinal),
                        mask_group,
                        &mut random_source,
                    )
                }?;
                family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .ensure_field_sampling_valid()?;
                let response_ordinal = material
                    .whir_sumcheck_initial_response_ordinal(epoch_owner, next_batch_ordinal)?;
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
                    epoch.epoch,
                    next_batch_ordinal,
                    sumcheck.mask_oracle(),
                )?;
                verify_selected_compact_whir_sumcheck_auxiliary_masking(
                    contract.verifier_inputs(),
                    &material.masking_coefficient_maps,
                    material
                        .masking_attempt_identity
                        .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
                    response_generation_state.verifier_messages(),
                    material.verified_base_masking_prefix(epoch_owner)?,
                    CompactWhirSumcheckBatchCoordinate::new(epoch.epoch, next_batch_ordinal),
                    sumcheck.auxiliary_target(),
                )
                .map_err(CompactPublicKeyMainEpochPreparationError::WhirSumcheckAuxiliaryMasking)?;
                material.whir_sumcheck_batches_mut(epoch_owner).push(
                    CompactPublicKeyWhirSumcheckBatch::new(
                        next_batch_ordinal,
                        response_ordinal,
                        sumcheck,
                        response_geometry.merkle_leaf_count(),
                    )?,
                );
                Ok(epoch_owner.sumcheck_prepared_poll(next_batch_ordinal))
            }
        }
    }

    pub(crate) fn prepare_pre_challenge_whir_base_case(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        self.prepare_whir_base_case(CompactPublicKeyWhirEpoch::PreChallenge)
    }

    pub(crate) fn prepare_main_whir_base_case(
        &mut self,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        self.prepare_whir_base_case(CompactPublicKeyWhirEpoch::Main)
    }

    fn prepare_whir_base_case(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let Self {
            family_material,
            response_generation_state,
            post_lookup_material,
        } = self;
        let material = post_lookup_material
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let contract = selected_compact_public_key_proof_contract()?;
        let epoch = epoch_owner.contract(&contract.verifier_inputs())?;
        let batch_count = epoch.folding_schedule.len();
        let code_switch_count = batch_count
            .checked_sub(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let final_batch_ordinal = u8::try_from(code_switch_count)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if material.whir_base_case(epoch_owner).is_some()
            || material.whir_base_covector_derivation.is_some()
            || material.whir_sumcheck_batches(epoch_owner).len() != batch_count
            || material.whir_code_switches(epoch_owner).len() != code_switch_count
            || !material
                .whir_sumcheck_batches(epoch_owner)
                .last()
                .is_some_and(|batch| {
                    batch.batch_ordinal == final_batch_ordinal && batch.state.is_complete()
                })
            || response_generation_state.checkpoint_boundary().is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let fresh_response_ordinal = unique_response_ordinal_for_component_role(
            &contract.verifier_inputs(),
            18,
            epoch.epoch,
            0,
            0,
        )?;
        let blinded_response_ordinal = unique_response_ordinal_for_component_role(
            &contract.verifier_inputs(),
            19,
            epoch.epoch,
            0,
            0,
        )?;
        if fresh_response_ordinal.checked_add(1) != Some(blinded_response_ordinal)
            || response_generation_state.verifier_messages().len()
                != usize::try_from(fresh_response_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }

        let public_covector_authority =
            CompactFactorOnePublicCovectorAuthority::from_canonical_public_input(
                contract.verifier_inputs(),
                family_material.public_input_bindings(),
                family_material.canonical_public_input_bytes(),
                family_material.decoded_public_input(),
            )?;
        let masking_attempt_identity = material
            .masking_attempt_identity
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        material.whir_base_covector_derivation = Some(CompactPublicKeyWhirBaseCovectorDerivation {
            epoch_owner,
            derivation: Some(
                begin_selected_compact_whir_base_covector_derivation(
                    &contract.verifier_inputs(),
                    masking_attempt_identity,
                    &public_covector_authority,
                    response_generation_state.canonical_proof_prefix_bytes(),
                    response_generation_state.verifier_messages(),
                    epoch.epoch,
                )
                .map_err(CompactPublicKeyMainEpochPreparationError::WhirBaseFreshMasking)?,
            ),
            authorization: None,
        });
        Ok(())
    }

    fn finish_whir_base_case_preparation(
        family_material: &mut CompactPublicKeyFamilyMaterial,
        response_generation_state: &CompactResponseGenerationState,
        material: &mut CompactPublicKeyPostLookupMaterial,
        contract: &CompactPublicKeyProofContract,
        epoch_owner: CompactPublicKeyWhirEpoch,
        verified_covector: CompactVerifiedWhirBaseCovector,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let epoch = epoch_owner.contract(&contract.verifier_inputs())?;
        let final_batch_ordinal = u8::try_from(
            epoch
                .folding_schedule
                .len()
                .checked_sub(1)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let fresh_response_ordinal = unique_response_ordinal_for_component_role(
            &contract.verifier_inputs(),
            18,
            epoch.epoch,
            0,
            0,
        )?;
        let blinded_response_ordinal = unique_response_ordinal_for_component_role(
            &contract.verifier_inputs(),
            19,
            epoch.epoch,
            0,
            0,
        )?;
        if fresh_response_ordinal.checked_add(1) != Some(blinded_response_ordinal)
            || response_generation_state.verifier_messages().len()
                != usize::try_from(fresh_response_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let (source_covector, mask_covectors) = verified_covector.into_parts();
        let mask_inputs = whir_base_mask_inputs(material, epoch_owner, epoch, mask_covectors)?;
        let final_batch = material
            .whir_sumcheck_batches(epoch_owner)
            .last()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if final_batch.state.residual_covector()? != source_covector.as_slice() {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let source_message = final_batch.state.residual_source()?.to_vec();
        let target = final_batch.state.residual_target()?;
        let final_folding_challenges = final_batch.state.round_challenges().to_vec();
        let final_source_randomness = material
            .whir_code_switches(epoch_owner)
            .last()
            .filter(|code_switch| {
                code_switch.round_ordinal.checked_add(1) == Some(final_batch_ordinal)
            })
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .state
            .source_encoding_randomness()
            .to_vec();
        let final_fold_contract = unique_whir_fold_contract(
            &contract.verifier_inputs(),
            epoch.epoch,
            final_batch_ordinal,
        )?;
        let state = {
            let mut random_source = family_material
                .metadata
                .pre_challenge
                .randomness
                .whir_random_adapter();
            CompactWhirBaseCaseState::new(
                CompactWhirBaseRelation::new(source_message, source_covector, target),
                &final_source_randomness,
                final_fold_contract,
                &final_folding_challenges,
                mask_inputs,
                &mut random_source,
            )
        }?;
        family_material
            .metadata
            .pre_challenge
            .randomness
            .ensure_field_sampling_valid()?;
        let fresh_response_index = usize::try_from(fresh_response_ordinal)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let blinded_response_index = usize::try_from(blinded_response_ordinal)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let fresh_response_geometry = family_material
            .response_merkle_geometries()
            .get(fresh_response_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let blinded_response_geometry = family_material
            .response_merkle_geometries()
            .get(blinded_response_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        validate_whir_base_response_geometry(
            fresh_response_geometry,
            contract
                .verifier_inputs()
                .response_component_roles
                .get(fresh_response_index)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            blinded_response_geometry,
            contract
                .verifier_inputs()
                .response_component_roles
                .get(blinded_response_index)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            epoch,
            final_fold_contract,
            &state,
        )?;
        material.set_whir_base_case(
            epoch_owner,
            CompactPublicKeyWhirBaseCase {
                fresh_response_ordinal,
                blinded_response_ordinal,
                state,
                fresh_response_leaf_count: fresh_response_geometry.merkle_leaf_count(),
                blinded_response_leaf_count: blinded_response_geometry.merkle_leaf_count(),
                fresh_claim_masking_verified: true,
                verified_blinded_response_masking: None,
                final_query_leaves: Vec::new(),
                verified_final_query_masking: None,
            },
        )?;
        Ok(())
    }

    pub(crate) fn poll_pre_challenge_whir_base_fresh_response<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        self.poll_whir_base_fresh_response(
            CompactPublicKeyWhirEpoch::PreChallenge,
            maximum_work_unit_count,
            response_storage,
        )
    }

    pub(crate) fn poll_main_whir_base_fresh_response<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        self.poll_whir_base_fresh_response(
            CompactPublicKeyWhirEpoch::Main,
            maximum_work_unit_count,
            response_storage,
        )
    }

    fn poll_whir_base_fresh_response<Storage: ProofExternalMemory>(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
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
        if let Some(active_derivation) = material.whir_base_covector_derivation.as_mut() {
            if active_derivation.epoch_owner != epoch_owner {
                return Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ));
            }
            if active_derivation.authorization.is_none() {
                let covector_poll = active_derivation
                    .derivation
                    .as_mut()
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ))?
                    .advance(maximum_work_unit_count)
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let completed_work_unit_count = match covector_poll {
                    CompactFactorOnePublicCovectorPoll::WorkCompleted {
                        completed_work_unit_count,
                    } => completed_work_unit_count,
                    CompactFactorOnePublicCovectorPoll::Complete {
                        completed_work_unit_count,
                        authorization,
                    } => {
                        active_derivation.derivation = None;
                        active_derivation.authorization = Some(authorization);
                        completed_work_unit_count
                    }
                };
                return Ok(epoch_owner.base_covector_step_poll(completed_work_unit_count));
            }
            let authorization = active_derivation.authorization.take().ok_or(
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ),
            )?;
            material.whir_base_covector_derivation = None;
            let contract = selected_compact_public_key_proof_contract()
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let epoch = epoch_owner
                .contract(&contract.verifier_inputs())
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let public_covector_authority =
                CompactFactorOnePublicCovectorAuthority::from_canonical_public_input(
                    contract.verifier_inputs(),
                    family_material.public_input_bindings(),
                    family_material.canonical_public_input_bytes(),
                    family_material.decoded_public_input(),
                )
                .map_err(CompactPublicKeyMainEpochPreparationError::from)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let verified_covector = finish_selected_compact_whir_base_covector_derivation(
                contract.verifier_inputs(),
                &material.masking_coefficient_maps,
                material.masking_attempt_identity.ok_or(
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ),
                )?,
                &public_covector_authority,
                response_generation_state.canonical_proof_prefix_bytes(),
                response_generation_state.verifier_messages(),
                material
                    .verified_base_masking_prefix(epoch_owner)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?,
                epoch.epoch,
                authorization,
            )
            .map_err(CompactPublicKeyMainEpochPreparationError::WhirBaseFreshMasking)
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            Self::finish_whir_base_case_preparation(
                family_material,
                response_generation_state,
                material,
                &contract,
                epoch_owner,
                verified_covector,
            )
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            return Ok(epoch_owner.base_covectors_prepared_poll());
        }
        let base_case = material.whir_base_case_mut(epoch_owner).ok_or(
            CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ),
        )?;
        let response_ordinal = base_case.fresh_response_ordinal;
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
                Ok(epoch_owner.base_prepared_poll())
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal: required_response_ordinal,
                leaf_ordinal,
            } if required_response_ordinal == response_ordinal => {
                let leaf = match base_case
                    .poll_fresh_response_leaf(leaf_ordinal, maximum_work_unit_count)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                {
                    CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    } => {
                        return Ok(epoch_owner.base_fresh_source_poll(processed_work_unit_count));
                    }
                    CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(leaf) => leaf,
                };
                let leaf_salt = family_material
                    .pre_challenge_material()
                    .randomness
                    .private_leaf_salt(
                        response_ordinal,
                        base_case.fresh_response_leaf_count,
                        leaf_ordinal,
                        &leaf,
                    );
                response_generation_state
                    .supply_next_response_leaf(&leaf, &leaf_salt)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                base_case
                    .mark_fresh_response_leaf_supplied(leaf_ordinal)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
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
                if !base_case.fresh_claim_masking_verified
                    || base_case.verified_blinded_response_masking.is_some()
                {
                    return Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ));
                }
                let contract = selected_compact_public_key_proof_contract()
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let epoch = epoch_owner
                    .contract(&contract.verifier_inputs())
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let combination_challenge = unique_completed_extension_role_challenge(
                    &contract.verifier_inputs(),
                    response_generation_state.verifier_messages(),
                    10,
                    epoch.epoch,
                    0,
                    0,
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                material
                    .bind_whir_base_combination_challenge(
                        epoch_owner,
                        contract.verifier_inputs(),
                        response_generation_state.verifier_messages(),
                        combination_challenge,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let canonical_randomness_cursor = family_material
                    .pre_challenge_material()
                    .randomness
                    .canonical_checkpoint_cursor_bytes();
                response_generation_state
                    .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(epoch_owner.base_fresh_checkpoint_poll())
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

    pub(crate) fn poll_pre_challenge_whir_base_blinded_response<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        self.poll_whir_base_blinded_response(
            CompactPublicKeyWhirEpoch::PreChallenge,
            maximum_work_unit_count,
            response_storage,
        )
    }

    pub(crate) fn poll_main_whir_base_blinded_response<Storage: ProofExternalMemory>(
        &mut self,
        maximum_work_unit_count: u64,
        response_storage: &mut Storage,
    ) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>>
    {
        self.poll_whir_base_blinded_response(
            CompactPublicKeyWhirEpoch::Main,
            maximum_work_unit_count,
            response_storage,
        )
    }

    fn poll_whir_base_blinded_response<Storage: ProofExternalMemory>(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
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
        let (response_ordinal, response_leaf_count) = material
            .whir_base_case(epoch_owner)
            .map(|base_case| {
                (
                    base_case.blinded_response_ordinal,
                    base_case.blinded_response_leaf_count,
                )
            })
            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ))?;
        match response_generation_state
            .poll(response_storage)
            .map_err(CompactPublicKeyMainEpochPollError::ResponsePoll)?
        {
            CompactResponseGenerationPoll::ResponseRequired {
                response_ordinal: required_response_ordinal,
            } if required_response_ordinal == response_ordinal => {
                let base_case = material.whir_base_case(epoch_owner).ok_or(
                    CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ),
                )?;
                if base_case.verified_blinded_response_masking.is_none()
                    || base_case.verified_final_query_masking.is_some()
                    || !base_case.final_query_leaves.is_empty()
                {
                    return Err(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ));
                }
                response_generation_state
                    .begin_response(
                        family_material
                            .pre_challenge_material()
                            .randomness
                            .fiat_shamir_round_salt(response_ordinal),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                Ok(epoch_owner.base_blinded_prepared_poll())
            }
            CompactResponseGenerationPoll::ResponseLeafRequired {
                response_ordinal: required_response_ordinal,
                leaf_ordinal,
            } if required_response_ordinal == response_ordinal => {
                let leaf = material
                    .whir_base_case(epoch_owner)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ))?
                    .blinded_response_leaf(leaf_ordinal)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
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
                let opening_query_leaf_ordinals = response_generation_state
                    .current_opening_query_leaf_ordinals(opened_response_ordinal)
                    .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                        CompactPublicKeyMainEpochPreparationError::WrongPhase,
                    ))?;
                let leaf = match material
                    .poll_whir_base_opened_leaf(
                        epoch_owner,
                        family_material,
                        opened_response_ordinal,
                        leaf_ordinal,
                        maximum_work_unit_count,
                        opening_query_leaf_ordinals,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                {
                    CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                        processed_work_unit_count,
                    } => {
                        return Ok(epoch_owner.base_final_query_poll(processed_work_unit_count));
                    }
                    CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(leaf) => leaf,
                };
                let masking_query_leaf = compact_masking_query_leaf(
                    family_material.response_merkle_geometries(),
                    u32::try_from(
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
                    })?,
                    opened_response_ordinal,
                    leaf_ordinal,
                    &leaf,
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
                material
                    .mark_whir_base_opened_leaf_supplied(
                        epoch_owner,
                        opened_response_ordinal,
                        leaf_ordinal,
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                material
                    .record_whir_base_query_leaf(epoch_owner, masking_query_leaf)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
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
                let contract = selected_compact_public_key_proof_contract()
                    .map_err(CompactPublicKeyMainEpochPreparationError::from)
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                if epoch_owner == CompactPublicKeyWhirEpoch::PreChallenge {
                    material
                        .record_deferred_pre_challenge_whir_base_query_leaves(
                            family_material,
                            &contract.verifier_inputs(),
                            response_generation_state.verifier_messages(),
                        )
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                }
                material
                    .verify_and_finish_whir_base_final_queries(
                        epoch_owner,
                        contract.verifier_inputs(),
                        response_generation_state.verifier_messages(),
                    )
                    .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let canonical_randomness_cursor = family_material
                    .pre_challenge_material()
                    .randomness
                    .canonical_checkpoint_cursor_bytes();
                response_generation_state
                    .supply_checkpoint_private_randomness_cursor(&canonical_randomness_cursor)
                    .map_err(CompactPublicKeyMainEpochPollError::ResponseGeneration)?;
                if epoch_owner == CompactPublicKeyWhirEpoch::PreChallenge {
                    material
                        .retire_pre_challenge_whir_generation_state(
                            contract.verifier_inputs(),
                            response_generation_state.verifier_messages(),
                        )
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                }
                Ok(epoch_owner.base_blinded_checkpoint_poll())
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

    pub(crate) fn prepare_main_whir_initial_sumcheck(
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
        if material
            .verified_pre_challenge_whir_base_masking_prefix
            .is_none()
            || material.pre_challenge_whir_relation_preparation.is_some()
            || !material.pre_challenge_whir_sumcheck_batches.is_empty()
            || !material.pre_challenge_whir_code_switches.is_empty()
            || material.pre_challenge_whir_base_case.is_some()
            || material.main_whir_covector_accumulator.is_some()
            || material.main_whir_covector_continuation.is_some()
            || material.main_whir_relation_preparation.is_some()
            || !material.main_whir_sumcheck_batches.is_empty()
            || response_generation_state.checkpoint_boundary().is_none()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let contract = selected_compact_public_key_proof_contract()?;
        let [_pre_challenge_epoch, main_epoch] = contract.verifier_inputs().whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        let completed_messages = response_generation_state.verifier_messages();
        let response_ordinal = unique_response_ordinal_for_component_role(
            &contract.verifier_inputs(),
            11,
            main_epoch.epoch,
            0,
            0,
        )?;
        if usize::try_from(response_ordinal)
            .ok()
            .is_none_or(|ordinal| ordinal != completed_messages.len())
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let mut cfw_sumcheck_point = Vec::new();
        cfw_sumcheck_point
            .try_reserve_exact(material.cfw_geometry.sumcheck_round_count())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        for round_index in 0..material.cfw_geometry.sumcheck_round_count() {
            cfw_sumcheck_point.push(unique_completed_extension_role_challenge(
                &contract.verifier_inputs(),
                completed_messages,
                4,
                0,
                0,
                u32::try_from(round_index)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )?);
        }
        let joint_challenge = unique_completed_extension_role_challenge(
            &contract.verifier_inputs(),
            completed_messages,
            5,
            0,
            0,
            0,
        )?;
        let opening_batching_challenge = unique_completed_extension_role_challenge(
            &contract.verifier_inputs(),
            completed_messages,
            6,
            main_epoch.epoch,
            0,
            0,
        )?;
        let cross_epoch_point = material
            .cross_epoch_point
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let copied_main_source_element_count = usize::try_from(
            family_material
                .relation()
                .cross_epoch_copy_geometry()
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
                .copied_element_count(),
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let combination =
            CompactCfwPublicMainCovectorCombination::from_public_challenges_before_whir_fold(
                material.cfw_geometry,
                cross_epoch_point,
                copied_main_source_element_count,
                &cfw_sumcheck_point,
                joint_challenge,
                opening_batching_challenge,
            )?;
        let (continuation, destination) = combination.into_parts();
        let transpose_source = CompactStructuredAssignmentTransposeSource::new(Rc::clone(
            family_material.row_source.assignment_source(),
        ));
        let accumulator = CompactStructuredWitnessCovectorAccumulator::from_public_relation(
            transpose_source,
            family_material.relation(),
            continuation.row_point(),
            continuation.matrix_role_weights(),
            destination,
        )?;
        material.main_whir_covector_accumulator = Some(accumulator);
        material.main_whir_covector_continuation = Some(continuation);
        Ok(())
    }

    pub(crate) fn poll_main_whir_initial_sumcheck_preparation(
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
        if material.main_whir_covector_accumulator.is_some() {
            let poll = material
                .main_whir_covector_accumulator
                .as_mut()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                .advance(maximum_work_unit_count)?;
            match poll {
                CompactStructuredWitnessCovectorAccumulatorPoll::StepCompleted {
                    step,
                    completed_work_unit_count,
                } => {
                    return Ok(
                        CompactPublicKeyMainEpochPoll::MainWhirCovectorStepCompleted {
                            step,
                            completed_work_unit_count,
                        },
                    );
                }
                CompactStructuredWitnessCovectorAccumulatorPoll::Complete(source_covector) => {
                    material.main_whir_covector_accumulator = None;
                    let continuation = material
                        .main_whir_covector_continuation
                        .take()
                        .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
                    let input_binding_challenge = continuation.batching_challenge();
                    let public_covectors =
                        continuation.finish_after_matrix_accumulation(source_covector)?;
                    material.main_whir_relation_preparation =
                        Some(CompactWhirMainRelationPreparation::new(
                            public_covectors,
                            material.cfw_mask_material.inner_masks(),
                            material.cfw_mask_material.outer_masks(),
                            material.cross_epoch_masks,
                            input_binding_challenge,
                        )?);
                    return Ok(CompactPublicKeyMainEpochPoll::MainWhirCovectorsPrepared);
                }
            }
        }

        if material.main_whir_relation_preparation.is_some() {
            let poll = material
                .main_whir_relation_preparation
                .as_mut()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                .poll(maximum_work_unit_count, |source_ordinal| {
                    family_material
                        .row_source
                        .witness_value(source_ordinal)
                        .map(compact_challenge_from_production)
                })
                .map_err(|error| match error {
                    CompactWhirMainRelationPreparationError::Whir(error) => {
                        CompactPublicKeyMainEpochPreparationError::Whir(error)
                    }
                    CompactWhirMainRelationPreparationError::Source(error) => {
                        CompactPublicKeyMainEpochPreparationError::Prover(error)
                    }
                })?;
            match poll {
                CompactWhirMainRelationPreparationPoll::SourceStepCompleted {
                    processed_work_unit_count,
                    relation_complete,
                } => {
                    return Ok(
                        CompactPublicKeyMainEpochPoll::MainWhirRelationSourceStepCompleted {
                            processed_work_unit_count,
                            relation_complete,
                        },
                    );
                }
                CompactWhirMainRelationPreparationPoll::Complete => {}
            }
            let preparation = material
                .main_whir_relation_preparation
                .take()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            let relation = preparation.finish()?;
            let contract = selected_compact_public_key_proof_contract()?;
            let [_pre_challenge_epoch, main_epoch] = contract.verifier_inputs().whir_epochs else {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            };
            let configuration = compact_whir_configuration_from_contract(main_epoch)?;
            let mask_group = unique_internal_mask_group(main_epoch, 4, 0)?;
            let initial_sumcheck = {
                let mut random_source = family_material
                    .metadata
                    .pre_challenge
                    .randomness
                    .whir_random_adapter();
                CompactWhirInitialSumcheckState::new(
                    relation,
                    &configuration,
                    0,
                    mask_group,
                    &mut random_source,
                )
            }?;
            family_material
                .metadata
                .pre_challenge
                .randomness
                .ensure_field_sampling_valid()?;
            let response_ordinal = unique_response_ordinal_for_component_role(
                &contract.verifier_inputs(),
                11,
                main_epoch.epoch,
                0,
                0,
            )?;
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
                main_epoch.epoch,
                0,
                initial_sumcheck.mask_oracle(),
            )?;
            let verified_base_prefix = material
                .verified_pre_challenge_whir_base_masking_prefix
                .as_ref()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            verify_selected_compact_whir_sumcheck_auxiliary_masking(
                contract.verifier_inputs(),
                &material.masking_coefficient_maps,
                material
                    .masking_attempt_identity
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
                response_generation_state.verifier_messages(),
                Some(verified_base_prefix),
                CompactWhirSumcheckBatchCoordinate::new(main_epoch.epoch, 0),
                initial_sumcheck.auxiliary_target(),
            )
            .map_err(CompactPublicKeyMainEpochPreparationError::WhirSumcheckAuxiliaryMasking)?;
            material
                .main_whir_sumcheck_batches
                .push(CompactPublicKeyWhirSumcheckBatch::new(
                    0,
                    response_ordinal,
                    initial_sumcheck,
                    response_geometry.merkle_leaf_count(),
                )?);
            return Ok(CompactPublicKeyMainEpochPoll::MainWhirSumcheckPrepared {
                batch_ordinal: 0,
            });
        }
        Err(CompactPublicKeyMainEpochPreparationError::WrongPhase)
    }

    pub(crate) fn poll_main_whir_sumcheck<Storage: ProofExternalMemory>(
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
        if material.main_whir_covector_accumulator.is_some()
            || material.main_whir_covector_continuation.is_some()
            || material.main_whir_relation_preparation.is_some()
        {
            return Err(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ));
        }
        poll_compact_public_key_whir_sumcheck(
            family_material,
            response_generation_state,
            material,
            CompactPublicKeyWhirEpoch::Main,
            maximum_work_unit_count,
            response_storage,
        )
    }

    #[cfg(test)]
    pub(crate) fn main_whir_initial_sumcheck_ready(&self) -> bool {
        self.post_lookup_material.as_ref().is_some_and(|material| {
            material
                .main_whir_sumcheck_batches
                .first()
                .is_some_and(|batch| batch.batch_ordinal == 0)
        })
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

    pub(crate) fn finish(
        self,
    ) -> Result<CompactResponseGenerationOutput, CompactPublicKeyMainEpochPreparationError> {
        let Self {
            family_material: _,
            response_generation_state,
            post_lookup_material,
        } = self;
        post_lookup_material
            .as_ref()
            .and_then(|material| material.main_whir_base_case.as_ref())
            .and_then(|base_case| base_case.verified_final_query_masking.as_ref())
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        Ok(response_generation_state.finish()?)
    }
}

fn poll_compact_public_key_whir_initial_sumcheck_state(
    family_material: &CompactPublicKeyFamilyMaterial,
    state: &mut CompactWhirInitialSumcheckState,
    maximum_work_unit_count: u64,
) -> Result<CompactWhirInitialSumcheckPoll, CompactPublicKeyMainEpochPreparationError> {
    if state.authenticated_source_replay_required() {
        return state
            .poll_replaying_authenticated_source(maximum_work_unit_count, |source_ordinal| {
                family_material
                    .row_source
                    .witness_value(source_ordinal)
                    .map(compact_challenge_from_production)
            })
            .map_err(|error| match error {
                CompactWhirInitialSumcheckSourceReplayError::Whir(error) => {
                    CompactPublicKeyMainEpochPreparationError::Whir(error)
                }
                CompactWhirInitialSumcheckSourceReplayError::Source(error) => {
                    CompactPublicKeyMainEpochPreparationError::Prover(error)
                }
            });
    }
    state.poll(maximum_work_unit_count).map_err(Into::into)
}

fn poll_compact_public_key_whir_sumcheck<Storage: ProofExternalMemory>(
    family_material: &mut CompactPublicKeyFamilyMaterial,
    response_generation_state: &mut CompactResponseGenerationState,
    material: &mut CompactPublicKeyPostLookupMaterial,
    epoch_owner: CompactPublicKeyWhirEpoch,
    maximum_work_unit_count: u64,
    response_storage: &mut Storage,
) -> Result<CompactPublicKeyMainEpochPoll, CompactPublicKeyMainEpochPollError<Storage::Error>> {
    let active_batch_ordinal = material
        .whir_sumcheck_batches(epoch_owner)
        .last()
        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
            CompactPublicKeyMainEpochPreparationError::WrongPhase,
        ))?
        .batch_ordinal;
    if material
        .whir_sumcheck_batches(epoch_owner)
        .last()
        .is_some_and(|batch| batch.bound_round_advance_required)
    {
        let sumcheck = &mut material
            .whir_sumcheck_batches_mut(epoch_owner)
            .last_mut()
            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ))?
            .state;
        let sumcheck_poll = poll_compact_public_key_whir_initial_sumcheck_state(
            family_material,
            sumcheck,
            maximum_work_unit_count,
        )
        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
        return match sumcheck_poll {
            CompactWhirInitialSumcheckPoll::BoundRound {
                round_ordinal,
                round_complete,
                ..
            } => {
                let active_batch = material
                    .whir_sumcheck_batches_mut(epoch_owner)
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
                Ok(epoch_owner.bound_round_poll(
                    active_batch_ordinal,
                    round_ordinal,
                    round_complete,
                ))
            }
            CompactWhirInitialSumcheckPoll::WeightScaling {
                scaling_complete, ..
            } => {
                if scaling_complete {
                    material
                        .whir_sumcheck_batches_mut(epoch_owner)
                        .last_mut()
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?
                        .bound_round_advance_required = false;
                    let batch_index = material
                        .whir_sumcheck_batches(epoch_owner)
                        .len()
                        .checked_sub(1)
                        .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                            CompactPublicKeyMainEpochPreparationError::WrongPhase,
                        ))?;
                    material
                        .validate_whir_sumcheck_completion_for_epoch(
                            epoch_owner,
                            response_generation_state.verifier_messages(),
                            batch_index,
                        )
                        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                    Ok(epoch_owner.sumcheck_complete_poll(active_batch_ordinal))
                } else {
                    Ok(epoch_owner.weight_scaling_poll(active_batch_ordinal, scaling_complete))
                }
            }
            CompactWhirInitialSumcheckPoll::RoundPolynomial { .. } => {
                Err(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))
            }
        };
    }

    if material
        .whir_sumcheck_batches(epoch_owner)
        .last()
        .is_some_and(|batch| batch.combination_challenge_bound)
        && material
            .whir_sumcheck_batches(epoch_owner)
            .last()
            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ))?
            .state
            .pending_round_wire()
            .is_err()
    {
        let sumcheck = &mut material
            .whir_sumcheck_batches_mut(epoch_owner)
            .last_mut()
            .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            ))?
            .state;
        return match poll_compact_public_key_whir_initial_sumcheck_state(
            family_material,
            sumcheck,
            maximum_work_unit_count,
        )
        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
        {
            CompactWhirInitialSumcheckPoll::RoundPolynomial {
                round_ordinal,
                polynomial_ready,
                ..
            } => Ok(epoch_owner.round_polynomial_poll(
                active_batch_ordinal,
                round_ordinal,
                polynomial_ready,
            )),
            _ => Err(CompactPublicKeyMainEpochPollError::Preparation(
                CompactPublicKeyMainEpochPreparationError::WrongPhase,
            )),
        };
    }

    let active_batch = material.whir_sumcheck_batches(epoch_owner).last().ok_or(
        CompactPublicKeyMainEpochPollError::Preparation(
            CompactPublicKeyMainEpochPreparationError::WrongPhase,
        ),
    )?;
    let response_ordinal = active_batch
        .expected_response_ordinal()
        .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
    let initial_response_ordinal = active_batch.initial_response_ordinal;
    if response_ordinal != initial_response_ordinal && !active_batch.round_masking_verified {
        let contract = selected_compact_public_key_proof_contract()
            .map_err(CompactPublicKeyMainEpochPreparationError::from)
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
        let inputs = contract.verifier_inputs();
        let epoch = epoch_owner
            .contract(&inputs)
            .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
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
            inputs,
            &material.masking_coefficient_maps,
            material.masking_attempt_identity.ok_or(
                CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ),
            )?,
            response_generation_state.verifier_messages(),
            material
                .verified_base_masking_prefix(epoch_owner)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?,
            epoch.epoch,
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
            .whir_sumcheck_batches_mut(epoch_owner)
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
                .whir_sumcheck_response_leaf(
                    epoch_owner,
                    family_material.response_merkle_geometries(),
                    response_ordinal,
                    leaf_ordinal,
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?
                .ok_or(CompactPublicKeyMainEpochPollError::Preparation(
                    CompactPublicKeyMainEpochPreparationError::WrongPhase,
                ))?;
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
            let inputs = contract.verifier_inputs();
            let epoch = epoch_owner
                .contract(&inputs)
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
            let canonical_randomness_cursor = family_material
                .pre_challenge_material()
                .randomness
                .canonical_checkpoint_cursor_bytes();
            if response_ordinal == initial_response_ordinal {
                let challenge = unique_completed_extension_role_challenge(
                    &inputs,
                    response_generation_state.verifier_messages(),
                    7,
                    epoch.epoch,
                    active_batch_ordinal,
                    0,
                )
                .map_err(CompactPublicKeyMainEpochPollError::Preparation)?;
                let active_batch = material
                    .whir_sumcheck_batches_mut(epoch_owner)
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
                Ok(epoch_owner.auxiliary_checkpoint_poll(active_batch_ordinal))
            } else {
                let active_batch = material
                    .whir_sumcheck_batches_mut(epoch_owner)
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
                    &inputs,
                    response_generation_state.verifier_messages(),
                    8,
                    epoch.epoch,
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
                Ok(epoch_owner.round_checkpoint_poll(active_batch_ordinal, round_ordinal))
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
    fn whir_sumcheck_batches(
        &self,
        epoch: CompactPublicKeyWhirEpoch,
    ) -> &[CompactPublicKeyWhirSumcheckBatch] {
        match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => &self.pre_challenge_whir_sumcheck_batches,
            CompactPublicKeyWhirEpoch::Main => &self.main_whir_sumcheck_batches,
        }
    }

    fn whir_sumcheck_batches_mut(
        &mut self,
        epoch: CompactPublicKeyWhirEpoch,
    ) -> &mut Vec<CompactPublicKeyWhirSumcheckBatch> {
        match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => {
                &mut self.pre_challenge_whir_sumcheck_batches
            }
            CompactPublicKeyWhirEpoch::Main => &mut self.main_whir_sumcheck_batches,
        }
    }

    fn whir_code_switches(
        &self,
        epoch: CompactPublicKeyWhirEpoch,
    ) -> &[CompactPublicKeyWhirCodeSwitch] {
        match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => &self.pre_challenge_whir_code_switches,
            CompactPublicKeyWhirEpoch::Main => &self.main_whir_code_switches,
        }
    }

    fn whir_code_switches_mut(
        &mut self,
        epoch: CompactPublicKeyWhirEpoch,
    ) -> &mut Vec<CompactPublicKeyWhirCodeSwitch> {
        match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => &mut self.pre_challenge_whir_code_switches,
            CompactPublicKeyWhirEpoch::Main => &mut self.main_whir_code_switches,
        }
    }

    fn whir_base_case(
        &self,
        epoch: CompactPublicKeyWhirEpoch,
    ) -> Option<&CompactPublicKeyWhirBaseCase> {
        match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => self.pre_challenge_whir_base_case.as_ref(),
            CompactPublicKeyWhirEpoch::Main => self.main_whir_base_case.as_ref(),
        }
    }

    fn whir_base_case_mut(
        &mut self,
        epoch: CompactPublicKeyWhirEpoch,
    ) -> Option<&mut CompactPublicKeyWhirBaseCase> {
        match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => self.pre_challenge_whir_base_case.as_mut(),
            CompactPublicKeyWhirEpoch::Main => self.main_whir_base_case.as_mut(),
        }
    }

    fn set_whir_base_case(
        &mut self,
        epoch: CompactPublicKeyWhirEpoch,
        base_case: CompactPublicKeyWhirBaseCase,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let destination = match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => &mut self.pre_challenge_whir_base_case,
            CompactPublicKeyWhirEpoch::Main => &mut self.main_whir_base_case,
        };
        if destination.is_some() {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        *destination = Some(base_case);
        Ok(())
    }

    fn retire_pre_challenge_whir_generation_state(
        &mut self,
        inputs: CompactPublicKeyVerifierInputs<'_>,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let completed_move_ordinal = u32::try_from(
            completed_messages
                .len()
                .checked_sub(1)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        require_pre_challenge_whir_response_state_retirement(&inputs, completed_move_ordinal)?;
        if self.pre_challenge_whir_relation_preparation.is_some()
            || self.pre_challenge_whir_sumcheck_batches.is_empty()
            || self.pre_challenge_whir_code_switches.is_empty()
            || self.whir_base_covector_derivation.is_some()
            || self
                .verified_pre_challenge_whir_base_masking_prefix
                .is_some()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let base_case = self
            .pre_challenge_whir_base_case
            .as_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if base_case.verified_blinded_response_masking.is_some()
            || !base_case.final_query_leaves.is_empty()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let verified_prefix = base_case
            .verified_final_query_masking
            .take()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;

        self.pre_challenge_whir_sumcheck_batches = Vec::new();
        self.pre_challenge_whir_code_switches = Vec::new();
        self.pre_challenge_whir_base_case = None;
        self.verified_pre_challenge_whir_base_masking_prefix = Some(verified_prefix);
        Ok(())
    }

    fn verified_base_masking_prefix(
        &self,
        epoch: CompactPublicKeyWhirEpoch,
    ) -> Result<Option<&CompactVerifiedBaseMaskingPrefix>, CompactPublicKeyMainEpochPreparationError>
    {
        match epoch {
            CompactPublicKeyWhirEpoch::PreChallenge => Ok(None),
            CompactPublicKeyWhirEpoch::Main => Ok(Some(
                self.verified_pre_challenge_whir_base_masking_prefix
                    .as_ref()
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
            )),
        }
    }

    fn whir_sumcheck_response_leaf(
        &self,
        epoch: CompactPublicKeyWhirEpoch,
        response_merkle_geometries: &[CompactResponseMerkleGeometry],
        response_ordinal: u32,
        leaf_ordinal: u64,
    ) -> Result<Option<CompactOwnedResponseLeaf>, CompactPublicKeyMainEpochPreparationError> {
        for batch in self.whir_sumcheck_batches(epoch) {
            if batch.owns_response_ordinal(response_ordinal)? {
                return batch
                    .response_leaf(response_merkle_geometries, response_ordinal, leaf_ordinal)
                    .map(Some);
            }
        }
        Ok(None)
    }

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

    fn whir_sumcheck_initial_response_ordinal(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        batch_ordinal: u8,
    ) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        if let Some(batch) = self
            .whir_sumcheck_batches(epoch_owner)
            .get(usize::from(batch_ordinal))
        {
            if batch.batch_ordinal != batch_ordinal {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            return Ok(batch.initial_response_ordinal);
        }
        let contract = selected_compact_public_key_proof_contract()?;
        let epoch = epoch_owner.contract(&contract.verifier_inputs())?;
        unique_response_ordinal_for_component_role(
            &contract.verifier_inputs(),
            11,
            epoch.epoch,
            batch_ordinal,
            0,
        )
    }

    fn whir_code_switch_response_ordinal(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        round_ordinal: u8,
    ) -> Result<u32, CompactPublicKeyMainEpochPreparationError> {
        if let Some(code_switch) = self
            .whir_code_switches(epoch_owner)
            .get(usize::from(round_ordinal))
        {
            if code_switch.round_ordinal != round_ordinal {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            return Ok(code_switch.response_ordinal);
        }
        let preceding_batch = self
            .whir_sumcheck_batches(epoch_owner)
            .get(usize::from(round_ordinal))
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if preceding_batch.batch_ordinal != round_ordinal {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        preceding_batch
            .initial_response_ordinal
            .checked_add(
                u32::try_from(preceding_batch.state.mask_messages().len())
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
                    .checked_add(1)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
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
        validate_whir_sumcheck_completion(
            &contract.verifier_inputs(),
            pre_challenge_epoch,
            completed_messages,
            &self.pre_challenge_whir_sumcheck_batches,
            batch_index,
        )?;
        let batch = self
            .pre_challenge_whir_sumcheck_batches
            .get(batch_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let folding_factor = usize::try_from(
            *pre_challenge_epoch
                .folding_schedule
                .get(batch_index)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
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
        if !initial_batch_claims_are_exact {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok(())
    }

    fn validate_main_whir_sumcheck_completion(
        &self,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        batch_index: usize,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let contract = selected_compact_public_key_proof_contract()?;
        let [_pre_challenge_epoch, main_epoch] = contract.verifier_inputs().whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        validate_whir_sumcheck_completion(
            &contract.verifier_inputs(),
            main_epoch,
            completed_messages,
            &self.main_whir_sumcheck_batches,
            batch_index,
        )
    }

    fn validate_whir_sumcheck_completion_for_epoch(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        batch_index: usize,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        match epoch_owner {
            CompactPublicKeyWhirEpoch::PreChallenge => self
                .validate_pre_challenge_whir_sumcheck_completion(completed_messages, batch_index),
            CompactPublicKeyWhirEpoch::Main => {
                self.validate_main_whir_sumcheck_completion(completed_messages, batch_index)
            }
        }
    }

    fn bind_whir_base_combination_challenge(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        inputs: CompactPublicKeyVerifierInputs<'_>,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        combination_challenge: CompactChallengeField,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let epoch = epoch_owner.contract(&inputs)?;
        let masking_attempt_identity = self
            .masking_attempt_identity
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let base_case = self
            .whir_base_case(epoch_owner)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if base_case.verified_blinded_response_masking.is_some()
            || base_case.verified_final_query_masking.is_some()
            || !base_case.final_query_leaves.is_empty()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let claim_coefficients = base_case.state.base_claim_coefficients()?;
        let verified_reveal_masking = verify_selected_compact_whir_base_reveal_masking(
            inputs,
            &self.masking_coefficient_maps,
            masking_attempt_identity,
            completed_messages,
            self.verified_base_masking_prefix(epoch_owner)?,
            epoch.epoch,
            &claim_coefficients,
        )?;
        let base_case = self
            .whir_base_case_mut(epoch_owner)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        base_case
            .state
            .bind_combination_challenge(combination_challenge)?;
        base_case.verified_blinded_response_masking = Some(verified_reveal_masking);
        Ok(())
    }

    fn poll_whir_base_opened_leaf(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        family_material: &CompactPublicKeyFamilyMaterial,
        response_ordinal: u32,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
        opening_query_leaf_ordinals: &[u64],
    ) -> Result<CompactPublicKeyCodeSwitchResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        let fresh_response_ordinal = self
            .whir_base_case(epoch_owner)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .fresh_response_ordinal;
        if response_ordinal == fresh_response_ordinal {
            return self
                .whir_base_case_mut(epoch_owner)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                .poll_opened_fresh_response_leaf(
                    leaf_ordinal,
                    maximum_work_unit_count,
                    opening_query_leaf_ordinals,
                );
        }
        let final_code_switch = self
            .whir_code_switches_mut(epoch_owner)
            .last_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if response_ordinal == final_code_switch.response_ordinal {
            return final_code_switch.poll_opened_response_leaf(
                leaf_ordinal,
                maximum_work_unit_count,
                opening_query_leaf_ordinals,
            );
        }
        Ok(CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(
            compact_public_key_response_leaf(
                family_material,
                self,
                response_ordinal,
                leaf_ordinal,
            )?,
        ))
    }

    fn mark_whir_base_opened_leaf_supplied(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        response_ordinal: u32,
        leaf_ordinal: u64,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let base_case = self
            .whir_base_case_mut(epoch_owner)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if response_ordinal == base_case.fresh_response_ordinal {
            return base_case.mark_fresh_response_leaf_supplied(leaf_ordinal);
        }
        let final_code_switch = self
            .whir_code_switches_mut(epoch_owner)
            .last_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if response_ordinal == final_code_switch.response_ordinal {
            return final_code_switch.mark_response_leaf_supplied(leaf_ordinal);
        }
        Ok(())
    }

    fn record_whir_base_query_leaf(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        query_leaf: Option<CompactMaskingQueryLeaf>,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let Some(query_leaf) = query_leaf else {
            return Ok(());
        };
        let query_leaves = &mut self
            .whir_base_case_mut(epoch_owner)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .final_query_leaves;
        query_leaves
            .try_reserve(1)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        query_leaves.push(query_leaf);
        Ok(())
    }

    fn record_deferred_pre_challenge_whir_base_query_leaves(
        &mut self,
        family_material: &CompactPublicKeyFamilyMaterial,
        inputs: &CompactPublicKeyVerifierInputs<'_>,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        };
        let current_move_ordinal = u32::try_from(
            completed_messages
                .len()
                .checked_sub(1)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
        )
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        let current_move = inputs
            .verifier_moves
            .get(
                usize::try_from(current_move_ordinal)
                    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            )
            .filter(|verifier_move| verifier_move.ordinal == current_move_ordinal)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if !current_move
            .role_coordinates
            .iter()
            .any(|role| (role.role_tag, role.epoch) == (11, pre_challenge_epoch.epoch))
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let mut deferred_component_count = 0_u8;
        for (geometry, roles) in inputs
            .response_merkle_geometries
            .iter()
            .zip(inputs.response_component_roles)
        {
            if geometry.components().len() != roles.len() {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            for (component, role) in geometry.components().iter().zip(roles) {
                if (
                    role.role_tag,
                    role.epoch,
                    role.batch_ordinal,
                    role.round_ordinal,
                ) != (5, 0, 0, 0)
                {
                    continue;
                }
                let CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    first_distinct_query_group_ordinal,
                    second_logical_verifier_move_ordinal,
                    ..
                } = component.query_selection()
                else {
                    return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
                };
                if first_logical_verifier_move_ordinal != current_move_ordinal
                    || second_logical_verifier_move_ordinal <= current_move_ordinal
                    || usize::try_from(second_logical_verifier_move_ordinal)
                        .is_ok_and(|move_index| move_index < completed_messages.len())
                {
                    return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
                }
                deferred_component_count = deferred_component_count
                    .checked_add(1)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                let query_positions = completed_messages
                    .get(
                        usize::try_from(first_logical_verifier_move_ordinal).map_err(|_| {
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                        })?,
                    )
                    .and_then(|message| {
                        message
                            .distinct_query_groups()
                            .get(usize::try_from(first_distinct_query_group_ordinal).ok()?)
                    })
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
                if query_positions.is_empty()
                    || query_positions
                        .last()
                        .is_none_or(|position| *position >= component.leaf_count())
                {
                    return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
                }
                for query_position in query_positions {
                    let leaf_ordinal = component
                        .first_leaf_ordinal()
                        .checked_add(*query_position)
                        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                    let leaf = compact_public_key_response_leaf(
                        family_material,
                        self,
                        geometry.response_ordinal(),
                        leaf_ordinal,
                    )?;
                    let query_leaf = compact_masking_query_leaf(
                        inputs.response_merkle_geometries,
                        current_move_ordinal,
                        geometry.response_ordinal(),
                        leaf_ordinal,
                        &leaf,
                    )?;
                    self.record_whir_base_query_leaf(
                        CompactPublicKeyWhirEpoch::PreChallenge,
                        query_leaf,
                    )?;
                }
            }
        }
        if deferred_component_count != 1 {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        Ok(())
    }

    fn verify_and_finish_whir_base_final_queries(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        inputs: CompactPublicKeyVerifierInputs<'_>,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let epoch = epoch_owner.contract(&inputs)?;
        let masking_attempt_identity = self
            .masking_attempt_identity
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let base_case = self
            .whir_base_case(epoch_owner)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if base_case.verified_blinded_response_masking.is_none()
            || base_case.verified_final_query_masking.is_some()
            || !base_case.state.fresh_source_opening_replay_complete()
            || !self
                .whir_code_switches(epoch_owner)
                .last()
                .is_some_and(|code_switch| code_switch.state.source_opening_replay_complete())
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let fresh_source_mirror_coefficients =
            base_case.state.fresh_source_mirror_coefficients()?;
        let mut fresh_mask_mirror_coefficients = Vec::new();
        fresh_mask_mirror_coefficients
            .try_reserve_exact(base_case.state.fresh_mask_group_count())
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
        for group_ordinal in 0..base_case.state.fresh_mask_group_count() {
            fresh_mask_mirror_coefficients.push(
                base_case
                    .state
                    .fresh_mask_mirror_coefficients(group_ordinal)?,
            );
        }
        let verified_final_query_masking = verify_selected_compact_whir_base_final_query_masking(
            inputs,
            &self.masking_coefficient_maps,
            masking_attempt_identity,
            completed_messages,
            self.verified_base_masking_prefix(epoch_owner)?,
            epoch.epoch,
            base_case
                .verified_blinded_response_masking
                .as_ref()
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
            &fresh_source_mirror_coefficients,
            &fresh_mask_mirror_coefficients,
            &base_case.final_query_leaves,
        )?;

        self.whir_code_switches_mut(epoch_owner)
            .last_mut()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .state
            .finish_source_opening_replay()?;
        let base_case = self
            .whir_base_case_mut(epoch_owner)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        base_case.state.finish_final_query_opening_replay()?;
        base_case.final_query_leaves.clear();
        base_case.verified_blinded_response_masking = None;
        base_case.verified_final_query_masking = Some(verified_final_query_masking);
        Ok(())
    }

    fn whir_response_leaf(
        &self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        response_merkle_geometries: &[CompactResponseMerkleGeometry],
        response_ordinal: u32,
        leaf_ordinal: u64,
    ) -> Result<Option<CompactOwnedResponseLeaf>, CompactPublicKeyMainEpochPreparationError> {
        if let Some(leaf) = self.whir_sumcheck_response_leaf(
            epoch_owner,
            response_merkle_geometries,
            response_ordinal,
            leaf_ordinal,
        )? {
            return Ok(Some(leaf));
        }
        for code_switch in self.whir_code_switches(epoch_owner) {
            if response_ordinal == code_switch.response_ordinal {
                return code_switch.response_leaf(leaf_ordinal).map(Some);
            }
        }
        if let Some(base_case) = self.whir_base_case(epoch_owner) {
            if response_ordinal == base_case.fresh_response_ordinal {
                return base_case.fresh_response_leaf(leaf_ordinal).map(Some);
            }
            if response_ordinal == base_case.blinded_response_ordinal {
                return base_case.blinded_response_leaf(leaf_ordinal).map(Some);
            }
        }
        Ok(None)
    }

    fn poll_code_switch_response_leaf(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        round_ordinal: u8,
        leaf_ordinal: u64,
        maximum_work_unit_count: u64,
    ) -> Result<CompactPublicKeyCodeSwitchResponseLeafPoll, CompactPublicKeyMainEpochPreparationError>
    {
        self.whir_code_switches_mut(epoch_owner)
            .get_mut(usize::from(round_ordinal))
            .filter(|code_switch| code_switch.round_ordinal == round_ordinal)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .poll_response_leaf(leaf_ordinal, maximum_work_unit_count)
    }

    fn mark_code_switch_response_leaf_supplied(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        round_ordinal: u8,
        leaf_ordinal: u64,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        self.whir_code_switches_mut(epoch_owner)
            .get_mut(usize::from(round_ordinal))
            .filter(|code_switch| code_switch.round_ordinal == round_ordinal)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .mark_response_leaf_supplied(leaf_ordinal)
    }

    fn poll_code_switch_source_query_evaluation(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        active_round_ordinal: u8,
        maximum_work_unit_count: u64,
        row_source: &SelectedCompactPublicKeyRowSource,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> Result<
        CompactPublicKeyCodeSwitchQueryEvaluationPoll,
        CompactPublicKeyMainEpochPreparationError,
    > {
        if active_round_ordinal == 0 {
            return match epoch_owner {
                CompactPublicKeyWhirEpoch::PreChallenge => {
                    Err(CompactPublicKeyMainEpochPreparationError::WrongPhase)
                }
                CompactPublicKeyWhirEpoch::Main => self.poll_main_source_query_evaluation(
                    maximum_work_unit_count,
                    row_source,
                    completed_messages,
                ),
            };
        }
        let active_index = usize::from(active_round_ordinal);
        let previous_index = active_index - 1;
        let (preceding_code_switches, active_and_later) = self
            .whir_code_switches_mut(epoch_owner)
            .split_at_mut(active_index);
        let previous_code_switch = preceding_code_switches
            .get_mut(previous_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        let active_code_switch = active_and_later
            .first_mut()
            .filter(|code_switch| code_switch.round_ordinal == active_round_ordinal)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if active_code_switch.source_query_masking_verified
            || active_code_switch.state.verifier_move_is_bound()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        if previous_code_switch.retained_source_queries.is_none() {
            let contract = selected_compact_public_key_proof_contract()?;
            let epoch = epoch_owner.contract(&contract.verifier_inputs())?;
            let (_combination_challenge, query_positions) = completed_code_switch_verifier_move(
                &contract.verifier_inputs(),
                completed_messages,
                epoch.epoch,
                u32::from(active_round_ordinal),
            )?;
            let [previous_source_end, _previous_mask_end] =
                previous_code_switch.component_boundaries()?;
            if query_positions.is_empty()
                || query_positions
                    .last()
                    .is_none_or(|position| *position >= previous_source_end)
            {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            if !previous_code_switch.state.can_begin_source_opening_replay() {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            let mut opening_rows = Vec::new();
            opening_rows
                .try_reserve_exact(query_positions.len())
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
            for query_position in query_positions {
                opening_rows.push(
                    usize::try_from(*query_position)
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
                );
            }
            previous_code_switch
                .state
                .begin_source_opening_replay(&opening_rows)?;
            previous_code_switch.retained_source_queries =
                Some(CompactPublicKeyRetainedSourceQueries::new(
                    query_positions,
                    previous_code_switch.state.source_oracle().width(),
                )?);
        }

        let width = previous_code_switch.state.source_oracle().width();
        let next_query_position = previous_code_switch
            .retained_source_queries
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .next_position()?;
        let Some(query_position) = next_query_position else {
            return previous_code_switch
                .state
                .source_opening_replay_complete()
                .then_some(CompactPublicKeyCodeSwitchQueryEvaluationPoll::Complete)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        };
        let row_ordinal = usize::try_from(query_position)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        match previous_code_switch
            .state
            .poll_source_oracle(maximum_work_unit_count)?
        {
            CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted {
                processed_work_unit_count,
            } => Ok(
                CompactPublicKeyCodeSwitchQueryEvaluationPoll::StepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                let row = previous_code_switch.state.source_row(row_ordinal)?;
                if row.len() != width {
                    return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
                }
                previous_code_switch
                    .retained_source_queries
                    .as_mut()
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                    .append_row(query_position, row)?;
                previous_code_switch
                    .state
                    .mark_source_row_supplied(row_ordinal)?;
                Ok(
                    CompactPublicKeyCodeSwitchQueryEvaluationPoll::StepCompleted {
                        processed_work_unit_count: u64::try_from(width).map_err(|_| {
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                        })?,
                    },
                )
            }
        }
    }

    fn poll_main_source_query_evaluation(
        &mut self,
        maximum_work_unit_count: u64,
        row_source: &SelectedCompactPublicKeyRowSource,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
    ) -> Result<
        CompactPublicKeyCodeSwitchQueryEvaluationPoll,
        CompactPublicKeyMainEpochPreparationError,
    > {
        let active_code_switch = self
            .main_whir_code_switches
            .first()
            .filter(|code_switch| code_switch.round_ordinal == 0)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if active_code_switch.source_query_masking_verified
            || active_code_switch.state.verifier_move_is_bound()
        {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        if self.main_source_queries.is_none() {
            let contract = selected_compact_public_key_proof_contract()?;
            let main_epoch =
                CompactPublicKeyWhirEpoch::Main.contract(&contract.verifier_inputs())?;
            let (_combination_challenge, query_positions) = completed_code_switch_verifier_move(
                &contract.verifier_inputs(),
                completed_messages,
                main_epoch.epoch,
                0,
            )?;
            let source_height = u64::try_from(self.main_source_oracle.encoded_height())
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
            if query_positions.is_empty()
                || query_positions
                    .last()
                    .is_none_or(|position| *position >= source_height)
            {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            if !self.main_source_oracle.can_begin_opening_replay() {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            let opening_rows = query_positions
                .iter()
                .copied()
                .map(|position| {
                    usize::try_from(position)
                        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.main_source_oracle
                .begin_opening_replay(&opening_rows)
                .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
            self.main_source_queries = Some(CompactPublicKeyRetainedSourceQueries::new(
                query_positions,
                self.main_source_oracle.width(),
            )?);
        }

        let next_query_position = self
            .main_source_queries
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .next_position()?;
        let Some(query_position) = next_query_position else {
            return (self.main_source_oracle.opening_replay_complete()
                && self
                    .main_source_queries
                    .as_ref()
                    .is_some_and(CompactPublicKeyRetainedSourceQueries::is_complete))
            .then_some(CompactPublicKeyCodeSwitchQueryEvaluationPoll::Complete)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        };
        let row_ordinal = usize::try_from(query_position)
            .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
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
                CompactPublicKeyCodeSwitchQueryEvaluationPoll::StepCompleted {
                    processed_work_unit_count,
                },
            ),
            CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                let row = self
                    .main_source_oracle
                    .response_row(row_ordinal)
                    .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
                let width = row.len();
                self.main_source_queries
                    .as_mut()
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
                    .append_row(query_position, row)?;
                self.main_source_oracle
                    .mark_response_row_supplied(row_ordinal)
                    .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
                Ok(
                    CompactPublicKeyCodeSwitchQueryEvaluationPoll::StepCompleted {
                        processed_work_unit_count: u64::try_from(width).map_err(|_| {
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                        })?,
                    },
                )
            }
        }
    }

    fn bind_code_switch_verifier_move(
        &mut self,
        epoch_owner: CompactPublicKeyWhirEpoch,
        family_material: &CompactPublicKeyFamilyMaterial,
        completed_messages: &[DecodedFixedUniformVerifierMessage],
        round_ordinal: u8,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        let code_switch_index = usize::from(round_ordinal);
        let code_switch = self
            .whir_code_switches(epoch_owner)
            .get(code_switch_index)
            .filter(|code_switch| code_switch.round_ordinal == round_ordinal)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        if code_switch.source_query_masking_verified || code_switch.state.verifier_move_is_bound() {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
        let contract = selected_compact_public_key_proof_contract()?;
        let epoch = epoch_owner.contract(&contract.verifier_inputs())?;
        let (combination_challenge, query_positions) = completed_code_switch_verifier_move(
            &contract.verifier_inputs(),
            completed_messages,
            epoch.epoch,
            u32::from(round_ordinal),
        )?;
        let folding_challenges = self
            .whir_sumcheck_batches(epoch_owner)
            .get(code_switch_index)
            .filter(|batch| batch.batch_ordinal == round_ordinal)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .state
            .round_challenges()
            .to_vec();
        let folded_source_openings = if round_ordinal == 0 {
            match epoch_owner {
                CompactPublicKeyWhirEpoch::PreChallenge => {
                    let mut query_outputs = family_material
                        .pre_challenge_material()
                        .source_query_outputs(query_positions)?;
                    verify_selected_compact_whir_source_query_masking(
                        contract.verifier_inputs(),
                        &self.masking_coefficient_maps,
                        self.masking_attempt_identity
                            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
                        completed_messages,
                        None,
                        epoch.epoch,
                        round_ordinal,
                        &query_outputs,
                    )
                    .map_err(|error| {
                        CompactPublicKeyMainEpochPreparationError::WhirSourceQueryMasking {
                            source_ordinal: round_ordinal,
                            error,
                        }
                    })?;
                    let folded_source_openings = fold_compact_whir_query_major_source_openings(
                        &query_outputs,
                        query_positions.len(),
                        &folding_challenges,
                    )?;
                    query_outputs.fill(CompactChallengeField::ZERO);
                    folded_source_openings
                }
                CompactPublicKeyWhirEpoch::Main => {
                    if !self.main_source_oracle.opening_replay_complete() {
                        return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
                    }
                    let retained_source_queries = self
                        .main_source_queries
                        .as_ref()
                        .filter(|queries| queries.is_complete())
                        .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
                    if retained_source_queries.positions() != query_positions {
                        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
                    }
                    verify_selected_compact_whir_source_query_masking(
                        contract.verifier_inputs(),
                        &self.masking_coefficient_maps,
                        self.masking_attempt_identity
                            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
                        completed_messages,
                        self.verified_base_masking_prefix(epoch_owner)?,
                        epoch.epoch,
                        round_ordinal,
                        retained_source_queries.outputs(),
                    )
                    .map_err(|error| {
                        CompactPublicKeyMainEpochPreparationError::WhirSourceQueryMasking {
                            source_ordinal: round_ordinal,
                            error,
                        }
                    })?;
                    fold_compact_whir_query_major_source_openings(
                        retained_source_queries.outputs(),
                        query_positions.len(),
                        &folding_challenges,
                    )?
                }
            }
        } else {
            let previous_code_switch = self
                .whir_code_switches(epoch_owner)
                .get(code_switch_index - 1)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            if !previous_code_switch.state.source_opening_replay_complete() {
                return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
            }
            if previous_code_switch
                .retained_source_queries
                .as_ref()
                .map(CompactPublicKeyRetainedSourceQueries::positions)
                != Some(query_positions)
            {
                return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
            }
            let retained_source_outputs = previous_code_switch
                .retained_source_queries
                .as_ref()
                .filter(|queries| queries.is_complete())
                .map(CompactPublicKeyRetainedSourceQueries::outputs)
                .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
            verify_selected_compact_whir_source_query_masking(
                contract.verifier_inputs(),
                &self.masking_coefficient_maps,
                self.masking_attempt_identity
                    .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?,
                completed_messages,
                self.verified_base_masking_prefix(epoch_owner)?,
                epoch.epoch,
                round_ordinal,
                retained_source_outputs,
            )
            .map_err(|error| {
                CompactPublicKeyMainEpochPreparationError::WhirSourceQueryMasking {
                    source_ordinal: round_ordinal,
                    error,
                }
            })?;
            fold_compact_whir_query_major_source_openings(
                retained_source_outputs,
                query_positions.len(),
                &folding_challenges,
            )?
        };
        let code_switch = self
            .whir_code_switches_mut(epoch_owner)
            .get_mut(code_switch_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
        code_switch.state.bind_verifier_move(
            query_positions,
            combination_challenge,
            folded_source_openings,
        )?;
        code_switch.source_query_masking_verified = true;
        if round_ordinal == 0 && epoch_owner == CompactPublicKeyWhirEpoch::Main {
            self.main_source_oracle
                .finish_opening_replay()
                .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?;
        } else if round_ordinal > 0 {
            self.whir_code_switches_mut(epoch_owner)[code_switch_index - 1]
                .state
                .finish_source_opening_replay()?;
        }
        Ok(())
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
            if self.main_source_oracle.opening_replay_complete() {
                self.retained_main_source_row(leaf_ordinal - inner_mask_end)?;
                return Ok(());
            }
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
        if self.main_source_oracle.opening_replay_complete() {
            return Ok(CompactPublicKeyPostLookupResponseLeafPoll::LeafReady(
                encoded_extension_values_response_leaf(Some(
                    self.retained_main_source_row(leaf_ordinal - inner_mask_end)?,
                ))?,
            ));
        }
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
            let main_source_row = leaf_ordinal - inner_mask_end;
            let row =
                if self.main_source_oracle.opening_replay_complete() {
                    self.retained_main_source_row(main_source_row)?
                } else {
                    self.main_source_oracle
                        .response_row(usize::try_from(main_source_row).map_err(|_| {
                            CompactPublicKeyMainEpochPreparationError::InvalidGeometry
                        })?)
                        .map_err(CompactPublicKeyMainEpochPreparationError::Whir)?
                };
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

    fn retained_main_source_row(
        &self,
        source_row_ordinal: u64,
    ) -> Result<&[CompactChallengeField], CompactPublicKeyMainEpochPreparationError> {
        self.main_source_queries
            .as_ref()
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?
            .row(source_row_ordinal)
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
        let mut random_source = randomness.whir_random_adapter();
        CompactCfwMaskMaterial::sample(cfw_geometry, || random_source.random())?
    };
    randomness.ensure_field_sampling_valid()?;
    let cfw_auxiliary_target = cfw_mask_material.auxiliary_target(cfw_geometry)?;
    let inner_mask_messages = copy_mask_messages(cfw_mask_material.inner_masks())?;
    let inner_mask_encoding_randomness = {
        let mut random_source = randomness.whir_random_adapter();
        sample_mask_encoding_randomness(
            &mut random_source,
            inner_mask_shape.width,
            inner_mask_shape.shape.randomness_len,
        )?
    };
    randomness.ensure_field_sampling_valid()?;
    let inner_mask_oracle = CompactWhirEncodedMaskGroup::encode(
        inner_mask_shape,
        &inner_mask_messages,
        &inner_mask_encoding_randomness,
    )?;
    let main_source_oracle = {
        let mut random_source = randomness.whir_random_adapter();
        CompactWhirRecomputableExtensionInitialOracle::sample(
            &main_configuration,
            &mut random_source,
        )?
    };
    randomness.ensure_field_sampling_valid()?;
    if main_source_oracle.source_element_count() != witness_length {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let outer_mask_messages = copy_mask_messages(cfw_mask_material.outer_masks())?;
    let outer_mask_encoding_randomness = {
        let mut random_source = randomness.whir_random_adapter();
        sample_mask_encoding_randomness(
            &mut random_source,
            outer_mask_shape.width,
            outer_mask_shape.shape.randomness_len,
        )?
    };
    randomness.ensure_field_sampling_valid()?;
    let outer_mask_oracle = CompactWhirEncodedMaskGroup::encode(
        outer_mask_shape,
        &outer_mask_messages,
        &outer_mask_encoding_randomness,
    )?;
    let cross_epoch_masks = {
        let mut random_source = randomness.whir_random_adapter();
        [random_source.random(), random_source.random()]
    };
    randomness.ensure_field_sampling_valid()?;
    let cross_epoch_mask_messages = vec![vec![cross_epoch_masks[0]], vec![cross_epoch_masks[1]]];
    let cross_epoch_mask_encoding_randomness = {
        let mut random_source = randomness.whir_random_adapter();
        sample_mask_encoding_randomness(
            &mut random_source,
            cross_epoch_mask_shape.width,
            cross_epoch_mask_shape.shape.randomness_len,
        )?
    };
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
        #[cfg(test)]
        test_only_cfw_masking_inconsistency_round_ordinals: Vec::new(),
        pre_challenge_whir_relation_preparation: None,
        pre_challenge_whir_sumcheck_batches: Vec::new(),
        pre_challenge_whir_code_switches: Vec::new(),
        pre_challenge_whir_base_case: None,
        verified_pre_challenge_whir_base_masking_prefix: None,
        main_whir_covector_accumulator: None,
        main_whir_covector_continuation: None,
        main_whir_relation_preparation: None,
        main_whir_sumcheck_batches: Vec::new(),
        main_whir_code_switches: Vec::new(),
        whir_base_covector_derivation: None,
        main_whir_base_case: None,
        main_source_queries: None,
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

fn validate_whir_sumcheck_completion(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    epoch: &CompactWhirEpochContract,
    completed_messages: &[DecodedFixedUniformVerifierMessage],
    batches: &[CompactPublicKeyWhirSumcheckBatch],
    batch_index: usize,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    let batch = batches
        .get(batch_index)
        .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase)?;
    let expected_batch_ordinal = u8::try_from(batch_index)
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if batch.batch_ordinal != expected_batch_ordinal {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let folding_factor = usize::try_from(
        *epoch
            .folding_schedule
            .get(batch_index)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
    )
    .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let source_length = whir_sumcheck_source_length(inputs, epoch, batch.batch_ordinal)?;
    let expected_residual_length = source_length
        .checked_shr(
            u32::try_from(folding_factor)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        )
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let mask_group = unique_internal_mask_group(epoch, 4, batch.batch_ordinal)?;
    let input_binding_challenge = if batch.batch_ordinal == 0 {
        unique_completed_extension_role_challenge(inputs, completed_messages, 6, epoch.epoch, 0, 0)?
    } else {
        completed_code_switch_verifier_move(
            inputs,
            completed_messages,
            epoch.epoch,
            u32::from(batch.batch_ordinal - 1),
        )?
        .0
    };
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
        || batch
            .state
            .mask_encoding_randomness()
            .iter()
            .any(|values| u64::try_from(values.len()).ok() != Some(mask_group.randomness_length))
        || !masking_outputs_are_exact
        || residual_source_claim != recomputed_residual_source_claim
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
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

fn whir_base_mask_inputs(
    material: &CompactPublicKeyPostLookupMaterial,
    epoch_owner: CompactPublicKeyWhirEpoch,
    epoch: &CompactWhirEpochContract,
    mask_covectors: Vec<Vec<Vec<CompactChallengeField>>>,
) -> Result<Vec<CompactWhirBaseMaskInput>, CompactPublicKeyMainEpochPreparationError> {
    let contract_count = epoch
        .external_mask_groups
        .len()
        .checked_add(epoch.internal_mask_groups.len())
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if mask_covectors.len() != contract_count {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }

    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(contract_count)
        .map_err(|_| CompactPublicKeyMainEpochPreparationError::AllocationLimitExceeded)?;
    for (contract, covectors) in epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .copied()
        .zip(mask_covectors)
    {
        let (messages, randomness) = match (contract.role_tag, contract.coordinate) {
            (1, 0) => (
                material
                    .cross_epoch_masks
                    .iter()
                    .copied()
                    .map(|mask| vec![mask])
                    .collect(),
                material.cross_epoch_mask_encoding_randomness.clone(),
            ),
            (2, 0) if epoch_owner == CompactPublicKeyWhirEpoch::Main => (
                material
                    .cfw_mask_material
                    .inner_masks()
                    .iter()
                    .map(|mask| mask.to_vec())
                    .collect(),
                material.inner_mask_encoding_randomness.clone(),
            ),
            (3, 0) if epoch_owner == CompactPublicKeyWhirEpoch::Main => (
                material
                    .cfw_mask_material
                    .outer_masks()
                    .iter()
                    .map(|mask| mask.to_vec())
                    .collect(),
                material.outer_mask_encoding_randomness.clone(),
            ),
            (4, batch_ordinal) => {
                let batch = material
                    .whir_sumcheck_batches(epoch_owner)
                    .get(usize::from(batch_ordinal))
                    .filter(|batch| {
                        batch.batch_ordinal == batch_ordinal && batch.state.is_complete()
                    })
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                (
                    batch.state.mask_messages().to_vec(),
                    batch.state.mask_encoding_randomness().to_vec(),
                )
            }
            (5, round_ordinal) => {
                let code_switch = material
                    .whir_code_switches(epoch_owner)
                    .get(usize::from(round_ordinal))
                    .filter(|code_switch| code_switch.round_ordinal == round_ordinal)
                    .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
                (
                    vec![code_switch.state.folded_previous_randomness()?.to_vec()],
                    vec![code_switch.state.switch_mask_encoding_randomness().to_vec()],
                )
            }
            _ => return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry),
        };
        inputs.push(CompactWhirBaseMaskInput::new(
            contract, messages, randomness, covectors,
        )?);
    }
    if inputs.len() != contract_count {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(inputs)
}

fn validate_whir_base_response_geometry(
    fresh_geometry: &CompactResponseMerkleGeometry,
    fresh_roles: &[CompactResponseComponentRoleContract],
    blinded_geometry: &CompactResponseMerkleGeometry,
    blinded_roles: &[CompactResponseComponentRoleContract],
    epoch: &CompactWhirEpochContract,
    final_fold: CompactWhirFoldContract,
    state: &CompactWhirBaseCaseState,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    let mask_contracts = epoch
        .external_mask_groups
        .iter()
        .chain(&epoch.internal_mask_groups)
        .copied()
        .collect::<Vec<_>>();
    let expected_component_count = mask_contracts
        .len()
        .checked_add(3)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    if state.fresh_mask_group_count() != mask_contracts.len()
        || fresh_geometry.components().len() != expected_component_count
        || fresh_roles.len() != expected_component_count
        || blinded_geometry.components().len() != expected_component_count
        || blinded_roles.len() != expected_component_count
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }

    let fresh_components = fresh_geometry.components();
    if (
        fresh_roles[0].role_tag,
        fresh_roles[0].epoch,
        fresh_roles[0].batch_ordinal,
        fresh_roles[0].round_ordinal,
    ) != (16, epoch.epoch, 0, 0)
        || fresh_components[0].first_leaf_ordinal() != 0
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    validate_extension_component_dimensions(
        &fresh_components[0],
        state.fresh_source_oracle().encoded_height(),
        state.fresh_source_oracle().width(),
    )?;
    let mut fresh_populated_leaf_count = fresh_components[0].leaf_count();
    for group_ordinal in 0..mask_contracts.len() {
        let component_index = group_ordinal + 1;
        let role = fresh_roles[component_index];
        if (
            role.role_tag,
            role.epoch,
            role.batch_ordinal,
            role.round_ordinal,
        ) != (
            17,
            epoch.epoch,
            u8::try_from(group_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            0,
        ) || fresh_components[component_index].first_leaf_ordinal() != fresh_populated_leaf_count
        {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        validate_extension_component(
            &fresh_components[component_index],
            state
                .fresh_mask_oracle(group_ordinal)
                .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?
                .encoded_matrix(),
        )?;
        fresh_populated_leaf_count = fresh_populated_leaf_count
            .checked_add(fresh_components[component_index].leaf_count())
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    }
    let fresh_claim_index = mask_contracts.len() + 1;
    let fresh_padding_index = fresh_claim_index + 1;
    if (
        fresh_roles[fresh_claim_index].role_tag,
        fresh_roles[fresh_claim_index].epoch,
        fresh_roles[fresh_claim_index].batch_ordinal,
        fresh_roles[fresh_claim_index].round_ordinal,
    ) != (18, epoch.epoch, 0, 0)
        || fresh_components[fresh_claim_index].first_leaf_ordinal() != fresh_populated_leaf_count
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    validate_extension_component_dimensions(&fresh_components[fresh_claim_index], 1, 1)?;
    fresh_populated_leaf_count = fresh_populated_leaf_count
        .checked_add(1)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    validate_whir_padding_component(
        &fresh_components[fresh_padding_index],
        fresh_roles[fresh_padding_index],
        fresh_populated_leaf_count,
        fresh_geometry.merkle_leaf_count(),
    )?;

    if final_fold.epoch != epoch.epoch || final_fold.batch_ordinal != 3 {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let blinded_components = blinded_geometry.components();
    let source_message_leaf_count = final_fold.message_length;
    let source_randomness_leaf_count = final_fold.hiding_randomness_length;
    if (
        blinded_roles[0].role_tag,
        blinded_roles[0].epoch,
        blinded_roles[0].batch_ordinal,
        blinded_roles[0].round_ordinal,
    ) != (19, epoch.epoch, 0, 0)
        || (
            blinded_roles[1].role_tag,
            blinded_roles[1].epoch,
            blinded_roles[1].batch_ordinal,
            blinded_roles[1].round_ordinal,
        ) != (20, epoch.epoch, 0, 0)
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    validate_scalar_extension_component(&blinded_components[0], 0, source_message_leaf_count)?;
    validate_scalar_extension_component(
        &blinded_components[1],
        source_message_leaf_count,
        source_randomness_leaf_count,
    )?;
    let mut blinded_populated_leaf_count = source_message_leaf_count
        .checked_add(source_randomness_leaf_count)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    for (group_ordinal, contract) in mask_contracts.iter().copied().enumerate() {
        let component_index = group_ordinal + 2;
        let role = blinded_roles[component_index];
        let reveal_count = contract
            .message_length
            .checked_add(contract.randomness_length)
            .and_then(|count| count.checked_mul(contract.width))
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if (
            role.role_tag,
            role.epoch,
            role.batch_ordinal,
            role.round_ordinal,
        ) != (
            21,
            epoch.epoch,
            u8::try_from(group_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
            0,
        ) {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        validate_scalar_extension_component(
            &blinded_components[component_index],
            blinded_populated_leaf_count,
            reveal_count,
        )?;
        blinded_populated_leaf_count = blinded_populated_leaf_count
            .checked_add(reveal_count)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    }
    let blinded_padding_index = mask_contracts.len() + 2;
    validate_whir_padding_component(
        &blinded_components[blinded_padding_index],
        blinded_roles[blinded_padding_index],
        blinded_populated_leaf_count,
        blinded_geometry.merkle_leaf_count(),
    )
}

fn validate_scalar_extension_component(
    component: &CompactResponseComponentGeometry,
    expected_first_leaf_ordinal: u64,
    expected_leaf_count: u64,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if component.value_kind() != CompactResponseLeafValueKind::ExtensionField
        || component.first_leaf_ordinal() != expected_first_leaf_ordinal
        || component.leaf_count() != expected_leaf_count
        || component.field_element_count_per_leaf() != 1
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn validate_whir_padding_component(
    component: &CompactResponseComponentGeometry,
    role: CompactResponseComponentRoleContract,
    expected_first_leaf_ordinal: u64,
    response_leaf_count: u64,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if (
        role.role_tag,
        role.epoch,
        role.batch_ordinal,
        role.round_ordinal,
    ) != (22, 0, 0, 0)
        || component.value_kind() != CompactResponseLeafValueKind::Padding
        || component.field_element_count_per_leaf() != 0
        || component.first_leaf_ordinal() != expected_first_leaf_ordinal
        || expected_first_leaf_ordinal.checked_add(component.leaf_count())
            != Some(response_leaf_count)
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
        || !material.pre_challenge_whir_code_switches.is_empty()
        || material.pre_challenge_whir_base_case.is_some()
        || material
            .verified_pre_challenge_whir_base_masking_prefix
            .is_some()
        || material.main_whir_covector_accumulator.is_some()
        || material.main_whir_covector_continuation.is_some()
        || material.main_whir_relation_preparation.is_some()
        || !material.main_whir_sumcheck_batches.is_empty()
        || !material.main_whir_code_switches.is_empty()
        || material.whir_base_covector_derivation.is_some()
        || material.main_whir_base_case.is_some()
        || material.main_source_queries.is_some()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
}

fn require_pre_challenge_whir_response_state_retirement(
    inputs: &CompactPublicKeyVerifierInputs<'_>,
    completed_move_ordinal: u32,
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    if inputs.response_merkle_geometries.len() != inputs.response_component_roles.len() {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let mut owned_response_count = 0_u32;
    for (geometry, roles) in inputs
        .response_merkle_geometries
        .iter()
        .zip(inputs.response_component_roles)
    {
        if geometry.components().len() != roles.len() {
            return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
        }
        let owns_pre_challenge_whir_material = roles
            .iter()
            .any(|role| role.epoch == 1 && (11..=21).contains(&role.role_tag));
        if !owns_pre_challenge_whir_material {
            continue;
        }
        owned_response_count = owned_response_count
            .checked_add(1)
            .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
        if geometry.last_query_verifier_move_ordinal() > completed_move_ordinal {
            return Err(CompactPublicKeyMainEpochPreparationError::WrongPhase);
        }
    }
    if owned_response_count == 0 {
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
    if let Some(leaf) = post_lookup_material.whir_response_leaf(
        CompactPublicKeyWhirEpoch::Main,
        family_material.response_merkle_geometries(),
        response_ordinal,
        leaf_ordinal,
    )? {
        return Ok(leaf);
    }
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
        _ => post_lookup_material
            .whir_response_leaf(
                CompactPublicKeyWhirEpoch::PreChallenge,
                family_material.response_merkle_geometries(),
                response_ordinal,
                leaf_ordinal,
            )?
            .ok_or(CompactPublicKeyMainEpochPreparationError::WrongPhase),
    }
}

fn compact_masking_query_leaf(
    response_merkle_geometries: &[CompactResponseMerkleGeometry],
    current_move_ordinal: u32,
    response_ordinal: u32,
    leaf_ordinal: u64,
    leaf: &CompactOwnedResponseLeaf,
) -> Result<Option<CompactMaskingQueryLeaf>, CompactPublicKeyMainEpochPreparationError> {
    let geometry = response_merkle_geometries
        .get(
            usize::try_from(response_ordinal)
                .map_err(|_| CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?,
        )
        .filter(|geometry| geometry.response_ordinal() == response_ordinal)
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    let component = geometry
        .components()
        .iter()
        .find(|component| {
            component.first_leaf_ordinal() <= leaf_ordinal
                && component
                    .first_leaf_ordinal()
                    .checked_add(component.leaf_count())
                    .is_some_and(|end| leaf_ordinal < end)
        })
        .ok_or(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)?;
    match component.query_selection() {
        CompactResponseQuerySelection::Unqueried | CompactResponseQuerySelection::EveryLeaf => {
            return Ok(None);
        }
        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
            logical_verifier_move_ordinal,
            ..
        } if logical_verifier_move_ordinal != current_move_ordinal => return Ok(None),
        CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
            first_logical_verifier_move_ordinal,
            second_logical_verifier_move_ordinal,
            ..
        } if first_logical_verifier_move_ordinal != current_move_ordinal
            && second_logical_verifier_move_ordinal != current_move_ordinal =>
        {
            return Ok(None);
        }
        CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. }
        | CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion { .. } => {}
    }
    let CompactOwnedResponseLeaf::ExtensionField(values) = leaf else {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    };
    if u64::try_from(values.len()).ok() != Some(component.field_element_count_per_leaf()) {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let values = values
        .iter()
        .copied()
        .map(compact_challenge_from_production)
        .collect();
    Ok(Some(CompactMaskingQueryLeaf::new(
        response_ordinal,
        leaf_ordinal,
        values,
    )?))
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

    let mut randomness = CompactGenerationAttemptRandomness::from_private_coins(private_coins)
        .map_err(CompactPublicKeyPreChallengeEncodingError::PrivateCoin)?;
    let encoded_oracle = {
        let mut random_source = randomness.whir_random_adapter();
        CompactWhirEncodedInitialOracle::encode(&configuration, source, &mut random_source)?
    };
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
    use rand::{SeedableRng, rngs::SmallRng};

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
    fn masking_query_leaf_requires_bound_geometry_and_exact_leaf_shape() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let (response_index, selected_component) =
            inputs
                .response_merkle_geometries
                .iter()
                .enumerate()
                .skip(1)
                .flat_map(|(response_index, geometry)| {
                    geometry
                        .components()
                        .iter()
                        .map(move |component| (response_index, component))
                })
                .find(|(_, component)| {
                    component.value_kind() == CompactResponseLeafValueKind::ExtensionField
                        && matches!(
                        component.query_selection(),
                        CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. }
                            | CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                                ..
                            }
                    )
                })
                .expect("selected compact contract contains a queried extension-field response");
        let response_ordinal = u32::try_from(response_index)
            .expect("selected response index fits the proof wire ordinal");
        let current_move_ordinal = match selected_component.query_selection() {
            CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                logical_verifier_move_ordinal,
                ..
            }
            | CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                first_logical_verifier_move_ordinal: logical_verifier_move_ordinal,
                ..
            } => logical_verifier_move_ordinal,
            CompactResponseQuerySelection::Unqueried | CompactResponseQuerySelection::EveryLeaf => {
                panic!("selected component is verifier queried")
            }
        };
        let leaf_ordinal = selected_component.first_leaf_ordinal();
        let field_element_count =
            usize::try_from(selected_component.field_element_count_per_leaf())
                .expect("selected response leaf width fits memory");
        let response_leaf = CompactOwnedResponseLeaf::extension_field(vec![
            crate::bgv::proof_suite::ProofChallengeExtensionElement::ZERO;
            field_element_count
        ]);

        let query_leaf = compact_masking_query_leaf(
            inputs.response_merkle_geometries,
            current_move_ordinal,
            response_ordinal,
            leaf_ordinal,
            &response_leaf,
        )
        .expect("bound queried leaf geometry validates")
        .expect("queried component produces a masking leaf");
        assert_eq!(query_leaf.response_ordinal(), response_ordinal);
        assert_eq!(query_leaf.leaf_ordinal(), leaf_ordinal);

        assert!(matches!(
            compact_masking_query_leaf(
                &inputs.response_merkle_geometries[1..],
                current_move_ordinal,
                response_ordinal,
                leaf_ordinal,
                &response_leaf,
            ),
            Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
        ));
        assert!(matches!(
            compact_masking_query_leaf(
                inputs.response_merkle_geometries,
                current_move_ordinal,
                response_ordinal,
                leaf_ordinal,
                &CompactOwnedResponseLeaf::extension_field(vec![
                    crate::bgv::proof_suite::ProofChallengeExtensionElement::ZERO;
                    field_element_count + 1
                ]),
            ),
            Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
        ));
        assert!(matches!(
            compact_masking_query_leaf(
                inputs.response_merkle_geometries,
                current_move_ordinal,
                response_ordinal,
                leaf_ordinal,
                &CompactOwnedResponseLeaf::padding(),
            ),
            Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
        ));
        assert!(matches!(
            compact_masking_query_leaf(
                inputs.response_merkle_geometries,
                u32::MAX,
                response_ordinal,
                leaf_ordinal,
                &response_leaf,
            ),
            Ok(None)
        ));
    }

    #[test]
    fn deferred_shared_root_uses_neutral_role_and_both_epoch_query_moves() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, main_epoch] = inputs.whir_epochs else {
            panic!("selected compact contract has both WHIR epochs")
        };
        let shared_components = inputs
            .response_merkle_geometries
            .iter()
            .zip(inputs.response_component_roles)
            .flat_map(|(geometry, roles)| {
                geometry
                    .components()
                    .iter()
                    .zip(roles)
                    .map(move |(component, role)| (geometry, component, role))
            })
            .filter(|(_, _, role)| role.role_tag == 5)
            .collect::<Vec<_>>();
        let [(geometry, component, role)] = shared_components.as_slice() else {
            panic!("selected compact contract has one shared cross-epoch mask root")
        };
        assert_eq!(
            (
                role.role_tag,
                role.epoch,
                role.batch_ordinal,
                role.round_ordinal,
            ),
            (5, 0, 0, 0)
        );
        assert_eq!(geometry.response_ordinal(), 1);
        let CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
            first_logical_verifier_move_ordinal,
            second_logical_verifier_move_ordinal,
            ..
        } = component.query_selection()
        else {
            panic!("shared cross-epoch mask root uses a two-move query union")
        };
        for (move_ordinal, expected_epoch) in [
            (
                first_logical_verifier_move_ordinal,
                pre_challenge_epoch.epoch,
            ),
            (second_logical_verifier_move_ordinal, main_epoch.epoch),
        ] {
            let verifier_move = inputs
                .verifier_moves
                .get(usize::try_from(move_ordinal).unwrap())
                .filter(|verifier_move| verifier_move.ordinal == move_ordinal)
                .expect("shared-root query move exists at its canonical ordinal");
            assert!(verifier_move.role_coordinates.iter().any(|query_role| {
                (query_role.role_tag, query_role.epoch) == (11, expected_epoch)
            }));
        }
    }

    #[test]
    fn pre_challenge_whir_state_retires_only_after_its_last_bound_query() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact public-key contract");
        let inputs = contract.verifier_inputs();
        let [pre_challenge_epoch, _main_epoch] = inputs.whir_epochs else {
            panic!("the selected contract has two WHIR epochs")
        };
        let final_query_move_ordinal = inputs
            .verifier_moves
            .iter()
            .find(|verifier_move| {
                verifier_move
                    .role_coordinates
                    .iter()
                    .any(|role| role.role_tag == 11 && role.epoch == pre_challenge_epoch.epoch)
            })
            .expect("the pre-challenge final-query move exists")
            .ordinal;
        assert!(final_query_move_ordinal > 0);
        assert_eq!(
            require_pre_challenge_whir_response_state_retirement(
                &inputs,
                final_query_move_ordinal - 1,
            ),
            Err(CompactPublicKeyMainEpochPreparationError::WrongPhase),
        );
        require_pre_challenge_whir_response_state_retirement(&inputs, final_query_move_ordinal)
            .expect("every pre-challenge WHIR response has reached its last bound query");
    }

    #[test]
    fn final_query_capture_excludes_historical_components_in_the_same_response() {
        let contract = selected_compact_public_key_proof_contract()
            .expect("selected compact contract decodes");
        let inputs = contract.verifier_inputs();
        let final_query_move_ordinal = inputs
            .response_merkle_geometries
            .iter()
            .flat_map(CompactResponseMerkleGeometry::components)
            .find_map(|component| match component.query_selection() {
                CompactResponseQuerySelection::VerifierMessageDistinctGroupUnion {
                    first_logical_verifier_move_ordinal,
                    ..
                } => Some(first_logical_verifier_move_ordinal),
                CompactResponseQuerySelection::Unqueried
                | CompactResponseQuerySelection::EveryLeaf
                | CompactResponseQuerySelection::VerifierMessageDistinctGroup { .. } => None,
            })
            .expect("selected compact contract has the shared-root query union");
        let (response_geometry, historical_component, historical_move_ordinal) = inputs
            .response_merkle_geometries
            .iter()
            .find_map(|geometry| {
                let opens_at_final_query = geometry.components().iter().any(|component| {
                    matches!(
                        component.query_selection(),
                        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                            logical_verifier_move_ordinal,
                            ..
                        } if logical_verifier_move_ordinal == final_query_move_ordinal
                    )
                });
                if !opens_at_final_query {
                    return None;
                }
                geometry.components().iter().find_map(|component| {
                    let CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal,
                        ..
                    } = component.query_selection()
                    else {
                        return None;
                    };
                    (logical_verifier_move_ordinal < final_query_move_ordinal
                        && component.value_kind() == CompactResponseLeafValueKind::ExtensionField)
                        .then_some((geometry, component, logical_verifier_move_ordinal))
                })
            })
            .expect("one retained response mixes historical and final-query components");
        let leaf_ordinal = historical_component.first_leaf_ordinal();
        let field_element_count =
            usize::try_from(historical_component.field_element_count_per_leaf())
                .expect("historical response leaf width fits memory");
        let response_leaf = CompactOwnedResponseLeaf::extension_field(vec![
            crate::bgv::proof_suite::ProofChallengeExtensionElement::ZERO;
            field_element_count
        ]);

        assert!(matches!(
            compact_masking_query_leaf(
                inputs.response_merkle_geometries,
                final_query_move_ordinal,
                response_geometry.response_ordinal(),
                leaf_ordinal,
                &response_leaf,
            ),
            Ok(None)
        ));
        assert!(matches!(
            compact_masking_query_leaf(
                inputs.response_merkle_geometries,
                historical_move_ordinal,
                response_geometry.response_ordinal(),
                leaf_ordinal,
                &response_leaf,
            ),
            Ok(Some(_))
        ));
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
    fn retained_code_switch_source_rows_reproduce_delayed_merkle_leaves() {
        let previous_source_contract = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 0,
            message_length: 8,
            hiding_randomness_length: 2,
            block_length: 16,
            oracle_width: 2,
            query_count: 2,
            unique_decoding_radius: 2,
        };
        let next_source_contract = CompactWhirFoldContract {
            epoch: 1,
            batch_ordinal: 1,
            message_length: 4,
            hiding_randomness_length: 2,
            block_length: 8,
            oracle_width: 2,
            query_count: 2,
            unique_decoding_radius: 0,
        };
        let switch_mask_contract = CompactWhirMaskGroupContract {
            role_tag: 5,
            coordinate: 0,
            width: 1,
            message_length: 2,
            randomness_length: 2,
            domain_size: 16,
            committed_encoding_source: 0,
        };
        let source_evaluations = (0..8_u64)
            .map(|ordinal| CompactChallengeField::from_u64(ordinal * 17 + 3))
            .collect::<Vec<_>>();
        let previous_encoding_randomness = (0..4_u64)
            .map(|ordinal| CompactChallengeField::from_u64(ordinal * 19 + 5))
            .collect::<Vec<_>>();
        let mut random_source = SmallRng::seed_from_u64(0xC0_DE_51_17);
        let state = CompactWhirCodeSwitchState::new_from_extension_source(
            source_evaluations,
            previous_encoding_randomness,
            &[CompactChallengeField::from_u64(23)],
            previous_source_contract,
            next_source_contract,
            switch_mask_contract,
            &mut random_source,
        )
        .expect("the compact code switch starts");
        let mut code_switch = CompactPublicKeyWhirCodeSwitch::new(0, 7, state);
        while !matches!(
            code_switch
                .state
                .poll_preparation(8)
                .expect("the compact code-switch preparation advances"),
            CompactWhirCodeSwitchPreparationPoll::Complete
        ) {}
        let source_leaf_count =
            u64::try_from(code_switch.state.source_oracle().encoded_height()).unwrap();
        let mask_leaf_count = u64::try_from(
            code_switch
                .state
                .switch_mask_oracle()
                .expect("the prepared switch mask exists")
                .encoded_matrix()
                .height(),
        )
        .unwrap();
        code_switch.response_leaf_count = (source_leaf_count + mask_leaf_count).next_power_of_two();

        let retained_positions = [1_u64, 7];
        let mut original_retained_leaves = Vec::new();
        for leaf_ordinal in 0..source_leaf_count {
            loop {
                match code_switch
                    .poll_response_leaf(leaf_ordinal, 8)
                    .expect("the sequential code-switch response advances")
                {
                    CompactPublicKeyCodeSwitchResponseLeafPoll::ArithmeticStepCompleted {
                        ..
                    } => {}
                    CompactPublicKeyCodeSwitchResponseLeafPoll::LeafReady(leaf) => {
                        if retained_positions.contains(&leaf_ordinal) {
                            original_retained_leaves.push((leaf_ordinal, leaf));
                        }
                        code_switch
                            .mark_response_leaf_supplied(leaf_ordinal)
                            .expect("the sequential response row advances custody");
                        break;
                    }
                }
            }
        }
        code_switch
            .state
            .bind_verifier_move(
                &[1, 11],
                CompactChallengeField::from_u64(29),
                vec![CompactChallengeField::ZERO; 2],
            )
            .expect("the preceding-source verifier move binds");
        let _relation_inputs = code_switch
            .state
            .take_relation_inputs()
            .expect("the next relation takes its owned inputs");

        let opening_rows = retained_positions
            .iter()
            .copied()
            .map(|position| usize::try_from(position).unwrap())
            .collect::<Vec<_>>();
        code_switch
            .state
            .begin_source_opening_replay(&opening_rows)
            .expect("the delayed source replay starts");
        code_switch.retained_source_queries = Some(
            CompactPublicKeyRetainedSourceQueries::new(
                &retained_positions,
                code_switch.state.source_oracle().width(),
            )
            .expect("the retained source query cache derives"),
        );
        for row_ordinal in opening_rows {
            loop {
                match code_switch
                    .state
                    .poll_source_oracle(8)
                    .expect("the delayed source replay advances")
                {
                    CompactWhirRecomputableExtensionPoll::ArithmeticStepCompleted { .. } => {}
                    CompactWhirRecomputableExtensionPoll::StripeReady { .. } => {
                        let row = code_switch
                            .state
                            .source_row(row_ordinal)
                            .expect("the requested source row is ready");
                        code_switch
                            .retained_source_queries
                            .as_mut()
                            .expect("the retained source query cache exists")
                            .append_row(u64::try_from(row_ordinal).unwrap(), row)
                            .expect("the retained source row is ordered");
                        code_switch
                            .state
                            .mark_source_row_supplied(row_ordinal)
                            .expect("the delayed source row advances custody");
                        break;
                    }
                }
            }
        }
        code_switch
            .state
            .finish_source_opening_replay()
            .expect("the completed replay releases the full source");

        for (leaf_ordinal, original_leaf) in original_retained_leaves {
            assert_eq!(
                code_switch
                    .response_leaf(leaf_ordinal)
                    .expect("the retained row reproduces its committed leaf"),
                original_leaf
            );
        }
        assert_eq!(
            code_switch.response_leaf(2),
            Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry)
        );
        assert!(code_switch.response_leaf(source_leaf_count).is_ok());
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
