//! Pollable production materialization for the compact public-key family.
//!
//! This state owns the authenticated assignment loader, encodes and retains the
//! pre-challenge source before the lookup challenge, accepts that challenge
//! only through the exact compact transcript authority, performs the bounded
//! batch inversion, and prepares the production structured-row source. It does
//! not yet execute CFW or either complete WHIR epoch and therefore cannot emit
//! a proof or mint a workflow capability.

use std::rc::Rc;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;
use rand::{Rng, RngExt};

use crate::bgv::proof_suite::{
    ProofBaseFieldElement,
    compact_cfw::{
        COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwError, CompactCfwGeometry,
        CompactCfwMaskMaterial, CompactCfwMaskedCrossEpochClaims, CompactCfwPrefixEvaluationError,
        CompactCfwPrefixEvaluationState, CompactChallengeField, compact_challenge_from_production,
        compact_challenge_to_production,
    },
    compact_cfw_external_prover::{
        CompactCfwExternalProverExecutionError, CompactCfwExternalProverSetupError,
        CompactCfwExternalProverState,
    },
    compact_generation_randomness::{
        COMPACT_GENERATION_RANDOMNESS_CURSOR_BYTE_LENGTH, CompactGenerationAttemptRandomness,
        CompactGenerationRandomnessCursorError,
    },
    compact_masking_coefficient_maps::{
        CompactMaskingCoefficientMapError, derive_compact_masking_coefficient_map_certificate,
    },
    compact_masking_public_covector::{
        CompactFactorOnePublicCovectorAuthority, CompactFactorOnePublicCovectorError,
    },
    compact_proof_contract::{
        CompactProofContractError, CompactWhirEpochContract, CompactWhirMaskGroupContract,
        selected_compact_public_key_proof_contract,
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
        CompactWhirEncodedInitialOracle, CompactWhirEncodedMaskGroup, CompactWhirError,
        CompactWhirRecomputableExtensionError, CompactWhirRecomputableExtensionInitialOracle,
        CompactWhirRecomputableExtensionPoll, compact_whir_configuration_from_contract,
        compact_whir_mask_group_shape,
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
    MaskingPublicCovector(CompactFactorOnePublicCovectorError),
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

impl From<CompactFactorOnePublicCovectorError> for CompactPublicKeyMainEpochPreparationError {
    fn from(error: CompactFactorOnePublicCovectorError) -> Self {
        Self::MaskingPublicCovector(error)
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
pub(crate) enum CompactPublicKeyMainEpochPollError<StorageError> {
    Preparation(CompactPublicKeyMainEpochPreparationError),
    ResponseGeneration(CompactResponseGenerationError),
    ResponsePoll(CompactResponseGenerationPollError<StorageError>),
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
    cross_epoch_point: Option<Vec<CompactChallengeField>>,
    cross_epoch_evaluation_state: Option<CompactCfwPrefixEvaluationState>,
    cross_epoch_claims: Option<CompactCfwMaskedCrossEpochClaims>,
    cross_epoch_response_leaf_count: u64,
    cfw_external_prover: Option<CompactCfwExternalProverState>,
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
        validate_production_masking_inputs(&self.family_material)?;
        self.post_lookup_material = Some(prepare_post_lookup_material(&mut self.family_material)?);
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
                    post_lookup_material
                        .prepare_cross_epoch_evaluation(family_material, cross_epoch_point)
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
    pub(crate) fn cfw_prover_auxiliary_target(&self) -> Option<CompactChallengeField> {
        Some(
            self.post_lookup_material
                .as_ref()?
                .cfw_external_prover
                .as_ref()?
                .auxiliary_target(),
        )
    }

    pub(crate) fn advance_current_cfw_round_polynomial<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        Option<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
        CompactCfwExternalProverExecutionError<Storage::Error>,
    > {
        let Self {
            family_material,
            post_lookup_material,
            ..
        } = self;
        post_lookup_material
            .as_mut()
            .and_then(|material| material.cfw_external_prover.as_mut())
            .ok_or(CompactCfwExternalProverExecutionError::Cfw(
                CompactCfwError::WrongProverPhase,
            ))?
            .advance_round_polynomial(&family_material.row_source, storage)
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
) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
    let contract = selected_compact_public_key_proof_contract()?;
    let verifier_inputs = contract.verifier_inputs();
    let contract_source_hash = verifier_inputs.canonical_source_hash()?.into_bytes();
    if verifier_inputs.relation != family_material.relation()
        || contract_source_hash != family_material.compact_construction_identity_hash()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    drop(derive_compact_masking_coefficient_map_certificate(
        contract.verifier_inputs(),
    )?);
    let _public_covector_authority =
        CompactFactorOnePublicCovectorAuthority::from_canonical_public_input(
            contract.verifier_inputs(),
            family_material.public_input_bindings(),
            family_material.canonical_public_input_bytes(),
            family_material.decoded_public_input(),
        )?;
    Ok(())
}

impl CompactPublicKeyPostLookupMaterial {
    fn prepare_cross_epoch_evaluation(
        &mut self,
        family_material: &CompactPublicKeyFamilyMaterial,
        point: Vec<CompactChallengeField>,
    ) -> Result<(), CompactPublicKeyMainEpochPreparationError> {
        if self.cross_epoch_point.is_some()
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
        let evaluation_state =
            CompactCfwPrefixEvaluationState::new(&point, copied_source_element_count)?;
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
        if self.cfw_external_prover.is_some()
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
        self.cfw_external_prover = Some(prover);
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
    let cfw_auxiliary_target = cfw_mask_material.auxiliary_target(cfw_geometry)?;
    let inner_mask_messages = copy_mask_messages(cfw_mask_material.inner_masks())?;
    let inner_mask_encoding_randomness = sample_mask_encoding_randomness(
        randomness.whir_random_source_mut(),
        inner_mask_shape.width,
        inner_mask_shape.shape.randomness_len,
    )?;
    let inner_mask_oracle = CompactWhirEncodedMaskGroup::encode(
        inner_mask_shape,
        &inner_mask_messages,
        &inner_mask_encoding_randomness,
    )?;
    let main_source_oracle = CompactWhirRecomputableExtensionInitialOracle::sample(
        &main_configuration,
        randomness.whir_random_source_mut(),
    )?;
    if main_source_oracle.source_element_count() != witness_length {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    let outer_mask_messages = copy_mask_messages(cfw_mask_material.outer_masks())?;
    let outer_mask_encoding_randomness = sample_mask_encoding_randomness(
        randomness.whir_random_source_mut(),
        outer_mask_shape.width,
        outer_mask_shape.shape.randomness_len,
    )?;
    let outer_mask_oracle = CompactWhirEncodedMaskGroup::encode(
        outer_mask_shape,
        &outer_mask_messages,
        &outer_mask_encoding_randomness,
    )?;
    let cross_epoch_masks = [
        randomness.whir_random_source_mut().random(),
        randomness.whir_random_source_mut().random(),
    ];
    let cross_epoch_mask_messages = vec![vec![cross_epoch_masks[0]], vec![cross_epoch_masks[1]]];
    let cross_epoch_mask_encoding_randomness = sample_mask_encoding_randomness(
        randomness.whir_random_source_mut(),
        cross_epoch_mask_shape.width,
        cross_epoch_mask_shape.shape.randomness_len,
    )?;
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
        cross_epoch_point: None,
        cross_epoch_evaluation_state: None,
        cross_epoch_claims: None,
        cross_epoch_response_leaf_count: cross_epoch_response_geometry.merkle_leaf_count(),
        cfw_external_prover: None,
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
        || material.cross_epoch_point.is_some()
        || material.cross_epoch_evaluation_state.is_some()
        || material.cross_epoch_claims.is_some()
        || material.cfw_external_prover.is_some()
    {
        return Err(CompactPublicKeyMainEpochPreparationError::InvalidGeometry);
    }
    Ok(())
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
