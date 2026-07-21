use super::super::verified_application_statement_hash;
#[cfg(test)]
use super::CompletedCommonProofGenerationResult;
use super::{
    BTreeMap, BTreeSet, BoundTreeConstructionKind, BoundedCommonProofByteSink,
    BoundedCommonProofByteSinkError, CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN,
    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH, CommonProofAuthenticatedSourceReadRequest,
    CommonProofAuxiliaryColumnSynthesisCursor, CommonProofBoundTreeLeafSaltRequest,
    CommonProofByteSink, CommonProofConstraintStreamQuotientBuilder, CommonProofEncodingError,
    CommonProofExternalMemoryRequirement, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPollResult, CommonProofMerkleMaterializer,
    CommonProofMerkleMaterializerProgress, CommonProofMerkleStoragePlan,
    CommonProofOpeningGeometry, CommonProofOpeningPrefetchProgress, CommonProofOpeningPrefetcher,
    CommonProofPreChallengeSourceCursor, CommonProofPreChallengeSourcePoll, CommonProofPrivacyMode,
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofQueryOpeningAbsorber,
    CommonProofQuotientComponentCursor, CommonProofQuotientConstraintTransformKey,
    CommonProofQuotientEvaluationProgress, CommonProofReplayPolynomialKey,
    CommonProofReplayPolynomialPlan, CommonProofReplayPolynomialReader,
    CommonProofReplayPolynomialRef, CommonProofReplayPolynomialWriter,
    CommonProofResidentMemoryConfiguration, CommonProofResidentMemoryPhase,
    CommonProofResidentMemoryPlan, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofSourcePolynomialRequestContext,
    CommonProofTranscript, CommonProofTranscriptSchedule, CommonProofTreeStorageError,
    CompleteProofTreeCatalog, ExternalPolynomialValue, ExternalPolynomialVector,
    ExternalStockhamTransform, ExternalStockhamTransformError, ExternalStockhamTransformPlan,
    ExternalStockhamTransformProgress, GeneratedCommonProofStoragePlanError, HASH_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, PrefetchedCommonProofOpeningArtifact,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain,
    ProofExternalMemory, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
    ProofExternalMemoryUsage, ProofTreeCatalogEntry, ProofTreeCatalogInput, ProofTreeCatalogSource,
    ProofTreeRole, ProofTreeValue, RelationApplicationChallengeAssignment, RelationColumnOrigin,
    RelationColumnValueType, RelationPlanCheckContext, RelationPlanVariant,
    RelationTreeDescriptor,
    SetupPolynomialColumnMajorMerkleReplay, SetupPolynomialColumnMajorMerkleReplayMode,
    SetupPolynomialColumnMajorMerkleRootPass, StatementOwnedMerkleReplay,
    StatementOwnedMerkleReplayMode, StoredCommonProofMerkleTree, StreamingHash512,
    ValidatedRelationPlanArtifact, Zeroizing, add_replay_polynomial_to_initial_fri,
    build_complete_proof_tree_catalog, canonical_common_proof_query_section_header,
    canonical_proof_object_header_bytes, common_proof_query_section_byte_length,
    common_proof_resident_memory_plan, construct_opening_batch_mask,
    construct_reversed_relation_column, encode_common_proof_query_tree_fragment, entry_leaf_count,
    evaluate_extension_at, evaluate_replay_polynomial_opening, extension_polynomial_degree,
    fold_extension_evaluations_in_place, generated_common_proof_storage_plan,
    insert_materialized_tree, map_external_polynomial_plan_error,
    map_private_coin_generation_error, proof_created_tree_roles_by_column,
    read_external_polynomial_base_values, read_external_polynomial_extension_values,
    read_external_polynomial_value, replay_polynomial_key_for_claim,
    sample_relation_application_challenges, statement_owned_tree_root, trim_extension_polynomial,
    unique_catalog_entry, validate_generation_relation_trees, write_common_proof_prefix,
};

const SETUP_POLYNOMIAL_COLUMN_REPLAY_BINDING_DOMAIN: &str =
    "sealed-lattice/common-proof/setup-polynomial-column-replay-binding/v1";

pub(crate) fn common_proof_source_provider_is_live_during_phase(
    phase: CommonProofResidentMemoryPhase,
) -> bool {
    matches!(
        phase,
        CommonProofResidentMemoryPhase::LoadingSourcePolynomials
            | CommonProofResidentMemoryPhase::ConstructingReversedColumns
            | CommonProofResidentMemoryPhase::TransformingBaseColumns
            | CommonProofResidentMemoryPhase::MaterializingBaseTrees
            | CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns
            | CommonProofResidentMemoryPhase::TransformingAuxiliaryColumns
            | CommonProofResidentMemoryPhase::MaterializingAuxiliaryTrees
            | CommonProofResidentMemoryPhase::ConstructingQuotient
            | CommonProofResidentMemoryPhase::MaterializingQuotientTrees
            | CommonProofResidentMemoryPhase::DerivingOpenings
            | CommonProofResidentMemoryPhase::ConstructingInitialFri
            | CommonProofResidentMemoryPhase::FoldingFri
            | CommonProofResidentMemoryPhase::PreparingQueryOutput
            | CommonProofResidentMemoryPhase::EmittingQueries
    )
}

fn enforce_source_provider_resident_memory_bound(
    resident_memory_plan: &CommonProofResidentMemoryPlan,
    source_polynomial_provider: &dyn CommonProofSourcePolynomialProvider,
) -> Result<u64, CommonProofProverError> {
    let provider_accounting = source_polynomial_provider.memory_accounting()?;
    let loading_phase = resident_memory_plan
        .phases()
        .iter()
        .find(|phase| phase.phase() == CommonProofResidentMemoryPhase::LoadingSourcePolynomials)
        .ok_or(CommonProofProverError::ResidentMemoryLimitExceeded)?;
    if loading_phase.relation_polynomial_working_set_byte_length()
        < provider_accounting.maximum_returned_source_polynomial_byte_length()
    {
        return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
    }
    let mut maximum_combined_resident_byte_length = 0_u64;
    for phase in resident_memory_plan
        .phases()
        .iter()
        .filter(|phase| common_proof_source_provider_is_live_during_phase(phase.phase()))
    {
        let (provider_persistent_byte_length, provider_transient_byte_length) = if phase.phase()
            == CommonProofResidentMemoryPhase::LoadingSourcePolynomials
        {
            (
                provider_accounting.loading_persistent_resident_byte_length(),
                provider_accounting.additional_loading_transient_byte_length(),
            )
        } else {
            (
                provider_accounting.post_source_polynomial_finish_persistent_resident_byte_length(),
                0,
            )
        };
        let combined_byte_length = phase
            .total_byte_length()
            .checked_add(provider_persistent_byte_length)
            .and_then(|length| length.checked_add(provider_transient_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if combined_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
            return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
        }
        maximum_combined_resident_byte_length =
            maximum_combined_resident_byte_length.max(combined_byte_length);
    }
    Ok(maximum_combined_resident_byte_length)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CommonProofGenerationStage {
    PreparingInputs = 1,
    MaterializingBaseTrees = 2,
    DerivingApplicationColumns = 3,
    MaterializingAuxiliaryTrees = 4,
    ConstructingQuotient = 5,
    MaterializingQuotientTrees = 6,
    DerivingDeepOpenings = 7,
    MaterializingOpeningMask = 8,
    FoldingFri = 9,
    EmittingPrefix = 10,
    EmittingQueries = 11,
    Finalizing = 12,
    Complete = 13,
    Cancelled = 14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationPoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    OutputFragmentAccepted,
    Complete,
}

/// One replayable commitment-round boundary. The ordinal is the fixed order
/// used by the runtime-build checkpoint profile. The committed-state digest is
/// recomputed from the exact phase position and every tree-root slot; it is
/// evidence for deterministic reconstruction, not a producer-supplied
/// acceptance field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofGenerationCheckpointBoundary {
    safe_boundary_ordinal: u32,
    position: [u8; 16],
    committed_state_digest: [u8; HASH_BYTE_LENGTH],
}

impl CommonProofGenerationCheckpointBoundary {
    pub(crate) const fn safe_boundary_ordinal(self) -> u32 {
        self.safe_boundary_ordinal
    }

    pub(crate) const fn position(self) -> [u8; 16] {
        self.position
    }

    pub(crate) const fn committed_state_digest(self) -> [u8; HASH_BYTE_LENGTH] {
        self.committed_state_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofGenerationPhase {
    PreparingInputs,
    LoadingPreChallengeSources,
    DerivingReversedColumns {
        next_binding_index: usize,
    },
    ConstructingReversedColumn {
        source_column_ordinal: u32,
        reversed_column_ordinal: u32,
        next_binding_index: usize,
    },
    TransformingBaseColumns {
        next_column_index: usize,
    },
    MaterializingBaseTrees {
        next_tree_index: usize,
    },
    DerivingApplicationColumns,
    DerivingAuxiliaryColumns,
    TransformingAuxiliaryColumns {
        next_column_index: usize,
    },
    MaterializingAuxiliaryTrees {
        next_tree_index: usize,
    },
    ConstructingQuotient,
    ConstructingQuotientConstraints,
    CompletingQuotientConstraint,
    MaterializingQuotientTrees {
        next_component_index: usize,
    },
    DerivingDeepOpenings,
    EvaluatingDeepOpenings {
        next_claim_index: usize,
    },
    MaterializingOpeningMask,
    PreparingFri,
    ConstructingInitialFri {
        next_claim_index: usize,
    },
    FoldingFri {
        next_fold_ordinal: u16,
    },
    FinishingFri,
    EmittingPrefix,
    EmittingQueryHeader,
    EmittingQueries {
        next_catalog_index: usize,
    },
    Finalizing,
    Complete,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofTreeContinuation {
    Base {
        next_tree_index: usize,
    },
    Auxiliary {
        next_tree_index: usize,
        tree_ordinal: u16,
    },
    Quotient {
        next_component_index: usize,
        component_ordinal: u16,
    },
    OpeningMask,
    Fri {
        fold_ordinal: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayWriteContinuation {
    PreChallengeSource,
    ReversedColumn { next_binding_index: usize },
    AuxiliaryColumn,
    QuotientComponent,
    OpeningBatchMask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayReadContinuation {
    ReversedColumnSource {
        source_column_ordinal: u32,
        reversed_column_ordinal: u32,
        next_binding_index: usize,
    },
    AuxiliarySynthesisInput {
        column_ordinal: u32,
    },
    DeepOpening {
        claim_index: usize,
    },
    OpeningBatchMaskTree,
    OpeningBatchMaskFri,
    InitialFriClaim {
        claim_index: usize,
    },
}

struct ActiveCommonProofReplayPolynomialWriter {
    key: CommonProofReplayPolynomialKey,
    writer: CommonProofReplayPolynomialWriter,
    continuation: CommonProofReplayWriteContinuation,
}

struct ActiveCommonProofReplayPolynomialReader {
    reader: CommonProofReplayPolynomialReader,
    continuation: CommonProofReplayReadContinuation,
}

struct ActiveRelationColumnTransform {
    column_ordinal: u32,
    transform: ExternalStockhamTransform,
    continuation: CommonProofRelationTransformContinuation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofRelationTransformContinuation {
    Base {
        next_column_index: usize,
    },
    Auxiliary {
        next_column_index: usize,
    },
    Quotient {
        transform_key: CommonProofQuotientConstraintTransformKey,
    },
    SetupPolynomialRoot {
        next_column_index: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupPolynomialColumnReaderPhase {
    ReadFirstHalf,
    ReadOppositeHalf,
    CompleteConsumeStep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupPolynomialColumnContinuation {
    Root {
        next_column_index: usize,
    },
    Query {
        catalog_index: usize,
        next_column_position: usize,
    },
}

struct ActiveSetupPolynomialColumnReader {
    vector: ExternalPolynomialVector,
    column_ordinal: u32,
    next_leaf_index: usize,
    first_half_values: Option<Zeroizing<Vec<ProofBaseFieldElement>>>,
    phase: SetupPolynomialColumnReaderPhase,
    continuation: SetupPolynomialColumnContinuation,
}

struct ActiveSetupPolynomialReplay {
    replay: SetupPolynomialColumnMajorMerkleReplay,
    catalog_index: usize,
    query_geometry: Option<CommonProofOpeningGeometry>,
}

struct ActiveRelationTreeLeafReader {
    leaf_index: usize,
    opposite_index: usize,
    column_ordinals: Vec<u32>,
    next_value_index: usize,
    first_values: Zeroizing<Vec<ProofTreeValue>>,
    opposite_values: Zeroizing<Vec<ProofTreeValue>>,
}

impl ActiveRelationTreeLeafReader {
    fn new(
        leaf_index: u64,
        evaluation_domain_size: usize,
        column_ordinals: Vec<u32>,
    ) -> Result<Self, CommonProofProverError> {
        if column_ordinals.is_empty() || evaluation_domain_size < 2 {
            return Err(CommonProofProverError::InvalidTree);
        }
        let leaf_index =
            usize::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        let opposite_index = leaf_index
            .checked_add(evaluation_domain_size / 2)
            .filter(|index| *index < evaluation_domain_size)
            .ok_or(CommonProofProverError::InvalidTree)?;
        let mut first_values = Zeroizing::new(Vec::new());
        first_values
            .try_reserve_exact(column_ordinals.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        let mut opposite_values = Zeroizing::new(Vec::new());
        opposite_values
            .try_reserve_exact(column_ordinals.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(Self {
            leaf_index,
            opposite_index,
            column_ordinals,
            next_value_index: 0,
            first_values,
            opposite_values,
        })
    }
}

struct ActiveCommonProofTreeMaterialization {
    materializer: CommonProofMerkleMaterializer,
    leaf_source: CommonProofTreeLeafSource,
    continuation: CommonProofTreeContinuation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatementOwnedReplayContinuation {
    Base {
        catalog_index: usize,
        next_tree_index: usize,
    },
    Query {
        catalog_index: usize,
        geometry: CommonProofOpeningGeometry,
    },
}

struct ActiveStatementOwnedReplay {
    replay: StatementOwnedMerkleReplay,
    column_ordinals: Option<Vec<u32>>,
    continuation: StatementOwnedReplayContinuation,
}

enum CommonProofTreeLeafSource {
    RelationColumns(Vec<u32>),
    QuotientComponent,
    OpeningBatchMask,
    FriEvaluations(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

type CommonProofPhasePairLeafValues = (
    Zeroizing<Vec<ProofTreeValue>>,
    Zeroizing<Vec<ProofTreeValue>>,
);

/// Persistent common prover state.  No storage yield restarts a transcript
/// round, re-samples private coins, or regenerates an already accepted output
/// fragment.  The browser owns the external-memory replay and output-chunk
/// acknowledgement loops; this state owns the cryptographic continuation.
pub(crate) struct CommonProofGenerationStateMachine {
    protocol_version: u16,
    suite_identifier: [u8; HASH_BYTE_LENGTH],
    application_statement_schema_identifier: u16,
    canonical_header_bytes: Vec<u8>,
    variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    transcript_schedule: CommonProofTranscriptSchedule,
    evaluation_domain: ProofEvaluationDomain,
    catalog: CompleteProofTreeCatalog,
    #[cfg(test)]
    resident_memory_plan: CommonProofResidentMemoryPlan,
    source_polynomial_provider: Option<Box<dyn CommonProofSourcePolynomialProvider>>,
    source_polynomial_request_context: CommonProofSourcePolynomialRequestContext,
    source_replay_identity_digest: [u8; HASH_BYTE_LENGTH],
    maximum_prefetched_query_byte_length: u64,
    maximum_output_fragment_byte_length: usize,
    storage_tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
    replay_polynomial_plans:
        BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayPolynomialPlan>,
    relation_evaluation_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
    quotient_constraint_transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, ExternalStockhamTransformPlan>,
    relation_evaluation_vectors: BTreeMap<u32, ExternalPolynomialVector>,
    external_memory_requirement: CommonProofExternalMemoryRequirement,
    executor: Option<ProofExternalMemoryExecutor>,
    terminal_external_memory_usage: Option<ProofExternalMemoryUsage>,
    phase: CommonProofGenerationPhase,
    active_tree_materialization: Option<ActiveCommonProofTreeMaterialization>,
    active_statement_owned_replay: Option<ActiveStatementOwnedReplay>,
    pending_tree_continuation: Option<CommonProofTreeContinuation>,
    active_replay_polynomial_writer: Option<ActiveCommonProofReplayPolynomialWriter>,
    active_replay_polynomial_reader: Option<ActiveCommonProofReplayPolynomialReader>,
    active_relation_column_transform: Option<ActiveRelationColumnTransform>,
    active_setup_polynomial_replay: Option<ActiveSetupPolynomialReplay>,
    active_setup_polynomial_column_reader: Option<ActiveSetupPolynomialColumnReader>,
    active_relation_tree_leaf_reader: Option<ActiveRelationTreeLeafReader>,
    pre_challenge_source_cursor: Option<CommonProofPreChallengeSourceCursor>,
    pending_authenticated_source_read: Option<CommonProofAuthenticatedSourceReadRequest>,
    auxiliary_column_synthesis_cursor: Option<CommonProofAuxiliaryColumnSynthesisCursor>,
    current_relation_column: Option<(u32, CommonProofSourcePolynomial)>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
    quotient_builder: Option<CommonProofConstraintStreamQuotientBuilder>,
    quotient_component_cursor: Option<CommonProofQuotientComponentCursor>,
    current_quotient_component: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    opening_points: Vec<ProofChallengeExtensionElement>,
    opening_batch_mask: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    deep_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_coefficients: Vec<ProofChallengeExtensionElement>,
    initial_fri_polynomial: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    fri_domain: Option<ProofEvaluationDomain>,
    fri_evaluations: Option<Zeroizing<Vec<ProofChallengeExtensionElement>>>,
    terminal_coefficients: Zeroizing<Vec<ProofChallengeExtensionElement>>,
    sorted_query_representatives: Vec<u64>,
    opening_geometries: Vec<CommonProofOpeningGeometry>,
    tree_roots: Vec<[u8; HASH_BYTE_LENGTH]>,
    root_present: Vec<bool>,
    setup_polynomial_root_passes: BTreeMap<u16, SetupPolynomialColumnMajorMerkleRootPass>,
    setup_polynomial_opening_artifacts: BTreeMap<u16, PrefetchedCommonProofOpeningArtifact>,
    stored_trees: BTreeMap<u16, StoredCommonProofMerkleTree>,
    transcript: Option<CommonProofTranscript>,
    query_opening_absorber: Option<CommonProofQueryOpeningAbsorber>,
    query_section_byte_length: Option<usize>,
    opening_prefetcher: Option<CommonProofOpeningPrefetcher>,
    pending_output_fragment: Option<Vec<u8>>,
}

impl CommonProofGenerationStateMachine {
    fn active_tree_leaf_values(
        &self,
        leaf_index: u64,
    ) -> Result<CommonProofPhasePairLeafValues, CommonProofProverError> {
        let leaf_index =
            usize::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
        let active = self
            .active_tree_materialization
            .as_ref()
            .ok_or(CommonProofProverError::InvalidTree)?;
        match &active.leaf_source {
            CommonProofTreeLeafSource::FriEvaluations(evaluations) => {
                if evaluations.len() < 2 || !evaluations.len().is_power_of_two() {
                    return Err(CommonProofProverError::InvalidFriLayer);
                }
                let opposite_index = leaf_index
                    .checked_add(evaluations.len() / 2)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                Ok((
                    Zeroizing::new(vec![ProofTreeValue::Extension(
                        *evaluations
                            .get(leaf_index)
                            .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    )]),
                    Zeroizing::new(vec![ProofTreeValue::Extension(
                        *evaluations
                            .get(opposite_index)
                            .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    )]),
                ))
            }
            leaf_source => {
                let opposite_index = leaf_index
                    .checked_add(self.evaluation_domain.size() / 2)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let first_point = self.evaluation_domain.point(leaf_index)?;
                let opposite_point = self.evaluation_domain.point(opposite_index)?;
                let mut first_values = Zeroizing::new(Vec::new());
                let mut opposite_values = Zeroizing::new(Vec::new());
                let row_width = match leaf_source {
                    CommonProofTreeLeafSource::RelationColumns(column_ordinals) => {
                        column_ordinals.len()
                    }
                    CommonProofTreeLeafSource::QuotientComponent
                    | CommonProofTreeLeafSource::OpeningBatchMask => 1,
                    CommonProofTreeLeafSource::FriEvaluations(_) => unreachable!(),
                };
                first_values
                    .try_reserve_exact(row_width)
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                opposite_values
                    .try_reserve_exact(row_width)
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                match leaf_source {
                    CommonProofTreeLeafSource::RelationColumns(column_ordinals) => {
                        let _ = column_ordinals;
                        return Err(CommonProofProverError::InvalidTree);
                    }
                    CommonProofTreeLeafSource::QuotientComponent => {
                        let coefficients = self
                            .current_quotient_component
                            .as_ref()
                            .ok_or(CommonProofProverError::InvalidQuotient)?;
                        first_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(first_point),
                        )));
                        opposite_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(opposite_point),
                        )));
                    }
                    CommonProofTreeLeafSource::OpeningBatchMask => {
                        let coefficients = self
                            .opening_batch_mask
                            .as_ref()
                            .ok_or(CommonProofProverError::InvalidMask)?;
                        first_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(first_point),
                        )));
                        opposite_values.push(ProofTreeValue::Extension(evaluate_extension_at(
                            coefficients,
                            ProofChallengeExtensionElement::from_base(opposite_point),
                        )));
                    }
                    CommonProofTreeLeafSource::FriEvaluations(_) => unreachable!(),
                }
                Ok((first_values, opposite_values))
            }
        }
    }

    fn poll_active_tree<Storage, Coins, SinkError>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, Coins::Error, SinkError>,
    >
    where
        Storage: ProofExternalMemory,
        Coins: CommonProofPrivateCoinSource,
    {
        let progress = {
            let executor = self
                .executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?;
            let active = self.active_tree_materialization.as_mut().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            active
                .materializer
                .advance_storage(executor, storage)
                .map_err(|error| match error {
                    CommonProofTreeStorageError::Prover(error) => {
                        CommonProofGenerationError::Prover(error)
                    }
                    CommonProofTreeStorageError::Storage(error) => {
                        CommonProofGenerationError::Storage(error)
                    }
                    CommonProofTreeStorageError::CoinSource(error) => match error {},
                })?
        };
        match progress {
            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted => {
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            CommonProofMerkleMaterializerProgress::NeedsLeafValues { leaf_index } => {
                let relation_column_ordinals =
                    self.active_tree_materialization
                        .as_ref()
                        .and_then(|active| match &active.leaf_source {
                            CommonProofTreeLeafSource::RelationColumns(column_ordinals) => {
                                Some(column_ordinals.clone())
                            }
                            _ => None,
                        });
                if let Some(column_ordinals) = relation_column_ordinals {
                    if self.active_relation_tree_leaf_reader.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.active_relation_tree_leaf_reader = Some(
                        ActiveRelationTreeLeafReader::new(
                            leaf_index,
                            self.evaluation_domain.size(),
                            column_ordinals,
                        )
                        .map_err(CommonProofGenerationError::Prover)?,
                    );
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let (first_values, opposite_values) = self
                    .active_tree_leaf_values(leaf_index)
                    .map_err(CommonProofGenerationError::Prover)?;
                let active = self.active_tree_materialization.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                active
                    .materializer
                    .supply_next_leaf(first_values, opposite_values, None, coins)
                    .map_err(|error| match error {
                        CommonProofTreeStorageError::Prover(error) => {
                            CommonProofGenerationError::Prover(error)
                        }
                        CommonProofTreeStorageError::Storage(error) => match error {
                            ProofExternalMemoryExecutorError::Execution(error) => {
                                CommonProofGenerationError::StoragePlan(error)
                            }
                            ProofExternalMemoryExecutorError::Storage(error)
                            | ProofExternalMemoryExecutorError::StorageCommit(error) => {
                                match error {}
                            }
                            ProofExternalMemoryExecutorError::StorageAbort {
                                operation_error,
                                ..
                            } => match operation_error {},
                        },
                        CommonProofTreeStorageError::CoinSource(error) => {
                            CommonProofGenerationError::CoinSource(error)
                        }
                    })?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofMerkleMaterializerProgress::Complete => {
                let ActiveCommonProofTreeMaterialization {
                    materializer,
                    leaf_source,
                    continuation,
                } = self.active_tree_materialization.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                let tree = materializer
                    .finish()
                    .map_err(CommonProofGenerationError::Prover)?;
                if let CommonProofTreeLeafSource::FriEvaluations(values) = leaf_source {
                    self.fri_evaluations = Some(values);
                }
                insert_materialized_tree(
                    tree,
                    &mut self.tree_roots,
                    &mut self.root_present,
                    &mut self.stored_trees,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                self.pending_tree_continuation = Some(continuation);
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
        }
    }

    fn poll_active_statement_owned_replay<StorageError, CoinError, SinkError>(
        &mut self,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<StorageError, CoinError, SinkError>,
    > {
        let next_leaf = self
            .active_statement_owned_replay
            .as_ref()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidTree,
            ))?
            .replay
            .next_leaf_index();
        if let Some(leaf_index) = next_leaf {
            if self.active_relation_tree_leaf_reader.is_some() {
                return Err(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
            let column_ordinals = self
                .active_statement_owned_replay
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?
                .column_ordinals
                .take()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
            self.active_relation_tree_leaf_reader = Some(
                ActiveRelationTreeLeafReader::new(
                    leaf_index,
                    self.evaluation_domain.size(),
                    column_ordinals,
                )
                .map_err(CommonProofGenerationError::Prover)?,
            );
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let active =
            self.active_statement_owned_replay
                .take()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
        match active.continuation {
            StatementOwnedReplayContinuation::Base {
                catalog_index,
                next_tree_index,
            } => {
                if active.replay.mode() != StatementOwnedMerkleReplayMode::RootPass
                    || active.column_ordinals.is_none()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                let root = active
                    .replay
                    .finish_root_pass()
                    .map_err(CommonProofGenerationError::Prover)?;
                if self.tree_roots.get(catalog_index).copied() != Some(root)
                    || self.root_present.get(catalog_index).copied() != Some(true)
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                self.pending_tree_continuation =
                    Some(CommonProofTreeContinuation::Base { next_tree_index });
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            StatementOwnedReplayContinuation::Query {
                catalog_index,
                geometry,
            } => {
                if active.replay.mode() != StatementOwnedMerkleReplayMode::OpeningPass
                    || active.column_ordinals.is_none()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                self.catalog.entries().get(catalog_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                let pass_one_root = self
                    .tree_roots
                    .get(catalog_index)
                    .copied()
                    .filter(|_| self.root_present.get(catalog_index).copied() == Some(true))
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ))?;
                let artifact = active
                    .replay
                    .finish_opening_pass(pass_one_root)
                    .map_err(CommonProofGenerationError::Prover)?;
                self.pending_output_fragment = Some(
                    encode_common_proof_query_tree_fragment(
                        &self.catalog,
                        catalog_index,
                        geometry,
                        &self.sorted_query_representatives,
                        &artifact,
                        self.maximum_output_fragment_byte_length,
                    )
                    .map_err(|error| match error {
                        CommonProofEncodingError::Prover(error) => {
                            CommonProofGenerationError::Prover(error)
                        }
                        CommonProofEncodingError::Sink(error) => map_bounded_fragment_error(error),
                        CommonProofEncodingError::Artifact(error) => {
                            CommonProofGenerationError::Prover(error)
                        }
                    })?,
                );
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
        }
    }

    pub(crate) fn new<'input>(
        input: CommonProofGenerationInput<'input>,
    ) -> Result<Self, CommonProofGenerationInitializationError> {
        let CommonProofGenerationInput {
            protocol_version,
            suite_identifier,
            canonical_application_statement_bytes,
            relation_plan,
            relation_context,
            schedule_position,
            top_count,
            relation_trees,
            source_polynomial_provider,
            maximum_external_memory_chunk_byte_length,
            maximum_proof_transport_chunk_byte_length,
            maximum_prefetched_query_byte_length,
        } = input;
        if maximum_prefetched_query_byte_length == 0
            || maximum_external_memory_chunk_byte_length
                != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || maximum_proof_transport_chunk_byte_length != MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        let validated_artifact =
            ValidatedRelationPlanArtifact::from_compiled_plan(relation_plan, relation_context)
                .map_err(CommonProofGenerationInitializationError::Profile)?;
        let canonical_header_bytes =
            canonical_proof_object_header_bytes(canonical_application_statement_bytes)
                .map_err(CommonProofGenerationInitializationError::Prover)?;
        let variant = relation_plan
            .select_variant(schedule_position, top_count)
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        let relation_plan_hash = relation_plan
            .canonical_hash()
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        let relation_plan_variant_hash = variant
            .canonical_hash()
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        let source_polynomial_request_context = CommonProofSourcePolynomialRequestContext::new(
            protocol_version,
            suite_identifier,
            validated_artifact.application_statement_schema_identifier(),
            verified_application_statement_hash(
                protocol_version,
                suite_identifier,
                validated_artifact.application_statement_schema_identifier(),
                canonical_application_statement_bytes,
            ),
            relation_plan_hash,
            relation_plan_variant_hash,
            schedule_position,
            top_count,
        );
        validate_generation_relation_trees(variant, &relation_trees)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        let transcript_schedule = variant
            .common_proof_transcript_schedule(relation_context)
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        let evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(variant.evaluation_domain_size()).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?,
            relation_context.evaluation_coset_offset,
        )
        .map_err(CommonProofProverError::from)
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        if evaluation_domain.generator().canonical() != relation_context.evaluation_domain_generator
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let catalog = build_complete_proof_tree_catalog(
            ProofTreeCatalogInput {
                suite_identifier,
                canonical_proof_object_header_bytes: canonical_header_bytes.clone(),
                application_statement_schema_identifier: validated_artifact
                    .application_statement_schema_identifier(),
                proof_field_index: 0,
                evaluation_domain_size: variant.evaluation_domain_size(),
                relation_trees: relation_trees.clone(),
            },
            &transcript_schedule,
        )
        .map_err(CommonProofGenerationInitializationError::Body)?;
        let storage_plan = generated_common_proof_storage_plan(
            variant,
            relation_context,
            &catalog,
            &transcript_schedule,
            maximum_external_memory_chunk_byte_length,
            true,
        )
        .map_err(|error| match error {
            GeneratedCommonProofStoragePlanError::Prover(error) => {
                CommonProofGenerationInitializationError::Prover(error)
            }
            GeneratedCommonProofStoragePlanError::Storage(error) => {
                CommonProofGenerationInitializationError::StoragePlan(error)
            }
        })?;
        if !storage_plan
            .setup_polynomial_query_transform_plans
            .is_empty()
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let resident_memory_plan = common_proof_resident_memory_plan(
            variant,
            relation_context,
            &transcript_schedule,
            &catalog,
            &storage_plan,
            CommonProofResidentMemoryConfiguration::new(
                validated_artifact.application_statement_schema_identifier(),
                u64::try_from(canonical_header_bytes.len()).map_err(|_| {
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                maximum_prefetched_query_byte_length,
                u64::from(maximum_external_memory_chunk_byte_length),
                u64::try_from(maximum_proof_transport_chunk_byte_length).map_err(|_| {
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
            ),
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        enforce_source_provider_resident_memory_bound(
            &resident_memory_plan,
            source_polynomial_provider.as_ref(),
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        let external_memory_requirement = storage_plan.external_memory_requirement;
        let executor = ProofExternalMemoryExecutor::new(storage_plan.external_memory_plan);
        let mut tree_roots = vec![[0_u8; HASH_BYTE_LENGTH]; catalog.entries().len()];
        let mut root_present = vec![false; catalog.entries().len()];
        for (tree_index, relation_tree) in relation_trees.iter().enumerate() {
            if let Some(root) = statement_owned_tree_root(relation_tree) {
                *tree_roots.get_mut(tree_index).ok_or(
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ),
                )? = root;
                *root_present.get_mut(tree_index).ok_or(
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ),
                )? = true;
            }
        }
        let application_challenge_assignment_count = transcript_schedule
            .ordered_application_challenge_groups()
            .iter()
            .try_fold(0_usize, |total, group| {
                total
                    .checked_add(usize::from(group.coordinate_count()))
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))
            })?;
        let mut application_challenges = Vec::new();
        application_challenges
            .try_reserve_exact(application_challenge_assignment_count)
            .map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::AllocationLimitExceeded,
                )
            })?;
        Ok(Self {
            protocol_version,
            suite_identifier,
            application_statement_schema_identifier: validated_artifact
                .application_statement_schema_identifier(),
            canonical_header_bytes,
            variant: variant.clone(),
            relation_context: relation_context.clone(),
            transcript_schedule,
            evaluation_domain,
            catalog,
            #[cfg(test)]
            resident_memory_plan,
            source_polynomial_provider: Some(source_polynomial_provider),
            source_polynomial_request_context,
            source_replay_identity_digest: [0_u8; HASH_BYTE_LENGTH],
            maximum_prefetched_query_byte_length,
            maximum_output_fragment_byte_length: maximum_proof_transport_chunk_byte_length,
            storage_tree_plans: storage_plan.tree_plans,
            replay_polynomial_plans: storage_plan.replay_polynomial_plans,
            relation_evaluation_transform_plans: storage_plan.relation_evaluation_transform_plans,
            quotient_constraint_transform_plans: storage_plan.quotient_constraint_transform_plans,
            relation_evaluation_vectors: BTreeMap::new(),
            external_memory_requirement,
            executor: Some(executor),
            terminal_external_memory_usage: None,
            phase: CommonProofGenerationPhase::PreparingInputs,
            active_tree_materialization: None,
            active_statement_owned_replay: None,
            pending_tree_continuation: None,
            active_replay_polynomial_writer: None,
            active_replay_polynomial_reader: None,
            active_relation_column_transform: None,
            active_setup_polynomial_replay: None,
            active_setup_polynomial_column_reader: None,
            active_relation_tree_leaf_reader: None,
            pre_challenge_source_cursor: None,
            pending_authenticated_source_read: None,
            auxiliary_column_synthesis_cursor: None,
            current_relation_column: None,
            application_challenges,
            quotient_builder: None,
            quotient_component_cursor: None,
            current_quotient_component: None,
            opening_points: Vec::new(),
            opening_batch_mask: None,
            deep_evaluations: Vec::new(),
            opening_batch_coefficients: Vec::new(),
            initial_fri_polynomial: None,
            fri_domain: None,
            fri_evaluations: None,
            terminal_coefficients: Zeroizing::new(Vec::new()),
            sorted_query_representatives: Vec::new(),
            opening_geometries: Vec::new(),
            tree_roots,
            root_present,
            setup_polynomial_root_passes: BTreeMap::new(),
            setup_polynomial_opening_artifacts: BTreeMap::new(),
            stored_trees: BTreeMap::new(),
            transcript: None,
            query_opening_absorber: None,
            query_section_byte_length: None,
            opening_prefetcher: None,
            pending_output_fragment: None,
        })
    }

    pub(crate) const fn stage(&self) -> CommonProofGenerationStage {
        match self.phase {
            CommonProofGenerationPhase::PreparingInputs
            | CommonProofGenerationPhase::LoadingPreChallengeSources
            | CommonProofGenerationPhase::DerivingReversedColumns { .. }
            | CommonProofGenerationPhase::ConstructingReversedColumn { .. }
            | CommonProofGenerationPhase::TransformingBaseColumns { .. } => {
                CommonProofGenerationStage::PreparingInputs
            }
            CommonProofGenerationPhase::MaterializingBaseTrees { .. } => {
                CommonProofGenerationStage::MaterializingBaseTrees
            }
            CommonProofGenerationPhase::DerivingApplicationColumns => {
                CommonProofGenerationStage::DerivingApplicationColumns
            }
            CommonProofGenerationPhase::DerivingAuxiliaryColumns
            | CommonProofGenerationPhase::TransformingAuxiliaryColumns { .. } => {
                CommonProofGenerationStage::DerivingApplicationColumns
            }
            CommonProofGenerationPhase::MaterializingAuxiliaryTrees { .. } => {
                CommonProofGenerationStage::MaterializingAuxiliaryTrees
            }
            CommonProofGenerationPhase::ConstructingQuotient
            | CommonProofGenerationPhase::ConstructingQuotientConstraints
            | CommonProofGenerationPhase::CompletingQuotientConstraint => {
                CommonProofGenerationStage::ConstructingQuotient
            }
            CommonProofGenerationPhase::MaterializingQuotientTrees { .. } => {
                CommonProofGenerationStage::MaterializingQuotientTrees
            }
            CommonProofGenerationPhase::DerivingDeepOpenings => {
                CommonProofGenerationStage::DerivingDeepOpenings
            }
            CommonProofGenerationPhase::EvaluatingDeepOpenings { .. } => {
                CommonProofGenerationStage::DerivingDeepOpenings
            }
            CommonProofGenerationPhase::MaterializingOpeningMask => {
                CommonProofGenerationStage::MaterializingOpeningMask
            }
            CommonProofGenerationPhase::PreparingFri
            | CommonProofGenerationPhase::ConstructingInitialFri { .. }
            | CommonProofGenerationPhase::FoldingFri { .. }
            | CommonProofGenerationPhase::FinishingFri => CommonProofGenerationStage::FoldingFri,
            CommonProofGenerationPhase::EmittingPrefix => {
                CommonProofGenerationStage::EmittingPrefix
            }
            CommonProofGenerationPhase::EmittingQueryHeader
            | CommonProofGenerationPhase::EmittingQueries { .. } => {
                CommonProofGenerationStage::EmittingQueries
            }
            CommonProofGenerationPhase::Finalizing => CommonProofGenerationStage::Finalizing,
            CommonProofGenerationPhase::Complete => CommonProofGenerationStage::Complete,
            CommonProofGenerationPhase::Cancelled => CommonProofGenerationStage::Cancelled,
        }
    }

    #[cfg(test)]
    pub(crate) const fn resident_memory_plan(&self) -> &CommonProofResidentMemoryPlan {
        &self.resident_memory_plan
    }

    pub(crate) const fn external_memory_requirement(&self) -> CommonProofExternalMemoryRequirement {
        self.external_memory_requirement
    }

    pub(crate) fn external_memory_usage(&self) -> Option<ProofExternalMemoryUsage> {
        self.terminal_external_memory_usage.or_else(|| {
            self.executor
                .as_ref()
                .map(ProofExternalMemoryExecutor::usage)
        })
    }

    pub(crate) const fn terminal_external_memory_usage(&self) -> Option<ProofExternalMemoryUsage> {
        self.terminal_external_memory_usage
    }

    pub(crate) const fn pending_authenticated_source_read(
        &self,
    ) -> Option<CommonProofAuthenticatedSourceReadRequest> {
        self.pending_authenticated_source_read
    }

    pub(crate) fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        if self.phase != CommonProofGenerationPhase::LoadingPreChallengeSources
            || self.pending_authenticated_source_read != Some(request)
            || authenticated_bytes.len()
                != usize::try_from(request.source_byte_length())
                    .map_err(|_| CommonProofProverError::CountOverflow)?
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.source_polynomial_provider
            .as_deref_mut()
            .ok_or(CommonProofProverError::InvalidInput)?
            .supply_authenticated_source_range(request, authenticated_bytes)?;
        self.pending_authenticated_source_read = None;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn resident_payload_is_empty(&self) -> bool {
        self.source_polynomial_provider.is_none()
            && self.active_tree_materialization.is_none()
            && self.active_statement_owned_replay.is_none()
            && self.pending_tree_continuation.is_none()
            && self.active_replay_polynomial_writer.is_none()
            && self.active_replay_polynomial_reader.is_none()
            && self.active_relation_column_transform.is_none()
            && self.active_setup_polynomial_replay.is_none()
            && self.active_setup_polynomial_column_reader.is_none()
            && self.active_relation_tree_leaf_reader.is_none()
            && self.pre_challenge_source_cursor.is_none()
            && self.pending_authenticated_source_read.is_none()
            && self.auxiliary_column_synthesis_cursor.is_none()
            && self.current_relation_column.is_none()
            && self.application_challenges.is_empty()
            && self.quotient_builder.is_none()
            && self.quotient_component_cursor.is_none()
            && self.current_quotient_component.is_none()
            && self.opening_points.is_empty()
            && self.opening_batch_mask.is_none()
            && self.deep_evaluations.is_empty()
            && self.opening_batch_coefficients.is_empty()
            && self.initial_fri_polynomial.is_none()
            && self.fri_domain.is_none()
            && self.fri_evaluations.is_none()
            && self.terminal_coefficients.is_empty()
            && self.sorted_query_representatives.is_empty()
            && self.opening_geometries.is_empty()
            && self.storage_tree_plans.is_empty()
            && self.replay_polynomial_plans.is_empty()
            && self.relation_evaluation_transform_plans.is_empty()
            && self.quotient_constraint_transform_plans.is_empty()
            && self.relation_evaluation_vectors.is_empty()
            && self.stored_trees.is_empty()
            && self.tree_roots.is_empty()
            && self.root_present.is_empty()
            && self.setup_polynomial_root_passes.is_empty()
            && self.setup_polynomial_opening_artifacts.is_empty()
            && self.transcript.is_none()
            && self.query_opening_absorber.is_none()
            && self.query_section_byte_length.is_none()
            && self.opening_prefetcher.is_none()
            && self.pending_output_fragment.is_none()
            && self.canonical_header_bytes.is_empty()
            && self.executor.is_none()
    }

    pub(crate) fn checkpoint_boundary(&self) -> Option<CommonProofGenerationCheckpointBoundary> {
        // Only completed proof commitment rounds are durable boundaries. In
        // particular, an internal polynomial pass is not independently
        // verifiable proof state even when its scratch object is sealed.
        // Prefix and query extraction are one uncheckpointed output
        // transaction, so no boundary exists after any proof byte is staged.
        if self.active_tree_materialization.is_some()
            || self.active_statement_owned_replay.is_some()
            || self.pending_tree_continuation.is_some()
            || self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_relation_column_transform.is_some()
            || self.active_setup_polynomial_replay.is_some()
            || self.active_setup_polynomial_column_reader.is_some()
            || self.active_relation_tree_leaf_reader.is_some()
            || self.pending_authenticated_source_read.is_some()
            || self.opening_prefetcher.is_some()
            || self.pending_output_fragment.is_some()
        {
            return None;
        }

        let (safe_boundary_ordinal, phase_tag, phase_ordinal) = match self.phase {
            CommonProofGenerationPhase::DerivingApplicationColumns => (1, 1, 0),
            CommonProofGenerationPhase::ConstructingQuotient => (2, 2, 0),
            CommonProofGenerationPhase::DerivingDeepOpenings => (3, 3, 0),
            CommonProofGenerationPhase::PreparingFri => (4, 4, 0),
            CommonProofGenerationPhase::FoldingFri { next_fold_ordinal }
                if next_fold_ordinal > 0
                    && next_fold_ordinal < self.transcript_schedule.fri_fold_count() =>
            {
                (
                    u32::from(next_fold_ordinal).checked_add(4)?,
                    5,
                    u32::from(next_fold_ordinal),
                )
            }
            _ => return None,
        };
        let mut position = [0_u8; 16];
        position[0] = phase_tag;
        position[4..8].copy_from_slice(&safe_boundary_ordinal.to_le_bytes());
        position[8..12].copy_from_slice(&phase_ordinal.to_le_bytes());

        let root_state_byte_length = self.root_present.len().checked_mul(1 + HASH_BYTE_LENGTH)?;
        let mut hasher = StreamingHash512::new(CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN, 3);
        hasher.absorb_part(&position);
        hasher.absorb_part(&self.source_replay_identity_digest);
        hasher.begin_part(u64::try_from(root_state_byte_length).ok()?);
        for (present, root) in self.root_present.iter().zip(&self.tree_roots) {
            hasher.absorb_raw(&[u8::from(*present)]);
            hasher.absorb_raw(root);
        }
        Some(CommonProofGenerationCheckpointBoundary {
            safe_boundary_ordinal,
            position,
            committed_state_digest: hasher.finalize(),
        })
    }

    fn setup_polynomial_replay_binding(
        &self,
    ) -> Result<[u8; HASH_BYTE_LENGTH], CommonProofProverError> {
        if self.source_replay_identity_digest == [0_u8; HASH_BYTE_LENGTH] {
            return Err(CommonProofProverError::InvalidInput);
        }
        let mut hasher = StreamingHash512::new(SETUP_POLYNOMIAL_COLUMN_REPLAY_BINDING_DOMAIN, 3);
        hasher.absorb_part(
            &self
                .source_polynomial_request_context
                .stable_generation_binding_hash(),
        );
        hasher.absorb_part(&self.source_replay_identity_digest);
        hasher.absorb_part(&self.canonical_header_bytes);
        let binding = hasher.finalize();
        if binding == [0_u8; HASH_BYTE_LENGTH] {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(binding)
    }

    fn setup_polynomial_tree_for_column(
        &self,
        column_ordinal: u32,
    ) -> Result<Option<(usize, usize)>, CommonProofProverError> {
        let mut matched_tree = None;
        for (catalog_index, descriptor) in self.variant.ordered_trees().iter().enumerate() {
            let RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            } = descriptor
            else {
                continue;
            };
            let Some(column_position) = ordered_column_ordinals
                .iter()
                .position(|candidate| *candidate == column_ordinal)
            else {
                continue;
            };
            let entry = self
                .catalog
                .entries()
                .get(catalog_index)
                .ok_or(CommonProofProverError::InvalidTree)?;
            if entry.setup_polynomial_construction().is_none()
                || entry.bound_root().is_none()
                || entry.uses_common_merkle_context()
                || matched_tree.is_some()
            {
                return Err(CommonProofProverError::InvalidTree);
            }
            matched_tree = Some((catalog_index, column_position));
        }
        Ok(matched_tree)
    }

    fn prepare_setup_polynomial_query_column_reader(
        &mut self,
        catalog_index: usize,
        column_position: usize,
    ) -> Result<(), CommonProofGenerationInitializationError> {
        if self.active_relation_column_transform.is_some()
            || self.active_setup_polynomial_column_reader.is_some()
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let column_ordinal = {
            let active = self.active_setup_polynomial_replay.as_ref().ok_or(
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidTree,
                ),
            )?;
            let column_ordinal = active
                .replay
                .ordered_column_ordinals()
                .get(column_position)
                .copied()
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            if active.catalog_index != catalog_index
                || active.query_geometry.is_none()
                || active.replay.mode() != SetupPolynomialColumnMajorMerkleReplayMode::OpeningPass
                || active.replay.next_column_ordinal() != Some(column_ordinal)
            {
                return Err(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
            column_ordinal
        };
        let vector = self
            .relation_evaluation_vectors
            .get(&column_ordinal)
            .copied()
            .ok_or(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        if vector.value_type() != RelationColumnValueType::Base
            || vector.element_count() != self.evaluation_domain.size()
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let next_column_position = column_position.checked_add(1).ok_or(
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow),
        )?;
        self.active_setup_polynomial_column_reader = Some(ActiveSetupPolynomialColumnReader {
            vector,
            column_ordinal,
            next_leaf_index: 0,
            first_half_values: None,
            phase: SetupPolynomialColumnReaderPhase::ReadFirstHalf,
            continuation: SetupPolynomialColumnContinuation::Query {
                catalog_index,
                next_column_position,
            },
        });
        Ok(())
    }

    fn prepare_next_setup_polynomial_opening_replay(
        &mut self,
    ) -> Result<bool, CommonProofGenerationInitializationError> {
        if self.active_setup_polynomial_replay.is_some()
            || self.active_setup_polynomial_column_reader.is_some()
            || self.active_relation_column_transform.is_some()
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        if self
            .setup_polynomial_opening_artifacts
            .keys()
            .any(|tree_catalog_index| {
                !self
                    .setup_polynomial_root_passes
                    .contains_key(tree_catalog_index)
            })
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let Some(tree_catalog_index) = self
            .setup_polynomial_root_passes
            .keys()
            .find(|tree_catalog_index| {
                !self
                    .setup_polynomial_opening_artifacts
                    .contains_key(tree_catalog_index)
            })
            .copied()
        else {
            return Ok(false);
        };
        let catalog_index = usize::from(tree_catalog_index);
        let entry = self.catalog.entries().get(catalog_index).ok_or(
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::InvalidTree),
        )?;
        let ordered_column_ordinals = match self.variant.ordered_trees().get(catalog_index) {
            Some(RelationTreeDescriptor::BoundPublic {
                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                ordered_column_ordinals,
                ..
            }) => ordered_column_ordinals.as_slice(),
            _ => {
                return Err(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
        };
        if ordered_column_ordinals.is_empty()
            || entry.tree_catalog_index() != tree_catalog_index
            || entry.setup_polynomial_construction().is_none()
            || entry.bound_root().is_none()
            || entry.uses_common_merkle_context()
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let geometry = *self.opening_geometries.get(catalog_index).ok_or(
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::InvalidTree),
        )?;
        let replay_binding = self
            .setup_polynomial_replay_binding()
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        let replay = SetupPolynomialColumnMajorMerkleReplay::new_opening_pass(
            entry,
            self.catalog.evaluation_domain_size(),
            ordered_column_ordinals,
            replay_binding,
            self.setup_polynomial_root_passes
                .get(&tree_catalog_index)
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?,
            &self.sorted_query_representatives,
            self.maximum_prefetched_query_byte_length,
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        if replay
            .memory_accounting()
            .map_err(CommonProofGenerationInitializationError::Prover)?
            .wasm_total_resident_owned_byte_length()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::ResidentMemoryLimitExceeded,
            ));
        }
        self.active_setup_polynomial_replay = Some(ActiveSetupPolynomialReplay {
            replay,
            catalog_index,
            query_geometry: Some(geometry),
        });
        self.prepare_setup_polynomial_query_column_reader(catalog_index, 0)?;
        Ok(true)
    }

    fn statement_owned_query_column_ordinals(
        &self,
    ) -> Result<BTreeSet<u32>, CommonProofProverError> {
        let mut column_ordinals = BTreeSet::new();
        for (tree_index, descriptor) in self.variant.ordered_trees().iter().enumerate() {
            let entry = self
                .catalog
                .entries()
                .get(tree_index)
                .ok_or(CommonProofProverError::InvalidTree)?;
            if entry.bound_root().is_none() || entry.uses_common_merkle_context() {
                continue;
            }
            let RelationTreeDescriptor::BoundPublic {
                ordered_column_ordinals,
                ..
            } = descriptor
            else {
                return Err(CommonProofProverError::InvalidTree);
            };
            column_ordinals.extend(ordered_column_ordinals.iter().copied());
        }
        Ok(column_ordinals)
    }

    fn quotient_column_ordinals(&self) -> Result<BTreeSet<u32>, CommonProofProverError> {
        let mut column_ordinals = BTreeSet::new();
        for constraint_ordinal in 0..self.variant.constraint_count() {
            column_ordinals.extend(
                self.variant
                    .constraint_column_queries(constraint_ordinal)?
                    .iter()
                    .map(|query| query.column_ordinal()),
            );
        }
        Ok(column_ordinals)
    }

    fn poll_active_relation_column_transform<Storage, CoinError, SinkError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let progress = {
            let executor = self
                .executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?;
            let active = self.active_relation_column_transform.as_mut().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
            )?;
            active
                .transform
                .advance(executor, storage)
                .map_err(|error| match error {
                    ExternalStockhamTransformError::Polynomial(error) => {
                        CommonProofGenerationError::StoragePlan(map_external_polynomial_plan_error(
                            error,
                        ))
                    }
                    ExternalStockhamTransformError::Storage(error) => {
                        CommonProofGenerationError::Storage(error)
                    }
                })?
        };
        match progress {
            ExternalStockhamTransformProgress::ArithmeticStepCompleted => {
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            ExternalStockhamTransformProgress::StorageTransactionCompleted
            | ExternalStockhamTransformProgress::PassCommitted(_) => {
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            ExternalStockhamTransformProgress::Complete(vector) => {
                let active = self.active_relation_column_transform.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?;
                self.phase = match active.continuation {
                    CommonProofRelationTransformContinuation::Base { next_column_index } => {
                        if self
                            .relation_evaluation_vectors
                            .insert(active.column_ordinal, vector)
                            .is_some()
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ));
                        }
                        CommonProofGenerationPhase::TransformingBaseColumns { next_column_index }
                    }
                    CommonProofRelationTransformContinuation::Auxiliary { next_column_index } => {
                        if self
                            .relation_evaluation_vectors
                            .insert(active.column_ordinal, vector)
                            .is_some()
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ));
                        }
                        CommonProofGenerationPhase::TransformingAuxiliaryColumns {
                            next_column_index,
                        }
                    }
                    CommonProofRelationTransformContinuation::Quotient { transform_key } => {
                        if active.column_ordinal != transform_key.column_ordinal() {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ));
                        }
                        self.quotient_builder
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ))?
                            .accept_transformed_column(transform_key, vector)
                            .map_err(CommonProofGenerationError::Prover)?;
                        CommonProofGenerationPhase::ConstructingQuotientConstraints
                    }
                    CommonProofRelationTransformContinuation::SetupPolynomialRoot {
                        next_column_index,
                    } => {
                        if self.active_setup_polynomial_column_reader.is_some()
                            || self
                                .relation_evaluation_vectors
                                .insert(active.column_ordinal, vector)
                                .is_some()
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ));
                        }
                        self.active_setup_polynomial_column_reader =
                            Some(ActiveSetupPolynomialColumnReader {
                                vector,
                                column_ordinal: active.column_ordinal,
                                next_leaf_index: 0,
                                first_half_values: None,
                                phase: SetupPolynomialColumnReaderPhase::ReadFirstHalf,
                                continuation: SetupPolynomialColumnContinuation::Root {
                                    next_column_index,
                                },
                            });
                        self.phase
                    }
                };
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
        }
    }

    fn poll_active_setup_polynomial_column_reader<Storage, CoinError, SinkError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let leaf_count = self.evaluation_domain.size() / 2;
        let maximum_element_count = usize::try_from(
            self.external_memory_requirement.maximum_chunk_byte_length()
                / u32::try_from(core::mem::size_of::<u64>()).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?,
        )
        .map_err(|_| CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow))?;
        if leaf_count == 0 || maximum_element_count == 0 {
            return Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let reader_phase = self
            .active_setup_polynomial_column_reader
            .as_ref()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?
            .phase;
        match reader_phase {
            SetupPolynomialColumnReaderPhase::ReadFirstHalf => {
                let (vector, element_offset, element_count) = {
                    let reader = self.active_setup_polynomial_column_reader.as_ref().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                    )?;
                    if reader.first_half_values.is_some() || reader.next_leaf_index >= leaf_count {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    (
                        reader.vector,
                        reader.next_leaf_index,
                        maximum_element_count.min(leaf_count - reader.next_leaf_index),
                    )
                };
                let values = read_external_polynomial_base_values(
                    self.executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?,
                    storage,
                    vector,
                    element_offset,
                    element_count,
                )
                .map_err(|error| match error {
                    ExternalStockhamTransformError::Polynomial(error) => {
                        CommonProofGenerationError::StoragePlan(map_external_polynomial_plan_error(
                            error,
                        ))
                    }
                    ExternalStockhamTransformError::Storage(error) => {
                        CommonProofGenerationError::Storage(error)
                    }
                })?;
                let reader = self.active_setup_polynomial_column_reader.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?;
                reader.first_half_values = Some(values);
                reader.phase = SetupPolynomialColumnReaderPhase::ReadOppositeHalf;
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            SetupPolynomialColumnReaderPhase::ReadOppositeHalf => {
                let (vector, column_ordinal, first_leaf_index, first_half_value_count) = {
                    let reader = self.active_setup_polynomial_column_reader.as_ref().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                    )?;
                    let first_half_value_count = reader
                        .first_half_values
                        .as_ref()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?
                        .len();
                    (
                        reader.vector,
                        reader.column_ordinal,
                        reader.next_leaf_index,
                        first_half_value_count,
                    )
                };
                let opposite_offset = leaf_count.checked_add(first_leaf_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow),
                )?;
                let opposite_half_values = read_external_polynomial_base_values(
                    self.executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?,
                    storage,
                    vector,
                    opposite_offset,
                    first_half_value_count,
                )
                .map_err(|error| match error {
                    ExternalStockhamTransformError::Polynomial(error) => {
                        CommonProofGenerationError::StoragePlan(map_external_polynomial_plan_error(
                            error,
                        ))
                    }
                    ExternalStockhamTransformError::Storage(error) => {
                        CommonProofGenerationError::Storage(error)
                    }
                })?;
                let first_half_values = self
                    .active_setup_polynomial_column_reader
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .first_half_values
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                self.active_setup_polynomial_replay
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ))?
                    .replay
                    .supply_next_column_chunk(
                        column_ordinal,
                        first_leaf_index,
                        &first_half_values,
                        &opposite_half_values,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                let next_leaf_index = first_leaf_index
                    .checked_add(first_half_values.len())
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                let reader = self.active_setup_polynomial_column_reader.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?;
                reader.next_leaf_index = next_leaf_index;
                reader.phase = if next_leaf_index == leaf_count {
                    SetupPolynomialColumnReaderPhase::CompleteConsumeStep
                } else {
                    SetupPolynomialColumnReaderPhase::ReadFirstHalf
                };
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            SetupPolynomialColumnReaderPhase::CompleteConsumeStep => {
                {
                    let reader = self.active_setup_polynomial_column_reader.as_ref().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                    )?;
                    if reader.next_leaf_index != leaf_count || reader.first_half_values.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                }
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .complete_step(storage)
                    .map_err(CommonProofGenerationError::Storage)?;
                let reader = self.active_setup_polynomial_column_reader.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?;
                match reader.continuation {
                    SetupPolynomialColumnContinuation::Root { next_column_index } => {
                        let replay_complete = self
                            .active_setup_polynomial_replay
                            .as_ref()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidTree,
                            ))?
                            .replay
                            .next_column_ordinal()
                            .is_none();
                        if replay_complete {
                            let active = self.active_setup_polynomial_replay.take().ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ),
                            )?;
                            if active.query_geometry.is_some()
                                || active.replay.mode()
                                    != SetupPolynomialColumnMajorMerkleReplayMode::RootPass
                            {
                                return Err(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ));
                            }
                            let root_pass = active
                                .replay
                                .finish_root_pass()
                                .map_err(CommonProofGenerationError::Prover)?;
                            let tree_catalog_index = root_pass.tree_catalog_index();
                            let catalog_index = usize::from(tree_catalog_index);
                            if catalog_index != active.catalog_index
                                || self.tree_roots.get(catalog_index).copied()
                                    != Some(root_pass.root())
                                || self.root_present.get(catalog_index).copied() != Some(true)
                                || self
                                    .setup_polynomial_root_passes
                                    .insert(tree_catalog_index, root_pass)
                                    .is_some()
                            {
                                return Err(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ));
                            }
                        }
                        self.phase = CommonProofGenerationPhase::TransformingBaseColumns {
                            next_column_index,
                        };
                    }
                    SetupPolynomialColumnContinuation::Query {
                        catalog_index,
                        next_column_position,
                    } => {
                        let next_column_ordinal = self
                            .active_setup_polynomial_replay
                            .as_ref()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidTree,
                            ))?
                            .replay
                            .next_column_ordinal();
                        if next_column_ordinal.is_some() {
                            self.prepare_setup_polynomial_query_column_reader(
                                catalog_index,
                                next_column_position,
                            )
                            .map_err(map_generation_initialization_error)?;
                        } else {
                            let active = self.active_setup_polynomial_replay.take().ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ),
                            )?;
                            if active.catalog_index != catalog_index
                                || active.query_geometry.is_none()
                                || active.replay.mode()
                                    != SetupPolynomialColumnMajorMerkleReplayMode::OpeningPass
                            {
                                return Err(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ));
                            }
                            let tree_catalog_index = self
                                .catalog
                                .entries()
                                .get(catalog_index)
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ))?
                                .tree_catalog_index();
                            let artifact = active
                                .replay
                                .finish_opening_pass(
                                    self.setup_polynomial_root_passes
                                        .get(&tree_catalog_index)
                                        .ok_or(CommonProofGenerationError::Prover(
                                            CommonProofProverError::InvalidTree,
                                        ))?,
                                )
                                .map_err(CommonProofGenerationError::Prover)?;
                            if self
                                .setup_polynomial_opening_artifacts
                                .insert(tree_catalog_index, artifact)
                                .is_some()
                            {
                                return Err(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ));
                            }
                        }
                    }
                }
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
        }
    }

    fn poll_active_relation_tree_leaf_reader<Storage, Coins, SinkError>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, Coins::Error, SinkError>,
    >
    where
        Storage: ProofExternalMemory,
        Coins: CommonProofPrivateCoinSource,
    {
        let is_complete = {
            let reader = self.active_relation_tree_leaf_reader.as_ref().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            reader.next_value_index
                >= reader.column_ordinals.len().checked_mul(2).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow),
                )?
        };
        if is_complete {
            let reader = self.active_relation_tree_leaf_reader.take().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            if let Some(tree_catalog_index) = self
                .active_statement_owned_replay
                .as_ref()
                .map(|active| active.replay.tree_catalog_index())
            {
                let persistent_leaf_salt = self
                    .bound_tree_leaf_salt(tree_catalog_index, reader.leaf_index)
                    .map_err(CommonProofGenerationError::Prover)?;
                let ActiveRelationTreeLeafReader {
                    column_ordinals,
                    first_values,
                    opposite_values,
                    ..
                } = reader;
                let active = self.active_statement_owned_replay.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                let replay_result = active.replay.supply_next_leaf_with_persistent_salt(
                    persistent_leaf_salt,
                    first_values,
                    opposite_values,
                );
                active.column_ordinals = Some(column_ordinals);
                replay_result.map_err(CommonProofGenerationError::Prover)?;
                return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
            }
            let tree_catalog_index = self
                .active_tree_materialization
                .as_ref()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?
                .materializer
                .tree_catalog_index();
            let persistent_leaf_salt = self
                .bound_tree_leaf_salt(tree_catalog_index, reader.leaf_index)
                .map_err(CommonProofGenerationError::Prover)?;
            self.active_tree_materialization
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?
                .materializer
                .supply_next_leaf(
                    reader.first_values,
                    reader.opposite_values,
                    persistent_leaf_salt,
                    coins,
                )
                .map_err(|error| match error {
                    CommonProofTreeStorageError::Prover(error) => {
                        CommonProofGenerationError::Prover(error)
                    }
                    CommonProofTreeStorageError::Storage(error) => match error {
                        ProofExternalMemoryExecutorError::Execution(error) => {
                            CommonProofGenerationError::StoragePlan(error)
                        }
                        ProofExternalMemoryExecutorError::Storage(error)
                        | ProofExternalMemoryExecutorError::StorageCommit(error) => match error {},
                        ProofExternalMemoryExecutorError::StorageAbort {
                            operation_error, ..
                        } => match operation_error {},
                    },
                    CommonProofTreeStorageError::CoinSource(error) => {
                        CommonProofGenerationError::CoinSource(error)
                    }
                })?;
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let (column_ordinal, element_index, is_opposite) = {
            let reader = self.active_relation_tree_leaf_reader.as_ref().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
            )?;
            let row_width = reader.column_ordinals.len();
            let is_opposite = reader.next_value_index >= row_width;
            let column_index = reader.next_value_index % row_width;
            (
                *reader.column_ordinals.get(column_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?,
                if is_opposite {
                    reader.opposite_index
                } else {
                    reader.leaf_index
                },
                is_opposite,
            )
        };
        let vector = self
            .relation_evaluation_vectors
            .get(&column_ordinal)
            .copied()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        let value = read_external_polynomial_value(
            self.executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?,
            storage,
            vector,
            element_index,
        )
        .map_err(|error| match error {
            ExternalStockhamTransformError::Polynomial(error) => {
                CommonProofGenerationError::StoragePlan(map_external_polynomial_plan_error(error))
            }
            ExternalStockhamTransformError::Storage(error) => {
                CommonProofGenerationError::Storage(error)
            }
        })?;
        let tree_value = match value {
            ExternalPolynomialValue::Base(value) => ProofTreeValue::Base(value),
            ExternalPolynomialValue::Extension(value) => ProofTreeValue::Extension(value),
        };
        let reader = self.active_relation_tree_leaf_reader.as_mut().ok_or(
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
        )?;
        if is_opposite {
            reader.opposite_values.push(tree_value);
        } else {
            reader.first_values.push(tree_value);
        }
        reader.next_value_index =
            reader
                .next_value_index
                .checked_add(1)
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
    }

    fn bound_tree_leaf_salt(
        &mut self,
        tree_catalog_index: u16,
        leaf_index: usize,
    ) -> Result<Option<[u8; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]>, CommonProofProverError>
    {
        let entry = self
            .catalog
            .entries()
            .get(usize::from(tree_catalog_index))
            .ok_or(CommonProofProverError::InvalidTree)?;
        if !entry.requires_persistent_leaf_salt() {
            return Ok(None);
        }
        let expected_root = entry
            .bound_root()
            .ok_or(CommonProofProverError::InvalidTree)?;
        self.source_polynomial_provider
            .as_deref_mut()
            .ok_or(CommonProofProverError::InvalidInput)?
            .provide_bound_tree_leaf_salt(CommonProofBoundTreeLeafSaltRequest::new(
                self.source_polynomial_request_context,
                tree_catalog_index,
                u64::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?,
                expected_root,
            ))
    }

    fn prepare_replay_polynomial_writer(
        &mut self,
        key: CommonProofReplayPolynomialKey,
        continuation: CommonProofReplayWriteContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_tree_materialization.is_some()
            || self.active_statement_owned_replay.is_some()
            || self.pending_tree_continuation.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let plan = self
            .replay_polynomial_plans
            .get(&key)
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let polynomial = match key {
            CommonProofReplayPolynomialKey::RelationColumn(column_ordinal) => {
                CommonProofReplayPolynomialRef::Source(
                    self.current_relation_column
                        .as_ref()
                        .filter(|(current_column_ordinal, _)| {
                            *current_column_ordinal == column_ordinal
                        })
                        .map(|(_, polynomial)| polynomial)
                        .ok_or(CommonProofProverError::InvalidColumn)?,
                )
            }
            CommonProofReplayPolynomialKey::QuotientComponent(_) => {
                CommonProofReplayPolynomialRef::Extension(
                    self.current_quotient_component
                        .as_deref()
                        .ok_or(CommonProofProverError::InvalidQuotient)?,
                )
            }
            CommonProofReplayPolynomialKey::OpeningBatchMask => {
                CommonProofReplayPolynomialRef::Extension(
                    self.opening_batch_mask
                        .as_deref()
                        .ok_or(CommonProofProverError::InvalidMask)?,
                )
            }
        };
        let writer = CommonProofReplayPolynomialWriter::new(plan, polynomial)?;
        self.active_replay_polynomial_writer = Some(ActiveCommonProofReplayPolynomialWriter {
            key,
            writer,
            continuation,
        });
        Ok(())
    }

    fn prepare_replay_polynomial_reader(
        &mut self,
        key: CommonProofReplayPolynomialKey,
        continuation: CommonProofReplayReadContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_tree_materialization.is_some()
            || self.active_statement_owned_replay.is_some()
            || self.pending_tree_continuation.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let plan = self
            .replay_polynomial_plans
            .get(&key)
            .copied()
            .ok_or(CommonProofProverError::InvalidInput)?;
        self.active_replay_polynomial_reader = Some(ActiveCommonProofReplayPolynomialReader {
            reader: CommonProofReplayPolynomialReader::new(plan)?,
            continuation,
        });
        Ok(())
    }

    fn poll_active_replay_polynomial_writer<Storage, CoinError, SinkError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let key = self
            .active_replay_polynomial_writer
            .as_ref()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ))?
            .key;
        let polynomial = match key {
            CommonProofReplayPolynomialKey::RelationColumn(column_ordinal) => {
                CommonProofReplayPolynomialRef::Source(
                    self.current_relation_column
                        .as_ref()
                        .filter(|(current_column_ordinal, _)| {
                            *current_column_ordinal == column_ordinal
                        })
                        .map(|(_, polynomial)| polynomial)
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?,
                )
            }
            CommonProofReplayPolynomialKey::QuotientComponent(_) => {
                CommonProofReplayPolynomialRef::Extension(
                    self.current_quotient_component.as_deref().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient),
                    )?,
                )
            }
            CommonProofReplayPolynomialKey::OpeningBatchMask => {
                CommonProofReplayPolynomialRef::Extension(
                    self.opening_batch_mask.as_deref().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidMask),
                    )?,
                )
            }
        };
        let active = self.active_replay_polynomial_writer.as_mut().ok_or(
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
        )?;
        let completed = active
            .writer
            .advance(
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?,
                storage,
                polynomial,
            )
            .map_err(CommonProofGenerationError::Storage)?;
        if completed {
            let continuation = self
                .active_replay_polynomial_writer
                .take()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?
                .continuation;
            match continuation {
                CommonProofReplayWriteContinuation::PreChallengeSource => {
                    self.current_relation_column = None;
                    self.phase = CommonProofGenerationPhase::LoadingPreChallengeSources;
                }
                CommonProofReplayWriteContinuation::ReversedColumn { next_binding_index } => {
                    self.current_relation_column = None;
                    self.phase =
                        CommonProofGenerationPhase::DerivingReversedColumns { next_binding_index };
                }
                CommonProofReplayWriteContinuation::AuxiliaryColumn => {
                    self.current_relation_column = None;
                    self.phase = CommonProofGenerationPhase::DerivingAuxiliaryColumns;
                }
                CommonProofReplayWriteContinuation::QuotientComponent => {}
                CommonProofReplayWriteContinuation::OpeningBatchMask => {
                    self.opening_batch_mask = None;
                    self.phase = CommonProofGenerationPhase::EvaluatingDeepOpenings {
                        next_claim_index: 0,
                    };
                }
            }
        }
        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
    }

    fn apply_replay_polynomial_read_continuation(
        &mut self,
        continuation: CommonProofReplayReadContinuation,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        match continuation {
            CommonProofReplayReadContinuation::ReversedColumnSource {
                source_column_ordinal,
                reversed_column_ordinal,
                next_binding_index,
            } => {
                if self.current_relation_column.is_some() {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                self.current_relation_column = Some((source_column_ordinal, polynomial));
                self.phase = CommonProofGenerationPhase::ConstructingReversedColumn {
                    source_column_ordinal,
                    reversed_column_ordinal,
                    next_binding_index,
                };
            }
            CommonProofReplayReadContinuation::AuxiliarySynthesisInput { column_ordinal } => {
                self.auxiliary_column_synthesis_cursor
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidColumn)?
                    .accept_input_column(column_ordinal, polynomial)?;
                self.phase = CommonProofGenerationPhase::DerivingAuxiliaryColumns;
            }
            CommonProofReplayReadContinuation::DeepOpening { claim_index } => {
                let claim = *self
                    .variant
                    .ordered_opening_claims()
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let opening_point = self
                    .opening_points
                    .get(
                        usize::try_from(claim.opening_point_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .copied()
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                self.deep_evaluations
                    .push(evaluate_replay_polynomial_opening(
                        &claim,
                        &polynomial,
                        opening_point,
                    )?);
                self.phase = CommonProofGenerationPhase::EvaluatingDeepOpenings {
                    next_claim_index: claim_index
                        .checked_add(1)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                };
            }
            CommonProofReplayReadContinuation::OpeningBatchMaskTree => {
                let CommonProofSourcePolynomial::Extension(coefficients) = polynomial else {
                    return Err(CommonProofProverError::InvalidMask);
                };
                self.opening_batch_mask = Some(coefficients);
                self.phase = CommonProofGenerationPhase::MaterializingOpeningMask;
            }
            CommonProofReplayReadContinuation::OpeningBatchMaskFri => {
                let CommonProofSourcePolynomial::Extension(coefficients) = polynomial else {
                    return Err(CommonProofProverError::InvalidMask);
                };
                let initial = self
                    .initial_fri_polynomial
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidFriLayer)?;
                if coefficients.len() > initial.len() {
                    return Err(CommonProofProverError::InvalidMask);
                }
                for (destination, coefficient) in
                    initial.iter_mut().zip(coefficients.iter().copied())
                {
                    *destination = destination.add(coefficient);
                }
                self.phase = CommonProofGenerationPhase::ConstructingInitialFri {
                    next_claim_index: 0,
                };
            }
            CommonProofReplayReadContinuation::InitialFriClaim { claim_index } => {
                let claim = *self
                    .variant
                    .ordered_opening_claims()
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let opening_point = self
                    .opening_points
                    .get(
                        usize::try_from(claim.opening_point_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .copied()
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let deep_evaluation = *self
                    .deep_evaluations
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                let batching_coefficient = *self
                    .opening_batch_coefficients
                    .get(claim_index)
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                add_replay_polynomial_to_initial_fri(
                    self.initial_fri_polynomial
                        .as_mut()
                        .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    usize::try_from(self.variant.opening_degree_bound_exclusive())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                    &claim,
                    polynomial,
                    opening_point,
                    deep_evaluation,
                    batching_coefficient,
                )?;
                self.phase = CommonProofGenerationPhase::ConstructingInitialFri {
                    next_claim_index: claim_index
                        .checked_add(1)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                };
            }
        }
        Ok(())
    }

    fn poll_active_replay_polynomial_reader<Storage, CoinError, SinkError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError>,
    >
    where
        Storage: ProofExternalMemory,
    {
        let completed = self
            .active_replay_polynomial_reader
            .as_mut()
            .ok_or(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ))?
            .reader
            .advance(
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?,
                storage,
            )
            .map_err(CommonProofGenerationError::Storage)?;
        if completed {
            let active = self.active_replay_polynomial_reader.take().ok_or(
                CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
            )?;
            let polynomial = active
                .reader
                .finish()
                .map_err(CommonProofGenerationError::Prover)?;
            self.apply_replay_polynomial_read_continuation(active.continuation, polynomial)
                .map_err(CommonProofGenerationError::Prover)?;
            Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
        } else {
            Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
        }
    }

    fn prepare_tree_materialization(
        &mut self,
        catalog_index: usize,
        leaf_source: CommonProofTreeLeafSource,
        continuation: CommonProofTreeContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_tree_materialization.is_some()
            || self.active_statement_owned_replay.is_some()
            || self.pending_tree_continuation.is_some()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let current_step = self
            .executor
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?
            .current_step();
        let entry = self
            .catalog
            .entries()
            .get(catalog_index)
            .ok_or(CommonProofProverError::InvalidTree)?;
        if entry.bound_root().is_some() && !entry.uses_common_merkle_context() {
            let CommonProofTreeLeafSource::RelationColumns(column_ordinals) = leaf_source else {
                return Err(CommonProofProverError::InvalidTree);
            };
            let CommonProofTreeContinuation::Base { next_tree_index } = continuation else {
                return Err(CommonProofProverError::InvalidTree);
            };
            if entry.setup_polynomial_construction().is_some() {
                let root_pass = self
                    .setup_polynomial_root_passes
                    .get(&entry.tree_catalog_index())
                    .ok_or(CommonProofProverError::InvalidTree)?;
                if root_pass.root()
                    != entry
                        .bound_root()
                        .ok_or(CommonProofProverError::InvalidTree)?
                    || self.tree_roots.get(catalog_index).copied() != Some(root_pass.root())
                    || self.root_present.get(catalog_index).copied() != Some(true)
                {
                    return Err(CommonProofProverError::InvalidTree);
                }
                self.pending_tree_continuation =
                    Some(CommonProofTreeContinuation::Base { next_tree_index });
                return Ok(());
            }
            let replay = StatementOwnedMerkleReplay::new_root_pass(
                entry,
                self.catalog.evaluation_domain_size(),
            )?;
            self.active_statement_owned_replay = Some(ActiveStatementOwnedReplay {
                replay,
                column_ordinals: Some(column_ordinals),
                continuation: StatementOwnedReplayContinuation::Base {
                    catalog_index,
                    next_tree_index,
                },
            });
            return Ok(());
        }
        let tree_plan = self
            .storage_tree_plans
            .remove(&entry.tree_catalog_index())
            .ok_or(CommonProofProverError::InvalidTree)?;
        let issued_step = tree_plan
            .object_plans()
            .first()
            .map(|plan| plan.issued_step())
            .ok_or(CommonProofProverError::InvalidTree)?;
        if current_step != issued_step {
            return Err(CommonProofProverError::InvalidTree);
        }
        let materializer = CommonProofMerkleMaterializer::new(
            entry,
            self.catalog.evaluation_domain_size(),
            tree_plan,
        )?;
        self.active_tree_materialization = Some(ActiveCommonProofTreeMaterialization {
            materializer,
            leaf_source,
            continuation,
        });
        Ok(())
    }

    fn apply_tree_continuation(
        &mut self,
        continuation: CommonProofTreeContinuation,
    ) -> Result<(), CommonProofGenerationInitializationError> {
        match continuation {
            CommonProofTreeContinuation::Base { next_tree_index } => {
                self.phase = CommonProofGenerationPhase::MaterializingBaseTrees { next_tree_index };
            }
            CommonProofTreeContinuation::Auxiliary {
                next_tree_index,
                tree_ordinal,
            } => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source
                        == ProofTreeCatalogSource::RelationProofCreated {
                            tree_role: ProofTreeRole::AuxiliaryOracle,
                            tree_ordinal,
                        }
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_auxiliary_root(
                        tree_ordinal,
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.phase =
                    CommonProofGenerationPhase::MaterializingAuxiliaryTrees { next_tree_index };
            }
            CommonProofTreeContinuation::Quotient {
                next_component_index,
                component_ordinal,
            } => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_quotient_root(
                        component_ordinal,
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.current_quotient_component = None;
                self.phase = CommonProofGenerationPhase::MaterializingQuotientTrees {
                    next_component_index,
                };
            }
            CommonProofTreeContinuation::OpeningMask => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::OpeningBatchMask
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_opening_batch_mask_root(
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.opening_batch_mask = None;
                self.phase = CommonProofGenerationPhase::PreparingFri;
            }
            CommonProofTreeContinuation::Fri { fold_ordinal } => {
                let entry = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::NonterminalFriLayer { fold_ordinal }
                })
                .map_err(CommonProofGenerationInitializationError::Prover)?;
                self.transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb_fri_layer_root(
                        fold_ordinal,
                        self.tree_roots[usize::from(entry.tree_catalog_index())],
                    )
                    .map_err(CommonProofGenerationInitializationError::Transcript)?;
                self.phase = CommonProofGenerationPhase::FoldingFri {
                    next_fold_ordinal: fold_ordinal.checked_add(1).ok_or(
                        CommonProofGenerationInitializationError::Prover(
                            CommonProofProverError::CountOverflow,
                        ),
                    )?,
                };
            }
        }
        Ok(())
    }

    pub(crate) fn poll<Storage, Coins, Sink>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
        sink: &mut Sink,
    ) -> CommonProofGenerationPollResult<Storage::Error, Coins::Error, Sink::Error>
    where
        Storage: ProofExternalMemory,
        Coins: CommonProofPrivateCoinSource,
        Sink: CommonProofByteSink,
    {
        if self.phase == CommonProofGenerationPhase::Cancelled {
            return Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        if self.phase == CommonProofGenerationPhase::Complete {
            return Ok(CommonProofGenerationPoll::Complete);
        }
        if let Some(continuation) = self.pending_tree_continuation {
            self.executor
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?
                .complete_step(storage)
                .map_err(CommonProofGenerationError::Storage)?;
            self.pending_tree_continuation = None;
            self.apply_tree_continuation(continuation)
                .map_err(map_generation_initialization_error)?;
            return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
        }
        if self.active_setup_polynomial_column_reader.is_some() {
            return self.poll_active_setup_polynomial_column_reader(storage);
        }
        if self.active_relation_tree_leaf_reader.is_some() {
            return self.poll_active_relation_tree_leaf_reader(storage, coins);
        }
        if self.active_statement_owned_replay.is_some() {
            return self.poll_active_statement_owned_replay();
        }
        if self.active_tree_materialization.is_some() {
            return self.poll_active_tree(storage, coins);
        }
        if self.active_replay_polynomial_writer.is_some() {
            return self.poll_active_replay_polynomial_writer(storage);
        }
        if self.active_replay_polynomial_reader.is_some() {
            return self.poll_active_replay_polynomial_reader(storage);
        }
        if self.active_relation_column_transform.is_some() {
            return self.poll_active_relation_column_transform(storage);
        }

        match self.phase {
            CommonProofGenerationPhase::PreparingInputs => {
                let mut opening_geometries = Vec::new();
                opening_geometries
                    .try_reserve_exact(self.catalog.entries().len())
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                for entry in self.catalog.entries() {
                    if let Some(tree_plan) =
                        self.storage_tree_plans.get(&entry.tree_catalog_index())
                    {
                        let leaf_count =
                            entry_leaf_count(entry, self.catalog.evaluation_domain_size())
                                .map_err(|_| {
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::InvalidTree,
                                    )
                                })?;
                        opening_geometries.push(CommonProofOpeningGeometry {
                            tree_catalog_index: entry.tree_catalog_index(),
                            leaf_count,
                            canonical_leaf_byte_length: tree_plan.canonical_leaf_byte_length(),
                        });
                    } else if entry.bound_root().is_some() && !entry.uses_common_merkle_context() {
                        opening_geometries.push(CommonProofOpeningGeometry {
                            tree_catalog_index: entry.tree_catalog_index(),
                            leaf_count: entry_leaf_count(
                                entry,
                                self.catalog.evaluation_domain_size(),
                            )
                            .map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                )
                            })?,
                            canonical_leaf_byte_length: super::canonical_leaf_byte_length(entry)
                                .map_err(|_| {
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::InvalidTree,
                                    )
                                })?,
                        });
                    } else {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                }
                let source_cursor = CommonProofPreChallengeSourceCursor::new(
                    &self.variant,
                    self.source_polynomial_request_context,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                self.opening_geometries = opening_geometries;
                self.pre_challenge_source_cursor = Some(source_cursor);
                self.phase = CommonProofGenerationPhase::LoadingPreChallengeSources;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::LoadingPreChallengeSources => {
                if self.current_relation_column.is_some() {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                if self.pending_authenticated_source_read.is_some() {
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let next_source = self
                    .pre_challenge_source_cursor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .next_source(
                        &self.variant,
                        self.source_polynomial_request_context,
                        self.source_polynomial_provider.as_deref_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        coins,
                        self.relation_context
                            .maximum_fiat_shamir_candidate_draws_per_output,
                    )
                    .map_err(map_private_coin_generation_error)?;
                let (column_ordinal, polynomial) = match next_source {
                    CommonProofPreChallengeSourcePoll::AuthenticatedSourceReadRequired => {
                        let request = self
                            .source_polynomial_provider
                            .as_deref()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?
                            .pending_authenticated_source_read_request()
                            .map_err(CommonProofGenerationError::Prover)?
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ))?;
                        self.pending_authenticated_source_read = Some(request);
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    }
                    CommonProofPreChallengeSourcePoll::Ready {
                        column_ordinal,
                        polynomial,
                    } => (column_ordinal, polynomial),
                    CommonProofPreChallengeSourcePoll::Complete => {
                        self.source_replay_identity_digest = self
                            .pre_challenge_source_cursor
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?
                            .finish(self.source_polynomial_provider.as_deref_mut().ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ),
                            )?)
                            .map_err(CommonProofGenerationError::Prover)?;
                        self.phase = CommonProofGenerationPhase::DerivingReversedColumns {
                            next_binding_index: 0,
                        };
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    }
                };
                self.current_relation_column = Some((column_ordinal, polynomial));
                self.prepare_replay_polynomial_writer(
                    CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                    CommonProofReplayWriteContinuation::PreChallengeSource,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::DerivingReversedColumns { next_binding_index } => {
                let binding = self
                    .pre_challenge_source_cursor
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .reversed_column_bindings()
                    .get(next_binding_index)
                    .copied();
                let Some((source_column_ordinal, reversed_column_ordinal)) = binding else {
                    self.pre_challenge_source_cursor = None;
                    self.executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .complete_step(storage)
                        .map_err(CommonProofGenerationError::Storage)?;
                    self.phase = CommonProofGenerationPhase::TransformingBaseColumns {
                        next_column_index: 0,
                    };
                    return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
                };
                self.prepare_replay_polynomial_reader(
                    CommonProofReplayPolynomialKey::RelationColumn(source_column_ordinal),
                    CommonProofReplayReadContinuation::ReversedColumnSource {
                        source_column_ordinal,
                        reversed_column_ordinal,
                        next_binding_index: next_binding_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingReversedColumn {
                source_column_ordinal,
                reversed_column_ordinal,
                next_binding_index,
            } => {
                let (current_column_ordinal, source) = self.current_relation_column.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?;
                if current_column_ordinal != source_column_ordinal {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                let reversed = construct_reversed_relation_column(
                    &self.variant,
                    source_column_ordinal,
                    reversed_column_ordinal,
                    source,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_generation_error)?;
                self.current_relation_column = Some((reversed_column_ordinal, reversed));
                self.prepare_replay_polynomial_writer(
                    CommonProofReplayPolynomialKey::RelationColumn(reversed_column_ordinal),
                    CommonProofReplayWriteContinuation::ReversedColumn { next_binding_index },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::TransformingBaseColumns { next_column_index } => {
                let mut tree_roles = proof_created_tree_roles_by_column(&self.variant)
                    .map_err(CommonProofGenerationError::Prover)?;
                add_bound_tree_base_roles(&self.variant, &mut tree_roles)
                    .map_err(CommonProofGenerationError::Prover)?;
                let next_column = (next_column_index..self.variant.ordered_columns().len()).find(
                    |column_index| {
                        u32::try_from(*column_index)
                            .ok()
                            .and_then(|column_ordinal| tree_roles.get(&column_ordinal).copied())
                            == Some(ProofTreeRole::BaseOracle)
                    },
                );
                let Some(column_index) = next_column else {
                    if self
                        .relation_evaluation_transform_plans
                        .keys()
                        .any(|column_ordinal| {
                            tree_roles.get(column_ordinal) == Some(&ProofTreeRole::BaseOracle)
                        })
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    if self.active_setup_polynomial_replay.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.phase =
                        CommonProofGenerationPhase::MaterializingBaseTrees { next_tree_index: 0 };
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                let column_ordinal = u32::try_from(column_index).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                let setup_polynomial_tree = self
                    .setup_polynomial_tree_for_column(column_ordinal)
                    .map_err(CommonProofGenerationError::Prover)?;
                if let Some((catalog_index, column_position)) = setup_polynomial_tree {
                    let ordered_column_ordinals =
                        match self.variant.ordered_trees().get(catalog_index) {
                            Some(RelationTreeDescriptor::BoundPublic {
                                construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                                ordered_column_ordinals,
                                ..
                            }) => ordered_column_ordinals.as_slice(),
                            _ => {
                                return Err(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidTree,
                                ));
                            }
                        };
                    if column_position == 0 {
                        if self.active_setup_polynomial_replay.is_some() {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidTree,
                            ));
                        }
                        let entry = self.catalog.entries().get(catalog_index).ok_or(
                            CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                        )?;
                        let replay = SetupPolynomialColumnMajorMerkleReplay::new_root_pass(
                            entry,
                            self.catalog.evaluation_domain_size(),
                            ordered_column_ordinals,
                            self.setup_polynomial_replay_binding()
                                .map_err(CommonProofGenerationError::Prover)?,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                        if replay
                            .memory_accounting()
                            .map_err(CommonProofGenerationError::Prover)?
                            .wasm_total_resident_owned_byte_length()
                            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::ResidentMemoryLimitExceeded,
                            ));
                        }
                        self.active_setup_polynomial_replay = Some(ActiveSetupPolynomialReplay {
                            replay,
                            catalog_index,
                            query_geometry: None,
                        });
                    } else {
                        let active = self.active_setup_polynomial_replay.as_ref().ok_or(
                            CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                        )?;
                        if active.catalog_index != catalog_index
                            || active.replay.ordered_column_ordinals() != ordered_column_ordinals
                            || active.query_geometry.is_some()
                            || active.replay.mode()
                                != SetupPolynomialColumnMajorMerkleReplayMode::RootPass
                            || active.replay.next_column_ordinal() != Some(column_ordinal)
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidTree,
                            ));
                        }
                    }
                } else if self.active_setup_polynomial_replay.is_some() {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                let plan = self
                    .relation_evaluation_transform_plans
                    .remove(&column_ordinal)
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                let transform = ExternalStockhamTransform::new(plan)
                    .map_err(map_external_polynomial_plan_error)
                    .map_err(CommonProofGenerationError::StoragePlan)?;
                self.active_relation_column_transform = Some(ActiveRelationColumnTransform {
                    column_ordinal,
                    transform,
                    continuation: if setup_polynomial_tree.is_some() {
                        CommonProofRelationTransformContinuation::SetupPolynomialRoot {
                            next_column_index: column_index.checked_add(1).ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                ),
                            )?,
                        }
                    } else {
                        CommonProofRelationTransformContinuation::Base {
                            next_column_index: column_index.checked_add(1).ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                ),
                            )?,
                        }
                    },
                });
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::MaterializingBaseTrees { next_tree_index } => {
                let next_tree = self
                    .variant
                    .ordered_trees()
                    .iter()
                    .enumerate()
                    .skip(next_tree_index)
                    .find_map(|(tree_index, descriptor)| match descriptor {
                        RelationTreeDescriptor::ProofCreated {
                            proof_tree_role: 1,
                            ordered_column_ordinals,
                        } => Some((tree_index, ordered_column_ordinals.clone())),
                        RelationTreeDescriptor::BoundPublic {
                            construction_kind: BoundTreeConstructionKind::SetupPolynomial,
                            ..
                        } => Some((tree_index, Vec::new())),
                        RelationTreeDescriptor::BoundPublic {
                            ordered_column_ordinals,
                            ..
                        } => Some((tree_index, ordered_column_ordinals.clone())),
                        _ => None,
                    });
                let Some((tree_index, ordered_column_ordinals)) = next_tree else {
                    self.source_polynomial_provider
                        .as_deref_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .finish_bound_tree_leaf_salts()
                        .map_err(CommonProofGenerationError::Prover)?;
                    self.phase = CommonProofGenerationPhase::DerivingApplicationColumns;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                self.prepare_tree_materialization(
                    tree_index,
                    CommonProofTreeLeafSource::RelationColumns(ordered_column_ordinals),
                    CommonProofTreeContinuation::Base {
                        next_tree_index: tree_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::DerivingApplicationColumns => {
                let mut transcript = CommonProofTranscript::new(
                    self.protocol_version,
                    self.suite_identifier,
                    self.application_statement_schema_identifier,
                    &self.canonical_header_bytes,
                    self.transcript_schedule.clone(),
                )
                .map_err(CommonProofGenerationError::Transcript)?;
                for tree_ordinal in self.transcript_schedule.ordered_base_tree_ordinals() {
                    let entry = unique_catalog_entry(&self.catalog, |source| {
                        source
                            == ProofTreeCatalogSource::RelationProofCreated {
                                tree_role: ProofTreeRole::BaseOracle,
                                tree_ordinal: *tree_ordinal,
                            }
                    })
                    .map_err(CommonProofGenerationError::Prover)?;
                    transcript
                        .absorb_base_root(
                            *tree_ordinal,
                            self.tree_roots[usize::from(entry.tree_catalog_index())],
                        )
                        .map_err(CommonProofGenerationError::Transcript)?;
                }
                let application_challenges = sample_relation_application_challenges(
                    &mut transcript,
                    &self.transcript_schedule,
                )
                .map_err(CommonProofGenerationError::Transcript)?;
                let auxiliary_column_synthesis_cursor =
                    CommonProofAuxiliaryColumnSynthesisCursor::new(
                        &self.variant,
                        &self.relation_context,
                        &application_challenges,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                self.application_challenges = application_challenges;
                self.auxiliary_column_synthesis_cursor = Some(auxiliary_column_synthesis_cursor);
                self.transcript = Some(transcript);
                self.phase = CommonProofGenerationPhase::DerivingAuxiliaryColumns;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::DerivingAuxiliaryColumns => {
                if self.current_relation_column.is_some() {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                if self
                    .auxiliary_column_synthesis_cursor
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .has_pending_output()
                {
                    let (column_ordinal, polynomial) = self
                        .auxiliary_column_synthesis_cursor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?
                        .take_next_output(
                            &self.variant,
                            coins,
                            self.relation_context
                                .maximum_fiat_shamir_candidate_draws_per_output,
                        )
                        .map_err(map_private_coin_generation_error)?
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?;
                    self.current_relation_column = Some((column_ordinal, polynomial));
                    self.prepare_replay_polynomial_writer(
                        CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                        CommonProofReplayWriteContinuation::AuxiliaryColumn,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if let Some(column_ordinal) = self
                    .auxiliary_column_synthesis_cursor
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .next_input_column_ordinal()
                {
                    self.prepare_replay_polynomial_reader(
                        CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                        CommonProofReplayReadContinuation::AuxiliarySynthesisInput {
                            column_ordinal,
                        },
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if self
                    .auxiliary_column_synthesis_cursor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .advance_ready_task()
                    .map_err(CommonProofGenerationError::Prover)?
                {
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if self
                    .auxiliary_column_synthesis_cursor
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .is_complete()
                {
                    self.executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .complete_step(storage)
                        .map_err(CommonProofGenerationError::Storage)?;
                    self.auxiliary_column_synthesis_cursor = None;
                    self.phase = CommonProofGenerationPhase::TransformingAuxiliaryColumns {
                        next_column_index: 0,
                    };
                    return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
                }
                Err(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))
            }
            CommonProofGenerationPhase::TransformingAuxiliaryColumns { next_column_index } => {
                let tree_roles = proof_created_tree_roles_by_column(&self.variant)
                    .map_err(CommonProofGenerationError::Prover)?;
                let next_column = (next_column_index..self.variant.ordered_columns().len()).find(
                    |column_index| {
                        u32::try_from(*column_index)
                            .ok()
                            .and_then(|column_ordinal| tree_roles.get(&column_ordinal).copied())
                            == Some(ProofTreeRole::AuxiliaryOracle)
                    },
                );
                let Some(column_index) = next_column else {
                    if !self.relation_evaluation_transform_plans.is_empty() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    self.phase = CommonProofGenerationPhase::MaterializingAuxiliaryTrees {
                        next_tree_index: 0,
                    };
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                let column_ordinal = u32::try_from(column_index).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                let plan = self
                    .relation_evaluation_transform_plans
                    .remove(&column_ordinal)
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                let transform = ExternalStockhamTransform::new(plan)
                    .map_err(map_external_polynomial_plan_error)
                    .map_err(CommonProofGenerationError::StoragePlan)?;
                self.active_relation_column_transform = Some(ActiveRelationColumnTransform {
                    column_ordinal,
                    transform,
                    continuation: CommonProofRelationTransformContinuation::Auxiliary {
                        next_column_index: column_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    },
                });
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::MaterializingAuxiliaryTrees { next_tree_index } => {
                let next_tree = self
                    .variant
                    .ordered_trees()
                    .iter()
                    .enumerate()
                    .skip(next_tree_index)
                    .find_map(|(tree_index, descriptor)| match descriptor {
                        RelationTreeDescriptor::ProofCreated {
                            proof_tree_role: 2,
                            ordered_column_ordinals,
                        } => Some((tree_index, ordered_column_ordinals.clone())),
                        _ => None,
                    });
                let Some((tree_index, ordered_column_ordinals)) = next_tree else {
                    self.phase = CommonProofGenerationPhase::ConstructingQuotient;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                let tree_ordinal = match self
                    .catalog
                    .entries()
                    .get(tree_index)
                    .map(ProofTreeCatalogEntry::source)
                {
                    Some(ProofTreeCatalogSource::RelationProofCreated {
                        tree_role: ProofTreeRole::AuxiliaryOracle,
                        tree_ordinal,
                    }) => tree_ordinal,
                    _ => {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                };
                self.prepare_tree_materialization(
                    tree_index,
                    CommonProofTreeLeafSource::RelationColumns(ordered_column_ordinals),
                    CommonProofTreeContinuation::Auxiliary {
                        next_tree_index: tree_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                        tree_ordinal,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingQuotient => {
                let statement_owned_query_column_ordinals = self
                    .statement_owned_query_column_ordinals()
                    .map_err(CommonProofGenerationError::Prover)?;
                let quotient_column_ordinals = self
                    .quotient_column_ordinals()
                    .map_err(CommonProofGenerationError::Prover)?;
                let mut quotient_evaluation_vectors = BTreeMap::new();
                let mut statement_owned_query_evaluation_vectors = BTreeMap::new();
                for (column_ordinal, vector) in
                    core::mem::take(&mut self.relation_evaluation_vectors)
                {
                    if quotient_column_ordinals.contains(&column_ordinal) {
                        quotient_evaluation_vectors.insert(column_ordinal, vector);
                    }
                    if statement_owned_query_column_ordinals.contains(&column_ordinal) {
                        statement_owned_query_evaluation_vectors.insert(column_ordinal, vector);
                    }
                }
                if statement_owned_query_evaluation_vectors.len()
                    != statement_owned_query_column_ordinals.len()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                for column_ordinal in &quotient_column_ordinals {
                    let column = self
                        .variant
                        .ordered_columns()
                        .get(usize::try_from(*column_ordinal).map_err(|_| {
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            )
                        })?)
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?;
                    if !matches!(column.origin(), RelationColumnOrigin::VerifierSequence { .. })
                        && !quotient_evaluation_vectors.contains_key(column_ordinal)
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                }
                self.relation_evaluation_vectors = statement_owned_query_evaluation_vectors;
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let mut composition_challenges = Vec::new();
                for constraint_ordinal in 0..self.transcript_schedule.composition_challenge_count()
                {
                    composition_challenges.push(
                        transcript
                            .sample_composition_challenge(constraint_ordinal)
                            .map_err(CommonProofGenerationError::Transcript)?,
                    );
                }
                self.quotient_builder = Some(
                    CommonProofConstraintStreamQuotientBuilder::new(
                        &self.variant,
                        &self.relation_context,
                        self.evaluation_domain,
                        quotient_evaluation_vectors,
                        core::mem::take(&mut self.application_challenges),
                        composition_challenges,
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                    )
                    .map_err(CommonProofGenerationError::Prover)?,
                );
                self.phase = CommonProofGenerationPhase::ConstructingQuotientConstraints;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingQuotientConstraints => {
                if let Some(transform_key) = self
                    .quotient_builder
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .next_transform_key()
                    .map_err(CommonProofGenerationError::Prover)?
                {
                    if !self
                        .variant
                        .ordered_columns()
                        .get(
                            usize::try_from(transform_key.column_ordinal()).map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                        )
                        .is_some_and(|column| {
                            matches!(
                                column.origin(),
                                RelationColumnOrigin::VerifierSequence { .. }
                            )
                        })
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    let plan = self
                        .quotient_constraint_transform_plans
                        .remove(&transform_key)
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?;
                    let transform = ExternalStockhamTransform::new(plan)
                        .map_err(map_external_polynomial_plan_error)
                        .map_err(CommonProofGenerationError::StoragePlan)?;
                    self.active_relation_column_transform = Some(ActiveRelationColumnTransform {
                        column_ordinal: transform_key.column_ordinal(),
                        transform,
                        continuation: CommonProofRelationTransformContinuation::Quotient {
                            transform_key,
                        },
                    });
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }

                let read_request = self
                    .quotient_builder
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .next_read_request()
                    .map_err(CommonProofGenerationError::Prover)?;
                if let Some(read_request) = read_request {
                    let values = {
                        let executor =
                            self.executor
                                .as_mut()
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ))?;
                        read_external_polynomial_extension_values(
                            executor,
                            storage,
                            read_request.vector(),
                            read_request.element_offset(),
                            read_request.element_count(),
                        )
                        .map_err(|error| match error {
                            ExternalStockhamTransformError::Polynomial(error) => {
                                CommonProofGenerationError::StoragePlan(
                                    map_external_polynomial_plan_error(error),
                                )
                            }
                            ExternalStockhamTransformError::Storage(error) => {
                                CommonProofGenerationError::Storage(error)
                            }
                        })?
                    };
                    self.quotient_builder
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .accept_read_values(read_request, values)
                        .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
                }

                let evaluation_progress = self
                    .quotient_builder
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .evaluate_ready_block(&self.variant, &self.relation_context)
                    .map_err(CommonProofGenerationError::Prover)?;
                if evaluation_progress == CommonProofQuotientEvaluationProgress::BlockComplete {
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                self.phase = CommonProofGenerationPhase::CompletingQuotientConstraint;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::CompletingQuotientConstraint => {
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .complete_step(storage)
                    .map_err(CommonProofGenerationError::Storage)?;
                let all_constraints_complete = self
                    .quotient_builder
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .complete_constraint()
                    .map_err(CommonProofGenerationError::Prover)?;
                if !all_constraints_complete {
                    self.phase = CommonProofGenerationPhase::ConstructingQuotientConstraints;
                    return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
                }
                if !self.quotient_constraint_transform_plans.is_empty() {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ));
                }
                let quotient = self
                    .quotient_builder
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .finish()
                    .map_err(CommonProofGenerationError::Prover)?;
                self.quotient_component_cursor = Some(
                    CommonProofQuotientComponentCursor::new(
                        &self.variant,
                        &self.relation_context,
                        quotient,
                    )
                    .map_err(CommonProofGenerationError::Prover)?,
                );
                self.phase = CommonProofGenerationPhase::MaterializingQuotientTrees {
                    next_component_index: 0,
                };
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            CommonProofGenerationPhase::MaterializingQuotientTrees {
                next_component_index,
            } => {
                if self.current_quotient_component.is_none() {
                    let component = self
                        .quotient_component_cursor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .next_component(
                            coins,
                            self.relation_context
                                .maximum_fiat_shamir_candidate_draws_per_output,
                        )
                        .map_err(map_private_coin_generation_error)?;
                    let Some(component) = component else {
                        self.quotient_component_cursor = None;
                        self.application_challenges.clear();
                        self.phase = CommonProofGenerationPhase::DerivingDeepOpenings;
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    };
                    self.current_quotient_component = Some(component);
                    let component_ordinal = u16::try_from(next_component_index).map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                    })?;
                    self.prepare_replay_polynomial_writer(
                        CommonProofReplayPolynomialKey::QuotientComponent(component_ordinal),
                        CommonProofReplayWriteContinuation::QuotientComponent,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let component_ordinal = u16::try_from(next_component_index).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                let catalog_index = unique_catalog_entry(&self.catalog, |source| {
                    source == ProofTreeCatalogSource::QuotientComponent { component_ordinal }
                })
                .map_err(CommonProofGenerationError::Prover)?
                .tree_catalog_index();
                self.prepare_tree_materialization(
                    usize::from(catalog_index),
                    CommonProofTreeLeafSource::QuotientComponent,
                    CommonProofTreeContinuation::Quotient {
                        next_component_index: next_component_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                        component_ordinal,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::DerivingDeepOpenings => {
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let mut deep_points = Vec::new();
                for point_ordinal in 0..self.transcript_schedule.deep_point_count() {
                    let mut relation_error = None;
                    let point = transcript.sample_deep_point(point_ordinal, |candidate| match self
                        .variant
                        .deep_point_candidate_is_forbidden(
                            &self.relation_context,
                            point_ordinal,
                            candidate,
                            &deep_points,
                        ) {
                        Ok(forbidden) => forbidden,
                        Err(error) => {
                            relation_error = Some(error);
                            true
                        }
                    });
                    if let Some(error) = relation_error {
                        return Err(CommonProofGenerationError::Relation(error));
                    }
                    deep_points.push(point.map_err(CommonProofGenerationError::Transcript)?);
                }
                let opening_points = self
                    .variant
                    .derive_opening_points(&self.relation_context, &deep_points)
                    .map_err(CommonProofGenerationError::Relation)?;
                let opening_batch_mask = construct_opening_batch_mask(
                    &self.variant,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_generation_error)?;
                self.opening_points = opening_points;
                self.opening_batch_mask = opening_batch_mask;
                self.deep_evaluations.clear();
                self.deep_evaluations
                    .try_reserve_exact(self.variant.ordered_opening_claims().len())
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                if self.transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing
                {
                    self.prepare_replay_polynomial_writer(
                        CommonProofReplayPolynomialKey::OpeningBatchMask,
                        CommonProofReplayWriteContinuation::OpeningBatchMask,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                } else {
                    if self.opening_batch_mask.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    self.phase = CommonProofGenerationPhase::EvaluatingDeepOpenings {
                        next_claim_index: 0,
                    };
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::EvaluatingDeepOpenings { next_claim_index } => {
                let Some(claim) = self
                    .variant
                    .ordered_opening_claims()
                    .get(next_claim_index)
                    .copied()
                else {
                    if self.deep_evaluations.len() != self.variant.ordered_opening_claims().len() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidOpening,
                        ));
                    }
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .absorb_deep_evaluations(&self.deep_evaluations)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    self.phase = CommonProofGenerationPhase::MaterializingOpeningMask;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                self.prepare_replay_polynomial_reader(
                    replay_polynomial_key_for_claim(&claim)
                        .map_err(CommonProofGenerationError::Prover)?,
                    CommonProofReplayReadContinuation::DeepOpening {
                        claim_index: next_claim_index,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::MaterializingOpeningMask => {
                if self.transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing
                {
                    if self.opening_batch_mask.is_none() {
                        self.prepare_replay_polynomial_reader(
                            CommonProofReplayPolynomialKey::OpeningBatchMask,
                            CommonProofReplayReadContinuation::OpeningBatchMaskTree,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    }
                    let catalog_index = unique_catalog_entry(&self.catalog, |source| {
                        source == ProofTreeCatalogSource::OpeningBatchMask
                    })
                    .map_err(CommonProofGenerationError::Prover)?
                    .tree_catalog_index();
                    self.prepare_tree_materialization(
                        usize::from(catalog_index),
                        CommonProofTreeLeafSource::OpeningBatchMask,
                        CommonProofTreeContinuation::OpeningMask,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                } else {
                    if self.opening_batch_mask.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    self.phase = CommonProofGenerationPhase::PreparingFri;
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::PreparingFri => {
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let mut opening_batch_coefficients = Vec::new();
                let opening_claim_count = usize::try_from(
                    self.transcript_schedule.opening_claim_count(),
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(
                        CommonProofProverError::AllocationLimitExceeded,
                    )
                })?;
                opening_batch_coefficients
                    .try_reserve_exact(opening_claim_count)
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                for claim_ordinal in 0..self.transcript_schedule.opening_claim_count() {
                    opening_batch_coefficients.push(
                        transcript
                            .sample_opening_batch_challenge(claim_ordinal)
                            .map_err(CommonProofGenerationError::Transcript)?,
                    );
                }
                if opening_batch_coefficients.len() != self.variant.ordered_opening_claims().len()
                    || self.deep_evaluations.len() != opening_batch_coefficients.len()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ));
                }
                let opening_degree_bound_exclusive = usize::try_from(
                    self.variant.opening_degree_bound_exclusive(),
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                let initial_coefficient_count = opening_degree_bound_exclusive
                    .checked_sub(1)
                    .filter(|count| *count != 0)
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ))?;
                self.opening_batch_coefficients = opening_batch_coefficients;
                self.initial_fri_polynomial = Some(Zeroizing::new(vec![
                    ProofChallengeExtensionElement::ZERO;
                    initial_coefficient_count
                ]));
                self.phase = CommonProofGenerationPhase::ConstructingInitialFri {
                    next_claim_index: 0,
                };
                if self.transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing
                {
                    self.prepare_replay_polynomial_reader(
                        CommonProofReplayPolynomialKey::OpeningBatchMask,
                        CommonProofReplayReadContinuation::OpeningBatchMaskFri,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingInitialFri { next_claim_index } => {
                if let Some(claim) = self
                    .variant
                    .ordered_opening_claims()
                    .get(next_claim_index)
                    .copied()
                {
                    self.prepare_replay_polynomial_reader(
                        replay_polynomial_key_for_claim(&claim)
                            .map_err(CommonProofGenerationError::Prover)?,
                        CommonProofReplayReadContinuation::InitialFriClaim {
                            claim_index: next_claim_index,
                        },
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let mut initial_fri_evaluations = self.initial_fri_polynomial.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidFriLayer),
                )?;
                trim_extension_polynomial(&mut initial_fri_evaluations);
                let opening_degree_bound_exclusive = usize::try_from(
                    self.variant.opening_degree_bound_exclusive(),
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                if extension_polynomial_degree(&initial_fri_evaluations)
                    .is_some_and(|degree| degree >= opening_degree_bound_exclusive - 1)
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidFriLayer,
                    ));
                }
                self.opening_points.clear();
                self.opening_batch_coefficients.clear();
                self.evaluation_domain
                    .evaluate_extension_polynomial_in_place(&mut initial_fri_evaluations)
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?;
                self.fri_domain = Some(self.evaluation_domain);
                self.fri_evaluations = Some(initial_fri_evaluations);
                self.phase = CommonProofGenerationPhase::FoldingFri {
                    next_fold_ordinal: 0,
                };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::FoldingFri { next_fold_ordinal } => {
                if next_fold_ordinal >= self.transcript_schedule.fri_fold_count() {
                    self.phase = CommonProofGenerationPhase::FinishingFri;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let challenge = self
                    .transcript
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .sample_fri_fold_challenge(next_fold_ordinal)
                    .map_err(CommonProofGenerationError::Transcript)?;
                let current_domain =
                    self.fri_domain
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidFriLayer,
                        ))?;
                let mut next_evaluations =
                    self.fri_evaluations
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidFriLayer,
                        ))?;
                fold_extension_evaluations_in_place(
                    &mut next_evaluations,
                    current_domain,
                    challenge,
                )
                .map_err(CommonProofProverError::from)
                .map_err(CommonProofGenerationError::Prover)?;
                let next_domain = current_domain
                    .folded()
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?;
                self.fri_domain = Some(next_domain);
                if next_fold_ordinal + 1 < self.transcript_schedule.fri_fold_count() {
                    let catalog_index = unique_catalog_entry(&self.catalog, |source| {
                        source
                            == ProofTreeCatalogSource::NonterminalFriLayer {
                                fold_ordinal: next_fold_ordinal,
                            }
                    })
                    .map_err(CommonProofGenerationError::Prover)?
                    .tree_catalog_index();
                    self.prepare_tree_materialization(
                        usize::from(catalog_index),
                        CommonProofTreeLeafSource::FriEvaluations(next_evaluations),
                        CommonProofTreeContinuation::Fri {
                            fold_ordinal: next_fold_ordinal,
                        },
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                } else {
                    self.fri_evaluations = Some(next_evaluations);
                    self.phase = CommonProofGenerationPhase::FoldingFri {
                        next_fold_ordinal: next_fold_ordinal.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    };
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::FinishingFri => {
                let fri_domain = self.fri_domain.ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidFriLayer,
                ))?;
                let mut terminal_coefficients =
                    self.fri_evaluations
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidFriLayer,
                        ))?;
                fri_domain
                    .interpolate_extension_polynomial_in_place(&mut terminal_coefficients)
                    .map_err(CommonProofProverError::from)
                    .map_err(CommonProofGenerationError::Prover)?;
                let terminal_coefficient_count = usize::try_from(
                    self.relation_context
                        .final_polynomial_degree_bound_exclusive,
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                if terminal_coefficient_count == 0
                    || extension_polynomial_degree(&terminal_coefficients)
                        .is_some_and(|degree| degree >= terminal_coefficient_count)
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidFriLayer,
                    ));
                }
                terminal_coefficients.resize(
                    terminal_coefficient_count,
                    ProofChallengeExtensionElement::ZERO,
                );
                terminal_coefficients.shrink_to_fit();
                let transcript =
                    self.transcript
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                transcript
                    .absorb_fri_terminal_coefficients(&terminal_coefficients)
                    .map_err(CommonProofGenerationError::Transcript)?;
                let mut sampled_query_representatives =
                    transcript
                        .sample_query_representatives()
                        .map_err(CommonProofGenerationError::Transcript)?;
                let sorted_query_representatives = transcript
                    .sorted_query_representatives()
                    .map_err(CommonProofGenerationError::Transcript)?;
                sampled_query_representatives.sort_unstable();
                if sampled_query_representatives != sorted_query_representatives
                    || !self.storage_tree_plans.is_empty()
                    || self.root_present.iter().any(|present| !present)
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                let query_section_byte_length = common_proof_query_section_byte_length(
                    &self.catalog,
                    &self.opening_geometries,
                    &sorted_query_representatives,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                let mut prefix_sink =
                    BoundedCommonProofByteSink::new(self.maximum_output_fragment_byte_length)
                        .map_err(map_bounded_fragment_error)?;
                write_common_proof_prefix(
                    &mut prefix_sink,
                    &self.canonical_header_bytes,
                    &self.catalog,
                    &self.tree_roots,
                    &self.deep_evaluations,
                    &terminal_coefficients,
                    &self.transcript_schedule,
                )
                .map_err(|error| match error {
                    CommonProofEncodingError::Prover(error) => {
                        CommonProofGenerationError::Prover(error)
                    }
                    CommonProofEncodingError::Sink(error) => map_bounded_fragment_error(error),
                    CommonProofEncodingError::Artifact(artifact) => match artifact {},
                })?;
                self.terminal_coefficients = terminal_coefficients;
                self.sorted_query_representatives = sorted_query_representatives;
                self.query_section_byte_length = Some(query_section_byte_length);
                self.pending_output_fragment = Some(prefix_sink.finish());
                self.deep_evaluations.clear();
                self.phase = CommonProofGenerationPhase::EmittingPrefix;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::EmittingPrefix => {
                let fragment = self.pending_output_fragment.as_deref().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                sink.write_bytes(fragment)
                    .map_err(CommonProofGenerationError::Sink)?;
                self.pending_output_fragment = None;
                let query_section_byte_length =
                    self.query_section_byte_length
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                self.query_opening_absorber = Some(
                    self.transcript
                        .as_ref()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .begin_query_openings(query_section_byte_length)
                        .map_err(CommonProofGenerationError::Transcript)?,
                );
                self.pending_output_fragment = Some(
                    canonical_common_proof_query_section_header(&self.catalog)
                        .map_err(CommonProofGenerationError::Prover)?
                        .to_vec(),
                );
                self.phase = CommonProofGenerationPhase::EmittingQueryHeader;
                Ok(CommonProofGenerationPoll::OutputFragmentAccepted)
            }
            CommonProofGenerationPhase::EmittingQueryHeader => {
                let fragment = self.pending_output_fragment.as_deref().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                sink.write_bytes(fragment)
                    .map_err(CommonProofGenerationError::Sink)?;
                self.query_opening_absorber
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .absorb(fragment)
                    .map_err(CommonProofGenerationError::Transcript)?;
                self.pending_output_fragment = None;
                self.source_polynomial_provider
                    .as_deref_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .rewind_bound_tree_leaf_salts()
                    .map_err(CommonProofGenerationError::Prover)?;
                self.phase = CommonProofGenerationPhase::EmittingQueries {
                    next_catalog_index: 0,
                };
                Ok(CommonProofGenerationPoll::OutputFragmentAccepted)
            }
            CommonProofGenerationPhase::EmittingQueries { next_catalog_index } => {
                if next_catalog_index == 0
                    && self.setup_polynomial_opening_artifacts.len()
                        < self.setup_polynomial_root_passes.len()
                {
                    if self.pending_output_fragment.is_some() || self.opening_prefetcher.is_some() {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    if !self
                        .prepare_next_setup_polynomial_opening_replay()
                        .map_err(map_generation_initialization_error)?
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if next_catalog_index == 0
                    && (self.setup_polynomial_opening_artifacts.len()
                        != self.setup_polynomial_root_passes.len()
                        || self
                            .setup_polynomial_opening_artifacts
                            .keys()
                            .any(|tree_catalog_index| {
                                !self
                                    .setup_polynomial_root_passes
                                    .contains_key(tree_catalog_index)
                            }))
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                if next_catalog_index >= self.catalog.entries().len() {
                    if self.active_setup_polynomial_replay.is_some()
                        || self.active_setup_polynomial_column_reader.is_some()
                        || !self.setup_polynomial_opening_artifacts.is_empty()
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    self.source_polynomial_provider
                        .as_deref_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .finish_bound_tree_leaf_salts()
                        .map_err(CommonProofGenerationError::Prover)?;
                    self.source_polynomial_provider = None;
                    self.relation_evaluation_vectors.clear();
                    self.setup_polynomial_root_passes.clear();
                    let absorber = self.query_opening_absorber.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?;
                    let mut transcript =
                        self.transcript
                            .take()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?;
                    transcript
                        .finish_query_openings(absorber)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    transcript
                        .finish()
                        .map_err(CommonProofGenerationError::Transcript)?;
                    self.phase = CommonProofGenerationPhase::Finalizing;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if let Some(fragment) = self.pending_output_fragment.as_deref() {
                    sink.write_bytes(fragment)
                        .map_err(CommonProofGenerationError::Sink)?;
                    self.query_opening_absorber
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .absorb(fragment)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    self.pending_output_fragment = None;
                    self.phase = CommonProofGenerationPhase::EmittingQueries {
                        next_catalog_index: next_catalog_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    };
                    return Ok(CommonProofGenerationPoll::OutputFragmentAccepted);
                }
                let entry = self.catalog.entries().get(next_catalog_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                let geometry = *self.opening_geometries.get(next_catalog_index).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                )?;
                if entry.bound_root().is_some() && !entry.uses_common_merkle_context() {
                    let RelationTreeDescriptor::BoundPublic {
                        ordered_column_ordinals,
                        ..
                    } = self.variant.ordered_trees().get(next_catalog_index).ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                    )?
                    else {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    };
                    if entry.setup_polynomial_construction().is_some() {
                        let artifact = self
                            .setup_polynomial_opening_artifacts
                            .remove(&entry.tree_catalog_index())
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidOpening,
                            ))?;
                        self.pending_output_fragment = Some(
                            encode_common_proof_query_tree_fragment(
                                &self.catalog,
                                next_catalog_index,
                                geometry,
                                &self.sorted_query_representatives,
                                &artifact,
                                self.maximum_output_fragment_byte_length,
                            )
                            .map_err(|error| match error {
                                CommonProofEncodingError::Prover(error) => {
                                    CommonProofGenerationError::Prover(error)
                                }
                                CommonProofEncodingError::Sink(error) => {
                                    map_bounded_fragment_error(error)
                                }
                                CommonProofEncodingError::Artifact(error) => {
                                    CommonProofGenerationError::Prover(error)
                                }
                            })?,
                        );
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    }
                    let replay = StatementOwnedMerkleReplay::new_opening_pass(
                        entry,
                        self.catalog.evaluation_domain_size(),
                        &self.sorted_query_representatives,
                        self.maximum_prefetched_query_byte_length,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    self.active_statement_owned_replay = Some(ActiveStatementOwnedReplay {
                        replay,
                        column_ordinals: Some(ordered_column_ordinals.clone()),
                        continuation: StatementOwnedReplayContinuation::Query {
                            catalog_index: next_catalog_index,
                            geometry,
                        },
                    });
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                if self.opening_prefetcher.is_none() {
                    let tree = self.stored_trees.get(&entry.tree_catalog_index()).ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree),
                    )?;
                    self.opening_prefetcher = Some(
                        CommonProofOpeningPrefetcher::new(
                            tree,
                            entry,
                            self.catalog.evaluation_domain_size(),
                            &self.sorted_query_representatives,
                            self.maximum_prefetched_query_byte_length,
                        )
                        .map_err(CommonProofGenerationError::Prover)?,
                    );
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let prefetch_progress = self
                    .opening_prefetcher
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ))?
                    .advance_storage(
                        self.executor
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?,
                        storage,
                    )
                    .map_err(CommonProofGenerationError::Storage)?;
                match prefetch_progress {
                    CommonProofOpeningPrefetchProgress::StorageTransactionCompleted => {
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    CommonProofOpeningPrefetchProgress::Complete => {
                        let artifact = self
                            .opening_prefetcher
                            .take()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidOpening,
                            ))?
                            .finish()
                            .map_err(CommonProofGenerationError::Prover)?;
                        self.pending_output_fragment = Some(
                            encode_common_proof_query_tree_fragment(
                                &self.catalog,
                                next_catalog_index,
                                geometry,
                                &self.sorted_query_representatives,
                                &artifact,
                                self.maximum_output_fragment_byte_length,
                            )
                            .map_err(|error| match error {
                                CommonProofEncodingError::Prover(error) => {
                                    CommonProofGenerationError::Prover(error)
                                }
                                CommonProofEncodingError::Sink(error) => {
                                    map_bounded_fragment_error(error)
                                }
                                CommonProofEncodingError::Artifact(error) => {
                                    CommonProofGenerationError::Prover(error)
                                }
                            })?,
                        );
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                }
            }
            CommonProofGenerationPhase::Finalizing => {
                self.executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .complete_step(storage)
                    .map_err(CommonProofGenerationError::Storage)?;
                let usage = self
                    .executor
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .finish()
                    .map_err(CommonProofGenerationError::StoragePlan)?;
                self.terminal_external_memory_usage = Some(usage);
                self.phase = CommonProofGenerationPhase::Complete;
                Ok(CommonProofGenerationPoll::Complete)
            }
            CommonProofGenerationPhase::Complete => Ok(CommonProofGenerationPoll::Complete),
            CommonProofGenerationPhase::Cancelled => Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            )),
        }
    }

    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.phase == CommonProofGenerationPhase::Cancelled {
            return Ok(());
        }
        if let Some(executor) = self.executor.as_mut() {
            executor.cancel(storage)?;
        }
        self.executor = None;
        self.phase = CommonProofGenerationPhase::Cancelled;
        self.active_tree_materialization = None;
        self.active_statement_owned_replay = None;
        self.pending_tree_continuation = None;
        self.active_replay_polynomial_writer = None;
        self.active_replay_polynomial_reader = None;
        self.active_relation_column_transform = None;
        self.active_setup_polynomial_replay = None;
        self.active_setup_polynomial_column_reader = None;
        self.active_relation_tree_leaf_reader = None;
        if let Some(source_polynomial_provider) = self.source_polynomial_provider.as_deref_mut() {
            source_polynomial_provider.cancel_pending_authenticated_source_read();
        }
        self.source_polynomial_provider = None;
        self.source_replay_identity_digest = [0_u8; HASH_BYTE_LENGTH];
        self.pre_challenge_source_cursor = None;
        self.pending_authenticated_source_read = None;
        self.auxiliary_column_synthesis_cursor = None;
        self.current_relation_column = None;
        self.application_challenges = Vec::new();
        self.quotient_builder = None;
        self.quotient_component_cursor = None;
        self.current_quotient_component = None;
        self.opening_points = Vec::new();
        self.opening_batch_mask = None;
        self.deep_evaluations = Vec::new();
        self.opening_batch_coefficients = Vec::new();
        self.initial_fri_polynomial = None;
        self.fri_domain = None;
        self.fri_evaluations = None;
        self.terminal_coefficients = Zeroizing::new(Vec::new());
        self.sorted_query_representatives = Vec::new();
        self.opening_geometries = Vec::new();
        self.storage_tree_plans = BTreeMap::new();
        self.replay_polynomial_plans = BTreeMap::new();
        self.relation_evaluation_transform_plans = BTreeMap::new();
        self.quotient_constraint_transform_plans = BTreeMap::new();
        self.relation_evaluation_vectors = BTreeMap::new();
        self.stored_trees = BTreeMap::new();
        self.tree_roots = Vec::new();
        self.root_present = Vec::new();
        self.setup_polynomial_root_passes = BTreeMap::new();
        self.setup_polynomial_opening_artifacts = BTreeMap::new();
        self.transcript = None;
        self.query_opening_absorber = None;
        self.query_section_byte_length = None;
        self.opening_prefetcher = None;
        self.pending_output_fragment = None;
        self.canonical_header_bytes = Vec::new();
        Ok(())
    }
}

fn add_bound_tree_base_roles(
    variant: &RelationPlanVariant,
    roles: &mut BTreeMap<u32, ProofTreeRole>,
) -> Result<(), CommonProofProverError> {
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::BoundPublic {
            ordered_column_ordinals,
            ..
        } = tree
        else {
            continue;
        };
        for column_ordinal in ordered_column_ordinals {
            match roles.insert(*column_ordinal, ProofTreeRole::BaseOracle) {
                Some(ProofTreeRole::BaseOracle) | None => {}
                Some(
                    ProofTreeRole::AuxiliaryOracle
                    | ProofTreeRole::QuotientComponent
                    | ProofTreeRole::OpeningBatchMask
                    | ProofTreeRole::NonterminalFriLayer,
                ) => return Err(CommonProofProverError::InvalidTree),
            }
        }
    }
    Ok(())
}

fn map_generation_initialization_error<StorageError, CoinError, SinkError>(
    error: CommonProofGenerationInitializationError,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        CommonProofGenerationInitializationError::Prover(error) => {
            CommonProofGenerationError::Prover(error)
        }
        CommonProofGenerationInitializationError::Profile(error) => {
            CommonProofGenerationError::Profile(error)
        }
        CommonProofGenerationInitializationError::Relation(error) => {
            CommonProofGenerationError::Relation(error)
        }
        CommonProofGenerationInitializationError::Body(error) => {
            CommonProofGenerationError::Body(error)
        }
        CommonProofGenerationInitializationError::Transcript(error) => {
            CommonProofGenerationError::Transcript(error)
        }
        CommonProofGenerationInitializationError::StoragePlan(error) => {
            CommonProofGenerationError::StoragePlan(error)
        }
    }
}

fn map_bounded_fragment_error<StorageError, CoinError, SinkError>(
    error: BoundedCommonProofByteSinkError,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        BoundedCommonProofByteSinkError::ByteLengthExceeded
        | BoundedCommonProofByteSinkError::AllocationLimitExceeded => {
            CommonProofGenerationError::Prover(CommonProofProverError::AllocationLimitExceeded)
        }
    }
}

#[cfg(test)]
pub(crate) fn generate_common_proof<Storage, Coins, Sink>(
    input: CommonProofGenerationInput<'_>,
    storage: &mut Storage,
    coins: &mut Coins,
    sink: &mut Sink,
) -> CompletedCommonProofGenerationResult<Storage, Coins, Sink>
where
    Storage: ProofExternalMemory,
    Coins: CommonProofPrivateCoinSource,
    Sink: CommonProofByteSink,
{
    let mut state_machine = CommonProofGenerationStateMachine::new(input)
        .map_err(map_generation_initialization_error)?;
    let generation_result = loop {
        match state_machine.poll(storage, coins, sink) {
            Ok(CommonProofGenerationPoll::Complete) => break Ok(()),
            Ok(
                CommonProofGenerationPoll::ArithmeticStepCompleted
                | CommonProofGenerationPoll::StorageTransactionCompleted
                | CommonProofGenerationPoll::OutputFragmentAccepted,
            ) => {}
            Err(error) => break Err(error),
        }
    };
    match generation_result {
        Ok(()) => Ok(()),
        Err(original) => match state_machine.cancel(storage) {
            Ok(()) => Err(original),
            Err(cleanup) => Err(CommonProofGenerationError::Cleanup {
                original: Box::new(original),
                cleanup,
            }),
        },
    }
}

#[cfg(test)]
mod source_provider_resident_memory_tests {
    use super::*;

    #[test]
    fn source_provider_lifetime_covers_every_phase_until_query_emission_finishes() {
        for phase in [
            CommonProofResidentMemoryPhase::LoadingSourcePolynomials,
            CommonProofResidentMemoryPhase::ConstructingReversedColumns,
            CommonProofResidentMemoryPhase::TransformingBaseColumns,
            CommonProofResidentMemoryPhase::MaterializingBaseTrees,
            CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns,
            CommonProofResidentMemoryPhase::TransformingAuxiliaryColumns,
            CommonProofResidentMemoryPhase::MaterializingAuxiliaryTrees,
            CommonProofResidentMemoryPhase::ConstructingQuotient,
            CommonProofResidentMemoryPhase::MaterializingQuotientTrees,
            CommonProofResidentMemoryPhase::DerivingOpenings,
            CommonProofResidentMemoryPhase::ConstructingInitialFri,
            CommonProofResidentMemoryPhase::FoldingFri,
            CommonProofResidentMemoryPhase::PreparingQueryOutput,
            CommonProofResidentMemoryPhase::EmittingQueries,
        ] {
            assert!(common_proof_source_provider_is_live_during_phase(phase));
        }
    }
}
