#[cfg(test)]
use super::CompletedCommonProofGenerationResult;
use super::{
    BTreeMap, BoundedCommonProofByteSink, BoundedCommonProofByteSinkError,
    CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN, CommonProofBoundOpeningProvider, CommonProofByteSink,
    CommonProofEncodingError, CommonProofGenerationError, CommonProofGenerationInitializationError,
    CommonProofGenerationInput, CommonProofGenerationPollResult, CommonProofMerkleMaterializer,
    CommonProofMerkleMaterializerProgress, CommonProofMerkleStoragePlan,
    CommonProofOpeningArtifact, CommonProofOpeningGeometry, CommonProofOpeningPrefetchProgress,
    CommonProofOpeningPrefetcher, CommonProofPreChallengeRelationColumns, CommonProofPrivacyMode,
    CommonProofPrivateCoinSource, CommonProofProverError, CommonProofQueryOpeningAbsorber,
    CommonProofQuotientComponentCursor, CommonProofReplayPolynomialKey,
    CommonProofReplayPolynomialPlan, CommonProofReplayPolynomialReader,
    CommonProofReplayPolynomialRef, CommonProofReplayPolynomialWriter,
    CommonProofReplayQuotientBuilder, CommonProofResidentMemoryPlan, CommonProofSourcePolynomial,
    CommonProofTranscript, CommonProofTranscriptSchedule, CommonProofTreeStorageError,
    CompleteProofTreeCatalog, ExternalPolynomialValue, ExternalPolynomialVector,
    ExternalStockhamTransform, ExternalStockhamTransformError, ExternalStockhamTransformPlan,
    ExternalStockhamTransformProgress, GeneratedCommonProofStoragePlanError, HASH_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    ProofBaseFieldElement, ProofChallengeExtensionElement, ProofEvaluationDomain,
    ProofExternalMemory, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
    ProofTreeCatalogEntry, ProofTreeCatalogInput, ProofTreeCatalogSource, ProofTreeRole,
    ProofTreeValue, RelationApplicationChallengeAssignment, RelationColumnDescriptor,
    RelationPlanCheckContext, RelationPlanVariant, RelationProofTreeInput, RelationTreeDescriptor,
    StoredCommonProofMerkleTree, StreamingHash512, ValidatedRelationPlanArtifact,
    add_replay_polynomial_to_initial_fri, build_complete_proof_tree_catalog,
    canonical_common_proof_query_section_header, canonical_proof_object_header_bytes,
    common_proof_query_section_byte_length, common_proof_resident_memory_plan,
    construct_opening_batch_mask, construct_post_challenge_relation_columns,
    construct_pre_challenge_relation_columns, encode_common_proof_query_tree_fragment,
    evaluate_extension_at, evaluate_replay_polynomial_opening, extension_polynomial_degree,
    fold_extension_evaluations_in_place, generated_common_proof_storage_plan,
    insert_materialized_tree, map_external_polynomial_plan_error,
    map_private_coin_generation_error, read_external_polynomial_value,
    replay_polynomial_key_for_claim, statement_owned_tree_root, trim_extension_polynomial,
    unique_catalog_entry, validate_generation_relation_trees, write_common_proof_prefix,
};

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
    MaterializingBaseTrees { next_tree_index: usize },
    DerivingApplicationColumns,
    PersistingRelationColumns { next_column_index: usize },
    TransformingRelationColumns { next_column_index: usize },
    MaterializingAuxiliaryTrees { next_tree_index: usize },
    ConstructingQuotient,
    ConstructingQuotientBlocks,
    MaterializingQuotientTrees { next_component_index: usize },
    DerivingDeepOpenings,
    EvaluatingDeepOpenings { next_claim_index: usize },
    MaterializingOpeningMask,
    PreparingFri,
    ConstructingInitialFri { next_claim_index: usize },
    FoldingFri { next_fold_ordinal: u16 },
    FinishingFri,
    EmittingPrefix,
    EmittingQueryHeader,
    EmittingQueries { next_catalog_index: usize },
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
    RelationColumn { next_column_index: usize },
    QuotientComponent,
    OpeningBatchMask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayReadContinuation {
    QuotientBlockColumn { column_index: usize },
    DeepOpening { claim_index: usize },
    OpeningBatchMaskTree,
    OpeningBatchMaskFri,
    InitialFriClaim { claim_index: usize },
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
}

struct ActiveRelationTreeLeafReader {
    leaf_index: usize,
    opposite_index: usize,
    column_ordinals: Vec<u32>,
    next_value_index: usize,
    first_values: Vec<ProofTreeValue>,
    opposite_values: Vec<ProofTreeValue>,
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
        let mut first_values = Vec::new();
        first_values
            .try_reserve_exact(column_ordinals.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        let mut opposite_values = Vec::new();
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

enum CommonProofTreeLeafSource {
    PreChallengeColumns(Vec<u32>),
    RelationColumns(Vec<u32>),
    QuotientComponent,
    OpeningBatchMask,
    FriEvaluations(Vec<ProofChallengeExtensionElement>),
}

fn evaluate_source_polynomial_tree_value(
    polynomial: &CommonProofSourcePolynomial,
    point: ProofBaseFieldElement,
) -> ProofTreeValue {
    match polynomial {
        CommonProofSourcePolynomial::Base(coefficients) => ProofTreeValue::Base(
            coefficients
                .iter()
                .rev()
                .fold(ProofBaseFieldElement::ZERO, |accumulated, coefficient| {
                    accumulated.multiply(point).add(*coefficient)
                }),
        ),
        CommonProofSourcePolynomial::Extension(coefficients) => {
            ProofTreeValue::Extension(evaluate_extension_at(
                coefficients,
                ProofChallengeExtensionElement::from_base(point),
            ))
        }
    }
}

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
    resident_memory_plan: CommonProofResidentMemoryPlan,
    relation_trees: Vec<RelationProofTreeInput>,
    provided_pre_challenge_columns: Option<BTreeMap<u32, CommonProofSourcePolynomial>>,
    maximum_prefetched_query_byte_length: u64,
    maximum_output_fragment_byte_length: usize,
    storage_tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
    replay_polynomial_plans:
        BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayPolynomialPlan>,
    relation_evaluation_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
    relation_evaluation_vectors: BTreeMap<u32, ExternalPolynomialVector>,
    executor: Option<ProofExternalMemoryExecutor>,
    phase: CommonProofGenerationPhase,
    active_tree_materialization: Option<ActiveCommonProofTreeMaterialization>,
    pending_tree_continuation: Option<CommonProofTreeContinuation>,
    active_replay_polynomial_writer: Option<ActiveCommonProofReplayPolynomialWriter>,
    active_replay_polynomial_reader: Option<ActiveCommonProofReplayPolynomialReader>,
    active_relation_column_transform: Option<ActiveRelationColumnTransform>,
    active_relation_tree_leaf_reader: Option<ActiveRelationTreeLeafReader>,
    pre_challenge_columns: Option<CommonProofPreChallengeRelationColumns>,
    columns: Option<Vec<CommonProofSourcePolynomial>>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
    quotient_builder: Option<CommonProofReplayQuotientBuilder>,
    quotient_component_cursor: Option<CommonProofQuotientComponentCursor>,
    current_quotient_component: Option<Vec<ProofChallengeExtensionElement>>,
    opening_points: Vec<ProofChallengeExtensionElement>,
    opening_batch_mask: Option<Vec<ProofChallengeExtensionElement>>,
    deep_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_coefficients: Vec<ProofChallengeExtensionElement>,
    initial_fri_polynomial: Option<Vec<ProofChallengeExtensionElement>>,
    fri_domain: Option<ProofEvaluationDomain>,
    fri_evaluations: Option<Vec<ProofChallengeExtensionElement>>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
    sorted_query_representatives: Vec<u64>,
    opening_geometries: Vec<CommonProofOpeningGeometry>,
    tree_roots: Vec<[u8; HASH_BYTE_LENGTH]>,
    root_present: Vec<bool>,
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
    ) -> Result<(Vec<ProofTreeValue>, Vec<ProofTreeValue>), CommonProofProverError> {
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
                    vec![ProofTreeValue::Extension(
                        *evaluations
                            .get(leaf_index)
                            .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    )],
                    vec![ProofTreeValue::Extension(
                        *evaluations
                            .get(opposite_index)
                            .ok_or(CommonProofProverError::InvalidFriLayer)?,
                    )],
                ))
            }
            leaf_source => {
                let opposite_index = leaf_index
                    .checked_add(self.evaluation_domain.size() / 2)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                let first_point = self.evaluation_domain.point(leaf_index)?;
                let opposite_point = self.evaluation_domain.point(opposite_index)?;
                let mut first_values = Vec::new();
                let mut opposite_values = Vec::new();
                let row_width = match leaf_source {
                    CommonProofTreeLeafSource::PreChallengeColumns(column_ordinals)
                    | CommonProofTreeLeafSource::RelationColumns(column_ordinals) => {
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
                    CommonProofTreeLeafSource::PreChallengeColumns(column_ordinals) => {
                        let columns = self
                            .pre_challenge_columns
                            .as_ref()
                            .ok_or(CommonProofProverError::InvalidColumn)?;
                        for column_ordinal in column_ordinals {
                            let polynomial = columns
                                .column(*column_ordinal)
                                .ok_or(CommonProofProverError::InvalidColumn)?;
                            first_values.push(evaluate_source_polynomial_tree_value(
                                polynomial,
                                first_point,
                            ));
                            opposite_values.push(evaluate_source_polynomial_tree_value(
                                polynomial,
                                opposite_point,
                            ));
                        }
                    }
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

    fn poll_active_tree<Storage, Coins, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, Coins::Error, SinkError, BoundOpeningError>,
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
                    .supply_next_leaf(first_values, opposite_values, coins)
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
            provided_pre_challenge_columns,
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
        let resident_memory_plan = common_proof_resident_memory_plan(
            variant,
            relation_context,
            &transcript_schedule,
            &catalog,
            maximum_prefetched_query_byte_length,
            u64::from(maximum_external_memory_chunk_byte_length),
            u64::try_from(maximum_proof_transport_chunk_byte_length).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?,
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?;
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
            resident_memory_plan,
            relation_trees,
            provided_pre_challenge_columns: Some(provided_pre_challenge_columns),
            maximum_prefetched_query_byte_length,
            maximum_output_fragment_byte_length: maximum_proof_transport_chunk_byte_length,
            storage_tree_plans: storage_plan.tree_plans,
            replay_polynomial_plans: storage_plan.replay_polynomial_plans,
            relation_evaluation_transform_plans: storage_plan.relation_evaluation_transform_plans,
            relation_evaluation_vectors: BTreeMap::new(),
            executor: Some(executor),
            phase: CommonProofGenerationPhase::PreparingInputs,
            active_tree_materialization: None,
            pending_tree_continuation: None,
            active_replay_polynomial_writer: None,
            active_replay_polynomial_reader: None,
            active_relation_column_transform: None,
            active_relation_tree_leaf_reader: None,
            pre_challenge_columns: None,
            columns: None,
            application_challenges: Vec::new(),
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
            terminal_coefficients: Vec::new(),
            sorted_query_representatives: Vec::new(),
            opening_geometries: Vec::new(),
            tree_roots,
            root_present,
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
            CommonProofGenerationPhase::PreparingInputs => {
                CommonProofGenerationStage::PreparingInputs
            }
            CommonProofGenerationPhase::MaterializingBaseTrees { .. } => {
                CommonProofGenerationStage::MaterializingBaseTrees
            }
            CommonProofGenerationPhase::DerivingApplicationColumns => {
                CommonProofGenerationStage::DerivingApplicationColumns
            }
            CommonProofGenerationPhase::PersistingRelationColumns { .. }
            | CommonProofGenerationPhase::TransformingRelationColumns { .. } => {
                CommonProofGenerationStage::DerivingApplicationColumns
            }
            CommonProofGenerationPhase::MaterializingAuxiliaryTrees { .. } => {
                CommonProofGenerationStage::MaterializingAuxiliaryTrees
            }
            CommonProofGenerationPhase::ConstructingQuotient
            | CommonProofGenerationPhase::ConstructingQuotientBlocks => {
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

    pub(crate) const fn resident_memory_plan(&self) -> &CommonProofResidentMemoryPlan {
        &self.resident_memory_plan
    }

    #[cfg(test)]
    pub(crate) fn resident_payload_is_empty(&self) -> bool {
        self.provided_pre_challenge_columns.is_none()
            && self.active_tree_materialization.is_none()
            && self.pending_tree_continuation.is_none()
            && self.active_replay_polynomial_writer.is_none()
            && self.active_replay_polynomial_reader.is_none()
            && self.active_relation_column_transform.is_none()
            && self.active_relation_tree_leaf_reader.is_none()
            && self.pre_challenge_columns.is_none()
            && self.columns.is_none()
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
            && self.relation_evaluation_vectors.is_empty()
            && self.stored_trees.is_empty()
            && self.tree_roots.is_empty()
            && self.root_present.is_empty()
            && self.transcript.is_none()
            && self.query_opening_absorber.is_none()
            && self.query_section_byte_length.is_none()
            && self.opening_prefetcher.is_none()
            && self.pending_output_fragment.is_none()
            && self.relation_trees.is_empty()
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
            || self.pending_tree_continuation.is_some()
            || self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_relation_column_transform.is_some()
            || self.active_relation_tree_leaf_reader.is_some()
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
        let mut hasher = StreamingHash512::new(CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN, 2);
        hasher.absorb_part(&position);
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

    fn executor_mut(&mut self) -> Result<&mut ProofExternalMemoryExecutor, CommonProofProverError> {
        self.executor
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)
    }

    fn poll_active_relation_column_transform<Storage, CoinError, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError, BoundOpeningError>,
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
                if self
                    .relation_evaluation_vectors
                    .insert(active.column_ordinal, vector)
                    .is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                let next_column_index = usize::try_from(active.column_ordinal)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                self.phase =
                    CommonProofGenerationPhase::TransformingRelationColumns { next_column_index };
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
        }
    }

    fn poll_active_relation_tree_leaf_reader<Storage, Coins, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, Coins::Error, SinkError, BoundOpeningError>,
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
            self.active_tree_materialization
                .as_mut()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?
                .materializer
                .supply_next_leaf(reader.first_values, reader.opposite_values, coins)
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

    fn prepare_replay_polynomial_writer(
        &mut self,
        key: CommonProofReplayPolynomialKey,
        continuation: CommonProofReplayWriteContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_tree_materialization.is_some()
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
                    self.columns
                        .as_ref()
                        .and_then(|columns| {
                            usize::try_from(column_ordinal)
                                .ok()
                                .and_then(|index| columns.get(index))
                        })
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

    fn poll_active_replay_polynomial_writer<Storage, CoinError, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError, BoundOpeningError>,
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
                    self.columns
                        .as_ref()
                        .and_then(|columns| {
                            usize::try_from(column_ordinal)
                                .ok()
                                .and_then(|index| columns.get(index))
                        })
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
                CommonProofReplayWriteContinuation::RelationColumn { next_column_index } => {
                    self.phase =
                        CommonProofGenerationPhase::PersistingRelationColumns { next_column_index };
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
            CommonProofReplayReadContinuation::QuotientBlockColumn { column_index } => {
                let expected_value_type = self
                    .variant
                    .ordered_columns()
                    .get(column_index)
                    .map(RelationColumnDescriptor::value_type)
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                if polynomial.value_type() != expected_value_type {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                self.quotient_builder
                    .as_mut()
                    .ok_or(CommonProofProverError::InvalidQuotient)?
                    .accept_column(column_index, polynomial)?;
                self.phase = CommonProofGenerationPhase::ConstructingQuotientBlocks;
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
                for (destination, coefficient) in initial.iter_mut().zip(coefficients) {
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

    fn poll_active_replay_polynomial_reader<Storage, CoinError, SinkError, BoundOpeningError>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, CoinError, SinkError, BoundOpeningError>,
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
        if self.active_tree_materialization.is_some() || self.pending_tree_continuation.is_some() {
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
        let materializer = CommonProofMerkleMaterializer::new(entry, tree_plan)?;
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

    pub(crate) fn poll<Storage, Coins, Sink, BoundOpenings>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
        sink: &mut Sink,
        bound_openings: &mut BoundOpenings,
    ) -> CommonProofGenerationPollResult<
        Storage::Error,
        Coins::Error,
        Sink::Error,
        BoundOpenings::Error,
    >
    where
        Storage: ProofExternalMemory,
        Coins: CommonProofPrivateCoinSource,
        Sink: CommonProofByteSink,
        BoundOpenings: CommonProofBoundOpeningProvider,
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
        if self.active_relation_tree_leaf_reader.is_some() {
            return self.poll_active_relation_tree_leaf_reader(storage, coins);
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
                        let leaf_count = entry
                            .common_context()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidTree,
                            ))?
                            .leaf_count()
                            .map_err(CommonProofProverError::from)
                            .map_err(CommonProofGenerationError::Prover)?;
                        opening_geometries.push(CommonProofOpeningGeometry {
                            tree_catalog_index: entry.tree_catalog_index(),
                            leaf_count,
                            canonical_leaf_byte_length: tree_plan.canonical_leaf_byte_length(),
                        });
                    } else if entry.source() == ProofTreeCatalogSource::RelationBoundPublic {
                        opening_geometries.push(
                            bound_openings
                                .opening_geometry(entry)
                                .map_err(CommonProofGenerationError::BoundOpening)?,
                        );
                    } else {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                }
                let provided_columns = self.provided_pre_challenge_columns.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                let pre_challenge_columns = construct_pre_challenge_relation_columns(
                    &self.variant,
                    provided_columns,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_generation_error)?;
                self.opening_geometries = opening_geometries;
                self.pre_challenge_columns = Some(pre_challenge_columns);
                self.phase =
                    CommonProofGenerationPhase::MaterializingBaseTrees { next_tree_index: 0 };
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
                        _ => None,
                    });
                let Some((tree_index, ordered_column_ordinals)) = next_tree else {
                    self.phase = CommonProofGenerationPhase::DerivingApplicationColumns;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                self.prepare_tree_materialization(
                    tree_index,
                    CommonProofTreeLeafSource::PreChallengeColumns(ordered_column_ordinals),
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
                let mut application_challenges = Vec::new();
                for challenge_group in self
                    .transcript_schedule
                    .ordered_application_challenge_groups()
                {
                    let challenge = challenge_group.challenge();
                    let values = transcript
                        .sample_application_challenge_group(challenge)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    if values.len() != usize::from(challenge_group.coordinate_count()) {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ));
                    }
                    for (repetition_ordinal, value) in values.into_iter().enumerate() {
                        application_challenges.push(
                            RelationApplicationChallengeAssignment::new(
                                challenge,
                                u16::try_from(repetition_ordinal).map_err(|_| {
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::CountOverflow,
                                    )
                                })?,
                                value,
                            )
                            .map_err(CommonProofGenerationError::Relation)?,
                        );
                    }
                }
                let pre_challenge_columns =
                    self.pre_challenge_columns
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                let columns = construct_post_challenge_relation_columns(
                    &self.variant,
                    &self.relation_context,
                    pre_challenge_columns,
                    &application_challenges,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_generation_error)?;
                self.application_challenges = application_challenges;
                self.columns = Some(columns);
                self.transcript = Some(transcript);
                self.phase = CommonProofGenerationPhase::PersistingRelationColumns {
                    next_column_index: 0,
                };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::PersistingRelationColumns { next_column_index } => {
                let column_count = self
                    .columns
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .len();
                if next_column_index >= column_count {
                    self.executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .complete_step(storage)
                        .map_err(CommonProofGenerationError::Storage)?;
                    self.columns = None;
                    self.phase = CommonProofGenerationPhase::TransformingRelationColumns {
                        next_column_index: 0,
                    };
                    return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
                }
                let column_ordinal = u32::try_from(next_column_index).map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                })?;
                self.prepare_replay_polynomial_writer(
                    CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                    CommonProofReplayWriteContinuation::RelationColumn {
                        next_column_index: next_column_index.checked_add(1).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ),
                        )?,
                    },
                )
                .map_err(CommonProofGenerationError::Prover)?;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::TransformingRelationColumns { next_column_index } => {
                if next_column_index >= self.variant.ordered_columns().len() {
                    if !self.relation_evaluation_transform_plans.is_empty()
                        || self.relation_evaluation_vectors.len()
                            != self.variant.ordered_columns().len()
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    self.phase = CommonProofGenerationPhase::MaterializingAuxiliaryTrees {
                        next_tree_index: 0,
                    };
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let column_ordinal = u32::try_from(next_column_index).map_err(|_| {
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
                    self.relation_evaluation_vectors.clear();
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
                    CommonProofReplayQuotientBuilder::new(
                        &self.variant,
                        &self.relation_context,
                        self.evaluation_domain,
                        core::mem::take(&mut self.application_challenges),
                        composition_challenges,
                    )
                    .map_err(CommonProofGenerationError::Prover)?,
                );
                self.columns = None;
                self.phase = CommonProofGenerationPhase::ConstructingQuotientBlocks;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            CommonProofGenerationPhase::ConstructingQuotientBlocks => {
                if let Some(column_index) = self
                    .quotient_builder
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .next_column_index()
                {
                    self.prepare_replay_polynomial_reader(
                        CommonProofReplayPolynomialKey::RelationColumn(
                            u32::try_from(column_index).map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                        ),
                        CommonProofReplayReadContinuation::QuotientBlockColumn { column_index },
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let completed = self
                    .quotient_builder
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .evaluate_ready_block(&self.variant, &self.relation_context)
                    .map_err(CommonProofGenerationError::Prover)?;
                if !completed {
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
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
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
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
                        self.columns = None;
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
                self.initial_fri_polynomial = Some(vec![
                    ProofChallengeExtensionElement::ZERO;
                    initial_coefficient_count
                ]);
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
                self.phase = CommonProofGenerationPhase::EmittingQueries {
                    next_catalog_index: 0,
                };
                Ok(CommonProofGenerationPoll::OutputFragmentAccepted)
            }
            CommonProofGenerationPhase::EmittingQueries { next_catalog_index } => {
                if next_catalog_index >= self.catalog.entries().len() {
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
                if entry.source() == ProofTreeCatalogSource::RelationBoundPublic {
                    self.pending_output_fragment = Some(
                        bound_openings
                            .encode_bound_opening_fragment(
                                &self.catalog,
                                next_catalog_index,
                                geometry,
                                &self.sorted_query_representatives,
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
                                    CommonProofGenerationError::BoundOpening(error)
                                }
                            })?,
                    );
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
                        let mut artifact = self
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
                                &mut artifact,
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
                self.executor
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .finish()
                    .map_err(CommonProofGenerationError::StoragePlan)?;
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
        self.pending_tree_continuation = None;
        self.active_replay_polynomial_writer = None;
        self.active_replay_polynomial_reader = None;
        self.active_relation_column_transform = None;
        self.active_relation_tree_leaf_reader = None;
        self.provided_pre_challenge_columns = None;
        self.pre_challenge_columns = None;
        self.columns = None;
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
        self.terminal_coefficients = Vec::new();
        self.sorted_query_representatives = Vec::new();
        self.opening_geometries = Vec::new();
        self.storage_tree_plans = BTreeMap::new();
        self.replay_polynomial_plans = BTreeMap::new();
        self.relation_evaluation_transform_plans = BTreeMap::new();
        self.relation_evaluation_vectors = BTreeMap::new();
        self.stored_trees = BTreeMap::new();
        self.tree_roots = Vec::new();
        self.root_present = Vec::new();
        self.transcript = None;
        self.query_opening_absorber = None;
        self.query_section_byte_length = None;
        self.opening_prefetcher = None;
        self.pending_output_fragment = None;
        self.relation_trees = Vec::new();
        self.canonical_header_bytes = Vec::new();
        Ok(())
    }
}

fn map_generation_initialization_error<StorageError, CoinError, SinkError, BoundOpeningError>(
    error: CommonProofGenerationInitializationError,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
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

fn map_bounded_fragment_error<StorageError, CoinError, SinkError, BoundOpeningError>(
    error: BoundedCommonProofByteSinkError,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError, BoundOpeningError> {
    match error {
        BoundedCommonProofByteSinkError::ByteLengthExceeded
        | BoundedCommonProofByteSinkError::AllocationLimitExceeded => {
            CommonProofGenerationError::Prover(CommonProofProverError::AllocationLimitExceeded)
        }
    }
}
#[cfg(test)]
pub(crate) fn generate_common_proof<Storage, Coins, Sink, BoundOpenings>(
    input: CommonProofGenerationInput<'_>,
    storage: &mut Storage,
    coins: &mut Coins,
    sink: &mut Sink,
    bound_openings: &mut BoundOpenings,
) -> CompletedCommonProofGenerationResult<Storage, Coins, Sink, BoundOpenings>
where
    Storage: ProofExternalMemory,
    Coins: CommonProofPrivateCoinSource,
    Sink: CommonProofByteSink,
    BoundOpenings: CommonProofBoundOpeningProvider,
{
    let mut state_machine = CommonProofGenerationStateMachine::new(input)
        .map_err(map_generation_initialization_error)?;
    let generation_result = loop {
        match state_machine.poll(storage, coins, sink, bound_openings) {
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
