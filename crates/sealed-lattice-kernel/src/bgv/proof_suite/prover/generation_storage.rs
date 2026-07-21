use super::{
    BTreeMap, BTreeSet, BoundTreeConstructionKind, COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH,
    CommonProofGenerationPoll, CommonProofGenerationStateMachine, CommonProofMerkleStoragePlan,
    CommonProofOpeningGeometry, CommonProofPrivacyMode, CommonProofPrivateCoinError,
    CommonProofProverError, CommonProofQuotientConstraintTransformKey, CommonProofSourcePolynomial,
    CommonProofSourcePolynomialProvider, CommonProofTranscriptSchedule, CompiledRelationPlan,
    CompleteProofTreeCatalog, ExternalPolynomialVector, ExternalStockhamTransformDirection,
    ExternalStockhamTransformPlan, HASH_BYTE_LENGTH, PROOF_CHALLENGE_EXTENSION_DEGREE,
    PrefetchedCommonProofOpeningArtifact, ProofBaseFieldElement, ProofBodyError,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofExternalMemory,
    ProofExternalMemoryError, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
    ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
    ProofExternalMemoryProtection, ProofLeafVisibility, ProofPrivacyMode, ProofProfileError,
    ProofTreeCatalogEntry, ProofTreeCatalogSource, ProofTreeRole, ProofTreeValue,
    RelationApplicationChallengeAssignment, RelationColumnOrigin, RelationColumnValueType,
    RelationMaskKind, RelationMaskTargetClass, RelationPlanCheckContext, RelationPlanError,
    RelationPlanVariant, RelationProofTreeInput, RelationTreeDescriptor,
    SetupPolynomialColumnMajorMerkleRootPass, StatementOwnedProofTreeInput,
    StoredCommonProofMerkleTree, TranscriptError, Zeroize, Zeroizing, canonical_leaf_byte_length,
    common_proof_merkle_storage_plan, entry_leaf_count,
    external_polynomial_extension_read_resident_memory_requirement,
    external_stockham_resident_memory_requirement, external_value_byte_length,
    map_external_polynomial_plan_error, maximum_minimal_frontier_node_count,
    proof_created_tree_roles_by_column, relation_column_replay_requirements,
    replay_polynomial_key_for_claim, rotated_relation_evaluation_position,
    setup_polynomial_column_major_merkle_replay_wasm_memory_bound, trim_extension_polynomial,
};
#[cfg(test)]
use super::{CommonProofByteSink, CommonProofPrivateCoinSource};

/// Complete application-owned inputs for one production common-proof
/// attempt.  Only genuine pre-challenge source columns are accepted:
/// integer-lift reversed and auxiliary columns are always synthesized by the
/// common prover.
pub(crate) struct CommonProofGenerationInput<'input> {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; HASH_BYTE_LENGTH],
    pub(crate) canonical_application_statement_bytes: &'input [u8],
    pub(crate) relation_plan: &'input CompiledRelationPlan,
    pub(crate) relation_context: &'input RelationPlanCheckContext,
    pub(crate) schedule_position: Option<u32>,
    pub(crate) top_count: Option<u16>,
    pub(crate) relation_trees: Vec<RelationProofTreeInput>,
    pub(crate) source_polynomial_provider: Box<dyn CommonProofSourcePolynomialProvider>,
    pub(crate) maximum_external_memory_chunk_byte_length: u32,
    pub(crate) maximum_proof_transport_chunk_byte_length: usize,
    pub(crate) maximum_prefetched_query_byte_length: u64,
}

#[derive(Debug)]
pub(crate) enum CommonProofGenerationError<StorageError, CoinError, SinkError> {
    Prover(CommonProofProverError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    StoragePlan(ProofExternalMemoryError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
    CoinSource(CoinError),
    Sink(SinkError),
    #[cfg(test)]
    Cleanup {
        original: Box<CommonProofGenerationError<StorageError, CoinError, SinkError>>,
        cleanup: ProofExternalMemoryExecutorError<StorageError>,
    },
}

impl<StorageError, CoinError, SinkError> core::fmt::Display
    for CommonProofGenerationError<StorageError, CoinError, SinkError>
where
    StorageError: core::fmt::Debug,
    CoinError: core::fmt::Debug,
    SinkError: core::fmt::Debug,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Prover(error) => write!(formatter, "common proof prover failed: {error:?}"),
            Self::Profile(error) => write!(formatter, "common proof profile failed: {error:?}"),
            Self::Relation(error) => write!(formatter, "common proof relation failed: {error:?}"),
            Self::Body(error) => write!(formatter, "common proof body failed: {error:?}"),
            Self::Transcript(error) => {
                write!(formatter, "common proof transcript failed: {error:?}")
            }
            Self::StoragePlan(error) => {
                write!(formatter, "common proof storage plan failed: {error:?}")
            }
            Self::Storage(error) => write!(formatter, "common proof storage failed: {error:?}"),
            Self::CoinSource(error) => {
                write!(
                    formatter,
                    "common proof private coin source failed: {error:?}"
                )
            }
            Self::Sink(error) => write!(formatter, "common proof output sink failed: {error:?}"),
            #[cfg(test)]
            Self::Cleanup { original, cleanup } => write!(
                formatter,
                "common proof failed ({original}); cleanup also failed: {cleanup:?}"
            ),
        }
    }
}

impl<StorageError, CoinError, SinkError> std::error::Error
    for CommonProofGenerationError<StorageError, CoinError, SinkError>
where
    StorageError: core::fmt::Debug,
    CoinError: core::fmt::Debug,
    SinkError: core::fmt::Debug,
{
}

pub(super) type CommonProofGenerationPollResult<StorageError, CoinError, SinkError> = Result<
    CommonProofGenerationPoll,
    CommonProofGenerationError<StorageError, CoinError, SinkError>,
>;

#[cfg(test)]
pub(super) type CompletedCommonProofGenerationResult<Storage, Coins, Sink> = Result<
    (),
    CommonProofGenerationError<
        <Storage as ProofExternalMemory>::Error,
        <Coins as CommonProofPrivateCoinSource>::Error,
        <Sink as CommonProofByteSink>::Error,
    >,
>;

pub(crate) struct GeneratedCommonProofStoragePlan {
    pub(super) external_memory_plan: ProofExternalMemoryPlan,
    pub(super) external_memory_requirement: CommonProofExternalMemoryRequirement,
    pub(super) tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
    pub(super) replay_polynomial_plans:
        BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayPolynomialPlan>,
    pub(super) relation_evaluation_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
    pub(super) setup_polynomial_query_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
    pub(super) quotient_constraint_transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, ExternalStockhamTransformPlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GeneratedCommonProofStorageResidentPayload {
    storage_plan_catalog_byte_length: u64,
    executor_catalog_byte_length: u64,
}

#[cfg(test)]
struct GeneratedCommonProofStorageResidentPayloadRequirementInput<'input> {
    tree_plans: &'input BTreeMap<u16, CommonProofMerkleStoragePlan>,
    replay_polynomial_plan_count: usize,
    relation_evaluation_transform_plan_count: usize,
    relation_transform_resident_owned_payload_byte_length: u64,
    setup_polynomial_query_transform_plan_count: usize,
    setup_query_transform_resident_owned_payload_byte_length: u64,
    quotient_constraint_transform_plan_count: usize,
    quotient_transform_resident_owned_payload_byte_length: u64,
    object_lifecycle_count: u32,
}

fn external_transform_resident_owned_payload_byte_length(
    plan: &ExternalStockhamTransformPlan,
) -> Result<u64, CommonProofProverError> {
    plan.resident_owned_payload_byte_length().map_err(|error| {
        match map_external_polynomial_plan_error(error) {
            ProofExternalMemoryError::ResourceLimitExceeded => {
                CommonProofProverError::CountOverflow
            }
            _ => CommonProofProverError::InvalidInput,
        }
    })
}

fn map_entry_payload_byte_length<Key, Value>(
    entry_count: usize,
) -> Result<u64, CommonProofProverError> {
    u64::try_from(entry_count)
        .ok()
        .and_then(|count| {
            count.checked_mul(u64::try_from(std::mem::size_of::<(Key, Value)>()).ok()?)
        })
        .ok_or(CommonProofProverError::CountOverflow)
}

impl GeneratedCommonProofStoragePlan {
    fn resident_owned_payload(
        &self,
    ) -> Result<GeneratedCommonProofStorageResidentPayload, CommonProofProverError> {
        let initial_tree_plan_catalog_byte_length = self.tree_plans.values().try_fold(
            map_entry_payload_byte_length::<u16, CommonProofMerkleStoragePlan>(
                self.tree_plans.len(),
            )?,
            |total, plan| checked_resident_add(total, plan.resident_owned_payload_byte_length()?),
        )?;
        let completed_tree_catalog_byte_length = self.tree_plans.values().try_fold(
            map_entry_payload_byte_length::<u16, StoredCommonProofMerkleTree>(
                self.tree_plans.len(),
            )?,
            |total, plan| {
                checked_resident_add(
                    total,
                    plan.stored_tree_resident_owned_payload_byte_length()?,
                )
            },
        )?;
        let replay_plan_catalog_byte_length = map_entry_payload_byte_length::<
            CommonProofReplayPolynomialKey,
            CommonProofReplayPolynomialPlan,
        >(self.replay_polynomial_plans.len())?;
        let relation_transform_resident_owned_payload_byte_length = self
            .relation_evaluation_transform_plans
            .values()
            .try_fold(0_u64, |total, plan| {
                checked_resident_add(
                    total,
                    external_transform_resident_owned_payload_byte_length(plan)?,
                )
            })?;
        let relation_transform_catalog_byte_length = checked_resident_add(
            map_entry_payload_byte_length::<u32, ExternalStockhamTransformPlan>(
                self.relation_evaluation_transform_plans.len(),
            )?,
            relation_transform_resident_owned_payload_byte_length,
        )?;
        let setup_query_transform_catalog_byte_length = self
            .setup_polynomial_query_transform_plans
            .values()
            .try_fold(
                map_entry_payload_byte_length::<u32, ExternalStockhamTransformPlan>(
                    self.setup_polynomial_query_transform_plans.len(),
                )?,
                |total, plan| {
                    checked_resident_add(
                        total,
                        external_transform_resident_owned_payload_byte_length(plan)?,
                    )
                },
            )?;
        let quotient_transform_catalog_byte_length =
            self.quotient_constraint_transform_plans.values().try_fold(
                map_entry_payload_byte_length::<
                    CommonProofQuotientConstraintTransformKey,
                    ExternalStockhamTransformPlan,
                >(self.quotient_constraint_transform_plans.len())?,
                |total, plan| {
                    checked_resident_add(
                        total,
                        external_transform_resident_owned_payload_byte_length(plan)?,
                    )
                },
            )?;
        let storage_plan_catalog_byte_length = [
            initial_tree_plan_catalog_byte_length.max(completed_tree_catalog_byte_length),
            replay_plan_catalog_byte_length,
            relation_transform_catalog_byte_length,
            setup_query_transform_catalog_byte_length,
            quotient_transform_catalog_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_resident_add)?;
        let executor_catalog_byte_length =
            ProofExternalMemoryExecutor::planned_resident_owned_payload_byte_length(
                &self.external_memory_plan,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?;
        Ok(GeneratedCommonProofStorageResidentPayload {
            storage_plan_catalog_byte_length,
            executor_catalog_byte_length,
        })
    }
}

#[cfg(test)]
fn generated_common_proof_storage_resident_payload_requirement(
    input: GeneratedCommonProofStorageResidentPayloadRequirementInput<'_>,
) -> Result<GeneratedCommonProofStorageResidentPayload, CommonProofProverError> {
    let GeneratedCommonProofStorageResidentPayloadRequirementInput {
        tree_plans,
        replay_polynomial_plan_count,
        relation_evaluation_transform_plan_count,
        relation_transform_resident_owned_payload_byte_length,
        setup_polynomial_query_transform_plan_count,
        setup_query_transform_resident_owned_payload_byte_length,
        quotient_constraint_transform_plan_count,
        quotient_transform_resident_owned_payload_byte_length,
        object_lifecycle_count,
    } = input;
    let initial_tree_plan_catalog_byte_length = tree_plans.values().try_fold(
        map_entry_payload_byte_length::<u16, CommonProofMerkleStoragePlan>(tree_plans.len())?,
        |total, plan| checked_resident_add(total, plan.resident_owned_payload_byte_length()?),
    )?;
    let completed_tree_catalog_byte_length = tree_plans.values().try_fold(
        map_entry_payload_byte_length::<u16, StoredCommonProofMerkleTree>(tree_plans.len())?,
        |total, plan| {
            checked_resident_add(
                total,
                plan.stored_tree_resident_owned_payload_byte_length()?,
            )
        },
    )?;
    let replay_plan_catalog_byte_length = map_entry_payload_byte_length::<
        CommonProofReplayPolynomialKey,
        CommonProofReplayPolynomialPlan,
    >(replay_polynomial_plan_count)?;
    let relation_transform_catalog_byte_length = checked_resident_add(
        map_entry_payload_byte_length::<u32, ExternalStockhamTransformPlan>(
            relation_evaluation_transform_plan_count,
        )?,
        relation_transform_resident_owned_payload_byte_length,
    )?;
    let setup_query_transform_catalog_byte_length = checked_resident_add(
        map_entry_payload_byte_length::<u32, ExternalStockhamTransformPlan>(
            setup_polynomial_query_transform_plan_count,
        )?,
        setup_query_transform_resident_owned_payload_byte_length,
    )?;
    let quotient_transform_catalog_byte_length = checked_resident_add(
        map_entry_payload_byte_length::<
            CommonProofQuotientConstraintTransformKey,
            ExternalStockhamTransformPlan,
        >(quotient_constraint_transform_plan_count)?,
        quotient_transform_resident_owned_payload_byte_length,
    )?;
    let storage_plan_catalog_byte_length = [
        initial_tree_plan_catalog_byte_length.max(completed_tree_catalog_byte_length),
        replay_plan_catalog_byte_length,
        relation_transform_catalog_byte_length,
        setup_query_transform_catalog_byte_length,
        quotient_transform_catalog_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_resident_add)?;
    let executor_catalog_byte_length =
        ProofExternalMemoryExecutor::required_resident_owned_payload_byte_length(
            object_lifecycle_count,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    Ok(GeneratedCommonProofStorageResidentPayload {
        storage_plan_catalog_byte_length,
        executor_catalog_byte_length,
    })
}

struct GeneratedCommonProofStorageGeometry {
    step_count: u32,
    maximum_chunk_byte_length: u32,
    maximum_transaction_payload_byte_length: u64,
    maximum_transaction_operation_count: u32,
    distinct_physical_object_count: u32,
    object_lifecycle_count: u32,
    maximum_stored_byte_length: u64,
    maximum_total_written_byte_length: u64,
    maximum_total_read_byte_length: u64,
    maximum_transaction_count: u64,
    #[cfg(test)]
    resident_payload_requirement: GeneratedCommonProofStorageResidentPayload,
    #[cfg(test)]
    relation_evaluation_transform_plan_count: usize,
    object_plans: Vec<ProofExternalMemoryObjectPlan>,
    tree_plans: BTreeMap<u16, CommonProofMerkleStoragePlan>,
    replay_polynomial_plans:
        BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayPolynomialPlan>,
    relation_evaluation_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
    setup_polynomial_query_transform_plans: BTreeMap<u32, ExternalStockhamTransformPlan>,
    quotient_constraint_transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, ExternalStockhamTransformPlan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeneratedCommonProofStorageGeometryMode {
    RetainExecutionPlan,
    #[cfg(test)]
    RequirementOnly,
}

impl GeneratedCommonProofStorageGeometryMode {
    const fn retains_execution_plan(self) -> bool {
        matches!(self, Self::RetainExecutionPlan)
    }
}

/// Exact liveness accounting for requirement-only derivation. The production
/// planner retains every lifecycle so the executor can consume it. Diagnostics
/// instead aggregate checked byte deltas by executor step and retain only one
/// last-use marker per physical object. This keeps the derivation proportional
/// to the schedule and object namespace rather than to every projected
/// transform lifecycle.
struct CommonProofExternalMemoryRequirementAccumulator {
    step_count: u32,
    liveness_byte_length_delta_by_step: Vec<i64>,
    deletion_step_is_used: Vec<bool>,
    last_use_step_by_object_ordinal: Vec<u32>,
    object_lifecycle_count: u64,
}

impl CommonProofExternalMemoryRequirementAccumulator {
    fn new(step_count: u32) -> Result<Self, GeneratedCommonProofStoragePlanError> {
        if step_count == 0 {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        let step_count_usize = usize::try_from(step_count).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let sweep_point_count =
            step_count_usize
                .checked_add(1)
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
        let mut liveness_byte_length_delta_by_step = Vec::new();
        liveness_byte_length_delta_by_step
            .try_reserve_exact(sweep_point_count)
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::AllocationLimitExceeded,
                )
            })?;
        liveness_byte_length_delta_by_step.resize(sweep_point_count, 0_i64);
        let mut deletion_step_is_used = Vec::new();
        deletion_step_is_used
            .try_reserve_exact(step_count_usize)
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::AllocationLimitExceeded,
                )
            })?;
        deletion_step_is_used.resize(step_count_usize, false);
        Ok(Self {
            step_count,
            liveness_byte_length_delta_by_step,
            deletion_step_is_used,
            last_use_step_by_object_ordinal: Vec::new(),
            object_lifecycle_count: 0,
        })
    }

    fn include_object_plans(
        &mut self,
        object_plans: &[ProofExternalMemoryObjectPlan],
    ) -> Result<(), GeneratedCommonProofStoragePlanError> {
        for object_plan in object_plans {
            if object_plan.exact_byte_length() == 0
                || object_plan.issued_step() > object_plan.seal_step()
                || object_plan.seal_step() > object_plan.last_use_step()
                || object_plan.last_use_step() >= self.step_count
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
            let object_ordinal = usize::try_from(object_plan.object().ordinal()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            if object_ordinal >= self.last_use_step_by_object_ordinal.len() {
                let required_length = object_ordinal.checked_add(1).ok_or(
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ),
                )?;
                let additional_length = required_length
                    .checked_sub(self.last_use_step_by_object_ordinal.len())
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                self.last_use_step_by_object_ordinal
                    .try_reserve_exact(additional_length)
                    .map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                self.last_use_step_by_object_ordinal
                    .resize(required_length, u32::MAX);
            }
            let previous_last_use_step = self.last_use_step_by_object_ordinal[object_ordinal];
            if previous_last_use_step != u32::MAX
                && previous_last_use_step >= object_plan.issued_step()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
            self.last_use_step_by_object_ordinal[object_ordinal] = object_plan.last_use_step();

            let issued_step = usize::try_from(object_plan.issued_step()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            let release_step = usize::try_from(object_plan.last_use_step().checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?)
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            let exact_byte_length =
                i64::try_from(object_plan.exact_byte_length()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?;
            self.liveness_byte_length_delta_by_step[issued_step] = self
                .liveness_byte_length_delta_by_step[issued_step]
                .checked_add(exact_byte_length)
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            self.liveness_byte_length_delta_by_step[release_step] = self
                .liveness_byte_length_delta_by_step[release_step]
                .checked_sub(exact_byte_length)
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            self.deletion_step_is_used[usize::try_from(object_plan.last_use_step()).map_err(
                |_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                },
            )?] = true;
            self.object_lifecycle_count = self.object_lifecycle_count.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
        }
        Ok(())
    }

    fn finish(
        self,
        next_object_ordinal: u32,
    ) -> Result<(u32, u32, u64, u64), GeneratedCommonProofStoragePlanError> {
        let distinct_physical_object_count =
            u32::try_from(self.last_use_step_by_object_ordinal.len()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
        if distinct_physical_object_count != next_object_ordinal
            || self.last_use_step_by_object_ordinal.contains(&u32::MAX)
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        let object_lifecycle_count = u32::try_from(self.object_lifecycle_count).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        if object_lifecycle_count < distinct_physical_object_count {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }

        let mut live_byte_length = 0_i64;
        let mut peak_stored_byte_length = 0_i64;
        for byte_length_delta in self.liveness_byte_length_delta_by_step {
            live_byte_length = live_byte_length.checked_add(byte_length_delta).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            if live_byte_length < 0 {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
            peak_stored_byte_length = peak_stored_byte_length.max(live_byte_length);
        }
        if live_byte_length != 0 || peak_stored_byte_length == 0 {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        let deletion_transaction_count = u64::try_from(
            self.deletion_step_is_used
                .into_iter()
                .filter(|step_is_used| *step_is_used)
                .count(),
        )
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        Ok((
            distinct_physical_object_count,
            object_lifecycle_count,
            u64::try_from(peak_stored_byte_length).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?,
            deletion_transaction_count,
        ))
    }
}

#[cfg(test)]
mod external_memory_requirement_accumulator_tests {
    use super::*;

    fn object_plan(
        object_ordinal: u32,
        exact_byte_length: u64,
        issued_step: u32,
        last_use_step: u32,
    ) -> ProofExternalMemoryObjectPlan {
        ProofExternalMemoryObjectPlan::new(
            ProofExternalMemoryObject::new(object_ordinal),
            ProofExternalMemoryProtection::PublicIntegrity,
            exact_byte_length,
            issued_step,
            issued_step,
            last_use_step,
        )
    }

    #[test]
    fn compressed_requirement_sweep_preserves_reuse_liveness_and_deletion_batches() {
        let mut accumulator = CommonProofExternalMemoryRequirementAccumulator::new(4)
            .expect("the four-step diagnostic sweep allocates");
        accumulator
            .include_object_plans(&[
                object_plan(0, 10, 0, 1),
                object_plan(1, 20, 1, 2),
                object_plan(0, 30, 2, 3),
            ])
            .expect("the non-overlapping physical-object reuse is valid");

        assert_eq!(
            accumulator.finish(2),
            Ok((2, 3, 50, 3)),
            "release events must precede issuances at the same step without hiding the exact peak",
        );
    }

    #[test]
    fn compressed_requirement_sweep_rejects_overlapping_physical_object_reuse() {
        let mut accumulator = CommonProofExternalMemoryRequirementAccumulator::new(3)
            .expect("the three-step diagnostic sweep allocates");
        let error = accumulator
            .include_object_plans(&[object_plan(0, 10, 0, 1), object_plan(0, 20, 1, 2)])
            .expect_err("one physical object cannot have overlapping lifecycles");

        assert_eq!(
            error,
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidInput),
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofExternalMemoryRequirement {
    step_count: u32,
    maximum_chunk_byte_length: u32,
    maximum_transaction_payload_byte_length: u64,
    distinct_physical_object_count: u32,
    object_lifecycle_count: u32,
    peak_stored_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count: u64,
}

impl CommonProofExternalMemoryRequirement {
    pub(crate) const fn step_count(self) -> u32 {
        self.step_count
    }

    pub(crate) const fn maximum_chunk_byte_length(self) -> u32 {
        self.maximum_chunk_byte_length
    }

    pub(crate) const fn maximum_transaction_payload_byte_length(self) -> u64 {
        self.maximum_transaction_payload_byte_length
    }

    pub(crate) const fn distinct_physical_object_count(self) -> u32 {
        self.distinct_physical_object_count
    }

    pub(crate) const fn object_lifecycle_count(self) -> u32 {
        self.object_lifecycle_count
    }

    pub(crate) const fn peak_stored_byte_length(self) -> u64 {
        self.peak_stored_byte_length
    }

    pub(crate) const fn total_written_byte_length(self) -> u64 {
        self.total_written_byte_length
    }

    pub(crate) const fn total_read_byte_length(self) -> u64 {
        self.total_read_byte_length
    }

    pub(crate) const fn transaction_count(self) -> u64 {
        self.transaction_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CommonProofReplayPolynomialKey {
    RelationColumn(u32),
    QuotientComponent(u16),
    OpeningBatchMask,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CommonProofReplayReadRequirement {
    read_count: u64,
    last_use_step: Option<u32>,
}

impl CommonProofReplayReadRequirement {
    fn include_reads(
        &mut self,
        read_count: u64,
        executor_step: u32,
    ) -> Result<(), CommonProofProverError> {
        self.read_count = self
            .read_count
            .checked_add(read_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.include_use(executor_step);
        Ok(())
    }

    fn include_use(&mut self, executor_step: u32) {
        self.last_use_step = Some(self.last_use_step.map_or(executor_step, |last_use_step| {
            last_use_step.max(executor_step)
        }));
    }
}

struct PendingCommonProofReplayObjectPlan {
    key: CommonProofReplayPolynomialKey,
    object: ProofExternalMemoryObject,
    protection: ProofExternalMemoryProtection,
    exact_byte_length: u64,
    issued_step: u32,
}

fn include_common_proof_replay_reads(
    requirements: &mut BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayReadRequirement>,
    key: CommonProofReplayPolynomialKey,
    read_count: u64,
    executor_step: u32,
) -> Result<(), CommonProofProverError> {
    if read_count == 0 {
        return Ok(());
    }
    requirements
        .entry(key)
        .or_default()
        .include_reads(read_count, executor_step)
}

fn include_common_proof_replay_use(
    requirements: &mut BTreeMap<CommonProofReplayPolynomialKey, CommonProofReplayReadRequirement>,
    key: CommonProofReplayPolynomialKey,
    executor_step: u32,
) {
    requirements
        .entry(key)
        .or_default()
        .include_use(executor_step);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CommonProofReplayPolynomialPlan {
    pub(super) object: ProofExternalMemoryObject,
    pub(super) value_type: RelationColumnValueType,
    pub(super) coefficient_count: usize,
    pub(super) exact_byte_length: u64,
}

pub(super) enum CommonProofReplayPolynomialRef<'polynomial> {
    Source(&'polynomial CommonProofSourcePolynomial),
    Extension(&'polynomial [ProofChallengeExtensionElement]),
}

impl CommonProofReplayPolynomialRef<'_> {
    fn value_type(&self) -> RelationColumnValueType {
        match self {
            Self::Source(polynomial) => polynomial.value_type(),
            Self::Extension(_) => RelationColumnValueType::ChallengeExtension,
        }
    }

    fn coefficient_count(&self) -> usize {
        match self {
            Self::Source(polynomial) => polynomial.coefficient_count(),
            Self::Extension(coefficients) => coefficients.len(),
        }
    }

    fn append_coefficient_bytes(
        &self,
        coefficient_index: usize,
        destination: &mut Vec<u8>,
    ) -> Result<(), CommonProofProverError> {
        match self {
            Self::Source(CommonProofSourcePolynomial::Base(coefficients)) => {
                destination.extend_from_slice(
                    &coefficients
                        .get(coefficient_index)
                        .copied()
                        .unwrap_or(ProofBaseFieldElement::ZERO)
                        .canonical()
                        .to_le_bytes(),
                );
            }
            Self::Source(CommonProofSourcePolynomial::Extension(coefficients)) => {
                for coordinate in coefficients
                    .get(coefficient_index)
                    .copied()
                    .unwrap_or(ProofChallengeExtensionElement::ZERO)
                    .canonical_coordinates()
                {
                    destination.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
            Self::Extension(coefficients) => {
                for coordinate in coefficients
                    .get(coefficient_index)
                    .copied()
                    .unwrap_or(ProofChallengeExtensionElement::ZERO)
                    .canonical_coordinates()
                {
                    destination.extend_from_slice(&coordinate.to_le_bytes());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommonProofReplayPolynomialWriterPhase {
    Begin,
    Append,
    Seal,
    Complete,
}

pub(super) struct CommonProofReplayPolynomialWriter {
    plan: CommonProofReplayPolynomialPlan,
    phase: CommonProofReplayPolynomialWriterPhase,
    next_coefficient_index: usize,
    pending_coefficient_bytes: Zeroizing<Vec<u8>>,
    pending_coefficient_byte_offset: usize,
    write_chunk: Zeroizing<Vec<u8>>,
}

impl CommonProofReplayPolynomialWriter {
    pub(super) fn new(
        plan: CommonProofReplayPolynomialPlan,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = u64::try_from(plan.coefficient_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(resident_value_byte_length(plan.value_type))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if polynomial.value_type() != plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > plan.coefficient_count
            || expected_byte_length != plan.exact_byte_length
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            plan,
            phase: CommonProofReplayPolynomialWriterPhase::Begin,
            next_coefficient_index: 0,
            pending_coefficient_bytes: Zeroizing::new(Vec::new()),
            pending_coefficient_byte_offset: 0,
            write_chunk: Zeroizing::new(Vec::new()),
        })
    }

    pub(super) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        polynomial: CommonProofReplayPolynomialRef<'_>,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if polynomial.value_type() != self.plan.value_type
            || polynomial.coefficient_count() == 0
            || polynomial.coefficient_count() > self.plan.coefficient_count
        {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        match self.phase {
            CommonProofReplayPolynomialWriterPhase::Begin => {
                executor.begin_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Append;
                Ok(false)
            }
            CommonProofReplayPolynomialWriterPhase::Append => {
                let value_byte_length =
                    usize::try_from(resident_value_byte_length(self.plan.value_type))
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                let maximum_chunk_byte_length =
                    usize::try_from(executor.maximum_chunk_byte_length())
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                if maximum_chunk_byte_length == 0 {
                    return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
                }
                loop {
                    if self.write_chunk.len() == maximum_chunk_byte_length {
                        executor.append_object_bytes(
                            storage,
                            self.plan.object,
                            &self.write_chunk,
                        )?;
                        self.write_chunk.zeroize();
                        if !self.pending_coefficient_bytes.is_empty()
                            && self.pending_coefficient_byte_offset
                                == self.pending_coefficient_bytes.len()
                        {
                            self.pending_coefficient_bytes.zeroize();
                            self.pending_coefficient_byte_offset = 0;
                            self.next_coefficient_index = self
                                .next_coefficient_index
                                .checked_add(1)
                                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                        }
                        return Ok(false);
                    }
                    if self.pending_coefficient_bytes.is_empty() {
                        if self.next_coefficient_index == self.plan.coefficient_count {
                            if self.write_chunk.is_empty() {
                                executor.seal_object(storage, self.plan.object)?;
                                self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                                return Ok(true);
                            }
                            executor.append_object_bytes(
                                storage,
                                self.plan.object,
                                &self.write_chunk,
                            )?;
                            self.write_chunk.zeroize();
                            self.phase = CommonProofReplayPolynomialWriterPhase::Seal;
                            return Ok(false);
                        }
                        self.pending_coefficient_bytes
                            .try_reserve_exact(value_byte_length)
                            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                        polynomial
                            .append_coefficient_bytes(
                                self.next_coefficient_index,
                                &mut self.pending_coefficient_bytes,
                            )
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
                        if self.pending_coefficient_bytes.len() != value_byte_length {
                            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
                        }
                        self.pending_coefficient_byte_offset = 0;
                    }
                    if self.pending_coefficient_byte_offset >= self.pending_coefficient_bytes.len()
                        || self.write_chunk.len() > maximum_chunk_byte_length
                    {
                        return Err(ProofExternalMemoryError::InvalidLifecycle.into());
                    }
                    let remaining_chunk_capacity =
                        maximum_chunk_byte_length - self.write_chunk.len();
                    self.write_chunk
                        .try_reserve_exact(remaining_chunk_capacity)
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                    let copied_byte_length = remaining_chunk_capacity.min(
                        self.pending_coefficient_bytes.len() - self.pending_coefficient_byte_offset,
                    );
                    let pending_coefficient_end = self
                        .pending_coefficient_byte_offset
                        .checked_add(copied_byte_length)
                        .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                    self.write_chunk.extend_from_slice(
                        &self.pending_coefficient_bytes
                            [self.pending_coefficient_byte_offset..pending_coefficient_end],
                    );
                    self.pending_coefficient_byte_offset = pending_coefficient_end;
                    if self.write_chunk.len() < maximum_chunk_byte_length
                        && self.pending_coefficient_byte_offset
                            == self.pending_coefficient_bytes.len()
                    {
                        self.pending_coefficient_bytes.zeroize();
                        self.pending_coefficient_byte_offset = 0;
                        self.next_coefficient_index = self
                            .next_coefficient_index
                            .checked_add(1)
                            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                    }
                }
            }
            CommonProofReplayPolynomialWriterPhase::Seal => {
                executor.seal_object(storage, self.plan.object)?;
                self.phase = CommonProofReplayPolynomialWriterPhase::Complete;
                Ok(true)
            }
            CommonProofReplayPolynomialWriterPhase::Complete => Ok(true),
        }
    }
}

enum CommonProofReplayPolynomialCoefficients {
    Base(Zeroizing<Vec<ProofBaseFieldElement>>),
    Extension(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

pub(super) struct CommonProofReplayPolynomialReader {
    plan: CommonProofReplayPolynomialPlan,
    next_coefficient_index: usize,
    coefficients: CommonProofReplayPolynomialCoefficients,
}

impl CommonProofReplayPolynomialReader {
    pub(super) fn new(
        plan: CommonProofReplayPolynomialPlan,
    ) -> Result<Self, CommonProofProverError> {
        let expected_byte_length = u64::try_from(plan.coefficient_count)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(resident_value_byte_length(plan.value_type))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if plan.coefficient_count == 0 || expected_byte_length != plan.exact_byte_length {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let coefficients = match plan.value_type {
            RelationColumnValueType::BaseField => {
                CommonProofReplayPolynomialCoefficients::Base(Zeroizing::new(Vec::new()))
            }
            RelationColumnValueType::ChallengeExtension => {
                CommonProofReplayPolynomialCoefficients::Extension(Zeroizing::new(Vec::new()))
            }
        };
        Ok(Self {
            plan,
            next_coefficient_index: 0,
            coefficients,
        })
    }

    pub(super) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.next_coefficient_index >= self.plan.coefficient_count {
            return Ok(true);
        }
        let value_byte_length = usize::try_from(resident_value_byte_length(self.plan.value_type))
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let maximum_coefficient_count = usize::try_from(executor.maximum_chunk_byte_length())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
            .checked_div(value_byte_length)
            .filter(|count| *count != 0)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let coefficient_count = maximum_coefficient_count
            .min(self.plan.coefficient_count - self.next_coefficient_index);
        let byte_length = coefficient_count
            .checked_mul(value_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(byte_length)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        bytes.resize(byte_length, 0);
        let offset = self
            .next_coefficient_index
            .checked_mul(value_byte_length)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        executor.read_object_bytes(storage, self.plan.object, offset, &mut bytes)?;
        match &mut self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(coefficients) => {
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                for encoded in bytes.chunks_exact(8) {
                    let mut value = [0_u8; 8];
                    value.copy_from_slice(encoded);
                    coefficients.push(
                        ProofBaseFieldElement::from_canonical(u64::from_le_bytes(value))
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                    );
                }
            }
            CommonProofReplayPolynomialCoefficients::Extension(coefficients) => {
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                for encoded in bytes.chunks_exact(value_byte_length) {
                    let mut coordinates = [0_u64; PROOF_CHALLENGE_EXTENSION_DEGREE];
                    for (coordinate, coordinate_bytes) in
                        coordinates.iter_mut().zip(encoded.chunks_exact(8))
                    {
                        let mut value = [0_u8; 8];
                        value.copy_from_slice(coordinate_bytes);
                        *coordinate = u64::from_le_bytes(value);
                    }
                    coefficients.push(
                        ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
                            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                    );
                }
            }
        }
        self.next_coefficient_index += coefficient_count;
        Ok(self.next_coefficient_index == self.plan.coefficient_count)
    }

    pub(super) fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        if self.next_coefficient_index != self.plan.coefficient_count {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(match self.coefficients {
            CommonProofReplayPolynomialCoefficients::Base(mut coefficients) => {
                while coefficients.len() > 1
                    && coefficients.last() == Some(&ProofBaseFieldElement::ZERO)
                {
                    coefficients.pop();
                }
                CommonProofSourcePolynomial::Base(coefficients)
            }
            CommonProofReplayPolynomialCoefficients::Extension(mut coefficients) => {
                trim_extension_polynomial(&mut coefficients);
                CommonProofSourcePolynomial::Extension(coefficients)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GeneratedCommonProofStoragePlanError {
    Prover(CommonProofProverError),
    Storage(ProofExternalMemoryError),
}

fn checked_add_u64(left: u64, right: u64) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_add(right)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))
}

fn checked_multiply_u64(
    left: u64,
    right: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    left.checked_mul(right)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))
}

fn ceiling_division_u64(
    numerator: u64,
    denominator: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    if numerator == 0 || denominator == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    Ok(numerator.checked_add(denominator - 1).ok_or(
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
    )? / denominator)
}

/// Gives one transform its own final-output identity while alternating both
/// identities across non-overlapping Stockham pass lifecycles.
fn stockham_output_object_pair(
    first_object_ordinal: u32,
) -> Result<[ProofExternalMemoryObject; 2], GeneratedCommonProofStoragePlanError> {
    let second_object_ordinal =
        first_object_ordinal
            .checked_add(1)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
    second_object_ordinal
        .checked_add(1)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    Ok([
        ProofExternalMemoryObject::new(first_object_ordinal),
        ProofExternalMemoryObject::new(second_object_ordinal),
    ])
}

struct CommonProofQuotientStreamRequirement {
    constraint_columns: Vec<Vec<u32>>,
    transform_count: u64,
    total_read_byte_length: u64,
    read_transaction_count: u64,
    maximum_rotation_block_byte_length: u64,
    maximum_read_working_set_byte_length: u64,
    maximum_read_transaction_overlap_peak_byte_length: u64,
    maximum_read_subphase_transient_byte_length: u64,
}

fn common_proof_quotient_stream_requirement(
    variant: &RelationPlanVariant,
    maximum_chunk_byte_length: u64,
) -> Result<CommonProofQuotientStreamRequirement, CommonProofProverError> {
    if maximum_chunk_byte_length == 0
        || variant.trace_domain_size() == 0
        || !variant
            .evaluation_domain_size()
            .is_multiple_of(variant.trace_domain_size())
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let evaluation_domain_size = usize::try_from(variant.evaluation_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_domain_size = usize::try_from(variant.trace_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_rotation_stride =
        usize::try_from(variant.evaluation_domain_size() / variant.trace_domain_size())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut constraint_columns = Vec::new();
    constraint_columns
        .try_reserve_exact(variant.constraint_count())
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    let mut transform_count = 0_u64;
    let mut total_read_byte_length = 0_u64;
    let mut read_transaction_count = 0_u64;
    let mut maximum_rotation_block_byte_length = 0_u64;
    let mut maximum_read_working_set_byte_length = 0_u64;
    let mut maximum_read_transaction_overlap_peak_byte_length = 0_u64;
    let mut maximum_read_subphase_transient_byte_length = 0_u64;
    let extension_value_byte_length =
        u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;

    for constraint_ordinal in 0..variant.constraint_count() {
        let queries = variant.constraint_column_queries(constraint_ordinal)?;
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(queries.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        for query in &queries {
            if columns.last().copied() != Some(query.column_ordinal()) {
                columns.push(query.column_ordinal());
            }
        }
        let mut block_start = 0_usize;
        while block_start < evaluation_domain_size {
            let block_end = block_start
                .checked_add(COMMON_PROOF_RELATION_EVALUATION_BLOCK_LENGTH)
                .ok_or(CommonProofProverError::CountOverflow)?
                .min(evaluation_domain_size);
            let block_element_count = block_end - block_start;
            let query_block_capacity_byte_length = u64::try_from(block_element_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?
                .checked_mul(extension_value_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let mut completed_query_block_byte_length = 0_u64;
            for query in &queries {
                let column = variant
                    .ordered_columns()
                    .get(
                        usize::try_from(query.column_ordinal())
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                let encoded_value_byte_length = external_value_byte_length(column.value_type());
                let maximum_chunk_element_count = maximum_chunk_byte_length
                    .checked_div(encoded_value_byte_length)
                    .filter(|count| *count != 0)
                    .ok_or(CommonProofProverError::InvalidInput)?;
                let rotated_block_start = rotated_relation_evaluation_position(
                    block_start,
                    evaluation_domain_size,
                    trace_domain_size,
                    trace_rotation_stride,
                    query.rotation_is_negative(),
                    query.rotation_magnitude(),
                )?;
                let mut logical_value_offset = 0_usize;
                while logical_value_offset < block_element_count {
                    let element_offset = rotated_block_start
                        .checked_add(logical_value_offset)
                        .ok_or(CommonProofProverError::CountOverflow)?
                        % evaluation_domain_size;
                    let element_count = (block_element_count - logical_value_offset)
                        .min(evaluation_domain_size - element_offset)
                        .min(
                            usize::try_from(maximum_chunk_element_count)
                                .map_err(|_| CommonProofProverError::CountOverflow)?,
                        );
                    if element_count == 0 {
                        return Err(CommonProofProverError::InvalidQuotient);
                    }
                    let encoded_read_byte_length = u64::try_from(element_count)
                        .map_err(|_| CommonProofProverError::CountOverflow)?
                        .checked_mul(encoded_value_byte_length)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    total_read_byte_length = total_read_byte_length
                        .checked_add(encoded_read_byte_length)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let read_resident_requirement =
                        external_polynomial_extension_read_resident_memory_requirement(
                            column.value_type(),
                            u64::try_from(element_count)
                                .map_err(|_| CommonProofProverError::CountOverflow)?,
                        )
                        .map_err(|error| match error {
                            super::ExternalPolynomialError::CountOverflow => {
                                CommonProofProverError::CountOverflow
                            }
                            super::ExternalPolynomialError::AllocationLimitExceeded => {
                                CommonProofProverError::AllocationLimitExceeded
                            }
                            _ => CommonProofProverError::InvalidInput,
                        })?;
                    maximum_read_working_set_byte_length = maximum_read_working_set_byte_length
                        .max(read_resident_requirement.component_working_set_byte_length());
                    maximum_read_transaction_overlap_peak_byte_length =
                        maximum_read_transaction_overlap_peak_byte_length
                            .max(read_resident_requirement.transaction_overlap_peak_byte_length());
                    let builder_byte_length_during_read = completed_query_block_byte_length
                        .checked_add(if logical_value_offset == 0 {
                            0
                        } else {
                            query_block_capacity_byte_length
                        })
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let read_transaction_peak_byte_length = builder_byte_length_during_read
                        .checked_add(read_resident_requirement.peak_byte_length())
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let accepted_values_byte_length = u64::try_from(element_count)
                        .map_err(|_| CommonProofProverError::CountOverflow)?
                        .checked_mul(extension_value_byte_length)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    let acceptance_peak_byte_length = completed_query_block_byte_length
                        .checked_add(query_block_capacity_byte_length)
                        .and_then(|length| length.checked_add(accepted_values_byte_length))
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    maximum_read_subphase_transient_byte_length =
                        maximum_read_subphase_transient_byte_length
                            .max(read_transaction_peak_byte_length)
                            .max(acceptance_peak_byte_length);
                    read_transaction_count = read_transaction_count
                        .checked_add(1)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                    logical_value_offset = logical_value_offset
                        .checked_add(element_count)
                        .ok_or(CommonProofProverError::CountOverflow)?;
                }
                completed_query_block_byte_length = completed_query_block_byte_length
                    .checked_add(query_block_capacity_byte_length)
                    .ok_or(CommonProofProverError::CountOverflow)?;
            }
            maximum_rotation_block_byte_length =
                maximum_rotation_block_byte_length.max(completed_query_block_byte_length);
            maximum_read_subphase_transient_byte_length =
                maximum_read_subphase_transient_byte_length.max(completed_query_block_byte_length);
            block_start = block_end;
        }
        transform_count = transform_count
            .checked_add(
                u64::try_from(columns.len()).map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        constraint_columns.push(columns);
    }
    if constraint_columns.is_empty()
        || transform_count == 0
        || maximum_rotation_block_byte_length == 0
        || maximum_read_working_set_byte_length == 0
        || maximum_read_transaction_overlap_peak_byte_length == 0
        || maximum_read_subphase_transient_byte_length == 0
    {
        return Err(CommonProofProverError::InvalidQuotient);
    }
    Ok(CommonProofQuotientStreamRequirement {
        constraint_columns,
        transform_count,
        total_read_byte_length,
        read_transaction_count,
        maximum_rotation_block_byte_length,
        maximum_read_working_set_byte_length,
        maximum_read_transaction_overlap_peak_byte_length,
        maximum_read_subphase_transient_byte_length,
    })
}

fn exact_peak_stored_byte_length(
    object_plans: &[ProofExternalMemoryObjectPlan],
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    let event_count =
        object_plans
            .len()
            .checked_mul(2)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
    let mut liveness_events = Vec::new();
    liveness_events
        .try_reserve_exact(event_count)
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::AllocationLimitExceeded,
            )
        })?;
    for object_plan in object_plans {
        liveness_events.push((
            object_plan.issued_step(),
            true,
            object_plan.exact_byte_length(),
        ));
        liveness_events.push((
            object_plan.last_use_step().checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?,
            false,
            object_plan.exact_byte_length(),
        ));
    }
    liveness_events.sort_unstable_by_key(|(step, is_issuance, _)| (*step, *is_issuance));
    let mut live_byte_length = 0_u64;
    let mut peak_stored_byte_length = 0_u64;
    for (_, is_issuance, byte_length) in liveness_events {
        if is_issuance {
            live_byte_length = checked_add_u64(live_byte_length, byte_length)?;
            peak_stored_byte_length = peak_stored_byte_length.max(live_byte_length);
        } else {
            live_byte_length = live_byte_length.checked_sub(byte_length).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidInput),
            )?;
        }
    }
    if live_byte_length != 0 || peak_stored_byte_length == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    Ok(peak_stored_byte_length)
}

pub(super) fn common_tree_materialization_write_transaction_count(
    leaf_count: u64,
    canonical_leaf_byte_length: u64,
    chunk_byte_length: u64,
) -> Result<u64, GeneratedCommonProofStoragePlanError> {
    if !leaf_count.is_power_of_two() {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    let leaf_object_byte_length = checked_multiply_u64(leaf_count, canonical_leaf_byte_length)?;
    let mut transaction_count = ceiling_division_u64(leaf_object_byte_length, chunk_byte_length)?;
    let mut level_node_count = leaf_count;
    loop {
        let level_byte_length = checked_multiply_u64(level_node_count, HASH_BYTE_LENGTH as u64)?;
        transaction_count = checked_add_u64(
            transaction_count,
            ceiling_division_u64(level_byte_length, chunk_byte_length)?,
        )?;
        if level_node_count == 1 {
            break;
        }
        level_node_count /= 2;
    }
    Ok(transaction_count)
}

fn common_tree_materialization_phase(source: ProofTreeCatalogSource) -> Option<u8> {
    match source {
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::BaseOracle,
            ..
        } => Some(0),
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::AuxiliaryOracle,
            ..
        } => Some(1),
        ProofTreeCatalogSource::QuotientComponent { .. } => Some(2),
        ProofTreeCatalogSource::OpeningBatchMask => Some(3),
        ProofTreeCatalogSource::NonterminalFriLayer { .. } => Some(4),
        ProofTreeCatalogSource::RelationBoundPublic => Some(0),
        ProofTreeCatalogSource::RelationProofCreated { .. } => None,
    }
}

fn entry_uses_statement_owned_replay(entry: &ProofTreeCatalogEntry) -> bool {
    entry.bound_root().is_some() && !entry.uses_common_merkle_context()
}

/// Generates the exact object liveness graph for every common tree.  Read and
/// transaction ceilings include worst-case query collisions and frontiers;
/// they are operational limits, never proof fields.
fn derive_generated_common_proof_storage_geometry(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    catalog: &CompleteProofTreeCatalog,
    transcript_schedule: &CommonProofTranscriptSchedule,
    maximum_chunk_byte_length: u32,
    include_replay_polynomials: bool,
    mode: GeneratedCommonProofStorageGeometryMode,
) -> Result<GeneratedCommonProofStorageGeometry, GeneratedCommonProofStoragePlanError> {
    if maximum_chunk_byte_length == 0 {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }
    let mut common_entries = catalog
        .entries()
        .iter()
        .filter_map(|entry| {
            common_tree_materialization_phase(entry.source())
                .map(|phase| (phase, entry.tree_catalog_index(), entry))
        })
        .collect::<Vec<_>>();
    common_entries.sort_unstable_by_key(|(phase, catalog_index, _)| (*phase, *catalog_index));
    if common_entries.is_empty() {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }

    let base_tree_count = common_entries
        .iter()
        .take_while(|(phase, _, _)| *phase == 0)
        .count();
    let auxiliary_tree_count = common_entries
        .iter()
        .filter(|(phase, _, _)| *phase == 1)
        .count();
    let mut tree_roles_by_column = proof_created_tree_roles_by_column(variant)
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
    let mut setup_polynomial_column_ordinals = BTreeSet::new();
    let mut ordered_setup_polynomial_column_ordinals = Vec::new();
    for tree in variant.ordered_trees() {
        let RelationTreeDescriptor::BoundPublic {
            construction_kind,
            ordered_column_ordinals,
            ..
        } = tree
        else {
            continue;
        };
        if *construction_kind == BoundTreeConstructionKind::SetupPolynomial
            && (ordered_column_ordinals.is_empty()
                || ordered_column_ordinals
                    .windows(2)
                    .any(|adjacent| adjacent[0] >= adjacent[1]))
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        for column_ordinal in ordered_column_ordinals {
            if *construction_kind == BoundTreeConstructionKind::SetupPolynomial {
                if !setup_polynomial_column_ordinals.insert(*column_ordinal) {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                ordered_setup_polynomial_column_ordinals.push(*column_ordinal);
            }
            match tree_roles_by_column.insert(*column_ordinal, ProofTreeRole::BaseOracle) {
                Some(ProofTreeRole::AuxiliaryOracle) => {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                Some(ProofTreeRole::BaseOracle) | None => {}
                Some(
                    ProofTreeRole::QuotientComponent
                    | ProofTreeRole::OpeningBatchMask
                    | ProofTreeRole::NonterminalFriLayer,
                ) => {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
            }
        }
    }
    if ordered_setup_polynomial_column_ordinals
        != setup_polynomial_column_ordinals
            .iter()
            .copied()
            .collect::<Vec<_>>()
    {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }
    if setup_polynomial_column_ordinals
        .iter()
        .any(|column_ordinal| {
            tree_roles_by_column.get(column_ordinal) != Some(&ProofTreeRole::BaseOracle)
        })
    {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }
    let base_tree_column_count = tree_roles_by_column
        .values()
        .filter(|role| **role == ProofTreeRole::BaseOracle)
        .count();
    let auxiliary_tree_column_count = tree_roles_by_column
        .values()
        .filter(|role| **role == ProofTreeRole::AuxiliaryOracle)
        .count();
    let transform_pass_count_per_column = variant.evaluation_domain_size().trailing_zeros();
    let quotient_stream_requirement =
        common_proof_quotient_stream_requirement(variant, u64::from(maximum_chunk_byte_length))
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
    let base_transform_pass_count = u32::try_from(base_tree_column_count)
        .ok()
        .and_then(|column_count| column_count.checked_mul(transform_pass_count_per_column))
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let setup_polynomial_column_count = u32::try_from(setup_polynomial_column_ordinals.len())
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
    let base_transform_work_step_count = base_transform_pass_count
        .checked_add(setup_polynomial_column_count)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let auxiliary_transform_pass_count = u32::try_from(auxiliary_tree_column_count)
        .ok()
        .and_then(|column_count| column_count.checked_mul(transform_pass_count_per_column))
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let first_base_transform_step = u32::from(include_replay_polynomials);
    let first_base_tree_step = first_base_transform_step
        .checked_add(if include_replay_polynomials {
            base_transform_work_step_count
        } else {
            0
        })
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let auxiliary_replay_step = first_base_tree_step
        .checked_add(u32::try_from(base_tree_count).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let first_auxiliary_transform_step = auxiliary_replay_step
        .checked_add(u32::from(include_replay_polynomials))
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let first_auxiliary_tree_step = first_auxiliary_transform_step
        .checked_add(if include_replay_polynomials {
            auxiliary_transform_pass_count
        } else {
            0
        })
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let first_quotient_transform_step = first_auxiliary_tree_step
        .checked_add(u32::try_from(auxiliary_tree_count).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let quotient_transform_pass_count = u32::try_from(
        quotient_stream_requirement
            .transform_count
            .checked_mul(u64::from(transform_pass_count_per_column))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?,
    )
    .map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let quotient_constraint_evaluation_step_count =
        u32::try_from(quotient_stream_requirement.constraint_columns.len()).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
    let quotient_work_step_count = if include_replay_polynomials {
        quotient_transform_pass_count
            .checked_add(quotient_constraint_evaluation_step_count)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?
    } else {
        0
    };
    let first_post_auxiliary_tree_step = first_quotient_transform_step
        .checked_add(quotient_work_step_count)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let mut materialization_steps = BTreeMap::new();
    let mut next_base_tree_step = first_base_tree_step;
    let mut next_auxiliary_tree_step = first_auxiliary_tree_step;
    let mut next_post_auxiliary_tree_step = first_post_auxiliary_tree_step;
    for (phase, catalog_index, _) in &common_entries {
        let materialization_step = match *phase {
            0 => {
                let step = next_base_tree_step;
                next_base_tree_step = next_base_tree_step.checked_add(1).ok_or(
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ),
                )?;
                step
            }
            1 => {
                let step = next_auxiliary_tree_step;
                next_auxiliary_tree_step = next_auxiliary_tree_step.checked_add(1).ok_or(
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ),
                )?;
                step
            }
            _ => {
                let step = next_post_auxiliary_tree_step;
                next_post_auxiliary_tree_step = next_post_auxiliary_tree_step
                    .checked_add(1)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                step
            }
        };
        if materialization_steps
            .insert(*catalog_index, materialization_step)
            .is_some()
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
    }
    let mut last_relation_evaluation_use_steps = BTreeMap::new();
    for (tree_index, descriptor) in variant.ordered_trees().iter().enumerate() {
        let ordered_column_ordinals = match descriptor {
            RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } if matches!(*proof_tree_role, 1 | 2) => ordered_column_ordinals,
            RelationTreeDescriptor::BoundPublic {
                ordered_column_ordinals,
                ..
            } => ordered_column_ordinals,
            RelationTreeDescriptor::ProofCreated { .. } => continue,
        };
        let tree_catalog_index = u16::try_from(tree_index).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let materialization_step = *materialization_steps.get(&tree_catalog_index).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidTree),
        )?;
        for column_ordinal in ordered_column_ordinals {
            last_relation_evaluation_use_steps
                .entry(*column_ordinal)
                .and_modify(|last_use_step: &mut u32| {
                    *last_use_step = (*last_use_step).max(materialization_step);
                })
                .or_insert(materialization_step);
        }
    }
    let first_setup_polynomial_query_transform_step = next_post_auxiliary_tree_step;
    let setup_polynomial_query_work_step_count = setup_polynomial_column_count
        .checked_mul(transform_pass_count_per_column.checked_add(1).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
        )?)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let query_step = first_setup_polynomial_query_transform_step
        .checked_add(if include_replay_polynomials {
            setup_polynomial_query_work_step_count
        } else {
            0
        })
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    for (tree_index, descriptor) in variant.ordered_trees().iter().enumerate() {
        let RelationTreeDescriptor::BoundPublic {
            ordered_column_ordinals,
            ..
        } = descriptor
        else {
            continue;
        };
        let entry = catalog.entries().get(tree_index).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidTree),
        )?;
        if !entry_uses_statement_owned_replay(entry) {
            continue;
        }
        for column_ordinal in ordered_column_ordinals {
            if setup_polynomial_column_ordinals.contains(column_ordinal) {
                continue;
            }
            last_relation_evaluation_use_steps
                .entry(*column_ordinal)
                .and_modify(|last_use_step| *last_use_step = (*last_use_step).max(query_step))
                .or_insert(query_step);
        }
    }
    let quotient_component_tree_count = u32::try_from(
        common_entries
            .iter()
            .filter(|(phase, _, _)| *phase == 2)
            .count(),
    )
    .map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let opening_mask_tree_count = u32::try_from(
        common_entries
            .iter()
            .filter(|(phase, _, _)| *phase == 3)
            .count(),
    )
    .map_err(|_| {
        GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let deep_opening_step = first_post_auxiliary_tree_step
        .checked_add(quotient_component_tree_count)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    let initial_fri_step = deep_opening_step
        .checked_add(opening_mask_tree_count)
        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    if initial_fri_step > query_step {
        return Err(GeneratedCommonProofStoragePlanError::Prover(
            CommonProofProverError::InvalidTree,
        ));
    }
    let step_count =
        query_step
            .checked_add(1)
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
    let mut requirement_accumulator = if mode.retains_execution_plan() {
        None
    } else {
        Some(CommonProofExternalMemoryRequirementAccumulator::new(
            step_count,
        )?)
    };
    let chunk_byte_length = u64::from(maximum_chunk_byte_length);
    let hash_read_transaction_count =
        ceiling_division_u64(HASH_BYTE_LENGTH as u64, chunk_byte_length)?;
    let maximum_opened_leaf_count = u64::from(transcript_schedule.unique_query_count());

    let mut next_object_ordinal = 0_u32;
    let mut object_plans = Vec::new();
    let mut tree_plans = BTreeMap::new();
    let mut replay_polynomial_plans = BTreeMap::new();
    let mut relation_evaluation_transform_plans = BTreeMap::new();
    let mut setup_polynomial_query_transform_plans = BTreeMap::new();
    let mut quotient_constraint_transform_plans = BTreeMap::new();
    let mut relation_evaluation_transform_plan_count = 0_usize;
    let mut setup_polynomial_query_transform_plan_count = 0_usize;
    let mut quotient_constraint_transform_plan_count = 0_usize;
    #[cfg(test)]
    let mut relation_transform_resident_owned_payload_byte_length = 0_u64;
    #[cfg(test)]
    let mut setup_query_transform_resident_owned_payload_byte_length = 0_u64;
    #[cfg(test)]
    let mut quotient_transform_resident_owned_payload_byte_length = 0_u64;
    let mut maximum_total_written_byte_length = 0_u64;
    let mut maximum_total_read_byte_length = 0_u64;
    let mut maximum_transaction_count = 0_u64;

    for (_, catalog_index, entry) in &common_entries {
        let materialization_step = *materialization_steps.get(catalog_index).ok_or(
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::InvalidTree),
        )?;
        if entry_uses_statement_owned_replay(entry) {
            let descriptor = variant
                .ordered_trees()
                .get(usize::from(*catalog_index))
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
            let RelationTreeDescriptor::BoundPublic {
                ordered_column_ordinals,
                ..
            } = descriptor
            else {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            };
            let leaf_count = u64::try_from(
                entry_leaf_count(entry, variant.evaluation_domain_size()).map_err(|error| {
                    match error {
                        ProofBodyError::CountOverflow => {
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::CountOverflow,
                            )
                        }
                        ProofBodyError::AllocationLimitExceeded => {
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::AllocationLimitExceeded,
                            )
                        }
                        _ => GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::InvalidTree,
                        ),
                    }
                })?,
            )
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            let mut row_byte_length = 0_u64;
            for column_ordinal in ordered_column_ordinals {
                let column = variant
                    .ordered_columns()
                    .get(usize::try_from(*column_ordinal).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                if column.value_type() != RelationColumnValueType::BaseField {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                row_byte_length = checked_add_u64(
                    row_byte_length,
                    resident_value_byte_length(column.value_type()),
                )?;
            }
            let paired_leaf_value_count =
                leaf_count
                    .checked_mul(2)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
            let one_pass_read_byte_length =
                checked_multiply_u64(paired_leaf_value_count, row_byte_length)?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                checked_multiply_u64(one_pass_read_byte_length, 2)?,
            )?;
            let ordered_column_count =
                u64::try_from(ordered_column_ordinals.len()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?;
            let one_pass_transaction_count = if entry.setup_polynomial_construction().is_some() {
                let half_column_byte_length = checked_multiply_u64(
                    leaf_count,
                    external_value_byte_length(RelationColumnValueType::BaseField),
                )?;
                checked_multiply_u64(
                    checked_multiply_u64(
                        ceiling_division_u64(half_column_byte_length, chunk_byte_length)?,
                        2,
                    )?,
                    ordered_column_count,
                )?
            } else {
                checked_multiply_u64(paired_leaf_value_count, ordered_column_count)?
            };
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                checked_multiply_u64(one_pass_transaction_count, 2)?,
            )?;
            continue;
        }
        let tree_plan = common_proof_merkle_storage_plan(
            entry,
            variant.evaluation_domain_size(),
            next_object_ordinal,
            materialization_step,
            query_step,
        )
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        next_object_ordinal = tree_plan.next_object_ordinal();
        let leaf_count = u64::try_from(
            entry_leaf_count(entry, variant.evaluation_domain_size()).map_err(
                |error| match error {
                    ProofBodyError::CountOverflow => GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ),
                    ProofBodyError::AllocationLimitExceeded => {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    }
                    _ => GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ),
                },
            )?,
        )
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let opened_leaf_count = maximum_opened_leaf_count.min(leaf_count);
        let tree_height = u64::from(leaf_count.trailing_zeros());
        let frontier_node_bound = checked_multiply_u64(opened_leaf_count, tree_height)?;
        let construction_digest_read_count = leaf_count
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::CountOverflow,
            ))?;
        let construction_read_byte_length =
            checked_multiply_u64(construction_digest_read_count, HASH_BYTE_LENGTH as u64)?;
        let query_leaf_read_byte_length = checked_multiply_u64(
            opened_leaf_count,
            u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?,
        )?;
        let query_frontier_read_byte_length =
            checked_multiply_u64(frontier_node_bound, HASH_BYTE_LENGTH as u64)?;
        maximum_total_read_byte_length = checked_add_u64(
            maximum_total_read_byte_length,
            checked_add_u64(
                construction_read_byte_length,
                checked_add_u64(query_leaf_read_byte_length, query_frontier_read_byte_length)?,
            )?,
        )?;
        if matches!(
            entry.source(),
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::BaseOracle | ProofTreeRole::AuxiliaryOracle,
                ..
            }
        ) {
            let descriptor = variant
                .ordered_trees()
                .get(usize::from(*catalog_index))
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ))?;
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } = descriptor
            else {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            };
            let expected_tree_role = match *proof_tree_role {
                1 => ProofTreeRole::BaseOracle,
                2 => ProofTreeRole::AuxiliaryOracle,
                _ => {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
            };
            if !matches!(
                entry.source(),
                ProofTreeCatalogSource::RelationProofCreated { tree_role, .. }
                    if tree_role == expected_tree_role
            ) {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidTree,
                ));
            }
            let mut row_byte_length = 0_u64;
            for column_ordinal in ordered_column_ordinals {
                let column = variant
                    .ordered_columns()
                    .get(usize::try_from(*column_ordinal).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                row_byte_length = checked_add_u64(
                    row_byte_length,
                    resident_value_byte_length(column.value_type()),
                )?;
            }
            let paired_leaf_value_count =
                leaf_count
                    .checked_mul(2)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                checked_multiply_u64(paired_leaf_value_count, row_byte_length)?,
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                checked_multiply_u64(
                    paired_leaf_value_count,
                    u64::try_from(ordered_column_ordinals.len()).map_err(|_| {
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        )
                    })?,
                )?,
            )?;
        }

        let object_count = u64::try_from(tree_plan.object_plans().len()).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(object_count, 2)?,
        )?;
        for object_plan in tree_plan.object_plans() {
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                object_plan.exact_byte_length(),
            )?;
        }
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            common_tree_materialization_write_transaction_count(
                leaf_count,
                u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                chunk_byte_length,
            )?,
        )?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_multiply_u64(construction_digest_read_count, hash_read_transaction_count)?,
        )?;
        let query_leaf_read_transaction_count = checked_multiply_u64(
            opened_leaf_count,
            ceiling_division_u64(
                u64::try_from(tree_plan.canonical_leaf_byte_length()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                chunk_byte_length,
            )?,
        )?;
        let query_frontier_read_transaction_count =
            checked_multiply_u64(frontier_node_bound, hash_read_transaction_count)?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            checked_add_u64(
                query_leaf_read_transaction_count,
                query_frontier_read_transaction_count,
            )?,
        )?;

        if let Some(accumulator) = requirement_accumulator.as_mut() {
            accumulator.include_object_plans(tree_plan.object_plans())?;
        } else {
            object_plans.extend_from_slice(tree_plan.object_plans());
        }
        if tree_plans.insert(*catalog_index, tree_plan).is_some() {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
    }
    if include_replay_polynomials {
        if auxiliary_replay_step >= query_step {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        let replay_protection = match variant.proof_privacy_mode() {
            ProofPrivacyMode::PublicOnly => ProofExternalMemoryProtection::PublicIntegrity,
            ProofPrivacyMode::SecretBearing => {
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption
            }
        };
        let mut replay_specifications = Vec::new();
        replay_specifications
            .try_reserve_exact(
                variant
                    .ordered_columns()
                    .len()
                    .checked_add(usize::from(transcript_schedule.quotient_component_count()))
                    .and_then(|count| {
                        count.checked_add(
                            if transcript_schedule.privacy_mode()
                                == CommonProofPrivacyMode::SecretBearing
                            {
                                1
                            } else {
                                0
                            },
                        )
                    })
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?,
            )
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::AllocationLimitExceeded,
                )
            })?;
        for (column_index, column) in variant.ordered_columns().iter().enumerate() {
            let column_ordinal = u32::try_from(column_index).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            let issued_step = if tree_roles_by_column.get(&column_ordinal)
                == Some(&ProofTreeRole::AuxiliaryOracle)
            {
                auxiliary_replay_step
            } else {
                0
            };
            replay_specifications.push((
                CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                column.value_type(),
                usize::try_from(column.source_degree_bound_exclusive()).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                issued_step,
            ));
        }
        for (_, catalog_index, entry) in &common_entries {
            match entry.source() {
                ProofTreeCatalogSource::QuotientComponent { component_ordinal } => {
                    replay_specifications.push((
                        CommonProofReplayPolynomialKey::QuotientComponent(component_ordinal),
                        RelationColumnValueType::ChallengeExtension,
                        usize::try_from(relation_context.quotient_component_degree_bound_exclusive)
                            .map_err(|_| {
                                GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?,
                        *materialization_steps.get(catalog_index).ok_or(
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidTree,
                            ),
                        )?,
                    ));
                }
                ProofTreeCatalogSource::OpeningBatchMask => {
                    let mut descriptors = variant.ordered_masks().iter().copied().filter(|mask| {
                        mask.mask_kind() == RelationMaskKind::OpeningBatch
                            && mask.target_class() == RelationMaskTargetClass::Batch
                            && mask.target_ordinal() == 0
                    });
                    let descriptor =
                        descriptors
                            .next()
                            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidMask,
                            ))?;
                    if descriptors.next().is_some() {
                        return Err(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    replay_specifications.push((
                        CommonProofReplayPolynomialKey::OpeningBatchMask,
                        RelationColumnValueType::ChallengeExtension,
                        usize::try_from(descriptor.mask_degree_bound_exclusive()).map_err(
                            |_| {
                                GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            },
                        )?,
                        *materialization_steps.get(catalog_index).ok_or(
                            GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::InvalidTree,
                            ),
                        )?,
                    ));
                }
                ProofTreeCatalogSource::RelationProofCreated { .. }
                | ProofTreeCatalogSource::NonterminalFriLayer { .. }
                | ProofTreeCatalogSource::RelationBoundPublic => {}
            }
        }
        let mut replay_read_requirements = BTreeMap::new();
        for (column_ordinal, requirement) in relation_column_replay_requirements(variant)
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?
        {
            let key = CommonProofReplayPolynomialKey::RelationColumn(column_ordinal);
            include_common_proof_replay_reads(
                &mut replay_read_requirements,
                key,
                requirement.pre_challenge_read_count,
                0,
            )
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
            include_common_proof_replay_reads(
                &mut replay_read_requirements,
                key,
                requirement.auxiliary_synthesis_read_count,
                auxiliary_replay_step,
            )
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        }
        for claim in variant.ordered_opening_claims() {
            let key = replay_polynomial_key_for_claim(claim)
                .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
            include_common_proof_replay_reads(
                &mut replay_read_requirements,
                key,
                1,
                deep_opening_step,
            )
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
            include_common_proof_replay_reads(
                &mut replay_read_requirements,
                key,
                1,
                initial_fri_step,
            )
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        }
        if transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing {
            // Besides its ordinary DEEP and initial-FRI opening-claim reads,
            // the secret opening-batch mask is replayed once to materialize
            // its tree and once to seed the initial FRI polynomial.
            include_common_proof_replay_reads(
                &mut replay_read_requirements,
                CommonProofReplayPolynomialKey::OpeningBatchMask,
                1,
                deep_opening_step,
            )
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
            include_common_proof_replay_reads(
                &mut replay_read_requirements,
                CommonProofReplayPolynomialKey::OpeningBatchMask,
                1,
                initial_fri_step,
            )
            .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        }
        let mut pending_replay_object_plans = Vec::new();
        pending_replay_object_plans
            .try_reserve_exact(replay_specifications.len())
            .map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::AllocationLimitExceeded,
                )
            })?;
        for (key, value_type, coefficient_count, issued_step) in replay_specifications {
            if coefficient_count == 0 || issued_step >= query_step {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
            let exact_byte_length = checked_multiply_u64(
                u64::try_from(coefficient_count).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?,
                resident_value_byte_length(value_type),
            )?;
            let replay_count = replay_read_requirements
                .get(&key)
                .map_or(0, |requirement| requirement.read_count);
            let object = ProofExternalMemoryObject::new(next_object_ordinal);
            next_object_ordinal = next_object_ordinal.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            pending_replay_object_plans.push(PendingCommonProofReplayObjectPlan {
                key,
                object,
                protection: replay_protection,
                exact_byte_length,
                issued_step,
            });
            maximum_total_written_byte_length =
                checked_add_u64(maximum_total_written_byte_length, exact_byte_length)?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                checked_multiply_u64(exact_byte_length, replay_count)?,
            )?;
            let object_chunk_count = ceiling_division_u64(exact_byte_length, chunk_byte_length)?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                checked_add_u64(
                    2,
                    checked_add_u64(
                        object_chunk_count,
                        checked_multiply_u64(object_chunk_count, replay_count)?,
                    )?,
                )?,
            )?;
            if replay_polynomial_plans
                .insert(
                    key,
                    CommonProofReplayPolynomialPlan {
                        object,
                        value_type,
                        coefficient_count,
                        exact_byte_length,
                    },
                )
                .is_some()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ));
            }
        }
        if replay_read_requirements
            .keys()
            .any(|key| !replay_polynomial_plans.contains_key(key))
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }

        let evaluation_domain = ProofEvaluationDomain::new(
            usize::try_from(variant.evaluation_domain_size()).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?,
            relation_context.evaluation_coset_offset,
        )
        .map_err(CommonProofProverError::from)
        .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
        let setup_polynomial_scratch_objects = if setup_polynomial_column_ordinals.is_empty() {
            None
        } else {
            let first = ProofExternalMemoryObject::new(next_object_ordinal);
            let second_ordinal = next_object_ordinal.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            let second = ProofExternalMemoryObject::new(second_ordinal);
            next_object_ordinal = second_ordinal.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
            Some([first, second])
        };
        let stockham_scratch_sequence = |scratch_objects: [ProofExternalMemoryObject; 2]| {
            (0..transform_pass_count_per_column)
                .map(|pass_ordinal| scratch_objects[usize::from((pass_ordinal % 2) as u8)])
                .collect::<Vec<_>>()
        };
        let mut next_base_transform_step = first_base_transform_step;
        let mut next_base_transform_index = 0_u32;
        let mut next_auxiliary_transform_index = 0_u32;
        for (&column_ordinal, &tree_role) in &tree_roles_by_column {
            let source_plan = replay_polynomial_plans
                .get(&CommonProofReplayPolynomialKey::RelationColumn(
                    column_ordinal,
                ))
                .copied()
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            let source = ExternalPolynomialVector::new(
                source_plan.object,
                source_plan.value_type,
                source_plan.coefficient_count,
            )
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            let first_executor_step = match tree_role {
                ProofTreeRole::BaseOracle => {
                    next_base_transform_index = next_base_transform_index.checked_add(1).ok_or(
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        ),
                    )?;
                    let first_executor_step = next_base_transform_step;
                    next_base_transform_step = next_base_transform_step
                        .checked_add(transform_pass_count_per_column)
                        .and_then(|step| {
                            step.checked_add(u32::from(
                                setup_polynomial_column_ordinals.contains(&column_ordinal),
                            ))
                        })
                        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    first_executor_step
                }
                ProofTreeRole::AuxiliaryOracle => {
                    let transform_index = next_auxiliary_transform_index;
                    next_auxiliary_transform_index = next_auxiliary_transform_index
                        .checked_add(1)
                        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    first_auxiliary_transform_step
                        .checked_add(
                            transform_index
                                .checked_mul(transform_pass_count_per_column)
                                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                ))?,
                        )
                        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?
                }
                _ => {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
            };
            include_common_proof_replay_use(
                &mut replay_read_requirements,
                CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                first_executor_step,
            );
            let is_setup_polynomial_column =
                setup_polynomial_column_ordinals.contains(&column_ordinal);
            let final_output_last_use_step = if is_setup_polynomial_column {
                first_executor_step
                    .checked_add(transform_pass_count_per_column)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?
            } else {
                last_relation_evaluation_use_steps
                    .get(&column_ordinal)
                    .copied()
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ))?
            };
            let transform_plan = if is_setup_polynomial_column {
                ExternalStockhamTransformPlan::new_with_output_objects(
                    evaluation_domain,
                    ExternalStockhamTransformDirection::Forward,
                    source,
                    &stockham_scratch_sequence(setup_polynomial_scratch_objects.ok_or(
                        GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::InvalidTree,
                        ),
                    )?),
                    first_executor_step,
                    final_output_last_use_step,
                    maximum_chunk_byte_length,
                    replay_protection,
                )
            } else {
                ExternalStockhamTransformPlan::new_with_output_objects(
                    evaluation_domain,
                    ExternalStockhamTransformDirection::Forward,
                    source,
                    &stockham_scratch_sequence(stockham_output_object_pair(next_object_ordinal)?),
                    first_executor_step,
                    final_output_last_use_step,
                    maximum_chunk_byte_length,
                    replay_protection,
                )
            }
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            if transform_plan.next_executor_step()
                != first_executor_step
                    .checked_add(evaluation_domain.size().trailing_zeros())
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            if !is_setup_polynomial_column {
                next_object_ordinal = transform_plan.next_object_ordinal();
            }
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                transform_plan.total_written_byte_length(),
            )?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                transform_plan.total_read_byte_length(),
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                transform_plan.transaction_count_excluding_deletions(),
            )?;
            if let Some(accumulator) = requirement_accumulator.as_mut() {
                accumulator.include_object_plans(transform_plan.object_plans())?;
            } else {
                object_plans.extend_from_slice(transform_plan.object_plans());
            }
            relation_evaluation_transform_plan_count = relation_evaluation_transform_plan_count
                .checked_add(1)
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            #[cfg(test)]
            {
                relation_transform_resident_owned_payload_byte_length = checked_add_u64(
                    relation_transform_resident_owned_payload_byte_length,
                    external_transform_resident_owned_payload_byte_length(&transform_plan)
                        .map_err(GeneratedCommonProofStoragePlanError::Prover)?,
                )?;
            }
            if mode.retains_execution_plan()
                && relation_evaluation_transform_plans
                    .insert(column_ordinal, transform_plan)
                    .is_some()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
        }
        if next_base_transform_step != first_base_tree_step
            || next_base_transform_index
                != u32::try_from(base_tree_column_count).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?
            || next_auxiliary_transform_index
                != u32::try_from(auxiliary_tree_column_count).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?
            || relation_evaluation_transform_plan_count
                != base_tree_column_count
                    .checked_add(auxiliary_tree_column_count)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }

        let mut next_quotient_step = first_quotient_transform_step;
        for (constraint_index, columns) in quotient_stream_requirement
            .constraint_columns
            .iter()
            .enumerate()
        {
            let constraint_ordinal = u32::try_from(constraint_index).map_err(|_| {
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
            })?;
            let constraint_transform_pass_count = u32::try_from(columns.len())
                .ok()
                .and_then(|column_count| column_count.checked_mul(transform_pass_count_per_column))
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let constraint_evaluation_step = next_quotient_step
                .checked_add(constraint_transform_pass_count)
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            for (constraint_column_index, column_ordinal) in columns.iter().copied().enumerate() {
                let source_plan = replay_polynomial_plans
                    .get(&CommonProofReplayPolynomialKey::RelationColumn(
                        column_ordinal,
                    ))
                    .copied()
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                let source = ExternalPolynomialVector::new(
                    source_plan.object,
                    source_plan.value_type,
                    source_plan.coefficient_count,
                )
                .map_err(map_external_polynomial_plan_error)
                .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
                let first_executor_step = next_quotient_step
                    .checked_add(
                        u32::try_from(constraint_column_index)
                            .map_err(|_| {
                                GeneratedCommonProofStoragePlanError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?
                            .checked_mul(transform_pass_count_per_column)
                            .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?,
                    )
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                include_common_proof_replay_use(
                    &mut replay_read_requirements,
                    CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                    first_executor_step,
                );
                let transform_plan = ExternalStockhamTransformPlan::new_with_output_objects(
                    evaluation_domain,
                    ExternalStockhamTransformDirection::Forward,
                    source,
                    &stockham_scratch_sequence(stockham_output_object_pair(next_object_ordinal)?),
                    first_executor_step,
                    constraint_evaluation_step,
                    maximum_chunk_byte_length,
                    replay_protection,
                )
                .map_err(map_external_polynomial_plan_error)
                .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
                if transform_plan.next_executor_step()
                    != first_executor_step
                        .checked_add(transform_pass_count_per_column)
                        .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?
                {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                next_object_ordinal = transform_plan.next_object_ordinal();
                maximum_total_written_byte_length = checked_add_u64(
                    maximum_total_written_byte_length,
                    transform_plan.total_written_byte_length(),
                )?;
                maximum_total_read_byte_length = checked_add_u64(
                    maximum_total_read_byte_length,
                    transform_plan.total_read_byte_length(),
                )?;
                maximum_transaction_count = checked_add_u64(
                    maximum_transaction_count,
                    transform_plan.transaction_count_excluding_deletions(),
                )?;
                if let Some(accumulator) = requirement_accumulator.as_mut() {
                    accumulator.include_object_plans(transform_plan.object_plans())?;
                } else {
                    object_plans.extend_from_slice(transform_plan.object_plans());
                }
                let transform_key = CommonProofQuotientConstraintTransformKey::new(
                    constraint_ordinal,
                    column_ordinal,
                );
                quotient_constraint_transform_plan_count = quotient_constraint_transform_plan_count
                    .checked_add(1)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                #[cfg(test)]
                {
                    quotient_transform_resident_owned_payload_byte_length = checked_add_u64(
                        quotient_transform_resident_owned_payload_byte_length,
                        external_transform_resident_owned_payload_byte_length(&transform_plan)
                            .map_err(GeneratedCommonProofStoragePlanError::Prover)?,
                    )?;
                }
                if mode.retains_execution_plan()
                    && quotient_constraint_transform_plans
                        .insert(transform_key, transform_plan)
                        .is_some()
                {
                    return Err(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
            }
            next_quotient_step = constraint_evaluation_step.checked_add(1).ok_or(
                GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow),
            )?;
        }
        if next_quotient_step != first_post_auxiliary_tree_step
            || quotient_constraint_transform_plan_count
                != usize::try_from(quotient_stream_requirement.transform_count).map_err(|_| {
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidQuotient,
            ));
        }
        maximum_total_read_byte_length = checked_add_u64(
            maximum_total_read_byte_length,
            quotient_stream_requirement.total_read_byte_length,
        )?;
        maximum_transaction_count = checked_add_u64(
            maximum_transaction_count,
            quotient_stream_requirement.read_transaction_count,
        )?;
        let mut next_setup_polynomial_query_transform_step =
            first_setup_polynomial_query_transform_step;
        for column_ordinal in setup_polynomial_column_ordinals.iter().copied() {
            let source_plan = replay_polynomial_plans
                .get(&CommonProofReplayPolynomialKey::RelationColumn(
                    column_ordinal,
                ))
                .copied()
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            let source = ExternalPolynomialVector::new(
                source_plan.object,
                source_plan.value_type,
                source_plan.coefficient_count,
            )
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            include_common_proof_replay_use(
                &mut replay_read_requirements,
                CommonProofReplayPolynomialKey::RelationColumn(column_ordinal),
                next_setup_polynomial_query_transform_step,
            );
            let consume_step = next_setup_polynomial_query_transform_step
                .checked_add(transform_pass_count_per_column)
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let transform_plan = ExternalStockhamTransformPlan::new_with_output_objects(
                evaluation_domain,
                ExternalStockhamTransformDirection::Forward,
                source,
                &stockham_scratch_sequence(setup_polynomial_scratch_objects.ok_or(
                    GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::InvalidTree,
                    ),
                )?),
                next_setup_polynomial_query_transform_step,
                consume_step,
                maximum_chunk_byte_length,
                replay_protection,
            )
            .map_err(map_external_polynomial_plan_error)
            .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
            if transform_plan.next_executor_step() != consume_step {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            maximum_total_written_byte_length = checked_add_u64(
                maximum_total_written_byte_length,
                transform_plan.total_written_byte_length(),
            )?;
            maximum_total_read_byte_length = checked_add_u64(
                maximum_total_read_byte_length,
                transform_plan.total_read_byte_length(),
            )?;
            maximum_transaction_count = checked_add_u64(
                maximum_transaction_count,
                transform_plan.transaction_count_excluding_deletions(),
            )?;
            if let Some(accumulator) = requirement_accumulator.as_mut() {
                accumulator.include_object_plans(transform_plan.object_plans())?;
            } else {
                object_plans.extend_from_slice(transform_plan.object_plans());
            }
            setup_polynomial_query_transform_plan_count =
                setup_polynomial_query_transform_plan_count
                    .checked_add(1)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
            #[cfg(test)]
            {
                setup_query_transform_resident_owned_payload_byte_length = checked_add_u64(
                    setup_query_transform_resident_owned_payload_byte_length,
                    external_transform_resident_owned_payload_byte_length(&transform_plan)
                        .map_err(GeneratedCommonProofStoragePlanError::Prover)?,
                )?;
            }
            if mode.retains_execution_plan()
                && setup_polynomial_query_transform_plans
                    .insert(column_ordinal, transform_plan)
                    .is_some()
            {
                return Err(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            next_setup_polynomial_query_transform_step =
                consume_step
                    .checked_add(1)
                    .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
        }
        if next_setup_polynomial_query_transform_step != query_step
            || setup_polynomial_query_transform_plan_count != setup_polynomial_column_ordinals.len()
        {
            return Err(GeneratedCommonProofStoragePlanError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        for pending in pending_replay_object_plans {
            let last_use_step = replay_read_requirements
                .get(&pending.key)
                .and_then(|requirement| requirement.last_use_step)
                .filter(|last_use_step| *last_use_step >= pending.issued_step)
                .ok_or(GeneratedCommonProofStoragePlanError::Prover(
                    CommonProofProverError::InvalidInput,
                ))?;
            let object_plan = ProofExternalMemoryObjectPlan::new(
                pending.object,
                pending.protection,
                pending.exact_byte_length,
                pending.issued_step,
                pending.issued_step,
                last_use_step,
            );
            if let Some(accumulator) = requirement_accumulator.as_mut() {
                accumulator.include_object_plans(core::slice::from_ref(&object_plan))?;
            } else {
                object_plans.push(object_plan);
            }
        }
    }
    // The executor deletes every object with the same exact last-use step in
    // one transaction, including objects owned by different transforms or
    // trees. Count those batches once after every source use is known.
    let (
        distinct_physical_object_count,
        object_lifecycle_count,
        maximum_stored_byte_length,
        deletion_transaction_count,
    ) = if let Some(accumulator) = requirement_accumulator {
        accumulator.finish(next_object_ordinal)?
    } else {
        let deletion_transaction_count = u64::try_from(
            object_plans
                .iter()
                .map(|object_plan| object_plan.last_use_step())
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let object_lifecycle_count = u32::try_from(object_plans.len()).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let distinct_physical_object_count = u32::try_from(
            object_plans
                .iter()
                .map(|plan| plan.object())
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let maximum_stored_byte_length = exact_peak_stored_byte_length(&object_plans)?;
        (
            distinct_physical_object_count,
            object_lifecycle_count,
            maximum_stored_byte_length,
            deletion_transaction_count,
        )
    };
    maximum_transaction_count =
        checked_add_u64(maximum_transaction_count, deletion_transaction_count)?;
    let maximum_transaction_operation_count = distinct_physical_object_count;
    #[cfg(test)]
    let resident_payload_requirement = generated_common_proof_storage_resident_payload_requirement(
        GeneratedCommonProofStorageResidentPayloadRequirementInput {
            tree_plans: &tree_plans,
            replay_polynomial_plan_count: replay_polynomial_plans.len(),
            relation_evaluation_transform_plan_count,
            relation_transform_resident_owned_payload_byte_length,
            setup_polynomial_query_transform_plan_count,
            setup_query_transform_resident_owned_payload_byte_length,
            quotient_constraint_transform_plan_count,
            quotient_transform_resident_owned_payload_byte_length,
            object_lifecycle_count,
        },
    )
    .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
    Ok(GeneratedCommonProofStorageGeometry {
        step_count,
        maximum_chunk_byte_length,
        maximum_transaction_payload_byte_length: chunk_byte_length,
        maximum_transaction_operation_count,
        distinct_physical_object_count,
        object_lifecycle_count,
        maximum_stored_byte_length,
        maximum_total_written_byte_length,
        maximum_total_read_byte_length,
        maximum_transaction_count,
        #[cfg(test)]
        resident_payload_requirement,
        #[cfg(test)]
        relation_evaluation_transform_plan_count,
        object_plans,
        tree_plans,
        replay_polynomial_plans,
        relation_evaluation_transform_plans,
        setup_polynomial_query_transform_plans,
        quotient_constraint_transform_plans,
    })
}

pub(super) fn generated_common_proof_storage_plan(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    catalog: &CompleteProofTreeCatalog,
    transcript_schedule: &CommonProofTranscriptSchedule,
    maximum_chunk_byte_length: u32,
    include_replay_polynomials: bool,
) -> Result<GeneratedCommonProofStoragePlan, GeneratedCommonProofStoragePlanError> {
    let geometry = derive_generated_common_proof_storage_geometry(
        variant,
        relation_context,
        catalog,
        transcript_schedule,
        maximum_chunk_byte_length,
        include_replay_polynomials,
        GeneratedCommonProofStorageGeometryMode::RetainExecutionPlan,
    )?;
    let GeneratedCommonProofStorageGeometry {
        step_count,
        maximum_chunk_byte_length,
        maximum_transaction_payload_byte_length,
        maximum_transaction_operation_count,
        distinct_physical_object_count,
        object_lifecycle_count,
        maximum_stored_byte_length,
        maximum_total_written_byte_length,
        maximum_total_read_byte_length,
        maximum_transaction_count,
        #[cfg(test)]
            resident_payload_requirement: _,
        #[cfg(test)]
            relation_evaluation_transform_plan_count: _,
        object_plans,
        tree_plans,
        replay_polynomial_plans,
        relation_evaluation_transform_plans,
        setup_polynomial_query_transform_plans,
        quotient_constraint_transform_plans,
    } = geometry;
    let external_memory_requirement = CommonProofExternalMemoryRequirement {
        step_count,
        maximum_chunk_byte_length,
        maximum_transaction_payload_byte_length,
        distinct_physical_object_count,
        object_lifecycle_count,
        peak_stored_byte_length: maximum_stored_byte_length,
        total_written_byte_length: maximum_total_written_byte_length,
        total_read_byte_length: maximum_total_read_byte_length,
        transaction_count: maximum_transaction_count,
    };
    let external_memory_plan = ProofExternalMemoryPlan::new(
        step_count,
        maximum_chunk_byte_length,
        maximum_transaction_payload_byte_length,
        maximum_transaction_operation_count,
        maximum_stored_byte_length,
        maximum_total_written_byte_length,
        maximum_total_read_byte_length,
        maximum_transaction_count,
        object_plans,
    )
    .map_err(GeneratedCommonProofStoragePlanError::Storage)?;
    Ok(GeneratedCommonProofStoragePlan {
        external_memory_plan,
        external_memory_requirement,
        tree_plans,
        replay_polynomial_plans,
        relation_evaluation_transform_plans,
        setup_polynomial_query_transform_plans,
        quotient_constraint_transform_plans,
    })
}

/// Derives exact browser scratch liveness and traffic before applying the
/// absolute storage ceiling. The production generation path constructs its
/// enforced plan from the same geometry.
#[cfg(test)]
pub(crate) fn common_proof_external_memory_requirement(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    catalog: &CompleteProofTreeCatalog,
    transcript_schedule: &CommonProofTranscriptSchedule,
    maximum_chunk_byte_length: u32,
) -> Result<CommonProofExternalMemoryRequirement, GeneratedCommonProofStoragePlanError> {
    let geometry = derive_generated_common_proof_storage_geometry(
        variant,
        relation_context,
        catalog,
        transcript_schedule,
        maximum_chunk_byte_length,
        true,
        GeneratedCommonProofStorageGeometryMode::RequirementOnly,
    )?;
    Ok(common_proof_external_memory_requirement_from_geometry(
        &geometry,
    ))
}

#[cfg(test)]
const fn common_proof_external_memory_requirement_from_geometry(
    geometry: &GeneratedCommonProofStorageGeometry,
) -> CommonProofExternalMemoryRequirement {
    CommonProofExternalMemoryRequirement {
        step_count: geometry.step_count,
        maximum_chunk_byte_length: geometry.maximum_chunk_byte_length,
        maximum_transaction_payload_byte_length: geometry.maximum_transaction_payload_byte_length,
        distinct_physical_object_count: geometry.distinct_physical_object_count,
        object_lifecycle_count: geometry.object_lifecycle_count,
        peak_stored_byte_length: geometry.maximum_stored_byte_length,
        total_written_byte_length: geometry.maximum_total_written_byte_length,
        total_read_byte_length: geometry.maximum_total_read_byte_length,
        transaction_count: geometry.maximum_transaction_count,
    }
}

pub(super) fn validate_generation_relation_trees(
    variant: &RelationPlanVariant,
    relation_trees: &[RelationProofTreeInput],
) -> Result<(), CommonProofProverError> {
    if relation_trees.len() != variant.ordered_trees().len() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for (descriptor, input) in variant.ordered_trees().iter().zip(relation_trees) {
        match (descriptor, input) {
            (
                RelationTreeDescriptor::ProofCreated {
                    proof_tree_role,
                    ordered_column_ordinals,
                },
                RelationProofTreeInput::ProofCreated {
                    tree_role,
                    row_width,
                    leaf_visibility,
                },
            ) => {
                let expected_role = match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(CommonProofProverError::InvalidTree),
                };
                let expected_width = u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| CommonProofProverError::CountOverflow)?;
                let expected_visibility = if ordered_column_ordinals.iter().any(|column_ordinal| {
                    usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|index| variant.ordered_columns().get(index))
                        .is_some_and(|column| column.origin() == &RelationColumnOrigin::Prover)
                }) {
                    ProofLeafVisibility::SecretBearing
                } else {
                    ProofLeafVisibility::Public
                };
                if *tree_role != expected_role
                    || *row_width != expected_width
                    || *leaf_visibility != expected_visibility
                {
                    return Err(CommonProofProverError::InvalidTree);
                }
                validate_generation_tree_columns(variant, ordered_column_ordinals, None)?;
            }
            (
                RelationTreeDescriptor::BoundPublic {
                    construction_kind,
                    expected_root_source_ordinal,
                    ordered_column_ordinals,
                    ..
                },
                RelationProofTreeInput::BoundPublic(statement_tree),
            ) => {
                validate_generation_tree_columns(
                    variant,
                    ordered_column_ordinals,
                    Some(*expected_root_source_ordinal),
                )?;
                let construction_matches = match (construction_kind, statement_tree) {
                    (
                        BoundTreeConstructionKind::CommittedMaterial,
                        StatementOwnedProofTreeInput::CommittedMaterial { .. },
                    ) => ordered_column_ordinals.len() == 4,
                    (
                        BoundTreeConstructionKind::SetupPolynomial,
                        StatementOwnedProofTreeInput::SetupPolynomial { row_width, .. },
                    ) => usize::try_from(*row_width)
                        .is_ok_and(|width| width == ordered_column_ordinals.len()),
                    _ => false,
                };
                if !construction_matches {
                    return Err(CommonProofProverError::InvalidTree);
                }
            }
            _ => return Err(CommonProofProverError::InvalidTree),
        }
    }
    Ok(())
}

fn validate_generation_tree_columns(
    variant: &RelationPlanVariant,
    ordered_column_ordinals: &[u32],
    expected_bound_root_source_ordinal: Option<u32>,
) -> Result<(), CommonProofProverError> {
    if ordered_column_ordinals.is_empty() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for column_ordinal in ordered_column_ordinals {
        let column = variant
            .ordered_columns()
            .get(
                usize::try_from(*column_ordinal)
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if column.value_type() != RelationColumnValueType::BaseField {
            return Err(CommonProofProverError::InvalidTree);
        }
        match (column.origin(), expected_bound_root_source_ordinal) {
            (
                RelationColumnOrigin::BoundTree {
                    expected_root_source_ordinal,
                },
                Some(expected),
            ) if *expected_root_source_ordinal == expected => {}
            (RelationColumnOrigin::BoundTree { .. }, _) | (_, Some(_)) => {
                return Err(CommonProofProverError::InvalidTree);
            }
            (_, None) => {}
        }
    }
    Ok(())
}

pub(super) fn statement_owned_tree_root(
    input: &RelationProofTreeInput,
) -> Option<[u8; HASH_BYTE_LENGTH]> {
    match input {
        RelationProofTreeInput::BoundPublic(
            StatementOwnedProofTreeInput::CommittedMaterial { expected_root, .. }
            | StatementOwnedProofTreeInput::SetupPolynomial { expected_root, .. },
        ) => Some(*expected_root),
        RelationProofTreeInput::ProofCreated { .. } => None,
    }
}

pub(super) fn unique_catalog_entry(
    catalog: &CompleteProofTreeCatalog,
    mut predicate: impl FnMut(ProofTreeCatalogSource) -> bool,
) -> Result<&ProofTreeCatalogEntry, CommonProofProverError> {
    let mut matches = catalog
        .entries()
        .iter()
        .filter(|entry| predicate(entry.source()));
    let entry = matches.next().ok_or(CommonProofProverError::InvalidTree)?;
    if matches.next().is_some() {
        return Err(CommonProofProverError::InvalidTree);
    }
    Ok(entry)
}

pub(super) fn map_private_coin_generation_error<StorageError, CoinError, SinkError>(
    error: CommonProofPrivateCoinError<CoinError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        CommonProofPrivateCoinError::Prover(error) => CommonProofGenerationError::Prover(error),
        CommonProofPrivateCoinError::CoinSource(error) => {
            CommonProofGenerationError::CoinSource(error)
        }
    }
}

pub(super) fn insert_materialized_tree(
    tree: StoredCommonProofMerkleTree,
    tree_roots: &mut [[u8; HASH_BYTE_LENGTH]],
    root_present: &mut [bool],
    stored_trees: &mut BTreeMap<u16, StoredCommonProofMerkleTree>,
) -> Result<(), CommonProofProverError> {
    let catalog_index = tree.tree_catalog_index();
    let tree_index = usize::from(catalog_index);
    let root = tree.root();
    let destination = tree_roots
        .get_mut(tree_index)
        .ok_or(CommonProofProverError::InvalidTree)?;
    let presence = root_present
        .get_mut(tree_index)
        .ok_or(CommonProofProverError::InvalidTree)?;
    if (*presence && *destination != root) || stored_trees.insert(catalog_index, tree).is_some() {
        return Err(CommonProofProverError::InvalidTree);
    }
    if !*presence {
        *destination = root;
        *presence = true;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommonProofGenerationInitializationError {
    Prover(CommonProofProverError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    Body(ProofBodyError),
    Transcript(TranscriptError),
    StoragePlan(ProofExternalMemoryError),
}

/// Absolute WASM-memory safety bound, distinct from phone qualification targets.
pub(crate) const MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH: u64 = 671_088_640;

/// Named source-owned payloads that remain outside the phase-local polynomial
/// and external-transaction working sets. The build accounts the one fixed
/// WebAssembly stack separately, exactly once. Standard-library allocator
/// metadata is validated by runtime peak measurements rather than represented
/// as a protocol-derived byte field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommonProofResidentInfrastructurePayloadAccounting {
    state_machine_inline_byte_length: u64,
    canonical_header_payload_byte_length: u64,
    relation_plan_catalog_payload_byte_length: u64,
    relation_context_catalog_payload_byte_length: u64,
    proof_tree_catalog_payload_byte_length: u64,
    storage_plan_catalog_payload_byte_length: u64,
    executor_catalog_payload_byte_length: u64,
    generation_catalog_payload_byte_length: u64,
    resident_phase_catalog_payload_byte_length: u64,
    transcript_persistent_payload_byte_length: u64,
    transcript_transient_payload_byte_length: u64,
    total_byte_length: u64,
}

impl CommonProofResidentInfrastructurePayloadAccounting {
    #[cfg(test)]
    pub(crate) const fn state_machine_inline_byte_length(self) -> u64 {
        self.state_machine_inline_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn canonical_header_payload_byte_length(self) -> u64 {
        self.canonical_header_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn relation_plan_catalog_payload_byte_length(self) -> u64 {
        self.relation_plan_catalog_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn relation_context_catalog_payload_byte_length(self) -> u64 {
        self.relation_context_catalog_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn proof_tree_catalog_payload_byte_length(self) -> u64 {
        self.proof_tree_catalog_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn storage_plan_catalog_payload_byte_length(self) -> u64 {
        self.storage_plan_catalog_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn executor_catalog_payload_byte_length(self) -> u64 {
        self.executor_catalog_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn generation_catalog_payload_byte_length(self) -> u64 {
        self.generation_catalog_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn resident_phase_catalog_payload_byte_length(self) -> u64 {
        self.resident_phase_catalog_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn transcript_persistent_payload_byte_length(self) -> u64 {
        self.transcript_persistent_payload_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn transcript_transient_payload_byte_length(self) -> u64 {
        self.transcript_transient_payload_byte_length
    }

    pub(crate) const fn total_byte_length(self) -> u64 {
        self.total_byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CommonProofResidentMemoryPhase {
    LoadingSourcePolynomials = 1,
    ConstructingReversedColumns = 2,
    TransformingBaseColumns = 3,
    MaterializingBaseTrees = 4,
    DerivingAuxiliaryColumns = 5,
    TransformingAuxiliaryColumns = 6,
    MaterializingAuxiliaryTrees = 7,
    ConstructingQuotient = 8,
    MaterializingQuotientTrees = 9,
    DerivingOpenings = 10,
    ConstructingInitialFri = 11,
    FoldingFri = 12,
    PreparingQueryOutput = 13,
    EmittingQueries = 14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofResidentMemoryPhasePlan {
    phase: CommonProofResidentMemoryPhase,
    infrastructure_payload_accounting: CommonProofResidentInfrastructurePayloadAccounting,
    relation_polynomial_working_set_byte_length: u64,
    auxiliary_trace_workspace_byte_length: u64,
    replay_polynomial_byte_length: u64,
    primary_vector_byte_length: u64,
    secondary_vector_byte_length: u64,
    claim_and_query_metadata_byte_length: u64,
    relation_rotation_block_byte_length: u64,
    external_working_set_byte_length: u64,
    external_transaction_overlap_peak_byte_length: u64,
    subphase_transient_peak_byte_length: u64,
    query_prefetch_byte_length: u64,
    output_fragment_byte_length: u64,
    stream_window_byte_length: u64,
    total_byte_length: u64,
}

impl CommonProofResidentMemoryPhasePlan {
    pub(crate) const fn phase(&self) -> CommonProofResidentMemoryPhase {
        self.phase
    }

    #[cfg(test)]
    pub(crate) const fn infrastructure_payload_accounting(
        &self,
    ) -> CommonProofResidentInfrastructurePayloadAccounting {
        self.infrastructure_payload_accounting
    }

    pub(crate) const fn relation_polynomial_working_set_byte_length(&self) -> u64 {
        self.relation_polynomial_working_set_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn auxiliary_trace_workspace_byte_length(&self) -> u64 {
        self.auxiliary_trace_workspace_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn replay_polynomial_byte_length(&self) -> u64 {
        self.replay_polynomial_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn primary_vector_byte_length(&self) -> u64 {
        self.primary_vector_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn secondary_vector_byte_length(&self) -> u64 {
        self.secondary_vector_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn claim_and_query_metadata_byte_length(&self) -> u64 {
        self.claim_and_query_metadata_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn relation_rotation_block_byte_length(&self) -> u64 {
        self.relation_rotation_block_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn external_working_set_byte_length(&self) -> u64 {
        self.external_working_set_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn external_transaction_overlap_peak_byte_length(&self) -> u64 {
        self.external_transaction_overlap_peak_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn subphase_transient_peak_byte_length(&self) -> u64 {
        self.subphase_transient_peak_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn query_prefetch_byte_length(&self) -> u64 {
        self.query_prefetch_byte_length
    }

    #[cfg(test)]
    pub(crate) const fn stream_window_byte_length(&self) -> u64 {
        self.stream_window_byte_length
    }

    pub(crate) const fn total_byte_length(&self) -> u64 {
        self.total_byte_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofResidentMemoryPlan {
    phases: Vec<CommonProofResidentMemoryPhasePlan>,
    peak_byte_length: u64,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofCapNeutralResourceRequirement {
    external_memory_requirement: CommonProofExternalMemoryRequirement,
    resident_memory_requirement: CommonProofResidentMemoryPlan,
}

#[cfg(test)]
impl CommonProofCapNeutralResourceRequirement {
    pub(crate) const fn external_memory_requirement(&self) -> CommonProofExternalMemoryRequirement {
        self.external_memory_requirement
    }

    pub(crate) const fn resident_memory_requirement(&self) -> &CommonProofResidentMemoryPlan {
        &self.resident_memory_requirement
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommonProofResidentMemoryConfiguration {
    application_statement_schema_identifier: u16,
    canonical_header_payload_byte_length: u64,
    maximum_prefetched_query_byte_length: u64,
    external_memory_write_chunk_byte_length: u64,
    maximum_stream_window_byte_length: u64,
}

impl CommonProofResidentMemoryConfiguration {
    pub(crate) const fn new(
        application_statement_schema_identifier: u16,
        canonical_header_payload_byte_length: u64,
        maximum_prefetched_query_byte_length: u64,
        external_memory_write_chunk_byte_length: u64,
        maximum_stream_window_byte_length: u64,
    ) -> Self {
        Self {
            application_statement_schema_identifier,
            canonical_header_payload_byte_length,
            maximum_prefetched_query_byte_length,
            external_memory_write_chunk_byte_length,
            maximum_stream_window_byte_length,
        }
    }
}

impl CommonProofResidentMemoryPlan {
    pub(crate) fn phases(&self) -> &[CommonProofResidentMemoryPhasePlan] {
        &self.phases
    }

    pub(crate) const fn peak_byte_length(&self) -> u64 {
        self.peak_byte_length
    }
}

fn checked_resident_add(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_add(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn checked_resident_multiply(left: u64, right: u64) -> Result<u64, CommonProofProverError> {
    left.checked_mul(right)
        .ok_or(CommonProofProverError::CountOverflow)
}

fn resident_value_byte_length(value_type: RelationColumnValueType) -> u64 {
    match value_type {
        RelationColumnValueType::BaseField => 8,
        RelationColumnValueType::ChallengeExtension => {
            u64::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE).expect("extension degree fits u64") * 8
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommonProofQueryPrefetchRequirement {
    maximum_payload_byte_length: u64,
    maximum_allocation_byte_length: u64,
}

fn common_proof_query_prefetch_entry_requirement(
    entry: &ProofTreeCatalogEntry,
    evaluation_domain_size: usize,
    evaluation_domain_size_u64: u64,
    unique_query_count: usize,
) -> Result<CommonProofQueryPrefetchRequirement, CommonProofProverError> {
    let leaf_count = entry_leaf_count(entry, evaluation_domain_size_u64)
        .map_err(|_| CommonProofProverError::InvalidTree)?;
    let canonical_leaf_byte_length =
        canonical_leaf_byte_length(entry).map_err(|_| CommonProofProverError::InvalidTree)?;
    let query_representatives_per_leaf = match entry.source() {
        ProofTreeCatalogSource::NonterminalFriLayer { .. } => evaluation_domain_size
            .checked_div(2)
            .and_then(|query_orbit_count| query_orbit_count.checked_div(leaf_count))
            .filter(|multiplicity| *multiplicity != 0)
            .ok_or(CommonProofProverError::InvalidTree)?,
        _ => 1,
    };
    let minimum_opened_leaf_count = unique_query_count
        .checked_add(query_representatives_per_leaf - 1)
        .and_then(|count| count.checked_div(query_representatives_per_leaf))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let maximum_opened_leaf_count = unique_query_count.min(leaf_count);
    if minimum_opened_leaf_count == 0 || minimum_opened_leaf_count > maximum_opened_leaf_count {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let digest_level_count = usize::try_from(leaf_count.trailing_zeros())
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_add(1)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let statement_owned_replay_transient_byte_length = if entry_uses_statement_owned_replay(entry) {
        let row_width = entry
            .materialized_row_width()
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        row_width
            .checked_mul(2)
            .and_then(|value_count| value_count.checked_mul(core::mem::size_of::<ProofTreeValue>()))
            .and_then(|length| length.checked_add(canonical_leaf_byte_length))
            .and_then(|length| {
                length.checked_add(row_width.checked_mul(core::mem::size_of::<u32>())?)
            })
            .ok_or(CommonProofProverError::CountOverflow)?
    } else {
        0
    };
    let mut maximum_payload_byte_length = 0_u64;
    let mut maximum_allocation_byte_length = 0_u64;
    for opened_leaf_count in minimum_opened_leaf_count..=maximum_opened_leaf_count {
        let frontier_node_count =
            maximum_minimal_frontier_node_count(leaf_count, opened_leaf_count).map_err(
                |error| match error {
                    ProofBodyError::CountOverflow => CommonProofProverError::CountOverflow,
                    ProofBodyError::AllocationLimitExceeded => {
                        CommonProofProverError::AllocationLimitExceeded
                    }
                    _ => CommonProofProverError::InvalidTree,
                },
            )?;
        let opened_leaf_payload_byte_length = opened_leaf_count
            .checked_mul(canonical_leaf_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let frontier_digest_byte_length = frontier_node_count
            .checked_mul(HASH_BYTE_LENGTH)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let payload_byte_length = opened_leaf_payload_byte_length
            .checked_add(frontier_digest_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let allocation_byte_length = payload_byte_length
            .checked_add(
                opened_leaf_count
                    .checked_mul(core::mem::size_of::<u64>())
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .and_then(|length| {
                length.checked_add(
                    frontier_node_count.checked_mul(core::mem::size_of::<(u32, u64)>())?,
                )
            })
            .and_then(|length| {
                if entry_uses_statement_owned_replay(entry) {
                    length
                        .checked_add(frontier_node_count.checked_mul(core::mem::size_of::<u8>())?)?
                        .checked_add(
                            digest_level_count
                                .checked_sub(1)?
                                .checked_mul(HASH_BYTE_LENGTH)?,
                        )
                        .and_then(|length| {
                            length.checked_add(statement_owned_replay_transient_byte_length)
                        })
                } else {
                    length.checked_add(
                        digest_level_count
                            .checked_mul(core::mem::size_of::<ProofExternalMemoryObject>())?,
                    )
                }
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
        maximum_payload_byte_length = maximum_payload_byte_length.max(
            u64::try_from(payload_byte_length)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        );
        maximum_allocation_byte_length = maximum_allocation_byte_length.max(
            u64::try_from(allocation_byte_length)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        );
    }
    Ok(CommonProofQueryPrefetchRequirement {
        maximum_payload_byte_length,
        maximum_allocation_byte_length,
    })
}

fn common_proof_query_prefetch_requirement(
    catalog: &CompleteProofTreeCatalog,
    unique_query_count: u32,
) -> Result<CommonProofQueryPrefetchRequirement, CommonProofProverError> {
    let unique_query_count =
        usize::try_from(unique_query_count).map_err(|_| CommonProofProverError::CountOverflow)?;
    if unique_query_count == 0 {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let evaluation_domain_size = usize::try_from(catalog.evaluation_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let mut maximum_payload_byte_length = 0_u64;
    let mut maximum_allocation_byte_length = 0_u64;
    for entry in catalog.entries() {
        let requirement = common_proof_query_prefetch_entry_requirement(
            entry,
            evaluation_domain_size,
            catalog.evaluation_domain_size(),
            unique_query_count,
        )?;
        maximum_payload_byte_length =
            maximum_payload_byte_length.max(requirement.maximum_payload_byte_length);
        // Setup-polynomial allocation liveness is derived separately from its
        // compact replay schedule. Keeping the former statement-replay proxy
        // here would both omit the leaf-hash arena and double-charge it later.
        if entry.setup_polynomial_construction().is_none() {
            maximum_allocation_byte_length =
                maximum_allocation_byte_length.max(requirement.maximum_allocation_byte_length);
        }
    }
    if maximum_payload_byte_length == 0 {
        return Err(CommonProofProverError::InvalidOpening);
    }
    Ok(CommonProofQueryPrefetchRequirement {
        maximum_payload_byte_length,
        maximum_allocation_byte_length,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SetupPolynomialReplayResidentRequirement {
    retained_root_pass_catalog_byte_length: u64,
    transforming_base_columns_dynamic_peak_byte_length: u64,
    emitting_queries_dynamic_peak_byte_length: u64,
}

fn setup_polynomial_replay_resident_requirement(
    catalog: &CompleteProofTreeCatalog,
    unique_query_count: u32,
    transform_or_reader_transient_peak_byte_length: u64,
) -> Result<SetupPolynomialReplayResidentRequirement, CommonProofProverError> {
    let evaluation_domain_size = usize::try_from(catalog.evaluation_domain_size())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let unique_query_count =
        usize::try_from(unique_query_count).map_err(|_| CommonProofProverError::CountOverflow)?;
    if unique_query_count == 0 {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let root_pass_map_entry_byte_length =
        map_entry_payload_byte_length::<u16, SetupPolynomialColumnMajorMerkleRootPass>(1)?;
    let opening_artifact_map_entry_byte_length =
        map_entry_payload_byte_length::<u16, PrefetchedCommonProofOpeningArtifact>(1)?;
    let mut setup_tree_memory = Vec::new();
    let mut opening_artifact_byte_lengths = BTreeMap::new();
    for entry in catalog
        .entries()
        .iter()
        .filter(|entry| entry.setup_polynomial_construction().is_some())
    {
        if entry.source() != ProofTreeCatalogSource::RelationBoundPublic
            || entry.bound_root().is_none()
            || entry.uses_common_merkle_context()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let (_, row_width) = entry
            .setup_polynomial_construction()
            .ok_or(CommonProofProverError::InvalidTree)?;
        let ordered_column_count =
            usize::try_from(row_width).map_err(|_| CommonProofProverError::CountOverflow)?;
        let leaf_count = entry_leaf_count(entry, catalog.evaluation_domain_size())
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        if unique_query_count > leaf_count {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let canonical_leaf_byte_length =
            canonical_leaf_byte_length(entry).map_err(|_| CommonProofProverError::InvalidTree)?;
        let frontier_node_count =
            maximum_minimal_frontier_node_count(leaf_count, unique_query_count).map_err(
                |error| match error {
                    ProofBodyError::CountOverflow => CommonProofProverError::CountOverflow,
                    ProofBodyError::AllocationLimitExceeded => {
                        CommonProofProverError::AllocationLimitExceeded
                    }
                    _ => CommonProofProverError::InvalidTree,
                },
            )?;
        let root_replay = setup_polynomial_column_major_merkle_replay_wasm_memory_bound(
            leaf_count,
            ordered_column_count,
            canonical_leaf_byte_length,
            0,
            0,
        )?;
        let opening_replay = setup_polynomial_column_major_merkle_replay_wasm_memory_bound(
            leaf_count,
            ordered_column_count,
            canonical_leaf_byte_length,
            unique_query_count,
            frontier_node_count,
        )?;
        let opening_artifact_byte_length = opening_replay
            .retained_opening_artifact_owned_byte_length()
            .checked_add(opening_artifact_map_entry_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if opening_artifact_byte_lengths
            .insert(entry.tree_catalog_index(), opening_artifact_byte_length)
            .is_some()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        setup_tree_memory.push((
            root_replay.replay_resident_owned_byte_length(),
            opening_replay.replay_resident_owned_byte_length(),
            opening_artifact_byte_length,
        ));
    }

    let retained_root_pass_catalog_byte_length = checked_resident_multiply(
        u64::try_from(setup_tree_memory.len())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        root_pass_map_entry_byte_length,
    )?;
    let mut completed_root_pass_byte_length = 0_u64;
    let mut transforming_base_columns_dynamic_peak_byte_length =
        transform_or_reader_transient_peak_byte_length;
    for (root_replay_byte_length, _, _) in &setup_tree_memory {
        let replay_subphase_byte_length = completed_root_pass_byte_length
            .checked_add(*root_replay_byte_length)
            .and_then(|length| length.checked_add(transform_or_reader_transient_peak_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        transforming_base_columns_dynamic_peak_byte_length =
            transforming_base_columns_dynamic_peak_byte_length.max(replay_subphase_byte_length);
        completed_root_pass_byte_length = completed_root_pass_byte_length
            .checked_add(root_pass_map_entry_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    transforming_base_columns_dynamic_peak_byte_length =
        transforming_base_columns_dynamic_peak_byte_length.max(
            retained_root_pass_catalog_byte_length
                .checked_add(transform_or_reader_transient_peak_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?,
        );

    let mut completed_opening_artifact_byte_length = 0_u64;
    let mut emitting_queries_dynamic_peak_byte_length = 0_u64;
    for (_, opening_replay_byte_length, opening_artifact_byte_length) in &setup_tree_memory {
        let replay_subphase_byte_length = completed_opening_artifact_byte_length
            .checked_add(*opening_replay_byte_length)
            .and_then(|length| length.checked_add(transform_or_reader_transient_peak_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        emitting_queries_dynamic_peak_byte_length =
            emitting_queries_dynamic_peak_byte_length.max(replay_subphase_byte_length);
        completed_opening_artifact_byte_length = completed_opening_artifact_byte_length
            .checked_add(*opening_artifact_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
    }
    emitting_queries_dynamic_peak_byte_length =
        emitting_queries_dynamic_peak_byte_length.max(completed_opening_artifact_byte_length);

    // Setup artifacts are all prepared before catalog-order output starts.
    // Earlier setup entries release their artifact after encoding; ordinary
    // tree prefetch therefore overlaps only artifacts for setup entries that
    // have not yet been emitted.
    let mut remaining_opening_artifact_byte_length = completed_opening_artifact_byte_length;
    for entry in catalog.entries() {
        if let Some(artifact_byte_length) =
            opening_artifact_byte_lengths.get(&entry.tree_catalog_index())
        {
            emitting_queries_dynamic_peak_byte_length = emitting_queries_dynamic_peak_byte_length
                .max(remaining_opening_artifact_byte_length);
            remaining_opening_artifact_byte_length = remaining_opening_artifact_byte_length
                .checked_sub(*artifact_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?;
            continue;
        }
        let entry_requirement = common_proof_query_prefetch_entry_requirement(
            entry,
            evaluation_domain_size,
            catalog.evaluation_domain_size(),
            unique_query_count,
        )?;
        let emission_subphase_byte_length = remaining_opening_artifact_byte_length
            .checked_add(entry_requirement.maximum_allocation_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?;
        emitting_queries_dynamic_peak_byte_length =
            emitting_queries_dynamic_peak_byte_length.max(emission_subphase_byte_length);
    }
    if remaining_opening_artifact_byte_length != 0 {
        return Err(CommonProofProverError::InvalidTree);
    }
    Ok(SetupPolynomialReplayResidentRequirement {
        retained_root_pass_catalog_byte_length,
        transforming_base_columns_dynamic_peak_byte_length,
        emitting_queries_dynamic_peak_byte_length,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CommonProofResidentMemoryPhaseInput {
    relation_polynomial_working_set_byte_length: u64,
    auxiliary_trace_workspace_byte_length: u64,
    replay_polynomial_byte_length: u64,
    primary_vector_byte_length: u64,
    secondary_vector_byte_length: u64,
    claim_and_query_metadata_byte_length: u64,
    relation_rotation_block_byte_length: u64,
    external_working_set_byte_length: u64,
    external_transaction_overlap_peak_byte_length: u64,
    exact_subphase_transient_peak_byte_length: Option<u64>,
    query_prefetch_byte_length: u64,
    output_fragment_byte_length: u64,
    stream_window_byte_length: u64,
}

fn resident_phase_plan_with_infrastructure(
    phase: CommonProofResidentMemoryPhase,
    infrastructure_payload_accounting: CommonProofResidentInfrastructurePayloadAccounting,
    input: CommonProofResidentMemoryPhaseInput,
) -> Result<CommonProofResidentMemoryPhasePlan, CommonProofProverError> {
    let CommonProofResidentMemoryPhaseInput {
        relation_polynomial_working_set_byte_length,
        auxiliary_trace_workspace_byte_length,
        replay_polynomial_byte_length,
        primary_vector_byte_length,
        secondary_vector_byte_length,
        claim_and_query_metadata_byte_length,
        relation_rotation_block_byte_length,
        external_working_set_byte_length,
        external_transaction_overlap_peak_byte_length,
        exact_subphase_transient_peak_byte_length,
        query_prefetch_byte_length,
        output_fragment_byte_length,
        stream_window_byte_length,
    } = input;
    let external_peak_byte_length =
        external_working_set_byte_length.max(external_transaction_overlap_peak_byte_length);
    let additive_subphase_transient_peak_byte_length = relation_rotation_block_byte_length
        .checked_add(external_peak_byte_length)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let subphase_transient_peak_byte_length = exact_subphase_transient_peak_byte_length
        .unwrap_or(additive_subphase_transient_peak_byte_length);
    if subphase_transient_peak_byte_length < relation_rotation_block_byte_length
        || subphase_transient_peak_byte_length < external_peak_byte_length
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let total_byte_length = [
        infrastructure_payload_accounting.total_byte_length(),
        relation_polynomial_working_set_byte_length,
        auxiliary_trace_workspace_byte_length,
        replay_polynomial_byte_length,
        primary_vector_byte_length,
        secondary_vector_byte_length,
        claim_and_query_metadata_byte_length,
        subphase_transient_peak_byte_length,
        query_prefetch_byte_length,
        output_fragment_byte_length,
        stream_window_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_resident_add)?;
    Ok(CommonProofResidentMemoryPhasePlan {
        phase,
        infrastructure_payload_accounting,
        relation_polynomial_working_set_byte_length,
        auxiliary_trace_workspace_byte_length,
        replay_polynomial_byte_length,
        primary_vector_byte_length,
        secondary_vector_byte_length,
        claim_and_query_metadata_byte_length,
        relation_rotation_block_byte_length,
        external_working_set_byte_length,
        external_transaction_overlap_peak_byte_length,
        subphase_transient_peak_byte_length,
        query_prefetch_byte_length,
        output_fragment_byte_length,
        stream_window_byte_length,
        total_byte_length,
    })
}

fn resident_infrastructure_payload_accounting(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    storage_payload: GeneratedCommonProofStorageResidentPayload,
    relation_evaluation_transform_plan_count: usize,
    configuration: CommonProofResidentMemoryConfiguration,
) -> Result<CommonProofResidentInfrastructurePayloadAccounting, CommonProofProverError> {
    let CommonProofResidentMemoryConfiguration {
        application_statement_schema_identifier,
        canonical_header_payload_byte_length,
        ..
    } = configuration;
    if canonical_header_payload_byte_length == 0 {
        return Err(CommonProofProverError::InvalidInput);
    }
    let relation_plan_catalog_payload_byte_length = variant
        .resident_owned_payload_byte_length()
        .map_err(|error| match error {
            RelationPlanError::CountOverflow => CommonProofProverError::CountOverflow,
            _ => CommonProofProverError::InvalidInput,
        })?;
    let relation_context_catalog_payload_byte_length = relation_context
        .resident_owned_payload_byte_length()
        .map_err(|error| match error {
            RelationPlanError::CountOverflow => CommonProofProverError::CountOverflow,
            _ => CommonProofProverError::InvalidInput,
        })?;
    let proof_tree_catalog_payload_byte_length = catalog
        .resident_owned_payload_byte_length()
        .map_err(|error| match error {
            ProofBodyError::CountOverflow => CommonProofProverError::CountOverflow,
            _ => CommonProofProverError::InvalidTree,
        })?;
    let transcript_payload = transcript_schedule
        .live_payload_memory_accounting(application_statement_schema_identifier)
        .map_err(|error| match error {
            TranscriptError::ChallengeCounterOverflow => CommonProofProverError::CountOverflow,
            _ => CommonProofProverError::InvalidInput,
        })?;
    let relation_evaluation_vector_catalog_byte_length =
        map_entry_payload_byte_length::<u32, ExternalPolynomialVector>(
            relation_evaluation_transform_plan_count,
        )?;
    let opening_geometry_catalog_byte_length = checked_resident_multiply(
        u64::try_from(catalog.entries().len())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(std::mem::size_of::<CommonProofOpeningGeometry>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let tree_root_catalog_byte_length = checked_resident_multiply(
        u64::try_from(catalog.entries().len())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        HASH_BYTE_LENGTH as u64,
    )?;
    let root_presence_catalog_byte_length = checked_resident_multiply(
        u64::try_from(catalog.entries().len())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        u64::try_from(std::mem::size_of::<bool>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let application_challenge_assignment_count = transcript_schedule
        .ordered_application_challenge_groups()
        .iter()
        .try_fold(0_u64, |total, group| {
            checked_resident_add(total, u64::from(group.coordinate_count()))
        })?;
    let application_challenge_assignment_catalog_byte_length = checked_resident_multiply(
        application_challenge_assignment_count,
        u64::try_from(std::mem::size_of::<RelationApplicationChallengeAssignment>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let generation_catalog_payload_byte_length = [
        relation_evaluation_vector_catalog_byte_length,
        opening_geometry_catalog_byte_length,
        tree_root_catalog_byte_length,
        root_presence_catalog_byte_length,
        application_challenge_assignment_catalog_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_resident_add)?;
    let resident_phase_catalog_payload_byte_length = checked_resident_multiply(
        u64::from(CommonProofResidentMemoryPhase::EmittingQueries as u8),
        u64::try_from(std::mem::size_of::<CommonProofResidentMemoryPhasePlan>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let state_machine_inline_byte_length =
        u64::try_from(std::mem::size_of::<CommonProofGenerationStateMachine>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    let transcript_persistent_payload_byte_length =
        transcript_payload.persistent_transcript_byte_length();
    let transcript_transient_payload_byte_length =
        transcript_payload.maximum_transient_byte_length();
    let total_byte_length = [
        state_machine_inline_byte_length,
        canonical_header_payload_byte_length,
        relation_plan_catalog_payload_byte_length,
        relation_context_catalog_payload_byte_length,
        proof_tree_catalog_payload_byte_length,
        storage_payload.storage_plan_catalog_byte_length,
        storage_payload.executor_catalog_byte_length,
        generation_catalog_payload_byte_length,
        resident_phase_catalog_payload_byte_length,
        transcript_persistent_payload_byte_length,
        transcript_transient_payload_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_resident_add)?;
    Ok(CommonProofResidentInfrastructurePayloadAccounting {
        state_machine_inline_byte_length,
        canonical_header_payload_byte_length,
        relation_plan_catalog_payload_byte_length,
        relation_context_catalog_payload_byte_length,
        proof_tree_catalog_payload_byte_length,
        storage_plan_catalog_payload_byte_length: storage_payload.storage_plan_catalog_byte_length,
        executor_catalog_payload_byte_length: storage_payload.executor_catalog_byte_length,
        generation_catalog_payload_byte_length,
        resident_phase_catalog_payload_byte_length,
        transcript_persistent_payload_byte_length,
        transcript_transient_payload_byte_length,
        total_byte_length,
    })
}

/// Derives the hard resident live-set for the implemented external-memory
/// schedule. Every potentially domain-sized state-machine field is assigned to
/// a phase: one current relation polynomial, one replay polynomial,
/// descriptor-local auxiliary trace rows, quotient and FRI vectors,
/// DEEP/opening metadata, terminal and query vectors, bounded external
/// materialization/transform/write working sets, query prefetch, output
/// staging, and the acknowledged stream window. Complete Merkle levels and
/// persisted polynomial vectors are external; no pre- or post-challenge
/// relation-column catalog is resident.
fn derive_common_proof_resident_memory_plan(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    storage_payload: GeneratedCommonProofStorageResidentPayload,
    relation_evaluation_transform_plan_count: usize,
    configuration: CommonProofResidentMemoryConfiguration,
) -> Result<CommonProofResidentMemoryPlan, CommonProofProverError> {
    let CommonProofResidentMemoryConfiguration {
        maximum_prefetched_query_byte_length,
        external_memory_write_chunk_byte_length,
        maximum_stream_window_byte_length,
        ..
    } = configuration;
    if maximum_prefetched_query_byte_length == 0
        || external_memory_write_chunk_byte_length == 0
        || maximum_stream_window_byte_length == 0
        || variant.evaluation_domain_size() != catalog.evaluation_domain_size()
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let evaluation_domain_size = variant.evaluation_domain_size();
    let trace_domain_size = variant.trace_domain_size();
    let infrastructure_payload_accounting = resident_infrastructure_payload_accounting(
        variant,
        relation_context,
        transcript_schedule,
        catalog,
        storage_payload,
        relation_evaluation_transform_plan_count,
        configuration,
    )?;
    let quotient_stream_requirement =
        common_proof_quotient_stream_requirement(variant, external_memory_write_chunk_byte_length)?;
    let query_prefetch_requirement =
        common_proof_query_prefetch_requirement(catalog, transcript_schedule.unique_query_count())?;
    if query_prefetch_requirement.maximum_payload_byte_length > maximum_prefetched_query_byte_length
    {
        return Err(CommonProofProverError::AllocationLimitExceeded);
    }
    let extension_value_byte_length =
        resident_value_byte_length(RelationColumnValueType::ChallengeExtension);
    let base_value_byte_length = resident_value_byte_length(RelationColumnValueType::BaseField);
    let trace_vector_byte_length =
        checked_resident_multiply(trace_domain_size, base_value_byte_length)?;
    let mut maximum_relation_polynomial_byte_length = 0_u64;
    let mut maximum_replay_source_byte_length = 0_u64;
    let mut maximum_replay_writer_working_set_byte_length = 0_u64;
    let mut maximum_stockham_working_set_byte_length = 0_u64;
    let mut maximum_stockham_transaction_overlap_peak_byte_length = 0_u64;
    for column in variant.ordered_columns() {
        let value_byte_length = resident_value_byte_length(column.value_type());
        let source_byte_length =
            checked_resident_multiply(column.source_degree_bound_exclusive(), value_byte_length)?;
        maximum_relation_polynomial_byte_length =
            maximum_relation_polynomial_byte_length.max(source_byte_length);
        maximum_replay_source_byte_length =
            maximum_replay_source_byte_length.max(source_byte_length);
        let maximum_scan_element_count = external_memory_write_chunk_byte_length
            .checked_div(value_byte_length)
            .filter(|count| *count != 0)
            .ok_or(CommonProofProverError::InvalidInput)?;
        let stockham_scan_byte_length =
            checked_resident_multiply(maximum_scan_element_count, value_byte_length)?;
        let stockham_requirement = external_stockham_resident_memory_requirement(
            stockham_scan_byte_length,
            external_memory_write_chunk_byte_length,
        )
        .map_err(|error| match error {
            super::ExternalPolynomialError::CountOverflow => CommonProofProverError::CountOverflow,
            super::ExternalPolynomialError::AllocationLimitExceeded => {
                CommonProofProverError::AllocationLimitExceeded
            }
            _ => CommonProofProverError::InvalidInput,
        })?;
        let replay_writer_working_set_byte_length =
            checked_resident_add(external_memory_write_chunk_byte_length, value_byte_length)?;
        maximum_replay_writer_working_set_byte_length =
            maximum_replay_writer_working_set_byte_length
                .max(replay_writer_working_set_byte_length);
        maximum_stockham_working_set_byte_length = maximum_stockham_working_set_byte_length
            .max(stockham_requirement.component_working_set_byte_length());
        maximum_stockham_transaction_overlap_peak_byte_length =
            maximum_stockham_transaction_overlap_peak_byte_length
                .max(stockham_requirement.transaction_overlap_peak_byte_length());
    }
    if maximum_relation_polynomial_byte_length == 0 || maximum_replay_source_byte_length == 0 {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let setup_polynomial_reader_chunk_byte_length = external_memory_write_chunk_byte_length
        .checked_div(base_value_byte_length)
        .and_then(|element_count| element_count.checked_mul(base_value_byte_length))
        .filter(|byte_length| *byte_length != 0)
        .ok_or(CommonProofProverError::InvalidInput)?;
    let setup_polynomial_reader_peak_byte_length =
        checked_resident_multiply(setup_polynomial_reader_chunk_byte_length, 2)?;
    let transform_or_reader_transient_peak_byte_length = maximum_stockham_working_set_byte_length
        .max(maximum_stockham_transaction_overlap_peak_byte_length)
        .max(setup_polynomial_reader_peak_byte_length);
    let setup_polynomial_replay_requirement = setup_polynomial_replay_resident_requirement(
        catalog,
        transcript_schedule.unique_query_count(),
        transform_or_reader_transient_peak_byte_length,
    )?;
    if setup_polynomial_replay_requirement.emitting_queries_dynamic_peak_byte_length
        < query_prefetch_requirement.maximum_allocation_byte_length
    {
        return Err(CommonProofProverError::InvalidInput);
    }
    let retained_setup_polynomial_root_pass_catalog_byte_length =
        setup_polynomial_replay_requirement.retained_root_pass_catalog_byte_length;

    let auxiliary_trace_workspace_byte_length = checked_resident_multiply(
        trace_vector_byte_length,
        super::maximum_auxiliary_synthesis_trace_vector_count(variant)?,
    )?;
    let mut maximum_trace_mask_polynomial_byte_length = 0_u64;
    for mask in variant.ordered_masks().iter().copied().filter(|mask| {
        mask.mask_kind() == RelationMaskKind::Trace
            && mask.target_class() == RelationMaskTargetClass::Column
    }) {
        let column = variant
            .ordered_columns()
            .get(
                usize::try_from(mask.target_ordinal())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )
            .ok_or(CommonProofProverError::InvalidMask)?;
        maximum_trace_mask_polynomial_byte_length =
            maximum_trace_mask_polynomial_byte_length.max(checked_resident_multiply(
                mask.mask_degree_bound_exclusive(),
                resident_value_byte_length(column.value_type()),
            )?);
    }
    let source_polynomial_construction_working_set_byte_length = checked_resident_add(
        maximum_relation_polynomial_byte_length,
        maximum_trace_mask_polynomial_byte_length,
    )?;
    let reversed_polynomial_construction_working_set_byte_length = checked_resident_add(
        maximum_replay_source_byte_length,
        checked_resident_multiply(trace_vector_byte_length, 2)?,
    )?
    .max(source_polynomial_construction_working_set_byte_length);
    let auxiliary_output_growth_byte_length =
        maximum_relation_polynomial_byte_length.saturating_sub(trace_vector_byte_length);

    let mut maximum_relation_merkle_working_set_byte_length = 0_u64;
    let mut maximum_extension_merkle_working_set_byte_length = 0_u64;
    for entry in catalog.entries() {
        if common_tree_materialization_phase(entry.source()).is_none() {
            continue;
        }
        let leaf_count = u64::try_from(
            entry_leaf_count(entry, catalog.evaluation_domain_size())
                .map_err(|_| CommonProofProverError::InvalidTree)?,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        if leaf_count == 0 || !leaf_count.is_power_of_two() {
            return Err(CommonProofProverError::InvalidTree);
        }
        let canonical_leaf_byte_length = u64::try_from(
            canonical_leaf_byte_length(entry).map_err(|_| CommonProofProverError::InvalidTree)?,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        if entry_uses_statement_owned_replay(entry) {
            // Setup-polynomial roots were already produced by the compact
            // column-major replay during the base-column transform phase.
            // Base-tree materialization only validates the retained root pass.
            if entry.setup_polynomial_construction().is_some() {
                continue;
            }
            let row_width = u64::try_from(
                entry
                    .materialized_row_width()
                    .map_err(|_| CommonProofProverError::InvalidTree)?,
            )
            .map_err(|_| CommonProofProverError::CountOverflow)?;
            let paired_typed_value_byte_length = checked_resident_multiply(
                checked_resident_multiply(row_width, 2)?,
                u64::try_from(core::mem::size_of::<ProofTreeValue>())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )?;
            let online_merkle_stack_byte_length = checked_resident_multiply(
                u64::from(leaf_count.trailing_zeros()),
                HASH_BYTE_LENGTH as u64,
            )?;
            let column_ordinal_byte_length = checked_resident_multiply(
                row_width,
                u64::try_from(core::mem::size_of::<u32>())
                    .map_err(|_| CommonProofProverError::CountOverflow)?,
            )?;
            let working_set_byte_length = checked_resident_add(
                checked_resident_add(
                    checked_resident_add(
                        paired_typed_value_byte_length,
                        canonical_leaf_byte_length,
                    )?,
                    online_merkle_stack_byte_length,
                )?,
                column_ordinal_byte_length,
            )?;
            maximum_relation_merkle_working_set_byte_length =
                maximum_relation_merkle_working_set_byte_length.max(working_set_byte_length);
            continue;
        }
        // The materializer owns one canonical leaf, both typed phase values,
        // the two child plus one parent digests, and two external-memory write
        // chunks that gather exact object-wide records. All complete levels
        // live in external memory.
        let working_set_byte_length = checked_resident_add(
            checked_resident_add(
                checked_resident_multiply(canonical_leaf_byte_length, 2)?,
                checked_resident_multiply(3, HASH_BYTE_LENGTH as u64)?,
            )?,
            checked_resident_multiply(external_memory_write_chunk_byte_length, 2)?,
        )?;
        match entry.source() {
            ProofTreeCatalogSource::RelationProofCreated { .. }
            | ProofTreeCatalogSource::RelationBoundPublic => {
                maximum_relation_merkle_working_set_byte_length =
                    maximum_relation_merkle_working_set_byte_length.max(working_set_byte_length);
            }
            ProofTreeCatalogSource::QuotientComponent { .. }
            | ProofTreeCatalogSource::OpeningBatchMask
            | ProofTreeCatalogSource::NonterminalFriLayer { .. } => {
                maximum_extension_merkle_working_set_byte_length =
                    maximum_extension_merkle_working_set_byte_length.max(working_set_byte_length);
            }
        }
    }
    let evaluation_extension_vector_byte_length =
        checked_resident_multiply(evaluation_domain_size, extension_value_byte_length)?;
    let relation_rotation_block_byte_length =
        quotient_stream_requirement.maximum_rotation_block_byte_length;
    let quotient_external_working_set_byte_length = maximum_stockham_working_set_byte_length
        .max(quotient_stream_requirement.maximum_read_working_set_byte_length);
    let quotient_external_transaction_overlap_peak_byte_length =
        maximum_stockham_transaction_overlap_peak_byte_length
            .max(quotient_stream_requirement.maximum_read_transaction_overlap_peak_byte_length);
    let quotient_stockham_transient_peak_byte_length = maximum_stockham_working_set_byte_length
        .max(maximum_stockham_transaction_overlap_peak_byte_length);
    let quotient_subphase_transient_peak_byte_length = quotient_stockham_transient_peak_byte_length
        .max(quotient_stream_requirement.maximum_read_subphase_transient_byte_length);
    let quotient_component_byte_length = checked_resident_multiply(
        relation_context.quotient_component_degree_bound_exclusive,
        extension_value_byte_length,
    )?;
    let opening_batch_mask_byte_length = {
        let mut matching_masks = variant.ordered_masks().iter().copied().filter(|mask| {
            mask.mask_kind() == RelationMaskKind::OpeningBatch
                && mask.target_class() == RelationMaskTargetClass::Batch
                && mask.target_ordinal() == 0
        });
        let mask = matching_masks.next();
        if matching_masks.next().is_some()
            || (transcript_schedule.privacy_mode() == CommonProofPrivacyMode::SecretBearing)
                != mask.is_some()
        {
            return Err(CommonProofProverError::InvalidMask);
        }
        mask.map_or(Ok(0), |descriptor| {
            checked_resident_multiply(
                descriptor.mask_degree_bound_exclusive(),
                extension_value_byte_length,
            )
        })?
    };
    let opening_accumulator_byte_length = checked_resident_multiply(
        variant
            .opening_degree_bound_exclusive()
            .checked_sub(1)
            .ok_or(CommonProofProverError::InvalidOpening)?,
        extension_value_byte_length,
    )?;
    // While creating a middle quotient component, the cursor owns the current
    // component and both neighboring telescoping randomizers. While
    // materializing it, the current component and previous randomizer instead
    // overlap one bounded Merkle working set.
    let quotient_component_creation_working_set_byte_length =
        checked_resident_multiply(quotient_component_byte_length, 3)?;
    let quotient_component_materialization_working_set_byte_length = checked_resident_add(
        checked_resident_multiply(quotient_component_byte_length, 2)?,
        maximum_extension_merkle_working_set_byte_length,
    )?;
    let quotient_component_phase_working_set_byte_length =
        quotient_component_creation_working_set_byte_length
            .max(quotient_component_materialization_working_set_byte_length);
    let opening_claim_count = u64::try_from(variant.ordered_opening_claims().len())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let opening_point_count = variant
        .ordered_opening_claims()
        .iter()
        .map(|claim| u64::from(claim.opening_point_ordinal()) + 1)
        .max()
        .unwrap_or(0);
    let opening_metadata_byte_length = checked_resident_multiply(
        checked_resident_add(
            checked_resident_multiply(opening_claim_count, 2)?,
            opening_point_count,
        )?,
        extension_value_byte_length,
    )?;
    let deep_evaluation_byte_length =
        checked_resident_multiply(opening_claim_count, extension_value_byte_length)?;
    let terminal_coefficient_byte_length = checked_resident_multiply(
        u64::from(relation_context.final_polynomial_degree_bound_exclusive),
        extension_value_byte_length,
    )?;
    let query_representative_byte_length = checked_resident_multiply(
        checked_resident_multiply(u64::from(transcript_schedule.unique_query_count()), 2)?,
        u64::try_from(core::mem::size_of::<u64>())
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let query_metadata_byte_length = checked_resident_add(
        checked_resident_add(
            terminal_coefficient_byte_length,
            checked_resident_multiply(opening_claim_count, extension_value_byte_length)?,
        )?,
        query_representative_byte_length,
    )?;
    let emitted_query_metadata_byte_length = checked_resident_add(
        terminal_coefficient_byte_length,
        checked_resident_multiply(
            u64::from(transcript_schedule.unique_query_count()),
            u64::try_from(core::mem::size_of::<u64>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?,
    )?;
    let auxiliary_relation_polynomial_working_set_byte_length = maximum_replay_source_byte_length
        .max(checked_resident_add(
            auxiliary_output_growth_byte_length,
            maximum_trace_mask_polynomial_byte_length,
        )?);
    let maximum_opening_replay_polynomial_byte_length = maximum_replay_source_byte_length
        .max(quotient_component_byte_length)
        .max(opening_batch_mask_byte_length);
    let opening_phase_vector_working_set_byte_length =
        maximum_opening_replay_polynomial_byte_length.max(checked_resident_add(
            opening_batch_mask_byte_length,
            maximum_extension_merkle_working_set_byte_length,
        )?);

    let resident_phase_plan = |phase, input| {
        resident_phase_plan_with_infrastructure(phase, infrastructure_payload_accounting, input)
    };
    let phases = vec![
        resident_phase_plan(
            CommonProofResidentMemoryPhase::LoadingSourcePolynomials,
            CommonProofResidentMemoryPhaseInput {
                relation_polynomial_working_set_byte_length:
                    source_polynomial_construction_working_set_byte_length,
                external_working_set_byte_length: maximum_replay_writer_working_set_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::ConstructingReversedColumns,
            CommonProofResidentMemoryPhaseInput {
                relation_polynomial_working_set_byte_length:
                    reversed_polynomial_construction_working_set_byte_length,
                external_working_set_byte_length: maximum_replay_writer_working_set_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::TransformingBaseColumns,
            CommonProofResidentMemoryPhaseInput {
                external_working_set_byte_length: maximum_stockham_working_set_byte_length,
                external_transaction_overlap_peak_byte_length:
                    maximum_stockham_transaction_overlap_peak_byte_length,
                exact_subphase_transient_peak_byte_length: Some(
                    setup_polynomial_replay_requirement
                        .transforming_base_columns_dynamic_peak_byte_length,
                ),
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::MaterializingBaseTrees,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                external_working_set_byte_length: maximum_relation_merkle_working_set_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::DerivingAuxiliaryColumns,
            CommonProofResidentMemoryPhaseInput {
                relation_polynomial_working_set_byte_length:
                    auxiliary_relation_polynomial_working_set_byte_length,
                auxiliary_trace_workspace_byte_length,
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                external_working_set_byte_length: maximum_replay_writer_working_set_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::TransformingAuxiliaryColumns,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                external_working_set_byte_length: maximum_stockham_working_set_byte_length,
                external_transaction_overlap_peak_byte_length:
                    maximum_stockham_transaction_overlap_peak_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::MaterializingAuxiliaryTrees,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                external_working_set_byte_length: maximum_relation_merkle_working_set_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::ConstructingQuotient,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                primary_vector_byte_length: evaluation_extension_vector_byte_length,
                relation_rotation_block_byte_length,
                external_working_set_byte_length: quotient_external_working_set_byte_length,
                external_transaction_overlap_peak_byte_length:
                    quotient_external_transaction_overlap_peak_byte_length,
                exact_subphase_transient_peak_byte_length: Some(
                    quotient_subphase_transient_peak_byte_length,
                ),
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::MaterializingQuotientTrees,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                primary_vector_byte_length: evaluation_extension_vector_byte_length,
                secondary_vector_byte_length: quotient_component_phase_working_set_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::DerivingOpenings,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                primary_vector_byte_length: opening_phase_vector_working_set_byte_length,
                claim_and_query_metadata_byte_length: opening_metadata_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::ConstructingInitialFri,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length: checked_resident_add(
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                    maximum_opening_replay_polynomial_byte_length,
                )?,
                primary_vector_byte_length: opening_accumulator_byte_length,
                claim_and_query_metadata_byte_length: opening_metadata_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::FoldingFri,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                primary_vector_byte_length: evaluation_extension_vector_byte_length,
                claim_and_query_metadata_byte_length: deep_evaluation_byte_length,
                external_working_set_byte_length: maximum_extension_merkle_working_set_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::PreparingQueryOutput,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                claim_and_query_metadata_byte_length: query_metadata_byte_length,
                output_fragment_byte_length: maximum_stream_window_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
        resident_phase_plan(
            CommonProofResidentMemoryPhase::EmittingQueries,
            CommonProofResidentMemoryPhaseInput {
                replay_polynomial_byte_length:
                    retained_setup_polynomial_root_pass_catalog_byte_length,
                claim_and_query_metadata_byte_length: emitted_query_metadata_byte_length,
                // This scheduled peak includes prior setup artifacts, the
                // active setup opening replay, and its transform-or-reader
                // overlap. It also covers ordinary catalog-order prefetch with
                // only the setup artifacts that remain live at that point.
                query_prefetch_byte_length: setup_polynomial_replay_requirement
                    .emitting_queries_dynamic_peak_byte_length,
                output_fragment_byte_length: maximum_stream_window_byte_length,
                stream_window_byte_length: maximum_stream_window_byte_length,
                ..CommonProofResidentMemoryPhaseInput::default()
            },
        )?,
    ];
    let peak_byte_length = phases
        .iter()
        .map(CommonProofResidentMemoryPhasePlan::total_byte_length)
        .max()
        .ok_or(CommonProofProverError::InvalidInput)?;
    Ok(CommonProofResidentMemoryPlan {
        phases,
        peak_byte_length,
    })
}

/// Derives the exact selected liveness requirement before applying the
/// absolute WebAssembly safety bound. Development accounting uses this to
/// report a concrete overage instead of replacing it with an opaque failure.
#[cfg(test)]
pub(crate) fn common_proof_cap_neutral_resource_requirement(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    configuration: CommonProofResidentMemoryConfiguration,
) -> Result<CommonProofCapNeutralResourceRequirement, GeneratedCommonProofStoragePlanError> {
    let external_memory_write_chunk_byte_length =
        u32::try_from(configuration.external_memory_write_chunk_byte_length).map_err(|_| {
            GeneratedCommonProofStoragePlanError::Prover(CommonProofProverError::CountOverflow)
        })?;
    let geometry = derive_generated_common_proof_storage_geometry(
        variant,
        relation_context,
        catalog,
        transcript_schedule,
        external_memory_write_chunk_byte_length,
        true,
        GeneratedCommonProofStorageGeometryMode::RequirementOnly,
    )?;
    let resident_memory_requirement = derive_common_proof_resident_memory_plan(
        variant,
        relation_context,
        transcript_schedule,
        catalog,
        geometry.resident_payload_requirement,
        geometry.relation_evaluation_transform_plan_count,
        configuration,
    )
    .map_err(GeneratedCommonProofStoragePlanError::Prover)?;
    Ok(CommonProofCapNeutralResourceRequirement {
        external_memory_requirement: common_proof_external_memory_requirement_from_geometry(
            &geometry,
        ),
        resident_memory_requirement,
    })
}

#[cfg(test)]
pub(crate) fn common_proof_resident_memory_requirement(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    configuration: CommonProofResidentMemoryConfiguration,
) -> Result<CommonProofResidentMemoryPlan, CommonProofProverError> {
    common_proof_cap_neutral_resource_requirement(
        variant,
        relation_context,
        transcript_schedule,
        catalog,
        configuration,
    )
    .map_err(|error| match error {
        GeneratedCommonProofStoragePlanError::Prover(error) => error,
        GeneratedCommonProofStoragePlanError::Storage(_) => CommonProofProverError::InvalidInput,
    })
    .map(|requirement| requirement.resident_memory_requirement)
}

pub(crate) fn common_proof_resident_memory_plan(
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    transcript_schedule: &CommonProofTranscriptSchedule,
    catalog: &CompleteProofTreeCatalog,
    storage_plan: &GeneratedCommonProofStoragePlan,
    configuration: CommonProofResidentMemoryConfiguration,
) -> Result<CommonProofResidentMemoryPlan, CommonProofProverError> {
    let storage_payload = storage_plan.resident_owned_payload()?;
    let plan = derive_common_proof_resident_memory_plan(
        variant,
        relation_context,
        transcript_schedule,
        catalog,
        storage_payload,
        storage_plan.relation_evaluation_transform_plans.len(),
        configuration,
    )?;
    if plan.peak_byte_length() > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH {
        return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
    }
    Ok(plan)
}
