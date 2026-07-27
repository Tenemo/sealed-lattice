//! Checked-plan production generation state for the row-code/WHIR construction.
//!
//! This state owns the authenticated application source before any proof byte
//! can be emitted. Authenticated source and derived columns are replayed from
//! browser-owned external memory. Phase commitments use a bounded stripe of
//! canonical SHAKE256 states, so the implementation schedule does not enter
//! the cryptographic identity and complete phase material is never resident.

use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet};

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

use super::exact_same_secret::{
    ExactSameSecretAggregateMetadata, ExactSameSecretAggregateSource,
    ExactSameSecretAggregateSourceAction, ExactSameSecretAggregateSourceTarget,
    ExactSameSecretOpeningSchedule, ExactSameSecretPhaseOpenings,
};
use super::relation_materialization::{
    RowCodeWhirAuxiliaryRelationMaterialization, RowCodeWhirAuxiliaryRelationMaterializationAction,
    RowCodeWhirQuotientMaterialization, RowCodeWhirQuotientMaterializationAction,
};
use super::same_secret_source_manifest::{
    SameSecretAuthenticatedSourceManifest, SameSecretAuthenticatedSourceManifestError,
};
use super::streaming_whir_prover::{
    StreamingPlainAggregateRetainedCommitmentGeneration,
    StreamingPlainAggregateRetainedCommitmentPoll, StreamingPlainAggregateRetainedOracleError,
    StreamingPlainAggregateRetainedProofGeneration, StreamingPlainAggregateRetainedProofPoll,
};
use super::{
    AuthenticatedColumn, ExactSameSecretAuthenticatedTranscriptPrefixRequest,
    ExactSameSecretTranscriptPrefixAuthorityBinding, ExtensionFieldChallenger,
    PreparedExactSameSecretTranscriptPrefix, RowCodeWhirConstructionPlan,
    column_commitment::{ColumnDigest, StripedColumnCommitmentBuilder},
    construction_plan::{
        ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT, RowCodeWhirCheckpointBoundary,
        RowCodeWhirOpenedPolynomialSource, RowCodeWhirPhase, RowCodeWhirProofSectionRole,
    },
    plain_whir::{
        PlainAggregateCommitment, PlainAggregateProof, plain_aggregate_pcs_for_construction_plan,
    },
    plan_row_code_whir_quotient_transform_storage,
    retained_oracle_codec::RetainedPlainWhirOracleStorageError,
    row_encoding::{RowCodeHighHalfSource, encode_row},
};
use crate::bgv::proof_suite::external_memory::{
    ProofExternalMemoryError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
};
use crate::bgv::proof_suite::external_polynomial::{
    ExternalStockhamTransform, ExternalStockhamTransformError, ExternalStockhamTransformPlan,
    ExternalStockhamTransformProgress, map_external_polynomial_plan_error,
    read_external_polynomial_extension_values,
};
use crate::bgv::proof_suite::prover::{
    CommonProofExternalMemoryRequirement, CommonProofGenerationCheckpointBoundary,
    CommonProofPreChallengeSourceCursor, CommonProofPreChallengeSourcePoll,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinError,
    CommonProofQuotientConstraintTransformKey, CommonProofReplayPolynomialPlan,
    CommonProofReplayPolynomialRangeDestination, CommonProofReplayPolynomialRangeReader,
    CommonProofReplayPolynomialReader, CommonProofReplayPolynomialRef,
    CommonProofReplayPolynomialWriter,
    authenticated_pre_challenge_source_coefficient_position_counts,
    canonical_proof_object_header_bytes, construct_reversed_relation_column,
    persisted_pre_challenge_column_coefficient_position_counts,
    relation_column_replay_requirements, relation_reversed_column_bindings,
    requested_pre_challenge_source_column_ordinals, validate_generation_relation_trees,
};
use crate::bgv::proof_suite::relation_plan::{
    BoundTreeRootUse, ProofPrivacyMode, RelationColumnValueType, RelationOpeningClaimDescriptor,
    RelationOpeningSourceClass,
};
use crate::bgv::proof_suite::transcript::{
    RowCodeWhirTranscript, RowCodeWhirTranscriptCheckpointCursor,
};
use crate::bgv::proof_suite::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofByteSink, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofProverError,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialRequestContext, MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, ProofBaseFieldElement,
    ProofChallengeExtensionElement, ProofExternalMemory, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryUsage,
    RelationApplicationChallengeAssignment, RelationPlanCheckContext, RelationPlanVariant,
    RelationProofTreeInput, ValidatedRelationPlanArtifact, construct_opening_batch_mask,
    evaluate_extension_at, sample_relation_application_challenges,
    verified_application_statement_hash,
};
use crate::hashing::StreamingHash512;

const HASH_BYTE_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirGenerationPhase {
    PreparingAuthenticatedSources,
    LoadingAuthenticatedSources,
    ConstructingReversedColumns,
    SamplingRowPads,
    CommittingBasePhase,
    AwaitingAuthenticatedTranscriptPrefix,
    DerivingAuxiliaryColumns,
    CommittingAuxiliaryPhase,
    PreparingQuotient,
    ConstructingQuotient,
    DerivingOpeningBatchMask,
    CommittingQuotientPhase,
    CompletingQuotientPhaseStorage,
    DerivingOutOfDomainOpenings,
    EvaluatingOutOfDomainOpenings { next_claim_index: usize },
    PreparingAggregateSource,
    MaterializingAggregateSource,
    CommittingAggregate,
    PreparingAggregateOpenings,
    MaterializingBasePhaseOpenings,
    MaterializingAuxiliaryPhaseOpenings,
    MaterializingQuotientPhaseOpenings,
    CompletingAggregateCommitment,
    GeneratingAggregateWhirProof,
    AwaitingExactProofAssembly,
    Cancelled,
}

const SOURCE_REPLAY_ISSUED_STEP: u32 = 0;
const AUXILIARY_REPLAY_ISSUED_STEP: u32 = 1;
const FIRST_QUOTIENT_TRANSFORM_STEP: u32 = 2;
const ROW_PAD_SEED_BYTE_LENGTH: usize = 3 * 32;
const MAXIMUM_PHASE_COMMITMENT_STRIPE_COLUMN_COUNT: usize = 1 << 20;
const MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH: usize = 16 * 1_024;
const ROW_CODE_WHIR_CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN: &str =
    "sealed-lattice/row-code-whir/checkpoint-committed-state/v1";
const SAME_SECRET_SOURCE_REPLAY_IDENTITY_HASH_DOMAIN: &str =
    "sealed-lattice/row-code-whir/same-secret-source-replay-identity/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirReplayPolynomialTarget {
    RelationColumn(u32),
    OpenedPolynomial(RowCodeWhirOpenedPolynomialSource),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirReplayWriteContinuation {
    AuthenticatedSource,
    ReversedColumn,
    AuxiliaryColumn,
    QuotientComponent { component_ordinal: u32 },
    OpeningBatchMask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirPhaseMaterializationPurpose {
    InitialCommitment,
    AuthenticatedOpenings,
}

struct PendingRowCodeWhirReplayPolynomial {
    target: RowCodeWhirReplayPolynomialTarget,
    polynomial: CommonProofSourcePolynomial,
    continuation: RowCodeWhirReplayWriteContinuation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirReplayReadContinuation {
    ReversedColumn {
        source_column_ordinal: u32,
        reversed_column_ordinal: u32,
    },
    AuxiliaryColumn {
        column_ordinal: u32,
    },
    OutOfDomainOpening {
        claim_index: usize,
    },
}

struct ActiveRowCodeWhirReplayPolynomialReader {
    reader: CommonProofReplayPolynomialReader,
    continuation: RowCodeWhirReplayReadContinuation,
}

enum ExactSameSecretAggregateSourceRange {
    Base(Zeroizing<Vec<ProofBaseFieldElement>>),
    Extension(Zeroizing<Vec<ProofChallengeExtensionElement>>),
}

impl ExactSameSecretAggregateSourceRange {
    fn new(action: ExactSameSecretAggregateSourceAction) -> Result<Self, CommonProofProverError> {
        let coefficient_count = action.source_range_length();
        if coefficient_count == 0 {
            return Err(CommonProofProverError::InvalidColumn);
        }
        match action.value_type() {
            RelationColumnValueType::BaseField => {
                let mut coefficients = Vec::new();
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                coefficients.resize(coefficient_count, ProofBaseFieldElement::ZERO);
                Ok(Self::Base(Zeroizing::new(coefficients)))
            }
            RelationColumnValueType::ChallengeExtension => {
                let mut coefficients = Vec::new();
                coefficients
                    .try_reserve_exact(coefficient_count)
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                coefficients.resize(coefficient_count, ProofChallengeExtensionElement::ZERO);
                Ok(Self::Extension(Zeroizing::new(coefficients)))
            }
        }
    }

    fn destination(&mut self) -> CommonProofReplayPolynomialRangeDestination<'_> {
        match self {
            Self::Base(coefficients) => {
                CommonProofReplayPolynomialRangeDestination::Base(coefficients)
            }
            Self::Extension(coefficients) => {
                CommonProofReplayPolynomialRangeDestination::Extension(coefficients)
            }
        }
    }

    fn into_source_polynomial(self) -> CommonProofSourcePolynomial {
        match self {
            Self::Base(coefficients) => {
                CommonProofSourcePolynomial::from_protected_base_coefficients(coefficients)
            }
            Self::Extension(coefficients) => {
                CommonProofSourcePolynomial::from_protected_extension_coefficients(coefficients)
            }
        }
    }
}

struct ActiveExactSameSecretAggregateSourceRead {
    action: ExactSameSecretAggregateSourceAction,
    reader: CommonProofReplayPolynomialRangeReader,
    source_range: ExactSameSecretAggregateSourceRange,
}

struct ActiveRowCodeWhirQuotientTransform {
    transform_key: CommonProofQuotientConstraintTransformKey,
    transform: ExternalStockhamTransform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirPhasePolynomialBinding {
    Relation {
        logical_block_index: usize,
        column_ordinal: u32,
        coefficient_chunk_ordinal: u32,
    },
    Opened {
        logical_block_index: usize,
        source: RowCodeWhirOpenedPolynomialSource,
        coefficient_chunk_ordinal: u32,
    },
}

struct RowCodeWhirGenerationStoragePlan {
    external_memory_plan: ProofExternalMemoryPlan,
    relation_polynomial_plans: BTreeMap<u32, CommonProofReplayPolynomialPlan>,
    opened_polynomial_plans:
        BTreeMap<RowCodeWhirOpenedPolynomialSource, CommonProofReplayPolynomialPlan>,
    quotient_transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, ExternalStockhamTransformPlan>,
    retained_oracles: [super::retained_oracle::RetainedPlainWhirEncodedOracle; 5],
}

impl RowCodeWhirGenerationStoragePlan {
    fn new(
        construction_plan: &RowCodeWhirConstructionPlan,
        variant: &RelationPlanVariant,
        relation_context: &RelationPlanCheckContext,
        reversed_column_bindings: &[(u32, u32)],
    ) -> Result<Self, CommonProofGenerationInitializationError> {
        let requested_source_column_ordinals =
            requested_pre_challenge_source_column_ordinals(variant)
                .map_err(CommonProofGenerationInitializationError::Prover)?;
        if requested_source_column_ordinals != construction_plan.requested_source_column_ordinals {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }

        let requested_source_columns = requested_source_column_ordinals
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let reversed_columns = reversed_column_bindings
            .iter()
            .map(|(_, reversed_column_ordinal)| *reversed_column_ordinal)
            .collect::<BTreeSet<_>>();
        if reversed_columns.len() != reversed_column_bindings.len()
            || reversed_column_bindings.iter().any(
                |(source_column_ordinal, reversed_column_ordinal)| {
                    !requested_source_columns.contains(source_column_ordinal)
                        || requested_source_columns.contains(reversed_column_ordinal)
                },
            )
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }

        let phase_columns = construction_plan
            .base_phase
            .iter()
            .chain(construction_plan.auxiliary_phase.iter())
            .flat_map(|phase| &phase.rows)
            .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
            .map(|chunk| chunk.column_ordinal)
            .collect::<BTreeSet<_>>();
        let mut phase_replay_counts = BTreeMap::<u32, u64>::new();
        for phase in construction_plan
            .base_phase
            .iter()
            .chain(construction_plan.auxiliary_phase.iter())
        {
            let stripe_count = phase
                .geometry
                .encoded_column_count
                .div_ceil(MAXIMUM_PHASE_COMMITMENT_STRIPE_COLUMN_COUNT);
            let stripe_count = u64::try_from(stripe_count).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?;
            let commitment_and_opening_replay_count = stripe_count.checked_mul(2).ok_or(
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ),
            )?;
            for chunk in phase
                .rows
                .iter()
                .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
            {
                let replay_count = phase_replay_counts.entry(chunk.column_ordinal).or_default();
                *replay_count = replay_count
                    .checked_add(commitment_and_opening_replay_count)
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
            }
        }
        let auxiliary_columns = construction_plan
            .auxiliary_phase
            .iter()
            .flat_map(|phase| &phase.rows)
            .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
            .map(|chunk| chunk.column_ordinal)
            .collect::<BTreeSet<_>>();
        let mut relation_opening_read_counts = BTreeMap::<u32, u64>::new();
        for claim in variant.ordered_opening_claims() {
            if claim.source_class() != RelationOpeningSourceClass::TreeColumn {
                continue;
            }
            let column_ordinal =
                claim
                    .column_ordinal()
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ))?;
            let read_count = relation_opening_read_counts
                .entry(column_ordinal)
                .or_default();
            *read_count = read_count.checked_add(1).ok_or(
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ),
            )?;
        }
        let mut replay_columns = requested_source_columns.clone();
        replay_columns.extend(reversed_columns.iter().copied());
        replay_columns.extend(auxiliary_columns.iter().copied());
        if replay_columns.len() > crate::bgv::proof_suite::external_memory::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT {
            return Err(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ));
        }

        let replay_requirements = relation_column_replay_requirements(variant)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        let source_coefficient_position_counts =
            persisted_pre_challenge_column_coefficient_position_counts(variant)
                .map_err(CommonProofGenerationInitializationError::Prover)?;
        if source_coefficient_position_counts.len() != requested_source_columns.len()
            || source_coefficient_position_counts
                .keys()
                .any(|column_ordinal| !requested_source_columns.contains(column_ordinal))
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let protection = match construction_plan.proof_privacy_mode {
            ProofPrivacyMode::PublicOnly => ProofExternalMemoryProtection::PublicIntegrity,
            ProofPrivacyMode::SecretBearing => {
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption
            }
        };
        let maximum_chunk_byte_length =
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
        let mut object_plans = Vec::with_capacity(replay_columns.len());
        let mut relation_polynomial_plans = BTreeMap::new();
        let mut maximum_total_written_byte_length = 0_u64;
        let mut maximum_total_read_byte_length = 0_u64;
        let mut maximum_transaction_count = 1_u64;
        for (object_index, column_ordinal) in replay_columns.into_iter().enumerate() {
            let descriptor = variant
                .ordered_columns()
                .get(usize::try_from(column_ordinal).map_err(|_| {
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?)
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?;
            let coefficient_position_count = source_coefficient_position_counts
                .get(&column_ordinal)
                .copied()
                .unwrap_or_else(|| descriptor.source_degree_bound_exclusive());
            let coefficient_count = usize::try_from(coefficient_position_count).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?;
            let object =
                ProofExternalMemoryObject::new(u32::try_from(object_index).map_err(|_| {
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::CountOverflow,
                    )
                })?);
            let polynomial_plan = CommonProofReplayPolynomialPlan::new(
                object,
                descriptor.value_type(),
                coefficient_count,
            )
            .map_err(CommonProofGenerationInitializationError::Prover)?;
            let issued_step = if auxiliary_columns.contains(&column_ordinal) {
                AUXILIARY_REPLAY_ISSUED_STEP
            } else {
                SOURCE_REPLAY_ISSUED_STEP
            };
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object,
                protection,
                polynomial_plan.exact_byte_length(),
                issued_step,
                issued_step,
                issued_step,
            ));
            let replay_requirement = replay_requirements
                .get(&column_ordinal)
                .copied()
                .unwrap_or_default();
            let phase_replay_count = phase_replay_counts
                .get(&column_ordinal)
                .copied()
                .unwrap_or_default();
            let aggregate_replay_count = u64::from(phase_columns.contains(&column_ordinal));
            let opening_replay_count = relation_opening_read_counts
                .get(&column_ordinal)
                .copied()
                .unwrap_or_default();
            let bound_replay_count = if requested_source_columns.contains(&column_ordinal)
                && !phase_columns.contains(&column_ordinal)
            {
                2
            } else {
                0
            };
            let total_read_count = replay_requirement
                .pre_challenge_read_count()
                .checked_add(replay_requirement.auxiliary_synthesis_read_count())
                .and_then(|count| count.checked_add(phase_replay_count))
                .and_then(|count| count.checked_add(aggregate_replay_count))
                .and_then(|count| count.checked_add(opening_replay_count))
                .and_then(|count| count.checked_add(bound_replay_count))
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let exact_byte_length = polynomial_plan.exact_byte_length();
            let chunk_count = exact_byte_length.div_ceil(maximum_chunk_byte_length);
            maximum_total_written_byte_length = maximum_total_written_byte_length
                .checked_add(exact_byte_length)
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            maximum_total_read_byte_length = maximum_total_read_byte_length
                .checked_add(exact_byte_length.checked_mul(total_read_count).ok_or(
                    CommonProofGenerationInitializationError::StoragePlan(
                        ProofExternalMemoryError::ResourceLimitExceeded,
                    ),
                )?)
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            maximum_transaction_count = maximum_transaction_count
                .checked_add(2)
                .and_then(|count| count.checked_add(chunk_count))
                .and_then(|count| {
                    chunk_count
                        .checked_mul(total_read_count)
                        .and_then(|reads| count.checked_add(reads))
                })
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            if relation_polynomial_plans
                .insert(column_ordinal, polynomial_plan)
                .is_some()
            {
                return Err(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
        }
        let quotient_phase_stripe_count = u64::try_from(
            construction_plan
                .quotient_phase
                .geometry
                .encoded_column_count
                .div_ceil(MAXIMUM_PHASE_COMMITMENT_STRIPE_COLUMN_COUNT),
        )
        .map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let mut opened_source_row_use_counts =
            BTreeMap::<RowCodeWhirOpenedPolynomialSource, u64>::new();
        let mut opened_source_points =
            BTreeMap::<RowCodeWhirOpenedPolynomialSource, BTreeSet<u32>>::new();
        for row in &construction_plan.quotient_phase.rows {
            let row_sources = row
                .logical_polynomial_chunks
                .iter()
                .flatten()
                .map(|chunk| chunk.source)
                .collect::<BTreeSet<_>>();
            for source in row_sources {
                let row_use_count = opened_source_row_use_counts.entry(source).or_default();
                *row_use_count = row_use_count.checked_add(1).ok_or(
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::CountOverflow,
                    ),
                )?;
                opened_source_points
                    .entry(source)
                    .or_default()
                    .extend(row.opening_point_ordinals.iter().copied());
            }
        }
        let quotient_component_sources =
            (0..construction_plan.quotient_phase.quotient_component_count)
                .map(
                    |component_ordinal| RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                        component_ordinal,
                    },
                )
                .collect::<BTreeSet<_>>();
        let opening_batch_mask_sources = match construction_plan
            .quotient_phase
            .opening_batch_mask_degree_bound_exclusive
        {
            Some(_) => BTreeSet::from([RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
                mask_ordinal: 0,
            }]),
            None => BTreeSet::new(),
        };
        let used_opened_sources = opened_source_row_use_counts
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected_opened_sources = quotient_component_sources
            .union(&opening_batch_mask_sources)
            .copied()
            .collect::<BTreeSet<_>>();
        if used_opened_sources != expected_opened_sources {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }

        let mut opened_polynomial_plans = BTreeMap::new();
        for source in expected_opened_sources {
            let degree_bound_exclusive = match source {
                RowCodeWhirOpenedPolynomialSource::QuotientComponent { .. } => {
                    construction_plan
                        .quotient_phase
                        .quotient_component_degree_bound_exclusive
                }
                RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { .. } => construction_plan
                    .quotient_phase
                    .opening_batch_mask_degree_bound_exclusive
                    .ok_or(CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?,
            };
            let coefficient_count = usize::try_from(degree_bound_exclusive).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?;
            let object = ProofExternalMemoryObject::new(
                u32::try_from(object_plans.len()).map_err(|_| {
                    CommonProofGenerationInitializationError::StoragePlan(
                        ProofExternalMemoryError::ResourceLimitExceeded,
                    )
                })?,
            );
            let polynomial_plan = CommonProofReplayPolynomialPlan::new(
                object,
                RelationColumnValueType::ChallengeExtension,
                coefficient_count,
            )
            .map_err(CommonProofGenerationInitializationError::Prover)?;
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object,
                protection,
                polynomial_plan.exact_byte_length(),
                AUXILIARY_REPLAY_ISSUED_STEP,
                AUXILIARY_REPLAY_ISSUED_STEP,
                AUXILIARY_REPLAY_ISSUED_STEP,
            ));
            let phase_read_count = opened_source_row_use_counts
                .get(&source)
                .copied()
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?
                .checked_mul(quotient_phase_stripe_count)
                .and_then(|count| count.checked_mul(2))
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let opening_read_count = u64::try_from(
                opened_source_points.get(&source).map_or(0, BTreeSet::len),
            )
            .map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?;
            let total_read_count = phase_read_count
                .checked_add(opening_read_count)
                .and_then(|count| count.checked_add(1))
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            let exact_byte_length = polynomial_plan.exact_byte_length();
            let chunk_count = exact_byte_length.div_ceil(maximum_chunk_byte_length);
            maximum_total_written_byte_length = maximum_total_written_byte_length
                .checked_add(exact_byte_length)
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            maximum_total_read_byte_length = maximum_total_read_byte_length
                .checked_add(exact_byte_length.checked_mul(total_read_count).ok_or(
                    CommonProofGenerationInitializationError::StoragePlan(
                        ProofExternalMemoryError::ResourceLimitExceeded,
                    ),
                )?)
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            maximum_transaction_count = maximum_transaction_count
                .checked_add(2)
                .and_then(|count| count.checked_add(chunk_count))
                .and_then(|count| {
                    chunk_count
                        .checked_mul(total_read_count)
                        .and_then(|reads| count.checked_add(reads))
                })
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            if opened_polynomial_plans
                .insert(source, polynomial_plan)
                .is_some()
            {
                return Err(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
        }

        let relation_object_plan_count = relation_polynomial_plans.len();
        let evaluation_domain = construction_plan
            .quotient_computation_evaluation_domain(relation_context)
            .map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidQuotient,
                )
            })?;
        let quotient_transform_storage_plan: super::RowCodeWhirQuotientTransformStoragePlan =
            plan_row_code_whir_quotient_transform_storage(
                variant,
                evaluation_domain,
                &relation_polynomial_plans,
                u32::try_from(object_plans.len()).map_err(|_| {
                    CommonProofGenerationInitializationError::StoragePlan(
                        ProofExternalMemoryError::ResourceLimitExceeded,
                    )
                })?,
                FIRST_QUOTIENT_TRANSFORM_STEP,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                protection,
            )
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        if quotient_transform_storage_plan
            .constraint_evaluation_steps
            .len()
            != variant.constraint_count()
            || quotient_transform_storage_plan.peak_active_output_count == 0
            || quotient_transform_storage_plan.next_executor_step <= FIRST_QUOTIENT_TRANSFORM_STEP
            || quotient_transform_storage_plan
                .source_last_use_steps
                .values()
                .any(|last_use_step| {
                    *last_use_step < FIRST_QUOTIENT_TRANSFORM_STEP
                        || *last_use_step >= quotient_transform_storage_plan.next_executor_step
                })
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidQuotient,
            ));
        }
        let quotient_materialization_step = quotient_transform_storage_plan.next_executor_step;
        let retained_start_step = quotient_materialization_step.checked_add(1).ok_or(
            CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ),
        )?;
        for (object_plan_index, object_plan) in object_plans.iter_mut().enumerate() {
            let (issued_step, seal_step) = if object_plan_index < relation_object_plan_count {
                (object_plan.issued_step(), object_plan.seal_step())
            } else {
                (quotient_materialization_step, quotient_materialization_step)
            };
            *object_plan = ProofExternalMemoryObjectPlan::new(
                object_plan.object(),
                object_plan.protection(),
                object_plan.exact_byte_length(),
                issued_step,
                seal_step,
                retained_start_step,
            );
        }
        maximum_total_written_byte_length = maximum_total_written_byte_length
            .checked_add(quotient_transform_storage_plan.total_written_byte_length)
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        maximum_total_read_byte_length = maximum_total_read_byte_length
            .checked_add(quotient_transform_storage_plan.total_read_byte_length)
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        maximum_transaction_count = maximum_transaction_count
            .checked_add(quotient_transform_storage_plan.transaction_count_excluding_deletions)
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        object_plans.extend_from_slice(&quotient_transform_storage_plan.object_plans);
        let pre_retained_deletion_transaction_count = u64::try_from(
            object_plans
                .iter()
                .map(|object_plan| object_plan.last_use_step())
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .map_err(|_| {
            CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            )
        })?;
        maximum_transaction_count = maximum_transaction_count
            .checked_add(pre_retained_deletion_transaction_count)
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;

        let retained_oracle_plan =
            super::retained_oracle::PlainWhirRetainedEncodedOraclePlan::for_construction_plan(
                construction_plan,
                quotient_transform_storage_plan.next_free_object_ordinal,
            )
            .map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidInput,
                )
            })?;
        let (retained_external_memory_plan, retained_oracles) = retained_oracle_plan.into_parts();
        if retained_external_memory_plan.maximum_chunk_byte_length()
            != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || retained_external_memory_plan.maximum_transaction_payload_byte_length()
                != maximum_chunk_byte_length
        {
            return Err(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::InvalidPlan,
            ));
        }
        let step_count = retained_start_step
            .checked_add(retained_external_memory_plan.step_count())
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        maximum_total_written_byte_length = maximum_total_written_byte_length
            .checked_add(retained_external_memory_plan.maximum_total_written_byte_length())
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        maximum_total_read_byte_length = maximum_total_read_byte_length
            .checked_add(retained_external_memory_plan.maximum_total_read_byte_length())
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        maximum_transaction_count = maximum_transaction_count
            .checked_add(retained_external_memory_plan.maximum_transaction_count())
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        for object_plan in retained_external_memory_plan.into_object_plans() {
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object_plan.object(),
                object_plan.protection(),
                object_plan.exact_byte_length(),
                object_plan
                    .issued_step()
                    .checked_add(retained_start_step)
                    .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                        ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?,
                object_plan
                    .seal_step()
                    .checked_add(retained_start_step)
                    .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                        ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?,
                object_plan
                    .last_use_step()
                    .checked_add(retained_start_step)
                    .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                        ProofExternalMemoryError::ResourceLimitExceeded,
                    ))?,
            ));
        }
        let (maximum_stored_byte_length, peak_live_object_count, largest_deletion_count) =
            exact_external_memory_liveness(&object_plans)?;
        let maximum_transaction_operation_count =
            peak_live_object_count.max(largest_deletion_count);
        let external_memory_plan = ProofExternalMemoryPlan::new(
            step_count,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            maximum_chunk_byte_length,
            maximum_transaction_operation_count,
            maximum_stored_byte_length,
            maximum_total_written_byte_length,
            maximum_total_read_byte_length,
            maximum_transaction_count,
            object_plans,
        )
        .map_err(CommonProofGenerationInitializationError::StoragePlan)?;
        Ok(Self {
            external_memory_plan,
            relation_polynomial_plans,
            opened_polynomial_plans,
            quotient_transform_plans: quotient_transform_storage_plan.transform_plans,
            retained_oracles,
        })
    }
}

fn checked_same_secret_source_manifest(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_plan_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    reversed_column_bindings: &[(u32, u32)],
) -> Result<SameSecretAuthenticatedSourceManifest, CommonProofGenerationInitializationError> {
    let map_error = |_: SameSecretAuthenticatedSourceManifestError| {
        CommonProofGenerationInitializationError::Prover(CommonProofProverError::InvalidColumn)
    };
    let manifest = SameSecretAuthenticatedSourceManifest::derive(
        construction_plan,
        relation_plan_variant,
        relation_context,
    )
    .map_err(map_error)?;
    manifest
        .validate_against(construction_plan, relation_plan_variant, relation_context)
        .map_err(map_error)?;
    if manifest.construction_identity()
        != construction_plan.canonical_identity_hash().map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::InvalidInput)
        })?
    {
        return Err(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::InvalidInput,
        ));
    }

    let expected_source_count =
        u64::try_from(construction_plan.requested_source_column_ordinals.len()).map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
        })?;
    let expected_reversed_column_count =
        u64::try_from(reversed_column_bindings.len()).map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
        })?;
    let raw_source_coefficient_position_counts =
        authenticated_pre_challenge_source_coefficient_position_counts(relation_plan_variant)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
    let persisted_source_coefficient_position_counts =
        persisted_pre_challenge_column_coefficient_position_counts(relation_plan_variant)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
    if [
        &raw_source_coefficient_position_counts,
        &persisted_source_coefficient_position_counts,
    ]
    .into_iter()
    .any(|coefficient_position_counts| {
        coefficient_position_counts.len()
            != construction_plan.requested_source_column_ordinals.len()
            || coefficient_position_counts
                .keys()
                .copied()
                .ne(construction_plan
                    .requested_source_column_ordinals
                    .iter()
                    .copied())
    }) {
        return Err(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }
    let expected_raw_source_coefficient_position_count = raw_source_coefficient_position_counts
        .values()
        .try_fold(0_u64, |total, count| {
            total
                .checked_add(*count)
                .ok_or(CommonProofProverError::CountOverflow)
        })
        .map_err(CommonProofGenerationInitializationError::Prover)?;
    let expected_persisted_source_coefficient_position_count =
        persisted_source_coefficient_position_counts
            .values()
            .try_fold(0_u64, |total, count| {
                total
                    .checked_add(*count)
                    .ok_or(CommonProofProverError::CountOverflow)
            })
            .map_err(CommonProofGenerationInitializationError::Prover)?;
    let expected_stored_column_count = expected_source_count
        .checked_add(expected_reversed_column_count)
        .ok_or(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;

    let input_bound_trees = construction_plan
        .bound_trees
        .iter()
        .filter(|tree| tree.root_use == BoundTreeRootUse::Input)
        .collect::<Vec<_>>();
    let expected_input_bound_tree_count = u64::try_from(input_bound_trees.len()).map_err(|_| {
        CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
    })?;
    let expected_logical_salt_count = input_bound_trees
        .iter()
        .try_fold(0_u64, |total, tree| {
            total
                .checked_add(
                    u64::try_from(tree.leaf_count)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::CountOverflow)
        })
        .map_err(CommonProofGenerationInitializationError::Prover)?;
    let expected_encoded_salt_count = input_bound_trees
        .iter()
        .try_fold(0_u64, |total, tree| {
            total
                .checked_add(
                    u64::try_from(tree.query_count)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::CountOverflow)
        })
        .map_err(CommonProofGenerationInitializationError::Prover)?;
    let salt_byte_length = u64::try_from(
        crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH,
    )
    .map_err(|_| {
        CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
    })?;
    if manifest
        .authenticated_source_polynomial_count()
        .map_err(map_error)?
        != expected_source_count
        || manifest
            .raw_authenticated_source_coefficient_position_count()
            .map_err(map_error)?
            != expected_raw_source_coefficient_position_count
        || manifest
            .persisted_pre_challenge_source_coefficient_position_count()
            .map_err(map_error)?
            != expected_persisted_source_coefficient_position_count
        || manifest
            .deterministic_reversed_column_count()
            .map_err(map_error)?
            != expected_reversed_column_count
        || manifest
            .stored_pre_challenge_column_count()
            .map_err(map_error)?
            != expected_stored_column_count
        || manifest
            .bound_material_input_tree_count()
            .map_err(map_error)?
            != expected_input_bound_tree_count
        || manifest
            .logical_bound_material_leaf_salt_count()
            .map_err(map_error)?
            != expected_logical_salt_count
        || manifest
            .logical_bound_material_leaf_salt_byte_length()
            .map_err(map_error)?
            != expected_logical_salt_count
                .checked_mul(salt_byte_length)
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?
        || manifest
            .encoded_queried_bound_material_leaf_salt_count()
            .map_err(map_error)?
            != expected_encoded_salt_count
        || manifest
            .encoded_queried_bound_material_leaf_salt_byte_length()
            .map_err(map_error)?
            != expected_encoded_salt_count
                .checked_mul(salt_byte_length)
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?
    {
        return Err(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::InvalidColumn,
        ));
    }

    let mut validation = manifest.begin_validation();
    for column_ordinal in &construction_plan.requested_source_column_ordinals {
        let descriptor = relation_plan_variant
            .ordered_columns()
            .get(usize::try_from(*column_ordinal).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                )
            })?)
            .ok_or(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ))?;
        validation
            .validate_next_authenticated_source(*column_ordinal, descriptor)
            .map_err(map_error)?;
    }
    for (source_column_ordinal, reversed_column_ordinal) in reversed_column_bindings {
        validation
            .validate_next_reversed_column(*source_column_ordinal, *reversed_column_ordinal)
            .map_err(map_error)?;
    }
    validation.finish().map_err(map_error)?;

    for tree in input_bound_trees {
        let leaf_count = u64::try_from(tree.leaf_count).map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
        })?;
        let query_count = u64::try_from(tree.query_count).map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
        })?;
        if leaf_count == 0 || query_count == 0 {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidTree,
            ));
        }
        for leaf_index in [0, leaf_count - 1] {
            manifest
                .validate_bound_material_leaf_salt_coordinate(
                    tree.relation_tree_ordinal,
                    tree.expected_root_source_ordinal,
                    tree.root_use,
                    leaf_index,
                )
                .map_err(map_error)?;
        }
        for query_ordinal in [0, query_count - 1] {
            manifest
                .validate_encoded_bound_material_query_coordinate(
                    tree.relation_tree_ordinal,
                    query_ordinal,
                    query_ordinal % leaf_count,
                )
                .map_err(map_error)?;
        }
    }
    Ok(manifest)
}

fn bind_same_secret_source_replay_identity(
    source_replay_identity_digest: [u8; HASH_BYTE_LENGTH],
    source_manifest_catalog_hash: [u8; HASH_BYTE_LENGTH],
) -> [u8; HASH_BYTE_LENGTH] {
    let mut hasher = StreamingHash512::new(SAME_SECRET_SOURCE_REPLAY_IDENTITY_HASH_DOMAIN, 2);
    hasher.absorb_part(&source_replay_identity_digest);
    hasher.absorb_part(&source_manifest_catalog_hash);
    hasher.finalize()
}

pub(in crate::bgv::proof_suite) fn planned_row_code_whir_external_memory_requirement(
    construction_plan: &RowCodeWhirConstructionPlan,
    variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<CommonProofExternalMemoryRequirement, CommonProofGenerationInitializationError> {
    let reversed_column_bindings = relation_reversed_column_bindings(variant)
        .map_err(CommonProofGenerationInitializationError::Prover)?;
    let storage_plan = RowCodeWhirGenerationStoragePlan::new(
        construction_plan,
        variant,
        relation_context,
        &reversed_column_bindings,
    )?;
    CommonProofExternalMemoryRequirement::from_external_memory_plan(
        &storage_plan.external_memory_plan,
    )
    .map_err(CommonProofGenerationInitializationError::StoragePlan)
}

fn exact_external_memory_liveness(
    object_plans: &[ProofExternalMemoryObjectPlan],
) -> Result<(u64, u32, u32), CommonProofGenerationInitializationError> {
    let mut events = Vec::with_capacity(object_plans.len().saturating_mul(2));
    let mut deletion_counts = BTreeMap::<u32, u32>::new();
    for object_plan in object_plans {
        events.push((
            object_plan.issued_step(),
            true,
            object_plan.exact_byte_length(),
        ));
        events.push((
            object_plan.last_use_step().checked_add(1).ok_or(
                CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?,
            false,
            object_plan.exact_byte_length(),
        ));
        let deletion_count = deletion_counts
            .entry(object_plan.last_use_step())
            .or_default();
        *deletion_count = deletion_count.checked_add(1).ok_or(
            CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ),
        )?;
    }
    events.sort_unstable_by_key(|(step, is_issuance, _)| (*step, *is_issuance));
    let mut live_byte_length = 0_u64;
    let mut live_object_count = 0_u32;
    let mut peak_byte_length = 0_u64;
    let mut peak_object_count = 0_u32;
    for (_, is_issuance, exact_byte_length) in events {
        if is_issuance {
            live_byte_length = live_byte_length.checked_add(exact_byte_length).ok_or(
                CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
            live_object_count = live_object_count.checked_add(1).ok_or(
                CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
            peak_byte_length = peak_byte_length.max(live_byte_length);
            peak_object_count = peak_object_count.max(live_object_count);
        } else {
            live_byte_length = live_byte_length.checked_sub(exact_byte_length).ok_or(
                CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::InvalidPlan,
                ),
            )?;
            live_object_count = live_object_count.checked_sub(1).ok_or(
                CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::InvalidPlan,
                ),
            )?;
        }
    }
    if live_byte_length != 0 || live_object_count != 0 || peak_byte_length == 0 {
        return Err(CommonProofGenerationInitializationError::StoragePlan(
            ProofExternalMemoryError::InvalidPlan,
        ));
    }
    Ok((
        peak_byte_length,
        peak_object_count,
        deletion_counts.values().copied().max().unwrap_or(0),
    ))
}

/// The checked relation-plan state shared by every family as it migrates to
/// the sole row-code/WHIR construction. Same-secret is merely the first
/// production caller; the state itself contains no family selector.
pub(in crate::bgv::proof_suite) struct RowCodeWhirGenerationStateMachine {
    construction_plan: RowCodeWhirConstructionPlan,
    construction_plan_identity_hash: [u8; HASH_BYTE_LENGTH],
    transcript_prefix_authority_binding: ExactSameSecretTranscriptPrefixAuthorityBinding,
    authenticated_transcript_prefix: Option<crate::bgv::proof_suite::CommonProofTranscript>,
    row_code_whir_transcript: Option<RowCodeWhirTranscript>,
    canonical_header_bytes: Vec<u8>,
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    relation_trees: Vec<RelationProofTreeInput>,
    source_polynomial_provider: Option<Box<dyn CommonProofSourcePolynomialProvider>>,
    source_request_context: CommonProofSourcePolynomialRequestContext,
    same_secret_source_manifest: SameSecretAuthenticatedSourceManifest,
    source_cursor: Option<CommonProofPreChallengeSourceCursor>,
    source_replay_identity_digest: Option<[u8; HASH_BYTE_LENGTH]>,
    reversed_column_bindings: Vec<(u32, u32)>,
    next_reversed_column_binding_index: usize,
    loaded_source_polynomial_count: usize,
    pending_authenticated_source_read: Option<CommonProofAuthenticatedSourceReadRequest>,
    pending_replay_polynomial: Option<PendingRowCodeWhirReplayPolynomial>,
    relation_replay_polynomial_plans: BTreeMap<u32, CommonProofReplayPolynomialPlan>,
    opened_replay_polynomial_plans:
        BTreeMap<RowCodeWhirOpenedPolynomialSource, CommonProofReplayPolynomialPlan>,
    quotient_transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, ExternalStockhamTransformPlan>,
    retained_oracles: Option<[super::retained_oracle::RetainedPlainWhirEncodedOracle; 5]>,
    external_memory_executor: Option<ProofExternalMemoryExecutor>,
    external_memory_requirement: CommonProofExternalMemoryRequirement,
    active_replay_polynomial_writer: Option<CommonProofReplayPolynomialWriter>,
    active_replay_polynomial_reader: Option<ActiveRowCodeWhirReplayPolynomialReader>,
    row_pad_seeds: Option<Zeroizing<[[u8; 32]; 3]>>,
    phase_commitment_builder: Option<StripedColumnCommitmentBuilder>,
    active_phase_commitment: Option<RowCodeWhirPhase>,
    active_phase_materialization_purpose: Option<RowCodeWhirPhaseMaterializationPurpose>,
    active_phase_authenticated_columns: Option<Vec<AuthenticatedColumn>>,
    active_phase_polynomial_reader: Option<CommonProofReplayPolynomialReader>,
    active_phase_polynomial_binding: Option<RowCodeWhirPhasePolynomialBinding>,
    phase_row_witness: Vec<Goldilocks>,
    next_phase_row_index: usize,
    next_phase_logical_chunk_index: usize,
    phase_roots: [Option<ColumnDigest>; 3],
    phase_authenticated_columns: [Option<Vec<AuthenticatedColumn>>; 3],
    phase_opening_frontiers: [Option<Vec<ColumnDigest>>; 3],
    exact_same_secret_phase_openings: Option<ExactSameSecretPhaseOpenings>,
    opening_points: Vec<ProofChallengeExtensionElement>,
    out_of_domain_evaluations: Vec<ProofChallengeExtensionElement>,
    opening_batch_mask_chunk_evaluations: Vec<ProofChallengeExtensionElement>,
    application_challenges: Vec<RelationApplicationChallengeAssignment>,
    auxiliary_materialization: Option<RowCodeWhirAuxiliaryRelationMaterialization>,
    quotient_materialization: Option<RowCodeWhirQuotientMaterialization>,
    active_quotient_transform: Option<ActiveRowCodeWhirQuotientTransform>,
    exact_same_secret_aggregate_source: Option<ExactSameSecretAggregateSource>,
    active_aggregate_source_read: Option<ActiveExactSameSecretAggregateSourceRead>,
    exact_same_secret_aggregate_metadata: Option<ExactSameSecretAggregateMetadata>,
    exact_same_secret_opening_schedule: Option<ExactSameSecretOpeningSchedule>,
    aggregate_challenger: Option<ExtensionFieldChallenger>,
    aggregate_commitment_generation: Option<StreamingPlainAggregateRetainedCommitmentGeneration>,
    aggregate_commitment: Option<PlainAggregateCommitment>,
    aggregate_proof_generation: Option<StreamingPlainAggregateRetainedProofGeneration>,
    aggregate_opening_proof: Option<PlainAggregateProof>,
    terminal_external_memory_usage: Option<ProofExternalMemoryUsage>,
    phase: RowCodeWhirGenerationPhase,
}

impl RowCodeWhirGenerationStateMachine {
    pub(in crate::bgv::proof_suite) fn new(
        input: CommonProofGenerationInput<'_>,
        construction_plan: &RowCodeWhirConstructionPlan,
        transcript_prefix_authority_binding: ExactSameSecretTranscriptPrefixAuthorityBinding,
    ) -> Result<Self, CommonProofGenerationInitializationError> {
        if input.maximum_prefetched_query_byte_length == 0
            || input.maximum_external_memory_chunk_byte_length
                != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || input.maximum_proof_transport_chunk_byte_length
                != MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        let validated_relation_plan = ValidatedRelationPlanArtifact::from_compiled_plan(
            input.relation_plan,
            input.relation_context,
        )
        .map_err(CommonProofGenerationInitializationError::Profile)?;
        let relation_plan_variant = input
            .relation_plan
            .select_variant(input.schedule_position, input.top_count)
            .map_err(CommonProofGenerationInitializationError::Relation)?
            .clone();
        let relation_plan_hash = input
            .relation_plan
            .canonical_hash()
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        let relation_plan_variant_hash = relation_plan_variant
            .canonical_hash()
            .map_err(CommonProofGenerationInitializationError::Relation)?;
        let construction_plan_identity_hash =
            construction_plan.canonical_identity_hash().map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidInput,
                )
            })?;
        if construction_plan.application_statement_schema_identifier
            != validated_relation_plan.application_statement_schema_identifier()
            || construction_plan.schedule_position != input.schedule_position
            || construction_plan.top_count != input.top_count
            || construction_plan.relation_plan_hash() != relation_plan_hash
            || construction_plan.relation_plan_variant_hash() != relation_plan_variant_hash
            || construction_plan.trace_domain_size != relation_plan_variant.trace_domain_size()
            || construction_plan.evaluation_domain_size
                != relation_plan_variant.evaluation_domain_size()
            || construction_plan_identity_hash == [0_u8; HASH_BYTE_LENGTH]
            || transcript_prefix_authority_binding
                .fiat_shamir_binding()
                .protocol_version()
                != input.protocol_version
            || transcript_prefix_authority_binding
                .fiat_shamir_binding()
                .suite_identifier()
                != input.suite_identifier
            || transcript_prefix_authority_binding
                .fiat_shamir_binding()
                .application_statement_schema_identifier()
                != validated_relation_plan.application_statement_schema_identifier()
            || transcript_prefix_authority_binding
                .fiat_shamir_binding()
                .relation_plan_hash()
                != relation_plan_hash
            || transcript_prefix_authority_binding
                .fiat_shamir_binding()
                .relation_plan_variant_hash()
                != relation_plan_variant_hash
            || transcript_prefix_authority_binding
                .fiat_shamir_binding()
                .construction_plan_identity_hash()
                != construction_plan_identity_hash
            || transcript_prefix_authority_binding
                .fiat_shamir_binding()
                .oracle_equation_catalog_hash()
                != construction_plan
                    .oracle_equation_catalog_hash()
                    .map_err(|_| {
                        CommonProofGenerationInitializationError::Prover(
                            CommonProofProverError::InvalidInput,
                        )
                    })?
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        validate_generation_relation_trees(&relation_plan_variant, &input.relation_trees)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        let canonical_header_bytes =
            canonical_proof_object_header_bytes(input.canonical_application_statement_bytes)
                .map_err(CommonProofGenerationInitializationError::Prover)?;
        let source_request_context = CommonProofSourcePolynomialRequestContext::new(
            input.protocol_version,
            input.suite_identifier,
            validated_relation_plan.application_statement_schema_identifier(),
            verified_application_statement_hash(
                input.protocol_version,
                input.suite_identifier,
                validated_relation_plan.application_statement_schema_identifier(),
                input.canonical_application_statement_bytes,
            ),
            relation_plan_hash,
            relation_plan_variant_hash,
            input.schedule_position,
            input.top_count,
        );
        require_bounded_source_provider(input.source_polynomial_provider.as_ref())?;
        let source_cursor = CommonProofPreChallengeSourceCursor::new(
            &relation_plan_variant,
            source_request_context,
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        let reversed_column_bindings = source_cursor.reversed_column_bindings().to_vec();
        let same_secret_source_manifest = checked_same_secret_source_manifest(
            construction_plan,
            &relation_plan_variant,
            input.relation_context,
            &reversed_column_bindings,
        )?;
        let generation_storage_plan = RowCodeWhirGenerationStoragePlan::new(
            construction_plan,
            &relation_plan_variant,
            input.relation_context,
            &reversed_column_bindings,
        )?;
        let external_memory_requirement =
            CommonProofExternalMemoryRequirement::from_external_memory_plan(
                &generation_storage_plan.external_memory_plan,
            )
            .map_err(CommonProofGenerationInitializationError::StoragePlan)?;
        let external_memory_executor =
            ProofExternalMemoryExecutor::new(generation_storage_plan.external_memory_plan);
        Ok(Self {
            construction_plan: construction_plan.clone(),
            construction_plan_identity_hash,
            transcript_prefix_authority_binding,
            authenticated_transcript_prefix: None,
            row_code_whir_transcript: None,
            canonical_header_bytes,
            relation_plan_variant,
            relation_context: input.relation_context.clone(),
            relation_trees: input.relation_trees,
            source_polynomial_provider: Some(input.source_polynomial_provider),
            source_request_context,
            same_secret_source_manifest,
            source_cursor: Some(source_cursor),
            source_replay_identity_digest: None,
            reversed_column_bindings,
            next_reversed_column_binding_index: 0,
            loaded_source_polynomial_count: 0,
            pending_authenticated_source_read: None,
            pending_replay_polynomial: None,
            relation_replay_polynomial_plans: generation_storage_plan.relation_polynomial_plans,
            opened_replay_polynomial_plans: generation_storage_plan.opened_polynomial_plans,
            quotient_transform_plans: generation_storage_plan.quotient_transform_plans,
            retained_oracles: Some(generation_storage_plan.retained_oracles),
            external_memory_executor: Some(external_memory_executor),
            external_memory_requirement,
            active_replay_polynomial_writer: None,
            active_replay_polynomial_reader: None,
            row_pad_seeds: None,
            phase_commitment_builder: None,
            active_phase_commitment: None,
            active_phase_materialization_purpose: None,
            active_phase_authenticated_columns: None,
            active_phase_polynomial_reader: None,
            active_phase_polynomial_binding: None,
            phase_row_witness: Vec::new(),
            next_phase_row_index: 0,
            next_phase_logical_chunk_index: 0,
            phase_roots: [None; 3],
            phase_authenticated_columns: std::array::from_fn(|_| None),
            phase_opening_frontiers: std::array::from_fn(|_| None),
            exact_same_secret_phase_openings: None,
            opening_points: Vec::new(),
            out_of_domain_evaluations: Vec::new(),
            opening_batch_mask_chunk_evaluations: Vec::new(),
            application_challenges: Vec::new(),
            auxiliary_materialization: None,
            quotient_materialization: None,
            active_quotient_transform: None,
            exact_same_secret_aggregate_source: None,
            active_aggregate_source_read: None,
            exact_same_secret_aggregate_metadata: None,
            exact_same_secret_opening_schedule: None,
            aggregate_challenger: None,
            aggregate_commitment_generation: None,
            aggregate_commitment: None,
            aggregate_proof_generation: None,
            aggregate_opening_proof: None,
            terminal_external_memory_usage: None,
            phase: RowCodeWhirGenerationPhase::PreparingAuthenticatedSources,
        })
    }

    pub(crate) const fn stage(&self) -> CommonProofGenerationStage {
        match self.phase {
            RowCodeWhirGenerationPhase::PreparingAuthenticatedSources
            | RowCodeWhirGenerationPhase::LoadingAuthenticatedSources => {
                CommonProofGenerationStage::PreparingInputs
            }
            RowCodeWhirGenerationPhase::ConstructingReversedColumns
            | RowCodeWhirGenerationPhase::SamplingRowPads
            | RowCodeWhirGenerationPhase::CommittingBasePhase => {
                CommonProofGenerationStage::MaterializingBaseTrees
            }
            RowCodeWhirGenerationPhase::AwaitingAuthenticatedTranscriptPrefix
            | RowCodeWhirGenerationPhase::DerivingAuxiliaryColumns => {
                CommonProofGenerationStage::DerivingApplicationColumns
            }
            RowCodeWhirGenerationPhase::CommittingAuxiliaryPhase => {
                CommonProofGenerationStage::MaterializingAuxiliaryTrees
            }
            RowCodeWhirGenerationPhase::PreparingQuotient
            | RowCodeWhirGenerationPhase::ConstructingQuotient => {
                CommonProofGenerationStage::ConstructingQuotient
            }
            RowCodeWhirGenerationPhase::DerivingOpeningBatchMask
            | RowCodeWhirGenerationPhase::CommittingQuotientPhase
            | RowCodeWhirGenerationPhase::CompletingQuotientPhaseStorage => {
                CommonProofGenerationStage::MaterializingQuotientTrees
            }
            RowCodeWhirGenerationPhase::DerivingOutOfDomainOpenings
            | RowCodeWhirGenerationPhase::EvaluatingOutOfDomainOpenings { .. }
            | RowCodeWhirGenerationPhase::PreparingAggregateSource => {
                CommonProofGenerationStage::DerivingOutOfDomainOpenings
            }
            RowCodeWhirGenerationPhase::MaterializingAggregateSource
            | RowCodeWhirGenerationPhase::CommittingAggregate
            | RowCodeWhirGenerationPhase::PreparingAggregateOpenings
            | RowCodeWhirGenerationPhase::MaterializingBasePhaseOpenings
            | RowCodeWhirGenerationPhase::MaterializingAuxiliaryPhaseOpenings
            | RowCodeWhirGenerationPhase::MaterializingQuotientPhaseOpenings
            | RowCodeWhirGenerationPhase::CompletingAggregateCommitment => {
                CommonProofGenerationStage::MaterializingOpeningMask
            }
            RowCodeWhirGenerationPhase::GeneratingAggregateWhirProof => {
                CommonProofGenerationStage::ReducingCommittedOracles
            }
            RowCodeWhirGenerationPhase::AwaitingExactProofAssembly => {
                CommonProofGenerationStage::Finalizing
            }
            RowCodeWhirGenerationPhase::Cancelled => CommonProofGenerationStage::Cancelled,
        }
    }

    pub(crate) const fn pending_authenticated_source_read(
        &self,
    ) -> Option<CommonProofAuthenticatedSourceReadRequest> {
        self.pending_authenticated_source_read
    }

    pub(crate) fn authenticated_transcript_prefix_request(
        &self,
    ) -> Result<ExactSameSecretAuthenticatedTranscriptPrefixRequest, CommonProofProverError> {
        if self.phase != RowCodeWhirGenerationPhase::AwaitingAuthenticatedTranscriptPrefix
            || self.authenticated_transcript_prefix.is_some()
            || self.phase_commitment_builder.is_some()
            || self.active_phase_commitment.is_some()
            || self.active_phase_materialization_purpose.is_some()
            || self.active_phase_authenticated_columns.is_some()
            || self.active_phase_polynomial_reader.is_some()
            || self.active_phase_polynomial_binding.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        ExactSameSecretAuthenticatedTranscriptPrefixRequest::new(
            self.transcript_prefix_authority_binding.clone(),
            self.source_replay_identity_digest
                .ok_or(CommonProofProverError::InvalidInput)?,
            column_digest_bytes(
                self.phase_root(RowCodeWhirPhase::Base)
                    .ok_or(CommonProofProverError::InvalidInput)?,
            ),
        )
    }

    pub(crate) fn supply_authenticated_transcript_prefix(
        &mut self,
        prepared: PreparedExactSameSecretTranscriptPrefix,
    ) -> Result<(), CommonProofProverError> {
        let expected_request = self.authenticated_transcript_prefix_request()?;
        if prepared.binding().request() != &expected_request
            || prepared.binding().verified_prerequisite_binding() == [0_u8; HASH_BYTE_LENGTH]
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        self.authenticated_transcript_prefix = Some(prepared.into_transcript());
        Ok(())
    }

    pub(crate) fn supply_authenticated_source_range(
        &mut self,
        request: CommonProofAuthenticatedSourceReadRequest,
        authenticated_bytes: Zeroizing<Box<[u8]>>,
    ) -> Result<(), CommonProofProverError> {
        if self.phase != RowCodeWhirGenerationPhase::LoadingAuthenticatedSources
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

    pub(crate) const fn external_memory_requirement(&self) -> CommonProofExternalMemoryRequirement {
        self.external_memory_requirement
    }

    pub(crate) fn external_memory_usage(&self) -> Option<ProofExternalMemoryUsage> {
        self.external_memory_executor
            .as_ref()
            .map(ProofExternalMemoryExecutor::usage)
            .or(self.terminal_external_memory_usage)
    }

    pub(crate) const fn terminal_external_memory_usage(&self) -> Option<ProofExternalMemoryUsage> {
        self.terminal_external_memory_usage
    }

    pub(crate) const fn canonical_output_byte_length(&self) -> Option<usize> {
        None
    }

    /// Reinstalls the authenticated canonical transcript cursor at the exact
    /// durable boundary reached by deterministic prefix replay. The live
    /// transcript must first reproduce the same bytes, and the restored
    /// transcript must re-emit them exactly before generation can continue.
    pub(crate) fn restore_authenticated_checkpoint_transcript_cursor(
        &mut self,
        canonical_cursor_bytes: &[u8],
        expected_cursor_digest: Option<[u8; HASH_BYTE_LENGTH]>,
    ) -> Result<(), CommonProofProverError> {
        let Some(live_transcript) = self.row_code_whir_transcript.as_ref() else {
            return if canonical_cursor_bytes.is_empty() && expected_cursor_digest.is_none() {
                Ok(())
            } else {
                Err(CommonProofProverError::InvalidInput)
            };
        };
        let Some(expected_cursor_digest) = expected_cursor_digest else {
            return Err(CommonProofProverError::InvalidInput);
        };
        if canonical_cursor_bytes.is_empty()
            || canonical_cursor_bytes.len()
                > MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let authenticated_cursor =
            RowCodeWhirTranscriptCheckpointCursor::from_canonical_bytes(canonical_cursor_bytes)
                .map_err(|_| CommonProofProverError::InvalidInput)?;
        let live_cursor = live_transcript
            .checkpoint_cursor(&self.construction_plan)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        if authenticated_cursor.digest() != expected_cursor_digest
            || live_cursor.digest() != authenticated_cursor.digest()
            || live_cursor.canonical_bytes() != authenticated_cursor.canonical_bytes()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let restored_transcript = RowCodeWhirTranscript::restore_checkpoint_cursor(
            &self.construction_plan,
            &authenticated_cursor,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let restored_cursor = restored_transcript
            .checkpoint_cursor(&self.construction_plan)
            .map_err(|_| CommonProofProverError::InvalidInput)?;
        if restored_cursor.digest() != authenticated_cursor.digest()
            || restored_cursor.canonical_bytes() != authenticated_cursor.canonical_bytes()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        self.row_code_whir_transcript = Some(restored_transcript);
        Ok(())
    }

    pub(crate) fn checkpoint_boundary(&self) -> Option<CommonProofGenerationCheckpointBoundary> {
        if self.pending_authenticated_source_read.is_some()
            || self.pending_replay_polynomial.is_some()
            || self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_aggregate_source_read.is_some()
            || self.active_phase_polynomial_reader.is_some()
            || self.active_phase_polynomial_binding.is_some()
            || self.phase_commitment_builder.is_some()
            || self.active_phase_commitment.is_some()
            || self.active_phase_materialization_purpose.is_some()
            || self.active_phase_authenticated_columns.is_some()
            || self.phase_authenticated_columns.iter().any(Option::is_some)
            || self.phase_opening_frontiers.iter().any(Option::is_some)
            || self.exact_same_secret_phase_openings.is_some()
            || self.auxiliary_materialization.is_some()
            || self.quotient_materialization.is_some()
            || self.active_quotient_transform.is_some()
            || self.exact_same_secret_aggregate_source.is_some()
            || self.aggregate_commitment_generation.is_some()
            || self.aggregate_proof_generation.is_some()
        {
            return None;
        }
        let expected_boundary = match self.phase {
            RowCodeWhirGenerationPhase::SamplingRowPads => {
                RowCodeWhirCheckpointBoundary::SourcesAndConstruction
            }
            RowCodeWhirGenerationPhase::AwaitingAuthenticatedTranscriptPrefix => {
                RowCodeWhirCheckpointBoundary::PhaseCommitment {
                    phase: RowCodeWhirPhase::Base,
                }
            }
            RowCodeWhirGenerationPhase::PreparingQuotient => {
                RowCodeWhirCheckpointBoundary::PhaseCommitment {
                    phase: RowCodeWhirPhase::Auxiliary,
                }
            }
            RowCodeWhirGenerationPhase::DerivingOutOfDomainOpenings => {
                RowCodeWhirCheckpointBoundary::PhaseCommitment {
                    phase: RowCodeWhirPhase::Quotient,
                }
            }
            RowCodeWhirGenerationPhase::PreparingAggregateSource => {
                RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask
            }
            _ => return None,
        };
        let checkpoint = self
            .construction_plan
            .checkpoints()
            .iter()
            .find(|checkpoint| checkpoint.boundary == expected_boundary)?;
        let source_replay_identity_digest = self.source_replay_identity_digest?;
        if source_replay_identity_digest == [0_u8; HASH_BYTE_LENGTH] {
            return None;
        }
        let mut position = [0_u8; 16];
        position[0] = 1;
        position[1] = match expected_boundary {
            RowCodeWhirCheckpointBoundary::SourcesAndConstruction => 1,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Base,
            } => 2,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Auxiliary,
            } => 3,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Quotient,
            } => 4,
            RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => 5,
            _ => return None,
        };
        position[4..8].copy_from_slice(&checkpoint.checkpoint_ordinal.to_le_bytes());
        position[8..12]
            .copy_from_slice(&checkpoint.next_transcript_operation_ordinal.to_le_bytes());
        position[12..16].copy_from_slice(&checkpoint.next_proof_section_ordinal.to_le_bytes());
        let required_phase_root_count = match expected_boundary {
            RowCodeWhirCheckpointBoundary::SourcesAndConstruction => 0,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Base,
            } => 1,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Auxiliary,
            } => 2,
            RowCodeWhirCheckpointBoundary::PhaseCommitment {
                phase: RowCodeWhirPhase::Quotient,
            } => 3,
            RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => 3,
            _ => return None,
        };
        if self.phase_roots[..required_phase_root_count]
            .iter()
            .any(Option::is_none)
            || self.phase_roots[required_phase_root_count..]
                .iter()
                .any(Option::is_some)
        {
            return None;
        }
        let includes_relation_evaluations =
            expected_boundary == RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask;
        if includes_relation_evaluations {
            if self.authenticated_transcript_prefix.is_some()
                || self.row_code_whir_transcript.is_none()
                || self.out_of_domain_evaluations.len()
                    != self.relation_plan_variant.ordered_opening_claims().len()
                || self.opening_batch_mask_chunk_evaluations.len()
                    != self.opening_batch_mask_chunk_evaluation_count().ok()?
            {
                return None;
            }
        } else if self.row_code_whir_transcript.is_some()
            || !self.opening_points.is_empty()
            || !self.out_of_domain_evaluations.is_empty()
            || !self.opening_batch_mask_chunk_evaluations.is_empty()
        {
            return None;
        }
        let transcript_cursor = if includes_relation_evaluations {
            let cursor = self
                .row_code_whir_transcript
                .as_ref()?
                .checkpoint_cursor(&self.construction_plan)
                .ok()?;
            if cursor.canonical_bytes().is_empty()
                || cursor.canonical_bytes().len()
                    > MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
            {
                return None;
            }
            Some(cursor)
        } else {
            None
        };
        let mut hasher = StreamingHash512::new(
            ROW_CODE_WHIR_CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN,
            if includes_relation_evaluations { 13 } else { 9 },
        );
        hasher.absorb_part(&position);
        hasher.absorb_part(&self.construction_plan_identity_hash);
        hasher.absorb_part(&source_replay_identity_digest);
        for root in self.phase_roots {
            hasher.absorb_part(&[u8::from(root.is_some())]);
            hasher.absorb_part(
                &root
                    .map(column_digest_bytes)
                    .unwrap_or([0_u8; HASH_BYTE_LENGTH]),
            );
        }
        if includes_relation_evaluations {
            absorb_extension_values_checkpoint_part(&mut hasher, &self.out_of_domain_evaluations)?;
            absorb_extension_values_checkpoint_part(
                &mut hasher,
                &self.opening_batch_mask_chunk_evaluations,
            )?;
            let transcript_cursor = transcript_cursor.as_ref()?;
            hasher.absorb_part(transcript_cursor.canonical_bytes());
            hasher.absorb_part(&transcript_cursor.digest());
        }
        let boundary = CommonProofGenerationCheckpointBoundary::new(
            checkpoint.checkpoint_ordinal,
            position,
            hasher.finalize(),
        );
        Some(match transcript_cursor {
            Some(cursor) => {
                let cursor_digest = cursor.digest();
                boundary
                    .with_canonical_transcript_cursor(cursor.into_canonical_bytes(), cursor_digest)
            }
            None => boundary,
        })
    }

    pub(crate) fn poll<Storage, Coins, Sink>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
        _sink: &mut Sink,
    ) -> Result<
        CommonProofGenerationPoll,
        CommonProofGenerationError<Storage::Error, Coins::Error, Sink::Error>,
    >
    where
        Storage: ProofExternalMemory,
        Coins: crate::bgv::proof_suite::CommonProofPrivateCoinSource,
        Sink: CommonProofByteSink,
    {
        if let Some(writer) = self.active_replay_polynomial_writer.as_mut() {
            let polynomial = &self
                .pending_replay_polynomial
                .as_ref()
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?
                .polynomial;
            let complete = writer
                .advance(
                    self.external_memory_executor.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    storage,
                    CommonProofReplayPolynomialRef::Source(polynomial),
                )
                .map_err(CommonProofGenerationError::Storage)?;
            if complete {
                self.active_replay_polynomial_writer = None;
                let pending = self.pending_replay_polynomial.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )?;
                let target_matches_continuation = match (pending.target, pending.continuation) {
                    (
                        RowCodeWhirReplayPolynomialTarget::RelationColumn(_),
                        RowCodeWhirReplayWriteContinuation::AuthenticatedSource
                        | RowCodeWhirReplayWriteContinuation::ReversedColumn
                        | RowCodeWhirReplayWriteContinuation::AuxiliaryColumn,
                    ) => true,
                    (
                        RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(
                            RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                                component_ordinal: target_ordinal,
                            },
                        ),
                        RowCodeWhirReplayWriteContinuation::QuotientComponent { component_ordinal },
                    ) => target_ordinal == component_ordinal,
                    (
                        RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(
                            RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { mask_ordinal: 0 },
                        ),
                        RowCodeWhirReplayWriteContinuation::OpeningBatchMask,
                    ) => true,
                    _ => false,
                };
                if !target_matches_continuation {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ));
                }
                match pending.continuation {
                    RowCodeWhirReplayWriteContinuation::AuthenticatedSource => {
                        self.loaded_source_polynomial_count = self
                            .loaded_source_polynomial_count
                            .checked_add(1)
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?;
                    }
                    RowCodeWhirReplayWriteContinuation::ReversedColumn
                    | RowCodeWhirReplayWriteContinuation::AuxiliaryColumn
                    | RowCodeWhirReplayWriteContinuation::OpeningBatchMask => {}
                    RowCodeWhirReplayWriteContinuation::QuotientComponent { component_ordinal } => {
                        self.quotient_materialization
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ))?
                            .acknowledge_persisted_component(component_ordinal)
                            .map_err(CommonProofGenerationError::Prover)?;
                    }
                }
            }
            return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
        }

        if let Some(active) = self.active_aggregate_source_read.as_mut() {
            let complete = {
                let ActiveExactSameSecretAggregateSourceRead {
                    reader,
                    source_range,
                    ..
                } = active;
                reader
                    .advance(
                        self.external_memory_executor.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        storage,
                        source_range.destination(),
                    )
                    .map_err(CommonProofGenerationError::Storage)?
            };
            if complete {
                let completed = self.active_aggregate_source_read.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                self.exact_same_secret_aggregate_source
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .supply_source_range(
                        completed.action,
                        completed.source_range.into_source_polynomial(),
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
            }
            return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
        }

        if let Some(active) = self.active_replay_polynomial_reader.as_mut() {
            let complete = active
                .reader
                .advance(
                    self.external_memory_executor.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    storage,
                )
                .map_err(CommonProofGenerationError::Storage)?;
            if complete {
                let active = self.active_replay_polynomial_reader.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                let source = active
                    .reader
                    .finish()
                    .map_err(CommonProofGenerationError::Prover)?;
                match active.continuation {
                    RowCodeWhirReplayReadContinuation::ReversedColumn {
                        source_column_ordinal,
                        reversed_column_ordinal,
                    } => {
                        let reversed = construct_reversed_relation_column(
                            &self.relation_plan_variant,
                            source_column_ordinal,
                            reversed_column_ordinal,
                            source,
                            coins,
                            self.relation_context
                                .maximum_fiat_shamir_candidate_draws_per_output,
                        )
                        .map_err(map_private_coin_error)?;
                        self.begin_replay_polynomial_write(
                            RowCodeWhirReplayPolynomialTarget::RelationColumn(
                                reversed_column_ordinal,
                            ),
                            reversed,
                            RowCodeWhirReplayWriteContinuation::ReversedColumn,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                        self.next_reversed_column_binding_index = self
                            .next_reversed_column_binding_index
                            .checked_add(1)
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?;
                    }
                    RowCodeWhirReplayReadContinuation::AuxiliaryColumn { column_ordinal } => {
                        self.auxiliary_materialization
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ))?
                            .supply_input(column_ordinal, source)
                            .map_err(CommonProofGenerationError::Prover)?;
                    }
                    RowCodeWhirReplayReadContinuation::OutOfDomainOpening { claim_index } => {
                        let claim = self
                            .relation_plan_variant
                            .ordered_opening_claims()
                            .get(claim_index)
                            .copied()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidOpening,
                            ))?;
                        let opening_point = self
                            .opening_points
                            .get(usize::try_from(claim.opening_point_ordinal()).map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?)
                            .copied()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidOpening,
                            ))?;
                        let evaluation = evaluate_opening_claim(&claim, &source, opening_point)
                            .map_err(CommonProofGenerationError::Prover)?;
                        if claim.source_class() == RelationOpeningSourceClass::BatchMask {
                            if !self.opening_batch_mask_chunk_evaluations.is_empty() {
                                return Err(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidOpening,
                                ));
                            }
                            self.opening_batch_mask_chunk_evaluations =
                                evaluate_opening_batch_mask_chunks(
                                    &source,
                                    opening_point,
                                    self.opening_batch_mask_chunk_evaluation_count()
                                        .map_err(CommonProofGenerationError::Prover)?,
                                )
                                .map_err(CommonProofGenerationError::Prover)?;
                        }
                        self.out_of_domain_evaluations.push(evaluation);
                        self.phase = RowCodeWhirGenerationPhase::EvaluatingOutOfDomainOpenings {
                            next_claim_index: claim_index.checked_add(1).ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                ),
                            )?,
                        };
                    }
                }
            }
            return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
        }

        if let Some(active) = self.active_quotient_transform.as_mut() {
            let progress = active
                .transform
                .advance(
                    self.external_memory_executor.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    storage,
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
            return match progress {
                ExternalStockhamTransformProgress::ArithmeticStepCompleted => {
                    Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                }
                ExternalStockhamTransformProgress::StorageTransactionCompleted
                | ExternalStockhamTransformProgress::PassCommitted(_) => {
                    Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                }
                ExternalStockhamTransformProgress::Complete(vector) => {
                    let active = self.active_quotient_transform.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient),
                    )?;
                    self.quotient_materialization
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .supply_transformed_column(active.transform_key, vector)
                        .map_err(CommonProofGenerationError::Prover)?;
                    Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                }
            };
        }

        if let Some(reader) = self.active_phase_polynomial_reader.as_mut() {
            let complete = reader
                .advance(
                    self.external_memory_executor.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    storage,
                )
                .map_err(CommonProofGenerationError::Storage)?;
            if complete {
                let reader = self.active_phase_polynomial_reader.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                let polynomial = reader
                    .finish()
                    .map_err(CommonProofGenerationError::Prover)?;
                match self.active_phase_polynomial_binding.take().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn),
                )? {
                    RowCodeWhirPhasePolynomialBinding::Relation {
                        logical_block_index,
                        column_ordinal,
                        coefficient_chunk_ordinal,
                    } => self
                        .copy_relation_phase_polynomial_chunk(
                            logical_block_index,
                            column_ordinal,
                            coefficient_chunk_ordinal,
                            polynomial,
                        )
                        .map_err(CommonProofGenerationError::Prover)?,
                    RowCodeWhirPhasePolynomialBinding::Opened {
                        logical_block_index,
                        source,
                        coefficient_chunk_ordinal,
                    } => self
                        .copy_quotient_phase_polynomial_chunk(
                            logical_block_index,
                            source,
                            coefficient_chunk_ordinal,
                            polynomial,
                        )
                        .map_err(CommonProofGenerationError::Prover)?,
                }
                self.next_phase_logical_chunk_index =
                    self.next_phase_logical_chunk_index.checked_add(1).ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow),
                    )?;
            }
            return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
        }

        match self.phase {
            RowCodeWhirGenerationPhase::PreparingAuthenticatedSources => {
                self.validate_retained_construction_input()
                    .map_err(CommonProofGenerationError::Prover)?;
                self.phase = RowCodeWhirGenerationPhase::LoadingAuthenticatedSources;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::LoadingAuthenticatedSources => {
                if self.pending_authenticated_source_read.is_some()
                    || self.pending_replay_polynomial.is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                let next_source = self
                    .source_cursor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .next_source(
                        &self.relation_plan_variant,
                        self.source_request_context,
                        self.source_polynomial_provider.as_deref_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        coins,
                        self.relation_context
                            .maximum_fiat_shamir_candidate_draws_per_output,
                    )
                    .map_err(map_private_coin_error)?;
                match next_source {
                    CommonProofPreChallengeSourcePoll::AuthenticatedSourceReadRequired => {
                        self.pending_authenticated_source_read = Some(
                            self.source_polynomial_provider
                                .as_deref()
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ))?
                                .pending_authenticated_source_read_request()
                                .map_err(CommonProofGenerationError::Prover)?
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidColumn,
                                ))?,
                        );
                    }
                    CommonProofPreChallengeSourcePoll::Ready {
                        column_ordinal,
                        polynomial,
                    } => {
                        let descriptor = self
                            .relation_plan_variant
                            .ordered_columns()
                            .get(usize::try_from(column_ordinal).map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })?)
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ))?;
                        self.same_secret_source_manifest
                            .validate_authenticated_source_at(
                                self.loaded_source_polynomial_count,
                                column_ordinal,
                                descriptor,
                            )
                            .map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidColumn,
                                )
                            })?;
                        self.begin_replay_polynomial_write(
                            RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal),
                            polynomial,
                            RowCodeWhirReplayWriteContinuation::AuthenticatedSource,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                    }
                    CommonProofPreChallengeSourcePoll::Complete => {
                        if self.loaded_source_polynomial_count
                            != self
                                .construction_plan
                                .requested_source_column_ordinals
                                .len()
                            || u64::try_from(self.loaded_source_polynomial_count).map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                )
                            })? != self
                                .same_secret_source_manifest
                                .authenticated_source_polynomial_count()
                                .map_err(|_| {
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::InvalidColumn,
                                    )
                                })?
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ));
                        }
                        let source_replay_identity_digest = self
                            .source_cursor
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
                        self.source_replay_identity_digest =
                            Some(bind_same_secret_source_replay_identity(
                                source_replay_identity_digest,
                                self.same_secret_source_manifest.catalog_hash(),
                            ));
                        self.source_cursor = None;
                        self.phase = RowCodeWhirGenerationPhase::ConstructingReversedColumns;
                    }
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::ConstructingReversedColumns => {
                self.validate_retained_construction_input()
                    .map_err(CommonProofGenerationError::Prover)?;
                let Some((source_column_ordinal, reversed_column_ordinal)) = self
                    .reversed_column_bindings
                    .get(self.next_reversed_column_binding_index)
                    .copied()
                else {
                    if u64::try_from(self.next_reversed_column_binding_index).map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                    })? != self
                        .same_secret_source_manifest
                        .deterministic_reversed_column_count()
                        .map_err(|_| {
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            )
                        })?
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    self.external_memory_executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .complete_step(storage)
                        .map_err(CommonProofGenerationError::Storage)?;
                    self.phase = RowCodeWhirGenerationPhase::SamplingRowPads;
                    return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
                };
                self.same_secret_source_manifest
                    .validate_reversed_column_at(
                        self.next_reversed_column_binding_index,
                        source_column_ordinal,
                        reversed_column_ordinal,
                    )
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidColumn)
                    })?;
                let plan = self
                    .relation_replay_polynomial_plans
                    .get(&source_column_ordinal)
                    .copied()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?;
                self.active_replay_polynomial_reader =
                    Some(ActiveRowCodeWhirReplayPolynomialReader {
                        reader: CommonProofReplayPolynomialReader::new(plan)
                            .map_err(CommonProofGenerationError::Prover)?,
                        continuation: RowCodeWhirReplayReadContinuation::ReversedColumn {
                            source_column_ordinal,
                            reversed_column_ordinal,
                        },
                    });
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::SamplingRowPads => {
                self.validate_retained_construction_input()
                    .map_err(CommonProofGenerationError::Prover)?;
                if self
                    .external_memory_executor
                    .as_ref()
                    .is_none_or(|executor| executor.current_step() != AUXILIARY_REPLAY_ISSUED_STEP)
                    || self
                        .source_replay_identity_digest
                        .is_none_or(|digest| digest == [0_u8; 64])
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                let row_pad_seeds = match self.construction_plan.proof_privacy_mode {
                    ProofPrivacyMode::SecretBearing => {
                        let mut row_pad_seed_bytes =
                            Zeroizing::new([0_u8; ROW_PAD_SEED_BYTE_LENGTH]);
                        coins
                            .fill_raw_bytes(
                                CommonProofPrivateCoinCoordinate::proof_salt(),
                                row_pad_seed_bytes.as_mut(),
                            )
                            .map_err(CommonProofGenerationError::CoinSource)?;
                        Some(Zeroizing::new([
                            row_pad_seed_bytes[0..32].try_into().map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                )
                            })?,
                            row_pad_seed_bytes[32..64].try_into().map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                )
                            })?,
                            row_pad_seed_bytes[64..96].try_into().map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                )
                            })?,
                        ]))
                    }
                    ProofPrivacyMode::PublicOnly => None,
                };
                self.prepare_relation_phase_materialization(
                    RowCodeWhirPhase::Base,
                    RowCodeWhirPhaseMaterializationPurpose::InitialCommitment,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                self.row_pad_seeds = row_pad_seeds;
                self.phase = RowCodeWhirGenerationPhase::CommittingBasePhase;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::CommittingBasePhase => self
                .poll_relation_phase_commitment(RowCodeWhirPhase::Base)
                .map_err(CommonProofGenerationError::Prover),
            RowCodeWhirGenerationPhase::AwaitingAuthenticatedTranscriptPrefix => {
                if self.phase_root(RowCodeWhirPhase::Base).is_none()
                    || self.phase_commitment_builder.is_some()
                    || self.active_phase_commitment.is_some()
                    || self.active_phase_polynomial_reader.is_some()
                    || self.active_phase_polynomial_binding.is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                if self.authenticated_transcript_prefix.is_none() {
                    Ok(CommonProofGenerationPoll::AuthenticatedTranscriptPrefixRequired)
                } else {
                    let application_challenges = sample_relation_application_challenges(
                        self.authenticated_transcript_prefix.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        self.construction_plan.relation_prefix_schedule(),
                    )
                    .map_err(CommonProofGenerationError::Transcript)?;
                    let auxiliary_materialization =
                        RowCodeWhirAuxiliaryRelationMaterialization::new(
                            &self.relation_plan_variant,
                            &self.relation_context,
                            &application_challenges,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                    self.application_challenges = application_challenges;
                    self.auxiliary_materialization = Some(auxiliary_materialization);
                    self.phase = RowCodeWhirGenerationPhase::DerivingAuxiliaryColumns;
                    Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                }
            }
            RowCodeWhirGenerationPhase::DerivingAuxiliaryColumns => {
                let action = self
                    .auxiliary_materialization
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .next_action(
                        &self.relation_plan_variant,
                        coins,
                        self.relation_context
                            .maximum_fiat_shamir_candidate_draws_per_output,
                    )
                    .map_err(map_private_coin_error)?;
                match action {
                    RowCodeWhirAuxiliaryRelationMaterializationAction::ReadColumn(
                        column_ordinal,
                    ) => {
                        let plan = self
                            .relation_replay_polynomial_plans
                            .get(&column_ordinal)
                            .copied()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ))?;
                        self.active_replay_polynomial_reader =
                            Some(ActiveRowCodeWhirReplayPolynomialReader {
                                reader: CommonProofReplayPolynomialReader::new(plan)
                                    .map_err(CommonProofGenerationError::Prover)?,
                                continuation: RowCodeWhirReplayReadContinuation::AuxiliaryColumn {
                                    column_ordinal,
                                },
                            });
                    }
                    RowCodeWhirAuxiliaryRelationMaterializationAction::PersistColumn {
                        column_ordinal,
                        polynomial,
                    } => {
                        self.begin_replay_polynomial_write(
                            RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal),
                            polynomial,
                            RowCodeWhirReplayWriteContinuation::AuxiliaryColumn,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                    }
                    RowCodeWhirAuxiliaryRelationMaterializationAction::Progressed => {}
                    RowCodeWhirAuxiliaryRelationMaterializationAction::Complete => {
                        self.auxiliary_materialization = None;
                        self.prepare_relation_phase_materialization(
                            RowCodeWhirPhase::Auxiliary,
                            RowCodeWhirPhaseMaterializationPurpose::InitialCommitment,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                        self.phase = RowCodeWhirGenerationPhase::CommittingAuxiliaryPhase;
                    }
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::CommittingAuxiliaryPhase => self
                .poll_relation_phase_commitment(RowCodeWhirPhase::Auxiliary)
                .map_err(CommonProofGenerationError::Prover),
            RowCodeWhirGenerationPhase::PreparingQuotient => {
                self.external_memory_executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .complete_step(storage)
                    .map_err(CommonProofGenerationError::Storage)?;
                let mut composition_challenges = Vec::new();
                composition_challenges
                    .try_reserve_exact(self.relation_plan_variant.constraint_count())
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                for constraint_index in 0..self.relation_plan_variant.constraint_count() {
                    composition_challenges.push(
                        self.authenticated_transcript_prefix
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?
                            .sample_composition_challenge(u32::try_from(constraint_index).map_err(
                                |_| {
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::CountOverflow,
                                    )
                                },
                            )?)
                            .map_err(CommonProofGenerationError::Transcript)?,
                    );
                }
                let evaluation_domain = self
                    .construction_plan
                    .quotient_computation_evaluation_domain(&self.relation_context)
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient)
                    })?;
                self.quotient_materialization = Some(
                    RowCodeWhirQuotientMaterialization::new(
                        &self.relation_plan_variant,
                        &self.relation_context,
                        evaluation_domain,
                        BTreeMap::new(),
                        core::mem::take(&mut self.application_challenges),
                        composition_challenges,
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                    )
                    .map_err(CommonProofGenerationError::Prover)?,
                );
                self.phase = RowCodeWhirGenerationPhase::ConstructingQuotient;
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            RowCodeWhirGenerationPhase::ConstructingQuotient => {
                let action = self
                    .quotient_materialization
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidQuotient,
                    ))?
                    .next_action(
                        &self.relation_plan_variant,
                        &self.relation_context,
                        coins,
                        self.relation_context
                            .maximum_fiat_shamir_candidate_draws_per_output,
                    )
                    .map_err(map_private_coin_error)?;
                match action {
                    RowCodeWhirQuotientMaterializationAction::Progressed => {
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    RowCodeWhirQuotientMaterializationAction::ConstraintCompleted => {
                        self.external_memory_executor
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?
                            .complete_step(storage)
                            .map_err(CommonProofGenerationError::Storage)?;
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    RowCodeWhirQuotientMaterializationAction::PersistQuotientComponent {
                        component_ordinal,
                        polynomial,
                    } => {
                        self.begin_replay_polynomial_write(
                            RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(
                                RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                                    component_ordinal,
                                },
                            ),
                            CommonProofSourcePolynomial::Extension(polynomial),
                            RowCodeWhirReplayWriteContinuation::QuotientComponent {
                                component_ordinal,
                            },
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    RowCodeWhirQuotientMaterializationAction::Complete => {
                        if !self.quotient_transform_plans.is_empty()
                            || self.active_quotient_transform.is_some()
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ));
                        }
                        self.quotient_materialization = None;
                        self.phase = RowCodeWhirGenerationPhase::DerivingOpeningBatchMask;
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    RowCodeWhirQuotientMaterializationAction::TransformColumn(transform_key) => {
                        let plan = self.quotient_transform_plans.remove(&transform_key).ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ),
                        )?;
                        self.active_quotient_transform = Some(ActiveRowCodeWhirQuotientTransform {
                            transform_key,
                            transform: ExternalStockhamTransform::new(plan)
                                .map_err(map_external_polynomial_plan_error)
                                .map_err(CommonProofGenerationError::StoragePlan)?,
                        });
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    RowCodeWhirQuotientMaterializationAction::ReadEvaluationRange(request) => {
                        let values = read_external_polynomial_extension_values(
                            self.external_memory_executor.as_mut().ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ),
                            )?,
                            storage,
                            request.vector(),
                            request.element_offset(),
                            request.element_count(),
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
                        })?;
                        self.quotient_materialization
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ))?
                            .supply_evaluation_values(request, values)
                            .map_err(CommonProofGenerationError::Prover)?;
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                }
            }
            RowCodeWhirGenerationPhase::DerivingOpeningBatchMask => {
                let opening_batch_mask = construct_opening_batch_mask(
                    &self.relation_plan_variant,
                    coins,
                    self.relation_context
                        .maximum_fiat_shamir_candidate_draws_per_output,
                )
                .map_err(map_private_coin_error)?;
                let expected_degree_bound = self
                    .construction_plan
                    .quotient_phase
                    .opening_batch_mask_degree_bound_exclusive
                    .map(|degree_bound| {
                        usize::try_from(degree_bound).map_err(|_| {
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            )
                        })
                    })
                    .transpose()?;
                if opening_batch_mask.as_ref().map(|mask| mask.len()) != expected_degree_bound {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidMask,
                    ));
                }
                if let Some(opening_batch_mask) = opening_batch_mask {
                    self.begin_replay_polynomial_write(
                        RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(
                            RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { mask_ordinal: 0 },
                        ),
                        CommonProofSourcePolynomial::Extension(opening_batch_mask),
                        RowCodeWhirReplayWriteContinuation::OpeningBatchMask,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                }
                self.phase = RowCodeWhirGenerationPhase::CommittingQuotientPhase;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::CommittingQuotientPhase => {
                if self.phase_commitment_builder.is_none() && self.active_phase_commitment.is_none()
                {
                    self.prepare_quotient_phase_materialization(
                        RowCodeWhirPhaseMaterializationPurpose::InitialCommitment,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                }
                self.poll_quotient_phase_commitment()
                    .map_err(CommonProofGenerationError::Prover)
            }
            RowCodeWhirGenerationPhase::CompletingQuotientPhaseStorage => {
                self.external_memory_executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .complete_step(storage)
                    .map_err(CommonProofGenerationError::Storage)?;
                self.phase = RowCodeWhirGenerationPhase::DerivingOutOfDomainOpenings;
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            RowCodeWhirGenerationPhase::DerivingOutOfDomainOpenings => {
                if !self.opening_points.is_empty()
                    || !self.out_of_domain_evaluations.is_empty()
                    || !self.opening_batch_mask_chunk_evaluations.is_empty()
                    || self.row_code_whir_transcript.is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                let point_count = self
                    .construction_plan
                    .relation_prefix_schedule()
                    .out_of_domain_point_count();
                let mut out_of_domain_points = Vec::new();
                out_of_domain_points
                    .try_reserve_exact(usize::from(point_count))
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                let relation_plan_variant = &self.relation_plan_variant;
                let relation_context = &self.relation_context;
                let transcript = self.authenticated_transcript_prefix.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                for point_ordinal in 0..point_count {
                    let mut relation_error = None;
                    let point = transcript.sample_out_of_domain_point(point_ordinal, |candidate| {
                        match relation_plan_variant.out_of_domain_point_candidate_is_forbidden(
                            relation_context,
                            point_ordinal,
                            candidate,
                            &out_of_domain_points,
                        ) {
                            Ok(is_forbidden) => is_forbidden,
                            Err(error) => {
                                relation_error = Some(error);
                                true
                            }
                        }
                    });
                    if let Some(error) = relation_error {
                        return Err(CommonProofGenerationError::Relation(error));
                    }
                    out_of_domain_points
                        .push(point.map_err(CommonProofGenerationError::Transcript)?);
                }
                self.opening_points = relation_plan_variant
                    .derive_opening_points(relation_context, &out_of_domain_points)
                    .map_err(CommonProofGenerationError::Relation)?;
                self.out_of_domain_evaluations
                    .try_reserve_exact(self.relation_plan_variant.ordered_opening_claims().len())
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(
                            CommonProofProverError::AllocationLimitExceeded,
                        )
                    })?;
                self.phase = RowCodeWhirGenerationPhase::EvaluatingOutOfDomainOpenings {
                    next_claim_index: 0,
                };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::EvaluatingOutOfDomainOpenings { next_claim_index } => {
                if self.out_of_domain_evaluations.len() != next_claim_index {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ));
                }
                let Some(claim) = self
                    .relation_plan_variant
                    .ordered_opening_claims()
                    .get(next_claim_index)
                    .copied()
                else {
                    if self.opening_batch_mask_chunk_evaluations.len()
                        != self
                            .opening_batch_mask_chunk_evaluation_count()
                            .map_err(CommonProofGenerationError::Prover)?
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidMask,
                        ));
                    }
                    self.authenticated_transcript_prefix
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .absorb_out_of_domain_evaluations(&self.out_of_domain_evaluations)
                        .map_err(CommonProofGenerationError::Transcript)?;
                    let row_code_whir_transcript = self
                        .authenticated_transcript_prefix
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .into_secret_bearing_row_code_whir_transcript(
                            &self.opening_batch_mask_chunk_evaluations,
                        )
                        .map_err(CommonProofGenerationError::Transcript)?;
                    if self
                        .row_code_whir_transcript
                        .replace(row_code_whir_transcript)
                        .is_some()
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ));
                    }
                    self.phase = RowCodeWhirGenerationPhase::PreparingAggregateSource;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                };
                let target = replay_polynomial_target_for_opening_claim(&claim)
                    .map_err(CommonProofGenerationError::Prover)?;
                let plan = match target {
                    RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal) => self
                        .relation_replay_polynomial_plans
                        .get(&column_ordinal)
                        .copied(),
                    RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(source) => {
                        self.opened_replay_polynomial_plans.get(&source).copied()
                    }
                }
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidOpening,
                ))?;
                if self.active_replay_polynomial_reader.is_some() {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                self.active_replay_polynomial_reader =
                    Some(ActiveRowCodeWhirReplayPolynomialReader {
                        reader: CommonProofReplayPolynomialReader::new(plan)
                            .map_err(CommonProofGenerationError::Prover)?,
                        continuation: RowCodeWhirReplayReadContinuation::OutOfDomainOpening {
                            claim_index: next_claim_index,
                        },
                    });
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::PreparingAggregateSource => {
                if self.exact_same_secret_aggregate_source.is_some()
                    || self.active_aggregate_source_read.is_some()
                    || self.exact_same_secret_aggregate_metadata.is_some()
                    || self.aggregate_challenger.is_some()
                    || self.aggregate_commitment_generation.is_some()
                    || self.aggregate_commitment.is_some()
                    || self.exact_same_secret_opening_schedule.is_some()
                    || self.aggregate_proof_generation.is_some()
                    || self.aggregate_opening_proof.is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                let aggregate_source = ExactSameSecretAggregateSource::new(
                    &self.construction_plan,
                    &self.relation_plan_variant,
                    &self.relation_context,
                    &self.same_secret_source_manifest,
                    self.source_request_context,
                    self.source_replay_identity_digest.ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    &self.transcript_prefix_authority_binding,
                    core::mem::take(&mut self.opening_points),
                    &self.out_of_domain_evaluations,
                    &self.opening_batch_mask_chunk_evaluations,
                    self.row_pad_seeds
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?,
                    self.row_code_whir_transcript.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                self.exact_same_secret_aggregate_source = Some(aggregate_source);
                self.phase = RowCodeWhirGenerationPhase::MaterializingAggregateSource;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::MaterializingAggregateSource => {
                let next_action = self
                    .exact_same_secret_aggregate_source
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .next_action();
                if let Some(action) = next_action {
                    self.begin_exact_same_secret_aggregate_source_read(action)
                        .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }

                let (witness, metadata, challenger, row_pad_seeds) = self
                    .exact_same_secret_aggregate_source
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .finish()
                    .and_then(|materialized| materialized.into_witness())
                    .map_err(CommonProofGenerationError::Prover)?;
                if metadata.binding_digest() == [0_u8; HASH_BYTE_LENGTH]
                    || metadata.construction_identity_hash() != self.construction_plan_identity_hash
                    || metadata.action_catalog_digest() == [0_u8; HASH_BYTE_LENGTH]
                    || metadata.action_count() == 0
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                let pcs = plain_aggregate_pcs_for_construction_plan(&self.construction_plan)
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
                    })?;
                let retained_oracles = self
                    .retained_oracles
                    .take()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .into_iter()
                    .collect();
                let commitment_generation =
                    StreamingPlainAggregateRetainedCommitmentGeneration::new(
                        &pcs,
                        witness,
                        retained_oracles,
                    )
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
                    })?;
                self.exact_same_secret_aggregate_metadata = Some(metadata);
                self.aggregate_challenger = Some(challenger);
                self.row_pad_seeds = Some(row_pad_seeds);
                self.aggregate_commitment_generation = Some(commitment_generation);
                self.phase = RowCodeWhirGenerationPhase::CommittingAggregate;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::CommittingAggregate => {
                let poll = self
                    .aggregate_commitment_generation
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .poll(
                        self.aggregate_challenger.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        self.external_memory_executor.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        storage,
                    )
                    .map_err(map_retained_whir_generation_error)?;
                match poll {
                    StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted => {
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted => {
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    StreamingPlainAggregateRetainedCommitmentPoll::CommitmentObserved(
                        commitment,
                    ) => {
                        if self.aggregate_commitment.replace(commitment).is_some() {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.phase = RowCodeWhirGenerationPhase::PreparingAggregateOpenings;
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingPlainAggregateRetainedCommitmentPoll::Complete(_) => Err(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    ),
                }
            }
            RowCodeWhirGenerationPhase::PreparingAggregateOpenings => {
                let metadata = self.exact_same_secret_aggregate_metadata.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                let schedule = metadata
                    .derive_opening_schedule_after_observed_commitment(
                        &self.construction_plan,
                        &self.relation_context,
                        self.aggregate_challenger.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                self.aggregate_commitment_generation
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .prepare_openings(
                        schedule.points(),
                        schedule.requested_columns_by_point(),
                        self.aggregate_challenger.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                    )
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
                    })?;
                self.exact_same_secret_opening_schedule = Some(schedule);
                self.prepare_relation_phase_materialization(
                    RowCodeWhirPhase::Base,
                    RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                )
                .map_err(CommonProofGenerationError::Prover)?;
                self.phase = RowCodeWhirGenerationPhase::MaterializingBasePhaseOpenings;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::MaterializingBasePhaseOpenings => self
                .poll_relation_phase_commitment(RowCodeWhirPhase::Base)
                .map_err(CommonProofGenerationError::Prover),
            RowCodeWhirGenerationPhase::MaterializingAuxiliaryPhaseOpenings => self
                .poll_relation_phase_commitment(RowCodeWhirPhase::Auxiliary)
                .map_err(CommonProofGenerationError::Prover),
            RowCodeWhirGenerationPhase::MaterializingQuotientPhaseOpenings => self
                .poll_quotient_phase_commitment()
                .map_err(CommonProofGenerationError::Prover),
            RowCodeWhirGenerationPhase::CompletingAggregateCommitment => {
                let poll = self
                    .aggregate_commitment_generation
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .poll(
                        self.aggregate_challenger.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        self.external_memory_executor.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        storage,
                    )
                    .map_err(map_retained_whir_generation_error)?;
                match poll {
                    StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted => {
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted => {
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    StreamingPlainAggregateRetainedCommitmentPoll::CommitmentObserved(_) => Err(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    ),
                    StreamingPlainAggregateRetainedCommitmentPoll::Complete(output) => {
                        let observed_commitment = self.aggregate_commitment.take().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?;
                        if output.commitment != observed_commitment {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.aggregate_commitment = Some(output.commitment.clone());
                        self.aggregate_commitment_generation = None;
                        self.aggregate_proof_generation = Some(
                            StreamingPlainAggregateRetainedProofGeneration::new(
                                output.commitment,
                                output.prover_data,
                            )
                            .map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                )
                            })?,
                        );
                        self.phase = RowCodeWhirGenerationPhase::GeneratingAggregateWhirProof;
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                }
            }
            RowCodeWhirGenerationPhase::GeneratingAggregateWhirProof => {
                let poll = self
                    .aggregate_proof_generation
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .poll(
                        self.aggregate_challenger.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        self.external_memory_executor.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        storage,
                    )
                    .map_err(map_retained_whir_generation_error)?;
                match poll {
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(_) => {
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(_) => {
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    StreamingPlainAggregateRetainedProofPoll::Complete(proof) => {
                        self.aggregate_proof_generation = None;
                        if self.aggregate_opening_proof.replace(proof).is_some() {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.phase = RowCodeWhirGenerationPhase::AwaitingExactProofAssembly;
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                }
            }
            RowCodeWhirGenerationPhase::AwaitingExactProofAssembly => {
                if self.exact_same_secret_aggregate_metadata.is_none()
                    || self.exact_same_secret_opening_schedule.is_none()
                    || self.aggregate_challenger.is_none()
                    || self.aggregate_opening_proof.is_none()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                Err(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidInput,
                ))
            }
            RowCodeWhirGenerationPhase::Cancelled => Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            )),
        }
    }

    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.phase == RowCodeWhirGenerationPhase::Cancelled {
            return Ok(());
        }
        if let Some(source_polynomial_provider) = self.source_polynomial_provider.as_deref_mut() {
            source_polynomial_provider.cancel_pending_authenticated_source_read();
        }
        if let Some(aggregate_source) = self.exact_same_secret_aggregate_source.take() {
            aggregate_source.cancel();
        }
        let retained_generator_cancelled_executor = if let Some(proof_generation) =
            self.aggregate_proof_generation.take()
        {
            proof_generation
                .cancel(
                    self.external_memory_executor
                        .as_mut()
                        .ok_or(ProofExternalMemoryError::InvalidLifecycle)?,
                    storage,
                )
                .map_err(map_retained_whir_cancel_error)?;
            true
        } else if let Some(commitment_generation) = self.aggregate_commitment_generation.take() {
            commitment_generation
                .cancel(
                    self.external_memory_executor
                        .as_mut()
                        .ok_or(ProofExternalMemoryError::InvalidLifecycle)?,
                    storage,
                )
                .map_err(map_retained_whir_cancel_error)?;
            true
        } else {
            false
        };
        if let Some(executor) = self.external_memory_executor.as_mut() {
            if !retained_generator_cancelled_executor {
                executor.cancel(storage)?;
            }
            self.terminal_external_memory_usage = Some(executor.usage());
        }
        self.external_memory_executor = None;
        self.source_polynomial_provider = None;
        self.source_cursor = None;
        self.pending_authenticated_source_read = None;
        self.pending_replay_polynomial = None;
        self.active_replay_polynomial_writer = None;
        self.active_replay_polynomial_reader = None;
        self.active_aggregate_source_read = None;
        self.row_pad_seeds = None;
        self.phase_commitment_builder = None;
        self.active_phase_commitment = None;
        self.active_phase_materialization_purpose = None;
        self.active_phase_authenticated_columns = None;
        self.active_phase_polynomial_reader = None;
        self.active_phase_polynomial_binding = None;
        self.authenticated_transcript_prefix = None;
        self.row_code_whir_transcript = None;
        self.opening_points.clear();
        self.out_of_domain_evaluations.clear();
        self.opening_batch_mask_chunk_evaluations.clear();
        self.application_challenges.clear();
        self.auxiliary_materialization = None;
        self.quotient_materialization = None;
        self.active_quotient_transform = None;
        self.exact_same_secret_aggregate_metadata = None;
        self.exact_same_secret_opening_schedule = None;
        self.aggregate_challenger = None;
        self.aggregate_commitment = None;
        self.aggregate_opening_proof = None;
        self.phase_row_witness.fill(Goldilocks::ZERO);
        self.phase_row_witness = Vec::new();
        self.phase_roots = [None; 3];
        self.phase_authenticated_columns = std::array::from_fn(|_| None);
        self.phase_opening_frontiers = std::array::from_fn(|_| None);
        self.exact_same_secret_phase_openings = None;
        self.relation_replay_polynomial_plans.clear();
        self.opened_replay_polynomial_plans.clear();
        self.quotient_transform_plans.clear();
        self.retained_oracles = None;
        self.canonical_header_bytes.clear();
        self.relation_trees.clear();
        self.phase = RowCodeWhirGenerationPhase::Cancelled;
        Ok(())
    }

    fn begin_exact_same_secret_aggregate_source_read(
        &mut self,
        action: ExactSameSecretAggregateSourceAction,
    ) -> Result<(), CommonProofProverError> {
        if self.phase != RowCodeWhirGenerationPhase::MaterializingAggregateSource
            || self.active_aggregate_source_read.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let plan = match action.target() {
            ExactSameSecretAggregateSourceTarget::RelationColumn { column_ordinal } => self
                .relation_replay_polynomial_plans
                .get(&column_ordinal)
                .copied(),
            ExactSameSecretAggregateSourceTarget::OpenedPolynomial { source } => {
                self.opened_replay_polynomial_plans.get(&source).copied()
            }
        }
        .ok_or(CommonProofProverError::InvalidColumn)?;
        let source_range_end = action
            .source_range_start()
            .checked_add(action.source_range_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if plan.value_type() != action.value_type()
            || plan.coefficient_count() != action.source_coefficient_count()
            || source_range_end > action.source_coefficient_count()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let reader = CommonProofReplayPolynomialRangeReader::new(
            plan,
            action.source_range_start()..source_range_end,
        )?;
        if reader.requested_coefficient_count() != action.source_range_length() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.active_aggregate_source_read = Some(ActiveExactSameSecretAggregateSourceRead {
            action,
            reader,
            source_range: ExactSameSecretAggregateSourceRange::new(action)?,
        });
        Ok(())
    }

    fn begin_replay_polynomial_write(
        &mut self,
        target: RowCodeWhirReplayPolynomialTarget,
        polynomial: CommonProofSourcePolynomial,
        continuation: RowCodeWhirReplayWriteContinuation,
    ) -> Result<(), CommonProofProverError> {
        if self.active_replay_polynomial_writer.is_some()
            || self.pending_replay_polynomial.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let plan = match target {
            RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal) => self
                .relation_replay_polynomial_plans
                .get(&column_ordinal)
                .copied(),
            RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(source) => {
                self.opened_replay_polynomial_plans.get(&source).copied()
            }
        }
        .ok_or(CommonProofProverError::InvalidColumn)?;
        let writer = CommonProofReplayPolynomialWriter::new(
            plan,
            CommonProofReplayPolynomialRef::Source(&polynomial),
        )?;
        self.pending_replay_polynomial = Some(PendingRowCodeWhirReplayPolynomial {
            target,
            polynomial,
            continuation,
        });
        self.active_replay_polynomial_writer = Some(writer);
        Ok(())
    }

    fn phase_root(&self, phase: RowCodeWhirPhase) -> Option<ColumnDigest> {
        self.phase_roots[row_code_whir_phase_index(phase)]
    }

    fn set_phase_root(
        &mut self,
        phase: RowCodeWhirPhase,
        root: ColumnDigest,
    ) -> Result<(), CommonProofProverError> {
        let slot = self
            .phase_roots
            .get_mut(row_code_whir_phase_index(phase))
            .ok_or(CommonProofProverError::InvalidTree)?;
        if slot.replace(root).is_some() {
            return Err(CommonProofProverError::InvalidTree);
        }
        Ok(())
    }

    fn validate_retained_construction_input(&self) -> Result<(), CommonProofProverError> {
        self.same_secret_source_manifest
            .validate_against(
                &self.construction_plan,
                &self.relation_plan_variant,
                &self.relation_context,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let expected_opened_sources = self
            .construction_plan
            .quotient_phase
            .rows
            .iter()
            .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
            .map(|chunk| chunk.source)
            .collect::<BTreeSet<_>>();
        let retained_oracles = self
            .retained_oracles
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?;
        if self.canonical_header_bytes.is_empty()
            || self
                .construction_plan
                .canonical_identity_hash()
                .map_err(|_| CommonProofProverError::InvalidInput)?
                != self.construction_plan_identity_hash
            || self.same_secret_source_manifest.construction_identity()
                != self.construction_plan_identity_hash
            || self.same_secret_source_manifest.catalog_hash() == [0_u8; HASH_BYTE_LENGTH]
            || self.construction_plan.relation_plan_variant_hash()
                != self.source_request_context.relation_plan_variant_hash()
            || self.construction_plan.relation_plan_hash()
                != self.source_request_context.relation_plan_hash()
            || self.construction_plan.trace_domain_size
                != self.relation_plan_variant.trace_domain_size()
            || self.construction_plan.evaluation_domain_size
                != self.relation_plan_variant.evaluation_domain_size()
            || self
                .opened_replay_polynomial_plans
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != expected_opened_sources
            || retained_oracles
                .iter()
                .any(|oracle| oracle.encoded_height == 0 || oracle.exact_byte_length == 0)
            || retained_oracles
                .windows(2)
                .any(|pair| pair[0].object >= pair[1].object)
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        validate_generation_relation_trees(&self.relation_plan_variant, &self.relation_trees)
    }

    fn opening_batch_mask_chunk_evaluation_count(&self) -> Result<usize, CommonProofProverError> {
        let mut matching_sections =
            self.construction_plan
                .proof_sections()
                .iter()
                .filter(|section| {
                    section.role == RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations
                });
        let section = matching_sections
            .next()
            .ok_or(CommonProofProverError::InvalidMask)?;
        if matching_sections.next().is_some() || section.item_count == 0 {
            return Err(CommonProofProverError::InvalidMask);
        }
        let degree_bound_exclusive = usize::try_from(
            self.construction_plan
                .quotient_phase
                .opening_batch_mask_degree_bound_exclusive
                .ok_or(CommonProofProverError::InvalidMask)?,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?;
        let coefficient_chunk_count =
            degree_bound_exclusive.div_ceil(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT);
        let matching_claim_count = self
            .relation_plan_variant
            .ordered_opening_claims()
            .iter()
            .filter(|claim| claim.source_class() == RelationOpeningSourceClass::BatchMask)
            .count();
        if coefficient_chunk_count != section.item_count || matching_claim_count != 1 {
            return Err(CommonProofProverError::InvalidMask);
        }
        Ok(section.item_count)
    }

    fn prepare_relation_phase_materialization(
        &mut self,
        phase_role: RowCodeWhirPhase,
        purpose: RowCodeWhirPhaseMaterializationPurpose,
    ) -> Result<(), CommonProofProverError> {
        if !matches!(
            phase_role,
            RowCodeWhirPhase::Base | RowCodeWhirPhase::Auxiliary
        ) || self.phase_commitment_builder.is_some()
            || self.active_phase_commitment.is_some()
            || self.active_phase_materialization_purpose.is_some()
            || self.active_phase_authenticated_columns.is_some()
            || self.active_phase_polynomial_reader.is_some()
            || self.active_phase_polynomial_binding.is_some()
            || !self.phase_row_witness.is_empty()
            || self.next_phase_row_index != 0
            || self.next_phase_logical_chunk_index != 0
            || match purpose {
                RowCodeWhirPhaseMaterializationPurpose::InitialCommitment => {
                    self.phase_root(phase_role).is_some()
                        || self.exact_same_secret_opening_schedule.is_some()
                }
                RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings => {
                    self.phase_root(phase_role).is_none()
                        || self.exact_same_secret_opening_schedule.is_none()
                        || self.phase_authenticated_columns[row_code_whir_phase_index(phase_role)]
                            .is_some()
                        || self.phase_opening_frontiers[row_code_whir_phase_index(phase_role)]
                            .is_some()
                        || self.exact_same_secret_phase_openings.is_some()
                }
            }
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let phase = match phase_role {
            RowCodeWhirPhase::Base => self.construction_plan.base_phase.as_ref(),
            RowCodeWhirPhase::Auxiliary => self.construction_plan.auxiliary_phase.as_ref(),
            RowCodeWhirPhase::Quotient => None,
        }
        .ok_or(CommonProofProverError::InvalidColumn)?;
        let expected_witness_value_count = ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
            .checked_mul(
                phase
                    .rows
                    .first()
                    .map_or(0, |row| row.logical_polynomial_chunks.len()),
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if phase.rows.len() != phase.geometry.row_count
            || expected_witness_value_count != phase.geometry.witness_values_per_row
            || phase.geometry.encoded_column_count == 0
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let opened_column_indices =
            self.phase_opening_traversal_indices(purpose, phase.geometry.encoded_column_count)?;
        let builder = StripedColumnCommitmentBuilder::new_with_opened_columns(
            phase.geometry.row_count,
            phase.geometry.encoded_column_count,
            MAXIMUM_PHASE_COMMITMENT_STRIPE_COLUMN_COUNT,
            &opened_column_indices,
        )
        .map_err(|_| CommonProofProverError::InvalidTree)?;
        let authenticated_opening_byte_length = opened_column_indices
            .len()
            .checked_mul(phase.geometry.row_count)
            .and_then(|value_count| value_count.checked_mul(size_of::<Goldilocks>()))
            .and_then(|value_byte_length| {
                opened_column_indices
                    .len()
                    .checked_mul(size_of::<AuthenticatedColumn>())
                    .and_then(|catalog_byte_length| {
                        value_byte_length.checked_add(catalog_byte_length)
                    })
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
        let maximum_live_byte_length = builder
            .maximum_hash_state_byte_length()
            .ok()
            .and_then(|byte_length| {
                phase
                    .geometry
                    .witness_values_per_row
                    .checked_mul(size_of::<Goldilocks>())
                    .and_then(|witness_byte_length| byte_length.checked_add(witness_byte_length))
            })
            .and_then(|byte_length| {
                phase
                    .geometry
                    .encoded_column_count
                    .checked_mul(size_of::<Goldilocks>())
                    .and_then(|encoded_row_byte_length| {
                        byte_length.checked_add(encoded_row_byte_length)
                    })
            })
            .and_then(|byte_length| byte_length.checked_add(authenticated_opening_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if u64::try_from(maximum_live_byte_length).map_or(true, |byte_length| {
            byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        }) {
            return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
        }
        let active_phase_authenticated_columns = match purpose {
            RowCodeWhirPhaseMaterializationPurpose::InitialCommitment => None,
            RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings => {
                Some(allocate_authenticated_phase_columns(
                    opened_column_indices.len(),
                    phase.geometry.row_count,
                )?)
            }
        };
        self.phase_row_witness = vec![Goldilocks::ZERO; phase.geometry.witness_values_per_row];
        self.phase_commitment_builder = Some(builder);
        self.active_phase_commitment = Some(phase_role);
        self.active_phase_materialization_purpose = Some(purpose);
        self.active_phase_authenticated_columns = active_phase_authenticated_columns;
        Ok(())
    }

    fn copy_relation_phase_polynomial_chunk(
        &mut self,
        logical_block_index: usize,
        expected_column_ordinal: u32,
        coefficient_chunk_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        let phase = match self.active_phase_commitment {
            Some(RowCodeWhirPhase::Base) => self.construction_plan.base_phase.as_ref(),
            Some(RowCodeWhirPhase::Auxiliary) => self.construction_plan.auxiliary_phase.as_ref(),
            _ => None,
        }
        .ok_or(CommonProofProverError::InvalidColumn)?;
        let row = phase
            .rows
            .get(self.next_phase_row_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let chunk = row
            .logical_polynomial_chunks
            .get(self.next_phase_logical_chunk_index)
            .copied()
            .flatten()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if logical_block_index != self.next_phase_logical_chunk_index
            || chunk.column_ordinal != expected_column_ordinal
            || chunk.coefficient_chunk_ordinal != coefficient_chunk_ordinal
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let CommonProofSourcePolynomial::Base(coefficients) = polynomial else {
            return Err(CommonProofProverError::InvalidColumn);
        };
        let source_start = usize::try_from(coefficient_chunk_ordinal)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if source_start >= coefficients.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_end = source_start
            .checked_add(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .map(|end| end.min(coefficients.len()))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination_start = logical_block_index
            .checked_mul(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let copied_value_count = source_end - source_start;
        let destination_end = destination_start
            .checked_add(copied_value_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination = self
            .phase_row_witness
            .get_mut(destination_start..destination_end)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        for (destination_value, coefficient) in destination
            .iter_mut()
            .zip(coefficients[source_start..source_end].iter())
        {
            *destination_value = Goldilocks::new(coefficient.canonical());
        }
        Ok(())
    }

    fn poll_relation_phase_commitment(
        &mut self,
        phase_role: RowCodeWhirPhase,
    ) -> Result<CommonProofGenerationPoll, CommonProofProverError> {
        if self.active_phase_commitment != Some(phase_role) {
            return Err(CommonProofProverError::InvalidInput);
        }
        let phase = match phase_role {
            RowCodeWhirPhase::Base => self.construction_plan.base_phase.as_ref(),
            RowCodeWhirPhase::Auxiliary => self.construction_plan.auxiliary_phase.as_ref(),
            RowCodeWhirPhase::Quotient => None,
        }
        .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.next_phase_row_index == phase.rows.len() {
            let complete = self
                .phase_commitment_builder
                .as_mut()
                .ok_or(CommonProofProverError::InvalidInput)?
                .complete_active_stripe()
                .map_err(|_| CommonProofProverError::InvalidTree)?;
            if complete {
                let (purpose, root) =
                    self.finish_active_phase_materialization(phase_role, phase.rows.len())?;
                match (purpose, phase_role) {
                    (
                        RowCodeWhirPhaseMaterializationPurpose::InitialCommitment,
                        RowCodeWhirPhase::Base,
                    ) => {
                        self.phase =
                            RowCodeWhirGenerationPhase::AwaitingAuthenticatedTranscriptPrefix;
                    }
                    (
                        RowCodeWhirPhaseMaterializationPurpose::InitialCommitment,
                        RowCodeWhirPhase::Auxiliary,
                    ) => {
                        let root_bytes = column_digest_bytes(root);
                        let tree_ordinals = self
                            .construction_plan
                            .relation_prefix_schedule()
                            .ordered_auxiliary_tree_ordinals()
                            .to_vec();
                        let transcript = self
                            .authenticated_transcript_prefix
                            .as_mut()
                            .ok_or(CommonProofProverError::InvalidInput)?;
                        for tree_ordinal in tree_ordinals {
                            transcript
                                .absorb_auxiliary_root(tree_ordinal, root_bytes)
                                .map_err(|_| CommonProofProverError::InvalidInput)?;
                        }
                        self.phase = RowCodeWhirGenerationPhase::PreparingQuotient;
                    }
                    (
                        RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                        RowCodeWhirPhase::Base,
                    ) => {
                        self.prepare_relation_phase_materialization(
                            RowCodeWhirPhase::Auxiliary,
                            RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                        )?;
                        self.phase =
                            RowCodeWhirGenerationPhase::MaterializingAuxiliaryPhaseOpenings;
                    }
                    (
                        RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                        RowCodeWhirPhase::Auxiliary,
                    ) => {
                        self.prepare_quotient_phase_materialization(
                            RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                        )?;
                        self.phase = RowCodeWhirGenerationPhase::MaterializingQuotientPhaseOpenings;
                    }
                    (_, RowCodeWhirPhase::Quotient) => {
                        return Err(CommonProofProverError::InvalidInput);
                    }
                }
            } else {
                self.next_phase_row_index = 0;
                self.next_phase_logical_chunk_index = 0;
                self.phase_row_witness.fill(Goldilocks::ZERO);
            }
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let row = phase
            .rows
            .get(self.next_phase_row_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.next_phase_logical_chunk_index < row.logical_polynomial_chunks.len() {
            let logical_block_index = self.next_phase_logical_chunk_index;
            let Some(chunk) = row.logical_polynomial_chunks[logical_block_index] else {
                self.next_phase_logical_chunk_index = self
                    .next_phase_logical_chunk_index
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
            };
            let plan = self
                .relation_replay_polynomial_plans
                .get(&chunk.column_ordinal)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            self.active_phase_polynomial_reader =
                Some(CommonProofReplayPolynomialReader::new(plan)?);
            self.active_phase_polynomial_binding =
                Some(RowCodeWhirPhasePolynomialBinding::Relation {
                    logical_block_index,
                    column_ordinal: chunk.column_ordinal,
                    coefficient_chunk_ordinal: chunk.coefficient_chunk_ordinal,
                });
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let row_high_half_source = match self.construction_plan.proof_privacy_mode {
            ProofPrivacyMode::SecretBearing => RowCodeHighHalfSource::PrivateMaskSeed(
                self.row_pad_seeds
                    .as_ref()
                    .and_then(|seeds| seeds.get(row_code_whir_phase_index(phase_role)))
                    .ok_or(CommonProofProverError::InvalidInput)?,
            ),
            ProofPrivacyMode::PublicOnly => {
                if self.row_pad_seeds.is_some() {
                    return Err(CommonProofProverError::InvalidInput);
                }
                RowCodeHighHalfSource::CanonicalPublicZeros
            }
        };
        let mut encoded_row = encode_row(
            phase.geometry,
            self.next_phase_row_index,
            &self.phase_row_witness,
            row_high_half_source,
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let active_column_range = self
            .phase_commitment_builder
            .as_ref()
            .and_then(StripedColumnCommitmentBuilder::active_column_range)
            .ok_or(CommonProofProverError::InvalidInput)?;
        self.capture_active_phase_authenticated_row(
            self.next_phase_row_index,
            active_column_range.clone(),
            &encoded_row,
        )?;
        self.phase_commitment_builder
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)?
            .absorb_active_stripe_row(
                self.next_phase_row_index,
                encoded_row
                    .get(active_column_range)
                    .ok_or(CommonProofProverError::InvalidColumn)?,
            )
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        encoded_row.fill(Goldilocks::ZERO);
        self.phase_row_witness.fill(Goldilocks::ZERO);
        self.next_phase_row_index = self
            .next_phase_row_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.next_phase_logical_chunk_index = 0;
        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
    }

    fn prepare_quotient_phase_materialization(
        &mut self,
        purpose: RowCodeWhirPhaseMaterializationPurpose,
    ) -> Result<(), CommonProofProverError> {
        if self.phase_commitment_builder.is_some()
            || self.active_phase_commitment.is_some()
            || self.active_phase_materialization_purpose.is_some()
            || self.active_phase_authenticated_columns.is_some()
            || self.active_phase_polynomial_reader.is_some()
            || self.active_phase_polynomial_binding.is_some()
            || !self.phase_row_witness.is_empty()
            || self.next_phase_row_index != 0
            || self.next_phase_logical_chunk_index != 0
            || match purpose {
                RowCodeWhirPhaseMaterializationPurpose::InitialCommitment => {
                    self.phase_root(RowCodeWhirPhase::Quotient).is_some()
                        || self.exact_same_secret_opening_schedule.is_some()
                }
                RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings => {
                    self.phase_root(RowCodeWhirPhase::Quotient).is_none()
                        || self.exact_same_secret_opening_schedule.is_none()
                        || self.phase_authenticated_columns
                            [row_code_whir_phase_index(RowCodeWhirPhase::Quotient)]
                        .is_some()
                        || self.phase_opening_frontiers
                            [row_code_whir_phase_index(RowCodeWhirPhase::Quotient)]
                        .is_some()
                        || self.exact_same_secret_phase_openings.is_some()
                }
            }
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let phase = &self.construction_plan.quotient_phase;
        let expected_witness_value_count = ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
            .checked_mul(
                phase
                    .rows
                    .first()
                    .map_or(0, |row| row.logical_polynomial_chunks.len()),
            )
            .ok_or(CommonProofProverError::CountOverflow)?;
        if phase.rows.len() != phase.geometry.row_count
            || expected_witness_value_count != phase.geometry.witness_values_per_row
            || phase.geometry.encoded_column_count == 0
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let opened_column_indices =
            self.phase_opening_traversal_indices(purpose, phase.geometry.encoded_column_count)?;
        let builder = StripedColumnCommitmentBuilder::new_with_opened_columns(
            phase.geometry.row_count,
            phase.geometry.encoded_column_count,
            MAXIMUM_PHASE_COMMITMENT_STRIPE_COLUMN_COUNT,
            &opened_column_indices,
        )
        .map_err(|_| CommonProofProverError::InvalidTree)?;
        let authenticated_opening_byte_length = opened_column_indices
            .len()
            .checked_mul(phase.geometry.row_count)
            .and_then(|value_count| value_count.checked_mul(size_of::<Goldilocks>()))
            .and_then(|value_byte_length| {
                opened_column_indices
                    .len()
                    .checked_mul(size_of::<AuthenticatedColumn>())
                    .and_then(|catalog_byte_length| {
                        value_byte_length.checked_add(catalog_byte_length)
                    })
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
        let maximum_live_byte_length = builder
            .maximum_hash_state_byte_length()
            .ok()
            .and_then(|byte_length| {
                phase
                    .geometry
                    .witness_values_per_row
                    .checked_mul(size_of::<Goldilocks>())
                    .and_then(|witness_byte_length| byte_length.checked_add(witness_byte_length))
            })
            .and_then(|byte_length| {
                phase
                    .geometry
                    .encoded_column_count
                    .checked_mul(size_of::<Goldilocks>())
                    .and_then(|encoded_row_byte_length| {
                        byte_length.checked_add(encoded_row_byte_length)
                    })
            })
            .and_then(|byte_length| byte_length.checked_add(authenticated_opening_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if u64::try_from(maximum_live_byte_length).map_or(true, |byte_length| {
            byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        }) {
            return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
        }
        let active_phase_authenticated_columns = match purpose {
            RowCodeWhirPhaseMaterializationPurpose::InitialCommitment => None,
            RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings => {
                Some(allocate_authenticated_phase_columns(
                    opened_column_indices.len(),
                    phase.geometry.row_count,
                )?)
            }
        };
        self.phase_row_witness = vec![Goldilocks::ZERO; phase.geometry.witness_values_per_row];
        self.phase_commitment_builder = Some(builder);
        self.active_phase_commitment = Some(RowCodeWhirPhase::Quotient);
        self.active_phase_materialization_purpose = Some(purpose);
        self.active_phase_authenticated_columns = active_phase_authenticated_columns;
        Ok(())
    }

    fn copy_quotient_phase_polynomial_chunk(
        &mut self,
        logical_block_index: usize,
        expected_source: RowCodeWhirOpenedPolynomialSource,
        coefficient_chunk_ordinal: u32,
        polynomial: CommonProofSourcePolynomial,
    ) -> Result<(), CommonProofProverError> {
        if self.active_phase_commitment != Some(RowCodeWhirPhase::Quotient) {
            return Err(CommonProofProverError::InvalidInput);
        }
        let row = self
            .construction_plan
            .quotient_phase
            .rows
            .get(self.next_phase_row_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let chunk = row
            .logical_polynomial_chunks
            .get(self.next_phase_logical_chunk_index)
            .copied()
            .flatten()
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if logical_block_index != self.next_phase_logical_chunk_index
            || chunk.source != expected_source
            || chunk.coefficient_chunk_ordinal != coefficient_chunk_ordinal
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let CommonProofSourcePolynomial::Extension(coefficients) = polynomial else {
            return Err(CommonProofProverError::InvalidColumn);
        };
        let extension_coordinate_index = usize::from(row.extension_coordinate_ordinal);
        let source_start = usize::try_from(coefficient_chunk_ordinal)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if source_start >= coefficients.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_end = source_start
            .checked_add(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .map(|end| end.min(coefficients.len()))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination_start = logical_block_index
            .checked_mul(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination_end = destination_start
            .checked_add(source_end - source_start)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination = self
            .phase_row_witness
            .get_mut(destination_start..destination_end)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        for (destination_value, coefficient) in destination
            .iter_mut()
            .zip(coefficients[source_start..source_end].iter())
        {
            let coordinate = coefficient
                .canonical_coordinates()
                .get(extension_coordinate_index)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            *destination_value = Goldilocks::new(coordinate);
        }
        Ok(())
    }

    fn poll_quotient_phase_commitment(
        &mut self,
    ) -> Result<CommonProofGenerationPoll, CommonProofProverError> {
        if self.active_phase_commitment != Some(RowCodeWhirPhase::Quotient) {
            return Err(CommonProofProverError::InvalidInput);
        }
        let phase = &self.construction_plan.quotient_phase;
        if self.next_phase_row_index == phase.rows.len() {
            let complete = self
                .phase_commitment_builder
                .as_mut()
                .ok_or(CommonProofProverError::InvalidInput)?
                .complete_active_stripe()
                .map_err(|_| CommonProofProverError::InvalidTree)?;
            if complete {
                let (purpose, root) = self.finish_active_phase_materialization(
                    RowCodeWhirPhase::Quotient,
                    phase.rows.len(),
                )?;
                match purpose {
                    RowCodeWhirPhaseMaterializationPurpose::InitialCommitment => {
                        self.authenticated_transcript_prefix
                            .as_mut()
                            .ok_or(CommonProofProverError::InvalidInput)?
                            .absorb_row_code_whir_quotient_phase_root(column_digest_bytes(root))
                            .map_err(|_| CommonProofProverError::InvalidInput)?;
                        self.phase = RowCodeWhirGenerationPhase::CompletingQuotientPhaseStorage;
                    }
                    RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings => {
                        self.finish_exact_same_secret_phase_openings()?;
                        self.phase = RowCodeWhirGenerationPhase::CompletingAggregateCommitment;
                    }
                }
            } else {
                self.next_phase_row_index = 0;
                self.next_phase_logical_chunk_index = 0;
                self.phase_row_witness.fill(Goldilocks::ZERO);
            }
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let row = phase
            .rows
            .get(self.next_phase_row_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.next_phase_logical_chunk_index < row.logical_polynomial_chunks.len() {
            let logical_block_index = self.next_phase_logical_chunk_index;
            let Some(chunk) = row.logical_polynomial_chunks[logical_block_index] else {
                self.next_phase_logical_chunk_index = self
                    .next_phase_logical_chunk_index
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
            };
            let plan = self
                .opened_replay_polynomial_plans
                .get(&chunk.source)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            self.active_phase_polynomial_reader =
                Some(CommonProofReplayPolynomialReader::new(plan)?);
            self.active_phase_polynomial_binding =
                Some(RowCodeWhirPhasePolynomialBinding::Opened {
                    logical_block_index,
                    source: chunk.source,
                    coefficient_chunk_ordinal: chunk.coefficient_chunk_ordinal,
                });
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let row_high_half_source = match self.construction_plan.proof_privacy_mode {
            ProofPrivacyMode::SecretBearing => RowCodeHighHalfSource::PrivateMaskSeed(
                self.row_pad_seeds
                    .as_ref()
                    .and_then(|seeds| {
                        seeds.get(row_code_whir_phase_index(RowCodeWhirPhase::Quotient))
                    })
                    .ok_or(CommonProofProverError::InvalidInput)?,
            ),
            ProofPrivacyMode::PublicOnly => {
                if self.row_pad_seeds.is_some() {
                    return Err(CommonProofProverError::InvalidInput);
                }
                RowCodeHighHalfSource::CanonicalPublicZeros
            }
        };
        let mut encoded_row = encode_row(
            phase.geometry,
            self.next_phase_row_index,
            &self.phase_row_witness,
            row_high_half_source,
        )
        .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let active_column_range = self
            .phase_commitment_builder
            .as_ref()
            .and_then(StripedColumnCommitmentBuilder::active_column_range)
            .ok_or(CommonProofProverError::InvalidInput)?;
        self.capture_active_phase_authenticated_row(
            self.next_phase_row_index,
            active_column_range.clone(),
            &encoded_row,
        )?;
        self.phase_commitment_builder
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)?
            .absorb_active_stripe_row(
                self.next_phase_row_index,
                encoded_row
                    .get(active_column_range)
                    .ok_or(CommonProofProverError::InvalidColumn)?,
            )
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        encoded_row.fill(Goldilocks::ZERO);
        self.phase_row_witness.fill(Goldilocks::ZERO);
        self.next_phase_row_index = self
            .next_phase_row_index
            .checked_add(1)
            .ok_or(CommonProofProverError::CountOverflow)?;
        self.next_phase_logical_chunk_index = 0;
        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
    }

    /// The canonical ascending encoded-column indices that this materialization
    /// pass must retain. The initial commitment pass retains none, so its
    /// Merkle frontier stays `O(log domain)`. The authenticated-openings pass
    /// retains exactly the plan-derived outer traversal columns, which is the
    /// same without-replacement subset the verifier recomputes.
    fn phase_opening_traversal_indices(
        &self,
        purpose: RowCodeWhirPhaseMaterializationPurpose,
        encoded_column_count: usize,
    ) -> Result<Vec<usize>, CommonProofProverError> {
        match purpose {
            RowCodeWhirPhaseMaterializationPurpose::InitialCommitment => Ok(Vec::new()),
            RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings => {
                let traversal_indices = self
                    .exact_same_secret_opening_schedule
                    .as_ref()
                    .ok_or(CommonProofProverError::InvalidInput)?
                    .outer_traversal_query_indices();
                if traversal_indices.len() != self.construction_plan.parameters.outer_query_count
                    || traversal_indices.is_empty()
                    || traversal_indices.windows(2).any(|pair| pair[0] >= pair[1])
                    || traversal_indices
                        .last()
                        .is_some_and(|column_index| *column_index >= encoded_column_count)
                {
                    return Err(CommonProofProverError::InvalidOpening);
                }
                let mut retained_indices = Vec::new();
                retained_indices
                    .try_reserve_exact(traversal_indices.len())
                    .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
                retained_indices.extend_from_slice(traversal_indices);
                Ok(retained_indices)
            }
        }
    }

    /// Retains the opened coordinates of one encoded row while the row is still
    /// live. Only the columns inside the active stripe are captured, so the
    /// caller never needs a second encoding pass or a resident codeword.
    fn capture_active_phase_authenticated_row(
        &mut self,
        row_index: usize,
        active_column_range: core::ops::Range<usize>,
        encoded_row: &[Goldilocks],
    ) -> Result<(), CommonProofProverError> {
        let Some(authenticated_columns) = self.active_phase_authenticated_columns.as_mut() else {
            if self.active_phase_materialization_purpose
                != Some(RowCodeWhirPhaseMaterializationPurpose::InitialCommitment)
            {
                return Err(CommonProofProverError::InvalidInput);
            }
            return Ok(());
        };
        let traversal_indices = self
            .exact_same_secret_opening_schedule
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?
            .outer_traversal_query_indices();
        if traversal_indices.len() != authenticated_columns.len() {
            return Err(CommonProofProverError::InvalidOpening);
        }
        let first_active_position = traversal_indices
            .partition_point(|column_index| *column_index < active_column_range.start);
        let following_active_position = traversal_indices
            .partition_point(|column_index| *column_index < active_column_range.end);
        for active_position in first_active_position..following_active_position {
            let column_index = traversal_indices[active_position];
            let value = encoded_row
                .get(column_index)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let authenticated_column = authenticated_columns
                .get_mut(active_position)
                .ok_or(CommonProofProverError::InvalidOpening)?;
            if authenticated_column.values.len() != row_index {
                return Err(CommonProofProverError::InvalidOpening);
            }
            authenticated_column.values.push(value);
        }
        Ok(())
    }

    /// Closes one completed phase materialization. The initial pass installs the
    /// phase root; the authenticated-openings pass must recompute exactly the
    /// same root before its retained columns and compact frontier are accepted.
    fn finish_active_phase_materialization(
        &mut self,
        phase_role: RowCodeWhirPhase,
        expected_row_count: usize,
    ) -> Result<(RowCodeWhirPhaseMaterializationPurpose, ColumnDigest), CommonProofProverError>
    {
        if self.active_phase_commitment != Some(phase_role)
            || self.active_phase_polynomial_reader.is_some()
            || self.active_phase_polynomial_binding.is_some()
            || self.next_phase_row_index != expected_row_count
            || expected_row_count == 0
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let purpose = self
            .active_phase_materialization_purpose
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let commitment = self
            .phase_commitment_builder
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?
            .finish_commitment()
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        let root = commitment.root;
        let phase_index = row_code_whir_phase_index(phase_role);
        match purpose {
            RowCodeWhirPhaseMaterializationPurpose::InitialCommitment => {
                if !commitment.frontier.is_empty()
                    || self.active_phase_authenticated_columns.is_some()
                {
                    return Err(CommonProofProverError::InvalidTree);
                }
                self.set_phase_root(phase_role, root)?;
            }
            RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings => {
                if self.phase_root(phase_role) != Some(root) {
                    return Err(CommonProofProverError::InvalidTree);
                }
                let authenticated_columns = self
                    .active_phase_authenticated_columns
                    .take()
                    .ok_or(CommonProofProverError::InvalidInput)?;
                if authenticated_columns.len()
                    != self.construction_plan.parameters.outer_query_count
                    || authenticated_columns
                        .iter()
                        .any(|column| column.values.len() != expected_row_count)
                {
                    return Err(CommonProofProverError::InvalidOpening);
                }
                if self.phase_authenticated_columns[phase_index]
                    .replace(authenticated_columns)
                    .is_some()
                    || self.phase_opening_frontiers[phase_index]
                        .replace(commitment.frontier)
                        .is_some()
                {
                    return Err(CommonProofProverError::InvalidInput);
                }
            }
        }
        self.active_phase_commitment = None;
        self.phase_row_witness = Vec::new();
        self.next_phase_row_index = 0;
        self.next_phase_logical_chunk_index = 0;
        Ok((purpose, root))
    }

    /// Collects the three completed phase openings once every phase has
    /// reproduced its committed root.
    fn finish_exact_same_secret_phase_openings(&mut self) -> Result<(), CommonProofProverError> {
        if self.exact_same_secret_phase_openings.is_some()
            || self.phase_commitment_builder.is_some()
            || self.active_phase_commitment.is_some()
            || self.active_phase_materialization_purpose.is_some()
            || self.active_phase_authenticated_columns.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let roots = [
            self.phase_root(RowCodeWhirPhase::Base)
                .ok_or(CommonProofProverError::InvalidTree)?,
            self.phase_root(RowCodeWhirPhase::Auxiliary)
                .ok_or(CommonProofProverError::InvalidTree)?,
            self.phase_root(RowCodeWhirPhase::Quotient)
                .ok_or(CommonProofProverError::InvalidTree)?,
        ];
        let mut authenticated_columns_by_phase: [Vec<AuthenticatedColumn>; 3] =
            std::array::from_fn(|_| Vec::new());
        let mut frontiers_by_phase: [Vec<ColumnDigest>; 3] = std::array::from_fn(|_| Vec::new());
        for phase_index in 0..authenticated_columns_by_phase.len() {
            authenticated_columns_by_phase[phase_index] = self.phase_authenticated_columns
                [phase_index]
                .take()
                .ok_or(CommonProofProverError::InvalidOpening)?;
            frontiers_by_phase[phase_index] = self.phase_opening_frontiers[phase_index]
                .take()
                .ok_or(CommonProofProverError::InvalidOpening)?;
        }
        if authenticated_columns_by_phase
            .iter()
            .any(|columns| columns.len() != self.construction_plan.parameters.outer_query_count)
        {
            return Err(CommonProofProverError::InvalidOpening);
        }
        self.exact_same_secret_phase_openings = Some(ExactSameSecretPhaseOpenings::new(
            roots,
            authenticated_columns_by_phase,
            frontiers_by_phase,
        ));
        Ok(())
    }
}

/// Reserves the exact retained-column capacity for one authenticated-openings
/// pass. Lengths stay zero so the row loop can assert canonical row order.
fn allocate_authenticated_phase_columns(
    opened_column_count: usize,
    row_count: usize,
) -> Result<Vec<AuthenticatedColumn>, CommonProofProverError> {
    if opened_column_count == 0 || row_count == 0 {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let mut authenticated_columns = Vec::new();
    authenticated_columns
        .try_reserve_exact(opened_column_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for _ in 0..opened_column_count {
        let mut values = Vec::new();
        values
            .try_reserve_exact(row_count)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        authenticated_columns.push(AuthenticatedColumn { values });
    }
    Ok(authenticated_columns)
}

fn replay_polynomial_target_for_opening_claim(
    claim: &RelationOpeningClaimDescriptor,
) -> Result<RowCodeWhirReplayPolynomialTarget, CommonProofProverError> {
    match claim.source_class() {
        RelationOpeningSourceClass::TreeColumn => {
            Ok(RowCodeWhirReplayPolynomialTarget::RelationColumn(
                claim
                    .column_ordinal()
                    .ok_or(CommonProofProverError::InvalidOpening)?,
            ))
        }
        RelationOpeningSourceClass::Quotient => {
            if claim.column_ordinal().is_some() {
                return Err(CommonProofProverError::InvalidOpening);
            }
            Ok(RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(
                RowCodeWhirOpenedPolynomialSource::QuotientComponent {
                    component_ordinal: claim.source_ordinal(),
                },
            ))
        }
        RelationOpeningSourceClass::BatchMask => {
            if claim.source_ordinal() != 0 || claim.column_ordinal().is_some() {
                return Err(CommonProofProverError::InvalidOpening);
            }
            Ok(RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(
                RowCodeWhirOpenedPolynomialSource::OpeningBatchMask { mask_ordinal: 0 },
            ))
        }
    }
}

fn evaluate_opening_claim(
    claim: &RelationOpeningClaimDescriptor,
    polynomial: &CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
) -> Result<ProofChallengeExtensionElement, CommonProofProverError> {
    let source_degree_bound_exclusive = usize::try_from(claim.source_degree_bound_exclusive())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    if polynomial.coefficient_count() == 0
        || polynomial.coefficient_count() > source_degree_bound_exclusive
        || (claim.source_class() != RelationOpeningSourceClass::TreeColumn
            && polynomial.value_type() != RelationColumnValueType::ChallengeExtension)
    {
        return Err(CommonProofProverError::InvalidOpening);
    }
    Ok(polynomial.evaluate_at(opening_point))
}

fn evaluate_opening_batch_mask_chunks(
    polynomial: &CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
    chunk_count: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    let CommonProofSourcePolynomial::Extension(coefficients) = polynomial else {
        return Err(CommonProofProverError::InvalidMask);
    };
    let maximum_coefficient_count = ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        .checked_mul(chunk_count)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if chunk_count == 0 || coefficients.is_empty() || coefficients.len() > maximum_coefficient_count
    {
        return Err(CommonProofProverError::InvalidMask);
    }
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(chunk_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for chunk_ordinal in 0..chunk_count {
        let chunk_start = chunk_ordinal
            .checked_mul(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if chunk_start >= coefficients.len() {
            evaluations.push(ProofChallengeExtensionElement::ZERO);
            continue;
        }
        let chunk_end = chunk_start
            .checked_add(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(coefficients.len());
        evaluations.push(evaluate_extension_at(
            &coefficients[chunk_start..chunk_end],
            opening_point,
        ));
    }
    Ok(evaluations)
}

fn absorb_extension_values_checkpoint_part(
    hasher: &mut StreamingHash512,
    values: &[ProofChallengeExtensionElement],
) -> Option<()> {
    let byte_length = values
        .len()
        .checked_mul(crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE)?
        .checked_mul(size_of::<u64>())?;
    hasher.begin_part(u64::try_from(byte_length).ok()?);
    for value in values {
        for coordinate in value.canonical_coordinates() {
            hasher.absorb_raw(&coordinate.to_le_bytes());
        }
    }
    Some(())
}

fn require_bounded_source_provider(
    source_polynomial_provider: &dyn CommonProofSourcePolynomialProvider,
) -> Result<(), CommonProofGenerationInitializationError> {
    let accounting = source_polynomial_provider
        .memory_accounting()
        .map_err(CommonProofGenerationInitializationError::Prover)?;
    let loading_resident_byte_length = accounting
        .loading_persistent_resident_byte_length()
        .checked_add(accounting.additional_loading_transient_byte_length())
        .and_then(|byte_length| {
            byte_length.checked_add(accounting.maximum_returned_source_polynomial_byte_length())
        })
        .ok_or(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::CountOverflow,
        ))?;
    if loading_resident_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || accounting.post_source_polynomial_finish_persistent_resident_byte_length()
            > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(CommonProofGenerationInitializationError::Prover(
            CommonProofProverError::ResidentMemoryLimitExceeded,
        ));
    }
    Ok(())
}

fn map_private_coin_error<StorageError, CoinError, SinkError>(
    error: CommonProofPrivateCoinError<CoinError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        CommonProofPrivateCoinError::Prover(error) => CommonProofGenerationError::Prover(error),
        CommonProofPrivateCoinError::CoinSource(error) => {
            CommonProofGenerationError::CoinSource(error)
        }
    }
}

fn map_retained_whir_generation_error<StorageError, CoinError, SinkError>(
    error: StreamingPlainAggregateRetainedOracleError<StorageError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        StreamingPlainAggregateRetainedOracleError::Geometry(_) => {
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
        }
        StreamingPlainAggregateRetainedOracleError::Storage(
            RetainedPlainWhirOracleStorageError::Codec(_),
        ) => CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
        StreamingPlainAggregateRetainedOracleError::Storage(
            RetainedPlainWhirOracleStorageError::ExternalMemory(error),
        ) => CommonProofGenerationError::Storage(error),
    }
}

fn map_retained_whir_cancel_error<StorageError>(
    error: StreamingPlainAggregateRetainedOracleError<StorageError>,
) -> ProofExternalMemoryExecutorError<StorageError> {
    match error {
        StreamingPlainAggregateRetainedOracleError::Geometry(_)
        | StreamingPlainAggregateRetainedOracleError::Storage(
            RetainedPlainWhirOracleStorageError::Codec(_),
        ) => ProofExternalMemoryError::InvalidLifecycle.into(),
        StreamingPlainAggregateRetainedOracleError::Storage(
            RetainedPlainWhirOracleStorageError::ExternalMemory(error),
        ) => error,
    }
}

const fn row_code_whir_phase_index(phase: RowCodeWhirPhase) -> usize {
    match phase {
        RowCodeWhirPhase::Base => 0,
        RowCodeWhirPhase::Auxiliary => 1,
        RowCodeWhirPhase::Quotient => 2,
    }
}

fn column_digest_bytes(digest: ColumnDigest) -> [u8; HASH_BYTE_LENGTH] {
    let mut bytes = [0_u8; HASH_BYTE_LENGTH];
    for (word_index, word) in digest.into_iter().enumerate() {
        bytes[word_index * size_of::<u64>()..(word_index + 1) * size_of::<u64>()]
            .copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::proof_suite::{
            external_memory::{
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
            },
            selected_relation_plans,
        },
        foundation::{
            MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
            MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
            ProofApplicationSlotCeilings,
        },
    };

    #[test]
    fn selected_same_secret_storage_plan_distinguishes_lifecycles_from_physical_custody() {
        let artifacts = selected_relation_plans().expect("selected relation plans derive");
        let artifact = artifacts
            .iter()
            .find(|artifact| {
                artifact.application_statement_schema_identifier()
                    == ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
            })
            .expect("the selected same-secret relation plan exists");
        let variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the selected same-secret relation plan has one variant");
        let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            artifact,
            variant.schedule_position(),
            variant.top_count(),
        )
        .expect("the selected same-secret construction plan derives");
        let requirement = planned_row_code_whir_external_memory_requirement(
            &construction_plan,
            variant,
            artifact.checked_context(),
        )
        .expect("the selected same-secret storage plan stays within absolute custody bounds");

        assert!(
            requirement.object_lifecycle_count() > requirement.distinct_physical_object_count(),
            "transform scratch and output identities must be reused only across disjoint lifecycles",
        );
        assert!(
            usize::try_from(requirement.distinct_physical_object_count())
                .is_ok_and(|count| count <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT),
        );
        assert!(
            requirement.peak_stored_byte_length()
                <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        );
        assert!(
            requirement.local_record_seal_invocation_count()
                < MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
        );
        assert!(
            requirement.local_record_sealed_plaintext_byte_length()
                < MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
        );
        assert!(!requirement.exceeds_active_root_seal_custody_budget());

        let raw_source_counts =
            authenticated_pre_challenge_source_coefficient_position_counts(variant)
                .expect("the raw authenticated-source census derives");
        let persisted_source_counts =
            persisted_pre_challenge_column_coefficient_position_counts(variant)
                .expect("the persisted pre-challenge census derives");
        assert_eq!(
            raw_source_counts.keys().collect::<Vec<_>>(),
            persisted_source_counts.keys().collect::<Vec<_>>()
        );
        assert_eq!(raw_source_counts.values().sum::<u64>(), 33_128_448);
        assert_eq!(persisted_source_counts.values().sum::<u64>(), 34_462_440);
        assert_eq!(
            construction_plan.requested_source_column_ordinals.len()
                + relation_reversed_column_bindings(variant)
                    .expect("the reversed-column catalog derives")
                    .len(),
            2_030,
        );
    }

    #[test]
    fn opening_batch_mask_chunks_preserve_polynomial_evaluation_and_exact_boundaries() {
        let opening_point =
            ProofChallengeExtensionElement::from_canonical_coordinates([17, 11, 5, 3, 2])
                .expect("the test opening point is canonical");
        let coefficient_count = ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT + 3;
        let coefficients = (0..coefficient_count)
            .map(|coefficient_index| {
                ProofChallengeExtensionElement::from_canonical_coordinates([
                    u64::try_from(coefficient_index % 251 + 1)
                        .expect("the bounded coefficient fits u64"),
                    0,
                    0,
                    0,
                    0,
                ])
                .expect("the bounded coefficient is canonical")
            })
            .collect::<Vec<_>>();
        let polynomial = CommonProofSourcePolynomial::from_extension_coefficients(coefficients);
        let chunk_evaluations = evaluate_opening_batch_mask_chunks(&polynomial, opening_point, 3)
            .expect("the partial final mask chunk evaluates");
        assert_eq!(chunk_evaluations.len(), 3);
        assert_eq!(chunk_evaluations[2], ProofChallengeExtensionElement::ZERO);

        let chunk_power = opening_point.power(
            u64::try_from(ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
                .expect("the logical chunk width fits u64"),
        );
        let mut current_chunk_power = ProofChallengeExtensionElement::ONE;
        let mut recombined_evaluation = ProofChallengeExtensionElement::ZERO;
        for chunk_evaluation in chunk_evaluations {
            recombined_evaluation =
                recombined_evaluation.add(chunk_evaluation.multiply(current_chunk_power));
            current_chunk_power = current_chunk_power.multiply(chunk_power);
        }
        assert_eq!(recombined_evaluation, polynomial.evaluate_at(opening_point));

        let exact_boundary = CommonProofSourcePolynomial::from_extension_coefficients(vec![
            ProofChallengeExtensionElement::ONE;
            ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        ]);
        let exact_boundary_evaluations =
            evaluate_opening_batch_mask_chunks(&exact_boundary, opening_point, 2)
                .expect("an exact first-chunk boundary evaluates");
        assert_eq!(
            exact_boundary_evaluations[1],
            ProofChallengeExtensionElement::ZERO,
        );
    }

    #[test]
    fn opening_batch_mask_chunks_refuse_empty_and_overlong_polynomials() {
        let opening_point = ProofChallengeExtensionElement::ONE;
        let empty = CommonProofSourcePolynomial::from_extension_coefficients(Vec::new());
        assert_eq!(
            evaluate_opening_batch_mask_chunks(&empty, opening_point, 2),
            Err(CommonProofProverError::InvalidMask),
        );

        let overlong = CommonProofSourcePolynomial::from_extension_coefficients(vec![
            ProofChallengeExtensionElement::ZERO;
            ROW_CODE_WHIR_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * 2 + 1
        ]);
        assert_eq!(
            evaluate_opening_batch_mask_chunks(&overlong, opening_point, 2),
            Err(CommonProofProverError::InvalidMask),
        );
    }
}
