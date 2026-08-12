//! Checked-plan production generation state for the row-code/WHIR construction.
//!
//! This state owns the authenticated application source before any proof byte
//! can be emitted. Authenticated source and derived columns are replayed from
//! browser-owned external memory. Phase commitments use a bounded stripe of
//! canonical SHAKE256 states, so the implementation schedule does not enter
//! the cryptographic identity and complete phase material is never resident.

use core::mem::size_of;
use std::collections::{BTreeMap, BTreeSet};

use p3_goldilocks::Goldilocks;
use zeroize::Zeroizing;

use super::aggregate_source_storage::{
    AggregateSourceStoragePlan, AggregateSourceTable, AggregateSourceValues, AggregateSourceWriter,
};
use super::aggregate_wide_hiding::{
    AggregateWideHidingMaterialGeneration, AggregateWideHidingMaterialGenerationError,
    AggregateWideHidingMaterialGenerationPoll, AggregateWideHidingMaterialShape,
    AggregateWideOpeningProof,
};
use super::aggregate_wide_prover::{
    StreamingAggregateWideCommitmentGeneration, StreamingAggregateWideCommitmentPoll,
    StreamingAggregateWideError, StreamingAggregateWideProofBoundary,
    StreamingAggregateWideProofGeneration, StreamingAggregateWideProofPoll,
};
use super::exact_same_secret::{
    ExactBoundLeafOpening, ExactBoundTreeAuthentication, ExactSameSecretAggregateMetadata,
    ExactSameSecretAggregateSource, ExactSameSecretAggregateSourceAction,
    ExactSameSecretAggregateSourceBatch, ExactSameSecretAggregateSourceTarget,
    ExactSameSecretAggregateWitness, ExactSameSecretPhaseOpenings, ExactSameSecretProof,
    ExactSameSecretProofEncodingProgress, ExactSameSecretProofSinkEncoder,
    ExactSameSecretProofSinkEncodingError, aggregate_source_materialization_pass_count,
    aggregate_source_resident_batch_column_count,
};
use super::opening_schedule::{
    RowCodeWhirBoundOpeningClaim, RowCodeWhirOpeningSchedule, RowCodeWhirPointRowWeights,
};
use super::relation_materialization::{
    RowCodeWhirAuxiliaryRelationMaterialization, RowCodeWhirAuxiliaryRelationMaterializationAction,
    RowCodeWhirQuotientMaterialization, RowCodeWhirQuotientMaterializationAction,
};
use super::same_secret_source_manifest::{
    SameSecretAuthenticatedSourceManifest, SameSecretAuthenticatedSourceManifestError,
};
use super::{
    AuthenticatedColumn, ChallengeField, ExactSameSecretAuthenticatedTranscriptPrefixRequest,
    ExactSameSecretTranscriptPrefixAuthorityBinding, ExtensionFieldChallenger,
    PreparedExactSameSecretTranscriptPrefix, RowCodeWhirConstructionPlan,
    RowCodeWhirQuotientColumnSourcePlan, RowCodeWhirQuotientColumnTransformPlan,
    aggregate_wide_pcs::{AggregateWideCommitment, aggregate_wide_pcs_for_construction_plan},
    bounded_dft::{BoundedBaseCosetDft, BoundedBaseCosetLaneDft},
    canonical_row_code_whir_family_body_byte_length_ceiling,
    column_commitment::{
        ColumnDigest, InterleavedColumnCommitmentBuilder, PrivateColumnLeafSaltContext,
    },
    commitment_liveness::{
        BOUND_TREE_AUTHENTICATION_STRIPE_LEAF_COUNT, CompleteGenerationLiveness,
        CompleteGenerationLivenessInput, derive_complete_generation_liveness,
        noncompact_aggregate_opening_path_byte_length,
    },
    construction_plan::{
        RowCodeWhirCheckpointBoundary, RowCodeWhirOpenedPolynomialSource, RowCodeWhirPhase,
        RowCodeWhirProofSectionRole,
    },
    plan_row_code_whir_quotient_transform_storage,
    row_encoding::{
        PRIVATE_ROW_PAD_PHASE_COUNT, PRIVATE_ROW_PAD_SEED_BYTE_LENGTH,
        PRIVATE_ROW_PAD_SEED_MATERIAL_BYTE_LENGTH, PrivateRowPadSeed, RowCodeHighHalfSource,
        RowEncodingGeometry, padded_base_row_coefficients,
    },
};
use crate::bgv::proof_suite::external_memory::{
    ProofExternalMemoryError, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
};
use crate::bgv::proof_suite::external_polynomial::{
    ExternalPolynomialReadError, ExternalPolynomialVector, map_external_polynomial_read_error,
    read_external_polynomial_values_as_extension,
};
use crate::bgv::proof_suite::prover::{
    CommonProofAuxiliaryColumnReconstructionCatalog,
    CommonProofAuxiliaryColumnReconstructionCursor, CommonProofBoundTreeLeafSaltRequest,
    CommonProofExternalMemoryRequirement, CommonProofGenerationCheckpointBoundary,
    CommonProofPreChallengeSourceCursor, CommonProofPreChallengeSourcePoll,
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinError,
    CommonProofQuotientConstraintTransformKey, CommonProofQuotientEvaluationReadRequest,
    CommonProofReplayPolynomialEncoding, CommonProofReplayPolynomialPlan,
    CommonProofReplayPolynomialRangeDestination, CommonProofReplayPolynomialRangeReader,
    CommonProofReplayPolynomialReader, CommonProofReplayPolynomialRef,
    CommonProofReplayPolynomialWriter, CommonProofSourceProviderMemoryAccounting, apply_trace_mask,
    authenticated_pre_challenge_source_coefficient_position_counts,
    canonical_proof_object_header_bytes, common_proof_auxiliary_materialization_liveness,
    common_proof_quotient_materialization_liveness, construct_reversed_relation_column,
    ordered_integer_lift_auxiliary_column_ordinals,
    persisted_pre_challenge_column_coefficient_position_counts, relation_reversed_column_bindings,
    requested_pre_challenge_source_column_ordinals, validate_generation_relation_trees,
    validate_source_column,
};
use crate::bgv::proof_suite::relation_plan::{
    BoundTreeConstructionKind, ProofPrivacyMode, RelationColumnOrigin, RelationColumnValueType,
    RelationOpeningClaimDescriptor, RelationOpeningSourceClass, RelationTreeDescriptor,
};
use crate::bgv::proof_suite::transcript::{
    RowCodeWhirTranscript, RowCodeWhirTranscriptCheckpointCursor,
};
use crate::bgv::proof_suite::{
    CommonProofAuthenticatedSourceReadRequest, CommonProofByteSink, CommonProofGenerationError,
    CommonProofGenerationInitializationError, CommonProofGenerationInput,
    CommonProofGenerationPoll, CommonProofGenerationStage, CommonProofProverError,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialReplayIdentity,
    CommonProofSourcePolynomialRequestContext, CommonProofSourceReplayIdentityCatalog,
    MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH, MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, ProofBaseFieldElement,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofExternalMemory,
    ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError, ProofExternalMemoryUsage,
    ProofTreeCatalogEntry, ProofTreeValue, RelationApplicationChallengeAssignment,
    RelationPlanCheckContext, RelationPlanVariant, RelationProofTreeInput,
    ValidatedRelationPlanArtifact, build_relation_bound_public_tree_catalog_entries,
    construct_opening_batch_mask, evaluate_extension_at, sample_relation_application_challenges,
    verified_application_statement_hash,
};
use crate::foundation::SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT;
use crate::hashing::{StreamingHash512, hash_framed_parts_512};

const HASH_BYTE_LENGTH: usize = 64;
const ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING: u32 =
    SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT;

fn validate_phase_materialization_shape(
    logical_polynomial_coefficient_count: usize,
    logical_polynomials_per_physical_row: usize,
    geometry: RowEncodingGeometry,
    actual_row_count: usize,
    has_noncanonical_padding_chunk: bool,
) -> Result<(), CommonProofProverError> {
    let expected_witness_value_count = logical_polynomial_coefficient_count
        .checked_mul(logical_polynomials_per_physical_row)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if actual_row_count != geometry.row_count
        || expected_witness_value_count != geometry.witness_values_per_row
        || geometry.encoded_column_count == 0
        || has_noncanonical_padding_chunk
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(())
}

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
    PersistingAggregateSourceBatch,
    ReleasingAggregateReplayStorage,
    SamplingAggregateWideHidingMaterial,
    CommittingAggregate,
    PreparingAggregateOpenings,
    MaterializingBoundAuthentications,
    MaterializingBasePhaseOpenings,
    MaterializingAuxiliaryPhaseOpenings,
    MaterializingQuotientPhaseOpenings,
    CompletingAggregateCommitment,
    GeneratingAggregateWhirProof,
    AwaitingExactProofAssembly,
    EncodingExactProofHeader,
    EncodingExactProof,
    Complete,
    Cancelled,
}

const AUXILIARY_REPLAY_ISSUED_STEP: u32 = 1;
const FIRST_QUOTIENT_TRANSFORM_STEP: u32 = 2;
pub(super) const MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT: usize = 1 << 19;
const MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH: usize = 16 * 1_024;
const ROW_CODE_WHIR_CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN: &str =
    "sealed-lattice/row-code-whir/checkpoint-committed-state/v1";
const ROW_CODE_WHIR_TRANSCRIPT_PREFIX_AUTHORITY_BINDING_DOMAIN: &str =
    "sealed-lattice/row-code-whir/transcript-prefix-authority-binding/v1";
const SAME_SECRET_SOURCE_REPLAY_IDENTITY_HASH_DOMAIN: &str =
    "sealed-lattice/row-code-whir/same-secret-source-replay-identity/v1";

type RowCodeWhirGenerationPollResult<StorageError, CoinError, SinkError> = Result<
    CommonProofGenerationPoll,
    CommonProofGenerationError<StorageError, CoinError, SinkError>,
>;

/// Construction-selected authority for the relation-prefix transcript.
///
/// Same-secret alone borrows an already verified VSS low-degree result and
/// therefore requires an opaque authenticated prefix. Every direct-bound
/// construction derives the same typed prefix locally from its canonical
/// proof header and checked construction plan.
pub(in crate::bgv::proof_suite) enum RowCodeWhirTranscriptPrefixAuthority {
    Direct,
    VerifiedVss(Box<ExactSameSecretTranscriptPrefixAuthorityBinding>),
}

impl RowCodeWhirTranscriptPrefixAuthority {
    fn verified_vss_binding(&self) -> Option<&ExactSameSecretTranscriptPrefixAuthorityBinding> {
        match self {
            Self::Direct => None,
            Self::VerifiedVss(binding) => Some(binding),
        }
    }

    fn aggregate_binding_digest(
        &self,
        construction_identity_hash: [u8; HASH_BYTE_LENGTH],
        stable_generation_binding_hash: [u8; HASH_BYTE_LENGTH],
    ) -> [u8; HASH_BYTE_LENGTH] {
        match self {
            Self::Direct => hash_framed_parts_512(
                ROW_CODE_WHIR_TRANSCRIPT_PREFIX_AUTHORITY_BINDING_DOMAIN,
                &[
                    &[0_u8],
                    &construction_identity_hash,
                    &stable_generation_binding_hash,
                ],
            ),
            Self::VerifiedVss(binding) => hash_framed_parts_512(
                ROW_CODE_WHIR_TRANSCRIPT_PREFIX_AUTHORITY_BINDING_DOMAIN,
                &[
                    &[1_u8],
                    &construction_identity_hash,
                    &stable_generation_binding_hash,
                    &binding.generation_binding_hash(),
                    &binding.attempt_identifier(),
                ],
            ),
        }
    }
}

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
    BoundTreeColumn {
        bound_tree_ordinal: usize,
        column_position: usize,
        column_ordinal: u32,
    },
}

enum RowCodeWhirRelationPolynomialReaderError<StorageError> {
    Prover(CommonProofProverError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowCodeWhirRelationPolynomialReaderPoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    AuthenticatedSourceReadRequired,
    Complete,
}

struct RecomputedSourcePolynomialReader {
    request_context: CommonProofSourcePolynomialRequestContext,
    column_ordinal: u32,
    descriptor: crate::bgv::proof_suite::relation_plan::RelationColumnDescriptor,
    expected_replay_identity: CommonProofSourcePolynomialReplayIdentity,
    trace_domain_size: u64,
    polynomial: Option<CommonProofSourcePolynomial>,
    private_mask: Option<CommonProofSourcePolynomial>,
}

impl RecomputedSourcePolynomialReader {
    fn new(
        request_context: CommonProofSourcePolynomialRequestContext,
        column_ordinal: u32,
        descriptor: crate::bgv::proof_suite::relation_plan::RelationColumnDescriptor,
        expected_replay_identity: CommonProofSourcePolynomialReplayIdentity,
        trace_domain_size: u64,
        private_mask: Option<CommonProofSourcePolynomial>,
    ) -> Result<Self, CommonProofProverError> {
        Ok(Self {
            request_context,
            column_ordinal,
            descriptor,
            expected_replay_identity,
            trace_domain_size,
            polynomial: None,
            private_mask,
        })
    }

    fn advance<Storage: ProofExternalMemory>(
        &mut self,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        RowCodeWhirRelationPolynomialReaderPoll,
        RowCodeWhirRelationPolynomialReaderError<Storage::Error>,
    > {
        if self.polynomial.is_none() {
            let provided = match source_provider
                .poll_replayed_source_polynomial(
                    self.request_context
                        .request(self.column_ordinal, &self.descriptor),
                )
                .map_err(RowCodeWhirRelationPolynomialReaderError::Prover)?
            {
                CommonProofSourcePolynomialProviderPoll::Ready(provided) => provided,
                CommonProofSourcePolynomialProviderPoll::AuthenticatedSourceReadRequired => {
                    return Ok(
                        RowCodeWhirRelationPolynomialReaderPoll::AuthenticatedSourceReadRequired,
                    );
                }
            };
            let (polynomial, replay_identity) = provided.into_parts();
            if replay_identity != self.expected_replay_identity {
                return Err(RowCodeWhirRelationPolynomialReaderError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            validate_source_column(&self.descriptor, &polynomial, self.trace_domain_size)
                .map_err(RowCodeWhirRelationPolynomialReaderError::Prover)?;
            self.polynomial = Some(polynomial);
            return Ok(RowCodeWhirRelationPolynomialReaderPoll::ArithmeticStepCompleted);
        }
        let _ = (executor, storage);
        Ok(RowCodeWhirRelationPolynomialReaderPoll::Complete)
    }

    fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let polynomial = self
            .polynomial
            .ok_or(CommonProofProverError::InvalidColumn)?;
        match self.private_mask {
            Some(private_mask) => {
                apply_trace_mask(polynomial, self.trace_domain_size, private_mask)
            }
            None => Ok(polynomial),
        }
    }
}

struct RecomputedReversedPolynomialReader {
    source_reader: Box<RowCodeWhirRelationPolynomialReader>,
    trace_domain_size: u64,
    unmasked_reversed: Option<CommonProofSourcePolynomial>,
    private_mask: Option<CommonProofSourcePolynomial>,
}

impl RecomputedReversedPolynomialReader {
    fn advance<Storage: ProofExternalMemory>(
        &mut self,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        RowCodeWhirRelationPolynomialReaderPoll,
        RowCodeWhirRelationPolynomialReaderError<Storage::Error>,
    > {
        if self.unmasked_reversed.is_none() {
            match self
                .source_reader
                .advance(source_provider, executor, storage)?
            {
                RowCodeWhirRelationPolynomialReaderPoll::Complete => {
                    let source_reader = core::mem::replace(
                        &mut self.source_reader,
                        Box::new(RowCodeWhirRelationPolynomialReader::Consumed),
                    );
                    let source = source_reader
                        .finish()
                        .map_err(RowCodeWhirRelationPolynomialReaderError::Prover)?;
                    self.unmasked_reversed = Some(
                        reconstruct_reversed_polynomial(self.trace_domain_size, source)
                            .map_err(RowCodeWhirRelationPolynomialReaderError::Prover)?,
                    );
                    return Ok(RowCodeWhirRelationPolynomialReaderPoll::ArithmeticStepCompleted);
                }
                progress => return Ok(progress),
            }
        }
        Ok(RowCodeWhirRelationPolynomialReaderPoll::Complete)
    }

    fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        let unmasked_reversed = self
            .unmasked_reversed
            .ok_or(CommonProofProverError::InvalidColumn)?;
        match self.private_mask {
            Some(private_mask) => {
                apply_trace_mask(unmasked_reversed, self.trace_domain_size, private_mask)
            }
            None => Ok(unmasked_reversed),
        }
    }
}

fn reconstruct_reversed_polynomial(
    trace_domain_size: u64,
    source: CommonProofSourcePolynomial,
) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
    let trace_domain = ProofEvaluationDomain::new_subgroup(
        usize::try_from(trace_domain_size).map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    let mut reversed_rows =
        crate::bgv::proof_suite::prover::base_trace_rows(&source, trace_domain)?;
    drop(source);
    reversed_rows.reverse();
    trace_domain.interpolate_base_polynomial_in_place(&mut reversed_rows)?;
    Ok(CommonProofSourcePolynomial::from_protected_base_coefficients(reversed_rows))
}

struct RecomputedAuxiliaryPolynomialReader {
    reconstruction: CommonProofAuxiliaryColumnReconstructionCursor,
    input_readers: Vec<(u32, RowCodeWhirRelationPolynomialReader)>,
    next_input_index: usize,
    private_mask: Zeroizing<Vec<ProofBaseFieldElement>>,
}

impl RecomputedAuxiliaryPolynomialReader {
    fn new(
        reconstruction: CommonProofAuxiliaryColumnReconstructionCursor,
        input_readers: Vec<(u32, RowCodeWhirRelationPolynomialReader)>,
        private_mask: Option<CommonProofSourcePolynomial>,
    ) -> Result<Self, CommonProofProverError> {
        let mask_coefficient_count = reconstruction.mask_coefficient_count();
        let private_mask = match private_mask {
            Some(CommonProofSourcePolynomial::Base(coefficients))
                if coefficients.len() == mask_coefficient_count =>
            {
                coefficients
            }
            None if mask_coefficient_count == 0 => Zeroizing::new(Vec::new()),
            _ => return Err(CommonProofProverError::InvalidMask),
        };
        if input_readers
            .iter()
            .map(|(column_ordinal, _)| *column_ordinal)
            .ne(reconstruction
                .ordered_input_column_ordinals()
                .iter()
                .copied())
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        Ok(Self {
            reconstruction,
            input_readers,
            next_input_index: 0,
            private_mask,
        })
    }

    fn advance<Storage: ProofExternalMemory>(
        &mut self,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        RowCodeWhirRelationPolynomialReaderPoll,
        RowCodeWhirRelationPolynomialReaderError<Storage::Error>,
    > {
        if let Some((column_ordinal, reader)) = self.input_readers.get_mut(self.next_input_index) {
            match reader.advance(source_provider, executor, storage)? {
                RowCodeWhirRelationPolynomialReaderPoll::Complete => {
                    let reader =
                        core::mem::replace(reader, RowCodeWhirRelationPolynomialReader::Consumed);
                    self.reconstruction
                        .accept_input_column(
                            *column_ordinal,
                            reader
                                .finish()
                                .map_err(RowCodeWhirRelationPolynomialReaderError::Prover)?,
                        )
                        .map_err(RowCodeWhirRelationPolynomialReaderError::Prover)?;
                    self.next_input_index = self.next_input_index.checked_add(1).ok_or(
                        RowCodeWhirRelationPolynomialReaderError::Prover(
                            CommonProofProverError::CountOverflow,
                        ),
                    )?;
                    return Ok(RowCodeWhirRelationPolynomialReaderPoll::ArithmeticStepCompleted);
                }
                progress => return Ok(progress),
            }
        }
        Ok(RowCodeWhirRelationPolynomialReaderPoll::Complete)
    }

    fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        if self.next_input_index != self.input_readers.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.reconstruction.finish(self.private_mask)
    }
}

enum RowCodeWhirRelationPolynomialReader {
    Stored(CommonProofReplayPolynomialReader),
    RecomputedSource(RecomputedSourcePolynomialReader),
    RecomputedReversed(RecomputedReversedPolynomialReader),
    RecomputedAuxiliary(RecomputedAuxiliaryPolynomialReader),
    Consumed,
}

impl RowCodeWhirRelationPolynomialReader {
    fn advance<Storage: ProofExternalMemory>(
        &mut self,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        RowCodeWhirRelationPolynomialReaderPoll,
        RowCodeWhirRelationPolynomialReaderError<Storage::Error>,
    > {
        match self {
            Self::Stored(reader) => reader
                .advance(executor, storage)
                .map(|complete| {
                    if complete {
                        RowCodeWhirRelationPolynomialReaderPoll::Complete
                    } else {
                        RowCodeWhirRelationPolynomialReaderPoll::StorageTransactionCompleted
                    }
                })
                .map_err(RowCodeWhirRelationPolynomialReaderError::Storage),
            Self::RecomputedSource(reader) => reader.advance(source_provider, executor, storage),
            Self::RecomputedReversed(reader) => reader.advance(source_provider, executor, storage),
            Self::RecomputedAuxiliary(reader) => reader.advance(source_provider, executor, storage),
            Self::Consumed => Err(RowCodeWhirRelationPolynomialReaderError::Prover(
                CommonProofProverError::InvalidColumn,
            )),
        }
    }

    fn finish(self) -> Result<CommonProofSourcePolynomial, CommonProofProverError> {
        match self {
            Self::Stored(reader) => reader.finish(),
            Self::RecomputedSource(reader) => reader.finish(),
            Self::RecomputedReversed(reader) => reader.finish(),
            Self::RecomputedAuxiliary(reader) => reader.finish(),
            Self::Consumed => Err(CommonProofProverError::InvalidColumn),
        }
    }
}

enum RowCodeWhirRelationPolynomialRangeReader {
    Stored(CommonProofReplayPolynomialRangeReader),
    Recomputed {
        reader: Option<Box<RowCodeWhirRelationPolynomialReader>>,
        coefficient_range: core::ops::Range<usize>,
    },
}

impl RowCodeWhirRelationPolynomialRangeReader {
    fn advance<Storage: ProofExternalMemory>(
        &mut self,
        source_provider: &mut dyn CommonProofSourcePolynomialProvider,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        destination: CommonProofReplayPolynomialRangeDestination<'_>,
    ) -> Result<
        RowCodeWhirRelationPolynomialReaderPoll,
        RowCodeWhirRelationPolynomialReaderError<Storage::Error>,
    > {
        match self {
            Self::Stored(reader) => reader
                .advance(executor, storage, destination)
                .map(|complete| {
                    if complete {
                        RowCodeWhirRelationPolynomialReaderPoll::Complete
                    } else {
                        RowCodeWhirRelationPolynomialReaderPoll::StorageTransactionCompleted
                    }
                })
                .map_err(RowCodeWhirRelationPolynomialReaderError::Storage),
            Self::Recomputed {
                reader,
                coefficient_range,
            } => {
                match reader
                    .as_mut()
                    .ok_or(RowCodeWhirRelationPolynomialReaderError::Prover(
                        CommonProofProverError::InvalidColumn,
                    ))?
                    .advance(source_provider, executor, storage)?
                {
                    RowCodeWhirRelationPolynomialReaderPoll::Complete => {}
                    progress => return Ok(progress),
                }
                let reader =
                    reader
                        .take()
                        .ok_or(RowCodeWhirRelationPolynomialReaderError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ))?;
                let polynomial = reader
                    .finish()
                    .map_err(RowCodeWhirRelationPolynomialReaderError::Prover)?;
                match (polynomial, destination) {
                    (
                        CommonProofSourcePolynomial::Base(coefficients),
                        CommonProofReplayPolynomialRangeDestination::Base(destination),
                    ) if destination.len() == coefficient_range.len()
                        && coefficient_range.end <= coefficients.len() =>
                    {
                        destination.copy_from_slice(&coefficients[coefficient_range.clone()]);
                        Ok(RowCodeWhirRelationPolynomialReaderPoll::Complete)
                    }
                    (
                        CommonProofSourcePolynomial::Extension(coefficients),
                        CommonProofReplayPolynomialRangeDestination::Extension(destination),
                    ) if destination.len() == coefficient_range.len()
                        && coefficient_range.end <= coefficients.len() =>
                    {
                        destination.copy_from_slice(&coefficients[coefficient_range.clone()]);
                        Ok(RowCodeWhirRelationPolynomialReaderPoll::Complete)
                    }
                    _ => Err(RowCodeWhirRelationPolynomialReaderError::Prover(
                        CommonProofProverError::InvalidColumn,
                    )),
                }
            }
        }
    }
}

struct ActiveRowCodeWhirReplayPolynomialReader {
    reader: RowCodeWhirRelationPolynomialReader,
    continuation: RowCodeWhirReplayReadContinuation,
}

const EXACT_BOUND_AUTHENTICATION_LEAVES_PER_POLL: usize = 4_096;

struct ActiveExactBoundTreeAuthenticationBuilder {
    entry: ProofTreeCatalogEntry,
    leaf_count: usize,
    row_width: usize,
    evaluation_domain: ProofEvaluationDomain,
    ordered_column_ordinals: Vec<u32>,
    query_indices: Vec<usize>,
    next_query_position: usize,
    maximum_stripe_leaf_count: usize,
    current_stripe_start: usize,
    current_stripe_end: usize,
    evaluated_column_stripes: Vec<Zeroizing<Vec<ProofBaseFieldElement>>>,
    active_column_dft: Option<BoundedBaseCosetDft>,
    opened_leaves: Vec<ExactBoundLeafOpening>,
    frontier_coordinates: Vec<(u32, u64)>,
    frontier_digests: Vec<Option<[u8; HASH_BYTE_LENGTH]>>,
    pending_left_digests: Vec<Option<[u8; HASH_BYTE_LENGTH]>>,
    next_leaf_index: usize,
    recomputed_root: Option<[u8; HASH_BYTE_LENGTH]>,
}

impl ActiveExactBoundTreeAuthenticationBuilder {
    fn new(
        entry: ProofTreeCatalogEntry,
        leaf_count: usize,
        query_indices: &[usize],
        evaluation_domain: ProofEvaluationDomain,
        ordered_column_ordinals: &[u32],
    ) -> Result<Self, CommonProofProverError> {
        Self::new_with_maximum_stripe_leaf_count(
            entry,
            leaf_count,
            query_indices,
            evaluation_domain,
            ordered_column_ordinals,
            BOUND_TREE_AUTHENTICATION_STRIPE_LEAF_COUNT,
        )
    }

    fn new_with_maximum_stripe_leaf_count(
        entry: ProofTreeCatalogEntry,
        leaf_count: usize,
        query_indices: &[usize],
        evaluation_domain: ProofEvaluationDomain,
        ordered_column_ordinals: &[u32],
        maximum_stripe_leaf_count: usize,
    ) -> Result<Self, CommonProofProverError> {
        let evaluation_count = leaf_count
            .checked_mul(2)
            .ok_or(CommonProofProverError::CountOverflow)?;
        let row_width = entry
            .materialized_row_width()
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        if leaf_count == 0
            || !leaf_count.is_power_of_two()
            || row_width == 0
            || entry.bound_root().is_none()
            || evaluation_domain.size() != evaluation_count
            || ordered_column_ordinals.len() != row_width
            || maximum_stripe_leaf_count == 0
            || !maximum_stripe_leaf_count.is_power_of_two()
            || query_indices.is_empty()
            || query_indices.windows(2).any(|pair| pair[0] >= pair[1])
            || query_indices
                .last()
                .is_some_and(|leaf_index| *leaf_index >= leaf_count)
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let stripe_leaf_count = leaf_count.min(maximum_stripe_leaf_count);
        let algorithm_live_byte_length = evaluation_count
            .checked_add(
                stripe_leaf_count
                    .checked_mul(2)
                    .and_then(|value_count| value_count.checked_mul(row_width))
                    .ok_or(CommonProofProverError::CountOverflow)?,
            )
            .and_then(|element_count| element_count.checked_mul(size_of::<ProofBaseFieldElement>()))
            .ok_or(CommonProofProverError::CountOverflow)?;
        if u64::try_from(algorithm_live_byte_length).map_or(true, |byte_length| {
            byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        }) {
            return Err(CommonProofProverError::ResidentMemoryLimitExceeded);
        }
        let query_indices_u64 = query_indices
            .iter()
            .copied()
            .map(|leaf_index| {
                u64::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let frontier_coordinates = crate::bgv::proof_suite::merkle::minimal_frontier_coordinates(
            &query_indices_u64,
            leaf_count,
        )
        .map_err(|_| CommonProofProverError::InvalidOpening)?;
        let frontier_digests = vec![None; frontier_coordinates.len()];
        let pending_left_digests = vec![None; leaf_count.trailing_zeros() as usize];
        let mut retained_query_indices = Vec::new();
        retained_query_indices
            .try_reserve_exact(query_indices.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        retained_query_indices.extend_from_slice(query_indices);
        let mut opened_leaves = Vec::new();
        opened_leaves
            .try_reserve_exact(query_indices.len())
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        Ok(Self {
            entry,
            leaf_count,
            row_width,
            evaluation_domain,
            ordered_column_ordinals: ordered_column_ordinals.to_vec(),
            query_indices: retained_query_indices,
            next_query_position: 0,
            maximum_stripe_leaf_count,
            current_stripe_start: 0,
            current_stripe_end: stripe_leaf_count,
            evaluated_column_stripes: Vec::with_capacity(row_width),
            active_column_dft: None,
            opened_leaves,
            frontier_coordinates,
            frontier_digests,
            pending_left_digests,
            next_leaf_index: 0,
            recomputed_root: None,
        })
    }

    fn next_column_request(&self) -> Option<(usize, u32)> {
        if self.recomputed_root.is_some()
            || self.active_column_dft.is_some()
            || self.evaluated_column_stripes.len() >= self.row_width
            || self.next_leaf_index != self.current_stripe_start
        {
            return None;
        }
        let column_position = self.evaluated_column_stripes.len();
        self.ordered_column_ordinals
            .get(column_position)
            .copied()
            .map(|column_ordinal| (column_position, column_ordinal))
    }

    fn begin_column(
        &mut self,
        column_position: usize,
        column_ordinal: u32,
        coefficients: Zeroizing<Vec<ProofBaseFieldElement>>,
    ) -> Result<(), CommonProofProverError> {
        if self.active_column_dft.is_some()
            || self.next_column_request() != Some((column_position, column_ordinal))
            || coefficients.is_empty()
            || coefficients.len() > self.evaluation_domain.size()
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.active_column_dft = Some(
            BoundedBaseCosetDft::new(coefficients, self.evaluation_domain)
                .map_err(|_| CommonProofProverError::InvalidColumn)?,
        );
        Ok(())
    }

    fn capture_frontier_digest(
        &mut self,
        level: u32,
        node_index: u64,
        digest: [u8; HASH_BYTE_LENGTH],
    ) -> Result<(), CommonProofProverError> {
        let Ok(position) = self
            .frontier_coordinates
            .binary_search(&(level, node_index))
        else {
            return Ok(());
        };
        let slot = self
            .frontier_digests
            .get_mut(position)
            .ok_or(CommonProofProverError::InvalidOpening)?;
        if slot.replace(digest).is_some() {
            return Err(CommonProofProverError::InvalidOpening);
        }
        Ok(())
    }

    fn poll(
        &mut self,
        source_polynomial_provider: &mut dyn CommonProofSourcePolynomialProvider,
        request_context: CommonProofSourcePolynomialRequestContext,
    ) -> Result<bool, CommonProofProverError> {
        if self.recomputed_root.is_some() || self.next_leaf_index >= self.leaf_count {
            return Err(CommonProofProverError::InvalidTree);
        }
        if let Some(active_dft) = self.active_column_dft.as_mut() {
            if !active_dft
                .poll()
                .map_err(|_| CommonProofProverError::InvalidColumn)?
            {
                return Ok(false);
            }
            let evaluations = self
                .active_column_dft
                .take()
                .ok_or(CommonProofProverError::InvalidColumn)?
                .into_values()
                .map_err(|_| CommonProofProverError::InvalidColumn)?;
            if evaluations.len() != self.evaluation_domain.size()
                || self.current_stripe_end <= self.current_stripe_start
                || self.current_stripe_end > self.leaf_count
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            let stripe_leaf_count = self.current_stripe_end - self.current_stripe_start;
            let mut stripe = Zeroizing::new(Vec::new());
            stripe
                .try_reserve_exact(
                    stripe_leaf_count
                        .checked_mul(2)
                        .ok_or(CommonProofProverError::CountOverflow)?,
                )
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
            stripe.extend_from_slice(
                &evaluations[self.current_stripe_start..self.current_stripe_end],
            );
            let opposite_start = self
                .leaf_count
                .checked_add(self.current_stripe_start)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let opposite_end = self
                .leaf_count
                .checked_add(self.current_stripe_end)
                .ok_or(CommonProofProverError::CountOverflow)?;
            stripe.extend_from_slice(&evaluations[opposite_start..opposite_end]);
            self.evaluated_column_stripes.push(stripe);
            return Ok(false);
        }
        if self.evaluated_column_stripes.len() != self.row_width
            || self.next_leaf_index < self.current_stripe_start
            || self.next_leaf_index >= self.current_stripe_end
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let poll_end = self
            .next_leaf_index
            .checked_add(EXACT_BOUND_AUTHENTICATION_LEAVES_PER_POLL)
            .ok_or(CommonProofProverError::CountOverflow)?
            .min(self.current_stripe_end);
        while self.next_leaf_index < poll_end {
            let leaf_index = self.next_leaf_index;
            let stripe_leaf_index = leaf_index - self.current_stripe_start;
            let stripe_leaf_count = self.current_stripe_end - self.current_stripe_start;
            let opposite_stripe_leaf_index = stripe_leaf_count
                .checked_add(stripe_leaf_index)
                .ok_or(CommonProofProverError::CountOverflow)?;
            let first_point_values = self
                .evaluated_column_stripes
                .iter()
                .map(|evaluations| evaluations[stripe_leaf_index])
                .collect::<Vec<_>>();
            let opposite_point_values = self
                .evaluated_column_stripes
                .iter()
                .map(|evaluations| evaluations[opposite_stripe_leaf_index])
                .collect::<Vec<_>>();
            let leaf_index_u64 =
                u64::try_from(leaf_index).map_err(|_| CommonProofProverError::CountOverflow)?;
            let persistent_salt = if self.entry.requires_persistent_leaf_salt() {
                let expected_root = self
                    .entry
                    .bound_root()
                    .ok_or(CommonProofProverError::InvalidTree)?;
                source_polynomial_provider
                    .provide_bound_tree_leaf_salt(CommonProofBoundTreeLeafSaltRequest::new(
                        request_context,
                        self.entry.tree_catalog_index(),
                        leaf_index_u64,
                        expected_root,
                    ))?
                    .ok_or(CommonProofProverError::InvalidOpening)?
                    .into()
            } else {
                None
            };
            let (_, mut digest) = self
                .entry
                .encode_materialized_leaf(
                    leaf_index_u64,
                    persistent_salt,
                    Zeroizing::new(
                        first_point_values
                            .iter()
                            .copied()
                            .map(ProofTreeValue::Base)
                            .collect(),
                    ),
                    Zeroizing::new(
                        opposite_point_values
                            .iter()
                            .copied()
                            .map(ProofTreeValue::Base)
                            .collect(),
                    ),
                )
                .map_err(|_| CommonProofProverError::InvalidTree)?;
            if self.query_indices.get(self.next_query_position).copied() == Some(leaf_index) {
                self.opened_leaves.push(ExactBoundLeafOpening::new(
                    persistent_salt,
                    first_point_values,
                    opposite_point_values,
                ));
                self.next_query_position = self
                    .next_query_position
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
            }
            let mut level = 0_usize;
            let mut node_index = leaf_index_u64;
            self.capture_frontier_digest(0, node_index, digest)?;
            while level < self.pending_left_digests.len() {
                let Some(left_digest) = self.pending_left_digests[level].take() else {
                    self.pending_left_digests[level] = Some(digest);
                    break;
                };
                level = level
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                node_index /= 2;
                digest = self
                    .entry
                    .materialized_parent_digest(
                        u32::try_from(level).map_err(|_| CommonProofProverError::CountOverflow)?,
                        node_index,
                        left_digest,
                        digest,
                    )
                    .map_err(|_| CommonProofProverError::InvalidTree)?;
                self.capture_frontier_digest(
                    u32::try_from(level).map_err(|_| CommonProofProverError::CountOverflow)?,
                    node_index,
                    digest,
                )?;
            }
            if level == self.pending_left_digests.len()
                && (leaf_index != self.leaf_count - 1
                    || self.recomputed_root.replace(digest).is_some())
            {
                return Err(CommonProofProverError::InvalidTree);
            }
            self.next_leaf_index = self
                .next_leaf_index
                .checked_add(1)
                .ok_or(CommonProofProverError::CountOverflow)?;
        }
        if self.next_leaf_index == self.current_stripe_end {
            self.evaluated_column_stripes.clear();
            if self.next_leaf_index < self.leaf_count {
                self.current_stripe_start = self.current_stripe_end;
                self.current_stripe_end = self
                    .current_stripe_start
                    .saturating_add(self.maximum_stripe_leaf_count)
                    .min(self.leaf_count);
            }
        }
        Ok(self.next_leaf_index == self.leaf_count)
    }

    fn finish(self) -> Result<ExactBoundTreeAuthentication, CommonProofProverError> {
        if self.next_leaf_index != self.leaf_count
            || self.current_stripe_end != self.leaf_count
            || self.active_column_dft.is_some()
            || !self.evaluated_column_stripes.is_empty()
            || self.next_query_position != self.query_indices.len()
            || self.opened_leaves.len() != self.query_indices.len()
            || self.pending_left_digests.iter().any(Option::is_some)
            || self.recomputed_root != self.entry.bound_root()
        {
            return Err(CommonProofProverError::InvalidTree);
        }
        let frontier = self
            .frontier_digests
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CommonProofProverError::InvalidOpening)?;
        Ok(ExactBoundTreeAuthentication::new(
            self.opened_leaves,
            frontier,
        ))
    }
}

fn row_code_whir_bound_tree_catalog_entries(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_trees: &[RelationProofTreeInput],
) -> Result<Vec<ProofTreeCatalogEntry>, CommonProofProverError> {
    let entries = build_relation_bound_public_tree_catalog_entries(relation_trees)
        .map_err(|_| CommonProofProverError::InvalidTree)?;
    if entries.len() != construction_plan.bound_trees.len() {
        return Err(CommonProofProverError::InvalidTree);
    }
    for (bound_tree_index, (planned_tree, entry)) in construction_plan
        .bound_trees
        .iter()
        .zip(&entries)
        .enumerate()
    {
        let construction_matches = match planned_tree.construction_kind {
            BoundTreeConstructionKind::CommittedMaterial => {
                entry.requires_persistent_leaf_salt() && !entry.uses_setup_polynomial_construction()
            }
            BoundTreeConstructionKind::SetupPolynomial => {
                !entry.requires_persistent_leaf_salt() && entry.uses_setup_polynomial_construction()
            }
        };
        if usize::try_from(planned_tree.bound_tree_ordinal).ok() != Some(bound_tree_index)
            || u16::try_from(planned_tree.relation_tree_ordinal).ok()
                != Some(entry.tree_catalog_index())
            || entry.bound_root().is_none()
            || entry.materialized_row_width().ok() != Some(planned_tree.ordered_columns.len())
            || !construction_matches
        {
            return Err(CommonProofProverError::InvalidTree);
        }
    }
    Ok(entries)
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
    reader: RowCodeWhirRelationPolynomialRangeReader,
    source_range: ExactSameSecretAggregateSourceRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveRowCodeWhirQuotientTransformPhase {
    Reading,
    Transforming,
    Writing,
    Completing,
}

struct ActiveRowCodeWhirQuotientTransform {
    transform_key: CommonProofQuotientConstraintTransformKey,
    plan: RowCodeWhirQuotientColumnTransformPlan,
    phase: ActiveRowCodeWhirQuotientTransformPhase,
    reader: Option<RowCodeWhirRelationPolynomialReader>,
    polynomial: Option<CommonProofSourcePolynomial>,
    writer: Option<CommonProofReplayPolynomialWriter>,
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
    external_memory_read_traffic: RowCodeWhirExternalMemoryReadTraffic,
    external_memory_transaction_traffic: RowCodeWhirExternalMemoryTransactionTraffic,
    relation_polynomial_shapes: BTreeMap<u32, (RelationColumnValueType, usize)>,
    auxiliary_reconstruction_catalog: CommonProofAuxiliaryColumnReconstructionCatalog,
    opened_polynomial_plans:
        BTreeMap<RowCodeWhirOpenedPolynomialSource, CommonProofReplayPolynomialPlan>,
    quotient_transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, RowCodeWhirQuotientColumnTransformPlan>,
    aggregate_source_table: AggregateSourceTable,
    aggregate_residuals: Vec<ExternalPolynomialVector>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RowCodeWhirExternalMemoryReadTraffic {
    opened_polynomial_replay_byte_length: u64,
    quotient_transform_byte_length: u64,
    aggregate_source_byte_length: u64,
}

impl RowCodeWhirExternalMemoryReadTraffic {
    fn total_byte_length(self) -> Option<u64> {
        self.opened_polynomial_replay_byte_length
            .checked_add(self.quotient_transform_byte_length)?
            .checked_add(self.aggregate_source_byte_length)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RowCodeWhirExternalMemoryTransactionTraffic {
    initialization_count: u64,
    opened_polynomial_replay_count: u64,
    quotient_transform_count: u64,
    pre_retained_deletion_count: u64,
    aggregate_source_count: u64,
}

impl RowCodeWhirExternalMemoryTransactionTraffic {
    fn total_count(self) -> Option<u64> {
        self.initialization_count
            .checked_add(self.opened_polynomial_replay_count)?
            .checked_add(self.quotient_transform_count)?
            .checked_add(self.pre_retained_deletion_count)?
            .checked_add(self.aggregate_source_count)
    }
}

const MAXIMUM_PACKED_REPLAY_OBJECT_BYTE_LENGTH: u64 =
    64 * MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as u64;

#[derive(Clone, Copy)]
struct PackedReplayPolynomialDescriptor<Key> {
    key: Key,
    value_type: RelationColumnValueType,
    coefficient_count: usize,
    encoding: CommonProofReplayPolynomialEncoding,
    exact_byte_length: u64,
    total_read_count: u64,
}

impl<Key: Copy> PackedReplayPolynomialDescriptor<Key> {
    fn new(
        key: Key,
        value_type: RelationColumnValueType,
        coefficient_count: usize,
        total_read_count: u64,
    ) -> Result<Self, CommonProofGenerationInitializationError> {
        Self::new_with_encoding(
            key,
            value_type,
            coefficient_count,
            total_read_count,
            CommonProofReplayPolynomialEncoding::CanonicalCoefficients,
        )
    }

    fn new_with_encoding(
        key: Key,
        value_type: RelationColumnValueType,
        coefficient_count: usize,
        total_read_count: u64,
        encoding: CommonProofReplayPolynomialEncoding,
    ) -> Result<Self, CommonProofGenerationInitializationError> {
        let exact_byte_length = CommonProofReplayPolynomialPlan::for_object_segment_with_encoding(
            ProofExternalMemoryObject::new(0),
            0,
            true,
            value_type,
            coefficient_count,
            encoding,
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?
        .exact_byte_length();
        Ok(Self {
            key,
            value_type,
            coefficient_count,
            encoding,
            exact_byte_length,
            total_read_count,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn append_packed_replay_polynomial_plans<Key: Copy + Ord>(
    descriptors: &[PackedReplayPolynomialDescriptor<Key>],
    protection: ProofExternalMemoryProtection,
    issued_step: u32,
    object_plans: &mut Vec<ProofExternalMemoryObjectPlan>,
    polynomial_plans: &mut BTreeMap<Key, CommonProofReplayPolynomialPlan>,
    maximum_total_written_byte_length: &mut u64,
    maximum_total_read_byte_length: &mut u64,
    maximum_transaction_count: &mut u64,
) -> Result<(), CommonProofGenerationInitializationError> {
    let maximum_chunk_byte_length =
        u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
    let mut group_start = 0_usize;
    while group_start < descriptors.len() {
        let mut group_end = group_start;
        let mut group_byte_length = 0_u64;
        while let Some(descriptor) = descriptors.get(group_end) {
            let next_group_byte_length = group_byte_length
                .checked_add(descriptor.exact_byte_length)
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            if group_end > group_start
                && next_group_byte_length > MAXIMUM_PACKED_REPLAY_OBJECT_BYTE_LENGTH
            {
                break;
            }
            group_byte_length = next_group_byte_length;
            group_end = group_end.checked_add(1).ok_or(
                CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ),
            )?;
            if group_byte_length >= MAXIMUM_PACKED_REPLAY_OBJECT_BYTE_LENGTH {
                break;
            }
        }
        if group_end == group_start || group_byte_length == 0 {
            return Err(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::InvalidPlan,
            ));
        }

        let object =
            ProofExternalMemoryObject::new(u32::try_from(object_plans.len()).map_err(|_| {
                CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                )
            })?);
        let mut object_byte_offset = 0_u64;
        let mut maximum_append_count = 0_u64;
        let mut object_transaction_count = 2_u64;
        for (relative_index, descriptor) in descriptors[group_start..group_end].iter().enumerate() {
            let seals_object = relative_index + 1 == group_end - group_start;
            let polynomial_plan =
                CommonProofReplayPolynomialPlan::for_object_segment_with_encoding(
                    object,
                    object_byte_offset,
                    seals_object,
                    descriptor.value_type,
                    descriptor.coefficient_count,
                    descriptor.encoding,
                )
                .map_err(CommonProofGenerationInitializationError::Prover)?;
            if polynomial_plan.exact_byte_length() != descriptor.exact_byte_length
                || polynomial_plans
                    .insert(descriptor.key, polynomial_plan)
                    .is_some()
            {
                return Err(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ));
            }
            let segment_append_count = descriptor
                .exact_byte_length
                .div_ceil(maximum_chunk_byte_length);
            maximum_append_count = maximum_append_count
                .checked_add(segment_append_count)
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            object_transaction_count = object_transaction_count
                .checked_add(segment_append_count)
                .and_then(|count| {
                    segment_append_count
                        .checked_mul(descriptor.total_read_count)
                        .and_then(|reads| count.checked_add(reads))
                })
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            *maximum_total_read_byte_length = maximum_total_read_byte_length
                .checked_add(
                    descriptor
                        .exact_byte_length
                        .checked_mul(descriptor.total_read_count)
                        .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                            ProofExternalMemoryError::ResourceLimitExceeded,
                        ))?,
                )
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
            object_byte_offset = object_byte_offset
                .checked_add(descriptor.exact_byte_length)
                .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                    ProofExternalMemoryError::ResourceLimitExceeded,
                ))?;
        }
        if object_byte_offset != group_byte_length {
            return Err(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::InvalidPlan,
            ));
        }
        object_plans.push(
            ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                object,
                protection,
                group_byte_length,
                maximum_append_count,
                issued_step,
                issued_step,
                issued_step,
            ),
        );
        *maximum_total_written_byte_length = maximum_total_written_byte_length
            .checked_add(group_byte_length)
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        *maximum_transaction_count = maximum_transaction_count
            .checked_add(object_transaction_count)
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        group_start = group_end;
    }
    Ok(())
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

        let auxiliary_columns = construction_plan
            .auxiliary_phase
            .iter()
            .flat_map(|phase| &phase.rows)
            .flat_map(|row| row.logical_polynomial_chunks.iter().flatten())
            .map(|chunk| chunk.column_ordinal)
            .collect::<BTreeSet<_>>();
        let mut bound_tree_columns = BTreeSet::new();
        for tree in variant.ordered_trees() {
            let RelationTreeDescriptor::BoundPublic {
                ordered_column_ordinals,
                ..
            } = tree
            else {
                continue;
            };
            for column_ordinal in ordered_column_ordinals {
                bound_tree_columns.insert(*column_ordinal);
            }
        }
        let mut replay_columns = requested_source_columns.clone();
        replay_columns.extend(reversed_columns.iter().copied());
        replay_columns.extend(auxiliary_columns.iter().copied());
        replay_columns.extend(bound_tree_columns);

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
        let mut object_plans = Vec::new();
        let mut maximum_total_written_byte_length = 0_u64;
        let mut opened_polynomial_replay_read_byte_length = 0_u64;
        let initialization_transaction_count = 1_u64;
        let mut maximum_transaction_count = initialization_transaction_count;

        let ordered_auxiliary_columns = ordered_integer_lift_auxiliary_column_ordinals(variant)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        if ordered_auxiliary_columns
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != auxiliary_columns
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let auxiliary_reconstruction_catalog =
            CommonProofAuxiliaryColumnReconstructionCatalog::new(variant)
                .map_err(CommonProofGenerationInitializationError::Prover)?;
        if auxiliary_reconstruction_catalog
            .ordered_column_ordinals()
            .collect::<BTreeSet<_>>()
            != auxiliary_columns
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }

        let replay_shape = |column_ordinal| {
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
            Ok::<_, CommonProofGenerationInitializationError>((
                descriptor.value_type(),
                coefficient_count,
            ))
        };
        let quotient_phase_lane_count = u64::try_from(
            construction_plan
                .quotient_phase
                .geometry
                .encoded_column_count
                .div_ceil(MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT),
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
        let mut opened_descriptors = Vec::new();
        let aggregate_source_materialization_pass_count =
            aggregate_source_materialization_pass_count(construction_plan)
                .map_err(CommonProofGenerationInitializationError::Prover)?;
        for source in expected_opened_sources.iter().copied() {
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
            let phase_read_count = opened_source_row_use_counts
                .get(&source)
                .copied()
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidColumn,
                ))?
                .checked_mul(quotient_phase_lane_count)
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
                .and_then(|count| {
                    opened_source_row_use_counts.get(&source).copied().and_then(
                        |aggregate_replay_count| {
                            aggregate_replay_count
                                .checked_mul(aggregate_source_materialization_pass_count)
                                .and_then(|replay_count| count.checked_add(replay_count))
                        },
                    )
                })
                .ok_or(CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::CountOverflow,
                ))?;
            opened_descriptors.push(PackedReplayPolynomialDescriptor::new(
                source,
                RelationColumnValueType::ChallengeExtension,
                coefficient_count,
                total_read_count,
            )?);
        }
        append_packed_replay_polynomial_plans(
            &opened_descriptors,
            protection,
            AUXILIARY_REPLAY_ISSUED_STEP,
            &mut object_plans,
            &mut opened_polynomial_plans,
            &mut maximum_total_written_byte_length,
            &mut opened_polynomial_replay_read_byte_length,
            &mut maximum_transaction_count,
        )?;
        if opened_polynomial_plans
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != expected_opened_sources
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let opened_polynomial_replay_transaction_count = maximum_transaction_count
            .checked_sub(initialization_transaction_count)
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::InvalidPlan,
            ))?;
        let replay_object_plan_count = object_plans.len();
        let evaluation_domain = construction_plan
            .quotient_computation_evaluation_domain(relation_context)
            .map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidQuotient,
                )
            })?;
        let relation_polynomial_shapes = replay_columns
            .iter()
            .copied()
            .map(|column_ordinal| {
                let (value_type, coefficient_count) = replay_shape(column_ordinal)?;
                Ok((column_ordinal, (value_type, coefficient_count)))
            })
            .collect::<Result<BTreeMap<_, _>, CommonProofGenerationInitializationError>>()?;
        let quotient_source_plans = relation_polynomial_shapes
            .iter()
            .map(|(column_ordinal, (value_type, coefficient_count))| {
                Ok((
                    *column_ordinal,
                    RowCodeWhirQuotientColumnSourcePlan::new(*value_type, *coefficient_count),
                ))
            })
            .collect::<Result<BTreeMap<_, _>, CommonProofGenerationInitializationError>>()?;
        if quotient_source_plans
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != replay_columns
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidColumn,
            ));
        }
        let quotient_transform_storage_plan: super::RowCodeWhirQuotientTransformStoragePlan =
            plan_row_code_whir_quotient_transform_storage(
                super::RowCodeWhirQuotientTransformStorageRequest {
                    variant,
                    relation_context,
                    evaluation_domain,
                    relation_replay_polynomial_plans: &quotient_source_plans,
                    first_free_object_ordinal: u32::try_from(object_plans.len()).map_err(|_| {
                        CommonProofGenerationInitializationError::StoragePlan(
                            ProofExternalMemoryError::ResourceLimitExceeded,
                        )
                    })?,
                    first_executor_step: FIRST_QUOTIENT_TRANSFORM_STEP,
                    maximum_chunk_byte_length:
                        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
                    protection,
                },
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
        for object_plan in &mut object_plans {
            *object_plan = ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                object_plan.object(),
                object_plan.protection(),
                object_plan.exact_byte_length(),
                object_plan.maximum_append_count(),
                quotient_materialization_step,
                quotient_materialization_step,
                retained_start_step,
            );
        }
        maximum_total_written_byte_length = maximum_total_written_byte_length
            .checked_add(quotient_transform_storage_plan.total_written_byte_length)
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
        let aggregate_pcs =
            aggregate_wide_pcs_for_construction_plan(construction_plan).map_err(|_| {
                CommonProofGenerationInitializationError::Prover(
                    CommonProofProverError::InvalidInput,
                )
            })?;
        let aggregate_storage_plan = AggregateSourceStoragePlan::try_new(
            &aggregate_pcs,
            construction_plan.selected_parameters().table_variable_count,
            construction_plan.aggregate_table_width(),
            construction_plan.selected_parameters().folding_factor,
            construction_plan.aggregate_logical_column_count(),
            quotient_transform_storage_plan.next_free_object_ordinal,
        )
        .map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::InvalidInput)
        })?;
        let (aggregate_external_memory_plan, aggregate_source_table, aggregate_residuals) =
            aggregate_storage_plan.into_parts();
        if aggregate_external_memory_plan.maximum_chunk_byte_length()
            != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            || aggregate_external_memory_plan.maximum_transaction_payload_byte_length()
                != maximum_chunk_byte_length
        {
            return Err(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::InvalidPlan,
            ));
        }
        let step_count = retained_start_step
            .checked_add(aggregate_external_memory_plan.step_count())
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        maximum_total_written_byte_length = maximum_total_written_byte_length
            .checked_add(aggregate_external_memory_plan.maximum_total_written_byte_length())
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        let external_memory_read_traffic = RowCodeWhirExternalMemoryReadTraffic {
            opened_polynomial_replay_byte_length: opened_polynomial_replay_read_byte_length,
            quotient_transform_byte_length: quotient_transform_storage_plan.total_read_byte_length,
            aggregate_source_byte_length: aggregate_external_memory_plan
                .maximum_total_read_byte_length(),
        };
        let maximum_total_read_byte_length = external_memory_read_traffic
            .total_byte_length()
            .ok_or(CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ))?;
        let external_memory_transaction_traffic = RowCodeWhirExternalMemoryTransactionTraffic {
            initialization_count: initialization_transaction_count,
            opened_polynomial_replay_count: opened_polynomial_replay_transaction_count,
            quotient_transform_count: quotient_transform_storage_plan
                .transaction_count_excluding_deletions,
            pre_retained_deletion_count: pre_retained_deletion_transaction_count,
            aggregate_source_count: aggregate_external_memory_plan.maximum_transaction_count(),
        };
        let maximum_transaction_count = external_memory_transaction_traffic.total_count().ok_or(
            CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::ResourceLimitExceeded,
            ),
        )?;
        for object_plan in aggregate_external_memory_plan.into_object_plans() {
            object_plans.push(
                ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                    object_plan.object(),
                    object_plan.protection(),
                    object_plan.exact_byte_length(),
                    object_plan.maximum_append_count(),
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
                ),
            );
        }
        let final_relation_replay_step = step_count.checked_sub(1).ok_or(
            CommonProofGenerationInitializationError::StoragePlan(
                ProofExternalMemoryError::InvalidPlan,
            ),
        )?;
        for object_plan in object_plans.iter_mut().take(replay_object_plan_count) {
            *object_plan = ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                object_plan.object(),
                object_plan.protection(),
                object_plan.exact_byte_length(),
                object_plan.maximum_append_count(),
                object_plan.issued_step(),
                object_plan.seal_step(),
                final_relation_replay_step,
            );
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
            external_memory_read_traffic,
            external_memory_transaction_traffic,
            relation_polynomial_shapes,
            auxiliary_reconstruction_catalog,
            opened_polynomial_plans,
            quotient_transform_plans: quotient_transform_storage_plan.transform_plans,
            aggregate_source_table,
            aggregate_residuals,
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

    let bound_material_salt_trees = construction_plan
        .bound_trees
        .iter()
        .filter(|tree| tree.construction_kind == BoundTreeConstructionKind::CommittedMaterial)
        .collect::<Vec<_>>();
    let expected_bound_material_tree_count = u64::try_from(bound_material_salt_trees.len())
        .map_err(|_| {
            CommonProofGenerationInitializationError::Prover(CommonProofProverError::CountOverflow)
        })?;
    let expected_logical_salt_count = bound_material_salt_trees
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
    let expected_encoded_salt_count = bound_material_salt_trees
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
        || manifest.bound_material_tree_count().map_err(map_error)?
            != expected_bound_material_tree_count
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

    for tree in bound_material_salt_trees {
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
    if storage_plan
        .external_memory_read_traffic
        .total_byte_length()
        != Some(
            storage_plan
                .external_memory_plan
                .maximum_total_read_byte_length(),
        )
    {
        return Err(CommonProofGenerationInitializationError::StoragePlan(
            ProofExternalMemoryError::InvalidPlan,
        ));
    }
    if storage_plan
        .external_memory_transaction_traffic
        .total_count()
        != Some(
            storage_plan
                .external_memory_plan
                .maximum_transaction_count(),
        )
    {
        return Err(CommonProofGenerationInitializationError::StoragePlan(
            ProofExternalMemoryError::InvalidPlan,
        ));
    }
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

fn resident_vector_allocation_byte_length<T>(
    capacity: usize,
) -> Result<u64, CommonProofProverError> {
    u64::try_from(capacity)
        .ok()
        .and_then(|count| {
            u64::try_from(size_of::<T>())
                .ok()
                .and_then(|element_byte_length| count.checked_mul(element_byte_length))
        })
        .ok_or(CommonProofProverError::CountOverflow)
}

fn resident_btree_allocation_upper_bound<Key, Value>(
    entry_count: usize,
) -> Result<u64, CommonProofProverError> {
    const BTREE_ENTRY_LINK_WORD_COUNT: u64 = 6;
    let entry_byte_length = u64::try_from(size_of::<(Key, Value)>())
        .map_err(|_| CommonProofProverError::CountOverflow)?
        .checked_add(
            BTREE_ENTRY_LINK_WORD_COUNT
                .checked_mul(
                    u64::try_from(size_of::<usize>())
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .ok_or(CommonProofProverError::CountOverflow)?,
        )
        .ok_or(CommonProofProverError::CountOverflow)?;
    u64::try_from(entry_count)
        .ok()
        .and_then(|count| count.checked_mul(entry_byte_length))
        .ok_or(CommonProofProverError::CountOverflow)
}

fn add_resident_byte_length(
    total: &mut u64,
    byte_length: u64,
) -> Result<(), CommonProofProverError> {
    *total = total
        .checked_add(byte_length)
        .ok_or(CommonProofProverError::CountOverflow)?;
    Ok(())
}

fn aggregate_source_action_count(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
) -> Result<(usize, usize), CommonProofProverError> {
    let trace_phase_action_count = construction_plan
        .base_phase
        .iter()
        .chain(&construction_plan.auxiliary_phase)
        .flat_map(|phase| &phase.rows)
        .try_fold(0_usize, |count, row| {
            count
                .checked_add(row.logical_polynomial_chunks.iter().flatten().count())
                .ok_or(CommonProofProverError::CountOverflow)
        })?;
    let quotient_phase_action_count =
        construction_plan
            .quotient_phase
            .rows
            .iter()
            .try_fold(0_usize, |count, row| {
                count
                    .checked_add(row.logical_polynomial_chunks.iter().flatten().count())
                    .ok_or(CommonProofProverError::CountOverflow)
            })?;
    let bound_claim_count = relation_variant
        .ordered_opening_claims()
        .iter()
        .filter(|claim| {
            claim
                .column_ordinal()
                .and_then(|column_ordinal| {
                    relation_variant
                        .ordered_columns()
                        .get(column_ordinal as usize)
                })
                .is_some_and(|column| {
                    claim.source_class() == RelationOpeningSourceClass::TreeColumn
                        && matches!(column.origin(), RelationColumnOrigin::BoundTree { .. })
                })
        })
        .count();
    let action_count = trace_phase_action_count
        .checked_add(quotient_phase_action_count)
        .and_then(|count| count.checked_add(bound_claim_count))
        .ok_or(CommonProofProverError::CountOverflow)?;
    Ok((action_count, bound_claim_count))
}

fn aggregate_source_control_payload_byte_length(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
) -> Result<u64, CommonProofProverError> {
    let opening_point_count = construction_plan
        .aggregate_opening_point_count()
        .map_err(|_| CommonProofProverError::InvalidOpening)?;
    let parameters = construction_plan.selected_parameters();
    let selector_count = parameters
        .logical_polynomials_per_physical_row
        .checked_ilog2()
        .ok_or(CommonProofProverError::CountOverflow)? as usize;
    let phase_row_count = construction_plan
        .base_phase
        .iter()
        .chain(&construction_plan.auxiliary_phase)
        .try_fold(
            construction_plan.quotient_phase.rows.len(),
            |count, phase| {
                count
                    .checked_add(phase.rows.len())
                    .ok_or(CommonProofProverError::CountOverflow)
            },
        )?;
    let challenge_count_per_point = selector_count
        .checked_add(phase_row_count)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let (action_count, bound_claim_count) =
        aggregate_source_action_count(construction_plan, relation_variant)?;

    [
        construction_plan
            .resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        relation_context
            .resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        resident_vector_allocation_byte_length::<ExactSameSecretAggregateSourceAction>(
            action_count,
        )?,
        resident_vector_allocation_byte_length::<RowCodeWhirPointRowWeights>(opening_point_count)?,
        resident_vector_allocation_byte_length::<ChallengeField>(
            opening_point_count
                .checked_mul(challenge_count_per_point)
                .ok_or(CommonProofProverError::CountOverflow)?,
        )?,
        resident_vector_allocation_byte_length::<ProofChallengeExtensionElement>(
            opening_point_count,
        )?,
        resident_vector_allocation_byte_length::<RowCodeWhirBoundOpeningClaim>(bound_claim_count)?,
    ]
    .into_iter()
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or(CommonProofProverError::CountOverflow)
    })
}

fn aggregate_source_row_peak_byte_length(
    construction_plan: &RowCodeWhirConstructionPlan,
) -> Result<u64, CommonProofProverError> {
    let parameters = construction_plan.selected_parameters();
    let base_field_element_byte_length = u64::try_from(size_of::<ProofBaseFieldElement>())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let extension_element_byte_length = u64::try_from(size_of::<ProofChallengeExtensionElement>())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let physical_row_witness_value_count = 1_usize
        .checked_shl(
            u32::try_from(parameters.physical_row_witness_variable_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .ok_or(CommonProofProverError::CountOverflow)?;
    let phase_row_witness_byte_length = u64::try_from(physical_row_witness_value_count)
        .ok()
        .and_then(|count| count.checked_mul(base_field_element_byte_length))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let padded_row_byte_length = u64::try_from(physical_row_witness_value_count)
        .ok()
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_mul(base_field_element_byte_length))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let maximum_replay_source_range_byte_length =
        u64::try_from(parameters.logical_polynomial_coefficient_count)
            .ok()
            .and_then(|count| count.checked_mul(extension_element_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
    #[cfg(feature = "primitive-measurement-evidence")]
    let quotient_accumulator_scratch_byte_length = if construction_plan
        .uses_opening_claim_quotient_batch()
        .map_err(|_| CommonProofProverError::InvalidOpening)?
    {
        u64::try_from(
            construction_plan
                .aggregate_opening_point_count()
                .map_err(|_| CommonProofProverError::InvalidOpening)?,
        )
        .ok()
        .and_then(|count| count.checked_mul(3))
        .and_then(|count| count.checked_mul(u64::try_from(size_of::<ChallengeField>()).ok()?))
        .ok_or(CommonProofProverError::CountOverflow)?
    } else {
        0
    };
    #[cfg(not(feature = "primitive-measurement-evidence"))]
    let quotient_accumulator_scratch_byte_length = 0_u64;

    phase_row_witness_byte_length
        .checked_add(padded_row_byte_length.max(maximum_replay_source_range_byte_length))
        .and_then(|total| total.checked_add(quotient_accumulator_scratch_byte_length))
        .ok_or(CommonProofProverError::CountOverflow)
}

#[allow(clippy::too_many_arguments)]
fn derive_generation_liveness(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    relation_trees: &Vec<RelationProofTreeInput>,
    bound_tree_entries: &Vec<ProofTreeCatalogEntry>,
    canonical_header_bytes: &Vec<u8>,
    source_cursor: &CommonProofPreChallengeSourceCursor,
    same_secret_source_manifest: &SameSecretAuthenticatedSourceManifest,
    reversed_column_bindings: &Vec<(u32, u32)>,
    storage_plan: &RowCodeWhirGenerationStoragePlan,
    source_provider: CommonProofSourceProviderMemoryAccounting,
    proof_transport_bridge_byte_length: usize,
) -> Result<CompleteGenerationLiveness, CommonProofProverError> {
    let input = derive_generation_liveness_input(
        construction_plan,
        relation_variant,
        relation_context,
        relation_trees,
        bound_tree_entries,
        canonical_header_bytes,
        source_cursor,
        same_secret_source_manifest,
        reversed_column_bindings,
        storage_plan,
        source_provider,
        proof_transport_bridge_byte_length,
    )?;
    derive_complete_generation_liveness(construction_plan, input)
        .map_err(|_| CommonProofProverError::ResidentMemoryLimitExceeded)
}

#[allow(clippy::too_many_arguments)]
fn derive_generation_liveness_input(
    construction_plan: &RowCodeWhirConstructionPlan,
    relation_variant: &RelationPlanVariant,
    relation_context: &RelationPlanCheckContext,
    relation_trees: &Vec<RelationProofTreeInput>,
    bound_tree_entries: &Vec<ProofTreeCatalogEntry>,
    canonical_header_bytes: &Vec<u8>,
    source_cursor: &CommonProofPreChallengeSourceCursor,
    same_secret_source_manifest: &SameSecretAuthenticatedSourceManifest,
    reversed_column_bindings: &Vec<(u32, u32)>,
    storage_plan: &RowCodeWhirGenerationStoragePlan,
    source_provider: CommonProofSourceProviderMemoryAccounting,
    proof_transport_bridge_byte_length: usize,
) -> Result<CompleteGenerationLivenessInput, CommonProofProverError> {
    let mut engine_control_byte_length =
        u64::try_from(size_of::<RowCodeWhirGenerationStateMachine>())
            .map_err(|_| CommonProofProverError::CountOverflow)?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        construction_plan
            .resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        relation_variant
            .resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        relation_context
            .resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_vector_allocation_byte_length::<u8>(canonical_header_bytes.capacity())?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_vector_allocation_byte_length::<RelationProofTreeInput>(
            relation_trees.capacity(),
        )?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_vector_allocation_byte_length::<ProofTreeCatalogEntry>(
            bound_tree_entries.capacity(),
        )?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        source_cursor.resident_owned_payload_byte_length()?.max(
            source_cursor.completed_replay_identity_catalog_resident_owned_payload_byte_length()?,
        ),
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        same_secret_source_manifest
            .resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_vector_allocation_byte_length::<(u32, u32)>(reversed_column_bindings.capacity())?,
    )?;
    if construction_plan.requires_verified_vss_bound_prerequisite() {
        add_resident_byte_length(
            &mut engine_control_byte_length,
            u64::try_from(size_of::<ExactSameSecretTranscriptPrefixAuthorityBinding>())
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )?;
    }
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_btree_allocation_upper_bound::<u32, (RelationColumnValueType, usize)>(
            storage_plan.relation_polynomial_shapes.len(),
        )?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        storage_plan
            .auxiliary_reconstruction_catalog
            .resident_owned_payload_byte_length()?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_btree_allocation_upper_bound::<
            RowCodeWhirOpenedPolynomialSource,
            CommonProofReplayPolynomialPlan,
        >(storage_plan.opened_polynomial_plans.len())?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_btree_allocation_upper_bound::<
            CommonProofQuotientConstraintTransformKey,
            RowCodeWhirQuotientColumnTransformPlan,
        >(storage_plan.quotient_transform_plans.len())?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        storage_plan
            .aggregate_source_table
            .resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        resident_vector_allocation_byte_length::<ExternalPolynomialVector>(
            storage_plan.aggregate_residuals.capacity(),
        )?,
    )?;
    add_resident_byte_length(
        &mut engine_control_byte_length,
        storage_plan
            .external_memory_plan
            .executor_resident_owned_payload_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )?;

    let auxiliary_liveness = common_proof_auxiliary_materialization_liveness(relation_variant)?;
    let base_field_element_byte_length = u64::try_from(size_of::<ProofBaseFieldElement>())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let extension_element_byte_length = u64::try_from(size_of::<ProofChallengeExtensionElement>())
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let trace_domain_byte_length = relation_variant
        .trace_domain_size()
        .checked_mul(base_field_element_byte_length)
        .ok_or(CommonProofProverError::CountOverflow)?;
    let maximum_private_mask_byte_length =
        u64::try_from(auxiliary_liveness.maximum_private_mask_coefficient_count())
            .ok()
            .and_then(|count| count.checked_mul(base_field_element_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
    let auxiliary_materialization_byte_length =
        u64::try_from(auxiliary_liveness.maximum_synthesis_live_trace_row_count())
            .ok()
            .and_then(|count| count.checked_mul(trace_domain_byte_length))
            .and_then(|byte_length| byte_length.checked_add(maximum_private_mask_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
    let recomputed_auxiliary_reader_byte_length =
        u64::try_from(auxiliary_liveness.maximum_recomputation_live_trace_row_count())
            .ok()
            .and_then(|count| count.checked_mul(trace_domain_byte_length))
            .and_then(|byte_length| byte_length.checked_add(maximum_private_mask_byte_length))
            .ok_or(CommonProofProverError::CountOverflow)?;
    let recomputed_source_reader_byte_length = source_provider
        .maximum_returned_source_polynomial_byte_length()
        .checked_add(trace_domain_byte_length)
        .and_then(|byte_length| byte_length.checked_add(maximum_private_mask_byte_length))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let maximum_replay_reader_byte_length =
        storage_plan.opened_polynomial_plans.values().try_fold(
            recomputed_auxiliary_reader_byte_length.max(recomputed_source_reader_byte_length),
            |maximum_byte_length, plan| {
                Ok::<_, CommonProofProverError>(
                    maximum_byte_length
                        .max(plan.maximum_reader_live_byte_length()?)
                        .max(plan.maximum_writer_live_byte_length()?),
                )
            },
        )?;

    let quotient_evaluation_domain = construction_plan
        .quotient_computation_evaluation_domain(relation_context)
        .map_err(|_| CommonProofProverError::InvalidQuotient)?;
    let quotient_liveness = common_proof_quotient_materialization_liveness(
        relation_variant,
        relation_context,
        quotient_evaluation_domain,
    )?;
    let maximum_transform_byte_length = storage_plan.quotient_transform_plans.values().try_fold(
        0_u64,
        |maximum_byte_length, plan| {
            let source_element_byte_length = match plan.source().value_type() {
                RelationColumnValueType::BaseField => base_field_element_byte_length,
                RelationColumnValueType::ChallengeExtension => extension_element_byte_length,
            };
            let source_byte_length = u64::try_from(plan.source().coefficient_count())
                .ok()
                .and_then(|count| count.checked_mul(source_element_byte_length))
                .ok_or(CommonProofProverError::CountOverflow)?;
            let transformed_byte_length = u64::try_from(plan.evaluation_domain().size())
                .ok()
                .and_then(|count| count.checked_mul(source_element_byte_length))
                .ok_or(CommonProofProverError::CountOverflow)?;
            let reallocation_peak = source_byte_length
                .checked_add(transformed_byte_length)
                .ok_or(CommonProofProverError::CountOverflow)?;
            Ok::<_, CommonProofProverError>(
                maximum_byte_length
                    .max(reallocation_peak)
                    .max(plan.output().maximum_writer_live_byte_length()?),
            )
        },
    )?;
    let quotient_preparation_byte_length = quotient_liveness
        .maximum_materialization_byte_length()
        .checked_add(maximum_transform_byte_length)
        .and_then(|byte_length| {
            byte_length.checked_add(u64::from(
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            ))
        })
        .ok_or(CommonProofProverError::CountOverflow)?;

    let parameters = construction_plan.selected_parameters();
    let aggregate_column_element_count = 1_usize
        .checked_shl(
            u32::try_from(parameters.table_variable_count)
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .ok_or(CommonProofProverError::CountOverflow)?;
    let aggregate_table_width = construction_plan.aggregate_table_width();
    if aggregate_table_width < 2 || !aggregate_table_width.is_power_of_two() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let aggregate_column_byte_length = u64::try_from(aggregate_column_element_count)
        .ok()
        .and_then(|count| count.checked_mul(extension_element_byte_length))
        .ok_or(CommonProofProverError::CountOverflow)?;
    let aggregate_batch_column_count =
        aggregate_source_resident_batch_column_count(construction_plan)?;
    let aggregate_source_batch_byte_length = u64::try_from(aggregate_batch_column_count)
        .ok()
        .and_then(|count| count.checked_mul(aggregate_column_byte_length))
        .and_then(|byte_length| {
            resident_vector_allocation_byte_length::<Vec<ChallengeField>>(
                aggregate_batch_column_count,
            )
            .ok()
            .and_then(|catalog_byte_length| byte_length.checked_add(catalog_byte_length))
        })
        .ok_or(CommonProofProverError::CountOverflow)?;
    // Loading one replay chunk and padding the completed physical row are
    // disjoint snapshots: the final source vector is dropped before padding.
    // The resident witness survives both, so the row peak is the witness plus
    // the larger successor allocation. Candidate quotient scratch is retained
    // across the same phase and is derived by the helper when present.
    let aggregate_source_row_byte_length =
        aggregate_source_row_peak_byte_length(construction_plan)?
            .checked_add(aggregate_source_control_payload_byte_length(
                construction_plan,
                relation_variant,
                relation_context,
            )?)
            .ok_or(CommonProofProverError::CountOverflow)?;

    let canonical_family_body_byte_length =
        canonical_row_code_whir_family_body_byte_length_ceiling(
            construction_plan,
            relation_variant,
            bound_tree_entries,
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
    let proof_accumulator_byte_length = u64::try_from(
        canonical_header_bytes
            .len()
            .checked_add(canonical_family_body_byte_length)
            .ok_or(CommonProofProverError::CountOverflow)?,
    )
    .map_err(|_| CommonProofProverError::CountOverflow)?
    .checked_add(
        noncompact_aggregate_opening_path_byte_length(construction_plan)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    )
    .ok_or(CommonProofProverError::CountOverflow)?;

    let transcript_operation_byte_length = construction_plan
        .transcript_operations_resident_owned_payload_byte_length()
        .map_err(|_| CommonProofProverError::CountOverflow)?;
    let transcript_role_byte_length =
        u64::try_from(construction_plan.transcript_operations().len())
            .ok()
            .and_then(|count| {
                u64::try_from(
                    size_of::<super::construction_plan::RowCodeWhirObservationRole>()
                        + size_of::<super::construction_plan::RowCodeWhirExtensionRole>(),
                )
                .ok()
                .and_then(|width| count.checked_mul(width))
            })
            .ok_or(CommonProofProverError::CountOverflow)?;
    let accepted_out_of_domain_point_byte_length = u64::from(
        construction_plan
            .relation_prefix_schedule()
            .out_of_domain_point_count(),
    )
    .checked_mul(extension_element_byte_length)
    .ok_or(CommonProofProverError::CountOverflow)?;
    let transcript_byte_length = u64::try_from(size_of::<
        crate::bgv::proof_suite::CommonProofTranscript,
    >())
    .map_err(|_| CommonProofProverError::CountOverflow)?
    .checked_add(transcript_operation_byte_length)
    .and_then(|total| total.checked_add(transcript_role_byte_length))
    .and_then(|total| total.checked_add(accepted_out_of_domain_point_byte_length))
    .and_then(|total| {
        total.checked_add(
            u64::try_from(MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH).ok()?,
        )
    })
    .ok_or(CommonProofProverError::CountOverflow)?;

    let hiding_configuration = super::hiding_whir::selected_hiding_whir_config(parameters)
        .map_err(|_| CommonProofProverError::InvalidMask)?;
    let private_material_shape = AggregateWideHidingMaterialShape::derive(&hiding_configuration)
        .map_err(|_| CommonProofProverError::InvalidMask)?;
    let private_material_byte_length =
        u64::try_from(private_material_shape.total_extension_element_count())
            .ok()
            .and_then(|count| count.checked_mul(extension_element_byte_length))
            .and_then(|byte_length| {
                byte_length
                    .checked_add(u64::try_from(PRIVATE_ROW_PAD_SEED_MATERIAL_BYTE_LENGTH).ok()?)
            })
            .ok_or(CommonProofProverError::CountOverflow)?;

    Ok(CompleteGenerationLivenessInput {
        engine_control_byte_length,
        source_provider,
        maximum_replay_reader_byte_length,
        auxiliary_materialization_byte_length,
        quotient_preparation_byte_length,
        aggregate_source_batch_byte_length,
        aggregate_source_row_byte_length,
        aggregate_opening_preparation_byte_length: aggregate_column_byte_length,
        proof_encoder_byte_length: proof_accumulator_byte_length,
        transcript_byte_length,
        private_material_byte_length,
        private_material_partition_transition_byte_length: u64::try_from(
            private_material_shape
                .partitioned_material_dynamic_payload_byte_length()
                .map_err(|_| CommonProofProverError::CountOverflow)?,
        )
        .map_err(|_| CommonProofProverError::CountOverflow)?,
        proof_transport_bridge_byte_length: u64::try_from(proof_transport_bridge_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)?,
    })
}

/// The checked relation-plan state shared by every family as it migrates to
/// the sole row-code/WHIR construction. Same-secret is merely the first
/// production caller; the state itself contains no family selector.
pub(in crate::bgv::proof_suite) struct RowCodeWhirGenerationStateMachine {
    construction_plan: RowCodeWhirConstructionPlan,
    construction_plan_identity_hash: [u8; HASH_BYTE_LENGTH],
    transcript_prefix_authority: RowCodeWhirTranscriptPrefixAuthority,
    authenticated_transcript_prefix: Option<crate::bgv::proof_suite::CommonProofTranscript>,
    row_code_whir_transcript: Option<RowCodeWhirTranscript>,
    canonical_header_bytes: Vec<u8>,
    relation_plan_variant: RelationPlanVariant,
    relation_context: RelationPlanCheckContext,
    relation_trees: Vec<RelationProofTreeInput>,
    bound_tree_entries: Vec<ProofTreeCatalogEntry>,
    source_polynomial_provider: Option<Box<dyn CommonProofSourcePolynomialProvider>>,
    source_request_context: CommonProofSourcePolynomialRequestContext,
    same_secret_source_manifest: SameSecretAuthenticatedSourceManifest,
    source_cursor: Option<CommonProofPreChallengeSourceCursor>,
    source_replay_identity_digest: Option<[u8; HASH_BYTE_LENGTH]>,
    source_replay_identity_catalog: Option<CommonProofSourceReplayIdentityCatalog>,
    reversed_column_bindings: Vec<(u32, u32)>,
    next_reversed_column_binding_index: usize,
    loaded_source_polynomial_count: usize,
    pending_authenticated_source_read: Option<CommonProofAuthenticatedSourceReadRequest>,
    pending_replay_polynomial: Option<PendingRowCodeWhirReplayPolynomial>,
    relation_polynomial_shapes: BTreeMap<u32, (RelationColumnValueType, usize)>,
    auxiliary_reconstruction_catalog: CommonProofAuxiliaryColumnReconstructionCatalog,
    opened_replay_polynomial_plans:
        BTreeMap<RowCodeWhirOpenedPolynomialSource, CommonProofReplayPolynomialPlan>,
    quotient_transform_plans:
        BTreeMap<CommonProofQuotientConstraintTransformKey, RowCodeWhirQuotientColumnTransformPlan>,
    aggregate_source_table: Option<AggregateSourceTable>,
    aggregate_residuals: Option<Vec<ExternalPolynomialVector>>,
    external_memory_executor: Option<ProofExternalMemoryExecutor>,
    external_memory_requirement: CommonProofExternalMemoryRequirement,
    active_replay_polynomial_writer: Option<CommonProofReplayPolynomialWriter>,
    active_replay_polynomial_reader: Option<ActiveRowCodeWhirReplayPolynomialReader>,
    row_pad_seeds: Option<Zeroizing<Box<[PrivateRowPadSeed]>>>,
    phase_commitment_builder: Option<InterleavedColumnCommitmentBuilder>,
    active_phase_commitment: Option<RowCodeWhirPhase>,
    active_phase_materialization_purpose: Option<RowCodeWhirPhaseMaterializationPurpose>,
    active_phase_authenticated_columns: Option<Vec<AuthenticatedColumn>>,
    active_phase_polynomial_reader: Option<RowCodeWhirRelationPolynomialReader>,
    active_phase_polynomial_binding: Option<RowCodeWhirPhasePolynomialBinding>,
    phase_row_witness: Zeroizing<Vec<ProofBaseFieldElement>>,
    active_phase_row_dft: Option<BoundedBaseCosetLaneDft>,
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
    auxiliary_reconstruction_challenges: Vec<RelationApplicationChallengeAssignment>,
    auxiliary_materialization: Option<RowCodeWhirAuxiliaryRelationMaterialization>,
    quotient_materialization: Option<RowCodeWhirQuotientMaterialization>,
    active_quotient_transform: Option<ActiveRowCodeWhirQuotientTransform>,
    pending_quotient_evaluation_read: Option<CommonProofQuotientEvaluationReadRequest>,
    exact_same_secret_aggregate_source: Option<ExactSameSecretAggregateSource>,
    active_aggregate_source_read: Option<ActiveExactSameSecretAggregateSourceRead>,
    active_aggregate_source_batch: Option<ExactSameSecretAggregateSourceBatch>,
    aggregate_source_writer: Option<AggregateSourceWriter>,
    aggregate_source_batch_column_offset: usize,
    exact_same_secret_aggregate_metadata: Option<ExactSameSecretAggregateMetadata>,
    exact_same_secret_aggregate_witness: Option<ExactSameSecretAggregateWitness>,
    exact_same_secret_opening_schedule: Option<RowCodeWhirOpeningSchedule>,
    next_bound_tree_ordinal: usize,
    active_bound_tree_authentication_builder: Option<ActiveExactBoundTreeAuthenticationBuilder>,
    bound_tree_authentications: Vec<ExactBoundTreeAuthentication>,
    aggregate_challenger: Option<ExtensionFieldChallenger>,
    aggregate_wide_hiding_material_generation: Option<AggregateWideHidingMaterialGeneration>,
    aggregate_commitment_generation: Option<StreamingAggregateWideCommitmentGeneration>,
    aggregate_commitment: Option<AggregateWideCommitment>,
    aggregate_wide_pad_commitment: Option<AggregateWideCommitment>,
    aggregate_proof_generation: Option<StreamingAggregateWideProofGeneration>,
    pending_aggregate_checkpoint_boundary: Option<RowCodeWhirCheckpointBoundary>,
    aggregate_wide_opening_proof: Option<AggregateWideOpeningProof>,
    exact_proof_encoder: Option<ExactSameSecretProofSinkEncoder>,
    canonical_output_byte_length: Option<usize>,
    terminal_external_memory_usage: Option<ProofExternalMemoryUsage>,
    phase: RowCodeWhirGenerationPhase,
}

impl RowCodeWhirGenerationStateMachine {
    pub(in crate::bgv::proof_suite) fn new(
        input: CommonProofGenerationInput<'_>,
        construction_plan: &RowCodeWhirConstructionPlan,
        transcript_prefix_authority: RowCodeWhirTranscriptPrefixAuthority,
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
        let retained_construction_plan = construction_plan.clone();
        let verified_vss_binding = transcript_prefix_authority.verified_vss_binding();
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
            || construction_plan.requires_verified_vss_bound_prerequisite()
                != verified_vss_binding.is_some()
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        if let Some(binding) = verified_vss_binding {
            let fiat_shamir_binding = binding.fiat_shamir_binding();
            if fiat_shamir_binding.protocol_version() != input.protocol_version
                || fiat_shamir_binding.suite_identifier() != input.suite_identifier
                || fiat_shamir_binding.application_statement_schema_identifier()
                    != validated_relation_plan.application_statement_schema_identifier()
                || fiat_shamir_binding.relation_plan_hash() != relation_plan_hash
                || fiat_shamir_binding.relation_plan_variant_hash() != relation_plan_variant_hash
                || fiat_shamir_binding.construction_plan_identity_hash()
                    != construction_plan_identity_hash
                || fiat_shamir_binding.oracle_equation_catalog_hash()
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
        }
        validate_generation_relation_trees(&relation_plan_variant, &input.relation_trees)
            .map_err(CommonProofGenerationInitializationError::Prover)?;
        let bound_tree_entries =
            row_code_whir_bound_tree_catalog_entries(construction_plan, &input.relation_trees)
                .map_err(|_| {
                    CommonProofGenerationInitializationError::Prover(
                        CommonProofProverError::InvalidTree,
                    )
                })?;
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
        let source_provider_accounting =
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
        let complete_generation_liveness = derive_generation_liveness(
            &retained_construction_plan,
            &relation_plan_variant,
            input.relation_context,
            &input.relation_trees,
            &bound_tree_entries,
            &canonical_header_bytes,
            &source_cursor,
            &same_secret_source_manifest,
            &reversed_column_bindings,
            &generation_storage_plan,
            source_provider_accounting,
            input.maximum_proof_transport_chunk_byte_length,
        )
        .map_err(CommonProofGenerationInitializationError::Prover)?;
        if complete_generation_liveness.phase_count() == 0
            || complete_generation_liveness.maximum_live_set_byte_length()
                > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        {
            return Err(CommonProofGenerationInitializationError::Prover(
                CommonProofProverError::ResidentMemoryLimitExceeded,
            ));
        }
        let external_memory_executor =
            ProofExternalMemoryExecutor::new(generation_storage_plan.external_memory_plan);
        Ok(Self {
            construction_plan: retained_construction_plan,
            construction_plan_identity_hash,
            transcript_prefix_authority,
            authenticated_transcript_prefix: None,
            row_code_whir_transcript: None,
            canonical_header_bytes,
            relation_plan_variant,
            relation_context: input.relation_context.clone(),
            relation_trees: input.relation_trees,
            bound_tree_entries,
            source_polynomial_provider: Some(input.source_polynomial_provider),
            source_request_context,
            same_secret_source_manifest,
            source_cursor: Some(source_cursor),
            source_replay_identity_digest: None,
            source_replay_identity_catalog: None,
            reversed_column_bindings,
            next_reversed_column_binding_index: 0,
            loaded_source_polynomial_count: 0,
            pending_authenticated_source_read: None,
            pending_replay_polynomial: None,
            relation_polynomial_shapes: generation_storage_plan.relation_polynomial_shapes,
            auxiliary_reconstruction_catalog: generation_storage_plan
                .auxiliary_reconstruction_catalog,
            opened_replay_polynomial_plans: generation_storage_plan.opened_polynomial_plans,
            quotient_transform_plans: generation_storage_plan.quotient_transform_plans,
            aggregate_source_table: Some(generation_storage_plan.aggregate_source_table),
            aggregate_residuals: Some(generation_storage_plan.aggregate_residuals),
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
            phase_row_witness: Zeroizing::new(Vec::new()),
            active_phase_row_dft: None,
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
            auxiliary_reconstruction_challenges: Vec::new(),
            auxiliary_materialization: None,
            quotient_materialization: None,
            active_quotient_transform: None,
            pending_quotient_evaluation_read: None,
            exact_same_secret_aggregate_source: None,
            active_aggregate_source_read: None,
            active_aggregate_source_batch: None,
            aggregate_source_writer: None,
            aggregate_source_batch_column_offset: 0,
            exact_same_secret_aggregate_metadata: None,
            exact_same_secret_aggregate_witness: None,
            exact_same_secret_opening_schedule: None,
            next_bound_tree_ordinal: 0,
            active_bound_tree_authentication_builder: None,
            bound_tree_authentications: Vec::new(),
            aggregate_challenger: None,
            aggregate_wide_hiding_material_generation: None,
            aggregate_commitment_generation: None,
            aggregate_commitment: None,
            aggregate_wide_pad_commitment: None,
            aggregate_proof_generation: None,
            pending_aggregate_checkpoint_boundary: None,
            aggregate_wide_opening_proof: None,
            exact_proof_encoder: None,
            canonical_output_byte_length: None,
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
            | RowCodeWhirGenerationPhase::PersistingAggregateSourceBatch
            | RowCodeWhirGenerationPhase::ReleasingAggregateReplayStorage
            | RowCodeWhirGenerationPhase::SamplingAggregateWideHidingMaterial
            | RowCodeWhirGenerationPhase::CommittingAggregate
            | RowCodeWhirGenerationPhase::PreparingAggregateOpenings
            | RowCodeWhirGenerationPhase::MaterializingBoundAuthentications
            | RowCodeWhirGenerationPhase::MaterializingBasePhaseOpenings
            | RowCodeWhirGenerationPhase::MaterializingAuxiliaryPhaseOpenings
            | RowCodeWhirGenerationPhase::MaterializingQuotientPhaseOpenings
            | RowCodeWhirGenerationPhase::CompletingAggregateCommitment => {
                CommonProofGenerationStage::MaterializingOpeningMask
            }
            RowCodeWhirGenerationPhase::GeneratingAggregateWhirProof => {
                CommonProofGenerationStage::ReducingCommittedOracles
            }
            RowCodeWhirGenerationPhase::AwaitingExactProofAssembly
            | RowCodeWhirGenerationPhase::EncodingExactProofHeader
            | RowCodeWhirGenerationPhase::EncodingExactProof
            | RowCodeWhirGenerationPhase::Complete => CommonProofGenerationStage::Finalizing,
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
            || self.active_phase_row_dft.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        ExactSameSecretAuthenticatedTranscriptPrefixRequest::new(
            self.transcript_prefix_authority
                .verified_vss_binding()
                .cloned()
                .ok_or(CommonProofProverError::InvalidInput)?,
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
        if self.pending_authenticated_source_read != Some(request)
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
        self.canonical_output_byte_length
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
        if self.row_code_whir_transcript.is_none() && self.aggregate_challenger.is_none() {
            return if canonical_cursor_bytes.is_empty() && expected_cursor_digest.is_none() {
                Ok(())
            } else {
                Err(CommonProofProverError::InvalidInput)
            };
        }
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
        let live_cursor = match (
            self.row_code_whir_transcript.as_ref(),
            self.aggregate_challenger.as_ref(),
        ) {
            (Some(transcript), None) => transcript
                .checkpoint_cursor(&self.construction_plan)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
            (None, Some(challenger)) => challenger
                .checkpoint_cursor(&self.construction_plan)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
            _ => return Err(CommonProofProverError::InvalidInput),
        };
        if authenticated_cursor.digest() != expected_cursor_digest
            || live_cursor.digest() != authenticated_cursor.digest()
            || live_cursor.canonical_bytes() != authenticated_cursor.canonical_bytes()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        match (
            self.row_code_whir_transcript.as_mut(),
            self.aggregate_challenger.as_mut(),
        ) {
            (Some(transcript), None) => {
                *transcript = RowCodeWhirTranscript::restore_checkpoint_cursor(
                    &self.construction_plan,
                    &authenticated_cursor,
                )
                .map_err(|_| CommonProofProverError::InvalidInput)?;
            }
            (None, Some(challenger)) => challenger
                .restore_checkpoint_cursor(&self.construction_plan, &authenticated_cursor)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
            _ => return Err(CommonProofProverError::InvalidInput),
        }
        let restored_cursor = match (
            self.row_code_whir_transcript.as_ref(),
            self.aggregate_challenger.as_ref(),
        ) {
            (Some(transcript), None) => transcript
                .checkpoint_cursor(&self.construction_plan)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
            (None, Some(challenger)) => challenger
                .checkpoint_cursor(&self.construction_plan)
                .map_err(|_| CommonProofProverError::InvalidInput)?,
            _ => return Err(CommonProofProverError::InvalidInput),
        };
        if restored_cursor.digest() != authenticated_cursor.digest()
            || restored_cursor.canonical_bytes() != authenticated_cursor.canonical_bytes()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        Ok(())
    }

    pub(crate) fn checkpoint_boundary(&self) -> Option<CommonProofGenerationCheckpointBoundary> {
        if let Some(expected_boundary) = self.pending_aggregate_checkpoint_boundary {
            return self.aggregate_checkpoint_boundary(expected_boundary);
        }
        if self.pending_authenticated_source_read.is_some()
            || self.pending_replay_polynomial.is_some()
            || self.active_replay_polynomial_writer.is_some()
            || self.active_replay_polynomial_reader.is_some()
            || self.active_aggregate_source_read.is_some()
            || self.active_phase_polynomial_reader.is_some()
            || self.active_phase_polynomial_binding.is_some()
            || self.active_phase_row_dft.is_some()
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
            || self.pending_quotient_evaluation_read.is_some()
            || self.exact_same_secret_aggregate_source.is_some()
            || self.exact_same_secret_aggregate_witness.is_some()
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
        if !self.phase_roots_match_checkpoint_boundary(expected_boundary) {
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

    fn aggregate_checkpoint_boundary(
        &self,
        expected_boundary: RowCodeWhirCheckpointBoundary,
    ) -> Option<CommonProofGenerationCheckpointBoundary> {
        if self.phase != RowCodeWhirGenerationPhase::GeneratingAggregateWhirProof
            || self.aggregate_proof_generation.is_none()
            || self.aggregate_wide_opening_proof.is_some()
            || self.exact_proof_encoder.is_some()
            || !self.scheduled_phase_roots_are_complete()
            || self.exact_same_secret_phase_openings.is_none()
            || self.bound_tree_authentications.len() != self.bound_tree_entries.len()
        {
            return None;
        }
        match expected_boundary {
            RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries
            | RowCodeWhirCheckpointBoundary::WhirRound { .. } => {}
            _ => return None,
        }
        let checkpoint = self
            .construction_plan
            .checkpoints()
            .iter()
            .find(|checkpoint| checkpoint.boundary == expected_boundary)?;
        let source_replay_identity_digest = self.source_replay_identity_digest?;
        if source_replay_identity_digest == [0_u8; HASH_BYTE_LENGTH] {
            return None;
        }
        let transcript_cursor = self
            .aggregate_challenger
            .as_ref()?
            .checkpoint_cursor(&self.construction_plan)
            .ok()?;
        if transcript_cursor.next_transcript_operation_index()
            != usize::try_from(checkpoint.next_transcript_operation_ordinal).ok()?
            || transcript_cursor.canonical_bytes().is_empty()
            || transcript_cursor.canonical_bytes().len()
                > MAXIMUM_ROW_CODE_WHIR_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
        {
            return None;
        }
        let aggregate_commitment =
            aggregate_commitment_digest_bytes(self.aggregate_commitment.as_ref()?)?;
        let pad_commitment =
            aggregate_commitment_digest_bytes(self.aggregate_wide_pad_commitment.as_ref()?)?;
        let mut position = [0_u8; 16];
        position[0] = 1;
        position[1] = match expected_boundary {
            RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries => 6,
            RowCodeWhirCheckpointBoundary::WhirRound { .. } => 7,
            _ => return None,
        };
        position[4..8].copy_from_slice(&checkpoint.checkpoint_ordinal.to_le_bytes());
        position[8..12]
            .copy_from_slice(&checkpoint.next_transcript_operation_ordinal.to_le_bytes());
        position[12..16].copy_from_slice(&checkpoint.next_proof_section_ordinal.to_le_bytes());

        let mut hasher =
            StreamingHash512::new(ROW_CODE_WHIR_CHECKPOINT_COMMITTED_STATE_HASH_DOMAIN, 15);
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
        absorb_extension_values_checkpoint_part(&mut hasher, &self.out_of_domain_evaluations)?;
        absorb_extension_values_checkpoint_part(
            &mut hasher,
            &self.opening_batch_mask_chunk_evaluations,
        )?;
        hasher.absorb_part(transcript_cursor.canonical_bytes());
        hasher.absorb_part(&transcript_cursor.digest());
        hasher.absorb_part(&aggregate_commitment);
        hasher.absorb_part(&pad_commitment);
        let cursor_digest = transcript_cursor.digest();
        Some(
            CommonProofGenerationCheckpointBoundary::new(
                checkpoint.checkpoint_ordinal,
                position,
                hasher.finalize(),
            )
            .with_canonical_transcript_cursor(
                transcript_cursor.into_canonical_bytes(),
                cursor_digest,
            ),
        )
    }

    pub(crate) fn poll<Storage, Coins, Sink>(
        &mut self,
        storage: &mut Storage,
        coins: &mut Coins,
        sink: &mut Sink,
    ) -> RowCodeWhirGenerationPollResult<Storage::Error, Coins::Error, Sink::Error>
    where
        Storage: ProofExternalMemory,
        Coins: crate::bgv::proof_suite::CommonProofPrivateCoinSource,
        Sink: CommonProofByteSink,
    {
        self.pending_aggregate_checkpoint_boundary = None;
        if self.phase == RowCodeWhirGenerationPhase::Cancelled {
            return Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
        if self.phase == RowCodeWhirGenerationPhase::Complete {
            return Ok(CommonProofGenerationPoll::Complete);
        }
        if self.pending_authenticated_source_read.is_some() {
            return Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            ));
        }
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
            let progress = {
                let ActiveExactSameSecretAggregateSourceRead {
                    reader,
                    source_range,
                    ..
                } = active;
                reader
                    .advance(
                        self.source_polynomial_provider.as_deref_mut().ok_or(
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
                        source_range.destination(),
                    )
                    .map_err(map_relation_polynomial_reader_error)?
            };
            if let Some(poll) = self
                .pending_poll_for_relation_reader_progress(progress)
                .map_err(CommonProofGenerationError::Prover)?
            {
                return Ok(poll);
            }
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
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        if let Some(active) = self.active_replay_polynomial_reader.as_mut() {
            let progress = active
                .reader
                .advance(
                    self.source_polynomial_provider.as_deref_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    self.external_memory_executor.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    storage,
                )
                .map_err(map_relation_polynomial_reader_error)?;
            if let Some(poll) = self
                .pending_poll_for_relation_reader_progress(progress)
                .map_err(CommonProofGenerationError::Prover)?
            {
                return Ok(poll);
            }
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
                        ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
                    )
                    .map_err(map_private_coin_error)?;
                    let _persisted = self
                        .begin_replay_polynomial_write(
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
                                self.construction_plan
                                    .parameters
                                    .logical_polynomial_coefficient_count,
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
                RowCodeWhirReplayReadContinuation::BoundTreeColumn {
                    bound_tree_ordinal,
                    column_position,
                    column_ordinal,
                } => {
                    let expected_column_request = self
                        .active_bound_tree_authentication_builder
                        .as_ref()
                        .and_then(ActiveExactBoundTreeAuthenticationBuilder::next_column_request);
                    if self.phase != RowCodeWhirGenerationPhase::MaterializingBoundAuthentications
                        || bound_tree_ordinal != self.next_bound_tree_ordinal
                        || expected_column_request != Some((column_position, column_ordinal))
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ));
                    }
                    let CommonProofSourcePolynomial::Base(coefficients) = source else {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    };
                    let is_bound_public_column = self
                        .relation_plan_variant
                        .ordered_columns()
                        .get(usize::try_from(column_ordinal).map_err(|_| {
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            )
                        })?)
                        .is_some_and(|column| {
                            matches!(column.origin(), RelationColumnOrigin::BoundTree { .. })
                        });
                    if !self
                        .relation_polynomial_shapes
                        .contains_key(&column_ordinal)
                        || !is_bound_public_column
                    {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                    self.active_bound_tree_authentication_builder
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidTree,
                        ))?
                        .begin_column(column_position, column_ordinal, coefficients)
                        .map_err(CommonProofGenerationError::Prover)?;
                }
            }
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        if self.active_quotient_transform.is_some() {
            let phase = self
                .active_quotient_transform
                .as_ref()
                .map(|active| active.phase)
                .ok_or(CommonProofGenerationError::Prover(
                    CommonProofProverError::InvalidQuotient,
                ))?;
            return match phase {
                ActiveRowCodeWhirQuotientTransformPhase::Reading => {
                    let progress = self
                        .active_quotient_transform
                        .as_mut()
                        .and_then(|active| active.reader.as_mut())
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .advance(
                            self.source_polynomial_provider.as_deref_mut().ok_or(
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
                        .map_err(map_relation_polynomial_reader_error)?;
                    if let Some(poll) = self
                        .pending_poll_for_relation_reader_progress(progress)
                        .map_err(CommonProofGenerationError::Prover)?
                    {
                        return Ok(poll);
                    }
                    let active = self.active_quotient_transform.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient),
                    )?;
                    active.polynomial = Some(
                        active
                            .reader
                            .take()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ))?
                            .finish()
                            .map_err(CommonProofGenerationError::Prover)?,
                    );
                    active.phase = ActiveRowCodeWhirQuotientTransformPhase::Transforming;
                    Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                }
                ActiveRowCodeWhirQuotientTransformPhase::Transforming => {
                    let active = self.active_quotient_transform.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient),
                    )?;
                    let polynomial =
                        active
                            .polynomial
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ))?;
                    evaluate_quotient_transform_in_place(active.plan, polynomial)
                        .map_err(CommonProofGenerationError::Prover)?;
                    active.writer = Some(
                        CommonProofReplayPolynomialWriter::new(
                            active.plan.output(),
                            CommonProofReplayPolynomialRef::Source(polynomial),
                        )
                        .map_err(CommonProofGenerationError::Prover)?,
                    );
                    active.phase = ActiveRowCodeWhirQuotientTransformPhase::Writing;
                    Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                }
                ActiveRowCodeWhirQuotientTransformPhase::Writing => {
                    let active = self.active_quotient_transform.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient),
                    )?;
                    let complete = active
                        .writer
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .advance(
                            self.external_memory_executor.as_mut().ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ),
                            )?,
                            storage,
                            CommonProofReplayPolynomialRef::Source(
                                active.polynomial.as_ref().ok_or(
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::InvalidQuotient,
                                    ),
                                )?,
                            ),
                        )
                        .map_err(CommonProofGenerationError::Storage)?;
                    if complete {
                        active.writer = None;
                        active.polynomial = None;
                        active.phase = ActiveRowCodeWhirQuotientTransformPhase::Completing;
                    }
                    Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                }
                ActiveRowCodeWhirQuotientTransformPhase::Completing => {
                    self.external_memory_executor
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?
                        .complete_step(storage)
                        .map_err(CommonProofGenerationError::Storage)?;
                    let active = self.active_quotient_transform.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidQuotient),
                    )?;
                    self.quotient_materialization
                        .as_mut()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidQuotient,
                        ))?
                        .supply_transformed_column(active.transform_key, active.plan.final_output())
                        .map_err(CommonProofGenerationError::Prover)?;
                    Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                }
            };
        }

        if let Some(request) = self.pending_quotient_evaluation_read {
            let values = read_external_polynomial_values_as_extension(
                self.external_memory_executor.as_mut().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?,
                storage,
                request.vector(),
                request.element_offset(),
                request.element_count(),
            )
            .map_err(|error| match error {
                ExternalPolynomialReadError::Polynomial(error) => {
                    CommonProofGenerationError::StoragePlan(map_external_polynomial_read_error(
                        error,
                    ))
                }
                ExternalPolynomialReadError::Storage(error) => {
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
            self.pending_quotient_evaluation_read = None;
            return Ok(CommonProofGenerationPoll::StorageTransactionCompleted);
        }

        if let Some(reader) = self.active_phase_polynomial_reader.as_mut() {
            let progress = reader
                .advance(
                    self.source_polynomial_provider.as_deref_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    self.external_memory_executor.as_mut().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    storage,
                )
                .map_err(map_relation_polynomial_reader_error)?;
            if let Some(poll) = self
                .pending_poll_for_relation_reader_progress(progress)
                .map_err(CommonProofGenerationError::Prover)?
            {
                return Ok(poll);
            }
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
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        match self.phase {
            RowCodeWhirGenerationPhase::PreparingAuthenticatedSources => {
                self.validate_source_construction_input()
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
                        ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
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
                        let persisted = self
                            .begin_replay_polynomial_write(
                                RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal),
                                polynomial,
                                RowCodeWhirReplayWriteContinuation::AuthenticatedSource,
                            )
                            .map_err(CommonProofGenerationError::Prover)?;
                        if !persisted {
                            self.loaded_source_polynomial_count = self
                                .loaded_source_polynomial_count
                                .checked_add(1)
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                ))?;
                        }
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
                        let source_replay_identity_catalog = self
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
                                source_replay_identity_catalog.aggregate_digest(),
                                self.same_secret_source_manifest.catalog_hash(),
                            ));
                        self.source_replay_identity_catalog = Some(source_replay_identity_catalog);
                        self.source_cursor = None;
                        self.phase = RowCodeWhirGenerationPhase::ConstructingReversedColumns;
                    }
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::ConstructingReversedColumns => {
                self.validate_source_construction_input()
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
                self.active_replay_polynomial_reader =
                    Some(ActiveRowCodeWhirReplayPolynomialReader {
                        reader: self
                            .relation_polynomial_reader(source_column_ordinal, coins)
                            .map_err(map_private_coin_error)?,
                        continuation: RowCodeWhirReplayReadContinuation::ReversedColumn {
                            source_column_ordinal,
                            reversed_column_ordinal,
                        },
                    });
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::SamplingRowPads => {
                self.validate_source_construction_input()
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
                            Zeroizing::new([0_u8; PRIVATE_ROW_PAD_SEED_MATERIAL_BYTE_LENGTH]);
                        coins
                            .fill_raw_bytes(
                                CommonProofPrivateCoinCoordinate::proof_salt(),
                                row_pad_seed_bytes.as_mut(),
                            )
                            .map_err(CommonProofGenerationError::CoinSource)?;
                        let mut row_pad_seeds =
                            [[0_u8; PRIVATE_ROW_PAD_SEED_BYTE_LENGTH]; PRIVATE_ROW_PAD_PHASE_COUNT];
                        for (phase_seed_ordinal, phase_seed) in row_pad_seeds.iter_mut().enumerate()
                        {
                            let seed_start = phase_seed_ordinal
                                .checked_mul(PRIVATE_ROW_PAD_SEED_BYTE_LENGTH)
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                ))?;
                            let seed_end = seed_start
                                .checked_add(PRIVATE_ROW_PAD_SEED_BYTE_LENGTH)
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::CountOverflow,
                                ))?;
                            phase_seed.copy_from_slice(
                                row_pad_seed_bytes.get(seed_start..seed_end).ok_or(
                                    CommonProofGenerationError::Prover(
                                        CommonProofProverError::InvalidInput,
                                    ),
                                )?,
                            );
                        }
                        Some(Zeroizing::new(Box::<[PrivateRowPadSeed]>::from(
                            row_pad_seeds,
                        )))
                    }
                    ProofPrivacyMode::PublicOnly => None,
                };
                self.row_pad_seeds = row_pad_seeds;
                if self.construction_plan.base_phase.is_some() {
                    self.prepare_relation_phase_materialization(
                        RowCodeWhirPhase::Base,
                        RowCodeWhirPhaseMaterializationPurpose::InitialCommitment,
                    )
                    .map_err(CommonProofGenerationError::Prover)?;
                    self.phase = RowCodeWhirGenerationPhase::CommittingBasePhase;
                } else {
                    self.phase = RowCodeWhirGenerationPhase::AwaitingAuthenticatedTranscriptPrefix;
                }
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::CommittingBasePhase => self
                .poll_relation_phase_commitment(RowCodeWhirPhase::Base, coins)
                .map_err(map_private_coin_error),
            RowCodeWhirGenerationPhase::AwaitingAuthenticatedTranscriptPrefix => {
                if self.construction_plan.base_phase.is_some()
                    != self.phase_root(RowCodeWhirPhase::Base).is_some()
                    || self.phase_commitment_builder.is_some()
                    || self.active_phase_commitment.is_some()
                    || self.active_phase_polynomial_reader.is_some()
                    || self.active_phase_polynomial_binding.is_some()
                    || self.active_phase_row_dft.is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                if self.authenticated_transcript_prefix.is_none()
                    && self
                        .transcript_prefix_authority
                        .verified_vss_binding()
                        .is_none()
                {
                    let mut transcript = crate::bgv::proof_suite::CommonProofTranscript::new_relation_prefix_for_construction_plan(
                        self.source_request_context.protocol_version(),
                        self.source_request_context.suite_identifier(),
                        &self.construction_plan,
                        self.source_request_context
                            .application_statement_schema_identifier(),
                        &self.canonical_header_bytes,
                        self.construction_plan.relation_prefix_schedule().clone(),
                    )
                    .map_err(CommonProofGenerationError::Transcript)?;
                    let base_tree_ordinals = self
                        .construction_plan
                        .relation_prefix_schedule()
                        .ordered_base_tree_ordinals()
                        .to_vec();
                    if !base_tree_ordinals.is_empty() {
                        let root_bytes =
                            column_digest_bytes(self.phase_root(RowCodeWhirPhase::Base).ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ),
                            )?);
                        for tree_ordinal in base_tree_ordinals {
                            transcript
                                .absorb_base_root(tree_ordinal, root_bytes)
                                .map_err(CommonProofGenerationError::Transcript)?;
                        }
                    }
                    self.authenticated_transcript_prefix = Some(transcript);
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
                    self.auxiliary_reconstruction_challenges = application_challenges.clone();
                    self.application_challenges = application_challenges;
                    if self.construction_plan.auxiliary_phase.is_some() {
                        let auxiliary_materialization =
                            RowCodeWhirAuxiliaryRelationMaterialization::new(
                                &self.relation_plan_variant,
                                &self.relation_context,
                                &self.application_challenges,
                            )
                            .map_err(CommonProofGenerationError::Prover)?;
                        self.auxiliary_materialization = Some(auxiliary_materialization);
                        self.phase = RowCodeWhirGenerationPhase::DerivingAuxiliaryColumns;
                    } else {
                        self.phase = RowCodeWhirGenerationPhase::PreparingQuotient;
                    }
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
                        ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
                    )
                    .map_err(map_private_coin_error)?;
                match action {
                    RowCodeWhirAuxiliaryRelationMaterializationAction::ReadColumn(
                        column_ordinal,
                    ) => {
                        self.active_replay_polynomial_reader =
                            Some(ActiveRowCodeWhirReplayPolynomialReader {
                                reader: self
                                    .relation_polynomial_reader(column_ordinal, coins)
                                    .map_err(map_private_coin_error)?,
                                continuation: RowCodeWhirReplayReadContinuation::AuxiliaryColumn {
                                    column_ordinal,
                                },
                            });
                    }
                    RowCodeWhirAuxiliaryRelationMaterializationAction::PersistColumn {
                        column_ordinal,
                        polynomial,
                    } => {
                        let _persisted = self
                            .begin_replay_polynomial_write(
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
                .poll_relation_phase_commitment(RowCodeWhirPhase::Auxiliary, coins)
                .map_err(map_private_coin_error),
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
                        ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
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
                        self.quotient_materialization
                            .as_mut()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ))?
                            .acknowledge_completed_constraint_storage_step()
                            .map_err(CommonProofGenerationError::Prover)?;
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    RowCodeWhirQuotientMaterializationAction::PersistQuotientComponent {
                        component_ordinal,
                        polynomial,
                    } => {
                        let persisted = self
                            .begin_replay_polynomial_write(
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
                        if !persisted {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ));
                        }
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
                        let column_ordinal = transform_key.column_ordinal();
                        if !self
                            .relation_polynomial_shapes
                            .contains_key(&column_ordinal)
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidColumn,
                            ));
                        }
                        self.active_quotient_transform = Some(ActiveRowCodeWhirQuotientTransform {
                            transform_key,
                            plan,
                            phase: ActiveRowCodeWhirQuotientTransformPhase::Reading,
                            reader: Some(
                                self.relation_polynomial_reader(column_ordinal, coins)
                                    .map_err(map_private_coin_error)?,
                            ),
                            polynomial: None,
                            writer: None,
                        });
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    RowCodeWhirQuotientMaterializationAction::ReadEvaluationRange(request) => {
                        if self
                            .pending_quotient_evaluation_read
                            .replace(request)
                            .is_some()
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidQuotient,
                            ));
                        }
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                }
            }
            RowCodeWhirGenerationPhase::DerivingOpeningBatchMask => {
                let opening_batch_mask = construct_opening_batch_mask(
                    &self.relation_plan_variant,
                    coins,
                    ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
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
                    let persisted = self
                        .begin_replay_polynomial_write(
                            RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(
                                RowCodeWhirOpenedPolynomialSource::OpeningBatchMask {
                                    mask_ordinal: 0,
                                },
                            ),
                            CommonProofSourcePolynomial::Extension(opening_batch_mask),
                            RowCodeWhirReplayWriteContinuation::OpeningBatchMask,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                    if !persisted {
                        return Err(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidColumn,
                        ));
                    }
                }
                self.phase = RowCodeWhirGenerationPhase::CommittingQuotientPhase;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::CommittingQuotientPhase => {
                if self.phase_commitment_builder.is_none()
                    && self.active_phase_commitment.is_none()
                    && self.active_phase_row_dft.is_none()
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
                    let authenticated_transcript_prefix = self
                        .authenticated_transcript_prefix
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?;
                    let row_code_whir_transcript =
                        match self.construction_plan.proof_privacy_mode {
                            ProofPrivacyMode::SecretBearing => authenticated_transcript_prefix
                                .into_secret_bearing_row_code_whir_transcript(
                                    &self.opening_batch_mask_chunk_evaluations,
                                ),
                            ProofPrivacyMode::PublicOnly => authenticated_transcript_prefix
                                .into_public_row_code_whir_transcript(),
                        }
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
                if self.active_replay_polynomial_reader.is_some() {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                self.active_replay_polynomial_reader =
                    Some(ActiveRowCodeWhirReplayPolynomialReader {
                        reader: self
                            .polynomial_reader(target, coins)
                            .map_err(map_private_coin_error)?,
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
                    || self.exact_same_secret_aggregate_witness.is_some()
                    || self.aggregate_challenger.is_some()
                    || self.aggregate_wide_hiding_material_generation.is_some()
                    || self.aggregate_commitment_generation.is_some()
                    || self.aggregate_commitment.is_some()
                    || self.aggregate_wide_pad_commitment.is_some()
                    || self.exact_same_secret_opening_schedule.is_some()
                    || self.next_bound_tree_ordinal != 0
                    || self.active_bound_tree_authentication_builder.is_some()
                    || !self.bound_tree_authentications.is_empty()
                    || self.aggregate_proof_generation.is_some()
                    || self.aggregate_wide_opening_proof.is_some()
                    || self.exact_proof_encoder.is_some()
                    || self.canonical_output_byte_length.is_some()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                let transcript_prefix_authority_binding_digest =
                    self.transcript_prefix_authority.aggregate_binding_digest(
                        self.construction_plan_identity_hash,
                        self.source_request_context.stable_generation_binding_hash(),
                    );
                let aggregate_source = ExactSameSecretAggregateSource::new(
                    &self.construction_plan,
                    &self.relation_plan_variant,
                    &self.relation_context,
                    &self.same_secret_source_manifest,
                    self.source_request_context,
                    self.source_replay_identity_digest.ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    transcript_prefix_authority_binding_digest,
                    core::mem::take(&mut self.opening_points),
                    &self.out_of_domain_evaluations,
                    &self.opening_batch_mask_chunk_evaluations,
                    self.row_pad_seeds.take(),
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
                    self.begin_exact_same_secret_aggregate_source_read(action, coins)
                        .map_err(map_private_coin_error)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }
                let batch = self
                    .exact_same_secret_aggregate_source
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .take_completed_batch()
                    .map_err(CommonProofGenerationError::Prover)?;
                let aggregate_table_width = self
                    .aggregate_source_table
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .table_width();
                let resident_batch_column_count =
                    aggregate_source_resident_batch_column_count(&self.construction_plan)
                        .map_err(CommonProofGenerationError::Prover)?;
                let expected_batch_column_count = aggregate_table_width
                    .checked_sub(batch.first_column_index())
                    .map(|remaining| remaining.min(resident_batch_column_count))
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?;
                if batch.columns().len() != expected_batch_column_count
                    || batch.first_column_index() >= aggregate_table_width
                    || !batch
                        .first_column_index()
                        .is_multiple_of(resident_batch_column_count)
                    || self.active_aggregate_source_batch.replace(batch).is_some()
                    || self.aggregate_source_writer.is_some()
                    || self.aggregate_source_batch_column_offset != 0
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                self.phase = if self
                    .active_aggregate_source_batch
                    .as_ref()
                    .is_some_and(|batch| batch.is_final_batch(aggregate_table_width))
                {
                    RowCodeWhirGenerationPhase::ReleasingAggregateReplayStorage
                } else {
                    RowCodeWhirGenerationPhase::PersistingAggregateSourceBatch
                };
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::ReleasingAggregateReplayStorage => {
                self.external_memory_executor
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .complete_step(storage)
                    .map_err(CommonProofGenerationError::Storage)?;
                self.phase = RowCodeWhirGenerationPhase::PersistingAggregateSourceBatch;
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            RowCodeWhirGenerationPhase::PersistingAggregateSourceBatch => {
                let batch = self.active_aggregate_source_batch.as_ref().ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                let column_offset = self.aggregate_source_batch_column_offset;
                let source_column = batch.columns().get(column_offset).ok_or(
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                )?;
                let global_column_index = batch
                    .first_column_index()
                    .checked_add(column_offset)
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::CountOverflow,
                    ))?;
                let vector = *self
                    .aggregate_source_table
                    .as_ref()
                    .and_then(|table| table.columns().get(global_column_index))
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?;
                let mut writer = match self.aggregate_source_writer.take() {
                    Some(writer) => writer,
                    None => AggregateSourceWriter::new(vector).map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
                    })?,
                };
                let complete = writer
                    .poll(
                        AggregateSourceValues::Slice(source_column),
                        self.external_memory_executor.as_mut().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?,
                        storage,
                    )
                    .map_err(CommonProofGenerationError::Storage)?;
                if complete {
                    self.aggregate_source_batch_column_offset = self
                        .aggregate_source_batch_column_offset
                        .checked_add(1)
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?;
                    if self.aggregate_source_batch_column_offset == batch.columns().len() {
                        let completed_first_column_index = batch.first_column_index();
                        let completed_column_count = batch.column_count();
                        self.active_aggregate_source_batch = None;
                        self.aggregate_source_batch_column_offset = 0;
                        let completed_end = completed_first_column_index
                            .checked_add(completed_column_count)
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?;
                        let aggregate_table_width = self
                            .aggregate_source_table
                            .as_ref()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?
                            .table_width();
                        if completed_end < aggregate_table_width {
                            self.exact_same_secret_aggregate_source
                                .as_mut()
                                .ok_or(CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ))?
                                .begin_next_batch()
                                .map_err(CommonProofGenerationError::Prover)?;
                            self.phase = RowCodeWhirGenerationPhase::MaterializingAggregateSource;
                        } else if completed_end == aggregate_table_width {
                            self.finish_aggregate_source_materialization()
                                .map_err(CommonProofGenerationError::Prover)?;
                            self.phase =
                                RowCodeWhirGenerationPhase::SamplingAggregateWideHidingMaterial;
                        } else {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                    }
                } else {
                    self.aggregate_source_writer = Some(writer);
                }
                Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
            }
            RowCodeWhirGenerationPhase::SamplingAggregateWideHidingMaterial => {
                let poll = self
                    .aggregate_wide_hiding_material_generation
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .poll(coins, ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING)
                    .map_err(map_aggregate_wide_hiding_material_generation_error)?;
                match poll {
                    AggregateWideHidingMaterialGenerationPoll::ExtensionElementSampled {
                        completed_count,
                    } => {
                        if completed_count == 0 {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    AggregateWideHidingMaterialGenerationPoll::Complete(material) => {
                        self.aggregate_wide_hiding_material_generation = None;
                        let witness = self.exact_same_secret_aggregate_witness.take().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?;
                        let pcs = aggregate_wide_pcs_for_construction_plan(&self.construction_plan)
                            .map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                )
                            })?;
                        let hiding_configuration = super::hiding_whir::selected_hiding_whir_config(
                            self.construction_plan.selected_parameters(),
                        )
                        .map_err(|_| {
                            CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
                        })?;
                        let source_table = self.aggregate_source_table.take().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?;
                        let residuals = self.aggregate_residuals.take().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?;
                        if witness.table_variable_count() != source_table.table_variable_count()
                            || witness.table_width() != source_table.table_width()
                            || witness.folding_factor() != source_table.folding_factor()
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.aggregate_commitment_generation = Some(
                            StreamingAggregateWideCommitmentGeneration::new(
                                &pcs,
                                hiding_configuration,
                                source_table,
                                residuals,
                                material,
                            )
                            .map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                )
                            })?,
                        );
                        self.phase = RowCodeWhirGenerationPhase::CommittingAggregate;
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                }
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
                    .map_err(map_aggregate_wide_generation_error)?;
                match poll {
                    StreamingAggregateWideCommitmentPoll::ArithmeticStepCompleted => {
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingAggregateWideCommitmentPoll::StorageTransactionCompleted => {
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    StreamingAggregateWideCommitmentPoll::CommitmentsObserved {
                        source_commitment,
                        pad_commitment,
                    } => {
                        if self
                            .aggregate_commitment
                            .replace(source_commitment)
                            .is_some()
                            || self
                                .aggregate_wide_pad_commitment
                                .replace(pad_commitment)
                                .is_some()
                        {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.phase = RowCodeWhirGenerationPhase::PreparingAggregateOpenings;
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingAggregateWideCommitmentPoll::Complete(_) => Err(
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
                self.phase = RowCodeWhirGenerationPhase::MaterializingBoundAuthentications;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::MaterializingBoundAuthentications => {
                if let Some(builder) = self.active_bound_tree_authentication_builder.as_mut() {
                    if let Some((column_position, column_ordinal)) = builder.next_column_request() {
                        if self.active_replay_polynomial_reader.is_some() {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.active_replay_polynomial_reader =
                            Some(ActiveRowCodeWhirReplayPolynomialReader {
                                reader: self
                                    .relation_polynomial_reader(column_ordinal, coins)
                                    .map_err(map_private_coin_error)?,
                                continuation: RowCodeWhirReplayReadContinuation::BoundTreeColumn {
                                    bound_tree_ordinal: self.next_bound_tree_ordinal,
                                    column_position,
                                    column_ordinal,
                                },
                            });
                        return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                    }
                    let complete = builder
                        .poll(
                            self.source_polynomial_provider.as_deref_mut().ok_or(
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                ),
                            )?,
                            self.source_request_context,
                        )
                        .map_err(CommonProofGenerationError::Prover)?;
                    if complete {
                        let authentication = self
                            .active_bound_tree_authentication_builder
                            .take()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidTree,
                            ))?
                            .finish()
                            .map_err(CommonProofGenerationError::Prover)?;
                        self.bound_tree_authentications.push(authentication);
                        self.next_bound_tree_ordinal = self
                            .next_bound_tree_ordinal
                            .checked_add(1)
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?;
                    }
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }

                if self.next_bound_tree_ordinal == self.bound_tree_entries.len() {
                    if self.bound_tree_authentications.len() != self.bound_tree_entries.len() {
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
                    let first_phase = self.construction_plan.phase_order.first().copied().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?;
                    self.begin_authenticated_phase_openings(first_phase)
                        .map_err(CommonProofGenerationError::Prover)?;
                    return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
                }

                let entry = self
                    .bound_tree_entries
                    .get(self.next_bound_tree_ordinal)
                    .cloned()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ))?;
                let descriptor = self
                    .relation_plan_variant
                    .ordered_trees()
                    .get(usize::from(entry.tree_catalog_index()))
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ))?;
                let RelationTreeDescriptor::BoundPublic {
                    ordered_column_ordinals,
                    ..
                } = descriptor
                else {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                };
                let bound_tree_row_width = entry.materialized_row_width().map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree)
                })?;
                if bound_tree_row_width == 0
                    || ordered_column_ordinals.len() != bound_tree_row_width
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                let query_indices = self
                    .exact_same_secret_opening_schedule
                    .as_ref()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidOpening,
                    ))?
                    .bound_tree_traversal_query_indices(self.next_bound_tree_ordinal)
                    .map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidOpening)
                    })?
                    .to_vec();
                let planned_bound_tree = self
                    .construction_plan
                    .bound_trees
                    .get(self.next_bound_tree_ordinal)
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ))?;
                let evaluation_domain_size =
                    usize::try_from(planned_bound_tree.evaluation_domain_size).map_err(|_| {
                        CommonProofGenerationError::Prover(CommonProofProverError::CountOverflow)
                    })?;
                if evaluation_domain_size < 2
                    || evaluation_domain_size & 1 != 0
                    || planned_bound_tree.leaf_count != evaluation_domain_size / 2
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidTree,
                    ));
                }
                let bound_leaf_count = planned_bound_tree.leaf_count;
                let evaluation_domain = ProofEvaluationDomain::new(
                    evaluation_domain_size,
                    self.relation_context.evaluation_coset_offset,
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidTree)
                })?;
                self.active_bound_tree_authentication_builder = Some(
                    ActiveExactBoundTreeAuthenticationBuilder::new(
                        entry,
                        bound_leaf_count,
                        &query_indices,
                        evaluation_domain,
                        ordered_column_ordinals,
                    )
                    .map_err(CommonProofGenerationError::Prover)?,
                );
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::MaterializingBasePhaseOpenings => self
                .poll_relation_phase_commitment(RowCodeWhirPhase::Base, coins)
                .map_err(map_private_coin_error),
            RowCodeWhirGenerationPhase::MaterializingAuxiliaryPhaseOpenings => self
                .poll_relation_phase_commitment(RowCodeWhirPhase::Auxiliary, coins)
                .map_err(map_private_coin_error),
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
                    .map_err(map_aggregate_wide_generation_error)?;
                match poll {
                    StreamingAggregateWideCommitmentPoll::ArithmeticStepCompleted => {
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingAggregateWideCommitmentPoll::StorageTransactionCompleted => {
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    StreamingAggregateWideCommitmentPoll::CommitmentsObserved { .. } => Err(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    ),
                    StreamingAggregateWideCommitmentPoll::Complete(output) => {
                        let output = *output;
                        let observed_commitment = self.aggregate_commitment.take().ok_or(
                            CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ),
                        )?;
                        if output.source_commitment != observed_commitment {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.aggregate_commitment = Some(output.source_commitment.clone());
                        self.aggregate_commitment_generation = None;
                        self.aggregate_proof_generation = Some(
                            StreamingAggregateWideProofGeneration::new(
                                output.source_commitment,
                                output.prover_data,
                            )
                            .map_err(|_| {
                                CommonProofGenerationError::Prover(
                                    CommonProofProverError::InvalidInput,
                                )
                            })?,
                        );
                        self.pending_aggregate_checkpoint_boundary =
                            Some(RowCodeWhirCheckpointBoundary::AggregateCommitmentsAndQueries);
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
                    .map_err(map_aggregate_wide_generation_error)?;
                match poll {
                    StreamingAggregateWideProofPoll::ArithmeticStepCompleted(boundary) => {
                        self.pending_aggregate_checkpoint_boundary =
                            durable_checkpoint_for_aggregate_proof_boundary(boundary);
                        Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
                    }
                    StreamingAggregateWideProofPoll::StorageTransactionCompleted(boundary) => {
                        self.pending_aggregate_checkpoint_boundary =
                            durable_checkpoint_for_aggregate_proof_boundary(boundary);
                        Ok(CommonProofGenerationPoll::StorageTransactionCompleted)
                    }
                    StreamingAggregateWideProofPoll::Complete(proof) => {
                        self.aggregate_proof_generation = None;
                        if self.aggregate_wide_opening_proof.replace(*proof).is_some() {
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
                    || self.exact_same_secret_aggregate_witness.is_some()
                    || self.exact_same_secret_opening_schedule.is_none()
                    || self.aggregate_challenger.is_none()
                    || self.aggregate_wide_pad_commitment.is_none()
                    || self.aggregate_wide_opening_proof.is_none()
                    || self.exact_proof_encoder.is_some()
                    || self.canonical_output_byte_length.is_some()
                    || self.bound_tree_authentications.len() != self.bound_tree_entries.len()
                {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                let opening_batch_mask_chunk_evaluations =
                    core::mem::take(&mut self.opening_batch_mask_chunk_evaluations);
                let proof = ExactSameSecretProof::new(
                    self.exact_same_secret_phase_openings.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidOpening),
                    )?,
                    core::mem::take(&mut self.out_of_domain_evaluations),
                    opening_batch_mask_chunk_evaluations,
                    self.aggregate_commitment
                        .take()
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::InvalidInput,
                        ))?,
                    self.aggregate_wide_pad_commitment.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput),
                    )?,
                    core::mem::take(&mut self.bound_tree_authentications),
                    self.aggregate_wide_opening_proof.take().ok_or(
                        CommonProofGenerationError::Prover(CommonProofProverError::InvalidOpening),
                    )?,
                );
                let encoder = ExactSameSecretProofSinkEncoder::new(
                    &self.construction_plan,
                    &self.relation_plan_variant,
                    &self.bound_tree_entries,
                    proof,
                )
                .map_err(|_| {
                    CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
                })?;
                self.canonical_output_byte_length = Some(
                    self.canonical_header_bytes
                        .len()
                        .checked_add(encoder.canonical_byte_length())
                        .ok_or(CommonProofGenerationError::Prover(
                            CommonProofProverError::CountOverflow,
                        ))?,
                );
                self.exact_proof_encoder = Some(encoder);
                self.exact_same_secret_aggregate_metadata = None;
                self.exact_same_secret_opening_schedule = None;
                self.aggregate_challenger = None;
                self.row_pad_seeds = None;
                self.phase = RowCodeWhirGenerationPhase::EncodingExactProofHeader;
                Ok(CommonProofGenerationPoll::ArithmeticStepCompleted)
            }
            RowCodeWhirGenerationPhase::EncodingExactProofHeader => {
                if self.canonical_header_bytes.is_empty() {
                    return Err(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ));
                }
                sink.write_bytes(&self.canonical_header_bytes)
                    .map_err(CommonProofGenerationError::Sink)?;
                self.phase = RowCodeWhirGenerationPhase::EncodingExactProof;
                Ok(CommonProofGenerationPoll::OutputFragmentAccepted)
            }
            RowCodeWhirGenerationPhase::EncodingExactProof => {
                let progress = self
                    .exact_proof_encoder
                    .as_mut()
                    .ok_or(CommonProofGenerationError::Prover(
                        CommonProofProverError::InvalidInput,
                    ))?
                    .write_next(sink)
                    .map_err(|error| match error {
                        ExactSameSecretProofSinkEncodingError::Sink(error) => {
                            CommonProofGenerationError::Sink(error)
                        }
                    })?;
                match progress {
                    ExactSameSecretProofEncodingProgress::Pending => {
                        Ok(CommonProofGenerationPoll::OutputFragmentAccepted)
                    }
                    ExactSameSecretProofEncodingProgress::Complete {
                        canonical_byte_length,
                    } => {
                        let complete_object_byte_length = self
                            .canonical_header_bytes
                            .len()
                            .checked_add(canonical_byte_length)
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::CountOverflow,
                            ))?;
                        if self.canonical_output_byte_length != Some(complete_object_byte_length) {
                            return Err(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ));
                        }
                        self.exact_proof_encoder = None;
                        let usage = self
                            .external_memory_executor
                            .take()
                            .ok_or(CommonProofGenerationError::Prover(
                                CommonProofProverError::InvalidInput,
                            ))?
                            .finish()
                            .map_err(CommonProofGenerationError::StoragePlan)?;
                        self.terminal_external_memory_usage = Some(usage);
                        self.relation_polynomial_shapes.clear();
                        self.auxiliary_reconstruction_challenges.clear();
                        self.opened_replay_polynomial_plans.clear();
                        self.quotient_transform_plans.clear();
                        self.bound_tree_entries.clear();
                        self.relation_trees.clear();
                        self.canonical_header_bytes.clear();
                        self.phase = RowCodeWhirGenerationPhase::Complete;
                        Ok(CommonProofGenerationPoll::Complete)
                    }
                }
            }
            RowCodeWhirGenerationPhase::Complete => Ok(CommonProofGenerationPoll::Complete),
            RowCodeWhirGenerationPhase::Cancelled => Err(CommonProofGenerationError::Prover(
                CommonProofProverError::InvalidInput,
            )),
        }
    }

    fn finish_aggregate_source_materialization(&mut self) -> Result<(), CommonProofProverError> {
        if self.active_aggregate_source_batch.is_some()
            || self.aggregate_source_writer.is_some()
            || self.aggregate_source_batch_column_offset != 0
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let (aggregate_witness, metadata, challenger, row_pad_seeds) = self
            .exact_same_secret_aggregate_source
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?
            .finish()?
            .into_parts();
        if metadata.binding_digest() == [0_u8; HASH_BYTE_LENGTH]
            || metadata.construction_identity_hash() != self.construction_plan_identity_hash
            || metadata.action_catalog_digest() == [0_u8; HASH_BYTE_LENGTH]
            || metadata.action_count() == 0
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let hiding_configuration = super::hiding_whir::selected_hiding_whir_config(
            self.construction_plan.selected_parameters(),
        )
        .map_err(|_| CommonProofProverError::InvalidInput)?;
        let hiding_material_generation =
            AggregateWideHidingMaterialGeneration::new(&hiding_configuration)
                .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        self.exact_same_secret_aggregate_metadata = Some(metadata);
        self.exact_same_secret_aggregate_witness = Some(aggregate_witness);
        self.aggregate_challenger = Some(challenger);
        self.row_pad_seeds = row_pad_seeds;
        self.aggregate_wide_hiding_material_generation = Some(hiding_material_generation);
        Ok(())
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
                .map_err(map_aggregate_wide_cancel_error)?;
            true
        } else if let Some(commitment_generation) = self.aggregate_commitment_generation.take() {
            commitment_generation
                .cancel(
                    self.external_memory_executor
                        .as_mut()
                        .ok_or(ProofExternalMemoryError::InvalidLifecycle)?,
                    storage,
                )
                .map_err(map_aggregate_wide_cancel_error)?;
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
        self.active_aggregate_source_batch = None;
        self.aggregate_source_writer = None;
        self.aggregate_source_batch_column_offset = 0;
        self.active_bound_tree_authentication_builder = None;
        self.bound_tree_authentications.clear();
        self.row_pad_seeds = None;
        self.phase_commitment_builder = None;
        self.active_phase_commitment = None;
        self.active_phase_materialization_purpose = None;
        self.active_phase_authenticated_columns = None;
        self.active_phase_polynomial_reader = None;
        self.active_phase_polynomial_binding = None;
        self.active_phase_row_dft = None;
        self.authenticated_transcript_prefix = None;
        self.row_code_whir_transcript = None;
        self.opening_points.clear();
        self.out_of_domain_evaluations.clear();
        self.opening_batch_mask_chunk_evaluations.clear();
        self.application_challenges.clear();
        self.auxiliary_reconstruction_challenges.clear();
        self.auxiliary_materialization = None;
        self.quotient_materialization = None;
        self.active_quotient_transform = None;
        self.pending_quotient_evaluation_read = None;
        self.exact_same_secret_aggregate_metadata = None;
        self.exact_same_secret_aggregate_witness = None;
        self.exact_same_secret_opening_schedule = None;
        self.aggregate_wide_hiding_material_generation = None;
        self.aggregate_challenger = None;
        self.aggregate_commitment = None;
        self.aggregate_wide_pad_commitment = None;
        self.pending_aggregate_checkpoint_boundary = None;
        self.aggregate_wide_opening_proof = None;
        self.exact_proof_encoder = None;
        self.canonical_output_byte_length = None;
        self.phase_row_witness.fill(ProofBaseFieldElement::ZERO);
        self.phase_row_witness = Zeroizing::new(Vec::new());
        self.phase_roots = [None; 3];
        self.phase_authenticated_columns = std::array::from_fn(|_| None);
        self.phase_opening_frontiers = std::array::from_fn(|_| None);
        self.exact_same_secret_phase_openings = None;
        self.relation_polynomial_shapes.clear();
        self.opened_replay_polynomial_plans.clear();
        self.quotient_transform_plans.clear();
        self.aggregate_source_table = None;
        self.aggregate_residuals = None;
        self.canonical_header_bytes.clear();
        self.relation_trees.clear();
        self.bound_tree_entries.clear();
        self.phase = RowCodeWhirGenerationPhase::Cancelled;
        Ok(())
    }

    fn relation_polynomial_reader<Coins>(
        &self,
        column_ordinal: u32,
        coins: &mut Coins,
    ) -> Result<RowCodeWhirRelationPolynomialReader, CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: crate::bgv::proof_suite::CommonProofPrivateCoinSource,
    {
        let private_mask =
            crate::bgv::proof_suite::prover::replay_relation_private_mask_polynomial(
                &self.relation_plan_variant,
                column_ordinal,
                coins,
                ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
            )?;
        if let Ok(source_index) = self
            .construction_plan
            .requested_source_column_ordinals
            .binary_search(&column_ordinal)
        {
            let descriptor = self
                .relation_plan_variant
                .ordered_columns()
                .get(
                    usize::try_from(column_ordinal)
                        .map_err(|_| CommonProofProverError::CountOverflow)?,
                )
                .cloned()
                .ok_or(CommonProofProverError::InvalidColumn)?;
            let catalog = self
                .source_replay_identity_catalog
                .as_ref()
                .filter(|catalog| {
                    catalog.len()
                        == self
                            .construction_plan
                            .requested_source_column_ordinals
                            .len()
                })
                .ok_or(CommonProofProverError::InvalidColumn)?;
            return RecomputedSourcePolynomialReader::new(
                self.source_request_context,
                column_ordinal,
                descriptor,
                catalog
                    .identity_at(source_index)
                    .ok_or(CommonProofProverError::InvalidColumn)?,
                self.relation_plan_variant.trace_domain_size(),
                private_mask,
            )
            .map(RowCodeWhirRelationPolynomialReader::RecomputedSource)
            .map_err(CommonProofPrivateCoinError::Prover);
        }
        if let Some((source_column_ordinal, _)) = self
            .reversed_column_bindings
            .iter()
            .find(|(_, reversed_column_ordinal)| *reversed_column_ordinal == column_ordinal)
            .copied()
        {
            return Ok(RowCodeWhirRelationPolynomialReader::RecomputedReversed(
                RecomputedReversedPolynomialReader {
                    source_reader: Box::new(
                        self.relation_polynomial_reader(source_column_ordinal, coins)?,
                    ),
                    trace_domain_size: self.relation_plan_variant.trace_domain_size(),
                    unmasked_reversed: None,
                    private_mask,
                },
            ));
        }
        if self
            .auxiliary_reconstruction_catalog
            .contains(column_ordinal)
            && !self.auxiliary_reconstruction_challenges.is_empty()
        {
            let reconstruction = CommonProofAuxiliaryColumnReconstructionCursor::new(
                &self.relation_plan_variant,
                &self.relation_context,
                &self.auxiliary_reconstruction_challenges,
                &self.auxiliary_reconstruction_catalog,
                column_ordinal,
            )?;
            let input_readers = reconstruction
                .ordered_input_column_ordinals()
                .iter()
                .copied()
                .map(|input_column_ordinal| {
                    Ok((
                        input_column_ordinal,
                        self.relation_polynomial_reader(input_column_ordinal, coins)?,
                    ))
                })
                .collect::<Result<Vec<_>, CommonProofPrivateCoinError<Coins::Error>>>()?;
            return RecomputedAuxiliaryPolynomialReader::new(
                reconstruction,
                input_readers,
                private_mask,
            )
            .map(RowCodeWhirRelationPolynomialReader::RecomputedAuxiliary)
            .map_err(CommonProofPrivateCoinError::Prover);
        }
        Err(CommonProofPrivateCoinError::Prover(
            CommonProofProverError::InvalidColumn,
        ))
    }

    fn pending_poll_for_relation_reader_progress(
        &mut self,
        progress: RowCodeWhirRelationPolynomialReaderPoll,
    ) -> Result<Option<CommonProofGenerationPoll>, CommonProofProverError> {
        match progress {
            RowCodeWhirRelationPolynomialReaderPoll::ArithmeticStepCompleted => {
                Ok(Some(CommonProofGenerationPoll::ArithmeticStepCompleted))
            }
            RowCodeWhirRelationPolynomialReaderPoll::StorageTransactionCompleted => {
                Ok(Some(CommonProofGenerationPoll::StorageTransactionCompleted))
            }
            RowCodeWhirRelationPolynomialReaderPoll::AuthenticatedSourceReadRequired => {
                let request = self
                    .source_polynomial_provider
                    .as_deref()
                    .ok_or(CommonProofProverError::InvalidInput)?
                    .pending_authenticated_source_read_request()?
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                if self
                    .pending_authenticated_source_read
                    .replace(request)
                    .is_some()
                {
                    return Err(CommonProofProverError::InvalidInput);
                }
                Ok(Some(CommonProofGenerationPoll::ArithmeticStepCompleted))
            }
            RowCodeWhirRelationPolynomialReaderPoll::Complete => Ok(None),
        }
    }

    fn polynomial_reader<Coins>(
        &self,
        target: RowCodeWhirReplayPolynomialTarget,
        coins: &mut Coins,
    ) -> Result<RowCodeWhirRelationPolynomialReader, CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: crate::bgv::proof_suite::CommonProofPrivateCoinSource,
    {
        match target {
            RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal) => {
                self.relation_polynomial_reader(column_ordinal, coins)
            }
            RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(source) => {
                Ok(RowCodeWhirRelationPolynomialReader::Stored(
                    CommonProofReplayPolynomialReader::new(
                        self.opened_replay_polynomial_plans
                            .get(&source)
                            .copied()
                            .ok_or(CommonProofProverError::InvalidColumn)?,
                    )?,
                ))
            }
        }
    }

    fn polynomial_range_reader<Coins>(
        &self,
        target: RowCodeWhirReplayPolynomialTarget,
        coefficient_range: core::ops::Range<usize>,
        coins: &mut Coins,
    ) -> Result<RowCodeWhirRelationPolynomialRangeReader, CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: crate::bgv::proof_suite::CommonProofPrivateCoinSource,
    {
        match target {
            RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal) => {
                let descriptor = self
                    .relation_plan_variant
                    .ordered_columns()
                    .get(
                        usize::try_from(column_ordinal)
                            .map_err(|_| CommonProofProverError::CountOverflow)?,
                    )
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                if coefficient_range.start > coefficient_range.end
                    || coefficient_range.end
                        > usize::try_from(descriptor.source_degree_bound_exclusive())
                            .map_err(|_| CommonProofProverError::CountOverflow)?
                {
                    return Err(CommonProofProverError::InvalidColumn.into());
                }
                Ok(RowCodeWhirRelationPolynomialRangeReader::Recomputed {
                    reader: Some(Box::new(
                        self.relation_polynomial_reader(column_ordinal, coins)?,
                    )),
                    coefficient_range,
                })
            }
            RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(source) => {
                let plan = self
                    .opened_replay_polynomial_plans
                    .get(&source)
                    .copied()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                CommonProofReplayPolynomialRangeReader::new(plan, coefficient_range)
                    .map(RowCodeWhirRelationPolynomialRangeReader::Stored)
                    .map_err(CommonProofPrivateCoinError::Prover)
            }
        }
    }

    fn begin_exact_same_secret_aggregate_source_read<Coins>(
        &mut self,
        action: ExactSameSecretAggregateSourceAction,
        coins: &mut Coins,
    ) -> Result<(), CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: crate::bgv::proof_suite::CommonProofPrivateCoinSource,
    {
        if self.phase != RowCodeWhirGenerationPhase::MaterializingAggregateSource
            || self.active_aggregate_source_read.is_some()
        {
            return Err(CommonProofProverError::InvalidInput.into());
        }
        let target = match action.target() {
            ExactSameSecretAggregateSourceTarget::RelationColumn { column_ordinal } => {
                RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal)
            }
            ExactSameSecretAggregateSourceTarget::OpenedPolynomial { source } => {
                RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(source)
            }
        };
        let (value_type, coefficient_count) = match target {
            RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal) => self
                .relation_polynomial_shapes
                .get(&column_ordinal)
                .copied()
                .ok_or(CommonProofProverError::InvalidColumn)?,
            RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(source) => {
                let plan = self
                    .opened_replay_polynomial_plans
                    .get(&source)
                    .copied()
                    .ok_or(CommonProofProverError::InvalidColumn)?;
                (plan.value_type(), plan.coefficient_count())
            }
        };
        let source_range_end = action
            .source_range_start()
            .checked_add(action.source_range_length())
            .ok_or(CommonProofProverError::CountOverflow)?;
        if value_type != action.value_type()
            || coefficient_count != action.source_coefficient_count()
            || source_range_end > action.source_coefficient_count()
        {
            return Err(CommonProofProverError::InvalidColumn.into());
        }
        let reader = self.polynomial_range_reader(
            target,
            action.source_range_start()..source_range_end,
            coins,
        )?;
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
    ) -> Result<bool, CommonProofProverError> {
        if self.active_replay_polynomial_writer.is_some()
            || self.pending_replay_polynomial.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let (plan, persisted_polynomial) = match target {
            RowCodeWhirReplayPolynomialTarget::RelationColumn(column_ordinal) => {
                let is_recomputed_relation_column = self
                    .construction_plan
                    .requested_source_column_ordinals
                    .binary_search(&column_ordinal)
                    .is_ok()
                    || self
                        .reversed_column_bindings
                        .iter()
                        .any(|(_, reversed)| *reversed == column_ordinal)
                    || self
                        .auxiliary_reconstruction_catalog
                        .contains(column_ordinal);
                let Some((expected_value_type, expected_coefficient_count)) = self
                    .relation_polynomial_shapes
                    .get(&column_ordinal)
                    .copied()
                else {
                    return Err(CommonProofProverError::InvalidColumn);
                };
                let has_expected_shape = match (&polynomial, expected_value_type) {
                    (
                        CommonProofSourcePolynomial::Base(coefficients),
                        RelationColumnValueType::BaseField,
                    ) => coefficients.len() == expected_coefficient_count,
                    (
                        CommonProofSourcePolynomial::Extension(coefficients),
                        RelationColumnValueType::ChallengeExtension,
                    ) => coefficients.len() == expected_coefficient_count,
                    _ => false,
                };
                if !is_recomputed_relation_column || !has_expected_shape {
                    return Err(CommonProofProverError::InvalidColumn);
                }
                drop(polynomial);
                return Ok(false);
            }
            RowCodeWhirReplayPolynomialTarget::OpenedPolynomial(source) => (
                self.opened_replay_polynomial_plans
                    .get(&source)
                    .copied()
                    .ok_or(CommonProofProverError::InvalidColumn)?,
                polynomial,
            ),
        };
        let writer = CommonProofReplayPolynomialWriter::new(
            plan,
            CommonProofReplayPolynomialRef::Source(&persisted_polynomial),
        )?;
        self.pending_replay_polynomial = Some(PendingRowCodeWhirReplayPolynomial {
            target,
            polynomial: persisted_polynomial,
            continuation,
        });
        self.active_replay_polynomial_writer = Some(writer);
        Ok(true)
    }

    fn phase_root(&self, phase: RowCodeWhirPhase) -> Option<ColumnDigest> {
        self.phase_roots[row_code_whir_phase_index(phase)]
    }

    fn phase_roots_match_checkpoint_boundary(
        &self,
        boundary: RowCodeWhirCheckpointBoundary,
    ) -> bool {
        let completed_phase_count = match boundary {
            RowCodeWhirCheckpointBoundary::SourcesAndConstruction => 0,
            RowCodeWhirCheckpointBoundary::PhaseCommitment { phase } => {
                let Some(position) = self
                    .construction_plan
                    .phase_order
                    .iter()
                    .position(|scheduled_phase| *scheduled_phase == phase)
                else {
                    return false;
                };
                position + 1
            }
            RowCodeWhirCheckpointBoundary::RelationEvaluationsAndMask => {
                self.construction_plan.phase_order.len()
            }
            _ => return false,
        };
        [
            RowCodeWhirPhase::Base,
            RowCodeWhirPhase::Auxiliary,
            RowCodeWhirPhase::Quotient,
        ]
        .into_iter()
        .all(|phase| {
            let should_be_present =
                self.construction_plan.phase_order[..completed_phase_count].contains(&phase);
            self.phase_root(phase).is_some() == should_be_present
        })
    }

    fn scheduled_phase_roots_are_complete(&self) -> bool {
        self.construction_plan
            .phase_order
            .iter()
            .all(|phase| self.phase_root(*phase).is_some())
            && [
                RowCodeWhirPhase::Base,
                RowCodeWhirPhase::Auxiliary,
                RowCodeWhirPhase::Quotient,
            ]
            .into_iter()
            .filter(|phase| !self.construction_plan.phase_order.contains(phase))
            .all(|phase| self.phase_root(phase).is_none())
    }

    fn begin_authenticated_phase_openings(
        &mut self,
        phase: RowCodeWhirPhase,
    ) -> Result<(), CommonProofProverError> {
        if !self.construction_plan.phase_order.contains(&phase) {
            return Err(CommonProofProverError::InvalidInput);
        }
        match phase {
            RowCodeWhirPhase::Base => {
                self.prepare_relation_phase_materialization(
                    phase,
                    RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                )?;
                self.phase = RowCodeWhirGenerationPhase::MaterializingBasePhaseOpenings;
            }
            RowCodeWhirPhase::Auxiliary => {
                self.prepare_relation_phase_materialization(
                    phase,
                    RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                )?;
                self.phase = RowCodeWhirGenerationPhase::MaterializingAuxiliaryPhaseOpenings;
            }
            RowCodeWhirPhase::Quotient => {
                self.prepare_quotient_phase_materialization(
                    RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                )?;
                self.phase = RowCodeWhirGenerationPhase::MaterializingQuotientPhaseOpenings;
            }
        }
        Ok(())
    }

    fn advance_authenticated_phase_openings(
        &mut self,
        completed_phase: RowCodeWhirPhase,
    ) -> Result<(), CommonProofProverError> {
        let completed_phase_position = self
            .construction_plan
            .phase_order
            .iter()
            .position(|phase| *phase == completed_phase)
            .ok_or(CommonProofProverError::InvalidInput)?;
        if let Some(next_phase) = self
            .construction_plan
            .phase_order
            .get(completed_phase_position + 1)
            .copied()
        {
            self.begin_authenticated_phase_openings(next_phase)
        } else {
            self.finish_exact_same_secret_phase_openings()?;
            self.source_polynomial_provider
                .as_deref_mut()
                .ok_or(CommonProofProverError::InvalidInput)?
                .finish_source_replay()?;
            self.source_polynomial_provider = None;
            self.phase = RowCodeWhirGenerationPhase::CompletingAggregateCommitment;
            Ok(())
        }
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

    fn validate_source_construction_input(&self) -> Result<(), CommonProofProverError> {
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
        let source_table = self
            .aggregate_source_table
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let residuals = self
            .aggregate_residuals
            .as_ref()
            .ok_or(CommonProofProverError::InvalidInput)?;
        let selected_parameters = self.construction_plan.selected_parameters();
        let expected_residual_count = self.construction_plan.whir_plan().rounds.len();
        let mut residual_variable_count = selected_parameters.polynomial_commitment_variable_count;
        let residual_shapes_match =
            residuals
                .iter()
                .enumerate()
                .all(|(residual_ordinal, residual)| {
                    let folding_factor = if residual_ordinal == 0 {
                        self.construction_plan
                            .whir_plan()
                            .initial_sumcheck_round_count
                    } else {
                        let Some(previous_round) = self
                            .construction_plan
                            .whir_plan()
                            .rounds
                            .get(residual_ordinal - 1)
                        else {
                            return false;
                        };
                        previous_round.following_sumcheck_round_count
                    };
                    let Some(next_variable_count) =
                        residual_variable_count.checked_sub(folding_factor)
                    else {
                        return false;
                    };
                    residual_variable_count = next_variable_count;
                    let Some(expected_element_count) = u32::try_from(next_variable_count)
                        .ok()
                        .and_then(|exponent| 1_usize.checked_shl(exponent))
                    else {
                        return false;
                    };
                    residual.value_type() == RelationColumnValueType::ChallengeExtension
                        && residual.element_count() == expected_element_count
                });
        let source_objects = source_table
            .columns()
            .iter()
            .map(|column| column.object())
            .chain(residuals.iter().map(|residual| residual.object()))
            .collect::<Vec<_>>();
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
            || source_table.table_variable_count() != selected_parameters.table_variable_count
            || source_table.table_width() != self.construction_plan.aggregate_table_width()
            || source_table.folding_factor() != selected_parameters.folding_factor
            || source_table.stacked_variable_count()
                != selected_parameters.polynomial_commitment_variable_count
            || residuals.len() != expected_residual_count
            || !residual_shapes_match
            || source_objects.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        validate_generation_relation_trees(&self.relation_plan_variant, &self.relation_trees)
    }

    fn opening_batch_mask_chunk_evaluation_count(&self) -> Result<usize, CommonProofProverError> {
        if self.construction_plan.proof_privacy_mode == ProofPrivacyMode::PublicOnly {
            if self
                .construction_plan
                .proof_sections()
                .iter()
                .any(|section| {
                    section.role == RowCodeWhirProofSectionRole::OpeningBatchMaskEvaluations
                })
                || self
                    .construction_plan
                    .quotient_phase
                    .opening_batch_mask_degree_bound_exclusive
                    .is_some()
                || self
                    .relation_plan_variant
                    .ordered_opening_claims()
                    .iter()
                    .any(|claim| claim.source_class() == RelationOpeningSourceClass::BatchMask)
            {
                return Err(CommonProofProverError::InvalidMask);
            }
            return Ok(0);
        }
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
        let logical_polynomial_coefficient_count = self
            .construction_plan
            .parameters
            .logical_polynomial_coefficient_count;
        if logical_polynomial_coefficient_count == 0 {
            return Err(CommonProofProverError::InvalidMask);
        }
        let coefficient_chunk_count =
            degree_bound_exclusive.div_ceil(logical_polynomial_coefficient_count);
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

    fn private_column_leaf_salt_context(
        &self,
        phase: RowCodeWhirPhase,
    ) -> Result<Option<PrivateColumnLeafSaltContext>, CommonProofProverError> {
        match self.construction_plan.proof_privacy_mode {
            ProofPrivacyMode::SecretBearing => {
                let seed = self
                    .row_pad_seeds
                    .as_ref()
                    .and_then(|seeds| seeds.get(row_code_whir_phase_index(phase)))
                    .ok_or(CommonProofProverError::InvalidMask)?;
                Ok(Some(PrivateColumnLeafSaltContext::new(
                    seed,
                    private_column_leaf_salt_role(phase),
                )))
            }
            ProofPrivacyMode::PublicOnly => {
                if self.row_pad_seeds.is_some() {
                    return Err(CommonProofProverError::InvalidMask);
                }
                Ok(None)
            }
        }
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
            || self.active_phase_row_dft.is_some()
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
        let logical_polynomial_coefficient_count = self
            .construction_plan
            .parameters
            .logical_polynomial_coefficient_count;
        let logical_polynomials_per_physical_row = self
            .construction_plan
            .parameters
            .logical_polynomials_per_physical_row;
        validate_phase_materialization_shape(
            logical_polynomial_coefficient_count,
            logical_polynomials_per_physical_row,
            phase.geometry,
            phase.rows.len(),
            phase.rows.iter().any(|row| {
                row.logical_polynomial_chunks
                    .get(logical_polynomials_per_physical_row..)
                    .is_none_or(|padding| padding.iter().any(Option::is_some))
            }),
        )?;
        let opened_column_indices =
            self.phase_opening_traversal_indices(purpose, phase.geometry.encoded_column_count)?;
        let builder = InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
            phase.geometry.row_count,
            phase.geometry.encoded_column_count,
            MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT,
            &opened_column_indices,
            self.private_column_leaf_salt_context(phase_role)?,
        )
        .map_err(|_| CommonProofProverError::InvalidTree)?;
        let phase_row_working_capacity = phase_row_working_capacity(phase.geometry)?;
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
                builder.maximum_digest_plane_byte_length().ok().and_then(
                    |digest_plane_byte_length| byte_length.checked_add(digest_plane_byte_length),
                )
            })
            .and_then(|byte_length| {
                builder
                    .metadata_allocation_byte_length()
                    .ok()
                    .and_then(|metadata_byte_length| byte_length.checked_add(metadata_byte_length))
            })
            .and_then(|byte_length| {
                phase_row_working_capacity
                    .checked_mul(size_of::<ProofBaseFieldElement>())
                    .and_then(|working_row_byte_length| {
                        byte_length.checked_add(working_row_byte_length)
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
                    &opened_column_indices,
                    phase.geometry.row_count,
                    phase.geometry.encoded_column_count,
                    self.private_column_leaf_salt_context(phase_role)?.as_ref(),
                )?)
            }
        };
        self.phase_row_witness = allocate_phase_row_witness(
            phase.geometry.witness_values_per_row,
            phase_row_working_capacity,
        )?;
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
        let logical_polynomial_coefficient_count = self
            .construction_plan
            .parameters
            .logical_polynomial_coefficient_count;
        let source_start = usize::try_from(coefficient_chunk_ordinal)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(logical_polynomial_coefficient_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if source_start >= coefficients.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_end = source_start
            .checked_add(logical_polynomial_coefficient_count)
            .map(|end| end.min(coefficients.len()))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination_start = logical_block_index
            .checked_mul(logical_polynomial_coefficient_count)
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
            *destination_value = *coefficient;
        }
        Ok(())
    }

    fn poll_relation_phase_commitment<Coins>(
        &mut self,
        phase_role: RowCodeWhirPhase,
        coins: &mut Coins,
    ) -> Result<CommonProofGenerationPoll, CommonProofPrivateCoinError<Coins::Error>>
    where
        Coins: crate::bgv::proof_suite::CommonProofPrivateCoinSource,
    {
        if self.active_phase_commitment != Some(phase_role) {
            return Err(CommonProofProverError::InvalidInput.into());
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
                .complete_active_lane()
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
                        self.advance_authenticated_phase_openings(RowCodeWhirPhase::Base)?;
                    }
                    (
                        RowCodeWhirPhaseMaterializationPurpose::AuthenticatedOpenings,
                        RowCodeWhirPhase::Auxiliary,
                    ) => {
                        self.advance_authenticated_phase_openings(RowCodeWhirPhase::Auxiliary)?;
                    }
                    (_, RowCodeWhirPhase::Quotient) => {
                        return Err(CommonProofProverError::InvalidInput.into());
                    }
                }
            } else {
                self.next_phase_row_index = 0;
                self.next_phase_logical_chunk_index = 0;
                self.phase_row_witness.fill(ProofBaseFieldElement::ZERO);
            }
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let row = phase
            .rows
            .get(self.next_phase_row_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.next_phase_logical_chunk_index
            < self
                .construction_plan
                .parameters
                .logical_polynomials_per_physical_row
        {
            let logical_block_index = self.next_phase_logical_chunk_index;
            let Some(chunk) = row.logical_polynomial_chunks[logical_block_index] else {
                self.next_phase_logical_chunk_index = self
                    .next_phase_logical_chunk_index
                    .checked_add(1)
                    .ok_or(CommonProofProverError::CountOverflow)?;
                return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
            };
            self.active_phase_polynomial_reader =
                Some(self.relation_polynomial_reader(chunk.column_ordinal, coins)?);
            self.active_phase_polynomial_binding =
                Some(RowCodeWhirPhasePolynomialBinding::Relation {
                    logical_block_index,
                    column_ordinal: chunk.column_ordinal,
                    coefficient_chunk_ordinal: chunk.coefficient_chunk_ordinal,
                });
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let private_row_pad_seed = match self.construction_plan.proof_privacy_mode {
            ProofPrivacyMode::SecretBearing => Some(
                *self
                    .row_pad_seeds
                    .as_ref()
                    .and_then(|seeds| seeds.get(row_code_whir_phase_index(phase_role)))
                    .ok_or(CommonProofProverError::InvalidInput)?,
            ),
            ProofPrivacyMode::PublicOnly => {
                if self.row_pad_seeds.is_some() {
                    return Err(CommonProofProverError::InvalidInput.into());
                }
                None
            }
        };
        let row_high_half_source = private_row_pad_seed.as_ref().map_or(
            RowCodeHighHalfSource::CanonicalPublicZeros,
            RowCodeHighHalfSource::PrivateMaskSeed,
        );
        self.poll_active_phase_row_dft(phase_role, phase.geometry, row_high_half_source)
            .map_err(Into::into)
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
            || self.active_phase_row_dft.is_some()
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
        let logical_polynomial_coefficient_count = self
            .construction_plan
            .parameters
            .logical_polynomial_coefficient_count;
        let logical_polynomials_per_physical_row = self
            .construction_plan
            .parameters
            .logical_polynomials_per_physical_row;
        validate_phase_materialization_shape(
            logical_polynomial_coefficient_count,
            logical_polynomials_per_physical_row,
            phase.geometry,
            phase.rows.len(),
            phase.rows.iter().any(|row| {
                row.logical_polynomial_chunks
                    .get(logical_polynomials_per_physical_row..)
                    .is_none_or(|padding| padding.iter().any(Option::is_some))
            }),
        )?;
        let opened_column_indices =
            self.phase_opening_traversal_indices(purpose, phase.geometry.encoded_column_count)?;
        let builder = InterleavedColumnCommitmentBuilder::new_with_opened_columns_and_private_salt(
            phase.geometry.row_count,
            phase.geometry.encoded_column_count,
            MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT,
            &opened_column_indices,
            self.private_column_leaf_salt_context(RowCodeWhirPhase::Quotient)?,
        )
        .map_err(|_| CommonProofProverError::InvalidTree)?;
        let phase_row_working_capacity = phase_row_working_capacity(phase.geometry)?;
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
                builder.maximum_digest_plane_byte_length().ok().and_then(
                    |digest_plane_byte_length| byte_length.checked_add(digest_plane_byte_length),
                )
            })
            .and_then(|byte_length| {
                builder
                    .metadata_allocation_byte_length()
                    .ok()
                    .and_then(|metadata_byte_length| byte_length.checked_add(metadata_byte_length))
            })
            .and_then(|byte_length| {
                phase_row_working_capacity
                    .checked_mul(size_of::<ProofBaseFieldElement>())
                    .and_then(|working_row_byte_length| {
                        byte_length.checked_add(working_row_byte_length)
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
                    &opened_column_indices,
                    phase.geometry.row_count,
                    phase.geometry.encoded_column_count,
                    self.private_column_leaf_salt_context(RowCodeWhirPhase::Quotient)?
                        .as_ref(),
                )?)
            }
        };
        self.phase_row_witness = allocate_phase_row_witness(
            phase.geometry.witness_values_per_row,
            phase_row_working_capacity,
        )?;
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
        let logical_polynomial_coefficient_count = self
            .construction_plan
            .parameters
            .logical_polynomial_coefficient_count;
        let source_start = usize::try_from(coefficient_chunk_ordinal)
            .map_err(|_| CommonProofProverError::CountOverflow)?
            .checked_mul(logical_polynomial_coefficient_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if source_start >= coefficients.len() {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let source_end = source_start
            .checked_add(logical_polynomial_coefficient_count)
            .map(|end| end.min(coefficients.len()))
            .ok_or(CommonProofProverError::CountOverflow)?;
        let destination_start = logical_block_index
            .checked_mul(logical_polynomial_coefficient_count)
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
            *destination_value = ProofBaseFieldElement::from_reduced(u128::from(coordinate));
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
                .complete_active_lane()
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
                        self.advance_authenticated_phase_openings(RowCodeWhirPhase::Quotient)?;
                    }
                }
            } else {
                self.next_phase_row_index = 0;
                self.next_phase_logical_chunk_index = 0;
                self.phase_row_witness.fill(ProofBaseFieldElement::ZERO);
            }
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let row = phase
            .rows
            .get(self.next_phase_row_index)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if self.next_phase_logical_chunk_index
            < self
                .construction_plan
                .parameters
                .logical_polynomials_per_physical_row
        {
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
                Some(RowCodeWhirRelationPolynomialReader::Stored(
                    CommonProofReplayPolynomialReader::new(plan)?,
                ));
            self.active_phase_polynomial_binding =
                Some(RowCodeWhirPhasePolynomialBinding::Opened {
                    logical_block_index,
                    source: chunk.source,
                    coefficient_chunk_ordinal: chunk.coefficient_chunk_ordinal,
                });
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }

        let private_row_pad_seed = match self.construction_plan.proof_privacy_mode {
            ProofPrivacyMode::SecretBearing => Some(
                *self
                    .row_pad_seeds
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
                None
            }
        };
        let row_high_half_source = private_row_pad_seed.as_ref().map_or(
            RowCodeHighHalfSource::CanonicalPublicZeros,
            RowCodeHighHalfSource::PrivateMaskSeed,
        );
        self.poll_active_phase_row_dft(
            RowCodeWhirPhase::Quotient,
            phase.geometry,
            row_high_half_source,
        )
    }

    /// Advances one phase row through one allocation-stable interleaved coset
    /// lane and streams it into the root-preserving commitment transpose.
    ///
    /// The witness, padded coefficients, and evaluations reuse one owned
    /// lane-or-coefficient-capacity allocation. No cached twiddle table or second encoded
    /// row overlaps the lane hasher.
    fn poll_active_phase_row_dft(
        &mut self,
        phase_role: RowCodeWhirPhase,
        geometry: RowEncodingGeometry,
        row_high_half_source: RowCodeHighHalfSource<'_>,
    ) -> Result<CommonProofGenerationPoll, CommonProofProverError> {
        if self.active_phase_commitment != Some(phase_role)
            || self.next_phase_logical_chunk_index
                != self
                    .construction_plan
                    .parameters
                    .logical_polynomials_per_physical_row
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        if self.active_phase_row_dft.is_none() {
            let working_capacity = phase_row_working_capacity(geometry)?;
            if self.phase_row_witness.len() != geometry.witness_values_per_row
                || self.phase_row_witness.capacity() < working_capacity
            {
                return Err(CommonProofProverError::InvalidColumn);
            }
            let (lane_column_count, lane_ordinal) = self
                .phase_commitment_builder
                .as_ref()
                .and_then(|builder| {
                    builder
                        .active_lane_ordinal()
                        .map(|lane_ordinal| (builder.lane_column_count(), lane_ordinal))
                })
                .ok_or(CommonProofProverError::InvalidInput)?;
            let witness =
                core::mem::replace(&mut self.phase_row_witness, Zeroizing::new(Vec::new()));
            let coefficients = padded_base_row_coefficients(
                geometry,
                self.next_phase_row_index,
                witness,
                row_high_half_source,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
            let evaluation_domain = ProofEvaluationDomain::new(
                geometry.encoded_column_count,
                self.relation_context.evaluation_coset_offset,
            )
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
            self.active_phase_row_dft = Some(
                BoundedBaseCosetLaneDft::new(
                    coefficients,
                    evaluation_domain,
                    lane_column_count,
                    lane_ordinal,
                )
                .map_err(|_| CommonProofProverError::InvalidColumn)?,
            );
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }
        if !self
            .active_phase_row_dft
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)?
            .poll()
            .map_err(|_| CommonProofProverError::InvalidColumn)?
        {
            return Ok(CommonProofGenerationPoll::ArithmeticStepCompleted);
        }
        let mut encoded_row = self
            .active_phase_row_dft
            .take()
            .ok_or(CommonProofProverError::InvalidInput)?
            .into_values()
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        let (lane_count, lane_column_count, lane_ordinal) = self
            .phase_commitment_builder
            .as_ref()
            .and_then(|builder| {
                builder.active_lane_ordinal().map(|lane_ordinal| {
                    (
                        builder.lane_count(),
                        builder.lane_column_count(),
                        lane_ordinal,
                    )
                })
            })
            .ok_or(CommonProofProverError::InvalidInput)?;
        if encoded_row.len() != lane_column_count {
            return Err(CommonProofProverError::InvalidColumn);
        }
        self.capture_active_phase_authenticated_row(
            self.next_phase_row_index,
            geometry.encoded_column_count,
            lane_count,
            lane_ordinal,
            &encoded_row,
        )?;
        self.phase_commitment_builder
            .as_mut()
            .ok_or(CommonProofProverError::InvalidInput)?
            .absorb_active_lane_base_row(self.next_phase_row_index, &encoded_row)
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        encoded_row.fill(ProofBaseFieldElement::ZERO);
        encoded_row.resize(geometry.witness_values_per_row, ProofBaseFieldElement::ZERO);
        self.phase_row_witness = encoded_row;
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
    /// live. Only the columns inside the active lane are captured, so the
    /// caller never needs a second encoding pass or a resident codeword.
    fn capture_active_phase_authenticated_row(
        &mut self,
        row_index: usize,
        encoded_column_count: usize,
        lane_count: usize,
        lane_ordinal: usize,
        encoded_row_lane: &[ProofBaseFieldElement],
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
        if lane_count == 0
            || !lane_count.is_power_of_two()
            || lane_ordinal >= lane_count
            || encoded_row_lane.len().checked_mul(lane_count) != Some(encoded_column_count)
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        for (active_position, column_index) in traversal_indices.iter().copied().enumerate() {
            let Some(value) = phase_commitment_lane_opening_value(
                encoded_column_count,
                lane_count,
                lane_ordinal,
                column_index,
                encoded_row_lane,
            )?
            else {
                continue;
            };
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
            || self.active_phase_row_dft.is_some()
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
        self.phase_row_witness = Zeroizing::new(Vec::new());
        self.next_phase_row_index = 0;
        self.next_phase_logical_chunk_index = 0;
        Ok((purpose, root))
    }

    /// Collects every scheduled phase opening once each phase has reproduced
    /// its committed root.
    fn finish_exact_same_secret_phase_openings(&mut self) -> Result<(), CommonProofProverError> {
        if self.exact_same_secret_phase_openings.is_some()
            || self.phase_commitment_builder.is_some()
            || self.active_phase_commitment.is_some()
            || self.active_phase_materialization_purpose.is_some()
            || self.active_phase_authenticated_columns.is_some()
            || self.active_phase_row_dft.is_some()
        {
            return Err(CommonProofProverError::InvalidInput);
        }
        let roots = self.phase_roots;
        let mut authenticated_columns_by_phase: [Option<Vec<AuthenticatedColumn>>; 3] =
            std::array::from_fn(|_| None);
        let mut frontiers_by_phase: [Option<Vec<ColumnDigest>>; 3] = std::array::from_fn(|_| None);
        for phase in [
            RowCodeWhirPhase::Base,
            RowCodeWhirPhase::Auxiliary,
            RowCodeWhirPhase::Quotient,
        ] {
            let phase_index = row_code_whir_phase_index(phase);
            let is_scheduled = self.construction_plan.phase_order.contains(&phase);
            if roots[phase_index].is_some() != is_scheduled
                || self.phase_authenticated_columns[phase_index].is_some() != is_scheduled
                || self.phase_opening_frontiers[phase_index].is_some() != is_scheduled
            {
                return Err(CommonProofProverError::InvalidOpening);
            }
            if is_scheduled {
                let columns = self.phase_authenticated_columns[phase_index]
                    .take()
                    .ok_or(CommonProofProverError::InvalidOpening)?;
                if columns.len() != self.construction_plan.parameters.outer_query_count {
                    return Err(CommonProofProverError::InvalidOpening);
                }
                authenticated_columns_by_phase[phase_index] = Some(columns);
                frontiers_by_phase[phase_index] = Some(
                    self.phase_opening_frontiers[phase_index]
                        .take()
                        .ok_or(CommonProofProverError::InvalidOpening)?,
                );
            }
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
    opened_column_indices: &[usize],
    row_count: usize,
    encoded_column_count: usize,
    private_leaf_salt: Option<&PrivateColumnLeafSaltContext>,
) -> Result<Vec<AuthenticatedColumn>, CommonProofProverError> {
    let opened_column_count = opened_column_indices.len();
    if opened_column_count == 0 || row_count == 0 {
        return Err(CommonProofProverError::InvalidOpening);
    }
    let mut authenticated_columns = Vec::new();
    authenticated_columns
        .try_reserve_exact(opened_column_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for column_index in opened_column_indices {
        let mut values = Vec::new();
        values
            .try_reserve_exact(row_count)
            .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
        let persistent_salt = private_leaf_salt
            .map(|context| context.salt(encoded_column_count, row_count, *column_index))
            .transpose()
            .map_err(|_| CommonProofProverError::InvalidTree)?;
        authenticated_columns.push(AuthenticatedColumn {
            persistent_salt,
            values,
        });
    }
    Ok(authenticated_columns)
}

fn phase_commitment_lane_opening_value(
    encoded_column_count: usize,
    lane_count: usize,
    lane_ordinal: usize,
    column_index: usize,
    encoded_row_lane: &[ProofBaseFieldElement],
) -> Result<Option<Goldilocks>, CommonProofProverError> {
    if encoded_column_count == 0
        || !encoded_column_count.is_power_of_two()
        || lane_count == 0
        || !lane_count.is_power_of_two()
        || lane_ordinal >= lane_count
        || column_index >= encoded_column_count
        || encoded_row_lane.len().checked_mul(lane_count) != Some(encoded_column_count)
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    if column_index % lane_count != lane_ordinal {
        return Ok(None);
    }
    encoded_row_lane
        .get(column_index / lane_count)
        .copied()
        .map(|value| Some(Goldilocks::new(value.canonical())))
        .ok_or(CommonProofProverError::InvalidColumn)
}

fn phase_row_working_capacity(
    geometry: RowEncodingGeometry,
) -> Result<usize, CommonProofProverError> {
    let lane_column_count = geometry
        .encoded_column_count
        .min(MAXIMUM_PHASE_COMMITMENT_LANE_COLUMN_COUNT);
    if lane_column_count == 0
        || !lane_column_count.is_power_of_two()
        || !geometry
            .encoded_column_count
            .is_multiple_of(lane_column_count)
        || geometry.padded_coefficient_count > geometry.encoded_column_count
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(geometry.padded_coefficient_count.max(lane_column_count))
}

fn allocate_phase_row_witness(
    witness_value_count: usize,
    working_capacity: usize,
) -> Result<Zeroizing<Vec<ProofBaseFieldElement>>, CommonProofProverError> {
    if witness_value_count == 0
        || working_capacity < witness_value_count
        || !working_capacity.is_power_of_two()
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    let mut witness = Vec::new();
    witness
        .try_reserve_exact(working_capacity)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    witness.resize(witness_value_count, ProofBaseFieldElement::ZERO);
    Ok(Zeroizing::new(witness))
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

fn evaluate_quotient_transform_in_place(
    plan: RowCodeWhirQuotientColumnTransformPlan,
    polynomial: &mut CommonProofSourcePolynomial,
) -> Result<(), CommonProofProverError> {
    let evaluation_domain = plan.evaluation_domain();
    if polynomial.value_type() != plan.source().value_type()
        || polynomial.coefficient_count() == 0
        || polynomial.coefficient_count() > plan.source().coefficient_count()
        || plan.output().coefficient_count() != evaluation_domain.size()
        || plan.output().value_type() != polynomial.value_type()
        || plan.output().exact_byte_length() > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    {
        return Err(CommonProofProverError::InvalidColumn);
    }
    match polynomial {
        CommonProofSourcePolynomial::Base(coefficients) => {
            evaluation_domain.evaluate_base_polynomial_in_place(coefficients)?;
        }
        CommonProofSourcePolynomial::Extension(coefficients) => {
            evaluation_domain.evaluate_extension_polynomial_in_place(coefficients)?;
        }
    }
    if polynomial.coefficient_count() != evaluation_domain.size() {
        return Err(CommonProofProverError::InvalidColumn);
    }
    Ok(())
}

fn evaluate_opening_batch_mask_chunks(
    polynomial: &CommonProofSourcePolynomial,
    opening_point: ProofChallengeExtensionElement,
    logical_polynomial_coefficient_count: usize,
    chunk_count: usize,
) -> Result<Vec<ProofChallengeExtensionElement>, CommonProofProverError> {
    let CommonProofSourcePolynomial::Extension(coefficients) = polynomial else {
        return Err(CommonProofProverError::InvalidMask);
    };
    let maximum_coefficient_count = logical_polynomial_coefficient_count
        .checked_mul(chunk_count)
        .ok_or(CommonProofProverError::CountOverflow)?;
    if logical_polynomial_coefficient_count == 0
        || chunk_count == 0
        || coefficients.is_empty()
        || coefficients.len() > maximum_coefficient_count
    {
        return Err(CommonProofProverError::InvalidMask);
    }
    let mut evaluations = Vec::new();
    evaluations
        .try_reserve_exact(chunk_count)
        .map_err(|_| CommonProofProverError::AllocationLimitExceeded)?;
    for chunk_ordinal in 0..chunk_count {
        let chunk_start = chunk_ordinal
            .checked_mul(logical_polynomial_coefficient_count)
            .ok_or(CommonProofProverError::CountOverflow)?;
        if chunk_start >= coefficients.len() {
            evaluations.push(ProofChallengeExtensionElement::ZERO);
            continue;
        }
        let chunk_end = chunk_start
            .checked_add(logical_polynomial_coefficient_count)
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
) -> Result<CommonProofSourceProviderMemoryAccounting, CommonProofGenerationInitializationError> {
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
    Ok(accounting)
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

fn map_relation_polynomial_reader_error<StorageError, CoinError, SinkError>(
    error: RowCodeWhirRelationPolynomialReaderError<StorageError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        RowCodeWhirRelationPolynomialReaderError::Prover(error) => {
            CommonProofGenerationError::Prover(error)
        }
        RowCodeWhirRelationPolynomialReaderError::Storage(error) => {
            CommonProofGenerationError::Storage(error)
        }
    }
}

fn map_aggregate_wide_hiding_material_generation_error<StorageError, CoinError, SinkError>(
    error: AggregateWideHidingMaterialGenerationError<CoinError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        AggregateWideHidingMaterialGenerationError::Geometry(_) => {
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
        }
        AggregateWideHidingMaterialGenerationError::CoinSource(error) => {
            CommonProofGenerationError::CoinSource(error)
        }
    }
}

fn map_aggregate_wide_generation_error<StorageError, CoinError, SinkError>(
    error: StreamingAggregateWideError<StorageError>,
) -> CommonProofGenerationError<StorageError, CoinError, SinkError> {
    match error {
        StreamingAggregateWideError::Geometry(message) => {
            drop(message);
            CommonProofGenerationError::Prover(CommonProofProverError::InvalidInput)
        }
        StreamingAggregateWideError::Storage(error) => CommonProofGenerationError::Storage(error),
    }
}

fn map_aggregate_wide_cancel_error<StorageError>(
    error: StreamingAggregateWideError<StorageError>,
) -> ProofExternalMemoryExecutorError<StorageError> {
    match error {
        StreamingAggregateWideError::Geometry(message) => {
            drop(message);
            ProofExternalMemoryError::InvalidLifecycle.into()
        }
        StreamingAggregateWideError::Storage(error) => error,
    }
}

const fn row_code_whir_phase_index(phase: RowCodeWhirPhase) -> usize {
    match phase {
        RowCodeWhirPhase::Base => 0,
        RowCodeWhirPhase::Auxiliary => 1,
        RowCodeWhirPhase::Quotient => 2,
    }
}

pub(super) const fn private_column_leaf_salt_role(phase: RowCodeWhirPhase) -> &'static [u8] {
    match phase {
        RowCodeWhirPhase::Base => b"relation-phase/base",
        RowCodeWhirPhase::Auxiliary => b"relation-phase/auxiliary",
        RowCodeWhirPhase::Quotient => b"relation-phase/quotient",
    }
}

fn durable_checkpoint_for_aggregate_proof_boundary(
    boundary: StreamingAggregateWideProofBoundary,
) -> Option<RowCodeWhirCheckpointBoundary> {
    match boundary {
        StreamingAggregateWideProofBoundary::RoundStorageReleased {
            completed_round_count,
        } => completed_round_count
            .checked_sub(1)
            .and_then(|round_ordinal| u32::try_from(round_ordinal).ok())
            .map(|round_ordinal| RowCodeWhirCheckpointBoundary::WhirRound { round_ordinal }),
        StreamingAggregateWideProofBoundary::MaskedSumcheckRound { .. }
        | StreamingAggregateWideProofBoundary::RoundOracleArithmetic { .. }
        | StreamingAggregateWideProofBoundary::RoundOracleStorage { .. }
        | StreamingAggregateWideProofBoundary::RoundQueriesPrepared { .. }
        | StreamingAggregateWideProofBoundary::BaseCasePrepared
        | StreamingAggregateWideProofBoundary::BaseSourceStorage
        | StreamingAggregateWideProofBoundary::BaseStorageReleased
        | StreamingAggregateWideProofBoundary::ProofReady => None,
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

fn aggregate_commitment_digest_bytes(
    commitment: &AggregateWideCommitment,
) -> Option<[u8; HASH_BYTE_LENGTH]> {
    let [root] = commitment.roots() else {
        return None;
    };
    let mut bytes = [0_u8; HASH_BYTE_LENGTH];
    for (word_index, word) in root.iter().copied().enumerate() {
        bytes[word_index * size_of::<u64>()..(word_index + 1) * size_of::<u64>()]
            .copy_from_slice(&word.to_le_bytes());
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "primitive-measurement-evidence")]
    use super::super::commitment_liveness::derive_phase_commitment_work_accounting;
    use super::super::commitment_liveness::{
        GenerationPhaseLivenessKind, derive_phase_commitment_geometry_accounting,
    };
    #[cfg(feature = "primitive-measurement-evidence")]
    use super::super::primitive_measurements::{
        VssPersistedCheckpointReplayBaseline, derive_bounded_vss_opening_claim_quotient_candidate,
        derive_vss_fused_bound_range_candidate_construction_plan,
        derive_vss_persisted_checkpoint_replay_candidate_ledgers,
    };
    use super::*;
    #[cfg(feature = "primitive-measurement-evidence")]
    use crate::bgv::proof_suite::relation_plan::fused_vss_radix_51_source_provider_memory_accounting;
    use crate::{
        bgv::proof_suite::{
            SelectedApplicationStatementContext, ValidatedRelationPlanArtifact,
            canonical_selected_application_statement_for_ceiling,
            compile_same_secret_relation_plan, compile_same_secret_relation_with_source_layout,
            compile_vss_share_linkage_relation_plan,
            external_memory::{
                AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
                NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
            },
            relation_plan::{
                same_secret_source_provider_memory_accounting,
                selected_vss_source_provider_memory_accounting,
            },
            selected_accounting::resource_accounting::selected_relation_tree_inputs,
            selected_committed_material_relation_plan_input, selected_relation_plan_check_context,
            selected_same_secret_relation_plan_input,
        },
        foundation::{
            FOUNDATION_PROFILE, Hash512, MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
            MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
            ProofApplicationSlotCeilings,
        },
    };

    struct BoundTreeTestSourceProvider;

    impl CommonProofSourcePolynomialProvider for BoundTreeTestSourceProvider {
        fn memory_accounting(
            &self,
        ) -> Result<
            crate::bgv::proof_suite::prover::CommonProofSourceProviderMemoryAccounting,
            CommonProofProverError,
        > {
            Ok(
                crate::bgv::proof_suite::prover::CommonProofSourceProviderMemoryAccounting::new(
                    1, 1, 1, 1,
                ),
            )
        }

        fn poll_source_polynomial(
            &mut self,
            _request: crate::bgv::proof_suite::prover::CommonProofSourcePolynomialRequest<'_>,
        ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
            Err(CommonProofProverError::InvalidColumn)
        }

        fn poll_replayed_source_polynomial(
            &mut self,
            _request: crate::bgv::proof_suite::prover::CommonProofSourcePolynomialRequest<'_>,
        ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
            Err(CommonProofProverError::InvalidColumn)
        }

        fn finish(&mut self) -> Result<(), CommonProofProverError> {
            Ok(())
        }
    }

    fn selected_setup_bound_tree_entry() -> ProofTreeCatalogEntry {
        let schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected same-secret context exists");
        let compiled_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("the selected same-secret input derives"),
            &relation_context,
        )
        .expect("the selected same-secret relation compiles");
        let variant = compiled_plan
            .variants()
            .first()
            .expect("the selected same-secret relation has one variant");
        let relation_trees =
            selected_relation_tree_inputs(variant).expect("the selected relation trees derive");
        build_relation_bound_public_tree_catalog_entries(&relation_trees)
            .expect("the selected bound-tree catalog derives")
            .into_iter()
            .find(ProofTreeCatalogEntry::uses_setup_polynomial_construction)
            .expect("the selected same-secret relation has setup-polynomial bound trees")
    }

    fn drive_test_bound_tree_builder(
        builder: &mut ActiveExactBoundTreeAuthenticationBuilder,
        coefficient_columns: &[Vec<ProofBaseFieldElement>],
    ) -> usize {
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; HASH_BYTE_LENGTH],
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
            [0x22; HASH_BYTE_LENGTH],
            [0x33; HASH_BYTE_LENGTH],
            [0x44; HASH_BYTE_LENGTH],
            None,
            None,
        );
        let mut source_provider = BoundTreeTestSourceProvider;
        let mut column_request_count = 0_usize;
        loop {
            if let Some((column_position, column_ordinal)) = builder.next_column_request() {
                builder
                    .begin_column(
                        column_position,
                        column_ordinal,
                        Zeroizing::new(coefficient_columns[column_position].clone()),
                    )
                    .expect("the bounded test column starts");
                column_request_count += 1;
                continue;
            }
            if builder
                .poll(&mut source_provider, request_context)
                .expect("the bounded test tree advances")
            {
                return column_request_count;
            }
        }
    }

    #[test]
    fn bound_tree_stripes_match_one_stripe_and_recompute_each_column() {
        let entry = selected_setup_bound_tree_entry();
        let row_width = entry
            .materialized_row_width()
            .expect("the selected setup row width derives");
        let leaf_count = 16;
        let evaluation_domain =
            ProofEvaluationDomain::new(leaf_count * 2, 7).expect("the test coset derives");
        let ordered_column_ordinals = (0..row_width)
            .map(|column_position| {
                u32::try_from(column_position).expect("the test column position fits u32")
            })
            .collect::<Vec<_>>();
        let coefficient_columns = (0..row_width)
            .map(|column_position| {
                (0..9)
                    .map(|coefficient_index| {
                        ProofBaseFieldElement::from_canonical(
                            u64::try_from(
                                (column_position + 1) * 1_003 + coefficient_index * 37 + 5,
                            )
                            .expect("the test coefficient fits u64"),
                        )
                        .expect("the test coefficient is canonical")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let query_indices = [0, 5, 15];
        let mut one_stripe =
            ActiveExactBoundTreeAuthenticationBuilder::new_with_maximum_stripe_leaf_count(
                entry.clone(),
                leaf_count,
                &query_indices,
                evaluation_domain,
                &ordered_column_ordinals,
                leaf_count,
            )
            .expect("the one-stripe reference initializes");
        let mut four_stripes =
            ActiveExactBoundTreeAuthenticationBuilder::new_with_maximum_stripe_leaf_count(
                entry,
                leaf_count,
                &query_indices,
                evaluation_domain,
                &ordered_column_ordinals,
                4,
            )
            .expect("the four-stripe builder initializes");

        assert_eq!(
            drive_test_bound_tree_builder(&mut one_stripe, &coefficient_columns),
            row_width,
        );
        assert_eq!(
            drive_test_bound_tree_builder(&mut four_stripes, &coefficient_columns),
            row_width * 4,
        );
        assert_eq!(four_stripes.recomputed_root, one_stripe.recomputed_root);
        assert_eq!(four_stripes.opened_leaves, one_stripe.opened_leaves);
        assert_eq!(four_stripes.frontier_digests, one_stripe.frontier_digests);
        assert_eq!(four_stripes.next_query_position, query_indices.len());
        assert!(four_stripes.evaluated_column_stripes.is_empty());
        assert!(four_stripes.active_column_dft.is_none());
    }

    #[test]
    fn bound_tree_stripes_refuse_noncanonical_geometry_and_query_order() {
        let entry = selected_setup_bound_tree_entry();
        let row_width = entry
            .materialized_row_width()
            .expect("the selected setup row width derives");
        let ordered_column_ordinals = (0..row_width)
            .map(|column_position| {
                u32::try_from(column_position).expect("the test column position fits u32")
            })
            .collect::<Vec<_>>();
        let evaluation_domain = ProofEvaluationDomain::new(32, 7).expect("the test coset derives");

        for maximum_stripe_leaf_count in [0, 3] {
            assert!(
                ActiveExactBoundTreeAuthenticationBuilder::new_with_maximum_stripe_leaf_count(
                    entry.clone(),
                    16,
                    &[1, 7],
                    evaluation_domain,
                    &ordered_column_ordinals,
                    maximum_stripe_leaf_count,
                )
                .is_err(),
            );
        }
        assert!(
            ActiveExactBoundTreeAuthenticationBuilder::new_with_maximum_stripe_leaf_count(
                entry,
                16,
                &[7, 7],
                evaluation_domain,
                &ordered_column_ordinals,
                4,
            )
            .is_err(),
        );
    }

    #[test]
    fn selected_vss_generation_manifest_and_compact_row_geometry_are_compatible() {
        let schema_identifier =
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected VSS relation context exists");
        let relation_input = selected_committed_material_relation_plan_input()
            .expect("the selected committed-material input derives");
        let compiled_plan =
            compile_vss_share_linkage_relation_plan(&relation_input, &relation_context)
                .expect("the selected VSS relation compiles");
        let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
            compiled_plan,
            &relation_context,
        )
        .expect("the selected VSS relation validates");
        let relation_variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the selected VSS relation has one variant");
        let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            &artifact,
            relation_variant.schedule_position(),
            relation_variant.top_count(),
        )
        .expect("the selected VSS construction plan derives");
        let reversed_column_bindings = relation_reversed_column_bindings(relation_variant)
            .expect("the selected VSS reversed-column catalog derives");

        let manifest = checked_same_secret_source_manifest(
            &construction_plan,
            relation_variant,
            artifact.checked_context(),
            &reversed_column_bindings,
        )
        .expect("generation accepts the candidate-specific VSS source manifest");

        assert_eq!(manifest.bound_material_tree_count(), Ok(112));
        let base_phase = construction_plan
            .base_phase
            .as_ref()
            .expect("the selected VSS construction has a base phase");
        let quotient_phase = &construction_plan.quotient_phase;
        let selected_row_width = construction_plan
            .parameters
            .logical_polynomials_per_physical_row;
        let expected_witness_value_count = construction_plan
            .parameters
            .logical_polynomial_coefficient_count
            * selected_row_width;
        let base_has_noncanonical_padding = base_phase.rows.iter().any(|row| {
            row.logical_polynomial_chunks
                .get(selected_row_width..)
                .is_none_or(|padding| padding.iter().any(Option::is_some))
        });
        let quotient_has_noncanonical_padding = quotient_phase.rows.iter().any(|row| {
            row.logical_polynomial_chunks
                .get(selected_row_width..)
                .is_none_or(|padding| padding.iter().any(Option::is_some))
        });

        assert_eq!(selected_row_width, 8);
        assert_eq!(base_phase.rows.len(), base_phase.geometry.row_count);
        assert_eq!(quotient_phase.rows.len(), quotient_phase.geometry.row_count);
        assert_eq!(
            expected_witness_value_count,
            base_phase.geometry.witness_values_per_row
        );
        assert_eq!(
            expected_witness_value_count,
            quotient_phase.geometry.witness_values_per_row
        );
        assert!(base_phase.rows.iter().all(|row| {
            row.logical_polynomial_chunks[selected_row_width..]
                .iter()
                .all(Option::is_none)
        }));
        assert!(quotient_phase.rows.iter().all(|row| {
            row.logical_polynomial_chunks[selected_row_width..]
                .iter()
                .all(Option::is_none)
        }));
        validate_phase_materialization_shape(
            construction_plan
                .parameters
                .logical_polynomial_coefficient_count,
            selected_row_width,
            base_phase.geometry,
            base_phase.rows.len(),
            base_has_noncanonical_padding,
        )
        .expect("the production base-materialization guard accepts the width-eight VSS plan");
        validate_phase_materialization_shape(
            construction_plan
                .parameters
                .logical_polynomial_coefficient_count,
            selected_row_width,
            quotient_phase.geometry,
            quotient_phase.rows.len(),
            quotient_has_noncanonical_padding,
        )
        .expect("the production quotient-materialization guard accepts the width-eight VSS plan");

        let base_commitment_accounting =
            derive_phase_commitment_geometry_accounting(base_phase.geometry)
                .expect("the production VSS base commitment accounting derives");
        assert_eq!(base_commitment_accounting.row_count, 1_128);
        assert_eq!(base_commitment_accounting.encoded_column_count, 16_777_216);
        assert_eq!(base_commitment_accounting.lane_column_count, 524_288);
        assert_eq!(base_commitment_accounting.lane_count, 32);
        assert_eq!(
            base_commitment_accounting.working_buffer_byte_length,
            4_194_304,
        );
        assert_eq!(
            base_commitment_accounting.hash_state_byte_length,
            104_857_600,
        );
        assert_eq!(
            base_commitment_accounting.digest_plane_byte_length,
            167_772_160,
        );
        assert_eq!(
            base_commitment_accounting.algorithm_live_set_byte_length,
            276_824_064,
        );
        assert_eq!(base_commitment_accounting.lane_dft_count_per_pass, 36_096);
        assert_eq!(
            base_commitment_accounting.butterfly_count_per_pass,
            179_784_646_656,
        );
        assert_eq!(
            base_commitment_accounting.coefficient_fold_count_per_pass,
            0,
        );
        assert_eq!(
            base_commitment_accounting.coset_multiplication_count_per_pass,
            18_924_699_648,
        );
        assert_eq!(
            base_commitment_accounting.column_value_delivery_count_per_pass,
            18_924_699_648,
        );
        assert_eq!(
            base_commitment_accounting.leaf_hash_query_count_per_pass,
            16_777_216,
        );
        assert_eq!(
            base_commitment_accounting.merkle_parent_hash_query_count_per_pass,
            16_777_215,
        );

        let stale_same_secret_row_width =
            super::super::construction_plan::ROW_CODE_WHIR_LOGICAL_POLYNOMIALS_PER_PHYSICAL_ROW;
        assert_eq!(stale_same_secret_row_width, 64);
        assert_eq!(
            validate_phase_materialization_shape(
                construction_plan
                    .parameters
                    .logical_polynomial_coefficient_count,
                stale_same_secret_row_width,
                base_phase.geometry,
                base_phase.rows.len(),
                base_has_noncanonical_padding,
            ),
            Err(CommonProofProverError::InvalidColumn),
            "the stale same-secret width reproduces the archived VSS base-materialization refusal",
        );
        assert_eq!(
            validate_phase_materialization_shape(
                construction_plan
                    .parameters
                    .logical_polynomial_coefficient_count
                    .checked_mul(2)
                    .expect("the hostile coefficient count fits usize"),
                selected_row_width,
                base_phase.geometry,
                base_phase.rows.len(),
                base_has_noncanonical_padding,
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
        assert_eq!(
            validate_phase_materialization_shape(
                construction_plan
                    .parameters
                    .logical_polynomial_coefficient_count,
                selected_row_width,
                base_phase.geometry,
                base_phase.rows.len() - 1,
                base_has_noncanonical_padding,
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
        assert_eq!(
            validate_phase_materialization_shape(
                construction_plan
                    .parameters
                    .logical_polynomial_coefficient_count,
                selected_row_width,
                base_phase.geometry,
                base_phase.rows.len(),
                true,
            ),
            Err(CommonProofProverError::InvalidColumn),
        );
        assert_eq!(
            validate_phase_materialization_shape(
                usize::MAX,
                2,
                base_phase.geometry,
                base_phase.rows.len(),
                false,
            ),
            Err(CommonProofProverError::CountOverflow),
        );
    }

    #[test]
    fn selected_vss_complete_generation_liveness_derives_from_the_production_layout() {
        let schema_identifier =
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected VSS relation context exists");
        let relation_input = selected_committed_material_relation_plan_input()
            .expect("the selected VSS relation input derives");
        let compiled_plan =
            compile_vss_share_linkage_relation_plan(&relation_input, &relation_context)
                .expect("the selected VSS relation compiles");
        let source_provider = selected_vss_source_provider_memory_accounting(
            &relation_input,
            &relation_context,
            &compiled_plan,
        )
        .expect("the selected VSS source-provider accounting derives");
        let relation_variant = compiled_plan
            .variants()
            .first()
            .expect("the selected VSS relation has one variant");
        let canonical_statement = canonical_selected_application_statement_for_ceiling(
            schema_identifier,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0_u8; Hash512::BYTE_LENGTH],
                relation_variant.schedule_position(),
                relation_variant.top_count(),
            ),
        )
        .expect("the selected VSS statement encodes");
        let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
            compiled_plan,
            &relation_context,
        )
        .expect("the selected VSS relation validates");
        let validated_variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the validated VSS relation has one variant");
        let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            &artifact,
            validated_variant.schedule_position(),
            validated_variant.top_count(),
        )
        .expect("the selected VSS construction derives");
        let relation_trees = selected_relation_tree_inputs(validated_variant)
            .expect("the selected VSS relation trees derive");
        let bound_tree_entries = build_relation_bound_public_tree_catalog_entries(&relation_trees)
            .expect("the selected VSS bound-tree entries derive");
        let canonical_header_bytes = canonical_proof_object_header_bytes(&canonical_statement)
            .expect("the selected VSS proof header derives");
        let relation_plan_hash = artifact
            .compiled_plan()
            .canonical_hash()
            .expect("the selected VSS relation plan hashes");
        let relation_plan_variant_hash = validated_variant
            .canonical_hash()
            .expect("the selected VSS relation variant hashes");
        let source_request_context = CommonProofSourcePolynomialRequestContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; HASH_BYTE_LENGTH],
            schema_identifier,
            [0x22; HASH_BYTE_LENGTH],
            relation_plan_hash,
            relation_plan_variant_hash,
            validated_variant.schedule_position(),
            validated_variant.top_count(),
        );
        let source_cursor =
            CommonProofPreChallengeSourceCursor::new(validated_variant, source_request_context)
                .expect("the selected VSS source cursor derives");
        let reversed_column_bindings = source_cursor.reversed_column_bindings().to_vec();
        let source_manifest = checked_same_secret_source_manifest(
            &construction_plan,
            validated_variant,
            &relation_context,
            &reversed_column_bindings,
        )
        .expect("the selected VSS source manifest derives");
        let storage_plan = RowCodeWhirGenerationStoragePlan::new(
            &construction_plan,
            validated_variant,
            &relation_context,
            &reversed_column_bindings,
        )
        .expect("the selected VSS storage plan derives");
        let complete_liveness = derive_generation_liveness(
            &construction_plan,
            validated_variant,
            &relation_context,
            &relation_trees,
            &bound_tree_entries,
            &canonical_header_bytes,
            &source_cursor,
            &source_manifest,
            &reversed_column_bindings,
            &storage_plan,
            source_provider,
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        )
        .expect("the complete selected VSS live set derives");
        let aggregate_source_row_byte_length =
            aggregate_source_row_peak_byte_length(&construction_plan)
                .expect("the selected VSS aggregate source row peak derives");
        let aggregate_source_control_byte_length = aggregate_source_control_payload_byte_length(
            &construction_plan,
            validated_variant,
            &relation_context,
        )
        .expect("the selected VSS aggregate source control payload derives");
        let aggregate_batch_column_count = construction_plan.aggregate_table_width() / 2;
        let aggregate_batch_byte_length = (1_u64
            << construction_plan.selected_parameters().table_variable_count)
            .checked_mul(
                u64::try_from(aggregate_batch_column_count)
                    .expect("the aggregate batch column count fits u64"),
            )
            .and_then(|count| {
                count.checked_mul(
                    u64::try_from(size_of::<ProofChallengeExtensionElement>())
                        .expect("the extension width fits u64"),
                )
            })
            .and_then(|byte_length| {
                byte_length.checked_add(
                    u64::try_from(aggregate_batch_column_count * size_of::<Vec<ChallengeField>>())
                        .expect("the aggregate column catalog width fits u64"),
                )
            })
            .expect("the selected VSS aggregate batch byte length adds");
        assert_eq!(aggregate_source_row_byte_length, 6_291_456);
        assert_eq!(aggregate_source_control_byte_length, 3_362_419);
        assert_eq!(aggregate_batch_byte_length, 335_544_704);
        assert_eq!(
            aggregate_batch_byte_length
                + aggregate_source_row_byte_length
                + aggregate_source_control_byte_length,
            345_198_579,
        );
        let phase_commitment = complete_liveness
            .rows()
            .iter()
            .find(|row| row.phase() == GenerationPhaseLivenessKind::PhaseCommitment)
            .expect("the selected VSS phase-commitment row exists");
        assert_eq!(
            phase_commitment.wasm_runtime_baseline_byte_length(),
            33_554_432
        );
        assert_eq!(phase_commitment.engine_control_byte_length(), 19_216_957);
        assert_eq!(phase_commitment.source_provider_byte_length(), 30_431_184);
        assert_eq!(phase_commitment.replay_reader_byte_length(), 11_534_336);
        assert_eq!(phase_commitment.dft_buffer_byte_length(), 4_194_304);
        assert_eq!(
            phase_commitment.merkle_and_frontier_byte_length(),
            276_973_656,
        );
        assert_eq!(
            phase_commitment.proof_encoder_non_salt_byte_length(),
            39_873_954,
        );
        assert_eq!(
            phase_commitment.transported_private_leaf_salt_byte_length(),
            4_268_672,
        );
        assert_eq!(phase_commitment.transcript_byte_length(), 223_432);
        assert_eq!(phase_commitment.private_material_byte_length(), 721_672);
        assert_eq!(phase_commitment.private_leaf_salt_state_byte_length(), 0);
        assert_eq!(
            phase_commitment.private_leaf_salt_workspace_byte_length(),
            392,
        );
        assert_eq!(
            phase_commitment.private_leaf_salt_uniqueness_set_byte_length(),
            0,
        );
        assert_eq!(phase_commitment.bridge_copy_byte_length(), 2_097_508);
        assert_eq!(phase_commitment.specialized_workspace_byte_length(), 0);
        let allocator_owned_byte_length = [
            phase_commitment.engine_control_byte_length(),
            phase_commitment.source_provider_byte_length(),
            phase_commitment.replay_reader_byte_length(),
            phase_commitment.dft_buffer_byte_length(),
            phase_commitment.merkle_and_frontier_byte_length(),
            phase_commitment.proof_encoder_non_salt_byte_length(),
            phase_commitment.transported_private_leaf_salt_byte_length(),
            phase_commitment.transcript_byte_length(),
            phase_commitment.private_material_byte_length(),
            phase_commitment.private_leaf_salt_state_byte_length(),
            phase_commitment.private_leaf_salt_workspace_byte_length(),
            phase_commitment.private_leaf_salt_uniqueness_set_byte_length(),
            phase_commitment.bridge_copy_byte_length(),
            phase_commitment.specialized_workspace_byte_length(),
        ]
        .into_iter()
        .try_fold(0_u64, |total, byte_length| total.checked_add(byte_length))
        .expect("the selected VSS owned live set adds");
        assert_eq!(allocator_owned_byte_length, 389_536_067);
        assert_eq!(
            phase_commitment.allocator_overhead_byte_length(),
            allocator_owned_byte_length.div_ceil(8),
        );
        assert_eq!(
            phase_commitment.allocator_overhead_byte_length(),
            48_692_009
        );
        assert_eq!(
            phase_commitment.total_byte_length(),
            phase_commitment.wasm_runtime_baseline_byte_length()
                + allocator_owned_byte_length
                + allocator_owned_byte_length.div_ceil(8),
        );
        assert_eq!(phase_commitment.total_byte_length(), 471_782_508);
        assert_eq!(
            complete_liveness.maximum_live_set_byte_length(),
            557_729_241
        );

        let base_phase = construction_plan
            .base_phase
            .as_ref()
            .expect("the selected VSS base phase exists");
        let geometry_accounting = derive_phase_commitment_geometry_accounting(base_phase.geometry)
            .expect("the selected VSS phase geometry derives");
        let retained_source_row_byte_length = geometry_accounting.working_buffer_byte_length;
        let additional_lane_hasher_byte_length = geometry_accounting.hash_state_byte_length;
        let grouped_phase_total = |active_lane_count: u64| {
            let additional_owned_byte_length = active_lane_count
                .checked_sub(1)
                .and_then(|additional_lane_count| {
                    additional_lane_count.checked_mul(additional_lane_hasher_byte_length)
                })
                .and_then(|additional_hashers| {
                    additional_hashers.checked_add(retained_source_row_byte_length)
                })
                .expect("the selected VSS grouped-lane live set adds");
            let grouped_owned_byte_length = allocator_owned_byte_length
                .checked_add(additional_owned_byte_length)
                .expect("the selected VSS grouped-lane owned live set adds");
            phase_commitment
                .wasm_runtime_baseline_byte_length()
                .checked_add(grouped_owned_byte_length)
                .and_then(|total| total.checked_add(grouped_owned_byte_length.div_ceil(8)))
                .expect("the selected VSS grouped-lane total adds")
        };
        let two_lane_total_byte_length = grouped_phase_total(2);
        assert_eq!(two_lane_total_byte_length, 594_465_900);
        assert_eq!(
            crate::bgv::proof_suite::prover::AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                .checked_sub(two_lane_total_byte_length),
            Some(9_513_876),
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH.checked_sub(two_lane_total_byte_length),
            Some(76_622_740),
        );
        let three_lane_total_byte_length = grouped_phase_total(3);
        assert_eq!(three_lane_total_byte_length, 712_430_700);
        assert!(three_lane_total_byte_length > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH);
    }

    #[cfg(feature = "primitive-measurement-evidence")]
    #[test]
    fn fused_vss_radix_51_candidate_complete_generation_liveness_derives() {
        let (relation_input, artifact, relation_context, construction_plan) =
            derive_vss_fused_bound_range_candidate_construction_plan(51)
                .expect("the fused VSS radix-51 candidate derives");
        let relation_variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the fused VSS radix-51 candidate has one variant");
        let source_provider = fused_vss_radix_51_source_provider_memory_accounting(
            &relation_input,
            &relation_context,
            artifact.compiled_plan(),
        )
        .expect("the fused VSS radix-51 source-provider accounting derives");
        let schema_identifier =
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        let canonical_statement = canonical_selected_application_statement_for_ceiling(
            schema_identifier,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0_u8; Hash512::BYTE_LENGTH],
                relation_variant.schedule_position(),
                relation_variant.top_count(),
            ),
        )
        .expect("the fused VSS radix-51 statement encodes");
        let relation_trees = selected_relation_tree_inputs(relation_variant)
            .expect("the fused VSS radix-51 relation trees derive");
        let bound_tree_entries = build_relation_bound_public_tree_catalog_entries(&relation_trees)
            .expect("the fused VSS radix-51 bound-tree entries derive");
        let canonical_header_bytes = canonical_proof_object_header_bytes(&canonical_statement)
            .expect("the fused VSS radix-51 proof header derives");
        let relation_plan_hash = artifact
            .compiled_plan()
            .canonical_hash()
            .expect("the fused VSS radix-51 relation plan hashes");
        let relation_plan_variant_hash = relation_variant
            .canonical_hash()
            .expect("the fused VSS radix-51 relation variant hashes");
        let source_request_context = CommonProofSourcePolynomialRequestContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x51; HASH_BYTE_LENGTH],
            schema_identifier,
            [0x52; HASH_BYTE_LENGTH],
            relation_plan_hash,
            relation_plan_variant_hash,
            relation_variant.schedule_position(),
            relation_variant.top_count(),
        );
        let source_cursor =
            CommonProofPreChallengeSourceCursor::new(relation_variant, source_request_context)
                .expect("the fused VSS radix-51 source cursor derives");
        let reversed_column_bindings = source_cursor.reversed_column_bindings().to_vec();
        let source_manifest =
            SameSecretAuthenticatedSourceManifest::derive_for_primitive_measurement_candidate(
                &construction_plan,
                relation_variant,
                &relation_context,
            )
            .expect("the fused VSS radix-51 source manifest derives");
        source_manifest
            .validate_against_primitive_measurement_candidate(
                &construction_plan,
                relation_variant,
                &relation_context,
            )
            .expect("the fused VSS radix-51 source manifest validates");
        let storage_plan = RowCodeWhirGenerationStoragePlan::new(
            &construction_plan,
            relation_variant,
            &relation_context,
            &reversed_column_bindings,
        )
        .expect("the fused VSS radix-51 storage plan derives");
        let external_memory_requirement =
            CommonProofExternalMemoryRequirement::from_external_memory_plan(
                &storage_plan.external_memory_plan,
            )
            .expect("the fused VSS radix-51 external-memory requirement derives");
        let liveness_input = derive_generation_liveness_input(
            &construction_plan,
            relation_variant,
            &relation_context,
            &relation_trees,
            &bound_tree_entries,
            &canonical_header_bytes,
            &source_cursor,
            &source_manifest,
            &reversed_column_bindings,
            &storage_plan,
            source_provider,
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        )
        .expect("the fused VSS radix-51 liveness input derives");
        let complete_liveness =
            derive_complete_generation_liveness(&construction_plan, liveness_input)
                .expect("the fused VSS radix-51 complete live set closes the hard bound");
        assert_eq!(
            aggregate_source_resident_batch_column_count(&construction_plan),
            Ok(1)
        );
        assert_eq!(
            aggregate_source_materialization_pass_count(&construction_plan),
            Ok(4)
        );
        assert_eq!(external_memory_requirement.step_count(), 24_104);
        assert_eq!(
            external_memory_requirement.maximum_chunk_byte_length(),
            1_048_576
        );
        assert_eq!(
            external_memory_requirement.maximum_transaction_payload_byte_length(),
            1_048_576
        );
        assert_eq!(
            external_memory_requirement.distinct_physical_object_count(),
            58
        );
        assert_eq!(external_memory_requirement.object_lifecycle_count(), 18_218);
        assert_eq!(
            external_memory_requirement.peak_stored_byte_length(),
            885_618_680
        );
        assert_eq!(
            external_memory_requirement.total_written_byte_length(),
            5_670_455_288
        );
        assert_eq!(
            external_memory_requirement.total_read_byte_length(),
            73_344_195_928
        );
        assert_eq!(external_memory_requirement.transaction_count(), 2_866_177);
        assert_eq!(
            external_memory_requirement.local_record_seal_invocation_count(),
            55_525
        );
        assert_eq!(
            external_memory_requirement.local_record_sealed_plaintext_byte_length(),
            5_670_619_250
        );
        assert_eq!(
            storage_plan.external_memory_read_traffic,
            RowCodeWhirExternalMemoryReadTraffic {
                opened_polynomial_replay_byte_length: 44_549_590_360,
                quotient_transform_byte_length: 5_597_298_688,
                aggregate_source_byte_length: 23_197_306_880,
            }
        );
        assert_eq!(
            storage_plan
                .external_memory_read_traffic
                .total_byte_length(),
            Some(external_memory_requirement.total_read_byte_length())
        );
        assert_eq!(
            storage_plan.external_memory_transaction_traffic,
            RowCodeWhirExternalMemoryTransactionTraffic {
                initialization_count: 1,
                opened_polynomial_replay_count: 48_568,
                quotient_transform_count: 2_787_686,
                pre_retained_deletion_count: 5_888,
                aggregate_source_count: 24_034,
            }
        );
        assert_eq!(
            storage_plan
                .external_memory_transaction_traffic
                .total_count(),
            Some(external_memory_requirement.transaction_count())
        );
        assert_eq!(
            external_memory_requirement
                .peak_stored_byte_length()
                .saturating_sub(NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
            617_183_224
        );
        assert_eq!(
            external_memory_requirement
                .peak_stored_byte_length()
                .saturating_sub(AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
            482_965_496
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                .checked_sub(external_memory_requirement.peak_stored_byte_length()),
            Some(188_123_144)
        );
        assert!(
            external_memory_requirement.peak_stored_byte_length()
                > AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        );
        assert!(
            external_memory_requirement.peak_stored_byte_length()
                <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        );
        assert!(!external_memory_requirement.exceeds_active_root_seal_custody_budget());
        let external_object_plans = storage_plan
            .external_memory_plan
            .clone()
            .into_object_plans();
        assert_eq!(external_object_plans.len(), 18_218);
        assert!(external_object_plans.iter().all(|object| {
            object.protection() == ProofExternalMemoryProtection::SecretAuthenticatedEncryption
                && object.issued_step() <= object.seal_step()
                && object.seal_step() <= object.last_use_step()
                && object.last_use_step() < external_memory_requirement.step_count()
        }));

        let expected_phase_totals = [
            (
                GenerationPhaseLivenessKind::LoadingAuthenticatedSources,
                178_450_846,
            ),
            (GenerationPhaseLivenessKind::SourceReplay, 319_450_104),
            (
                GenerationPhaseLivenessKind::RelationMaterialization,
                319_450_104,
            ),
            (GenerationPhaseLivenessKind::PhaseCommitment, 665_012_106),
            (
                GenerationPhaseLivenessKind::QuotientPreparation,
                325_724_087,
            ),
            (GenerationPhaseLivenessKind::AggregateSource, 565_644_904),
            (
                GenerationPhaseLivenessKind::PrivateMaterialSampling,
                224_710_101,
            ),
            (
                GenerationPhaseLivenessKind::AggregateOpeningPreparation,
                412_642_296,
            ),
            (
                GenerationPhaseLivenessKind::AggregateCommitment,
                639_135_873,
            ),
            (
                GenerationPhaseLivenessKind::BoundTreeAuthentication,
                450_391_644,
            ),
            (GenerationPhaseLivenessKind::WhirOpening, 607_111_227),
            (GenerationPhaseLivenessKind::BaseCaseOpening, 273_640_707),
            (GenerationPhaseLivenessKind::CanonicalEncoding, 196_928_091),
        ];
        assert_eq!(complete_liveness.rows().len(), expected_phase_totals.len());
        for (row, (expected_phase, expected_total_byte_length)) in
            complete_liveness.rows().iter().zip(expected_phase_totals)
        {
            assert_eq!(row.phase(), expected_phase);
            assert_eq!(row.total_byte_length(), expected_total_byte_length);
            let allocator_owned_byte_length = [
                row.engine_control_byte_length(),
                row.source_provider_byte_length(),
                row.replay_reader_byte_length(),
                row.dft_buffer_byte_length(),
                row.merkle_and_frontier_byte_length(),
                row.proof_encoder_non_salt_byte_length(),
                row.transported_private_leaf_salt_byte_length(),
                row.transcript_byte_length(),
                row.private_material_byte_length(),
                row.private_leaf_salt_state_byte_length(),
                row.private_leaf_salt_workspace_byte_length(),
                row.private_leaf_salt_uniqueness_set_byte_length(),
                row.bridge_copy_byte_length(),
                row.specialized_workspace_byte_length(),
            ]
            .into_iter()
            .try_fold(0_u64, |total, byte_length| total.checked_add(byte_length))
            .expect("the fused VSS radix-51 phase-owned live set adds");
            assert_eq!(
                row.allocator_overhead_byte_length(),
                allocator_owned_byte_length.div_ceil(8)
            );
            assert_eq!(
                row.total_byte_length(),
                row.wasm_runtime_baseline_byte_length()
                    + allocator_owned_byte_length
                    + allocator_owned_byte_length.div_ceil(8)
            );
        }
        let phase_commitment = complete_liveness
            .rows()
            .iter()
            .find(|row| row.phase() == GenerationPhaseLivenessKind::PhaseCommitment)
            .expect("the fused VSS radix-51 phase-commitment row exists");
        assert_eq!(phase_commitment.engine_control_byte_length(), 95_769_616);
        assert_eq!(phase_commitment.source_provider_byte_length(), 29_843_072);
        assert_eq!(phase_commitment.replay_reader_byte_length(), 84_934_656);
        assert_eq!(phase_commitment.dft_buffer_byte_length(), 33_554_432);
        assert_eq!(
            phase_commitment.merkle_and_frontier_byte_length(),
            273_611_400
        );
        assert_eq!(
            phase_commitment.proof_encoder_non_salt_byte_length(),
            36_276_930
        );
        assert_eq!(
            phase_commitment.transported_private_leaf_salt_byte_length(),
            4_268_544
        );
        assert_eq!(phase_commitment.transcript_byte_length(), 217_888);
        assert_eq!(phase_commitment.private_material_byte_length(), 721_672);
        assert_eq!(phase_commitment.bridge_copy_byte_length(), 2_097_508);
        assert_eq!(
            phase_commitment.allocator_overhead_byte_length(),
            70_161_964
        );
        let aggregate_source = complete_liveness
            .rows()
            .iter()
            .find(|row| row.phase() == GenerationPhaseLivenessKind::AggregateSource)
            .expect("the fused VSS radix-51 aggregate-source row exists");
        assert_eq!(
            aggregate_source.specialized_workspace_byte_length(),
            218_839_822
        );
        let aggregate_commitment = complete_liveness
            .rows()
            .iter()
            .find(|row| row.phase() == GenerationPhaseLivenessKind::AggregateCommitment)
            .expect("the fused VSS radix-51 aggregate-commitment row exists");
        assert_eq!(aggregate_commitment.dft_buffer_byte_length(), 335_544_320);
        assert_eq!(
            aggregate_commitment.merkle_and_frontier_byte_length(),
            33_554_432
        );
        let whir_opening = complete_liveness
            .rows()
            .iter()
            .find(|row| row.phase() == GenerationPhaseLivenessKind::WhirOpening)
            .expect("the fused VSS radix-51 WHIR-opening row exists");
        assert_eq!(whir_opening.source_provider_byte_length(), 0);
        assert_eq!(
            complete_liveness.maximum_live_set_byte_length(),
            phase_commitment.total_byte_length()
        );
        assert_eq!(
            complete_liveness.maximum_live_set_byte_length(),
            665_012_106
        );
        assert_eq!(
            complete_liveness
                .maximum_live_set_byte_length()
                .saturating_sub(
                    crate::bgv::proof_suite::prover::NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
                ),
            262_358_922
        );
        assert_eq!(
            complete_liveness
                .maximum_live_set_byte_length()
                .saturating_sub(
                crate::bgv::proof_suite::prover::AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
            ),
            61_032_330
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                .checked_sub(complete_liveness.maximum_live_set_byte_length()),
            Some(6_076_534)
        );
        assert!(
            complete_liveness.maximum_live_set_byte_length()
                > crate::bgv::proof_suite::prover::AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        );
        assert!(
            complete_liveness.maximum_live_set_byte_length()
                <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        );
        let phase_commitment_work = complete_liveness.phase_commitment_work();
        assert_eq!(phase_commitment_work.geometry_count, 2);
        assert_eq!(phase_commitment_work.materialization_pass_count, 2);
        assert_eq!(phase_commitment_work.lane_dft_count, 3_328);
        assert_eq!(phase_commitment_work.butterfly_count, 16_575_889_408);
        assert_eq!(phase_commitment_work.coefficient_fold_count, 12_213_813_248);
        assert_eq!(
            phase_commitment_work.coset_multiplication_count,
            1_744_830_464
        );
        assert_eq!(
            phase_commitment_work.column_value_delivery_count,
            1_744_830_464
        );
        assert_eq!(phase_commitment_work.leaf_hash_query_count, 67_108_864);
        assert_eq!(
            phase_commitment_work.merkle_parent_hash_query_count,
            67_108_860
        );
        assert_eq!(
            phase_commitment_work.private_leaf_salt_derivation_count,
            67_108_864
        );
    }

    #[cfg(feature = "primitive-measurement-evidence")]
    #[test]
    fn bounded_vss_quotient_candidate_complete_generation_liveness_derives() {
        let (relation_input, artifact, relation_context, construction_plan) =
            derive_bounded_vss_opening_claim_quotient_candidate()
                .expect("the bounded VSS quotient candidate derives");
        let relation_variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the bounded VSS quotient candidate has one variant");
        assert!(
            construction_plan
                .uses_opening_claim_quotient_batch()
                .expect("the bounded VSS quotient layout derives")
        );
        let source_provider = selected_vss_source_provider_memory_accounting(
            &relation_input,
            &relation_context,
            artifact.compiled_plan(),
        )
        .expect("the bounded VSS quotient source-provider accounting derives");
        let schema_identifier =
            ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER;
        let canonical_statement = canonical_selected_application_statement_for_ceiling(
            schema_identifier,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0_u8; Hash512::BYTE_LENGTH],
                relation_variant.schedule_position(),
                relation_variant.top_count(),
            ),
        )
        .expect("the bounded VSS quotient statement encodes");
        let relation_trees = selected_relation_tree_inputs(relation_variant)
            .expect("the bounded VSS quotient relation trees derive");
        let bound_tree_entries = build_relation_bound_public_tree_catalog_entries(&relation_trees)
            .expect("the bounded VSS quotient bound-tree entries derive");
        let canonical_header_bytes = canonical_proof_object_header_bytes(&canonical_statement)
            .expect("the bounded VSS quotient proof header derives");
        let relation_plan_hash = artifact
            .compiled_plan()
            .canonical_hash()
            .expect("the bounded VSS quotient relation plan hashes");
        let relation_plan_variant_hash = relation_variant
            .canonical_hash()
            .expect("the bounded VSS quotient relation variant hashes");
        let source_request_context = CommonProofSourcePolynomialRequestContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x31; HASH_BYTE_LENGTH],
            schema_identifier,
            [0x32; HASH_BYTE_LENGTH],
            relation_plan_hash,
            relation_plan_variant_hash,
            relation_variant.schedule_position(),
            relation_variant.top_count(),
        );
        let source_cursor =
            CommonProofPreChallengeSourceCursor::new(relation_variant, source_request_context)
                .expect("the bounded VSS quotient source cursor derives");
        let reversed_column_bindings = source_cursor.reversed_column_bindings().to_vec();
        assert_eq!(
            SameSecretAuthenticatedSourceManifest::derive(
                &construction_plan,
                relation_variant,
                &relation_context,
            ),
            Err(SameSecretAuthenticatedSourceManifestError::WrongSelectedContext),
            "the candidate context remains refused by the selected manifest route",
        );
        let mut wrong_candidate_context = relation_context.clone();
        wrong_candidate_context.maximum_fiat_shamir_candidate_draws_per_output =
            wrong_candidate_context
                .maximum_fiat_shamir_candidate_draws_per_output
                .checked_add(1)
                .expect("the hostile candidate-draw count fits u32");
        assert_eq!(
            SameSecretAuthenticatedSourceManifest::derive_for_primitive_measurement_candidate(
                &construction_plan,
                relation_variant,
                &wrong_candidate_context,
            ),
            Err(SameSecretAuthenticatedSourceManifestError::RelationVariantMismatch),
            "the candidate-only manifest route remains bound to its exact checked context",
        );
        let source_manifest =
            SameSecretAuthenticatedSourceManifest::derive_for_primitive_measurement_candidate(
                &construction_plan,
                relation_variant,
                &relation_context,
            )
            .expect("the bounded VSS quotient candidate source manifest derives");
        source_manifest
            .validate_against_primitive_measurement_candidate(
                &construction_plan,
                relation_variant,
                &relation_context,
            )
            .expect("the bounded VSS quotient candidate source manifest validates");
        assert_eq!(
            source_manifest.construction_identity(),
            construction_plan
                .canonical_identity_hash()
                .expect("the bounded VSS quotient construction identity hashes"),
        );
        assert_eq!(
            source_manifest
                .authenticated_source_polynomial_count()
                .expect("the bounded VSS quotient source count derives"),
            u64::try_from(construction_plan.requested_source_column_ordinals.len())
                .expect("the bounded VSS quotient source count fits u64"),
        );
        let storage_plan = RowCodeWhirGenerationStoragePlan::new(
            &construction_plan,
            relation_variant,
            &relation_context,
            &reversed_column_bindings,
        )
        .expect("the bounded VSS quotient storage plan derives");
        let external_memory_requirement =
            CommonProofExternalMemoryRequirement::from_external_memory_plan(
                &storage_plan.external_memory_plan,
            )
            .expect("the bounded VSS quotient external-memory requirement derives");
        let external_memory_read_traffic = storage_plan.external_memory_read_traffic;
        let external_memory_transaction_traffic = storage_plan.external_memory_transaction_traffic;
        assert_eq!(external_memory_requirement.step_count(), 4_864);
        assert_eq!(
            external_memory_requirement.maximum_chunk_byte_length(),
            1_048_576,
        );
        assert_eq!(
            external_memory_requirement.maximum_transaction_payload_byte_length(),
            1_048_576,
        );
        assert_eq!(
            external_memory_requirement.distinct_physical_object_count(),
            29
        );
        assert_eq!(external_memory_requirement.object_lifecycle_count(), 3_444);
        assert_eq!(
            external_memory_requirement.peak_stored_byte_length(),
            870_692_320
        );
        assert_eq!(
            external_memory_requirement.total_written_byte_length(),
            15_281_718_752
        );
        assert_eq!(
            external_memory_requirement.total_read_byte_length(),
            194_914_822_240
        );
        assert_eq!(external_memory_requirement.transaction_count(), 22_485_444);
        assert_eq!(
            external_memory_requirement.local_record_seal_invocation_count(),
            21_473
        );
        assert_eq!(
            external_memory_requirement.local_record_sealed_plaintext_byte_length(),
            15_281_749_748,
        );
        assert_eq!(
            external_memory_read_traffic,
            RowCodeWhirExternalMemoryReadTraffic {
                opened_polynomial_replay_byte_length: 126_041_544_800,
                quotient_transform_byte_length: 45_675_970_560,
                aggregate_source_byte_length: 23_197_306_880,
            },
        );
        assert_eq!(
            external_memory_read_traffic.total_byte_length(),
            Some(external_memory_requirement.total_read_byte_length()),
        );
        assert_eq!(
            external_memory_transaction_traffic,
            RowCodeWhirExternalMemoryTransactionTraffic {
                initialization_count: 1,
                opened_polynomial_replay_count: 128_410,
                quotient_transform_count: 22_331_577,
                pre_retained_deletion_count: 1_422,
                aggregate_source_count: 24_034,
            },
        );
        assert_eq!(
            external_memory_transaction_traffic.total_count(),
            Some(external_memory_requirement.transaction_count()),
        );
        assert_eq!(
            external_memory_requirement
                .peak_stored_byte_length()
                .saturating_sub(NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
            602_256_864,
        );
        assert_eq!(
            external_memory_requirement
                .peak_stored_byte_length()
                .saturating_sub(AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
            468_039_136,
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                .checked_sub(external_memory_requirement.peak_stored_byte_length()),
            Some(203_049_504),
        );
        assert!(
            external_memory_requirement.peak_stored_byte_length()
                <= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
        );
        assert!(!external_memory_requirement.exceeds_active_root_seal_custody_budget());
        let complete_liveness = derive_generation_liveness(
            &construction_plan,
            relation_variant,
            &relation_context,
            &relation_trees,
            &bound_tree_entries,
            &canonical_header_bytes,
            &source_cursor,
            &source_manifest,
            &reversed_column_bindings,
            &storage_plan,
            source_provider,
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        )
        .expect("the bounded VSS quotient complete live set derives");
        let aggregate_source_row_byte_length =
            aggregate_source_row_peak_byte_length(&construction_plan)
                .expect("the bounded VSS quotient aggregate row peak derives");
        let aggregate_source_control_byte_length = aggregate_source_control_payload_byte_length(
            &construction_plan,
            relation_variant,
            &relation_context,
        )
        .expect("the bounded VSS quotient aggregate control payload derives");
        let aggregate_batch_column_count =
            aggregate_source_resident_batch_column_count(&construction_plan)
                .expect("the bounded VSS quotient resident batch width derives");
        let aggregate_batch_byte_length = (1_u64
            << construction_plan.selected_parameters().table_variable_count)
            .checked_mul(
                u64::try_from(aggregate_batch_column_count)
                    .expect("the bounded VSS quotient batch width fits u64"),
            )
            .and_then(|count| {
                count.checked_mul(
                    u64::try_from(size_of::<ProofChallengeExtensionElement>())
                        .expect("the extension width fits u64"),
                )
            })
            .and_then(|byte_length| {
                byte_length.checked_add(
                    u64::try_from(aggregate_batch_column_count * size_of::<Vec<ChallengeField>>())
                        .expect("the bounded VSS quotient column catalog fits u64"),
                )
            })
            .expect("the bounded VSS quotient aggregate batch byte length adds");
        let aggregate_source = complete_liveness
            .rows()
            .iter()
            .find(|row| row.phase() == GenerationPhaseLivenessKind::AggregateSource)
            .expect("the bounded VSS quotient aggregate-source row exists");
        assert_eq!(
            aggregate_source.specialized_workspace_byte_length(),
            aggregate_batch_byte_length
                + aggregate_source_row_byte_length
                + aggregate_source_control_byte_length,
        );
        assert_eq!(aggregate_batch_byte_length, 167_772_184);
        assert_eq!(aggregate_source_row_byte_length, 50_334_528);
        assert_eq!(aggregate_source_control_byte_length, 1_393_198);
        assert_eq!(
            aggregate_source.specialized_workspace_byte_length(),
            219_499_910,
        );
        let expected_phase_totals = [
            (
                GenerationPhaseLivenessKind::LoadingAuthenticatedSources,
                86_502_517,
            ),
            (GenerationPhaseLivenessKind::SourceReplay, 225_712_971),
            (
                GenerationPhaseLivenessKind::RelationMaterialization,
                225_712_971,
            ),
            (GenerationPhaseLivenessKind::PhaseCommitment, 571_598_892),
            (
                GenerationPhaseLivenessKind::QuotientPreparation,
                269_536_194,
            ),
            (GenerationPhaseLivenessKind::AggregateSource, 472_650_370),
            (
                GenerationPhaseLivenessKind::PrivateMaterialSampling,
                130_972_968,
            ),
            (
                GenerationPhaseLivenessKind::AggregateOpeningPreparation,
                318_905_163,
            ),
            (
                GenerationPhaseLivenessKind::AggregateCommitment,
                545_398_740,
            ),
            (
                GenerationPhaseLivenessKind::BoundTreeAuthentication,
                356_654_511,
            ),
            (GenerationPhaseLivenessKind::WhirOpening, 513_063_414),
            (GenerationPhaseLivenessKind::BaseCaseOpening, 179_592_894),
            (GenerationPhaseLivenessKind::CanonicalEncoding, 102_880_278),
        ];
        assert_eq!(complete_liveness.rows().len(), expected_phase_totals.len());
        for (row, (expected_phase, expected_total_byte_length)) in
            complete_liveness.rows().iter().zip(expected_phase_totals)
        {
            assert_eq!(row.phase(), expected_phase);
            assert_eq!(row.total_byte_length(), expected_total_byte_length);
        }
        assert_eq!(aggregate_source.engine_control_byte_length(), 11_814_312);
        assert_eq!(aggregate_source.source_provider_byte_length(), 30_119_232);
        assert_eq!(aggregate_source.replay_reader_byte_length(), 84_934_656);
        assert_eq!(
            aggregate_source.proof_encoder_non_salt_byte_length(),
            36_636_578
        );
        assert_eq!(
            aggregate_source.transported_private_leaf_salt_byte_length(),
            4_268_544
        );
        assert_eq!(aggregate_source.transcript_byte_length(), 215_488);
        assert_eq!(aggregate_source.private_material_byte_length(), 721_672);
        assert_eq!(aggregate_source.bridge_copy_byte_length(), 2_097_508);
        assert_eq!(
            aggregate_source.allocator_overhead_byte_length(),
            48_788_438
        );
        let phase_commitment_work = complete_liveness.phase_commitment_work();
        assert_eq!(phase_commitment_work.geometry_count, 2);
        assert_eq!(phase_commitment_work.materialization_pass_count, 2);
        assert_eq!(phase_commitment_work.lane_dft_count, 11_840);
        assert_eq!(phase_commitment_work.butterfly_count, 58_971_914_240);
        assert_eq!(phase_commitment_work.coefficient_fold_count, 43_452_989_440);
        assert_eq!(
            phase_commitment_work.coset_multiplication_count,
            6_207_569_920
        );
        assert_eq!(
            phase_commitment_work.column_value_delivery_count,
            6_207_569_920
        );
        assert_eq!(phase_commitment_work.leaf_hash_query_count, 67_108_864);
        assert_eq!(
            phase_commitment_work.merkle_parent_hash_query_count,
            67_108_860
        );
        assert_eq!(
            phase_commitment_work.private_leaf_salt_derivation_count,
            67_108_864
        );
        let selected_relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected VSS relation context exists");
        let selected_relation_input = selected_committed_material_relation_plan_input()
            .expect("the selected VSS relation input derives");
        let selected_compiled_plan = compile_vss_share_linkage_relation_plan(
            &selected_relation_input,
            &selected_relation_context,
        )
        .expect("the selected VSS relation compiles");
        let selected_artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
            selected_compiled_plan,
            &selected_relation_context,
        )
        .expect("the selected VSS relation validates");
        let selected_variant = selected_artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the selected VSS relation has one variant");
        let selected_construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            &selected_artifact,
            selected_variant.schedule_position(),
            selected_variant.top_count(),
        )
        .expect("the selected VSS construction derives");
        let selected_phase_commitment_work =
            derive_phase_commitment_work_accounting(&selected_construction_plan)
                .expect("the selected VSS phase-work ledger derives");
        assert_eq!(selected_phase_commitment_work.geometry_count, 2);
        assert_eq!(selected_phase_commitment_work.materialization_pass_count, 2);
        assert_eq!(selected_phase_commitment_work.lane_dft_count, 73_472);
        assert_eq!(
            selected_phase_commitment_work.butterfly_count,
            365_944_635_392
        );
        assert_eq!(selected_phase_commitment_work.coefficient_fold_count, 0);
        assert_eq!(
            selected_phase_commitment_work.coset_multiplication_count,
            38_520_487_936
        );
        assert_eq!(
            selected_phase_commitment_work.column_value_delivery_count,
            38_520_487_936
        );
        assert_eq!(
            selected_phase_commitment_work.leaf_hash_query_count,
            67_108_864
        );
        assert_eq!(
            selected_phase_commitment_work.merkle_parent_hash_query_count,
            67_108_860
        );
        assert_eq!(
            selected_phase_commitment_work.private_leaf_salt_derivation_count,
            67_108_864,
        );
        assert!(
            phase_commitment_work.lane_dft_count * 10
                > selected_phase_commitment_work.lane_dft_count,
            "the bounded candidate does not provide a tenfold complete lane-DFT reduction",
        );
        assert!(
            phase_commitment_work.butterfly_count * 10
                > selected_phase_commitment_work.butterfly_count,
            "the bounded candidate does not provide a tenfold complete butterfly reduction",
        );
        assert!(
            phase_commitment_work.column_value_delivery_count * 10
                > selected_phase_commitment_work.column_value_delivery_count,
            "the bounded candidate does not provide a tenfold complete value-delivery reduction",
        );
        assert_eq!(
            phase_commitment_work.leaf_hash_query_count,
            selected_phase_commitment_work.leaf_hash_query_count,
            "the bounded candidate does not reduce complete phase-leaf hashing",
        );
        assert_eq!(
            complete_liveness.maximum_live_set_byte_length(),
            571_598_892
        );
        assert_eq!(
            complete_liveness
                .maximum_live_set_byte_length()
                .saturating_sub(
                    crate::bgv::proof_suite::prover::NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
                ),
            168_945_708,
        );
        assert_eq!(
            crate::bgv::proof_suite::prover::AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                .checked_sub(complete_liveness.maximum_live_set_byte_length()),
            Some(32_380_884),
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                .checked_sub(complete_liveness.maximum_live_set_byte_length()),
            Some(99_489_748),
        );
        assert!(
            complete_liveness.maximum_live_set_byte_length()
                <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        );

        let phase_commitment_live_set_byte_length = complete_liveness
            .rows()
            .iter()
            .find(|row| row.phase() == GenerationPhaseLivenessKind::PhaseCommitment)
            .expect("the bounded VSS quotient phase-commitment row exists")
            .total_byte_length();
        let checkpoint_candidates = derive_vss_persisted_checkpoint_replay_candidate_ledgers(
            VssPersistedCheckpointReplayBaseline {
                maximum_wasm_live_set_byte_length: complete_liveness.maximum_live_set_byte_length(),
                phase_commitment_live_set_byte_length,
                maximum_scratch_stored_byte_length: external_memory_requirement
                    .peak_stored_byte_length(),
                scratch_total_written_byte_length: external_memory_requirement
                    .total_written_byte_length(),
                scratch_total_read_byte_length: external_memory_requirement
                    .total_read_byte_length(),
                scratch_transaction_count: external_memory_requirement.transaction_count(),
                scratch_object_count: u64::from(
                    external_memory_requirement.distinct_physical_object_count(),
                ),
            },
        )
        .expect("the persisted-checkpoint replay candidate family derives");
        assert_eq!(checkpoint_candidates.len(), 5);
        assert_eq!(
            checkpoint_candidates
                .iter()
                .map(|candidate| (
                    candidate.checkpoint_level,
                    candidate.phase_geometry_count,
                    candidate.physical_row_count,
                    candidate.checkpoint_leaf_count,
                    candidate.maximum_recomputed_leaf_count_per_geometry,
                    candidate.checkpoint_root_count_per_geometry,
                    candidate.checkpoint_plane_byte_length,
                    candidate.checkpoint_chunk_count,
                ))
                .collect::<Vec<_>>(),
            vec![
                (1, 2, 185, 2, 774, 8_388_608, 1_073_741_824, 1_024),
                (2, 2, 185, 4, 1_548, 4_194_304, 536_870_912, 512),
                (3, 2, 185, 8, 3_096, 2_097_152, 268_435_456, 256),
                (4, 2, 185, 16, 6_192, 1_048_576, 134_217_728, 128),
                (5, 2, 185, 32, 12_384, 524_288, 67_108_864, 64),
            ],
        );
        assert_eq!(
            checkpoint_candidates
                .iter()
                .map(|candidate| (
                    candidate.combined_scratch_stored_byte_length,
                    candidate.scratch_hard_bound_headroom_byte_length,
                    candidate.scratch_hard_bound_overage_byte_length,
                    candidate.combined_scratch_total_written_byte_length,
                    candidate.combined_scratch_total_read_byte_length,
                    candidate.combined_scratch_transaction_count,
                    candidate.combined_scratch_object_count,
                    candidate.checkpoint_boundary_transport_byte_length,
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    1_944_434_144,
                    0,
                    870_692_320,
                    16_355_460_576,
                    195_988_564_064,
                    22_487_498,
                    31,
                    2_148_124_232,
                ),
                (
                    1_407_563_232,
                    0,
                    333_821_408,
                    15_818_589_664,
                    195_451_693_152,
                    22_486_474,
                    31,
                    1_074_062_920,
                ),
                (
                    1_139_127_776,
                    0,
                    65_385_952,
                    15_550_154_208,
                    195_183_257_696,
                    22_485_962,
                    31,
                    537_032_264,
                ),
                (
                    1_004_910_048,
                    68_831_776,
                    0,
                    15_415_936_480,
                    195_049_039_968,
                    22_485_706,
                    31,
                    268_516_936,
                ),
                (
                    937_801_184,
                    135_940_640,
                    0,
                    15_348_827_616,
                    194_981_931_104,
                    22_485_578,
                    31,
                    134_259_272,
                ),
            ],
        );
        assert_eq!(
            checkpoint_candidates
                .iter()
                .map(|candidate| (
                    candidate.lower_selected_output_count_per_lane,
                    candidate.higher_selected_output_count_per_lane,
                    candidate.lower_output_lane_count,
                    candidate.higher_output_lane_count,
                    candidate.selected_butterfly_count_per_physical_row,
                    candidate.opening_pass_butterfly_count,
                    candidate.complete_butterfly_count,
                ))
                .collect::<Vec<_>>(),
            vec![
                (24, 25, 26, 6, 54_623_482, 10_105_344_170, 39_591_301_290),
                (48, 49, 20, 12, 63_011_316, 11_657_093_460, 41_143_050_580),
                (96, 97, 8, 24, 71_398_376, 13_208_699_560, 42_694_656_680),
                (193, 194, 16, 16, 79_783_888, 14_760_019_280, 44_245_976_400),
                (387, 387, 32, 0, 88_166_304, 16_310_766_240, 45_796_723_360),
            ],
        );
        assert_eq!(
            checkpoint_candidates
                .iter()
                .map(|candidate| (
                    candidate.complete_column_value_delivery_count,
                    candidate.complete_leaf_hash_query_count,
                    candidate.complete_salted_leaf_keccak_permutation_count,
                    candidate.complete_merkle_parent_hash_query_count,
                ))
                .collect::<Vec<_>>(),
            vec![
                (3_103_928_150, 33_555_980, 251_669_850, 50_332_418),
                (3_104_071_340, 33_557_528, 251_681_460, 41_945_358),
                (3_104_357_720, 33_560_624, 251_704_680, 37_754_150),
                (3_104_930_480, 33_566_816, 251_751_120, 35_663_190),
                (3_106_076_000, 33_579_200, 251_844_000, 34_626_998),
            ],
        );
        assert_eq!(
            checkpoint_candidates
                .iter()
                .map(|candidate| (
                    candidate.maximum_selected_schedule_owned_byte_length,
                    candidate.phase_commitment_live_set_upper_bound_byte_length,
                    candidate.combined_wasm_live_set_upper_bound_byte_length,
                    candidate.wasm_hard_bound_headroom_byte_length,
                ))
                .collect::<Vec<_>>(),
            vec![
                (790_128, 572_487_786, 572_487_786, 98_600_854),
                (428_568, 572_081_031, 572_081_031, 99_007_609),
                (298_392, 571_934_583, 571_934_583, 99_154_057),
                (234_536, 571_862_745, 571_862_745, 99_225_895),
                (184_416, 571_806_360, 571_806_360, 99_282_280),
            ],
        );
        for candidate in &checkpoint_candidates {
            assert_eq!(candidate.checkpoint_object_count, 2);
            assert_eq!(candidate.checkpoint_local_record_seal_invocation_count, 0);
            assert_eq!(candidate.root_pass_butterfly_count, 29_485_957_120);
            assert_eq!(candidate.complete_lane_dft_count, 11_840);
            assert_eq!(candidate.complete_coefficient_fold_count, 43_452_989_440);
            assert_eq!(candidate.complete_coset_multiplication_count, 6_207_569_920);
            assert_eq!(candidate.complete_bit_reversal_visit_count, 6_207_569_920);
            assert_eq!(
                candidate.complete_private_leaf_salt_derivation_count,
                candidate.complete_leaf_hash_query_count
            );
            assert_eq!(
                candidate.selected_vss_complete_butterfly_count,
                365_944_635_392
            );
            assert_eq!(
                candidate.selected_vss_complete_coset_multiplication_count,
                38_520_487_936,
            );
            assert_eq!(
                candidate.selected_vss_complete_column_value_delivery_count,
                38_520_487_936,
            );
            assert_eq!(
                candidate.selected_vss_complete_salted_leaf_keccak_permutation_count,
                2_382_364_672,
            );
            assert!(candidate.maximum_selected_schedule_owned_byte_length < 1_048_576);
            assert!(
                candidate.phase_commitment_live_set_upper_bound_byte_length
                    > complete_liveness.maximum_live_set_byte_length(),
            );
            assert_eq!(
                candidate.combined_wasm_live_set_upper_bound_byte_length,
                candidate.phase_commitment_live_set_upper_bound_byte_length,
            );
            assert!(!candidate.has_tenfold_butterfly_reduction);
            assert!(!candidate.has_tenfold_coset_reduction);
            assert!(candidate.has_tenfold_column_delivery_reduction);
            assert!(!candidate.has_tenfold_salted_leaf_permutation_reduction);
            assert!(!candidate.eligible_for_focused_browser_measurement);
        }
        assert!(
            checkpoint_candidates[..3]
                .iter()
                .all(|candidate| !candidate.scratch_within_hard_bound)
        );
        assert!(
            checkpoint_candidates[3..]
                .iter()
                .all(|candidate| candidate.scratch_within_hard_bound)
        );
    }

    #[test]
    fn phase_commitment_lane_opening_mapping_restores_natural_coordinates() {
        let encoded_column_count = 64;
        let lane_count = 4;
        for lane_ordinal in 0..lane_count {
            let lane = (0..encoded_column_count / lane_count)
                .map(|within_lane_index| {
                    ProofBaseFieldElement::from_canonical(
                        u64::try_from(within_lane_index * lane_count + lane_ordinal)
                            .expect("the focused column index fits u64"),
                    )
                    .expect("the focused column index is canonical")
                })
                .collect::<Vec<_>>();
            for column_index in 0..encoded_column_count {
                let value = phase_commitment_lane_opening_value(
                    encoded_column_count,
                    lane_count,
                    lane_ordinal,
                    column_index,
                    &lane,
                )
                .expect("the focused lane mapping is valid");
                if column_index % lane_count == lane_ordinal {
                    assert_eq!(value, Some(Goldilocks::new(column_index as u64)),);
                } else {
                    assert_eq!(value, None);
                }
            }
        }
        let valid_lane = vec![ProofBaseFieldElement::ZERO; 16];
        assert!(phase_commitment_lane_opening_value(64, 3, 0, 0, &valid_lane).is_err());
        assert!(phase_commitment_lane_opening_value(64, 4, 4, 0, &valid_lane).is_err());
        assert!(phase_commitment_lane_opening_value(64, 4, 0, 64, &valid_lane).is_err());
        assert!(phase_commitment_lane_opening_value(64, 4, 0, 0, &valid_lane[..15]).is_err());
    }

    #[test]
    fn generation_private_mask_sampler_ceiling_is_distinct_from_fiat_shamir() {
        let relation_context = selected_relation_plan_check_context(
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
        )
        .expect("the selected same-secret relation context exists");

        assert_eq!(
            ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
            SELECTED_MAXIMUM_PRIVATE_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        );
        assert_eq!(ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING, 64);
        assert_eq!(
            relation_context.maximum_fiat_shamir_candidate_draws_per_output,
            128,
        );
        assert_ne!(
            ROW_CODE_WHIR_PRIVATE_SAMPLER_CANDIDATE_DRAW_CEILING,
            relation_context.maximum_fiat_shamir_candidate_draws_per_output,
            "private mask streams and public Fiat-Shamir streams have distinct exhaustion ledgers",
        );
    }

    #[test]
    fn selected_same_secret_storage_plan_distinguishes_lifecycles_from_physical_custody() {
        let schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected same-secret relation context exists");
        let compiled_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &relation_context,
        )
        .expect("the selected same-secret relation compiles");
        let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
            compiled_plan,
            &relation_context,
        )
        .expect("the selected same-secret relation validates");
        let variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the selected same-secret relation plan has one variant");
        let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            &artifact,
            variant.schedule_position(),
            variant.top_count(),
        )
        .expect("the selected same-secret construction plan derives");
        let reversed_column_bindings = relation_reversed_column_bindings(variant)
            .expect("the selected same-secret reversed-column bindings derive");
        let storage_plan = RowCodeWhirGenerationStoragePlan::new(
            &construction_plan,
            variant,
            artifact.checked_context(),
            &reversed_column_bindings,
        )
        .expect("the selected same-secret storage plan stays within absolute custody bounds");
        let requirement = CommonProofExternalMemoryRequirement::from_external_memory_plan(
            &storage_plan.external_memory_plan,
        )
        .expect("the selected same-secret external-memory requirement derives");
        let read_traffic = storage_plan.external_memory_read_traffic;
        let derived_total_read_byte_length = read_traffic
            .total_byte_length()
            .expect("the selected same-secret read traffic sums without overflow");
        let derived_quotient_transform_read_byte_length = storage_plan
            .quotient_transform_plans
            .values()
            .try_fold(0_u64, |total_byte_length, transform_plan| {
                total_byte_length.checked_add(transform_plan.total_read_byte_length())
            })
            .expect("the quotient-transform read traffic sums without overflow");
        let transaction_traffic = storage_plan.external_memory_transaction_traffic;
        let derived_transaction_count = transaction_traffic
            .total_count()
            .expect("the selected same-secret transaction traffic sums without overflow");

        assert_eq!(requirement.step_count(), 14_276);
        assert_eq!(requirement.distinct_physical_object_count(), 29);
        assert_eq!(requirement.object_lifecycle_count(), 10_231);
        assert_eq!(requirement.peak_stored_byte_length(), 849_756_760);
        assert_eq!(requirement.total_written_byte_length(), 6_219_960_920);
        assert!(read_traffic.opened_polynomial_replay_byte_length > 0);
        assert!(read_traffic.aggregate_source_byte_length > 0);
        assert_eq!(
            read_traffic.quotient_transform_byte_length,
            derived_quotient_transform_read_byte_length,
        );
        assert_eq!(
            requirement.total_read_byte_length(),
            derived_total_read_byte_length,
        );
        assert_eq!(transaction_traffic.initialization_count, 1);
        assert!(transaction_traffic.opened_polynomial_replay_count > 0);
        assert!(transaction_traffic.quotient_transform_count > 0);
        assert!(transaction_traffic.pre_retained_deletion_count > 0);
        assert!(transaction_traffic.aggregate_source_count > 0);
        assert_eq!(requirement.transaction_count(), derived_transaction_count);
        assert_eq!(requirement.local_record_seal_invocation_count(), 31_518);
        assert_eq!(
            requirement.local_record_sealed_plaintext_byte_length(),
            6_220_052_999,
        );
        assert_eq!(
            requirement
                .peak_stored_byte_length()
                .saturating_sub(NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
            581_321_304,
        );
        assert_eq!(
            requirement
                .peak_stored_byte_length()
                .saturating_sub(AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH),
            447_103_576,
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                .checked_sub(requirement.peak_stored_byte_length()),
            Some(223_985_064),
        );
        assert!(
            requirement.peak_stored_byte_length()
                < NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH * 4,
            "the reviewed scratch variance is bounded, not orders of magnitude",
        );

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
    fn selected_same_secret_complete_generation_liveness_is_derived_from_the_production_layout() {
        let schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected same-secret relation context exists");
        let relation_input = selected_same_secret_relation_plan_input()
            .expect("the selected same-secret relation input derives");
        let compiled =
            compile_same_secret_relation_with_source_layout(&relation_input, &relation_context)
                .expect("the selected same-secret relation and source layout compile");
        let relation_variant = compiled
            .relation_plan
            .variants()
            .first()
            .expect("the selected same-secret relation has one variant");
        let canonical_statement = canonical_selected_application_statement_for_ceiling(
            schema_identifier,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                [0_u8; Hash512::BYTE_LENGTH],
                relation_variant.schedule_position(),
                relation_variant.top_count(),
            ),
        )
        .expect("the selected same-secret statement encodes");
        let accounting = same_secret_source_provider_memory_accounting(
            relation_variant,
            &relation_context,
            relation_input.ring_degree,
            &compiled.source_layout,
            canonical_statement.len(),
        )
        .expect("the production source-provider memory accounting derives");
        let relation_variant_payload_byte_length = relation_variant
            .resident_owned_payload_byte_length()
            .expect("the selected relation payload derives");
        let relation_context_payload_byte_length = relation_context
            .resident_owned_payload_byte_length()
            .expect("the selected relation context payload derives");
        let validated = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
            compiled.relation_plan,
            &relation_context,
        )
        .expect("the selected same-secret relation validates");
        let construction_plan =
            RowCodeWhirConstructionPlan::for_selected_variant(&validated, None, None)
                .expect("the selected same-secret construction plan derives");
        let construction_identity_byte_length = construction_plan
            .canonical_identity_bytes()
            .expect("the selected construction identity encodes")
            .len();

        assert_eq!(canonical_statement.len(), 884);
        assert_eq!(relation_variant_payload_byte_length, 4_986_144);
        assert_eq!(relation_context_payload_byte_length, 736);
        assert_eq!(construction_identity_byte_length, 994_031);
        assert_eq!(size_of::<RowCodeWhirGenerationStateMachine>(), 20_288);
        assert_eq!(size_of::<super::super::RowCodeWhirChallenger>(), 552);
        assert_eq!(
            accounting.loading_persistent_resident_byte_length(),
            5_529_060
        );
        assert_eq!(
            accounting.post_source_polynomial_finish_persistent_resident_byte_length(),
            5_004_772,
        );
        assert_eq!(
            accounting.additional_loading_transient_byte_length(),
            9_225_026
        );
        assert_eq!(
            accounting.maximum_returned_source_polynomial_byte_length(),
            131_072
        );
        assert_eq!(
            accounting
                .loading_persistent_resident_byte_length()
                .checked_add(accounting.additional_loading_transient_byte_length())
                .and_then(|bytes| {
                    bytes.checked_add(accounting.maximum_returned_source_polynomial_byte_length())
                }),
            Some(14_885_158),
        );

        let validated_variant = validated
            .compiled_plan()
            .variants()
            .first()
            .expect("the validated same-secret relation has one variant");
        let relation_trees = selected_relation_tree_inputs(validated_variant)
            .expect("the selected relation trees derive");
        let bound_tree_entries = build_relation_bound_public_tree_catalog_entries(&relation_trees)
            .expect("the selected bound-tree entries derive");
        let canonical_header_bytes = canonical_proof_object_header_bytes(&canonical_statement)
            .expect("the canonical proof header derives");
        let relation_plan_hash = validated
            .compiled_plan()
            .canonical_hash()
            .expect("the selected relation plan hashes");
        let relation_plan_variant_hash = validated_variant
            .canonical_hash()
            .expect("the selected relation variant hashes");
        let source_request_context = CommonProofSourcePolynomialRequestContext::new(
            FOUNDATION_PROFILE.protocol_version,
            [0x11; HASH_BYTE_LENGTH],
            schema_identifier,
            [0x22; HASH_BYTE_LENGTH],
            relation_plan_hash,
            relation_plan_variant_hash,
            validated_variant.schedule_position(),
            validated_variant.top_count(),
        );
        let source_cursor =
            CommonProofPreChallengeSourceCursor::new(validated_variant, source_request_context)
                .expect("the selected source cursor derives");
        let reversed_column_bindings = source_cursor.reversed_column_bindings().to_vec();
        let source_manifest = checked_same_secret_source_manifest(
            &construction_plan,
            validated_variant,
            &relation_context,
            &reversed_column_bindings,
        )
        .expect("the selected source manifest derives");
        let storage_plan = RowCodeWhirGenerationStoragePlan::new(
            &construction_plan,
            validated_variant,
            &relation_context,
            &reversed_column_bindings,
        )
        .expect("the selected storage plan derives");
        let quotient_evaluation_domain = construction_plan
            .quotient_computation_evaluation_domain(&relation_context)
            .expect("the quotient evaluation domain derives");
        let quotient_liveness = common_proof_quotient_materialization_liveness(
            validated_variant,
            &relation_context,
            quotient_evaluation_domain,
        )
        .expect("the quotient liveness derives");
        let quotient_builder_byte_length = quotient_liveness
            .quotient_evaluation_byte_length()
            .checked_add(quotient_liveness.maximum_block_value_byte_length())
            .and_then(|total| total.checked_add(quotient_liveness.catalog_resident_byte_length()))
            .and_then(|total| {
                u64::try_from(validated_variant.constraint_count())
                    .ok()
                    .and_then(|count| {
                        count.checked_mul(
                            u64::try_from(size_of::<ProofChallengeExtensionElement>()).ok()?,
                        )
                    })
                    .and_then(|byte_length| total.checked_add(byte_length))
            })
            .expect("the quotient builder accounting adds");
        assert_eq!(
            quotient_liveness.maximum_materialization_byte_length(),
            quotient_builder_byte_length
                .max(quotient_liveness.maximum_component_transition_byte_length()),
        );
        let aggregate_source_row_byte_length =
            aggregate_source_row_peak_byte_length(&construction_plan)
                .expect("the aggregate source row peak derives");
        let aggregate_source_control_byte_length = aggregate_source_control_payload_byte_length(
            &construction_plan,
            validated_variant,
            &relation_context,
        )
        .expect("the aggregate source control payload derives");
        let aggregate_column_element_count =
            1_u64 << construction_plan.selected_parameters().table_variable_count;
        let aggregate_batch_column_count = construction_plan.aggregate_table_width() / 2;
        let aggregate_batch_byte_length = aggregate_column_element_count
            .checked_mul(
                u64::try_from(aggregate_batch_column_count)
                    .expect("the aggregate batch column count fits u64"),
            )
            .and_then(|count| {
                count.checked_mul(
                    u64::try_from(size_of::<ProofChallengeExtensionElement>())
                        .expect("the extension width fits u64"),
                )
            })
            .and_then(|byte_length| {
                byte_length.checked_add(
                    u64::try_from(aggregate_batch_column_count * size_of::<Vec<ChallengeField>>())
                        .expect("the aggregate column catalog width fits u64"),
                )
            })
            .expect("the aggregate batch byte length adds");
        assert_eq!(aggregate_source_row_byte_length, 50_331_648);
        assert_eq!(aggregate_source_control_byte_length, 550_729);
        assert_eq!(aggregate_batch_byte_length, 335_544_368);
        assert_eq!(
            aggregate_batch_byte_length
                + aggregate_source_row_byte_length
                + aggregate_source_control_byte_length,
            386_426_745,
        );
        let complete_liveness = derive_generation_liveness(
            &construction_plan,
            validated_variant,
            &relation_context,
            &relation_trees,
            &bound_tree_entries,
            &canonical_header_bytes,
            &source_cursor,
            &source_manifest,
            &reversed_column_bindings,
            &storage_plan,
            accounting,
            MAXIMUM_COMMON_PROOF_CHUNK_BYTE_LENGTH,
        )
        .expect("the complete selected live set derives");
        let phase_commitment_work = complete_liveness.phase_commitment_work();
        assert_eq!(phase_commitment_work.geometry_count, 3);
        assert_eq!(phase_commitment_work.materialization_pass_count, 2);
        assert_eq!(phase_commitment_work.lane_dft_count, 3_968);
        assert_eq!(phase_commitment_work.butterfly_count, 19_763_560_448);
        assert_eq!(phase_commitment_work.coefficient_fold_count, 14_562_623_488,);
        assert_eq!(
            phase_commitment_work.coset_multiplication_count,
            2_080_374_784,
        );
        assert_eq!(
            phase_commitment_work.column_value_delivery_count,
            2_080_374_784,
        );
        assert_eq!(phase_commitment_work.leaf_hash_query_count, 100_663_296);
        assert_eq!(
            phase_commitment_work.merkle_parent_hash_query_count,
            100_663_290,
        );
        assert_eq!(
            phase_commitment_work.private_leaf_salt_derivation_count,
            100_663_296,
        );
        let expected_rows = [
            (
                GenerationPhaseLivenessKind::LoadingAuthenticatedSources,
                131_072,
                0,
                0,
                0,
                0,
                0,
                0,
                65_180_850,
            ),
            (
                GenerationPhaseLivenessKind::SourceReplay,
                84_934_656,
                0,
                0,
                0,
                0,
                0,
                0,
                158_744_247,
            ),
            (
                GenerationPhaseLivenessKind::RelationMaterialization,
                84_934_656,
                0,
                0,
                0,
                0,
                0,
                1_185_104,
                160_077_489,
            ),
            (
                GenerationPhaseLivenessKind::PhaseCommitment,
                84_934_656,
                33_554_432,
                273_580_440,
                0,
                392,
                0,
                0,
                504_271_419,
            ),
            (
                GenerationPhaseLivenessKind::QuotientPreparation,
                84_934_656,
                0,
                0,
                0,
                0,
                0,
                7_280_808,
                166_935_156,
            ),
            (
                GenerationPhaseLivenessKind::AggregateSource,
                84_934_656,
                0,
                0,
                0,
                0,
                0,
                386_426_745,
                593_474_335,
            ),
            (
                GenerationPhaseLivenessKind::PrivateMaterialSampling,
                0,
                0,
                0,
                0,
                0,
                0,
                721_720,
                64_004_694,
            ),
            (
                GenerationPhaseLivenessKind::AggregateOpeningPreparation,
                0,
                0,
                0,
                0,
                0,
                0,
                167_772_160,
                251_936_439,
            ),
            (
                GenerationPhaseLivenessKind::AggregateCommitment,
                0,
                335_544_320,
                33_554_432,
                56,
                976,
                0,
                0,
                478_430_016,
            ),
            (
                GenerationPhaseLivenessKind::BoundTreeAuthentication,
                0,
                134_217_728,
                67_109_408,
                0,
                0,
                0,
                0,
                289_685_787,
            ),
            (
                GenerationPhaseLivenessKind::WhirOpening,
                0,
                335_544_320,
                33_554_432,
                56,
                976,
                0,
                1_376_720,
                474_348_457,
            ),
            (
                GenerationPhaseLivenessKind::BaseCaseOpening,
                0,
                10_485_760,
                16_777_216,
                56,
                976,
                0,
                46_794_256,
                140_877_937,
            ),
            (
                GenerationPhaseLivenessKind::CanonicalEncoding,
                0,
                0,
                0,
                0,
                0,
                750_488,
                0,
                58_406_689,
            ),
        ];
        assert_eq!(complete_liveness.rows().len(), expected_rows.len());
        for (
            row,
            (
                phase,
                replay,
                dft,
                merkle,
                private_salt_state,
                private_salt_workspace,
                private_salt_uniqueness,
                specialized,
                total,
            ),
        ) in complete_liveness.rows().iter().zip(expected_rows)
        {
            assert_eq!(row.phase(), phase);
            assert_eq!(row.wasm_runtime_baseline_byte_length(), 33_554_432);
            assert_eq!(row.engine_control_byte_length(), 10_200_609);
            assert_eq!(
                row.source_provider_byte_length(),
                if phase == GenerationPhaseLivenessKind::LoadingAuthenticatedSources {
                    14_754_086
                } else if matches!(
                    phase,
                    GenerationPhaseLivenessKind::WhirOpening
                        | GenerationPhaseLivenessKind::BaseCaseOpening
                        | GenerationPhaseLivenessKind::CanonicalEncoding
                ) {
                    0
                } else {
                    5_004_772
                },
            );
            assert_eq!(row.replay_reader_byte_length(), replay);
            assert_eq!(row.dft_buffer_byte_length(), dft);
            assert_eq!(row.merkle_and_frontier_byte_length(), merkle);
            assert_eq!(
                row.proof_encoder_non_salt_byte_length(),
                if phase == GenerationPhaseLivenessKind::LoadingAuthenticatedSources {
                    0
                } else {
                    7_567_402
                },
            );
            assert_eq!(
                row.transported_private_leaf_salt_byte_length(),
                if phase == GenerationPhaseLivenessKind::LoadingAuthenticatedSources {
                    0
                } else {
                    545_792
                },
            );
            assert_eq!(row.transcript_byte_length(), 207_424);
            assert_eq!(row.private_material_byte_length(), 721_672);
            assert_eq!(
                row.private_leaf_salt_state_byte_length(),
                private_salt_state
            );
            assert_eq!(
                row.private_leaf_salt_workspace_byte_length(),
                private_salt_workspace,
            );
            assert_eq!(
                row.private_leaf_salt_uniqueness_set_byte_length(),
                private_salt_uniqueness,
            );
            assert_eq!(row.bridge_copy_byte_length(), 2_097_508);
            assert_eq!(row.specialized_workspace_byte_length(), specialized);
            let owned_byte_length = row
                .engine_control_byte_length()
                .checked_add(row.source_provider_byte_length())
                .and_then(|owned| owned.checked_add(row.replay_reader_byte_length()))
                .and_then(|owned| owned.checked_add(row.dft_buffer_byte_length()))
                .and_then(|owned| owned.checked_add(row.merkle_and_frontier_byte_length()))
                .and_then(|owned| owned.checked_add(row.proof_encoder_non_salt_byte_length()))
                .and_then(|owned| {
                    owned.checked_add(row.transported_private_leaf_salt_byte_length())
                })
                .and_then(|owned| owned.checked_add(row.transcript_byte_length()))
                .and_then(|owned| owned.checked_add(row.private_material_byte_length()))
                .and_then(|owned| owned.checked_add(row.private_leaf_salt_state_byte_length()))
                .and_then(|owned| owned.checked_add(row.private_leaf_salt_workspace_byte_length()))
                .and_then(|owned| {
                    owned.checked_add(row.private_leaf_salt_uniqueness_set_byte_length())
                })
                .and_then(|owned| owned.checked_add(row.bridge_copy_byte_length()))
                .and_then(|owned| owned.checked_add(row.specialized_workspace_byte_length()))
                .expect("the independently reconciled phase total adds");
            assert_eq!(
                row.allocator_overhead_byte_length(),
                owned_byte_length.div_ceil(8),
            );
            assert_eq!(
                row.total_byte_length(),
                row.wasm_runtime_baseline_byte_length()
                    + owned_byte_length
                    + owned_byte_length.div_ceil(8),
            );
            assert_eq!(row.total_byte_length(), total);
        }
        assert_eq!(
            complete_liveness.maximum_live_set_byte_length(),
            593_474_335,
        );
        assert_eq!(
            complete_liveness
                .maximum_live_set_byte_length()
                .saturating_sub(
                    crate::bgv::proof_suite::prover::NOMINAL_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH,
                ),
            190_821_151,
        );
        assert_eq!(
            crate::bgv::proof_suite::prover::AUTOMATIC_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                .checked_sub(complete_liveness.maximum_live_set_byte_length(),),
            Some(10_505_441),
        );
        assert_eq!(
            MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
                .checked_sub(complete_liveness.maximum_live_set_byte_length()),
            Some(77_614_305),
        );
    }

    #[test]
    fn planned_base_field_quotient_transform_matches_owned_evaluation_in_place() {
        let schema_identifier =
            ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(schema_identifier)
            .expect("the selected same-secret relation context exists");
        let compiled_plan = compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()
                .expect("the selected same-secret relation input derives"),
            &relation_context,
        )
        .expect("the selected same-secret relation compiles");
        let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
            compiled_plan,
            &relation_context,
        )
        .expect("the selected same-secret relation validates");
        let variant = artifact
            .compiled_plan()
            .variants()
            .first()
            .expect("the selected same-secret relation plan has one variant");
        let construction_plan = RowCodeWhirConstructionPlan::for_selected_variant(
            &artifact,
            variant.schedule_position(),
            variant.top_count(),
        )
        .expect("the selected same-secret construction plan derives");
        let reversed_column_bindings = relation_reversed_column_bindings(variant)
            .expect("the selected reversed-column catalog derives");
        let storage_plan = RowCodeWhirGenerationStoragePlan::new(
            &construction_plan,
            variant,
            artifact.checked_context(),
            &reversed_column_bindings,
        )
        .expect("the selected storage plan derives");

        let transform_plan = storage_plan
            .quotient_transform_plans
            .values()
            .copied()
            .find(|plan| plan.source().value_type() == RelationColumnValueType::BaseField)
            .expect("the selected relation has base-field quotient transforms");
        assert!(
            storage_plan
                .quotient_transform_plans
                .values()
                .all(|plan| plan.source().value_type() == RelationColumnValueType::BaseField)
        );
        let evaluation_domain = transform_plan.evaluation_domain();
        let coefficient_count = transform_plan.source().coefficient_count().min(257);
        let coefficients = (0..coefficient_count)
            .map(|coefficient_index| {
                ProofBaseFieldElement::from_canonical(
                    u64::try_from(coefficient_index * 17 + 3)
                        .expect("the bounded coefficient fits u64"),
                )
                .expect("the bounded coefficient is canonical")
            })
            .collect::<Vec<_>>();
        let expected = evaluation_domain
            .evaluate_base_polynomial(&coefficients)
            .expect("the reference base-field transform succeeds");
        let mut polynomial = CommonProofSourcePolynomial::from_base_coefficients(coefficients);
        evaluate_quotient_transform_in_place(transform_plan, &mut polynomial)
            .expect("the planned base-field transform succeeds");
        let CommonProofSourcePolynomial::Base(actual) = polynomial else {
            panic!("the base-field transform changed representation")
        };
        assert_eq!(&*actual, &expected);

        let mut wrong_representation =
            CommonProofSourcePolynomial::from_extension_coefficients(vec![
                ProofChallengeExtensionElement::ONE,
            ]);
        assert_eq!(
            evaluate_quotient_transform_in_place(transform_plan, &mut wrong_representation),
            Err(CommonProofProverError::InvalidColumn),
        );
    }

    #[test]
    fn opening_batch_mask_chunks_preserve_polynomial_evaluation_and_exact_boundaries() {
        const TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT: usize = 64;
        let opening_point =
            ProofChallengeExtensionElement::from_canonical_coordinates([17, 11, 5, 3, 2])
                .expect("the test opening point is canonical");
        let coefficient_count = TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT + 3;
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
        let chunk_evaluations = evaluate_opening_batch_mask_chunks(
            &polynomial,
            opening_point,
            TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT,
            3,
        )
        .expect("the partial final mask chunk evaluates");
        assert_eq!(chunk_evaluations.len(), 3);
        assert_eq!(chunk_evaluations[2], ProofChallengeExtensionElement::ZERO);

        let chunk_power = opening_point.power(
            u64::try_from(TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT)
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
            TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT
        ]);
        let exact_boundary_evaluations = evaluate_opening_batch_mask_chunks(
            &exact_boundary,
            opening_point,
            TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT,
            2,
        )
        .expect("an exact first-chunk boundary evaluates");
        assert_eq!(
            exact_boundary_evaluations[1],
            ProofChallengeExtensionElement::ZERO,
        );
    }

    #[test]
    fn opening_batch_mask_chunks_refuse_empty_and_overlong_polynomials() {
        const TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT: usize = 64;
        let opening_point = ProofChallengeExtensionElement::ONE;
        let empty = CommonProofSourcePolynomial::from_extension_coefficients(Vec::new());
        assert_eq!(
            evaluate_opening_batch_mask_chunks(
                &empty,
                opening_point,
                TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT,
                2,
            ),
            Err(CommonProofProverError::InvalidMask),
        );
        let nonempty = CommonProofSourcePolynomial::from_extension_coefficients(vec![
            ProofChallengeExtensionElement::ONE,
        ]);
        assert_eq!(
            evaluate_opening_batch_mask_chunks(&nonempty, opening_point, 0, 2),
            Err(CommonProofProverError::InvalidMask),
        );

        let overlong = CommonProofSourcePolynomial::from_extension_coefficients(vec![
            ProofChallengeExtensionElement::ZERO;
            TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT * 2 + 1
        ]);
        assert_eq!(
            evaluate_opening_batch_mask_chunks(
                &overlong,
                opening_point,
                TEST_LOGICAL_POLYNOMIAL_COEFFICIENT_COUNT,
                2,
            ),
            Err(CommonProofProverError::InvalidMask),
        );
    }
}
