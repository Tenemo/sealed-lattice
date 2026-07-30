//! Allocation-bounded aggregate-wide hiding prover.
//!
//! One secret pad is committed after the source oracle and before any
//! claim-dependent challenge. Disjoint pad slices hide every sumcheck wire and
//! code-switch randomness view. Encoded source oracles live in browser-owned
//! external memory; only one bounded stripe and the current source polynomial
//! remain resident in WebAssembly.

use std::collections::BTreeSet;

use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::ExtensionMmcs;
use p3_field::{PrimeCharacteristicRing, dot_product};
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch,
    constraints::{Constraint, Statements, statement::SelectStatement},
    layout::{Layout, PrefixInitialSumcheckProver, PrefixOpeningBatchBuilder, TableShape},
    strategy::{SumcheckProver, VariableOrder},
};
use p3_whir::{
    BaseCaseZkConfig, BaseCaseZkProver, FoldedRsCode, MaskCodeShape, MaskGroupShape,
    MaskGroupWitness, PreparedBaseCaseZkProof, QueryOpening, switch_mask_covector,
};

use super::aggregate_source_storage::{
    AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH, AggregateSourceTable, AggregateSourceValues,
    AggregateSourceWriter, decode_source_values,
};
use super::aggregate_wide_hiding::{
    AggregateWideCommittedPad, AggregateWideHidingMaterial, AggregateWideOpeningProof,
    AggregateWidePadClaim, AggregateWidePadLayout, AggregateWideRoundProof,
    PrecommittedMaskedSumcheck, fold_limb_randomness, switch_mask_delta,
};
use super::aggregate_wide_pcs::{AggregateLayout, AggregateWideCommitment, AggregateWidePcs};
use super::hiding_whir::SelectedHidingWhirConfig;
use super::oracle_geometry::{checked_power_of_two, sample_distinct_query_indices};
use super::recomputable_oracle::{
    RecomputableOracleError, RecomputableOracleOutput, RecomputableOraclePass,
    RecomputableOraclePoll, RecomputableOracleSource,
};
use super::source_compression::{ExternalSourceCompression, ExternalSourceCompressionPoll};
use super::{ChallengeField, CommitmentScheme, DiscreteFourierTransform, ExtensionFieldChallenger};
use crate::bgv::proof_suite::external_polynomial::ExternalPolynomialVector;
use crate::bgv::proof_suite::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError,
};

type PreparedAggregateWideBaseCase =
    PreparedBaseCaseZkProof<ChallengeField, ChallengeField, CommitmentScheme>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamingAggregateWideCommitmentStage {
    BuildRoot,
    ObserveCommitments,
    AwaitOpeningPreparation,
    PrepareOpenings,
    Complete,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingAggregateWideCommitmentGeneration {
    config: SelectedHidingWhirConfig,
    extension_mmcs: ExtensionMmcs<ChallengeField, ChallengeField, CommitmentScheme>,
    dft: DiscreteFourierTransform,
    source_table: AggregateSourceTable,
    residuals: Vec<ExternalPolynomialVector>,
    detached_layout: Option<AggregateLayout>,
    oracle_randomness: Vec<Vec<ChallengeField>>,
    pad_layout: AggregateWidePadLayout,
    pad_message: Option<Vec<ChallengeField>>,
    pad_randomness: Option<Vec<ChallengeField>>,
    base_case_fresh_material: Option<p3_whir::BaseCaseFreshMaterial<ChallengeField>>,
    oracle_pass: Option<RecomputableOraclePass>,
    opening_preparation: Option<DetachedOpeningPreparation>,
    source_commitment: Option<AggregateWideCommitment>,
    committed_pad: Option<AggregateWideCommittedPad>,
    prepared_prover_data: Option<StreamingAggregateWideProverData>,
    stage: StreamingAggregateWideCommitmentStage,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingAggregateWideProverData {
    config: SelectedHidingWhirConfig,
    extension_mmcs: ExtensionMmcs<ChallengeField, ChallengeField, CommitmentScheme>,
    dft: DiscreteFourierTransform,
    source_table: AggregateSourceTable,
    residuals: Vec<ExternalPolynomialVector>,
    oracle_randomness: Vec<Vec<ChallengeField>>,
    pad_layout: AggregateWidePadLayout,
    committed_pad: AggregateWideCommittedPad,
    base_case_fresh_material: p3_whir::BaseCaseFreshMaterial<ChallengeField>,
    evaluations: Vec<OpeningBatch<ChallengeField>>,
    initial_sumcheck: PrefixInitialSumcheckProver<ChallengeField, ChallengeField>,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingAggregateWideCommitmentOutput {
    pub(in crate::bgv::proof_suite::row_code_whir) source_commitment: AggregateWideCommitment,
    pub(in crate::bgv::proof_suite::row_code_whir) prover_data: StreamingAggregateWideProverData,
}

pub(in crate::bgv::proof_suite::row_code_whir) enum StreamingAggregateWideCommitmentPoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    CommitmentsObserved {
        source_commitment: AggregateWideCommitment,
        pad_commitment: AggregateWideCommitment,
    },
    Complete(StreamingAggregateWideCommitmentOutput),
}

struct DetachedOpeningPreparation {
    table: AggregateSourceTable,
    layout: Option<AggregateLayout>,
    builders: Vec<PrefixOpeningBatchBuilder<ChallengeField, ChallengeField>>,
    requested_columns: Vec<usize>,
    current_requested_column_ordinal: usize,
    current_element_offset: usize,
    current_column_values: Vec<ChallengeField>,
    encoded_chunk: Vec<u8>,
    decoded_chunk: Vec<ChallengeField>,
}

struct DetachedOpeningPreparationOutput {
    layout: AggregateLayout,
    evaluations: Vec<OpeningBatch<ChallengeField>>,
}

enum DetachedOpeningPreparationPoll {
    StorageTransactionCompleted,
    Complete(DetachedOpeningPreparationOutput),
}

impl DetachedOpeningPreparation {
    fn new(
        table: AggregateSourceTable,
        layout: AggregateLayout,
        points: &[Point<ChallengeField>],
        requested_columns_by_point: &[Vec<usize>],
    ) -> Result<Self, String> {
        if points.len() != requested_columns_by_point.len() || points.is_empty() {
            return Err("detached opening preparation has an invalid schedule".to_owned());
        }
        let mut builders = Vec::with_capacity(points.len());
        let mut requested_columns = BTreeSet::new();
        for (point, columns) in points.iter().zip(requested_columns_by_point) {
            let request = OpeningBatch::new(columns.clone(), Vec::new());
            builders.push(
                layout
                    .prepare_opening_batch(0, request, point.clone())
                    .map_err(str::to_owned)?,
            );
            requested_columns.extend(columns.iter().copied());
        }
        Ok(Self {
            table,
            layout: Some(layout),
            builders,
            requested_columns: requested_columns.into_iter().collect(),
            current_requested_column_ordinal: 0,
            current_element_offset: 0,
            current_column_values: Vec::new(),
            encoded_chunk: Vec::new(),
            decoded_chunk: Vec::new(),
        })
    }

    fn poll<Storage: ProofExternalMemory>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<DetachedOpeningPreparationPoll, ProofExternalMemoryExecutorError<Storage::Error>>
    {
        let Some(column_index) = self
            .requested_columns
            .get(self.current_requested_column_ordinal)
            .copied()
        else {
            let mut layout = self
                .layout
                .take()
                .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
            let mut evaluations = Vec::with_capacity(self.builders.len());
            for builder in core::mem::take(&mut self.builders) {
                evaluations.push(
                    layout
                        .record_prepared_opening(builder, challenger)
                        .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?,
                );
            }
            return Ok(DetachedOpeningPreparationPoll::Complete(
                DetachedOpeningPreparationOutput {
                    layout,
                    evaluations,
                },
            ));
        };
        let vector = self.table.columns()[column_index];
        if self.current_column_values.is_empty() {
            self.current_column_values = ChallengeField::zero_vec(vector.element_count());
        }
        let maximum_element_count = usize::try_from(executor.maximum_chunk_byte_length())
            .ok()
            .and_then(|bytes| bytes.checked_div(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH))
            .filter(|count| *count > 0)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let element_count = maximum_element_count.min(
            vector
                .element_count()
                .saturating_sub(self.current_element_offset),
        );
        if element_count == 0 {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        let byte_offset = self
            .current_element_offset
            .checked_mul(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let byte_length = element_count
            .checked_mul(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        self.encoded_chunk.clear();
        self.encoded_chunk.resize(byte_length, 0);
        executor.read_object_bytes(
            storage,
            vector.object(),
            byte_offset,
            &mut self.encoded_chunk,
        )?;
        self.decoded_chunk.clear();
        self.decoded_chunk
            .resize(element_count, ChallengeField::ZERO);
        decode_source_values(&self.encoded_chunk, &mut self.decoded_chunk)
            .map_err(ProofExternalMemoryExecutorError::Execution)?;
        self.current_column_values
            [self.current_element_offset..self.current_element_offset + element_count]
            .copy_from_slice(&self.decoded_chunk);
        self.decoded_chunk.fill(ChallengeField::ZERO);
        self.decoded_chunk.clear();
        self.current_element_offset += element_count;
        if self.current_element_offset == vector.element_count() {
            let mut polynomial = Poly::new(core::mem::take(&mut self.current_column_values));
            for builder in &mut self.builders {
                builder
                    .absorb_column(column_index, &polynomial)
                    .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
            }
            polynomial.as_mut_slice().fill(ChallengeField::ZERO);
            self.current_element_offset = 0;
            self.current_requested_column_ordinal += 1;
        }
        Ok(DetachedOpeningPreparationPoll::StorageTransactionCompleted)
    }
}

impl Drop for DetachedOpeningPreparation {
    fn drop(&mut self) {
        self.current_column_values.fill(ChallengeField::ZERO);
        self.encoded_chunk.fill(0);
        self.decoded_chunk.fill(ChallengeField::ZERO);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamingAggregateWideProofStage {
    BeginMaskedSumcheck,
    AdvanceMaskedSumcheck,
    FinishMaskedSumcheck,
    CompressInitialSource,
    BeginRound,
    WriteCurrentOracle,
    ReadCurrentRoot,
    SampleRoundQueries,
    ReadPreviousOracle,
    PrepareRound,
    CompleteRoundExternalMemoryStep,
    PrepareBaseCase,
    ReadBaseSource,
    CompleteBaseExternalMemoryStep,
    Finish,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) enum StreamingAggregateWideProofBoundary {
    MaskedSumcheckRound {
        batch_ordinal: usize,
        completed_round_count: usize,
    },
    RoundOracleArithmetic {
        round_ordinal: usize,
    },
    RoundOracleStorage {
        round_ordinal: usize,
    },
    RoundQueriesPrepared {
        round_ordinal: usize,
    },
    RoundStorageReleased {
        completed_round_count: usize,
    },
    BaseCasePrepared,
    BaseSourceStorage,
    BaseStorageReleased,
    ProofReady,
}

pub(in crate::bgv::proof_suite::row_code_whir) enum StreamingAggregateWideProofPoll {
    ArithmeticStepCompleted(StreamingAggregateWideProofBoundary),
    StorageTransactionCompleted(StreamingAggregateWideProofBoundary),
    Complete(AggregateWideOpeningProof),
}

pub(in crate::bgv::proof_suite::row_code_whir) enum StreamingAggregateWideError<StorageError> {
    Geometry(String),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingAggregateWideProofGeneration {
    config: SelectedHidingWhirConfig,
    extension_mmcs: ExtensionMmcs<ChallengeField, ChallengeField, CommitmentScheme>,
    dft: DiscreteFourierTransform,
    source_table: AggregateSourceTable,
    residuals: Vec<ExternalPolynomialVector>,
    oracle_roots: Vec<AggregateWideCommitment>,
    oracle_randomness: Vec<Vec<ChallengeField>>,
    current_folded_oracle_randomness: Vec<ChallengeField>,
    pad_layout: AggregateWidePadLayout,
    pad_claim: AggregateWidePadClaim,
    committed_pad: AggregateWideCommittedPad,
    base_case_fresh_material: p3_whir::BaseCaseFreshMaterial<ChallengeField>,
    evaluations: Option<Vec<OpeningBatch<ChallengeField>>>,
    initial_sumcheck: Option<PrefixInitialSumcheckProver<ChallengeField, ChallengeField>>,
    sumcheck_prover: Option<SumcheckProver<ChallengeField, ChallengeField>>,
    masked_sumcheck: Option<PrecommittedMaskedSumcheck>,
    initial_source_compression: Option<ExternalSourceCompression>,
    sumchecks: Vec<p3_sumcheck::zk::ZkSumcheckData<ChallengeField, ChallengeField>>,
    rounds: Vec<AggregateWideRoundProof>,
    base_case: Option<p3_whir::BaseCaseZkProof<ChallengeField, ChallengeField, CommitmentScheme>>,
    prepared_base_case: Option<PreparedAggregateWideBaseCase>,
    current_target: ChallengeField,
    folding_randomness: Point<ChallengeField>,
    current_batch_ordinal: usize,
    current_round_ordinal: usize,
    current_source_writer: Option<AggregateSourceWriter>,
    current_oracle_pass: Option<RecomputableOraclePass>,
    current_round_commitment: Option<AggregateWideCommitment>,
    current_switch_mask_delta: Vec<ChallengeField>,
    current_round_proof_of_work_witness: ChallengeField,
    round_query_indices: Vec<usize>,
    pending_openings: Option<RecomputableOracleOutput>,
    stage: StreamingAggregateWideProofStage,
}

impl StreamingAggregateWideCommitmentGeneration {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        pcs: &AggregateWidePcs,
        config: SelectedHidingWhirConfig,
        source_table: AggregateSourceTable,
        residuals: Vec<ExternalPolynomialVector>,
        material: AggregateWideHidingMaterial,
    ) -> Result<Self, String> {
        validate_matching_configuration(pcs, &config)?;
        if source_table.stacked_variable_count() != config.num_variables
            || source_table.folding_factor() != config.round_folding_factor(0)
            || residuals.len() != config.n_rounds()
        {
            return Err("aggregate-wide source catalog has the wrong geometry".to_owned());
        }
        let mut residual_variable_count = config.num_variables;
        for (residual_ordinal, residual) in residuals.iter().enumerate() {
            residual_variable_count = residual_variable_count
                .checked_sub(config.round_folding_factor(residual_ordinal))
                .ok_or_else(|| "aggregate-wide residual arity underflowed".to_owned())?;
            if residual.element_count()
                != checked_power_of_two(residual_variable_count, "aggregate residual length")?
            {
                return Err("aggregate-wide residual catalog has the wrong length".to_owned());
            }
        }
        if material.oracle_randomness.len() != config.n_rounds() + 1 {
            return Err("aggregate-wide oracle randomness has the wrong epoch count".to_owned());
        }
        for (oracle_ordinal, randomness) in material.oracle_randomness.iter().enumerate() {
            let expected_length = config.oracle_randomness[oracle_ordinal]
                .checked_shl(
                    u32::try_from(config.round_folding_factor(oracle_ordinal))
                        .map_err(|_| "aggregate-wide folding factor exceeds u32".to_owned())?,
                )
                .ok_or_else(|| "aggregate-wide oracle randomness length overflowed".to_owned())?;
            if randomness.len() != expected_length {
                return Err(format!(
                    "aggregate-wide oracle randomness {oracle_ordinal} has {} elements, expected {expected_length}",
                    randomness.len()
                ));
            }
        }

        let pad_layout = AggregateWidePadLayout::derive(&config)?;
        if material.pad_message.len() != pad_layout.message_length()
            || material.pad_randomness.len() != config.sumcheck_mask.randomness_len
        {
            return Err("aggregate-wide pad material has the wrong shape".to_owned());
        }
        let oracle_pass = RecomputableOraclePass::new(
            RecomputableOracleSource::ExternalTable(source_table.clone()),
            config.num_variables,
            config.round_folding_factor(0),
            checked_power_of_two(config.starting_log_inv_rate, "starting inverse rate")?,
            material.oracle_randomness[0].clone(),
            &[],
        )
        .map_err(|error| format!("construct aggregate-wide initial oracle pass: {error}"))?;
        let detached_layout = AggregateLayout::new_detached(
            vec![TableShape::new(
                source_table.table_variable_count(),
                source_table.table_width(),
            )],
            source_table.folding_factor(),
        )
        .map_err(|_| "construct aggregate-wide detached layout".to_owned())?;

        Ok(Self {
            config,
            extension_mmcs: pcs.extension_mmcs.clone(),
            dft: pcs.dft.clone(),
            source_table,
            residuals,
            detached_layout: Some(detached_layout),
            oracle_randomness: material.oracle_randomness,
            pad_layout,
            pad_message: Some(material.pad_message),
            pad_randomness: Some(material.pad_randomness),
            base_case_fresh_material: Some(material.base_case_fresh_material),
            oracle_pass: Some(oracle_pass),
            opening_preparation: None,
            source_commitment: None,
            committed_pad: None,
            prepared_prover_data: None,
            stage: StreamingAggregateWideCommitmentStage::BuildRoot,
        })
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn prepare_openings(
        &mut self,
        points: &[Point<ChallengeField>],
        requested_columns_by_point: &[Vec<usize>],
        _challenger: &mut ExtensionFieldChallenger,
    ) -> Result<(), String> {
        if self.stage != StreamingAggregateWideCommitmentStage::AwaitOpeningPreparation {
            return Err(
                "aggregate-wide openings may be prepared only after both commitments are observed"
                    .to_owned(),
            );
        }
        if points.len() != requested_columns_by_point.len()
            || self.config.commitment_ood_samples != 0
        {
            return Err("aggregate-wide opening request has an unsupported shape".to_owned());
        }

        for (point, requested_columns) in points.iter().zip(requested_columns_by_point) {
            if point.num_variables() != self.source_table.table_variable_count()
                || requested_columns.is_empty()
                || requested_columns
                    .iter()
                    .any(|column_index| *column_index >= self.source_table.table_width())
                || requested_columns
                    .windows(2)
                    .any(|adjacent| adjacent[0] >= adjacent[1])
            {
                return Err("aggregate-wide opening request does not match the source".to_owned());
            }
        }
        let layout = self
            .detached_layout
            .take()
            .ok_or_else(|| "aggregate-wide detached layout is missing".to_owned())?;
        if self.config.round_folding_factor(0) != layout.folding()
            || AggregateLayout::variable_order() != VariableOrder::Prefix
        {
            return Err("aggregate-wide layout has the wrong prefix folding".to_owned());
        }
        self.opening_preparation = Some(DetachedOpeningPreparation::new(
            self.source_table.clone(),
            layout,
            points,
            requested_columns_by_point,
        )?);
        self.stage = StreamingAggregateWideCommitmentStage::PrepareOpenings;
        Ok(())
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<StreamingAggregateWideCommitmentPoll, StreamingAggregateWideError<Storage::Error>>
    {
        match self.stage {
            StreamingAggregateWideCommitmentStage::BuildRoot => {
                let oracle_pass = self.oracle_pass.as_mut().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide initial oracle pass is missing")
                })?;
                match oracle_pass
                    .poll_external(executor, storage)
                    .map_err(map_recomputable_oracle_error)?
                {
                    RecomputableOraclePoll::ArithmeticStepCompleted => {
                        Ok(StreamingAggregateWideCommitmentPoll::ArithmeticStepCompleted)
                    }
                    RecomputableOraclePoll::StorageTransactionCompleted => {
                        Ok(StreamingAggregateWideCommitmentPoll::StorageTransactionCompleted)
                    }
                    RecomputableOraclePoll::Complete(output) => {
                        if !output.rows.is_empty() || !output.paths.is_empty() {
                            return Err(Self::geometry_error(
                                "aggregate-wide root pass retained unexpected openings",
                            ));
                        }
                        self.oracle_pass = None;
                        self.source_commitment = Some(output.root);
                        self.stage = StreamingAggregateWideCommitmentStage::ObserveCommitments;
                        Ok(StreamingAggregateWideCommitmentPoll::ArithmeticStepCompleted)
                    }
                }
            }
            StreamingAggregateWideCommitmentStage::PrepareOpenings => {
                let preparation = self.opening_preparation.as_mut().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide opening preparation is missing")
                })?;
                match preparation
                    .poll(challenger, executor, storage)
                    .map_err(|error| StreamingAggregateWideError::Storage(error))?
                {
                    DetachedOpeningPreparationPoll::StorageTransactionCompleted => {
                        Ok(StreamingAggregateWideCommitmentPoll::StorageTransactionCompleted)
                    }
                    DetachedOpeningPreparationPoll::Complete(output) => {
                        self.opening_preparation = None;
                        let initial_sumcheck = output.layout.begin_initial_sumcheck(challenger);
                        self.prepared_prover_data = Some(StreamingAggregateWideProverData {
                            config: self.config.clone(),
                            extension_mmcs: self.extension_mmcs.clone(),
                            dft: self.dft.clone(),
                            source_table: self.source_table.clone(),
                            residuals: core::mem::take(&mut self.residuals),
                            oracle_randomness: core::mem::take(&mut self.oracle_randomness),
                            pad_layout: self.pad_layout.clone(),
                            committed_pad: self.committed_pad.take().ok_or_else(|| {
                                Self::geometry_error("aggregate-wide committed pad is missing")
                            })?,
                            base_case_fresh_material: self
                                .base_case_fresh_material
                                .take()
                                .ok_or_else(|| {
                                    Self::geometry_error(
                                        "aggregate-wide fresh base material is missing",
                                    )
                                })?,
                            evaluations: output.evaluations,
                            initial_sumcheck,
                        });
                        self.stage = StreamingAggregateWideCommitmentStage::Complete;
                        Ok(StreamingAggregateWideCommitmentPoll::ArithmeticStepCompleted)
                    }
                }
            }
            StreamingAggregateWideCommitmentStage::ObserveCommitments => {
                let source_commitment = self.source_commitment.clone().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide source commitment is missing")
                })?;
                challenger.observe(source_commitment.clone());
                let committed_pad = AggregateWideCommittedPad::commit(
                    &self.extension_mmcs,
                    aggregate_wide_pad_shape(&self.config, &self.pad_layout),
                    self.pad_message.take().ok_or_else(|| {
                        Self::geometry_error("aggregate-wide pad message is missing")
                    })?,
                    self.pad_randomness.take().ok_or_else(|| {
                        Self::geometry_error("aggregate-wide pad randomness is missing")
                    })?,
                    challenger,
                )
                .map_err(Self::geometry_error)?;
                let pad_commitment = committed_pad.commitment().clone();
                self.committed_pad = Some(committed_pad);
                self.stage = StreamingAggregateWideCommitmentStage::AwaitOpeningPreparation;
                Ok(StreamingAggregateWideCommitmentPoll::CommitmentsObserved {
                    source_commitment,
                    pad_commitment,
                })
            }
            StreamingAggregateWideCommitmentStage::AwaitOpeningPreparation => {
                Err(Self::geometry_error(
                    "aggregate-wide commitment is waiting for opening preparation",
                ))
            }
            StreamingAggregateWideCommitmentStage::Complete => {
                Ok(StreamingAggregateWideCommitmentPoll::Complete(
                    StreamingAggregateWideCommitmentOutput {
                        source_commitment: self.source_commitment.take().ok_or_else(|| {
                            Self::geometry_error("aggregate-wide completed source root is missing")
                        })?,
                        prover_data: self.prepared_prover_data.take().ok_or_else(|| {
                            Self::geometry_error("aggregate-wide completed prover data is missing")
                        })?,
                    },
                ))
            }
        }
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn cancel<Storage: ProofExternalMemory>(
        self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<(), StreamingAggregateWideError<Storage::Error>> {
        executor
            .cancel(storage)
            .map_err(StreamingAggregateWideError::Storage)
    }

    fn geometry_error<StorageError>(
        message: impl Into<String>,
    ) -> StreamingAggregateWideError<StorageError> {
        StreamingAggregateWideError::Geometry(message.into())
    }
}

impl StreamingAggregateWideProofGeneration {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        initial_commitment: AggregateWideCommitment,
        prover_data: StreamingAggregateWideProverData,
    ) -> Result<Self, String> {
        if prover_data.oracle_randomness.len() != prover_data.config.n_rounds() + 1 {
            return Err(
                "aggregate-wide prover data has the wrong randomness epoch count".to_owned(),
            );
        }
        let pad_message_length = prover_data.pad_layout.message_length();
        Ok(Self {
            config: prover_data.config,
            extension_mmcs: prover_data.extension_mmcs,
            dft: prover_data.dft,
            source_table: prover_data.source_table,
            residuals: prover_data.residuals,
            oracle_roots: vec![initial_commitment],
            oracle_randomness: prover_data.oracle_randomness,
            current_folded_oracle_randomness: Vec::new(),
            pad_layout: prover_data.pad_layout,
            pad_claim: AggregateWidePadClaim::new(pad_message_length),
            committed_pad: prover_data.committed_pad,
            base_case_fresh_material: prover_data.base_case_fresh_material,
            evaluations: Some(prover_data.evaluations),
            initial_sumcheck: Some(prover_data.initial_sumcheck),
            sumcheck_prover: None,
            masked_sumcheck: None,
            initial_source_compression: None,
            sumchecks: Vec::new(),
            rounds: Vec::new(),
            base_case: None,
            prepared_base_case: None,
            current_target: ChallengeField::ZERO,
            folding_randomness: Point::default(),
            current_batch_ordinal: 0,
            current_round_ordinal: 0,
            current_source_writer: None,
            current_oracle_pass: None,
            current_round_commitment: None,
            current_switch_mask_delta: Vec::new(),
            current_round_proof_of_work_witness: ChallengeField::ZERO,
            round_query_indices: Vec::new(),
            pending_openings: None,
            stage: StreamingAggregateWideProofStage::BeginMaskedSumcheck,
        })
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<StreamingAggregateWideProofPoll, StreamingAggregateWideError<Storage::Error>> {
        match self.stage {
            StreamingAggregateWideProofStage::BeginMaskedSumcheck => {
                self.begin_masked_sumcheck(challenger)?;
                self.stage = StreamingAggregateWideProofStage::AdvanceMaskedSumcheck;
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::MaskedSumcheckRound {
                        batch_ordinal: self.current_batch_ordinal,
                        completed_round_count: 0,
                    },
                ))
            }
            StreamingAggregateWideProofStage::AdvanceMaskedSumcheck => {
                let masked = self.masked_sumcheck.as_mut().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide masked sumcheck is missing")
                })?;
                let advanced = masked
                    .advance_round(challenger)
                    .map_err(Self::geometry_error)?;
                let completed_round_count = masked.completed_round_count();
                if !advanced {
                    self.stage = StreamingAggregateWideProofStage::FinishMaskedSumcheck;
                }
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::MaskedSumcheckRound {
                        batch_ordinal: self.current_batch_ordinal,
                        completed_round_count,
                    },
                ))
            }
            StreamingAggregateWideProofStage::FinishMaskedSumcheck => {
                if self.current_batch_ordinal == 0 {
                    let folding_point = self
                        .masked_sumcheck
                        .as_ref()
                        .ok_or_else(|| {
                            Self::geometry_error("aggregate-wide masked sumcheck is missing")
                        })?
                        .randomness();
                    self.initial_source_compression = Some(
                        ExternalSourceCompression::new(self.source_table.clone(), folding_point)
                            .map_err(Self::geometry_error)?,
                    );
                    self.stage = StreamingAggregateWideProofStage::CompressInitialSource;
                } else {
                    self.finish_masked_sumcheck(None)?;
                    self.stage = StreamingAggregateWideProofStage::CompleteRoundExternalMemoryStep;
                }
                let completed_round_count = self.masked_sumcheck.as_ref().map_or_else(
                    || self.folding_randomness.num_variables(),
                    |state| state.completed_round_count(),
                );
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::MaskedSumcheckRound {
                        batch_ordinal: self.current_batch_ordinal,
                        completed_round_count,
                    },
                ))
            }
            StreamingAggregateWideProofStage::CompressInitialSource => {
                let compression = self.initial_source_compression.as_mut().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide initial source compression is missing")
                })?;
                match compression
                    .poll(executor, storage)
                    .map_err(|error| StreamingAggregateWideError::Storage(error))?
                {
                    ExternalSourceCompressionPoll::StorageTransactionCompleted => Ok(
                        StreamingAggregateWideProofPoll::StorageTransactionCompleted(
                            StreamingAggregateWideProofBoundary::RoundOracleStorage {
                                round_ordinal: 0,
                            },
                        ),
                    ),
                    ExternalSourceCompressionPoll::Complete(compressed) => {
                        self.initial_source_compression = None;
                        self.finish_masked_sumcheck(Some(compressed))?;
                        self.stage = StreamingAggregateWideProofStage::BeginRound;
                        Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                            StreamingAggregateWideProofBoundary::MaskedSumcheckRound {
                                batch_ordinal: 0,
                                completed_round_count: self.folding_randomness.num_variables(),
                            },
                        ))
                    }
                }
            }
            StreamingAggregateWideProofStage::BeginRound => {
                if self.current_round_ordinal == self.config.n_rounds() {
                    self.stage = StreamingAggregateWideProofStage::PrepareBaseCase;
                    return Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                        StreamingAggregateWideProofBoundary::BaseCasePrepared,
                    ));
                }
                let expected_variable_count = self.config.num_variables
                    - self.config.total_folded_through(self.current_round_ordinal);
                if self.sumcheck_prover()?.num_variables() != expected_variable_count {
                    return Err(Self::geometry_error(format!(
                        "aggregate-wide round {} has {} variables, expected {expected_variable_count}",
                        self.current_round_ordinal,
                        self.sumcheck_prover()?.num_variables()
                    )));
                }
                let next_folding_factor = self
                    .config
                    .round_folding_factor(self.current_round_ordinal + 1);
                let residual =
                    *self
                        .residuals
                        .get(self.current_round_ordinal)
                        .ok_or_else(|| {
                            Self::geometry_error("aggregate-wide residual descriptor is missing")
                        })?;
                if residual.element_count()
                    != checked_power_of_two(expected_variable_count, "aggregate residual length")
                        .map_err(Self::geometry_error)?
                {
                    return Err(Self::geometry_error(
                        "aggregate-wide residual descriptor has the wrong shape",
                    ));
                }
                self.current_source_writer =
                    Some(AggregateSourceWriter::new(residual).map_err(Self::geometry_error)?);
                self.current_oracle_pass = Some(
                    RecomputableOraclePass::new(
                        RecomputableOracleSource::ResidentPolynomial,
                        expected_variable_count,
                        next_folding_factor,
                        self.config.inv_rate(self.current_round_ordinal),
                        self.oracle_randomness[self.current_round_ordinal + 1].clone(),
                        &[],
                    )
                    .map_err(Self::geometry_error)?,
                );
                self.stage = StreamingAggregateWideProofStage::WriteCurrentOracle;
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::RoundOracleArithmetic {
                        round_ordinal: self.current_round_ordinal,
                    },
                ))
            }
            StreamingAggregateWideProofStage::WriteCurrentOracle => {
                let mut writer = self.current_source_writer.take().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide residual writer is missing")
                })?;
                let complete = writer
                    .poll(
                        AggregateSourceValues::Polynomial(self.sumcheck_prover()?.evals_view()),
                        executor,
                        storage,
                    )
                    .map_err(|error| StreamingAggregateWideError::Storage(error))?;
                if complete {
                    self.stage = StreamingAggregateWideProofStage::ReadCurrentRoot;
                } else {
                    self.current_source_writer = Some(writer);
                }
                Ok(
                    StreamingAggregateWideProofPoll::StorageTransactionCompleted(
                        StreamingAggregateWideProofBoundary::RoundOracleStorage {
                            round_ordinal: self.current_round_ordinal,
                        },
                    ),
                )
            }
            StreamingAggregateWideProofStage::ReadCurrentRoot => {
                let mut oracle_pass = self.current_oracle_pass.take().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide round root pass is missing")
                })?;
                let oracle_poll = {
                    let source = self.sumcheck_prover()?.evals_view();
                    oracle_pass
                        .poll_resident(source)
                        .map_err(Self::geometry_error)?
                };
                match oracle_poll {
                    RecomputableOraclePoll::StorageTransactionCompleted => {
                        return Err(Self::geometry_error(
                            "resident aggregate-wide root requested external storage",
                        ));
                    }
                    RecomputableOraclePoll::ArithmeticStepCompleted => {
                        self.current_oracle_pass = Some(oracle_pass);
                        Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                            StreamingAggregateWideProofBoundary::RoundOracleArithmetic {
                                round_ordinal: self.current_round_ordinal,
                            },
                        ))
                    }
                    RecomputableOraclePoll::Complete(output) => {
                        if !output.rows.is_empty() || !output.paths.is_empty() {
                            return Err(Self::geometry_error(
                                "aggregate-wide round root pass retained unexpected openings",
                            ));
                        }
                        challenger.observe(output.root.clone());
                        let switch_mask_delta = switch_mask_delta(
                            &self.pad_layout,
                            self.current_round_ordinal,
                            &self.current_folded_oracle_randomness,
                            self.committed_pad.message(),
                        )
                        .map_err(Self::geometry_error)?;
                        challenger.observe_algebra_slice(&switch_mask_delta);
                        self.current_switch_mask_delta = switch_mask_delta;
                        self.current_round_commitment = Some(output.root.clone());
                        self.oracle_roots.push(output.root);
                        self.stage = StreamingAggregateWideProofStage::SampleRoundQueries;
                        Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                            StreamingAggregateWideProofBoundary::RoundOracleArithmetic {
                                round_ordinal: self.current_round_ordinal,
                            },
                        ))
                    }
                }
            }
            StreamingAggregateWideProofStage::SampleRoundQueries => {
                let round = &self.config.round_parameters[self.current_round_ordinal];
                self.current_round_proof_of_work_witness = if round.pow_bits == 0 {
                    ChallengeField::ZERO
                } else {
                    challenger.grind(round.pow_bits)
                };
                let _: ChallengeField = challenger.sample();
                self.round_query_indices = sample_distinct_query_indices(
                    round.domain_size,
                    self.config.round_folding_factor(self.current_round_ordinal),
                    round.num_queries,
                    challenger,
                )
                .map_err(Self::geometry_error)?;
                let oracle_ordinal = self.current_round_ordinal;
                let source_variable_count = self.config.num_variables
                    - (0..oracle_ordinal)
                        .map(|ordinal| self.config.round_folding_factor(ordinal))
                        .sum::<usize>();
                let source = if oracle_ordinal == 0 {
                    RecomputableOracleSource::ExternalTable(self.source_table.clone())
                } else {
                    RecomputableOracleSource::ExternalPolynomial(
                        *self.residuals.get(oracle_ordinal - 1).ok_or_else(|| {
                            Self::geometry_error(
                                "aggregate-wide query source descriptor is missing",
                            )
                        })?,
                    )
                };
                let inverse_rate = if oracle_ordinal == 0 {
                    checked_power_of_two(self.config.starting_log_inv_rate, "starting inverse rate")
                        .map_err(Self::geometry_error)?
                } else {
                    self.config.inv_rate(oracle_ordinal - 1)
                };
                self.current_oracle_pass = Some(
                    RecomputableOraclePass::new(
                        source,
                        source_variable_count,
                        self.config.round_folding_factor(oracle_ordinal),
                        inverse_rate,
                        self.oracle_randomness[oracle_ordinal].clone(),
                        &self.round_query_indices,
                    )
                    .map_err(Self::geometry_error)?,
                );
                self.stage = StreamingAggregateWideProofStage::ReadPreviousOracle;
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::RoundQueriesPrepared {
                        round_ordinal: self.current_round_ordinal,
                    },
                ))
            }
            StreamingAggregateWideProofStage::ReadPreviousOracle => {
                let oracle_pass = self.current_oracle_pass.as_mut().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide previous-oracle pass is missing")
                })?;
                match oracle_pass
                    .poll_external(executor, storage)
                    .map_err(map_recomputable_oracle_error)?
                {
                    RecomputableOraclePoll::ArithmeticStepCompleted => {
                        Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                            StreamingAggregateWideProofBoundary::RoundOracleArithmetic {
                                round_ordinal: self.current_round_ordinal,
                            },
                        ))
                    }
                    RecomputableOraclePoll::StorageTransactionCompleted => Ok(
                        StreamingAggregateWideProofPoll::StorageTransactionCompleted(
                            StreamingAggregateWideProofBoundary::RoundOracleStorage {
                                round_ordinal: self.current_round_ordinal,
                            },
                        ),
                    ),
                    RecomputableOraclePoll::Complete(output) => {
                        self.current_oracle_pass = None;
                        self.pending_openings = Some(output);
                        self.stage = StreamingAggregateWideProofStage::PrepareRound;
                        Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                            StreamingAggregateWideProofBoundary::RoundQueriesPrepared {
                                round_ordinal: self.current_round_ordinal,
                            },
                        ))
                    }
                }
            }
            StreamingAggregateWideProofStage::PrepareRound => {
                self.prepare_round(challenger)?;
                self.current_batch_ordinal = self.current_round_ordinal + 1;
                self.stage = StreamingAggregateWideProofStage::BeginMaskedSumcheck;
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::RoundQueriesPrepared {
                        round_ordinal: self.current_round_ordinal,
                    },
                ))
            }
            StreamingAggregateWideProofStage::CompleteRoundExternalMemoryStep => {
                executor
                    .complete_step(storage)
                    .map_err(StreamingAggregateWideError::Storage)?;
                self.current_round_ordinal += 1;
                self.stage = StreamingAggregateWideProofStage::BeginRound;
                Ok(
                    StreamingAggregateWideProofPoll::StorageTransactionCompleted(
                        StreamingAggregateWideProofBoundary::RoundStorageReleased {
                            completed_round_count: self.current_round_ordinal,
                        },
                    ),
                )
            }
            StreamingAggregateWideProofStage::PrepareBaseCase => {
                self.prepare_base_case(challenger)?;
                self.stage = StreamingAggregateWideProofStage::ReadBaseSource;
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::BaseCasePrepared,
                ))
            }
            StreamingAggregateWideProofStage::ReadBaseSource => {
                let oracle_pass = self.current_oracle_pass.as_mut().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide base source pass is missing")
                })?;
                match oracle_pass
                    .poll_external(executor, storage)
                    .map_err(map_recomputable_oracle_error)?
                {
                    RecomputableOraclePoll::ArithmeticStepCompleted => {
                        Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                            StreamingAggregateWideProofBoundary::BaseCasePrepared,
                        ))
                    }
                    RecomputableOraclePoll::StorageTransactionCompleted => Ok(
                        StreamingAggregateWideProofPoll::StorageTransactionCompleted(
                            StreamingAggregateWideProofBoundary::BaseSourceStorage,
                        ),
                    ),
                    RecomputableOraclePoll::Complete(output) => {
                        self.current_oracle_pass = None;
                        self.finish_base_case(output)?;
                        self.stage =
                            StreamingAggregateWideProofStage::CompleteBaseExternalMemoryStep;
                        Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                            StreamingAggregateWideProofBoundary::BaseCasePrepared,
                        ))
                    }
                }
            }
            StreamingAggregateWideProofStage::CompleteBaseExternalMemoryStep => {
                executor
                    .complete_step(storage)
                    .map_err(StreamingAggregateWideError::Storage)?;
                self.stage = StreamingAggregateWideProofStage::Finish;
                Ok(
                    StreamingAggregateWideProofPoll::StorageTransactionCompleted(
                        StreamingAggregateWideProofBoundary::BaseStorageReleased,
                    ),
                )
            }
            StreamingAggregateWideProofStage::Finish => {
                challenger
                    .ensure_sampling_succeeded()
                    .map_err(Self::geometry_error)?;
                self.stage = StreamingAggregateWideProofStage::Complete;
                Ok(StreamingAggregateWideProofPoll::ArithmeticStepCompleted(
                    StreamingAggregateWideProofBoundary::ProofReady,
                ))
            }
            StreamingAggregateWideProofStage::Complete => {
                let query_index_schedule = challenger
                    .sampled_query_index_schedule()
                    .map_err(Self::geometry_error)?;
                Ok(StreamingAggregateWideProofPoll::Complete(
                    AggregateWideOpeningProof::new(
                        self.committed_pad.commitment().clone(),
                        self.evaluations.take().ok_or_else(|| {
                            Self::geometry_error("aggregate-wide evaluations are missing")
                        })?,
                        core::mem::take(&mut self.sumchecks),
                        core::mem::take(&mut self.rounds),
                        self.base_case.take().ok_or_else(|| {
                            Self::geometry_error("aggregate-wide base case is missing")
                        })?,
                        query_index_schedule,
                    ),
                ))
            }
        }
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn cancel<Storage: ProofExternalMemory>(
        self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<(), StreamingAggregateWideError<Storage::Error>> {
        executor
            .cancel(storage)
            .map_err(StreamingAggregateWideError::Storage)
    }

    fn begin_masked_sumcheck<StorageError>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<(), StreamingAggregateWideError<StorageError>> {
        let masks = self
            .pad_layout
            .sumcheck_masks(self.current_batch_ordinal, self.committed_pad.message())
            .map_err(Self::geometry_error)?;
        let pow_bits = if self.current_batch_ordinal == 0 {
            self.config.starting_folding_pow_bits
        } else {
            self.config.round_parameters[self.current_batch_ordinal - 1].folding_pow_bits
        };
        let masked = if self.current_batch_ordinal == 0 {
            PrecommittedMaskedSumcheck::begin_initial(
                self.initial_sumcheck.take().ok_or_else(|| {
                    Self::geometry_error("aggregate-wide initial sumcheck is missing")
                })?,
                masks,
                pow_bits,
                challenger,
            )
        } else {
            let auxiliary_claim = self
                .pad_claim
                .evaluate(self.committed_pad.message())
                .map_err(Self::geometry_error)?;
            let source = self.sumcheck_prover.take().ok_or_else(|| {
                Self::geometry_error("aggregate-wide residual sumcheck prover is missing")
            })?;
            if source.claimed_sum() + auxiliary_claim != self.current_target {
                return Err(Self::geometry_error(
                    "aggregate-wide residual claim does not match its public target",
                ));
            }
            PrecommittedMaskedSumcheck::begin_residual(
                source,
                masks,
                auxiliary_claim,
                pow_bits,
                challenger,
            )
        }
        .map_err(Self::geometry_error)?;
        self.masked_sumcheck = Some(masked);
        Ok(())
    }

    fn finish_masked_sumcheck<StorageError>(
        &mut self,
        initial_compressed: Option<Poly<ChallengeField>>,
    ) -> Result<(), StreamingAggregateWideError<StorageError>> {
        let masked = self
            .masked_sumcheck
            .take()
            .ok_or_else(|| Self::geometry_error("aggregate-wide masked sumcheck is missing"))?;
        let output = match initial_compressed {
            Some(compressed) => masked.finish_initial_with_compressed(compressed),
            None => masked.finish(),
        }
        .map_err(Self::geometry_error)?;
        let batch_layout = self
            .pad_layout
            .sumcheck_batch(self.current_batch_ordinal)
            .map_err(Self::geometry_error)?;
        self.pad_claim
            .record_sumcheck_batch(batch_layout, output.eps, &output.randomness)
            .map_err(Self::geometry_error)?;
        let folded_length = self.config.oracle_randomness[self.current_batch_ordinal];
        self.current_folded_oracle_randomness = fold_limb_randomness(
            &self.oracle_randomness[self.current_batch_ordinal],
            folded_length,
            &output.randomness,
        )
        .map_err(Self::geometry_error)?;
        self.current_target = output.residual_prover.claimed_sum()
            + self
                .pad_claim
                .evaluate(self.committed_pad.message())
                .map_err(Self::geometry_error)?;
        self.folding_randomness = output.randomness;
        self.sumcheck_prover = Some(output.residual_prover);
        self.sumchecks.push(output.proof);
        Ok(())
    }

    fn prepare_round<StorageError>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<(), StreamingAggregateWideError<StorageError>> {
        let openings = self
            .pending_openings
            .take()
            .ok_or_else(|| Self::geometry_error("aggregate-wide round openings are missing"))?;
        let expected_root = self
            .oracle_roots
            .get(self.current_round_ordinal)
            .ok_or_else(|| Self::geometry_error("aggregate-wide prior oracle root is missing"))?;
        if &openings.root != expected_root
            || openings.rows.len() != self.round_query_indices.len()
            || openings.paths.len() != self.round_query_indices.len()
        {
            return Err(Self::geometry_error(
                "aggregate-wide prior-oracle opening pass has the wrong root or shape",
            ));
        }

        let num_variables = self.sumcheck_prover()?.num_variables();
        let message_length = checked_power_of_two(num_variables, "aggregate-wide source length")
            .map_err(Self::geometry_error)?;
        if self.current_folded_oracle_randomness.len()
            != self.config.oracle_randomness[self.current_round_ordinal]
        {
            return Err(Self::geometry_error(
                "aggregate-wide folded oracle randomness has the wrong length",
            ));
        }
        let folded_domain_generator =
            self.config.round_parameters[self.current_round_ordinal].folded_domain_gen;
        let mut public_statement = SelectStatement::initialize(num_variables);
        let mut source_statement = SelectStatement::initialize(num_variables);
        let mut query_points = Vec::with_capacity(self.round_query_indices.len());
        let mut queries = Vec::with_capacity(self.round_query_indices.len());
        let query_value_is_base = self.current_round_ordinal == 0;
        for ((query_index, values), path) in self
            .round_query_indices
            .iter()
            .copied()
            .zip(openings.rows)
            .zip(openings.paths)
        {
            if values.len()
                != checked_power_of_two(
                    self.config.round_folding_factor(self.current_round_ordinal),
                    "aggregate-wide opened row width",
                )
                .map_err(Self::geometry_error)?
            {
                return Err(Self::geometry_error(
                    "aggregate-wide opened oracle row has the wrong width",
                ));
            }
            let query_polynomial = Poly::new(values);
            let full_evaluation = if query_value_is_base {
                query_polynomial.eval_base(&self.folding_randomness)
            } else {
                query_polynomial.eval_ext::<ChallengeField>(&self.folding_randomness)
            };
            let query_point = folded_domain_generator.exp_u64(query_index as u64);
            let randomness_evaluation = trailing_coefficient_evaluation(
                &self.current_folded_oracle_randomness,
                message_length,
                query_point,
            );
            public_statement.add_constraint(query_point, full_evaluation);
            source_statement.add_constraint(query_point, full_evaluation - randomness_evaluation);
            query_points.push(query_point);
            let values = query_polynomial.into_evals();
            queries.push(if query_value_is_base {
                QueryOpening::Base {
                    values,
                    proof: path,
                }
            } else {
                QueryOpening::Extension {
                    values,
                    proof: path,
                }
            });
        }

        let combination = challenger.sample_algebra_element();
        let public_constraint = Constraint::new(
            combination,
            num_variables,
            vec![Statements::Select(public_statement)],
        );
        let source_constraint = Constraint::new(
            combination,
            num_variables,
            vec![Statements::Select(source_statement)],
        );
        public_constraint.combine_evals(&mut self.current_target);
        self.sumcheck_prover
            .as_mut()
            .ok_or_else(|| Self::geometry_error("aggregate-wide sumcheck prover is missing"))?
            .apply_constraint(&source_constraint);

        let carried_multiplier = public_constraint.carried_claim_multiplier();
        self.pad_claim.batch_carried_claim(carried_multiplier);
        let query_coefficients = public_constraint
            .challenge_powers(0)
            .take(query_points.len())
            .collect::<Vec<_>>();
        let logical_mask_covector = switch_mask_covector(
            message_length,
            self.current_folded_oracle_randomness.len(),
            0,
            &[],
            &[],
            &query_points,
            &query_coefficients,
        );
        let switch_mask_delta = core::mem::take(&mut self.current_switch_mask_delta);
        let pad_range = self
            .pad_layout
            .switch_mask_range(self.current_round_ordinal)
            .map_err(Self::geometry_error)?;
        self.pad_claim
            .record_switch_mask_delta(pad_range, &logical_mask_covector, &switch_mask_delta)
            .map_err(Self::geometry_error)?;
        let reconstructed_target = self.sumcheck_prover()?.claimed_sum()
            + self
                .pad_claim
                .evaluate(self.committed_pad.message())
                .map_err(Self::geometry_error)?;
        if reconstructed_target != self.current_target {
            return Err(Self::geometry_error(
                "aggregate-wide code-switch relation failed its same-secret identity",
            ));
        }

        self.rounds.push(AggregateWideRoundProof {
            commitment: self.current_round_commitment.take().ok_or_else(|| {
                Self::geometry_error("aggregate-wide round commitment is missing")
            })?,
            switch_mask_delta,
            proof_of_work_witness: self.current_round_proof_of_work_witness,
            queries,
        });
        Ok(())
    }

    fn prepare_base_case<StorageError>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<(), StreamingAggregateWideError<StorageError>> {
        let final_config = self.config.final_round_config();
        let source_code = FoldedRsCode::new(
            checked_power_of_two(final_config.num_variables, "aggregate-wide base message")
                .map_err(Self::geometry_error)?,
            self.config.oracle_randomness[self.config.n_rounds()],
            final_config.domain_size >> final_config.folding_factor,
        );
        let base_config = BaseCaseZkConfig {
            code: source_code,
            mask_groups: vec![MaskGroupShape {
                shape: aggregate_wide_pad_shape(&self.config, &self.pad_layout),
                width: 1,
            }],
            num_queries: self.config.final_queries,
            mask_queries: self.config.mask_queries,
            pow_bits: self.config.final_pow_bits,
        };
        let base_prover = BaseCaseZkProver {
            config: &base_config,
            extension_mmcs: &self.extension_mmcs,
        };
        let source_message = self.sumcheck_prover()?.evals();
        let source_covector = self.sumcheck_prover()?.weights();
        let pad_messages = core::slice::from_ref(self.committed_pad.message_vector());
        let pad_randomness = core::slice::from_ref(self.committed_pad.randomness_vector());
        let pad_covectors = core::slice::from_ref(self.pad_claim.covector_vector());
        let mask_witnesses = [MaskGroupWitness {
            messages: pad_messages,
            randomness: pad_randomness,
            covectors: pad_covectors,
            data: self.committed_pad.prover_data(),
        }];
        let expected_target = dot_product::<ChallengeField, _, _>(
            source_message.as_slice().iter().copied(),
            source_covector.as_slice().iter().copied(),
        ) + self
            .pad_claim
            .evaluate(self.committed_pad.message())
            .map_err(Self::geometry_error)?;
        if expected_target != self.current_target
            || self.current_folded_oracle_randomness.len()
                != self.config.oracle_randomness[self.config.n_rounds()]
        {
            return Err(Self::geometry_error(
                "aggregate-wide base relation has the wrong target or randomness shape",
            ));
        }
        let prepared = base_prover.prepare_with_material(
            &self.dft,
            source_message.as_slice(),
            &self.current_folded_oracle_randomness,
            source_covector.as_slice(),
            &mask_witnesses,
            &self.base_case_fresh_material,
            challenger,
        );
        let final_oracle_ordinal = self.config.n_rounds();
        self.current_oracle_pass = Some(
            RecomputableOraclePass::new(
                RecomputableOracleSource::ExternalPolynomial(*self.residuals.last().ok_or_else(
                    || Self::geometry_error("aggregate-wide final source descriptor is missing"),
                )?),
                final_config.num_variables,
                self.config.round_folding_factor(final_oracle_ordinal),
                self.config.inv_rate(final_oracle_ordinal - 1),
                self.oracle_randomness[final_oracle_ordinal].clone(),
                prepared.source_positions(),
            )
            .map_err(Self::geometry_error)?,
        );
        self.prepared_base_case = Some(prepared);
        Ok(())
    }

    fn finish_base_case<StorageError>(
        &mut self,
        openings: RecomputableOracleOutput,
    ) -> Result<(), StreamingAggregateWideError<StorageError>> {
        let expected_root = self
            .oracle_roots
            .get(self.config.n_rounds())
            .ok_or_else(|| Self::geometry_error("aggregate-wide final oracle root is missing"))?;
        let prepared = self
            .prepared_base_case
            .take()
            .ok_or_else(|| Self::geometry_error("aggregate-wide prepared base case is missing"))?;
        if &openings.root != expected_root
            || openings.rows.len() != prepared.source_positions().len()
            || openings.paths.len() != prepared.source_positions().len()
        {
            return Err(Self::geometry_error(
                "aggregate-wide base source openings have the wrong root or shape",
            ));
        }
        let source_queries = openings
            .rows
            .into_iter()
            .zip(openings.paths)
            .map(|(values, proof)| QueryOpening::Extension { values, proof })
            .collect();
        self.base_case = Some(
            prepared
                .finish(source_queries)
                .map_err(Self::geometry_error)?,
        );
        Ok(())
    }

    fn sumcheck_prover<StorageError>(
        &self,
    ) -> Result<
        &SumcheckProver<ChallengeField, ChallengeField>,
        StreamingAggregateWideError<StorageError>,
    > {
        self.sumcheck_prover
            .as_ref()
            .ok_or_else(|| Self::geometry_error("aggregate-wide sumcheck prover is missing"))
    }

    fn geometry_error<StorageError>(
        message: impl Into<String>,
    ) -> StreamingAggregateWideError<StorageError> {
        StreamingAggregateWideError::Geometry(message.into())
    }
}

fn trailing_coefficient_evaluation(
    coefficients: &[ChallengeField],
    message_length: usize,
    point: ChallengeField,
) -> ChallengeField {
    let mut power = point.exp_u64(message_length as u64);
    let mut evaluation = ChallengeField::ZERO;
    for coefficient in coefficients {
        evaluation += *coefficient * power;
        power *= point;
    }
    evaluation
}

fn aggregate_wide_pad_shape(
    config: &SelectedHidingWhirConfig,
    layout: &AggregateWidePadLayout,
) -> MaskCodeShape {
    MaskCodeShape::new(
        layout.message_length(),
        config.mask_queries,
        super::aggregate_wide_hiding::AGGREGATE_WIDE_PAD_LOG_INVERSE_RATE,
    )
}

fn validate_matching_configuration(
    pcs: &AggregateWidePcs,
    config: &SelectedHidingWhirConfig,
) -> Result<(), String> {
    if pcs.num_variables != config.num_variables
        || pcs.n_rounds() != config.n_rounds()
        || pcs.starting_log_inv_rate != config.starting_log_inv_rate
        || (0..=config.n_rounds()).any(|ordinal| {
            pcs.round_folding_factor(ordinal) != config.round_folding_factor(ordinal)
        })
        || (0..config.n_rounds()).any(|ordinal| {
            pcs.round_parameters[ordinal].domain_size
                != config.round_parameters[ordinal].domain_size
                || pcs.round_parameters[ordinal].num_queries
                    != config.round_parameters[ordinal].num_queries
                || pcs.round_parameters[ordinal].ood_samples != 0
        })
        || pcs.final_queries != config.final_queries
    {
        return Err("plain and aggregate-wide configurations do not share one geometry".to_owned());
    }
    Ok(())
}

fn map_recomputable_oracle_error<StorageError>(
    error: RecomputableOracleError<StorageError>,
) -> StreamingAggregateWideError<StorageError> {
    match error {
        RecomputableOracleError::Geometry(message) => {
            StreamingAggregateWideError::Geometry(message)
        }
        RecomputableOracleError::Storage(error) => StreamingAggregateWideError::Storage(error),
    }
}
