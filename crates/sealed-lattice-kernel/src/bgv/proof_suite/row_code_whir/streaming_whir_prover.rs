//! Allocation-bounded plain-WHIR prover.
//!
//! The upstream prover retains every Merkle layer beside each encoded
//! codeword. The initial target commitment is large enough that this exceeds
//! the participant WebAssembly memory ceiling. This adapter preserves the
//! upstream transcript and proof types while deriving roots and authentication
//! paths in separate deterministic passes. Encoded matrices are released
//! after each pass; only their smaller source polynomial and a logarithmic
//! Merkle frontier remain live between transcript stages.

use core::mem::size_of;
use std::collections::BTreeMap;

use p3_challenger::{
    CanObserve, CanSample, CanSampleUniformBits, FieldChallenger, GrindingChallenger,
};
use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
#[cfg(test)]
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_sumcheck::{
    OpeningBatch, SumcheckData,
    constraints::{
        Constraint, Statements,
        statement::{EqStatement, SelectStatement},
    },
    layout::{Layout, PrefixInitialSumcheckProver, Witness},
    product_polynomial::PolyView,
    strategy::{SumcheckProver, VariableOrder},
};
use p3_symmetric::{MerkleCap, PseudoCompressionFunction};
use p3_whir::{PcsProof, QueryOpening, WhirConfig, WhirProof, WhirRoundProof};
use tiny_keccak::keccakf;

use super::{
    ChallengeField, DomainSeparatedShake256, ExtensionFieldChallenger, MERKLE_DIGEST_WORD_LENGTH,
    NodeCompressor, ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN, ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
    ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN,
    plain_whir::{
        AggregateLayout, PlainAggregateCommitment, PlainAggregatePcs, PlainAggregateProof,
    },
    retained_oracle::RetainedPlainWhirEncodedOracle,
    retained_oracle_codec::{
        RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH, RetainedPlainWhirCanonicalReader,
        RetainedPlainWhirCanonicalWriter, RetainedPlainWhirOracleCodecError,
        RetainedPlainWhirOracleScratchCodec, RetainedPlainWhirOracleStorageError,
    },
};
use crate::bgv::proof_suite::{
    ProofExternalMemory, ProofExternalMemoryExecutor, ProofExternalMemoryObject,
};

type MerkleDigest = [u64; MERKLE_DIGEST_WORD_LENGTH];
type PlainAggregateWhirConfig =
    WhirConfig<ChallengeField, ChallengeField, ExtensionFieldChallenger>;

const SHAKE256_STATE_WORD_LENGTH: usize = 25;
const SHAKE256_RATE_BYTE_LENGTH: usize = 136;
const SHAKE256_DELIMITER: u8 = 0x1f;
const SHAKE256_FINAL_BIT: u8 = 0x80;
const MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT: usize = 1 << 15;

#[cfg(test)]
pub(super) struct StreamingPlainAggregateProverData {
    layout: AggregateLayout,
}

pub(super) struct StreamingPlainAggregateInitialSumcheck {
    prover: Option<PrefixInitialSumcheckProver<ChallengeField, ChallengeField>>,
    proof: SumcheckData<ChallengeField, ChallengeField>,
}

pub(super) struct StreamingPlainAggregateInitialSumcheckOutput {
    pub(super) prover: SumcheckProver<ChallengeField, ChallengeField>,
    pub(super) folding_randomness: Point<ChallengeField>,
    pub(super) proof: SumcheckData<ChallengeField, ChallengeField>,
}

pub(super) enum StreamingPlainAggregateInitialSumcheckPoll {
    RoundAdvanced { completed_round_count: usize },
    Complete(StreamingPlainAggregateInitialSumcheckOutput),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamingPlainAggregateRetainedCommitmentStage {
    WriteOracle,
    ReadRoot,
    ObserveCommitment,
    AwaitOpeningPreparation,
    CompleteExternalMemoryStep,
    Complete,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingPlainAggregateRetainedCommitmentGeneration
{
    config: PlainAggregateWhirConfig,
    witness: Option<Witness<ChallengeField>>,
    retained_oracles: Vec<RetainedPlainWhirEncodedOracle>,
    writer: Option<StreamingPlainAggregateRetainedOracleWriter>,
    reader: Option<StreamingPlainAggregateRetainedOracleReader>,
    commitment: Option<PlainAggregateCommitment>,
    prepared_prover_data: Option<StreamingPlainAggregateRetainedProverData>,
    stage: StreamingPlainAggregateRetainedCommitmentStage,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingPlainAggregateRetainedProverData {
    config: PlainAggregateWhirConfig,
    retained_oracles: Vec<RetainedPlainWhirEncodedOracle>,
    proof: WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
    evaluations: Vec<OpeningBatch<ChallengeField>>,
    initial_sumcheck: StreamingPlainAggregateInitialSumcheck,
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingPlainAggregateRetainedCommitmentOutput
{
    pub(in crate::bgv::proof_suite::row_code_whir) commitment: PlainAggregateCommitment,
    pub(in crate::bgv::proof_suite::row_code_whir) prover_data:
        StreamingPlainAggregateRetainedProverData,
}

pub(in crate::bgv::proof_suite::row_code_whir) enum StreamingPlainAggregateRetainedCommitmentPoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    CommitmentObserved(PlainAggregateCommitment),
    Complete(StreamingPlainAggregateRetainedCommitmentOutput),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamingPlainAggregateRetainedProofStage {
    InitialSumcheck,
    BeginRound,
    WriteCurrentOracle,
    ReadCurrentRoot,
    SampleRoundOutOfDomain,
    SampleRoundQueries,
    ReadPreviousOracle,
    FoldRound,
    CompleteRoundExternalMemoryStep,
    SampleFinalQueries,
    ReadFinalOracle,
    CompleteFinalExternalMemoryStep,
    FoldFinalSumcheck,
    Finish,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::proof_suite::row_code_whir) enum StreamingPlainAggregateRetainedProofBoundary {
    InitialSumcheckRound {
        completed_round_count: usize,
    },
    RoundOracleArithmetic {
        round_index: usize,
    },
    RoundOracleStorage {
        round_index: usize,
    },
    RoundOutOfDomainSample {
        round_index: usize,
        completed_sample_count: usize,
    },
    RoundQueriesPrepared {
        round_index: usize,
    },
    RoundSumcheckRound {
        round_index: usize,
        completed_round_count: usize,
    },
    RoundStorageReleased {
        completed_round_count: usize,
    },
    FinalPolynomialObserved,
    FinalQueriesPrepared,
    FinalOracleStorage,
    FinalStorageReleased,
    FinalSumcheckRound {
        completed_round_count: usize,
    },
    ProofReady,
}

pub(in crate::bgv::proof_suite::row_code_whir) enum StreamingPlainAggregateRetainedProofPoll {
    ArithmeticStepCompleted(StreamingPlainAggregateRetainedProofBoundary),
    StorageTransactionCompleted(StreamingPlainAggregateRetainedProofBoundary),
    Complete(PlainAggregateProof),
}

pub(in crate::bgv::proof_suite::row_code_whir) struct StreamingPlainAggregateRetainedProofGeneration
{
    config: PlainAggregateWhirConfig,
    retained_oracles: Vec<RetainedPlainWhirEncodedOracle>,
    oracle_roots: Vec<PlainAggregateCommitment>,
    proof: Option<WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>>,
    evaluations: Option<Vec<OpeningBatch<ChallengeField>>>,
    initial_sumcheck: Option<StreamingPlainAggregateInitialSumcheck>,
    sumcheck_prover: Option<SumcheckProver<ChallengeField, ChallengeField>>,
    folding_randomness: Point<ChallengeField>,
    next_folding_randomness: Point<ChallengeField>,
    current_round_index: usize,
    current_oracle_writer: Option<StreamingPlainAggregateRetainedOracleWriter>,
    current_oracle_reader: Option<StreamingPlainAggregateRetainedOracleReader>,
    round_out_of_domain_statement: Option<EqStatement<ChallengeField>>,
    next_round_out_of_domain_sample_index: usize,
    round_query_indices: Vec<usize>,
    pending_constraint: Option<Constraint<ChallengeField, ChallengeField>>,
    pending_sumcheck_data: SumcheckData<ChallengeField, ChallengeField>,
    pending_sumcheck_round_count: usize,
    completed_pending_sumcheck_round_count: usize,
    stage: StreamingPlainAggregateRetainedProofStage,
}

impl StreamingPlainAggregateInitialSumcheck {
    pub(super) fn new(layout: AggregateLayout, challenger: &mut ExtensionFieldChallenger) -> Self {
        Self {
            prover: Some(layout.begin_initial_sumcheck(challenger)),
            proof: SumcheckData::default(),
        }
    }

    /// Advances no more than one transcript-bound initial sumcheck round.
    pub(super) fn poll(
        &mut self,
        proof_of_work_bits: usize,
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<StreamingPlainAggregateInitialSumcheckPoll, String> {
        let prover = self
            .prover
            .as_mut()
            .ok_or_else(|| "plain WHIR initial sumcheck was already completed".to_owned())?;
        if prover.advance_round(&mut self.proof, proof_of_work_bits, challenger) {
            return Ok(StreamingPlainAggregateInitialSumcheckPoll::RoundAdvanced {
                completed_round_count: prover.completed_round_count(),
            });
        }

        let prover = self
            .prover
            .take()
            .ok_or_else(|| "plain WHIR initial sumcheck state is missing".to_owned())?;
        let (prover, folding_randomness) = prover.try_finish().map_err(|state| {
            self.prover = Some(state);
            "plain WHIR initial sumcheck still has unprocessed rounds".to_owned()
        })?;
        Ok(StreamingPlainAggregateInitialSumcheckPoll::Complete(
            StreamingPlainAggregateInitialSumcheckOutput {
                prover,
                folding_randomness,
                proof: core::mem::take(&mut self.proof),
            },
        ))
    }
}

#[cfg(test)]
pub(super) struct StreamingPlainAggregateOpeningRequest<'request> {
    pcs: &'request PlainAggregatePcs,
    initial_commitment: &'request PlainAggregateCommitment,
    points: &'request [Point<ChallengeField>],
    requested_columns_by_point: &'request [Vec<usize>],
}

#[cfg(test)]
impl<'request> StreamingPlainAggregateOpeningRequest<'request> {
    pub(super) fn new(
        pcs: &'request PlainAggregatePcs,
        initial_commitment: &'request PlainAggregateCommitment,
        points: &'request [Point<ChallengeField>],
        requested_columns_by_point: &'request [Vec<usize>],
    ) -> Self {
        Self {
            pcs,
            initial_commitment,
            points,
            requested_columns_by_point,
        }
    }
}

#[cfg(test)]
struct EncodedMatrix {
    values: Vec<ChallengeField>,
    width: usize,
    height: usize,
}

#[cfg(test)]
struct MatrixOpenings {
    root: PlainAggregateCommitment,
    rows: Vec<Vec<ChallengeField>>,
    paths: Vec<Vec<MerkleDigest>>,
}

#[derive(Clone, Copy)]
enum QueryValueKind {
    Base,
    Extension,
}

#[cfg(test)]
struct RetainedRoundSource {
    polynomial: Poly<ChallengeField>,
    root: PlainAggregateCommitment,
    query_value_kind: QueryValueKind,
    folding_factor: usize,
    inverse_rate: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StreamingPlainAggregateRetainedOracleError<StorageError> {
    Geometry(String),
    Storage(RetainedPlainWhirOracleStorageError<StorageError>),
}

impl<StorageError> From<RetainedPlainWhirOracleStorageError<StorageError>>
    for StreamingPlainAggregateRetainedOracleError<StorageError>
{
    fn from(error: RetainedPlainWhirOracleStorageError<StorageError>) -> Self {
        Self::Storage(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamingPlainAggregateRetainedOracleWriteStage {
    Begin,
    PrepareStripeColumn,
    WriteStripeColumn,
    Seal,
    Finish,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamingPlainAggregateRetainedOracleWritePoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    Complete { object: ProofExternalMemoryObject },
}

/// Incremental encoder for one retained WHIR oracle.
///
/// A preparation poll reads exactly one logical source column through
/// `PolyView::copy_logical_range_into`, computes its complete DFT, retains only
/// the requested stripe, and releases the complete encoded column. Storage
/// polls append at most one canonical record through the retained-oracle codec.
pub(super) struct StreamingPlainAggregateRetainedOracleWriter {
    descriptor: RetainedPlainWhirEncodedOracle,
    codec: RetainedPlainWhirOracleScratchCodec,
    writer: Option<RetainedPlainWhirCanonicalWriter>,
    source_variable_count: usize,
    source_height: usize,
    encoded_height: usize,
    stripe_column_values: Vec<ChallengeField>,
    stage: StreamingPlainAggregateRetainedOracleWriteStage,
}

impl StreamingPlainAggregateRetainedOracleWriter {
    pub(super) fn new(
        descriptor: RetainedPlainWhirEncodedOracle,
        source_variable_count: usize,
        folding_factor: usize,
        inverse_rate: usize,
    ) -> Result<Self, RetainedPlainWhirOracleCodecError> {
        let (width, source_height, encoded_height) =
            checked_prefix_encoding_geometry(source_variable_count, folding_factor, inverse_rate)
                .map_err(|_| RetainedPlainWhirOracleCodecError::InvalidEncodedHeight)?;
        if width != RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH
            || encoded_height != descriptor.encoded_height
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidEncodedHeight);
        }
        let codec = RetainedPlainWhirOracleScratchCodec::try_new(encoded_height)?;
        if codec.exact_byte_length() != descriptor.exact_byte_length {
            return Err(RetainedPlainWhirOracleCodecError::InvalidEncodedHeight);
        }
        Ok(Self {
            descriptor,
            codec,
            writer: Some(RetainedPlainWhirCanonicalWriter::new(
                codec,
                descriptor.object,
            )),
            source_variable_count,
            source_height,
            encoded_height,
            stripe_column_values: Vec::new(),
            stage: StreamingPlainAggregateRetainedOracleWriteStage::Begin,
        })
    }

    pub(super) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        source: PolyView<'_, ChallengeField, ChallengeField>,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        StreamingPlainAggregateRetainedOracleWritePoll,
        StreamingPlainAggregateRetainedOracleError<Storage::Error>,
    > {
        if source.num_variables() != self.source_variable_count {
            return Err(StreamingPlainAggregateRetainedOracleError::Geometry(
                "retained plain WHIR source variable count changed".to_owned(),
            ));
        }

        match self.stage {
            StreamingPlainAggregateRetainedOracleWriteStage::Begin => {
                self.writer
                    .as_mut()
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR writer is missing".to_owned(),
                        )
                    })?
                    .begin(executor, storage)?;
                self.stage = StreamingPlainAggregateRetainedOracleWriteStage::PrepareStripeColumn;
                Ok(StreamingPlainAggregateRetainedOracleWritePoll::StorageTransactionCompleted)
            }
            StreamingPlainAggregateRetainedOracleWriteStage::PrepareStripeColumn => {
                let (stripe_index, column_index) = self
                    .writer
                    .as_ref()
                    .and_then(RetainedPlainWhirCanonicalWriter::next_stripe_column)
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR writer has no next stripe column".to_owned(),
                        )
                    })?;
                let source_start =
                    column_index
                        .checked_mul(self.source_height)
                        .ok_or_else(|| {
                            StreamingPlainAggregateRetainedOracleError::Geometry(
                                "retained plain WHIR source range overflowed".to_owned(),
                            )
                        })?;
                let mut encoded_column = ChallengeField::zero_vec(self.encoded_height);
                if let Err(error) = source.copy_logical_range_into(
                    source_start,
                    self.source_height,
                    &mut encoded_column[..self.source_height],
                ) {
                    encoded_column.fill(ChallengeField::ZERO);
                    return Err(StreamingPlainAggregateRetainedOracleError::Geometry(
                        format!("copy retained plain WHIR source column: {error:?}"),
                    ));
                }
                let mut encoded_column = Radix2Dit::<ChallengeField>::default().dft(encoded_column);
                let stripe_start = stripe_index
                    .checked_mul(self.codec.stripe_row_count())
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR stripe start overflowed".to_owned(),
                        )
                    })?;
                let stripe_row_count =
                    self.codec
                        .stripe_row_count_at(stripe_index)
                        .map_err(|error| {
                            StreamingPlainAggregateRetainedOracleError::Storage(
                                RetainedPlainWhirOracleStorageError::Codec(error),
                            )
                        })?;
                let stripe_end = stripe_start.checked_add(stripe_row_count).ok_or_else(|| {
                    StreamingPlainAggregateRetainedOracleError::Geometry(
                        "retained plain WHIR stripe end overflowed".to_owned(),
                    )
                })?;
                self.stripe_column_values
                    .extend_from_slice(&encoded_column[stripe_start..stripe_end]);
                encoded_column.fill(ChallengeField::ZERO);
                self.stage = StreamingPlainAggregateRetainedOracleWriteStage::WriteStripeColumn;
                Ok(StreamingPlainAggregateRetainedOracleWritePoll::ArithmeticStepCompleted)
            }
            StreamingPlainAggregateRetainedOracleWriteStage::WriteStripeColumn => {
                let writer = self.writer.as_mut().ok_or_else(|| {
                    StreamingPlainAggregateRetainedOracleError::Geometry(
                        "retained plain WHIR writer is missing".to_owned(),
                    )
                })?;
                let (stripe_index, column_index) =
                    writer.next_stripe_column().ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR stripe-column cursor ended early".to_owned(),
                        )
                    })?;
                let progress = writer.advance_stripe_column(
                    executor,
                    storage,
                    stripe_index,
                    column_index,
                    &self.stripe_column_values,
                )?;
                if progress.stripe_column_complete {
                    self.stripe_column_values.fill(ChallengeField::ZERO);
                    self.stripe_column_values.clear();
                    self.stage = if progress.object_complete {
                        StreamingPlainAggregateRetainedOracleWriteStage::Seal
                    } else {
                        StreamingPlainAggregateRetainedOracleWriteStage::PrepareStripeColumn
                    };
                }
                if progress.stored_record_byte_length == 0 {
                    Ok(StreamingPlainAggregateRetainedOracleWritePoll::ArithmeticStepCompleted)
                } else {
                    Ok(StreamingPlainAggregateRetainedOracleWritePoll::StorageTransactionCompleted)
                }
            }
            StreamingPlainAggregateRetainedOracleWriteStage::Seal => {
                self.writer
                    .as_mut()
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR writer is missing".to_owned(),
                        )
                    })?
                    .seal(executor, storage)?;
                self.stage = StreamingPlainAggregateRetainedOracleWriteStage::Finish;
                Ok(StreamingPlainAggregateRetainedOracleWritePoll::StorageTransactionCompleted)
            }
            StreamingPlainAggregateRetainedOracleWriteStage::Finish => {
                let object = self
                    .writer
                    .take()
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR writer is missing".to_owned(),
                        )
                    })?
                    .finish()
                    .map_err(|error| {
                        StreamingPlainAggregateRetainedOracleError::Storage(
                            RetainedPlainWhirOracleStorageError::Codec(error),
                        )
                    })?;
                if object != self.descriptor.object {
                    return Err(StreamingPlainAggregateRetainedOracleError::Geometry(
                        "retained plain WHIR writer returned the wrong object".to_owned(),
                    ));
                }
                self.stage = StreamingPlainAggregateRetainedOracleWriteStage::Complete;
                Ok(StreamingPlainAggregateRetainedOracleWritePoll::Complete { object })
            }
            StreamingPlainAggregateRetainedOracleWriteStage::Complete => {
                Err(StreamingPlainAggregateRetainedOracleError::Geometry(
                    "retained plain WHIR writer was polled after completion".to_owned(),
                ))
            }
        }
    }
}

impl Drop for StreamingPlainAggregateRetainedOracleWriter {
    fn drop(&mut self) {
        self.stripe_column_values.fill(ChallengeField::ZERO);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamingPlainAggregateRetainedOracleReadStage {
    ReadRecord,
    Finish,
    Complete,
}

pub(super) struct StreamingPlainAggregateRetainedOracleReadOutput {
    pub(super) root: PlainAggregateCommitment,
    pub(super) rows: Vec<Vec<ChallengeField>>,
    pub(super) paths: Vec<Vec<MerkleDigest>>,
}

pub(super) enum StreamingPlainAggregateRetainedOracleReadPoll {
    StorageTransactionCompleted,
    Complete(StreamingPlainAggregateRetainedOracleReadOutput),
}

/// Incremental authenticated scan of one retained WHIR encoded oracle.
///
/// Each poll reads at most one canonical storage record. The state reconstructs
/// one stripe column at a time, hashes rows through a logarithmic Merkle
/// frontier, and retains only explicitly requested rows and authentication
/// paths.
pub(super) struct StreamingPlainAggregateRetainedOracleReader {
    descriptor: RetainedPlainWhirEncodedOracle,
    codec: RetainedPlainWhirOracleScratchCodec,
    reader: Option<RetainedPlainWhirCanonicalReader>,
    merkle_builder: Option<StreamingMerkleBuilder>,
    leaf_hasher: Option<StreamingMatrixLeafHasher>,
    query_indices: Vec<usize>,
    opened_rows: Vec<Vec<ChallengeField>>,
    next_stripe_index: usize,
    next_column_index: usize,
    stripe_column_values: Vec<ChallengeField>,
    stage: StreamingPlainAggregateRetainedOracleReadStage,
}

impl StreamingPlainAggregateRetainedOracleReader {
    pub(super) fn new(
        descriptor: RetainedPlainWhirEncodedOracle,
        query_indices: &[usize],
    ) -> Result<Self, RetainedPlainWhirOracleCodecError> {
        let codec = RetainedPlainWhirOracleScratchCodec::try_new(descriptor.encoded_height)?;
        if codec.exact_byte_length() != descriptor.exact_byte_length
            || query_indices
                .windows(2)
                .any(|window| window[0] >= window[1])
            || query_indices
                .last()
                .is_some_and(|last| *last >= descriptor.encoded_height)
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidEncodedHeight);
        }
        let capture_targets = if query_indices.is_empty() {
            None
        } else {
            Some(merkle_capture_targets(
                descriptor.encoded_height,
                query_indices,
            ))
        };
        let merkle_builder =
            StreamingMerkleBuilder::new(descriptor.encoded_height, capture_targets)
                .map_err(|_| RetainedPlainWhirOracleCodecError::InvalidEncodedHeight)?;
        Ok(Self {
            descriptor,
            codec,
            reader: Some(RetainedPlainWhirCanonicalReader::new(
                codec,
                descriptor.object,
            )),
            merkle_builder: Some(merkle_builder),
            leaf_hasher: None,
            query_indices: query_indices.to_vec(),
            opened_rows: vec![
                vec![ChallengeField::ZERO; RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH];
                query_indices.len()
            ],
            next_stripe_index: 0,
            next_column_index: 0,
            stripe_column_values: Vec::new(),
            stage: StreamingPlainAggregateRetainedOracleReadStage::ReadRecord,
        })
    }

    pub(super) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        StreamingPlainAggregateRetainedOracleReadPoll,
        StreamingPlainAggregateRetainedOracleError<Storage::Error>,
    > {
        match self.stage {
            StreamingPlainAggregateRetainedOracleReadStage::ReadRecord => {
                let mut decoded_values = Vec::new();
                let complete = self
                    .reader
                    .as_mut()
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR reader is missing".to_owned(),
                        )
                    })?
                    .advance(executor, storage, |value| decoded_values.push(value))?;
                self.accept_decoded_values(&decoded_values)
                    .map_err(StreamingPlainAggregateRetainedOracleError::Geometry)?;
                decoded_values.fill(ChallengeField::ZERO);
                if complete {
                    self.stage = StreamingPlainAggregateRetainedOracleReadStage::Finish;
                }
                Ok(StreamingPlainAggregateRetainedOracleReadPoll::StorageTransactionCompleted)
            }
            StreamingPlainAggregateRetainedOracleReadStage::Finish => {
                let object = self
                    .reader
                    .take()
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR reader is missing".to_owned(),
                        )
                    })?
                    .finish()
                    .map_err(|error| {
                        StreamingPlainAggregateRetainedOracleError::Storage(
                            RetainedPlainWhirOracleStorageError::Codec(error),
                        )
                    })?;
                if object != self.descriptor.object
                    || self.next_stripe_index != self.codec.stripe_count()
                    || self.next_column_index != 0
                    || !self.stripe_column_values.is_empty()
                    || self.leaf_hasher.is_some()
                {
                    return Err(StreamingPlainAggregateRetainedOracleError::Geometry(
                        "retained plain WHIR reader ended at the wrong shape".to_owned(),
                    ));
                }
                let (root, paths) = self
                    .merkle_builder
                    .take()
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "retained plain WHIR Merkle builder is missing".to_owned(),
                        )
                    })?
                    .finish()
                    .map_err(StreamingPlainAggregateRetainedOracleError::Geometry)?;
                self.stage = StreamingPlainAggregateRetainedOracleReadStage::Complete;
                Ok(StreamingPlainAggregateRetainedOracleReadPoll::Complete(
                    StreamingPlainAggregateRetainedOracleReadOutput {
                        root: MerkleCap::new(vec![root]),
                        rows: core::mem::take(&mut self.opened_rows),
                        paths: paths.unwrap_or_default(),
                    },
                ))
            }
            StreamingPlainAggregateRetainedOracleReadStage::Complete => {
                Err(StreamingPlainAggregateRetainedOracleError::Geometry(
                    "retained plain WHIR reader was polled after completion".to_owned(),
                ))
            }
        }
    }

    fn accept_decoded_values(&mut self, values: &[ChallengeField]) -> Result<(), String> {
        for value in values {
            if self.next_stripe_index >= self.codec.stripe_count() {
                return Err("retained plain WHIR reader produced trailing values".to_owned());
            }
            let stripe_row_count = self
                .codec
                .stripe_row_count_at(self.next_stripe_index)
                .map_err(|error| format!("derive retained plain WHIR stripe shape: {error:?}"))?;
            self.stripe_column_values.push(*value);
            if self.stripe_column_values.len() < stripe_row_count {
                continue;
            }
            if self.stripe_column_values.len() > stripe_row_count {
                return Err("retained plain WHIR reader overfilled one stripe column".to_owned());
            }

            if self.leaf_hasher.is_none() {
                self.leaf_hasher = Some(StreamingMatrixLeafHasher::new(stripe_row_count)?);
            }
            let stripe_start = self
                .next_stripe_index
                .checked_mul(self.codec.stripe_row_count())
                .ok_or_else(|| "retained plain WHIR stripe start overflowed".to_owned())?;
            for (query_ordinal, query_index) in self.query_indices.iter().copied().enumerate() {
                if let Some(stripe_row_index) = query_index.checked_sub(stripe_start) {
                    if stripe_row_index < stripe_row_count {
                        self.opened_rows[query_ordinal][self.next_column_index] =
                            self.stripe_column_values[stripe_row_index];
                    }
                }
            }
            self.leaf_hasher
                .as_mut()
                .ok_or_else(|| "retained plain WHIR leaf hasher is missing".to_owned())?
                .absorb_column(&self.stripe_column_values)?;
            self.stripe_column_values.fill(ChallengeField::ZERO);
            self.stripe_column_values.clear();
            self.next_column_index += 1;

            if self.next_column_index == RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH {
                let leaf_hasher = self
                    .leaf_hasher
                    .take()
                    .ok_or_else(|| "retained plain WHIR leaf hasher is missing".to_owned())?;
                let merkle_builder = self
                    .merkle_builder
                    .as_mut()
                    .ok_or_else(|| "retained plain WHIR Merkle builder is missing".to_owned())?;
                for digest in leaf_hasher.finish_digests() {
                    merkle_builder.push(digest)?;
                }
                self.next_column_index = 0;
                self.next_stripe_index += 1;
            }
        }
        Ok(())
    }
}

impl Drop for StreamingPlainAggregateRetainedOracleReader {
    fn drop(&mut self) {
        self.stripe_column_values.fill(ChallengeField::ZERO);
        for row in &mut self.opened_rows {
            row.fill(ChallengeField::ZERO);
        }
    }
}

impl StreamingPlainAggregateRetainedCommitmentGeneration {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        pcs: &PlainAggregatePcs,
        witness: Witness<ChallengeField>,
        retained_oracles: Vec<RetainedPlainWhirEncodedOracle>,
    ) -> Result<Self, String> {
        if witness.num_variables() != pcs.num_variables {
            return Err(format!(
                "plain WHIR witness has {} variables, expected {}",
                witness.num_variables(),
                pcs.num_variables
            ));
        }
        validate_retained_oracle_catalog(&pcs.config, &retained_oracles)?;
        let initial_oracle = retained_oracles
            .first()
            .copied()
            .ok_or_else(|| "plain WHIR retained-oracle catalog is empty".to_owned())?;
        let writer = StreamingPlainAggregateRetainedOracleWriter::new(
            initial_oracle,
            pcs.num_variables,
            pcs.round_folding_factor(0),
            checked_power_of_two(pcs.params.starting_log_inv_rate, "starting inverse rate")?,
        )
        .map_err(|error| format!("construct initial retained-oracle writer: {error:?}"))?;
        Ok(Self {
            config: pcs.config.clone(),
            witness: Some(witness),
            retained_oracles,
            writer: Some(writer),
            reader: None,
            commitment: None,
            prepared_prover_data: None,
            stage: StreamingPlainAggregateRetainedCommitmentStage::WriteOracle,
        })
    }

    /// Records every opening that depends on the authenticated source before
    /// the retained-oracle executor is allowed to release its first step.
    ///
    /// The commitment poll deliberately stops at `CommitmentObserved`. The
    /// enclosing generator derives its explicit points from that commitment,
    /// calls this method once, and only then resumes polling. Consuming the
    /// witness here preserves its allocations for the initial sumcheck without
    /// cloning the four-message aggregate.
    pub(in crate::bgv::proof_suite::row_code_whir) fn prepare_openings(
        &mut self,
        points: &[Point<ChallengeField>],
        requested_columns_by_point: &[Vec<usize>],
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<(), String> {
        if self.stage != StreamingPlainAggregateRetainedCommitmentStage::AwaitOpeningPreparation {
            return Err(
                "plain WHIR openings may be prepared only after the commitment is observed"
                    .to_owned(),
            );
        }
        if points.len() != requested_columns_by_point.len() {
            return Err("plain WHIR points and opening requests have different lengths".to_owned());
        }

        let table_shapes = self
            .witness
            .as_ref()
            .ok_or_else(|| "plain WHIR commitment witness is missing".to_owned())?
            .table_shapes();
        if table_shapes.len() != 1 {
            return Err("plain WHIR aggregate witness must contain exactly one table".to_owned());
        }
        let table_shape = table_shapes[0];
        for (point, requested_columns) in points.iter().zip(requested_columns_by_point) {
            if point.num_variables() != table_shape.num_variables()
                || requested_columns.is_empty()
                || requested_columns
                    .iter()
                    .any(|column_index| *column_index >= table_shape.width())
                || requested_columns
                    .windows(2)
                    .any(|adjacent| adjacent[0] >= adjacent[1])
            {
                return Err(
                    "plain WHIR opening request does not match the aggregate witness".to_owned(),
                );
            }
        }

        let witness = self
            .witness
            .take()
            .ok_or_else(|| "plain WHIR commitment witness is missing".to_owned())?;
        let mut layout = AggregateLayout::from_witness(witness);
        if self.config.round_folding_factor(0) != layout.folding() {
            return Err("plain WHIR layout has the wrong initial folding factor".to_owned());
        }
        if AggregateLayout::variable_order() != VariableOrder::Prefix {
            return Err("bounded plain WHIR prover requires prefix variable order".to_owned());
        }

        let mut proof = empty_plain_whir_proof_for_config(&self.config);
        proof.initial_ood_answers = (0..self.config.commitment_ood_samples)
            .map(|_| layout.add_virtual_eval(challenger))
            .collect();
        let evaluations = points
            .iter()
            .cloned()
            .zip(requested_columns_by_point)
            .map(|(point, requested_columns)| {
                let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
                layout.eval_at_point(0, &request, point, challenger)
            })
            .collect();
        let initial_sumcheck = StreamingPlainAggregateInitialSumcheck::new(layout, challenger);
        self.prepared_prover_data = Some(StreamingPlainAggregateRetainedProverData {
            config: self.config.clone(),
            retained_oracles: core::mem::take(&mut self.retained_oracles),
            proof,
            evaluations,
            initial_sumcheck,
        });
        self.stage = StreamingPlainAggregateRetainedCommitmentStage::CompleteExternalMemoryStep;
        Ok(())
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        StreamingPlainAggregateRetainedCommitmentPoll,
        StreamingPlainAggregateRetainedOracleError<Storage::Error>,
    > {
        match self.stage {
            StreamingPlainAggregateRetainedCommitmentStage::WriteOracle => {
                let source = self
                    .witness
                    .as_ref()
                    .ok_or_else(|| {
                        StreamingPlainAggregateRetainedOracleError::Geometry(
                            "plain WHIR commitment witness is missing".to_owned(),
                        )
                    })?
                    .poly();
                let writer = self.writer.as_mut().ok_or_else(|| {
                    StreamingPlainAggregateRetainedOracleError::Geometry(
                        "plain WHIR commitment writer is missing".to_owned(),
                    )
                })?;
                match writer.poll(PolyView::Scalar(source), executor, storage)? {
                    StreamingPlainAggregateRetainedOracleWritePoll::ArithmeticStepCompleted => {
                        Ok(
                            StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted,
                        )
                    }
                    StreamingPlainAggregateRetainedOracleWritePoll::StorageTransactionCompleted => {
                        Ok(
                            StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted,
                        )
                    }
                    StreamingPlainAggregateRetainedOracleWritePoll::Complete { object } => {
                        let initial_oracle = self.retained_oracles[0];
                        if object != initial_oracle.object {
                            return Err(
                                StreamingPlainAggregateRetainedOracleError::Geometry(
                                    "plain WHIR initial retained writer returned the wrong object"
                                        .to_owned(),
                                ),
                            );
                        }
                        self.writer = None;
                        self.reader = Some(
                            StreamingPlainAggregateRetainedOracleReader::new(initial_oracle, &[])
                                .map_err(|error| {
                                    StreamingPlainAggregateRetainedOracleError::Storage(
                                        RetainedPlainWhirOracleStorageError::Codec(error),
                                    )
                                })?,
                        );
                        self.stage = StreamingPlainAggregateRetainedCommitmentStage::ReadRoot;
                        Ok(
                            StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted,
                        )
                    }
                }
            }
            StreamingPlainAggregateRetainedCommitmentStage::ReadRoot => {
                let reader = self.reader.as_mut().ok_or_else(|| {
                    StreamingPlainAggregateRetainedOracleError::Geometry(
                        "plain WHIR commitment reader is missing".to_owned(),
                    )
                })?;
                match reader.poll(executor, storage)? {
                    StreamingPlainAggregateRetainedOracleReadPoll::StorageTransactionCompleted => {
                        Ok(
                            StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted,
                        )
                    }
                    StreamingPlainAggregateRetainedOracleReadPoll::Complete(output) => {
                        if !output.rows.is_empty() || !output.paths.is_empty() {
                            return Err(
                                StreamingPlainAggregateRetainedOracleError::Geometry(
                                    "plain WHIR root pass retained unexpected openings".to_owned(),
                                ),
                            );
                        }
                        self.reader = None;
                        self.commitment = Some(output.root);
                        self.stage =
                            StreamingPlainAggregateRetainedCommitmentStage::ObserveCommitment;
                        Ok(
                            StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted,
                        )
                    }
                }
            }
            StreamingPlainAggregateRetainedCommitmentStage::ObserveCommitment => {
                let commitment = self.commitment.clone().ok_or_else(|| {
                    StreamingPlainAggregateRetainedOracleError::Geometry(
                        "plain WHIR commitment root is missing".to_owned(),
                    )
                })?;
                challenger.observe(commitment.clone());
                self.stage =
                    StreamingPlainAggregateRetainedCommitmentStage::AwaitOpeningPreparation;
                Ok(StreamingPlainAggregateRetainedCommitmentPoll::CommitmentObserved(commitment))
            }
            StreamingPlainAggregateRetainedCommitmentStage::AwaitOpeningPreparation => {
                Err(StreamingPlainAggregateRetainedOracleError::Geometry(
                    "plain WHIR commitment is waiting for source-dependent opening preparation"
                        .to_owned(),
                ))
            }
            StreamingPlainAggregateRetainedCommitmentStage::CompleteExternalMemoryStep => {
                executor.complete_step(storage).map_err(|error| {
                    StreamingPlainAggregateRetainedOracleError::Storage(
                        RetainedPlainWhirOracleStorageError::ExternalMemory(error),
                    )
                })?;
                self.stage = StreamingPlainAggregateRetainedCommitmentStage::Complete;
                Ok(StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted)
            }
            StreamingPlainAggregateRetainedCommitmentStage::Complete => {
                let commitment = self.commitment.take().ok_or_else(|| {
                    StreamingPlainAggregateRetainedOracleError::Geometry(
                        "plain WHIR completed commitment is missing".to_owned(),
                    )
                })?;
                let prover_data = self.prepared_prover_data.take().ok_or_else(|| {
                    StreamingPlainAggregateRetainedOracleError::Geometry(
                        "plain WHIR completed commitment prover data is missing".to_owned(),
                    )
                })?;
                Ok(StreamingPlainAggregateRetainedCommitmentPoll::Complete(
                    StreamingPlainAggregateRetainedCommitmentOutput {
                        commitment,
                        prover_data,
                    },
                ))
            }
        }
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn cancel<Storage: ProofExternalMemory>(
        self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<(), StreamingPlainAggregateRetainedOracleError<Storage::Error>> {
        executor.cancel(storage).map_err(|error| {
            StreamingPlainAggregateRetainedOracleError::Storage(
                RetainedPlainWhirOracleStorageError::ExternalMemory(error),
            )
        })
    }
}

impl StreamingPlainAggregateRetainedProofGeneration {
    pub(in crate::bgv::proof_suite::row_code_whir) fn new(
        initial_commitment: PlainAggregateCommitment,
        prover_data: StreamingPlainAggregateRetainedProverData,
    ) -> Result<Self, String> {
        validate_retained_oracle_catalog(&prover_data.config, &prover_data.retained_oracles)?;

        Ok(Self {
            config: prover_data.config,
            retained_oracles: prover_data.retained_oracles,
            oracle_roots: vec![initial_commitment],
            proof: Some(prover_data.proof),
            evaluations: Some(prover_data.evaluations),
            initial_sumcheck: Some(prover_data.initial_sumcheck),
            sumcheck_prover: None,
            folding_randomness: Point::default(),
            next_folding_randomness: Point::default(),
            current_round_index: 0,
            current_oracle_writer: None,
            current_oracle_reader: None,
            round_out_of_domain_statement: None,
            next_round_out_of_domain_sample_index: 0,
            round_query_indices: Vec::new(),
            pending_constraint: None,
            pending_sumcheck_data: SumcheckData::default(),
            pending_sumcheck_round_count: 0,
            completed_pending_sumcheck_round_count: 0,
            stage: StreamingPlainAggregateRetainedProofStage::InitialSumcheck,
        })
    }

    /// Advances one bounded arithmetic action or one external-memory action.
    ///
    /// Transcript mutations never share a poll with an external-memory action,
    /// so a yielded browser transaction can be replayed without repeating a
    /// challenge or sumcheck round. A complete proof is returned only from the
    /// terminal `Complete` result.
    pub(in crate::bgv::proof_suite::row_code_whir) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        challenger: &mut ExtensionFieldChallenger,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<
        StreamingPlainAggregateRetainedProofPoll,
        StreamingPlainAggregateRetainedOracleError<Storage::Error>,
    > {
        match self.stage {
            StreamingPlainAggregateRetainedProofStage::InitialSumcheck => {
                let initial_sumcheck = self.initial_sumcheck.as_mut().ok_or_else(|| {
                    Self::geometry_error("plain WHIR initial sumcheck state is missing")
                })?;
                match initial_sumcheck
                    .poll(self.config.starting_folding_pow_bits, challenger)
                    .map_err(StreamingPlainAggregateRetainedOracleError::Geometry)?
                {
                    StreamingPlainAggregateInitialSumcheckPoll::RoundAdvanced {
                        completed_round_count,
                    } => Ok(
                        StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                            StreamingPlainAggregateRetainedProofBoundary::InitialSumcheckRound {
                                completed_round_count,
                            },
                        ),
                    ),
                    StreamingPlainAggregateInitialSumcheckPoll::Complete(output) => {
                        self.initial_sumcheck = None;
                        self.proof_mut()?.initial_sumcheck = output.proof;
                        self.sumcheck_prover = Some(output.prover);
                        self.folding_randomness = output.folding_randomness;
                        self.stage = StreamingPlainAggregateRetainedProofStage::BeginRound;
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::InitialSumcheckRound {
                                    completed_round_count: self.config.round_folding_factor(0),
                                },
                            ),
                        )
                    }
                }
            }
            StreamingPlainAggregateRetainedProofStage::BeginRound => {
                let expected_variable_count = self.config.num_variables
                    - self.config.total_folded_through(self.current_round_index);
                if self.sumcheck_prover()?.num_variables() != expected_variable_count {
                    return Err(Self::geometry_error(format!(
                        "plain WHIR round {} has {} variables, expected {expected_variable_count}",
                        self.current_round_index,
                        self.sumcheck_prover()?.num_variables(),
                    )));
                }
                if self.current_round_index == self.config.n_rounds() {
                    let final_polynomial = self.sumcheck_prover()?.evals();
                    challenger.observe_algebra_slice(final_polynomial.as_slice());
                    self.proof_mut()?.final_poly = Some(final_polynomial);
                    let final_pow_bits = self.config.final_pow_bits;
                    if final_pow_bits > 0 {
                        self.proof_mut()?.final_pow_witness = challenger.grind(final_pow_bits);
                    }
                    self.stage = StreamingPlainAggregateRetainedProofStage::SampleFinalQueries;
                    return Ok(
                        StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                            StreamingPlainAggregateRetainedProofBoundary::FinalPolynomialObserved,
                        ),
                    );
                }

                let next_folding_factor = self
                    .config
                    .round_folding_factor(self.current_round_index + 1);
                let current_oracle = self.retained_oracles[self.current_round_index + 1];
                self.current_oracle_writer = Some(
                    StreamingPlainAggregateRetainedOracleWriter::new(
                        current_oracle,
                        expected_variable_count,
                        next_folding_factor,
                        self.config.inv_rate(self.current_round_index),
                    )
                    .map_err(|error| {
                        Self::geometry_error(format!(
                            "construct plain WHIR round {} retained writer: {error:?}",
                            self.current_round_index
                        ))
                    })?,
                );
                self.stage = StreamingPlainAggregateRetainedProofStage::WriteCurrentOracle;
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::RoundOracleArithmetic {
                            round_index: self.current_round_index,
                        },
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::WriteCurrentOracle => {
                let sumcheck_prover = self
                    .sumcheck_prover
                    .as_ref()
                    .ok_or_else(|| Self::geometry_error("plain WHIR sumcheck prover is missing"))?;
                let source = sumcheck_prover.evals_view();
                let writer = self.current_oracle_writer.as_mut().ok_or_else(|| {
                    Self::geometry_error("plain WHIR round retained writer is missing")
                })?;
                match writer.poll(source, executor, storage)? {
                    StreamingPlainAggregateRetainedOracleWritePoll::ArithmeticStepCompleted => Ok(
                        StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                            StreamingPlainAggregateRetainedProofBoundary::RoundOracleArithmetic {
                                round_index: self.current_round_index,
                            },
                        ),
                    ),
                    StreamingPlainAggregateRetainedOracleWritePoll::StorageTransactionCompleted => {
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::RoundOracleStorage {
                                    round_index: self.current_round_index,
                                },
                            ),
                        )
                    }
                    StreamingPlainAggregateRetainedOracleWritePoll::Complete { object } => {
                        let descriptor = self.retained_oracles[self.current_round_index + 1];
                        if object != descriptor.object {
                            return Err(Self::geometry_error(
                                "plain WHIR round retained writer returned the wrong object",
                            ));
                        }
                        self.current_oracle_writer = None;
                        self.current_oracle_reader = Some(
                            StreamingPlainAggregateRetainedOracleReader::new(descriptor, &[])
                                .map_err(|error| {
                                    StreamingPlainAggregateRetainedOracleError::Storage(
                                        RetainedPlainWhirOracleStorageError::Codec(error),
                                    )
                                })?,
                        );
                        self.stage = StreamingPlainAggregateRetainedProofStage::ReadCurrentRoot;
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::RoundOracleArithmetic {
                                    round_index: self.current_round_index,
                                },
                            ),
                        )
                    }
                }
            }
            StreamingPlainAggregateRetainedProofStage::ReadCurrentRoot => {
                let reader = self.current_oracle_reader.as_mut().ok_or_else(|| {
                    Self::geometry_error("plain WHIR round retained root reader is missing")
                })?;
                match reader.poll(executor, storage)? {
                    StreamingPlainAggregateRetainedOracleReadPoll::StorageTransactionCompleted => {
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::RoundOracleStorage {
                                    round_index: self.current_round_index,
                                },
                            ),
                        )
                    }
                    StreamingPlainAggregateRetainedOracleReadPoll::Complete(output) => {
                        let round_index = self.current_round_index;
                        if !output.rows.is_empty() || !output.paths.is_empty() {
                            return Err(Self::geometry_error(
                                "plain WHIR round root pass retained unexpected openings",
                            ));
                        }
                        self.current_oracle_reader = None;
                        challenger.observe(output.root.clone());
                        self.proof_mut()?.rounds[round_index].commitment =
                            Some(output.root.clone());
                        self.oracle_roots.push(output.root);
                        self.round_out_of_domain_statement = Some(EqStatement::initialize(
                            self.sumcheck_prover()?.num_variables(),
                        ));
                        self.next_round_out_of_domain_sample_index = 0;
                        self.stage =
                            StreamingPlainAggregateRetainedProofStage::SampleRoundOutOfDomain;
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::RoundOracleArithmetic {
                                    round_index: self.current_round_index,
                                },
                            ),
                        )
                    }
                }
            }
            StreamingPlainAggregateRetainedProofStage::SampleRoundOutOfDomain => {
                let round_index = self.current_round_index;
                let target_sample_count = self.config.round_parameters[round_index].ood_samples;
                if self.next_round_out_of_domain_sample_index < target_sample_count {
                    let variable_count = self.sumcheck_prover()?.num_variables();
                    let point = Point::expand_from_univariate(
                        challenger.sample_algebra_element(),
                        variable_count,
                    );
                    let evaluation = self.sumcheck_prover()?.eval(&point);
                    challenger.observe_algebra_element(evaluation);
                    self.proof_mut()?.rounds[round_index]
                        .ood_answers
                        .push(evaluation);
                    self.round_out_of_domain_statement
                        .as_mut()
                        .ok_or_else(|| {
                            Self::geometry_error(
                                "plain WHIR round out-of-domain statement is missing",
                            )
                        })?
                        .add_evaluated_constraint(point, evaluation);
                    self.next_round_out_of_domain_sample_index += 1;
                } else {
                    self.stage = StreamingPlainAggregateRetainedProofStage::SampleRoundQueries;
                }
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::RoundOutOfDomainSample {
                            round_index: self.current_round_index,
                            completed_sample_count: self.next_round_out_of_domain_sample_index,
                        },
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::SampleRoundQueries => {
                let round_index = self.current_round_index;
                let round_parameters = &self.config.round_parameters[round_index];
                let pow_bits = round_parameters.pow_bits;
                let domain_size = round_parameters.domain_size;
                let num_queries = round_parameters.num_queries;
                if pow_bits > 0 {
                    self.proof_mut()?.rounds[round_index].pow_witness = challenger.grind(pow_bits);
                }
                let _: ChallengeField = challenger.sample();
                self.round_query_indices = sample_distinct_query_indices(
                    domain_size,
                    self.config.round_folding_factor(round_index),
                    num_queries,
                    challenger,
                )
                .map_err(StreamingPlainAggregateRetainedOracleError::Geometry)?;
                self.current_oracle_reader = Some(
                    StreamingPlainAggregateRetainedOracleReader::new(
                        self.retained_oracles[round_index],
                        &self.round_query_indices,
                    )
                    .map_err(|error| {
                        StreamingPlainAggregateRetainedOracleError::Storage(
                            RetainedPlainWhirOracleStorageError::Codec(error),
                        )
                    })?,
                );
                self.stage = StreamingPlainAggregateRetainedProofStage::ReadPreviousOracle;
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::RoundQueriesPrepared {
                            round_index,
                        },
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::ReadPreviousOracle => {
                let reader = self.current_oracle_reader.as_mut().ok_or_else(|| {
                    Self::geometry_error("plain WHIR previous retained reader is missing")
                })?;
                match reader.poll(executor, storage)? {
                    StreamingPlainAggregateRetainedOracleReadPoll::StorageTransactionCompleted => {
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::RoundOracleStorage {
                                    round_index: self.current_round_index,
                                },
                            ),
                        )
                    }
                    StreamingPlainAggregateRetainedOracleReadPoll::Complete(output) => {
                        self.current_oracle_reader = None;
                        self.prepare_round_fold(output, challenger)?;
                        self.stage = StreamingPlainAggregateRetainedProofStage::FoldRound;
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::RoundQueriesPrepared {
                                    round_index: self.current_round_index,
                                },
                            ),
                        )
                    }
                }
            }
            StreamingPlainAggregateRetainedProofStage::FoldRound => {
                let round_index = self.current_round_index;
                let folding_pow_bits = self.config.round_parameters[round_index].folding_pow_bits;
                let constraint = self.pending_constraint.take();
                let one_round_randomness = self
                    .sumcheck_prover
                    .as_mut()
                    .ok_or_else(|| Self::geometry_error("plain WHIR sumcheck prover is missing"))?
                    .compute_sumcheck_polynomials(
                        &mut self.pending_sumcheck_data,
                        challenger,
                        1,
                        folding_pow_bits,
                        constraint,
                    );
                self.next_folding_randomness.extend(&one_round_randomness);
                self.completed_pending_sumcheck_round_count += 1;
                self.pending_sumcheck_round_count = self
                    .pending_sumcheck_round_count
                    .checked_sub(1)
                    .ok_or_else(|| Self::geometry_error("plain WHIR round sumcheck underflowed"))?;
                if self.pending_sumcheck_round_count == 0 {
                    let completed_sumcheck = core::mem::take(&mut self.pending_sumcheck_data);
                    self.proof_mut()?.rounds[round_index].sumcheck = completed_sumcheck;
                    self.folding_randomness = core::mem::take(&mut self.next_folding_randomness);
                    self.stage =
                        StreamingPlainAggregateRetainedProofStage::CompleteRoundExternalMemoryStep;
                }
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::RoundSumcheckRound {
                            round_index,
                            completed_round_count: self.completed_pending_sumcheck_round_count,
                        },
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::CompleteRoundExternalMemoryStep => {
                executor.complete_step(storage).map_err(|error| {
                    StreamingPlainAggregateRetainedOracleError::Storage(
                        RetainedPlainWhirOracleStorageError::ExternalMemory(error),
                    )
                })?;
                self.current_round_index += 1;
                self.stage = StreamingPlainAggregateRetainedProofStage::BeginRound;
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::RoundStorageReleased {
                            completed_round_count: self.current_round_index,
                        },
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::SampleFinalQueries => {
                let final_round = self.config.final_round_config();
                self.round_query_indices = sample_distinct_query_indices(
                    final_round.domain_size,
                    self.config.round_folding_factor(self.config.n_rounds()),
                    self.config.final_queries,
                    challenger,
                )
                .map_err(StreamingPlainAggregateRetainedOracleError::Geometry)?;
                self.current_oracle_reader = Some(
                    StreamingPlainAggregateRetainedOracleReader::new(
                        self.retained_oracles[self.config.n_rounds()],
                        &self.round_query_indices,
                    )
                    .map_err(|error| {
                        StreamingPlainAggregateRetainedOracleError::Storage(
                            RetainedPlainWhirOracleStorageError::Codec(error),
                        )
                    })?,
                );
                self.stage = StreamingPlainAggregateRetainedProofStage::ReadFinalOracle;
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::FinalQueriesPrepared,
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::ReadFinalOracle => {
                let reader = self.current_oracle_reader.as_mut().ok_or_else(|| {
                    Self::geometry_error("plain WHIR final retained reader is missing")
                })?;
                match reader.poll(executor, storage)? {
                    StreamingPlainAggregateRetainedOracleReadPoll::StorageTransactionCompleted => {
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::FinalOracleStorage,
                            ),
                        )
                    }
                    StreamingPlainAggregateRetainedOracleReadPoll::Complete(output) => {
                        self.current_oracle_reader = None;
                        self.prepare_final_queries(output)?;
                        self.stage = StreamingPlainAggregateRetainedProofStage::CompleteFinalExternalMemoryStep;
                        Ok(
                            StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                                StreamingPlainAggregateRetainedProofBoundary::FinalQueriesPrepared,
                            ),
                        )
                    }
                }
            }
            StreamingPlainAggregateRetainedProofStage::CompleteFinalExternalMemoryStep => {
                executor.complete_step(storage).map_err(|error| {
                    StreamingPlainAggregateRetainedOracleError::Storage(
                        RetainedPlainWhirOracleStorageError::ExternalMemory(error),
                    )
                })?;
                self.pending_sumcheck_data = SumcheckData::default();
                self.pending_sumcheck_round_count = self.config.final_sumcheck_rounds;
                self.completed_pending_sumcheck_round_count = 0;
                self.stage = if self.pending_sumcheck_round_count == 0 {
                    StreamingPlainAggregateRetainedProofStage::Finish
                } else {
                    StreamingPlainAggregateRetainedProofStage::FoldFinalSumcheck
                };
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::FinalStorageReleased,
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::FoldFinalSumcheck => {
                self.sumcheck_prover
                    .as_mut()
                    .ok_or_else(|| Self::geometry_error("plain WHIR sumcheck prover is missing"))?
                    .compute_sumcheck_polynomials(
                        &mut self.pending_sumcheck_data,
                        challenger,
                        1,
                        self.config.final_folding_pow_bits,
                        None,
                    );
                self.completed_pending_sumcheck_round_count += 1;
                self.pending_sumcheck_round_count = self
                    .pending_sumcheck_round_count
                    .checked_sub(1)
                    .ok_or_else(|| Self::geometry_error("plain WHIR final sumcheck underflowed"))?;
                if self.pending_sumcheck_round_count == 0 {
                    let completed_sumcheck = core::mem::take(&mut self.pending_sumcheck_data);
                    self.proof_mut()?.final_sumcheck = Some(completed_sumcheck);
                    self.stage = StreamingPlainAggregateRetainedProofStage::Finish;
                }
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::FinalSumcheckRound {
                            completed_round_count: self.completed_pending_sumcheck_round_count,
                        },
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::Finish => {
                challenger
                    .ensure_sampling_succeeded()
                    .map_err(StreamingPlainAggregateRetainedOracleError::Geometry)?;
                self.stage = StreamingPlainAggregateRetainedProofStage::Complete;
                Ok(
                    StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(
                        StreamingPlainAggregateRetainedProofBoundary::ProofReady,
                    ),
                )
            }
            StreamingPlainAggregateRetainedProofStage::Complete => Ok(
                StreamingPlainAggregateRetainedProofPoll::Complete(PcsProof {
                    whir: self.proof.take().ok_or_else(|| {
                        Self::geometry_error("plain WHIR completed proof is missing")
                    })?,
                    evals: self.evaluations.take().ok_or_else(|| {
                        Self::geometry_error("plain WHIR completed evaluations are missing")
                    })?,
                }),
            ),
        }
    }

    pub(in crate::bgv::proof_suite::row_code_whir) fn cancel<Storage: ProofExternalMemory>(
        self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<(), StreamingPlainAggregateRetainedOracleError<Storage::Error>> {
        executor.cancel(storage).map_err(|error| {
            StreamingPlainAggregateRetainedOracleError::Storage(
                RetainedPlainWhirOracleStorageError::ExternalMemory(error),
            )
        })
    }

    fn prepare_round_fold<StorageError>(
        &mut self,
        openings: StreamingPlainAggregateRetainedOracleReadOutput,
        challenger: &mut ExtensionFieldChallenger,
    ) -> Result<(), StreamingPlainAggregateRetainedOracleError<StorageError>> {
        let expected_root = self
            .oracle_roots
            .get(self.current_round_index)
            .cloned()
            .ok_or_else(|| Self::geometry_error("plain WHIR previous oracle root is missing"))?;
        if openings.root != expected_root {
            return Err(Self::geometry_error(
                "plain WHIR retained opening pass produced the wrong root",
            ));
        }
        if openings.rows.len() != self.round_query_indices.len()
            || openings.paths.len() != self.round_query_indices.len()
        {
            return Err(Self::geometry_error(
                "plain WHIR retained opening pass returned the wrong query count",
            ));
        }

        let query_value_kind = if self.current_round_index == 0 {
            QueryValueKind::Base
        } else {
            QueryValueKind::Extension
        };
        let round_index = self.current_round_index;
        let folded_domain_generator = self.config.round_parameters[round_index].folded_domain_gen;
        let mut selection_statement =
            SelectStatement::initialize(self.sumcheck_prover()?.num_variables());
        let mut queries = Vec::with_capacity(self.round_query_indices.len());
        for ((query_index, values), path) in self
            .round_query_indices
            .iter()
            .copied()
            .zip(openings.rows)
            .zip(openings.paths)
        {
            let query_polynomial = Poly::new(values);
            let evaluation = match query_value_kind {
                QueryValueKind::Base => query_polynomial.eval_base(&self.folding_randomness),
                QueryValueKind::Extension => {
                    query_polynomial.eval_ext::<ChallengeField>(&self.folding_randomness)
                }
            };
            selection_statement.add_constraint(
                folded_domain_generator.exp_u64(query_index as u64),
                evaluation,
            );
            let values = query_polynomial.into_evals();
            queries.push(match query_value_kind {
                QueryValueKind::Base => QueryOpening::Base {
                    values,
                    proof: path,
                },
                QueryValueKind::Extension => QueryOpening::Extension {
                    values,
                    proof: path,
                },
            });
        }
        self.proof_mut()?.rounds[round_index].queries = queries;
        let out_of_domain_statement = self
            .round_out_of_domain_statement
            .take()
            .ok_or_else(|| Self::geometry_error("plain WHIR round statement is missing"))?;
        self.pending_constraint = Some(Constraint::new(
            challenger.sample_algebra_element(),
            self.sumcheck_prover()?.num_variables(),
            vec![
                Statements::Eq(out_of_domain_statement),
                Statements::Select(selection_statement),
            ],
        ));
        self.pending_sumcheck_data = SumcheckData::default();
        self.pending_sumcheck_round_count = self
            .config
            .round_folding_factor(self.current_round_index + 1);
        self.completed_pending_sumcheck_round_count = 0;
        self.next_folding_randomness = Point::default();
        if self.pending_sumcheck_round_count == 0 {
            return Err(Self::geometry_error(
                "plain WHIR round has an empty folding schedule",
            ));
        }
        Ok(())
    }

    fn prepare_final_queries<StorageError>(
        &mut self,
        openings: StreamingPlainAggregateRetainedOracleReadOutput,
    ) -> Result<(), StreamingPlainAggregateRetainedOracleError<StorageError>> {
        let expected_root = self
            .oracle_roots
            .get(self.config.n_rounds())
            .cloned()
            .ok_or_else(|| Self::geometry_error("plain WHIR final oracle root is missing"))?;
        if openings.root != expected_root
            || openings.rows.len() != self.round_query_indices.len()
            || openings.paths.len() != self.round_query_indices.len()
        {
            return Err(Self::geometry_error(
                "plain WHIR final retained opening pass has the wrong shape or root",
            ));
        }
        let query_value_kind = if self.config.n_rounds() == 0 {
            QueryValueKind::Base
        } else {
            QueryValueKind::Extension
        };
        self.proof_mut()?.final_queries = openings
            .rows
            .into_iter()
            .zip(openings.paths)
            .map(|(values, path)| match query_value_kind {
                QueryValueKind::Base => QueryOpening::Base {
                    values,
                    proof: path,
                },
                QueryValueKind::Extension => QueryOpening::Extension {
                    values,
                    proof: path,
                },
            })
            .collect();
        Ok(())
    }

    fn proof_mut<StorageError>(
        &mut self,
    ) -> Result<
        &mut WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
        StreamingPlainAggregateRetainedOracleError<StorageError>,
    > {
        self.proof
            .as_mut()
            .ok_or_else(|| Self::geometry_error("plain WHIR proof state is missing"))
    }

    fn sumcheck_prover<StorageError>(
        &self,
    ) -> Result<
        &SumcheckProver<ChallengeField, ChallengeField>,
        StreamingPlainAggregateRetainedOracleError<StorageError>,
    > {
        self.sumcheck_prover
            .as_ref()
            .ok_or_else(|| Self::geometry_error("plain WHIR sumcheck prover is missing"))
    }

    fn geometry_error<StorageError>(
        message: impl Into<String>,
    ) -> StreamingPlainAggregateRetainedOracleError<StorageError> {
        StreamingPlainAggregateRetainedOracleError::Geometry(message.into())
    }
}

#[cfg(test)]
pub(super) fn commit_streaming_plain_aggregate(
    pcs: &PlainAggregatePcs,
    witness: Witness<ChallengeField>,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<(PlainAggregateCommitment, StreamingPlainAggregateProverData), String> {
    if witness.num_variables() != pcs.num_variables {
        return Err(format!(
            "plain WHIR witness has {} variables, expected {}",
            witness.num_variables(),
            pcs.num_variables
        ));
    }
    let commitment = stream_prefix_polynomial(
        PolyView::Scalar(witness.poly()),
        pcs.round_folding_factor(0),
        1_usize
            .checked_shl(
                u32::try_from(pcs.params.starting_log_inv_rate)
                    .map_err(|_| "starting log-inverse rate exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "starting inverse rate overflowed".to_owned())?,
        None,
    )?
    .root;
    challenger.observe(commitment.clone());
    Ok((
        commitment,
        streaming_plain_aggregate_prover_data(pcs, witness)?,
    ))
}

#[cfg(test)]
pub(super) fn streaming_plain_aggregate_prover_data(
    pcs: &PlainAggregatePcs,
    witness: Witness<ChallengeField>,
) -> Result<StreamingPlainAggregateProverData, String> {
    if witness.num_variables() != pcs.num_variables {
        return Err(format!(
            "plain WHIR witness has {} variables, expected {}",
            witness.num_variables(),
            pcs.num_variables
        ));
    }
    Ok(StreamingPlainAggregateProverData {
        layout: AggregateLayout::from_witness(witness),
    })
}

#[cfg(test)]
pub(super) fn open_streaming_plain_aggregate_batches_at_points<RecomputeInitialPolynomial>(
    request: StreamingPlainAggregateOpeningRequest<'_>,
    mut prover_data: StreamingPlainAggregateProverData,
    challenger: &mut ExtensionFieldChallenger,
    mut recompute_initial_polynomial: RecomputeInitialPolynomial,
) -> Result<PlainAggregateProof, String>
where
    RecomputeInitialPolynomial: FnMut() -> Result<Poly<ChallengeField>, String>,
{
    if request.points.len() != request.requested_columns_by_point.len() {
        return Err("plain WHIR points and opening requests have different lengths".to_owned());
    }
    let mut whir = empty_plain_whir_proof(request.pcs);
    whir.initial_ood_answers = (0..request.pcs.commitment_ood_samples)
        .map(|_| prover_data.layout.add_virtual_eval(challenger))
        .collect();
    let evaluations = request
        .points
        .iter()
        .cloned()
        .zip(request.requested_columns_by_point)
        .map(|(point, requested_columns)| {
            let request = OpeningBatch::new(requested_columns.clone(), Vec::new());
            prover_data
                .layout
                .eval_at_point(0, &request, point, challenger)
        })
        .collect();
    let mut initial_polynomial_recomputation = InitialPolynomialRecomputation {
        expected_commitment: request.initial_commitment,
        recompute: &mut recompute_initial_polynomial,
    };
    prove_streaming_whir(
        request.pcs,
        &mut whir,
        challenger,
        prover_data.layout,
        &mut initial_polynomial_recomputation,
    )?;
    challenger.ensure_sampling_succeeded()?;
    Ok(PcsProof {
        whir,
        evals: evaluations,
    })
}

#[cfg(test)]
struct InitialPolynomialRecomputation<'source, RecomputeInitialPolynomial> {
    expected_commitment: &'source PlainAggregateCommitment,
    recompute: &'source mut RecomputeInitialPolynomial,
}

#[cfg(test)]
fn prove_streaming_whir<RecomputeInitialPolynomial>(
    pcs: &PlainAggregatePcs,
    proof: &mut WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
    challenger: &mut ExtensionFieldChallenger,
    layout: AggregateLayout,
    initial_polynomial_recomputation: &mut InitialPolynomialRecomputation<
        '_,
        RecomputeInitialPolynomial,
    >,
) -> Result<(), String>
where
    RecomputeInitialPolynomial: FnMut() -> Result<Poly<ChallengeField>, String>,
{
    if pcs.round_folding_factor(0) != layout.folding() {
        return Err("plain WHIR layout has the wrong initial folding factor".to_owned());
    }
    let variable_order = AggregateLayout::variable_order();
    if variable_order != VariableOrder::Prefix {
        return Err("bounded plain WHIR prover requires prefix variable order".to_owned());
    }
    let mut initial_sumcheck = StreamingPlainAggregateInitialSumcheck::new(layout, challenger);
    let (mut sumcheck_prover, mut folding_randomness) = loop {
        match initial_sumcheck.poll(pcs.starting_folding_pow_bits, challenger)? {
            StreamingPlainAggregateInitialSumcheckPoll::RoundAdvanced {
                completed_round_count,
            } => {
                debug_assert!(completed_round_count <= pcs.round_folding_factor(0));
            }
            StreamingPlainAggregateInitialSumcheckPoll::Complete(output) => {
                proof.initial_sumcheck = output.proof;
                break (output.prover, output.folding_randomness);
            }
        }
    };
    let mut retained_round_source: Option<RetainedRoundSource> = None;

    for round_index in 0..=pcs.n_rounds() {
        let expected_variable_count = pcs.num_variables - pcs.total_folded_through(round_index);
        if sumcheck_prover.num_variables() != expected_variable_count {
            return Err(format!(
                "plain WHIR round {round_index} has {} variables, expected {expected_variable_count}",
                sumcheck_prover.num_variables()
            ));
        }
        if round_index == pcs.n_rounds() {
            prove_final_round(
                pcs,
                proof,
                challenger,
                &mut sumcheck_prover,
                retained_round_source.take(),
                initial_polynomial_recomputation,
            )?;
            break;
        }

        let round_parameters = &pcs.round_parameters[round_index];
        let next_folding_factor = pcs.round_folding_factor(round_index + 1);
        let current_root = stream_prefix_polynomial(
            sumcheck_prover.evals_view(),
            next_folding_factor,
            pcs.inv_rate(round_index),
            None,
        )?
        .root;
        challenger.observe(current_root.clone());
        proof.rounds[round_index].commitment = Some(current_root.clone());

        let mut out_of_domain_statement = EqStatement::initialize(sumcheck_prover.num_variables());
        let mut out_of_domain_answers = Vec::with_capacity(round_parameters.ood_samples);
        for _ in 0..round_parameters.ood_samples {
            let point = Point::expand_from_univariate(
                challenger.sample_algebra_element(),
                sumcheck_prover.num_variables(),
            );
            let evaluation = sumcheck_prover.eval(&point);
            challenger.observe_algebra_element(evaluation);
            out_of_domain_answers.push(evaluation);
            out_of_domain_statement.add_evaluated_constraint(point, evaluation);
        }
        proof.rounds[round_index].ood_answers = out_of_domain_answers;

        if round_parameters.pow_bits > 0 {
            proof.rounds[round_index].pow_witness = challenger.grind(round_parameters.pow_bits);
        }
        let _: ChallengeField = challenger.sample();
        let query_indices = sample_distinct_query_indices(
            round_parameters.domain_size,
            pcs.round_folding_factor(round_index),
            round_parameters.num_queries,
            challenger,
        )?;
        let previous_openings = if let Some(previous) = retained_round_source.take() {
            let openings = stream_prefix_polynomial(
                PolyView::Scalar(&previous.polynomial),
                previous.folding_factor,
                previous.inverse_rate,
                Some(&query_indices),
            )?;
            if openings.root != previous.root {
                return Err(format!(
                    "plain WHIR round {round_index} recomputed the wrong prior commitment"
                ));
            }
            (openings, previous.query_value_kind)
        } else {
            let initial_polynomial = (initial_polynomial_recomputation.recompute)()?;
            if initial_polynomial.num_variables() != pcs.num_variables {
                return Err(format!(
                    "recomputed initial polynomial has {} variables, expected {}",
                    initial_polynomial.num_variables(),
                    pcs.num_variables
                ));
            }
            let openings = stream_prefix_polynomial(
                PolyView::Scalar(&initial_polynomial),
                pcs.round_folding_factor(0),
                1_usize
                    .checked_shl(
                        u32::try_from(pcs.params.starting_log_inv_rate)
                            .map_err(|_| "starting log-inverse rate exceeds u32".to_owned())?,
                    )
                    .ok_or_else(|| "starting inverse rate overflowed".to_owned())?,
                Some(&query_indices),
            )?;
            drop(initial_polynomial);
            if openings.root != *initial_polynomial_recomputation.expected_commitment {
                return Err("recomputed initial polynomial has the wrong commitment".to_owned());
            }
            (openings, QueryValueKind::Base)
        };

        let query_randomness = folding_randomness.clone();
        let mut selection_statement = SelectStatement::initialize(sumcheck_prover.num_variables());
        let mut queries = Vec::with_capacity(query_indices.len());
        for ((query_index, values), path) in query_indices
            .iter()
            .copied()
            .zip(previous_openings.0.rows)
            .zip(previous_openings.0.paths)
        {
            let query_polynomial = Poly::new(values);
            let evaluation = match previous_openings.1 {
                QueryValueKind::Base => query_polynomial.eval_base(&query_randomness),
                QueryValueKind::Extension => {
                    query_polynomial.eval_ext::<ChallengeField>(&query_randomness)
                }
            };
            let domain_point = round_parameters
                .folded_domain_gen
                .exp_u64(query_index as u64);
            selection_statement.add_constraint(domain_point, evaluation);
            let values = query_polynomial.into_evals();
            queries.push(match previous_openings.1 {
                QueryValueKind::Base => QueryOpening::Base {
                    values,
                    proof: path,
                },
                QueryValueKind::Extension => QueryOpening::Extension {
                    values,
                    proof: path,
                },
            });
        }
        proof.rounds[round_index].queries = queries;

        let constraint = Constraint::new(
            challenger.sample_algebra_element(),
            sumcheck_prover.num_variables(),
            vec![
                Statements::Eq(out_of_domain_statement),
                Statements::Select(selection_statement),
            ],
        );
        let retained_current_polynomial = sumcheck_prover.evals();
        let mut sumcheck_data = SumcheckData::default();
        folding_randomness = sumcheck_prover.compute_sumcheck_polynomials(
            &mut sumcheck_data,
            challenger,
            next_folding_factor,
            round_parameters.folding_pow_bits,
            Some(constraint),
        );
        proof.rounds[round_index].sumcheck = sumcheck_data;
        retained_round_source = Some(RetainedRoundSource {
            polynomial: retained_current_polynomial,
            root: current_root,
            query_value_kind: QueryValueKind::Extension,
            folding_factor: next_folding_factor,
            inverse_rate: pcs.inv_rate(round_index),
        });
    }
    Ok(())
}

#[cfg(test)]
fn prove_final_round<RecomputeInitialPolynomial>(
    pcs: &PlainAggregatePcs,
    proof: &mut WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme>,
    challenger: &mut ExtensionFieldChallenger,
    sumcheck_prover: &mut p3_sumcheck::strategy::SumcheckProver<ChallengeField, ChallengeField>,
    retained_round_source: Option<RetainedRoundSource>,
    initial_polynomial_recomputation: &mut InitialPolynomialRecomputation<
        '_,
        RecomputeInitialPolynomial,
    >,
) -> Result<(), String>
where
    RecomputeInitialPolynomial: FnMut() -> Result<Poly<ChallengeField>, String>,
{
    let final_polynomial = sumcheck_prover.evals();
    challenger.observe_algebra_slice(final_polynomial.as_slice());
    proof.final_poly = Some(final_polynomial);
    if pcs.final_pow_bits > 0 {
        proof.final_pow_witness = challenger.grind(pcs.final_pow_bits);
    }
    let final_query_indices = sample_distinct_query_indices(
        pcs.final_round_config().domain_size,
        pcs.round_folding_factor(pcs.n_rounds()),
        pcs.final_queries,
        challenger,
    )?;
    let (openings, query_value_kind) = if let Some(previous) = retained_round_source {
        let openings = stream_prefix_polynomial(
            PolyView::Scalar(&previous.polynomial),
            previous.folding_factor,
            previous.inverse_rate,
            Some(&final_query_indices),
        )?;
        if openings.root != previous.root {
            return Err("plain WHIR final round recomputed the wrong prior commitment".to_owned());
        }
        (openings, previous.query_value_kind)
    } else {
        let initial_polynomial = (initial_polynomial_recomputation.recompute)()?;
        let openings = stream_prefix_polynomial(
            PolyView::Scalar(&initial_polynomial),
            pcs.round_folding_factor(0),
            1_usize
                .checked_shl(
                    u32::try_from(pcs.params.starting_log_inv_rate)
                        .map_err(|_| "starting log-inverse rate exceeds u32".to_owned())?,
                )
                .ok_or_else(|| "starting inverse rate overflowed".to_owned())?,
            Some(&final_query_indices),
        )?;
        if openings.root != *initial_polynomial_recomputation.expected_commitment {
            return Err("recomputed initial polynomial has the wrong commitment".to_owned());
        }
        (openings, QueryValueKind::Base)
    };
    proof.final_queries = openings
        .rows
        .into_iter()
        .zip(openings.paths)
        .map(|(values, path)| match query_value_kind {
            QueryValueKind::Base => QueryOpening::Base {
                values,
                proof: path,
            },
            QueryValueKind::Extension => QueryOpening::Extension {
                values,
                proof: path,
            },
        })
        .collect();

    if pcs.final_sumcheck_rounds > 0 {
        let mut sumcheck_data = SumcheckData::default();
        sumcheck_prover.compute_sumcheck_polynomials(
            &mut sumcheck_data,
            challenger,
            pcs.final_sumcheck_rounds,
            pcs.final_folding_pow_bits,
            None,
        );
        proof.final_sumcheck = Some(sumcheck_data);
    }
    Ok(())
}

fn sample_distinct_query_indices(
    domain_size: usize,
    folding_factor: usize,
    query_count: usize,
    challenger: &mut ExtensionFieldChallenger,
) -> Result<Vec<usize>, String> {
    let folded_domain_size = domain_size
        .checked_shr(
            u32::try_from(folding_factor)
                .map_err(|_| "plain WHIR folding factor exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR folded query domain overflowed".to_owned())?;
    if folded_domain_size == 0 || !folded_domain_size.is_power_of_two() {
        return Err("plain WHIR folded query domain is not a nonzero power of two".to_owned());
    }
    let bit_length = folded_domain_size.ilog2() as usize;
    let target_count = query_count.min(folded_domain_size);
    let mut indices = Vec::with_capacity(target_count);
    while indices.len() < target_count {
        let candidate = challenger
            .sample_uniform_bits::<true>(bit_length)
            .map_err(|_| {
                "plain WHIR query sampling unexpectedly requested resampling".to_owned()
            })?;
        if !indices.contains(&candidate) {
            indices.push(candidate);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}

struct StreamingMatrixLeafHasher {
    states: Vec<[u64; SHAKE256_STATE_WORD_LENGTH]>,
    next_rate_byte: usize,
}

impl StreamingMatrixLeafHasher {
    fn new(row_count: usize) -> Result<Self, String> {
        if row_count == 0 || row_count > MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT {
            return Err("plain WHIR leaf-hasher stripe has an unsupported row count".to_owned());
        }
        let mut base_state = [0_u64; SHAKE256_STATE_WORD_LENGTH];
        let mut next_rate_byte = 0_usize;
        absorb_shake_bytes(
            &mut base_state,
            &mut next_rate_byte,
            ROW_CODE_WHIR_SHAKE256_PROTOCOL_DOMAIN,
        );
        absorb_shake_bytes(
            &mut base_state,
            &mut next_rate_byte,
            &(ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN.len() as u64).to_le_bytes(),
        );
        absorb_shake_bytes(
            &mut base_state,
            &mut next_rate_byte,
            ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN,
        );
        Ok(Self {
            states: vec![base_state; row_count],
            next_rate_byte,
        })
    }

    fn absorb_column(&mut self, column: &[ChallengeField]) -> Result<(), String> {
        if column.len() != self.states.len() {
            return Err("plain WHIR encoded column has the wrong row count".to_owned());
        }
        let starting_rate_byte = self.next_rate_byte;
        let mut expected_next_rate_byte = None;
        for (state, value) in self.states.iter_mut().zip(column) {
            let mut next_rate_byte = starting_rate_byte;
            for coefficient in
                <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(value)
            {
                absorb_shake_word(state, &mut next_rate_byte, coefficient.as_canonical_u64());
            }
            if let Some(expected) = expected_next_rate_byte {
                debug_assert_eq!(next_rate_byte, expected);
            } else {
                expected_next_rate_byte = Some(next_rate_byte);
            }
        }
        self.next_rate_byte = expected_next_rate_byte.unwrap_or(starting_rate_byte);
        Ok(())
    }

    fn finish_digests(self) -> impl Iterator<Item = MerkleDigest> {
        let next_rate_byte = self.next_rate_byte;
        self.states.into_iter().map(move |mut state| {
            xor_shake_byte(&mut state, next_rate_byte, SHAKE256_DELIMITER);
            xor_shake_byte(
                &mut state,
                SHAKE256_RATE_BYTE_LENGTH - 1,
                SHAKE256_FINAL_BIT,
            );
            keccakf(&mut state);
            core::array::from_fn(|word_index| state[word_index])
        })
    }
}

fn absorb_shake_bytes(
    state: &mut [u64; SHAKE256_STATE_WORD_LENGTH],
    next_rate_byte: &mut usize,
    bytes: &[u8],
) {
    for byte in bytes {
        xor_shake_byte(state, *next_rate_byte, *byte);
        *next_rate_byte += 1;
        if *next_rate_byte == SHAKE256_RATE_BYTE_LENGTH {
            keccakf(state);
            *next_rate_byte = 0;
        }
    }
}

fn absorb_shake_word(
    state: &mut [u64; SHAKE256_STATE_WORD_LENGTH],
    next_rate_byte: &mut usize,
    word: u64,
) {
    let available_rate_bytes = SHAKE256_RATE_BYTE_LENGTH - *next_rate_byte;
    if available_rate_bytes >= size_of::<u64>() {
        let state_word_index = *next_rate_byte / size_of::<u64>();
        let bit_offset = (*next_rate_byte % size_of::<u64>()) * u8::BITS as usize;
        state[state_word_index] ^= word << bit_offset;
        if bit_offset != 0 {
            state[state_word_index + 1] ^= word >> (u64::BITS as usize - bit_offset);
        }
        *next_rate_byte += size_of::<u64>();
        if *next_rate_byte == SHAKE256_RATE_BYTE_LENGTH {
            keccakf(state);
            *next_rate_byte = 0;
        }
        return;
    }

    let bytes = word.to_le_bytes();
    absorb_shake_bytes(state, next_rate_byte, &bytes[..available_rate_bytes]);
    absorb_shake_bytes(state, next_rate_byte, &bytes[available_rate_bytes..]);
}

fn xor_shake_byte(state: &mut [u64; SHAKE256_STATE_WORD_LENGTH], rate_byte_index: usize, byte: u8) {
    debug_assert!(rate_byte_index < SHAKE256_RATE_BYTE_LENGTH);
    let word_index = rate_byte_index / size_of::<u64>();
    let bit_offset = (rate_byte_index % size_of::<u64>()) * u8::BITS as usize;
    state[word_index] ^= u64::from(byte) << bit_offset;
}

#[cfg(test)]
fn stream_prefix_polynomial(
    polynomial: PolyView<'_, ChallengeField, ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
    query_indices: Option<&[usize]>,
) -> Result<MatrixOpenings, String> {
    stream_prefix_polynomial_with_maximum_leaf_hasher_row_count(
        polynomial,
        folding_factor,
        inverse_rate,
        query_indices,
        MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT,
    )
}

#[cfg(test)]
fn stream_prefix_polynomial_with_maximum_leaf_hasher_row_count(
    polynomial: PolyView<'_, ChallengeField, ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
    query_indices: Option<&[usize]>,
    maximum_leaf_hasher_row_count: usize,
) -> Result<MatrixOpenings, String> {
    let (width, source_height, height) =
        prefix_encoding_geometry(polynomial, folding_factor, inverse_rate)?;
    if maximum_leaf_hasher_row_count == 0
        || !maximum_leaf_hasher_row_count.is_power_of_two()
        || maximum_leaf_hasher_row_count > MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT
    {
        return Err("plain WHIR leaf-hasher stripe bound is invalid".to_owned());
    }
    if query_indices.is_some_and(|indices| {
        indices.windows(2).any(|window| window[0] >= window[1])
            || indices.last().is_some_and(|last| *last >= height)
    }) {
        return Err("plain WHIR query indices are not canonical for the matrix".to_owned());
    }

    let mut opened_rows = query_indices.map_or_else(Vec::new, |indices| {
        vec![vec![ChallengeField::ZERO; width]; indices.len()]
    });
    let capture_targets = query_indices.map(|indices| merkle_capture_targets(height, indices));
    let mut merkle_builder = StreamingMerkleBuilder::new(height, capture_targets)?;
    let transform = Radix2Dit::<ChallengeField>::default();
    for stripe_start in (0..height).step_by(maximum_leaf_hasher_row_count) {
        let stripe_end = stripe_start
            .checked_add(maximum_leaf_hasher_row_count)
            .map_or(height, |end| end.min(height));
        let mut leaf_hasher = StreamingMatrixLeafHasher::new(stripe_end - stripe_start)?;
        for source_column in 0..width {
            let source_start = source_column
                .checked_mul(source_height)
                .ok_or_else(|| "plain WHIR source range overflowed".to_owned())?;
            let mut encoded_column = ChallengeField::zero_vec(height);
            polynomial
                .copy_logical_range_into(
                    source_start,
                    source_height,
                    &mut encoded_column[..source_height],
                )
                .map_err(|error| format!("copy plain WHIR source column range: {error:?}"))?;
            let encoded_column = transform.dft(encoded_column);
            if let Some(indices) = query_indices {
                for (query_ordinal, query_index) in indices.iter().copied().enumerate() {
                    if (stripe_start..stripe_end).contains(&query_index) {
                        opened_rows[query_ordinal][source_column] = encoded_column[query_index];
                    }
                }
            }
            leaf_hasher.absorb_column(&encoded_column[stripe_start..stripe_end])?;
        }
        for digest in leaf_hasher.finish_digests() {
            merkle_builder.push(digest)?;
        }
    }

    let (root, paths) = merkle_builder.finish()?;
    Ok(MatrixOpenings {
        root: MerkleCap::new(vec![root]),
        rows: opened_rows,
        paths: paths.unwrap_or_default(),
    })
}

#[cfg(test)]
fn prefix_encoding_geometry(
    polynomial: PolyView<'_, ChallengeField, ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
) -> Result<(usize, usize, usize), String> {
    let geometry =
        checked_prefix_encoding_geometry(polynomial.num_variables(), folding_factor, inverse_rate)?;
    let (width, source_height, _) = geometry;
    let expected_source_value_count = source_height
        .checked_mul(width)
        .ok_or_else(|| "plain WHIR source value count overflowed".to_owned())?;
    if polynomial.num_evals() != expected_source_value_count {
        return Err("plain WHIR polynomial length does not match its arity".to_owned());
    }
    Ok(geometry)
}

fn checked_prefix_encoding_geometry(
    source_variable_count: usize,
    folding_factor: usize,
    inverse_rate: usize,
) -> Result<(usize, usize, usize), String> {
    if folding_factor > source_variable_count {
        return Err("plain WHIR folding factor exceeds the polynomial arity".to_owned());
    }
    if inverse_rate == 0 || !inverse_rate.is_power_of_two() {
        return Err("plain WHIR inverse rate is not a nonzero power of two".to_owned());
    }
    let width = 1_usize
        .checked_shl(
            u32::try_from(folding_factor)
                .map_err(|_| "plain WHIR folding factor exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR encoded width overflowed".to_owned())?;
    let source_height = 1_usize
        .checked_shl(
            u32::try_from(source_variable_count - folding_factor)
                .map_err(|_| "plain WHIR source height exponent exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "plain WHIR source height overflowed".to_owned())?;
    let height = source_height
        .checked_mul(inverse_rate)
        .ok_or_else(|| "plain WHIR encoded height overflowed".to_owned())?;
    Ok((width, source_height, height))
}

#[cfg(test)]
fn encode_prefix_polynomial(
    polynomial: &Poly<ChallengeField>,
    folding_factor: usize,
    inverse_rate: usize,
) -> Result<EncodedMatrix, String> {
    let (width, source_height, height) =
        prefix_encoding_geometry(PolyView::Scalar(polynomial), folding_factor, inverse_rate)?;
    let value_count = height
        .checked_mul(width)
        .ok_or_else(|| "plain WHIR encoded value count overflowed".to_owned())?;
    let mut values = ChallengeField::zero_vec(value_count);
    for source_row in 0..source_height {
        for source_column in 0..width {
            values[source_row * width + source_column] =
                polynomial.as_slice()[source_column * source_height + source_row];
        }
    }
    bounded_dft_rows(&mut values, width, height)?;
    Ok(EncodedMatrix {
        values,
        width,
        height,
    })
}

#[cfg(test)]
fn bounded_dft_rows(
    values: &mut Vec<ChallengeField>,
    width: usize,
    height: usize,
) -> Result<(), String> {
    let expected_value_count = width
        .checked_mul(height)
        .ok_or_else(|| "plain WHIR DFT matrix value count overflowed".to_owned())?;
    if height == 0 || !height.is_power_of_two() || values.len() != expected_value_count {
        return Err("plain WHIR DFT matrix has invalid geometry".to_owned());
    }
    if height == 1 {
        return Ok(());
    }
    let matrix = RowMajorMatrix::new(core::mem::take(values), width);
    *values = Radix2Dit::<ChallengeField>::default()
        .dft_batch(matrix)
        .values;
    Ok(())
}

fn node_compressor() -> NodeCompressor {
    NodeCompressor::new(DomainSeparatedShake256 {
        domain: ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
    })
}

type CaptureTargets = Vec<BTreeMap<usize, Vec<(usize, usize)>>>;
type MerkleBuilderOutput = (MerkleDigest, Option<Vec<Vec<MerkleDigest>>>);

fn merkle_capture_targets(height: usize, query_indices: &[usize]) -> CaptureTargets {
    let tree_depth = height.ilog2() as usize;
    let mut capture_targets = vec![BTreeMap::<usize, Vec<(usize, usize)>>::new(); tree_depth];
    for (query_ordinal, query_index) in query_indices.iter().copied().enumerate() {
        for (level, level_targets) in capture_targets.iter_mut().enumerate() {
            let sibling_index = (query_index >> level) ^ 1;
            level_targets
                .entry(sibling_index)
                .or_default()
                .push((query_ordinal, level));
        }
    }
    capture_targets
}

struct StreamingMerkleBuilder {
    leaf_count: usize,
    next_leaf_index: usize,
    capture_targets: Option<CaptureTargets>,
    paths: Option<Vec<Vec<MerkleDigest>>>,
    captured: Option<Vec<Vec<bool>>>,
    frontier: Vec<Option<MerkleDigest>>,
    compressor: NodeCompressor,
}

impl StreamingMerkleBuilder {
    fn new(leaf_count: usize, capture_targets: Option<CaptureTargets>) -> Result<Self, String> {
        if leaf_count == 0 || !leaf_count.is_power_of_two() {
            return Err("plain WHIR Merkle leaf count is not a power of two".to_owned());
        }
        let tree_depth = leaf_count.ilog2() as usize;
        if capture_targets
            .as_ref()
            .is_some_and(|targets| targets.len() != tree_depth)
        {
            return Err("plain WHIR Merkle capture depth is invalid".to_owned());
        }
        let query_count = capture_targets
            .as_ref()
            .map(|targets| {
                targets
                    .iter()
                    .flat_map(BTreeMap::values)
                    .flat_map(|placements| placements.iter().map(|(ordinal, _)| *ordinal))
                    .max()
                    .map_or(0, |maximum| maximum + 1)
            })
            .unwrap_or(0);
        Ok(Self {
            leaf_count,
            next_leaf_index: 0,
            paths: capture_targets
                .as_ref()
                .map(|_| vec![vec![[0_u64; MERKLE_DIGEST_WORD_LENGTH]; tree_depth]; query_count]),
            captured: capture_targets
                .as_ref()
                .map(|_| vec![vec![false; tree_depth]; query_count]),
            capture_targets,
            frontier: vec![None::<MerkleDigest>; tree_depth + 1],
            compressor: node_compressor(),
        })
    }

    fn push(&mut self, mut digest: MerkleDigest) -> Result<(), String> {
        if self.next_leaf_index >= self.leaf_count {
            return Err("plain WHIR Merkle builder received an extra leaf".to_owned());
        }
        let leaf_index = self.next_leaf_index;
        let mut level = 0_usize;
        let mut node_index = leaf_index;
        capture_digest(
            self.capture_targets.as_ref(),
            self.paths.as_mut(),
            self.captured.as_mut(),
            level,
            node_index,
            digest,
        )?;
        loop {
            let Some(left_digest) = self.frontier[level].take() else {
                self.frontier[level] = Some(digest);
                break;
            };
            digest = self.compressor.compress([left_digest, digest]);
            level += 1;
            node_index >>= 1;
            capture_digest(
                self.capture_targets.as_ref(),
                self.paths.as_mut(),
                self.captured.as_mut(),
                level,
                node_index,
                digest,
            )?;
        }
        self.next_leaf_index += 1;
        Ok(())
    }

    fn finish(self) -> Result<MerkleBuilderOutput, String> {
        if self.next_leaf_index != self.leaf_count {
            return Err("plain WHIR Merkle builder ended before its final leaf".to_owned());
        }
        let tree_depth = self.leaf_count.ilog2() as usize;
        let root = self
            .frontier
            .last()
            .and_then(|root| *root)
            .ok_or_else(|| "plain WHIR Merkle walk did not produce a root".to_owned())?;
        if self.frontier[..tree_depth].iter().any(Option::is_some) {
            return Err("plain WHIR Merkle walk left an incomplete frontier".to_owned());
        }
        if self
            .captured
            .as_ref()
            .is_some_and(|captured| captured.iter().flatten().any(|was_captured| !was_captured))
        {
            return Err(
                "plain WHIR Merkle walk did not capture every authentication node".to_owned(),
            );
        }
        Ok((root, self.paths))
    }
}

fn capture_digest(
    capture_targets: Option<&CaptureTargets>,
    paths: Option<&mut Vec<Vec<MerkleDigest>>>,
    captured: Option<&mut Vec<Vec<bool>>>,
    level: usize,
    node_index: usize,
    digest: MerkleDigest,
) -> Result<(), String> {
    let (Some(targets), Some(paths), Some(captured)) = (capture_targets, paths, captured) else {
        return Ok(());
    };
    let Some(level_targets) = targets.get(level) else {
        return Ok(());
    };
    let Some(placements) = level_targets.get(&node_index) else {
        return Ok(());
    };
    for (query_ordinal, path_position) in placements {
        let was_captured = captured
            .get_mut(*query_ordinal)
            .and_then(|query| query.get_mut(*path_position))
            .ok_or_else(|| "plain WHIR Merkle capture target is out of range".to_owned())?;
        if *was_captured {
            return Err("plain WHIR Merkle authentication node was captured twice".to_owned());
        }
        paths[*query_ordinal][*path_position] = digest;
        *was_captured = true;
    }
    Ok(())
}

fn checked_power_of_two(exponent: usize, label: &str) -> Result<usize, String> {
    1_usize
        .checked_shl(u32::try_from(exponent).map_err(|_| format!("{label} exponent exceeds u32"))?)
        .ok_or_else(|| format!("{label} overflowed"))
}

fn validate_retained_oracle_catalog(
    config: &PlainAggregateWhirConfig,
    retained_oracles: &[RetainedPlainWhirEncodedOracle],
) -> Result<(), String> {
    let expected_oracle_count = config
        .n_rounds()
        .checked_add(1)
        .ok_or_else(|| "plain WHIR retained-oracle count overflowed".to_owned())?;
    if retained_oracles.len() != expected_oracle_count {
        return Err(format!(
            "plain WHIR retained-oracle catalog has {} objects, expected {expected_oracle_count}",
            retained_oracles.len()
        ));
    }

    let mut object_ordinals = BTreeMap::new();
    for (oracle_index, descriptor) in retained_oracles.iter().enumerate() {
        if object_ordinals
            .insert(descriptor.object.ordinal(), oracle_index)
            .is_some()
        {
            return Err("plain WHIR retained-oracle catalog reuses an object ordinal".to_owned());
        }
        let domain_size = if oracle_index < config.n_rounds() {
            config.round_parameters[oracle_index].domain_size
        } else {
            config.final_round_config().domain_size
        };
        let folding_factor = config.round_folding_factor(oracle_index);
        if checked_power_of_two(folding_factor, "retained-oracle folding width")?
            != RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH
        {
            return Err("plain WHIR retained-oracle catalog has an unsupported width".to_owned());
        }
        let encoded_height = domain_size
            .checked_shr(
                u32::try_from(folding_factor)
                    .map_err(|_| "plain WHIR retained folding factor exceeds u32".to_owned())?,
            )
            .ok_or_else(|| "plain WHIR retained encoded height overflowed".to_owned())?;
        if encoded_height == 0 || !encoded_height.is_power_of_two() {
            return Err("plain WHIR retained encoded height is invalid".to_owned());
        }
        let exact_byte_length = RetainedPlainWhirOracleScratchCodec::try_new(encoded_height)
            .map_err(|error| format!("derive retained-oracle byte length: {error:?}"))?
            .exact_byte_length();
        if descriptor.encoded_height != encoded_height
            || descriptor.exact_byte_length != exact_byte_length
        {
            return Err(format!(
                "plain WHIR retained-oracle descriptor {oracle_index} does not match construction geometry"
            ));
        }
    }
    Ok(())
}

fn empty_plain_whir_proof_for_config(
    config: &PlainAggregateWhirConfig,
) -> WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme> {
    WhirProof {
        initial_ood_answers: Vec::with_capacity(config.commitment_ood_samples),
        initial_sumcheck: Default::default(),
        rounds: (0..config.n_rounds())
            .map(|_| WhirRoundProof::default())
            .collect(),
        final_poly: None,
        final_pow_witness: ChallengeField::ZERO,
        final_queries: Vec::with_capacity(config.final_queries),
        final_sumcheck: None,
    }
}

#[cfg(test)]
fn empty_plain_whir_proof(
    pcs: &PlainAggregatePcs,
) -> WhirProof<ChallengeField, ChallengeField, super::CommitmentScheme> {
    empty_plain_whir_proof_for_config(&pcs.config)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_commit::Mmcs;
    use p3_dft::TwoAdicSubgroupDft;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_sumcheck::layout::{Table, TableShape};
    use zeroize::Zeroizing;

    use super::*;
    use crate::bgv::proof_suite::row_code_whir::{
        plain_whir::{
            commit_plain_aggregate_batch, open_plain_aggregate_batches_at_points,
            plain_aggregate_challenger, plain_aggregate_encoded_oracle_geometries,
            plain_aggregate_pcs_with_parameters, verify_plain_aggregate_batches_at_points,
        },
        plain_whir_wire::encode_plain_whir_batch_proof,
        retained_oracle_codec::RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH,
    };
    use crate::bgv::proof_suite::{
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, ProofExternalMemoryObjectPlan,
        ProofExternalMemoryPlan, ProofExternalMemoryProtection,
    };

    const MAXIMUM_RETAINED_STATE_MACHINE_TEST_POLL_COUNT: usize = 10_000;

    #[derive(Default)]
    struct RetainedOracleTestStorage {
        transaction_active: bool,
        transaction_operation_count: u32,
        maximum_transaction_operation_count: u32,
        objects: BTreeMap<ProofExternalMemoryObject, RetainedOracleTestObject>,
    }

    struct RetainedOracleTestObject {
        exact_byte_length: u64,
        bytes: Vec<u8>,
        sealed: bool,
    }

    impl RetainedOracleTestStorage {
        fn record_operation(&mut self) -> Result<(), &'static str> {
            if !self.transaction_active {
                return Err("storage operation is outside a transaction");
            }
            self.transaction_operation_count = self
                .transaction_operation_count
                .checked_add(1)
                .ok_or("storage operation count overflowed")?;
            if self.transaction_operation_count > self.maximum_transaction_operation_count {
                return Err("storage transaction operation bound was exceeded");
            }
            Ok(())
        }

        fn mutate_first_coordinate_to_noncanonical(&mut self, object: ProofExternalMemoryObject) {
            self.objects
                .get_mut(&object)
                .expect("retained object exists")
                .bytes[..size_of::<u64>()]
                .copy_from_slice(&u64::MAX.to_le_bytes());
        }
    }

    impl ProofExternalMemory for RetainedOracleTestStorage {
        type Error = &'static str;

        fn begin_transaction(
            &mut self,
            maximum_payload_byte_length: u64,
            maximum_operation_count: u32,
        ) -> Result<(), Self::Error> {
            if self.transaction_active
                || maximum_payload_byte_length
                    < u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
                || maximum_operation_count == 0
            {
                return Err("invalid storage transaction");
            }
            self.transaction_active = true;
            self.transaction_operation_count = 0;
            self.maximum_transaction_operation_count = maximum_operation_count;
            Ok(())
        }

        fn create_object(
            &mut self,
            object: ProofExternalMemoryObject,
            protection: ProofExternalMemoryProtection,
            exact_byte_length: u64,
        ) -> Result<(), Self::Error> {
            self.record_operation()?;
            if protection != ProofExternalMemoryProtection::SecretAuthenticatedEncryption
                || exact_byte_length == 0
                || self
                    .objects
                    .insert(
                        object,
                        RetainedOracleTestObject {
                            exact_byte_length,
                            bytes: Vec::new(),
                            sealed: false,
                        },
                    )
                    .is_some()
            {
                return Err("invalid retained object creation");
            }
            Ok(())
        }

        fn append_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            expected_offset: u64,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.record_operation()?;
            let retained = self.objects.get_mut(&object).ok_or("object is missing")?;
            if retained.sealed
                || u64::try_from(retained.bytes.len()) != Ok(expected_offset)
                || u64::try_from(bytes.len())
                    .ok()
                    .and_then(|byte_length| expected_offset.checked_add(byte_length))
                    .is_none_or(|end| end > retained.exact_byte_length)
            {
                return Err("invalid retained object append");
            }
            retained.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn append_owned_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            expected_offset: u64,
            bytes: &mut Zeroizing<Vec<u8>>,
        ) -> Result<(), Self::Error> {
            self.append_object_bytes(object, expected_offset, bytes.as_slice())
        }

        fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            self.record_operation()?;
            let retained = self.objects.get_mut(&object).ok_or("object is missing")?;
            if retained.sealed
                || u64::try_from(retained.bytes.len()) != Ok(retained.exact_byte_length)
            {
                return Err("invalid retained object seal");
            }
            retained.sealed = true;
            Ok(())
        }

        fn read_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.record_operation()?;
            let retained = self.objects.get(&object).ok_or("object is missing")?;
            let start = usize::try_from(offset).map_err(|_| "read offset exceeds usize")?;
            let end = start
                .checked_add(destination.len())
                .ok_or("read range overflowed")?;
            if !retained.sealed || end > retained.bytes.len() {
                return Err("invalid retained object read");
            }
            destination.copy_from_slice(&retained.bytes[start..end]);
            Ok(())
        }

        fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            self.record_operation()?;
            self.objects.remove(&object).ok_or("object is missing")?;
            Ok(())
        }

        fn commit_transaction(&mut self) -> Result<(), Self::Error> {
            if !self.transaction_active || self.transaction_operation_count == 0 {
                return Err("invalid storage transaction commit");
            }
            self.transaction_active = false;
            Ok(())
        }

        fn abort_transaction(&mut self) -> Result<(), Self::Error> {
            if !self.transaction_active {
                return Err("storage transaction is not active");
            }
            self.transaction_active = false;
            Ok(())
        }
    }

    fn retained_oracle_fixture(
        variable_count: usize,
        folding_factor: usize,
        inverse_rate: usize,
    ) -> (RetainedPlainWhirEncodedOracle, ProofExternalMemoryPlan) {
        let (_, _, encoded_height) =
            checked_prefix_encoding_geometry(variable_count, folding_factor, inverse_rate)
                .expect("retained fixture geometry");
        let exact_byte_length = u64::try_from(encoded_height)
            .expect("encoded height fits u64")
            .checked_mul(
                u64::try_from(RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH)
                    .expect("encoded width fits u64"),
            )
            .and_then(|value_count| {
                value_count.checked_mul(
                    u64::try_from(RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH)
                        .expect("field byte length fits u64"),
                )
            })
            .expect("retained fixture byte length");
        let object = ProofExternalMemoryObject::new(17);
        let descriptor = RetainedPlainWhirEncodedOracle {
            object,
            encoded_height,
            exact_byte_length,
        };
        let plan = ProofExternalMemoryPlan::new(
            1,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
            1,
            exact_byte_length,
            exact_byte_length,
            exact_byte_length.checked_mul(2).expect("two read passes"),
            6,
            vec![ProofExternalMemoryObjectPlan::new(
                object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                exact_byte_length,
                0,
                0,
                0,
            )],
        )
        .expect("retained fixture external-memory plan");
        (descriptor, plan)
    }

    fn retained_oracle_catalog_fixture(
        pcs: &PlainAggregatePcs,
    ) -> (Vec<RetainedPlainWhirEncodedOracle>, ProofExternalMemoryPlan) {
        let geometries =
            plain_aggregate_encoded_oracle_geometries(pcs).expect("retained catalog geometry");
        let mut descriptors = Vec::with_capacity(geometries.len());
        let mut object_plans = Vec::with_capacity(geometries.len());
        let mut total_byte_length = 0_u64;
        let mut peak_stored_byte_length = 0_u64;
        let mut previous_byte_length = 0_u64;
        for (oracle_index, geometry) in geometries.into_iter().enumerate() {
            assert_eq!(geometry.width, RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH);
            let codec = RetainedPlainWhirOracleScratchCodec::try_new(geometry.height)
                .expect("retained catalog codec");
            let exact_byte_length = codec.exact_byte_length();
            let object = ProofExternalMemoryObject::new(
                100_u32
                    .checked_add(u32::try_from(oracle_index).expect("oracle index fits u32"))
                    .expect("oracle ordinal"),
            );
            let step = u32::try_from(oracle_index).expect("oracle step fits u32");
            descriptors.push(RetainedPlainWhirEncodedOracle {
                object,
                encoded_height: geometry.height,
                exact_byte_length,
            });
            object_plans.push(ProofExternalMemoryObjectPlan::new(
                object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                exact_byte_length,
                step,
                step,
                step.checked_add(1).expect("oracle last-use step"),
            ));
            peak_stored_byte_length = peak_stored_byte_length.max(
                previous_byte_length
                    .checked_add(exact_byte_length)
                    .expect("retained overlap"),
            );
            previous_byte_length = exact_byte_length;
            total_byte_length = total_byte_length
                .checked_add(exact_byte_length)
                .expect("retained total byte length");
        }
        let step_count = u32::try_from(descriptors.len() + 1).expect("step count fits u32");
        let plan = ProofExternalMemoryPlan::new(
            step_count,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
            2,
            peak_stored_byte_length,
            total_byte_length,
            total_byte_length.checked_mul(2).expect("two oracle reads"),
            100_000,
            object_plans,
        )
        .expect("retained catalog external-memory plan");
        (descriptors, plan)
    }

    fn write_retained_oracle(
        polynomial: &Poly<ChallengeField>,
        descriptor: RetainedPlainWhirEncodedOracle,
        variable_count: usize,
        folding_factor: usize,
        inverse_rate: usize,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut RetainedOracleTestStorage,
    ) {
        let mut writer = StreamingPlainAggregateRetainedOracleWriter::new(
            descriptor,
            variable_count,
            folding_factor,
            inverse_rate,
        )
        .expect("retained oracle writer");
        for _ in 0..64 {
            match writer
                .poll(PolyView::Scalar(polynomial), executor, storage)
                .expect("advance retained oracle writer")
            {
                StreamingPlainAggregateRetainedOracleWritePoll::Complete { object } => {
                    assert_eq!(object, descriptor.object);
                    return;
                }
                StreamingPlainAggregateRetainedOracleWritePoll::ArithmeticStepCompleted
                | StreamingPlainAggregateRetainedOracleWritePoll::StorageTransactionCompleted => {}
            }
        }
        panic!("retained oracle writer did not complete within its bounded fixture schedule");
    }

    fn read_retained_oracle(
        descriptor: RetainedPlainWhirEncodedOracle,
        query_indices: &[usize],
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut RetainedOracleTestStorage,
    ) -> StreamingPlainAggregateRetainedOracleReadOutput {
        let mut reader =
            StreamingPlainAggregateRetainedOracleReader::new(descriptor, query_indices)
                .expect("retained oracle reader");
        for _ in 0..16 {
            match reader
                .poll(executor, storage)
                .expect("advance retained oracle reader")
            {
                StreamingPlainAggregateRetainedOracleReadPoll::StorageTransactionCompleted => {}
                StreamingPlainAggregateRetainedOracleReadPoll::Complete(output) => return output,
            }
        }
        panic!("retained oracle reader did not complete within its bounded fixture schedule");
    }

    fn deterministic_messages(variable_count: usize, width: usize) -> Vec<Poly<ChallengeField>> {
        (0..width)
            .map(|column_index| {
                Poly::new(
                    (0..1_usize << variable_count)
                        .map(|row_index| {
                            ChallengeField::from_u64(
                                column_index as u64 * 65_537 + row_index as u64 * 257 + 11,
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn bounded_dft_matches_the_upstream_transform() {
        let width = 8;
        let height = 64;
        let original = (0..width * height)
            .map(|index| ChallengeField::from_u64(index as u64 * 17 + 5))
            .collect::<Vec<_>>();
        let expected = super::super::DiscreteFourierTransform::default()
            .dft_batch(RowMajorMatrix::new(original.clone(), width))
            .values;
        let mut actual = original;
        bounded_dft_rows(&mut actual, width, height).expect("bounded DFT");
        assert_eq!(actual, expected);
    }

    #[test]
    fn column_streamed_merkle_paths_match_the_upstream_commitment() {
        let polynomial = Poly::new(
            (0..1_usize << 9)
                .map(|index| ChallengeField::from_u64(index as u64 * 31 + 7))
                .collect(),
        );
        let matrix = encode_prefix_polynomial(&polynomial, 3, 4).expect("encoded matrix");
        let pcs = plain_aggregate_pcs_with_parameters(9, 2, 3).expect("plain WHIR");
        let upstream_matrix = RowMajorMatrix::new(matrix.values.clone(), matrix.width);
        let (upstream_root, upstream_data) = pcs.mmcs.commit_matrix(upstream_matrix);
        let query_indices = [0, 1, 7, 19, matrix.height - 1];
        let streamed = stream_prefix_polynomial_with_maximum_leaf_hasher_row_count(
            PolyView::Scalar(&polynomial),
            3,
            4,
            Some(&query_indices),
            16,
        )
        .expect("stripe-streamed openings");
        assert_eq!(streamed.root, upstream_root);
        for (query_ordinal, query_index) in query_indices.iter().copied().enumerate() {
            let upstream = pcs.mmcs.open_batch(query_index, &upstream_data);
            assert_eq!(streamed.rows[query_ordinal], upstream.opened_values[0]);
            assert_eq!(streamed.paths[query_ordinal], upstream.opening_proof);
        }
    }

    #[test]
    fn retained_oracle_root_and_opening_passes_match_in_memory_bytes() {
        let variable_count = 9;
        let folding_factor = 3;
        let inverse_rate = 4;
        let polynomial = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| ChallengeField::from_u64(index as u64 * 131 + 29))
                .collect(),
        );
        let query_indices = [0, 1, 31, 129, 255];
        let (descriptor, plan) =
            retained_oracle_fixture(variable_count, folding_factor, inverse_rate);
        let mut executor = ProofExternalMemoryExecutor::new(plan);
        let mut storage = RetainedOracleTestStorage::default();

        write_retained_oracle(
            &polynomial,
            descriptor,
            variable_count,
            folding_factor,
            inverse_rate,
            &mut executor,
            &mut storage,
        );
        let root_pass = read_retained_oracle(descriptor, &[], &mut executor, &mut storage);
        let opening_pass =
            read_retained_oracle(descriptor, &query_indices, &mut executor, &mut storage);
        let in_memory = stream_prefix_polynomial_with_maximum_leaf_hasher_row_count(
            PolyView::Scalar(&polynomial),
            folding_factor,
            inverse_rate,
            Some(&query_indices),
            16,
        )
        .expect("in-memory oracle");

        assert!(root_pass.rows.is_empty());
        assert!(root_pass.paths.is_empty());
        assert_eq!(root_pass.root, in_memory.root);
        assert_eq!(opening_pass.root, in_memory.root);
        assert_eq!(opening_pass.rows, in_memory.rows);
        assert_eq!(opening_pass.paths, in_memory.paths);

        executor
            .complete_step(&mut storage)
            .expect("delete retained oracle after its final pass");
        let usage = executor.finish().expect("finish retained oracle plan");
        assert_eq!(
            usage.total_written_byte_length(),
            descriptor.exact_byte_length
        );
        assert_eq!(
            usage.total_read_byte_length(),
            descriptor.exact_byte_length * 2
        );
        assert_eq!(usage.deleted_object_count(), 1);
        assert!(storage.objects.is_empty());
    }

    #[test]
    fn retained_oracle_reader_rejects_a_noncanonical_stored_coordinate() {
        let variable_count = 9;
        let folding_factor = 3;
        let inverse_rate = 4;
        let polynomial = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| ChallengeField::from_u64(index as u64 * 17 + 3))
                .collect(),
        );
        let (descriptor, plan) =
            retained_oracle_fixture(variable_count, folding_factor, inverse_rate);
        let mut executor = ProofExternalMemoryExecutor::new(plan);
        let mut storage = RetainedOracleTestStorage::default();
        write_retained_oracle(
            &polynomial,
            descriptor,
            variable_count,
            folding_factor,
            inverse_rate,
            &mut executor,
            &mut storage,
        );
        storage.mutate_first_coordinate_to_noncanonical(descriptor.object);
        let mut reader = StreamingPlainAggregateRetainedOracleReader::new(descriptor, &[])
            .expect("retained oracle reader");

        assert!(matches!(
            reader.poll(&mut executor, &mut storage),
            Err(StreamingPlainAggregateRetainedOracleError::Storage(
                RetainedPlainWhirOracleStorageError::Codec(
                    RetainedPlainWhirOracleCodecError::NonCanonicalCoordinate {
                        coordinate_index: 0
                    }
                )
            ))
        ));
        executor
            .cancel(&mut storage)
            .expect("cancel malformed retained-oracle attempt");
        assert!(storage.objects.is_empty());
    }

    #[test]
    fn cancelled_retained_oracle_writer_leaves_storage_reusable() {
        let variable_count = 9;
        let folding_factor = 3;
        let inverse_rate = 4;
        let polynomial = Poly::new(
            (0..1_usize << variable_count)
                .map(|index| ChallengeField::from_u64(index as u64 * 43 + 7))
                .collect(),
        );
        let (descriptor, first_plan) =
            retained_oracle_fixture(variable_count, folding_factor, inverse_rate);
        let mut first_executor = ProofExternalMemoryExecutor::new(first_plan);
        let mut storage = RetainedOracleTestStorage::default();
        let mut cancelled_writer = StreamingPlainAggregateRetainedOracleWriter::new(
            descriptor,
            variable_count,
            folding_factor,
            inverse_rate,
        )
        .expect("cancelled retained oracle writer");
        assert_eq!(
            cancelled_writer
                .poll(
                    PolyView::Scalar(&polynomial),
                    &mut first_executor,
                    &mut storage,
                )
                .expect("begin cancelled writer"),
            StreamingPlainAggregateRetainedOracleWritePoll::StorageTransactionCompleted
        );
        assert_eq!(
            cancelled_writer
                .poll(
                    PolyView::Scalar(&polynomial),
                    &mut first_executor,
                    &mut storage,
                )
                .expect("prepare cancelled writer stripe"),
            StreamingPlainAggregateRetainedOracleWritePoll::ArithmeticStepCompleted
        );
        drop(cancelled_writer);
        first_executor
            .cancel(&mut storage)
            .expect("cancel retained oracle storage");
        assert!(storage.objects.is_empty());

        let (_, replay_plan) =
            retained_oracle_fixture(variable_count, folding_factor, inverse_rate);
        let mut replay_executor = ProofExternalMemoryExecutor::new(replay_plan);
        write_retained_oracle(
            &polynomial,
            descriptor,
            variable_count,
            folding_factor,
            inverse_rate,
            &mut replay_executor,
            &mut storage,
        );
        assert_eq!(
            storage
                .objects
                .get(&descriptor.object)
                .expect("replayed retained oracle exists")
                .bytes
                .len(),
            usize::try_from(descriptor.exact_byte_length).expect("fixture byte length fits usize")
        );
        replay_executor
            .cancel(&mut storage)
            .expect("clean up replayed retained oracle");
        assert!(storage.objects.is_empty());
    }

    #[test]
    fn cancelled_retained_commitment_cleans_storage_and_allows_a_fresh_attempt() {
        let table_variable_count = 7;
        let table_width = 4;
        let variable_count = table_variable_count + 2;
        let messages = deterministic_messages(table_variable_count, table_width);
        let pcs = plain_aggregate_pcs_with_parameters(variable_count, 2, 3)
            .expect("plain WHIR configuration");
        let make_move_only_witness = || {
            let ordinary_witness = AggregateLayout::new_witness(
                vec![Table::new(messages.clone())],
                pcs.round_folding_factor(0),
            );
            let interleaved_polynomial = ordinary_witness.poly().clone();
            drop(ordinary_witness);
            Witness::from_interleaved_poly(
                vec![TableShape::new(table_variable_count, table_width)],
                pcs.round_folding_factor(0),
                interleaved_polynomial,
            )
            .expect("move-only retained witness")
        };
        let (retained_oracles, first_plan) = retained_oracle_catalog_fixture(&pcs);
        let mut storage = RetainedOracleTestStorage::default();

        let mut first_executor = ProofExternalMemoryExecutor::new(first_plan);
        let mut first_challenger = plain_aggregate_challenger(&pcs, b"cancelled retained attempt");
        let mut cancelled_generation = StreamingPlainAggregateRetainedCommitmentGeneration::new(
            &pcs,
            make_move_only_witness(),
            retained_oracles.clone(),
        )
        .expect("cancelled retained commitment generation");
        let mut first_commitment_was_observed = false;
        for _ in 0..MAXIMUM_RETAINED_STATE_MACHINE_TEST_POLL_COUNT {
            match cancelled_generation
                .poll(&mut first_challenger, &mut first_executor, &mut storage)
                .expect("advance cancelled retained commitment")
            {
                StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted
                | StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted => {}
                StreamingPlainAggregateRetainedCommitmentPoll::CommitmentObserved(_) => {
                    first_commitment_was_observed = true;
                    break;
                }
                StreamingPlainAggregateRetainedCommitmentPoll::Complete(_) => {
                    panic!("retained commitment completed before opening preparation")
                }
            }
        }
        assert!(first_commitment_was_observed);
        assert!(!storage.objects.is_empty());
        cancelled_generation
            .cancel(&mut first_executor, &mut storage)
            .expect("cancel retained commitment");
        assert!(storage.objects.is_empty());
        assert!(!storage.transaction_active);

        let (_, fresh_plan) = retained_oracle_catalog_fixture(&pcs);
        let mut fresh_executor = ProofExternalMemoryExecutor::new(fresh_plan);
        let mut fresh_challenger = plain_aggregate_challenger(&pcs, b"fresh retained attempt");
        let mut fresh_generation = StreamingPlainAggregateRetainedCommitmentGeneration::new(
            &pcs,
            make_move_only_witness(),
            retained_oracles,
        )
        .expect("fresh retained commitment generation");
        let mut fresh_commitment_was_observed = false;
        let mut fresh_commitment_output = None;
        let points = [Point::new(vec![ChallengeField::TWO; table_variable_count])];
        let requested_columns = [vec![0]];
        for _ in 0..MAXIMUM_RETAINED_STATE_MACHINE_TEST_POLL_COUNT {
            match fresh_generation
                .poll(&mut fresh_challenger, &mut fresh_executor, &mut storage)
                .expect("advance fresh retained commitment")
            {
                StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted
                | StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted => {}
                StreamingPlainAggregateRetainedCommitmentPoll::CommitmentObserved(_) => {
                    assert!(!fresh_commitment_was_observed);
                    fresh_commitment_was_observed = true;
                    fresh_generation
                        .prepare_openings(&points, &requested_columns, &mut fresh_challenger)
                        .expect("prepare fresh retained openings");
                }
                StreamingPlainAggregateRetainedCommitmentPoll::Complete(output) => {
                    fresh_commitment_output = Some(output);
                    break;
                }
            }
        }
        assert!(fresh_commitment_was_observed);
        let fresh_commitment_output = fresh_commitment_output
            .expect("fresh retained commitment completes within the bounded poll count");
        let mut cancelled_proof_generation = StreamingPlainAggregateRetainedProofGeneration::new(
            fresh_commitment_output.commitment,
            fresh_commitment_output.prover_data,
        )
        .expect("fresh retained proof generation");
        let mut proof_storage_boundary_was_reached = false;
        for _ in 0..MAXIMUM_RETAINED_STATE_MACHINE_TEST_POLL_COUNT {
            match cancelled_proof_generation
                .poll(&mut fresh_challenger, &mut fresh_executor, &mut storage)
                .expect("advance retained proof before cancellation")
            {
                StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(_) => {}
                StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(_) => {
                    proof_storage_boundary_was_reached = true;
                    break;
                }
                StreamingPlainAggregateRetainedProofPoll::Complete(_) => {
                    panic!("retained proof completed before its first storage boundary")
                }
            }
        }
        assert!(proof_storage_boundary_was_reached);
        cancelled_proof_generation
            .cancel(&mut fresh_executor, &mut storage)
            .expect("cancel fresh retained proof");
        assert!(storage.objects.is_empty());
        assert!(!storage.transaction_active);
    }

    #[test]
    fn bounded_prover_matches_upstream_canonical_bytes() {
        let table_variable_count = 10;
        let table_width = 4;
        let variable_count = table_variable_count + 2;
        let messages = deterministic_messages(table_variable_count, table_width);
        let points = vec![
            Point::new(
                (0..table_variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 3 + 2))
                    .collect(),
            ),
            Point::new(
                (0..table_variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 11 + 5))
                    .collect(),
            ),
        ];
        let requested_columns = vec![vec![0, 2], vec![1, 3]];
        let pcs = plain_aggregate_pcs_with_parameters(variable_count, 2, 3)
            .expect("plain WHIR configuration");
        let statement = b"bounded plain WHIR parity";

        let mut upstream_challenger = plain_aggregate_challenger(&pcs, statement);
        let (upstream_commitment, upstream_data) =
            commit_plain_aggregate_batch(&pcs, messages.clone(), &mut upstream_challenger);
        let upstream_proof = open_plain_aggregate_batches_at_points(
            &pcs,
            upstream_data,
            &points,
            &requested_columns,
            &mut upstream_challenger,
        );

        let witness =
            AggregateLayout::new_witness(vec![Table::new(messages)], pcs.round_folding_factor(0));
        let initial_polynomial = witness.poly().clone();
        let mut bounded_challenger = plain_aggregate_challenger(&pcs, statement);
        let (bounded_commitment, bounded_data) =
            commit_streaming_plain_aggregate(&pcs, witness, &mut bounded_challenger)
                .expect("bounded commitment");
        let bounded_proof = open_streaming_plain_aggregate_batches_at_points(
            StreamingPlainAggregateOpeningRequest::new(
                &pcs,
                &bounded_commitment,
                &points,
                &requested_columns,
            ),
            bounded_data,
            &mut bounded_challenger,
            || Ok(initial_polynomial.clone()),
        )
        .expect("bounded proof");

        assert_eq!(bounded_commitment, upstream_commitment);
        let upstream_wire =
            encode_plain_whir_batch_proof(&pcs, &upstream_proof, &[2, 2], table_width)
                .expect("encode upstream proof");
        let bounded_wire =
            encode_plain_whir_batch_proof(&pcs, &bounded_proof, &[2, 2], table_width)
                .expect("encode bounded proof");
        assert_eq!(bounded_wire, upstream_wire);

        let mut verifier_challenger = plain_aggregate_challenger(&pcs, statement);
        verify_plain_aggregate_batches_at_points(
            &pcs,
            &bounded_commitment,
            &bounded_proof,
            &points,
            table_variable_count,
            table_width,
            &requested_columns,
            &mut verifier_challenger,
        )
        .expect("verify bounded proof");
    }

    #[test]
    fn retained_state_machine_matches_upstream_canonical_bytes() {
        let table_variable_count = 7;
        let table_width = 4;
        let variable_count = table_variable_count + 2;
        let messages = deterministic_messages(table_variable_count, table_width);
        let points = vec![
            Point::new(
                (0..table_variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 5 + 3))
                    .collect(),
            ),
            Point::new(
                (0..table_variable_count)
                    .map(|index| ChallengeField::from_u64(index as u64 * 13 + 7))
                    .collect(),
            ),
        ];
        let requested_columns = vec![vec![0, 2], vec![1, 3]];
        let pcs = plain_aggregate_pcs_with_parameters(variable_count, 2, 3)
            .expect("plain WHIR configuration");
        let statement = b"retained plain WHIR parity";

        let mut upstream_challenger = plain_aggregate_challenger(&pcs, statement);
        let (upstream_commitment, upstream_data) =
            commit_plain_aggregate_batch(&pcs, messages.clone(), &mut upstream_challenger);
        let upstream_proof = open_plain_aggregate_batches_at_points(
            &pcs,
            upstream_data,
            &points,
            &requested_columns,
            &mut upstream_challenger,
        );

        let ordinary_witness =
            AggregateLayout::new_witness(vec![Table::new(messages)], pcs.round_folding_factor(0));
        let interleaved_polynomial = ordinary_witness.poly().clone();
        drop(ordinary_witness);
        let witness = Witness::from_interleaved_poly(
            vec![TableShape::new(table_variable_count, table_width)],
            pcs.round_folding_factor(0),
            interleaved_polynomial,
        )
        .expect("move-only retained witness");
        let (retained_oracles, plan) = retained_oracle_catalog_fixture(&pcs);
        let mut executor = ProofExternalMemoryExecutor::new(plan);
        let mut storage = RetainedOracleTestStorage::default();
        let mut retained_challenger = plain_aggregate_challenger(&pcs, statement);
        let mut commitment_generation = StreamingPlainAggregateRetainedCommitmentGeneration::new(
            &pcs,
            witness,
            retained_oracles,
        )
        .expect("retained commitment generation");

        let mut commitment_output = None;
        let mut commitment_was_observed = false;
        for _ in 0..MAXIMUM_RETAINED_STATE_MACHINE_TEST_POLL_COUNT {
            match commitment_generation
                .poll(&mut retained_challenger, &mut executor, &mut storage)
                .expect("advance retained commitment")
            {
                StreamingPlainAggregateRetainedCommitmentPoll::ArithmeticStepCompleted
                | StreamingPlainAggregateRetainedCommitmentPoll::StorageTransactionCompleted => {}
                StreamingPlainAggregateRetainedCommitmentPoll::CommitmentObserved(commitment) => {
                    assert!(!commitment_was_observed);
                    commitment_was_observed = true;
                    assert_eq!(commitment, upstream_commitment);
                    assert_eq!(executor.current_step(), 0);
                    assert_eq!(storage.objects.len(), 1);
                    assert!(matches!(
                        commitment_generation.poll(
                            &mut retained_challenger,
                            &mut executor,
                            &mut storage
                        ),
                        Err(StreamingPlainAggregateRetainedOracleError::Geometry(message))
                            if message.contains("waiting for source-dependent opening preparation")
                    ));
                    commitment_generation
                        .prepare_openings(&points, &requested_columns, &mut retained_challenger)
                        .expect("prepare retained openings before source release");
                }
                StreamingPlainAggregateRetainedCommitmentPoll::Complete(output) => {
                    commitment_output = Some(output);
                    break;
                }
            }
        }
        assert!(commitment_was_observed);
        let commitment_output =
            commitment_output.expect("retained commitment completes within the bounded poll count");
        assert_eq!(executor.current_step(), 1);

        let retained_commitment = commitment_output.commitment.clone();
        let mut proof_generation = StreamingPlainAggregateRetainedProofGeneration::new(
            commitment_output.commitment,
            commitment_output.prover_data,
        )
        .expect("retained proof generation");
        let mut retained_proof = None;
        for _ in 0..MAXIMUM_RETAINED_STATE_MACHINE_TEST_POLL_COUNT {
            match proof_generation
                .poll(&mut retained_challenger, &mut executor, &mut storage)
                .expect("advance retained proof")
            {
                StreamingPlainAggregateRetainedProofPoll::ArithmeticStepCompleted(_)
                | StreamingPlainAggregateRetainedProofPoll::StorageTransactionCompleted(_) => {}
                StreamingPlainAggregateRetainedProofPoll::Complete(proof) => {
                    retained_proof = Some(proof);
                    break;
                }
            }
        }
        let retained_proof =
            retained_proof.expect("retained proof completes within the bounded poll count");
        executor.finish().expect("finish retained proof storage");
        assert!(storage.objects.is_empty());

        let upstream_wire =
            encode_plain_whir_batch_proof(&pcs, &upstream_proof, &[2, 2], table_width)
                .expect("encode upstream proof");
        let retained_wire =
            encode_plain_whir_batch_proof(&pcs, &retained_proof, &[2, 2], table_width)
                .expect("encode retained proof");
        assert_eq!(retained_wire, upstream_wire);

        let mut verifier_challenger = plain_aggregate_challenger(&pcs, statement);
        verify_plain_aggregate_batches_at_points(
            &pcs,
            &retained_commitment,
            &retained_proof,
            &points,
            table_variable_count,
            table_width,
            &requested_columns,
            &mut verifier_challenger,
        )
        .expect("verify retained proof");
    }

    #[test]
    fn recomputed_initial_polynomial_is_bound_to_the_commitment() {
        let table_variable_count = 6;
        let table_width = 4;
        let variable_count = table_variable_count + 2;
        let messages = deterministic_messages(table_variable_count, table_width);
        let pcs = plain_aggregate_pcs_with_parameters(variable_count, 2, 3)
            .expect("plain WHIR configuration");
        let witness =
            AggregateLayout::new_witness(vec![Table::new(messages)], pcs.round_folding_factor(0));
        let mut challenger = plain_aggregate_challenger(&pcs, b"changed initial source");
        let (commitment, prover_data) =
            commit_streaming_plain_aggregate(&pcs, witness, &mut challenger)
                .expect("bounded commitment");
        let point = Point::new(vec![ChallengeField::TWO; table_variable_count]);
        let changed = Poly::new(vec![ChallengeField::ONE; 1_usize << variable_count]);
        let points = [point];
        let requested_columns = [vec![0]];
        let result = open_streaming_plain_aggregate_batches_at_points(
            StreamingPlainAggregateOpeningRequest::new(
                &pcs,
                &commitment,
                &points,
                &requested_columns,
            ),
            prover_data,
            &mut challenger,
            || Ok(changed.clone()),
        );
        let error = match result {
            Ok(_) => panic!("changed recomputed source must fail"),
            Err(error) => error,
        };
        assert!(error.contains("wrong commitment"));
    }

    #[test]
    fn stripe_streaming_bounds_live_leaf_hash_states() {
        let exact_initial_height = 1_usize << 20;
        let full_leaf_state_byte_length =
            exact_initial_height * SHAKE256_STATE_WORD_LENGTH * core::mem::size_of::<u64>();
        let striped_leaf_state_byte_length = MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT
            * SHAKE256_STATE_WORD_LENGTH
            * core::mem::size_of::<u64>();
        let encoded_column_byte_length =
            exact_initial_height * core::mem::size_of::<ChallengeField>();
        assert_eq!(
            exact_initial_height / MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT,
            32
        );
        assert_eq!(striped_leaf_state_byte_length, 6_553_600);
        assert!(striped_leaf_state_byte_length < full_leaf_state_byte_length / 16);
        assert!(striped_leaf_state_byte_length + encoded_column_byte_length < 64 * 1_048_576);
    }

    #[test]
    fn selected_move_only_witness_has_bounded_static_liveness() {
        let selected_variable_count =
            super::super::construction_plan::RowCodeWhirSelectedParameters::selected()
                .polynomial_commitment_variable_count;
        let challenge_field_byte_length = core::mem::size_of::<ChallengeField>();
        let stacked_witness_byte_length = (1_usize << selected_variable_count)
            .checked_mul(challenge_field_byte_length)
            .expect("selected witness byte length");
        let source_column_byte_length = (1_usize << (selected_variable_count - 2))
            .checked_mul(challenge_field_byte_length)
            .expect("selected source-column byte length");
        let encoded_column_byte_length = (1_usize << (selected_variable_count - 1))
            .checked_mul(challenge_field_byte_length)
            .expect("selected encoded-column byte length");
        let stripe_byte_length = MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT
            .checked_mul(challenge_field_byte_length)
            .expect("selected stripe byte length");
        let leaf_state_byte_length = MAXIMUM_STREAMING_LEAF_HASHER_ROW_COUNT
            .checked_mul(SHAKE256_STATE_WORD_LENGTH)
            .and_then(|word_count| word_count.checked_mul(core::mem::size_of::<u64>()))
            .expect("selected leaf-state byte length");

        assert_eq!(challenge_field_byte_length, 40);
        assert_eq!(stacked_witness_byte_length, 80 * 1_048_576);
        assert_eq!(source_column_byte_length, 20 * 1_048_576);
        assert_eq!(encoded_column_byte_length, 40 * 1_048_576);
        let duplicated_table_layout_byte_length = stacked_witness_byte_length
            .checked_mul(2)
            .expect("duplicated witness byte length");
        let move_only_opening_peak = stacked_witness_byte_length + source_column_byte_length;
        let retained_commitment_peak = stacked_witness_byte_length
            + encoded_column_byte_length
            + stripe_byte_length.max(leaf_state_byte_length);
        assert!(move_only_opening_peak < duplicated_table_layout_byte_length);
        assert!(retained_commitment_peak < 128 * 1_048_576);
    }
}
