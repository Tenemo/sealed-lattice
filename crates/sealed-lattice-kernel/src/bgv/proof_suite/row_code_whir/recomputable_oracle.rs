//! Recomputable aggregate-wide WHIR oracle commitments and openings.
//!
//! Only unencoded source coefficients are retained. Each commitment or query
//! pass regenerates the eight encoded columns once per bounded row stripe,
//! updates a 64-byte leaf chaining value per stripe row, and keeps only the
//! logarithmic Merkle frontier and explicitly requested rows. No complete
//! encoded codeword or Merkle tree is stored in WebAssembly or browser
//! external memory.

use std::collections::BTreeMap;

use p3_field::PrimeCharacteristicRing;
use p3_sumcheck::product_polynomial::PolyView;
use p3_symmetric::{MerkleCap, PseudoCompressionFunction};

use super::aggregate_source_storage::{
    AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH, AggregateSourceTable, decode_source_values,
};
use super::aggregate_wide_pcs::AggregateWideCommitment;
use super::bounded_dft::BoundedRadix2Dft;
use super::oracle_geometry::logical_column_selector_index;
use super::{
    ChallengeField, ColumnStreamableLeafHasher, ColumnStreamableLeafState, DomainSeparatedShake256,
    MERKLE_DIGEST_WORD_LENGTH, NodeCompressor, ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN,
    ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
};
use crate::bgv::proof_suite::external_polynomial::ExternalPolynomialVector;
use crate::bgv::proof_suite::{
    ProofExternalMemory, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
};

type MerkleDigest = [u64; MERKLE_DIGEST_WORD_LENGTH];

const ENCODED_ORACLE_WIDTH: usize = 8;
const MAXIMUM_ARITHMETIC_ROWS_PER_POLL: usize = 1 << 15;
pub(super) const AGGREGATE_ORACLE_LEAF_STATE_STRIPE_ROW_COUNT: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RecomputableOracleSource {
    ExternalTable(AggregateSourceTable),
    ExternalPolynomial(ExternalPolynomialVector),
    ResidentPolynomial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecomputableOracleStage {
    PrepareStripe,
    PrepareColumn,
    LoadSource,
    AppendRandomness,
    Transform,
    AbsorbColumn,
    BuildMerkle,
    Finish,
    Complete,
}

pub(super) struct RecomputableOracleOutput {
    pub(super) root: AggregateWideCommitment,
    pub(super) rows: Vec<Vec<ChallengeField>>,
    pub(super) paths: Vec<Vec<MerkleDigest>>,
}

pub(super) enum RecomputableOraclePoll {
    ArithmeticStepCompleted,
    StorageTransactionCompleted,
    Complete(RecomputableOracleOutput),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RecomputableOracleError<StorageError> {
    Geometry(String),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
}

impl<StorageError> From<ProofExternalMemoryExecutorError<StorageError>>
    for RecomputableOracleError<StorageError>
{
    fn from(error: ProofExternalMemoryExecutorError<StorageError>) -> Self {
        Self::Storage(error)
    }
}

/// One root-building or query-opening pass over a retained source oracle.
pub(super) struct RecomputableOraclePass {
    source: RecomputableOracleSource,
    source_variable_count: usize,
    source_height: usize,
    encoded_height: usize,
    randomness_rows: usize,
    randomness: Vec<ChallengeField>,
    query_indices: Vec<usize>,
    opened_rows: Vec<Vec<ChallengeField>>,
    leaf_hasher: ColumnStreamableLeafHasher,
    initial_leaf_state: ColumnStreamableLeafState,
    leaf_states: Vec<ColumnStreamableLeafState>,
    merkle_builder: Option<StreamingMerkleBuilder>,
    current_column_index: usize,
    current_stripe_start: usize,
    current_stripe_end: usize,
    maximum_stripe_row_count: usize,
    current_table_column_index: usize,
    current_source_offset: usize,
    current_absorb_offset: usize,
    encoded_values: Option<Vec<ChallengeField>>,
    dft: Option<BoundedRadix2Dft>,
    encoded_storage_chunk: Vec<u8>,
    decoded_storage_chunk: Vec<ChallengeField>,
    stage: RecomputableOracleStage,
}

impl RecomputableOraclePass {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        source: RecomputableOracleSource,
        source_variable_count: usize,
        folding_factor: usize,
        inverse_rate: usize,
        randomness: Vec<ChallengeField>,
        query_indices: &[usize],
    ) -> Result<Self, String> {
        Self::new_with_maximum_stripe_row_count(
            source,
            source_variable_count,
            folding_factor,
            inverse_rate,
            randomness,
            query_indices,
            AGGREGATE_ORACLE_LEAF_STATE_STRIPE_ROW_COUNT,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_maximum_stripe_row_count(
        source: RecomputableOracleSource,
        source_variable_count: usize,
        folding_factor: usize,
        inverse_rate: usize,
        randomness: Vec<ChallengeField>,
        query_indices: &[usize],
        maximum_stripe_row_count: usize,
    ) -> Result<Self, String> {
        if folding_factor != ENCODED_ORACLE_WIDTH.ilog2() as usize
            || folding_factor > source_variable_count
            || inverse_rate == 0
            || !inverse_rate.is_power_of_two()
            || maximum_stripe_row_count == 0
            || !maximum_stripe_row_count.is_power_of_two()
        {
            return Err("recomputable oracle has an unsupported encoding geometry".to_owned());
        }
        let source_height = 1_usize
            .checked_shl((source_variable_count - folding_factor) as u32)
            .ok_or_else(|| "recomputable oracle source height overflowed".to_owned())?;
        let encoded_height = source_height
            .checked_mul(inverse_rate)
            .ok_or_else(|| "recomputable oracle encoded height overflowed".to_owned())?;
        if !randomness.len().is_multiple_of(ENCODED_ORACLE_WIDTH)
            || query_indices.windows(2).any(|pair| pair[0] >= pair[1])
            || query_indices
                .last()
                .is_some_and(|index| *index >= encoded_height)
        {
            return Err("recomputable oracle has invalid randomness or queries".to_owned());
        }
        let randomness_rows = randomness.len() / ENCODED_ORACLE_WIDTH;
        if source_height
            .checked_add(randomness_rows)
            .is_none_or(|occupied| occupied > encoded_height)
        {
            return Err("recomputable oracle randomness exceeds the encoded column".to_owned());
        }
        match &source {
            RecomputableOracleSource::ExternalTable(table) => {
                if table.stacked_variable_count() != source_variable_count
                    || table.folding_factor() != folding_factor
                    || source_height % table.table_width() != 0
                {
                    return Err("recomputable initial table does not match the oracle".to_owned());
                }
            }
            RecomputableOracleSource::ExternalPolynomial(vector) => {
                if vector.element_count() != (1_usize << source_variable_count) {
                    return Err(
                        "recomputable residual polynomial does not match the oracle".to_owned()
                    );
                }
            }
            RecomputableOracleSource::ResidentPolynomial => {}
        }

        let leaf_hasher = ColumnStreamableLeafHasher::new(DomainSeparatedShake256 {
            domain: ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN,
        });
        let initial_leaf_state = leaf_hasher.initial_state(ENCODED_ORACLE_WIDTH);
        let capture_targets = if query_indices.is_empty() {
            None
        } else {
            Some(merkle_capture_targets(encoded_height, query_indices))
        };
        Ok(Self {
            source,
            source_variable_count,
            source_height,
            encoded_height,
            randomness_rows,
            randomness,
            query_indices: query_indices.to_vec(),
            opened_rows: vec![
                vec![ChallengeField::ZERO; ENCODED_ORACLE_WIDTH];
                query_indices.len()
            ],
            leaf_hasher,
            initial_leaf_state,
            leaf_states: Vec::with_capacity(maximum_stripe_row_count.min(encoded_height)),
            merkle_builder: Some(StreamingMerkleBuilder::new(
                encoded_height,
                capture_targets,
            )?),
            current_column_index: 0,
            current_stripe_start: 0,
            current_stripe_end: maximum_stripe_row_count.min(encoded_height),
            maximum_stripe_row_count,
            current_table_column_index: 0,
            current_source_offset: 0,
            current_absorb_offset: 0,
            encoded_values: None,
            dft: None,
            encoded_storage_chunk: Vec::new(),
            decoded_storage_chunk: Vec::new(),
            stage: RecomputableOracleStage::PrepareStripe,
        })
    }

    pub(super) fn poll_resident(
        &mut self,
        source: PolyView<'_, ChallengeField, ChallengeField>,
    ) -> Result<RecomputableOraclePoll, String> {
        if self.source != RecomputableOracleSource::ResidentPolynomial
            || source.num_variables() != self.source_variable_count
        {
            return Err("resident recomputable oracle source has the wrong shape".to_owned());
        }
        if self.stage == RecomputableOracleStage::LoadSource {
            let element_count = maximum_source_elements_per_poll().min(
                self.source_height
                    .saturating_sub(self.current_source_offset),
            );
            if element_count == 0 {
                return Err("resident recomputable oracle source ended early".to_owned());
            }
            let source_start = self
                .current_column_index
                .checked_mul(self.source_height)
                .and_then(|start| start.checked_add(self.current_source_offset))
                .ok_or_else(|| "resident recomputable oracle range overflowed".to_owned())?;
            let destination = self
                .encoded_values
                .as_mut()
                .and_then(|values| {
                    values.get_mut(
                        self.current_source_offset..self.current_source_offset + element_count,
                    )
                })
                .ok_or_else(|| "resident recomputable oracle destination is missing".to_owned())?;
            source
                .copy_logical_range_into(source_start, element_count, destination)
                .map_err(|error| format!("copy resident recomputable oracle source: {error:?}"))?;
            self.current_source_offset += element_count;
            if self.current_source_offset == self.source_height {
                self.stage = RecomputableOracleStage::AppendRandomness;
            }
            return Ok(RecomputableOraclePoll::ArithmeticStepCompleted);
        }
        self.poll_arithmetic::<core::convert::Infallible>()
            .map_err(|error| match error {
                RecomputableOracleError::Geometry(message) => message,
                RecomputableOracleError::Storage(ProofExternalMemoryExecutorError::Execution(
                    error,
                )) => format!("resident recomputable oracle execution: {error:?}"),
                RecomputableOracleError::Storage(
                    ProofExternalMemoryExecutorError::Storage(never)
                    | ProofExternalMemoryExecutorError::StorageCommit(never),
                ) => match never {},
                RecomputableOracleError::Storage(
                    ProofExternalMemoryExecutorError::StorageAbort {
                        operation_error: never,
                        ..
                    },
                ) => match never {},
            })
    }

    pub(super) fn poll_external<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<RecomputableOraclePoll, RecomputableOracleError<Storage::Error>> {
        if self.source == RecomputableOracleSource::ResidentPolynomial {
            return Err(RecomputableOracleError::Geometry(
                "external recomputable oracle poll received a resident source".to_owned(),
            ));
        }
        if self.stage == RecomputableOracleStage::LoadSource {
            self.load_external_source(executor, storage)?;
            return Ok(RecomputableOraclePoll::StorageTransactionCompleted);
        }
        self.poll_arithmetic()
    }

    fn poll_arithmetic<StorageError>(
        &mut self,
    ) -> Result<RecomputableOraclePoll, RecomputableOracleError<StorageError>> {
        match self.stage {
            RecomputableOracleStage::PrepareStripe => {
                if self.current_stripe_start >= self.encoded_height
                    || self.current_stripe_end <= self.current_stripe_start
                    || self.current_stripe_end > self.encoded_height
                    || !self.leaf_states.is_empty()
                    || self.encoded_values.is_some()
                    || self.dft.is_some()
                {
                    return Err(Self::geometry(
                        "recomputable oracle stripe state is invalid",
                    ));
                }
                self.leaf_states.resize(
                    self.current_stripe_end - self.current_stripe_start,
                    self.initial_leaf_state,
                );
                self.current_column_index = 0;
                self.stage = RecomputableOracleStage::PrepareColumn;
                Ok(RecomputableOraclePoll::ArithmeticStepCompleted)
            }
            RecomputableOracleStage::PrepareColumn => {
                if self.current_column_index >= ENCODED_ORACLE_WIDTH
                    || self.encoded_values.is_some()
                    || self.dft.is_some()
                {
                    return Err(Self::geometry(
                        "recomputable oracle column state is invalid",
                    ));
                }
                self.encoded_values = Some(ChallengeField::zero_vec(self.encoded_height));
                self.current_table_column_index = 0;
                self.current_source_offset = 0;
                self.current_absorb_offset = self.current_stripe_start;
                self.stage = RecomputableOracleStage::LoadSource;
                Ok(RecomputableOraclePoll::ArithmeticStepCompleted)
            }
            RecomputableOracleStage::LoadSource => Err(Self::geometry(
                "recomputable oracle source requires the matching load poll",
            )),
            RecomputableOracleStage::AppendRandomness => {
                let randomness_start = self
                    .current_column_index
                    .checked_mul(self.randomness_rows)
                    .ok_or_else(|| Self::geometry("recomputable randomness range overflowed"))?;
                let randomness_end = randomness_start
                    .checked_add(self.randomness_rows)
                    .ok_or_else(|| Self::geometry("recomputable randomness range overflowed"))?;
                self.encoded_values
                    .as_mut()
                    .and_then(|values| {
                        values
                            .get_mut(self.source_height..self.source_height + self.randomness_rows)
                    })
                    .ok_or_else(|| Self::geometry("recomputable randomness destination is absent"))?
                    .copy_from_slice(&self.randomness[randomness_start..randomness_end]);
                self.dft = Some(
                    BoundedRadix2Dft::new(
                        self.encoded_values
                            .take()
                            .ok_or_else(|| Self::geometry("recomputable DFT input is absent"))?,
                    )
                    .map_err(Self::geometry)?,
                );
                self.stage = RecomputableOracleStage::Transform;
                Ok(RecomputableOraclePoll::ArithmeticStepCompleted)
            }
            RecomputableOracleStage::Transform => {
                let complete = self
                    .dft
                    .as_mut()
                    .ok_or_else(|| Self::geometry("recomputable DFT state is absent"))?
                    .poll()
                    .map_err(Self::geometry)?;
                if complete {
                    self.encoded_values = Some(
                        self.dft
                            .take()
                            .ok_or_else(|| Self::geometry("recomputable DFT state is absent"))?
                            .into_values()
                            .map_err(Self::geometry)?,
                    );
                    self.stage = RecomputableOracleStage::AbsorbColumn;
                }
                Ok(RecomputableOraclePoll::ArithmeticStepCompleted)
            }
            RecomputableOracleStage::AbsorbColumn => {
                let end = self
                    .current_absorb_offset
                    .saturating_add(MAXIMUM_ARITHMETIC_ROWS_PER_POLL)
                    .min(self.current_stripe_end);
                let encoded_values = self
                    .encoded_values
                    .as_ref()
                    .ok_or_else(|| Self::geometry("recomputable encoded column is absent"))?;
                for (row_index, encoded_value) in encoded_values
                    .iter()
                    .copied()
                    .enumerate()
                    .take(end)
                    .skip(self.current_absorb_offset)
                {
                    let stripe_row_index = row_index - self.current_stripe_start;
                    self.leaf_states[stripe_row_index] = self.leaf_hasher.absorb_column(
                        self.leaf_states[stripe_row_index],
                        self.current_column_index,
                        encoded_value,
                    );
                }
                for (query_ordinal, query_index) in self.query_indices.iter().copied().enumerate() {
                    if (self.current_absorb_offset..end).contains(&query_index) {
                        self.opened_rows[query_ordinal][self.current_column_index] =
                            encoded_values[query_index];
                    }
                }
                self.current_absorb_offset = end;
                if end == self.current_stripe_end {
                    let mut values = self
                        .encoded_values
                        .take()
                        .ok_or_else(|| Self::geometry("recomputable encoded column is absent"))?;
                    values.fill(ChallengeField::ZERO);
                    self.current_column_index += 1;
                    self.stage = if self.current_column_index == ENCODED_ORACLE_WIDTH {
                        self.current_source_offset = 0;
                        RecomputableOracleStage::BuildMerkle
                    } else {
                        RecomputableOracleStage::PrepareColumn
                    };
                }
                Ok(RecomputableOraclePoll::ArithmeticStepCompleted)
            }
            RecomputableOracleStage::BuildMerkle => {
                let end = self
                    .current_source_offset
                    .saturating_add(MAXIMUM_ARITHMETIC_ROWS_PER_POLL)
                    .min(self.leaf_states.len());
                let merkle_builder = self
                    .merkle_builder
                    .as_mut()
                    .ok_or_else(|| Self::geometry("recomputable Merkle builder is absent"))?;
                for row_index in self.current_source_offset..end {
                    let digest = self
                        .leaf_hasher
                        .finish_leaf(ENCODED_ORACLE_WIDTH, self.leaf_states[row_index]);
                    merkle_builder.push(digest).map_err(Self::geometry)?;
                    self.leaf_states[row_index] = ColumnStreamableLeafState::ZERO;
                }
                self.current_source_offset = end;
                if end == self.leaf_states.len() {
                    self.leaf_states.clear();
                    self.current_stripe_start = self.current_stripe_end;
                    if self.current_stripe_start == self.encoded_height {
                        self.stage = RecomputableOracleStage::Finish;
                    } else {
                        self.current_stripe_end = self
                            .current_stripe_start
                            .saturating_add(self.maximum_stripe_row_count)
                            .min(self.encoded_height);
                        self.stage = RecomputableOracleStage::PrepareStripe;
                    }
                }
                Ok(RecomputableOraclePoll::ArithmeticStepCompleted)
            }
            RecomputableOracleStage::Finish => {
                let (root, paths) = self
                    .merkle_builder
                    .take()
                    .ok_or_else(|| Self::geometry("recomputable Merkle builder is absent"))?
                    .finish()
                    .map_err(Self::geometry)?;
                self.randomness.fill(ChallengeField::ZERO);
                self.stage = RecomputableOracleStage::Complete;
                Ok(RecomputableOraclePoll::Complete(RecomputableOracleOutput {
                    root: MerkleCap::new(vec![root]),
                    rows: core::mem::take(&mut self.opened_rows),
                    paths: paths.unwrap_or_default(),
                }))
            }
            RecomputableOracleStage::Complete => Err(Self::geometry(
                "recomputable oracle pass was polled after completion",
            )),
        }
    }

    fn load_external_source<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<(), RecomputableOracleError<Storage::Error>> {
        let maximum_element_count = usize::try_from(executor.maximum_chunk_byte_length())
            .ok()
            .and_then(|bytes| bytes.checked_div(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH))
            .filter(|count| *count > 0)
            .ok_or_else(|| Self::geometry("recomputable source chunk is invalid"))?;
        let (vector, element_offset, element_count, scatter_stride, scatter_column) =
            match &self.source {
                RecomputableOracleSource::ExternalPolynomial(vector) => {
                    let element_count = maximum_element_count.min(
                        self.source_height
                            .saturating_sub(self.current_source_offset),
                    );
                    let element_offset = self
                        .current_column_index
                        .checked_mul(self.source_height)
                        .and_then(|offset| offset.checked_add(self.current_source_offset))
                        .ok_or_else(|| Self::geometry("recomputable source range overflowed"))?;
                    (*vector, element_offset, element_count, 1, 0)
                }
                RecomputableOracleSource::ExternalTable(table) => {
                    let local_count = self.source_height / table.table_width();
                    let element_count = maximum_element_count
                        .min(local_count.saturating_sub(self.current_source_offset));
                    let element_offset = self
                        .current_column_index
                        .checked_mul(local_count)
                        .and_then(|offset| offset.checked_add(self.current_source_offset))
                        .ok_or_else(|| Self::geometry("recomputable table range overflowed"))?;
                    let vector = *table
                        .columns()
                        .get(self.current_table_column_index)
                        .ok_or_else(|| Self::geometry("recomputable table column is absent"))?;
                    let selector_index = logical_column_selector_index(
                        self.current_table_column_index,
                        table.table_width(),
                    )
                    .map_err(Self::geometry)?;
                    (
                        vector,
                        element_offset,
                        element_count,
                        table.table_width(),
                        selector_index,
                    )
                }
                RecomputableOracleSource::ResidentPolynomial => {
                    return Err(Self::geometry(
                        "external recomputable source unexpectedly became resident",
                    ));
                }
            };
        if element_count == 0 {
            return Err(Self::geometry("recomputable external source ended early"));
        }
        let byte_offset = element_offset
            .checked_mul(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or_else(|| Self::geometry("recomputable source byte offset overflowed"))?;
        let byte_length = element_count
            .checked_mul(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
            .ok_or_else(|| Self::geometry("recomputable source byte length overflowed"))?;
        self.encoded_storage_chunk.clear();
        self.encoded_storage_chunk.resize(byte_length, 0);
        executor.read_object_bytes(
            storage,
            vector.object(),
            byte_offset,
            &mut self.encoded_storage_chunk,
        )?;
        self.decoded_storage_chunk.clear();
        self.decoded_storage_chunk
            .resize(element_count, ChallengeField::ZERO);
        decode_source_values(&self.encoded_storage_chunk, &mut self.decoded_storage_chunk)
            .map_err(|error| {
                RecomputableOracleError::Storage(ProofExternalMemoryExecutorError::Execution(error))
            })?;
        let encoded_values = self
            .encoded_values
            .as_mut()
            .ok_or_else(|| Self::geometry("recomputable encoded destination is absent"))?;
        for (local_offset, value) in self.decoded_storage_chunk.iter().copied().enumerate() {
            let destination_index = self
                .current_source_offset
                .checked_add(local_offset)
                .and_then(|row| row.checked_mul(scatter_stride))
                .and_then(|index| index.checked_add(scatter_column))
                .ok_or_else(|| Self::geometry("recomputable source scatter overflowed"))?;
            *encoded_values
                .get_mut(destination_index)
                .ok_or_else(|| Self::geometry("recomputable source scatter is out of range"))? =
                value;
        }
        self.decoded_storage_chunk.fill(ChallengeField::ZERO);
        self.decoded_storage_chunk.clear();
        self.current_source_offset += element_count;
        let current_column_length = match &self.source {
            RecomputableOracleSource::ExternalTable(table) => {
                self.source_height / table.table_width()
            }
            RecomputableOracleSource::ExternalPolynomial(_) => self.source_height,
            RecomputableOracleSource::ResidentPolynomial => unreachable!(),
        };
        if self.current_source_offset == current_column_length {
            self.current_source_offset = 0;
            if let RecomputableOracleSource::ExternalTable(table) = &self.source {
                self.current_table_column_index += 1;
                if self.current_table_column_index < table.table_width() {
                    return Ok(());
                }
            }
            self.stage = RecomputableOracleStage::AppendRandomness;
        }
        Ok(())
    }

    fn geometry<StorageError>(message: impl Into<String>) -> RecomputableOracleError<StorageError> {
        RecomputableOracleError::Geometry(message.into())
    }
}

impl Drop for RecomputableOraclePass {
    fn drop(&mut self) {
        self.randomness.fill(ChallengeField::ZERO);
        self.leaf_states.fill(ColumnStreamableLeafState::ZERO);
        if let Some(values) = self.encoded_values.as_mut() {
            values.fill(ChallengeField::ZERO);
        }
        self.encoded_storage_chunk.fill(0);
        self.decoded_storage_chunk.fill(ChallengeField::ZERO);
        for row in &mut self.opened_rows {
            row.fill(ChallengeField::ZERO);
        }
    }
}

fn maximum_source_elements_per_poll() -> usize {
    (1 << 20) / AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH
}

pub(super) fn aggregate_oracle_leaf_state_stripe_count(
    encoded_height: usize,
) -> Result<usize, String> {
    if encoded_height == 0 || !encoded_height.is_power_of_two() {
        return Err("aggregate oracle encoded height is invalid".to_owned());
    }
    Ok(encoded_height.div_ceil(AGGREGATE_ORACLE_LEAF_STATE_STRIPE_ROW_COUNT))
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
            return Err("recomputable Merkle leaf count is not a power of two".to_owned());
        }
        let tree_depth = leaf_count.ilog2() as usize;
        if capture_targets
            .as_ref()
            .is_some_and(|targets| targets.len() != tree_depth)
        {
            return Err("recomputable Merkle capture depth is invalid".to_owned());
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
            compressor: NodeCompressor::new(DomainSeparatedShake256 {
                domain: ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
            }),
        })
    }

    fn push(&mut self, mut digest: MerkleDigest) -> Result<(), String> {
        if self.next_leaf_index >= self.leaf_count {
            return Err("recomputable Merkle builder received an extra leaf".to_owned());
        }
        let mut level = 0_usize;
        let mut node_index = self.next_leaf_index;
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
            return Err("recomputable Merkle builder ended early".to_owned());
        }
        let tree_depth = self.leaf_count.ilog2() as usize;
        let root = self
            .frontier
            .last()
            .and_then(|root| *root)
            .ok_or_else(|| "recomputable Merkle root is absent".to_owned())?;
        if self.frontier[..tree_depth].iter().any(Option::is_some)
            || self
                .captured
                .as_ref()
                .is_some_and(|rows| rows.iter().flatten().any(|captured| !captured))
        {
            return Err("recomputable Merkle frontier is incomplete".to_owned());
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
    let Some(placements) = targets
        .get(level)
        .and_then(|level_targets| level_targets.get(&node_index))
    else {
        return Ok(());
    };
    for (query_ordinal, path_position) in placements {
        let was_captured = captured
            .get_mut(*query_ordinal)
            .and_then(|row| row.get_mut(*path_position))
            .ok_or_else(|| "recomputable Merkle capture coordinate is invalid".to_owned())?;
        if *was_captured {
            return Err("recomputable Merkle node was captured twice".to_owned());
        }
        paths[*query_ordinal][*path_position] = digest;
        *was_captured = true;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p3_commit::Mmcs;
    use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
    use p3_matrix::dense::RowMajorMatrix;

    use super::super::aggregate_source_storage::{AggregateSourceValues, AggregateSourceWriter};
    use super::super::oracle_geometry::interleaved_source_index;
    use super::*;
    use crate::bgv::proof_suite::external_memory::{
        ProofExternalMemoryObject, ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
        ProofExternalMemoryProtection, tests::TestStorage,
    };
    use crate::bgv::proof_suite::relation_plan::RelationColumnValueType;
    use crate::bgv::proof_suite::row_code_whir::{CommitmentScheme, LeafHasher};

    #[test]
    fn resident_striped_recomputation_matches_the_configured_mmcs_root_and_paths() {
        let source_variable_count = 7;
        let folding_factor = 3;
        let inverse_rate = 2;
        let source = (0..1_usize << source_variable_count)
            .map(|index| ChallengeField::from_u64((index as u64 + 3).pow(3)))
            .collect::<Vec<_>>();
        let randomness = (0..ENCODED_ORACLE_WIDTH * 2)
            .map(|index| ChallengeField::from_u64(1_000 + index as u64))
            .collect::<Vec<_>>();
        let query_indices = [0, 3, 17, 31];

        let source_height = 1 << (source_variable_count - folding_factor);
        let encoded_height = source_height * inverse_rate;
        let randomness_rows = randomness.len() / ENCODED_ORACLE_WIDTH;
        let mut matrix_values = vec![ChallengeField::ZERO; encoded_height * ENCODED_ORACLE_WIDTH];
        for column_index in 0..ENCODED_ORACLE_WIDTH {
            let mut column = vec![ChallengeField::ZERO; encoded_height];
            column[..source_height].copy_from_slice(
                &source[column_index * source_height..(column_index + 1) * source_height],
            );
            column[source_height..source_height + randomness_rows].copy_from_slice(
                &randomness[column_index * randomness_rows..(column_index + 1) * randomness_rows],
            );
            let column = Radix2Dit::<ChallengeField>::default().dft(column);
            for (row_index, value) in column.into_iter().enumerate() {
                matrix_values[row_index * ENCODED_ORACLE_WIDTH + column_index] = value;
            }
        }
        let mmcs = CommitmentScheme::new(
            LeafHasher::new(DomainSeparatedShake256 {
                domain: ROW_CODE_WHIR_AGGREGATE_LEAF_DOMAIN,
            }),
            NodeCompressor::new(DomainSeparatedShake256 {
                domain: ROW_CODE_WHIR_AGGREGATE_NODE_DOMAIN,
            }),
            0,
        );
        let matrix = RowMajorMatrix::new(matrix_values, ENCODED_ORACLE_WIDTH);
        let (expected_root, prover_data) = mmcs.commit(vec![matrix]);
        let expected_openings = query_indices
            .iter()
            .map(|index| mmcs.open_batch(*index, &prover_data))
            .collect::<Vec<_>>();

        let mut pass = RecomputableOraclePass::new_with_maximum_stripe_row_count(
            RecomputableOracleSource::ResidentPolynomial,
            source_variable_count,
            folding_factor,
            inverse_rate,
            randomness,
            &query_indices,
            8,
        )
        .expect("the recomputable pass is valid");
        let source_poly = p3_multilinear_util::poly::Poly::new(source);
        let output = loop {
            match pass
                .poll_resident(PolyView::Scalar(&source_poly))
                .expect("the resident pass advances")
            {
                RecomputableOraclePoll::ArithmeticStepCompleted => {}
                RecomputableOraclePoll::StorageTransactionCompleted => {
                    panic!("a resident pass cannot request storage")
                }
                RecomputableOraclePoll::Complete(output) => break output,
            }
        };
        assert_eq!(output.root, expected_root);
        for (query_ordinal, opening) in expected_openings.into_iter().enumerate() {
            assert_eq!(output.rows[query_ordinal], opening.opened_values[0]);
            assert_eq!(output.paths[query_ordinal], opening.opening_proof);
        }
    }

    #[test]
    fn stripe_geometry_rejects_ambiguous_or_unbounded_sizes() {
        let source = RecomputableOracleSource::ResidentPolynomial;
        for maximum_stripe_row_count in [0, 3] {
            assert!(
                RecomputableOraclePass::new_with_maximum_stripe_row_count(
                    source.clone(),
                    7,
                    3,
                    2,
                    Vec::new(),
                    &[],
                    maximum_stripe_row_count,
                )
                .is_err(),
            );
        }
        assert_eq!(aggregate_oracle_leaf_state_stripe_count(1 << 23), Ok(8));
        assert_eq!(aggregate_oracle_leaf_state_stripe_count(1 << 22), Ok(4));
        assert_eq!(aggregate_oracle_leaf_state_stripe_count(1 << 21), Ok(2));
        assert_eq!(aggregate_oracle_leaf_state_stripe_count(1 << 20), Ok(1));
        assert!(aggregate_oracle_leaf_state_stripe_count(0).is_err());
        assert!(aggregate_oracle_leaf_state_stripe_count(3).is_err());
    }

    #[test]
    fn external_table_recomputation_matches_resident_recomputation_and_selector_order() {
        const SOURCE_VARIABLE_COUNT: usize = 7;
        const TABLE_VARIABLE_COUNT: usize = 5;
        const TABLE_WIDTH: usize = 4;
        const FOLDING_FACTOR: usize = 3;
        const INVERSE_RATE: usize = 2;
        const TABLE_COLUMN_ELEMENT_COUNT: usize = 1 << TABLE_VARIABLE_COUNT;
        const MAXIMUM_CHUNK_BYTE_LENGTH: u32 = 256;

        let logical_columns = (0..TABLE_WIDTH)
            .map(|logical_column_index| {
                (0..TABLE_COLUMN_ELEMENT_COUNT)
                    .map(|local_index| {
                        ChallengeField::from_u64(
                            10_000 * (logical_column_index as u64 + 1)
                                + (local_index as u64 + 7).pow(3),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut resident_source =
            vec![ChallengeField::ZERO; TABLE_WIDTH * TABLE_COLUMN_ELEMENT_COUNT];
        for (logical_column_index, column) in logical_columns.iter().enumerate() {
            for (local_index, value) in column.iter().copied().enumerate() {
                resident_source[interleaved_source_index(
                    local_index,
                    logical_column_index,
                    TABLE_WIDTH,
                )
                .expect("the selector index is valid")] = value;
            }
        }
        let randomness = (0..ENCODED_ORACLE_WIDTH * 2)
            .map(|index| ChallengeField::from_u64(20_000 + index as u64))
            .collect::<Vec<_>>();
        let query_indices = [0, 3, 17, 31];

        let mut resident_pass = RecomputableOraclePass::new(
            RecomputableOracleSource::ResidentPolynomial,
            SOURCE_VARIABLE_COUNT,
            FOLDING_FACTOR,
            INVERSE_RATE,
            randomness.clone(),
            &query_indices,
        )
        .expect("the resident pass is valid");
        let resident_polynomial = p3_multilinear_util::poly::Poly::new(resident_source);
        let resident_output = loop {
            match resident_pass
                .poll_resident(PolyView::Scalar(&resident_polynomial))
                .expect("the resident pass advances")
            {
                RecomputableOraclePoll::ArithmeticStepCompleted => {}
                RecomputableOraclePoll::StorageTransactionCompleted => {
                    panic!("a resident pass cannot request storage")
                }
                RecomputableOraclePoll::Complete(output) => break output,
            }
        };

        let column_byte_length =
            u64::try_from(TABLE_COLUMN_ELEMENT_COUNT * AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
                .expect("the column byte length fits u64");
        let total_byte_length = column_byte_length * TABLE_WIDTH as u64;
        let maximum_append_count = column_byte_length.div_ceil(u64::from(
            MAXIMUM_CHUNK_BYTE_LENGTH / AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH as u32
                * AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH as u32,
        ));
        let vectors = (0..TABLE_WIDTH)
            .map(|logical_column_index| {
                ExternalPolynomialVector::new(
                    ProofExternalMemoryObject::new(logical_column_index as u32),
                    RelationColumnValueType::ChallengeExtension,
                    TABLE_COLUMN_ELEMENT_COUNT,
                )
                .expect("the external column is valid")
            })
            .collect::<Vec<_>>();
        let object_plans = vectors
            .iter()
            .map(|vector| {
                ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                    vector.object(),
                    ProofExternalMemoryProtection::PublicIntegrity,
                    column_byte_length,
                    maximum_append_count,
                    0,
                    0,
                    0,
                )
            })
            .collect::<Vec<_>>();
        let plan = ProofExternalMemoryPlan::new(
            1,
            MAXIMUM_CHUNK_BYTE_LENGTH,
            u64::from(MAXIMUM_CHUNK_BYTE_LENGTH),
            TABLE_WIDTH as u32,
            total_byte_length,
            total_byte_length,
            total_byte_length,
            65,
            object_plans,
        )
        .expect("the external table plan is valid");
        let table =
            AggregateSourceTable::new(vectors.clone(), TABLE_VARIABLE_COUNT, FOLDING_FACTOR)
                .expect("the external table is valid");
        let mut executor = ProofExternalMemoryExecutor::new(plan);
        let mut storage = TestStorage::default();
        for (vector, column) in vectors.into_iter().zip(&logical_columns) {
            let mut writer = AggregateSourceWriter::new(vector).expect("the writer is valid");
            while !writer
                .poll(
                    AggregateSourceValues::Slice(column),
                    &mut executor,
                    &mut storage,
                )
                .expect("the source column writes")
            {}
        }

        let mut external_pass = RecomputableOraclePass::new(
            RecomputableOracleSource::ExternalTable(table),
            SOURCE_VARIABLE_COUNT,
            FOLDING_FACTOR,
            INVERSE_RATE,
            randomness,
            &query_indices,
        )
        .expect("the external pass is valid");
        let external_output = loop {
            match external_pass
                .poll_external(&mut executor, &mut storage)
                .expect("the external pass advances")
            {
                RecomputableOraclePoll::ArithmeticStepCompleted
                | RecomputableOraclePoll::StorageTransactionCompleted => {}
                RecomputableOraclePoll::Complete(output) => break output,
            }
        };

        assert_eq!(external_output.root, resident_output.root);
        assert_eq!(external_output.rows, resident_output.rows);
        assert_eq!(external_output.paths, resident_output.paths);
        executor
            .complete_step(&mut storage)
            .expect("the source objects are deleted after their last use");
        let usage = executor.finish().expect("the executor finishes");
        assert_eq!(usage.total_written_byte_length(), total_byte_length);
        assert_eq!(usage.total_read_byte_length(), total_byte_length);
        assert_eq!(usage.peak_stored_byte_length(), total_byte_length);
        assert_eq!(usage.deleted_object_count(), TABLE_WIDTH as u32);
    }
}
