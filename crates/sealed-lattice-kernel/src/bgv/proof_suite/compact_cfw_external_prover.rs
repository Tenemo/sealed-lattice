//! Transaction-driving external-memory CFW prover.
//!
//! The resident prover remains the small reference oracle. This owner streams
//! the same canonical row pairs through the shared scalar state, writes every
//! folded matrix vector through the validated external-memory plan, and keeps
//! only bounded chunks resident. Each storage-backed advance performs at most
//! one executor transaction. Append bytes are regenerated from retained field
//! values so a recorder/replay pass observes identical bytes after ownership
//! of the first encoded buffer has moved to the transaction request.

use zeroize::{Zeroize, Zeroizing};

use super::compact_cfw::{
    COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH, COMPACT_CFW_MATRIX_COUNT,
    COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH, CompactCfwError, CompactCfwGeometry,
    CompactCfwMaskMaterial, CompactCfwProverFinish, CompactCfwRoundAccumulator,
    CompactCfwScalarProverState, CompactChallengeField, compact_cfw_fold_row_pair,
    compact_challenge_from_production, compact_challenge_to_production,
};
use super::compact_cfw_external::{CompactCfwExternalPlanError, CompactCfwExternalStorageCatalog};
use super::external_memory::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryUsage,
};
use super::external_polynomial::{
    ExternalPolynomialError, ExternalPolynomialReadError, ExternalPolynomialVector,
    read_external_polynomial_values_as_extension_into,
};
use super::{PROOF_CHALLENGE_EXTENSION_DEGREE, ProofChallengeExtensionElement};

const BASE_FIELD_ELEMENT_BYTE_LENGTH: usize = core::mem::size_of::<u64>();
const EXTENSION_FIELD_ELEMENT_BYTE_LENGTH: usize =
    PROOF_CHALLENGE_EXTENSION_DEGREE * BASE_FIELD_ELEMENT_BYTE_LENGTH;

/// Canonical initial matrix rows for one compact CFW relation instance.
///
/// Production implementations derive these values from authenticated
/// assignment material and the checked structured matrices. The array order
/// is left multiplicand, right multiplicand, then product.
pub(crate) trait CompactCfwExternalRowSource {
    fn witness_length(&self) -> Result<usize, CompactCfwError>;

    fn row_count(&self) -> Result<usize, CompactCfwError>;

    fn evaluate_row(
        &self,
        row_ordinal: usize,
    ) -> Result<[ProofChallengeExtensionElement; COMPACT_CFW_MATRIX_COUNT], CompactCfwError>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwExternalProverSetupError {
    Cfw(CompactCfwError),
    Plan(CompactCfwExternalPlanError),
}

impl From<CompactCfwError> for CompactCfwExternalProverSetupError {
    fn from(error: CompactCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl From<CompactCfwExternalPlanError> for CompactCfwExternalProverSetupError {
    fn from(error: CompactCfwExternalPlanError) -> Self {
        Self::Plan(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwExternalProverExecutionError<StorageError> {
    Cfw(CompactCfwError),
    ExternalPolynomial(ExternalPolynomialError),
    Storage(ProofExternalMemoryExecutorError<StorageError>),
}

impl<StorageError> From<CompactCfwError> for CompactCfwExternalProverExecutionError<StorageError> {
    fn from(error: CompactCfwError) -> Self {
        Self::Cfw(error)
    }
}

impl<StorageError> From<ProofExternalMemoryExecutorError<StorageError>>
    for CompactCfwExternalProverExecutionError<StorageError>
{
    fn from(error: ProofExternalMemoryExecutorError<StorageError>) -> Self {
        Self::Storage(error)
    }
}

impl<StorageError> From<ExternalPolynomialReadError<StorageError>>
    for CompactCfwExternalProverExecutionError<StorageError>
{
    fn from(error: ExternalPolynomialReadError<StorageError>) -> Self {
        match error {
            ExternalPolynomialReadError::Polynomial(error) => Self::ExternalPolynomial(error),
            ExternalPolynomialReadError::Storage(error) => Self::Storage(error),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompactCfwExternalProverFinishError {
    Cfw(CompactCfwError),
    ExternalMemory(ProofExternalMemoryError),
}

pub(crate) struct CompactCfwExternalProverOutput {
    finish: CompactCfwProverFinish,
    usage: ProofExternalMemoryUsage,
}

impl CompactCfwExternalProverOutput {
    pub(crate) const fn finish(&self) -> &CompactCfwProverFinish {
        &self.finish
    }

    pub(crate) const fn usage(&self) -> ProofExternalMemoryUsage {
        self.usage
    }

    pub(crate) fn into_finish(self) -> CompactCfwProverFinish {
        self.finish
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactCfwExternalProverPhase {
    DerivingRoundPolynomial,
    AwaitingRoundChallenge,
    FirstRoundBeginningObjects,
    FirstRoundPreparingChunk,
    FirstRoundAppendingChunk,
    FirstRoundSealingObjects,
    FirstRoundCompletingStep,
    LaterRoundBeginningObject,
    LaterRoundReadingInput,
    LaterRoundAppendingChunk,
    LaterRoundSealingObject,
    LaterRoundCompletingStep,
    FinalCleanup,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactCfwExternalProverMemoryGeometry {
    state_inline_byte_length: u64,
    runtime_index_heap_byte_length: u64,
    executor_heap_byte_length: u64,
    inner_mask_heap_byte_length: u64,
    outer_mask_heap_byte_length: u64,
    equality_point_heap_byte_length: u64,
    round_challenge_heap_byte_length: u64,
    maximum_accumulator_suffix_heap_byte_length: u64,
    work_chunk_heap_byte_length: u64,
    maximum_encoded_chunk_byte_length: u64,
    resident_owned_byte_length: u64,
    maximum_kernel_live_byte_length: u64,
}

impl CompactCfwExternalProverMemoryGeometry {
    pub(crate) fn derive(
        geometry: CompactCfwGeometry,
    ) -> Result<Self, CompactCfwExternalProverSetupError> {
        let catalog = CompactCfwExternalStorageCatalog::derive(geometry)?;
        let state_inline_byte_length =
            u64::try_from(core::mem::size_of::<CompactCfwExternalProverState>())
                .map_err(|_| CompactCfwError::CountOverflow)?;
        let runtime_index_heap_byte_length =
            catalog.runtime_index_resident_owned_payload_byte_length()?;
        let executor_heap_byte_length = catalog.executor_resident_owned_payload_byte_length();
        let challenge_element_byte_length =
            u64::try_from(core::mem::size_of::<CompactChallengeField>())
                .map_err(|_| CompactCfwError::CountOverflow)?;
        let production_element_byte_length =
            u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                .map_err(|_| CompactCfwError::CountOverflow)?;
        if challenge_element_byte_length != EXTENSION_FIELD_ELEMENT_BYTE_LENGTH as u64
            || production_element_byte_length != EXTENSION_FIELD_ELEMENT_BYTE_LENGTH as u64
        {
            return Err(CompactCfwError::IncompatibleChallengeField.into());
        }
        let inner_mask_heap_byte_length = checked_memory_product(&[
            u64::try_from(geometry.inner_mask_count())
                .map_err(|_| CompactCfwError::CountOverflow)?,
            u64::try_from(COMPACT_CFW_INNER_MASK_MESSAGE_LENGTH)
                .map_err(|_| CompactCfwError::CountOverflow)?,
            challenge_element_byte_length,
        ])?;
        let outer_mask_heap_byte_length = checked_memory_product(&[
            u64::try_from(geometry.outer_mask_count())
                .map_err(|_| CompactCfwError::CountOverflow)?,
            u64::try_from(COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH)
                .map_err(|_| CompactCfwError::CountOverflow)?,
            challenge_element_byte_length,
        ])?;
        let round_count = u64::try_from(geometry.sumcheck_round_count())
            .map_err(|_| CompactCfwError::CountOverflow)?;
        let equality_point_heap_byte_length =
            checked_memory_product(&[round_count, challenge_element_byte_length])?;
        let round_challenge_heap_byte_length = equality_point_heap_byte_length;
        let maximum_accumulator_suffix_heap_byte_length = checked_memory_product(&[
            round_count
                .checked_sub(1)
                .ok_or(CompactCfwError::InvalidGeometry)?,
            challenge_element_byte_length,
        ])?;
        let maximum_encoded_chunk_byte_length = u64::from(catalog.maximum_chunk_byte_length());
        let maximum_chunk_element_count = maximum_encoded_chunk_byte_length
            .checked_div(production_element_byte_length)
            .filter(|count| *count != 0)
            .ok_or(CompactCfwError::InvalidGeometry)?;
        let work_chunk_heap_byte_length = checked_memory_product(&[
            COMPACT_CFW_MATRIX_COUNT as u64,
            maximum_chunk_element_count,
            production_element_byte_length,
        ])?;
        let resident_owned_byte_length = [
            state_inline_byte_length,
            runtime_index_heap_byte_length,
            executor_heap_byte_length,
            inner_mask_heap_byte_length,
            outer_mask_heap_byte_length,
            equality_point_heap_byte_length,
            round_challenge_heap_byte_length,
            maximum_accumulator_suffix_heap_byte_length,
            work_chunk_heap_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, checked_memory_add)?;
        let maximum_kernel_live_byte_length = checked_memory_add(
            resident_owned_byte_length,
            maximum_encoded_chunk_byte_length,
        )?;
        Ok(Self {
            state_inline_byte_length,
            runtime_index_heap_byte_length,
            executor_heap_byte_length,
            inner_mask_heap_byte_length,
            outer_mask_heap_byte_length,
            equality_point_heap_byte_length,
            round_challenge_heap_byte_length,
            maximum_accumulator_suffix_heap_byte_length,
            work_chunk_heap_byte_length,
            maximum_encoded_chunk_byte_length,
            resident_owned_byte_length,
            maximum_kernel_live_byte_length,
        })
    }

    pub(crate) const fn state_inline_byte_length(self) -> u64 {
        self.state_inline_byte_length
    }

    pub(crate) const fn runtime_index_heap_byte_length(self) -> u64 {
        self.runtime_index_heap_byte_length
    }

    pub(crate) const fn executor_heap_byte_length(self) -> u64 {
        self.executor_heap_byte_length
    }

    pub(crate) const fn inner_mask_heap_byte_length(self) -> u64 {
        self.inner_mask_heap_byte_length
    }

    pub(crate) const fn outer_mask_heap_byte_length(self) -> u64 {
        self.outer_mask_heap_byte_length
    }

    pub(crate) const fn equality_point_heap_byte_length(self) -> u64 {
        self.equality_point_heap_byte_length
    }

    pub(crate) const fn round_challenge_heap_byte_length(self) -> u64 {
        self.round_challenge_heap_byte_length
    }

    pub(crate) const fn maximum_accumulator_suffix_heap_byte_length(self) -> u64 {
        self.maximum_accumulator_suffix_heap_byte_length
    }

    pub(crate) const fn work_chunk_heap_byte_length(self) -> u64 {
        self.work_chunk_heap_byte_length
    }

    pub(crate) const fn maximum_encoded_chunk_byte_length(self) -> u64 {
        self.maximum_encoded_chunk_byte_length
    }

    pub(crate) const fn resident_owned_byte_length(self) -> u64 {
        self.resident_owned_byte_length
    }

    pub(crate) const fn maximum_kernel_live_byte_length(self) -> u64 {
        self.maximum_kernel_live_byte_length
    }
}

pub(crate) struct CompactCfwExternalProverState {
    round_vectors: Vec<[ExternalPolynomialVector; COMPACT_CFW_MATRIX_COUNT]>,
    round_output_steps: Vec<[u32; COMPACT_CFW_MATRIX_COUNT]>,
    external_step_count: u32,
    executor: ProofExternalMemoryExecutor,
    scalar_state: CompactCfwScalarProverState,
    phase: CompactCfwExternalProverPhase,
    round_accumulator: Option<CompactCfwRoundAccumulator>,
    derivation_element_offset: usize,
    derivation_matrix_ordinal: usize,
    work_chunks: [Zeroizing<Vec<ProofChallengeExtensionElement>>; COMPACT_CFW_MATRIX_COUNT],
    bound_challenge: Option<CompactChallengeField>,
    writing_round_ordinal: usize,
    writing_matrix_ordinal: usize,
    fold_input_element_offset: usize,
    final_folded_values: [Option<ProofChallengeExtensionElement>; COMPACT_CFW_MATRIX_COUNT],
}

impl CompactCfwExternalProverState {
    pub(crate) fn prepare(
        row_source: &impl CompactCfwExternalRowSource,
        mask_material: CompactCfwMaskMaterial,
        constraint_combining_challenge: CompactChallengeField,
        equality_point: Vec<CompactChallengeField>,
    ) -> Result<Self, CompactCfwExternalProverSetupError> {
        let geometry = CompactCfwGeometry::derive(row_source.witness_length()?)?;
        if row_source.row_count()? != geometry.r1cs_row_count() {
            return Err(CompactCfwError::InvalidMatrixSource.into());
        }
        let catalog = CompactCfwExternalStorageCatalog::derive(geometry)?;
        let (external_plan, round_vectors, round_output_steps, external_step_count) =
            catalog.into_runtime_parts();
        let executor = ProofExternalMemoryExecutor::new(external_plan);
        let maximum_chunk_byte_length = usize::try_from(executor.maximum_chunk_byte_length())
            .map_err(|_| CompactCfwError::CountOverflow)?;
        let maximum_chunk_element_count = maximum_chunk_byte_length
            .checked_div(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH)
            .filter(|count| *count != 0)
            .ok_or(CompactCfwError::InvalidGeometry)?;
        let mut work_chunks = core::array::from_fn(|_| Zeroizing::new(Vec::new()));
        for chunk in &mut work_chunks {
            chunk
                .try_reserve_exact(maximum_chunk_element_count)
                .map_err(|_| CompactCfwError::AllocationLimitExceeded)?;
            if chunk.capacity() != maximum_chunk_element_count {
                return Err(CompactCfwError::AllocationLimitExceeded.into());
            }
        }
        let scalar_state = CompactCfwScalarProverState::begin(
            geometry,
            mask_material,
            constraint_combining_challenge,
            equality_point,
        )?;
        let round_accumulator = Some(scalar_state.round_accumulator()?);
        Ok(Self {
            round_vectors,
            round_output_steps,
            external_step_count,
            executor,
            scalar_state,
            phase: CompactCfwExternalProverPhase::DerivingRoundPolynomial,
            round_accumulator,
            derivation_element_offset: 0,
            derivation_matrix_ordinal: 0,
            work_chunks,
            bound_challenge: None,
            writing_round_ordinal: 0,
            writing_matrix_ordinal: 0,
            fold_input_element_offset: 0,
            final_folded_values: [None; COMPACT_CFW_MATRIX_COUNT],
        })
    }

    pub(crate) const fn auxiliary_target(&self) -> CompactChallengeField {
        self.scalar_state.auxiliary_target()
    }

    pub(crate) fn advance_round_polynomial<Storage: ProofExternalMemory>(
        &mut self,
        row_source: &impl CompactCfwExternalRowSource,
        storage: &mut Storage,
    ) -> Result<
        Option<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
        CompactCfwExternalProverExecutionError<Storage::Error>,
    > {
        if self.phase != CompactCfwExternalProverPhase::DerivingRoundPolynomial {
            return Err(CompactCfwError::WrongProverPhase.into());
        }
        self.check_row_source_geometry(row_source)?;
        if self.scalar_state.round_ordinal() == 0 {
            self.advance_first_round_derivation(row_source)
        } else {
            self.advance_external_round_derivation(storage)
        }
    }

    pub(crate) fn bind_round_challenge(
        &mut self,
        challenge: CompactChallengeField,
    ) -> Result<(), CompactCfwError> {
        if self.phase != CompactCfwExternalProverPhase::AwaitingRoundChallenge {
            return Err(CompactCfwError::WrongProverPhase);
        }
        self.scalar_state.bind_round_challenge(challenge)?;
        self.writing_round_ordinal = self
            .scalar_state
            .round_ordinal()
            .checked_sub(1)
            .ok_or(CompactCfwError::CountOverflow)?;
        self.writing_matrix_ordinal = 0;
        self.fold_input_element_offset = 0;
        self.bound_challenge = Some(challenge);
        self.clear_work_chunks();
        self.phase = if self.writing_round_ordinal == 0 {
            CompactCfwExternalProverPhase::FirstRoundBeginningObjects
        } else {
            CompactCfwExternalProverPhase::LaterRoundBeginningObject
        };
        Ok(())
    }

    pub(crate) fn advance_bound_round<Storage: ProofExternalMemory>(
        &mut self,
        row_source: &impl CompactCfwExternalRowSource,
        storage: &mut Storage,
    ) -> Result<bool, CompactCfwExternalProverExecutionError<Storage::Error>> {
        self.check_row_source_geometry(row_source)?;
        match self.phase {
            CompactCfwExternalProverPhase::FirstRoundBeginningObjects => {
                self.begin_first_round_object(storage)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::FirstRoundPreparingChunk => {
                self.prepare_first_round_chunk(row_source)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::FirstRoundAppendingChunk => {
                self.append_first_round_chunk(storage)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::FirstRoundSealingObjects => {
                self.seal_first_round_object(storage)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::FirstRoundCompletingStep => {
                self.executor.complete_step(storage)?;
                self.complete_written_round()
            }
            CompactCfwExternalProverPhase::LaterRoundBeginningObject => {
                self.begin_later_round_object(storage)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::LaterRoundReadingInput => {
                self.read_and_fold_later_round_chunk(storage)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::LaterRoundAppendingChunk => {
                self.append_later_round_chunk(storage)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::LaterRoundSealingObject => {
                self.seal_later_round_object(storage)?;
                Ok(false)
            }
            CompactCfwExternalProverPhase::LaterRoundCompletingStep => {
                self.executor.complete_step(storage)?;
                if self.writing_matrix_ordinal + 1 < COMPACT_CFW_MATRIX_COUNT {
                    self.writing_matrix_ordinal += 1;
                    self.fold_input_element_offset = 0;
                    self.phase = CompactCfwExternalProverPhase::LaterRoundBeginningObject;
                    Ok(false)
                } else {
                    self.complete_written_round()
                }
            }
            CompactCfwExternalProverPhase::FinalCleanup => {
                self.executor.complete_step(storage)?;
                if self.executor.current_step() == self.external_step_count {
                    self.phase = CompactCfwExternalProverPhase::Complete;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(CompactCfwError::WrongProverPhase.into()),
        }
    }

    pub(crate) fn finish(
        self,
    ) -> Result<CompactCfwExternalProverOutput, CompactCfwExternalProverFinishError> {
        if self.phase != CompactCfwExternalProverPhase::Complete {
            return Err(CompactCfwExternalProverFinishError::Cfw(
                CompactCfwError::WrongProverPhase,
            ));
        }
        let mut folded_matrix_values =
            [ProofChallengeExtensionElement::ZERO; COMPACT_CFW_MATRIX_COUNT];
        for (destination, source) in folded_matrix_values
            .iter_mut()
            .zip(self.final_folded_values)
        {
            *destination = source.ok_or(CompactCfwExternalProverFinishError::Cfw(
                CompactCfwError::WrongProverPhase,
            ))?;
        }
        let folded_matrix_values = folded_matrix_values.map(compact_challenge_from_production);
        let finish = self
            .scalar_state
            .finish(folded_matrix_values)
            .map_err(CompactCfwExternalProverFinishError::Cfw)?;
        let usage = self
            .executor
            .finish()
            .map_err(CompactCfwExternalProverFinishError::ExternalMemory)?;
        Ok(CompactCfwExternalProverOutput { finish, usage })
    }

    fn check_row_source_geometry<StorageError>(
        &self,
        row_source: &impl CompactCfwExternalRowSource,
    ) -> Result<(), CompactCfwExternalProverExecutionError<StorageError>> {
        if row_source.witness_length()? != self.scalar_state.geometry().witness_length()
            || row_source.row_count()? != self.scalar_state.geometry().r1cs_row_count()
        {
            return Err(CompactCfwError::InvalidMatrixSource.into());
        }
        Ok(())
    }

    fn maximum_chunk_element_count<StorageError>(
        &self,
    ) -> Result<usize, CompactCfwExternalProverExecutionError<StorageError>> {
        let maximum_chunk_byte_length = usize::try_from(self.executor.maximum_chunk_byte_length())
            .map_err(|_| resource_limit_error())?;
        maximum_chunk_byte_length
            .checked_div(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH)
            .filter(|count| *count != 0)
            .ok_or_else(resource_limit_error)
    }

    fn advance_first_round_derivation<StorageError>(
        &mut self,
        row_source: &impl CompactCfwExternalRowSource,
    ) -> Result<
        Option<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
        CompactCfwExternalProverExecutionError<StorageError>,
    > {
        let maximum_row_pair_count = self.maximum_chunk_element_count::<StorageError>()? / 2;
        if maximum_row_pair_count == 0 || self.derivation_element_offset % 2 != 0 {
            return Err(resource_limit_error());
        }
        let row_count = row_source.row_count()?;
        let remaining_row_count = row_count
            .checked_sub(self.derivation_element_offset)
            .ok_or(CompactCfwError::CountOverflow)?;
        let row_pair_count = maximum_row_pair_count.min(remaining_row_count / 2);
        for local_pair_ordinal in 0..row_pair_count {
            let first_row_ordinal = self
                .derivation_element_offset
                .checked_add(
                    local_pair_ordinal
                        .checked_mul(2)
                        .ok_or(CompactCfwError::CountOverflow)?,
                )
                .ok_or(CompactCfwError::CountOverflow)?;
            let values_at_zero = row_source
                .evaluate_row(first_row_ordinal)?
                .map(compact_challenge_from_production);
            let values_at_one = row_source
                .evaluate_row(first_row_ordinal + 1)?
                .map(compact_challenge_from_production);
            self.round_accumulator
                .as_mut()
                .ok_or(CompactCfwError::WrongProverPhase)?
                .absorb_next_row_pair(values_at_zero, values_at_one)?;
        }
        self.derivation_element_offset = self
            .derivation_element_offset
            .checked_add(
                row_pair_count
                    .checked_mul(2)
                    .ok_or(CompactCfwError::CountOverflow)?,
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        if self.derivation_element_offset == row_count {
            self.finish_round_derivation().map(Some)
        } else {
            Ok(None)
        }
    }

    fn advance_external_round_derivation<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<
        Option<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]>,
        CompactCfwExternalProverExecutionError<Storage::Error>,
    > {
        let round_ordinal = self.scalar_state.round_ordinal();
        let input_vectors = *self
            .round_vectors
            .get(round_ordinal - 1)
            .ok_or(CompactCfwError::WrongProverPhase)?;
        let input_element_count = input_vectors[0].element_count();
        if input_vectors
            .iter()
            .any(|vector| vector.element_count() != input_element_count)
            || self.derivation_element_offset >= input_element_count
        {
            return Err(CompactCfwError::InvalidMatrixSource.into());
        }
        let chunk_element_count = self
            .maximum_chunk_element_count::<Storage::Error>()?
            .min(input_element_count - self.derivation_element_offset);
        let matrix_ordinal = self.derivation_matrix_ordinal;
        read_external_polynomial_values_as_extension_into(
            &mut self.executor,
            storage,
            input_vectors[matrix_ordinal],
            self.derivation_element_offset,
            chunk_element_count,
            &mut self.work_chunks[matrix_ordinal],
        )?;
        self.derivation_matrix_ordinal += 1;
        if self.derivation_matrix_ordinal < COMPACT_CFW_MATRIX_COUNT {
            return Ok(None);
        }

        if chunk_element_count % 2 != 0
            || self
                .work_chunks
                .iter()
                .any(|values| values.len() != chunk_element_count)
        {
            return Err(CompactCfwError::InvalidMatrixSource.into());
        }
        let accumulator = self
            .round_accumulator
            .as_mut()
            .ok_or(CompactCfwError::WrongProverPhase)?;
        for local_pair_ordinal in 0..chunk_element_count / 2 {
            let first_element_ordinal = local_pair_ordinal * 2;
            let values_at_zero = core::array::from_fn(|current_matrix_ordinal| {
                compact_challenge_from_production(
                    self.work_chunks[current_matrix_ordinal][first_element_ordinal],
                )
            });
            let values_at_one = core::array::from_fn(|current_matrix_ordinal| {
                compact_challenge_from_production(
                    self.work_chunks[current_matrix_ordinal][first_element_ordinal + 1],
                )
            });
            accumulator.absorb_next_row_pair(values_at_zero, values_at_one)?;
        }
        self.clear_work_chunks();
        self.derivation_matrix_ordinal = 0;
        self.derivation_element_offset = self
            .derivation_element_offset
            .checked_add(chunk_element_count)
            .ok_or(CompactCfwError::CountOverflow)?;
        if self.derivation_element_offset == input_element_count {
            self.finish_round_derivation().map(Some)
        } else {
            Ok(None)
        }
    }

    fn finish_round_derivation<StorageError>(
        &mut self,
    ) -> Result<
        [CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH],
        CompactCfwExternalProverExecutionError<StorageError>,
    > {
        let polynomial = self
            .round_accumulator
            .take()
            .ok_or(CompactCfwError::WrongProverPhase)?
            .finish()?;
        self.scalar_state.accept_round_polynomial(polynomial)?;
        self.phase = CompactCfwExternalProverPhase::AwaitingRoundChallenge;
        Ok(polynomial)
    }

    fn begin_first_round_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactCfwExternalProverExecutionError<Storage::Error>> {
        let object = self.output_vector()?.object();
        self.executor.begin_object(storage, object)?;
        self.writing_matrix_ordinal += 1;
        if self.writing_matrix_ordinal == COMPACT_CFW_MATRIX_COUNT {
            self.writing_matrix_ordinal = 0;
            self.phase = CompactCfwExternalProverPhase::FirstRoundPreparingChunk;
        }
        Ok(())
    }

    fn prepare_first_round_chunk<StorageError>(
        &mut self,
        row_source: &impl CompactCfwExternalRowSource,
    ) -> Result<(), CompactCfwExternalProverExecutionError<StorageError>> {
        let maximum_output_element_count = self.maximum_chunk_element_count::<StorageError>()?;
        let row_count = row_source.row_count()?;
        if self.fold_input_element_offset >= row_count || self.fold_input_element_offset % 2 != 0 {
            return Err(CompactCfwError::WrongProverPhase.into());
        }
        let remaining_output_element_count = (row_count - self.fold_input_element_offset) / 2;
        let output_element_count = maximum_output_element_count.min(remaining_output_element_count);
        for values in &mut self.work_chunks {
            values
                .try_reserve_exact(output_element_count)
                .map_err(|_| resource_limit_error())?;
        }
        let challenge = self
            .bound_challenge
            .ok_or(CompactCfwError::WrongProverPhase)?;
        for local_output_ordinal in 0..output_element_count {
            let first_row_ordinal = self
                .fold_input_element_offset
                .checked_add(
                    local_output_ordinal
                        .checked_mul(2)
                        .ok_or(CompactCfwError::CountOverflow)?,
                )
                .ok_or(CompactCfwError::CountOverflow)?;
            let values_at_zero = row_source.evaluate_row(first_row_ordinal)?;
            let values_at_one = row_source.evaluate_row(first_row_ordinal + 1)?;
            for matrix_ordinal in 0..COMPACT_CFW_MATRIX_COUNT {
                let folded_value = compact_cfw_fold_row_pair(
                    compact_challenge_from_production(values_at_zero[matrix_ordinal]),
                    compact_challenge_from_production(values_at_one[matrix_ordinal]),
                    challenge,
                );
                self.work_chunks[matrix_ordinal]
                    .push(compact_challenge_to_production(folded_value)?);
            }
        }
        self.fold_input_element_offset = self
            .fold_input_element_offset
            .checked_add(
                output_element_count
                    .checked_mul(2)
                    .ok_or(CompactCfwError::CountOverflow)?,
            )
            .ok_or(CompactCfwError::CountOverflow)?;
        self.writing_matrix_ordinal = 0;
        self.phase = CompactCfwExternalProverPhase::FirstRoundAppendingChunk;
        Ok(())
    }

    fn append_first_round_chunk<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactCfwExternalProverExecutionError<Storage::Error>> {
        let matrix_ordinal = self.writing_matrix_ordinal;
        let vector = self.output_vector()?;
        let mut encoded =
            encode_extension_values::<Storage::Error>(&self.work_chunks[matrix_ordinal])?;
        self.executor
            .append_owned_object_bytes(storage, vector.object(), &mut encoded)?;
        self.capture_final_folded_value(matrix_ordinal, vector.element_count())?;
        self.work_chunks[matrix_ordinal].zeroize();
        self.work_chunks[matrix_ordinal].clear();
        self.writing_matrix_ordinal += 1;
        if self.writing_matrix_ordinal == COMPACT_CFW_MATRIX_COUNT {
            self.writing_matrix_ordinal = 0;
            self.phase = if self.fold_input_element_offset
                == self.scalar_state.geometry().r1cs_row_count()
            {
                CompactCfwExternalProverPhase::FirstRoundSealingObjects
            } else {
                CompactCfwExternalProverPhase::FirstRoundPreparingChunk
            };
        }
        Ok(())
    }

    fn seal_first_round_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactCfwExternalProverExecutionError<Storage::Error>> {
        let object = self.output_vector()?.object();
        self.executor.seal_object(storage, object)?;
        self.writing_matrix_ordinal += 1;
        if self.writing_matrix_ordinal == COMPACT_CFW_MATRIX_COUNT {
            self.writing_matrix_ordinal = 0;
            self.phase = CompactCfwExternalProverPhase::FirstRoundCompletingStep;
        }
        Ok(())
    }

    fn begin_later_round_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactCfwExternalProverExecutionError<Storage::Error>> {
        self.check_current_output_step()?;
        let object = self.output_vector()?.object();
        self.executor.begin_object(storage, object)?;
        self.phase = CompactCfwExternalProverPhase::LaterRoundReadingInput;
        Ok(())
    }

    fn read_and_fold_later_round_chunk<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactCfwExternalProverExecutionError<Storage::Error>> {
        let input_vector = self.input_vector()?;
        if self.fold_input_element_offset >= input_vector.element_count() {
            return Err(CompactCfwError::WrongProverPhase.into());
        }
        let read_element_count = self
            .maximum_chunk_element_count::<Storage::Error>()?
            .min(input_vector.element_count() - self.fold_input_element_offset);
        if read_element_count % 2 != 0 {
            return Err(CompactCfwError::InvalidMatrixSource.into());
        }
        let matrix_ordinal = self.writing_matrix_ordinal;
        let input_work_chunk_ordinal = (matrix_ordinal + 1) % COMPACT_CFW_MATRIX_COUNT;
        read_external_polynomial_values_as_extension_into(
            &mut self.executor,
            storage,
            input_vector,
            self.fold_input_element_offset,
            read_element_count,
            &mut self.work_chunks[input_work_chunk_ordinal],
        )?;
        let challenge = self
            .bound_challenge
            .ok_or(CompactCfwError::WrongProverPhase)?;
        let (input_values, pending_folded_values) = distinct_work_chunks(
            &mut self.work_chunks,
            input_work_chunk_ordinal,
            matrix_ordinal,
        )?;
        let required_output_capacity = pending_folded_values
            .len()
            .checked_add(read_element_count / 2)
            .ok_or_else(resource_limit_error)?;
        if pending_folded_values.capacity() < required_output_capacity {
            return Err(resource_limit_error());
        }
        for pair in input_values.chunks_exact(2) {
            let folded_value = compact_cfw_fold_row_pair(
                compact_challenge_from_production(pair[0]),
                compact_challenge_from_production(pair[1]),
                challenge,
            );
            pending_folded_values.push(compact_challenge_to_production(folded_value)?);
        }
        self.work_chunks[input_work_chunk_ordinal].zeroize();
        self.work_chunks[input_work_chunk_ordinal].clear();
        self.fold_input_element_offset = self
            .fold_input_element_offset
            .checked_add(read_element_count)
            .ok_or(CompactCfwError::CountOverflow)?;
        let maximum_output_element_count = self.maximum_chunk_element_count::<Storage::Error>()?;
        if self.work_chunks[matrix_ordinal].len() == maximum_output_element_count
            || self.fold_input_element_offset == input_vector.element_count()
        {
            self.phase = CompactCfwExternalProverPhase::LaterRoundAppendingChunk;
        }
        Ok(())
    }

    fn append_later_round_chunk<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactCfwExternalProverExecutionError<Storage::Error>> {
        let matrix_ordinal = self.writing_matrix_ordinal;
        let output_vector = self.output_vector()?;
        let mut encoded =
            encode_extension_values::<Storage::Error>(&self.work_chunks[matrix_ordinal])?;
        self.executor
            .append_owned_object_bytes(storage, output_vector.object(), &mut encoded)?;
        self.capture_final_folded_value(matrix_ordinal, output_vector.element_count())?;
        self.work_chunks[matrix_ordinal].zeroize();
        self.work_chunks[matrix_ordinal].clear();
        self.phase = if self.fold_input_element_offset == self.input_vector()?.element_count() {
            CompactCfwExternalProverPhase::LaterRoundSealingObject
        } else {
            CompactCfwExternalProverPhase::LaterRoundReadingInput
        };
        Ok(())
    }

    fn seal_later_round_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), CompactCfwExternalProverExecutionError<Storage::Error>> {
        let object = self.output_vector()?.object();
        self.executor.seal_object(storage, object)?;
        self.phase = CompactCfwExternalProverPhase::LaterRoundCompletingStep;
        Ok(())
    }

    fn complete_written_round<StorageError>(
        &mut self,
    ) -> Result<bool, CompactCfwExternalProverExecutionError<StorageError>> {
        self.bound_challenge = None;
        self.fold_input_element_offset = 0;
        if self.writing_round_ordinal + 1 == self.scalar_state.geometry().sumcheck_round_count() {
            self.phase = CompactCfwExternalProverPhase::FinalCleanup;
            Ok(false)
        } else {
            self.round_accumulator = Some(self.scalar_state.round_accumulator()?);
            self.derivation_element_offset = 0;
            self.derivation_matrix_ordinal = 0;
            self.clear_work_chunks();
            self.phase = CompactCfwExternalProverPhase::DerivingRoundPolynomial;
            Ok(true)
        }
    }

    fn input_vector<StorageError>(
        &self,
    ) -> Result<ExternalPolynomialVector, CompactCfwExternalProverExecutionError<StorageError>>
    {
        self.writing_round_ordinal
            .checked_sub(1)
            .and_then(|round_ordinal| self.round_vectors.get(round_ordinal))
            .and_then(|vectors| vectors.get(self.writing_matrix_ordinal))
            .copied()
            .ok_or_else(|| CompactCfwError::WrongProverPhase.into())
    }

    fn output_vector<StorageError>(
        &self,
    ) -> Result<ExternalPolynomialVector, CompactCfwExternalProverExecutionError<StorageError>>
    {
        self.round_vectors
            .get(self.writing_round_ordinal)
            .and_then(|vectors| vectors.get(self.writing_matrix_ordinal))
            .copied()
            .ok_or_else(|| CompactCfwError::WrongProverPhase.into())
    }

    fn check_current_output_step<StorageError>(
        &self,
    ) -> Result<(), CompactCfwExternalProverExecutionError<StorageError>> {
        let expected_step = self
            .round_output_steps
            .get(self.writing_round_ordinal)
            .and_then(|steps| steps.get(self.writing_matrix_ordinal))
            .copied()
            .ok_or(CompactCfwError::WrongProverPhase)?;
        if self.executor.current_step() != expected_step {
            return Err(CompactCfwError::WrongProverPhase.into());
        }
        Ok(())
    }

    fn capture_final_folded_value<StorageError>(
        &mut self,
        matrix_ordinal: usize,
        output_element_count: usize,
    ) -> Result<(), CompactCfwExternalProverExecutionError<StorageError>> {
        if output_element_count == 1 {
            let value = self.work_chunks[matrix_ordinal]
                .first()
                .copied()
                .ok_or(CompactCfwError::InvalidMatrixSource)?;
            if self.final_folded_values[matrix_ordinal]
                .replace(value)
                .is_some()
            {
                return Err(CompactCfwError::WrongProverPhase.into());
            }
        }
        Ok(())
    }

    fn clear_work_chunks(&mut self) {
        for chunk in &mut self.work_chunks {
            chunk.zeroize();
            chunk.clear();
        }
    }
}

fn checked_memory_add(left: u64, right: u64) -> Result<u64, CompactCfwError> {
    left.checked_add(right)
        .ok_or(CompactCfwError::CountOverflow)
}

fn checked_memory_product(factors: &[u64]) -> Result<u64, CompactCfwError> {
    factors.iter().copied().try_fold(1_u64, |product, factor| {
        product
            .checked_mul(factor)
            .ok_or(CompactCfwError::CountOverflow)
    })
}

fn distinct_work_chunks(
    work_chunks: &mut [Zeroizing<Vec<ProofChallengeExtensionElement>>; COMPACT_CFW_MATRIX_COUNT],
    input_chunk_ordinal: usize,
    output_chunk_ordinal: usize,
) -> Result<
    (
        &[ProofChallengeExtensionElement],
        &mut Zeroizing<Vec<ProofChallengeExtensionElement>>,
    ),
    CompactCfwError,
> {
    if input_chunk_ordinal == output_chunk_ordinal
        || input_chunk_ordinal >= COMPACT_CFW_MATRIX_COUNT
        || output_chunk_ordinal >= COMPACT_CFW_MATRIX_COUNT
    {
        return Err(CompactCfwError::InvalidGeometry);
    }
    if input_chunk_ordinal < output_chunk_ordinal {
        let (before_output, output_and_after) = work_chunks.split_at_mut(output_chunk_ordinal);
        Ok((
            &before_output[input_chunk_ordinal],
            &mut output_and_after[0],
        ))
    } else {
        let (before_input, input_and_after) = work_chunks.split_at_mut(input_chunk_ordinal);
        Ok((&input_and_after[0], &mut before_input[output_chunk_ordinal]))
    }
}

fn encode_extension_values<StorageError>(
    values: &[ProofChallengeExtensionElement],
) -> Result<Zeroizing<Vec<u8>>, CompactCfwExternalProverExecutionError<StorageError>> {
    if values.is_empty() {
        return Err(CompactCfwError::InvalidMatrixSource.into());
    }
    let byte_length = values
        .len()
        .checked_mul(EXTENSION_FIELD_ELEMENT_BYTE_LENGTH)
        .ok_or_else(resource_limit_error)?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(byte_length)
        .map_err(|_| resource_limit_error())?;
    for value in values {
        for coordinate in value.canonical_coordinates() {
            encoded.extend_from_slice(&coordinate.to_le_bytes());
        }
    }
    if encoded.len() != byte_length {
        return Err(CompactCfwError::InvalidMatrixSource.into());
    }
    Ok(encoded)
}

fn resource_limit_error<StorageError>() -> CompactCfwExternalProverExecutionError<StorageError> {
    CompactCfwExternalProverExecutionError::Storage(ProofExternalMemoryExecutorError::Execution(
        ProofExternalMemoryError::ResourceLimitExceeded,
    ))
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_goldilocks::Goldilocks;

    use super::*;
    use crate::bgv::proof_suite::compact_cfw::{
        CompactCfwMatrixRole, CompactCfwR1csMatrices, CompactCfwTranscript,
        PreparedCompactCfwProver,
    };
    use crate::bgv::proof_suite::external_memory::{
        ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionOperation,
        ProofExternalMemoryTransactionRecorder, ProofExternalMemoryTransactionReplay,
        ProofExternalMemoryTransactionRequest, tests::TestStorage,
    };

    #[derive(Clone, Copy)]
    struct DiagonalBooleanR1cs {
        witness_length: usize,
    }

    impl CompactCfwR1csMatrices for DiagonalBooleanR1cs {
        fn witness_length(&self) -> usize {
            self.witness_length
        }

        fn evaluate_assignment_rows(
            &self,
            _matrix_role: CompactCfwMatrixRole,
            public_input: &[CompactChallengeField],
            witness: &[CompactChallengeField],
        ) -> Result<Vec<CompactChallengeField>, CompactCfwError> {
            if public_input.len() != self.witness_length || witness.len() != self.witness_length {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            Ok(public_input.iter().chain(witness).copied().collect())
        }

        fn public_contribution_at_row_point(
            &self,
            _matrix_role: CompactCfwMatrixRole,
            row_point: &[CompactChallengeField],
            public_input: &[CompactChallengeField],
        ) -> Result<CompactChallengeField, CompactCfwError> {
            if row_point.len() != self.witness_length.ilog2() as usize + 1
                || public_input.len() != self.witness_length
            {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            Ok(public_input
                .iter()
                .enumerate()
                .map(|(column_ordinal, &value)| {
                    value * test_boolean_point_weight(row_point, column_ordinal)
                })
                .sum())
        }

        fn accumulate_weighted_witness_covector_at_row_point(
            &self,
            row_point: &[CompactChallengeField],
            matrix_role_weights: [CompactChallengeField; COMPACT_CFW_MATRIX_COUNT],
            destination: &mut [CompactChallengeField],
        ) -> Result<(), CompactCfwError> {
            if row_point.len() != self.witness_length.ilog2() as usize + 1
                || destination.len() != self.witness_length
            {
                return Err(CompactCfwError::InvalidMatrixSource);
            }
            let combined_weight = matrix_role_weights
                .into_iter()
                .sum::<CompactChallengeField>();
            for (column_ordinal, destination_value) in destination.iter_mut().enumerate() {
                *destination_value += combined_weight
                    * test_boolean_point_weight(row_point, self.witness_length + column_ordinal);
            }
            Ok(())
        }
    }

    struct DenseExternalRowSource {
        witness_length: usize,
        rows: [Vec<ProofChallengeExtensionElement>; COMPACT_CFW_MATRIX_COUNT],
        evaluated_row_count: Cell<usize>,
    }

    impl DenseExternalRowSource {
        fn from_assignment(
            matrices: &impl CompactCfwR1csMatrices,
            public_input: &[CompactChallengeField],
            witness: &[CompactChallengeField],
        ) -> Self {
            let rows = CompactCfwMatrixRole::ALL.map(|matrix_role| {
                matrices
                    .evaluate_assignment_rows(matrix_role, public_input, witness)
                    .expect("the test matrix assignment evaluates")
                    .into_iter()
                    .map(|value| {
                        compact_challenge_to_production(value)
                            .expect("the test value uses production field coordinates")
                    })
                    .collect()
            });
            Self {
                witness_length: matrices.witness_length(),
                rows,
                evaluated_row_count: Cell::new(0),
            }
        }
    }

    impl CompactCfwExternalRowSource for DenseExternalRowSource {
        fn witness_length(&self) -> Result<usize, CompactCfwError> {
            Ok(self.witness_length)
        }

        fn row_count(&self) -> Result<usize, CompactCfwError> {
            let row_count = self.rows[0].len();
            if self.rows.iter().all(|rows| rows.len() == row_count) {
                Ok(row_count)
            } else {
                Err(CompactCfwError::InvalidMatrixSource)
            }
        }

        fn evaluate_row(
            &self,
            row_ordinal: usize,
        ) -> Result<[ProofChallengeExtensionElement; COMPACT_CFW_MATRIX_COUNT], CompactCfwError>
        {
            let values = core::array::from_fn(|matrix_ordinal| {
                self.rows[matrix_ordinal].get(row_ordinal).copied()
            });
            let [Some(left), Some(right), Some(product)] = values else {
                return Err(CompactCfwError::InvalidMatrixSource);
            };
            self.evaluated_row_count.set(
                self.evaluated_row_count
                    .get()
                    .checked_add(1)
                    .ok_or(CompactCfwError::CountOverflow)?,
            );
            Ok([left, right, product])
        }
    }

    fn extension_value(seed: u64) -> CompactChallengeField {
        CompactChallengeField::from_basis_coefficients_fn(|coordinate_ordinal| {
            Goldilocks::from_u64(seed + coordinate_ordinal as u64 * 17)
        })
    }

    fn test_boolean_point_weight(
        point: &[CompactChallengeField],
        boolean_index: usize,
    ) -> CompactChallengeField {
        point
            .iter()
            .enumerate()
            .map(|(coordinate_ordinal, &coordinate)| {
                let bit_ordinal = point.len() - 1 - coordinate_ordinal;
                if (boolean_index >> bit_ordinal) & 1 == 0 {
                    CompactChallengeField::ONE - coordinate
                } else {
                    coordinate
                }
            })
            .product()
    }

    fn execute_recorded_transaction(
        request: &ProofExternalMemoryTransactionRequest,
        storage: &mut TestStorage,
    ) -> Vec<Zeroizing<Vec<u8>>> {
        storage
            .begin_transaction(u64::MAX, u32::MAX)
            .expect("the test backend transaction begins");
        let mut read_results = Vec::new();
        for operation in request.operations() {
            match operation {
                ProofExternalMemoryTransactionOperation::Create {
                    object,
                    protection,
                    exact_byte_length,
                } => storage
                    .create_object(*object, *protection, *exact_byte_length)
                    .expect("the test backend object is created"),
                ProofExternalMemoryTransactionOperation::Append {
                    object,
                    expected_offset,
                    bytes,
                } => storage
                    .append_object_bytes(*object, *expected_offset, bytes)
                    .expect("the test backend bytes append"),
                ProofExternalMemoryTransactionOperation::Seal { object } => storage
                    .seal_object(*object)
                    .expect("the test backend object seals"),
                ProofExternalMemoryTransactionOperation::Read {
                    object,
                    offset,
                    byte_length,
                } => {
                    let mut result = Zeroizing::new(vec![
                        0_u8;
                        usize::try_from(*byte_length).expect(
                            "the test read length fits usize"
                        )
                    ]);
                    storage
                        .read_object_bytes(*object, *offset, &mut result)
                        .expect("the test backend bytes read");
                    read_results.push(result);
                }
                ProofExternalMemoryTransactionOperation::Delete { object } => storage
                    .delete_object(*object)
                    .expect("the test backend object deletes"),
            }
        }
        storage
            .commit_transaction()
            .expect("the test backend transaction commits");
        read_results
    }

    fn advance_round_polynomial_with_record_replay(
        prover: &mut CompactCfwExternalProverState,
        row_source: &impl CompactCfwExternalRowSource,
        recorder: &mut ProofExternalMemoryTransactionRecorder,
        backend_storage: &mut TestStorage,
    ) -> Option<[CompactChallengeField; COMPACT_CFW_OUTER_MASK_MESSAGE_LENGTH]> {
        match prover.advance_round_polynomial(row_source, recorder) {
            Ok(polynomial) => polynomial,
            Err(CompactCfwExternalProverExecutionError::Storage(
                ProofExternalMemoryExecutorError::StorageCommit(
                    ProofExternalMemoryTransactionAdapterError::Yielded,
                ),
            )) => {
                let request = recorder
                    .take_yielded_request()
                    .expect("the round-polynomial transaction yielded a request");
                let read_results = execute_recorded_transaction(&request, backend_storage);
                let mut replay = ProofExternalMemoryTransactionReplay::new(request, read_results)
                    .expect("the round-polynomial response matches the request");
                prover
                    .advance_round_polynomial(row_source, &mut replay)
                    .expect("the round-polynomial transaction replays")
            }
            Err(error) => panic!("unexpected round-polynomial error: {error:?}"),
        }
    }

    fn advance_bound_round_with_record_replay(
        prover: &mut CompactCfwExternalProverState,
        row_source: &impl CompactCfwExternalRowSource,
        recorder: &mut ProofExternalMemoryTransactionRecorder,
        backend_storage: &mut TestStorage,
    ) -> bool {
        match prover.advance_bound_round(row_source, recorder) {
            Ok(is_complete) => is_complete,
            Err(CompactCfwExternalProverExecutionError::Storage(
                ProofExternalMemoryExecutorError::StorageCommit(
                    ProofExternalMemoryTransactionAdapterError::Yielded,
                ),
            )) => {
                let request = recorder
                    .take_yielded_request()
                    .expect("the bound-round transaction yielded a request");
                let read_results = execute_recorded_transaction(&request, backend_storage);
                let mut replay = ProofExternalMemoryTransactionReplay::new(request, read_results)
                    .expect("the bound-round response matches the request");
                prover
                    .advance_bound_round(row_source, &mut replay)
                    .expect("the bound-round transaction replays")
            }
            Err(error) => panic!("unexpected bound-round error: {error:?}"),
        }
    }

    #[test]
    fn external_memory_prover_matches_resident_transcript_and_exact_plan_usage() {
        let matrices = DiagonalBooleanR1cs { witness_length: 16 };
        let geometry = CompactCfwGeometry::derive(matrices.witness_length())
            .expect("the test CFW geometry is valid");
        let public_input = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64((ordinal % 3 == 0) as u64))
            .collect::<Vec<_>>();
        let witness = (0..matrices.witness_length())
            .map(|ordinal| CompactChallengeField::from_u64((ordinal % 2 == 0) as u64))
            .collect::<Vec<_>>();
        let row_source =
            DenseExternalRowSource::from_assignment(&matrices, &public_input, &witness);
        let mut mask_seed = 10_000_u64;
        let mask_material = CompactCfwMaskMaterial::sample(geometry, || {
            mask_seed += 29;
            extension_value(mask_seed)
        })
        .expect("the test mask material is valid");
        let equality_point = (0..geometry.sumcheck_round_count())
            .map(|ordinal| extension_value(20_000 + ordinal as u64 * 31))
            .collect::<Vec<_>>();
        let round_challenges = (0..geometry.sumcheck_round_count())
            .map(|ordinal| extension_value(30_000 + ordinal as u64 * 37))
            .collect::<Vec<_>>();
        let constraint_combining_challenge = extension_value(40_001);

        let prepared = PreparedCompactCfwProver::prepare(
            &matrices,
            &public_input,
            &witness,
            mask_material.clone(),
        )
        .expect("the resident reference prover prepares");
        let auxiliary_target = prepared.auxiliary_target();
        let mut resident = prepared
            .begin(constraint_combining_challenge, equality_point.clone())
            .expect("the resident reference prover begins");
        let mut external = CompactCfwExternalProverState::prepare(
            &row_source,
            mask_material,
            constraint_combining_challenge,
            equality_point,
        )
        .expect("the external-memory prover prepares");
        assert_eq!(external.auxiliary_target(), auxiliary_target);

        let mut recorder = ProofExternalMemoryTransactionRecorder::new();
        let mut backend_storage = TestStorage::default();
        let mut resident_round_polynomials = Vec::with_capacity(round_challenges.len());
        let mut external_round_polynomials = Vec::with_capacity(round_challenges.len());
        for (round_ordinal, &challenge) in round_challenges.iter().enumerate() {
            let resident_polynomial = resident
                .next_round_polynomial()
                .expect("the resident round polynomial derives");
            let mut derivation_poll_count = 0_usize;
            let external_polynomial = loop {
                derivation_poll_count += 1;
                assert!(derivation_poll_count <= 16);
                if let Some(polynomial) = advance_round_polynomial_with_record_replay(
                    &mut external,
                    &row_source,
                    &mut recorder,
                    &mut backend_storage,
                ) {
                    break polynomial;
                }
            };
            assert_eq!(external_polynomial, resident_polynomial);
            resident_round_polynomials.push(resident_polynomial);
            external_round_polynomials.push(external_polynomial);

            resident
                .bind_round_challenge(challenge)
                .expect("the resident challenge binds");
            if round_ordinal + 1 == round_challenges.len() {
                assert_eq!(
                    external.bind_round_challenge(CompactChallengeField::ZERO),
                    Err(CompactCfwError::InvalidFinalChallenge)
                );
            }
            external
                .bind_round_challenge(challenge)
                .expect("the external challenge binds");
            let mut bound_round_poll_count = 0_usize;
            while !advance_bound_round_with_record_replay(
                &mut external,
                &row_source,
                &mut recorder,
                &mut backend_storage,
            ) {
                bound_round_poll_count += 1;
                assert!(bound_round_poll_count <= 128);
            }
        }

        let resident_finish = resident.finish().expect("the resident prover finishes");
        let external_output = external.finish().expect("the external prover finishes");
        assert_eq!(
            external_output.finish().outer_evaluations(),
            resident_finish.outer_evaluations()
        );
        assert_eq!(
            external_output.finish().final_values(),
            resident_finish.final_values()
        );

        let expected_catalog = CompactCfwExternalStorageCatalog::derive(geometry)
            .expect("the expected external-memory catalog derives");
        let usage = external_output.usage();
        assert_eq!(
            usage.total_written_byte_length(),
            expected_catalog.total_written_byte_length()
        );
        assert_eq!(
            usage.total_read_byte_length(),
            expected_catalog.total_read_byte_length()
        );
        assert_eq!(
            usage.peak_stored_byte_length(),
            expected_catalog.peak_stored_byte_length()
        );
        assert_eq!(
            usage.transaction_count(),
            expected_catalog.total_transaction_count()
        );
        assert_eq!(
            u64::from(usage.deleted_object_count()),
            expected_catalog.object_lifecycle_count()
        );
        assert_eq!(
            row_source.evaluated_row_count.get(),
            geometry.r1cs_row_count() * 2
        );

        let external_finish = external_output.into_finish();
        let resident_transcript = CompactCfwTranscript::new(
            auxiliary_target,
            resident_round_polynomials,
            resident_finish.outer_evaluations().to_vec(),
            resident_finish.final_values(),
        );
        let external_transcript = CompactCfwTranscript::new(
            auxiliary_target,
            external_round_polynomials,
            external_finish.outer_evaluations().to_vec(),
            external_finish.final_values(),
        );
        assert_eq!(external_transcript, resident_transcript);
    }

    #[test]
    fn external_memory_prover_refuses_malformed_source_geometry_and_wrong_phase() {
        let matrices = DiagonalBooleanR1cs { witness_length: 4 };
        let public_input = vec![CompactChallengeField::ZERO; 4];
        let witness = vec![CompactChallengeField::ZERO; 4];
        let mut row_source =
            DenseExternalRowSource::from_assignment(&matrices, &public_input, &witness);
        row_source.rows[2].pop();
        let geometry = CompactCfwGeometry::derive(4).expect("the test geometry is valid");
        let mask_material = CompactCfwMaskMaterial::sample(geometry, || extension_value(51))
            .expect("the test masks are valid");
        let equality_point = vec![extension_value(61); geometry.sumcheck_round_count()];
        assert!(matches!(
            CompactCfwExternalProverState::prepare(
                &row_source,
                mask_material,
                extension_value(71),
                equality_point,
            ),
            Err(CompactCfwExternalProverSetupError::Cfw(
                CompactCfwError::InvalidMatrixSource
            ))
        ));

        let valid_row_source =
            DenseExternalRowSource::from_assignment(&matrices, &public_input, &witness);
        let mask_material = CompactCfwMaskMaterial::sample(geometry, || extension_value(81))
            .expect("the test masks are valid");
        let mut external = CompactCfwExternalProverState::prepare(
            &valid_row_source,
            mask_material,
            extension_value(91),
            vec![extension_value(101); geometry.sumcheck_round_count()],
        )
        .expect("the valid test prover prepares");
        assert_eq!(
            external.bind_round_challenge(extension_value(111)),
            Err(CompactCfwError::WrongProverPhase)
        );
        let mut storage = TestStorage::default();
        assert!(matches!(
            external.advance_bound_round(&valid_row_source, &mut storage),
            Err(CompactCfwExternalProverExecutionError::Cfw(
                CompactCfwError::WrongProverPhase
            ))
        ));
        assert!(matches!(
            external.finish(),
            Err(CompactCfwExternalProverFinishError::Cfw(
                CompactCfwError::WrongProverPhase
            ))
        ));
    }
}
