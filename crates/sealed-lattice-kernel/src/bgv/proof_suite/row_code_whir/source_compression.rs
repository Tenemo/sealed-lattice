//! Streaming prefix compression of an external aggregate source table.
//!
//! The full interleaved polynomial is never resident. Each canonical source
//! column is read once and accumulated into the exact scalar residual selected
//! by the first prefix-sumcheck challenges.

use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::{point::Point, poly::Poly};

use super::ChallengeField;
use super::aggregate_source_storage::{
    AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH, AggregateSourceTable, decode_source_values,
};
use super::oracle_geometry::logical_column_selector_index;
use crate::bgv::proof_suite::{
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError,
};

pub(super) enum ExternalSourceCompressionPoll {
    StorageTransactionCompleted,
    Complete(Poly<ChallengeField>),
}

pub(super) struct ExternalSourceCompression {
    table: AggregateSourceTable,
    folding_point: Point<ChallengeField>,
    residual: Option<Vec<ChallengeField>>,
    current_column_index: usize,
    current_element_offset: usize,
    encoded_chunk: Vec<u8>,
    decoded_chunk: Vec<ChallengeField>,
}

impl ExternalSourceCompression {
    pub(super) fn new(
        table: AggregateSourceTable,
        folding_point: Point<ChallengeField>,
    ) -> Result<Self, String> {
        if folding_point.num_variables() != table.folding_factor()
            || table.folding_factor() > table.stacked_variable_count()
        {
            return Err("external source compression has an invalid point".to_owned());
        }
        let residual_variable_count = table
            .stacked_variable_count()
            .checked_sub(table.folding_factor())
            .ok_or_else(|| "external source residual arity underflowed".to_owned())?;
        let residual_element_count = 1_usize
            .checked_shl(
                u32::try_from(residual_variable_count)
                    .map_err(|_| "external source residual arity exceeds u32")?,
            )
            .ok_or_else(|| "external source residual length overflowed".to_owned())?;
        let mut residual = Vec::new();
        residual
            .try_reserve_exact(residual_element_count)
            .map_err(|_| "allocate external source residual".to_owned())?;
        residual.resize(residual_element_count, ChallengeField::ZERO);
        Ok(Self {
            table,
            folding_point,
            residual: Some(residual),
            current_column_index: 0,
            current_element_offset: 0,
            encoded_chunk: Vec::new(),
            decoded_chunk: Vec::new(),
        })
    }

    pub(super) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<ExternalSourceCompressionPoll, ProofExternalMemoryExecutorError<Storage::Error>>
    {
        if self.current_column_index == self.table.table_width() {
            let residual = self
                .residual
                .take()
                .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
            return Ok(ExternalSourceCompressionPoll::Complete(Poly::new(residual)));
        }
        let maximum_element_count = usize::try_from(executor.maximum_chunk_byte_length())
            .ok()
            .and_then(|bytes| bytes.checked_div(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH))
            .filter(|count| *count > 0)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let vector = self.table.columns()[self.current_column_index];
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
        accumulate_source_chunk(
            self.residual
                .as_mut()
                .ok_or(ProofExternalMemoryError::InvalidLifecycle)?,
            self.table.table_width(),
            self.table.folding_factor(),
            self.current_column_index,
            self.current_element_offset,
            &self.decoded_chunk,
            &self.folding_point,
        )
        .map_err(ProofExternalMemoryExecutorError::Execution)?;
        self.decoded_chunk.fill(ChallengeField::ZERO);
        self.decoded_chunk.clear();
        self.current_element_offset += element_count;
        if self.current_element_offset == vector.element_count() {
            self.current_element_offset = 0;
            self.current_column_index += 1;
        }
        Ok(ExternalSourceCompressionPoll::StorageTransactionCompleted)
    }
}

impl Drop for ExternalSourceCompression {
    fn drop(&mut self) {
        if let Some(residual) = self.residual.as_mut() {
            residual.fill(ChallengeField::ZERO);
        }
        self.encoded_chunk.fill(0);
        self.decoded_chunk.fill(ChallengeField::ZERO);
    }
}

fn accumulate_source_chunk(
    residual: &mut [ChallengeField],
    table_width: usize,
    folding_factor: usize,
    logical_column_index: usize,
    first_local_index: usize,
    values: &[ChallengeField],
    folding_point: &Point<ChallengeField>,
) -> Result<(), ProofExternalMemoryError> {
    if !table_width.is_power_of_two()
        || logical_column_index >= table_width
        || folding_point.num_variables() != folding_factor
    {
        return Err(ProofExternalMemoryError::InvalidPlan);
    }
    let selector_variable_count = table_width.ilog2() as usize;
    let selector_index = logical_column_selector_index(logical_column_index, table_width)
        .map_err(|_| ProofExternalMemoryError::InvalidPlan)?;
    let residual_element_count = residual.len();
    if !residual_element_count.is_power_of_two() {
        return Err(ProofExternalMemoryError::InvalidPlan);
    }
    let residual_variable_count = residual_element_count.ilog2() as usize;
    let prefix_element_count = 1_usize
        .checked_shl(
            u32::try_from(folding_factor)
                .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?,
        )
        .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
    let mut prefix_weights = Vec::with_capacity(prefix_element_count);
    for prefix_index in 0..prefix_element_count {
        let mut weight = ChallengeField::ONE;
        for (variable_index, coordinate) in folding_point.as_slice().iter().copied().enumerate() {
            let bit_position = folding_factor - 1 - variable_index;
            weight *= if prefix_index & (1 << bit_position) == 0 {
                ChallengeField::ONE - coordinate
            } else {
                coordinate
            };
        }
        prefix_weights.push(weight);
    }
    let residual_mask = residual_element_count - 1;
    for (local_offset, value) in values.iter().copied().enumerate() {
        let local_index = first_local_index
            .checked_add(local_offset)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let stacked_index = local_index
            .checked_shl(selector_variable_count as u32)
            .and_then(|index| index.checked_add(selector_index))
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let prefix_index = stacked_index >> residual_variable_count;
        let residual_index = stacked_index & residual_mask;
        let weight = *prefix_weights
            .get(prefix_index)
            .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?;
        *residual
            .get_mut(residual_index)
            .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)? += weight * value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_columns_match_interleaved_prefix_compression() {
        for (table_variable_count, table_width, folding_factor) in
            [(5_usize, 4_usize, 3_usize), (3_usize, 32_usize, 3_usize)]
        {
            let local_count = 1 << table_variable_count;
            let stacked_variable_count = table_variable_count + table_width.ilog2() as usize;
            let columns = (0..table_width)
                .map(|column_index| {
                    (0..local_count)
                        .map(|local_index| {
                            ChallengeField::from_u64(
                                1 + (column_index * local_count + local_index) as u64,
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mut stacked = ChallengeField::zero_vec(1 << stacked_variable_count);
            let selector_variable_count = table_width.ilog2() as usize;
            for (logical_column_index, column) in columns.iter().enumerate() {
                let selector_index = logical_column_index.reverse_bits()
                    >> (usize::BITS as usize - selector_variable_count);
                for (local_index, value) in column.iter().copied().enumerate() {
                    stacked[(local_index << selector_variable_count) | selector_index] = value;
                }
            }
            let folding_point = Point::new(vec![
                ChallengeField::from_u64(3),
                ChallengeField::from_u64(5),
                ChallengeField::from_u64(7),
            ]);
            let expected = Poly::new(stacked).compress_prefix(&folding_point, ChallengeField::ONE);
            let mut actual =
                ChallengeField::zero_vec(1 << (stacked_variable_count - folding_factor));
            for (column_index, column) in columns.iter().enumerate() {
                for (chunk_index, chunk) in column.chunks(7).enumerate() {
                    accumulate_source_chunk(
                        &mut actual,
                        table_width,
                        folding_factor,
                        column_index,
                        chunk_index * 7,
                        chunk,
                        &folding_point,
                    )
                    .expect("valid streamed source chunk");
                }
            }
            assert_eq!(actual, expected.into_evals());
        }
    }
}
