//! Canonical external storage for recomputable aggregate-wide oracle sources.
//!
//! The selected commitment never retains an encoded Reed--Solomon codeword.
//! It stores only the unencoded source table (column-major for the initial
//! aggregate) and one unencoded residual polynomial for each later epoch.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_sumcheck::product_polynomial::PolyView;
use zeroize::Zeroizing;

use super::aggregate_wide_pcs::AggregateWidePcs;
use super::{ChallengeField, challenge_from_production};
use crate::bgv::proof_suite::external_memory::{
    ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan,
};
use crate::bgv::proof_suite::external_polynomial::ExternalPolynomialVector;
use crate::bgv::proof_suite::relation_plan::RelationColumnValueType;
use crate::bgv::proof_suite::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, ProofChallengeExtensionElement,
    ProofExternalMemory, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject, ProofExternalMemoryProtection,
};

pub(super) const AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH: usize = 5 * 8;

pub(super) struct AggregateSourceStoragePlan {
    external_memory_plan: ProofExternalMemoryPlan,
    table: AggregateSourceTable,
    residuals: Vec<ExternalPolynomialVector>,
}

impl AggregateSourceStoragePlan {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_new(
        pcs: &AggregateWidePcs,
        table_variable_count: usize,
        table_width: usize,
        folding_factor: usize,
        maximum_opened_column_count: usize,
        first_physical_object_ordinal: u32,
    ) -> Result<Self, String> {
        if table_width < 2
            || !table_width.is_power_of_two()
            || table_variable_count + table_width.ilog2() as usize != pcs.num_variables
            || folding_factor != pcs.round_folding_factor(0)
            || maximum_opened_column_count == 0
            || maximum_opened_column_count > table_width
        {
            return Err("aggregate source storage geometry is invalid".to_owned());
        }
        let local_element_count = 1_usize
            .checked_shl(
                u32::try_from(table_variable_count)
                    .map_err(|_| "aggregate source table arity exceeds u32")?,
            )
            .ok_or_else(|| "aggregate source table length overflowed".to_owned())?;
        let element_byte_length = u64::try_from(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
            .map_err(|_| "aggregate source element width exceeds u64")?;
        let column_byte_length = u64::try_from(local_element_count)
            .ok()
            .and_then(|count| count.checked_mul(element_byte_length))
            .ok_or_else(|| "aggregate source column byte length overflowed".to_owned())?;
        let chunk_byte_length = u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
        let maximum_chunk_element_count = usize::try_from(chunk_byte_length)
            .ok()
            .and_then(|bytes| bytes.checked_div(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH))
            .filter(|count| *count > 0)
            .ok_or_else(|| "aggregate source chunk cannot hold one element".to_owned())?;
        let step_count = u32::try_from(
            pcs.n_rounds()
                .checked_add(2)
                .ok_or_else(|| "aggregate source step count overflowed".to_owned())?,
        )
        .map_err(|_| "aggregate source step count exceeds u32".to_owned())?;

        let mut object_plans = Vec::new();
        let mut columns = Vec::with_capacity(table_width);
        let mut next_object_ordinal = first_physical_object_ordinal;
        let half_width = table_width / 2;
        let column_append_count =
            contiguous_element_transaction_count(local_element_count, maximum_chunk_element_count)?;
        for column_index in 0..table_width {
            let object = ProofExternalMemoryObject::new(next_object_ordinal);
            next_object_ordinal = next_object_ordinal
                .checked_add(1)
                .ok_or_else(|| "aggregate source object ordinal overflowed".to_owned())?;
            let issued_step = if column_index < half_width { 0 } else { 1 };
            object_plans.push(
                ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                    object,
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    column_byte_length,
                    column_append_count,
                    issued_step,
                    issued_step,
                    1,
                ),
            );
            columns.push(source_vector(object, local_element_count)?);
        }
        let table = AggregateSourceTable::new(columns, table_variable_count, folding_factor)?;

        let mut residuals = Vec::with_capacity(pcs.n_rounds());
        let mut residual_byte_lengths = Vec::with_capacity(pcs.n_rounds());
        let mut residual_read_transaction_count = 0_u64;
        let mut residual_variable_count = pcs.num_variables;
        for residual_ordinal in 1..=pcs.n_rounds() {
            residual_variable_count = residual_variable_count
                .checked_sub(pcs.round_folding_factor(residual_ordinal - 1))
                .ok_or_else(|| "aggregate residual variable count underflowed".to_owned())?;
            let element_count = 1_usize
                .checked_shl(
                    u32::try_from(residual_variable_count)
                        .map_err(|_| "aggregate residual arity exceeds u32")?,
                )
                .ok_or_else(|| "aggregate residual length overflowed".to_owned())?;
            let exact_byte_length = u64::try_from(element_count)
                .ok()
                .and_then(|count| count.checked_mul(element_byte_length))
                .ok_or_else(|| "aggregate residual byte length overflowed".to_owned())?;
            let object = ProofExternalMemoryObject::new(next_object_ordinal);
            next_object_ordinal = next_object_ordinal
                .checked_add(1)
                .ok_or_else(|| "aggregate residual object ordinal overflowed".to_owned())?;
            let issued_step = u32::try_from(residual_ordinal)
                .map_err(|_| "aggregate residual step exceeds u32".to_owned())?;
            object_plans.push(
                ProofExternalMemoryObjectPlan::new_with_maximum_append_count(
                    object,
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    exact_byte_length,
                    contiguous_element_transaction_count(
                        element_count,
                        maximum_chunk_element_count,
                    )?,
                    issued_step,
                    issued_step,
                    issued_step
                        .checked_add(1)
                        .ok_or_else(|| "aggregate residual last-use step overflowed".to_owned())?,
                ),
            );
            residuals.push(source_vector(object, element_count)?);
            residual_byte_lengths.push(exact_byte_length);
            residual_read_transaction_count = residual_read_transaction_count
                .checked_add(recomputable_vector_read_transaction_count(
                    element_count,
                    pcs.round_folding_factor(residual_ordinal),
                    maximum_chunk_element_count,
                )?)
                .ok_or_else(|| "aggregate residual read transaction count overflowed".to_owned())?;
        }

        let table_byte_length = column_byte_length
            .checked_mul(u64::try_from(table_width).map_err(|_| "table width exceeds u64")?)
            .ok_or_else(|| "aggregate source table byte length overflowed".to_owned())?;
        let total_written_byte_length = residual_byte_lengths
            .iter()
            .try_fold(table_byte_length, |total, length| {
                total.checked_add(*length)
            })
            .ok_or_else(|| "aggregate source write accounting overflowed".to_owned())?;
        let opened_column_byte_length = column_byte_length
            .checked_mul(
                u64::try_from(maximum_opened_column_count)
                    .map_err(|_| "opened column count exceeds u64")?,
            )
            .ok_or_else(|| "aggregate opened-column accounting overflowed".to_owned())?;
        let total_read_byte_length = residual_byte_lengths
            .iter()
            .try_fold(
                table_byte_length
                    .checked_mul(3)
                    .and_then(|bytes| bytes.checked_add(opened_column_byte_length))
                    .ok_or_else(|| "aggregate initial read accounting overflowed".to_owned())?,
                |total, length| total.checked_add(*length),
            )
            .ok_or_else(|| "aggregate source read accounting overflowed".to_owned())?;
        let maximum_stored_byte_length = residual_byte_lengths
            .first()
            .copied()
            .unwrap_or(0)
            .checked_add(table_byte_length)
            .ok_or_else(|| "aggregate source peak storage overflowed".to_owned())?;
        let append_transaction_count = object_plans
            .iter()
            .try_fold(0_u64, |total, object| {
                total.checked_add(object.maximum_append_count())
            })
            .ok_or_else(|| "aggregate append transaction count overflowed".to_owned())?;
        let full_column_read_transaction_count =
            contiguous_element_transaction_count(local_element_count, maximum_chunk_element_count)?;
        let table_recomputation_transaction_count = recomputable_table_read_transaction_count(
            local_element_count,
            table_width,
            folding_factor,
            maximum_chunk_element_count,
        )?
        .checked_mul(2)
        .ok_or_else(|| "aggregate table recomputation count overflowed".to_owned())?;
        let sequential_table_read_count = u64::try_from(
            table_width
                .checked_add(maximum_opened_column_count)
                .ok_or_else(|| "aggregate sequential read column count overflowed".to_owned())?,
        )
        .ok()
        .and_then(|count| count.checked_mul(full_column_read_transaction_count))
        .ok_or_else(|| "aggregate sequential read transaction count overflowed".to_owned())?;
        let read_transaction_count = table_recomputation_transaction_count
            .checked_add(sequential_table_read_count)
            .and_then(|count| count.checked_add(residual_read_transaction_count))
            .ok_or_else(|| "aggregate read transaction count overflowed".to_owned())?;
        let object_count = u64::try_from(object_plans.len())
            .map_err(|_| "aggregate source object count exceeds u64")?;
        let deletion_transaction_count = u64::try_from(pcs.n_rounds() + 1)
            .map_err(|_| "aggregate deletion transaction count exceeds u64")?;
        let maximum_transaction_count = append_transaction_count
            .checked_add(read_transaction_count)
            .and_then(|count| count.checked_add(object_count.checked_mul(2)?))
            .and_then(|count| count.checked_add(deletion_transaction_count))
            .ok_or_else(|| "aggregate transaction accounting overflowed".to_owned())?;
        let maximum_transaction_operation_count = u32::try_from(table_width.max(2))
            .map_err(|_| "aggregate transaction operation count exceeds u32".to_owned())?;
        let external_memory_plan = ProofExternalMemoryPlan::new(
            step_count,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            chunk_byte_length,
            maximum_transaction_operation_count,
            maximum_stored_byte_length,
            total_written_byte_length,
            total_read_byte_length,
            maximum_transaction_count,
            object_plans,
        )
        .map_err(|error| format!("construct aggregate source storage plan: {error:?}"))?;
        Ok(Self {
            external_memory_plan,
            table,
            residuals,
        })
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        ProofExternalMemoryPlan,
        AggregateSourceTable,
        Vec<ExternalPolynomialVector>,
    ) {
        (self.external_memory_plan, self.table, self.residuals)
    }
}

fn contiguous_element_transaction_count(
    element_count: usize,
    maximum_chunk_element_count: usize,
) -> Result<u64, String> {
    if element_count == 0 || maximum_chunk_element_count == 0 {
        return Err("aggregate source transaction geometry is empty".to_owned());
    }
    u64::try_from(element_count.div_ceil(maximum_chunk_element_count))
        .map_err(|_| "aggregate source transaction count exceeds u64".to_owned())
}

fn recomputable_vector_read_transaction_count(
    element_count: usize,
    folding_factor: usize,
    maximum_chunk_element_count: usize,
) -> Result<u64, String> {
    let encoded_width = 1_usize
        .checked_shl(
            u32::try_from(folding_factor)
                .map_err(|_| "aggregate folding factor exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "aggregate encoded width overflowed".to_owned())?;
    if element_count == 0 || element_count % encoded_width != 0 {
        return Err("aggregate recomputable vector does not split evenly".to_owned());
    }
    let segment_transaction_count = contiguous_element_transaction_count(
        element_count / encoded_width,
        maximum_chunk_element_count,
    )?;
    u64::try_from(encoded_width)
        .ok()
        .and_then(|width| width.checked_mul(segment_transaction_count))
        .ok_or_else(|| "aggregate recomputable read transaction count overflowed".to_owned())
}

fn recomputable_table_read_transaction_count(
    column_element_count: usize,
    table_width: usize,
    folding_factor: usize,
    maximum_chunk_element_count: usize,
) -> Result<u64, String> {
    let encoded_width = 1_usize
        .checked_shl(
            u32::try_from(folding_factor)
                .map_err(|_| "aggregate folding factor exceeds u32".to_owned())?,
        )
        .ok_or_else(|| "aggregate encoded width overflowed".to_owned())?;
    if table_width == 0
        || !table_width.is_power_of_two()
        || column_element_count == 0
        || column_element_count % encoded_width != 0
    {
        return Err("aggregate recomputable table does not split evenly".to_owned());
    }
    let segment_transaction_count = contiguous_element_transaction_count(
        column_element_count / encoded_width,
        maximum_chunk_element_count,
    )?;
    u64::try_from(table_width)
        .ok()
        .and_then(|width| width.checked_mul(encoded_width as u64))
        .and_then(|segment_count| segment_count.checked_mul(segment_transaction_count))
        .ok_or_else(|| "aggregate recomputable table read count overflowed".to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AggregateSourceTable {
    columns: Vec<ExternalPolynomialVector>,
    table_variable_count: usize,
    folding_factor: usize,
}

impl AggregateSourceTable {
    pub(super) fn new(
        columns: Vec<ExternalPolynomialVector>,
        table_variable_count: usize,
        folding_factor: usize,
    ) -> Result<Self, String> {
        let expected_element_count = 1_usize
            .checked_shl(
                u32::try_from(table_variable_count)
                    .map_err(|_| "aggregate source table variable count exceeds u32")?,
            )
            .ok_or_else(|| "aggregate source table element count overflowed".to_owned())?;
        if columns.is_empty()
            || !columns.len().is_power_of_two()
            || folding_factor == 0
            || folding_factor > table_variable_count + columns.len().ilog2() as usize
            || columns.iter().any(|column| {
                column.value_type() != RelationColumnValueType::ChallengeExtension
                    || column.element_count() != expected_element_count
            })
        {
            return Err("aggregate source table has an invalid shape".to_owned());
        }
        Ok(Self {
            columns,
            table_variable_count,
            folding_factor,
        })
    }

    pub(super) fn columns(&self) -> &[ExternalPolynomialVector] {
        &self.columns
    }

    pub(super) const fn table_variable_count(&self) -> usize {
        self.table_variable_count
    }

    pub(super) fn table_width(&self) -> usize {
        self.columns.len()
    }

    pub(super) const fn folding_factor(&self) -> usize {
        self.folding_factor
    }

    pub(super) fn stacked_variable_count(&self) -> usize {
        self.table_variable_count + self.columns.len().ilog2() as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateSourceWriterStage {
    Begin,
    Append,
    Seal,
    Complete,
}

pub(super) enum AggregateSourceValues<'values> {
    Slice(&'values [ChallengeField]),
    Polynomial(PolyView<'values, ChallengeField, ChallengeField>),
}

impl AggregateSourceValues<'_> {
    fn element_count(&self) -> usize {
        match self {
            Self::Slice(values) => values.len(),
            Self::Polynomial(polynomial) => 1_usize << polynomial.num_variables(),
        }
    }

    fn copy_range(
        &self,
        element_offset: usize,
        destination: &mut [ChallengeField],
    ) -> Result<(), ProofExternalMemoryError> {
        match self {
            Self::Slice(values) => destination.copy_from_slice(
                values
                    .get(element_offset..element_offset + destination.len())
                    .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?,
            ),
            Self::Polynomial(polynomial) => polynomial
                .copy_logical_range_into(element_offset, destination.len(), destination)
                .map_err(|_| ProofExternalMemoryError::WrongOffsetOrLength)?,
        }
        Ok(())
    }
}

/// Append-only canonical writer for one unencoded source column or residual.
pub(super) struct AggregateSourceWriter {
    vector: ExternalPolynomialVector,
    next_element_offset: usize,
    encoded_chunk: Zeroizing<Vec<u8>>,
    decoded_chunk: Vec<ChallengeField>,
    stage: AggregateSourceWriterStage,
}

impl AggregateSourceWriter {
    pub(super) fn new(vector: ExternalPolynomialVector) -> Result<Self, String> {
        if vector.value_type() != RelationColumnValueType::ChallengeExtension
            || vector.element_count() == 0
        {
            return Err("aggregate source writer has an invalid vector".to_owned());
        }
        Ok(Self {
            vector,
            next_element_offset: 0,
            encoded_chunk: Zeroizing::new(Vec::new()),
            decoded_chunk: Vec::new(),
            stage: AggregateSourceWriterStage::Begin,
        })
    }

    pub(super) fn poll<Storage: ProofExternalMemory>(
        &mut self,
        source: AggregateSourceValues<'_>,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<bool, ProofExternalMemoryExecutorError<Storage::Error>> {
        if source.element_count() != self.vector.element_count() {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        match self.stage {
            AggregateSourceWriterStage::Begin => {
                executor.begin_object(storage, self.vector.object())?;
                self.stage = AggregateSourceWriterStage::Append;
                Ok(false)
            }
            AggregateSourceWriterStage::Append => {
                let maximum_chunk_byte_length =
                    usize::try_from(executor.maximum_chunk_byte_length())
                        .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                let maximum_element_count = maximum_chunk_byte_length
                    .checked_div(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
                    .filter(|count| *count > 0)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                let element_count = maximum_element_count.min(
                    self.vector
                        .element_count()
                        .saturating_sub(self.next_element_offset),
                );
                if element_count == 0 {
                    return Err(ProofExternalMemoryError::InvalidLifecycle.into());
                }
                self.decoded_chunk.clear();
                self.decoded_chunk
                    .resize(element_count, ChallengeField::ZERO);
                source.copy_range(self.next_element_offset, &mut self.decoded_chunk)?;
                self.encoded_chunk.clear();
                self.encoded_chunk
                    .try_reserve_exact(element_count * AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
                for value in &self.decoded_chunk {
                    for coordinate in <ChallengeField as BasedVectorSpace<Goldilocks>>::
                        as_basis_coefficients_slice(value)
                    {
                        self.encoded_chunk
                            .extend_from_slice(&coordinate.as_canonical_u64().to_le_bytes());
                    }
                }
                executor.append_owned_object_bytes(
                    storage,
                    self.vector.object(),
                    &mut self.encoded_chunk,
                )?;
                self.decoded_chunk.fill(ChallengeField::ZERO);
                self.decoded_chunk.clear();
                self.next_element_offset = self
                    .next_element_offset
                    .checked_add(element_count)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                if self.next_element_offset == self.vector.element_count() {
                    self.stage = AggregateSourceWriterStage::Seal;
                }
                Ok(false)
            }
            AggregateSourceWriterStage::Seal => {
                executor.seal_object(storage, self.vector.object())?;
                self.stage = AggregateSourceWriterStage::Complete;
                Ok(true)
            }
            AggregateSourceWriterStage::Complete => Ok(true),
        }
    }
}

impl Drop for AggregateSourceWriter {
    fn drop(&mut self) {
        self.encoded_chunk.fill(0);
        self.decoded_chunk.fill(ChallengeField::ZERO);
    }
}

pub(super) fn decode_source_values(
    encoded: &[u8],
    destination: &mut [ChallengeField],
) -> Result<(), ProofExternalMemoryError> {
    if encoded.len()
        != destination
            .len()
            .checked_mul(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?
    {
        return Err(ProofExternalMemoryError::WrongOffsetOrLength);
    }
    for (destination, encoded_value) in destination
        .iter_mut()
        .zip(encoded.chunks_exact(AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH))
    {
        let mut coordinates = [0_u64; 5];
        for (coordinate, bytes) in coordinates.iter_mut().zip(encoded_value.chunks_exact(8)) {
            *coordinate = u64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| ProofExternalMemoryError::WrongOffsetOrLength)?,
            );
        }
        let production = ProofChallengeExtensionElement::from_canonical_coordinates(coordinates)
            .map_err(|_| ProofExternalMemoryError::InvalidLifecycle)?;
        *destination = challenge_from_production(production);
    }
    Ok(())
}

pub(super) fn source_vector(
    object: ProofExternalMemoryObject,
    element_count: usize,
) -> Result<ExternalPolynomialVector, String> {
    ExternalPolynomialVector::new(
        object,
        RelationColumnValueType::ChallengeExtension,
        element_count,
    )
    .map_err(|_| "construct aggregate source external vector".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_source_codec_rejects_noncanonical_coordinates() {
        let mut encoded = vec![0_u8; AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH];
        encoded[..8].copy_from_slice(&0xffff_ffff_0000_0001_u64.to_le_bytes());
        let mut destination = [ChallengeField::ZERO];
        assert_eq!(
            decode_source_values(&encoded, &mut destination),
            Err(ProofExternalMemoryError::InvalidLifecycle)
        );
    }

    #[test]
    fn source_transaction_accounting_uses_element_aligned_chunks_and_pass_boundaries() {
        let maximum_chunk_element_count = MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
            as usize
            / AGGREGATE_SOURCE_ELEMENT_BYTE_LENGTH;
        assert_eq!(maximum_chunk_element_count, 26_214);

        assert_eq!(
            contiguous_element_transaction_count(1 << 22, maximum_chunk_element_count),
            Ok(161),
            "a 160 MiB column needs a final element-aligned transaction",
        );
        assert_eq!(
            recomputable_table_read_transaction_count(1 << 22, 4, 3, maximum_chunk_element_count,),
            Ok(672),
            "the width-four table is read as eight bounded segments per logical column",
        );
        assert_eq!(
            recomputable_table_read_transaction_count(1 << 19, 32, 3, maximum_chunk_element_count,),
            Ok(768),
            "the width-32 table preserves every encoded-column boundary",
        );
        assert_eq!(
            recomputable_vector_read_transaction_count(1 << 24, 3, maximum_chunk_element_count,),
            Ok(648),
            "a contiguous residual has only its eight encoded-column boundaries",
        );
        assert!(
            recomputable_vector_read_transaction_count(15, 3, maximum_chunk_element_count,)
                .is_err(),
            "an uneven encoded-column split is rejected",
        );
    }
}
