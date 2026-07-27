use core::{mem::size_of, ops::Range};

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use zeroize::{Zeroize, Zeroizing};

use super::ChallengeField;
use crate::bgv::proof_suite::{
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofExternalMemory, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryObject,
};

pub(super) const RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH: usize = 8;
pub(super) const RETAINED_PLAIN_WHIR_STRIPE_ROW_COUNT: usize = 1 << 15;
pub(super) const RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH: usize =
    PROOF_CHALLENGE_EXTENSION_DEGREE * size_of::<u64>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetainedPlainWhirOracleCodecError {
    InvalidEncodedHeight,
    InvalidStripeRowCount,
    StripeOutOfRange,
    ColumnOutOfRange,
    ObjectRangeOutOfRange,
    RangeDoesNotBelongToStripeColumn,
    ArithmeticOverflow,
    WrongStripeColumnValueCount,
    WrongDestinationByteLength,
    NonContiguousChunk,
    InvalidLifecycle,
    WrongStripeColumnOrder,
    TruncatedCanonicalValue,
    NonCanonicalCoordinate { coordinate_index: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RetainedPlainWhirOracleStorageError<StorageError> {
    Codec(RetainedPlainWhirOracleCodecError),
    ExternalMemory(ProofExternalMemoryExecutorError<StorageError>),
}

impl<StorageError> From<RetainedPlainWhirOracleCodecError>
    for RetainedPlainWhirOracleStorageError<StorageError>
{
    fn from(error: RetainedPlainWhirOracleCodecError) -> Self {
        Self::Codec(error)
    }
}

impl<StorageError> From<ProofExternalMemoryExecutorError<StorageError>>
    for RetainedPlainWhirOracleStorageError<StorageError>
{
    fn from(error: ProofExternalMemoryExecutorError<StorageError>) -> Self {
        Self::ExternalMemory(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetainedPlainWhirOracleWriteProgress {
    pub(super) stored_record_byte_length: u32,
    pub(super) stripe_column_complete: bool,
    pub(super) object_complete: bool,
}

/// Canonical stripe-major storage layout for one retained plain-WHIR oracle.
///
/// Stripe height is a checked implementation schedule. It is not serialized,
/// hashed, or otherwise included in the proof construction identity. The
/// selected schedule holds `2^15 * 8` challenge-field values, exactly ten
/// mebibytes, in each complete stripe. Storage records remain the external
/// memory boundary's exact one-mebibyte records, except for the final nonempty
/// record of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetainedPlainWhirOracleScratchCodec {
    encoded_height: usize,
    stripe_row_count: usize,
    stripe_count: usize,
    exact_byte_length: u64,
}

impl RetainedPlainWhirOracleScratchCodec {
    pub(super) fn try_new(
        encoded_height: usize,
    ) -> Result<Self, RetainedPlainWhirOracleCodecError> {
        Self::try_new_with_stripe_row_count(encoded_height, RETAINED_PLAIN_WHIR_STRIPE_ROW_COUNT)
    }

    pub(super) fn try_new_with_stripe_row_count(
        encoded_height: usize,
        stripe_row_count: usize,
    ) -> Result<Self, RetainedPlainWhirOracleCodecError> {
        if encoded_height == 0 {
            return Err(RetainedPlainWhirOracleCodecError::InvalidEncodedHeight);
        }
        if stripe_row_count == 0
            || !stripe_row_count.is_power_of_two()
            || stripe_row_count > RETAINED_PLAIN_WHIR_STRIPE_ROW_COUNT
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidStripeRowCount);
        }
        let complete_stripe_byte_length =
            checked_byte_length(stripe_row_count, RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH)?;
        if complete_stripe_byte_length
            % u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            != 0
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidStripeRowCount);
        }
        let exact_byte_length =
            checked_byte_length(encoded_height, RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH)?;
        Ok(Self {
            encoded_height,
            stripe_row_count,
            stripe_count: encoded_height.div_ceil(stripe_row_count),
            exact_byte_length,
        })
    }

    pub(super) const fn exact_byte_length(self) -> u64 {
        self.exact_byte_length
    }

    pub(super) const fn stripe_row_count(self) -> usize {
        self.stripe_row_count
    }

    pub(super) const fn stripe_count(self) -> usize {
        self.stripe_count
    }

    pub(super) fn storage_record_count(self) -> Result<usize, RetainedPlainWhirOracleCodecError> {
        usize::try_from(self.exact_byte_length.div_ceil(u64::from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        )))
        .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)
    }

    pub(super) fn stripe_row_count_at(
        self,
        stripe_index: usize,
    ) -> Result<usize, RetainedPlainWhirOracleCodecError> {
        let starting_row = stripe_index
            .checked_mul(self.stripe_row_count)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        if stripe_index >= self.stripe_count || starting_row >= self.encoded_height {
            return Err(RetainedPlainWhirOracleCodecError::StripeOutOfRange);
        }
        Ok((self.encoded_height - starting_row).min(self.stripe_row_count))
    }

    pub(super) fn stripe_column_byte_range(
        self,
        stripe_index: usize,
        column_index: usize,
    ) -> Result<Range<u64>, RetainedPlainWhirOracleCodecError> {
        if column_index >= RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH {
            return Err(RetainedPlainWhirOracleCodecError::ColumnOutOfRange);
        }
        let stripe_row_count = self.stripe_row_count_at(stripe_index)?;
        let starting_row = stripe_index
            .checked_mul(self.stripe_row_count)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let stripe_start =
            checked_byte_length(starting_row, RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH)?;
        let stripe_column_byte_length = checked_byte_length(stripe_row_count, 1)?;
        let column_offset = u64::try_from(column_index)
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?
            .checked_mul(stripe_column_byte_length)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let start = stripe_start
            .checked_add(column_offset)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let end = start
            .checked_add(stripe_column_byte_length)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        if end > self.exact_byte_length {
            return Err(RetainedPlainWhirOracleCodecError::ArithmeticOverflow);
        }
        Ok(start..end)
    }

    pub(super) fn storage_record_byte_range(
        self,
        record_index: usize,
    ) -> Result<Range<u64>, RetainedPlainWhirOracleCodecError> {
        let start = u64::try_from(record_index)
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?
            .checked_mul(u64::from(
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            ))
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        if start >= self.exact_byte_length {
            return Err(RetainedPlainWhirOracleCodecError::ObjectRangeOutOfRange);
        }
        let end = start
            .checked_add(u64::from(
                MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            ))
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?
            .min(self.exact_byte_length);
        Ok(start..end)
    }

    /// Encodes a byte range belonging to one stripe column.
    pub(super) fn encode_stripe_column_bytes_into(
        self,
        stripe_index: usize,
        column_index: usize,
        stripe_column_values: &[ChallengeField],
        object_byte_range: Range<u64>,
        destination: &mut [u8],
    ) -> Result<(), RetainedPlainWhirOracleCodecError> {
        self.validate_object_byte_range(&object_byte_range)?;
        let stripe_column_range = self.stripe_column_byte_range(stripe_index, column_index)?;
        if object_byte_range.start < stripe_column_range.start
            || object_byte_range.end > stripe_column_range.end
        {
            return Err(RetainedPlainWhirOracleCodecError::RangeDoesNotBelongToStripeColumn);
        }
        if stripe_column_values.len() != self.stripe_row_count_at(stripe_index)? {
            return Err(RetainedPlainWhirOracleCodecError::WrongStripeColumnValueCount);
        }
        let requested_byte_length = object_byte_range
            .end
            .checked_sub(object_byte_range.start)
            .ok_or(RetainedPlainWhirOracleCodecError::ObjectRangeOutOfRange)?;
        if u64::try_from(destination.len()) != Ok(requested_byte_length) {
            return Err(RetainedPlainWhirOracleCodecError::WrongDestinationByteLength);
        }

        let field_byte_length = u64::try_from(RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH)
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let relative_start = object_byte_range.start - stripe_column_range.start;
        let mut value_index = usize::try_from(relative_start / field_byte_length)
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let mut byte_offset_within_value = usize::try_from(relative_start % field_byte_length)
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let mut destination_offset = 0_usize;
        while destination_offset < destination.len() {
            let value = stripe_column_values
                .get(value_index)
                .ok_or(RetainedPlainWhirOracleCodecError::ObjectRangeOutOfRange)?;
            let canonical_value = Zeroizing::new(encode_canonical_challenge_field(*value));
            let byte_count = (RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH
                - byte_offset_within_value)
                .min(destination.len() - destination_offset);
            destination[destination_offset..destination_offset + byte_count].copy_from_slice(
                &canonical_value[byte_offset_within_value..byte_offset_within_value + byte_count],
            );
            destination_offset += byte_count;
            value_index += 1;
            byte_offset_within_value = 0;
        }
        Ok(())
    }

    pub(super) fn decoder(self) -> RetainedPlainWhirCanonicalDecoder {
        RetainedPlainWhirCanonicalDecoder {
            next_byte_offset: 0,
            ending_byte_offset: self.exact_byte_length,
            carry: [0_u8; RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH],
            carried_byte_length: 0,
        }
    }

    fn validate_object_byte_range(
        self,
        object_byte_range: &Range<u64>,
    ) -> Result<(), RetainedPlainWhirOracleCodecError> {
        if object_byte_range.start >= object_byte_range.end
            || object_byte_range.end > self.exact_byte_length
        {
            return Err(RetainedPlainWhirOracleCodecError::ObjectRangeOutOfRange);
        }
        Ok(())
    }
}

/// Incremental canonical writer for one retained encoded oracle.
///
/// Stripe columns are supplied in stripe-major order. At most one storage
/// record is appended per call. The append allocation is transferred to the
/// external-memory adapter. One bounded retry image remains in Rust custody
/// until commit because the browser recorder may consume the allocation before
/// yielding while the executor cursor intentionally remains unchanged.
pub(super) struct RetainedPlainWhirCanonicalWriter {
    codec: RetainedPlainWhirOracleScratchCodec,
    object: ProofExternalMemoryObject,
    next_stripe_index: usize,
    next_column_index: usize,
    committed_byte_offset: u64,
    write_record: Zeroizing<Vec<u8>>,
    retry_record: Zeroizing<Vec<u8>>,
    begun: bool,
    sealed: bool,
}

impl RetainedPlainWhirCanonicalWriter {
    pub(super) fn new(
        codec: RetainedPlainWhirOracleScratchCodec,
        object: ProofExternalMemoryObject,
    ) -> Self {
        Self {
            codec,
            object,
            next_stripe_index: 0,
            next_column_index: 0,
            committed_byte_offset: 0,
            write_record: Zeroizing::new(Vec::new()),
            retry_record: Zeroizing::new(Vec::new()),
            begun: false,
            sealed: false,
        }
    }

    pub(super) const fn next_stripe_column(&self) -> Option<(usize, usize)> {
        if self.next_stripe_index < self.codec.stripe_count {
            Some((self.next_stripe_index, self.next_column_index))
        } else {
            None
        }
    }

    pub(super) fn begin<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<(), RetainedPlainWhirOracleStorageError<Storage::Error>> {
        self.validate_executor(executor)?;
        if self.begun
            || self.sealed
            || self.committed_byte_offset != 0
            || !self.write_record.is_empty()
            || !self.retry_record.is_empty()
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
        }
        executor.begin_object(storage, self.object)?;
        self.begun = true;
        Ok(())
    }

    pub(super) fn advance_stripe_column<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        stripe_index: usize,
        column_index: usize,
        stripe_column_values: &[ChallengeField],
    ) -> Result<
        RetainedPlainWhirOracleWriteProgress,
        RetainedPlainWhirOracleStorageError<Storage::Error>,
    > {
        self.validate_executor(executor)?;
        if !self.begun || self.sealed || !self.retry_record.is_empty() {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
        }
        if self.next_stripe_column() != Some((stripe_index, column_index)) {
            return Err(RetainedPlainWhirOracleCodecError::WrongStripeColumnOrder.into());
        }
        if stripe_column_values.len() != self.codec.stripe_row_count_at(stripe_index)? {
            return Err(RetainedPlainWhirOracleCodecError::WrongStripeColumnValueCount.into());
        }

        let stripe_column_range = self
            .codec
            .stripe_column_byte_range(stripe_index, column_index)?;
        let buffered_byte_length = u64::try_from(self.write_record.len())
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let prepared_start = self
            .committed_byte_offset
            .checked_add(buffered_byte_length)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        if prepared_start < stripe_column_range.start || prepared_start > stripe_column_range.end {
            return Err(RetainedPlainWhirOracleCodecError::NonContiguousChunk.into());
        }
        let expected_record_byte_length = self.expected_record_byte_length()?;
        if buffered_byte_length > expected_record_byte_length {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
        }
        let prepared_end = self
            .committed_byte_offset
            .checked_add(expected_record_byte_length)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?
            .min(stripe_column_range.end);
        if prepared_start < prepared_end {
            let appended_byte_length = usize::try_from(prepared_end - prepared_start)
                .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
            let previous_record_byte_length = self.write_record.len();
            self.write_record
                .try_reserve_exact(appended_byte_length)
                .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
            self.write_record.resize(
                previous_record_byte_length
                    .checked_add(appended_byte_length)
                    .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?,
                0,
            );
            self.codec.encode_stripe_column_bytes_into(
                stripe_index,
                column_index,
                stripe_column_values,
                prepared_start..prepared_end,
                &mut self.write_record[previous_record_byte_length..],
            )?;
        }

        let prepared_object_byte_offset = self
            .committed_byte_offset
            .checked_add(
                u64::try_from(self.write_record.len())
                    .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?,
            )
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let stripe_column_complete = prepared_object_byte_offset == stripe_column_range.end;
        let record_complete = u64::try_from(self.write_record.len())
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?
            == expected_record_byte_length;
        if !record_complete {
            if !stripe_column_complete {
                return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
            }
            self.advance_stripe_column_cursor()?;
            return Ok(RetainedPlainWhirOracleWriteProgress {
                stored_record_byte_length: 0,
                stripe_column_complete: true,
                object_complete: false,
            });
        }

        let stored_record_byte_length = u32::try_from(self.write_record.len())
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        self.prepare_retry_record()?;
        if let Err(error) =
            executor.append_owned_object_bytes(storage, self.object, &mut self.write_record)
        {
            self.restore_retry_record();
            return Err(error.into());
        }
        clear_zeroizing_bytes(&mut self.write_record);
        clear_zeroizing_bytes(&mut self.retry_record);
        self.committed_byte_offset = prepared_object_byte_offset;
        if stripe_column_complete {
            self.advance_stripe_column_cursor()?;
        }
        let object_complete = self.committed_byte_offset == self.codec.exact_byte_length();
        if object_complete != self.next_stripe_column().is_none() {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
        }
        Ok(RetainedPlainWhirOracleWriteProgress {
            stored_record_byte_length,
            stripe_column_complete,
            object_complete,
        })
    }

    pub(super) fn seal<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
    ) -> Result<(), RetainedPlainWhirOracleStorageError<Storage::Error>> {
        self.validate_executor(executor)?;
        if !self.begun
            || self.sealed
            || self.next_stripe_column().is_some()
            || self.committed_byte_offset != self.codec.exact_byte_length()
            || !self.write_record.is_empty()
            || !self.retry_record.is_empty()
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
        }
        executor.seal_object(storage, self.object)?;
        self.sealed = true;
        Ok(())
    }

    pub(super) fn finish(
        self,
    ) -> Result<ProofExternalMemoryObject, RetainedPlainWhirOracleCodecError> {
        if !self.begun
            || !self.sealed
            || self.next_stripe_column().is_some()
            || self.committed_byte_offset != self.codec.exact_byte_length()
            || !self.write_record.is_empty()
            || !self.retry_record.is_empty()
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle);
        }
        Ok(self.object)
    }

    fn expected_record_byte_length(&self) -> Result<u64, RetainedPlainWhirOracleCodecError> {
        let remaining_object_byte_length = self
            .codec
            .exact_byte_length()
            .checked_sub(self.committed_byte_offset)
            .ok_or(RetainedPlainWhirOracleCodecError::InvalidLifecycle)?;
        let expected_record_byte_length = remaining_object_byte_length.min(u64::from(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        ));
        if expected_record_byte_length == 0 {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle);
        }
        Ok(expected_record_byte_length)
    }

    fn prepare_retry_record(&mut self) -> Result<(), RetainedPlainWhirOracleCodecError> {
        clear_zeroizing_bytes(&mut self.retry_record);
        self.retry_record
            .try_reserve_exact(self.write_record.len())
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        self.retry_record
            .extend_from_slice(self.write_record.as_slice());
        Ok(())
    }

    fn restore_retry_record(&mut self) {
        if self.write_record.is_empty() {
            core::mem::swap(&mut self.write_record, &mut self.retry_record);
        }
        clear_zeroizing_bytes(&mut self.retry_record);
    }

    fn advance_stripe_column_cursor(&mut self) -> Result<(), RetainedPlainWhirOracleCodecError> {
        self.next_column_index = self
            .next_column_index
            .checked_add(1)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        if self.next_column_index == RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH {
            self.next_column_index = 0;
            self.next_stripe_index = self
                .next_stripe_index
                .checked_add(1)
                .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        }
        Ok(())
    }

    fn validate_executor(
        &self,
        executor: &ProofExternalMemoryExecutor,
    ) -> Result<(), RetainedPlainWhirOracleCodecError> {
        if executor.maximum_chunk_byte_length()
            != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle);
        }
        Ok(())
    }
}

/// Incremental canonical reader for a complete retained oracle.
///
/// Each read exactly matches one record emitted by the writer. Values become
/// visible only after the whole record has passed canonical validation.
pub(super) struct RetainedPlainWhirCanonicalReader {
    codec: RetainedPlainWhirOracleScratchCodec,
    object: ProofExternalMemoryObject,
    decoder: RetainedPlainWhirCanonicalDecoder,
    next_record_index: usize,
    read_record: Zeroizing<Vec<u8>>,
}

impl RetainedPlainWhirCanonicalReader {
    pub(super) fn new(
        codec: RetainedPlainWhirOracleScratchCodec,
        object: ProofExternalMemoryObject,
    ) -> Self {
        Self {
            codec,
            object,
            decoder: codec.decoder(),
            next_record_index: 0,
            read_record: Zeroizing::new(Vec::new()),
        }
    }

    pub(super) fn advance<Storage: ProofExternalMemory>(
        &mut self,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut Storage,
        mut accept_value: impl FnMut(ChallengeField),
    ) -> Result<bool, RetainedPlainWhirOracleStorageError<Storage::Error>> {
        if executor.maximum_chunk_byte_length()
            != MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH
        {
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
        }
        if self.next_record_index == self.codec.storage_record_count()? {
            return Ok(true);
        }
        let read_range = self
            .codec
            .storage_record_byte_range(self.next_record_index)?;
        let read_byte_length = usize::try_from(read_range.end - read_range.start)
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        clear_zeroizing_bytes(&mut self.read_record);
        self.read_record
            .try_reserve_exact(read_byte_length)
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        self.read_record.resize(read_byte_length, 0);
        if let Err(error) = executor.read_object_bytes(
            storage,
            self.object,
            read_range.start,
            self.read_record.as_mut_slice(),
        ) {
            clear_zeroizing_bytes(&mut self.read_record);
            return Err(error.into());
        }

        let mut validation_decoder = self.decoder.clone();
        let validated_value_count = match validation_decoder.decode_chunk(
            read_range.start,
            self.read_record.as_slice(),
            |_| {},
        ) {
            Ok(value_count) => value_count,
            Err(error) => {
                clear_zeroizing_bytes(&mut self.read_record);
                return Err(error.into());
            }
        };
        let decoded_value_count = self.decoder.decode_chunk(
            read_range.start,
            self.read_record.as_slice(),
            &mut accept_value,
        )?;
        if decoded_value_count != validated_value_count {
            clear_zeroizing_bytes(&mut self.read_record);
            return Err(RetainedPlainWhirOracleCodecError::InvalidLifecycle.into());
        }
        self.next_record_index = self
            .next_record_index
            .checked_add(1)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        clear_zeroizing_bytes(&mut self.read_record);
        Ok(self.next_record_index == self.codec.storage_record_count()?)
    }

    pub(super) fn finish(
        self,
    ) -> Result<ProofExternalMemoryObject, RetainedPlainWhirOracleCodecError> {
        if self.next_record_index != self.codec.storage_record_count()?
            || !self.read_record.is_empty()
        {
            return Err(RetainedPlainWhirOracleCodecError::TruncatedCanonicalValue);
        }
        self.decoder.finish()?;
        Ok(self.object)
    }
}

/// Incrementally decodes storage records while retaining at most one partial
/// canonical field element between calls.
#[derive(Clone)]
pub(super) struct RetainedPlainWhirCanonicalDecoder {
    next_byte_offset: u64,
    ending_byte_offset: u64,
    carry: [u8; RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH],
    carried_byte_length: usize,
}

impl RetainedPlainWhirCanonicalDecoder {
    pub(super) fn decode_chunk(
        &mut self,
        object_byte_offset: u64,
        bytes: &[u8],
        mut accept_value: impl FnMut(ChallengeField),
    ) -> Result<usize, RetainedPlainWhirOracleCodecError> {
        if object_byte_offset != self.next_byte_offset {
            return Err(RetainedPlainWhirOracleCodecError::NonContiguousChunk);
        }
        let chunk_byte_length = u64::try_from(bytes.len())
            .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        let chunk_end = object_byte_offset
            .checked_add(chunk_byte_length)
            .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?;
        if bytes.is_empty() || chunk_end > self.ending_byte_offset {
            return Err(RetainedPlainWhirOracleCodecError::ObjectRangeOutOfRange);
        }

        let mut source_offset = 0_usize;
        let mut decoded_value_count = 0_usize;
        if self.carried_byte_length != 0 {
            let needed_byte_length =
                RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH - self.carried_byte_length;
            let copied_byte_length = needed_byte_length.min(bytes.len());
            self.carry[self.carried_byte_length..self.carried_byte_length + copied_byte_length]
                .copy_from_slice(&bytes[..copied_byte_length]);
            self.carried_byte_length += copied_byte_length;
            source_offset += copied_byte_length;
            if self.carried_byte_length == RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH {
                accept_value(decode_canonical_challenge_field(&self.carry)?);
                decoded_value_count += 1;
                self.carry.zeroize();
                self.carried_byte_length = 0;
            }
        }

        while bytes.len() - source_offset >= RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH {
            let ending_offset = source_offset + RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH;
            let canonical_value: &[u8; RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH] = bytes
                [source_offset..ending_offset]
                .try_into()
                .expect("an exactly sized canonical value converts to an array");
            accept_value(decode_canonical_challenge_field(canonical_value)?);
            decoded_value_count += 1;
            source_offset = ending_offset;
        }

        let remaining_byte_length = bytes.len() - source_offset;
        if remaining_byte_length != 0 {
            self.carry.zeroize();
            self.carry[..remaining_byte_length].copy_from_slice(&bytes[source_offset..]);
            self.carried_byte_length = remaining_byte_length;
        }
        self.next_byte_offset = chunk_end;
        Ok(decoded_value_count)
    }

    pub(super) fn finish(self) -> Result<(), RetainedPlainWhirOracleCodecError> {
        if self.next_byte_offset != self.ending_byte_offset || self.carried_byte_length != 0 {
            return Err(RetainedPlainWhirOracleCodecError::TruncatedCanonicalValue);
        }
        Ok(())
    }
}

impl Drop for RetainedPlainWhirCanonicalDecoder {
    fn drop(&mut self) {
        self.carry.zeroize();
        self.carried_byte_length = 0;
    }
}

fn checked_byte_length(
    row_count: usize,
    width: usize,
) -> Result<u64, RetainedPlainWhirOracleCodecError> {
    u64::try_from(row_count)
        .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?
        .checked_mul(
            u64::try_from(width)
                .map_err(|_| RetainedPlainWhirOracleCodecError::ArithmeticOverflow)?,
        )
        .and_then(|value_count| {
            value_count
                .checked_mul(u64::try_from(RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH).ok()?)
        })
        .ok_or(RetainedPlainWhirOracleCodecError::ArithmeticOverflow)
}

fn clear_zeroizing_bytes(bytes: &mut Zeroizing<Vec<u8>>) {
    bytes.as_mut_slice().zeroize();
    bytes.clear();
}

fn encode_canonical_challenge_field(
    value: ChallengeField,
) -> [u8; RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH] {
    let coefficients =
        <ChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(&value);
    debug_assert_eq!(coefficients.len(), PROOF_CHALLENGE_EXTENSION_DEGREE);
    let mut canonical = [0_u8; RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH];
    for (coefficient, destination) in coefficients
        .iter()
        .zip(canonical.chunks_exact_mut(size_of::<u64>()))
    {
        destination.copy_from_slice(&coefficient.as_canonical_u64().to_le_bytes());
    }
    canonical
}

fn decode_canonical_challenge_field(
    canonical: &[u8; RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH],
) -> Result<ChallengeField, RetainedPlainWhirOracleCodecError> {
    let mut coefficients = [Goldilocks::ZERO; PROOF_CHALLENGE_EXTENSION_DEGREE];
    for (coordinate_index, (source, coefficient)) in canonical
        .chunks_exact(size_of::<u64>())
        .zip(coefficients.iter_mut())
        .enumerate()
    {
        let coordinate = u64::from_le_bytes(
            source
                .try_into()
                .expect("an eight-byte canonical coordinate converts to an array"),
        );
        if coordinate >= PROOF_BASE_FIELD_MODULUS {
            return Err(RetainedPlainWhirOracleCodecError::NonCanonicalCoordinate {
                coordinate_index,
            });
        }
        *coefficient = Goldilocks::new(coordinate);
    }
    Ok(ChallengeField::new(coefficients))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::bgv::proof_suite::{
        ProofExternalMemoryObjectPlan, ProofExternalMemoryPlan, ProofExternalMemoryProtection,
    };

    const ONE_MEBIBYTE: usize = 1_048_576;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestStorageError {
        NoTransaction,
        DuplicateObject,
        MissingObject,
        WrongLength,
        InjectedAppendFailure,
    }

    #[derive(Clone)]
    struct TestObject {
        bytes: Vec<u8>,
        exact_byte_length: usize,
        sealed: bool,
    }

    #[derive(Default)]
    struct TestStorage {
        committed: BTreeMap<ProofExternalMemoryObject, TestObject>,
        transaction: Option<BTreeMap<ProofExternalMemoryObject, TestObject>>,
        fail_next_owned_append: bool,
        owned_append_count: usize,
        read_ranges: Vec<Range<u64>>,
    }

    impl ProofExternalMemory for TestStorage {
        type Error = TestStorageError;

        fn begin_transaction(&mut self, _: u64, _: u32) -> Result<(), Self::Error> {
            if self.transaction.is_some() {
                return Err(TestStorageError::DuplicateObject);
            }
            self.transaction = Some(self.committed.clone());
            Ok(())
        }

        fn create_object(
            &mut self,
            object: ProofExternalMemoryObject,
            _: ProofExternalMemoryProtection,
            exact_byte_length: u64,
        ) -> Result<(), Self::Error> {
            let transaction = self
                .transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?;
            if transaction.contains_key(&object) {
                return Err(TestStorageError::DuplicateObject);
            }
            transaction.insert(
                object,
                TestObject {
                    bytes: Vec::new(),
                    exact_byte_length: usize::try_from(exact_byte_length)
                        .map_err(|_| TestStorageError::WrongLength)?,
                    sealed: false,
                },
            );
            Ok(())
        }

        fn append_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            expected_offset: u64,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            self.append(object, expected_offset, bytes)
        }

        fn append_owned_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            expected_offset: u64,
            bytes: &mut Zeroizing<Vec<u8>>,
        ) -> Result<(), Self::Error> {
            self.owned_append_count += 1;
            let owned_bytes = core::mem::replace(bytes, Zeroizing::new(Vec::new()));
            if self.fail_next_owned_append {
                self.fail_next_owned_append = false;
                return Err(TestStorageError::InjectedAppendFailure);
            }
            self.append(object, expected_offset, owned_bytes.as_slice())
        }

        fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            let object = self
                .transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?
                .get_mut(&object)
                .ok_or(TestStorageError::MissingObject)?;
            if object.bytes.len() != object.exact_byte_length {
                return Err(TestStorageError::WrongLength);
            }
            object.sealed = true;
            Ok(())
        }

        fn read_object_bytes(
            &mut self,
            object: ProofExternalMemoryObject,
            offset: u64,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            let transaction = self
                .transaction
                .as_ref()
                .ok_or(TestStorageError::NoTransaction)?;
            let object = transaction
                .get(&object)
                .ok_or(TestStorageError::MissingObject)?;
            let start = usize::try_from(offset).map_err(|_| TestStorageError::WrongLength)?;
            let end = start
                .checked_add(destination.len())
                .ok_or(TestStorageError::WrongLength)?;
            let source = object
                .bytes
                .get(start..end)
                .ok_or(TestStorageError::WrongLength)?;
            destination.copy_from_slice(source);
            self.read_ranges.push(offset..u64::try_from(end).unwrap());
            Ok(())
        }

        fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            self.transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?
                .remove(&object)
                .ok_or(TestStorageError::MissingObject)?;
            Ok(())
        }

        fn commit_transaction(&mut self) -> Result<(), Self::Error> {
            self.committed = self
                .transaction
                .take()
                .ok_or(TestStorageError::NoTransaction)?;
            Ok(())
        }

        fn abort_transaction(&mut self) -> Result<(), Self::Error> {
            self.transaction
                .take()
                .ok_or(TestStorageError::NoTransaction)?;
            Ok(())
        }
    }

    impl TestStorage {
        fn append(
            &mut self,
            object: ProofExternalMemoryObject,
            expected_offset: u64,
            bytes: &[u8],
        ) -> Result<(), TestStorageError> {
            let object = self
                .transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?
                .get_mut(&object)
                .ok_or(TestStorageError::MissingObject)?;
            if object.sealed
                || usize::try_from(expected_offset).ok() != Some(object.bytes.len())
                || object.bytes.len() + bytes.len() > object.exact_byte_length
            {
                return Err(TestStorageError::WrongLength);
            }
            object.bytes.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn test_value(stripe_index: usize, column_index: usize, row_index: usize) -> ChallengeField {
        let value_ordinal = stripe_index * 1009 + column_index * 101 + row_index * 17;
        ChallengeField::new(core::array::from_fn(|coordinate_index| {
            Goldilocks::from_u64(
                u64::try_from(value_ordinal * 7 + coordinate_index + 1)
                    .expect("the test coordinate fits u64"),
            )
        }))
    }

    fn stripe_column_values(
        codec: RetainedPlainWhirOracleScratchCodec,
        stripe_index: usize,
        column_index: usize,
    ) -> Vec<ChallengeField> {
        (0..codec.stripe_row_count_at(stripe_index).unwrap())
            .map(|row_index| test_value(stripe_index, column_index, row_index))
            .collect()
    }

    fn test_plan(
        codec: RetainedPlainWhirOracleScratchCodec,
        object: ProofExternalMemoryObject,
        read_pass_count: u64,
    ) -> ProofExternalMemoryPlan {
        let record_count = u64::try_from(codec.storage_record_count().unwrap()).unwrap();
        let maximum_total_read_byte_length = codec
            .exact_byte_length()
            .checked_mul(read_pass_count.max(1))
            .unwrap();
        ProofExternalMemoryPlan::new(
            1,
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
            u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
            1,
            codec.exact_byte_length(),
            codec.exact_byte_length(),
            maximum_total_read_byte_length,
            record_count
                .checked_mul(read_pass_count.max(1) + 1)
                .and_then(|count| count.checked_add(3))
                .unwrap(),
            vec![ProofExternalMemoryObjectPlan::new(
                object,
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                codec.exact_byte_length(),
                0,
                0,
                0,
            )],
        )
        .expect("the retained-oracle test plan is valid")
    }

    fn write_complete_object(
        codec: RetainedPlainWhirOracleScratchCodec,
        object: ProofExternalMemoryObject,
        executor: &mut ProofExternalMemoryExecutor,
        storage: &mut TestStorage,
    ) -> Vec<ChallengeField> {
        let mut writer = RetainedPlainWhirCanonicalWriter::new(codec, object);
        writer.begin(executor, storage).expect("begin the object");
        let mut expected_values = Vec::new();
        while let Some((stripe_index, column_index)) = writer.next_stripe_column() {
            let values = stripe_column_values(codec, stripe_index, column_index);
            let mut column_complete = false;
            while !column_complete {
                let progress = writer
                    .advance_stripe_column(executor, storage, stripe_index, column_index, &values)
                    .expect("append the next stripe-column extent");
                column_complete = progress.stripe_column_complete;
            }
            expected_values.extend_from_slice(&values);
        }
        assert!(writer.write_record.is_empty());
        assert!(writer.retry_record.is_empty());
        writer.seal(executor, storage).expect("seal the object");
        assert_eq!(writer.finish(), Ok(object));
        expected_values
    }

    #[test]
    fn selected_stripes_and_storage_records_have_exact_boundaries() {
        let one_mebibyte = u64::try_from(ONE_MEBIBYTE).unwrap();
        let selected_stripe_byte_length = checked_byte_length(
            RETAINED_PLAIN_WHIR_STRIPE_ROW_COUNT,
            RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH,
        )
        .unwrap();
        assert_eq!(selected_stripe_byte_length, 10 * one_mebibyte);

        for (encoded_height, expected_stripe_count, expected_record_count) in [
            (1 << 20, 32, 320),
            (1 << 19, 16, 160),
            (1 << 18, 8, 80),
            (1 << 17, 4, 40),
            (1 << 16, 2, 20),
        ] {
            let codec = RetainedPlainWhirOracleScratchCodec::try_new(encoded_height).unwrap();
            assert_eq!(codec.stripe_row_count(), 1 << 15);
            assert_eq!(codec.stripe_count(), expected_stripe_count);
            assert_eq!(codec.storage_record_count(), Ok(expected_record_count));
            for record_index in 0..expected_record_count {
                let range = codec.storage_record_byte_range(record_index).unwrap();
                assert_eq!(range.end - range.start, one_mebibyte);
            }
        }
    }

    #[test]
    fn nonmultiple_height_uses_one_short_final_stripe_and_record() {
        let codec =
            RetainedPlainWhirOracleScratchCodec::try_new(RETAINED_PLAIN_WHIR_STRIPE_ROW_COUNT + 3)
                .unwrap();
        assert_eq!(codec.stripe_count(), 2);
        assert_eq!(codec.stripe_row_count_at(0), Ok(1 << 15));
        assert_eq!(codec.stripe_row_count_at(1), Ok(3));
        assert_eq!(codec.storage_record_count(), Ok(11));
        assert_eq!(
            codec.stripe_column_byte_range(1, 0),
            Ok(10_485_760..10_485_880)
        );
        assert_eq!(
            codec.stripe_column_byte_range(1, 7),
            Ok(10_486_600..10_486_720)
        );
        assert_eq!(
            codec.storage_record_byte_range(10),
            Ok(10_485_760..10_486_720)
        );
    }

    #[test]
    fn writer_and_reader_round_trip_canonical_stripe_major_bytes() {
        let codec = RetainedPlainWhirOracleScratchCodec::try_new(3).unwrap();
        let object = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(test_plan(codec, object, 1));
        let mut storage = TestStorage::default();
        let expected_values = write_complete_object(codec, object, &mut executor, &mut storage);

        let stored_bytes = &storage.committed.get(&object).unwrap().bytes;
        assert_eq!(stored_bytes.len(), 960);
        let expected_bytes = expected_values
            .iter()
            .flat_map(|value| encode_canonical_challenge_field(*value))
            .collect::<Vec<_>>();
        assert_eq!(stored_bytes, &expected_bytes);
        assert_eq!(storage.owned_append_count, 1);

        let mut reader = RetainedPlainWhirCanonicalReader::new(codec, object);
        let mut decoded_values = Vec::new();
        assert!(
            reader
                .advance(&mut executor, &mut storage, |value| decoded_values
                    .push(value))
                .expect("read the only storage record")
        );
        assert!(reader.read_record.is_empty());
        assert_eq!(reader.finish(), Ok(object));
        assert_eq!(decoded_values, expected_values);
        assert_eq!(storage.read_ranges, vec![0..960]);
    }

    #[test]
    fn codec_and_writer_reject_wrong_stripe_column_order_and_length() {
        assert_eq!(
            RetainedPlainWhirOracleScratchCodec::try_new(0),
            Err(RetainedPlainWhirOracleCodecError::InvalidEncodedHeight)
        );
        for stripe_row_count in [0, 1 << 13, (1 << 15) + 1] {
            assert_eq!(
                RetainedPlainWhirOracleScratchCodec::try_new_with_stripe_row_count(
                    1,
                    stripe_row_count,
                ),
                Err(RetainedPlainWhirOracleCodecError::InvalidStripeRowCount)
            );
        }
        assert!(
            RetainedPlainWhirOracleScratchCodec::try_new_with_stripe_row_count(1, 1 << 14).is_ok()
        );

        let codec = RetainedPlainWhirOracleScratchCodec::try_new(2).unwrap();
        assert_eq!(
            codec.stripe_column_byte_range(1, 0),
            Err(RetainedPlainWhirOracleCodecError::StripeOutOfRange)
        );
        assert_eq!(
            codec.stripe_column_byte_range(0, 8),
            Err(RetainedPlainWhirOracleCodecError::ColumnOutOfRange)
        );
        assert_eq!(
            codec.storage_record_byte_range(1),
            Err(RetainedPlainWhirOracleCodecError::ObjectRangeOutOfRange)
        );

        let object = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(test_plan(codec, object, 1));
        let mut storage = TestStorage::default();
        let mut writer = RetainedPlainWhirCanonicalWriter::new(codec, object);
        writer.begin(&mut executor, &mut storage).unwrap();
        let values = stripe_column_values(codec, 0, 0);
        assert_eq!(
            writer.advance_stripe_column(&mut executor, &mut storage, 0, 1, &values),
            Err(RetainedPlainWhirOracleStorageError::Codec(
                RetainedPlainWhirOracleCodecError::WrongStripeColumnOrder
            ))
        );
        assert_eq!(
            writer.advance_stripe_column(&mut executor, &mut storage, 1, 0, &values),
            Err(RetainedPlainWhirOracleStorageError::Codec(
                RetainedPlainWhirOracleCodecError::WrongStripeColumnOrder
            ))
        );
        assert_eq!(
            writer.advance_stripe_column(&mut executor, &mut storage, 0, 0, &values[..1],),
            Err(RetainedPlainWhirOracleStorageError::Codec(
                RetainedPlainWhirOracleCodecError::WrongStripeColumnValueCount
            ))
        );
        let mut destination = [0_u8; 40];
        assert_eq!(
            codec.encode_stripe_column_bytes_into(0, 0, &values, 80..120, &mut destination,),
            Err(RetainedPlainWhirOracleCodecError::RangeDoesNotBelongToStripeColumn)
        );
        assert_eq!(
            codec.encode_stripe_column_bytes_into(0, 0, &values, 0..40, &mut destination[..39],),
            Err(RetainedPlainWhirOracleCodecError::WrongDestinationByteLength)
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_limb_split_across_record_boundary() {
        let codec = RetainedPlainWhirOracleScratchCodec::try_new(3_277).unwrap();
        assert_eq!(codec.exact_byte_length(), 1_048_640);
        let mut bytes = vec![0_u8; usize::try_from(codec.exact_byte_length()).unwrap()];
        bytes[ONE_MEBIBYTE..ONE_MEBIBYTE + 8]
            .copy_from_slice(&PROOF_BASE_FIELD_MODULUS.to_le_bytes());
        let mut decoder = codec.decoder();
        assert_eq!(
            decoder
                .decode_chunk(0, &bytes[..ONE_MEBIBYTE], |_| {})
                .unwrap(),
            ONE_MEBIBYTE / RETAINED_PLAIN_WHIR_CHALLENGE_FIELD_BYTE_LENGTH
        );
        assert_eq!(
            decoder.decode_chunk(
                u64::try_from(ONE_MEBIBYTE).unwrap(),
                &bytes[ONE_MEBIBYTE..],
                |_| {},
            ),
            Err(RetainedPlainWhirOracleCodecError::NonCanonicalCoordinate {
                coordinate_index: 2,
            })
        );
    }

    #[test]
    fn decoder_rejects_truncation_surplus_and_noncontiguous_chunks() {
        let codec = RetainedPlainWhirOracleScratchCodec::try_new(1).unwrap();
        let exact_byte_length = usize::try_from(codec.exact_byte_length()).unwrap();
        let bytes = vec![0_u8; exact_byte_length];

        let mut truncated = codec.decoder();
        truncated
            .decode_chunk(0, &bytes[..exact_byte_length - 1], |_| {})
            .unwrap();
        assert_eq!(
            truncated.finish(),
            Err(RetainedPlainWhirOracleCodecError::TruncatedCanonicalValue)
        );

        let mut surplus = codec.decoder();
        surplus.decode_chunk(0, &bytes, |_| {}).unwrap();
        assert_eq!(
            surplus.decode_chunk(codec.exact_byte_length(), &[0], |_| {}),
            Err(RetainedPlainWhirOracleCodecError::ObjectRangeOutOfRange)
        );

        let mut noncontiguous = codec.decoder();
        assert_eq!(
            noncontiguous.decode_chunk(1, &[0], |_| {}),
            Err(RetainedPlainWhirOracleCodecError::NonContiguousChunk)
        );
    }

    #[test]
    fn reader_refuses_truncated_storage_and_wrong_object() {
        let codec = RetainedPlainWhirOracleScratchCodec::try_new(1).unwrap();
        let object = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(test_plan(codec, object, 2));
        let mut storage = TestStorage::default();
        write_complete_object(codec, object, &mut executor, &mut storage);
        storage.committed.get_mut(&object).unwrap().bytes.pop();

        let mut truncated_reader = RetainedPlainWhirCanonicalReader::new(codec, object);
        assert!(matches!(
            truncated_reader.advance(&mut executor, &mut storage, |_| {}),
            Err(RetainedPlainWhirOracleStorageError::ExternalMemory(_))
        ));
        assert!(truncated_reader.read_record.is_empty());

        let wrong_object = ProofExternalMemoryObject::new(1);
        let mut wrong_object_reader = RetainedPlainWhirCanonicalReader::new(codec, wrong_object);
        assert!(matches!(
            wrong_object_reader.advance(&mut executor, &mut storage, |_| {}),
            Err(RetainedPlainWhirOracleStorageError::ExternalMemory(_))
        ));
        assert!(wrong_object_reader.read_record.is_empty());
    }

    #[test]
    fn owned_append_failure_preserves_retry_cursor_and_exact_bytes() {
        let codec = RetainedPlainWhirOracleScratchCodec::try_new(3_277).unwrap();
        let object = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(test_plan(codec, object, 1));
        let mut storage = TestStorage::default();
        let mut writer = RetainedPlainWhirCanonicalWriter::new(codec, object);
        writer.begin(&mut executor, &mut storage).unwrap();

        for column_index in 0..7 {
            let values = stripe_column_values(codec, 0, column_index);
            let progress = writer
                .advance_stripe_column(&mut executor, &mut storage, 0, column_index, &values)
                .unwrap();
            assert!(progress.stripe_column_complete);
            assert_eq!(progress.stored_record_byte_length, 0);
        }
        assert_eq!(writer.next_stripe_column(), Some((0, 7)));
        let final_column_values = stripe_column_values(codec, 0, 7);
        storage.fail_next_owned_append = true;
        assert!(matches!(
            writer.advance_stripe_column(&mut executor, &mut storage, 0, 7, &final_column_values,),
            Err(RetainedPlainWhirOracleStorageError::ExternalMemory(_))
        ));
        assert_eq!(writer.next_stripe_column(), Some((0, 7)));
        assert_eq!(writer.committed_byte_offset, 0);
        assert_eq!(writer.write_record.len(), ONE_MEBIBYTE);
        assert!(writer.retry_record.is_empty());
        assert!(storage.committed.get(&object).unwrap().bytes.is_empty());

        let first_record_progress = writer
            .advance_stripe_column(&mut executor, &mut storage, 0, 7, &final_column_values)
            .unwrap();
        assert_eq!(first_record_progress.stored_record_byte_length, 1_048_576);
        assert!(!first_record_progress.stripe_column_complete);
        assert_eq!(writer.next_stripe_column(), Some((0, 7)));
        assert!(writer.write_record.is_empty());
        assert!(writer.retry_record.is_empty());

        let final_record_progress = writer
            .advance_stripe_column(&mut executor, &mut storage, 0, 7, &final_column_values)
            .unwrap();
        assert_eq!(final_record_progress.stored_record_byte_length, 64);
        assert!(final_record_progress.stripe_column_complete);
        assert!(final_record_progress.object_complete);
        writer.seal(&mut executor, &mut storage).unwrap();
        assert_eq!(writer.finish(), Ok(object));

        let mut decoder = codec.decoder();
        let stored_bytes = &storage.committed.get(&object).unwrap().bytes;
        let mut decoded_values = Vec::new();
        for record_index in 0..codec.storage_record_count().unwrap() {
            let range = codec.storage_record_byte_range(record_index).unwrap();
            decoder
                .decode_chunk(
                    range.start,
                    &stored_bytes[usize::try_from(range.start).unwrap()
                        ..usize::try_from(range.end).unwrap()],
                    |value| decoded_values.push(value),
                )
                .unwrap();
        }
        decoder.finish().unwrap();
        let expected_values = (0..RETAINED_PLAIN_WHIR_ENCODED_ORACLE_WIDTH)
            .flat_map(|column_index| stripe_column_values(codec, 0, column_index))
            .collect::<Vec<_>>();
        assert_eq!(decoded_values, expected_values);
        assert_eq!(storage.owned_append_count, 3);
    }
}
