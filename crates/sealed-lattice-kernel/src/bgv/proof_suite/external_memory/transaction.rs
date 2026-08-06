use zeroize::{Zeroize, Zeroizing};

use crate::hashing::{StreamingHash512, hash_framed_parts_512};

use super::plan::{
    ProofExternalMemory, ProofExternalMemoryObject, ProofExternalMemoryProtection,
    ProofExternalMemoryTransactionOperation,
};
use super::{
    EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH, EXTERNAL_MEMORY_READ_DIGEST_DOMAIN,
    EXTERNAL_MEMORY_READ_RESULT_HEADER_BYTE_LENGTH, EXTERNAL_MEMORY_REQUEST_DIGEST_DOMAIN,
    EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH, EXTERNAL_MEMORY_REQUEST_MESSAGE_KIND,
    EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION, EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH,
    EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND, HASH_BYTE_LENGTH,
};

const EXTERNAL_MEMORY_NO_PROTECTION_CODE: u16 = 0;
const EXTERNAL_MEMORY_PUBLIC_INTEGRITY_PROTECTION_CODE: u16 = 1;
const EXTERNAL_MEMORY_SECRET_AUTHENTICATED_ENCRYPTION_PROTECTION_CODE: u16 = 2;
const EXTERNAL_MEMORY_CREATE_OPERATION_CODE: u16 = 1;
const EXTERNAL_MEMORY_APPEND_OPERATION_CODE: u16 = 2;
const EXTERNAL_MEMORY_SEAL_OPERATION_CODE: u16 = 3;
const EXTERNAL_MEMORY_READ_OPERATION_CODE: u16 = 4;
const EXTERNAL_MEMORY_DELETE_OPERATION_CODE: u16 = 5;
pub(crate) const EXTERNAL_MEMORY_SINGLE_OPERATION_VECTOR_CAPACITY_CEILING: usize = 4;
pub(crate) const EXTERNAL_MEMORY_SINGLE_APPEND_RECYCLER_CAPACITY_CEILING: usize = 4;
pub(crate) const EXTERNAL_MEMORY_SINGLE_READ_RESULT_VECTOR_CAPACITY_CEILING: usize = 1;
pub(crate) const EXTERNAL_MEMORY_SINGLE_APPEND_REPLAY_LENGTH_CAPACITY_CEILING: usize = 4;

type RecycledTransactionStorage = (
    Vec<ProofExternalMemoryTransactionOperation>,
    Vec<Zeroizing<Vec<u8>>>,
);

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryTransactionRequest {
    runtime_binding_hash: [u8; HASH_BYTE_LENGTH],
    request_sequence: u64,
    maximum_payload_byte_length: u64,
    maximum_operation_count: u32,
    operations: Vec<ProofExternalMemoryTransactionOperation>,
    request_digest_after_export: Option<[u8; HASH_BYTE_LENGTH]>,
    append_replay_byte_lengths: Vec<Option<u64>>,
}

impl ProofExternalMemoryTransactionRequest {
    pub(crate) const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    #[cfg(test)]
    pub(crate) fn operations(&self) -> &[ProofExternalMemoryTransactionOperation] {
        &self.operations
    }

    #[cfg(test)]
    pub(crate) fn append_payload_storage_identity(&self) -> Option<(usize, usize)> {
        self.operations.iter().find_map(|operation| {
            let ProofExternalMemoryTransactionOperation::Append { bytes, .. } = operation else {
                return None;
            };
            Some((bytes.as_ptr() as usize, bytes.capacity()))
        })
    }

    pub(crate) fn prepare_exported_request_binding(
        &mut self,
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        if self.request_digest_after_export.is_some() || !self.append_replay_byte_lengths.is_empty()
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle);
        }
        let request_digest = self.derive_request_digest()?;
        self.append_replay_byte_lengths
            .try_reserve_exact(self.operations.len())
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        if self.maximum_operation_count == 1
            && self.append_replay_byte_lengths.capacity()
                > EXTERNAL_MEMORY_SINGLE_APPEND_REPLAY_LENGTH_CAPACITY_CEILING
        {
            return Err(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded);
        }
        for operation in &self.operations {
            let byte_length = match operation {
                ProofExternalMemoryTransactionOperation::Append { bytes, .. } => {
                    Some(u64::try_from(bytes.len()).map_err(|_| {
                        ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded
                    })?)
                }
                _ => None,
            };
            self.append_replay_byte_lengths.push(byte_length);
        }
        self.request_digest_after_export = Some(request_digest);
        Ok(())
    }

    pub(crate) fn release_exported_append_payloads(
        &mut self,
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        if self.request_digest_after_export.is_none()
            || self.append_replay_byte_lengths.len() != self.operations.len()
            || self.operations.iter().enumerate().any(
                |(operation_index, operation)| match operation {
                    ProofExternalMemoryTransactionOperation::Append { bytes, .. } => self
                        .append_replay_byte_length(operation_index)
                        .is_none_or(|byte_length| {
                            u64::try_from(bytes.len()).ok() != Some(byte_length)
                        }),
                    _ => self.append_replay_byte_length(operation_index).is_some(),
                },
            )
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle);
        }
        for operation in &mut self.operations {
            if let ProofExternalMemoryTransactionOperation::Append { bytes, .. } = operation {
                let released = core::mem::replace(bytes, Zeroizing::new(Vec::new()));
                drop(released);
            }
        }
        Ok(())
    }

    fn append_replay_byte_length(&self, operation_index: usize) -> Option<u64> {
        self.append_replay_byte_lengths
            .get(operation_index)
            .copied()
            .flatten()
    }

    #[cfg(test)]
    pub(crate) fn append_payload_was_released(&self) -> bool {
        self.operations
            .iter()
            .enumerate()
            .filter_map(|(operation_index, operation)| {
                matches!(
                    operation,
                    ProofExternalMemoryTransactionOperation::Append { .. }
                )
                .then_some((operation_index, operation))
            })
            .all(|(operation_index, operation)| {
                self.append_replay_byte_length(operation_index).is_some()
                    && matches!(
                        operation,
                        ProofExternalMemoryTransactionOperation::Append { bytes, .. }
                            if bytes.is_empty() && bytes.capacity() == 0
                    )
            })
    }

    pub(crate) fn encoded_worker_request_byte_length(
        &self,
    ) -> Result<usize, ProofExternalMemoryTransactionAdapterError> {
        EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH
            .checked_add(self.encoded_operation_byte_length()?)
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)
    }

    /// Encodes the exact yielded transaction directly into caller-owned
    /// storage without building a second full-payload operation buffer. The
    /// digest covers every operation ordinal, object, range, protection mode,
    /// and append byte. Production export caches that canonical digest before
    /// the append allocation is released and reuses it as the replay binding.
    pub(crate) fn encode_worker_request_into(
        &self,
        encoded: &mut [u8],
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        let expected_byte_length = self.encoded_worker_request_byte_length()?;
        if encoded.len() != expected_byte_length {
            return Err(ProofExternalMemoryTransactionAdapterError::WrongReadLength);
        }
        let result = self.encode_worker_request_into_validated_output(encoded);
        if result.is_err() {
            encoded.zeroize();
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn encode_worker_request(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProofExternalMemoryTransactionAdapterError> {
        let byte_length = self.encoded_worker_request_byte_length()?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(byte_length)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        encoded.resize(byte_length, 0);
        self.encode_worker_request_into(encoded.as_mut_slice())?;
        Ok(encoded)
    }

    fn encode_worker_request_into_validated_output(
        &self,
        encoded: &mut [u8],
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        let operation_count = u32::try_from(self.operations.len())
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?;
        let request_digest = self.request_digest()?;
        let mut operation_offset = EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH;
        self.visit_encoded_operation_parts(|part| {
            let end = operation_offset
                .checked_add(part.len())
                .filter(|end| *end <= encoded.len())
                .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
            encoded[operation_offset..end].copy_from_slice(part);
            operation_offset = end;
            Ok(())
        })?;
        if operation_offset != encoded.len() {
            return Err(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded);
        }
        let mut header_offset = 0_usize;
        write_exact_bytes(
            encoded,
            &mut header_offset,
            &EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes(),
        )?;
        write_exact_bytes(
            encoded,
            &mut header_offset,
            &EXTERNAL_MEMORY_REQUEST_MESSAGE_KIND.to_le_bytes(),
        )?;
        write_exact_bytes(
            encoded,
            &mut header_offset,
            &self.maximum_payload_byte_length.to_le_bytes(),
        )?;
        write_exact_bytes(
            encoded,
            &mut header_offset,
            &self.maximum_operation_count.to_le_bytes(),
        )?;
        write_exact_bytes(encoded, &mut header_offset, &operation_count.to_le_bytes())?;
        write_exact_bytes(
            encoded,
            &mut header_offset,
            &self.request_sequence.to_le_bytes(),
        )?;
        write_exact_bytes(encoded, &mut header_offset, &self.runtime_binding_hash)?;
        write_exact_bytes(encoded, &mut header_offset, &request_digest)?;
        if header_offset != EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH {
            return Err(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded);
        }
        Ok(())
    }

    /// Decodes and authenticates one hostile worker response. The response is
    /// accepted only when it contains exactly one result for each requested
    /// read, in the same operation order and with the exact object, range,
    /// payload length, request digest, and recomputed payload digest.
    #[cfg(test)]
    pub(crate) fn decode_worker_response(
        &self,
        encoded: &[u8],
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, ProofExternalMemoryTransactionAdapterError> {
        let mut read_results = Vec::new();
        self.decode_worker_response_into(encoded, &mut read_results)?;
        Ok(read_results)
    }

    pub(crate) fn decode_worker_response_into(
        &self,
        encoded: &[u8],
        read_results: &mut Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        let expected_request_digest = self.request_digest()?;
        if encoded.len() < EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH {
            return Err(ProofExternalMemoryTransactionAdapterError::MalformedWorkerResponse);
        }
        let mut decoder = ExternalMemoryMessageDecoder::new(encoded);
        if decoder.read_u16()? != EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION
            || decoder.read_u16()? != EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND
            || decoder.read_u64()? != self.request_sequence
            || decoder.read_array::<HASH_BYTE_LENGTH>()? != expected_request_digest
        {
            return Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest);
        }
        let expected_read_count = self
            .operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation,
                    ProofExternalMemoryTransactionOperation::Read { .. }
                )
            })
            .count();
        let result_count = usize::try_from(decoder.read_u32()?)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?;
        if result_count != expected_read_count
            || encoded.len()
                < EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH
                    .checked_add(
                        result_count
                            .checked_mul(EXTERNAL_MEMORY_READ_RESULT_HEADER_BYTE_LENGTH)
                            .ok_or(
                                ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded,
                            )?,
                    )
                    .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?
        {
            return Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding);
        }
        if read_results.len() > result_count {
            for removed in read_results.drain(result_count..) {
                drop(removed);
            }
        }
        read_results
            .try_reserve_exact(result_count.saturating_sub(read_results.len()))
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        while read_results.len() < result_count {
            read_results.push(Zeroizing::new(Vec::new()));
        }
        if self.maximum_operation_count == 1
            && read_results.capacity() > EXTERNAL_MEMORY_SINGLE_READ_RESULT_VECTOR_CAPACITY_CEILING
        {
            return Err(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded);
        }
        let mut total_payload_byte_length = 0_u64;
        let mut next_read_result = 0_usize;
        for (expected_operation_index, operation) in self.operations.iter().enumerate() {
            let ProofExternalMemoryTransactionOperation::Read {
                object: expected_object,
                offset: expected_offset,
                byte_length: expected_byte_length,
            } = operation
            else {
                continue;
            };
            let operation_index = usize::try_from(decoder.read_u32()?)
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::WrongOperationBinding)?;
            let object = ProofExternalMemoryObject::new(decoder.read_u32()?);
            let offset = decoder.read_u64()?;
            let byte_length = decoder.read_u32()?;
            if decoder.read_u32()? != 0
                || operation_index != expected_operation_index
                || object != *expected_object
                || offset != *expected_offset
                || byte_length != *expected_byte_length
            {
                return Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding);
            }
            let supplied_digest = decoder.read_array::<HASH_BYTE_LENGTH>()?;
            let bytes =
                decoder
                    .read_bytes(usize::try_from(byte_length).map_err(|_| {
                        ProofExternalMemoryTransactionAdapterError::WrongReadLength
                    })?)?;
            total_payload_byte_length = total_payload_byte_length
                .checked_add(u64::from(byte_length))
                .filter(|length| *length <= self.maximum_payload_byte_length)
                .ok_or(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded)?;
            let expected_digest = external_memory_read_digest(
                &expected_request_digest,
                u32::try_from(operation_index).map_err(|_| {
                    ProofExternalMemoryTransactionAdapterError::WrongOperationBinding
                })?,
                object,
                offset,
                bytes,
            );
            if supplied_digest != expected_digest {
                return Err(ProofExternalMemoryTransactionAdapterError::WrongReadDigest);
            }
            let owned_bytes = read_results
                .get_mut(next_read_result)
                .ok_or(ProofExternalMemoryTransactionAdapterError::WrongReadLength)?;
            clear_and_reserve_zeroizing_bytes(owned_bytes, bytes.len())?;
            owned_bytes.extend_from_slice(bytes);
            next_read_result += 1;
        }
        if !decoder.is_complete() || next_read_result != result_count {
            return Err(ProofExternalMemoryTransactionAdapterError::MalformedWorkerResponse);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn encode_test_worker_response(
        &self,
        read_results: &[Vec<u8>],
    ) -> Result<Vec<u8>, ProofExternalMemoryTransactionAdapterError> {
        let request_digest = self.request_digest()?;
        let expected_read_count = self
            .operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation,
                    ProofExternalMemoryTransactionOperation::Read { .. }
                )
            })
            .count();
        if read_results.len() != expected_read_count {
            return Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding);
        }
        let payload_byte_length = read_results.iter().try_fold(0_usize, |total, bytes| {
            total
                .checked_add(bytes.len())
                .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)
        })?;
        let total_byte_length = EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH
            .checked_add(
                expected_read_count
                    .checked_mul(EXTERNAL_MEMORY_READ_RESULT_HEADER_BYTE_LENGTH)
                    .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?,
            )
            .and_then(|length| length.checked_add(payload_byte_length))
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(total_byte_length)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        encoded.extend_from_slice(&EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes());
        encoded.extend_from_slice(&EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND.to_le_bytes());
        encoded.extend_from_slice(&self.request_sequence.to_le_bytes());
        encoded.extend_from_slice(&request_digest);
        encoded.extend_from_slice(
            &u32::try_from(expected_read_count)
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?
                .to_le_bytes(),
        );
        let mut next_read_result = 0_usize;
        for (operation_index, operation) in self.operations.iter().enumerate() {
            let ProofExternalMemoryTransactionOperation::Read {
                object,
                offset,
                byte_length,
            } = operation
            else {
                continue;
            };
            let bytes = read_results
                .get(next_read_result)
                .ok_or(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding)?;
            if bytes.len()
                != usize::try_from(*byte_length)
                    .map_err(|_| ProofExternalMemoryTransactionAdapterError::WrongReadLength)?
            {
                return Err(ProofExternalMemoryTransactionAdapterError::WrongReadLength);
            }
            let operation_index = u32::try_from(operation_index)
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::WrongOperationBinding)?;
            let digest = external_memory_read_digest(
                &request_digest,
                operation_index,
                *object,
                *offset,
                bytes,
            );
            encoded.extend_from_slice(&operation_index.to_le_bytes());
            encoded.extend_from_slice(&object.ordinal().to_le_bytes());
            encoded.extend_from_slice(&offset.to_le_bytes());
            encoded.extend_from_slice(&byte_length.to_le_bytes());
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&digest);
            encoded.extend_from_slice(bytes);
            next_read_result += 1;
        }
        Ok(encoded)
    }

    pub(crate) fn read_result_count(&self) -> usize {
        self.operations
            .iter()
            .filter(|operation| {
                matches!(
                    operation,
                    ProofExternalMemoryTransactionOperation::Read { .. }
                )
            })
            .count()
    }

    fn encoded_operation_byte_length(
        &self,
    ) -> Result<usize, ProofExternalMemoryTransactionAdapterError> {
        let metadata_byte_length = self
            .operations
            .len()
            .checked_mul(EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH)
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        let append_byte_length = self.operations.iter().enumerate().try_fold(
            0_usize,
            |total, (operation_index, operation)| match operation {
                ProofExternalMemoryTransactionOperation::Append { bytes, .. } => {
                    let byte_length = self
                        .append_replay_byte_length(operation_index)
                        .map_or_else(
                            || Ok(bytes.len()),
                            |recorded_byte_length| {
                                usize::try_from(recorded_byte_length).map_err(|_| {
                                ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded
                            })
                            },
                        )?;
                    total
                        .checked_add(byte_length)
                        .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)
                }
                _ => Ok(total),
            },
        )?;
        metadata_byte_length
            .checked_add(append_byte_length)
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)
    }

    fn visit_encoded_operation_parts(
        &self,
        mut visit: impl FnMut(&[u8]) -> Result<(), ProofExternalMemoryTransactionAdapterError>,
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        for (operation_index, operation) in self.operations.iter().enumerate() {
            let operation_index = u32::try_from(operation_index)
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?;
            if let ProofExternalMemoryTransactionOperation::Append { bytes, .. } = operation {
                let resident_byte_length = u64::try_from(bytes.len()).map_err(|_| {
                    ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded
                })?;
                if self
                    .append_replay_byte_length(usize::try_from(operation_index).map_err(|_| {
                        ProofExternalMemoryTransactionAdapterError::OperationCountExceeded
                    })?)
                    .is_some_and(|recorded_byte_length| {
                        recorded_byte_length != resident_byte_length
                    })
                {
                    return Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle);
                }
            }
            visit_external_memory_operation_parts(operation_index, operation, None, &mut visit)?;
        }
        Ok(())
    }

    fn request_digest_prefix(
        &self,
        operation_count: u32,
        operation_byte_length: usize,
    ) -> Result<StreamingHash512, ProofExternalMemoryTransactionAdapterError> {
        let mut hasher = StreamingHash512::new(EXTERNAL_MEMORY_REQUEST_DIGEST_DOMAIN, 7);
        hasher.absorb_part(&EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes());
        hasher.absorb_part(&self.runtime_binding_hash);
        hasher.absorb_part(&self.request_sequence.to_le_bytes());
        hasher.absorb_part(&self.maximum_payload_byte_length.to_le_bytes());
        hasher.absorb_part(&self.maximum_operation_count.to_le_bytes());
        hasher.absorb_part(&operation_count.to_le_bytes());
        hasher
            .begin_part(u64::try_from(operation_byte_length).map_err(|_| {
                ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded
            })?);
        Ok(hasher)
    }

    pub(super) fn request_digest(
        &self,
    ) -> Result<[u8; HASH_BYTE_LENGTH], ProofExternalMemoryTransactionAdapterError> {
        if let Some(request_digest) = self.request_digest_after_export {
            return Ok(request_digest);
        }
        self.derive_request_digest()
    }

    fn derive_request_digest(
        &self,
    ) -> Result<[u8; HASH_BYTE_LENGTH], ProofExternalMemoryTransactionAdapterError> {
        let operation_count = u32::try_from(self.operations.len())
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?;
        let operation_byte_length = self.encoded_operation_byte_length()?;
        let mut hasher = self.request_digest_prefix(operation_count, operation_byte_length)?;
        self.visit_encoded_operation_parts(|part| {
            hasher.absorb_raw(part);
            Ok(())
        })?;
        Ok(hasher.finalize())
    }
}

fn visit_external_memory_operation_parts(
    operation_index: u32,
    operation: &ProofExternalMemoryTransactionOperation,
    replayed_append_payload: Option<&[u8]>,
    visit: &mut impl FnMut(&[u8]) -> Result<(), ProofExternalMemoryTransactionAdapterError>,
) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
    let (operation_kind, protection, object, position, payload_byte_length, payload) =
        match operation {
            ProofExternalMemoryTransactionOperation::Create {
                object,
                protection,
                exact_byte_length,
            } if replayed_append_payload.is_none() => (
                EXTERNAL_MEMORY_CREATE_OPERATION_CODE,
                external_memory_protection_code(*protection),
                *object,
                0_u64,
                *exact_byte_length,
                &[][..],
            ),
            ProofExternalMemoryTransactionOperation::Append {
                object,
                expected_offset,
                bytes,
            } => {
                let payload = replayed_append_payload.unwrap_or(bytes.as_slice());
                (
                    EXTERNAL_MEMORY_APPEND_OPERATION_CODE,
                    EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                    *object,
                    *expected_offset,
                    u64::try_from(payload.len()).map_err(|_| {
                        ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded
                    })?,
                    payload,
                )
            }
            ProofExternalMemoryTransactionOperation::Seal { object }
                if replayed_append_payload.is_none() =>
            {
                (
                    EXTERNAL_MEMORY_SEAL_OPERATION_CODE,
                    EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                    *object,
                    0_u64,
                    0_u64,
                    &[][..],
                )
            }
            ProofExternalMemoryTransactionOperation::Read {
                object,
                offset,
                byte_length,
            } if replayed_append_payload.is_none() => (
                EXTERNAL_MEMORY_READ_OPERATION_CODE,
                EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                *object,
                *offset,
                u64::from(*byte_length),
                &[][..],
            ),
            ProofExternalMemoryTransactionOperation::Delete { object }
                if replayed_append_payload.is_none() =>
            {
                (
                    EXTERNAL_MEMORY_DELETE_OPERATION_CODE,
                    EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                    *object,
                    0_u64,
                    0_u64,
                    &[][..],
                )
            }
            _ => return Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle),
        };
    visit(&operation_index.to_le_bytes())?;
    visit(&operation_kind.to_le_bytes())?;
    visit(&protection.to_le_bytes())?;
    visit(&object.ordinal().to_le_bytes())?;
    visit(&0_u32.to_le_bytes())?;
    visit(&position.to_le_bytes())?;
    visit(&payload_byte_length.to_le_bytes())?;
    visit(payload)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryTransactionAdapterError {
    /// Expected completion signal from the recording pass.  The caller takes
    /// the request, performs it asynchronously, then retries through replay.
    Yielded,
    InvalidLifecycle,
    InvalidReplay,
    WrongReadLength,
    OperationCountExceeded,
    PayloadByteLengthExceeded,
    AllocationLimitExceeded,
    MalformedWorkerResponse,
    WrongRequestDigest,
    WrongOperationBinding,
    WrongReadDigest,
}

fn external_memory_protection_code(protection: ProofExternalMemoryProtection) -> u16 {
    match protection {
        ProofExternalMemoryProtection::PublicIntegrity => {
            EXTERNAL_MEMORY_PUBLIC_INTEGRITY_PROTECTION_CODE
        }
        ProofExternalMemoryProtection::SecretAuthenticatedEncryption => {
            EXTERNAL_MEMORY_SECRET_AUTHENTICATED_ENCRYPTION_PROTECTION_CODE
        }
    }
}

pub(super) fn external_memory_read_digest(
    request_digest: &[u8; HASH_BYTE_LENGTH],
    operation_index: u32,
    object: ProofExternalMemoryObject,
    offset: u64,
    bytes: &[u8],
) -> [u8; HASH_BYTE_LENGTH] {
    hash_framed_parts_512(
        EXTERNAL_MEMORY_READ_DIGEST_DOMAIN,
        &[
            request_digest,
            &operation_index.to_le_bytes(),
            &object.ordinal().to_le_bytes(),
            &offset.to_le_bytes(),
            &u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes(),
            bytes,
        ],
    )
}

struct ExternalMemoryMessageDecoder<'encoded> {
    encoded: &'encoded [u8],
    offset: usize,
}

impl<'encoded> ExternalMemoryMessageDecoder<'encoded> {
    const fn new(encoded: &'encoded [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, ProofExternalMemoryTransactionAdapterError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, ProofExternalMemoryTransactionAdapterError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, ProofExternalMemoryTransactionAdapterError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_array<const BYTE_LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; BYTE_LENGTH], ProofExternalMemoryTransactionAdapterError> {
        let bytes = self.read_bytes(BYTE_LENGTH)?;
        bytes
            .try_into()
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::MalformedWorkerResponse)
    }

    fn read_bytes(
        &mut self,
        byte_length: usize,
    ) -> Result<&'encoded [u8], ProofExternalMemoryTransactionAdapterError> {
        let end = self
            .offset
            .checked_add(byte_length)
            .filter(|end| *end <= self.encoded.len())
            .ok_or(ProofExternalMemoryTransactionAdapterError::MalformedWorkerResponse)?;
        let bytes = self
            .encoded
            .get(self.offset..end)
            .ok_or(ProofExternalMemoryTransactionAdapterError::MalformedWorkerResponse)?;
        self.offset = end;
        Ok(bytes)
    }

    const fn is_complete(&self) -> bool {
        self.offset == self.encoded.len()
    }
}

/// First half of a browser storage call.  It records the exact transaction and
/// intentionally makes `commit_transaction` fail with `Yielded`, which keeps
/// the executor's cryptographic/liveness state unchanged.
pub(crate) struct ProofExternalMemoryTransactionRecorder {
    runtime_binding_hash: [u8; HASH_BYTE_LENGTH],
    next_request_sequence: u64,
    active_maximum_payload_byte_length: Option<u64>,
    active_maximum_operation_count: Option<u32>,
    active_payload_byte_length: u64,
    active_operations: Vec<ProofExternalMemoryTransactionOperation>,
    recycled_append_bytes: Vec<Zeroizing<Vec<u8>>>,
    yielded_request: Option<ProofExternalMemoryTransactionRequest>,
}

impl Default for ProofExternalMemoryTransactionRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofExternalMemoryTransactionRecorder {
    pub(crate) fn new() -> Self {
        Self::for_runtime_binding([0; HASH_BYTE_LENGTH], 1)
    }

    pub(crate) const fn for_runtime_binding(
        runtime_binding_hash: [u8; HASH_BYTE_LENGTH],
        next_request_sequence: u64,
    ) -> Self {
        Self {
            runtime_binding_hash,
            next_request_sequence,
            active_maximum_payload_byte_length: None,
            active_maximum_operation_count: None,
            active_payload_byte_length: 0,
            active_operations: Vec::new(),
            recycled_append_bytes: Vec::new(),
            yielded_request: None,
        }
    }

    pub(crate) fn with_recycled_storage(
        runtime_binding_hash: [u8; HASH_BYTE_LENGTH],
        next_request_sequence: u64,
        active_operations: Vec<ProofExternalMemoryTransactionOperation>,
        recycled_append_bytes: Vec<Zeroizing<Vec<u8>>>,
    ) -> Self {
        Self {
            runtime_binding_hash,
            next_request_sequence,
            active_maximum_payload_byte_length: None,
            active_maximum_operation_count: None,
            active_payload_byte_length: 0,
            active_operations,
            recycled_append_bytes,
            yielded_request: None,
        }
    }

    pub(crate) fn take_yielded_request(&mut self) -> Option<ProofExternalMemoryTransactionRequest> {
        self.yielded_request.take()
    }

    pub(crate) fn take_recycled_append_bytes(&mut self) -> Vec<Zeroizing<Vec<u8>>> {
        core::mem::take(&mut self.recycled_append_bytes)
    }

    fn record(
        &mut self,
        operation: ProofExternalMemoryTransactionOperation,
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        let operation_payload_byte_length = match &operation {
            ProofExternalMemoryTransactionOperation::Append { bytes, .. } => {
                u64::try_from(bytes.len()).map_err(|_| {
                    ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded
                })?
            }
            ProofExternalMemoryTransactionOperation::Read { byte_length, .. } => {
                u64::from(*byte_length)
            }
            _ => 0,
        };
        let next_payload_byte_length =
            self.prepare_operation_recording(operation_payload_byte_length)?;
        self.active_operations.push(operation);
        self.active_payload_byte_length = next_payload_byte_length;
        Ok(())
    }

    fn prepare_operation_recording(
        &mut self,
        operation_payload_byte_length: u64,
    ) -> Result<u64, ProofExternalMemoryTransactionAdapterError> {
        if self.active_maximum_payload_byte_length.is_none()
            || self.active_maximum_operation_count.is_none()
            || self.yielded_request.is_some()
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle);
        }
        let maximum_operation_count = usize::try_from(
            self.active_maximum_operation_count
                .ok_or(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)?,
        )
        .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?;
        if self.active_operations.len() >= maximum_operation_count {
            return Err(ProofExternalMemoryTransactionAdapterError::OperationCountExceeded);
        }
        let next_payload_byte_length = self
            .active_payload_byte_length
            .checked_add(operation_payload_byte_length)
            .ok_or(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded)?;
        if next_payload_byte_length
            > self
                .active_maximum_payload_byte_length
                .ok_or(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)?
        {
            return Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded);
        }
        self.active_operations
            .try_reserve_exact(1)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        if maximum_operation_count == 1
            && self.active_operations.capacity()
                > EXTERNAL_MEMORY_SINGLE_OPERATION_VECTOR_CAPACITY_CEILING
        {
            return Err(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded);
        }
        Ok(next_payload_byte_length)
    }
}

impl ProofExternalMemory for ProofExternalMemoryTransactionRecorder {
    type Error = ProofExternalMemoryTransactionAdapterError;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error> {
        if maximum_payload_byte_length == 0
            || maximum_operation_count == 0
            || self.next_request_sequence == 0
            || self.active_maximum_payload_byte_length.is_some()
            || self.active_maximum_operation_count.is_some()
            || self.active_payload_byte_length != 0
            || self.yielded_request.is_some()
            || !self.active_operations.is_empty()
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle);
        }
        self.active_maximum_payload_byte_length = Some(maximum_payload_byte_length);
        self.active_maximum_operation_count = Some(maximum_operation_count);
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        self.record(ProofExternalMemoryTransactionOperation::Create {
            object,
            protection,
            exact_byte_length,
        })
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let mut owned_bytes = self
            .recycled_append_bytes
            .pop()
            .unwrap_or_else(|| Zeroizing::new(Vec::new()));
        clear_and_reserve_zeroizing_bytes(&mut owned_bytes, bytes.len())?;
        owned_bytes.extend_from_slice(bytes);
        self.record(ProofExternalMemoryTransactionOperation::Append {
            object,
            expected_offset,
            bytes: owned_bytes,
        })
    }

    fn append_owned_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), Self::Error> {
        let operation_payload_byte_length = u64::try_from(bytes.len())
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded)?;
        let next_payload_byte_length =
            self.prepare_operation_recording(operation_payload_byte_length)?;
        let owned_bytes = core::mem::replace(bytes, Zeroizing::new(Vec::new()));
        self.active_operations
            .push(ProofExternalMemoryTransactionOperation::Append {
                object,
                expected_offset,
                bytes: owned_bytes,
            });
        self.active_payload_byte_length = next_payload_byte_length;
        Ok(())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        self.record(ProofExternalMemoryTransactionOperation::Seal { object })
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let byte_length = u32::try_from(destination.len())
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::WrongReadLength)?;
        destination.fill(0);
        self.record(ProofExternalMemoryTransactionOperation::Read {
            object,
            offset,
            byte_length,
        })
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        self.record(ProofExternalMemoryTransactionOperation::Delete { object })
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        let maximum_payload_byte_length = self
            .active_maximum_payload_byte_length
            .take()
            .ok_or(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)?;
        let maximum_operation_count = self
            .active_maximum_operation_count
            .take()
            .ok_or(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle)?;
        if self.active_operations.is_empty() || self.yielded_request.is_some() {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidLifecycle);
        }
        self.yielded_request = Some(ProofExternalMemoryTransactionRequest {
            runtime_binding_hash: self.runtime_binding_hash,
            request_sequence: self.next_request_sequence,
            maximum_payload_byte_length,
            maximum_operation_count,
            operations: core::mem::take(&mut self.active_operations),
            request_digest_after_export: None,
            append_replay_byte_lengths: Vec::new(),
        });
        self.next_request_sequence = self.next_request_sequence.checked_add(1).unwrap_or(0);
        self.active_payload_byte_length = 0;
        Err(ProofExternalMemoryTransactionAdapterError::Yielded)
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        self.active_maximum_payload_byte_length = None;
        self.active_maximum_operation_count = None;
        self.active_payload_byte_length = 0;
        self.active_operations.clear();
        Ok(())
    }
}

/// Second half of a browser storage call.  It validates that the retried
/// executor operation is byte-for-byte identical to the yielded request and
/// supplies only the corresponding IndexedDB read results.
pub(crate) struct ProofExternalMemoryTransactionReplay {
    request: ProofExternalMemoryTransactionRequest,
    read_results: Vec<Zeroizing<Vec<u8>>>,
    replayed_request_hasher: Option<StreamingHash512>,
    next_operation_index: usize,
    next_read_result_index: usize,
    active: bool,
}

impl ProofExternalMemoryTransactionReplay {
    pub(crate) fn new(
        request: ProofExternalMemoryTransactionRequest,
        read_results: Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, ProofExternalMemoryTransactionAdapterError> {
        if request.maximum_payload_byte_length == 0
            || request.maximum_operation_count == 0
            || request.operations.is_empty()
            || request.operations.len()
                > usize::try_from(request.maximum_operation_count).map_err(|_| {
                    ProofExternalMemoryTransactionAdapterError::OperationCountExceeded
                })?
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        let has_exported_request_binding = request.request_digest_after_export.is_some();
        if has_exported_request_binding
            != (request.append_replay_byte_lengths.len() == request.operations.len())
            || request
                .operations
                .iter()
                .enumerate()
                .any(|(operation_index, operation)| match operation {
                    ProofExternalMemoryTransactionOperation::Append { bytes, .. } => {
                        match request.append_replay_byte_length(operation_index) {
                            Some(byte_length) => {
                                !bytes.is_empty() || bytes.capacity() != 0 || byte_length == 0
                            }
                            None => has_exported_request_binding,
                        }
                    }
                    _ => request.append_replay_byte_length(operation_index).is_some(),
                })
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        let payload_byte_length = request.operations.iter().enumerate().try_fold(
            0_u64,
            |total, (operation_index, operation)| {
                    let operation_byte_length = match operation {
                        ProofExternalMemoryTransactionOperation::Append { bytes, .. } => request
                            .append_replay_byte_length(operation_index)
                            .map_or_else(
                                || {
                                    u64::try_from(bytes.len()).map_err(|_| {
                                        ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded
                                    })
                                },
                                Ok,
                            )?,
                        ProofExternalMemoryTransactionOperation::Read { byte_length, .. } => {
                            u64::from(*byte_length)
                        }
                        _ => 0,
                    };
                    total.checked_add(operation_byte_length).ok_or(
                        ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded,
                    )
                },
        )?;
        if payload_byte_length > request.maximum_payload_byte_length {
            return Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded);
        }
        let mut supplied_results = read_results.iter();
        for operation in &request.operations {
            if let ProofExternalMemoryTransactionOperation::Read { byte_length, .. } = operation {
                let result = supplied_results
                    .next()
                    .ok_or(ProofExternalMemoryTransactionAdapterError::WrongReadLength)?;
                if result.len()
                    != usize::try_from(*byte_length)
                        .map_err(|_| ProofExternalMemoryTransactionAdapterError::WrongReadLength)?
                {
                    return Err(ProofExternalMemoryTransactionAdapterError::WrongReadLength);
                }
            }
        }
        if supplied_results.next().is_some() {
            return Err(ProofExternalMemoryTransactionAdapterError::WrongReadLength);
        }
        Ok(Self {
            request,
            read_results,
            replayed_request_hasher: None,
            next_operation_index: 0,
            next_read_result_index: 0,
            active: false,
        })
    }

    fn accept(
        &mut self,
        operation: ProofExternalMemoryTransactionOperation,
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        if !self.active
            || self.request.operations.get(self.next_operation_index) != Some(&operation)
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        if let Some(hasher) = self.replayed_request_hasher.as_mut() {
            let operation_index = u32::try_from(self.next_operation_index)
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
            visit_external_memory_operation_parts(operation_index, &operation, None, &mut |part| {
                hasher.absorb_raw(part);
                Ok(())
            })
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
        }
        self.next_operation_index += 1;
        Ok(())
    }

    fn accept_append(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
        if !self.active {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        let Some(ProofExternalMemoryTransactionOperation::Append {
            object: expected_object,
            expected_offset: expected_expected_offset,
            bytes: expected_bytes,
        }) = self.request.operations.get(self.next_operation_index)
        else {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        };
        if *expected_object != object || *expected_expected_offset != expected_offset {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        if let Some(expected_byte_length) = self
            .request
            .append_replay_byte_length(self.next_operation_index)
        {
            let byte_length = u64::try_from(bytes.len())
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
            if byte_length != expected_byte_length {
                return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
            }
        } else if expected_bytes.as_slice() != bytes {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        if let Some(hasher) = self.replayed_request_hasher.as_mut() {
            let operation_index = u32::try_from(self.next_operation_index)
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
            visit_external_memory_operation_parts(
                operation_index,
                self.request
                    .operations
                    .get(self.next_operation_index)
                    .ok_or(ProofExternalMemoryTransactionAdapterError::InvalidReplay)?,
                Some(bytes),
                &mut |part| {
                    hasher.absorb_raw(part);
                    Ok(())
                },
            )
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
        }
        self.next_operation_index += 1;
        Ok(())
    }

    pub(crate) fn into_recycled_storage(
        self,
        recycled_append_bytes: &mut Vec<Zeroizing<Vec<u8>>>,
    ) -> Result<RecycledTransactionStorage, ProofExternalMemoryTransactionAdapterError> {
        let single_operation_transaction = self.request.maximum_operation_count == 1;
        let mut operations = self.request.operations;
        for operation in &mut operations {
            if let ProofExternalMemoryTransactionOperation::Append { bytes, .. } = operation {
                bytes.as_mut_slice().zeroize();
                bytes.clear();
                if bytes.capacity() != 0 {
                    recycled_append_bytes
                        .push(core::mem::replace(bytes, Zeroizing::new(Vec::new())));
                }
                if single_operation_transaction
                    && recycled_append_bytes.capacity()
                        > EXTERNAL_MEMORY_SINGLE_APPEND_RECYCLER_CAPACITY_CEILING
                {
                    return Err(
                        ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded,
                    );
                }
            }
        }
        operations.clear();
        let mut read_results = self.read_results;
        for bytes in &mut read_results {
            bytes.as_mut_slice().zeroize();
            bytes.clear();
        }
        Ok((operations, read_results))
    }

    pub(crate) fn transaction_is_complete(&self) -> bool {
        !self.active
            && self.replayed_request_hasher.is_none()
            && self.next_operation_index == self.request.operations.len()
            && self.next_read_result_index == self.read_results.len()
    }
}

impl ProofExternalMemory for ProofExternalMemoryTransactionReplay {
    type Error = ProofExternalMemoryTransactionAdapterError;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error> {
        if self.active
            || self.next_operation_index != 0
            || self.replayed_request_hasher.is_some()
            || maximum_payload_byte_length != self.request.maximum_payload_byte_length
            || maximum_operation_count != self.request.maximum_operation_count
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        if self.request.request_digest_after_export.is_some() {
            let operation_count = u32::try_from(self.request.operations.len())
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
            let operation_byte_length = self
                .request
                .encoded_operation_byte_length()
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
            self.replayed_request_hasher = Some(
                self.request
                    .request_digest_prefix(operation_count, operation_byte_length)
                    .map_err(|_| ProofExternalMemoryTransactionAdapterError::InvalidReplay)?,
            );
        }
        self.active = true;
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        self.accept(ProofExternalMemoryTransactionOperation::Create {
            object,
            protection,
            exact_byte_length,
        })
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.accept_append(object, expected_offset, bytes)
    }

    fn append_owned_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), Self::Error> {
        self.accept_append(object, expected_offset, bytes.as_slice())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        self.accept(ProofExternalMemoryTransactionOperation::Seal { object })
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.accept(ProofExternalMemoryTransactionOperation::Read {
            object,
            offset,
            byte_length: u32::try_from(destination.len())
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::WrongReadLength)?,
        })?;
        let result = self
            .read_results
            .get(self.next_read_result_index)
            .ok_or(ProofExternalMemoryTransactionAdapterError::WrongReadLength)?;
        if result.len() != destination.len() {
            return Err(ProofExternalMemoryTransactionAdapterError::WrongReadLength);
        }
        destination.copy_from_slice(result);
        self.next_read_result_index += 1;
        Ok(())
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        self.accept(ProofExternalMemoryTransactionOperation::Delete { object })
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        if !self.active
            || self.next_operation_index != self.request.operations.len()
            || self.next_read_result_index != self.read_results.len()
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
        }
        if let Some(hasher) = self.replayed_request_hasher.take() {
            let expected_request_digest = self
                .request
                .request_digest_after_export
                .ok_or(ProofExternalMemoryTransactionAdapterError::InvalidReplay)?;
            if hasher.finalize() != expected_request_digest {
                return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
            }
        }
        self.active = false;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        self.active = false;
        self.replayed_request_hasher = None;
        Ok(())
    }
}

fn clear_and_reserve_zeroizing_bytes(
    bytes: &mut Zeroizing<Vec<u8>>,
    required_byte_length: usize,
) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
    bytes.as_mut_slice().zeroize();
    bytes.clear();
    if bytes.capacity() < required_byte_length {
        bytes
            .try_reserve_exact(required_byte_length)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
    }
    Ok(())
}

fn write_exact_bytes(
    output: &mut [u8],
    offset: &mut usize,
    bytes: &[u8],
) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
    let end = offset
        .checked_add(bytes.len())
        .filter(|end| *end <= output.len())
        .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
    output[*offset..end].copy_from_slice(bytes);
    *offset = end;
    Ok(())
}
