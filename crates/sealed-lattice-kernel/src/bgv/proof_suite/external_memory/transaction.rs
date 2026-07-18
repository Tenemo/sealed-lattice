use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::hashing::hash_framed_parts_512;

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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryTransactionRequest {
    runtime_binding_hash: [u8; HASH_BYTE_LENGTH],
    request_sequence: u64,
    maximum_payload_byte_length: u64,
    maximum_operation_count: u32,
    operations: Vec<ProofExternalMemoryTransactionOperation>,
}

impl ProofExternalMemoryTransactionRequest {
    pub(crate) const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    pub(crate) const fn maximum_payload_byte_length(&self) -> u64 {
        self.maximum_payload_byte_length
    }

    pub(crate) const fn maximum_operation_count(&self) -> u32 {
        self.maximum_operation_count
    }

    pub(crate) fn operations(&self) -> &[ProofExternalMemoryTransactionOperation] {
        &self.operations
    }

    /// Encodes the exact yielded transaction for the browser worker. The
    /// digest covers every operation ordinal, object, range, protection mode,
    /// and append byte. It is returned by the host with every read response so
    /// a delayed or reordered response cannot be supplied to another yield.
    pub(crate) fn encode_worker_request(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProofExternalMemoryTransactionAdapterError> {
        let operation_bytes = self.encode_operation_bytes()?;
        let request_digest = self.request_digest(&operation_bytes)?;
        let byte_length = EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH
            .checked_add(operation_bytes.len())
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(byte_length)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        encoded.extend_from_slice(&EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes());
        encoded.extend_from_slice(&EXTERNAL_MEMORY_REQUEST_MESSAGE_KIND.to_le_bytes());
        encoded.extend_from_slice(&self.maximum_payload_byte_length.to_le_bytes());
        encoded.extend_from_slice(&self.maximum_operation_count.to_le_bytes());
        encoded.extend_from_slice(
            &u32::try_from(self.operations.len())
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&self.request_sequence.to_le_bytes());
        encoded.extend_from_slice(&self.runtime_binding_hash);
        encoded.extend_from_slice(&request_digest);
        encoded.extend_from_slice(&operation_bytes);
        Ok(encoded)
    }

    /// Decodes and authenticates one hostile worker response. The response is
    /// accepted only when it contains exactly one result for each requested
    /// read, in the same operation order and with the exact object, range,
    /// payload length, request digest, and recomputed payload digest.
    pub(crate) fn decode_worker_response(
        &self,
        encoded: &[u8],
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, ProofExternalMemoryTransactionAdapterError> {
        let operation_bytes = self.encode_operation_bytes()?;
        let expected_request_digest = self.request_digest(&operation_bytes)?;
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
        let mut read_results = Vec::new();
        read_results
            .try_reserve_exact(result_count)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        let mut total_payload_byte_length = 0_u64;
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
            let mut owned_bytes = Zeroizing::new(Vec::new());
            owned_bytes
                .try_reserve_exact(bytes.len())
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
            owned_bytes.extend_from_slice(bytes);
            read_results.push(owned_bytes);
        }
        if !decoder.is_complete() {
            return Err(ProofExternalMemoryTransactionAdapterError::MalformedWorkerResponse);
        }
        Ok(read_results)
    }

    #[cfg(test)]
    pub(crate) fn encode_test_worker_response(
        &self,
        read_results: &[Vec<u8>],
    ) -> Result<Vec<u8>, ProofExternalMemoryTransactionAdapterError> {
        let operation_bytes = self.encode_operation_bytes()?;
        let request_digest = self.request_digest(&operation_bytes)?;
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

    pub(super) fn encode_operation_bytes(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProofExternalMemoryTransactionAdapterError> {
        let metadata_byte_length = self
            .operations
            .len()
            .checked_mul(EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH)
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        let append_byte_length = self
            .operations
            .iter()
            .try_fold(0_usize, |total, operation| match operation {
                ProofExternalMemoryTransactionOperation::Append { bytes, .. } => total
                    .checked_add(bytes.len())
                    .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded),
                _ => Ok(total),
            })?;
        let encoded_byte_length = metadata_byte_length
            .checked_add(append_byte_length)
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(encoded_byte_length)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        for (operation_index, operation) in self.operations.iter().enumerate() {
            let operation_index = u32::try_from(operation_index)
                .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?;
            encoded.extend_from_slice(&operation_index.to_le_bytes());
            let (operation_kind, protection, object, position, payload_byte_length, payload) =
                match operation {
                    ProofExternalMemoryTransactionOperation::Create {
                        object,
                        protection,
                        exact_byte_length,
                    } => (
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
                    } => (
                        EXTERNAL_MEMORY_APPEND_OPERATION_CODE,
                        EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                        *object,
                        *expected_offset,
                        u64::try_from(bytes.len()).map_err(|_| {
                            ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded
                        })?,
                        bytes.as_slice(),
                    ),
                    ProofExternalMemoryTransactionOperation::Seal { object } => (
                        EXTERNAL_MEMORY_SEAL_OPERATION_CODE,
                        EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                        *object,
                        0_u64,
                        0_u64,
                        &[][..],
                    ),
                    ProofExternalMemoryTransactionOperation::Read {
                        object,
                        offset,
                        byte_length,
                    } => (
                        EXTERNAL_MEMORY_READ_OPERATION_CODE,
                        EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                        *object,
                        *offset,
                        u64::from(*byte_length),
                        &[][..],
                    ),
                    ProofExternalMemoryTransactionOperation::Delete { object } => (
                        EXTERNAL_MEMORY_DELETE_OPERATION_CODE,
                        EXTERNAL_MEMORY_NO_PROTECTION_CODE,
                        *object,
                        0_u64,
                        0_u64,
                        &[][..],
                    ),
                };
            encoded.extend_from_slice(&operation_kind.to_le_bytes());
            encoded.extend_from_slice(&protection.to_le_bytes());
            encoded.extend_from_slice(&object.ordinal().to_le_bytes());
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&position.to_le_bytes());
            encoded.extend_from_slice(&payload_byte_length.to_le_bytes());
            encoded.extend_from_slice(payload);
        }
        Ok(encoded)
    }

    pub(super) fn request_digest(
        &self,
        operation_bytes: &[u8],
    ) -> Result<[u8; HASH_BYTE_LENGTH], ProofExternalMemoryTransactionAdapterError> {
        let operation_count = u32::try_from(self.operations.len())
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::OperationCountExceeded)?;
        Ok(hash_framed_parts_512(
            EXTERNAL_MEMORY_REQUEST_DIGEST_DOMAIN,
            &[
                &EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes(),
                &self.runtime_binding_hash,
                &self.request_sequence.to_le_bytes(),
                &self.maximum_payload_byte_length.to_le_bytes(),
                &self.maximum_operation_count.to_le_bytes(),
                &operation_count.to_le_bytes(),
                operation_bytes,
            ],
        ))
    }
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
            yielded_request: None,
        }
    }

    pub(crate) fn take_yielded_request(&mut self) -> Option<ProofExternalMemoryTransactionRequest> {
        self.yielded_request.take()
    }

    fn record(
        &mut self,
        operation: ProofExternalMemoryTransactionOperation,
    ) -> Result<(), ProofExternalMemoryTransactionAdapterError> {
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
            .try_reserve(1)
            .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        self.active_operations.push(operation);
        self.active_payload_byte_length = next_payload_byte_length;
        Ok(())
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
        let bytes = copy_transaction_bytes(bytes)?;
        self.record(ProofExternalMemoryTransactionOperation::Append {
            object,
            expected_offset,
            bytes,
        })
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
        let payload_byte_length =
            request
                .operations
                .iter()
                .try_fold(0_u64, |total, operation| {
                    let operation_byte_length = match operation {
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
                    total.checked_add(operation_byte_length).ok_or(
                        ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded,
                    )
                })?;
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
        self.next_operation_index += 1;
        Ok(())
    }

    pub(crate) fn transaction_is_complete(&self) -> bool {
        !self.active
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
            || maximum_payload_byte_length != self.request.maximum_payload_byte_length
            || maximum_operation_count != self.request.maximum_operation_count
        {
            return Err(ProofExternalMemoryTransactionAdapterError::InvalidReplay);
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
        let bytes = copy_transaction_bytes(bytes)?;
        self.accept(ProofExternalMemoryTransactionOperation::Append {
            object,
            expected_offset,
            bytes,
        })
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
        self.active = false;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        self.active = false;
        Ok(())
    }
}

fn copy_transaction_bytes(
    source: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProofExternalMemoryTransactionAdapterError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(source.len())
        .map_err(|_| ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
    bytes.extend_from_slice(source);
    Ok(Zeroizing::new(bytes))
}
