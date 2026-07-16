//! Bounded external-memory execution for browser proof generation.
//!
//! The storage implementation is deliberately abstract.  Native callers may
//! implement it directly.  A browser uses the recorder/replay adapter below:
//! the first kernel call yields one bounded owned transaction request, the
//! worker awaits its transaction-owned IndexedDB runtime, and the next kernel
//! call replays the exact request with the returned read bytes.  Executor state
//! changes only after that successful replay.  No filesystem, thread, blocking
//! JavaScript callback, or whole proof in memory is required.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use zeroize::Zeroizing;

use crate::hashing::hash_framed_parts_512;

const EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION: u16 = 1;
const EXTERNAL_MEMORY_REQUEST_MESSAGE_KIND: u16 = 1;
const EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND: u16 = 2;
const EXTERNAL_MEMORY_REQUEST_DIGEST_DOMAIN: &str =
    "sealed-lattice/common-proof/external-memory-request/v1";
const EXTERNAL_MEMORY_READ_DIGEST_DOMAIN: &str =
    "sealed-lattice/common-proof/external-memory-read/v1";
const EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH: usize = 156;
const EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH: usize = 80;
const EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH: usize = 32;
const EXTERNAL_MEMORY_READ_RESULT_HEADER_BYTE_LENGTH: usize = 88;
const HASH_BYTE_LENGTH: usize = 64;

/// Fixed browser scratch ceilings. The worker-side custody layer enforces the
/// corresponding object and encrypted-record limits before touching IndexedDB.
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT: usize = 4_096;
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH: u64 = 268_435_456;

/// One plan-local external-memory object.  The surrounding proof transaction
/// supplies the unguessable lease and transaction identifiers; this ordinal is
/// only an address inside that already-authorized namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProofExternalMemoryObject(u32);

impl ProofExternalMemoryObject {
    pub(crate) const fn new(ordinal: u32) -> Self {
        Self(ordinal)
    }

    pub(crate) const fn ordinal(self) -> u32 {
        self.0
    }
}

/// Protection the transaction substrate must apply while bytes are outside
/// the proof worker.  Secret scratch is never written through the public path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryProtection {
    PublicIntegrity,
    SecretAuthenticatedEncryption,
}

/// One build-linked liveness entry.  Steps are dense zero-based executor
/// phases.  Writes may occur from `issued_step` through `seal_step`; reads may
/// occur after sealing through `last_use_step`; the executor deletes the object
/// transactionally when that last-use step completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryObjectPlan {
    object: ProofExternalMemoryObject,
    protection: ProofExternalMemoryProtection,
    exact_byte_length: u64,
    issued_step: u32,
    seal_step: u32,
    last_use_step: u32,
}

impl ProofExternalMemoryObjectPlan {
    pub(crate) const fn new(
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
        issued_step: u32,
        seal_step: u32,
        last_use_step: u32,
    ) -> Self {
        Self {
            object,
            protection,
            exact_byte_length,
            issued_step,
            seal_step,
            last_use_step,
        }
    }

    pub(crate) const fn object(self) -> ProofExternalMemoryObject {
        self.object
    }

    pub(crate) const fn protection(self) -> ProofExternalMemoryProtection {
        self.protection
    }

    pub(crate) const fn exact_byte_length(self) -> u64 {
        self.exact_byte_length
    }

    pub(crate) const fn issued_step(self) -> u32 {
        self.issued_step
    }

    pub(crate) const fn seal_step(self) -> u32 {
        self.seal_step
    }

    pub(crate) const fn last_use_step(self) -> u32 {
        self.last_use_step
    }
}

/// Hard resource ceilings for one generated storage/liveness plan.  These are
/// runtime controls, not proof fields and not verifier inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryPlan {
    step_count: u32,
    maximum_chunk_byte_length: u32,
    maximum_transaction_payload_byte_length: u64,
    maximum_transaction_operation_count: u32,
    maximum_stored_byte_length: u64,
    maximum_total_written_byte_length: u64,
    maximum_total_read_byte_length: u64,
    maximum_transaction_count: u64,
    objects: Vec<ProofExternalMemoryObjectPlan>,
}

impl ProofExternalMemoryPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        step_count: u32,
        maximum_chunk_byte_length: u32,
        maximum_transaction_payload_byte_length: u64,
        maximum_transaction_operation_count: u32,
        maximum_stored_byte_length: u64,
        maximum_total_written_byte_length: u64,
        maximum_total_read_byte_length: u64,
        maximum_transaction_count: u64,
        objects: Vec<ProofExternalMemoryObjectPlan>,
    ) -> Result<Self, ProofExternalMemoryError> {
        let plan = Self {
            step_count,
            maximum_chunk_byte_length,
            maximum_transaction_payload_byte_length,
            maximum_transaction_operation_count,
            maximum_stored_byte_length,
            maximum_total_written_byte_length,
            maximum_total_read_byte_length,
            maximum_transaction_count,
            objects,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), ProofExternalMemoryError> {
        if self.step_count == 0
            || self.maximum_chunk_byte_length == 0
            || self.maximum_transaction_payload_byte_length == 0
            || self.maximum_transaction_operation_count == 0
            || self.maximum_stored_byte_length == 0
            || self.maximum_total_written_byte_length == 0
            || self.maximum_total_read_byte_length == 0
            || self.maximum_transaction_count == 0
            || self.objects.is_empty()
            || u64::from(self.maximum_chunk_byte_length)
                > self.maximum_transaction_payload_byte_length
        {
            return Err(ProofExternalMemoryError::InvalidPlan);
        }
        if self.objects.len()
            > usize::try_from(self.maximum_transaction_operation_count)
                .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
            || self.objects.len() > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT
            || usize::try_from(self.maximum_transaction_operation_count)
                .ok()
                .is_none_or(|operation_count| {
                    operation_count > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT
                })
            || self.maximum_stored_byte_length
                > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }

        let mut object_ordinals = BTreeSet::new();
        let mut scheduled_total_write = 0_u64;
        let event_count = self
            .objects
            .len()
            .checked_mul(2)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let mut liveness_events = Vec::new();
        liveness_events
            .try_reserve_exact(event_count)
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        for object in &self.objects {
            if object.exact_byte_length == 0
                || object.issued_step > object.seal_step
                || object.seal_step > object.last_use_step
                || object.last_use_step >= self.step_count
                || !object_ordinals.insert(object.object)
            {
                return Err(ProofExternalMemoryError::InvalidPlan);
            }
            scheduled_total_write = scheduled_total_write
                .checked_add(object.exact_byte_length)
                .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            liveness_events.push((object.issued_step, true, object.exact_byte_length));
            liveness_events.push((
                object
                    .last_use_step
                    .checked_add(1)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?,
                false,
                object.exact_byte_length,
            ));
        }
        if scheduled_total_write > self.maximum_total_written_byte_length {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }

        // An object occupies external storage from issuance through its
        // declared last-use step.  Event sweeping keeps validation bounded by
        // the object count even when an invalid caller supplies a huge step
        // count.  Deletions sort before issuances at the same step.
        liveness_events.sort_unstable_by_key(|(step, is_issuance, _)| (*step, *is_issuance));
        let mut live_byte_length = 0_u64;
        for (_, is_issuance, exact_byte_length) in liveness_events {
            if is_issuance {
                live_byte_length = live_byte_length
                    .checked_add(exact_byte_length)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
                if live_byte_length > self.maximum_stored_byte_length {
                    return Err(ProofExternalMemoryError::ResourceLimitExceeded);
                }
            } else {
                live_byte_length = live_byte_length
                    .checked_sub(exact_byte_length)
                    .ok_or(ProofExternalMemoryError::InvalidPlan)?;
            }
        }
        if live_byte_length != 0 {
            return Err(ProofExternalMemoryError::InvalidPlan);
        }
        Ok(())
    }

    pub(crate) const fn step_count(&self) -> u32 {
        self.step_count
    }

    pub(crate) const fn maximum_chunk_byte_length(&self) -> u32 {
        self.maximum_chunk_byte_length
    }

    pub(crate) const fn maximum_transaction_operation_count(&self) -> u32 {
        self.maximum_transaction_operation_count
    }

    pub(crate) fn objects(&self) -> &[ProofExternalMemoryObjectPlan] {
        &self.objects
    }
}

/// The transaction-owned browser storage boundary.  Implementations must make
/// `commit_transaction` atomic and use copy-on-write storage.  A secret object
/// must be encrypted and authenticated before a successful commit. A failed
/// commit is repaired from the existing authenticated journal before this
/// executor is resumed.
pub(crate) trait ProofExternalMemory {
    type Error;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error>;

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error>;

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error>;

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error>;

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error>;

    fn commit_transaction(&mut self) -> Result<(), Self::Error>;

    fn abort_transaction(&mut self) -> Result<(), Self::Error>;
}

/// One owned operation in a yielded browser transaction.  Secret append bytes
/// are already protected by the transaction-owned storage custody layer before
/// they become durable; this request never becomes a proof artifact.
#[derive(PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryTransactionOperation {
    Create {
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    },
    Append {
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    },
    Seal {
        object: ProofExternalMemoryObject,
    },
    Read {
        object: ProofExternalMemoryObject,
        offset: u64,
        byte_length: u32,
    },
    Delete {
        object: ProofExternalMemoryObject,
    },
}

impl fmt::Debug for ProofExternalMemoryTransactionOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create {
                object,
                protection,
                exact_byte_length,
            } => formatter
                .debug_struct("Create")
                .field("object", object)
                .field("protection", protection)
                .field("exact_byte_length", exact_byte_length)
                .finish(),
            Self::Append {
                object,
                expected_offset,
                bytes,
            } => formatter
                .debug_struct("Append")
                .field("object", object)
                .field("expected_offset", expected_offset)
                .field("byte_length", &bytes.len())
                .field("bytes", &"[REDACTED]")
                .finish(),
            Self::Seal { object } => formatter
                .debug_struct("Seal")
                .field("object", object)
                .finish(),
            Self::Read {
                object,
                offset,
                byte_length,
            } => formatter
                .debug_struct("Read")
                .field("object", object)
                .field("offset", offset)
                .field("byte_length", byte_length)
                .finish(),
            Self::Delete { object } => formatter
                .debug_struct("Delete")
                .field("object", object)
                .finish(),
        }
    }
}

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
    ) -> Result<Vec<u8>, ProofExternalMemoryTransactionAdapterError> {
        let operation_bytes = self.encode_operation_bytes()?;
        let request_digest = self.request_digest(&operation_bytes)?;
        let byte_length = EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH
            .checked_add(operation_bytes.len())
            .ok_or(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded)?;
        let mut encoded = Vec::new();
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
    ) -> Result<Vec<Vec<u8>>, ProofExternalMemoryTransactionAdapterError> {
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
            let mut owned_bytes = Vec::new();
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

    fn encode_operation_bytes(
        &self,
    ) -> Result<Vec<u8>, ProofExternalMemoryTransactionAdapterError> {
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
        let mut encoded = Vec::new();
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
                        1_u16,
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
                        2_u16,
                        0_u16,
                        *object,
                        *expected_offset,
                        u64::try_from(bytes.len()).map_err(|_| {
                            ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded
                        })?,
                        bytes.as_slice(),
                    ),
                    ProofExternalMemoryTransactionOperation::Seal { object } => {
                        (3_u16, 0_u16, *object, 0_u64, 0_u64, &[][..])
                    }
                    ProofExternalMemoryTransactionOperation::Read {
                        object,
                        offset,
                        byte_length,
                    } => (
                        4_u16,
                        0_u16,
                        *object,
                        *offset,
                        u64::from(*byte_length),
                        &[][..],
                    ),
                    ProofExternalMemoryTransactionOperation::Delete { object } => {
                        (5_u16, 0_u16, *object, 0_u64, 0_u64, &[][..])
                    }
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

    fn request_digest(
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
        ProofExternalMemoryProtection::PublicIntegrity => 1,
        ProofExternalMemoryProtection::SecretAuthenticatedEncryption => 2,
    }
}

fn external_memory_read_digest(
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
        mut read_results: Vec<Vec<u8>>,
    ) -> Result<Self, ProofExternalMemoryTransactionAdapterError> {
        let mut protected_read_results = Vec::new();
        if protected_read_results
            .try_reserve_exact(read_results.len())
            .is_err()
        {
            for result in &mut read_results {
                result.fill(0);
            }
            return Err(ProofExternalMemoryTransactionAdapterError::AllocationLimitExceeded);
        }
        protected_read_results.extend(read_results.into_iter().map(Zeroizing::new));
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
        let mut supplied_results = protected_read_results.iter();
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
            read_results: protected_read_results,
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

/// Cancellation is owned by the participant-operation worker.  It is checked
/// between every bounded storage transaction and every arithmetic chunk.
pub(crate) trait ProofCancellation {
    fn cancellation_requested(&self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofExternalMemoryObjectState {
    Issued,
    Writing { written_byte_length: u64 },
    Sealed,
    Claimed,
    Consumed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryUsage {
    pub(crate) total_written_byte_length: u64,
    pub(crate) total_read_byte_length: u64,
    pub(crate) peak_stored_byte_length: u64,
    pub(crate) transaction_count: u64,
    pub(crate) deleted_object_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryError {
    InvalidPlan,
    UnknownObject,
    WrongStep,
    InvalidLifecycle,
    WrongOffsetOrLength,
    ResourceLimitExceeded,
    Cancelled,
    Incomplete,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProofExternalMemoryExecutorError<StorageError> {
    Execution(ProofExternalMemoryError),
    Storage(StorageError),
    StorageAbort {
        operation_error: StorageError,
        abort_error: StorageError,
    },
    StorageCommit(StorageError),
}

impl<StorageError> From<ProofExternalMemoryError>
    for ProofExternalMemoryExecutorError<StorageError>
{
    fn from(error: ProofExternalMemoryError) -> Self {
        Self::Execution(error)
    }
}

/// Stateful plan executor.  It mirrors only small lifecycle metadata; object
/// contents remain in the external store and reads use caller-owned bounded
/// buffers.
pub(crate) struct ProofExternalMemoryExecutor {
    plan: ProofExternalMemoryPlan,
    current_step: u32,
    states: BTreeMap<ProofExternalMemoryObject, ProofExternalMemoryObjectState>,
    current_stored_byte_length: u64,
    usage: ProofExternalMemoryUsage,
    terminal: bool,
}

impl ProofExternalMemoryExecutor {
    pub(crate) fn new(plan: ProofExternalMemoryPlan) -> Result<Self, ProofExternalMemoryError> {
        plan.validate()?;
        let states = plan
            .objects
            .iter()
            .map(|object| (object.object, ProofExternalMemoryObjectState::Issued))
            .collect();
        Ok(Self {
            plan,
            current_step: 0,
            states,
            current_stored_byte_length: 0,
            usage: ProofExternalMemoryUsage::default(),
            terminal: false,
        })
    }

    pub(crate) const fn current_step(&self) -> u32 {
        self.current_step
    }

    pub(crate) const fn maximum_chunk_byte_length(&self) -> u32 {
        self.plan.maximum_chunk_byte_length
    }

    pub(crate) const fn usage(&self) -> ProofExternalMemoryUsage {
        self.usage
    }

    pub(crate) fn begin_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        let object_plan = self.object_plan(object)?;
        if self.current_step != object_plan.issued_step
            || self.state(object)? != ProofExternalMemoryObjectState::Issued
        {
            return Err(ProofExternalMemoryError::WrongStep.into());
        }
        let next_stored_byte_length = self
            .current_stored_byte_length
            .checked_add(object_plan.exact_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if next_stored_byte_length > self.plan.maximum_stored_byte_length {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }

        self.run_mutating_transaction(storage, 0, |storage| {
            storage.create_object(
                object_plan.object,
                object_plan.protection,
                object_plan.exact_byte_length,
            )
        })?;
        self.states.insert(
            object,
            ProofExternalMemoryObjectState::Writing {
                written_byte_length: 0,
            },
        );
        self.current_stored_byte_length = next_stored_byte_length;
        self.usage.peak_stored_byte_length = self
            .usage
            .peak_stored_byte_length
            .max(self.current_stored_byte_length);
        Ok(())
    }

    pub(crate) fn append_object_bytes<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
        bytes: &[u8],
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        if bytes.is_empty()
            || bytes.len()
                > usize::try_from(self.plan.maximum_chunk_byte_length)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
        {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        let object_plan = self.object_plan(object)?;
        if self.current_step < object_plan.issued_step || self.current_step > object_plan.seal_step
        {
            return Err(ProofExternalMemoryError::WrongStep.into());
        }
        let ProofExternalMemoryObjectState::Writing {
            written_byte_length,
        } = self.state(object)?
        else {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        };
        let chunk_byte_length = u64::try_from(bytes.len())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let remaining_object_byte_length = object_plan
            .exact_byte_length
            .checked_sub(written_byte_length)
            .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
        let expected_chunk_byte_length =
            remaining_object_byte_length.min(u64::from(self.plan.maximum_chunk_byte_length));
        if chunk_byte_length != expected_chunk_byte_length {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        let next_object_byte_length = written_byte_length
            .checked_add(chunk_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let next_total_written = self
            .usage
            .total_written_byte_length
            .checked_add(chunk_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if next_object_byte_length > object_plan.exact_byte_length
            || next_total_written > self.plan.maximum_total_written_byte_length
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }

        self.run_mutating_transaction(storage, chunk_byte_length, |storage| {
            storage.append_object_bytes(object, written_byte_length, bytes)
        })?;
        self.states.insert(
            object,
            ProofExternalMemoryObjectState::Writing {
                written_byte_length: next_object_byte_length,
            },
        );
        self.usage.total_written_byte_length = next_total_written;
        Ok(())
    }

    pub(crate) fn seal_object<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        let object_plan = self.object_plan(object)?;
        if self.current_step > object_plan.seal_step
            || self.state(object)?
                != (ProofExternalMemoryObjectState::Writing {
                    written_byte_length: object_plan.exact_byte_length,
                })
        {
            return Err(ProofExternalMemoryError::Incomplete.into());
        }
        self.run_mutating_transaction(storage, 0, |storage| storage.seal_object(object))?;
        self.states
            .insert(object, ProofExternalMemoryObjectState::Sealed);
        Ok(())
    }

    pub(crate) fn read_object_bytes<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        if destination.is_empty()
            || destination.len()
                > usize::try_from(self.plan.maximum_chunk_byte_length)
                    .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?
        {
            return Err(ProofExternalMemoryError::WrongOffsetOrLength.into());
        }
        let object_plan = self.object_plan(object)?;
        if self.current_step < object_plan.seal_step
            || self.current_step > object_plan.last_use_step
            || !matches!(
                self.state(object)?,
                ProofExternalMemoryObjectState::Sealed | ProofExternalMemoryObjectState::Claimed
            )
        {
            return Err(ProofExternalMemoryError::InvalidLifecycle.into());
        }
        let destination_byte_length = u64::try_from(destination.len())
            .map_err(|_| ProofExternalMemoryError::ResourceLimitExceeded)?;
        let end = offset
            .checked_add(destination_byte_length)
            .ok_or(ProofExternalMemoryError::WrongOffsetOrLength)?;
        let next_total_read = self
            .usage
            .total_read_byte_length
            .checked_add(destination_byte_length)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if end > object_plan.exact_byte_length
            || next_total_read > self.plan.maximum_total_read_byte_length
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }

        self.begin_transaction(storage)?;
        if let Err(operation_error) = storage.read_object_bytes(object, offset, destination) {
            return Err(abort_after_storage_error(storage, operation_error));
        }
        if let Err(error) = storage.commit_transaction() {
            return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
        }
        self.record_transaction()?;
        self.states
            .insert(object, ProofExternalMemoryObjectState::Claimed);
        self.usage.total_read_byte_length = next_total_read;
        Ok(())
    }

    /// Completes the current liveness step, deleting every object whose exact
    /// last use is this step in one transaction.  A seal deadline cannot be
    /// crossed with an incomplete object.
    pub(crate) fn complete_step<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        self.require_active()?;
        for object_plan in &self.plan.objects {
            if object_plan.seal_step == self.current_step
                && matches!(
                    self.state(object_plan.object)?,
                    ProofExternalMemoryObjectState::Issued
                        | ProofExternalMemoryObjectState::Writing { .. }
                )
            {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
        }

        let due_for_deletion = self
            .plan
            .objects
            .iter()
            .filter(|object| object.last_use_step == self.current_step)
            .copied()
            .collect::<Vec<_>>();
        for object in &due_for_deletion {
            if !matches!(
                self.state(object.object)?,
                ProofExternalMemoryObjectState::Sealed | ProofExternalMemoryObjectState::Claimed
            ) {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
        }

        if !due_for_deletion.is_empty() {
            self.begin_transaction(storage)?;
            for object in &due_for_deletion {
                if let Err(operation_error) = storage.delete_object(object.object) {
                    return Err(abort_after_storage_error(storage, operation_error));
                }
            }
            if let Err(error) = storage.commit_transaction() {
                return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
            }
            self.record_transaction()?;
            for object in &due_for_deletion {
                self.states
                    .insert(object.object, ProofExternalMemoryObjectState::Consumed);
                self.current_stored_byte_length = self
                    .current_stored_byte_length
                    .checked_sub(object.exact_byte_length)
                    .ok_or(ProofExternalMemoryError::InvalidLifecycle)?;
                self.usage.deleted_object_count = self
                    .usage
                    .deleted_object_count
                    .checked_add(1)
                    .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
            }
        }

        self.current_step = self
            .current_step
            .checked_add(1)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if self.current_step == self.plan.step_count {
            if self.current_stored_byte_length != 0
                || self
                    .states
                    .values()
                    .any(|state| *state != ProofExternalMemoryObjectState::Consumed)
            {
                return Err(ProofExternalMemoryError::Incomplete.into());
            }
            self.terminal = true;
        }
        Ok(())
    }

    pub(crate) fn check_cancellation<Storage, Cancellation>(
        &mut self,
        storage: &mut Storage,
        cancellation: &Cancellation,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>>
    where
        Storage: ProofExternalMemory,
        Cancellation: ProofCancellation,
    {
        if !cancellation.cancellation_requested() {
            return Ok(());
        }
        self.cancel(storage)?;
        Err(ProofExternalMemoryError::Cancelled.into())
    }

    /// Idempotently makes every live object unreachable.  The backend's
    /// best-effort physical deletion happens behind the committed transaction.
    pub(crate) fn cancel<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.terminal {
            return Ok(());
        }
        let live_objects = self
            .states
            .iter()
            .filter_map(|(object, state)| {
                matches!(
                    state,
                    ProofExternalMemoryObjectState::Writing { .. }
                        | ProofExternalMemoryObjectState::Sealed
                        | ProofExternalMemoryObjectState::Claimed
                )
                .then_some(*object)
            })
            .collect::<Vec<_>>();
        if !live_objects.is_empty() {
            self.begin_transaction(storage)?;
            for object in &live_objects {
                if let Err(operation_error) = storage.delete_object(*object) {
                    return Err(abort_after_storage_error(storage, operation_error));
                }
            }
            if let Err(error) = storage.commit_transaction() {
                return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
            }
            self.record_transaction()?;
        }
        for state in self.states.values_mut() {
            if *state != ProofExternalMemoryObjectState::Consumed {
                *state = ProofExternalMemoryObjectState::Cancelled;
            }
        }
        self.current_stored_byte_length = 0;
        self.terminal = true;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<ProofExternalMemoryUsage, ProofExternalMemoryError> {
        if !self.terminal
            || self.current_step != self.plan.step_count
            || self.current_stored_byte_length != 0
        {
            return Err(ProofExternalMemoryError::Incomplete);
        }
        Ok(self.usage)
    }

    fn object_plan(
        &self,
        object: ProofExternalMemoryObject,
    ) -> Result<ProofExternalMemoryObjectPlan, ProofExternalMemoryError> {
        self.plan
            .objects
            .iter()
            .find(|entry| entry.object == object)
            .copied()
            .ok_or(ProofExternalMemoryError::UnknownObject)
    }

    fn state(
        &self,
        object: ProofExternalMemoryObject,
    ) -> Result<ProofExternalMemoryObjectState, ProofExternalMemoryError> {
        self.states
            .get(&object)
            .copied()
            .ok_or(ProofExternalMemoryError::UnknownObject)
    }

    fn require_active(&self) -> Result<(), ProofExternalMemoryError> {
        if self.terminal || self.current_step >= self.plan.step_count {
            return Err(ProofExternalMemoryError::InvalidLifecycle);
        }
        Ok(())
    }

    fn begin_transaction<Storage: ProofExternalMemory>(
        &mut self,
        storage: &mut Storage,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>> {
        if self.usage.transaction_count >= self.plan.maximum_transaction_count {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }
        storage
            .begin_transaction(
                self.plan.maximum_transaction_payload_byte_length,
                self.plan.maximum_transaction_operation_count,
            )
            .map_err(ProofExternalMemoryExecutorError::Storage)
    }

    fn record_transaction(&mut self) -> Result<(), ProofExternalMemoryError> {
        self.usage.transaction_count = self
            .usage
            .transaction_count
            .checked_add(1)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        if self.usage.transaction_count > self.plan.maximum_transaction_count {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn run_mutating_transaction<Storage, Operation>(
        &mut self,
        storage: &mut Storage,
        payload_byte_length: u64,
        operation: Operation,
    ) -> Result<(), ProofExternalMemoryExecutorError<Storage::Error>>
    where
        Storage: ProofExternalMemory,
        Operation: FnOnce(&mut Storage) -> Result<(), Storage::Error>,
    {
        if payload_byte_length > self.plan.maximum_transaction_payload_byte_length {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded.into());
        }
        self.begin_transaction(storage)?;
        if let Err(operation_error) = operation(storage) {
            return Err(abort_after_storage_error(storage, operation_error));
        }
        if let Err(error) = storage.commit_transaction() {
            return Err(ProofExternalMemoryExecutorError::StorageCommit(error));
        }
        self.record_transaction()?;
        Ok(())
    }
}

fn abort_after_storage_error<Storage: ProofExternalMemory>(
    storage: &mut Storage,
    operation_error: Storage::Error,
) -> ProofExternalMemoryExecutorError<Storage::Error> {
    match storage.abort_transaction() {
        Ok(()) => ProofExternalMemoryExecutorError::Storage(operation_error),
        Err(abort_error) => ProofExternalMemoryExecutorError::StorageAbort {
            operation_error,
            abort_error,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestStorageError {
        NoTransaction,
        Duplicate,
        Missing,
        WrongLength,
    }

    #[derive(Clone)]
    struct TestObject {
        bytes: Vec<u8>,
        exact_byte_length: usize,
        sealed: bool,
        protection: ProofExternalMemoryProtection,
    }

    #[derive(Default)]
    struct TestStorage {
        committed: BTreeMap<ProofExternalMemoryObject, TestObject>,
        transaction: Option<BTreeMap<ProofExternalMemoryObject, TestObject>>,
    }

    impl ProofExternalMemory for TestStorage {
        type Error = TestStorageError;

        fn begin_transaction(&mut self, _: u64, _: u32) -> Result<(), Self::Error> {
            if self.transaction.is_some() {
                return Err(TestStorageError::Duplicate);
            }
            self.transaction = Some(self.committed.clone());
            Ok(())
        }

        fn create_object(
            &mut self,
            object: ProofExternalMemoryObject,
            protection: ProofExternalMemoryProtection,
            exact_byte_length: u64,
        ) -> Result<(), Self::Error> {
            let transaction = self
                .transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?;
            if transaction.contains_key(&object) {
                return Err(TestStorageError::Duplicate);
            }
            transaction.insert(
                object,
                TestObject {
                    bytes: Vec::new(),
                    exact_byte_length: usize::try_from(exact_byte_length)
                        .map_err(|_| TestStorageError::WrongLength)?,
                    sealed: false,
                    protection,
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
            let object = self
                .transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?
                .get_mut(&object)
                .ok_or(TestStorageError::Missing)?;
            if object.sealed
                || usize::try_from(expected_offset).ok() != Some(object.bytes.len())
                || object.bytes.len() + bytes.len() > object.exact_byte_length
            {
                return Err(TestStorageError::WrongLength);
            }
            object.bytes.extend_from_slice(bytes);
            Ok(())
        }

        fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            let object = self
                .transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?
                .get_mut(&object)
                .ok_or(TestStorageError::Missing)?;
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
            let object = self
                .transaction
                .as_ref()
                .ok_or(TestStorageError::NoTransaction)?
                .get(&object)
                .ok_or(TestStorageError::Missing)?;
            let offset = usize::try_from(offset).map_err(|_| TestStorageError::WrongLength)?;
            let source = object
                .bytes
                .get(offset..offset + destination.len())
                .ok_or(TestStorageError::WrongLength)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
            self.transaction
                .as_mut()
                .ok_or(TestStorageError::NoTransaction)?
                .remove(&object)
                .ok_or(TestStorageError::Missing)?;
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

    fn plan() -> ProofExternalMemoryPlan {
        ProofExternalMemoryPlan::new(
            3,
            4,
            4,
            2,
            12,
            16,
            24,
            32,
            vec![
                ProofExternalMemoryObjectPlan::new(
                    ProofExternalMemoryObject::new(0),
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    8,
                    0,
                    0,
                    2,
                ),
                ProofExternalMemoryObjectPlan::new(
                    ProofExternalMemoryObject::new(1),
                    ProofExternalMemoryProtection::PublicIntegrity,
                    4,
                    1,
                    1,
                    1,
                ),
            ],
        )
        .expect("valid external-memory plan")
    }

    fn single_object_write_plan(
        maximum_chunk_byte_length: u32,
        exact_byte_length: u64,
    ) -> ProofExternalMemoryPlan {
        let maximum_transaction_count = exact_byte_length
            .div_ceil(u64::from(maximum_chunk_byte_length))
            .checked_add(3)
            .expect("the test transaction ceiling fits u64");
        ProofExternalMemoryPlan::new(
            1,
            maximum_chunk_byte_length,
            u64::from(maximum_chunk_byte_length),
            1,
            exact_byte_length,
            exact_byte_length,
            1,
            maximum_transaction_count,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                exact_byte_length,
                0,
                0,
                0,
            )],
        )
        .expect("the single-object write plan is valid")
    }

    #[test]
    fn executor_enforces_chunked_writes_random_reads_and_exact_last_use() {
        let first = ProofExternalMemoryObject::new(0);
        let second = ProofExternalMemoryObject::new(1);
        let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
        let mut storage = TestStorage::default();

        executor
            .begin_object(&mut storage, first)
            .expect("first starts");
        executor
            .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
            .expect("first chunk writes");
        executor
            .append_object_bytes(&mut storage, first, &[5, 6, 7, 8])
            .expect("second chunk writes");
        executor
            .seal_object(&mut storage, first)
            .expect("first seals");
        executor
            .complete_step(&mut storage)
            .expect("step zero completes");

        executor
            .begin_object(&mut storage, second)
            .expect("second starts");
        executor
            .append_object_bytes(&mut storage, second, &[9, 10, 11, 12])
            .expect("second writes");
        executor
            .seal_object(&mut storage, second)
            .expect("second seals");
        let mut suffix = [0_u8; 3];
        executor
            .read_object_bytes(&mut storage, first, 5, &mut suffix)
            .expect("random suffix read");
        assert_eq!(suffix, [6, 7, 8]);
        executor
            .complete_step(&mut storage)
            .expect("second is deleted");
        assert!(!storage.committed.contains_key(&second));
        assert_eq!(
            storage.committed.get(&first).map(|entry| entry.protection),
            Some(ProofExternalMemoryProtection::SecretAuthenticatedEncryption),
        );

        let mut prefix = [0_u8; 2];
        executor
            .read_object_bytes(&mut storage, first, 0, &mut prefix)
            .expect("first remains through last use");
        assert_eq!(prefix, [1, 2]);
        executor
            .complete_step(&mut storage)
            .expect("final deletion commits");
        let usage = executor.finish().expect("executor finishes");
        assert_eq!(usage.total_written_byte_length, 12);
        assert_eq!(usage.total_read_byte_length, 5);
        assert_eq!(usage.peak_stored_byte_length, 12);
        assert_eq!(usage.deleted_object_count, 2);
        assert!(storage.committed.is_empty());
    }

    #[test]
    fn executor_accepts_only_full_intermediate_chunks_and_the_exact_declared_tail() {
        let object = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 10))
            .expect("the exact-chunk executor starts");
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, object)
            .expect("the object begins");

        executor
            .append_object_bytes(&mut storage, object, &[1, 2, 3, 4])
            .expect("the first full intermediate chunk appends");
        executor
            .append_object_bytes(&mut storage, object, &[5, 6, 7, 8])
            .expect("the second full intermediate chunk appends");
        executor
            .append_object_bytes(&mut storage, object, &[9, 10])
            .expect("the exact declared tail appends");
        executor
            .seal_object(&mut storage, object)
            .expect("the canonically chunked object seals");

        assert_eq!(
            storage
                .committed
                .get(&object)
                .map(|entry| entry.bytes.as_slice()),
            Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10][..]),
        );
    }

    #[test]
    fn executor_rejects_zero_short_and_oversized_appends_without_advancing() {
        let object = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 6))
            .expect("the hostile-shape executor starts");
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, object)
            .expect("the object begins");
        let transaction_count_after_create = executor.usage().transaction_count;

        for rejected_bytes in [&[][..], &[1, 2, 3][..], &[1, 2, 3, 4, 5][..]] {
            assert_eq!(
                executor.append_object_bytes(&mut storage, object, rejected_bytes),
                Err(ProofExternalMemoryExecutorError::Execution(
                    ProofExternalMemoryError::WrongOffsetOrLength,
                )),
            );
            assert_eq!(
                storage
                    .committed
                    .get(&object)
                    .map(|entry| entry.bytes.len()),
                Some(0),
            );
            assert_eq!(
                executor.usage().transaction_count,
                transaction_count_after_create,
            );
        }

        executor
            .append_object_bytes(&mut storage, object, &[1, 2, 3, 4])
            .expect("the exact intermediate chunk still appends after refusals");
        let transaction_count_after_intermediate_chunk = executor.usage().transaction_count;
        assert_eq!(
            executor.append_object_bytes(&mut storage, object, &[5]),
            Err(ProofExternalMemoryExecutorError::Execution(
                ProofExternalMemoryError::WrongOffsetOrLength,
            )),
            "a one-byte-short tail is rejected",
        );
        assert_eq!(
            storage
                .committed
                .get(&object)
                .map(|entry| entry.bytes.as_slice()),
            Some(&[1, 2, 3, 4][..]),
        );
        assert_eq!(
            executor.usage().transaction_count,
            transaction_count_after_intermediate_chunk,
        );
        executor
            .append_object_bytes(&mut storage, object, &[5, 6])
            .expect("the exact tail still appends after refusal");
    }

    #[test]
    fn executor_accepts_a_short_object_as_one_exact_chunk() {
        let object = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(single_object_write_plan(4, 3))
            .expect("the one-chunk executor starts");
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, object)
            .expect("the short object begins");
        assert_eq!(
            executor.append_object_bytes(&mut storage, object, &[1, 2]),
            Err(ProofExternalMemoryExecutorError::Execution(
                ProofExternalMemoryError::WrongOffsetOrLength,
            )),
            "a one-byte-short one-chunk object is rejected",
        );
        executor
            .append_object_bytes(&mut storage, object, &[1, 2, 3])
            .expect("the complete one-chunk object appends");
        executor
            .seal_object(&mut storage, object)
            .expect("the complete one-chunk object seals");
    }

    #[test]
    fn plan_and_executor_reject_overrun_incomplete_seal_and_late_use() {
        assert_eq!(
            ProofExternalMemoryPlan::new(
                1,
                8,
                4,
                1,
                8,
                8,
                8,
                8,
                vec![ProofExternalMemoryObjectPlan::new(
                    ProofExternalMemoryObject::new(0),
                    ProofExternalMemoryProtection::PublicIntegrity,
                    8,
                    0,
                    0,
                    0,
                )],
            ),
            Err(ProofExternalMemoryError::InvalidPlan),
        );

        let first = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, first)
            .expect("first starts");
        executor
            .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
            .expect("partial write succeeds");
        assert!(matches!(
            executor.complete_step(&mut storage),
            Err(ProofExternalMemoryExecutorError::Execution(
                ProofExternalMemoryError::Incomplete
            )),
        ));
        assert!(matches!(
            executor.append_object_bytes(&mut storage, first, &[0; 5]),
            Err(ProofExternalMemoryExecutorError::Execution(
                ProofExternalMemoryError::WrongOffsetOrLength
            )),
        ));
    }

    #[test]
    fn plan_validation_work_is_bounded_by_object_count_not_step_count() {
        let plan = ProofExternalMemoryPlan::new(
            u32::MAX,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            vec![ProofExternalMemoryObjectPlan::new(
                ProofExternalMemoryObject::new(0),
                ProofExternalMemoryProtection::PublicIntegrity,
                1,
                0,
                0,
                u32::MAX - 1,
            )],
        )
        .expect("large step identifiers do not expand validation work");
        assert_eq!(plan.step_count(), u32::MAX);
    }

    #[test]
    fn browser_scratch_plan_accepts_exact_object_and_byte_ceilings_and_refuses_one_over() {
        assert_eq!(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT, 4_096);
        assert_eq!(
            MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
            268_435_456
        );
        let exact_object_count = u32::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
            .expect("the fixed object ceiling fits u32");
        let exact_object_plan = (0..exact_object_count)
            .map(|object_ordinal| {
                ProofExternalMemoryObjectPlan::new(
                    ProofExternalMemoryObject::new(object_ordinal),
                    ProofExternalMemoryProtection::PublicIntegrity,
                    1,
                    0,
                    0,
                    0,
                )
            })
            .collect::<Vec<_>>();
        ProofExternalMemoryPlan::new(
            1,
            1,
            1,
            exact_object_count,
            u64::from(exact_object_count),
            u64::from(exact_object_count),
            1,
            1,
            exact_object_plan,
        )
        .expect("the exact browser object ceiling is accepted");

        let one_over_object_count = exact_object_count + 1;
        let one_over_object_plan = (0..one_over_object_count)
            .map(|object_ordinal| {
                ProofExternalMemoryObjectPlan::new(
                    ProofExternalMemoryObject::new(object_ordinal),
                    ProofExternalMemoryProtection::PublicIntegrity,
                    1,
                    0,
                    0,
                    0,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ProofExternalMemoryPlan::new(
                1,
                1,
                1,
                one_over_object_count,
                u64::from(one_over_object_count),
                u64::from(one_over_object_count),
                1,
                1,
                one_over_object_plan,
            ),
            Err(ProofExternalMemoryError::ResourceLimitExceeded),
        );

        assert_eq!(
            ProofExternalMemoryPlan::new(
                1,
                1,
                1,
                one_over_object_count,
                1,
                1,
                1,
                1,
                vec![ProofExternalMemoryObjectPlan::new(
                    ProofExternalMemoryObject::new(0),
                    ProofExternalMemoryProtection::PublicIntegrity,
                    1,
                    0,
                    0,
                    0,
                )],
            ),
            Err(ProofExternalMemoryError::ResourceLimitExceeded),
            "a caller cannot raise the per-transaction operation ceiling",
        );

        let plan_at_byte_ceiling = |stored_byte_length| {
            ProofExternalMemoryPlan::new(
                1,
                1,
                1,
                1,
                stored_byte_length,
                stored_byte_length,
                1,
                1,
                vec![ProofExternalMemoryObjectPlan::new(
                    ProofExternalMemoryObject::new(0),
                    ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                    stored_byte_length,
                    0,
                    0,
                    0,
                )],
            )
        };
        plan_at_byte_ceiling(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH)
            .expect("the exact browser scratch-byte ceiling is accepted");
        assert_eq!(
            plan_at_byte_ceiling(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH + 1),
            Err(ProofExternalMemoryError::ResourceLimitExceeded),
        );
    }

    #[test]
    fn browser_transaction_yield_and_exact_replay_change_state_only_after_replay() {
        let first = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
        let mut recorder = ProofExternalMemoryTransactionRecorder::new();

        assert_eq!(
            executor.begin_object(&mut recorder, first),
            Err(ProofExternalMemoryExecutorError::StorageCommit(
                ProofExternalMemoryTransactionAdapterError::Yielded,
            ))
        );
        assert_eq!(executor.usage().transaction_count, 0);
        let request = recorder
            .take_yielded_request()
            .expect("create transaction yielded");
        assert_eq!(
            request.operations(),
            &[ProofExternalMemoryTransactionOperation::Create {
                object: first,
                protection: ProofExternalMemoryProtection::SecretAuthenticatedEncryption,
                exact_byte_length: 8,
            }]
        );
        let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
            .expect("create response has no reads");
        executor
            .begin_object(&mut replay, first)
            .expect("successful IndexedDB create replays");
        assert_eq!(executor.usage().transaction_count, 1);

        assert_eq!(
            executor.append_object_bytes(&mut recorder, first, &[1, 2, 3, 4]),
            Err(ProofExternalMemoryExecutorError::StorageCommit(
                ProofExternalMemoryTransactionAdapterError::Yielded,
            ))
        );
        let request = recorder
            .take_yielded_request()
            .expect("append transaction yielded");
        let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
            .expect("append response has no reads");
        executor
            .append_object_bytes(&mut replay, first, &[1, 2, 3, 4])
            .expect("successful IndexedDB append replays");

        assert_eq!(
            executor.append_object_bytes(&mut recorder, first, &[5, 6, 7, 8]),
            Err(ProofExternalMemoryExecutorError::StorageCommit(
                ProofExternalMemoryTransactionAdapterError::Yielded,
            ))
        );
        let request = recorder
            .take_yielded_request()
            .expect("second append transaction yielded");
        let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
            .expect("second append response has no reads");
        executor
            .append_object_bytes(&mut replay, first, &[5, 6, 7, 8])
            .expect("successful second IndexedDB append replays");

        assert_eq!(
            executor.seal_object(&mut recorder, first),
            Err(ProofExternalMemoryExecutorError::StorageCommit(
                ProofExternalMemoryTransactionAdapterError::Yielded,
            ))
        );
        let request = recorder
            .take_yielded_request()
            .expect("seal transaction yielded");
        let mut replay = ProofExternalMemoryTransactionReplay::new(request, Vec::new())
            .expect("seal response has no reads");
        executor
            .seal_object(&mut replay, first)
            .expect("successful IndexedDB seal replays");
        executor
            .complete_step(&mut recorder)
            .expect("first liveness step has no deletion");

        let mut destination = [0_u8; 4];
        assert_eq!(
            executor.read_object_bytes(&mut recorder, first, 0, &mut destination),
            Err(ProofExternalMemoryExecutorError::StorageCommit(
                ProofExternalMemoryTransactionAdapterError::Yielded,
            ))
        );
        assert_eq!(destination, [0; 4]);
        let request = recorder
            .take_yielded_request()
            .expect("read transaction yielded");
        let mut replay = ProofExternalMemoryTransactionReplay::new(request, vec![vec![1, 2, 3, 4]])
            .expect("read response has the exact requested length");
        executor
            .read_object_bytes(&mut replay, first, 0, &mut destination)
            .expect("successful IndexedDB read replays");
        assert_eq!(destination, [1, 2, 3, 4]);
    }

    fn record_worker_response_test_request(
        recorder: &mut ProofExternalMemoryTransactionRecorder,
    ) -> ProofExternalMemoryTransactionRequest {
        let append_object = ProofExternalMemoryObject::new(2);
        let first_read_object = ProofExternalMemoryObject::new(7);
        let second_read_object = ProofExternalMemoryObject::new(9);
        recorder
            .begin_transaction(64, 4)
            .expect("worker response transaction starts");
        recorder
            .append_object_bytes(append_object, 0, &[9, 8, 7])
            .expect("worker response append records");
        let mut first_read = [0_u8; 4];
        recorder
            .read_object_bytes(first_read_object, 3, &mut first_read)
            .expect("first worker response read records");
        recorder
            .seal_object(append_object)
            .expect("worker response seal records");
        let mut second_read = [0_u8; 3];
        recorder
            .read_object_bytes(second_read_object, 11, &mut second_read)
            .expect("second worker response read records");
        assert_eq!(
            recorder.commit_transaction(),
            Err(ProofExternalMemoryTransactionAdapterError::Yielded),
        );
        recorder
            .take_yielded_request()
            .expect("worker response request yielded")
    }

    fn encode_worker_test_response(
        request: &ProofExternalMemoryTransactionRequest,
        ordered_results: &[(u32, ProofExternalMemoryObject, u64, &[u8])],
    ) -> Vec<u8> {
        let operation_bytes = request
            .encode_operation_bytes()
            .expect("test request operations encode");
        let request_digest = request
            .request_digest(&operation_bytes)
            .expect("test request digest derives");
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION.to_le_bytes());
        encoded.extend_from_slice(&EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND.to_le_bytes());
        encoded.extend_from_slice(&request.request_sequence().to_le_bytes());
        encoded.extend_from_slice(&request_digest);
        encoded.extend_from_slice(
            &u32::try_from(ordered_results.len())
                .expect("test response result count fits u32")
                .to_le_bytes(),
        );
        for (operation_index, object, offset, bytes) in ordered_results {
            encoded.extend_from_slice(&operation_index.to_le_bytes());
            encoded.extend_from_slice(&object.ordinal().to_le_bytes());
            encoded.extend_from_slice(&offset.to_le_bytes());
            encoded.extend_from_slice(
                &u32::try_from(bytes.len())
                    .expect("test response byte length fits u32")
                    .to_le_bytes(),
            );
            encoded.extend_from_slice(&0_u32.to_le_bytes());
            encoded.extend_from_slice(&external_memory_read_digest(
                &request_digest,
                *operation_index,
                *object,
                *offset,
                bytes,
            ));
            encoded.extend_from_slice(bytes);
        }
        encoded
    }

    #[test]
    fn worker_response_decoder_binds_sequence_operation_object_range_and_digest() {
        let mut recorder =
            ProofExternalMemoryTransactionRecorder::for_runtime_binding([0x41; 64], 7);
        let request = record_worker_response_test_request(&mut recorder);
        let first_read_object = ProofExternalMemoryObject::new(7);
        let second_read_object = ProofExternalMemoryObject::new(9);
        let ordered_results = [
            (1, first_read_object, 3, &[1, 2, 3, 4][..]),
            (3, second_read_object, 11, &[5, 6, 7][..]),
        ];
        let valid_response = encode_worker_test_response(&request, &ordered_results);
        assert_eq!(
            request
                .decode_worker_response(&valid_response)
                .expect("exact worker response decodes"),
            vec![vec![1, 2, 3, 4], vec![5, 6, 7]],
        );

        let mut wrong_sequence = valid_response.clone();
        wrong_sequence[4] ^= 1;
        assert_eq!(
            request.decode_worker_response(&wrong_sequence),
            Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
        );

        let mut wrong_request_digest = valid_response.clone();
        wrong_request_digest[12] ^= 1;
        assert_eq!(
            request.decode_worker_response(&wrong_request_digest),
            Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
        );

        let first_result_offset = EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH;
        let mut wrong_operation_ordinal = valid_response.clone();
        wrong_operation_ordinal[first_result_offset] ^= 1;
        assert_eq!(
            request.decode_worker_response(&wrong_operation_ordinal),
            Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
        );

        let mut wrong_object = valid_response.clone();
        wrong_object[first_result_offset + 4] ^= 1;
        assert_eq!(
            request.decode_worker_response(&wrong_object),
            Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
        );

        let mut wrong_range = valid_response.clone();
        wrong_range[first_result_offset + 8] ^= 1;
        assert_eq!(
            request.decode_worker_response(&wrong_range),
            Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
        );

        let mut wrong_read_digest = valid_response.clone();
        wrong_read_digest[first_result_offset + 24] ^= 1;
        assert_eq!(
            request.decode_worker_response(&wrong_read_digest),
            Err(ProofExternalMemoryTransactionAdapterError::WrongReadDigest),
        );

        let reordered_response = encode_worker_test_response(
            &request,
            &[
                (3, second_read_object, 11, &[5, 6, 7]),
                (1, first_read_object, 3, &[1, 2, 3, 4]),
            ],
        );
        assert_eq!(
            request.decode_worker_response(&reordered_response),
            Err(ProofExternalMemoryTransactionAdapterError::WrongOperationBinding),
        );

        let next_request = record_worker_response_test_request(&mut recorder);
        assert_eq!(next_request.request_sequence(), 8);
        assert_eq!(
            next_request.decode_worker_response(&valid_response),
            Err(ProofExternalMemoryTransactionAdapterError::WrongRequestDigest),
        );
    }

    #[test]
    fn browser_transaction_boundary_enforces_both_resource_ceilings_and_redacts_payloads() {
        let object = ProofExternalMemoryObject::new(7);
        let mut recorder = ProofExternalMemoryTransactionRecorder::new();
        recorder
            .begin_transaction(4, 1)
            .expect("bounded transaction starts");
        recorder
            .append_object_bytes(object, 0, &[0x11, 0x22, 0x33, 0x44])
            .expect("payload at the exact ceiling is accepted");
        assert_eq!(
            recorder.seal_object(object),
            Err(ProofExternalMemoryTransactionAdapterError::OperationCountExceeded),
        );
        recorder
            .abort_transaction()
            .expect("rejected transaction aborts");

        recorder
            .begin_transaction(3, 2)
            .expect("second bounded transaction starts");
        assert_eq!(
            recorder.append_object_bytes(object, 0, &[0x11, 0x22, 0x33, 0x44]),
            Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded),
        );
        recorder
            .abort_transaction()
            .expect("overlong payload transaction aborts");

        recorder
            .begin_transaction(3, 1)
            .expect("bounded read transaction starts");
        let mut oversized_read = [0xff; 4];
        assert_eq!(
            recorder.read_object_bytes(object, 0, &mut oversized_read),
            Err(ProofExternalMemoryTransactionAdapterError::PayloadByteLengthExceeded),
        );
        assert_eq!(oversized_read, [0; 4]);
        recorder
            .abort_transaction()
            .expect("overlong read transaction aborts");

        let operation = ProofExternalMemoryTransactionOperation::Append {
            object,
            expected_offset: 0,
            bytes: Zeroizing::new(vec![0xde, 0xad, 0xbe, 0xef]),
        };
        let debug_output = format!("{operation:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(debug_output.contains("byte_length: 4"));
    }

    struct RequestedCancellation;

    impl ProofCancellation for RequestedCancellation {
        fn cancellation_requested(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_transactionally_removes_secret_scratch() {
        let first = ProofExternalMemoryObject::new(0);
        let mut executor = ProofExternalMemoryExecutor::new(plan()).expect("valid plan starts");
        let mut storage = TestStorage::default();
        executor
            .begin_object(&mut storage, first)
            .expect("first starts");
        executor
            .append_object_bytes(&mut storage, first, &[1, 2, 3, 4])
            .expect("partial secret scratch writes");
        assert!(matches!(
            executor.check_cancellation(&mut storage, &RequestedCancellation),
            Err(ProofExternalMemoryExecutorError::Execution(
                ProofExternalMemoryError::Cancelled
            )),
        ));
        assert!(storage.committed.is_empty());
    }
}
