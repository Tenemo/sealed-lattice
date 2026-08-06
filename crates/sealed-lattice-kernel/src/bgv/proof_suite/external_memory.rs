//! Bounded external-memory execution for browser proof generation.
//!
//! The storage implementation is deliberately abstract.  Native callers may
//! implement it directly.  A browser uses the recorder/replay adapter below:
//! the first kernel call yields one bounded owned transaction request, the
//! worker awaits its transaction-owned IndexedDB runtime, and the next kernel
//! call replays the exact request with the returned read bytes.  Executor state
//! changes only after that successful replay.  No filesystem, thread, blocking
//! JavaScript callback, or whole proof in memory is required.

#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
use zeroize::Zeroizing;

use super::MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH;

const EXTERNAL_MEMORY_REQUEST_SCHEMA_VERSION: u16 = 1;
const EXTERNAL_MEMORY_REQUEST_MESSAGE_KIND: u16 = 1;
const EXTERNAL_MEMORY_RESPONSE_MESSAGE_KIND: u16 = 2;
const EXTERNAL_MEMORY_REQUEST_DIGEST_DOMAIN: &str =
    "sealed-lattice/common-proof/external-memory-request/v1";
const EXTERNAL_MEMORY_READ_DIGEST_DOMAIN: &str =
    "sealed-lattice/common-proof/external-memory-read/v1";
pub(crate) const EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH: usize = 156;
const EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH: usize = 80;
pub(crate) const EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH: usize = 32;
const EXTERNAL_MEMORY_READ_RESULT_HEADER_BYTE_LENGTH: usize = 88;
const HASH_BYTE_LENGTH: usize = 64;

pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_APPEND_REQUEST_BYTE_LENGTH: u64 =
    EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH as u64
        + EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH as u64
        + MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as u64;
pub(crate) const COMMON_PROOF_EXTERNAL_MEMORY_EMPTY_RESPONSE_BYTE_LENGTH: u64 =
    EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH as u64;
pub(crate) const COMMON_PROOF_EXTERNAL_MEMORY_READ_REQUEST_BYTE_LENGTH: u64 =
    EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH as u64
        + EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH as u64;
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_READ_RESPONSE_BYTE_LENGTH: u64 =
    EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH as u64
        + EXTERNAL_MEMORY_READ_RESULT_HEADER_BYTE_LENGTH as u64
        + MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH as u64;
#[cfg(test)]
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_COPIED_BUFFER_BYTE_LENGTH: u64 =
    if MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_APPEND_REQUEST_BYTE_LENGTH
        > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_READ_RESPONSE_BYTE_LENGTH
    {
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_APPEND_REQUEST_BYTE_LENGTH
    } else {
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_READ_RESPONSE_BYTE_LENGTH
    };
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH: u64 = {
    let append_transfer_live_byte_length =
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_APPEND_REQUEST_BYTE_LENGTH
            + COMMON_PROOF_EXTERNAL_MEMORY_EMPTY_RESPONSE_BYTE_LENGTH;
    let read_transfer_live_byte_length = COMMON_PROOF_EXTERNAL_MEMORY_READ_REQUEST_BYTE_LENGTH
        + MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_READ_RESPONSE_BYTE_LENGTH;
    if append_transfer_live_byte_length > read_transfer_live_byte_length {
        append_transfer_live_byte_length
    } else {
        read_transfer_live_byte_length
    }
};

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofExternalMemoryBoundaryGeometry {
    append_request_byte_length: u64,
    empty_response_byte_length: u64,
    read_request_byte_length: u64,
    read_response_byte_length: u64,
}

#[cfg(any(test, feature = "primitive-measurement-evidence"))]
impl ProofExternalMemoryBoundaryGeometry {
    pub(crate) fn derive(
        maximum_payload_byte_length: u64,
    ) -> Result<Self, ProofExternalMemoryError> {
        if maximum_payload_byte_length == 0
            || maximum_payload_byte_length
                > u64::from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
        {
            return Err(ProofExternalMemoryError::ResourceLimitExceeded);
        }
        let append_request_byte_length = (EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH as u64)
            .checked_add(EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH as u64)
            .and_then(|length| length.checked_add(maximum_payload_byte_length))
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let read_request_byte_length = (EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH as u64)
            .checked_add(EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH as u64)
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        let read_response_byte_length = (EXTERNAL_MEMORY_RESPONSE_HEADER_BYTE_LENGTH as u64)
            .checked_add(EXTERNAL_MEMORY_READ_RESULT_HEADER_BYTE_LENGTH as u64)
            .and_then(|length| length.checked_add(maximum_payload_byte_length))
            .ok_or(ProofExternalMemoryError::ResourceLimitExceeded)?;
        Ok(Self {
            append_request_byte_length,
            empty_response_byte_length: COMMON_PROOF_EXTERNAL_MEMORY_EMPTY_RESPONSE_BYTE_LENGTH,
            read_request_byte_length,
            read_response_byte_length,
        })
    }

    pub(crate) const fn append_request_byte_length(self) -> u64 {
        self.append_request_byte_length
    }

    pub(crate) const fn empty_response_byte_length(self) -> u64 {
        self.empty_response_byte_length
    }

    pub(crate) const fn read_request_byte_length(self) -> u64 {
        self.read_request_byte_length
    }

    pub(crate) const fn read_response_byte_length(self) -> u64 {
        self.read_response_byte_length
    }
}

/// Browser scratch planning targets and the absolute safety bound. Values
/// above the automatic target require an engineering review but remain valid
/// when the exact plan stays within the hard bound.
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT: usize = 4_096;
#[cfg(test)]
pub(crate) const NOMINAL_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH: u64 = 268_435_456;
#[cfg(test)]
pub(crate) const AUTOMATIC_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH: u64 = 402_653_184;
pub(crate) const MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH: u64 = 1_073_741_824;

mod executor;
mod plan;
mod transaction;

#[cfg(test)]
use transaction::external_memory_read_digest;

pub(crate) use executor::{
    ProofExternalMemoryError, ProofExternalMemoryExecutor, ProofExternalMemoryExecutorError,
    ProofExternalMemoryUsage,
};
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(crate) use plan::ProofExternalMemoryTransactionOperation;
pub(crate) use plan::{
    ProofExternalMemory, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
    ProofExternalMemorySecretSealCustodyRequirement,
};
pub(crate) use transaction::{
    EXTERNAL_MEMORY_SINGLE_APPEND_RECYCLER_CAPACITY_CEILING,
    ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionRecorder,
    ProofExternalMemoryTransactionReplay, ProofExternalMemoryTransactionRequest,
};
#[cfg(any(test, feature = "primitive-measurement-evidence"))]
pub(crate) use transaction::{
    EXTERNAL_MEMORY_SINGLE_APPEND_REPLAY_LENGTH_CAPACITY_CEILING,
    EXTERNAL_MEMORY_SINGLE_OPERATION_VECTOR_CAPACITY_CEILING,
    EXTERNAL_MEMORY_SINGLE_READ_RESULT_VECTOR_CAPACITY_CEILING,
};

#[cfg(test)]
#[path = "external_memory/tests.rs"]
pub(crate) mod tests;
