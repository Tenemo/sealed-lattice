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

mod executor;
mod plan;
mod transaction;

#[cfg(test)]
use transaction::external_memory_read_digest;

pub(crate) use executor::{
    ProofCancellation, ProofExternalMemoryError, ProofExternalMemoryExecutor,
    ProofExternalMemoryExecutorError, ProofExternalMemoryUsage,
};
pub(crate) use plan::{
    ProofExternalMemory, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection,
    ProofExternalMemoryTransactionOperation,
};
pub(crate) use transaction::{
    ProofExternalMemoryTransactionAdapterError, ProofExternalMemoryTransactionRecorder,
    ProofExternalMemoryTransactionReplay, ProofExternalMemoryTransactionRequest,
};

#[cfg(test)]
#[path = "external_memory/tests.rs"]
mod tests;
