//! Packed-DEEP-FRI arm for the synthetic backend bakeoff and guarded width evidence.
//!
//! This module deliberately does not construct a selected-suite relation plan.
//! It commits the frozen public two-equation fragment through the production
//! polynomial, transcript, canonical body, Merkle, opening, and FRI primitives.

use std::collections::BTreeMap;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
use std::io::{Seek, SeekFrom};
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use num_bigint::BigUint;
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
use crate::foundation::FOUNDATION_PROFILE;
use crate::hashing::hash_framed_parts_512;
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
use crate::{
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH,
    },
    hashing::{StreamingHash512, to_hex},
};

use super::{
    CommonProofPrivacyMode, CommonProofSourcePolynomial, CommonProofTranscript,
    CommonProofTranscriptSchedule, CompleteProofTreeCatalog, MAXIMUM_COMMON_PROOF_BYTE_LENGTH,
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH, OpenedFriLayerPair,
    PROOF_BASE_FIELD_MODULUS, PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement,
    ProofBodyError, ProofBodyLayout, ProofChallengeExtensionElement, ProofEvaluationDomain,
    ProofExternalMemory, ProofExternalMemoryObject, ProofExternalMemoryProtection,
    ProofFriQueryVerifier, ProofLeafVisibility, ProofOpeningClaimEvaluation, ProofTreeCatalogEntry,
    ProofTreeCatalogInput, ProofTreeCatalogSource, ProofTreeOpening, ProofTreeRole, ProofTreeValue,
    RelationProofTreeInput, build_complete_proof_tree_catalog, decode_proof_body_prefix,
    fold_extension_evaluations_in_place,
    merkle::CommonProofMerklePathReplay,
    opening::evaluate_initial_fri_pair,
    proof_backend_bakeoff::{ProofBackendBakeoffFixture, ProofBackendBakeoffResult},
    proof_query_tree_byte_length,
    prover::{
        BoundedCommonProofByteSink, CommonProofByteSink, CommonProofOpeningGeometry,
        add_bakeoff_polynomial_to_initial_fri, canonical_common_proof_query_section_header,
        canonical_proof_object_header_bytes, common_proof_query_section_byte_length,
        write_common_proof_prefix,
    },
};

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
use super::{
    external_memory::{
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
    },
    merkle::ProofOraclePhasePairLeafDigestBuilder,
    prover::encode_common_proof_query_tree_fragment_with_layout,
};

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
use super::{
    CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource, ProofExternalMemoryExecutor,
    ProofExternalMemoryObjectPlan,
    external_memory::ProofExternalMemoryPlan,
    proof_backend_bakeoff::{
        ProofBackendBakeoffArmOutput, canonical_frozen_fri_public_statement,
        recompute_frozen_input_identity, validate_frozen_core_statement,
        validated_frozen_fri_public_statement,
    },
    prover::{
        CommonProofMerkleMaterializer, CommonProofMerkleMaterializerProgress,
        CommonProofMerkleStoragePlan, CommonProofOpeningPrefetchProgress,
        CommonProofOpeningPrefetcher, StoredCommonProofMerkleTree,
        common_proof_merkle_storage_plan, encode_common_proof_query_tree_fragment,
    },
};
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
use super::{
    MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH, ProofExternalMemoryTransactionRequest,
    external_memory::{
        EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH, EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH,
        EXTERNAL_MEMORY_SINGLE_APPEND_RECYCLER_CAPACITY_CEILING,
        EXTERNAL_MEMORY_SINGLE_OPERATION_VECTOR_CAPACITY_CEILING,
        EXTERNAL_MEMORY_SINGLE_READ_RESULT_VECTOR_CAPACITY_CEILING,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_COPIED_BUFFER_BYTE_LENGTH,
        ProofExternalMemoryTransactionOperation,
    },
};
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
use crate::foundation::{
    MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT,
    MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT,
};

#[cfg(any(
    all(
        test,
        not(target_arch = "wasm32"),
        feature = "proof-storage-width-evidence"
    ),
    feature = "proof-storage-width-browser-evidence"
))]
mod proof_storage_width_browser_evidence;

const PROTOCOL_VERSION: u16 = 1;
const SYNTHETIC_APPLICATION_SCHEMA_IDENTIFIER: u16 = u16::MAX;
const PROOF_FIELD_INDEX: u16 = 0;
const TRACE_DOMAIN_SIZE: usize = 16_384;
const EVALUATION_DOMAIN_SIZE: usize = 131_072;
const QUERY_ORBIT_COUNT: u64 = 65_536;
const UNIQUE_QUERY_COUNT: u32 = 183;
const EVALUATION_COSET_OFFSET: u64 = 7;
const OPENING_DEGREE_BOUND_EXCLUSIVE: usize = 16_384;
const TERMINAL_COEFFICIENT_COUNT: usize = 256;
const FRI_FOLD_COUNT: usize = 6;
const TREE_COUNT: usize = 7;
const COLUMN_COUNT: usize = 8;
const CIPHERTEXT_MODULUS: u64 = 1_953_759_233;
const MATERIAL_RADIX: u64 = 129_140_163;
const MAXIMUM_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 128;
const EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH: u32 =
    MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH;
const MAXIMUM_PROOF_BYTE_LENGTH: usize = MAXIMUM_COMMON_PROOF_BYTE_LENGTH;
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
const MAXIMUM_PREFETCHED_QUERY_BYTE_LENGTH: u64 = 16 * 1_024 * 1_024;
const SECURITY_BIT_TARGET: u32 = 128;
const FRI_TRADEOFF_NUMERATOR: u32 = 5;
const FRI_TRADEOFF_DENOMINATOR: u32 = 8;
const MERKLE_DIGEST_BYTE_LENGTH: usize = 64;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH: u64 = 64;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const WIDTH_CONSERVATIVE_BTREE_ENTRY_STORAGE_MULTIPLIER: u64 = 16;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const WIDTH_CONSERVATIVE_EXTERNAL_MEMORY_OPERATION_BYTE_LENGTH: u64 = 48;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) const WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH: usize = 1_024;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const WIDTH_NATIVE_CUSTODY_PATH_HEADER_BYTE_LENGTH_CEILING: u64 = 32;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const WIDTH_NATIVE_CUSTODY_PATH_VECTOR_HEADER_BYTE_LENGTH_CEILING: u64 = 24;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) const WIDTH_ACTIVE_COLUMN_LDE_SCRATCH_BYTE_LENGTH: u64 =
    (EVALUATION_DOMAIN_SIZE * core::mem::size_of::<ProofBaseFieldElement>()) as u64;
const CLASSICAL_COLLISION_SECURITY_BIT_FLOOR: u32 = 256;
const GENERIC_QUANTUM_COLLISION_SECURITY_BIT_FLOOR: u32 = 170;
const CLASSICAL_ROUND_BY_ROUND_SOUNDNESS_BIT_FLOOR: u32 = 258;
const FIAT_SHAMIR_HASH_BIT_COUNT: u32 = 512;
const SOURCE_OPENING_CLAIM_COUNT: usize = COLUMN_COUNT + 1;
const BATCHED_FUNCTION_COUNT: usize = SOURCE_OPENING_CLAIM_COUNT * 2;
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
const MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT: usize = COLUMN_COUNT;
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
const MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT: usize = 3_451;
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
const PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN: u64 = 16_384 * 8;
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
const PUBLIC_SOURCE_REPLAY_COUNT: u64 = 6;
const FROZEN_REED_SOLOMON_LIST_SIZE_BOUND: u64 = 15;
const FOLD_MUTUAL_CORRELATED_AGREEMENT_NUMERATOR: u64 = 3_388_295_433_915;
const BATCH_MUTUAL_CORRELATED_AGREEMENT_NUMERATOR: u64 = 58_515_324_314_494;

type ProofBaseFieldColumns = [Vec<ProofBaseFieldElement>; COLUMN_COUNT];
type MaterializedProofTreePhasePair = (
    Zeroizing<Vec<ProofTreeValue>>,
    Zeroizing<Vec<ProofTreeValue>>,
);

const _: () = assert!(UNIQUE_QUERY_COUNT == 183);
const _: () = assert!(FRI_TRADEOFF_NUMERATOR == 5 && FRI_TRADEOFF_DENOMINATOR == 8);
const _: () = assert!(MERKLE_DIGEST_BYTE_LENGTH == 64);
const _: () = assert!(CLASSICAL_COLLISION_SECURITY_BIT_FLOOR == 256);
const _: () = assert!(GENERIC_QUANTUM_COLLISION_SECURITY_BIT_FLOOR == 170);
const _: () = assert!(CLASSICAL_ROUND_BY_ROUND_SOUNDNESS_BIT_FLOOR >= 2 * SECURITY_BIT_TARGET + 2);
const _: () = assert!(SOURCE_OPENING_CLAIM_COUNT == 9 && BATCHED_FUNCTION_COUNT == 18);
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const _: () = assert!(core::mem::size_of::<ProofTreeValue>() == 48);
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const _: () = assert!(core::mem::size_of::<Vec<ProofTreeValue>>() == 24);
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const _: () = assert!(core::mem::size_of::<ProofChallengeExtensionElement>() == 40);
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const _: () = assert!(core::mem::size_of::<(u64, AuthenticatedPhasePair)>() == 56);
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const _: () = assert!(core::mem::size_of::<BTreeMap<u64, AuthenticatedPhasePair>>() == 24);
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
const _: () = assert!(core::mem::size_of::<AuthenticatedTreeOpening>() == 32);

fn failure(context: &str, error: impl core::fmt::Debug) -> String {
    format!("{context}: {error:?}")
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) fn width_maximum_copied_buffer_byte_length() -> ProofBackendBakeoffResult<u64> {
    u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length)
        .map_err(|_| "foundation copied-buffer cap does not fit u64".to_owned())
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InMemoryExternalMemoryError {
    DuplicateTransaction,
    MissingTransaction,
    DuplicateObject,
    MissingObject,
    OperationLimitExceeded,
    PayloadLimitExceeded,
    StorageLimitExceeded,
    WrongOffsetOrLength,
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
struct InMemoryExternalMemoryObject {
    bytes: Vec<u8>,
    exact_byte_length: usize,
    protection: ProofExternalMemoryProtection,
    sealed: bool,
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
impl Drop for InMemoryExternalMemoryObject {
    fn drop(&mut self) {
        if self.protection == ProofExternalMemoryProtection::SecretAuthenticatedEncryption {
            self.bytes.zeroize();
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
enum InMemoryExternalMemoryUndo {
    RemoveCreated(ProofExternalMemoryObject),
    TruncateAppended {
        object: ProofExternalMemoryObject,
        previous_byte_length: usize,
    },
    RestoreSeal {
        object: ProofExternalMemoryObject,
        previous_sealed: bool,
    },
    RestoreDeleted {
        object: ProofExternalMemoryObject,
        value: InMemoryExternalMemoryObject,
    },
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
struct InMemoryExternalMemoryTransaction {
    objects: BTreeMap<ProofExternalMemoryObject, InMemoryExternalMemoryObject>,
    undo: Vec<InMemoryExternalMemoryUndo>,
    remaining_payload_byte_length: usize,
    remaining_operation_count: u32,
}

/// Transaction-correct best-latency adapter for the frozen bakeoff arm.
///
/// Every persisted payload remains resident and is therefore included in the
/// measured process RSS. Reads, writes, and committed transactions are still
/// charged at this adapter boundary; no file cache or baseline subtraction can
/// hide the memory tradeoff of this deliberately resident comparison case.
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
struct BoundedInMemoryExternalMemory {
    maximum_byte_length: usize,
    committed: BTreeMap<ProofExternalMemoryObject, InMemoryExternalMemoryObject>,
    transaction: Option<InMemoryExternalMemoryTransaction>,
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
impl BoundedInMemoryExternalMemory {
    fn new(maximum_byte_length: usize) -> Self {
        Self {
            maximum_byte_length,
            committed: BTreeMap::new(),
            transaction: None,
        }
    }

    fn transaction_for_operation(
        &mut self,
        payload_byte_length: usize,
    ) -> Result<&mut InMemoryExternalMemoryTransaction, InMemoryExternalMemoryError> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(InMemoryExternalMemoryError::MissingTransaction)?;
        transaction.remaining_operation_count = transaction
            .remaining_operation_count
            .checked_sub(1)
            .ok_or(InMemoryExternalMemoryError::OperationLimitExceeded)?;
        transaction.remaining_payload_byte_length = transaction
            .remaining_payload_byte_length
            .checked_sub(payload_byte_length)
            .ok_or(InMemoryExternalMemoryError::PayloadLimitExceeded)?;
        Ok(transaction)
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
impl ProofExternalMemory for BoundedInMemoryExternalMemory {
    type Error = InMemoryExternalMemoryError;

    fn begin_transaction(
        &mut self,
        maximum_payload_byte_length: u64,
        maximum_operation_count: u32,
    ) -> Result<(), Self::Error> {
        if self.transaction.is_some() {
            return Err(InMemoryExternalMemoryError::DuplicateTransaction);
        }
        let mut undo = Vec::new();
        undo.try_reserve_exact(
            usize::try_from(maximum_operation_count)
                .map_err(|_| InMemoryExternalMemoryError::StorageLimitExceeded)?,
        )
        .map_err(|_| InMemoryExternalMemoryError::StorageLimitExceeded)?;
        self.transaction = Some(InMemoryExternalMemoryTransaction {
            objects: std::mem::take(&mut self.committed),
            undo,
            remaining_payload_byte_length: usize::try_from(maximum_payload_byte_length)
                .map_err(|_| InMemoryExternalMemoryError::PayloadLimitExceeded)?,
            remaining_operation_count: maximum_operation_count,
        });
        Ok(())
    }

    fn create_object(
        &mut self,
        object: ProofExternalMemoryObject,
        protection: ProofExternalMemoryProtection,
        exact_byte_length: u64,
    ) -> Result<(), Self::Error> {
        let maximum_byte_length = self.maximum_byte_length;
        let exact_byte_length = usize::try_from(exact_byte_length)
            .map_err(|_| InMemoryExternalMemoryError::StorageLimitExceeded)?;
        let transaction = self.transaction_for_operation(0)?;
        if transaction.objects.contains_key(&object) {
            return Err(InMemoryExternalMemoryError::DuplicateObject);
        }
        transaction
            .objects
            .values()
            .try_fold(0_usize, |total, stored| {
                total.checked_add(stored.exact_byte_length)
            })
            .and_then(|total| total.checked_add(exact_byte_length))
            .filter(|total| *total <= maximum_byte_length)
            .ok_or(InMemoryExternalMemoryError::StorageLimitExceeded)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(exact_byte_length)
            .map_err(|_| InMemoryExternalMemoryError::StorageLimitExceeded)?;
        transaction.objects.insert(
            object,
            InMemoryExternalMemoryObject {
                bytes,
                exact_byte_length,
                protection,
                sealed: false,
            },
        );
        transaction
            .undo
            .push(InMemoryExternalMemoryUndo::RemoveCreated(object));
        Ok(())
    }

    fn append_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        expected_offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(bytes.len())?;
        let expected_offset = usize::try_from(expected_offset)
            .map_err(|_| InMemoryExternalMemoryError::WrongOffsetOrLength)?;
        let previous_byte_length = {
            let stored = transaction
                .objects
                .get_mut(&object)
                .ok_or(InMemoryExternalMemoryError::MissingObject)?;
            stored
                .bytes
                .len()
                .checked_add(bytes.len())
                .filter(|length| *length <= stored.exact_byte_length)
                .ok_or(InMemoryExternalMemoryError::WrongOffsetOrLength)?;
            if stored.sealed || stored.bytes.len() != expected_offset {
                return Err(InMemoryExternalMemoryError::WrongOffsetOrLength);
            }
            stored.bytes.len()
        };
        transaction
            .undo
            .push(InMemoryExternalMemoryUndo::TruncateAppended {
                object,
                previous_byte_length,
            });
        transaction
            .objects
            .get_mut(&object)
            .ok_or(InMemoryExternalMemoryError::MissingObject)?
            .bytes
            .extend_from_slice(bytes);
        Ok(())
    }

    fn seal_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(0)?;
        let previous_sealed = {
            let stored = transaction
                .objects
                .get(&object)
                .ok_or(InMemoryExternalMemoryError::MissingObject)?;
            if stored.sealed || stored.bytes.len() != stored.exact_byte_length {
                return Err(InMemoryExternalMemoryError::WrongOffsetOrLength);
            }
            stored.sealed
        };
        transaction
            .undo
            .push(InMemoryExternalMemoryUndo::RestoreSeal {
                object,
                previous_sealed,
            });
        transaction
            .objects
            .get_mut(&object)
            .ok_or(InMemoryExternalMemoryError::MissingObject)?
            .sealed = true;
        Ok(())
    }

    fn read_object_bytes(
        &mut self,
        object: ProofExternalMemoryObject,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        let stored = self
            .transaction_for_operation(destination.len())?
            .objects
            .get(&object)
            .ok_or(InMemoryExternalMemoryError::MissingObject)?;
        let offset = usize::try_from(offset)
            .map_err(|_| InMemoryExternalMemoryError::WrongOffsetOrLength)?;
        let end = offset
            .checked_add(destination.len())
            .ok_or(InMemoryExternalMemoryError::WrongOffsetOrLength)?;
        if !stored.sealed {
            return Err(InMemoryExternalMemoryError::WrongOffsetOrLength);
        }
        destination.copy_from_slice(
            stored
                .bytes
                .get(offset..end)
                .ok_or(InMemoryExternalMemoryError::WrongOffsetOrLength)?,
        );
        Ok(())
    }

    fn delete_object(&mut self, object: ProofExternalMemoryObject) -> Result<(), Self::Error> {
        let transaction = self.transaction_for_operation(0)?;
        let value = transaction
            .objects
            .remove(&object)
            .ok_or(InMemoryExternalMemoryError::MissingObject)?;
        transaction
            .undo
            .push(InMemoryExternalMemoryUndo::RestoreDeleted { object, value });
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), Self::Error> {
        let transaction = self
            .transaction
            .take()
            .ok_or(InMemoryExternalMemoryError::MissingTransaction)?;
        self.committed = transaction.objects;
        Ok(())
    }

    fn abort_transaction(&mut self) -> Result<(), Self::Error> {
        let mut transaction = self
            .transaction
            .take()
            .ok_or(InMemoryExternalMemoryError::MissingTransaction)?;
        while let Some(undo) = transaction.undo.pop() {
            match undo {
                InMemoryExternalMemoryUndo::RemoveCreated(object) => {
                    transaction
                        .objects
                        .remove(&object)
                        .ok_or(InMemoryExternalMemoryError::MissingObject)?;
                }
                InMemoryExternalMemoryUndo::TruncateAppended {
                    object,
                    previous_byte_length,
                } => {
                    let stored = transaction
                        .objects
                        .get_mut(&object)
                        .ok_or(InMemoryExternalMemoryError::MissingObject)?;
                    if previous_byte_length > stored.bytes.len() {
                        return Err(InMemoryExternalMemoryError::WrongOffsetOrLength);
                    }
                    if stored.protection
                        == ProofExternalMemoryProtection::SecretAuthenticatedEncryption
                    {
                        stored.bytes[previous_byte_length..].zeroize();
                    }
                    stored.bytes.truncate(previous_byte_length);
                }
                InMemoryExternalMemoryUndo::RestoreSeal {
                    object,
                    previous_sealed,
                } => {
                    transaction
                        .objects
                        .get_mut(&object)
                        .ok_or(InMemoryExternalMemoryError::MissingObject)?
                        .sealed = previous_sealed;
                }
                InMemoryExternalMemoryUndo::RestoreDeleted { object, value } => {
                    if transaction.objects.insert(object, value).is_some() {
                        return Err(InMemoryExternalMemoryError::DuplicateObject);
                    }
                }
            }
        }
        self.committed = transaction.objects;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NoPrivateCoinError {
    PrivateCoordinateRequested,
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
struct NoPrivateCoins;

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
impl CommonProofPrivateCoinSource for NoPrivateCoins {
    type Error = NoPrivateCoinError;

    fn sample_modulo(
        &mut self,
        _coordinate: CommonProofPrivateCoinCoordinate,
        _modulus: u64,
        _maximum_candidate_draws_per_output: u32,
    ) -> Result<u64, Self::Error> {
        Err(NoPrivateCoinError::PrivateCoordinateRequested)
    }

    fn fill_raw_bytes(
        &mut self,
        _coordinate: CommonProofPrivateCoinCoordinate,
        _destination: &mut [u8],
    ) -> Result<(), Self::Error> {
        Err(NoPrivateCoinError::PrivateCoordinateRequested)
    }
}

fn transcript_schedule() -> ProofBackendBakeoffResult<CommonProofTranscriptSchedule> {
    CommonProofTranscriptSchedule::new(
        vec![0],
        Vec::new(),
        Vec::new(),
        2,
        1,
        1,
        u32::try_from(BATCHED_FUNCTION_COUNT)
            .map_err(|_| "batched function count overflowed".to_owned())?,
        u16::try_from(FRI_FOLD_COUNT).map_err(|_| "FRI fold count overflowed".to_owned())?,
        u32::try_from(TERMINAL_COEFFICIENT_COUNT)
            .map_err(|_| "terminal coefficient count overflowed".to_owned())?,
        UNIQUE_QUERY_COUNT,
        QUERY_ORBIT_COUNT,
        MAXIMUM_CANDIDATE_DRAWS_PER_OUTPUT,
        CommonProofPrivacyMode::PublicOnly,
    )
    .map_err(|error| failure("construct frozen transcript schedule", error))
}

fn exact_error_sum_is_below_power_of_two(
    terms: &[(BigUint, BigUint)],
    bit_count: u32,
) -> ProofBackendBakeoffResult<bool> {
    if terms.is_empty()
        || terms
            .iter()
            .any(|(_, denominator)| denominator == &BigUint::from(0_u8))
    {
        return Err("soundness ledger contains no term or a zero denominator".to_owned());
    }
    let common_denominator = terms
        .iter()
        .fold(BigUint::from(1_u8), |product, (_, denominator)| {
            product * denominator
        });
    let common_numerator = terms
        .iter()
        .fold(BigUint::from(0_u8), |total, (numerator, denominator)| {
            total + numerator * (&common_denominator / denominator)
        });
    Ok((common_numerator << bit_count as usize) < common_denominator)
}

/// Validates the exact arbitrary-prover soundness ledger for the frozen arm.
///
/// GMW25 Theorem 5.2 is applied to the six fixed radix-two folds with tradeoff
/// parameter `theta = 5/8`; its query term is therefore `(3/8)^183`. The
/// BCHKS mutual-correlated-agreement bound uses
/// `eta = ceil(8 + 6 sqrt(2)) = 17` and the exact post-fold domain lengths.
/// GMW25 Appendix A.2 is applied to the eighteen fixed functions in the
/// source-plus-shifted-normalized opening batch using eighteen independently
/// sampled coefficients. Sequential two-function reduction contributes the
/// frozen batch MCA numerator below.
///
/// At agreement `3n/8`, the exact pair-counting bound makes every frozen
/// `RS_16384` list have size at most fifteen. The eight adaptive pre-DEEP
/// choices therefore contribute `15^8/P`; after
/// the DEEP point, the nine lists and the degree-32,767 identity contribute
/// `15^9 * 32,767 / (P - 147,457)`. Sampling query representatives uniformly
/// without replacement can only improve the theorem's independent-query upper
/// bound. Every comparison below is exact integer arithmetic.
///
/// The 64-byte SHAKE256 roots provide a 256-bit generic classical collision
/// work factor under the ideal-XOF model. Their approximately 170.7-bit generic
/// quantum collision-query work factor is recorded separately and is not used
/// as a QROM proof-soundness term; QROM closure remains open.
///
/// The BCS/BT24 Fiat--Shamir compiler bound is
/// `epsilon_FS(Q, kappa) = Q epsilon_RBR + 3(Q^2 + 1) / 2^kappa`. The strict
/// 258-bit round-by-round floor and `kappa = 512` are checked below at a
/// `Q = 2^128` classical random-oracle query budget, yielding strictly more
/// than 128 bits of noninteractive classical ROM security.
fn validate_frozen_fri_soundness_profile() -> ProofBackendBakeoffResult<()> {
    let expected_terminal_domain_size = TERMINAL_COEFFICIENT_COUNT
        .checked_mul(8)
        .ok_or_else(|| "frozen terminal-domain size overflowed".to_owned())?;
    if EVALUATION_DOMAIN_SIZE != OPENING_DEGREE_BOUND_EXCLUSIVE * 8
        || EVALUATION_DOMAIN_SIZE >> FRI_FOLD_COUNT != expected_terminal_domain_size
        || QUERY_ORBIT_COUNT
            != u64::try_from(EVALUATION_DOMAIN_SIZE / 2)
                .map_err(|_| "frozen query orbit does not fit u64".to_owned())?
        || UNIQUE_QUERY_COUNT != 183
        || FRI_TRADEOFF_NUMERATOR != 5
        || FRI_TRADEOFF_DENOMINATOR != 8
        || MERKLE_DIGEST_BYTE_LENGTH != 64
        || CLASSICAL_COLLISION_SECURITY_BIT_FLOOR != 256
        || GENERIC_QUANTUM_COLLISION_SECURITY_BIT_FLOOR != 170
        || PROOF_CHALLENGE_EXTENSION_DEGREE != 5
        || SOURCE_OPENING_CLAIM_COUNT != 9
        || BATCHED_FUNCTION_COUNT != 18
    {
        return Err("frozen FRI security geometry changed without a new derivation".to_owned());
    }

    let query_acceptance_numerator = FRI_TRADEOFF_DENOMINATOR
        .checked_sub(FRI_TRADEOFF_NUMERATOR)
        .ok_or_else(|| "FRI query-bound numerator overflowed".to_owned())?;
    let query_acceptance_denominator = FRI_TRADEOFF_DENOMINATOR;
    if query_acceptance_numerator != 3 || query_acceptance_denominator != 8 {
        return Err("frozen FRI query-bound fraction changed".to_owned());
    }
    let query_numerator = BigUint::from(query_acceptance_numerator).pow(UNIQUE_QUERY_COUNT);
    let query_denominator = BigUint::from(query_acceptance_denominator).pow(UNIQUE_QUERY_COUNT);

    let extension_degree = u32::try_from(PROOF_CHALLENGE_EXTENSION_DEGREE)
        .map_err(|_| "challenge-extension degree does not fit u32".to_owned())?;
    let field_order = BigUint::from(PROOF_BASE_FIELD_MODULUS).pow(extension_degree);
    let forbidden_deep_point_count = 1_u64
        .checked_add(
            u64::try_from(TRACE_DOMAIN_SIZE)
                .map_err(|_| "trace domain size does not fit u64".to_owned())?,
        )
        .and_then(|count| count.checked_add(u64::try_from(EVALUATION_DOMAIN_SIZE).ok()?))
        .ok_or_else(|| "forbidden DEEP-point count overflowed".to_owned())?;
    let forbidden_deep_point_count = BigUint::from(forbidden_deep_point_count);
    if field_order <= forbidden_deep_point_count {
        return Err("forbidden DEEP-point set exhausts the challenge field".to_owned());
    }
    let accepted_deep_point_space = &field_order - &forbidden_deep_point_count;

    let post_fold_domain_length_sum = (1..=FRI_FOLD_COUNT)
        .try_fold(0_usize, |total, fold_ordinal| {
            total.checked_add(EVALUATION_DOMAIN_SIZE >> fold_ordinal)
        })
        .ok_or_else(|| "post-fold domain-length sum overflowed".to_owned())?;
    let bchks_eta = 17_u64;
    let eta_offset = bchks_eta
        .checked_sub(8)
        .ok_or_else(|| "BCHKS eta offset underflowed".to_owned())?;
    let previous_eta_offset = eta_offset
        .checked_sub(1)
        .ok_or_else(|| "BCHKS previous eta offset underflowed".to_owned())?;
    if post_fold_domain_length_sum != 129_024
        || eta_offset * eta_offset < 72
        || previous_eta_offset * previous_eta_offset >= 72
    {
        return Err("frozen GMW25/BCHKS fold geometry changed".to_owned());
    }
    // Lemma 2.4 at rate 1/8, theta 5/8, and eta 17 has the common
    // rational upper bound
    //
    //   (420,175,525 * |L| + 840) / (16 * P)
    //
    // for every two-function reduction, using sqrt(2) < 3/2. Folding
    // applies it once on each post-fold domain. The 18-function independent
    // batch first pays 1/P when its leading coefficient is zero, then uses
    // seventeen sequential two-function reductions. Ceiling only after each
    // complete union keeps the stored integer numerators conservative.
    let twice_eta_plus_one = u128::from(bchks_eta)
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "twice BCHKS eta plus one overflowed".to_owned())?;
    let scaled_mca_domain_coefficient = twice_eta_plus_one
        .checked_pow(5)
        .and_then(|value| value.checked_mul(8))
        .and_then(|value| {
            value.checked_add(
                3_u128
                    .checked_mul(twice_eta_plus_one)?
                    .checked_mul(u128::from(FRI_TRADEOFF_NUMERATOR))?,
            )
        })
        .ok_or_else(|| "scaled MCA domain coefficient overflowed".to_owned())?;
    let scaled_mca_constant_term = 3_u128
        .checked_mul(twice_eta_plus_one)
        .and_then(|value| value.checked_mul(u128::from(FRI_TRADEOFF_DENOMINATOR)))
        .ok_or_else(|| "scaled MCA constant term overflowed".to_owned())?;
    let mca_common_denominator = 16_u128;
    if twice_eta_plus_one != 35
        || scaled_mca_domain_coefficient != 420_175_525
        || scaled_mca_constant_term != 840
    {
        return Err("frozen BCHKS rational reduction changed".to_owned());
    }
    let post_fold_domain_length_sum_u128 = u128::try_from(post_fold_domain_length_sum)
        .map_err(|_| "post-fold domain sum does not fit u128".to_owned())?;
    let fri_fold_count_u128 = u128::try_from(FRI_FOLD_COUNT)
        .map_err(|_| "FRI fold count does not fit u128".to_owned())?;
    let scaled_fold_mca_numerator = scaled_mca_domain_coefficient
        .checked_mul(post_fold_domain_length_sum_u128)
        .and_then(|value| {
            value.checked_add(scaled_mca_constant_term.checked_mul(fri_fold_count_u128)?)
        })
        .ok_or_else(|| "scaled fold MCA numerator overflowed".to_owned())?;
    let derived_fold_mca_numerator = scaled_fold_mca_numerator
        .checked_add(mca_common_denominator - 1)
        .and_then(|value| value.checked_div(mca_common_denominator))
        .ok_or_else(|| "fold MCA ceiling overflowed".to_owned())?;
    let batch_reduction_count = BATCHED_FUNCTION_COUNT
        .checked_sub(1)
        .ok_or_else(|| "batch reduction count underflowed".to_owned())?;
    let evaluation_domain_size_u128 = u128::try_from(EVALUATION_DOMAIN_SIZE)
        .map_err(|_| "evaluation domain size does not fit u128".to_owned())?;
    let batch_reduction_count_u128 = u128::try_from(batch_reduction_count)
        .map_err(|_| "batch reduction count does not fit u128".to_owned())?;
    let scaled_single_batch_reduction = scaled_mca_domain_coefficient
        .checked_mul(evaluation_domain_size_u128)
        .and_then(|value| value.checked_add(scaled_mca_constant_term))
        .ok_or_else(|| "scaled batch MCA reduction overflowed".to_owned())?;
    let scaled_batch_mca_numerator = scaled_single_batch_reduction
        .checked_mul(batch_reduction_count_u128)
        .and_then(|value| value.checked_add(mca_common_denominator))
        .ok_or_else(|| "scaled batch MCA numerator overflowed".to_owned())?;
    let derived_batch_mca_numerator = scaled_batch_mca_numerator
        .checked_add(mca_common_denominator - 1)
        .and_then(|value| value.checked_div(mca_common_denominator))
        .ok_or_else(|| "batch MCA ceiling overflowed".to_owned())?;
    if derived_fold_mca_numerator != u128::from(FOLD_MUTUAL_CORRELATED_AGREEMENT_NUMERATOR)
        || derived_batch_mca_numerator != u128::from(BATCH_MUTUAL_CORRELATED_AGREEMENT_NUMERATOR)
    {
        return Err("frozen GMW25/BCHKS MCA numerator derivation changed".to_owned());
    }

    let minimum_agreement_count = EVALUATION_DOMAIN_SIZE
        .checked_mul(3)
        .and_then(|value| value.checked_div(8))
        .ok_or_else(|| "minimum agreement count overflowed".to_owned())?;
    let maximum_codeword_degree = OPENING_DEGREE_BOUND_EXCLUSIVE
        .checked_sub(1)
        .ok_or_else(|| "maximum codeword degree underflowed".to_owned())?;
    let pair_count_denominator = minimum_agreement_count
        .checked_mul(minimum_agreement_count)
        .and_then(|value| value.checked_div(EVALUATION_DOMAIN_SIZE))
        .and_then(|value| value.checked_sub(maximum_codeword_degree))
        .ok_or_else(|| "Reed-Solomon list denominator overflowed".to_owned())?;
    let pair_count_numerator = minimum_agreement_count
        .checked_sub(maximum_codeword_degree)
        .ok_or_else(|| "Reed-Solomon list numerator underflowed".to_owned())?;
    let derived_list_size_bound = pair_count_numerator
        .checked_div(pair_count_denominator)
        .ok_or_else(|| "Reed-Solomon list denominator is zero".to_owned())?;
    if minimum_agreement_count != 49_152
        || pair_count_numerator != 32_769
        || pair_count_denominator != 2_049
        || derived_list_size_bound
            != usize::try_from(FROZEN_REED_SOLOMON_LIST_SIZE_BOUND)
                .map_err(|_| "list-size bound does not fit usize".to_owned())?
    {
        return Err("frozen pair-counting Reed-Solomon list bound changed".to_owned());
    }

    let adaptive_alpha_numerator = BigUint::from(FROZEN_REED_SOLOMON_LIST_SIZE_BOUND).pow(8);
    let fold_and_batch_numerator = BigUint::from(FOLD_MUTUAL_CORRELATED_AGREEMENT_NUMERATOR)
        + BigUint::from(BATCH_MUTUAL_CORRELATED_AGREEMENT_NUMERATOR)
        + &adaptive_alpha_numerator;
    if fold_and_batch_numerator != BigUint::from(61_906_182_639_034_u64) {
        return Err("frozen fold, batch, and adaptive-alpha numerator changed".to_owned());
    }
    let deep_identity_numerator =
        BigUint::from(FROZEN_REED_SOLOMON_LIST_SIZE_BOUND).pow(9) * BigUint::from(32_767_u64);
    if deep_identity_numerator != BigUint::from(1_259_673_556_640_625_u64)
        || forbidden_deep_point_count != BigUint::from(147_457_u64)
    {
        return Err("frozen adaptive DEEP-identity ledger changed".to_owned());
    }

    let algebraic_terms = [
        (fold_and_batch_numerator.clone(), field_order.clone()),
        (
            deep_identity_numerator.clone(),
            accepted_deep_point_space.clone(),
        ),
    ];
    if !exact_error_sum_is_below_power_of_two(&algebraic_terms, 269)?
        || exact_error_sum_is_below_power_of_two(&algebraic_terms, 270)?
    {
        return Err("frozen algebraic soundness is not in the audited 269-bit interval".to_owned());
    }

    let round_by_round_terms = [
        (query_numerator.clone(), query_denominator.clone()),
        (fold_and_batch_numerator.clone(), field_order.clone()),
        (
            deep_identity_numerator.clone(),
            accepted_deep_point_space.clone(),
        ),
    ];
    let previous_query_count = UNIQUE_QUERY_COUNT
        .checked_sub(1)
        .ok_or_else(|| "previous FRI query count underflowed".to_owned())?;
    let previous_query_terms = [
        (
            BigUint::from(query_acceptance_numerator).pow(previous_query_count),
            BigUint::from(query_acceptance_denominator).pow(previous_query_count),
        ),
        (fold_and_batch_numerator, field_order),
        (deep_identity_numerator, accepted_deep_point_space),
    ];
    if !exact_error_sum_is_below_power_of_two(
        &round_by_round_terms,
        CLASSICAL_ROUND_BY_ROUND_SOUNDNESS_BIT_FLOOR,
    )? || exact_error_sum_is_below_power_of_two(
        &previous_query_terms,
        CLASSICAL_ROUND_BY_ROUND_SOUNDNESS_BIT_FLOOR,
    )? {
        return Err(
            "183 queries are not the minimum preserving strict 258-bit round-by-round soundness"
                .to_owned(),
        );
    }

    let classical_oracle_query_budget = BigUint::from(1_u8) << SECURITY_BIT_TARGET as usize;
    let fiat_shamir_terms = round_by_round_terms
        .iter()
        .map(|(numerator, denominator)| {
            (
                numerator * &classical_oracle_query_budget,
                denominator.clone(),
            )
        })
        .chain(core::iter::once((
            BigUint::from(3_u8)
                * (&classical_oracle_query_budget * &classical_oracle_query_budget
                    + BigUint::from(1_u8)),
            BigUint::from(1_u8) << FIAT_SHAMIR_HASH_BIT_COUNT as usize,
        )))
        .collect::<Vec<_>>();
    if !exact_error_sum_is_below_power_of_two(&fiat_shamir_terms, SECURITY_BIT_TARGET)? {
        return Err("frozen Fiat-Shamir compiler ledger does not preserve 128 ROM bits".to_owned());
    }
    Ok(())
}

struct FrozenProofProfile {
    suite_identifier: [u8; 64],
    application_statement_schema_identifier: u16,
    canonical_core_statement: Vec<u8>,
    canonical_header: Vec<u8>,
    expected_fri_base_root: [u8; 64],
    schedule: CommonProofTranscriptSchedule,
    layout: ProofBodyLayout,
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn public_width_proof_profile(
    input_identity_shake256_hex: &str,
    public_base_leaf_column_count: usize,
    expected_fri_base_root: [u8; 64],
) -> ProofBackendBakeoffResult<(FrozenProofProfile, Vec<u8>)> {
    validate_frozen_fri_soundness_profile()?;
    let canonical_core_statement = canonical_public_width_core_statement(
        input_identity_shake256_hex,
        public_base_leaf_column_count,
    )?;
    let canonical_statement =
        canonical_public_width_statement(&canonical_core_statement, expected_fri_base_root)?;
    let canonical_header = canonical_proof_object_header_bytes(&canonical_statement)
        .map_err(|error| failure("construct public-width proof header", error))?;
    let suite_identifier = hash_framed_parts_512(
        "sealed-lattice/proof-replay-evidence/synthetic-suite/v1",
        &[&canonical_statement, input_identity_shake256_hex.as_bytes()],
    );
    let schedule = transcript_schedule()?;
    let catalog = proof_catalog_with_public_base_width(
        &canonical_core_statement,
        input_identity_shake256_hex,
        &schedule,
        public_base_leaf_column_count,
    )?;
    let layout = ProofBodyLayout::new(
        catalog,
        &schedule,
        u32::try_from(TERMINAL_COEFFICIENT_COUNT)
            .map_err(|_| "terminal coefficient count does not fit u32".to_owned())?,
    )
    .map_err(|error| failure("construct public-width proof body layout", error))?;
    Ok((
        FrozenProofProfile {
            suite_identifier,
            application_statement_schema_identifier: SYNTHETIC_APPLICATION_SCHEMA_IDENTIFIER,
            canonical_core_statement,
            canonical_header,
            expected_fri_base_root,
            schedule,
            layout,
        },
        canonical_statement,
    ))
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
struct PublicWidthStatementBindings {
    canonical_core_statement: Vec<u8>,
    public_base_leaf_column_count: usize,
    expected_fri_base_root: [u8; 64],
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn public_width_unsigned64(
    item: &CanonicalItem,
    field_name: &str,
) -> ProofBackendBakeoffResult<u64> {
    if item.item_type() != CanonicalItemType::Unsigned64 {
        return Err(format!(
            "public-width {field_name} is not an unsigned 64-bit value"
        ));
    }
    let canonical_bytes: [u8; 8] = item
        .canonical_bytes()
        .try_into()
        .map_err(|_| format!("public-width {field_name} does not contain eight bytes"))?;
    Ok(u64::from_le_bytes(canonical_bytes))
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn validated_public_width_statement(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<PublicWidthStatementBindings> {
    let decoded = CanonicalTuple::decode(canonical_statement, &CanonicalDecodeLimits::default())
        .map_err(|error| format!("decode public-width canonical statement: {error}"))?;
    if decoded.schema_identifier != u16::MAX || decoded.schema_version != 2 {
        return Err("public-width statement schema identifier or version changed".to_owned());
    }
    if decoded.items.len() != 3
        || decoded.items[0].item_type() != CanonicalItemType::Ascii
        || decoded.items[1].item_type() != CanonicalItemType::NestedTuple
        || decoded.items[2].item_type() != CanonicalItemType::Hash512
    {
        return Err("public-width statement binding shape changed".to_owned());
    }
    let statement_domain = decoded.items[0]
        .variable_value_bytes()
        .map_err(|error| format!("decode public-width statement domain: {error}"))?;
    if statement_domain != PUBLIC_WIDTH_STATEMENT_DOMAIN.as_bytes() {
        return Err("public-width statement domain changed".to_owned());
    }

    let canonical_core_statement = decoded.items[1].canonical_bytes().to_vec();
    let decoded_core =
        CanonicalTuple::decode(&canonical_core_statement, &CanonicalDecodeLimits::default())
            .map_err(|error| format!("decode public-width core statement: {error}"))?;
    if decoded_core.schema_identifier != u16::MAX || decoded_core.schema_version != 1 {
        return Err("public-width core statement schema identifier or version changed".to_owned());
    }
    if decoded_core.items.len() != 8
        || decoded_core.items[..7]
            .iter()
            .any(|item| item.item_type() != CanonicalItemType::Unsigned64)
        || decoded_core.items[7].item_type() != CanonicalItemType::Ascii
    {
        return Err("public-width core statement binding shape changed".to_owned());
    }
    let fixed_values = [
        (0, 10, "roster size"),
        (1, 32_768, "ring dimension"),
        (2, 257, "plaintext modulus"),
        (
            3,
            u64::try_from(TRACE_DOMAIN_SIZE)
                .map_err(|_| "trace row count does not fit u64".to_owned())?,
            "trace row count",
        ),
        (5, CIPHERTEXT_MODULUS, "ciphertext modulus"),
        (6, MATERIAL_RADIX, "material radix"),
    ];
    for (item_index, expected_value, field_name) in fixed_values {
        if public_width_unsigned64(&decoded_core.items[item_index], field_name)? != expected_value {
            return Err(format!("public-width {field_name} changed"));
        }
    }
    let public_base_leaf_column_count = usize::try_from(public_width_unsigned64(
        &decoded_core.items[4],
        "public base leaf column count",
    )?)
    .map_err(|_| "public-width column count does not fit usize".to_owned())?;
    if !(MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT..=MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT)
        .contains(&public_base_leaf_column_count)
    {
        return Err(format!(
            "public-width column count must be in {MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT}..={MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT}"
        ));
    }
    let statement_input_identity = decoded_core.items[7]
        .variable_value_bytes()
        .map_err(|error| format!("decode public-width input identity: {error}"))?;
    if statement_input_identity != input_identity_shake256_hex.as_bytes() {
        return Err("public-width statement does not bind the supplied input identity".to_owned());
    }
    let recomputed_core_statement = canonical_public_width_core_statement(
        input_identity_shake256_hex,
        public_base_leaf_column_count,
    )?;
    if recomputed_core_statement != canonical_core_statement {
        return Err("public-width core statement is not canonical".to_owned());
    }

    let expected_fri_base_root: [u8; 64] = decoded.items[2]
        .canonical_bytes()
        .try_into()
        .map_err(|_| "public-width base root is not 512 bits".to_owned())?;
    let recomputed_statement =
        canonical_public_width_statement(&canonical_core_statement, expected_fri_base_root)?;
    if decoded
        .encode()
        .map_err(|error| format!("re-encode public-width statement: {error}"))?
        != canonical_statement
        || recomputed_statement != canonical_statement
    {
        return Err(
            "public-width statement does not match fresh public-input derivation".to_owned(),
        );
    }
    Ok(PublicWidthStatementBindings {
        canonical_core_statement,
        public_base_leaf_column_count,
        expected_fri_base_root,
    })
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn public_width_proof_profile_from_public_input(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<FrozenProofProfile> {
    let bindings =
        validated_public_width_statement(canonical_statement, input_identity_shake256_hex)?;
    let (profile, recomputed_statement) = public_width_proof_profile(
        input_identity_shake256_hex,
        bindings.public_base_leaf_column_count,
        bindings.expected_fri_base_root,
    )?;
    if profile.canonical_core_statement != bindings.canonical_core_statement
        || recomputed_statement != canonical_statement
    {
        return Err("fresh public-width profile diverges from its canonical statement".to_owned());
    }
    Ok(profile)
}

fn authenticated_base_column_count(
    profile: &FrozenProofProfile,
) -> ProofBackendBakeoffResult<usize> {
    usize::try_from(
        profile
            .layout
            .catalog()
            .entries()
            .first()
            .and_then(ProofTreeCatalogEntry::common_context)
            .ok_or_else(|| "proof profile is missing its base-tree context".to_owned())?
            .row_width(),
    )
    .map_err(|_| "proof profile base-tree width does not fit usize".to_owned())
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn public_width_fresh_profile_reconstruction_parses_root_and_width_and_rejects_unbound_input() {
    let identity = "0".repeat(128);
    let root = [0x31_u8; 64];
    let (profile, canonical_statement) =
        public_width_proof_profile(&identity, MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT, root)
            .expect("construct canonical public-width profile");
    let reconstructed =
        public_width_proof_profile_from_public_input(&canonical_statement, &identity)
            .expect("reconstruct canonical public-width profile");
    assert_eq!(reconstructed.expected_fri_base_root, root);
    assert_eq!(
        authenticated_base_column_count(&reconstructed).expect("read reconstructed width"),
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT
    );
    assert_eq!(reconstructed.canonical_header, profile.canonical_header);

    let alternate_root = [0x32_u8; 64];
    let alternate_root_statement = canonical_public_width_statement(
        &canonical_public_width_core_statement(&identity, MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT)
            .expect("construct alternate-root core statement"),
        alternate_root,
    )
    .expect("construct alternate-root statement");
    let alternate_root_profile =
        public_width_proof_profile_from_public_input(&alternate_root_statement, &identity)
            .expect("parse alternate bound root");
    assert_eq!(
        alternate_root_profile.expected_fri_base_root,
        alternate_root
    );
    assert_ne!(
        alternate_root_profile.canonical_header,
        profile.canonical_header
    );

    let alternate_width = MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT + 1;
    let alternate_width_statement = canonical_public_width_statement(
        &canonical_public_width_core_statement(&identity, alternate_width)
            .expect("construct alternate-width core statement"),
        root,
    )
    .expect("construct alternate-width statement");
    let alternate_width_profile =
        public_width_proof_profile_from_public_input(&alternate_width_statement, &identity)
            .expect("parse alternate bound width");
    assert_eq!(
        authenticated_base_column_count(&alternate_width_profile)
            .expect("read alternate reconstructed width"),
        alternate_width
    );

    assert!(
        public_width_proof_profile_from_public_input(&canonical_statement, &"1".repeat(128))
            .is_err()
    );

    let invalid_width_statement = canonical_public_width_statement(
        &canonical_public_width_core_statement(
            &identity,
            MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT + 1,
        )
        .expect("construct invalid-width core statement"),
        root,
    )
    .expect("construct invalid-width statement");
    assert!(
        public_width_proof_profile_from_public_input(&invalid_width_statement, &identity).is_err()
    );

    let mut malformed_statement = canonical_statement;
    malformed_statement.push(0);
    assert!(public_width_proof_profile_from_public_input(&malformed_statement, &identity).is_err());
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn frozen_proof_profile_for_generation(
    fixture: &ProofBackendBakeoffFixture,
) -> ProofBackendBakeoffResult<FrozenProofProfile> {
    let recomputed_identity = recompute_frozen_input_identity(&fixture.columns)?;
    if recomputed_identity != fixture.input_identity_shake256_hex {
        return Err("frozen input identity does not match the exact eight columns".to_owned());
    }
    let profile = frozen_proof_profile_from_public_input(
        &fixture.canonical_fri_statement,
        &fixture.input_identity_shake256_hex,
    )?;
    if profile.canonical_core_statement != fixture.canonical_core_statement
        || profile.expected_fri_base_root != fixture.expected_fri_base_root
    {
        return Err("FRI fixture bindings diverge from its canonical statement".to_owned());
    }
    Ok(profile)
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn frozen_proof_profile_from_public_input(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
) -> ProofBackendBakeoffResult<FrozenProofProfile> {
    validate_frozen_fri_soundness_profile()?;
    let public_bindings =
        validated_frozen_fri_public_statement(canonical_statement, input_identity_shake256_hex)?;
    let canonical_header = canonical_proof_object_header_bytes(canonical_statement)
        .map_err(|error| failure("construct canonical proof header", error))?;
    let suite_identifier = hash_framed_parts_512(
        "sealed-lattice/proof-backend-bakeoff/synthetic-suite/v1",
        &[canonical_statement, input_identity_shake256_hex.as_bytes()],
    );
    let schedule = transcript_schedule()?;
    let catalog = frozen_catalog(
        &public_bindings.canonical_core_statement,
        input_identity_shake256_hex,
        &schedule,
    )?;
    let layout = ProofBodyLayout::new(
        catalog,
        &schedule,
        u32::try_from(TERMINAL_COEFFICIENT_COUNT)
            .map_err(|_| "terminal coefficient count does not fit u32".to_owned())?,
    )
    .map_err(|error| failure("construct frozen proof body layout", error))?;
    Ok(FrozenProofProfile {
        suite_identifier,
        application_statement_schema_identifier: SYNTHETIC_APPLICATION_SCHEMA_IDENTIFIER,
        canonical_core_statement: public_bindings.canonical_core_statement,
        canonical_header,
        expected_fri_base_root: public_bindings.expected_fri_base_root,
        schedule,
        layout,
    })
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn frozen_catalog(
    canonical_catalog_statement: &[u8],
    input_identity_shake256_hex: &str,
    schedule: &CommonProofTranscriptSchedule,
) -> ProofBackendBakeoffResult<CompleteProofTreeCatalog> {
    proof_catalog_with_public_base_width(
        canonical_catalog_statement,
        input_identity_shake256_hex,
        schedule,
        COLUMN_COUNT,
    )
}

fn proof_catalog_with_public_base_width(
    canonical_catalog_statement: &[u8],
    input_identity_shake256_hex: &str,
    schedule: &CommonProofTranscriptSchedule,
    public_base_leaf_column_count: usize,
) -> ProofBackendBakeoffResult<CompleteProofTreeCatalog> {
    if public_base_leaf_column_count < COLUMN_COUNT {
        return Err("public base tree cannot omit an algebraic source column".to_owned());
    }
    let catalog_header = canonical_proof_object_header_bytes(canonical_catalog_statement)
        .map_err(|error| failure("construct canonical catalog header", error))?;
    let catalog_suite_identifier = hash_framed_parts_512(
        "sealed-lattice/proof-backend-bakeoff/synthetic-suite/v1",
        &[
            canonical_catalog_statement,
            input_identity_shake256_hex.as_bytes(),
        ],
    );
    let catalog = build_complete_proof_tree_catalog(
        ProofTreeCatalogInput {
            suite_identifier: catalog_suite_identifier,
            canonical_proof_object_header_bytes: catalog_header,
            application_statement_schema_identifier: SYNTHETIC_APPLICATION_SCHEMA_IDENTIFIER,
            proof_field_index: PROOF_FIELD_INDEX,
            evaluation_domain_size: u64::try_from(EVALUATION_DOMAIN_SIZE)
                .map_err(|_| "evaluation domain size does not fit u64".to_owned())?,
            relation_trees: vec![RelationProofTreeInput::ProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                row_width: u32::try_from(public_base_leaf_column_count)
                    .map_err(|_| "column count does not fit u32".to_owned())?,
                leaf_visibility: ProofLeafVisibility::Public,
            }],
        },
        schedule,
    )
    .map_err(|error| failure("construct frozen proof tree catalog", error))?;
    validate_catalog(&catalog, public_base_leaf_column_count)?;
    Ok(catalog)
}

fn validate_catalog(
    catalog: &CompleteProofTreeCatalog,
    public_base_leaf_column_count: usize,
) -> ProofBackendBakeoffResult<()> {
    let entries = catalog.entries();
    if entries.len() != TREE_COUNT
        || !matches!(
            entries[0].source(),
            ProofTreeCatalogSource::RelationProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                tree_ordinal: 0,
            }
        )
        || entries[1].source()
            != (ProofTreeCatalogSource::QuotientComponent {
                component_ordinal: 0,
            })
    {
        return Err("frozen proof tree catalog prefix is not base then quotient".to_owned());
    }
    let base_context = entries[0]
        .common_context()
        .ok_or_else(|| "public base tree does not use the common Merkle context".to_owned())?;
    if usize::try_from(base_context.row_width())
        .map_err(|_| "public base row width does not fit usize".to_owned())?
        != public_base_leaf_column_count
        || base_context.leaf_visibility() != ProofLeafVisibility::Public
    {
        return Err("public base tree catalog geometry changed".to_owned());
    }
    for fold_ordinal in 0..FRI_FOLD_COUNT - 1 {
        if entries[fold_ordinal + 2].source()
            != (ProofTreeCatalogSource::NonterminalFriLayer {
                fold_ordinal: u16::try_from(fold_ordinal)
                    .map_err(|_| "FRI fold ordinal does not fit u16".to_owned())?,
            })
        {
            return Err("frozen proof tree catalog FRI order changed".to_owned());
        }
    }
    Ok(())
}

fn evaluate_base_coefficients_at(
    coefficients: &[ProofBaseFieldElement],
    point: ProofChallengeExtensionElement,
) -> ProofChallengeExtensionElement {
    coefficients.iter().rev().fold(
        ProofChallengeExtensionElement::ZERO,
        |accumulated, coefficient| {
            accumulated
                .multiply(point)
                .add(ProofChallengeExtensionElement::from_base(*coefficient))
        },
    )
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn build_column_polynomials_and_evaluations(
    columns: &[Vec<u64>; COLUMN_COUNT],
    trace_domain: ProofEvaluationDomain,
    evaluation_domain: ProofEvaluationDomain,
) -> ProofBackendBakeoffResult<(ProofBaseFieldColumns, ProofBaseFieldColumns)> {
    let mut coefficients = Vec::with_capacity(COLUMN_COUNT);
    let mut evaluations = Vec::with_capacity(COLUMN_COUNT);
    for column in columns {
        if column.len() != TRACE_DOMAIN_SIZE {
            return Err("frozen column row count changed".to_owned());
        }
        let trace_evaluations = column
            .iter()
            .copied()
            .map(|value| {
                ProofBaseFieldElement::from_canonical(value)
                    .map_err(|error| failure("convert frozen trace value", error))
            })
            .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
        let column_coefficients = trace_domain
            .interpolate_base_polynomial(&trace_evaluations)
            .map_err(|error| failure("interpolate frozen trace column", error))?;
        if column_coefficients.is_empty()
            || column_coefficients.len() > OPENING_DEGREE_BOUND_EXCLUSIVE
        {
            return Err("frozen trace column exceeded its degree bound".to_owned());
        }
        let column_evaluations = evaluation_domain
            .evaluate_base_polynomial(&column_coefficients)
            .map_err(|error| failure("evaluate frozen trace column LDE", error))?;
        coefficients.push(column_coefficients);
        evaluations.push(column_evaluations);
    }
    let coefficients: [Vec<ProofBaseFieldElement>; COLUMN_COUNT] = coefficients
        .try_into()
        .map_err(|_| "frozen coefficient column count changed".to_owned())?;
    let evaluations: [Vec<ProofBaseFieldElement>; COLUMN_COUNT] = evaluations
        .try_into()
        .map_err(|_| "frozen LDE column count changed".to_owned())?;
    Ok((coefficients, evaluations))
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn recompute_base_tree_root(
    catalog: &CompleteProofTreeCatalog,
    column_evaluations: &[Vec<ProofBaseFieldElement>; COLUMN_COUNT],
) -> ProofBackendBakeoffResult<[u8; 64]> {
    let entry = catalog
        .entries()
        .first()
        .ok_or_else(|| "frozen catalog has no base-tree entry".to_owned())?;
    let context = entry
        .common_context()
        .ok_or_else(|| "frozen base tree does not use the common Merkle context".to_owned())?;
    let mut replay = CommonProofMerklePathReplay::new(context, &[])
        .map_err(|error| failure("initialize frozen base-root replay", error))?;
    let values = MaterializedTreeValues::BaseColumns(column_evaluations);
    let leaf_count = EVALUATION_DOMAIN_SIZE
        .checked_div(2)
        .filter(|count| *count != 0)
        .ok_or_else(|| "frozen base tree has no leaves".to_owned())?;
    for leaf_index in 0..leaf_count {
        let (first_values, opposite_values) = values.phase_pair(leaf_index)?;
        let (_, leaf_digest) = entry
            .encode_materialized_leaf(
                u64::try_from(leaf_index)
                    .map_err(|_| "frozen base leaf index does not fit u64".to_owned())?,
                None,
                first_values,
                opposite_values,
            )
            .map_err(|error| failure("encode frozen base leaf for root replay", error))?;
        replay
            .absorb_leaf_digest(
                u64::try_from(leaf_index)
                    .map_err(|_| "frozen base leaf index does not fit u64".to_owned())?,
                leaf_digest,
            )
            .map_err(|error| failure("absorb frozen base leaf digest", error))?;
    }
    let (root, frontier_coordinates, frontier_digests) = replay
        .finish(None)
        .map_err(|error| failure("finish frozen base-root replay", error))?;
    if !frontier_coordinates.is_empty() || !frontier_digests.is_empty() {
        return Err("root-only frozen base replay retained an authentication frontier".to_owned());
    }
    Ok(root)
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
pub(super) fn derive_frozen_fri_base_root(
    canonical_core_statement: &[u8],
    input_identity_shake256_hex: &str,
    columns: &[Vec<u64>; COLUMN_COUNT],
) -> ProofBackendBakeoffResult<[u8; 64]> {
    let recomputed_identity = recompute_frozen_input_identity(columns)?;
    if recomputed_identity != input_identity_shake256_hex {
        return Err("FRI base-root input does not match the exact raw-input identity".to_owned());
    }
    validate_frozen_core_statement(canonical_core_statement, input_identity_shake256_hex)?;
    validate_frozen_fri_soundness_profile()?;
    let schedule = transcript_schedule()?;
    let catalog = frozen_catalog(
        canonical_core_statement,
        input_identity_shake256_hex,
        &schedule,
    )?;
    let trace_domain = ProofEvaluationDomain::new_subgroup(TRACE_DOMAIN_SIZE)
        .map_err(|error| failure("construct root-derivation trace subgroup", error))?;
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .map_err(|error| failure("construct root-derivation evaluation coset", error))?;
    let (_, column_evaluations) =
        build_column_polynomials_and_evaluations(columns, trace_domain, evaluation_domain)?;
    recompute_base_tree_root(&catalog, &column_evaluations)
}

fn add_base_source_polynomial_to_initial_fri(
    initial_fri_coefficients: &mut [ProofChallengeExtensionElement],
    source_coefficients: &[ProofBaseFieldElement],
    batching_coefficient: ProofChallengeExtensionElement,
) -> ProofBackendBakeoffResult<()> {
    if initial_fri_coefficients.len() != OPENING_DEGREE_BOUND_EXCLUSIVE
        || source_coefficients.is_empty()
        || source_coefficients.len() > OPENING_DEGREE_BOUND_EXCLUSIVE
    {
        return Err("frozen base source polynomial has the wrong batching shape".to_owned());
    }
    for (destination, source) in initial_fri_coefficients
        .iter_mut()
        .zip(source_coefficients.iter().copied())
    {
        *destination = destination
            .add(ProofChallengeExtensionElement::from_base(source).multiply(batching_coefficient));
    }
    Ok(())
}

fn add_extension_source_polynomial_to_initial_fri(
    initial_fri_coefficients: &mut [ProofChallengeExtensionElement],
    source_coefficients: &[ProofChallengeExtensionElement],
    batching_coefficient: ProofChallengeExtensionElement,
) -> ProofBackendBakeoffResult<()> {
    if initial_fri_coefficients.len() != OPENING_DEGREE_BOUND_EXCLUSIVE
        || source_coefficients.is_empty()
        || source_coefficients.len() > OPENING_DEGREE_BOUND_EXCLUSIVE
    {
        return Err("frozen extension source polynomial has the wrong batching shape".to_owned());
    }
    for (destination, source) in initial_fri_coefficients
        .iter_mut()
        .zip(source_coefficients.iter().copied())
    {
        *destination = destination.add(source.multiply(batching_coefficient));
    }
    Ok(())
}

fn affine_residual(
    values: &[ProofChallengeExtensionElement],
    first_column_index: usize,
    material_radix: ProofBaseFieldElement,
    ciphertext_modulus: ProofBaseFieldElement,
) -> ProofBackendBakeoffResult<ProofChallengeExtensionElement> {
    let digit_zero = *values
        .get(first_column_index)
        .ok_or_else(|| "missing frozen digit-zero value".to_owned())?;
    let digit_one = *values
        .get(first_column_index + 1)
        .ok_or_else(|| "missing frozen digit-one value".to_owned())?;
    let shifted_secret = *values
        .get(first_column_index + 2)
        .ok_or_else(|| "missing frozen shifted-secret value".to_owned())?;
    let negative_indicator = *values
        .get(first_column_index + 3)
        .ok_or_else(|| "missing frozen negative-indicator value".to_owned())?;
    Ok(digit_zero
        .add(digit_one.multiply_base(material_radix))
        .subtract(shifted_secret)
        .add(ProofChallengeExtensionElement::ONE)
        .subtract(negative_indicator.multiply_base(ciphertext_modulus)))
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn construct_full_quotient_evaluations(
    evaluation_domain: ProofEvaluationDomain,
    column_evaluations: &[Vec<ProofBaseFieldElement>; COLUMN_COUNT],
    composition_challenges: &[ProofChallengeExtensionElement],
) -> ProofBackendBakeoffResult<Vec<ProofChallengeExtensionElement>> {
    if composition_challenges.len() != 2
        || column_evaluations
            .iter()
            .any(|column| column.len() != EVALUATION_DOMAIN_SIZE)
    {
        return Err("frozen quotient input shape changed".to_owned());
    }
    let material_radix = ProofBaseFieldElement::from_canonical(MATERIAL_RADIX)
        .map_err(|error| failure("convert frozen material radix", error))?;
    let ciphertext_modulus = ProofBaseFieldElement::from_canonical(CIPHERTEXT_MODULUS)
        .map_err(|error| failure("convert frozen ciphertext modulus", error))?;
    let mut quotient_evaluations = Vec::with_capacity(EVALUATION_DOMAIN_SIZE);
    for evaluation_position in 0..EVALUATION_DOMAIN_SIZE {
        let values: [ProofChallengeExtensionElement; COLUMN_COUNT] =
            std::array::from_fn(|column_index| {
                ProofChallengeExtensionElement::from_base(
                    column_evaluations[column_index][evaluation_position],
                )
            });
        let first_residual = affine_residual(&values, 0, material_radix, ciphertext_modulus)?;
        let second_residual = affine_residual(&values, 4, material_radix, ciphertext_modulus)?;
        let evaluation_point = ProofChallengeExtensionElement::from_base(
            evaluation_domain
                .point(evaluation_position)
                .map_err(|error| failure("derive quotient evaluation point", error))?,
        );
        let trace_zeroifier = evaluation_point
            .power(
                u64::try_from(TRACE_DOMAIN_SIZE)
                    .map_err(|_| "trace domain size does not fit u64".to_owned())?,
            )
            .subtract(ProofChallengeExtensionElement::ONE);
        if trace_zeroifier.is_zero() {
            return Err("evaluation coset intersects the trace subgroup".to_owned());
        }
        let composed_numerator = composition_challenges[0]
            .multiply(first_residual)
            .add(composition_challenges[1].multiply(second_residual));
        quotient_evaluations.push(
            composed_numerator
                .divide(trace_zeroifier)
                .map_err(|error| failure("normalize frozen quotient evaluation", error))?,
        );
    }
    Ok(quotient_evaluations)
}

fn deep_point_is_forbidden(
    candidate: ProofChallengeExtensionElement,
    evaluation_domain: ProofEvaluationDomain,
) -> bool {
    if candidate.is_zero() {
        return true;
    }
    let trace_collision =
        candidate.power(TRACE_DOMAIN_SIZE as u64) == ProofChallengeExtensionElement::ONE;
    let coordinates = candidate.canonical_coordinates();
    let candidate_is_in_base_field = coordinates[1..].iter().all(|coordinate| *coordinate == 0);
    let evaluation_coset_collision = candidate_is_in_base_field
        && candidate.power(EVALUATION_DOMAIN_SIZE as u64)
            == ProofChallengeExtensionElement::from_base(
                evaluation_domain
                    .coset_offset()
                    .power(EVALUATION_DOMAIN_SIZE as u64),
            );
    trace_collision || evaluation_coset_collision
}

#[cfg(test)]
fn test_extension(value: u64) -> ProofChallengeExtensionElement {
    ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(value).expect("small canonical test value"),
    )
}

#[test]
fn packed_deep_fri_filter_excludes_every_denominator_and_shift_collision() {
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .expect("construct frozen evaluation coset");
    assert!(deep_point_is_forbidden(
        ProofChallengeExtensionElement::ZERO,
        evaluation_domain,
    ));
    assert!(deep_point_is_forbidden(
        ProofChallengeExtensionElement::ONE,
        evaluation_domain,
    ));
    assert!(deep_point_is_forbidden(
        ProofChallengeExtensionElement::from_base(evaluation_domain.coset_offset()),
        evaluation_domain,
    ));
    assert!(!deep_point_is_forbidden(
        ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
            .expect("canonical non-base-field point"),
        evaluation_domain,
    ));
}

#[test]
fn shifted_opening_batch_exposes_the_exact_degree_gap_counterexample() {
    let opening_point = test_extension(3);
    let evaluation_point = test_extension(7);
    let mut degree_four_source = vec![ProofChallengeExtensionElement::ZERO; 5];
    degree_four_source[4] = ProofChallengeExtensionElement::ONE;
    let opened_value = opening_point.power(4);
    let unshifted_normalized = vec![
        opening_point.power(3),
        opening_point.power(2),
        opening_point,
        ProofChallengeExtensionElement::ONE,
    ];
    let normalized_evaluation =
        super::evaluate_extension_at(&unshifted_normalized, evaluation_point);
    assert_eq!(
        normalized_evaluation,
        super::evaluate_extension_at(&degree_four_source, evaluation_point)
            .subtract(opened_value)
            .divide(evaluation_point.subtract(opening_point))
            .expect("noncolliding evaluation point"),
    );
    assert_eq!(unshifted_normalized.len(), 4);

    let mut shifted_normalized = vec![ProofChallengeExtensionElement::ZERO];
    shifted_normalized.extend_from_slice(&unshifted_normalized);
    assert_eq!(shifted_normalized.len(), 5);
    assert_eq!(
        super::evaluate_extension_at(&shifted_normalized, evaluation_point),
        evaluation_point.multiply(normalized_evaluation),
    );

    let combined_leading_coefficient = degree_four_source[4].add(shifted_normalized[4]);
    assert_eq!(combined_leading_coefficient, test_extension(2),);
}

#[test]
fn shifted_opening_batch_prover_and_verifier_use_the_same_polynomial() {
    let source_coefficients = vec![
        test_extension(5),
        test_extension(2),
        test_extension(7),
        ProofChallengeExtensionElement::ONE,
    ];
    let opening_point = test_extension(13);
    let opened_value = super::evaluate_extension_at(&source_coefficients, opening_point);
    let batching_coefficient = test_extension(11);
    let mut prover_coefficients = vec![ProofChallengeExtensionElement::ZERO; 4];
    add_bakeoff_polynomial_to_initial_fri(
        &mut prover_coefficients,
        5,
        4,
        CommonProofSourcePolynomial::from_extension_coefficients(source_coefficients.clone()),
        opening_point,
        opened_value,
        batching_coefficient,
    )
    .expect("construct shifted normalized opening polynomial");
    assert_eq!(prover_coefficients[0], ProofChallengeExtensionElement::ZERO,);

    let evaluation_point =
        ProofBaseFieldElement::from_canonical(7).expect("small canonical evaluation point");
    let positive_point = ProofChallengeExtensionElement::from_base(evaluation_point);
    let opposite_point = ProofChallengeExtensionElement::from_base(evaluation_point.negate());
    let source_pair = OpenedFriLayerPair::new(
        super::evaluate_extension_at(&source_coefficients, positive_point),
        super::evaluate_extension_at(&source_coefficients, opposite_point),
    );
    let verifier_pair = evaluate_initial_fri_pair(
        5,
        evaluation_point,
        &[ProofOpeningClaimEvaluation::new(
            4,
            opening_point,
            opened_value,
            source_pair,
            batching_coefficient,
        )],
        None,
    )
    .expect("evaluate shifted normalized opening pair");
    assert_eq!(
        verifier_pair,
        OpenedFriLayerPair::new(
            super::evaluate_extension_at(&prover_coefficients, positive_point),
            super::evaluate_extension_at(&prover_coefficients, opposite_point),
        ),
    );
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrozenExternalMemoryAccounting {
    peak_stored_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count: u64,
    object_count: u32,
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
impl FrozenExternalMemoryAccounting {
    fn total_io_byte_length(self) -> ProofBackendBakeoffResult<u64> {
        self.total_written_byte_length
            .checked_add(self.total_read_byte_length)
            .ok_or_else(|| "external I/O byte length overflowed".to_owned())
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn exact_chunk_count(
    exact_byte_length: u64,
    chunk_byte_length: u64,
) -> ProofBackendBakeoffResult<u64> {
    if exact_byte_length == 0 || chunk_byte_length == 0 {
        return Err("external-memory chunk count requires nonzero lengths".to_owned());
    }
    exact_byte_length
        .checked_add(chunk_byte_length - 1)
        .and_then(|rounded| rounded.checked_div(chunk_byte_length))
        .ok_or_else(|| "external-memory chunk count overflowed".to_owned())
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
pub(super) const PUBLIC_SOURCE_RECIPE_DOMAIN: &str =
    "sealed-lattice/proof-storage/public-column-replay/v1";
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
pub(super) const PUBLIC_SOURCE_INPUT_IDENTITY_HASH_DOMAIN: &str =
    "proof-storage/public-source-input/v1";
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
pub(super) const PUBLIC_SOURCE_DERIVATION_ALGORITHM_IDENTIFIER: &str =
    "splitmix64-column-row-goldilocks-canonical-v1";
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
pub(super) const PUBLIC_SOURCE_SEED_HEX: &str = "6a09e667f3bcc909";
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
const PUBLIC_SOURCE_SEED: u64 = 0x6a09_e667_f3bc_c909;
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) const WIDTH_BACKEND_PROFILE_IDENTIFIER: &str =
    "packed-deep-fri-goldilocks5-rate-1-8-six-fold-rs256-183-query-v1";
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) const WIDTH_CUSTODY_SCHEMA_IDENTIFIER: &str = "bounded-external-storage-replay-v1";
#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) const WIDTH_RELEASE_PROFILE_IDENTIFIER: &str = "release-desktop-browser-wasm-v1";
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
pub(super) const WIDTH_REPRESENTATIVE_BROWSER_COLUMN_COUNT: usize = 512;
#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
const PUBLIC_WIDTH_STATEMENT_DOMAIN: &str =
    "sealed-lattice/proof-replay-evidence/packed-deep-fri-statement/v1";

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PublicSourceReplayAccounting {
    total_read_byte_length: u64,
    total_written_byte_length: u64,
    transaction_count: u64,
    lde_transform_count: u64,
    absorbed_leaf_value_count: u64,
    opened_value_count: u64,
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) fn validate_native_custody_path_byte_length(
    path: &Path,
    description: &str,
) -> ProofBackendBakeoffResult<()> {
    if path.as_os_str().as_encoded_bytes().len() > WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH {
        return Err(format!(
            "{description} exceeds the bounded native custody path length"
        ));
    }
    Ok(())
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
struct PublicSourceReplayCustody {
    directory_path: PathBuf,
    object_paths: Vec<PathBuf>,
    artifact_path: Option<PathBuf>,
    input_identity_shake256_hex: String,
    accounting: PublicSourceReplayAccounting,
    finished: bool,
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
struct PublicSourceCustodyConstructionGuard {
    directory_path: PathBuf,
    object_paths: Vec<PathBuf>,
    directory_created: bool,
    armed: bool,
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
impl PublicSourceCustodyConstructionGuard {
    fn new(directory_path: PathBuf, object_capacity: usize) -> ProofBackendBakeoffResult<Self> {
        let mut object_paths = Vec::new();
        object_paths
            .try_reserve_exact(object_capacity)
            .map_err(|_| "public source replay catalog allocation failed".to_owned())?;
        Ok(Self {
            directory_path,
            object_paths,
            directory_created: false,
            armed: true,
        })
    }

    fn mark_directory_created(&mut self) {
        self.directory_created = true;
    }

    fn disarm(mut self) -> Vec<PathBuf> {
        self.armed = false;
        std::mem::take(&mut self.object_paths)
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
impl Drop for PublicSourceCustodyConstructionGuard {
    fn drop(&mut self) {
        if self.armed {
            for object_path in &self.object_paths {
                let _ = fs::remove_file(object_path);
            }
            if self.directory_created {
                let _ = fs::remove_dir(&self.directory_path);
            }
        }
    }
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn public_source_identity_hasher(
    frozen_input_identity_shake256_hex: &str,
    public_base_leaf_column_count: usize,
) -> ProofBackendBakeoffResult<StreamingHash512> {
    let width = u64::try_from(public_base_leaf_column_count)
        .map_err(|_| "public base width does not fit u64".to_owned())?;
    let row_count = u64::try_from(TRACE_DOMAIN_SIZE)
        .map_err(|_| "public source row count does not fit u64".to_owned())?;
    let value_byte_length = width
        .checked_mul(row_count)
        .and_then(|count| count.checked_mul(8))
        .ok_or_else(|| "public source identity byte length overflowed".to_owned())?;
    let mut hasher = StreamingHash512::new(PUBLIC_SOURCE_INPUT_IDENTITY_HASH_DOMAIN, 5);
    hasher.absorb_part(frozen_input_identity_shake256_hex.as_bytes());
    hasher.absorb_part(PUBLIC_SOURCE_RECIPE_DOMAIN.as_bytes());
    hasher.absorb_part(&width.to_le_bytes());
    hasher.absorb_part(&row_count.to_le_bytes());
    hasher.begin_part(value_byte_length);
    Ok(hasher)
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn public_source_value(
    fixture: &ProofBackendBakeoffFixture,
    column_index: usize,
    row_index: usize,
) -> u64 {
    if column_index < COLUMN_COUNT {
        fixture.columns[column_index][row_index]
    } else {
        deterministic_public_source_value(column_index, row_index)
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) fn derive_public_source_input_identity(
    fixture: &ProofBackendBakeoffFixture,
    public_base_leaf_column_count: usize,
) -> ProofBackendBakeoffResult<String> {
    if !(MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT..=MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT)
        .contains(&public_base_leaf_column_count)
        || fixture
            .columns
            .iter()
            .any(|column| column.len() != TRACE_DOMAIN_SIZE)
    {
        return Err("public source identity geometry is invalid".to_owned());
    }
    let mut hasher = public_source_identity_hasher(
        &fixture.input_identity_shake256_hex,
        public_base_leaf_column_count,
    )?;
    let chunk_byte_length = usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
        .map_err(|_| "external-memory chunk length does not fit usize".to_owned())?;
    let mut chunk = Vec::with_capacity(chunk_byte_length);
    for column_index in 0..public_base_leaf_column_count {
        for row_index in 0..TRACE_DOMAIN_SIZE {
            chunk.extend_from_slice(
                &public_source_value(fixture, column_index, row_index).to_le_bytes(),
            );
            if chunk.len() == chunk_byte_length {
                hasher.absorb_raw(&chunk);
                chunk.clear();
            }
        }
    }
    if !chunk.is_empty() {
        hasher.absorb_raw(&chunk);
    }
    Ok(to_hex(&hasher.finalize()))
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
impl PublicSourceReplayCustody {
    fn new(
        fixture: &ProofBackendBakeoffFixture,
        public_base_leaf_column_count: usize,
        directory_path: PathBuf,
    ) -> ProofBackendBakeoffResult<Self> {
        Self::new_with_injected_create_failure(
            fixture,
            public_base_leaf_column_count,
            directory_path,
            None,
        )
    }

    fn new_with_injected_create_failure(
        fixture: &ProofBackendBakeoffFixture,
        public_base_leaf_column_count: usize,
        directory_path: PathBuf,
        fail_after_created_column: Option<usize>,
    ) -> ProofBackendBakeoffResult<Self> {
        if !(MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT..=MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT)
            .contains(&public_base_leaf_column_count)
        {
            return Err(format!(
                "public base width must be in {MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT}..={MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT}"
            ));
        }
        if fixture
            .columns
            .iter()
            .any(|column| column.len() != TRACE_DOMAIN_SIZE)
        {
            return Err("frozen algebraic source geometry changed".to_owned());
        }
        validate_native_custody_path_byte_length(
            &directory_path,
            "public source custody directory",
        )?;
        if !directory_path.is_absolute() || directory_path.exists() {
            return Err("public source custody directory must be a new absolute path".to_owned());
        }
        let directory_path = directory_path.into_boxed_path().into_path_buf();
        let mut construction_guard = PublicSourceCustodyConstructionGuard::new(
            directory_path.clone(),
            public_base_leaf_column_count,
        )?;
        fs::create_dir(&directory_path)
            .map_err(|error| format!("create public source custody directory: {error}"))?;
        construction_guard.mark_directory_created();
        let width = u64::try_from(public_base_leaf_column_count)
            .map_err(|_| "public base width does not fit u64".to_owned())?;
        let mut identity_hasher = public_source_identity_hasher(
            &fixture.input_identity_shake256_hex,
            public_base_leaf_column_count,
        )?;

        let mut accounting = PublicSourceReplayAccounting::default();
        for column_index in 0..public_base_leaf_column_count {
            let object_path = directory_path
                .join(format!("public-column-{column_index:04}.bin"))
                .into_boxed_path()
                .into_path_buf();
            validate_native_custody_path_byte_length(&object_path, "public source custody object")?;
            let mut object = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&object_path)
                .map_err(|error| format!("create public source object: {error}"))?;
            construction_guard.object_paths.push(object_path);
            if fail_after_created_column == Some(column_index) {
                return Err("injected public source construction failure".to_owned());
            }
            accounting.transaction_count = accounting
                .transaction_count
                .checked_add(1)
                .ok_or_else(|| "public source create-transaction count overflowed".to_owned())?;
            let mut chunk = Vec::with_capacity(
                usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
                    .map_err(|_| "external-memory chunk length does not fit usize".to_owned())?,
            );
            for row_index in 0..TRACE_DOMAIN_SIZE {
                let value = public_source_value(fixture, column_index, row_index);
                let encoded = value.to_le_bytes();
                identity_hasher.absorb_raw(&encoded);
                chunk.extend_from_slice(&encoded);
                if chunk.len()
                    == usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
                        .map_err(|_| "external-memory chunk length does not fit usize".to_owned())?
                {
                    object
                        .write_all(&chunk)
                        .map_err(|error| format!("write public source object range: {error}"))?;
                    accounting.total_written_byte_length = accounting
                        .total_written_byte_length
                        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                            "public source write length does not fit u64".to_owned()
                        })?)
                        .ok_or_else(|| "public source written-byte count overflowed".to_owned())?;
                    accounting.transaction_count =
                        accounting.transaction_count.checked_add(1).ok_or_else(|| {
                            "public source write-transaction count overflowed".to_owned()
                        })?;
                    chunk.clear();
                }
            }
            if !chunk.is_empty() {
                object
                    .write_all(&chunk)
                    .map_err(|error| format!("write final public source object range: {error}"))?;
                accounting.total_written_byte_length =
                    accounting
                        .total_written_byte_length
                        .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                            "public source write length does not fit u64".to_owned()
                        })?)
                        .ok_or_else(|| "public source written-byte count overflowed".to_owned())?;
                accounting.transaction_count = accounting
                    .transaction_count
                    .checked_add(1)
                    .ok_or_else(|| "public source write-transaction count overflowed".to_owned())?;
            }
            object
                .sync_all()
                .map_err(|error| format!("durably seal public source object: {error}"))?;
            accounting.transaction_count = accounting
                .transaction_count
                .checked_add(1)
                .ok_or_else(|| "public source seal-transaction count overflowed".to_owned())?;
            let exact_length = object
                .metadata()
                .map_err(|error| format!("inspect public source object: {error}"))?
                .len();
            if exact_length != PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN {
                return Err("public source object length changed during custody".to_owned());
            }
        }
        let expected_written_byte_length = PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN
            .checked_mul(width)
            .ok_or_else(|| "public source written-byte count overflowed".to_owned())?;
        if accounting.total_written_byte_length != expected_written_byte_length {
            return Err("public source custody did not write every source byte".to_owned());
        }
        let object_paths = construction_guard.disarm();
        Ok(Self {
            directory_path,
            object_paths,
            artifact_path: None,
            input_identity_shake256_hex: to_hex(&identity_hasher.finalize()),
            accounting,
            finished: false,
        })
    }

    fn evaluate_column(
        &mut self,
        column_index: usize,
        trace_domain: ProofEvaluationDomain,
        evaluation_domain: ProofEvaluationDomain,
        retain_coefficients: bool,
        mut identity_hasher: Option<&mut StreamingHash512>,
    ) -> ProofBackendBakeoffResult<(
        Vec<ProofBaseFieldElement>,
        Option<Vec<ProofBaseFieldElement>>,
    )> {
        let object_path = self
            .object_paths
            .get(column_index)
            .ok_or_else(|| "public source replay column is missing".to_owned())?;

        let mut object = File::open(object_path)
            .map_err(|error| format!("open public source object: {error}"))?;
        let mut working = Vec::with_capacity(TRACE_DOMAIN_SIZE);
        let mut remaining_byte_length = PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN;
        let mut chunk = vec![
            0_u8;
            usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH).map_err(|_| {
                "external-memory chunk length does not fit usize".to_owned()
            })?
        ];
        while remaining_byte_length != 0 {
            let read_byte_length = usize::try_from(
                remaining_byte_length.min(u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)),
            )
            .map_err(|_| "public source read length does not fit usize".to_owned())?;
            object
                .read_exact(&mut chunk[..read_byte_length])
                .map_err(|error| format!("read public source object range: {error}"))?;
            if let Some(hasher) = identity_hasher.as_mut() {
                hasher.absorb_raw(&chunk[..read_byte_length]);
            }
            if read_byte_length % 8 != 0 {
                return Err("public source range split one field element".to_owned());
            }
            for encoded in chunk[..read_byte_length].chunks_exact(8) {
                let value =
                    u64::from_le_bytes(encoded.try_into().map_err(|_| {
                        "public source field encoding is not eight bytes".to_owned()
                    })?);
                working.push(
                    ProofBaseFieldElement::from_canonical(value)
                        .map_err(|error| failure("convert public source value", error))?,
                );
            }
            let read_byte_length_u64 = u64::try_from(read_byte_length)
                .map_err(|_| "public source read length does not fit u64".to_owned())?;
            self.accounting.total_read_byte_length = self
                .accounting
                .total_read_byte_length
                .checked_add(read_byte_length_u64)
                .ok_or_else(|| "public source read-byte count overflowed".to_owned())?;
            self.accounting.transaction_count = self
                .accounting
                .transaction_count
                .checked_add(1)
                .ok_or_else(|| "public source read-transaction count overflowed".to_owned())?;
            remaining_byte_length -= read_byte_length_u64;
        }
        let mut trailing = [0_u8; 1];
        if object
            .read(&mut trailing)
            .map_err(|error| format!("check public source object boundary: {error}"))?
            != 0
            || working.len() != TRACE_DOMAIN_SIZE
        {
            return Err("public source replay object has the wrong exact length".to_owned());
        }
        trace_domain
            .interpolate_base_polynomial_in_place(&mut working)
            .map_err(|error| failure("interpolate replayed public source", error))?;
        if working.is_empty() || working.len() > OPENING_DEGREE_BOUND_EXCLUSIVE {
            return Err("replayed public source exceeded its degree bound".to_owned());
        }
        let retained_coefficients = retain_coefficients.then(|| working.clone());
        evaluation_domain
            .evaluate_base_polynomial_in_place(&mut working)
            .map_err(|error| failure("evaluate replayed public source LDE", error))?;
        if working.len() != EVALUATION_DOMAIN_SIZE {
            return Err("replayed public source LDE has the wrong length".to_owned());
        }
        self.accounting.lde_transform_count = self
            .accounting
            .lde_transform_count
            .checked_add(1)
            .ok_or_else(|| "public source LDE-transform count overflowed".to_owned())?;
        Ok((working, retained_coefficients))
    }

    fn record_absorbed_leaf_values(&mut self, count: usize) -> ProofBackendBakeoffResult<()> {
        self.accounting.absorbed_leaf_value_count = self
            .accounting
            .absorbed_leaf_value_count
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| "absorbed public leaf value count does not fit u64".to_owned())?,
            )
            .ok_or_else(|| "absorbed public leaf value count overflowed".to_owned())?;
        Ok(())
    }

    fn record_opened_values(&mut self, count: usize) -> ProofBackendBakeoffResult<()> {
        self.accounting.opened_value_count = self
            .accounting
            .opened_value_count
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| "opened public value count does not fit u64".to_owned())?,
            )
            .ok_or_else(|| "opened public value count overflowed".to_owned())?;
        Ok(())
    }

    fn accounting(&self) -> PublicSourceReplayAccounting {
        self.accounting
    }

    fn object_count(&self) -> usize {
        self.object_paths.len()
    }

    fn exact_input_identity(
        &mut self,
        frozen_input_identity_shake256_hex: &str,
    ) -> ProofBackendBakeoffResult<String> {
        let mut hasher = public_source_identity_hasher(
            frozen_input_identity_shake256_hex,
            self.object_paths.len(),
        )?;
        let mut total_read_byte_length = 0_u64;
        let mut transaction_count = 0_u64;
        for object_path in &self.object_paths {
            let mut object = File::open(object_path)
                .map_err(|error| format!("open public source identity object: {error}"))?;
            let mut remaining_byte_length = PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN;
            let mut chunk = vec![
                0_u8;
                usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH).map_err(
                    |_| "external-memory chunk length does not fit usize".to_owned()
                )?
            ];
            while remaining_byte_length != 0 {
                let read_byte_length = usize::try_from(
                    remaining_byte_length.min(u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)),
                )
                .map_err(|_| "public source identity read length does not fit usize".to_owned())?;
                object
                    .read_exact(&mut chunk[..read_byte_length])
                    .map_err(|error| format!("read public source identity range: {error}"))?;
                hasher.absorb_raw(&chunk[..read_byte_length]);
                let read_byte_length_u64 = u64::try_from(read_byte_length).map_err(|_| {
                    "public source identity read length does not fit u64".to_owned()
                })?;
                total_read_byte_length = total_read_byte_length
                    .checked_add(read_byte_length_u64)
                    .ok_or_else(|| {
                    "public source identity read-byte count overflowed".to_owned()
                })?;
                transaction_count = transaction_count.checked_add(1).ok_or_else(|| {
                    "public source identity read-transaction count overflowed".to_owned()
                })?;
                remaining_byte_length -= read_byte_length_u64;
            }
            if object
                .read(&mut [0_u8; 1])
                .map_err(|error| format!("check public source identity boundary: {error}"))?
                != 0
            {
                return Err("public source identity object has trailing bytes".to_owned());
            }
        }
        self.accounting.total_read_byte_length = self
            .accounting
            .total_read_byte_length
            .checked_add(total_read_byte_length)
            .ok_or_else(|| "public source identity read-byte count overflowed".to_owned())?;
        self.accounting.transaction_count = self
            .accounting
            .transaction_count
            .checked_add(transaction_count)
            .ok_or_else(|| "public source identity read-transaction count overflowed".to_owned())?;
        Ok(to_hex(&hasher.finalize()))
    }

    fn checked_input_identity(&self) -> &str {
        &self.input_identity_shake256_hex
    }

    fn append_counted_ranges(
        &mut self,
        object: &mut File,
        bytes: &[u8],
    ) -> ProofBackendBakeoffResult<()> {
        let chunk_byte_length = usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            .map_err(|_| "external-memory chunk length does not fit usize".to_owned())?;
        for chunk in bytes.chunks(chunk_byte_length) {
            object
                .write_all(chunk)
                .map_err(|error| format!("append canonical artifact range: {error}"))?;
            self.accounting.total_written_byte_length = self
                .accounting
                .total_written_byte_length
                .checked_add(
                    u64::try_from(chunk.len())
                        .map_err(|_| "artifact append length does not fit u64".to_owned())?,
                )
                .ok_or_else(|| "artifact written-byte count overflowed".to_owned())?;
            self.accounting.transaction_count = self
                .accounting
                .transaction_count
                .checked_add(1)
                .ok_or_else(|| "artifact append-transaction count overflowed".to_owned())?;
        }
        Ok(())
    }

    fn read_counted_ranges(
        &mut self,
        object: &mut File,
        destination: &mut [u8],
    ) -> ProofBackendBakeoffResult<()> {
        let chunk_byte_length = usize::try_from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH)
            .map_err(|_| "external-memory chunk length does not fit usize".to_owned())?;
        for chunk in destination.chunks_mut(chunk_byte_length) {
            object
                .read_exact(chunk)
                .map_err(|error| format!("read canonical artifact range: {error}"))?;
            self.accounting.total_read_byte_length = self
                .accounting
                .total_read_byte_length
                .checked_add(
                    u64::try_from(chunk.len())
                        .map_err(|_| "artifact read length does not fit u64".to_owned())?,
                )
                .ok_or_else(|| "artifact read-byte count overflowed".to_owned())?;
            self.accounting.transaction_count = self
                .accounting
                .transaction_count
                .checked_add(1)
                .ok_or_else(|| "artifact read-transaction count overflowed".to_owned())?;
        }
        Ok(())
    }

    fn store_canonical_artifact(
        &mut self,
        canonical_artifact: &[u8],
        opened_leaf_element_ranges: &[(usize, usize)],
    ) -> ProofBackendBakeoffResult<(u64, u64, u64)> {
        self.store_canonical_artifact_with_injected_failure(
            canonical_artifact,
            opened_leaf_element_ranges,
            false,
        )
    }

    fn store_canonical_artifact_with_injected_failure(
        &mut self,
        canonical_artifact: &[u8],
        opened_leaf_element_ranges: &[(usize, usize)],
        fail_after_preleaf_write: bool,
    ) -> ProofBackendBakeoffResult<(u64, u64, u64)> {
        if canonical_artifact.is_empty()
            || self.artifact_path.is_some()
            || opened_leaf_element_ranges.is_empty()
            || !opened_leaf_element_ranges
                .windows(2)
                .all(|pair| pair[0].1 == pair[1].0)
            || opened_leaf_element_ranges
                .last()
                .is_some_and(|range| range.1 > canonical_artifact.len())
        {
            return Err("canonical artifact range plan is invalid".to_owned());
        }
        let artifact_path = self
            .directory_path
            .join("canonical-proof.bin")
            .into_boxed_path()
            .into_path_buf();
        validate_native_custody_path_byte_length(
            &artifact_path,
            "canonical artifact custody object",
        )?;
        let mut object = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&artifact_path)
            .map_err(|error| format!("create canonical artifact object: {error}"))?;
        self.artifact_path = Some(artifact_path);
        self.accounting.transaction_count = self
            .accounting
            .transaction_count
            .checked_add(1)
            .ok_or_else(|| "artifact create-transaction count overflowed".to_owned())?;
        let first_range_start = opened_leaf_element_ranges[0].0;
        let pre_leaf_chunk_count = exact_chunk_count(
            u64::try_from(first_range_start)
                .map_err(|_| "pre-leaf artifact length does not fit u64".to_owned())?,
            u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
        )?;
        self.append_counted_ranges(&mut object, &canonical_artifact[..first_range_start])?;
        if fail_after_preleaf_write {
            return Err("injected canonical artifact write failure".to_owned());
        }
        let mut opened_leaf_range_chunk_count = 0_u64;
        for &(start, end) in opened_leaf_element_ranges {
            opened_leaf_range_chunk_count = opened_leaf_range_chunk_count
                .checked_add(exact_chunk_count(
                    u64::try_from(end - start)
                        .map_err(|_| "opened leaf range length does not fit u64".to_owned())?,
                    u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
                )?)
                .ok_or_else(|| "opened leaf range chunk count overflowed".to_owned())?;
            self.append_counted_ranges(&mut object, &canonical_artifact[start..end])?;
        }
        let final_range_end = opened_leaf_element_ranges
            .last()
            .map(|range| range.1)
            .ok_or_else(|| "canonical artifact has no opened leaf ranges".to_owned())?;
        let post_leaf_chunk_count = exact_chunk_count(
            u64::try_from(canonical_artifact.len() - final_range_end)
                .map_err(|_| "post-leaf artifact length does not fit u64".to_owned())?,
            u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
        )?;
        self.append_counted_ranges(&mut object, &canonical_artifact[final_range_end..])?;
        object
            .sync_all()
            .map_err(|error| format!("durably seal canonical artifact object: {error}"))?;
        self.accounting.transaction_count = self
            .accounting
            .transaction_count
            .checked_add(1)
            .ok_or_else(|| "artifact seal-transaction count overflowed".to_owned())?;
        if object
            .metadata()
            .map_err(|error| format!("inspect canonical artifact object: {error}"))?
            .len()
            != u64::try_from(canonical_artifact.len())
                .map_err(|_| "canonical artifact length does not fit u64".to_owned())?
        {
            return Err("canonical artifact object has the wrong exact length".to_owned());
        }
        Ok((
            opened_leaf_range_chunk_count,
            pre_leaf_chunk_count,
            post_leaf_chunk_count,
        ))
    }

    fn read_canonical_artifact(
        &mut self,
        exact_byte_length: usize,
        opened_leaf_element_ranges: &[(usize, usize)],
    ) -> ProofBackendBakeoffResult<Vec<u8>> {
        let artifact_path = self
            .artifact_path
            .as_ref()
            .ok_or_else(|| "canonical artifact object is missing".to_owned())?;
        let mut object = File::open(artifact_path)
            .map_err(|error| format!("open canonical artifact object: {error}"))?;
        let mut canonical_artifact = vec![0_u8; exact_byte_length];
        let first_range_start = opened_leaf_element_ranges
            .first()
            .map(|range| range.0)
            .ok_or_else(|| "canonical artifact has no opened leaf ranges".to_owned())?;
        self.read_counted_ranges(&mut object, &mut canonical_artifact[..first_range_start])?;
        for &(start, end) in opened_leaf_element_ranges {
            self.read_counted_ranges(&mut object, &mut canonical_artifact[start..end])?;
        }
        let final_range_end = opened_leaf_element_ranges
            .last()
            .map(|range| range.1)
            .ok_or_else(|| "canonical artifact has no opened leaf ranges".to_owned())?;
        self.read_counted_ranges(&mut object, &mut canonical_artifact[final_range_end..])?;
        if object
            .read(&mut [0_u8; 1])
            .map_err(|error| format!("check canonical artifact boundary: {error}"))?
            != 0
        {
            return Err("canonical artifact object has trailing bytes".to_owned());
        }
        Ok(canonical_artifact)
    }

    fn finish(&mut self) -> ProofBackendBakeoffResult<PublicSourceReplayAccounting> {
        if self.finished {
            return Err("public source custody was already released".to_owned());
        }
        let deletion_transaction_count = u64::try_from(self.object_paths.len())
            .map_err(|_| "source deletion count does not fit u64".to_owned())?
            .checked_add(u64::from(self.artifact_path.is_some()))
            .ok_or_else(|| "custody deletion-transaction count overflowed".to_owned())?;
        self.accounting
            .transaction_count
            .checked_add(deletion_transaction_count)
            .ok_or_else(|| "custody transaction count would overflow during cleanup".to_owned())?;

        let mut first_error = None;
        if let Some(artifact_path) = self.artifact_path.as_ref() {
            match fs::remove_file(artifact_path) {
                Ok(()) => {
                    self.artifact_path = None;
                    self.accounting.transaction_count += 1;
                }
                Err(error) => {
                    first_error =
                        Some(format!("remove canonical artifact custody object: {error}"));
                }
            }
        }
        let mut failed_object_paths = Vec::new();
        for object_path in std::mem::take(&mut self.object_paths) {
            match fs::remove_file(&object_path) {
                Ok(()) => self.accounting.transaction_count += 1,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(format!("remove public source custody object: {error}"));
                    }
                    failed_object_paths.push(object_path);
                }
            }
        }
        self.object_paths = failed_object_paths;
        if let Err(error) = fs::remove_dir(&self.directory_path)
            && first_error.is_none()
        {
            first_error = Some(format!("remove public source custody directory: {error}"));
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.finished = true;
        Ok(self.accounting)
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
impl Drop for PublicSourceReplayCustody {
    fn drop(&mut self) {
        if !self.finished {
            if let Some(artifact_path) = self.artifact_path.take() {
                let _ = fs::remove_file(artifact_path);
            }
            for object_path in &self.object_paths {
                let _ = fs::remove_file(object_path);
            }
            let _ = fs::remove_dir(&self.directory_path);
        }
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn validate_public_source_replay_work_counts(
    accounting: PublicSourceReplayAccounting,
    public_base_leaf_column_count: usize,
) -> ProofBackendBakeoffResult<()> {
    let width = u64::try_from(public_base_leaf_column_count)
        .map_err(|_| "public base width does not fit u64".to_owned())?;
    let expected_lde_transform_count = PUBLIC_SOURCE_REPLAY_COUNT
        .checked_mul(width)
        .ok_or_else(|| "public source LDE count overflowed".to_owned())?;
    if accounting.lde_transform_count != expected_lde_transform_count {
        return Err("public source replay did not execute exactly six LDEs per column".to_owned());
    }
    let expected_absorbed_leaf_value_count = 393_216_u64
        .checked_mul(width)
        .ok_or_else(|| "absorbed public leaf value count overflowed".to_owned())?;
    if accounting.absorbed_leaf_value_count != expected_absorbed_leaf_value_count {
        return Err(
            "public source replay did not absorb exactly 393216 leaf values per column".to_owned(),
        );
    }
    let expected_opened_value_count = 366_u64
        .checked_mul(width)
        .ok_or_else(|| "opened public value count overflowed".to_owned())?;
    if accounting.opened_value_count != expected_opened_value_count {
        return Err(
            "fresh public source replay did not open exactly 366 values per column".to_owned(),
        );
    }
    Ok(())
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn deterministic_public_source_value(column_index: usize, row_index: usize) -> u64 {
    let column =
        u64::try_from(column_index).expect("bounded public source column index must fit u64");
    let row = u64::try_from(row_index).expect("bounded public source row index must fit u64");
    let mut value = PUBLIC_SOURCE_SEED
        ^ column.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ row.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (value ^ (value >> 31)) % PROOF_BASE_FIELD_MODULUS
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn repository_local_unique_custody_test_path(label: &str) -> PathBuf {
    let scratch_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("temp");
    fs::create_dir_all(&scratch_root).expect("create repository-local scratch directory");
    let unique_suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock follows the Unix epoch")
        .as_nanos();
    scratch_root.join(format!("{label}-{}-{unique_suffix}", std::process::id()))
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn public_source_constructor_failure_removes_every_partial_custody_object() {
    let fixture = super::proof_backend_bakeoff::frozen_fixture()
        .expect("construct public source cleanup fixture");
    let custody_directory =
        repository_local_unique_custody_test_path("proof-storage-width-constructor-cleanup");
    assert!(!custody_directory.exists());
    let result = PublicSourceReplayCustody::new_with_injected_create_failure(
        &fixture,
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT,
        custody_directory.clone(),
        Some(0),
    );
    assert!(matches!(
        result,
        Err(ref message) if message == "injected public source construction failure"
    ));
    assert!(
        !custody_directory.exists(),
        "constructor failure left a partial custody directory"
    );
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn canonical_artifact_write_failure_removes_every_partial_custody_object() {
    let fixture = super::proof_backend_bakeoff::frozen_fixture()
        .expect("construct canonical artifact cleanup fixture");
    let custody_directory =
        repository_local_unique_custody_test_path("proof-storage-width-artifact-cleanup");
    let mut custody = PublicSourceReplayCustody::new(
        &fixture,
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT,
        custody_directory.clone(),
    )
    .expect("construct artifact cleanup custody");
    let canonical_artifact = vec![0x5a_u8; 96];
    let result = custody.store_canonical_artifact_with_injected_failure(
        &canonical_artifact,
        &[(16, 32)],
        true,
    );
    assert!(matches!(
        result,
        Err(ref message) if message == "injected canonical artifact write failure"
    ));
    drop(custody);
    assert!(
        !custody_directory.exists(),
        "artifact write failure left a partial custody directory"
    );
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn public_source_identity_binds_value_column_row_width_and_orientation() {
    let fixture = super::proof_backend_bakeoff::frozen_fixture()
        .expect("construct public source identity fixture");
    let width_nine_directory =
        repository_local_unique_custody_test_path("proof-storage-width-identity-nine");
    let mut width_nine = PublicSourceReplayCustody::new(
        &fixture,
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT + 1,
        width_nine_directory.clone(),
    )
    .expect("construct width-nine public source custody");
    let baseline = width_nine.checked_input_identity().to_owned();
    assert_eq!(
        width_nine
            .exact_input_identity(&fixture.input_identity_shake256_hex)
            .expect("recompute baseline source identity"),
        baseline,
    );

    let extra_column_path = width_nine.object_paths[MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT].clone();
    let mut extra_column = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&extra_column_path)
        .expect("open extra public source column for mutation");
    let mut original_value_bytes = [0_u8; 8];
    extra_column
        .read_exact(&mut original_value_bytes)
        .expect("read first extra-column value");
    let original_value = u64::from_le_bytes(original_value_bytes);
    let mutated_value = if original_value + 1 == PROOF_BASE_FIELD_MODULUS {
        0
    } else {
        original_value + 1
    };
    extra_column
        .seek(SeekFrom::Start(0))
        .expect("seek to first extra-column value");
    extra_column
        .write_all(&mutated_value.to_le_bytes())
        .expect("write mutated extra-column value");
    extra_column.sync_all().expect("sync mutated source value");
    drop(extra_column);
    assert_ne!(
        width_nine
            .exact_input_identity(&fixture.input_identity_shake256_hex)
            .expect("hash value-mutated source"),
        baseline,
    );

    let mut extra_column = OpenOptions::new()
        .write(true)
        .open(&extra_column_path)
        .expect("open extra public source column for restoration");
    extra_column
        .write_all(&original_value_bytes)
        .expect("restore first extra-column value");
    extra_column.sync_all().expect("sync restored source value");
    drop(extra_column);
    assert_eq!(
        width_nine
            .exact_input_identity(&fixture.input_identity_shake256_hex)
            .expect("hash restored source"),
        baseline,
    );

    width_nine.object_paths.swap(
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT - 1,
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT,
    );
    assert_ne!(
        width_nine
            .exact_input_identity(&fixture.input_identity_shake256_hex)
            .expect("hash column-reordered source"),
        baseline,
    );
    width_nine.object_paths.swap(
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT - 1,
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT,
    );

    let original_extra_column =
        fs::read(&extra_column_path).expect("read extra source orientation");
    let mut reversed_extra_column = Vec::with_capacity(original_extra_column.len());
    for encoded_value in original_extra_column.chunks_exact(8).rev() {
        reversed_extra_column.extend_from_slice(encoded_value);
    }
    fs::write(&extra_column_path, &reversed_extra_column)
        .expect("write reversed extra source orientation");
    assert_ne!(
        width_nine
            .exact_input_identity(&fixture.input_identity_shake256_hex)
            .expect("hash row-reversed source"),
        baseline,
    );
    fs::write(&extra_column_path, &original_extra_column)
        .expect("restore extra source orientation");
    assert_eq!(
        width_nine
            .exact_input_identity(&fixture.input_identity_shake256_hex)
            .expect("hash row-restored source"),
        baseline,
    );

    let width_ten_directory =
        repository_local_unique_custody_test_path("proof-storage-width-identity-ten");
    let mut width_ten = PublicSourceReplayCustody::new(
        &fixture,
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT + 2,
        width_ten_directory.clone(),
    )
    .expect("construct width-ten public source custody");
    assert_ne!(width_ten.checked_input_identity(), baseline);
    width_ten
        .finish()
        .expect("remove width-ten identity custody");
    width_nine
        .finish()
        .expect("remove width-nine identity custody");
    assert!(!width_ten_directory.exists());
    assert!(!width_nine_directory.exists());
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn fresh_public_base_replay_refuses_source_and_statement_root_equivocation() {
    let fixture = super::proof_backend_bakeoff::frozen_fixture()
        .expect("construct fresh public-base equivocation fixture");
    let width = MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT + 1;
    let custody_directory =
        repository_local_unique_custody_test_path("proof-storage-width-root-equivocation");
    let mut custody = PublicSourceReplayCustody::new(&fixture, width, custody_directory.clone())
        .expect("construct fresh public-base equivocation custody");
    let expected_input_identity = custody.checked_input_identity().to_owned();
    let canonical_core_statement =
        canonical_public_width_core_statement(&expected_input_identity, width)
            .expect("construct fresh public-base core statement");
    let catalog = proof_catalog_with_public_base_width(
        &canonical_core_statement,
        &expected_input_identity,
        &transcript_schedule().expect("construct transcript schedule"),
        width,
    )
    .expect("construct fresh public-base catalog");
    let trace_domain = ProofEvaluationDomain::new_subgroup(TRACE_DOMAIN_SIZE)
        .expect("construct fresh public-base trace subgroup");
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .expect("construct fresh public-base evaluation coset");
    let (expected_root, _) = recompute_public_base_root(
        &catalog.entries()[0],
        &mut custody,
        trace_domain,
        evaluation_domain,
    )
    .expect("derive statement-bound public base root");
    let query_representatives = [0, 17, 65_535];
    let openings = recompute_fresh_public_base_root_and_query_values(
        &mut custody,
        FreshPublicBaseReplayRequest {
            entry: &catalog.entries()[0],
            trace_domain,
            evaluation_domain,
            sorted_query_representatives: &query_representatives,
            frozen_input_identity_shake256_hex: &fixture.input_identity_shake256_hex,
            expected_input_identity_shake256_hex: &expected_input_identity,
            expected_root,
        },
        None,
    )
    .expect("accept exact fresh source and statement root");
    assert_eq!(openings.len(), query_representatives.len());

    let mut wrong_root = expected_root;
    wrong_root[0] ^= 1;
    let accounting_before_wrong_root = custody.accounting();
    assert!(matches!(
        recompute_fresh_public_base_root_and_query_values(
            &mut custody,
            FreshPublicBaseReplayRequest {
                entry: &catalog.entries()[0],
                trace_domain,
                evaluation_domain,
                sorted_query_representatives: &query_representatives,
                frozen_input_identity_shake256_hex: &fixture.input_identity_shake256_hex,
                expected_input_identity_shake256_hex: &expected_input_identity,
                expected_root: wrong_root,
            },
            None,
        ),
        Err(ref message) if message.contains("statement-bound root")
    ));
    let accounting_after_wrong_root = custody.accounting();
    let width_u64 = u64::try_from(width).expect("fresh public-base width fits u64");
    assert_eq!(
        accounting_after_wrong_root.lde_transform_count,
        accounting_before_wrong_root.lde_transform_count + 2 * width_u64,
        "wrong-root refusal must execute both fresh source passes"
    );
    assert_eq!(
        accounting_after_wrong_root.absorbed_leaf_value_count,
        accounting_before_wrong_root.absorbed_leaf_value_count
            + 2 * u64::try_from(EVALUATION_DOMAIN_SIZE / 2)
                .expect("public-base leaf count fits u64")
                * width_u64,
        "wrong-root refusal must rebuild the complete source-derived root"
    );
    assert_eq!(
        accounting_after_wrong_root.opened_value_count,
        accounting_before_wrong_root.opened_value_count
            + 2 * u64::try_from(query_representatives.len()).expect("query count fits u64")
                * width_u64,
        "wrong-root refusal must extract only the precommitted query values"
    );

    let extra_column_path = custody.object_paths[MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT].clone();
    let mutation_offset = 31_u64 * 8;
    let mut extra_column = OpenOptions::new()
        .read(true)
        .open(&extra_column_path)
        .expect("open unqueried extra public column");
    extra_column
        .seek(SeekFrom::Start(mutation_offset))
        .expect("seek to unqueried extra-column value");
    let mut original_value_bytes = [0_u8; 8];
    extra_column
        .read_exact(&mut original_value_bytes)
        .expect("read unqueried extra-column value");
    let original_value = u64::from_le_bytes(original_value_bytes);
    let mutated_value = if original_value + 1 == PROOF_BASE_FIELD_MODULUS {
        0
    } else {
        original_value + 1
    };
    drop(extra_column);
    let mutated_value_bytes = mutated_value.to_le_bytes();
    let mut mutate_between_replay_passes = |_: &mut PublicSourceReplayCustody| {
        let mut extra_column = OpenOptions::new()
            .write(true)
            .open(&extra_column_path)
            .map_err(|error| {
                format!("open extra public column for pass-boundary mutation: {error}")
            })?;
        extra_column
            .seek(SeekFrom::Start(mutation_offset))
            .map_err(|error| format!("seek to pass-boundary mutation: {error}"))?;
        extra_column
            .write_all(&mutated_value_bytes)
            .map_err(|error| format!("write pass-boundary mutation: {error}"))?;
        extra_column
            .sync_all()
            .map_err(|error| format!("sync pass-boundary mutation: {error}"))?;
        Ok(())
    };
    assert!(matches!(
        recompute_fresh_public_base_root_and_query_values(
            &mut custody,
            FreshPublicBaseReplayRequest {
                entry: &catalog.entries()[0],
                trace_domain,
                evaluation_domain,
                sorted_query_representatives: &query_representatives,
                frozen_input_identity_shake256_hex: &fixture.input_identity_shake256_hex,
                expected_input_identity_shake256_hex: &expected_input_identity,
                expected_root,
            },
            Some(&mut mutate_between_replay_passes),
        ),
        Err(ref message) if message.contains("pass 2 changed the bound input identity")
    ));

    let mut extra_column = OpenOptions::new()
        .write(true)
        .open(&extra_column_path)
        .expect("open extra public column for restoration");
    extra_column
        .seek(SeekFrom::Start(mutation_offset))
        .expect("seek to mutated extra-column value");
    extra_column
        .write_all(&original_value_bytes)
        .expect("restore unqueried extra-column value");
    extra_column
        .sync_all()
        .expect("sync restored extra-column value");
    drop(extra_column);
    custody
        .finish()
        .expect("remove fresh public-base equivocation custody");
    assert!(!custody_directory.exists());
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn custody_finish_continues_cleanup_after_one_object_is_already_missing() {
    let fixture = super::proof_backend_bakeoff::frozen_fixture()
        .expect("construct non-short-circuiting cleanup fixture");
    let custody_directory =
        repository_local_unique_custody_test_path("proof-storage-width-finish-cleanup");
    let mut custody = PublicSourceReplayCustody::new(
        &fixture,
        MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT,
        custody_directory.clone(),
    )
    .expect("construct non-short-circuiting cleanup custody");
    let missing_path = custody.object_paths[0].clone();
    let remaining_paths = custody.object_paths[1..].to_vec();
    fs::remove_file(&missing_path).expect("remove one custody object before finish");

    let result = custody.finish();
    assert!(
        matches!(result, Err(ref message) if message.starts_with("remove public source custody object:")),
        "finish must preserve the first cleanup error"
    );
    assert!(!custody_directory.exists());
    assert!(remaining_paths.iter().all(|path| !path.exists()));
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn custody_directory_path_refuses_relative_out_of_parent_and_existing_paths() {
    let scratch_parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("temp");
    fs::create_dir_all(&scratch_parent).expect("create repository-local scratch parent");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock follows Unix epoch")
        .as_nanos();
    let test_parent = scratch_parent.join(format!(
        "proof-storage-width-custody-path-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&test_parent).expect("create custody-path test parent");
    let result_path = test_parent.join("width-result.json");
    let valid_path = test_parent.join("precommitted.bounded-custody");
    assert_eq!(
        super::proof_storage_width_evidence::validate_custody_directory_path(
            &result_path,
            valid_path.clone(),
        )
        .expect("accept new direct-child custody path"),
        valid_path
    );
    assert!(
        super::proof_storage_width_evidence::validate_custody_directory_path(
            &result_path,
            PathBuf::from("relative.bounded-custody"),
        )
        .is_err()
    );
    assert!(
        super::proof_storage_width_evidence::validate_custody_directory_path(
            &result_path,
            scratch_parent.join("out-of-parent.bounded-custody"),
        )
        .is_err()
    );
    fs::create_dir(&valid_path).expect("create existing custody directory");
    assert!(
        super::proof_storage_width_evidence::validate_custody_directory_path(
            &result_path,
            valid_path.clone(),
        )
        .is_err()
    );
    fs::remove_dir(&valid_path).expect("remove existing custody directory");
    fs::remove_dir(&test_parent).expect("remove custody-path test parent");
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn native_custody_path_bound_covers_constructed_source_and_artifact_paths() {
    let prefix = PathBuf::from("C:\\");
    let prefix_byte_length = prefix.as_os_str().as_encoded_bytes().len();
    let directory_component = "a".repeat(
        WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH
            .checked_sub(prefix_byte_length)
            .expect("path limit accommodates the absolute prefix"),
    );
    let directory_path = prefix.join(directory_component);
    assert_eq!(
        directory_path.as_os_str().as_encoded_bytes().len(),
        WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH
    );
    validate_native_custody_path_byte_length(&directory_path, "test directory")
        .expect("accept an exact-bound custody directory");
    assert!(
        validate_native_custody_path_byte_length(
            &directory_path.join("public-column-0000.bin"),
            "test source object",
        )
        .is_err(),
        "constructed source path must retain the same finite bound"
    );
    assert!(
        validate_native_custody_path_byte_length(
            &directory_path.join("canonical-proof.bin"),
            "test proof object",
        )
        .is_err(),
        "constructed proof path must retain the same finite bound"
    );
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn observed_public_source_work_counts_fail_closed_independently() {
    let width = MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT;
    let width_u64 = u64::try_from(width).expect("minimum width fits u64");
    let exact = PublicSourceReplayAccounting {
        lde_transform_count: 6 * width_u64,
        absorbed_leaf_value_count: 393_216 * width_u64,
        opened_value_count: 366 * width_u64,
        ..PublicSourceReplayAccounting::default()
    };
    validate_public_source_replay_work_counts(exact, width)
        .expect("accept exact observed public-source work counts");

    let mut wrong_lde = exact;
    wrong_lde.lde_transform_count -= 1;
    assert!(matches!(
        validate_public_source_replay_work_counts(wrong_lde, width),
        Err(ref message) if message.contains("six LDEs")
    ));
    let mut wrong_absorbed = exact;
    wrong_absorbed.absorbed_leaf_value_count -= 1;
    assert!(matches!(
        validate_public_source_replay_work_counts(wrong_absorbed, width),
        Err(ref message) if message.contains("393216 leaf values")
    ));
    let mut wrong_opened = exact;
    wrong_opened.opened_value_count -= 1;
    assert!(matches!(
        validate_public_source_replay_work_counts(wrong_opened, width),
        Err(ref message) if message.contains("366 values")
    ));

    let mut custody = PublicSourceReplayCustody {
        directory_path: PathBuf::new(),
        object_paths: Vec::new(),
        artifact_path: None,
        input_identity_shake256_hex: String::new(),
        accounting: PublicSourceReplayAccounting {
            absorbed_leaf_value_count: u64::MAX,
            opened_value_count: u64::MAX,
            ..PublicSourceReplayAccounting::default()
        },
        finished: true,
    };
    assert!(custody.record_absorbed_leaf_values(1).is_err());
    assert!(custody.record_opened_values(1).is_err());
}

#[cfg(feature = "proof-storage-width-evidence")]
#[test]
fn static_wasm_ceiling_includes_prover_and_fresh_verifier_public_opening_workspaces() {
    let point = proof_storage_width_static_point(MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT)
        .expect("derive full-width static memory ceiling");
    let width =
        u64::try_from(MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT).expect("bounded width fits u64");
    let query_count = u64::from(UNIQUE_QUERY_COUNT);
    let minimum_prover_value_bytes = query_count
        .checked_mul(width)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| {
            count.checked_mul(
                u64::try_from(core::mem::size_of::<ProofTreeValue>())
                    .expect("proof-tree value size fits u64"),
            )
        })
        .expect("minimum prover workspace fits u64");
    assert!(
        point.prover_public_opening_workspace_byte_length_ceiling > minimum_prover_value_bytes,
        "prover workspace must include vector and allocator overhead"
    );
    let minimum_verifier_value_bytes = query_count
        .checked_mul(width)
        .and_then(|count| count.checked_mul(4))
        .and_then(|count| {
            count.checked_mul(
                u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
                    .expect("extension element size fits u64"),
            )
        })
        .expect("minimum verifier workspace fits u64");
    assert!(
        point.fresh_verifier_public_opening_workspace_byte_length_ceiling
            > minimum_verifier_value_bytes,
        "fresh-verifier workspace must include every map and allocator overhead"
    );
    assert_eq!(
        point.copied_buffer_byte_length_ceiling,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_COPIED_BUFFER_BYTE_LENGTH
    );
    assert_eq!(point.copied_buffer_byte_length_ceiling, 49_340);
    assert_eq!(
        point.boundary_transfer_byte_length_ceiling,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH
    );
    assert_eq!(point.boundary_transfer_byte_length_ceiling, 49_508);
    assert_eq!(point.digest_state_container_byte_length_ceiling, 88);
    assert!(
        point.frozen_fixture_and_container_byte_length_ceiling > 1_048_576,
        "fixture ceiling must include its eight column payloads and every owning container"
    );
    assert_eq!(point.canonical_artifact_container_byte_length_ceiling, 264);
    assert_eq!(
        point.fresh_verifier_outer_vector_container_byte_length_ceiling,
        8_960
    );
    assert_eq!(
        point.raw_abi_request_copy_workspace_byte_length_ceiling,
        345_680
    );
    assert_eq!(
        point.raw_abi_response_decode_workspace_byte_length_ceiling,
        345_704
    );
    assert_eq!(
        point.raw_abi_transfer_workspace_byte_length_ceiling,
        point.raw_abi_response_decode_workspace_byte_length_ceiling
    );
    assert!(
        point.raw_abi_transfer_workspace_byte_length_ceiling
            > point.boundary_transfer_byte_length_ceiling,
        "raw ABI workspace must cover simultaneous request custody and output ownership"
    );
    assert_eq!(
        point.browser_operation_registry_byte_length_ceiling, 64_552,
        "browser operation registry must stay source-derived from its operation and BTree node"
    );
    assert_eq!(
        point.native_custody_metadata_byte_length_ceiling, 3_867_448,
        "native custody metadata must include every 32-byte PathBuf header"
    );
    let recomputed_wasm_ceiling = point
        .digest_state_byte_length_ceiling
        .checked_add(point.digest_state_container_byte_length_ceiling)
        .and_then(|length| {
            length.checked_add(point.frozen_fixture_and_container_byte_length_ceiling)
        })
        .and_then(|length| length.checked_add(point.active_column_lde_scratch_byte_length))
        .and_then(|length| {
            length.checked_add(point.retained_algebraic_coefficient_byte_length_ceiling)
        })
        .and_then(|length| length.checked_add(point.extension_domain_working_byte_length_ceiling))
        .and_then(|length| {
            length.checked_add(point.canonical_artifact_live_copy_byte_length_ceiling)
        })
        .and_then(|length| {
            length.checked_add(point.canonical_artifact_container_byte_length_ceiling)
        })
        .and_then(|length| {
            length.checked_add(point.opening_artifact_and_transcript_byte_length_ceiling)
        })
        .and_then(|length| {
            length.checked_add(point.prover_public_opening_workspace_byte_length_ceiling)
        })
        .and_then(|length| {
            length.checked_add(point.fresh_verifier_public_opening_workspace_byte_length_ceiling)
        })
        .and_then(|length| {
            length.checked_add(point.fresh_verifier_outer_vector_container_byte_length_ceiling)
        })
        .and_then(|length| length.checked_add(point.raw_abi_transfer_workspace_byte_length_ceiling))
        .and_then(|length| length.checked_add(point.browser_operation_registry_byte_length_ceiling))
        .expect("recomputed WASM ceiling fits u64");
    assert_eq!(
        point.wasm_memory_byte_length_ceiling,
        recomputed_wasm_ceiling
    );
    assert!(
        point.wasm_memory_byte_length_ceiling <= MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
    );
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn canonical_public_width_core_statement(
    input_identity_shake256_hex: &str,
    public_base_leaf_column_count: usize,
) -> ProofBackendBakeoffResult<Vec<u8>> {
    if input_identity_shake256_hex.len() != 128
        || !input_identity_shake256_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("public source input identity is not canonical lowercase hex".to_owned());
    }
    CanonicalTuple::new(
        u16::MAX,
        1,
        vec![
            CanonicalItem::unsigned64(10),
            CanonicalItem::unsigned64(32_768),
            CanonicalItem::unsigned64(257),
            CanonicalItem::unsigned64(
                u64::try_from(TRACE_DOMAIN_SIZE)
                    .map_err(|_| "trace row count does not fit u64".to_owned())?,
            ),
            CanonicalItem::unsigned64(
                u64::try_from(public_base_leaf_column_count)
                    .map_err(|_| "public base width does not fit u64".to_owned())?,
            ),
            CanonicalItem::unsigned64(CIPHERTEXT_MODULUS),
            CanonicalItem::unsigned64(MATERIAL_RADIX),
            CanonicalItem::nonempty_ascii(input_identity_shake256_hex)
                .map_err(|error| format!("encode public source input identity: {error}"))?,
        ],
    )
    .encode()
    .map_err(|error| format!("encode public-width core statement: {error}"))
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn canonical_public_width_statement(
    canonical_core_statement: &[u8],
    expected_base_root: [u8; 64],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let decoded_core = CanonicalTuple::decode(
        canonical_core_statement,
        &crate::foundation::CanonicalDecodeLimits::default(),
    )
    .map_err(|error| format!("decode public-width core statement: {error}"))?;
    if decoded_core
        .encode()
        .map_err(|error| format!("re-encode public-width core statement: {error}"))?
        != canonical_core_statement
    {
        return Err("public-width core statement is not canonical".to_owned());
    }
    CanonicalTuple::new(
        u16::MAX,
        2,
        vec![
            CanonicalItem::nonempty_ascii(PUBLIC_WIDTH_STATEMENT_DOMAIN)
                .map_err(|error| format!("encode public-width statement domain: {error}"))?,
            CanonicalItem::nested_tuple(&decoded_core)
                .map_err(|error| format!("encode public-width core binding: {error}"))?,
            CanonicalItem::hash512(expected_base_root),
        ],
    )
    .encode()
    .map_err(|error| format!("encode public-width statement: {error}"))
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn public_base_digest_builders(
    context: &super::ProofMerkleTreeContext,
) -> ProofBackendBakeoffResult<Vec<ProofOraclePhasePairLeafDigestBuilder>> {
    let leaf_count = context
        .leaf_count()
        .map_err(|error| failure("derive public base leaf count", error))?;
    (0..leaf_count)
        .map(|leaf_index| {
            ProofOraclePhasePairLeafDigestBuilder::new_public_base(
                context,
                u64::try_from(leaf_index)
                    .map_err(|_| "public base leaf index does not fit u64".to_owned())?,
            )
            .map_err(|error| failure("initialize public base leaf digest", error))
        })
        .collect()
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn recompute_public_base_root(
    entry: &ProofTreeCatalogEntry,
    custody: &mut PublicSourceReplayCustody,
    trace_domain: ProofEvaluationDomain,
    evaluation_domain: ProofEvaluationDomain,
) -> ProofBackendBakeoffResult<([u8; 64], ProofBaseFieldColumns)> {
    let context = entry
        .common_context()
        .ok_or_else(|| "public base entry has no common Merkle context".to_owned())?;
    if usize::try_from(context.row_width())
        .map_err(|_| "public base row width does not fit usize".to_owned())?
        != custody.object_count()
        || context.leaf_visibility() != ProofLeafVisibility::Public
    {
        return Err("public base root context does not match replay custody".to_owned());
    }
    let leaf_count = context
        .leaf_count()
        .map_err(|error| failure("derive public base leaf count", error))?;
    let mut digest_builders = public_base_digest_builders(context)?;
    let mut retained_coefficients = Vec::with_capacity(COLUMN_COUNT);
    for column_index in 0..custody.object_count() {
        let (evaluations, coefficients) = custody.evaluate_column(
            column_index,
            trace_domain,
            evaluation_domain,
            column_index < COLUMN_COUNT,
            None,
        )?;
        if let Some(coefficients) = coefficients {
            retained_coefficients.push(coefficients);
        }
        for (digest_builder, value) in digest_builders
            .iter_mut()
            .zip(evaluations[..leaf_count].iter().copied())
        {
            digest_builder
                .absorb_first_value(ProofTreeValue::Base(value))
                .map_err(|error| failure("absorb public base first-point value", error))?;
        }
        custody.record_absorbed_leaf_values(leaf_count)?;
    }
    for digest_builder in &mut digest_builders {
        digest_builder
            .begin_opposite_values()
            .map_err(|error| failure("begin public base opposite-point values", error))?;
    }
    for column_index in 0..custody.object_count() {
        let (evaluations, retained) =
            custody.evaluate_column(column_index, trace_domain, evaluation_domain, false, None)?;
        if retained.is_some() {
            return Err("opposite public base replay retained coefficients".to_owned());
        }
        for (digest_builder, value) in digest_builders
            .iter_mut()
            .zip(evaluations[leaf_count..].iter().copied())
        {
            digest_builder
                .absorb_opposite_value(ProofTreeValue::Base(value))
                .map_err(|error| failure("absorb public base opposite-point value", error))?;
        }
        custody.record_absorbed_leaf_values(leaf_count)?;
    }
    let mut replay = CommonProofMerklePathReplay::new(context, &[])
        .map_err(|error| failure("initialize public base root replay", error))?;
    for (leaf_index, digest_builder) in digest_builders.into_iter().enumerate() {
        replay
            .absorb_leaf_digest(
                u64::try_from(leaf_index)
                    .map_err(|_| "public base leaf index does not fit u64".to_owned())?,
                digest_builder
                    .finish()
                    .map_err(|error| failure("finish public base leaf digest", error))?,
            )
            .map_err(|error| failure("absorb public base leaf digest", error))?;
    }
    let (root, frontier_coordinates, frontier_digests) = replay
        .finish(None)
        .map_err(|error| failure("finish public base root replay", error))?;
    if !frontier_coordinates.is_empty() || !frontier_digests.is_empty() {
        return Err("root-only public base replay retained a frontier".to_owned());
    }
    let retained_coefficients: ProofBaseFieldColumns =
        retained_coefficients.try_into().map_err(|_| {
            "public base replay did not retain exactly eight algebraic columns".to_owned()
        })?;
    Ok((root, retained_coefficients))
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn recompute_public_base_opening(
    entry: &ProofTreeCatalogEntry,
    custody: &mut PublicSourceReplayCustody,
    trace_domain: ProofEvaluationDomain,
    evaluation_domain: ProofEvaluationDomain,
    sorted_query_representatives: &[u64],
    expected_root: [u8; 64],
) -> ProofBackendBakeoffResult<super::prover::PrefetchedCommonProofOpeningArtifact> {
    let context = entry
        .common_context()
        .ok_or_else(|| "public base entry has no common Merkle context".to_owned())?;
    let leaf_count = context
        .leaf_count()
        .map_err(|error| failure("derive public base leaf count", error))?;
    if sorted_query_representatives.is_empty()
        || !sorted_query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_query_representatives
            .last()
            .is_some_and(|index| usize::try_from(*index).map_or(true, |index| index >= leaf_count))
    {
        return Err("public base opening query indexes are not canonical".to_owned());
    }
    let mut digest_builders = public_base_digest_builders(context)?;
    let mut first_values = (0..sorted_query_representatives.len())
        .map(|_| Vec::with_capacity(custody.object_count()))
        .collect::<Vec<_>>();
    let mut opposite_values = (0..sorted_query_representatives.len())
        .map(|_| Vec::with_capacity(custody.object_count()))
        .collect::<Vec<_>>();
    for column_index in 0..custody.object_count() {
        let (evaluations, retained) =
            custody.evaluate_column(column_index, trace_domain, evaluation_domain, false, None)?;
        if retained.is_some() {
            return Err("public base opening retained coefficients".to_owned());
        }
        for (digest_builder, value) in digest_builders
            .iter_mut()
            .zip(evaluations[..leaf_count].iter().copied())
        {
            digest_builder
                .absorb_first_value(ProofTreeValue::Base(value))
                .map_err(|error| failure("absorb public base opening first value", error))?;
        }
        for (position, query_index) in sorted_query_representatives.iter().copied().enumerate() {
            first_values[position].push(ProofTreeValue::Base(
                evaluations[usize::try_from(query_index)
                    .map_err(|_| "public base query index does not fit usize".to_owned())?],
            ));
        }
        custody.record_absorbed_leaf_values(leaf_count)?;
    }
    for digest_builder in &mut digest_builders {
        digest_builder
            .begin_opposite_values()
            .map_err(|error| failure("begin public base opening opposite values", error))?;
    }
    for column_index in 0..custody.object_count() {
        let (evaluations, retained) =
            custody.evaluate_column(column_index, trace_domain, evaluation_domain, false, None)?;
        if retained.is_some() {
            return Err("public base opening retained opposite coefficients".to_owned());
        }
        for (digest_builder, value) in digest_builders
            .iter_mut()
            .zip(evaluations[leaf_count..].iter().copied())
        {
            digest_builder
                .absorb_opposite_value(ProofTreeValue::Base(value))
                .map_err(|error| failure("absorb public base opening opposite value", error))?;
        }
        for (position, query_index) in sorted_query_representatives.iter().copied().enumerate() {
            let opposite_index = usize::try_from(query_index)
                .map_err(|_| "public base query index does not fit usize".to_owned())?
                .checked_add(leaf_count)
                .ok_or_else(|| "public base opposite query index overflowed".to_owned())?;
            opposite_values[position].push(ProofTreeValue::Base(evaluations[opposite_index]));
        }
        custody.record_absorbed_leaf_values(leaf_count)?;
    }
    let mut replay = CommonProofMerklePathReplay::new(context, sorted_query_representatives)
        .map_err(|error| failure("initialize public base opening replay", error))?;
    for (leaf_index, digest_builder) in digest_builders.into_iter().enumerate() {
        replay
            .absorb_leaf_digest(
                u64::try_from(leaf_index)
                    .map_err(|_| "public base leaf index does not fit u64".to_owned())?,
                digest_builder
                    .finish()
                    .map_err(|error| failure("finish public base opening leaf digest", error))?,
            )
            .map_err(|error| failure("replay public base opening leaf", error))?;
    }
    let (root, frontier_coordinates, frontier_digests) = replay
        .finish(Some(expected_root))
        .map_err(|error| failure("finish public base opening replay", error))?;
    if root != expected_root {
        return Err("public base opening replay changed its root".to_owned());
    }
    let mut opened_leaf_bytes = Vec::with_capacity(sorted_query_representatives.len());
    for ((leaf_index, first_values), opposite_values) in sorted_query_representatives
        .iter()
        .copied()
        .zip(first_values)
        .zip(opposite_values)
    {
        let leaf = super::ProofOraclePhasePairLeaf::new(
            context,
            leaf_index,
            None,
            first_values,
            opposite_values,
        )
        .map_err(|error| failure("construct recomputed public base leaf", error))?;
        opened_leaf_bytes
            .push(Zeroizing::new(leaf.canonical_bytes().map_err(|error| {
                failure("encode recomputed public base leaf", error)
            })?));
    }
    let canonical_leaf_byte_length = super::body::canonical_leaf_byte_length(entry)
        .map_err(|error| failure("derive public base canonical leaf length", error))?;
    super::prover::PrefetchedCommonProofOpeningArtifact::from_recomputed_common_tree(
        entry.tree_catalog_index(),
        leaf_count,
        canonical_leaf_byte_length,
        sorted_query_representatives.to_vec(),
        opened_leaf_bytes,
        frontier_coordinates,
        frontier_digests,
    )
    .map_err(|error| failure("construct recomputed public base opening", error))
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
struct FreshPublicBaseReplayRequest<'input> {
    entry: &'input ProofTreeCatalogEntry,
    trace_domain: ProofEvaluationDomain,
    evaluation_domain: ProofEvaluationDomain,
    sorted_query_representatives: &'input [u64],
    frozen_input_identity_shake256_hex: &'input str,
    expected_input_identity_shake256_hex: &'input str,
    expected_root: [u8; 64],
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
type BetweenFreshPublicSourceReplayPasses<'callback> =
    &'callback mut dyn FnMut(&mut PublicSourceReplayCustody) -> ProofBackendBakeoffResult<()>;

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn recompute_fresh_public_base_root_and_query_values(
    custody: &mut PublicSourceReplayCustody,
    request: FreshPublicBaseReplayRequest<'_>,
    #[cfg(test)] mut between_replay_passes: Option<BetweenFreshPublicSourceReplayPasses<'_>>,
) -> ProofBackendBakeoffResult<BTreeMap<u64, AuthenticatedPhasePair>> {
    let FreshPublicBaseReplayRequest {
        entry,
        trace_domain,
        evaluation_domain,
        sorted_query_representatives,
        frozen_input_identity_shake256_hex,
        expected_input_identity_shake256_hex,
        expected_root,
    } = request;
    let context = entry
        .common_context()
        .ok_or_else(|| "fresh public base entry has no common Merkle context".to_owned())?;
    if usize::try_from(context.row_width())
        .map_err(|_| "fresh public base row width does not fit usize".to_owned())?
        != custody.object_count()
        || context.leaf_visibility() != ProofLeafVisibility::Public
    {
        return Err("fresh public base context does not match replay custody".to_owned());
    }
    let leaf_count = context
        .leaf_count()
        .map_err(|error| failure("derive fresh public base leaf count", error))?;
    if sorted_query_representatives.is_empty()
        || !sorted_query_representatives
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || sorted_query_representatives
            .last()
            .is_some_and(|index| usize::try_from(*index).map_or(true, |index| index >= leaf_count))
    {
        return Err("fresh public base query indexes are not canonical".to_owned());
    }
    let mut digest_builders = public_base_digest_builders(context)?;
    let mut first_values = (0..sorted_query_representatives.len())
        .map(|_| Vec::with_capacity(custody.object_count()))
        .collect::<Vec<_>>();
    let mut opposite_values = (0..sorted_query_representatives.len())
        .map(|_| Vec::with_capacity(custody.object_count()))
        .collect::<Vec<_>>();
    for replay_pass in 0..2 {
        if replay_pass == 1 {
            for digest_builder in &mut digest_builders {
                digest_builder.begin_opposite_values().map_err(|error| {
                    failure("begin fresh public base opposite-point values", error)
                })?;
            }
        }
        let mut identity_hasher = public_source_identity_hasher(
            frozen_input_identity_shake256_hex,
            custody.object_count(),
        )?;
        for column_index in 0..custody.object_count() {
            let (evaluations, retained) = custody.evaluate_column(
                column_index,
                trace_domain,
                evaluation_domain,
                false,
                Some(&mut identity_hasher),
            )?;
            if retained.is_some() {
                return Err("fresh public source replay retained coefficients".to_owned());
            }
            if replay_pass == 0 {
                for (digest_builder, value) in digest_builders
                    .iter_mut()
                    .zip(evaluations[..leaf_count].iter().copied())
                {
                    digest_builder
                        .absorb_first_value(ProofTreeValue::Base(value))
                        .map_err(|error| {
                            failure("absorb fresh public base first-point value", error)
                        })?;
                }
            } else {
                for (digest_builder, value) in digest_builders
                    .iter_mut()
                    .zip(evaluations[leaf_count..].iter().copied())
                {
                    digest_builder
                        .absorb_opposite_value(ProofTreeValue::Base(value))
                        .map_err(|error| {
                            failure("absorb fresh public base opposite-point value", error)
                        })?;
                }
            }
            for (position, query_index) in sorted_query_representatives.iter().copied().enumerate()
            {
                let query_index = usize::try_from(query_index)
                    .map_err(|_| "fresh public query index does not fit usize".to_owned())?;
                let evaluation_index = if replay_pass == 0 {
                    query_index
                } else {
                    query_index
                        .checked_add(leaf_count)
                        .ok_or_else(|| "fresh public opposite query index overflowed".to_owned())?
                };
                let value =
                    ProofChallengeExtensionElement::from_base(evaluations[evaluation_index]);
                if replay_pass == 0 {
                    first_values[position].push(value);
                } else {
                    opposite_values[position].push(value);
                }
            }
            custody.record_absorbed_leaf_values(leaf_count)?;
            custody.record_opened_values(sorted_query_representatives.len())?;
        }
        let replayed_input_identity_shake256_hex = to_hex(&identity_hasher.finalize());
        if replayed_input_identity_shake256_hex != expected_input_identity_shake256_hex {
            return Err(format!(
                "fresh public source replay pass {} changed the bound input identity",
                replay_pass + 1
            ));
        }
        #[cfg(test)]
        if replay_pass == 0
            && let Some(mutate_between_replay_passes) = between_replay_passes.as_deref_mut()
        {
            mutate_between_replay_passes(custody)?;
        }
    }
    let mut replay = CommonProofMerklePathReplay::new(context, &[])
        .map_err(|error| failure("initialize fresh public base root replay", error))?;
    for (leaf_index, digest_builder) in digest_builders.into_iter().enumerate() {
        replay
            .absorb_leaf_digest(
                u64::try_from(leaf_index)
                    .map_err(|_| "fresh public base leaf index does not fit u64".to_owned())?,
                digest_builder
                    .finish()
                    .map_err(|error| failure("finish fresh public base leaf digest", error))?,
            )
            .map_err(|error| failure("absorb fresh public base leaf digest", error))?;
    }
    let (recomputed_root, frontier_coordinates, frontier_digests) = replay
        .finish(None)
        .map_err(|error| failure("finish fresh public base root replay", error))?;
    if recomputed_root != expected_root
        || !frontier_coordinates.is_empty()
        || !frontier_digests.is_empty()
    {
        return Err("fresh public base replay changed the statement-bound root".to_owned());
    }
    sorted_query_representatives
        .iter()
        .copied()
        .zip(first_values)
        .zip(opposite_values)
        .map(|((leaf_index, first_values), opposite_values)| {
            Ok((
                leaf_index,
                AuthenticatedPhasePair {
                    first_values,
                    opposite_values,
                },
            ))
        })
        .collect()
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn recompute_extension_tree_root(
    entry: &ProofTreeCatalogEntry,
    evaluations: &[ProofChallengeExtensionElement],
) -> ProofBackendBakeoffResult<[u8; 64]> {
    let context = entry
        .common_context()
        .ok_or_else(|| "extension tree has no common Merkle context".to_owned())?;
    let values = MaterializedTreeValues::ExtensionColumn(evaluations);
    let leaf_count = context
        .leaf_count()
        .map_err(|error| failure("derive extension-tree leaf count", error))?;
    let mut replay = CommonProofMerklePathReplay::new(context, &[])
        .map_err(|error| failure("initialize extension-tree root replay", error))?;
    for leaf_index in 0..leaf_count {
        let (first_values, opposite_values) = values.phase_pair(leaf_index)?;
        let (_, digest) = entry
            .encode_materialized_leaf(
                u64::try_from(leaf_index)
                    .map_err(|_| "extension leaf index does not fit u64".to_owned())?,
                None,
                first_values,
                opposite_values,
            )
            .map_err(|error| failure("encode extension-tree leaf", error))?;
        replay
            .absorb_leaf_digest(
                u64::try_from(leaf_index)
                    .map_err(|_| "extension leaf index does not fit u64".to_owned())?,
                digest,
            )
            .map_err(|error| failure("replay extension-tree leaf", error))?;
    }
    let (root, frontier_coordinates, frontier_digests) = replay
        .finish(None)
        .map_err(|error| failure("finish extension-tree root replay", error))?;
    if !frontier_coordinates.is_empty() || !frontier_digests.is_empty() {
        return Err("root-only extension-tree replay retained a frontier".to_owned());
    }
    Ok(root)
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn recompute_extension_tree_opening(
    entry: &ProofTreeCatalogEntry,
    evaluations: &[ProofChallengeExtensionElement],
    sorted_query_representatives: &[u64],
    expected_root: [u8; 64],
) -> ProofBackendBakeoffResult<super::prover::PrefetchedCommonProofOpeningArtifact> {
    let context = entry
        .common_context()
        .ok_or_else(|| "extension tree has no common Merkle context".to_owned())?;
    let leaf_count = context
        .leaf_count()
        .map_err(|error| failure("derive extension-tree leaf count", error))?;
    let opened_leaf_indexes = super::prover::opened_leaf_indexes(
        entry.source(),
        u64::try_from(EVALUATION_DOMAIN_SIZE)
            .map_err(|_| "evaluation domain size does not fit u64".to_owned())?,
        sorted_query_representatives,
    )
    .map_err(|error| failure("derive extension-tree opened indexes", error))?;
    let values = MaterializedTreeValues::ExtensionColumn(evaluations);
    let mut replay = CommonProofMerklePathReplay::new(context, &opened_leaf_indexes)
        .map_err(|error| failure("initialize extension-tree opening replay", error))?;
    let mut opened_leaf_bytes = Vec::with_capacity(opened_leaf_indexes.len());
    let mut next_opened_position = 0_usize;
    for leaf_index in 0..leaf_count {
        let (first_values, opposite_values) = values.phase_pair(leaf_index)?;
        let (canonical_leaf_bytes, digest) = entry
            .encode_materialized_leaf(
                u64::try_from(leaf_index)
                    .map_err(|_| "extension leaf index does not fit u64".to_owned())?,
                None,
                first_values,
                opposite_values,
            )
            .map_err(|error| failure("encode extension-tree opening leaf", error))?;
        if opened_leaf_indexes.get(next_opened_position).copied()
            == Some(
                u64::try_from(leaf_index)
                    .map_err(|_| "extension leaf index does not fit u64".to_owned())?,
            )
        {
            opened_leaf_bytes.push(Zeroizing::new(canonical_leaf_bytes));
            next_opened_position += 1;
        }
        replay
            .absorb_leaf_digest(
                u64::try_from(leaf_index)
                    .map_err(|_| "extension leaf index does not fit u64".to_owned())?,
                digest,
            )
            .map_err(|error| failure("replay extension-tree opening leaf", error))?;
    }
    if next_opened_position != opened_leaf_indexes.len() {
        return Err("extension-tree opening omitted a queried leaf".to_owned());
    }
    let (_, frontier_coordinates, frontier_digests) = replay
        .finish(Some(expected_root))
        .map_err(|error| failure("finish extension-tree opening replay", error))?;
    let canonical_leaf_byte_length = super::body::canonical_leaf_byte_length(entry)
        .map_err(|error| failure("derive extension-tree canonical leaf length", error))?;
    super::prover::PrefetchedCommonProofOpeningArtifact::from_recomputed_common_tree(
        entry.tree_catalog_index(),
        leaf_count,
        canonical_leaf_byte_length,
        opened_leaf_indexes,
        opened_leaf_bytes,
        frontier_coordinates,
        frontier_digests,
    )
    .map_err(|error| failure("construct recomputed extension-tree opening", error))
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn storage_plans(
    catalog: &CompleteProofTreeCatalog,
) -> ProofBackendBakeoffResult<(
    Vec<CommonProofMerkleStoragePlan>,
    ProofExternalMemoryPlan,
    FrozenExternalMemoryAccounting,
)> {
    storage_plans_from_catalog_index(catalog, 0)
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn storage_plans_from_catalog_index(
    catalog: &CompleteProofTreeCatalog,
    first_catalog_index: usize,
) -> ProofBackendBakeoffResult<(
    Vec<CommonProofMerkleStoragePlan>,
    ProofExternalMemoryPlan,
    FrozenExternalMemoryAccounting,
)> {
    if first_catalog_index >= catalog.entries().len() {
        return Err("first stored-tree catalog index is outside the catalog".to_owned());
    }
    let stored_tree_count = catalog.entries().len() - first_catalog_index;
    let evaluation_domain_size = u64::try_from(EVALUATION_DOMAIN_SIZE)
        .map_err(|_| "evaluation domain size does not fit u64".to_owned())?;
    let external_memory_chunk_byte_length = u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
    let mut first_object_ordinal = 0_u32;
    let mut tree_plans = Vec::with_capacity(stored_tree_count);
    let mut object_plans = Vec::<ProofExternalMemoryObjectPlan>::with_capacity(stored_tree_count);
    let mut total_written_byte_length = 0_u64;
    let mut total_read_byte_length = 0_u64;
    let mut write_transaction_count = 0_u64;
    let mut read_transaction_count = 0_u64;
    let mut lifecycle_transaction_count = 0_u64;
    let mut deletion_count_by_step = BTreeMap::<u32, u32>::new();
    for entry in &catalog.entries()[first_catalog_index..] {
        let plan = common_proof_merkle_storage_plan(
            entry,
            evaluation_domain_size,
            first_object_ordinal,
            0,
            1,
        )
        .map_err(|error| failure("derive path-only Merkle storage plan", error))?;
        if plan.object_plans().len() != 1 {
            return Err("path-only Merkle plan did not derive one leaf object".to_owned());
        }
        let leaf_count = super::body::entry_leaf_count(entry, evaluation_domain_size)
            .map_err(|error| failure("derive stored Merkle leaf count", error))?;
        let canonical_leaf_byte_length = u64::try_from(plan.canonical_leaf_byte_length())
            .map_err(|_| "canonical Merkle leaf length does not fit u64".to_owned())?;
        let expected_object_byte_length = u64::try_from(leaf_count)
            .ok()
            .and_then(|count| count.checked_mul(canonical_leaf_byte_length))
            .ok_or_else(|| "stored Merkle object length overflowed".to_owned())?;
        let object_plan = plan.object_plans()[0];
        if object_plan.exact_byte_length() != expected_object_byte_length
            || object_plan.issued_step() != 0
            || object_plan.seal_step() != 0
            || object_plan.last_use_step() != 1
        {
            return Err("path-only Merkle object lifecycle changed".to_owned());
        }
        total_written_byte_length = total_written_byte_length
            .checked_add(expected_object_byte_length)
            .ok_or_else(|| "external written-byte count overflowed".to_owned())?;
        total_read_byte_length = total_read_byte_length
            .checked_add(expected_object_byte_length)
            .ok_or_else(|| "external read-byte count overflowed".to_owned())?;
        write_transaction_count = write_transaction_count
            .checked_add(exact_chunk_count(
                expected_object_byte_length,
                external_memory_chunk_byte_length,
            )?)
            .ok_or_else(|| "external write-transaction count overflowed".to_owned())?;
        let read_transactions_per_leaf = exact_chunk_count(
            canonical_leaf_byte_length,
            external_memory_chunk_byte_length,
        )?;
        read_transaction_count = read_transaction_count
            .checked_add(
                u64::try_from(leaf_count)
                    .ok()
                    .and_then(|count| count.checked_mul(read_transactions_per_leaf))
                    .ok_or_else(|| "external read-transaction count overflowed".to_owned())?,
            )
            .ok_or_else(|| "external read-transaction count overflowed".to_owned())?;
        lifecycle_transaction_count = lifecycle_transaction_count
            .checked_add(2)
            .ok_or_else(|| "external lifecycle-transaction count overflowed".to_owned())?;
        let deletion_count = deletion_count_by_step
            .entry(object_plan.last_use_step())
            .or_default();
        *deletion_count = deletion_count
            .checked_add(1)
            .ok_or_else(|| "external deletion count overflowed".to_owned())?;
        first_object_ordinal = plan.next_object_ordinal();
        object_plans.extend_from_slice(plan.object_plans());
        tree_plans.push(plan);
    }
    if tree_plans.len() != stored_tree_count
        || object_plans.len() != stored_tree_count
        || first_object_ordinal != u32::try_from(stored_tree_count).unwrap_or(u32::MAX)
    {
        return Err("path-only storage object count diverged from its catalog suffix".to_owned());
    }
    let step_count = object_plans
        .iter()
        .map(|plan| plan.last_use_step())
        .max()
        .and_then(|last_use_step| last_use_step.checked_add(1))
        .ok_or_else(|| "external-memory step count overflowed".to_owned())?;
    if step_count != 2 {
        return Err("path-only external-memory step count changed".to_owned());
    }
    let maximum_transaction_operation_count = deletion_count_by_step
        .values()
        .copied()
        .max()
        .ok_or_else(|| "path-only external-memory deletion schedule is empty".to_owned())?;
    let mut peak_stored_byte_length = 0_u64;
    for step in 0..step_count {
        let stored_at_step = object_plans
            .iter()
            .filter(|plan| plan.issued_step() <= step && step <= plan.last_use_step())
            .try_fold(0_u64, |total, plan| {
                total.checked_add(plan.exact_byte_length())
            })
            .ok_or_else(|| "external peak stored-byte count overflowed".to_owned())?;
        peak_stored_byte_length = peak_stored_byte_length.max(stored_at_step);
    }
    let deletion_transaction_count = u64::try_from(deletion_count_by_step.len())
        .map_err(|_| "external deletion-transaction count does not fit u64".to_owned())?;
    let transaction_count = write_transaction_count
        .checked_add(read_transaction_count)
        .and_then(|count| count.checked_add(lifecycle_transaction_count))
        .and_then(|count| count.checked_add(deletion_transaction_count))
        .ok_or_else(|| "external transaction count overflowed".to_owned())?;
    let object_count = u32::try_from(object_plans.len())
        .map_err(|_| "external object count does not fit u32".to_owned())?;
    let accounting = FrozenExternalMemoryAccounting {
        peak_stored_byte_length,
        total_written_byte_length,
        total_read_byte_length,
        transaction_count,
        object_count,
    };
    let executor_plan = ProofExternalMemoryPlan::new(
        step_count,
        EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH,
        external_memory_chunk_byte_length,
        maximum_transaction_operation_count,
        accounting.peak_stored_byte_length,
        accounting.total_written_byte_length,
        accounting.total_read_byte_length,
        accounting.transaction_count,
        object_plans,
    )
    .map_err(|error| failure("construct exact path-only external-memory plan", error))?;
    Ok((tree_plans, executor_plan, accounting))
}

enum MaterializedTreeValues<'values> {
    #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
    BaseColumns(&'values ProofBaseFieldColumns),
    ExtensionColumn(&'values [ProofChallengeExtensionElement]),
}

impl MaterializedTreeValues<'_> {
    fn evaluation_count(&self) -> usize {
        match self {
            #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
            Self::BaseColumns(columns) => columns[0].len(),
            Self::ExtensionColumn(values) => values.len(),
        }
    }

    fn phase_pair(
        &self,
        leaf_index: usize,
    ) -> ProofBackendBakeoffResult<MaterializedProofTreePhasePair> {
        let leaf_count = self
            .evaluation_count()
            .checked_div(2)
            .filter(|count| *count != 0)
            .ok_or_else(|| "materialized tree has no phase-pair leaves".to_owned())?;
        if leaf_index >= leaf_count {
            return Err("materialized tree leaf index is outside its domain".to_owned());
        }
        let opposite_index = leaf_index
            .checked_add(leaf_count)
            .ok_or_else(|| "materialized opposite index overflowed".to_owned())?;
        match self {
            #[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
            Self::BaseColumns(columns) => {
                if columns
                    .iter()
                    .any(|column| column.len() != self.evaluation_count())
                {
                    return Err("base Merkle columns have inconsistent lengths".to_owned());
                }
                Ok((
                    Zeroizing::new(
                        columns
                            .iter()
                            .map(|column| ProofTreeValue::Base(column[leaf_index]))
                            .collect(),
                    ),
                    Zeroizing::new(
                        columns
                            .iter()
                            .map(|column| ProofTreeValue::Base(column[opposite_index]))
                            .collect(),
                    ),
                ))
            }
            Self::ExtensionColumn(values) => Ok((
                Zeroizing::new(vec![ProofTreeValue::Extension(values[leaf_index])]),
                Zeroizing::new(vec![ProofTreeValue::Extension(values[opposite_index])]),
            )),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn materialize_tree(
    entry: &ProofTreeCatalogEntry,
    storage_plan: CommonProofMerkleStoragePlan,
    values: MaterializedTreeValues<'_>,
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut BoundedInMemoryExternalMemory,
    coins: &mut NoPrivateCoins,
) -> ProofBackendBakeoffResult<StoredCommonProofMerkleTree> {
    let mut materializer = CommonProofMerkleMaterializer::new(
        entry,
        u64::try_from(EVALUATION_DOMAIN_SIZE)
            .map_err(|_| "evaluation domain size does not fit u64".to_owned())?,
        storage_plan,
    )
    .map_err(|error| failure("initialize path-only Merkle materializer", error))?;
    loop {
        match materializer
            .advance_storage(executor, storage)
            .map_err(|error| failure("advance path-only Merkle materializer", error))?
        {
            CommonProofMerkleMaterializerProgress::StorageTransactionCompleted => {}
            CommonProofMerkleMaterializerProgress::NeedsLeafValues { leaf_index } => {
                let leaf_index = usize::try_from(leaf_index)
                    .map_err(|_| "Merkle leaf index does not fit usize".to_owned())?;
                let (first_values, opposite_values) = values.phase_pair(leaf_index)?;
                materializer
                    .supply_next_leaf(first_values, opposite_values, None, coins)
                    .map_err(|error| failure("supply public Merkle phase pair", error))?;
            }
            CommonProofMerkleMaterializerProgress::Complete => break,
        }
    }
    materializer
        .finish()
        .map_err(|error| failure("finish path-only Merkle materializer", error))
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn prefetch_opening(
    tree: &StoredCommonProofMerkleTree,
    entry: &ProofTreeCatalogEntry,
    sorted_query_representatives: &[u64],
    executor: &mut ProofExternalMemoryExecutor,
    storage: &mut BoundedInMemoryExternalMemory,
) -> ProofBackendBakeoffResult<super::prover::PrefetchedCommonProofOpeningArtifact> {
    let mut prefetcher = CommonProofOpeningPrefetcher::new(
        tree,
        entry,
        u64::try_from(EVALUATION_DOMAIN_SIZE)
            .map_err(|_| "evaluation domain size does not fit u64".to_owned())?,
        sorted_query_representatives,
        MAXIMUM_PREFETCHED_QUERY_BYTE_LENGTH,
    )
    .map_err(|error| failure("initialize root-authenticated opening prefetch", error))?;
    while let CommonProofOpeningPrefetchProgress::StorageTransactionCompleted = prefetcher
        .advance_storage(executor, storage)
        .map_err(|error| failure("advance root-authenticated opening prefetch", error))?
    {}
    prefetcher
        .finish()
        .map_err(|error| failure("finish root-authenticated opening prefetch", error))
}

fn opening_geometries(
    catalog: &CompleteProofTreeCatalog,
) -> ProofBackendBakeoffResult<Vec<CommonProofOpeningGeometry>> {
    catalog
        .entries()
        .iter()
        .map(|entry| {
            let leaf_count = super::body::entry_leaf_count(
                entry,
                u64::try_from(EVALUATION_DOMAIN_SIZE)
                    .map_err(|_| "evaluation domain size does not fit u64".to_owned())?,
            )
            .map_err(|error| failure("derive query leaf count", error))?;
            let canonical_leaf_byte_length = super::body::canonical_leaf_byte_length(entry)
                .map_err(|error| failure("derive canonical query leaf length", error))?;
            Ok(CommonProofOpeningGeometry {
                tree_catalog_index: entry.tree_catalog_index(),
                leaf_count,
                canonical_leaf_byte_length,
            })
        })
        .collect()
}

fn verify_deep_quotient_identity(
    deep_point: ProofChallengeExtensionElement,
    deep_evaluations: &[ProofChallengeExtensionElement],
    composition_challenges: &[ProofChallengeExtensionElement],
) -> ProofBackendBakeoffResult<()> {
    if deep_evaluations.len() != BATCHED_FUNCTION_COUNT || composition_challenges.len() != 2 {
        return Err("frozen DEEP quotient identity shape changed".to_owned());
    }
    let (source_deep_evaluations, repeated_deep_evaluations) =
        deep_evaluations.split_at(SOURCE_OPENING_CLAIM_COUNT);
    if source_deep_evaluations != repeated_deep_evaluations {
        return Err("frozen DEEP evaluations do not repeat the nine source claims".to_owned());
    }
    let material_radix = ProofBaseFieldElement::from_canonical(MATERIAL_RADIX)
        .map_err(|error| failure("convert frozen material radix", error))?;
    let ciphertext_modulus = ProofBaseFieldElement::from_canonical(CIPHERTEXT_MODULUS)
        .map_err(|error| failure("convert frozen ciphertext modulus", error))?;
    let first_residual = affine_residual(
        source_deep_evaluations,
        0,
        material_radix,
        ciphertext_modulus,
    )?;
    let second_residual = affine_residual(
        source_deep_evaluations,
        4,
        material_radix,
        ciphertext_modulus,
    )?;
    let trace_zeroifier = deep_point
        .power(
            u64::try_from(TRACE_DOMAIN_SIZE)
                .map_err(|_| "trace domain size does not fit u64".to_owned())?,
        )
        .subtract(ProofChallengeExtensionElement::ONE);
    if trace_zeroifier.is_zero() {
        return Err("DEEP point lies on the frozen trace domain".to_owned());
    }
    let expected_numerator = composition_challenges[0]
        .multiply(first_residual)
        .add(composition_challenges[1].multiply(second_residual));
    let actual_numerator = trace_zeroifier.multiply(source_deep_evaluations[COLUMN_COUNT]);
    if actual_numerator != expected_numerator {
        return Err("DEEP quotient evaluation does not bind both affine equations".to_owned());
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
struct GeneratedPackedDeepFri {
    compact_canonical_proof: Vec<u8>,
}

fn compact_canonical_proof(
    profile: &FrozenProofProfile,
    canonical_full_proof: &[u8],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let base_root_start = profile.canonical_header.len();
    let base_root_end = base_root_start
        .checked_add(MERKLE_DIGEST_BYTE_LENGTH)
        .ok_or_else(|| "packed-DEEP-FRI base-root offset overflowed".to_owned())?;
    if canonical_full_proof.len() <= base_root_end
        || !canonical_full_proof.starts_with(&profile.canonical_header)
    {
        return Err("full packed-DEEP-FRI proof does not carry the checked header".to_owned());
    }
    if &canonical_full_proof[base_root_start..base_root_end]
        != profile.expected_fri_base_root.as_slice()
    {
        return Err("full packed-DEEP-FRI proof does not carry the checked base root".to_owned());
    }
    let compact_byte_length = canonical_full_proof
        .len()
        .checked_sub(MERKLE_DIGEST_BYTE_LENGTH)
        .ok_or_else(|| "compact packed-DEEP-FRI proof length underflowed".to_owned())?;
    let mut compact_proof = Vec::with_capacity(compact_byte_length);
    compact_proof.extend_from_slice(&canonical_full_proof[..base_root_start]);
    compact_proof.extend_from_slice(&canonical_full_proof[base_root_end..]);
    Ok(compact_proof)
}

fn expand_compact_canonical_proof(
    profile: &FrozenProofProfile,
    compact_proof: &[u8],
) -> ProofBackendBakeoffResult<Vec<u8>> {
    let header_byte_length = profile.canonical_header.len();
    if compact_proof.len() <= header_byte_length
        || !compact_proof.starts_with(&profile.canonical_header)
    {
        return Err(
            "compact packed-DEEP-FRI proof header does not match the checked statement".to_owned(),
        );
    }
    let full_byte_length = compact_proof
        .len()
        .checked_add(MERKLE_DIGEST_BYTE_LENGTH)
        .ok_or_else(|| "expanded packed-DEEP-FRI proof length overflowed".to_owned())?;
    let mut canonical_full_proof = Vec::with_capacity(full_byte_length);
    canonical_full_proof.extend_from_slice(&compact_proof[..header_byte_length]);
    canonical_full_proof.extend_from_slice(&profile.expected_fri_base_root);
    canonical_full_proof.extend_from_slice(&compact_proof[header_byte_length..]);
    Ok(canonical_full_proof)
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn public_width_initial_fri_evaluations(
    column_coefficients: &ProofBaseFieldColumns,
    quotient_coefficients: &[ProofChallengeExtensionElement],
    evaluation_domain: ProofEvaluationDomain,
    deep_point: ProofChallengeExtensionElement,
    deep_evaluations: &[ProofChallengeExtensionElement],
    opening_batch_challenges: &[ProofChallengeExtensionElement],
) -> ProofBackendBakeoffResult<Vec<ProofChallengeExtensionElement>> {
    if deep_evaluations.len() != BATCHED_FUNCTION_COUNT
        || opening_batch_challenges.len() != BATCHED_FUNCTION_COUNT
    {
        return Err("public-width initial FRI batching shape changed".to_owned());
    }
    let (source_batch_challenges, normalized_batch_challenges) =
        opening_batch_challenges.split_at(SOURCE_OPENING_CLAIM_COUNT);
    let shifted_normalized_opening_degree_bound = OPENING_DEGREE_BOUND_EXCLUSIVE
        .checked_add(1)
        .ok_or_else(|| "shifted normalized opening degree bound overflowed".to_owned())?;
    let mut initial_fri_coefficients =
        vec![ProofChallengeExtensionElement::ZERO; OPENING_DEGREE_BOUND_EXCLUSIVE];
    for column_ordinal in 0..COLUMN_COUNT {
        add_base_source_polynomial_to_initial_fri(
            &mut initial_fri_coefficients,
            &column_coefficients[column_ordinal],
            source_batch_challenges[column_ordinal],
        )?;
        add_bakeoff_polynomial_to_initial_fri(
            &mut initial_fri_coefficients,
            shifted_normalized_opening_degree_bound,
            OPENING_DEGREE_BOUND_EXCLUSIVE,
            CommonProofSourcePolynomial::from_base_coefficients(
                column_coefficients[column_ordinal].clone(),
            ),
            deep_point,
            deep_evaluations[column_ordinal],
            normalized_batch_challenges[column_ordinal],
        )
        .map_err(|error| failure("add replayed normalized base claim to initial FRI", error))?;
    }
    add_extension_source_polynomial_to_initial_fri(
        &mut initial_fri_coefficients,
        quotient_coefficients,
        source_batch_challenges[COLUMN_COUNT],
    )?;
    add_bakeoff_polynomial_to_initial_fri(
        &mut initial_fri_coefficients,
        shifted_normalized_opening_degree_bound,
        OPENING_DEGREE_BOUND_EXCLUSIVE,
        CommonProofSourcePolynomial::from_extension_coefficients(quotient_coefficients.to_vec()),
        deep_point,
        deep_evaluations[COLUMN_COUNT],
        normalized_batch_challenges[COLUMN_COUNT],
    )
    .map_err(|error| {
        failure(
            "add replayed normalized quotient claim to initial FRI",
            error,
        )
    })?;
    evaluation_domain
        .evaluate_extension_polynomial_in_place(&mut initial_fri_coefficients)
        .map_err(|error| failure("evaluate replayed initial FRI polynomial", error))?;
    Ok(initial_fri_coefficients)
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn generate_packed_deep_fri(
    fixture: &ProofBackendBakeoffFixture,
) -> ProofBackendBakeoffResult<GeneratedPackedDeepFri> {
    let profile = frozen_proof_profile_for_generation(fixture)?;
    let trace_domain = ProofEvaluationDomain::new_subgroup(TRACE_DOMAIN_SIZE)
        .map_err(|error| failure("construct frozen trace subgroup", error))?;
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .map_err(|error| failure("construct frozen evaluation coset", error))?;
    let (column_coefficients, column_evaluations) = build_column_polynomials_and_evaluations(
        &fixture.columns,
        trace_domain,
        evaluation_domain,
    )?;
    let (tree_storage_plans, external_plan, external_accounting) =
        storage_plans(profile.layout.catalog())?;
    let mut storage_plan_iterator = tree_storage_plans.into_iter();
    let mut executor = ProofExternalMemoryExecutor::new(external_plan);
    // The full backing is intentionally resident. The outer process guard must
    // count these bytes in absolute RSS while the adapter counters charge the
    // identical logical reads, writes, and committed transactions.
    let mut storage = BoundedInMemoryExternalMemory::new(
        usize::try_from(external_accounting.peak_stored_byte_length)
            .map_err(|_| "external stored-byte limit does not fit usize".to_owned())?,
    );
    let mut coins = NoPrivateCoins;
    let mut stored_trees = Vec::with_capacity(TREE_COUNT);

    let base_tree = materialize_tree(
        &profile.layout.catalog().entries()[0],
        storage_plan_iterator
            .next()
            .ok_or_else(|| "missing base-tree storage plan".to_owned())?,
        MaterializedTreeValues::BaseColumns(&column_evaluations),
        &mut executor,
        &mut storage,
        &mut coins,
    )?;
    if base_tree.root() != profile.expected_fri_base_root {
        return Err(
            "materialized FRI base root does not match the exact statement binding".to_owned(),
        );
    }
    let mut transcript = CommonProofTranscript::new(
        PROTOCOL_VERSION,
        profile.suite_identifier,
        profile.application_statement_schema_identifier,
        &profile.canonical_header,
        profile.schedule.clone(),
    )
    .map_err(|error| failure("initialize frozen common-proof transcript", error))?;
    transcript
        .absorb_base_root(0, base_tree.root())
        .map_err(|error| failure("absorb frozen base root", error))?;
    stored_trees.push(base_tree);

    let composition_challenges = (0_u32..2)
        .map(|constraint_ordinal| {
            transcript
                .sample_composition_challenge(constraint_ordinal)
                .map_err(|error| failure("sample composition challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
    let quotient_evaluations = construct_full_quotient_evaluations(
        evaluation_domain,
        &column_evaluations,
        &composition_challenges,
    )?;
    drop(column_evaluations);
    let quotient_tree = materialize_tree(
        &profile.layout.catalog().entries()[1],
        storage_plan_iterator
            .next()
            .ok_or_else(|| "missing quotient-tree storage plan".to_owned())?,
        MaterializedTreeValues::ExtensionColumn(&quotient_evaluations),
        &mut executor,
        &mut storage,
        &mut coins,
    )?;
    transcript
        .absorb_quotient_root(0, quotient_tree.root())
        .map_err(|error| failure("absorb frozen quotient root", error))?;
    stored_trees.push(quotient_tree);

    let deep_point = transcript
        .sample_deep_point(0, |candidate| {
            deep_point_is_forbidden(candidate, evaluation_domain)
        })
        .map_err(|error| failure("sample frozen DEEP point", error))?;
    let mut quotient_coefficients = evaluation_domain
        .interpolate_extension_polynomial(&quotient_evaluations)
        .map_err(|error| failure("interpolate full frozen quotient", error))?;
    drop(quotient_evaluations);
    if quotient_coefficients.is_empty()
        || quotient_coefficients.len() > OPENING_DEGREE_BOUND_EXCLUSIVE
    {
        return Err("frozen quotient exceeded its opening degree bound".to_owned());
    }
    let mut source_deep_evaluations = column_coefficients
        .iter()
        .map(|coefficients| evaluate_base_coefficients_at(coefficients, deep_point))
        .collect::<Vec<_>>();
    source_deep_evaluations.push(super::evaluate_extension_at(
        &quotient_coefficients,
        deep_point,
    ));
    let mut deep_evaluations = Vec::with_capacity(BATCHED_FUNCTION_COUNT);
    deep_evaluations.extend_from_slice(&source_deep_evaluations);
    // The shared transcript schedule has one count for serialized evaluations
    // and opening-batch challenges. These exact duplicates are domain-separated
    // coefficient-seed framing only; they are not claimed evaluations of R_i.
    // The fresh verifier requires both halves to match before sampling all
    // eighteen independent batching coefficients.
    deep_evaluations.extend_from_slice(&source_deep_evaluations);
    verify_deep_quotient_identity(deep_point, &deep_evaluations, &composition_challenges)?;
    transcript
        .absorb_deep_evaluations(&deep_evaluations)
        .map_err(|error| failure("absorb frozen DEEP evaluations", error))?;

    let opening_batch_challenges = (0_u32
        ..u32::try_from(BATCHED_FUNCTION_COUNT)
            .map_err(|_| "batched function count does not fit u32".to_owned())?)
        .map(|claim_ordinal| {
            transcript
                .sample_opening_batch_challenge(claim_ordinal)
                .map_err(|error| failure("sample opening-batch challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
    let (source_batch_challenges, normalized_batch_challenges) =
        opening_batch_challenges.split_at(SOURCE_OPENING_CLAIM_COUNT);
    let shifted_normalized_opening_degree_bound = OPENING_DEGREE_BOUND_EXCLUSIVE
        .checked_add(1)
        .ok_or_else(|| "shifted normalized opening degree bound overflowed".to_owned())?;
    // For each source F_i opened to v_i at z, define
    // H_i = (F_i - v_i) / (X - z) and R_i = X H_i. The eighteen independent
    // challenges test I = sum a_i F_i + sum b_i R_i as one RS_16384 word.
    // The local identity X(F_i-v_i)=(X-z)R_i and z != 0 force every accepted
    // R_i to be divisible by X, closing the one-degree opening-quotient gap.
    let mut initial_fri_coefficients =
        vec![ProofChallengeExtensionElement::ZERO; OPENING_DEGREE_BOUND_EXCLUSIVE];
    for column_ordinal in 0..COLUMN_COUNT {
        add_base_source_polynomial_to_initial_fri(
            &mut initial_fri_coefficients,
            &column_coefficients[column_ordinal],
            source_batch_challenges[column_ordinal],
        )?;
        add_bakeoff_polynomial_to_initial_fri(
            &mut initial_fri_coefficients,
            shifted_normalized_opening_degree_bound,
            OPENING_DEGREE_BOUND_EXCLUSIVE,
            CommonProofSourcePolynomial::from_base_coefficients(
                column_coefficients[column_ordinal].clone(),
            ),
            deep_point,
            deep_evaluations[column_ordinal],
            normalized_batch_challenges[column_ordinal],
        )
        .map_err(|error| failure("add shifted normalized base claim to initial FRI", error))?;
    }
    add_extension_source_polynomial_to_initial_fri(
        &mut initial_fri_coefficients,
        &quotient_coefficients,
        source_batch_challenges[COLUMN_COUNT],
    )?;
    add_bakeoff_polynomial_to_initial_fri(
        &mut initial_fri_coefficients,
        shifted_normalized_opening_degree_bound,
        OPENING_DEGREE_BOUND_EXCLUSIVE,
        CommonProofSourcePolynomial::from_extension_coefficients(quotient_coefficients.clone()),
        deep_point,
        deep_evaluations[COLUMN_COUNT],
        normalized_batch_challenges[COLUMN_COUNT],
    )
    .map_err(|error| {
        failure(
            "add shifted normalized quotient claim to initial FRI",
            error,
        )
    })?;
    drop(column_coefficients);
    evaluation_domain
        .evaluate_extension_polynomial_in_place(&mut initial_fri_coefficients)
        .map_err(|error| failure("evaluate frozen initial FRI polynomial", error))?;

    let mut current_fri_evaluations = initial_fri_coefficients;
    let mut current_fri_domain = evaluation_domain;
    for fold_ordinal in 0..FRI_FOLD_COUNT {
        let fold_ordinal_u16 = u16::try_from(fold_ordinal)
            .map_err(|_| "FRI fold ordinal does not fit u16".to_owned())?;
        let fold_challenge = transcript
            .sample_fri_fold_challenge(fold_ordinal_u16)
            .map_err(|error| failure("sample FRI fold challenge", error))?;
        fold_extension_evaluations_in_place(
            &mut current_fri_evaluations,
            current_fri_domain,
            fold_challenge,
        )
        .map_err(|error| failure("fold complete frozen FRI layer", error))?;
        current_fri_domain = current_fri_domain
            .folded()
            .map_err(|error| failure("derive folded frozen FRI domain", error))?;
        if fold_ordinal + 1 < FRI_FOLD_COUNT {
            let catalog_index = fold_ordinal + 2;
            let tree = materialize_tree(
                &profile.layout.catalog().entries()[catalog_index],
                storage_plan_iterator
                    .next()
                    .ok_or_else(|| "missing nonterminal FRI storage plan".to_owned())?,
                MaterializedTreeValues::ExtensionColumn(&current_fri_evaluations),
                &mut executor,
                &mut storage,
                &mut coins,
            )?;
            transcript
                .absorb_fri_layer_root(fold_ordinal_u16, tree.root())
                .map_err(|error| failure("absorb nonterminal FRI root", error))?;
            stored_trees.push(tree);
        }
    }
    if storage_plan_iterator.next().is_some() || stored_trees.len() != TREE_COUNT {
        return Err("frozen Merkle tree count diverged from its catalog".to_owned());
    }
    let mut terminal_coefficients = current_fri_evaluations;
    current_fri_domain
        .interpolate_extension_polynomial_in_place(&mut terminal_coefficients)
        .map_err(|error| failure("interpolate frozen FRI terminal polynomial", error))?;
    if terminal_coefficients.len() > TERMINAL_COEFFICIENT_COUNT {
        return Err("frozen FRI terminal polynomial exceeded degree 255".to_owned());
    }
    terminal_coefficients.resize(
        TERMINAL_COEFFICIENT_COUNT,
        ProofChallengeExtensionElement::ZERO,
    );
    transcript
        .absorb_fri_terminal_coefficients(&terminal_coefficients)
        .map_err(|error| failure("absorb frozen FRI terminal coefficients", error))?;
    let mut sampled_query_representatives = transcript
        .sample_query_representatives()
        .map_err(|error| failure("sample frozen FRI query representatives", error))?;
    let sorted_query_representatives = transcript
        .sorted_query_representatives()
        .map_err(|error| failure("sort frozen FRI query representatives", error))?;
    sampled_query_representatives.sort_unstable();
    if sampled_query_representatives != sorted_query_representatives {
        return Err("frozen FRI query representatives are not canonical".to_owned());
    }

    executor
        .complete_step(&mut storage)
        .map_err(|error| failure("complete Merkle materialization step", error))?;
    let geometries = opening_geometries(profile.layout.catalog())?;
    let query_section_byte_length = common_proof_query_section_byte_length(
        profile.layout.catalog(),
        &geometries,
        &sorted_query_representatives,
    )
    .map_err(|error| failure("derive exact query-section length", error))?;
    let mut sink = BoundedCommonProofByteSink::new(MAXIMUM_PROOF_BYTE_LENGTH)
        .map_err(|error| failure("initialize bounded canonical proof sink", error))?;
    let tree_roots = stored_trees
        .iter()
        .map(StoredCommonProofMerkleTree::root)
        .collect::<Vec<_>>();
    write_common_proof_prefix(
        &mut sink,
        &profile.canonical_header,
        profile.layout.catalog(),
        &tree_roots,
        &deep_evaluations,
        &terminal_coefficients,
        &profile.schedule,
    )
    .map_err(|error| failure("encode canonical packed-DEEP-FRI prefix", error))?;
    let mut query_opening_absorber = transcript
        .begin_query_openings(query_section_byte_length)
        .map_err(|error| failure("begin canonical query-opening transcript round", error))?;
    let query_header = canonical_common_proof_query_section_header(profile.layout.catalog())
        .map_err(|error| failure("encode canonical query-section header", error))?;
    sink.write_bytes(&query_header)
        .map_err(|error| failure("write canonical query-section header", error))?;
    query_opening_absorber
        .absorb(&query_header)
        .map_err(|error| failure("absorb canonical query-section header", error))?;
    for catalog_index in 0..TREE_COUNT {
        let artifact = prefetch_opening(
            &stored_trees[catalog_index],
            &profile.layout.catalog().entries()[catalog_index],
            &sorted_query_representatives,
            &mut executor,
            &mut storage,
        )?;
        let exact_fragment_byte_length = proof_query_tree_byte_length(
            &profile.layout,
            catalog_index,
            &sorted_query_representatives,
        )
        .map_err(|error| failure("derive exact query-tree fragment length", error))?;
        let fragment = encode_common_proof_query_tree_fragment(
            profile.layout.catalog(),
            catalog_index,
            geometries[catalog_index],
            &sorted_query_representatives,
            &artifact,
            exact_fragment_byte_length,
        )
        .map_err(|error| failure("encode canonical query-tree fragment", error))?;
        sink.write_bytes(&fragment)
            .map_err(|error| failure("write canonical query-tree fragment", error))?;
        query_opening_absorber
            .absorb(&fragment)
            .map_err(|error| failure("absorb canonical query-tree fragment", error))?;
    }
    executor
        .complete_step(&mut storage)
        .map_err(|error| failure("complete Merkle opening and deletion step", error))?;
    let usage = executor
        .finish()
        .map_err(|error| failure("finish exact external-memory lifecycle", error))?;
    transcript
        .finish_query_openings(query_opening_absorber)
        .map_err(|error| failure("finish canonical query-opening transcript round", error))?;
    transcript
        .finish()
        .map_err(|error| failure("finish frozen common-proof transcript", error))?;
    if !storage.committed.is_empty()
        || usage.peak_stored_byte_length() != external_accounting.peak_stored_byte_length
        || usage.total_written_byte_length() != external_accounting.total_written_byte_length
        || usage.total_read_byte_length() != external_accounting.total_read_byte_length
        || usage.transaction_count() != external_accounting.transaction_count
        || usage.deleted_object_count() != external_accounting.object_count
        || usage
            .total_written_byte_length()
            .checked_add(usage.total_read_byte_length())
            != Some(external_accounting.total_io_byte_length()?)
    {
        return Err(format!(
            "path-only external-memory usage changed: written={}, read={}, peak={}, transactions={}, deleted={}",
            usage.total_written_byte_length(),
            usage.total_read_byte_length(),
            usage.peak_stored_byte_length(),
            usage.transaction_count(),
            usage.deleted_object_count(),
        ));
    }
    quotient_coefficients.zeroize();
    let canonical_full_proof = sink.finish();
    let expected_proof_byte_length = profile
        .canonical_header
        .len()
        .checked_add(
            super::proof_body_prefix_byte_length(&profile.layout)
                .map_err(|error| failure("derive canonical body-prefix length", error))?,
        )
        .and_then(|length| length.checked_add(query_section_byte_length))
        .ok_or_else(|| "canonical proof byte length overflowed".to_owned())?;
    if canonical_full_proof.len() != expected_proof_byte_length {
        return Err(format!(
            "canonical proof length mismatch: expected {expected_proof_byte_length}, got {}",
            canonical_full_proof.len()
        ));
    }
    let compact_canonical_proof = compact_canonical_proof(&profile, &canonical_full_proof)?;
    Ok(GeneratedPackedDeepFri {
        compact_canonical_proof,
    })
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) struct ProofStorageWidthEvidenceOutput {
    pub(super) public_base_leaf_column_count: usize,
    pub(super) input_identity_shake256_hex: String,
    pub(super) base_root: [u8; 64],
    pub(super) canonical_artifact_byte_length: u64,
    pub(super) recomputed_canonical_artifact_byte_length: u64,
    pub(super) artifact_shake256_hex: String,
    pub(super) source_replay_byte_length: u64,
    pub(super) queried_leaf_payload_byte_length: u64,
    pub(super) public_base_leaf_byte_length: u64,
    pub(super) opened_leaf_element_byte_length: u64,
    pub(super) opened_leaf_range_chunk_count: u64,
    pub(super) canonical_artifact_preleaf_range_chunk_count: u64,
    pub(super) canonical_artifact_postleaf_range_chunk_count: u64,
    pub(super) canonical_artifact_nonleaf_range_chunk_count: u64,
    pub(super) physical_object_peak: u64,
    pub(super) stored_scratch_peak_byte_length: u64,
    pub(super) lde_transform_count: u64,
    pub(super) absorbed_leaf_value_count: u64,
    pub(super) opened_value_count: u64,
    pub(super) external_read_byte_length: u64,
    pub(super) external_written_byte_length: u64,
    pub(super) external_committed_transaction_count: u64,
    pub(super) source_committed_transaction_count: u64,
    pub(super) source_object_seal_transaction_count: u64,
    pub(super) proof_object_seal_transaction_count: u64,
    pub(super) local_record_seal_invocation_count: u64,
    pub(super) sealed_secret_plaintext_byte_length: u64,
    pub(super) custody_cleanup_completed: bool,
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) struct ProofStorageWidthStaticPoint {
    pub(super) width: u64,
    pub(super) source_replay_byte_length: u64,
    pub(super) public_base_leaf_byte_length: u64,
    pub(super) opened_leaf_element_byte_length: u64,
    pub(super) legacy_base_leaf_object_byte_length: u64,
    pub(super) queried_leaf_payload_byte_length: u64,
    pub(super) base_opening_column_payload_byte_length: u64,
    pub(super) opened_leaf_range_chunk_count: u64,
    pub(super) source_physical_object_count: u64,
    pub(super) proof_physical_object_count: u64,
    pub(super) physical_object_peak: u64,
    pub(super) source_committed_transaction_count: u64,
    pub(super) source_object_seal_transaction_count: u64,
    pub(super) proof_object_seal_transaction_count: u64,
    pub(super) local_record_seal_invocation_count: u64,
    pub(super) sealed_secret_plaintext_byte_length: u64,
    pub(super) active_column_lde_scratch_byte_length: u64,
    pub(super) lde_transform_count: u64,
    pub(super) absorbed_leaf_value_count: u64,
    pub(super) opened_value_count: u64,
    pub(super) canonical_proof_byte_length_ceiling: u64,
    pub(super) canonical_artifact_nonleaf_range_chunk_count_ceiling: u64,
    pub(super) transport_byte_length_ceiling: u64,
    pub(super) external_read_byte_length_ceiling: u64,
    pub(super) external_written_byte_length_ceiling: u64,
    pub(super) external_io_byte_length_ceiling: u64,
    pub(super) committed_transaction_count_ceiling: u64,
    pub(super) stored_scratch_peak_byte_length_ceiling: u64,
    pub(super) copied_buffer_byte_length_ceiling: u64,
    pub(super) digest_state_byte_length_ceiling: u64,
    pub(super) digest_state_container_byte_length_ceiling: u64,
    pub(super) frozen_fixture_and_container_byte_length_ceiling: u64,
    pub(super) retained_algebraic_coefficient_byte_length_ceiling: u64,
    pub(super) extension_domain_working_byte_length_ceiling: u64,
    pub(super) canonical_artifact_live_copy_byte_length_ceiling: u64,
    pub(super) canonical_artifact_container_byte_length_ceiling: u64,
    pub(super) opening_artifact_and_transcript_byte_length_ceiling: u64,
    pub(super) prover_public_opening_workspace_byte_length_ceiling: u64,
    pub(super) fresh_verifier_public_opening_workspace_byte_length_ceiling: u64,
    pub(super) fresh_verifier_outer_vector_container_byte_length_ceiling: u64,
    pub(super) boundary_transfer_byte_length_ceiling: u64,
    pub(super) raw_abi_request_copy_workspace_byte_length_ceiling: u64,
    pub(super) raw_abi_response_decode_workspace_byte_length_ceiling: u64,
    pub(super) raw_abi_transfer_workspace_byte_length_ceiling: u64,
    pub(super) browser_operation_registry_byte_length_ceiling: u64,
    pub(super) native_custody_metadata_byte_length_ceiling: u64,
    pub(super) wasm_memory_byte_length_ceiling: u64,
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn frozen_fixture_and_container_byte_length_ceiling() -> ProofBackendBakeoffResult<u64> {
    let fixture = super::proof_backend_bakeoff::frozen_fixture()?;
    let vector_header_byte_length = u64::try_from(core::mem::size_of::<Vec<u8>>())
        .map_err(|_| "frozen fixture vector header length does not fit u64".to_owned())?;
    let container_byte_length = u64::try_from(COLUMN_COUNT)
        .ok()
        .and_then(|count| count.checked_add(2))
        .and_then(|count| count.checked_mul(vector_header_byte_length))
        .and_then(|length| {
            length.checked_add(
                u64::try_from(core::mem::size_of::<[u8; MERKLE_DIGEST_BYTE_LENGTH]>()).ok()?,
            )
        })
        .and_then(|length| length.checked_add(u64::try_from(core::mem::size_of::<String>()).ok()?))
        .ok_or_else(|| "frozen fixture container ceiling overflowed".to_owned())?;
    let column_payload_byte_length = fixture.columns.iter().try_fold(0_u64, |total, column| {
        u64::try_from(column.capacity())
            .ok()
            .and_then(|capacity| {
                capacity.checked_mul(u64::try_from(core::mem::size_of::<u64>()).ok()?)
            })
            .and_then(|length| total.checked_add(length))
            .ok_or_else(|| "frozen fixture column payload ceiling overflowed".to_owned())
    })?;
    let canonical_statement_payload_byte_length = u64::try_from(
        fixture
            .canonical_core_statement
            .capacity()
            .checked_add(fixture.canonical_fri_statement.capacity())
            .ok_or_else(|| "frozen statement capacity overflowed".to_owned())?,
    )
    .map_err(|_| "frozen statement capacity does not fit u64".to_owned())?;
    let input_identity_payload_byte_length =
        u64::try_from(fixture.input_identity_shake256_hex.capacity())
            .map_err(|_| "frozen input identity capacity does not fit u64".to_owned())?;
    let allocation_count = u64::try_from(COLUMN_COUNT + 3)
        .map_err(|_| "frozen fixture allocation count does not fit u64".to_owned())?;
    container_byte_length
        .checked_add(column_payload_byte_length)
        .and_then(|length| length.checked_add(canonical_statement_payload_byte_length))
        .and_then(|length| length.checked_add(input_identity_payload_byte_length))
        .and_then(|length| {
            allocation_count
                .checked_mul(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
                .and_then(|overhead| length.checked_add(overhead))
        })
        .ok_or_else(|| "frozen fixture memory ceiling overflowed".to_owned())
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn raw_abi_transfer_workspace_byte_length_ceilings() -> ProofBackendBakeoffResult<(u64, u64, u64)> {
    let chunk_byte_length = u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
    let request_header_byte_length = u64::try_from(EXTERNAL_MEMORY_REQUEST_HEADER_BYTE_LENGTH)
        .map_err(|_| "external-memory request header length does not fit u64".to_owned())?;
    let operation_header_byte_length = u64::try_from(EXTERNAL_MEMORY_OPERATION_HEADER_BYTE_LENGTH)
        .map_err(|_| "external-memory operation header length does not fit u64".to_owned())?;
    let maximum_encoded_append_request_byte_length = chunk_byte_length
        .checked_add(request_header_byte_length)
        .and_then(|length| length.checked_add(operation_header_byte_length))
        .ok_or_else(|| "encoded append request length overflowed".to_owned())?;
    let request_container_byte_length =
        u64::try_from(core::mem::size_of::<ProofExternalMemoryTransactionRequest>())
            .map_err(|_| "external-memory request container length does not fit u64".to_owned())?;
    let native_operation_byte_length =
        u64::try_from(core::mem::size_of::<ProofExternalMemoryTransactionOperation>())
            .map_err(|_| "external-memory operation length does not fit u64".to_owned())?;
    if native_operation_byte_length > WIDTH_CONSERVATIVE_EXTERNAL_MEMORY_OPERATION_BYTE_LENGTH {
        return Err("external-memory operation exceeded its native64 static ceiling".to_owned());
    }
    let operation_vector_storage_byte_length =
        u64::try_from(EXTERNAL_MEMORY_SINGLE_OPERATION_VECTOR_CAPACITY_CEILING)
            .ok()
            .and_then(|capacity| {
                WIDTH_CONSERVATIVE_EXTERNAL_MEMORY_OPERATION_BYTE_LENGTH.checked_mul(capacity)
            })
            .ok_or_else(|| "external-memory operation storage ceiling overflowed".to_owned())?;
    let vector_header_byte_length = u64::try_from(core::mem::size_of::<Vec<u8>>())
        .map_err(|_| "raw ABI vector header length does not fit u64".to_owned())?;
    let read_result_vector_storage_byte_length =
        u64::try_from(EXTERNAL_MEMORY_SINGLE_READ_RESULT_VECTOR_CAPACITY_CEILING)
            .ok()
            .and_then(|capacity| capacity.checked_mul(vector_header_byte_length))
            .ok_or_else(|| "read-result vector backing ceiling overflowed".to_owned())?;
    let append_recycler_vector_storage_byte_length =
        u64::try_from(EXTERNAL_MEMORY_SINGLE_APPEND_RECYCLER_CAPACITY_CEILING)
            .ok()
            .and_then(|capacity| capacity.checked_mul(vector_header_byte_length))
            .ok_or_else(|| "append recycler vector backing ceiling overflowed".to_owned())?;

    // At append request copy after an earlier read, seven maximum-payload
    // allocations coexist: browser append/read scratch, request-owned append,
    // recycled read result, operation encoding, cached request, and the raw
    // ABI boundary. The request, its one-operation backing, and the emptied
    // append recycler's fixed outer backing remain live.
    let request_copy_payload_byte_length = chunk_byte_length
        .checked_mul(4)
        .and_then(|length| {
            chunk_byte_length
                .checked_add(operation_header_byte_length)
                .and_then(|operation_encoding| length.checked_add(operation_encoding))
        })
        .and_then(|length| {
            maximum_encoded_append_request_byte_length
                .checked_mul(2)
                .and_then(|encodings| length.checked_add(encodings))
        })
        .ok_or_else(|| "raw ABI request-copy payload ceiling overflowed".to_owned())?;
    let request_copy_container_byte_length = vector_header_byte_length
        .checked_mul(4)
        .and_then(|length| length.checked_add(vector_header_byte_length))
        .and_then(|length| length.checked_add(read_result_vector_storage_byte_length))
        .and_then(|length| length.checked_add(vector_header_byte_length))
        .and_then(|length| length.checked_add(append_recycler_vector_storage_byte_length))
        .and_then(|length| length.checked_add(request_container_byte_length))
        .and_then(|length| length.checked_add(operation_vector_storage_byte_length))
        .ok_or_else(|| "raw ABI request-copy container ceiling overflowed".to_owned())?;
    let request_copy_workspace_byte_length_ceiling = request_copy_payload_byte_length
        .checked_add(request_copy_container_byte_length)
        .and_then(|length| {
            10_u64
                .checked_mul(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
                .and_then(|overhead| length.checked_add(overhead))
        })
        .ok_or_else(|| "raw ABI request-copy workspace ceiling overflowed".to_owned())?;

    // Supplying the empty append response clears, but deliberately retains,
    // the cached request allocation. The fixed raw ABI boundary allocation
    // also remains live. Response decoding constructs a local empty
    // read-result Vec while the runtime's empty recycler header remains live.
    let append_response_decode_payload_byte_length = chunk_byte_length
        .checked_mul(4)
        .and_then(|length| {
            chunk_byte_length
                .checked_add(operation_header_byte_length)
                .and_then(|operation_encoding| length.checked_add(operation_encoding))
        })
        .and_then(|length| length.checked_add(maximum_encoded_append_request_byte_length))
        .and_then(|length| length.checked_add(maximum_encoded_append_request_byte_length))
        .ok_or_else(|| "raw ABI append-response payload ceiling overflowed".to_owned())?;
    let append_response_decode_workspace_byte_length_ceiling =
        append_response_decode_payload_byte_length
            .checked_add(request_copy_container_byte_length)
            .and_then(|length| length.checked_add(vector_header_byte_length))
            .and_then(|length| {
                10_u64
                    .checked_mul(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
                    .and_then(|overhead| length.checked_add(overhead))
            })
            .ok_or_else(|| "raw ABI append-response workspace ceiling overflowed".to_owned())?;

    // At a full read response after an append, the recycler retains one append
    // payload and its four-slot outer backing while the decoded read result is
    // filled. The cached request, fixed raw ABI boundary, operation encoding,
    // and the emptied runtime read-recycler header keep their capacities.
    let read_response_decode_payload_byte_length = chunk_byte_length
        .checked_mul(4)
        .and_then(|length| {
            chunk_byte_length
                .checked_add(operation_header_byte_length)
                .and_then(|operation_encoding| length.checked_add(operation_encoding))
        })
        .and_then(|length| length.checked_add(maximum_encoded_append_request_byte_length))
        .and_then(|length| length.checked_add(maximum_encoded_append_request_byte_length))
        .ok_or_else(|| "raw ABI response-decode payload ceiling overflowed".to_owned())?;
    let read_response_decode_container_byte_length = vector_header_byte_length
        .checked_mul(4)
        .and_then(|length| length.checked_add(vector_header_byte_length))
        .and_then(|length| length.checked_add(append_recycler_vector_storage_byte_length))
        .and_then(|length| length.checked_add(vector_header_byte_length))
        .and_then(|length| length.checked_add(vector_header_byte_length))
        .and_then(|length| length.checked_add(read_result_vector_storage_byte_length))
        .and_then(|length| length.checked_add(request_container_byte_length))
        .and_then(|length| length.checked_add(operation_vector_storage_byte_length))
        .ok_or_else(|| "raw ABI read-response container ceiling overflowed".to_owned())?;
    let read_response_decode_workspace_byte_length_ceiling =
        read_response_decode_payload_byte_length
            .checked_add(read_response_decode_container_byte_length)
            .and_then(|length| {
                10_u64
                    .checked_mul(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
                    .and_then(|overhead| length.checked_add(overhead))
            })
            .ok_or_else(|| "raw ABI response-decode workspace ceiling overflowed".to_owned())?;
    let response_decode_workspace_byte_length_ceiling =
        append_response_decode_workspace_byte_length_ceiling
            .max(read_response_decode_workspace_byte_length_ceiling);
    Ok((
        request_copy_workspace_byte_length_ceiling,
        response_decode_workspace_byte_length_ceiling,
        request_copy_workspace_byte_length_ceiling
            .max(response_decode_workspace_byte_length_ceiling),
    ))
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
fn native_custody_metadata_byte_length_ceiling(width: u64) -> ProofBackendBakeoffResult<u64> {
    let path_count = width
        .checked_add(2)
        .ok_or_else(|| "native custody path count overflowed".to_owned())?;
    let observed_path_header_byte_length = u64::try_from(core::mem::size_of::<PathBuf>())
        .map_err(|_| "native custody path header length does not fit u64".to_owned())?;
    if observed_path_header_byte_length > WIDTH_NATIVE_CUSTODY_PATH_HEADER_BYTE_LENGTH_CEILING {
        return Err("native custody path header exceeds its frozen ceiling".to_owned());
    }
    let observed_path_vector_header_byte_length =
        u64::try_from(core::mem::size_of::<Vec<PathBuf>>())
            .map_err(|_| "native custody path-vector header length does not fit u64".to_owned())?;
    if observed_path_vector_header_byte_length
        > WIDTH_NATIVE_CUSTODY_PATH_VECTOR_HEADER_BYTE_LENGTH_CEILING
    {
        return Err("native custody path-vector header exceeds its frozen ceiling".to_owned());
    }
    let path_payload_and_container_byte_length =
        WIDTH_NATIVE_CUSTODY_PATH_HEADER_BYTE_LENGTH_CEILING
            .checked_add(
                u64::try_from(WIDTH_MAXIMUM_NATIVE_CUSTODY_PATH_BYTE_LENGTH)
                    .map_err(|_| "native custody path limit does not fit u64".to_owned())?,
            )
            .and_then(|length| {
                length.checked_add(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
            })
            .ok_or_else(|| "native custody path metadata ceiling overflowed".to_owned())?;
    path_count
        .checked_mul(path_payload_and_container_byte_length)
        .and_then(|length| {
            length.checked_add(WIDTH_NATIVE_CUSTODY_PATH_VECTOR_HEADER_BYTE_LENGTH_CEILING)
        })
        .and_then(|length| {
            length.checked_add(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
        })
        .ok_or_else(|| "native custody metadata ceiling overflowed".to_owned())
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) fn proof_storage_width_static_point(
    public_base_leaf_column_count: usize,
) -> ProofBackendBakeoffResult<ProofStorageWidthStaticPoint> {
    if !(MINIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT..=MAXIMUM_PUBLIC_BASE_LEAF_COLUMN_COUNT)
        .contains(&public_base_leaf_column_count)
    {
        return Err("static public base width is outside the scheduled domain".to_owned());
    }
    let input_identity_shake256_hex = format!("{public_base_leaf_column_count:0128x}");
    let (profile, _) = public_width_proof_profile(
        &input_identity_shake256_hex,
        public_base_leaf_column_count,
        [1_u8; 64],
    )?;
    let proof_ceiling = super::canonical_common_proof_byte_length_ceiling(
        profile.canonical_header.len(),
        &profile.layout,
    )
    .map_err(|error| failure("derive public-width canonical proof ceiling", error))?;
    let canonical_proof_byte_length_ceiling = u64::try_from(proof_ceiling.proof_byte_length())
        .map_err(|_| "canonical proof ceiling does not fit u64".to_owned())?
        .checked_sub(MERKLE_DIGEST_BYTE_LENGTH as u64)
        .ok_or_else(|| "compact canonical proof ceiling underflowed".to_owned())?;
    let width = u64::try_from(public_base_leaf_column_count)
        .map_err(|_| "public base width does not fit u64".to_owned())?;
    let source_replay_byte_length = PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN
        .checked_mul(width)
        .ok_or_else(|| "static source replay byte length overflowed".to_owned())?;
    let public_base_leaf_byte_length = 124_u64
        .checked_add(
            16_u64
                .checked_mul(width)
                .ok_or_else(|| "static public leaf length overflowed".to_owned())?,
        )
        .ok_or_else(|| "static public leaf length overflowed".to_owned())?;
    let catalog_leaf_byte_length = u64::try_from(
        super::body::canonical_leaf_byte_length(&profile.layout.catalog().entries()[0])
            .map_err(|error| failure("derive static public leaf length", error))?,
    )
    .map_err(|_| "catalog public leaf length does not fit u64".to_owned())?;
    if catalog_leaf_byte_length != public_base_leaf_byte_length {
        return Err("static public leaf formula diverges from the catalog".to_owned());
    }
    let opened_leaf_element_byte_length = public_base_leaf_byte_length
        .checked_add(4)
        .ok_or_else(|| "static opened-leaf element length overflowed".to_owned())?;
    let legacy_base_leaf_object_byte_length = public_base_leaf_byte_length
        .checked_mul(65_536)
        .ok_or_else(|| "legacy base-leaf object length overflowed".to_owned())?;
    let queried_leaf_payload_byte_length = public_base_leaf_byte_length
        .checked_mul(u64::from(UNIQUE_QUERY_COUNT))
        .ok_or_else(|| "static queried leaf payload overflowed".to_owned())?;
    let base_opening_column_payload_byte_length = 16_u64
        .checked_mul(width)
        .and_then(|length| length.checked_mul(u64::from(UNIQUE_QUERY_COUNT)))
        .ok_or_else(|| "static base-opening column payload overflowed".to_owned())?;
    let opened_leaf_range_chunk_count = exact_chunk_count(
        opened_leaf_element_byte_length,
        u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
    )?
    .checked_mul(u64::from(UNIQUE_QUERY_COUNT))
    .ok_or_else(|| "static opened-leaf range chunk count overflowed".to_owned())?;
    let source_committed_transaction_count = width
        .checked_mul(24)
        .ok_or_else(|| "static source transaction count overflowed".to_owned())?;
    // The 183 framed opened-leaf elements are each independent semantic
    // ranges. The bytes before and after them form two more semantic ranges;
    // splitting an arbitrary byte string at one boundary adds at most one
    // chunk beyond chunking the unsplit canonical proof.
    let canonical_artifact_nonleaf_range_chunk_count_ceiling = exact_chunk_count(
        canonical_proof_byte_length_ceiling,
        u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH),
    )?
    .checked_add(1)
    .ok_or_else(|| "static nonleaf artifact range ceiling overflowed".to_owned())?;
    let committed_transaction_count_ceiling = source_committed_transaction_count
        .checked_add(3)
        .and_then(|count| {
            opened_leaf_range_chunk_count
                .checked_add(canonical_artifact_nonleaf_range_chunk_count_ceiling)
                .and_then(|range_count| range_count.checked_mul(2))
                .and_then(|artifact_count| count.checked_add(artifact_count))
        })
        .ok_or_else(|| "static transaction ceiling overflowed".to_owned())?;
    let external_written_byte_length_ceiling = source_replay_byte_length
        .checked_add(canonical_proof_byte_length_ceiling)
        .ok_or_else(|| "static written-byte ceiling overflowed".to_owned())?;
    let external_read_byte_length_ceiling = source_replay_byte_length
        .checked_mul(6)
        .and_then(|length| length.checked_add(canonical_proof_byte_length_ceiling))
        .ok_or_else(|| "static read-byte ceiling overflowed".to_owned())?;
    let external_io_byte_length_ceiling = external_read_byte_length_ceiling
        .checked_add(external_written_byte_length_ceiling)
        .ok_or_else(|| "static I/O ceiling overflowed".to_owned())?;
    let stored_scratch_peak_byte_length_ceiling = source_replay_byte_length
        .checked_add(canonical_proof_byte_length_ceiling)
        .ok_or_else(|| "static stored-scratch ceiling overflowed".to_owned())?;
    let active_column_lde_scratch_byte_length = WIDTH_ACTIVE_COLUMN_LDE_SCRATCH_BYTE_LENGTH;
    let copied_buffer_byte_length_ceiling =
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_COPIED_BUFFER_BYTE_LENGTH;
    let boundary_transfer_byte_length_ceiling =
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_BOUNDARY_TRANSFER_LIVE_BYTE_LENGTH;
    let digest_state_byte_length = u64::try_from(core::mem::size_of::<
        ProofOraclePhasePairLeafDigestBuilder,
    >())
    .map_err(|_| "digest state length does not fit u64".to_owned())?
    .checked_mul(65_536)
    .and_then(|length| {
        length.checked_add(u64::try_from(core::mem::size_of::<Option<StreamingHash512>>()).ok()?)
    })
    .ok_or_else(|| "digest-state memory ceiling overflowed".to_owned())?;
    let digest_state_container_byte_length_ceiling = u64::try_from(core::mem::size_of::<
        Vec<ProofOraclePhasePairLeafDigestBuilder>,
    >())
    .map_err(|_| "digest-state vector header length does not fit u64".to_owned())?
    .checked_add(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
    .ok_or_else(|| "digest-state container ceiling overflowed".to_owned())?;
    let frozen_fixture_and_container_byte_length_ceiling =
        frozen_fixture_and_container_byte_length_ceiling()?;
    let retained_algebraic_coefficient_byte_length_ceiling = u64::try_from(COLUMN_COUNT)
        .ok()
        .and_then(|count| count.checked_mul(u64::try_from(TRACE_DOMAIN_SIZE).ok()?))
        .and_then(|count| {
            count.checked_mul(u64::try_from(core::mem::size_of::<ProofBaseFieldElement>()).ok()?)
        })
        .ok_or_else(|| "retained coefficient memory ceiling overflowed".to_owned())?;
    let one_extension_domain_byte_length = u64::try_from(EVALUATION_DOMAIN_SIZE)
        .ok()
        .and_then(|count| {
            count.checked_mul(
                u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>()).ok()?,
            )
        })
        .ok_or_else(|| "extension-domain memory ceiling overflowed".to_owned())?;
    // The quotient evaluations coexist with at most one initial/replayed FRI
    // evaluation vector. All transforms are in place.
    let extension_domain_working_byte_length_ceiling = one_extension_domain_byte_length
        .checked_mul(2)
        .ok_or_else(|| "extension working-memory ceiling overflowed".to_owned())?;
    // Compacting or expanding the canonical proof can retain the input and
    // output vectors simultaneously. Opened leaves/frontiers and transcript
    // metadata are separately bounded by one complete canonical-proof ceiling.
    let canonical_artifact_live_copy_byte_length_ceiling = canonical_proof_byte_length_ceiling
        .checked_mul(2)
        .ok_or_else(|| "canonical artifact live-copy ceiling overflowed".to_owned())?;
    let canonical_artifact_container_byte_length_ceiling =
        u64::try_from(core::mem::size_of::<Vec<u8>>())
            .map_err(|_| "canonical artifact vector header length does not fit u64".to_owned())?
            .checked_add(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
            .and_then(|length| length.checked_mul(3))
            .ok_or_else(|| "canonical artifact container ceiling overflowed".to_owned())?;
    let opening_artifact_and_transcript_byte_length_ceiling = canonical_proof_byte_length_ceiling;
    let query_count = u64::from(UNIQUE_QUERY_COUNT);
    let proof_tree_value_byte_length = u64::try_from(core::mem::size_of::<ProofTreeValue>())
        .map_err(|_| "proof-tree value length does not fit u64".to_owned())?;
    let vector_header_byte_length = u64::try_from(core::mem::size_of::<Vec<ProofTreeValue>>())
        .map_err(|_| "vector header length does not fit u64".to_owned())?;
    let prover_public_opening_value_byte_length = query_count
        .checked_mul(width)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_mul(proof_tree_value_byte_length))
        .ok_or_else(|| "prover public-opening value ceiling overflowed".to_owned())?;
    let prover_public_opening_container_byte_length = query_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_mul(vector_header_byte_length))
        .ok_or_else(|| "prover public-opening container ceiling overflowed".to_owned())?;
    let prover_public_opening_allocation_count = query_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(2))
        .ok_or_else(|| "prover public-opening allocation count overflowed".to_owned())?;
    let prover_public_opening_workspace_byte_length_ceiling =
        prover_public_opening_value_byte_length
            .checked_add(prover_public_opening_container_byte_length)
            .and_then(|length| {
                prover_public_opening_allocation_count
                    .checked_mul(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
                    .and_then(|overhead| length.checked_add(overhead))
            })
            .ok_or_else(|| "prover public-opening workspace ceiling overflowed".to_owned())?;

    // Fresh verification holds one replay-derived base map and seven decoded
    // authenticated maps at the comparison point. The base map pair occurs
    // twice at full width; the other six authenticated maps are width one.
    // BTree storage is bounded pessimistically as one 16-entry node payload
    // per logical entry, plus one allocator allowance for every node and
    // every inner value vector.
    let extension_element_byte_length =
        u64::try_from(core::mem::size_of::<ProofChallengeExtensionElement>())
            .map_err(|_| "extension element length does not fit u64".to_owned())?;
    let fresh_verifier_extension_element_count = query_count
        .checked_mul(width)
        .and_then(|count| count.checked_mul(4))
        .and_then(|count| {
            query_count
                .checked_mul(u64::try_from(TREE_COUNT - 1).ok()?.checked_mul(2)?)
                .and_then(|extension_tree_count| count.checked_add(extension_tree_count))
        })
        .ok_or_else(|| "fresh-verifier public-opening element count overflowed".to_owned())?;
    let fresh_verifier_value_byte_length = fresh_verifier_extension_element_count
        .checked_mul(extension_element_byte_length)
        .ok_or_else(|| "fresh-verifier public-opening value ceiling overflowed".to_owned())?;
    let fresh_verifier_map_count = u64::try_from(TREE_COUNT)
        .map_err(|_| "tree count does not fit u64".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "fresh-verifier map count overflowed".to_owned())?;
    let fresh_verifier_entry_count = query_count
        .checked_mul(fresh_verifier_map_count)
        .ok_or_else(|| "fresh-verifier map entry count overflowed".to_owned())?;
    let map_entry_byte_length =
        u64::try_from(core::mem::size_of::<(u64, AuthenticatedPhasePair)>())
            .map_err(|_| "authenticated map entry length does not fit u64".to_owned())?;
    let fresh_verifier_container_byte_length = fresh_verifier_entry_count
        .checked_mul(WIDTH_CONSERVATIVE_BTREE_ENTRY_STORAGE_MULTIPLIER)
        .and_then(|count| count.checked_mul(map_entry_byte_length))
        .and_then(|length| {
            fresh_verifier_map_count
                .checked_mul(
                    u64::try_from(core::mem::size_of::<BTreeMap<u64, AuthenticatedPhasePair>>())
                        .ok()?,
                )
                .and_then(|map_headers| length.checked_add(map_headers))
        })
        .and_then(|length| {
            u64::try_from(TREE_COUNT)
                .ok()?
                .checked_mul(u64::try_from(core::mem::size_of::<AuthenticatedTreeOpening>()).ok()?)
                .and_then(|opening_headers| length.checked_add(opening_headers))
        })
        .ok_or_else(|| "fresh-verifier container ceiling overflowed".to_owned())?;
    let fresh_verifier_allocation_count = fresh_verifier_entry_count
        .checked_mul(3)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| "fresh-verifier allocation count overflowed".to_owned())?;
    let fresh_verifier_public_opening_workspace_byte_length_ceiling =
        fresh_verifier_value_byte_length
            .checked_add(fresh_verifier_container_byte_length)
            .and_then(|length| {
                fresh_verifier_allocation_count
                    .checked_mul(WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH)
                    .and_then(|overhead| length.checked_add(overhead))
            })
            .ok_or_else(|| {
                "fresh-verifier public-opening workspace ceiling overflowed".to_owned()
            })?;
    let fresh_verifier_outer_vector_container_byte_length_ceiling =
        u64::try_from(core::mem::size_of::<Vec<Vec<ProofChallengeExtensionElement>>>())
            .map_err(|_| "fresh-verifier outer vector header length does not fit u64".to_owned())?
            .checked_mul(2)
            .and_then(|length| {
                query_count
                    .checked_mul(2)
                    .and_then(|count| count.checked_mul(vector_header_byte_length))
                    .and_then(|headers| length.checked_add(headers))
            })
            .and_then(|length| {
                WIDTH_CONSERVATIVE_HEAP_ALLOCATION_OVERHEAD_BYTE_LENGTH
                    .checked_mul(2)
                    .and_then(|overhead| length.checked_add(overhead))
            })
            .ok_or_else(|| "fresh-verifier outer vector ceiling overflowed".to_owned())?;
    let (
        raw_abi_request_copy_workspace_byte_length_ceiling,
        raw_abi_response_decode_workspace_byte_length_ceiling,
        raw_abi_transfer_workspace_byte_length_ceiling,
    ) = raw_abi_transfer_workspace_byte_length_ceilings()?;
    let browser_operation_registry_byte_length_ceiling =
        proof_storage_width_browser_evidence::browser_operation_registry_byte_length_ceiling()?;
    let native_custody_metadata_byte_length_ceiling =
        native_custody_metadata_byte_length_ceiling(width)?;
    let wasm_memory_byte_length_ceiling = digest_state_byte_length
        .checked_add(digest_state_container_byte_length_ceiling)
        .and_then(|length| length.checked_add(frozen_fixture_and_container_byte_length_ceiling))
        .and_then(|length| length.checked_add(active_column_lde_scratch_byte_length))
        .and_then(|length| length.checked_add(retained_algebraic_coefficient_byte_length_ceiling))
        .and_then(|length| length.checked_add(extension_domain_working_byte_length_ceiling))
        .and_then(|length| length.checked_add(canonical_artifact_live_copy_byte_length_ceiling))
        .and_then(|length| length.checked_add(canonical_artifact_container_byte_length_ceiling))
        .and_then(|length| length.checked_add(opening_artifact_and_transcript_byte_length_ceiling))
        .and_then(|length| length.checked_add(prover_public_opening_workspace_byte_length_ceiling))
        .and_then(|length| {
            length.checked_add(fresh_verifier_public_opening_workspace_byte_length_ceiling)
        })
        .and_then(|length| {
            length.checked_add(fresh_verifier_outer_vector_container_byte_length_ceiling)
        })
        .and_then(|length| length.checked_add(raw_abi_transfer_workspace_byte_length_ceiling))
        .and_then(|length| length.checked_add(browser_operation_registry_byte_length_ceiling))
        .ok_or_else(|| "WASM memory ceiling overflowed".to_owned())?;
    let physical_object_peak = width
        .checked_add(1)
        .ok_or_else(|| "static physical object count overflowed".to_owned())?;
    let local_record_seal_invocation_count = 0_u64;
    let sealed_secret_plaintext_byte_length = 0_u64;
    if canonical_proof_byte_length_ceiling
        > u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .map_err(|_| "common-proof cap does not fit u64".to_owned())?
        || canonical_proof_byte_length_ceiling > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || stored_scratch_peak_byte_length_ceiling
            > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        || physical_object_peak
            > u64::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
                .map_err(|_| "external object cap does not fit u64".to_owned())?
        || copied_buffer_byte_length_ceiling > width_maximum_copied_buffer_byte_length()?
        || wasm_memory_byte_length_ceiling > MAXIMUM_COMMON_PROOF_WASM_RESIDENT_BYTE_LENGTH
        || local_record_seal_invocation_count
            > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
        || sealed_secret_plaintext_byte_length
            > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT
    {
        return Err("static public-width point exceeds an absolute cap".to_owned());
    }
    Ok(ProofStorageWidthStaticPoint {
        width,
        source_replay_byte_length,
        public_base_leaf_byte_length,
        opened_leaf_element_byte_length,
        legacy_base_leaf_object_byte_length,
        queried_leaf_payload_byte_length,
        base_opening_column_payload_byte_length,
        opened_leaf_range_chunk_count,
        source_physical_object_count: width,
        proof_physical_object_count: 1,
        physical_object_peak,
        source_committed_transaction_count,
        source_object_seal_transaction_count: width,
        proof_object_seal_transaction_count: 1,
        local_record_seal_invocation_count,
        sealed_secret_plaintext_byte_length,
        active_column_lde_scratch_byte_length,
        lde_transform_count: 6_u64
            .checked_mul(width)
            .ok_or_else(|| "static LDE-transform count overflowed".to_owned())?,
        absorbed_leaf_value_count: 393_216_u64
            .checked_mul(width)
            .ok_or_else(|| "static absorbed-value count overflowed".to_owned())?,
        opened_value_count: 366_u64
            .checked_mul(width)
            .ok_or_else(|| "static opened-value count overflowed".to_owned())?,
        canonical_proof_byte_length_ceiling,
        canonical_artifact_nonleaf_range_chunk_count_ceiling,
        transport_byte_length_ceiling: canonical_proof_byte_length_ceiling,
        external_read_byte_length_ceiling,
        external_written_byte_length_ceiling,
        external_io_byte_length_ceiling,
        committed_transaction_count_ceiling,
        stored_scratch_peak_byte_length_ceiling,
        copied_buffer_byte_length_ceiling,
        digest_state_byte_length_ceiling: digest_state_byte_length,
        digest_state_container_byte_length_ceiling,
        frozen_fixture_and_container_byte_length_ceiling,
        retained_algebraic_coefficient_byte_length_ceiling,
        extension_domain_working_byte_length_ceiling,
        canonical_artifact_live_copy_byte_length_ceiling,
        canonical_artifact_container_byte_length_ceiling,
        opening_artifact_and_transcript_byte_length_ceiling,
        prover_public_opening_workspace_byte_length_ceiling,
        fresh_verifier_public_opening_workspace_byte_length_ceiling,
        fresh_verifier_outer_vector_container_byte_length_ceiling,
        boundary_transfer_byte_length_ceiling,
        raw_abi_request_copy_workspace_byte_length_ceiling,
        raw_abi_response_decode_workspace_byte_length_ceiling,
        raw_abi_transfer_workspace_byte_length_ceiling,
        browser_operation_registry_byte_length_ceiling,
        native_custody_metadata_byte_length_ceiling,
        wasm_memory_byte_length_ceiling,
    })
}

#[cfg(any(
    feature = "proof-storage-width-evidence",
    feature = "proof-storage-width-browser-evidence"
))]
fn base_opened_leaf_element_ranges(
    profile: &FrozenProofProfile,
    query_header_byte_length: usize,
    local_ranges: &[(usize, usize)],
) -> ProofBackendBakeoffResult<Vec<(usize, usize)>> {
    if local_ranges.len()
        != usize::try_from(UNIQUE_QUERY_COUNT).expect("fixed query count must fit usize")
        || !local_ranges.windows(2).all(|pair| pair[0].1 == pair[1].0)
    {
        return Err("base opened-leaf layout is not the canonical contiguous list".to_owned());
    }
    let full_prefix_byte_length = super::proof_body_prefix_byte_length(&profile.layout)
        .map_err(|error| failure("derive public-width proof prefix length", error))?;
    let base_fragment_offset = profile
        .canonical_header
        .len()
        .checked_add(full_prefix_byte_length)
        .and_then(|offset| offset.checked_sub(MERKLE_DIGEST_BYTE_LENGTH))
        .and_then(|offset| offset.checked_add(query_header_byte_length))
        .ok_or_else(|| "compact base fragment offset overflowed".to_owned())?;
    let mut ranges = Vec::with_capacity(local_ranges.len());
    for &(local_start, local_end) in local_ranges {
        ranges.push((
            base_fragment_offset
                .checked_add(local_start)
                .ok_or_else(|| "base opened-leaf absolute offset overflowed".to_owned())?,
            base_fragment_offset
                .checked_add(local_end)
                .ok_or_else(|| "base opened-leaf absolute end overflowed".to_owned())?,
        ));
    }
    Ok(ranges)
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "proof-storage-width-evidence"
))]
pub(super) fn execute_proof_storage_width_evidence(
    fixture: &ProofBackendBakeoffFixture,
    public_base_leaf_column_count: usize,
    custody_directory_path: PathBuf,
) -> ProofBackendBakeoffResult<ProofStorageWidthEvidenceOutput> {
    let mut custody = PublicSourceReplayCustody::new(
        fixture,
        public_base_leaf_column_count,
        custody_directory_path,
    )?;
    let input_identity_shake256_hex = custody.checked_input_identity().to_owned();
    let canonical_core_statement = canonical_public_width_core_statement(
        &input_identity_shake256_hex,
        public_base_leaf_column_count,
    )?;
    let schedule = transcript_schedule()?;
    let root_catalog = proof_catalog_with_public_base_width(
        &canonical_core_statement,
        &input_identity_shake256_hex,
        &schedule,
        public_base_leaf_column_count,
    )?;
    let trace_domain = ProofEvaluationDomain::new_subgroup(TRACE_DOMAIN_SIZE)
        .map_err(|error| failure("construct public-width trace subgroup", error))?;
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .map_err(|error| failure("construct public-width evaluation coset", error))?;
    let (base_root, column_coefficients) = recompute_public_base_root(
        &root_catalog.entries()[0],
        &mut custody,
        trace_domain,
        evaluation_domain,
    )?;
    let (profile, canonical_statement) = public_width_proof_profile(
        &input_identity_shake256_hex,
        public_base_leaf_column_count,
        base_root,
    )?;
    if profile.canonical_core_statement != canonical_core_statement
        || profile.layout.catalog().entries()[0]
            .common_context()
            .ok_or_else(|| "public-width profile lost its base context".to_owned())?
            .context_hash()
            .map_err(|error| failure("hash public-width profile base context", error))?
            != root_catalog.entries()[0]
                .common_context()
                .ok_or_else(|| "public-width root catalog lost its base context".to_owned())?
                .context_hash()
                .map_err(|error| failure("hash public-width root base context", error))?
    {
        return Err("public-width root catalog diverges from its proof profile".to_owned());
    }

    let mut transcript = CommonProofTranscript::new(
        PROTOCOL_VERSION,
        profile.suite_identifier,
        profile.application_statement_schema_identifier,
        &profile.canonical_header,
        profile.schedule.clone(),
    )
    .map_err(|error| failure("initialize public-width transcript", error))?;
    transcript
        .absorb_base_root(0, base_root)
        .map_err(|error| failure("absorb public-width base root", error))?;
    let composition_challenges = (0_u32..2)
        .map(|constraint_ordinal| {
            transcript
                .sample_composition_challenge(constraint_ordinal)
                .map_err(|error| failure("sample public-width composition challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;

    // Both frozen affine relations are polynomial identities. Their exact
    // quotient is therefore zero, so no eight-column LDE matrix needs to be
    // retained merely to rediscover the same zero evaluations.
    let quotient_evaluations = vec![ProofChallengeExtensionElement::ZERO; EVALUATION_DOMAIN_SIZE];
    let quotient_coefficients = vec![ProofChallengeExtensionElement::ZERO];
    let quotient_root = recompute_extension_tree_root(
        &profile.layout.catalog().entries()[1],
        &quotient_evaluations,
    )?;
    transcript
        .absorb_quotient_root(0, quotient_root)
        .map_err(|error| failure("absorb public-width quotient root", error))?;
    let deep_point = transcript
        .sample_deep_point(0, |candidate| {
            deep_point_is_forbidden(candidate, evaluation_domain)
        })
        .map_err(|error| failure("sample public-width DEEP point", error))?;
    let mut source_deep_evaluations = column_coefficients
        .iter()
        .map(|coefficients| evaluate_base_coefficients_at(coefficients, deep_point))
        .collect::<Vec<_>>();
    source_deep_evaluations.push(ProofChallengeExtensionElement::ZERO);
    let mut deep_evaluations = Vec::with_capacity(BATCHED_FUNCTION_COUNT);
    deep_evaluations.extend_from_slice(&source_deep_evaluations);
    deep_evaluations.extend_from_slice(&source_deep_evaluations);
    verify_deep_quotient_identity(deep_point, &deep_evaluations, &composition_challenges)?;
    transcript
        .absorb_deep_evaluations(&deep_evaluations)
        .map_err(|error| failure("absorb public-width DEEP evaluations", error))?;
    let opening_batch_challenges = (0_u32
        ..u32::try_from(BATCHED_FUNCTION_COUNT)
            .map_err(|_| "batched function count does not fit u32".to_owned())?)
        .map(|claim_ordinal| {
            transcript
                .sample_opening_batch_challenge(claim_ordinal)
                .map_err(|error| failure("sample public-width opening challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;

    let mut tree_roots = Vec::with_capacity(TREE_COUNT);
    tree_roots.push(base_root);
    tree_roots.push(quotient_root);
    let mut current_fri_evaluations = public_width_initial_fri_evaluations(
        &column_coefficients,
        &quotient_coefficients,
        evaluation_domain,
        deep_point,
        &deep_evaluations,
        &opening_batch_challenges,
    )?;
    let mut current_fri_domain = evaluation_domain;
    for fold_ordinal in 0..FRI_FOLD_COUNT {
        let fold_ordinal_u16 = u16::try_from(fold_ordinal)
            .map_err(|_| "FRI fold ordinal does not fit u16".to_owned())?;
        let fold_challenge = transcript
            .sample_fri_fold_challenge(fold_ordinal_u16)
            .map_err(|error| failure("sample public-width FRI challenge", error))?;
        fold_extension_evaluations_in_place(
            &mut current_fri_evaluations,
            current_fri_domain,
            fold_challenge,
        )
        .map_err(|error| failure("fold public-width FRI layer", error))?;
        current_fri_domain = current_fri_domain
            .folded()
            .map_err(|error| failure("derive public-width folded domain", error))?;
        if fold_ordinal + 1 < FRI_FOLD_COUNT {
            let root = recompute_extension_tree_root(
                &profile.layout.catalog().entries()[fold_ordinal + 2],
                &current_fri_evaluations,
            )?;
            transcript
                .absorb_fri_layer_root(fold_ordinal_u16, root)
                .map_err(|error| failure("absorb public-width FRI root", error))?;
            tree_roots.push(root);
        }
    }
    if tree_roots.len() != TREE_COUNT {
        return Err("public-width root count diverged from its catalog".to_owned());
    }
    let mut terminal_coefficients = current_fri_evaluations;
    current_fri_domain
        .interpolate_extension_polynomial_in_place(&mut terminal_coefficients)
        .map_err(|error| failure("interpolate public-width terminal polynomial", error))?;
    if terminal_coefficients.len() > TERMINAL_COEFFICIENT_COUNT {
        return Err("public-width terminal polynomial exceeded degree 255".to_owned());
    }
    terminal_coefficients.resize(
        TERMINAL_COEFFICIENT_COUNT,
        ProofChallengeExtensionElement::ZERO,
    );
    transcript
        .absorb_fri_terminal_coefficients(&terminal_coefficients)
        .map_err(|error| failure("absorb public-width terminal coefficients", error))?;
    let mut sampled_query_representatives = transcript
        .sample_query_representatives()
        .map_err(|error| failure("sample public-width query representatives", error))?;
    let sorted_query_representatives = transcript
        .sorted_query_representatives()
        .map_err(|error| failure("sort public-width query representatives", error))?;
    sampled_query_representatives.sort_unstable();
    if sampled_query_representatives != sorted_query_representatives {
        return Err("public-width query representatives are not canonical".to_owned());
    }

    let mut opening_artifacts = Vec::with_capacity(TREE_COUNT);
    opening_artifacts.push(recompute_public_base_opening(
        &profile.layout.catalog().entries()[0],
        &mut custody,
        trace_domain,
        evaluation_domain,
        &sorted_query_representatives,
        base_root,
    )?);
    opening_artifacts.push(recompute_extension_tree_opening(
        &profile.layout.catalog().entries()[1],
        &quotient_evaluations,
        &sorted_query_representatives,
        quotient_root,
    )?);
    let mut replayed_fri_evaluations = public_width_initial_fri_evaluations(
        &column_coefficients,
        &quotient_coefficients,
        evaluation_domain,
        deep_point,
        &deep_evaluations,
        &opening_batch_challenges,
    )?;
    let mut replayed_fri_domain = evaluation_domain;
    let mut replay_transcript = CommonProofTranscript::new(
        PROTOCOL_VERSION,
        profile.suite_identifier,
        profile.application_statement_schema_identifier,
        &profile.canonical_header,
        profile.schedule.clone(),
    )
    .map_err(|error| failure("initialize public-width opening replay transcript", error))?;
    replay_transcript
        .absorb_base_root(0, base_root)
        .map_err(|error| failure("replay public-width base root", error))?;
    for constraint_ordinal in 0_u32..2 {
        let replayed = replay_transcript
            .sample_composition_challenge(constraint_ordinal)
            .map_err(|error| failure("replay public-width composition challenge", error))?;
        if replayed
            != composition_challenges[usize::try_from(constraint_ordinal)
                .map_err(|_| "composition ordinal does not fit usize".to_owned())?]
        {
            return Err("public-width composition challenge replay diverged".to_owned());
        }
    }
    replay_transcript
        .absorb_quotient_root(0, quotient_root)
        .map_err(|error| failure("replay public-width quotient root", error))?;
    let replayed_deep_point = replay_transcript
        .sample_deep_point(0, |candidate| {
            deep_point_is_forbidden(candidate, evaluation_domain)
        })
        .map_err(|error| failure("replay public-width DEEP point", error))?;
    if replayed_deep_point != deep_point {
        return Err("public-width DEEP point replay diverged".to_owned());
    }
    replay_transcript
        .absorb_deep_evaluations(&deep_evaluations)
        .map_err(|error| failure("replay public-width DEEP evaluations", error))?;
    for (claim_ordinal, expected) in opening_batch_challenges.iter().copied().enumerate() {
        let replayed = replay_transcript
            .sample_opening_batch_challenge(
                u32::try_from(claim_ordinal)
                    .map_err(|_| "opening claim ordinal does not fit u32".to_owned())?,
            )
            .map_err(|error| failure("replay public-width opening challenge", error))?;
        if replayed != expected {
            return Err("public-width opening challenge replay diverged".to_owned());
        }
    }
    for fold_ordinal in 0..FRI_FOLD_COUNT {
        let fold_ordinal_u16 = u16::try_from(fold_ordinal)
            .map_err(|_| "FRI fold ordinal does not fit u16".to_owned())?;
        let fold_challenge = replay_transcript
            .sample_fri_fold_challenge(fold_ordinal_u16)
            .map_err(|error| failure("replay public-width FRI challenge", error))?;
        fold_extension_evaluations_in_place(
            &mut replayed_fri_evaluations,
            replayed_fri_domain,
            fold_challenge,
        )
        .map_err(|error| failure("replay public-width FRI fold", error))?;
        replayed_fri_domain = replayed_fri_domain
            .folded()
            .map_err(|error| failure("derive replayed public-width domain", error))?;
        if fold_ordinal + 1 < FRI_FOLD_COUNT {
            replay_transcript
                .absorb_fri_layer_root(fold_ordinal_u16, tree_roots[fold_ordinal + 2])
                .map_err(|error| failure("replay public-width FRI root", error))?;
            opening_artifacts.push(recompute_extension_tree_opening(
                &profile.layout.catalog().entries()[fold_ordinal + 2],
                &replayed_fri_evaluations,
                &sorted_query_representatives,
                tree_roots[fold_ordinal + 2],
            )?);
        }
    }
    if opening_artifacts.len() != TREE_COUNT {
        return Err("public-width opening artifact count changed".to_owned());
    }
    let canonical_leaf_byte_length =
        u64::try_from(opening_artifacts[0].canonical_leaf_byte_length())
            .map_err(|_| "public base leaf length does not fit u64".to_owned())?;

    let geometries = opening_geometries(profile.layout.catalog())?;
    let query_section_byte_length = common_proof_query_section_byte_length(
        profile.layout.catalog(),
        &geometries,
        &sorted_query_representatives,
    )
    .map_err(|error| failure("derive public-width query-section length", error))?;
    let mut sink = BoundedCommonProofByteSink::new(MAXIMUM_PROOF_BYTE_LENGTH)
        .map_err(|error| failure("initialize public-width proof sink", error))?;
    write_common_proof_prefix(
        &mut sink,
        &profile.canonical_header,
        profile.layout.catalog(),
        &tree_roots,
        &deep_evaluations,
        &terminal_coefficients,
        &profile.schedule,
    )
    .map_err(|error| failure("encode public-width proof prefix", error))?;
    let mut query_opening_absorber = transcript
        .begin_query_openings(query_section_byte_length)
        .map_err(|error| failure("begin public-width query-opening round", error))?;
    let query_header = canonical_common_proof_query_section_header(profile.layout.catalog())
        .map_err(|error| failure("encode public-width query header", error))?;
    sink.write_bytes(&query_header)
        .map_err(|error| failure("write public-width query header", error))?;
    query_opening_absorber
        .absorb(&query_header)
        .map_err(|error| failure("absorb public-width query header", error))?;
    let mut base_opened_leaf_local_ranges = None;
    for catalog_index in 0..TREE_COUNT {
        let exact_fragment_byte_length = proof_query_tree_byte_length(
            &profile.layout,
            catalog_index,
            &sorted_query_representatives,
        )
        .map_err(|error| failure("derive public-width query fragment length", error))?;
        let (fragment, opened_leaf_local_ranges) =
            encode_common_proof_query_tree_fragment_with_layout(
                profile.layout.catalog(),
                catalog_index,
                geometries[catalog_index],
                &sorted_query_representatives,
                &opening_artifacts[catalog_index],
                exact_fragment_byte_length,
            )
            .map_err(|error| failure("encode public-width query fragment", error))?
            .into_parts();
        if catalog_index == 0 {
            base_opened_leaf_local_ranges = Some(opened_leaf_local_ranges);
        }
        sink.write_bytes(&fragment)
            .map_err(|error| failure("write public-width query fragment", error))?;
        query_opening_absorber
            .absorb(&fragment)
            .map_err(|error| failure("absorb public-width query fragment", error))?;
    }
    drop(opening_artifacts);
    transcript
        .finish_query_openings(query_opening_absorber)
        .map_err(|error| failure("finish public-width query-opening round", error))?;
    transcript
        .finish()
        .map_err(|error| failure("finish public-width transcript", error))?;
    let canonical_full_proof = sink.finish();
    let compact_canonical_proof = compact_canonical_proof(&profile, &canonical_full_proof)?;
    drop(canonical_full_proof);
    let opened_leaf_element_ranges = base_opened_leaf_element_ranges(
        &profile,
        query_header.len(),
        base_opened_leaf_local_ranges
            .as_deref()
            .ok_or_else(|| "public-width base query layout is missing".to_owned())?,
    )?;
    let canonical_artifact_byte_length = u64::try_from(compact_canonical_proof.len())
        .map_err(|_| "public-width artifact length does not fit u64".to_owned())?;
    let recomputed_canonical_artifact_byte_length = profile
        .canonical_header
        .len()
        .checked_add(
            super::proof_body_prefix_byte_length(&profile.layout)
                .map_err(|error| failure("recompute public-width prefix length", error))?,
        )
        .and_then(|length| length.checked_add(query_section_byte_length))
        .and_then(|length| length.checked_sub(MERKLE_DIGEST_BYTE_LENGTH))
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(|| "recomputed public-width artifact length overflowed".to_owned())?;
    if recomputed_canonical_artifact_byte_length != canonical_artifact_byte_length {
        return Err("public-width canonical artifact length diverges from its layout".to_owned());
    }
    let (
        opened_leaf_range_chunk_count,
        canonical_artifact_preleaf_range_chunk_count,
        canonical_artifact_postleaf_range_chunk_count,
    ) = custody.store_canonical_artifact(&compact_canonical_proof, &opened_leaf_element_ranges)?;
    let canonical_artifact_nonleaf_range_chunk_count = canonical_artifact_preleaf_range_chunk_count
        .checked_add(canonical_artifact_postleaf_range_chunk_count)
        .ok_or_else(|| "nonleaf artifact range chunk count overflowed".to_owned())?;
    drop(compact_canonical_proof);
    let canonical_artifact = custody.read_canonical_artifact(
        usize::try_from(canonical_artifact_byte_length)
            .map_err(|_| "public-width artifact length does not fit usize".to_owned())?,
        &opened_leaf_element_ranges,
    )?;
    let fresh_verifier_profile = public_width_proof_profile_from_public_input(
        &canonical_statement,
        &input_identity_shake256_hex,
    )?;
    // Producer-cached query positions are an untrusted prefetch hint only.
    // Complete source identity and root replay finishes before the fresh
    // transcript exists; verification then derives its own query positions
    // and requires the authenticated opening map to match exactly.
    let fresh_public_base_openings = recompute_fresh_public_base_root_and_query_values(
        &mut custody,
        FreshPublicBaseReplayRequest {
            entry: &fresh_verifier_profile.layout.catalog().entries()[0],
            trace_domain,
            evaluation_domain,
            sorted_query_representatives: &sorted_query_representatives,
            frozen_input_identity_shake256_hex: &fixture.input_identity_shake256_hex,
            expected_input_identity_shake256_hex: &input_identity_shake256_hex,
            expected_root: fresh_verifier_profile.expected_fri_base_root,
        },
        #[cfg(test)]
        None,
    )?;
    verify_packed_deep_fri_with_profile(
        &fresh_verifier_profile,
        &canonical_artifact,
        Some(fresh_public_base_openings),
    )?;
    let artifact_shake256_hex = to_hex(&hash_framed_parts_512(
        "proof-storage/public-width-canonical-artifact/v1",
        &[
            canonical_artifact.as_slice(),
            canonical_statement.as_slice(),
        ],
    ));
    drop(canonical_artifact);

    let width = u64::try_from(public_base_leaf_column_count)
        .map_err(|_| "public base width does not fit u64".to_owned())?;
    let source_replay_byte_length = PUBLIC_SOURCE_REPLAY_BYTE_LENGTH_PER_COLUMN
        .checked_mul(width)
        .ok_or_else(|| "public source replay byte length overflowed".to_owned())?;
    let queried_leaf_payload_byte_length = canonical_leaf_byte_length
        .checked_mul(u64::from(UNIQUE_QUERY_COUNT))
        .ok_or_else(|| "queried public leaf payload length overflowed".to_owned())?;
    let opened_leaf_element_byte_length = canonical_leaf_byte_length
        .checked_add(4)
        .ok_or_else(|| "opened public leaf element length overflowed".to_owned())?;
    let physical_object_peak = width
        .checked_add(1)
        .ok_or_else(|| "public custody object count overflowed".to_owned())?;
    let stored_scratch_peak_byte_length = source_replay_byte_length
        .checked_add(canonical_artifact_byte_length)
        .ok_or_else(|| "public custody stored-byte peak overflowed".to_owned())?;
    let accounting_before_cleanup = custody.accounting();
    validate_public_source_replay_work_counts(
        accounting_before_cleanup,
        public_base_leaf_column_count,
    )?;
    let accounting = custody.finish()?;
    let local_record_seal_invocation_count = 0_u64;
    let sealed_secret_plaintext_byte_length = 0_u64;
    let source_committed_transaction_count = width
        .checked_mul(24)
        .ok_or_else(|| "source transaction count overflowed".to_owned())?;
    let expected_transaction_count = width
        .checked_mul(24)
        .and_then(|count| count.checked_add(3))
        .and_then(|count| {
            opened_leaf_range_chunk_count
                .checked_add(canonical_artifact_nonleaf_range_chunk_count)
                .and_then(|artifact_range_count| artifact_range_count.checked_mul(2))
                .and_then(|artifact_transactions| count.checked_add(artifact_transactions))
        })
        .ok_or_else(|| "bounded-custody transaction formula overflowed".to_owned())?;
    if accounting.transaction_count != expected_transaction_count {
        return Err(format!(
            "bounded-custody transaction count changed: expected {expected_transaction_count}, got {}",
            accounting.transaction_count
        ));
    }
    if canonical_artifact_byte_length
        > u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
            .map_err(|_| "common-proof cap does not fit u64".to_owned())?
        || canonical_artifact_byte_length > MAXIMUM_CANONICAL_STREAM_BYTE_LENGTH
        || stored_scratch_peak_byte_length > MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
        || physical_object_peak
            > u64::try_from(MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
                .map_err(|_| "external object cap does not fit u64".to_owned())?
        || local_record_seal_invocation_count
            > MAXIMUM_LOCAL_RECORD_SEAL_INVOCATIONS_PER_ACTIVE_ROOT
        || sealed_secret_plaintext_byte_length
            > MAXIMUM_LOCAL_RECORD_SEALED_PLAINTEXT_BYTES_PER_ACTIVE_ROOT
    {
        return Err("public-width evidence exceeded an absolute resource cap".to_owned());
    }
    Ok(ProofStorageWidthEvidenceOutput {
        public_base_leaf_column_count,
        input_identity_shake256_hex,
        base_root,
        canonical_artifact_byte_length,
        recomputed_canonical_artifact_byte_length,
        artifact_shake256_hex,
        source_replay_byte_length,
        queried_leaf_payload_byte_length,
        public_base_leaf_byte_length: canonical_leaf_byte_length,
        opened_leaf_element_byte_length,
        opened_leaf_range_chunk_count,
        canonical_artifact_preleaf_range_chunk_count,
        canonical_artifact_postleaf_range_chunk_count,
        canonical_artifact_nonleaf_range_chunk_count,
        physical_object_peak,
        stored_scratch_peak_byte_length,
        lde_transform_count: accounting.lde_transform_count,
        absorbed_leaf_value_count: accounting.absorbed_leaf_value_count,
        opened_value_count: accounting.opened_value_count,
        external_read_byte_length: accounting.total_read_byte_length,
        external_written_byte_length: accounting.total_written_byte_length,
        external_committed_transaction_count: accounting.transaction_count,
        source_committed_transaction_count,
        source_object_seal_transaction_count: width,
        proof_object_seal_transaction_count: 1,
        local_record_seal_invocation_count,
        sealed_secret_plaintext_byte_length,
        custody_cleanup_completed: true,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedPhasePair {
    first_values: Vec<ProofChallengeExtensionElement>,
    opposite_values: Vec<ProofChallengeExtensionElement>,
}

#[derive(Clone, Debug)]
struct AuthenticatedTreeOpening {
    tree_catalog_index: u16,
    pairs_by_leaf_index: BTreeMap<u64, AuthenticatedPhasePair>,
}

struct AuthenticatedQueryVerification<'input> {
    evaluation_domain: ProofEvaluationDomain,
    sorted_query_representatives: &'input [u64],
    openings: &'input [AuthenticatedTreeOpening],
    deep_point: ProofChallengeExtensionElement,
    deep_evaluations: &'input [ProofChallengeExtensionElement],
    opening_batch_challenges: &'input [ProofChallengeExtensionElement],
    fri_fold_challenges: Vec<ProofChallengeExtensionElement>,
    terminal_coefficients: Vec<ProofChallengeExtensionElement>,
    authenticated_base_column_count: usize,
}

fn authenticated_values(
    values: &[ProofTreeValue],
    expect_base_values: bool,
) -> ProofBackendBakeoffResult<Vec<ProofChallengeExtensionElement>> {
    values
        .iter()
        .copied()
        .map(|value| match (expect_base_values, value) {
            (true, ProofTreeValue::Base(value)) => {
                Ok(ProofChallengeExtensionElement::from_base(value))
            }
            (false, ProofTreeValue::Extension(value)) => Ok(value),
            _ => Err("authenticated tree leaf has the wrong field value type".to_owned()),
        })
        .collect()
}

fn authenticate_opening_values(
    opening: ProofTreeOpening<'_>,
    authenticated_base_column_count: usize,
) -> ProofBackendBakeoffResult<AuthenticatedTreeOpening> {
    let entry = opening.catalog_entry();
    let (expected_width, expect_base_values) = match entry.source() {
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::BaseOracle,
            tree_ordinal: 0,
        } => (authenticated_base_column_count, true),
        ProofTreeCatalogSource::QuotientComponent {
            component_ordinal: 0,
        }
        | ProofTreeCatalogSource::NonterminalFriLayer { .. } => (1, false),
        _ => return Err("authenticated opening belongs to an unexpected tree role".to_owned()),
    };
    let mut pairs_by_leaf_index = BTreeMap::new();
    for leaf in opening.leaves() {
        if leaf.first_point_values().len() != expected_width
            || leaf.opposite_point_values().len() != expected_width
        {
            return Err("authenticated phase-pair leaf has the wrong row width".to_owned());
        }
        let pair = AuthenticatedPhasePair {
            first_values: authenticated_values(leaf.first_point_values(), expect_base_values)?,
            opposite_values: authenticated_values(
                leaf.opposite_point_values(),
                expect_base_values,
            )?,
        };
        if pairs_by_leaf_index
            .insert(leaf.leaf_index(), pair)
            .is_some()
        {
            return Err("authenticated opening repeated one leaf index".to_owned());
        }
    }
    if pairs_by_leaf_index.is_empty() {
        return Err("authenticated opening contains no leaves".to_owned());
    }
    Ok(AuthenticatedTreeOpening {
        tree_catalog_index: entry.tree_catalog_index(),
        pairs_by_leaf_index,
    })
}

fn authenticated_pair(
    openings: &[AuthenticatedTreeOpening],
    catalog_index: usize,
    leaf_index: u64,
) -> ProofBackendBakeoffResult<&AuthenticatedPhasePair> {
    let opening = openings
        .get(catalog_index)
        .ok_or_else(|| "missing authenticated tree opening".to_owned())?;
    if usize::from(opening.tree_catalog_index) != catalog_index {
        return Err("authenticated tree opening order changed".to_owned());
    }
    opening
        .pairs_by_leaf_index
        .get(&leaf_index)
        .ok_or_else(|| "missing authenticated query leaf".to_owned())
}

fn single_extension_pair(
    pair: &AuthenticatedPhasePair,
) -> ProofBackendBakeoffResult<OpenedFriLayerPair> {
    if pair.first_values.len() != 1 || pair.opposite_values.len() != 1 {
        return Err("authenticated extension tree leaf is not width one".to_owned());
    }
    Ok(OpenedFriLayerPair::new(
        pair.first_values[0],
        pair.opposite_values[0],
    ))
}

fn verify_authenticated_queries(
    input: AuthenticatedQueryVerification<'_>,
) -> ProofBackendBakeoffResult<()> {
    let AuthenticatedQueryVerification {
        evaluation_domain,
        sorted_query_representatives,
        openings,
        deep_point,
        deep_evaluations,
        opening_batch_challenges,
        fri_fold_challenges,
        terminal_coefficients,
        authenticated_base_column_count,
    } = input;
    if openings.len() != TREE_COUNT
        || deep_evaluations.len() != BATCHED_FUNCTION_COUNT
        || opening_batch_challenges.len() != BATCHED_FUNCTION_COUNT
    {
        return Err("fresh verifier opening shape changed".to_owned());
    }
    let (source_deep_evaluations, repeated_deep_evaluations) =
        deep_evaluations.split_at(SOURCE_OPENING_CLAIM_COUNT);
    if source_deep_evaluations != repeated_deep_evaluations {
        return Err("fresh verifier received inconsistent repeated DEEP evaluations".to_owned());
    }
    let (source_batch_challenges, normalized_batch_challenges) =
        opening_batch_challenges.split_at(SOURCE_OPENING_CLAIM_COUNT);
    let fri_verifier = ProofFriQueryVerifier::new(
        evaluation_domain,
        fri_fold_challenges,
        terminal_coefficients,
        TERMINAL_COEFFICIENT_COUNT,
    )
    .map_err(|error| failure("initialize fresh FRI query verifier", error))?;
    for &query_representative in sorted_query_representatives {
        let base_pair = authenticated_pair(openings, 0, query_representative)?;
        if authenticated_base_column_count < COLUMN_COUNT
            || base_pair.first_values.len() != authenticated_base_column_count
            || base_pair.opposite_values.len() != authenticated_base_column_count
        {
            return Err("authenticated base opening has the wrong custody width".to_owned());
        }
        let quotient_pair =
            single_extension_pair(authenticated_pair(openings, 1, query_representative)?)?;
        let mut source_pairs = Vec::with_capacity(SOURCE_OPENING_CLAIM_COUNT);
        for column_ordinal in 0..COLUMN_COUNT {
            source_pairs.push(OpenedFriLayerPair::new(
                base_pair.first_values[column_ordinal],
                base_pair.opposite_values[column_ordinal],
            ));
        }
        source_pairs.push(quotient_pair);
        let normalized_opening_claims = source_pairs
            .iter()
            .copied()
            .enumerate()
            .map(|(claim_ordinal, source_pair)| {
                Ok(ProofOpeningClaimEvaluation::new(
                    u64::try_from(OPENING_DEGREE_BOUND_EXCLUSIVE)
                        .map_err(|_| "opening degree bound does not fit u64".to_owned())?,
                    deep_point,
                    source_deep_evaluations[claim_ordinal],
                    source_pair,
                    normalized_batch_challenges[claim_ordinal],
                ))
            })
            .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
        let evaluation_position = usize::try_from(query_representative)
            .map_err(|_| "query representative does not fit usize".to_owned())?;
        let evaluation_point = evaluation_domain
            .point(evaluation_position)
            .map_err(|error| failure("derive fresh-verifier query point", error))?;
        let shifted_normalized_opening_degree_bound = OPENING_DEGREE_BOUND_EXCLUSIVE
            .checked_add(1)
            .ok_or_else(|| "shifted normalized opening degree bound overflowed".to_owned())?;
        let shifted_normalized_pair = evaluate_initial_fri_pair(
            u64::try_from(shifted_normalized_opening_degree_bound)
                .map_err(|_| "shifted opening degree bound does not fit u64".to_owned())?,
            evaluation_point,
            &normalized_opening_claims,
            None,
        )
        .map_err(|error| failure("evaluate shifted normalized opening batch", error))?;
        // `evaluate_initial_fri_pair` uses one degree of left shift here, so
        // it returns the authenticated R_i = X(F_i-v_i)/(X-z) contribution.
        // Add the independently weighted source values to reconstruct I at
        // both queried points before beginning the ordinary FRI path check.
        let mut initial_first = shifted_normalized_pair.first();
        let mut initial_opposite = shifted_normalized_pair.opposite();
        for (source_pair, batching_coefficient) in source_pairs
            .iter()
            .zip(source_batch_challenges.iter().copied())
        {
            initial_first = initial_first.add(source_pair.first().multiply(batching_coefficient));
            initial_opposite =
                initial_opposite.add(source_pair.opposite().multiply(batching_coefficient));
        }
        let initial_pair = OpenedFriLayerPair::new(initial_first, initial_opposite);
        let mut query_state = fri_verifier
            .begin_query(query_representative, initial_pair)
            .map_err(|error| failure("begin fresh FRI query", error))?;
        for fold_ordinal in 0..FRI_FOLD_COUNT - 1 {
            let layer_leaf_count = EVALUATION_DOMAIN_SIZE
                .checked_shr(
                    u32::try_from(fold_ordinal + 2)
                        .map_err(|_| "FRI layer shift does not fit u32".to_owned())?,
                )
                .filter(|count| *count != 0)
                .ok_or_else(|| "FRI layer leaf count is invalid".to_owned())?;
            let layer_leaf_index = query_representative
                % u64::try_from(layer_leaf_count)
                    .map_err(|_| "FRI layer leaf count does not fit u64".to_owned())?;
            let next_layer_pair = single_extension_pair(authenticated_pair(
                openings,
                fold_ordinal + 2,
                layer_leaf_index,
            )?)?;
            fri_verifier
                .verify_nonterminal_layer(&mut query_state, fold_ordinal, next_layer_pair)
                .map_err(|error| failure("verify nonterminal FRI layer", error))?;
        }
        fri_verifier
            .finish_query(query_state)
            .map_err(|error| failure("verify FRI terminal evaluation", error))?;
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn verify_packed_deep_fri(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
    compact_proof: &[u8],
) -> ProofBackendBakeoffResult<()> {
    let profile =
        frozen_proof_profile_from_public_input(canonical_statement, input_identity_shake256_hex)?;
    #[cfg(feature = "proof-storage-width-evidence")]
    {
        verify_packed_deep_fri_with_profile(&profile, compact_proof, None)
    }
    #[cfg(all(
        not(feature = "proof-storage-width-evidence"),
        feature = "proof-storage-width-browser-evidence"
    ))]
    {
        verify_packed_deep_fri_with_profile(&profile, compact_proof, None)
    }
    #[cfg(not(any(
        feature = "proof-storage-width-evidence",
        feature = "proof-storage-width-browser-evidence"
    )))]
    {
        verify_packed_deep_fri_with_profile(&profile, compact_proof)
    }
}

fn verify_packed_deep_fri_with_profile(
    profile: &FrozenProofProfile,
    compact_proof: &[u8],
    #[cfg(any(
        feature = "proof-storage-width-evidence",
        feature = "proof-storage-width-browser-evidence"
    ))]
    precomputed_public_base_openings: Option<BTreeMap<u64, AuthenticatedPhasePair>>,
) -> ProofBackendBakeoffResult<()> {
    let authenticated_base_column_count = authenticated_base_column_count(profile)?;
    if authenticated_base_column_count < COLUMN_COUNT {
        return Err("authenticated base custody omits an algebraic column".to_owned());
    }
    let canonical_full_proof = expand_compact_canonical_proof(profile, compact_proof)?;
    let canonical_proof = canonical_full_proof.as_slice();
    let body_source = &canonical_proof[profile.canonical_header.len()..];
    let pending = decode_proof_body_prefix(
        body_source,
        body_source.len(),
        body_source.len(),
        &profile.layout,
    )
    .map_err(|error| failure("decode canonical packed-DEEP-FRI prefix", error))?;
    let tree_roots = pending.tree_roots().to_vec();
    let deep_evaluations = pending.deep_evaluations().to_vec();
    let terminal_coefficients = pending.terminal_coefficients().to_vec();
    if tree_roots.len() != TREE_COUNT
        || deep_evaluations.len() != BATCHED_FUNCTION_COUNT
        || terminal_coefficients.len() != TERMINAL_COEFFICIENT_COUNT
    {
        return Err("decoded packed-DEEP-FRI prefix has the wrong shape".to_owned());
    }
    if tree_roots[0] != profile.expected_fri_base_root {
        return Err("FRI base root does not match the exact statement binding".to_owned());
    }
    let evaluation_domain =
        ProofEvaluationDomain::new(EVALUATION_DOMAIN_SIZE, EVALUATION_COSET_OFFSET)
            .map_err(|error| failure("construct fresh-verifier evaluation coset", error))?;
    let mut transcript = CommonProofTranscript::new(
        PROTOCOL_VERSION,
        profile.suite_identifier,
        profile.application_statement_schema_identifier,
        &profile.canonical_header,
        profile.schedule.clone(),
    )
    .map_err(|error| failure("initialize fresh common-proof transcript", error))?;
    transcript
        .absorb_base_root(0, tree_roots[0])
        .map_err(|error| failure("fresh verifier absorb base root", error))?;
    let composition_challenges = (0_u32..2)
        .map(|constraint_ordinal| {
            transcript
                .sample_composition_challenge(constraint_ordinal)
                .map_err(|error| failure("fresh verifier sample composition challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
    transcript
        .absorb_quotient_root(0, tree_roots[1])
        .map_err(|error| failure("fresh verifier absorb quotient root", error))?;
    let deep_point = transcript
        .sample_deep_point(0, |candidate| {
            deep_point_is_forbidden(candidate, evaluation_domain)
        })
        .map_err(|error| failure("fresh verifier sample DEEP point", error))?;
    verify_deep_quotient_identity(deep_point, &deep_evaluations, &composition_challenges)?;
    transcript
        .absorb_deep_evaluations(&deep_evaluations)
        .map_err(|error| failure("fresh verifier absorb DEEP evaluations", error))?;
    let opening_batch_challenges = (0_u32
        ..u32::try_from(BATCHED_FUNCTION_COUNT)
            .map_err(|_| "batched function count does not fit u32".to_owned())?)
        .map(|claim_ordinal| {
            transcript
                .sample_opening_batch_challenge(claim_ordinal)
                .map_err(|error| failure("fresh verifier sample opening challenge", error))
        })
        .collect::<ProofBackendBakeoffResult<Vec<_>>>()?;
    let mut fri_fold_challenges = Vec::with_capacity(FRI_FOLD_COUNT);
    for fold_ordinal in 0..FRI_FOLD_COUNT {
        let fold_ordinal_u16 = u16::try_from(fold_ordinal)
            .map_err(|_| "FRI fold ordinal does not fit u16".to_owned())?;
        fri_fold_challenges.push(
            transcript
                .sample_fri_fold_challenge(fold_ordinal_u16)
                .map_err(|error| failure("fresh verifier sample FRI challenge", error))?,
        );
        if fold_ordinal + 1 < FRI_FOLD_COUNT {
            transcript
                .absorb_fri_layer_root(fold_ordinal_u16, tree_roots[fold_ordinal + 2])
                .map_err(|error| failure("fresh verifier absorb FRI root", error))?;
        }
    }
    transcript
        .absorb_fri_terminal_coefficients(&terminal_coefficients)
        .map_err(|error| failure("fresh verifier absorb terminal coefficients", error))?;
    let mut sampled_query_representatives = transcript
        .sample_query_representatives()
        .map_err(|error| failure("fresh verifier sample query representatives", error))?;
    let sorted_query_representatives = transcript
        .sorted_query_representatives()
        .map_err(|error| failure("fresh verifier sort query representatives", error))?;
    sampled_query_representatives.sort_unstable();
    if sampled_query_representatives != sorted_query_representatives {
        return Err("fresh verifier query order is not canonical".to_owned());
    }
    #[cfg(any(
        feature = "proof-storage-width-evidence",
        feature = "proof-storage-width-browser-evidence"
    ))]
    let expected_public_base_openings = precomputed_public_base_openings;
    let query_section_byte_length = pending
        .query_section_byte_length()
        .map_err(|error| failure("derive decoded query-section length", error))?;
    let mut query_opening_absorber = transcript
        .begin_query_openings(query_section_byte_length)
        .map_err(|error| failure("fresh verifier begin query-opening transcript round", error))?;
    let mut authenticated_openings = Vec::with_capacity(TREE_COUNT);
    let mut opening_error = None;
    let decoded_body_result = pending.decode_query_section(
        &sorted_query_representatives,
        &mut query_opening_absorber,
        |opening| match authenticate_opening_values(opening, authenticated_base_column_count) {
            Ok(authenticated) => {
                authenticated_openings.push(authenticated);
                Ok(())
            }
            Err(error) => {
                opening_error = Some(error);
                Err(ProofBodyError::InvalidLeaf)
            }
        },
    );
    if let Some(error) = opening_error {
        return Err(error);
    }
    let decoded_body = decoded_body_result.map_err(|error| {
        failure(
            "authenticate canonical packed-DEEP-FRI query section",
            error,
        )
    })?;
    if decoded_body.tree_roots() != tree_roots
        || decoded_body.deep_evaluations() != deep_evaluations
        || decoded_body.terminal_coefficients() != terminal_coefficients
    {
        return Err("decoded proof body changed across its query section".to_owned());
    }
    #[cfg(any(
        feature = "proof-storage-width-evidence",
        feature = "proof-storage-width-browser-evidence"
    ))]
    if let Some(expected_public_base_openings) = expected_public_base_openings {
        let authenticated_base_opening = authenticated_openings
            .first()
            .ok_or_else(|| "fresh verifier is missing the public base opening".to_owned())?;
        if authenticated_base_opening.pairs_by_leaf_index != expected_public_base_openings {
            return Err(
                "authenticated public base opening diverges from replay custody".to_owned(),
            );
        }
    }
    verify_authenticated_queries(AuthenticatedQueryVerification {
        evaluation_domain,
        sorted_query_representatives: &sorted_query_representatives,
        openings: &authenticated_openings,
        deep_point,
        deep_evaluations: &deep_evaluations,
        opening_batch_challenges: &opening_batch_challenges,
        fri_fold_challenges,
        terminal_coefficients,
        authenticated_base_column_count,
    })?;
    drop(authenticated_openings);
    transcript
        .finish_query_openings(query_opening_absorber)
        .map_err(|error| {
            failure(
                "fresh verifier finish query-opening transcript round",
                error,
            )
        })?;
    transcript
        .finish()
        .map_err(|error| failure("fresh verifier finish common-proof transcript", error))?;
    let canonical_round_trip = compact_canonical_proof(profile, canonical_proof)?;
    if canonical_round_trip != compact_proof {
        return Err("compact packed-DEEP-FRI proof encoding is not canonical".to_owned());
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
pub(super) fn execute_packed_deep_fri(
    fixture: &ProofBackendBakeoffFixture,
) -> ProofBackendBakeoffResult<ProofBackendBakeoffArmOutput> {
    let generated = generate_packed_deep_fri(fixture)?;
    Ok(ProofBackendBakeoffArmOutput {
        canonical_artifact: generated.compact_canonical_proof,
    })
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
fn require_byte_mutation_rejected(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
    compact_canonical_proof: &[u8],
    byte_index: usize,
    mutation_name: &str,
) -> ProofBackendBakeoffResult<()> {
    let mut mutated = compact_canonical_proof.to_vec();
    let byte = mutated
        .get_mut(byte_index)
        .ok_or_else(|| format!("{mutation_name} byte index is outside the canonical proof"))?;
    *byte ^= 1;
    if verify_packed_deep_fri(canonical_statement, input_identity_shake256_hex, &mutated).is_ok() {
        return Err(format!(
            "fresh packed-DEEP-FRI verifier accepted the {mutation_name} mutation"
        ));
    }
    Ok(())
}

/// Runs untimed adversarial checks against a generated canonical artifact.
///
/// The measured arm calls only fresh verification of the unmodified proof;
/// this mutation matrix is owned by a separate preflight so its work cannot
/// contaminate any bakeoff sample.
#[cfg(all(test, not(target_arch = "wasm32"), feature = "proof-backend-bakeoff"))]
pub(super) fn verify_packed_deep_fri_mutations(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
    compact_canonical_proof: &[u8],
    alternate_affine_valid_base_root: [u8; 64],
) -> ProofBackendBakeoffResult<()> {
    verify_packed_deep_fri(
        canonical_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
    )?;
    let profile =
        frozen_proof_profile_from_public_input(canonical_statement, input_identity_shake256_hex)?;
    let header_byte_length = profile.canonical_header.len();
    let deep_evaluation_offset = header_byte_length
        .checked_add(MERKLE_DIGEST_BYTE_LENGTH)
        .and_then(|offset| offset.checked_add(6))
        .ok_or_else(|| "DEEP-evaluation mutation offset overflowed".to_owned())?;
    let terminal_coefficient_offset = deep_evaluation_offset
        .checked_add(BATCHED_FUNCTION_COUNT * 40)
        .and_then(|offset| offset.checked_add((FRI_FOLD_COUNT - 1) * 64))
        .and_then(|offset| offset.checked_add(6))
        .ok_or_else(|| "terminal-coefficient mutation offset overflowed".to_owned())?;
    let query_section_offset = header_byte_length
        .checked_add(
            super::proof_body_prefix_byte_length(&profile.layout)
                .map_err(|error| failure("derive mutation query-section offset", error))?,
        )
        .and_then(|offset| offset.checked_sub(MERKLE_DIGEST_BYTE_LENGTH))
        .ok_or_else(|| "query-section mutation offset overflowed".to_owned())?;

    if alternate_affine_valid_base_root == profile.expected_fri_base_root {
        return Err(
            "alternate affine-valid base tree unexpectedly shares the frozen root".to_owned(),
        );
    }
    let alternate_statement = canonical_frozen_fri_public_statement(
        input_identity_shake256_hex,
        alternate_affine_valid_base_root,
    )?;
    let alternate_header = canonical_proof_object_header_bytes(&alternate_statement)
        .map_err(|error| failure("construct alternate checked FRI proof header", error))?;
    if alternate_header.len() != header_byte_length {
        return Err("alternate checked FRI proof header length changed".to_owned());
    }
    let mut proof_with_alternate_base_root = compact_canonical_proof.to_vec();
    proof_with_alternate_base_root[..header_byte_length].copy_from_slice(&alternate_header);
    if verify_packed_deep_fri(
        &alternate_statement,
        input_identity_shake256_hex,
        &proof_with_alternate_base_root,
    )
    .is_ok()
    {
        return Err(
            "fresh packed-DEEP-FRI verifier accepted an alternate affine-valid base root"
                .to_owned(),
        );
    }

    require_byte_mutation_rejected(
        canonical_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
        0,
        "canonical header",
    )?;
    require_byte_mutation_rejected(
        canonical_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
        header_byte_length,
        "quotient root",
    )?;
    require_byte_mutation_rejected(
        canonical_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
        deep_evaluation_offset,
        "DEEP evaluation",
    )?;
    require_byte_mutation_rejected(
        canonical_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
        deep_evaluation_offset + SOURCE_OPENING_CLAIM_COUNT * 40,
        "repeated DEEP evaluation",
    )?;
    require_byte_mutation_rejected(
        canonical_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
        terminal_coefficient_offset,
        "FRI terminal coefficient",
    )?;
    require_byte_mutation_rejected(
        canonical_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
        query_section_offset + 36,
        "authenticated query opening",
    )?;

    let mut proof_with_trailing_byte = compact_canonical_proof.to_vec();
    proof_with_trailing_byte.push(0);
    if verify_packed_deep_fri(
        canonical_statement,
        input_identity_shake256_hex,
        &proof_with_trailing_byte,
    )
    .is_ok()
    {
        return Err("fresh packed-DEEP-FRI verifier accepted trailing bytes".to_owned());
    }

    let mut changed_identity_bytes = input_identity_shake256_hex.as_bytes().to_vec();
    let first_identity_byte = changed_identity_bytes
        .first_mut()
        .ok_or_else(|| "packed-DEEP-FRI public input identity is empty".to_owned())?;
    *first_identity_byte = if *first_identity_byte == b'0' {
        b'1'
    } else {
        b'0'
    };
    let changed_identity = String::from_utf8(changed_identity_bytes)
        .map_err(|error| format!("mutated public input identity is not UTF-8: {error}"))?;
    if verify_packed_deep_fri(
        canonical_statement,
        &changed_identity,
        compact_canonical_proof,
    )
    .is_ok()
    {
        return Err(
            "fresh packed-DEEP-FRI verifier accepted a wrong public input identity".to_owned(),
        );
    }

    let mut changed_statement = canonical_statement.to_vec();
    changed_statement.push(0);
    if verify_packed_deep_fri(
        &changed_statement,
        input_identity_shake256_hex,
        compact_canonical_proof,
    )
    .is_ok()
    {
        return Err(
            "fresh packed-DEEP-FRI verifier accepted a wrong canonical statement".to_owned(),
        );
    }
    Ok(())
}
