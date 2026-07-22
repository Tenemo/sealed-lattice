//! Packed-DEEP-FRI arm for the native-only synthetic backend bakeoff.
//!
//! This module deliberately does not construct a selected-suite relation plan.
//! It commits the frozen public two-equation fragment through the production
//! polynomial, transcript, canonical body, Merkle, opening, and FRI primitives.

use std::collections::BTreeMap;

use num_bigint::BigUint;
use zeroize::{Zeroize, Zeroizing};

use crate::hashing::{hash_framed_parts_512, hash512_hex};

use super::{
    CommonProofPrivacyMode, CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource,
    CommonProofSourcePolynomial, CommonProofTranscript, CommonProofTranscriptSchedule,
    CompleteProofTreeCatalog, OpenedFriLayerPair, PROOF_BASE_FIELD_MODULUS,
    PROOF_CHALLENGE_EXTENSION_DEGREE, ProofBaseFieldElement, ProofBodyError, ProofBodyLayout,
    ProofChallengeExtensionElement, ProofEvaluationDomain, ProofExternalMemory,
    ProofExternalMemoryExecutor, ProofExternalMemoryObject, ProofExternalMemoryObjectPlan,
    ProofExternalMemoryPlan, ProofExternalMemoryProtection, ProofFriQueryVerifier,
    ProofLeafVisibility, ProofOpeningClaimEvaluation, ProofTreeCatalogEntry, ProofTreeCatalogInput,
    ProofTreeCatalogSource, ProofTreeOpening, ProofTreeRole, ProofTreeValue,
    RelationProofTreeInput, build_complete_proof_tree_catalog, decode_proof_body_prefix,
    fold_extension_evaluations_in_place,
    merkle::CommonProofMerklePathReplay,
    opening::evaluate_initial_fri_pair,
    proof_backend_bakeoff::{
        ProofBackendBakeoffArmOutput, ProofBackendBakeoffFixture, ProofBackendBakeoffResult,
        canonical_frozen_fri_public_statement, recompute_frozen_input_identity,
        validate_frozen_core_statement, validated_frozen_fri_public_statement,
    },
    proof_query_tree_byte_length,
    prover::{
        BoundedCommonProofByteSink, CommonProofByteSink, CommonProofMerkleMaterializer,
        CommonProofMerkleMaterializerProgress, CommonProofMerkleStoragePlan,
        CommonProofOpeningGeometry, CommonProofOpeningPrefetchProgress,
        CommonProofOpeningPrefetcher, StoredCommonProofMerkleTree,
        add_bakeoff_polynomial_to_initial_fri, canonical_common_proof_query_section_header,
        canonical_proof_object_header_bytes, common_proof_merkle_storage_plan,
        common_proof_query_section_byte_length, encode_common_proof_query_tree_fragment,
        write_common_proof_prefix,
    },
};

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
const EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH: u32 = 49_152;
const MAXIMUM_PROOF_BYTE_LENGTH: usize = 16 * 1_024 * 1_024;
const MAXIMUM_PREFETCHED_QUERY_BYTE_LENGTH: u64 = 16 * 1_024 * 1_024;
const SECURITY_BIT_TARGET: u32 = 128;
const FRI_TRADEOFF_NUMERATOR: u32 = 5;
const FRI_TRADEOFF_DENOMINATOR: u32 = 8;
const MERKLE_DIGEST_BYTE_LENGTH: usize = 64;
const CLASSICAL_COLLISION_SECURITY_BIT_FLOOR: u32 = 256;
const GENERIC_QUANTUM_COLLISION_SECURITY_BIT_FLOOR: u32 = 170;
const CLASSICAL_ROUND_BY_ROUND_SOUNDNESS_BIT_FLOOR: u32 = 258;
const FIAT_SHAMIR_HASH_BIT_COUNT: u32 = 512;
const SOURCE_OPENING_CLAIM_COUNT: usize = COLUMN_COUNT + 1;
const BATCHED_FUNCTION_COUNT: usize = SOURCE_OPENING_CLAIM_COUNT * 2;
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

fn failure(context: &str, error: impl core::fmt::Debug) -> String {
    format!("{context}: {error:?}")
}

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

struct InMemoryExternalMemoryObject {
    bytes: Vec<u8>,
    exact_byte_length: usize,
    protection: ProofExternalMemoryProtection,
    sealed: bool,
}

impl Drop for InMemoryExternalMemoryObject {
    fn drop(&mut self) {
        if self.protection == ProofExternalMemoryProtection::SecretAuthenticatedEncryption {
            self.bytes.zeroize();
        }
    }
}

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
struct BoundedInMemoryExternalMemory {
    maximum_byte_length: usize,
    committed: BTreeMap<ProofExternalMemoryObject, InMemoryExternalMemoryObject>,
    transaction: Option<InMemoryExternalMemoryTransaction>,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NoPrivateCoinError {
    PrivateCoordinateRequested,
}

struct NoPrivateCoins;

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

fn frozen_catalog(
    canonical_catalog_statement: &[u8],
    input_identity_shake256_hex: &str,
    schedule: &CommonProofTranscriptSchedule,
) -> ProofBackendBakeoffResult<CompleteProofTreeCatalog> {
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
                row_width: u32::try_from(COLUMN_COUNT)
                    .map_err(|_| "column count does not fit u32".to_owned())?,
                leaf_visibility: ProofLeafVisibility::Public,
            }],
        },
        schedule,
    )
    .map_err(|error| failure("construct frozen proof tree catalog", error))?;
    validate_catalog(&catalog)?;
    Ok(catalog)
}

fn validate_catalog(catalog: &CompleteProofTreeCatalog) -> ProofBackendBakeoffResult<()> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrozenExternalMemoryAccounting {
    peak_stored_byte_length: u64,
    total_written_byte_length: u64,
    total_read_byte_length: u64,
    transaction_count: u64,
    object_count: u32,
}

impl FrozenExternalMemoryAccounting {
    fn total_io_byte_length(self) -> ProofBackendBakeoffResult<u64> {
        self.total_written_byte_length
            .checked_add(self.total_read_byte_length)
            .ok_or_else(|| "external I/O byte length overflowed".to_owned())
    }
}

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

fn storage_plans(
    catalog: &CompleteProofTreeCatalog,
) -> ProofBackendBakeoffResult<(
    Vec<CommonProofMerkleStoragePlan>,
    ProofExternalMemoryPlan,
    FrozenExternalMemoryAccounting,
)> {
    let evaluation_domain_size = u64::try_from(EVALUATION_DOMAIN_SIZE)
        .map_err(|_| "evaluation domain size does not fit u64".to_owned())?;
    let external_memory_chunk_byte_length = u64::from(EXTERNAL_MEMORY_CHUNK_BYTE_LENGTH);
    let mut first_object_ordinal = 0_u32;
    let mut tree_plans = Vec::with_capacity(catalog.entries().len());
    let mut object_plans = Vec::<ProofExternalMemoryObjectPlan>::with_capacity(TREE_COUNT);
    let mut total_written_byte_length = 0_u64;
    let mut total_read_byte_length = 0_u64;
    let mut write_transaction_count = 0_u64;
    let mut read_transaction_count = 0_u64;
    let mut lifecycle_transaction_count = 0_u64;
    let mut deletion_count_by_step = BTreeMap::<u32, u32>::new();
    for entry in catalog.entries() {
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
    if tree_plans.len() != TREE_COUNT
        || object_plans.len() != TREE_COUNT
        || first_object_ordinal != u32::try_from(TREE_COUNT).unwrap_or(u32::MAX)
    {
        return Err("path-only storage did not derive exactly seven objects".to_owned());
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
    BaseColumns(&'values ProofBaseFieldColumns),
    ExtensionColumn(&'values [ProofChallengeExtensionElement]),
}

impl MaterializedTreeValues<'_> {
    fn evaluation_count(&self) -> usize {
        match self {
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

struct GeneratedPackedDeepFri {
    compact_canonical_proof: Vec<u8>,
    external_read_byte_length: u64,
    external_written_byte_length: u64,
    external_transaction_count: u64,
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
        external_read_byte_length: usage.total_read_byte_length(),
        external_written_byte_length: usage.total_written_byte_length(),
        external_transaction_count: usage.transaction_count(),
    })
}

#[derive(Clone, Debug)]
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
) -> ProofBackendBakeoffResult<AuthenticatedTreeOpening> {
    let entry = opening.catalog_entry();
    let (expected_width, expect_base_values) = match entry.source() {
        ProofTreeCatalogSource::RelationProofCreated {
            tree_role: ProofTreeRole::BaseOracle,
            tree_ordinal: 0,
        } => (COLUMN_COUNT, true),
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
        if base_pair.first_values.len() != COLUMN_COUNT
            || base_pair.opposite_values.len() != COLUMN_COUNT
        {
            return Err("authenticated base opening is not width eight".to_owned());
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

fn verify_packed_deep_fri(
    canonical_statement: &[u8],
    input_identity_shake256_hex: &str,
    compact_proof: &[u8],
) -> ProofBackendBakeoffResult<()> {
    let profile =
        frozen_proof_profile_from_public_input(canonical_statement, input_identity_shake256_hex)?;
    let canonical_full_proof = expand_compact_canonical_proof(&profile, compact_proof)?;
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
        |opening| match authenticate_opening_values(opening) {
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
    verify_authenticated_queries(AuthenticatedQueryVerification {
        evaluation_domain,
        sorted_query_representatives: &sorted_query_representatives,
        openings: &authenticated_openings,
        deep_point,
        deep_evaluations: &deep_evaluations,
        opening_batch_challenges: &opening_batch_challenges,
        fri_fold_challenges,
        terminal_coefficients,
    })?;
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
    let canonical_round_trip = compact_canonical_proof(&profile, canonical_proof)?;
    if canonical_round_trip != compact_proof {
        return Err("compact packed-DEEP-FRI proof encoding is not canonical".to_owned());
    }
    Ok(())
}

pub(super) fn execute_packed_deep_fri(
    fixture: &ProofBackendBakeoffFixture,
) -> ProofBackendBakeoffResult<ProofBackendBakeoffArmOutput> {
    let generated = generate_packed_deep_fri(fixture)?;
    verify_packed_deep_fri(
        &fixture.canonical_fri_statement,
        &fixture.input_identity_shake256_hex,
        &generated.compact_canonical_proof,
    )?;
    let proof_shake256_hex = hash512_hex(
        "proof-backend-bakeoff/canonical-artifact/v1",
        &[generated.compact_canonical_proof.as_slice()],
    );
    Ok(ProofBackendBakeoffArmOutput {
        canonical_artifact: generated.compact_canonical_proof,
        proof_shake256_hex,
        external_read_byte_length: generated.external_read_byte_length,
        external_written_byte_length: generated.external_written_byte_length,
        external_committed_transaction_count: generated.external_transaction_count,
    })
}

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
