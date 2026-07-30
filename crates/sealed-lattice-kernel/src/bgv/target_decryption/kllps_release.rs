use std::{collections::BTreeMap, fmt, mem::size_of, rc::Rc};

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{Signed, ToPrimitive, Zero};
use zeroize::Zeroizing;

use super::canonical_partial_stream::{
    CanonicalTargetPartialDecryptionStream, TargetPartialDecryptionRole,
    TargetPartialDecryptionStreamError, encode_target_partial_decryption_stream,
};
use super::ciphertext_codec::decode_verified_target_ciphertext;

#[cfg(test)]
use crate::bgv::proof_suite::{
    CommonProofSourceProviderMemoryAccounting,
    target_release_source_provider_memory_accounting_for_source,
};

use crate::{
    bgv::{
        direct_ballots::{MAXIMUM_SCORE, MINIMUM_SCORE},
        encoding::decode_plaintext_coefficients_to_scalar_lanes,
        evaluator::{
            engine::Ciphertext,
            noise_recurrence::{
                DirectBallotTargetReleaseNoiseInput, TargetReleaseNoiseStage,
                direct_ballot_target_noise_bounds, direct_ballot_target_release_noise_trace,
            },
            top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        },
        modular_arithmetic::{add_mod_fast, inverse_mod, mul_mod_fast, sub_mod_fast},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt_in_place},
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
        proof_suite::{
            BorrowedVerifiedCommonProofCapability, CommonProofGenerationAuthorization,
            CommonProofGenerationPreparationError, CommonProofGenerationSources,
            CommonProofProverError, CommonProofRuntimeError, CommonProofRuntimeLimits,
            ConsumedVerifiedCommonProofCapability, PreparedCommonProofGeneration,
            PrivateRandomnessCommonProofCoinError, PrivateRandomnessCommonProofCoinSource,
            TargetReleaseModulusWitness, TargetReleaseRoleWitness,
            TargetReleaseSourcePolynomialAdapter, TargetReleaseVerifiedColumnEvaluator,
            TargetReleaseWitnessError, TargetReleaseWitnessSource,
            TargetReleaseWitnessSourceMemoryAccounting, VerifiedTargetReleaseModulusInput,
            VerifiedTargetReleaseProof, canonical_selected_target_share_statement,
            selected_target_release_relation, verified_application_statement_hash,
        },
        setup::{
            VerifiedAcceptedSetupAuthority, VerifiedAcceptedSetupAuthorityHandle,
            VerifiedAcceptedSetupParticipantTargetReleaseLease,
            lease_verified_participant_target_release_source,
            with_verified_accepted_setup_authority,
            with_verified_participant_target_release_source,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        ActionPrivateRandomness, CanonicalStreamDomain, CanonicalStreamReadbackVerifier,
        FOUNDATION_PROFILE, Hash512, PersistentProofCoinInput, PersistentProofWitnessCoinBinding,
        PreparedActionProofAttemptSource, PrivateRandomCursor, PrivateRandomnessDomain,
        ProofApplicationSlot, ProofApplicationSlotCeilings, RefusalReason, SelectedSuiteCapability,
        StateCapabilityKind, StateVerifier, StreamDescriptor, VerificationResult, VerifiedFinality,
        VerifiedStateOutput, VerifiedStateReservation,
        bind_prepared_action_proof_attempt_to_canonical_witness,
        derive_canonical_stream_descriptor, selected_target_data_prime_coordinates,
    },
    hashing::hash_framed_parts_512,
};

pub(crate) const KLLPS_PARTICIPANT_COUNT: usize = 10;
pub(crate) const KLLPS_RECONSTRUCTION_THRESHOLD: usize = 4;
pub(crate) const KLLPS_DENOMINATOR_CLEARING_FACTOR: u64 = 4;
pub(crate) const KLLPS_THRESHOLD_SIMULATION_BIT_LENGTH: u32 = 96;
pub(crate) const KLLPS_PAIRED_TARGET_ROLE_COUNT: usize = 2;
const KLLPS_SPACED_POINT_COUNT: usize = 16;
pub(crate) const KLLPS_SUBRING_DEGREE: usize = KLLPS_SPACED_POINT_COUNT / 2;
pub(crate) const KLLPS_POINT_STRIDE: usize = (2 * POLYNOMIAL_DEGREE) / KLLPS_SPACED_POINT_COUNT;
const MAXIMUM_AUTHORIZED_COEFFICIENT_NORM: u64 = 44;
const MAXIMUM_UNAUTHORIZED_COEFFICIENT_NORM: u64 = 8;
const TARGET_FLOODING_CONTEXT_HASH_DOMAIN: &str =
    "sealed-lattice/target-release/flooding-context/v1";
const TARGET_RELEASE_WITNESS_SOURCE_BINDING_DOMAIN: &str =
    "sealed-lattice/target-release/witness-source-binding/v1";
const TARGET_RELEASE_CANONICAL_SEMANTIC_WITNESS_DOMAIN: &[u8] =
    b"sealed-lattice/target-release/canonical-semantic-witness/v1";

type SubringPolynomial = [u64; KLLPS_SUBRING_DEGREE];

/// Non-serialized bindings shared by the finalized target and every accepted
/// paired share. The common-proof and state verifiers are the only intended
/// constructors outside this arithmetic module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KllpsReleaseBinding {
    pub(crate) suite_id: [u8; 64],
    pub(crate) ceremony_context_hash: [u8; 64],
    pub(crate) action_context_hash: [u8; 64],
    pub(crate) roster_hash: [u8; 64],
    pub(crate) verified_setup_source_hash: [u8; 64],
    pub(crate) finality_hash: [u8; 64],
    pub(crate) authorization_hash: [u8; 64],
    pub(crate) target_identifier_full_digest: [u8; 64],
    pub(crate) target_order_full_digest: [u8; 64],
}

/// Reset-safe authority for one participant's share-generation attempt. This
/// is checked at proof generation and proof/state application, but it is not a
/// cross-participant reconstruction identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KllpsParticipantReleaseBinding {
    pub(crate) reservation_intent_object_hash: [u8; 64],
    pub(crate) subject_participant_id: [u8; 64],
    pub(crate) state_key: [u8; 64],
}

#[derive(Debug)]
pub(crate) struct KllpsTargetPair {
    binding: KllpsReleaseBinding,
    participant_binding: KllpsParticipantReleaseBinding,
    target_identifier: Ciphertext,
    target_order: Ciphertext,
}

/// Finalized cross-participant target authority used only after individual
/// paired shares have already passed their participant state and board gates.
/// It retains the verifier-derived action selection geometry and deliberately
/// carries no participant reservation binding.
#[derive(Debug)]
pub(crate) struct KllpsReconstructionTargetPair {
    binding: KllpsReleaseBinding,
    option_count: u16,
    top_count: u16,
    target_identifier: Ciphertext,
    target_order: Ciphertext,
}

impl KllpsReconstructionTargetPair {
    fn from_verified_finality(
        binding: KllpsReleaseBinding,
        top_count: u16,
        target_identifier: Ciphertext,
        target_order: Ciphertext,
    ) -> CanonicalResult<Self> {
        let option_count = FOUNDATION_PROFILE.option_count;
        if top_count == 0 || top_count > option_count {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "KLLPS reconstruction top count is outside the verified action profile",
            ));
        }
        validate_target_ciphertext(&target_identifier)?;
        validate_target_ciphertext(&target_order)?;
        if target_identifier.level != target_order.level
            || target_identifier.decrypt_scaling != target_order.decrypt_scaling
        {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "paired KLLPS reconstruction targets must use the same target basis and decryption scaling",
            ));
        }
        Ok(Self {
            binding,
            option_count,
            top_count,
            target_identifier,
            target_order,
        })
    }
}

impl KllpsTargetPair {
    /// Binds already-verified finality ciphertexts to the exact release and
    /// reset-safe reservation context. This performs shape validation, not
    /// finality verification.
    fn from_verified_finality(
        binding: KllpsReleaseBinding,
        participant_binding: KllpsParticipantReleaseBinding,
        target_identifier: Ciphertext,
        target_order: Ciphertext,
    ) -> CanonicalResult<Self> {
        validate_target_ciphertext(&target_identifier)?;
        validate_target_ciphertext(&target_order)?;
        if target_identifier.level != target_order.level
            || target_identifier.decrypt_scaling != target_order.decrypt_scaling
        {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "paired KLLPS targets must use the same target basis and decryption scaling",
            ));
        }

        Ok(Self {
            binding,
            participant_binding,
            target_identifier,
            target_order,
        })
    }

    pub(crate) fn binding(&self) -> &KllpsReleaseBinding {
        &self.binding
    }

    pub(crate) fn participant_binding(&self) -> &KllpsParticipantReleaseBinding {
        &self.participant_binding
    }

    pub(crate) fn level(&self) -> usize {
        self.target_identifier.level
    }
}

#[cfg(test)]
pub(crate) fn kllps_target_pair_from_verified_evaluator_execution_for_tests(
    binding: KllpsReleaseBinding,
    participant_binding: KllpsParticipantReleaseBinding,
    target_identifier: Ciphertext,
    target_order: Ciphertext,
) -> CanonicalResult<KllpsTargetPair> {
    KllpsTargetPair::from_verified_finality(
        binding,
        participant_binding,
        target_identifier,
        target_order,
    )
}

/// Authenticates the exact finalized target bytes and derives every release
/// binding from verifier-owned finality and reset-safe state authority. Caller
/// bytes can supply storage, but cannot select the target level, decryption
/// scaling, context, roster, authorization, or stream digests.
pub(crate) fn verify_finalized_kllps_target_pair(
    state_verifier: &StateVerifier,
    verified_finality: &VerifiedFinality,
    verified_reservation: &VerifiedStateReservation,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
) -> VerificationResult<KllpsTargetPair> {
    match verify_finalized_kllps_target_pair_inner(
        state_verifier,
        verified_finality,
        verified_reservation,
        target_identifier_bytes,
        target_order_bytes,
    ) {
        Ok(target_pair) => VerificationResult::valid(target_pair),
        Err(refusal_reason) => VerificationResult::refused(refusal_reason),
    }
}

fn verify_finalized_kllps_target_pair_inner(
    state_verifier: &StateVerifier,
    verified_finality: &VerifiedFinality,
    verified_reservation: &VerifiedStateReservation,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
) -> Result<KllpsTargetPair, RefusalReason> {
    let statement = verified_finality.statement();
    let state_roster_hash = state_verifier
        .roster_hash()
        .map_err(|error| error.refusal_reason)?;
    if state_roster_hash != statement.roster_hash()
        || verified_reservation.capability_kind() != StateCapabilityKind::TargetRelease
        || verified_reservation.suite_id() != statement.suite_identifier()
        || verified_reservation.ceremony_context_hash() != statement.ceremony_context_hash()
        || verified_reservation.action_context_hash() != statement.action_context_hash()
    {
        return Err(RefusalReason::WrongContext);
    }
    let subject_participant_id = verified_reservation.subject_participant_id();
    let subject_is_in_roster = state_verifier.roster().entries.iter().any(|entry| {
        entry
            .participant_identity()
            .is_ok_and(|participant_identity| participant_identity == subject_participant_id)
    });
    if !subject_is_in_roster {
        return Err(RefusalReason::WrongContext);
    }

    let (binding, target_identifier, target_order) = authenticate_finalized_kllps_target_sources(
        verified_finality,
        target_identifier_bytes,
        target_order_bytes,
    )?;
    if verified_reservation.authorization_hash().into_bytes() != binding.authorization_hash {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    let participant_binding = KllpsParticipantReleaseBinding {
        reservation_intent_object_hash: verified_reservation.intent_object_hash().into_bytes(),
        subject_participant_id: subject_participant_id.into_bytes(),
        state_key: verified_reservation.state_key().into_bytes(),
    };
    KllpsTargetPair::from_verified_finality(
        binding,
        participant_binding,
        target_identifier,
        target_order,
    )
    .map_err(|error| canonical_target_refusal(&error))
}

/// Re-authenticates the exact finalized target for threshold reconstruction.
/// Participant state/output and board bindings are already embodied by each
/// `VerifiedKllpsPairedShare`; this source contributes only the shared finality
/// ciphertexts and cross-participant release binding.
pub(crate) fn verify_finalized_kllps_reconstruction_target_pair(
    verified_finality: &VerifiedFinality,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
) -> VerificationResult<KllpsReconstructionTargetPair> {
    match authenticate_finalized_kllps_target_sources(
        verified_finality,
        target_identifier_bytes,
        target_order_bytes,
    )
    .and_then(|(binding, target_identifier, target_order)| {
        KllpsReconstructionTargetPair::from_verified_finality(
            binding,
            verified_finality.top_count(),
            target_identifier,
            target_order,
        )
        .map_err(|error| canonical_target_refusal(&error))
    }) {
        Ok(target_pair) => VerificationResult::valid(target_pair),
        Err(refusal_reason) => VerificationResult::refused(refusal_reason),
    }
}

fn authenticate_finalized_kllps_target_sources(
    verified_finality: &VerifiedFinality,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
) -> Result<(KllpsReleaseBinding, Ciphertext, Ciphertext), RefusalReason> {
    let statement = verified_finality.statement();
    if statement
        .finality_hash()
        .map_err(|error| error.refusal_reason)?
        != verified_finality.finality_hash()
    {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    let authorization_hash = verified_finality
        .target_release_authorization_hash()
        .map_err(|error| error.refusal_reason)?;
    authenticate_exact_stream(
        verified_finality.open_target_identifier_readback()?,
        target_identifier_bytes,
    )?;
    authenticate_exact_stream(
        verified_finality.open_target_order_readback()?,
        target_order_bytes,
    )?;

    let target_level = usize::from(verified_finality.target_level());
    let decrypt_scaling = verified_finality.decrypt_scaling();
    let target_identifier =
        decode_verified_target_ciphertext(target_identifier_bytes, target_level, decrypt_scaling)
            .map_err(|error| canonical_target_refusal(&error))?;
    let target_order =
        decode_verified_target_ciphertext(target_order_bytes, target_level, decrypt_scaling)
            .map_err(|error| canonical_target_refusal(&error))?;
    let binding = KllpsReleaseBinding {
        suite_id: statement.suite_identifier().into_bytes(),
        ceremony_context_hash: statement.ceremony_context_hash().into_bytes(),
        action_context_hash: statement.action_context_hash().into_bytes(),
        roster_hash: statement.roster_hash().into_bytes(),
        verified_setup_source_hash: verified_finality.verified_setup_source_hash().into_bytes(),
        finality_hash: verified_finality.finality_hash().into_bytes(),
        authorization_hash: authorization_hash.into_bytes(),
        target_identifier_full_digest: verified_finality
            .target_identifier_full_object_digest()
            .into_bytes(),
        target_order_full_digest: verified_finality
            .target_order_full_object_digest()
            .into_bytes(),
    };
    Ok((binding, target_identifier, target_order))
}

fn authenticate_exact_stream(
    mut readback: CanonicalStreamReadbackVerifier,
    canonical_bytes: &[u8],
) -> Result<(), RefusalReason> {
    for (chunk_index, chunk_bytes) in canonical_bytes
        .chunks(crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        readback.authenticate_chunk(chunk_index, chunk_bytes)?;
    }
    readback.finish().into_result().map(|_| ())
}

fn canonical_target_refusal(error: &CanonicalError) -> RefusalReason {
    match error.code {
        CanonicalErrorCode::MalformedLength | CanonicalErrorCode::ComponentMismatch => {
            RefusalReason::WrongTypeOrLength
        }
        CanonicalErrorCode::UnsupportedObjectVersion => RefusalReason::UnsupportedVersionOrSuite,
        CanonicalErrorCode::DuplicateField
        | CanonicalErrorCode::InvalidEnum
        | CanonicalErrorCode::InvalidProtocolObject
        | CanonicalErrorCode::InvalidHex
        | CanonicalErrorCode::InvalidUtf8
        | CanonicalErrorCode::MalformedMagic
        | CanonicalErrorCode::MalformedVarUint
        | CanonicalErrorCode::NonCanonicalVarUint
        | CanonicalErrorCode::TrailingBytes => RefusalReason::MalformedEncoding,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KllpsPairedPartialDecryption {
    binding: KllpsReleaseBinding,
    roster_position: usize,
    target_identifier_by_limb: Vec<Vec<u64>>,
    target_order_by_limb: Vec<Vec<u64>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KllpsPairedPartialDecryptionStreams {
    target_identifier: KllpsPartialDecryptionRoleStream,
    target_order: KllpsPartialDecryptionRoleStream,
}

/// One canonical role stream with its role fixed at construction. The two
/// target roles are moved and consumed independently so no paired resident
/// buffer can cross the copied-buffer ceiling as the selected level changes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct KllpsPartialDecryptionRoleStream {
    role: TargetPartialDecryptionRole,
    canonical_bytes: Vec<u8>,
}

/// Fixed-width signed-magnitude storage for one secret flooding polynomial.
/// The retained limbs and signs are scrubbed on drop; arbitrary-width integer
/// values exist only inside a callback-scoped arithmetic scratch.
struct ZeroizingSignedLimbPolynomial {
    coefficient_count: usize,
    magnitude_limb_count: usize,
    negative_flags: Zeroizing<Vec<u8>>,
    magnitude_limbs: Zeroizing<Vec<u64>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedLimbPolynomialAllocationByteLengths {
    retained_heap_byte_length: u64,
    bigint_callback_ready_resident_byte_length: u64,
    bigint_callback_construction_transient_byte_length: u64,
}

impl ZeroizingSignedLimbPolynomial {
    fn allocation_byte_lengths_from_dimensions(
        coefficient_count: usize,
        magnitude_limb_count: usize,
    ) -> Result<SignedLimbPolynomialAllocationByteLengths, TargetReleaseWitnessError> {
        if coefficient_count == 0 || magnitude_limb_count == 0 {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let magnitude_limb_byte_length = coefficient_count
            .checked_mul(magnitude_limb_count)
            .and_then(|count| count.checked_mul(size_of::<u64>()))
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        let negative_flag_byte_length = u64::try_from(coefficient_count)
            .map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
        let retained_heap_byte_length = negative_flag_byte_length
            .checked_add(magnitude_limb_byte_length)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        let bigint_catalog_byte_length = coefficient_count
            .checked_mul(size_of::<BigInt>())
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        let one_coefficient_conversion_byte_length = magnitude_limb_count
            .checked_mul(size_of::<u64>())
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        let bigint_callback_ready_resident_byte_length = bigint_catalog_byte_length
            .checked_add(magnitude_limb_byte_length)
            .ok_or(TargetReleaseWitnessError::CountOverflow)?;
        Ok(SignedLimbPolynomialAllocationByteLengths {
            retained_heap_byte_length,
            bigint_callback_ready_resident_byte_length,
            bigint_callback_construction_transient_byte_length:
                one_coefficient_conversion_byte_length,
        })
    }

    fn new(coefficient_count: usize, maximum_magnitude: &BigUint) -> CanonicalResult<Self> {
        if coefficient_count == 0 || maximum_magnitude.is_zero() {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "target flooding signed-limb storage requires positive dimensions",
            ));
        }
        let magnitude_limb_count =
            usize::try_from(maximum_magnitude.bits().div_ceil(64)).map_err(|_| {
                invalid_release(
                    CanonicalErrorCode::MalformedLength,
                    "target flooding signed-limb width does not fit this runtime",
                )
            })?;
        let flattened_limb_count = coefficient_count
            .checked_mul(magnitude_limb_count)
            .ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::MalformedLength,
                    "target flooding signed-limb storage length overflows",
                )
            })?;
        Ok(Self {
            coefficient_count,
            magnitude_limb_count,
            negative_flags: Zeroizing::new(Vec::with_capacity(coefficient_count)),
            magnitude_limbs: Zeroizing::new(Vec::with_capacity(flattened_limb_count)),
        })
    }

    fn push_centered_sample(&mut self, sample: BigUint, center: &BigUint) -> CanonicalResult<()> {
        if self.negative_flags.len() >= self.coefficient_count {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "target flooding signed-limb storage received too many coefficients",
            ));
        }
        let (negative, magnitude) = if sample < *center {
            (true, center - sample)
        } else {
            (false, sample - center)
        };
        let magnitude_bytes = Zeroizing::new(magnitude.to_bytes_le());
        let maximum_byte_length = self
            .magnitude_limb_count
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::MalformedLength,
                    "target flooding signed-limb byte length overflows",
                )
            })?;
        if magnitude_bytes.len() > maximum_byte_length {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "target flooding sample exceeds its retained signed-limb width",
            ));
        }
        self.negative_flags
            .push(u8::from(negative && !magnitude.is_zero()));
        for limb_ordinal in 0..self.magnitude_limb_count {
            let byte_start = limb_ordinal * core::mem::size_of::<u64>();
            let byte_end = (byte_start + core::mem::size_of::<u64>()).min(magnitude_bytes.len());
            let mut limb_bytes = [0_u8; core::mem::size_of::<u64>()];
            if byte_start < byte_end {
                limb_bytes[..byte_end - byte_start]
                    .copy_from_slice(&magnitude_bytes[byte_start..byte_end]);
            }
            self.magnitude_limbs.push(u64::from_le_bytes(limb_bytes));
        }
        Ok(())
    }

    fn finish(self) -> CanonicalResult<Self> {
        if self.negative_flags.len() != self.coefficient_count
            || self.magnitude_limbs.len() != self.coefficient_count * self.magnitude_limb_count
        {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "target flooding signed-limb storage is incomplete",
            ));
        }
        Ok(self)
    }

    fn with_bigints<Output, Operation>(
        &self,
        operation: Operation,
    ) -> Result<Output, TargetReleaseWitnessError>
    where
        Operation:
            for<'scratch> FnOnce(&'scratch [BigInt]) -> Result<Output, TargetReleaseWitnessError>,
    {
        let scratch = self.bigint_scratch()?;
        operation(&scratch)
    }

    fn with_bigints_canonical<Output, Operation>(
        &self,
        operation: Operation,
    ) -> CanonicalResult<Output>
    where
        Operation: for<'scratch> FnOnce(&'scratch [BigInt]) -> CanonicalResult<Output>,
    {
        let scratch = self.bigint_scratch().map_err(|_| {
            invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "target flooding signed-limb scratch is malformed",
            )
        })?;
        operation(&scratch)
    }

    fn bigint_scratch(&self) -> Result<Vec<BigInt>, TargetReleaseWitnessError> {
        if self.negative_flags.len() != self.coefficient_count
            || self.magnitude_limbs.len() != self.coefficient_count * self.magnitude_limb_count
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let mut scratch = Vec::with_capacity(self.coefficient_count);
        for coefficient_ordinal in 0..self.coefficient_count {
            let limb_start = coefficient_ordinal * self.magnitude_limb_count;
            let limb_end = limb_start + self.magnitude_limb_count;
            let mut magnitude_bytes = Zeroizing::new(Vec::with_capacity(
                self.magnitude_limb_count * core::mem::size_of::<u64>(),
            ));
            for limb in &self.magnitude_limbs[limb_start..limb_end] {
                magnitude_bytes.extend_from_slice(&limb.to_le_bytes());
            }
            let magnitude = BigUint::from_bytes_le(&magnitude_bytes);
            let sign = if magnitude.is_zero() {
                Sign::NoSign
            } else if self.negative_flags[coefficient_ordinal] == 1 {
                Sign::Minus
            } else if self.negative_flags[coefficient_ordinal] == 0 {
                Sign::Plus
            } else {
                return Err(TargetReleaseWitnessError::InvalidWitness);
            };
            scratch.push(BigInt::from_biguint(sign, magnitude));
        }
        Ok(scratch)
    }

    fn retained_heap_byte_length(&self) -> Result<u64, TargetReleaseWitnessError> {
        let allocation_byte_lengths = Self::allocation_byte_lengths_from_dimensions(
            self.coefficient_count,
            self.magnitude_limb_count,
        )?;
        if self.negative_flags.capacity() != self.coefficient_count
            || self.magnitude_limbs.capacity()
                != self
                    .coefficient_count
                    .checked_mul(self.magnitude_limb_count)
                    .ok_or(TargetReleaseWitnessError::CountOverflow)?
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        Ok(allocation_byte_lengths.retained_heap_byte_length)
    }

    fn bigint_callback_allocation_byte_lengths(
        &self,
    ) -> Result<SignedLimbPolynomialAllocationByteLengths, TargetReleaseWitnessError> {
        if self.coefficient_count == 0
            || self.magnitude_limb_count == 0
            || self.negative_flags.len() != self.coefficient_count
            || self.magnitude_limbs.len()
                != self
                    .coefficient_count
                    .checked_mul(self.magnitude_limb_count)
                    .ok_or(TargetReleaseWitnessError::CountOverflow)?
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        // `BigUint::from_bytes_le` retains at most the same byte width as the
        // fixed u64 magnitude source. The final one-coefficient byte buffer is
        // dropped before the callback body starts, so it cannot overlap the
        // adapter's role-layer construction scratch.
        Self::allocation_byte_lengths_from_dimensions(
            self.coefficient_count,
            self.magnitude_limb_count,
        )
    }

    #[cfg(test)]
    fn zeroize_and_is_empty(&mut self) -> bool {
        use zeroize::Zeroize;

        self.negative_flags.zeroize();
        self.magnitude_limbs.zeroize();
        self.negative_flags.is_empty() && self.magnitude_limbs.is_empty()
    }
}

/// One browser-owned target-release attempt after the accepted setup,
/// finalized target, reset-safe reservation, and private randomness authority
/// have all agreed. Flooding errors and the aggregate threshold share remain
/// process-local and are exposed only to the exact proof-family adapter.
pub(crate) struct AuthorizedKllpsPairedPartialDecryption {
    application_slot: ProofApplicationSlot,
    participant_binding: KllpsParticipantReleaseBinding,
    partial_decryption: KllpsPairedPartialDecryption,
    flooding_polynomials_by_role: [ZeroizingSignedLimbPolynomial; KLLPS_PAIRED_TARGET_ROLE_COUNT],
    flooding_cursors_by_role: [PrivateRandomCursor; KLLPS_PAIRED_TARGET_ROLE_COUNT],
}

impl AuthorizedKllpsPairedPartialDecryption {
    fn with_flooding_errors<Output, Operation>(
        &self,
        role_ordinal: usize,
        operation: Operation,
    ) -> Result<Output, TargetReleaseWitnessError>
    where
        Operation:
            for<'scratch> FnOnce(&'scratch [BigInt]) -> Result<Output, TargetReleaseWitnessError>,
    {
        self.flooding_polynomials_by_role
            .get(role_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?
            .with_bigints(operation)
    }
}

/// Long-lived proof source for one authorized paired release. The accepted
/// committed trees and zeroizing threshold shares remain behind the owned VSS
/// lease, while the proof runtime receives at most one borrowed limb at a
/// time. Canonical partial streams are encoded once and retained for the
/// eventual output bundle.
pub(crate) struct KllpsTargetReleaseWitnessSource {
    proof_witness: KllpsTargetReleaseProofWitnessSource,
    partial_streams: KllpsPairedPartialDecryptionStreams,
    canonical_application_statement_bytes: Vec<u8>,
    application_statement_hash: [u8; 64],
}

struct KllpsTargetReleaseProofWitnessSource {
    accepted_share_lease: VerifiedAcceptedSetupParticipantTargetReleaseLease,
    authorized_partial: AuthorizedKllpsPairedPartialDecryption,
    ordered_target_data_prime_coordinates: Box<[(u16, u64)]>,
    converted_target_identifier_by_limb: Vec<Vec<u64>>,
    converted_target_order_by_limb: Vec<Vec<u64>>,
    restart_binding_hash: [u8; 64],
}

/// One prepared common proof paired with the exact canonical partial streams
/// that become its state-certified output. Both large streams move out of the
/// witness preparation exactly once; the common prover retains only the
/// private arithmetic witness that it consumes.
pub(crate) struct PreparedKllpsTargetReleaseGeneration {
    common_generation: PreparedCommonProofGeneration,
    partial_streams: KllpsPairedPartialDecryptionStreams,
}

impl PreparedKllpsTargetReleaseGeneration {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PreparedCommonProofGeneration,
        KllpsPartialDecryptionRoleStream,
        KllpsPartialDecryptionRoleStream,
    ) {
        let (target_identifier, target_order) = self.partial_streams.into_role_streams();
        (self.common_generation, target_identifier, target_order)
    }
}

#[derive(Debug)]
pub(crate) enum KllpsTargetReleaseGenerationPreparationError {
    Proof(CommonProofGenerationPreparationError),
    Prover(CommonProofProverError),
    Runtime(CommonProofRuntimeError),
    PrivateCoins(PrivateRandomnessCommonProofCoinError),
    Witness(TargetReleaseWitnessError),
}

impl From<CommonProofGenerationPreparationError> for KllpsTargetReleaseGenerationPreparationError {
    fn from(error: CommonProofGenerationPreparationError) -> Self {
        Self::Proof(error)
    }
}

impl From<CommonProofProverError> for KllpsTargetReleaseGenerationPreparationError {
    fn from(error: CommonProofProverError) -> Self {
        Self::Prover(error)
    }
}

impl From<CommonProofRuntimeError> for KllpsTargetReleaseGenerationPreparationError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<PrivateRandomnessCommonProofCoinError> for KllpsTargetReleaseGenerationPreparationError {
    fn from(error: PrivateRandomnessCommonProofCoinError) -> Self {
        Self::PrivateCoins(error)
    }
}

impl From<TargetReleaseWitnessError> for KllpsTargetReleaseGenerationPreparationError {
    fn from(error: TargetReleaseWitnessError) -> Self {
        Self::Witness(error)
    }
}

impl KllpsTargetReleaseWitnessSource {
    pub(crate) const fn application_slot(&self) -> ProofApplicationSlot {
        self.proof_witness.authorized_partial.application_slot
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) fn prepare_common_generation(
        self,
        action_private_randomness: Rc<ActionPrivateRandomness>,
        prepared_attempt: PreparedActionProofAttemptSource,
        limits: CommonProofRuntimeLimits,
    ) -> Result<PreparedKllpsTargetReleaseGeneration, KllpsTargetReleaseGenerationPreparationError>
    {
        if prepared_attempt.application_slot() != self.application_slot()
            || prepared_attempt.application_statement_hash().into_bytes()
                != self.application_statement_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        let KllpsTargetReleaseWitnessSource {
            proof_witness,
            partial_streams,
            canonical_application_statement_bytes,
            application_statement_hash,
        } = self;
        let application_slot = proof_witness.authorized_partial.application_slot;
        let (relation_plan, coordinate_capacity, source_polynomials) =
            TargetReleaseSourcePolynomialAdapter::new_selected(
                FOUNDATION_PROFILE.protocol_version,
                application_slot.suite_identifier().into_bytes(),
                application_statement_hash,
                proof_witness,
            )?;
        let persistent_proof_coin_input = PersistentProofCoinInput::new(
            prepared_attempt.application_slot(),
            prepared_attempt.application_statement_hash(),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let mut witness_binding = action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_proof_coin_input)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        source_polynomials.absorb_canonical_semantic_witness(&mut witness_binding)?;
        let witness_bound_attempt = bind_prepared_action_proof_attempt_to_canonical_witness(
            prepared_attempt,
            witness_binding,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let private_randomness_attempt_identifier =
            witness_bound_attempt.private_randomness_attempt_identifier();
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                FOUNDATION_PROFILE.protocol_version,
                &canonical_application_statement_bytes,
            )?;
        let private_coins = PrivateRandomnessCommonProofCoinSource::new(
            action_private_randomness,
            ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
            Hash512::from_bytes(authorization.binding_hash()),
            private_randomness_attempt_identifier,
            coordinate_capacity,
        )?;
        let relation_trees = source_polynomials.relation_tree_inputs()?;
        let common_generation = PreparedCommonProofGeneration::from_row_code_whir_sources(
            authorization,
            relation_plan,
            canonical_application_statement_bytes,
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(KllpsTargetReleaseGenerationPreparationError::from)?;
        Ok(PreparedKllpsTargetReleaseGeneration {
            common_generation,
            partial_streams,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KllpsTargetReleaseProofWitnessMemoryByteLengths {
    unique_owned_heap_byte_length: u64,
    shared_allocation_byte_length: u64,
    flooding_callback_ready_resident_byte_length: u64,
    flooding_callback_construction_transient_byte_length: u64,
    modulus_callback_transient_byte_length: u64,
}

impl KllpsTargetReleaseProofWitnessMemoryByteLengths {
    #[cfg(test)]
    fn additional_persistent_resident_byte_length(self) -> Result<u64, TargetReleaseWitnessError> {
        self.unique_owned_heap_byte_length
            .checked_add(self.shared_allocation_byte_length)
            .ok_or(TargetReleaseWitnessError::CountOverflow)
    }
}

fn nested_u64_vector_heap_byte_length_from_dimensions(
    outer_count: usize,
    inner_count: usize,
) -> Result<u64, TargetReleaseWitnessError> {
    if outer_count == 0 || inner_count == 0 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let outer_element_byte_length = u64::try_from(size_of::<Vec<u64>>())
        .map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
    let inner_element_byte_length =
        u64::try_from(size_of::<u64>()).map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
    let outer_catalog_byte_length = u64::try_from(outer_count)
        .ok()
        .and_then(|count| count.checked_mul(outer_element_byte_length))
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    let inner_payload_byte_length = u64::try_from(outer_count)
        .ok()
        .and_then(|outer_count| {
            u64::try_from(inner_count)
                .ok()
                .and_then(|inner_count| outer_count.checked_mul(inner_count))
        })
        .and_then(|count| count.checked_mul(inner_element_byte_length))
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    outer_catalog_byte_length
        .checked_add(inner_payload_byte_length)
        .ok_or(TargetReleaseWitnessError::CountOverflow)
}

fn target_data_prime_coordinate_catalog_byte_length(
    coordinate_count: usize,
) -> Result<u64, TargetReleaseWitnessError> {
    if coordinate_count == 0 {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    let coordinate_byte_length = u64::try_from(size_of::<(u16, u64)>())
        .map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
    u64::try_from(coordinate_count)
        .ok()
        .and_then(|count| count.checked_mul(coordinate_byte_length))
        .ok_or(TargetReleaseWitnessError::CountOverflow)
}

fn nested_u64_vector_heap_byte_length(
    vectors: &[Vec<u64>],
    outer_capacity: usize,
    expected_outer_count: usize,
    expected_inner_count: usize,
) -> Result<u64, TargetReleaseWitnessError> {
    if vectors.len() != expected_outer_count
        || outer_capacity != expected_outer_count
        || vectors.iter().any(|values| {
            values.len() != expected_inner_count || values.capacity() != expected_inner_count
        })
    {
        return Err(TargetReleaseWitnessError::InvalidWitness);
    }
    nested_u64_vector_heap_byte_length_from_dimensions(expected_outer_count, expected_inner_count)
}

fn selected_kllps_target_release_proof_witness_memory_byte_lengths()
-> Result<KllpsTargetReleaseProofWitnessMemoryByteLengths, TargetReleaseWitnessError> {
    let active_limb_count = selected_target_data_prime_coordinates()
        .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?
        .len();
    let (lease_unique_owned_heap_byte_length, lease_shared_allocation_byte_length) =
        VerifiedAcceptedSetupParticipantTargetReleaseLease::memory_byte_lengths_from_dimensions(
            active_limb_count,
            POLYNOMIAL_DEGREE,
        )
        .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
    let coordinate_catalog_byte_length =
        target_data_prime_coordinate_catalog_byte_length(active_limb_count)?;
    let one_nested_limb_catalog_byte_length =
        nested_u64_vector_heap_byte_length_from_dimensions(active_limb_count, POLYNOMIAL_DEGREE)?;
    let all_nested_limb_catalogs_byte_length = one_nested_limb_catalog_byte_length
        .checked_mul(4)
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    let flooding_bound = selected_factor_four_flooding_bound()
        .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
    let flooding_magnitude_limb_count = usize::try_from(flooding_bound.bits().div_ceil(64))
        .map_err(|_| TargetReleaseWitnessError::CountOverflow)?;
    let flooding_allocation_byte_lengths =
        ZeroizingSignedLimbPolynomial::allocation_byte_lengths_from_dimensions(
            POLYNOMIAL_DEGREE,
            flooding_magnitude_limb_count,
        )?;
    let all_flooding_polynomial_retained_byte_length = flooding_allocation_byte_lengths
        .retained_heap_byte_length
        .checked_mul(
            u64::try_from(KLLPS_PAIRED_TARGET_ROLE_COUNT)
                .map_err(|_| TargetReleaseWitnessError::CountOverflow)?,
        )
        .ok_or(TargetReleaseWitnessError::CountOverflow)?;
    let unique_owned_heap_byte_length = [
        lease_unique_owned_heap_byte_length,
        coordinate_catalog_byte_length,
        all_nested_limb_catalogs_byte_length,
        all_flooding_polynomial_retained_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, |total, byte_length| {
        total
            .checked_add(byte_length)
            .ok_or(TargetReleaseWitnessError::CountOverflow)
    })?;
    Ok(KllpsTargetReleaseProofWitnessMemoryByteLengths {
        unique_owned_heap_byte_length,
        shared_allocation_byte_length: lease_shared_allocation_byte_length,
        flooding_callback_ready_resident_byte_length: flooding_allocation_byte_lengths
            .bigint_callback_ready_resident_byte_length,
        flooding_callback_construction_transient_byte_length: flooding_allocation_byte_lengths
            .bigint_callback_construction_transient_byte_length,
        modulus_callback_transient_byte_length: 0,
    })
}

#[cfg(test)]
pub(crate) fn selected_kllps_target_release_source_provider_memory_accounting()
-> Result<CommonProofSourceProviderMemoryAccounting, CommonProofProverError> {
    let source_memory =
        selected_kllps_target_release_proof_witness_memory_byte_lengths().map_err(|error| {
            match error {
                TargetReleaseWitnessError::CountOverflow
                | TargetReleaseWitnessError::IntegerOverflow => {
                    CommonProofProverError::CountOverflow
                }
                TargetReleaseWitnessError::Relation(error) => {
                    CommonProofProverError::Relation(error)
                }
                TargetReleaseWitnessError::Field(error) => CommonProofProverError::Field(error),
                TargetReleaseWitnessError::Polynomial(error) => {
                    CommonProofProverError::Polynomial(error)
                }
                TargetReleaseWitnessError::InvalidWitness => CommonProofProverError::InvalidInput,
            }
        })?;
    let compilation =
        selected_target_release_relation().map_err(|_| CommonProofProverError::InvalidInput)?;
    target_release_source_provider_memory_accounting_for_source::<
        KllpsTargetReleaseProofWitnessSource,
    >(
        &compilation,
        source_memory
            .additional_persistent_resident_byte_length()
            .map_err(|_| CommonProofProverError::CountOverflow)?,
        source_memory.flooding_callback_ready_resident_byte_length,
        source_memory.flooding_callback_construction_transient_byte_length,
        source_memory.modulus_callback_transient_byte_length,
    )
}

impl TargetReleaseWitnessSource for KllpsTargetReleaseProofWitnessSource {
    fn memory_accounting(
        &self,
    ) -> Result<TargetReleaseWitnessSourceMemoryAccounting, TargetReleaseWitnessError> {
        let lease_memory_accounting = self
            .accepted_share_lease
            .memory_accounting()
            .map_err(|_| TargetReleaseWitnessError::InvalidWitness)?;
        let active_limb_count = self.ordered_target_data_prime_coordinates.len();
        if self.accepted_share_lease.limb_count() != active_limb_count {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let coordinate_catalog_byte_length =
            target_data_prime_coordinate_catalog_byte_length(active_limb_count)?;
        let partial_identifier_byte_length = nested_u64_vector_heap_byte_length(
            &self
                .authorized_partial
                .partial_decryption
                .target_identifier_by_limb,
            self.authorized_partial
                .partial_decryption
                .target_identifier_by_limb
                .capacity(),
            active_limb_count,
            POLYNOMIAL_DEGREE,
        )?;
        let partial_order_byte_length = nested_u64_vector_heap_byte_length(
            &self
                .authorized_partial
                .partial_decryption
                .target_order_by_limb,
            self.authorized_partial
                .partial_decryption
                .target_order_by_limb
                .capacity(),
            active_limb_count,
            POLYNOMIAL_DEGREE,
        )?;
        let converted_identifier_byte_length = nested_u64_vector_heap_byte_length(
            &self.converted_target_identifier_by_limb,
            self.converted_target_identifier_by_limb.capacity(),
            active_limb_count,
            POLYNOMIAL_DEGREE,
        )?;
        let converted_order_byte_length = nested_u64_vector_heap_byte_length(
            &self.converted_target_order_by_limb,
            self.converted_target_order_by_limb.capacity(),
            active_limb_count,
            POLYNOMIAL_DEGREE,
        )?;
        let flooding_polynomial_retained_byte_length = self
            .authorized_partial
            .flooding_polynomials_by_role
            .iter()
            .try_fold(0_u64, |total, polynomial| {
                total
                    .checked_add(polynomial.retained_heap_byte_length()?)
                    .ok_or(TargetReleaseWitnessError::CountOverflow)
            })?;
        let (
            flooding_callback_ready_resident_byte_length,
            flooding_callback_construction_transient_byte_length,
        ) = self
            .authorized_partial
            .flooding_polynomials_by_role
            .iter()
            .try_fold((0_u64, 0_u64), |maximums, polynomial| {
                let allocation_byte_lengths =
                    polynomial.bigint_callback_allocation_byte_lengths()?;
                Ok::<_, TargetReleaseWitnessError>((
                    maximums
                        .0
                        .max(allocation_byte_lengths.bigint_callback_ready_resident_byte_length),
                    maximums.1.max(
                        allocation_byte_lengths.bigint_callback_construction_transient_byte_length,
                    ),
                ))
            })?;
        if flooding_callback_ready_resident_byte_length == 0
            || flooding_callback_construction_transient_byte_length == 0
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        let unique_owned_heap_byte_length = [
            lease_memory_accounting.unique_owned_heap_byte_length(),
            coordinate_catalog_byte_length,
            partial_identifier_byte_length,
            partial_order_byte_length,
            converted_identifier_byte_length,
            converted_order_byte_length,
            flooding_polynomial_retained_byte_length,
        ]
        .into_iter()
        .try_fold(0_u64, |total, byte_length| {
            total
                .checked_add(byte_length)
                .ok_or(TargetReleaseWitnessError::CountOverflow)
        })?;
        let accounting = TargetReleaseWitnessSourceMemoryAccounting::new(
            unique_owned_heap_byte_length,
            lease_memory_accounting.shared_allocations().to_vec(),
            flooding_callback_ready_resident_byte_length,
            flooding_callback_construction_transient_byte_length,
            0,
        )?;
        let selected_memory = selected_kllps_target_release_proof_witness_memory_byte_lengths()?;
        if accounting.unique_owned_heap_byte_length()
            != selected_memory.unique_owned_heap_byte_length
            || accounting.shared_allocation_byte_length()
                != selected_memory.shared_allocation_byte_length
            || accounting.flooding_callback_ready_resident_byte_length()
                != selected_memory.flooding_callback_ready_resident_byte_length
            || accounting.flooding_callback_construction_transient_byte_length()
                != selected_memory.flooding_callback_construction_transient_byte_length
            || accounting.modulus_callback_transient_byte_length()
                != selected_memory.modulus_callback_transient_byte_length
        {
            return Err(TargetReleaseWitnessError::InvalidWitness);
        }
        Ok(accounting)
    }

    fn with_flooding_errors<Output, Operation>(
        &self,
        role_ordinal: usize,
        operation: Operation,
    ) -> Result<Output, TargetReleaseWitnessError>
    where
        Operation:
            for<'scratch> FnOnce(&'scratch [BigInt]) -> Result<Output, TargetReleaseWitnessError>,
    {
        self.authorized_partial
            .with_flooding_errors(role_ordinal, operation)
    }

    fn with_modulus_witness<Output, Operation>(
        &self,
        modulus_ordinal: usize,
        operation: Operation,
    ) -> Result<Output, TargetReleaseWitnessError>
    where
        Operation: for<'input> FnOnce(
            TargetReleaseModulusWitness<'input>,
        ) -> Result<Output, TargetReleaseWitnessError>,
    {
        let converted_target_identifier = self
            .converted_target_identifier_by_limb
            .get(modulus_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let converted_target_order = self
            .converted_target_order_by_limb
            .get(modulus_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let target_identifier_partial = self
            .authorized_partial
            .partial_decryption
            .target_identifier_by_limb
            .get(modulus_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let target_order_partial = self
            .authorized_partial
            .partial_decryption
            .target_order_by_limb
            .get(modulus_ordinal)
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        let (expected_data_modulus_index, expected_modulus) = self
            .ordered_target_data_prime_coordinates
            .get(modulus_ordinal)
            .copied()
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?;
        self.accepted_share_lease
            .with_limb(
                modulus_ordinal,
                |data_modulus_index, modulus, threshold_share, committed_share| {
                    if data_modulus_index != expected_data_modulus_index
                        || modulus != expected_modulus
                    {
                        return Err(TargetReleaseWitnessError::InvalidWitness);
                    }
                    operation(TargetReleaseModulusWitness {
                        committed_share_source: committed_share,
                        threshold_share,
                        roles: [
                            TargetReleaseRoleWitness {
                                converted_a: converted_target_identifier,
                                partial_decryption: target_identifier_partial,
                            },
                            TargetReleaseRoleWitness {
                                converted_a: converted_target_order,
                                partial_decryption: target_order_partial,
                            },
                        ],
                    })
                },
            )
            .ok_or(TargetReleaseWitnessError::InvalidWitness)?
    }

    fn source_restart_binding_hash(&self) -> [u8; 64] {
        self.restart_binding_hash
    }

    fn absorb_canonical_semantic_witness(
        &self,
        binding: &mut PersistentProofWitnessCoinBinding,
    ) -> Result<(), TargetReleaseWitnessError> {
        let map_binding_error = |_| TargetReleaseWitnessError::InvalidWitness;
        binding
            .absorb_canonical_bytes(TARGET_RELEASE_CANONICAL_SEMANTIC_WITNESS_DOMAIN)
            .map_err(map_binding_error)?;
        binding
            .absorb_canonical_bytes(&2_u16.to_le_bytes())
            .map_err(map_binding_error)?;
        for role_ordinal in 0..KLLPS_PAIRED_TARGET_ROLE_COUNT {
            binding
                .absorb_canonical_bytes(&(role_ordinal as u16).to_le_bytes())
                .map_err(map_binding_error)?;
            self.with_flooding_errors(role_ordinal, |errors| {
                binding
                    .absorb_canonical_bytes(
                        &u64::try_from(errors.len())
                            .map_err(|_| TargetReleaseWitnessError::CountOverflow)?
                            .to_le_bytes(),
                    )
                    .map_err(map_binding_error)?;
                for error in errors {
                    binding
                        .absorb_canonical_bytes(&error.to_signed_bytes_le())
                        .map_err(map_binding_error)?;
                }
                Ok(())
            })?;
        }
        binding
            .absorb_canonical_bytes(
                &u64::try_from(self.ordered_target_data_prime_coordinates.len())
                    .map_err(|_| TargetReleaseWitnessError::CountOverflow)?
                    .to_le_bytes(),
            )
            .map_err(map_binding_error)?;
        for modulus_ordinal in 0..self.ordered_target_data_prime_coordinates.len() {
            binding
                .absorb_canonical_bytes(
                    &u64::try_from(modulus_ordinal)
                        .map_err(|_| TargetReleaseWitnessError::CountOverflow)?
                        .to_le_bytes(),
                )
                .map_err(map_binding_error)?;
            self.with_modulus_witness(modulus_ordinal, |witness| {
                binding
                    .absorb_canonical_u64_values(witness.threshold_share)
                    .map_err(map_binding_error)
            })?;
        }
        Ok(())
    }
}

pub(crate) fn lease_authorized_target_release_witness_source(
    accepted_setup_authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
    target_pair: &KllpsTargetPair,
    authorized_partial: AuthorizedKllpsPairedPartialDecryption,
) -> CanonicalResult<KllpsTargetReleaseWitnessSource> {
    let binding = target_pair.binding();
    let participant_binding = target_pair.participant_binding();
    let active_limb_count = target_pair.level() + 1;
    let selected_target_coordinates = selected_target_data_prime_coordinates().map_err(|_| {
        invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "selected target basis does not resolve against the sharing basis",
        )
    })?;
    if authorized_partial.partial_decryption.binding != *binding
        || authorized_partial.participant_binding != *participant_binding
        || authorized_partial.partial_decryption.roster_position
            >= usize::from(FOUNDATION_PROFILE.participant_count)
        || authorized_partial
            .partial_decryption
            .target_identifier_by_limb
            .len()
            != active_limb_count
        || authorized_partial
            .partial_decryption
            .target_order_by_limb
            .len()
            != active_limb_count
        || selected_target_coordinates.len() != active_limb_count
        || target_pair.level() != CANONICAL_TARGET_CIPHERTEXT_LEVEL
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "target-release witness does not match the finalized target",
        ));
    }
    let accepted_roots_by_limb = with_verified_accepted_setup_authority(
        accepted_setup_authority_handle,
        |accepted_setup_authority| {
            accepted_setup_authority
                .participant_release_material(participant_binding.subject_participant_id)
                .ok_or_else(|| {
                    invalid_release(
                        CanonicalErrorCode::ComponentMismatch,
                        "accepted setup has no public release material for the target-share subject",
                    )
                })?
                .selected_target_aggregate_threshold_roots()
        },
    )?;
    let accepted_share_lease = lease_verified_participant_target_release_source(
        accepted_setup_authority_handle,
        participant_binding.subject_participant_id,
    )?;
    if accepted_share_lease.participant_identity() != participant_binding.subject_participant_id
        || usize::from(accepted_share_lease.roster_position())
            != authorized_partial.partial_decryption.roster_position
        || accepted_share_lease.limb_count() != active_limb_count
        || accepted_roots_by_limb.len() != active_limb_count
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "accepted setup does not match the target-release proof witness",
        ));
    }

    let converted_target_identifier_by_limb = selected_target_coordinates
        .iter()
        .map(|(data_modulus_index, modulus)| {
            target_pair.target_identifier.components[1]
                .get(usize::from(*data_modulus_index))
                .ok_or_else(|| {
                    invalid_release(
                        CanonicalErrorCode::MalformedLength,
                        "target identifier does not cover the selected target basis",
                    )
                })
                .and_then(|component| converted_target_component(component, *modulus))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let converted_target_order_by_limb = selected_target_coordinates
        .iter()
        .map(|(data_modulus_index, modulus)| {
            target_pair.target_order.components[1]
                .get(usize::from(*data_modulus_index))
                .ok_or_else(|| {
                    invalid_release(
                        CanonicalErrorCode::MalformedLength,
                        "target order does not cover the selected target basis",
                    )
                })
                .and_then(|component| converted_target_component(component, *modulus))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if converted_target_identifier_by_limb.len() != active_limb_count
        || converted_target_order_by_limb.len() != active_limb_count
    {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "finalized target does not contain the complete selected release basis",
        ));
    }

    let partial_streams = authorized_partial.partial_decryption.encode_streams()?;
    let application_slot_hash = authorized_partial
        .application_slot
        .hash()
        .map_err(private_randomness_error)?
        .into_bytes();
    let target_identifier_cursor = authorized_partial.flooding_cursors_by_role[0]
        .encode()
        .map_err(private_randomness_error)?;
    let target_order_cursor = authorized_partial.flooding_cursors_by_role[1]
        .encode()
        .map_err(private_randomness_error)?;
    let roster_position = accepted_share_lease.roster_position().to_le_bytes();
    let active_limb_count_bytes = u64::try_from(active_limb_count)
        .map_err(|_| {
            invalid_release(
                CanonicalErrorCode::MalformedLength,
                "target-release limb count does not fit u64",
            )
        })?
        .to_le_bytes();
    for (target_basis_position, (expected_data_modulus_index, expected_modulus)) in
        selected_target_coordinates.iter().copied().enumerate()
    {
        let expected_root = accepted_roots_by_limb
            .get(target_basis_position)
            .copied()
            .ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::ComponentMismatch,
                    "accepted setup public roots do not cover the selected target basis",
                )
            })?;
        let leased_root = accepted_share_lease
            .with_limb(
                target_basis_position,
                |data_modulus_index, modulus, _, committed_share| {
                    if data_modulus_index != expected_data_modulus_index
                        || modulus != expected_modulus
                    {
                        return None;
                    }
                    Some(committed_share.root())
                },
            )
            .flatten()
            .ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::ComponentMismatch,
                    "accepted setup target limb is outside the selected ordered basis",
                )
            })?;
        if leased_root != expected_root {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "accepted setup private target opening does not match its verifier-accepted public root",
            ));
        }
    }
    let target_identifier_descriptor = partial_streams.target_identifier_descriptor()?;
    let target_order_descriptor = partial_streams.target_order_descriptor()?;
    let canonical_application_statement_bytes = canonical_selected_target_share_statement(
        FOUNDATION_PROFILE.protocol_version,
        binding.suite_id,
        binding.ceremony_context_hash,
        binding.action_context_hash,
        binding.roster_hash,
        binding.verified_setup_source_hash,
        binding.finality_hash,
        participant_binding.reservation_intent_object_hash,
        participant_binding.subject_participant_id,
        accepted_share_lease.roster_position(),
        &accepted_roots_by_limb,
        &target_identifier_descriptor,
        &target_order_descriptor,
    )
    .map_err(|error| {
        invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("target-share statement cannot be encoded: {error:?}"),
        )
    })?;
    let application_statement_hash = verified_application_statement_hash(
        FOUNDATION_PROFILE.protocol_version,
        binding.suite_id,
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        &canonical_application_statement_bytes,
    );
    let accepted_roots = accepted_roots_by_limb
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let restart_binding_hash = hash_framed_parts_512(
        TARGET_RELEASE_WITNESS_SOURCE_BINDING_DOMAIN,
        &[
            &binding.suite_id,
            &binding.ceremony_context_hash,
            &binding.action_context_hash,
            &binding.roster_hash,
            &binding.verified_setup_source_hash,
            &binding.finality_hash,
            &participant_binding.reservation_intent_object_hash,
            &participant_binding.subject_participant_id,
            &participant_binding.state_key,
            &binding.authorization_hash,
            &binding.target_identifier_full_digest,
            &binding.target_order_full_digest,
            &application_slot_hash,
            &application_statement_hash,
            &roster_position,
            &active_limb_count_bytes,
            &accepted_roots,
            partial_streams.target_identifier_bytes(),
            partial_streams.target_order_bytes(),
            &target_identifier_cursor,
            &target_order_cursor,
        ],
    );
    Ok(KllpsTargetReleaseWitnessSource {
        proof_witness: KllpsTargetReleaseProofWitnessSource {
            accepted_share_lease,
            authorized_partial,
            ordered_target_data_prime_coordinates: selected_target_coordinates,
            converted_target_identifier_by_limb,
            converted_target_order_by_limb,
            restart_binding_hash,
        },
        partial_streams,
        canonical_application_statement_bytes,
        application_statement_hash,
    })
}

impl fmt::Debug for AuthorizedKllpsPairedPartialDecryption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedKllpsPairedPartialDecryption")
            .field("application_slot", &self.application_slot)
            .field("partial_decryption", &self.partial_decryption)
            .field("flooding_polynomials_by_role", &"[REDACTED]")
            .field("flooding_cursors_by_role", &"[REDACTED]")
            .finish()
    }
}

impl KllpsPairedPartialDecryptionStreams {
    pub(crate) fn decode_partial(
        binding: KllpsReleaseBinding,
        roster_position: usize,
        target_identifier_bytes: &[u8],
        target_order_bytes: &[u8],
    ) -> CanonicalResult<KllpsPairedPartialDecryption> {
        if target_identifier_bytes.is_empty()
            || target_order_bytes.is_empty()
            || target_identifier_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || target_order_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
        {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "canonical KLLPS role stream exceeds the copied-buffer bound",
            ));
        }
        let target_identifier =
            CanonicalTargetPartialDecryptionStream::decode(target_identifier_bytes)
                .map_err(partial_stream_error)?;
        let target_order = CanonicalTargetPartialDecryptionStream::decode(target_order_bytes)
            .map_err(partial_stream_error)?;
        if target_identifier.role() != TargetPartialDecryptionRole::TargetIdentifier
            || target_order.role() != TargetPartialDecryptionRole::TargetOrder
        {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "paired KLLPS partial streams use the wrong role order",
            ));
        }
        Ok(KllpsPairedPartialDecryption {
            binding,
            roster_position,
            target_identifier_by_limb: target_identifier
                .ordered_limbs()
                .map_err(partial_stream_error)?,
            target_order_by_limb: target_order.ordered_limbs().map_err(partial_stream_error)?,
        })
    }

    pub(crate) fn target_identifier_bytes(&self) -> &[u8] {
        self.target_identifier.canonical_bytes()
    }

    pub(crate) fn target_order_bytes(&self) -> &[u8] {
        self.target_order.canonical_bytes()
    }

    pub(crate) fn target_identifier_descriptor(&self) -> CanonicalResult<StreamDescriptor> {
        self.target_identifier.descriptor()
    }

    pub(crate) fn target_order_descriptor(&self) -> CanonicalResult<StreamDescriptor> {
        self.target_order.descriptor()
    }

    pub(crate) fn into_role_streams(
        self,
    ) -> (
        KllpsPartialDecryptionRoleStream,
        KllpsPartialDecryptionRoleStream,
    ) {
        (self.target_identifier, self.target_order)
    }
}

impl KllpsPartialDecryptionRoleStream {
    fn new(role: TargetPartialDecryptionRole, canonical_bytes: Vec<u8>) -> CanonicalResult<Self> {
        if canonical_bytes.is_empty()
            || canonical_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
        {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "canonical KLLPS role stream exceeds the copied-buffer bound",
            ));
        }
        Ok(Self {
            role,
            canonical_bytes,
        })
    }

    pub(crate) const fn role(&self) -> TargetPartialDecryptionRole {
        self.role
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn descriptor(&self) -> CanonicalResult<StreamDescriptor> {
        let stream_domain = match self.role() {
            TargetPartialDecryptionRole::TargetIdentifier => {
                CanonicalStreamDomain::TargetIdentifierPartialDecryption
            }
            TargetPartialDecryptionRole::TargetOrder => {
                CanonicalStreamDomain::TargetOrderPartialDecryption
            }
        };
        derive_canonical_stream_descriptor(stream_domain, &self.canonical_bytes).map_err(|reason| {
            invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("target partial stream descriptor refused: {reason:?}"),
            )
        })
    }
}

impl KllpsPairedPartialDecryption {
    pub(crate) fn encode_streams(&self) -> CanonicalResult<KllpsPairedPartialDecryptionStreams> {
        Ok(KllpsPairedPartialDecryptionStreams {
            target_identifier: KllpsPartialDecryptionRoleStream::new(
                TargetPartialDecryptionRole::TargetIdentifier,
                encode_target_partial_decryption_stream(
                    TargetPartialDecryptionRole::TargetIdentifier,
                    &self.target_identifier_by_limb,
                )
                .map_err(partial_stream_error)?,
            )?,
            target_order: KllpsPartialDecryptionRoleStream::new(
                TargetPartialDecryptionRole::TargetOrder,
                encode_target_partial_decryption_stream(
                    TargetPartialDecryptionRole::TargetOrder,
                    &self.target_order_by_limb,
                )
                .map_err(partial_stream_error)?,
            )?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct VerifiedKllpsPairedShare {
    partial_decryption: KllpsPairedPartialDecryption,
}

/// Fully checked target-share terminal held while the generic common-proof
/// capability remains live. Completion is infallible and consumes that exact
/// capability, so a failed family or destination preflight is retryable.
pub(crate) struct VerifiedKllpsPairedSharePreflight {
    verified_share: VerifiedKllpsPairedShare,
}

impl VerifiedKllpsPairedSharePreflight {
    pub(crate) fn complete(
        self,
        _verified_common_proof: ConsumedVerifiedCommonProofCapability,
    ) -> VerifiedKllpsPairedShare {
        self.verified_share
    }
}

pub(crate) struct KllpsShareVerificationSources<'input> {
    pub(crate) accepted_setup_authority: &'input VerifiedAcceptedSetupAuthority,
    pub(crate) verified_finality: &'input VerifiedFinality,
    pub(crate) verified_reservation: &'input VerifiedStateReservation,
    pub(crate) verified_output: &'input VerifiedStateOutput,
    pub(crate) target_pair: &'input KllpsTargetPair,
    pub(crate) target_identifier_partial_bytes: &'input [u8],
    pub(crate) target_order_partial_bytes: &'input [u8],
}

/// Reconstructs the sole verifier-sequence view for schema `0x1621` from the
/// finalized target and the two canonical partial-decryption streams. The
/// selected relation supplies every modulus, scale, column, and bound; the
/// caller cannot provide an alternate arithmetic profile.
pub(crate) fn verified_target_release_column_evaluator(
    target_pair: &KllpsTargetPair,
    roster_position: usize,
    target_identifier_partial_bytes: &[u8],
    target_order_partial_bytes: &[u8],
) -> CanonicalResult<TargetReleaseVerifiedColumnEvaluator> {
    let partial_decryption = KllpsPairedPartialDecryptionStreams::decode_partial(
        target_pair.binding.clone(),
        roster_position,
        target_identifier_partial_bytes,
        target_order_partial_bytes,
    )?;
    let selected_target_coordinates = selected_target_data_prime_coordinates().map_err(|_| {
        invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "selected target basis does not resolve for target-share verification",
        )
    })?;
    if selected_target_coordinates.len() != target_pair.level() + 1
        || partial_decryption.target_identifier_by_limb.len() != selected_target_coordinates.len()
        || partial_decryption.target_order_by_limb.len() != selected_target_coordinates.len()
    {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "target-share streams do not cover the complete selected target basis",
        ));
    }

    let converted_target_identifier_by_limb = selected_target_coordinates
        .iter()
        .map(|(data_modulus_index, modulus)| {
            target_pair.target_identifier.components[1]
                .get(usize::from(*data_modulus_index))
                .ok_or_else(|| {
                    invalid_release(
                        CanonicalErrorCode::MalformedLength,
                        "target identifier does not cover the selected target basis",
                    )
                })
                .and_then(|component| converted_target_component(component, *modulus))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let converted_target_order_by_limb = selected_target_coordinates
        .iter()
        .map(|(data_modulus_index, modulus)| {
            target_pair.target_order.components[1]
                .get(usize::from(*data_modulus_index))
                .ok_or_else(|| {
                    invalid_release(
                        CanonicalErrorCode::MalformedLength,
                        "target order does not cover the selected target basis",
                    )
                })
                .and_then(|component| converted_target_component(component, *modulus))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let public_moduli = (0..selected_target_coordinates.len())
        .map(|modulus_ordinal| VerifiedTargetReleaseModulusInput {
            roles: [
                TargetReleaseRoleWitness {
                    converted_a: &converted_target_identifier_by_limb[modulus_ordinal],
                    partial_decryption: &partial_decryption.target_identifier_by_limb
                        [modulus_ordinal],
                },
                TargetReleaseRoleWitness {
                    converted_a: &converted_target_order_by_limb[modulus_ordinal],
                    partial_decryption: &partial_decryption.target_order_by_limb[modulus_ordinal],
                },
            ],
        })
        .collect::<Vec<_>>();
    selected_target_release_relation()
        .map_err(|_| {
            invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "selected target-release relation is unavailable",
            )
        })?
        .verified_column_evaluator(&public_moduli)
        .map_err(|_| {
            invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "canonical target-share streams do not satisfy the selected verifier layout",
            )
        })
}

pub(crate) fn preflight_kllps_paired_share_from_borrowed_common_proof(
    verified_common_proof: BorrowedVerifiedCommonProofCapability<'_>,
    sources: KllpsShareVerificationSources<'_>,
) -> CanonicalResult<VerifiedKllpsPairedSharePreflight> {
    let verified_target_release_proof = VerifiedTargetReleaseProof::from_borrowed_common_proof(
        verified_common_proof.verified_proof(),
    )
    .map_err(|_| {
        invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "common proof does not name the target-share application",
        )
    })?;
    let verified_share = preflight_kllps_paired_share_binding(
        &verified_target_release_proof,
        verified_common_proof.proof_stream_domain(),
        verified_common_proof.proof_stream_descriptor(),
        sources,
    )?;
    Ok(VerifiedKllpsPairedSharePreflight { verified_share })
}

fn preflight_kllps_paired_share_binding(
    verified_target_release_proof: &VerifiedTargetReleaseProof,
    verified_proof_stream_domain: CanonicalStreamDomain,
    verified_proof_stream_descriptor: &StreamDescriptor,
    sources: KllpsShareVerificationSources<'_>,
) -> CanonicalResult<VerifiedKllpsPairedShare> {
    verified_target_release_proof
        .require_selected_relation()
        .map_err(|_| {
            invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "common proof does not use the selected target-release relation",
            )
        })?;
    let setup_authority = sources.accepted_setup_authority;
    let binding = sources.target_pair.binding();
    let participant_binding = sources.target_pair.participant_binding();
    if setup_authority.protocol_version() != FOUNDATION_PROFILE.protocol_version
        || setup_authority.suite_identifier() != binding.suite_id
        || setup_authority.ceremony_context_hash() != binding.ceremony_context_hash
        || setup_authority.action_context_hash() != binding.action_context_hash
        || setup_authority.roster_hash() != binding.roster_hash
        || setup_authority.exact_verified_setup_source_hash() != binding.verified_setup_source_hash
        || setup_authority.ring_degree() != POLYNOMIAL_DEGREE
        || setup_authority.ordered_data_moduli() != DATA_PRIMES
        || setup_authority
            .ordered_data_modulus_indices()
            .iter()
            .copied()
            .ne((0..DATA_PRIMES.len()).map(|index| index as u16))
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "accepted setup authority does not match the selected KLLPS release binding",
        ));
    }

    let finality_statement = sources.verified_finality.statement();
    if finality_statement.suite_identifier().into_bytes() != binding.suite_id
        || finality_statement.ceremony_context_hash().into_bytes() != binding.ceremony_context_hash
        || finality_statement.action_context_hash().into_bytes() != binding.action_context_hash
        || finality_statement.roster_hash().into_bytes() != binding.roster_hash
        || sources.verified_finality.finality_hash().into_bytes() != binding.finality_hash
        || sources
            .verified_finality
            .verified_setup_source_hash()
            .into_bytes()
            != binding.verified_setup_source_hash
        || sources
            .verified_finality
            .target_identifier_full_object_digest()
            .into_bytes()
            != binding.target_identifier_full_digest
        || sources
            .verified_finality
            .target_order_full_object_digest()
            .into_bytes()
            != binding.target_order_full_digest
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "verified finality does not match the KLLPS release binding",
        ));
    }

    let reservation = sources.verified_reservation;
    let output = sources.verified_output;
    if reservation.capability_kind() != StateCapabilityKind::TargetRelease
        || reservation.suite_id().into_bytes() != binding.suite_id
        || reservation.ceremony_context_hash().into_bytes() != binding.ceremony_context_hash
        || reservation.action_context_hash().into_bytes() != binding.action_context_hash
        || reservation.intent_object_hash().into_bytes()
            != participant_binding.reservation_intent_object_hash
        || reservation.subject_participant_id().into_bytes()
            != participant_binding.subject_participant_id
        || reservation.state_key().into_bytes() != participant_binding.state_key
        || reservation.authorization_hash().into_bytes() != binding.authorization_hash
        || output.capability_kind() != reservation.capability_kind()
        || output.suite_id() != reservation.suite_id()
        || output.ceremony_context_hash() != reservation.ceremony_context_hash()
        || output.action_context_hash() != reservation.action_context_hash()
        || output.reservation_intent_object_hash() != reservation.intent_object_hash()
        || output.subject_participant_id() != reservation.subject_participant_id()
        || output.state_key() != reservation.state_key()
        || output.authorization_hash() != reservation.authorization_hash()
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "state-certified output does not match the reset-safe KLLPS reservation",
        ));
    }
    let output_bundle = output.target_release_output_bundle().ok_or_else(|| {
        invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "state-certified target release has no authenticated exact-output bundle",
        )
    })?;
    if output_bundle.finality_hash().into_bytes() != binding.finality_hash
        || output_bundle.reservation_intent_object_hash().into_bytes()
            != participant_binding.reservation_intent_object_hash
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "target-release exact output names another finality or reservation",
        ));
    }

    authenticate_exact_stream(
        output_bundle
            .open_target_identifier_readback()
            .map_err(|reason| release_readback_error(reason, "target identifier partial"))?,
        sources.target_identifier_partial_bytes,
    )
    .map_err(|reason| release_readback_error(reason, "target identifier partial"))?;
    authenticate_exact_stream(
        output_bundle
            .open_target_order_readback()
            .map_err(|reason| release_readback_error(reason, "target order partial"))?,
        sources.target_order_partial_bytes,
    )
    .map_err(|reason| release_readback_error(reason, "target order partial"))?;
    if verified_proof_stream_domain != CanonicalStreamDomain::MaliciousTargetShareProof
        || verified_proof_stream_descriptor != output_bundle.malicious_share_proof_descriptor()
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "common proof stream does not match the state-certified target-share proof",
        ));
    }

    let participant_material = setup_authority
        .participant_release_material(participant_binding.subject_participant_id)
        .ok_or_else(|| {
            invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "target release subject has no accepted setup material",
            )
        })?;
    if participant_material.participant_identity() != participant_binding.subject_participant_id {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "accepted setup participant identity does not match the release subject",
        ));
    }
    let accepted_roots_by_limb =
        participant_material.selected_target_aggregate_threshold_roots()?;

    let roster_position = usize::from(participant_material.roster_position());
    let partial_decryption = KllpsPairedPartialDecryptionStreams::decode_partial(
        binding.clone(),
        roster_position,
        sources.target_identifier_partial_bytes,
        sources.target_order_partial_bytes,
    )?;

    let canonical_statement = canonical_selected_target_share_statement(
        setup_authority.protocol_version(),
        binding.suite_id,
        binding.ceremony_context_hash,
        binding.action_context_hash,
        binding.roster_hash,
        binding.verified_setup_source_hash,
        binding.finality_hash,
        participant_binding.reservation_intent_object_hash,
        participant_binding.subject_participant_id,
        participant_material.roster_position(),
        &accepted_roots_by_limb,
        output_bundle.target_identifier_descriptor(),
        output_bundle.target_order_descriptor(),
    )
    .map_err(|error| {
        invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("verified target-share statement cannot be encoded: {error:?}"),
        )
    })?;
    let expected_statement_hash = verified_application_statement_hash(
        setup_authority.protocol_version(),
        binding.suite_id,
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        &canonical_statement,
    );
    if verified_target_release_proof.application_statement_hash() != expected_statement_hash {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "common proof does not bind the verifier-derived target-share statement",
        ));
    }

    VerifiedKllpsPairedShare::from_common_proof_verifier(sources.target_pair, partial_decryption)
}

fn release_readback_error(reason: RefusalReason, stream_name: &str) -> CanonicalError {
    let code = match reason {
        RefusalReason::WrongTypeOrLength | RefusalReason::OutsideSupportedProfile => {
            CanonicalErrorCode::MalformedLength
        }
        RefusalReason::UnsupportedVersionOrSuite => CanonicalErrorCode::UnsupportedObjectVersion,
        RefusalReason::MalformedEncoding => CanonicalErrorCode::MalformedMagic,
        RefusalReason::WrongContext
        | RefusalReason::WrongHashOrRoot
        | RefusalReason::InvalidSignature
        | RefusalReason::DuplicateIdentity
        | RefusalReason::Equivocation
        | RefusalReason::MissingPrerequisite
        | RefusalReason::InvalidProof
        | RefusalReason::InvalidArithmeticRelation
        | RefusalReason::ConsumedState => CanonicalErrorCode::ComponentMismatch,
    };
    invalid_release(
        code,
        format!("authenticated {stream_name} stream readback refused: {reason:?}"),
    )
}

impl VerifiedKllpsPairedShare {
    /// Constructs the arithmetic capability only after schema `0x1621`, the
    /// accepted VSS material roots, both role equations, and the common proof
    /// have been verified by the caller.
    fn from_common_proof_verifier(
        target_pair: &KllpsTargetPair,
        partial_decryption: KllpsPairedPartialDecryption,
    ) -> CanonicalResult<Self> {
        if partial_decryption.binding != target_pair.binding {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "KLLPS paired share is bound to another release context",
            ));
        }
        validate_roster_position(partial_decryption.roster_position)?;
        validate_partial_limb_set(
            &partial_decryption.target_identifier_by_limb,
            target_pair.level(),
        )?;
        validate_partial_limb_set(
            &partial_decryption.target_order_by_limb,
            target_pair.level(),
        )?;

        Ok(Self { partial_decryption })
    }

    pub(crate) fn roster_position(&self) -> usize {
        self.partial_decryption.roster_position
    }

    #[cfg(test)]
    pub(crate) fn role_partials_for_tests(&self) -> [&[Vec<u64>]; 2] {
        [
            &self.partial_decryption.target_identifier_by_limb,
            &self.partial_decryption.target_order_by_limb,
        ]
    }
}

#[cfg(test)]
pub(crate) fn generate_verified_factor_four_paired_share_for_tests<ThresholdShareLimb>(
    target_pair: &KllpsTargetPair,
    roster_position: usize,
    threshold_share_by_limb: &[ThresholdShareLimb],
    target_identifier_flooding_error: &[BigInt],
    target_order_flooding_error: &[BigInt],
    flooding_coefficient_bound: &BigUint,
) -> CanonicalResult<VerifiedKllpsPairedShare>
where
    ThresholdShareLimb: AsRef<[u64]>,
{
    let partial_decryption = generate_factor_four_paired_partial_decryption(
        target_pair,
        roster_position,
        threshold_share_by_limb,
        target_identifier_flooding_error,
        target_order_flooding_error,
        flooding_coefficient_bound,
    )?;
    VerifiedKllpsPairedShare::from_common_proof_verifier(target_pair, partial_decryption)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReconstructedKllpsTargetPair {
    target_identifier_coefficients: Vec<u64>,
    target_order_coefficients: Vec<u64>,
}

impl ReconstructedKllpsTargetPair {
    #[cfg(test)]
    pub(crate) fn decode_scalar_lanes(&self) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
        Ok((
            decode_plaintext_coefficients_to_scalar_lanes(&self.target_identifier_coefficients)?,
            decode_plaintext_coefficients_to_scalar_lanes(&self.target_order_coefficients)?,
        ))
    }

    fn decode_ordered_option_identifiers(
        &self,
        top_count: u16,
        option_count: u16,
    ) -> CanonicalResult<Vec<u32>> {
        let target_identifier_slots =
            decode_plaintext_coefficients_to_scalar_lanes(&self.target_identifier_coefficients)?;
        let target_order_slots =
            decode_plaintext_coefficients_to_scalar_lanes(&self.target_order_coefficients)?;
        canonical_ordered_option_identifiers(
            &target_identifier_slots,
            &target_order_slots,
            usize::from(top_count),
            usize::from(option_count),
        )
    }
}

fn canonical_ordered_option_identifiers(
    target_identifier_slots: &[u64],
    target_order_slots: &[u64],
    top_count: usize,
    option_count: usize,
) -> CanonicalResult<Vec<u32>> {
    if top_count == 0 || top_count > option_count {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "decoded KLLPS target top count is outside the action profile",
        ));
    }
    if target_identifier_slots.len() != target_order_slots.len()
        || target_identifier_slots.len() < option_count
    {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "decoded KLLPS target roles do not cover one common logical-slot layout",
        ));
    }

    let mut ordered_option_identifiers = vec![0_u32; top_count];
    let mut selected_option_count = 0_usize;
    for option_index in 0..option_count {
        let target_identifier = target_identifier_slots[option_index];
        let target_order = target_order_slots[option_index];
        if (target_identifier == 0) != (target_order == 0) {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "decoded KLLPS target roles select different option support",
            ));
        }
        if target_identifier == 0 {
            continue;
        }

        let expected_identifier = u64::try_from(option_index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::MalformedLength,
                    "decoded KLLPS target option identifier overflows",
                )
            })?;
        if target_identifier != expected_identifier {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "decoded KLLPS target identifier is outside its canonical option slot",
            ));
        }
        let target_order_index = usize::try_from(target_order)
            .ok()
            .and_then(|order| order.checked_sub(1))
            .filter(|order_index| *order_index < top_count)
            .ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "decoded KLLPS target order is outside the action-selected range",
                )
            })?;
        let canonical_identifier = u32::try_from(target_identifier).map_err(|_| {
            invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "decoded KLLPS target identifier does not fit the canonical result",
            )
        })?;
        if ordered_option_identifiers[target_order_index] != 0 {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "decoded KLLPS target repeats an action-selected order",
            ));
        }
        ordered_option_identifiers[target_order_index] = canonical_identifier;
        selected_option_count = selected_option_count.checked_add(1).ok_or_else(|| {
            invalid_release(
                CanonicalErrorCode::MalformedLength,
                "decoded KLLPS target selected-option count overflows",
            )
        })?;
    }

    if target_identifier_slots[option_count..]
        .iter()
        .chain(&target_order_slots[option_count..])
        .any(|slot| *slot != 0)
    {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "decoded KLLPS target has a nonzero reserved slot",
        ));
    }
    if selected_option_count != top_count || ordered_option_identifiers.contains(&0) {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "decoded KLLPS target does not contain exactly the action-selected rank permutation",
        ));
    }

    Ok(ordered_option_identifiers)
}

pub(crate) fn generate_authorized_factor_four_paired_partial_decryption(
    selected_suite: &SelectedSuiteCapability,
    accepted_setup_authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
    action_private_randomness: &ActionPrivateRandomness,
    target_pair: &KllpsTargetPair,
    application_slot: ProofApplicationSlot,
) -> CanonicalResult<AuthorizedKllpsPairedPartialDecryption> {
    with_verified_participant_target_release_source(
        accepted_setup_authority_handle,
        target_pair.participant_binding().subject_participant_id,
        |accepted_setup_authority, target_release_source| {
            let threshold_share_by_limb = target_release_source
                .ordered_limbs()
                .iter()
                .map(|limb| limb.threshold_share())
                .collect::<Vec<_>>();
            generate_authorized_factor_four_paired_partial_decryption_from_sources(
                selected_suite,
                accepted_setup_authority,
                action_private_randomness,
                target_pair,
                application_slot,
                &threshold_share_by_limb,
            )
        },
    )
}

fn generate_authorized_factor_four_paired_partial_decryption_from_sources<ThresholdShareLimb>(
    selected_suite: &SelectedSuiteCapability,
    accepted_setup_authority: &VerifiedAcceptedSetupAuthority,
    action_private_randomness: &ActionPrivateRandomness,
    target_pair: &KllpsTargetPair,
    application_slot: ProofApplicationSlot,
    threshold_share_by_limb: &[ThresholdShareLimb],
) -> CanonicalResult<AuthorizedKllpsPairedPartialDecryption>
where
    ThresholdShareLimb: AsRef<[u64]>,
{
    let binding = target_pair.binding();
    let participant_binding = target_pair.participant_binding();
    let derivation_input = action_private_randomness.derivation_input();
    let participant_material = accepted_setup_authority
        .participant_release_material(participant_binding.subject_participant_id)
        .ok_or_else(|| {
            invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "accepted setup has no target-release material for the reserved participant",
            )
        })?;
    let roster_position = usize::from(participant_material.roster_position());
    if selected_suite.protocol_version() != FOUNDATION_PROFILE.protocol_version
        || selected_suite.suite_identifier() != binding.suite_id
        || selected_suite.ordered_data_primes() != DATA_PRIMES
        || usize::try_from(selected_suite.polynomial_degree()).ok() != Some(POLYNOMIAL_DEGREE)
        || accepted_setup_authority.protocol_version() != selected_suite.protocol_version()
        || accepted_setup_authority.suite_identifier() != binding.suite_id
        || accepted_setup_authority.ceremony_context_hash() != binding.ceremony_context_hash
        || accepted_setup_authority.action_context_hash() != binding.action_context_hash
        || accepted_setup_authority.roster_hash() != binding.roster_hash
        || accepted_setup_authority.exact_verified_setup_source_hash()
            != binding.verified_setup_source_hash
        || accepted_setup_authority.ring_degree() != POLYNOMIAL_DEGREE
        || accepted_setup_authority.ordered_data_moduli() != DATA_PRIMES
        || participant_material.participant_identity() != participant_binding.subject_participant_id
        || derivation_input.suite_identifier().into_bytes() != binding.suite_id
        || derivation_input.ceremony_context_hash().into_bytes() != binding.ceremony_context_hash
        || derivation_input.action_context_hash().into_bytes() != binding.action_context_hash
        || derivation_input.participant_identity().into_bytes()
            != participant_binding.subject_participant_id
        || application_slot.suite_identifier().into_bytes() != binding.suite_id
        || application_slot.ceremony_context_hash().into_bytes() != binding.ceremony_context_hash
        || application_slot.action_context_hash().into_bytes() != binding.action_context_hash
        || application_slot.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER
        || application_slot.roster_position() != Some(participant_material.roster_position())
        || application_slot.schedule_position().is_some()
        || application_slot.producer_sequence().is_some()
        || target_pair.level() != CANONICAL_TARGET_CIPHERTEXT_LEVEL
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "target release authorities do not agree on the selected participant and action",
        ));
    }
    validate_threshold_share(threshold_share_by_limb, target_pair.level())?;
    let accepted_roots_by_limb =
        participant_material.selected_target_aggregate_threshold_roots()?;

    let flooding_coefficient_bound = selected_factor_four_flooding_bound()?;
    let attempt_identifier = action_private_randomness
        .target_release_attempt_identifier(application_slot)
        .map_err(private_randomness_error)?;
    let flooding_context_hash = target_flooding_context_hash(
        selected_suite,
        accepted_setup_authority,
        target_pair,
        application_slot,
        &accepted_roots_by_limb,
        &flooding_coefficient_bound,
    )?;
    let maximum_candidate_draws =
        selected_suite.maximum_private_sampler_candidate_draws_per_output();
    let mut target_identifier_stream = action_private_randomness
        .begin_stream(
            PrivateRandomnessDomain::target_flooding(1).map_err(private_randomness_error)?,
            flooding_context_hash,
            attempt_identifier,
        )
        .map_err(private_randomness_error)?;
    let mut target_order_stream = action_private_randomness
        .begin_stream(
            PrivateRandomnessDomain::target_flooding(2).map_err(private_randomness_error)?,
            flooding_context_hash,
            attempt_identifier,
        )
        .map_err(private_randomness_error)?;
    let target_identifier_flooding_polynomial = sample_uniform_flooding_polynomial(
        &mut target_identifier_stream,
        &flooding_coefficient_bound,
        maximum_candidate_draws,
    )?;
    let target_order_flooding_polynomial = sample_uniform_flooding_polynomial(
        &mut target_order_stream,
        &flooding_coefficient_bound,
        maximum_candidate_draws,
    )?;
    let flooding_cursors_by_role = [
        target_identifier_stream.cursor(),
        target_order_stream.cursor(),
    ];
    let partial_decryption = target_identifier_flooding_polynomial.with_bigints_canonical(
        |target_identifier_flooding_error| {
            target_order_flooding_polynomial.with_bigints_canonical(|target_order_flooding_error| {
                generate_factor_four_paired_partial_decryption(
                    target_pair,
                    roster_position,
                    threshold_share_by_limb,
                    target_identifier_flooding_error,
                    target_order_flooding_error,
                    &flooding_coefficient_bound,
                )
            })
        },
    )?;

    Ok(AuthorizedKllpsPairedPartialDecryption {
        application_slot,
        participant_binding: participant_binding.clone(),
        partial_decryption,
        flooding_polynomials_by_role: [
            target_identifier_flooding_polynomial,
            target_order_flooding_polynomial,
        ],
        flooding_cursors_by_role,
    })
}

fn generate_factor_four_paired_partial_decryption<ThresholdShareLimb>(
    target_pair: &KllpsTargetPair,
    roster_position: usize,
    threshold_share_by_limb: &[ThresholdShareLimb],
    target_identifier_flooding_error: &[BigInt],
    target_order_flooding_error: &[BigInt],
    flooding_coefficient_bound: &BigUint,
) -> CanonicalResult<KllpsPairedPartialDecryption>
where
    ThresholdShareLimb: AsRef<[u64]>,
{
    validate_roster_position(roster_position)?;
    validate_threshold_share(threshold_share_by_limb, target_pair.target_identifier.level)?;
    validate_flooding_error(target_identifier_flooding_error, flooding_coefficient_bound)?;
    validate_flooding_error(target_order_flooding_error, flooding_coefficient_bound)?;

    let active_primes = &DATA_PRIMES[..=target_pair.target_identifier.level];
    let mut target_identifier_by_limb = Vec::with_capacity(active_primes.len());
    let mut target_order_by_limb = Vec::with_capacity(active_primes.len());
    for (limb_index, modulus) in active_primes.iter().copied().enumerate() {
        let threshold_share_transform =
            forward_negacyclic_ntt(threshold_share_by_limb[limb_index].as_ref(), modulus)?;
        target_identifier_by_limb.push(factor_four_partial_limb(
            &target_pair.target_identifier.components[1][limb_index],
            &threshold_share_transform,
            target_identifier_flooding_error,
            modulus,
        )?);
        target_order_by_limb.push(factor_four_partial_limb(
            &target_pair.target_order.components[1][limb_index],
            &threshold_share_transform,
            target_order_flooding_error,
            modulus,
        )?);
    }

    Ok(KllpsPairedPartialDecryption {
        binding: target_pair.binding.clone(),
        roster_position,
        target_identifier_by_limb,
        target_order_by_limb,
    })
}

fn target_flooding_context_hash(
    selected_suite: &SelectedSuiteCapability,
    accepted_setup_authority: &VerifiedAcceptedSetupAuthority,
    target_pair: &KllpsTargetPair,
    application_slot: ProofApplicationSlot,
    ordered_selected_target_aggregate_threshold_roots: &[[u8; 64]],
    flooding_coefficient_bound: &BigUint,
) -> CanonicalResult<Hash512> {
    let binding = target_pair.binding();
    let participant_binding = target_pair.participant_binding();
    let application_slot_hash = application_slot
        .hash()
        .map_err(private_randomness_error)?
        .into_bytes();
    let protocol_version = selected_suite.protocol_version().to_le_bytes();
    let target_level = u64::try_from(target_pair.level())
        .map_err(|_| {
            invalid_release(
                CanonicalErrorCode::MalformedLength,
                "target level overflows",
            )
        })?
        .to_le_bytes();
    let decrypt_scaling = target_pair.target_identifier.decrypt_scaling.to_le_bytes();
    let root_count = u64::try_from(ordered_selected_target_aggregate_threshold_roots.len())
        .map_err(|_| {
            invalid_release(
                CanonicalErrorCode::MalformedLength,
                "aggregate threshold root count overflows",
            )
        })?
        .to_le_bytes();
    let ordered_roots = ordered_selected_target_aggregate_threshold_roots
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let flooding_bound_bytes = flooding_coefficient_bound.to_bytes_le();
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        TARGET_FLOODING_CONTEXT_HASH_DOMAIN,
        &[
            &protocol_version,
            &binding.suite_id,
            &binding.ceremony_context_hash,
            &binding.action_context_hash,
            &binding.roster_hash,
            &binding.verified_setup_source_hash,
            &binding.finality_hash,
            &participant_binding.reservation_intent_object_hash,
            &participant_binding.subject_participant_id,
            &participant_binding.state_key,
            &binding.authorization_hash,
            &binding.target_identifier_full_digest,
            &binding.target_order_full_digest,
            &application_slot_hash,
            &accepted_setup_authority.collective_public_key_root(),
            &target_level,
            &decrypt_scaling,
            &root_count,
            &ordered_roots,
            &flooding_bound_bytes,
        ],
    )))
}

fn sample_uniform_flooding_polynomial(
    stream: &mut crate::foundation::PrivateRandomnessStream<'_>,
    coefficient_bound: &BigUint,
    maximum_candidate_draws_per_coefficient: u32,
) -> CanonicalResult<ZeroizingSignedLimbPolynomial> {
    if coefficient_bound.is_zero() || maximum_candidate_draws_per_coefficient == 0 {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "target flooding sampler requires positive suite bounds",
        ));
    }
    let sample_range = coefficient_bound * 2_u8 + BigUint::from(1_u8);
    let sample_bit_length = usize::try_from(sample_range.bits()).map_err(|_| {
        invalid_release(
            CanonicalErrorCode::MalformedLength,
            "target flooding sampler width does not fit this runtime",
        )
    })?;
    let sample_byte_length = sample_bit_length.checked_add(7).ok_or_else(|| {
        invalid_release(
            CanonicalErrorCode::MalformedLength,
            "target flooding sampler byte width overflows",
        )
    })? / 8;
    let unused_high_bit_count = sample_byte_length * 8 - sample_bit_length;
    let high_byte_mask = u8::MAX >> unused_high_bit_count;
    let mut candidate_bytes = Zeroizing::new(vec![0_u8; sample_byte_length]);
    let mut coefficients =
        ZeroizingSignedLimbPolynomial::new(POLYNOMIAL_DEGREE, coefficient_bound)?;
    for _ in 0..POLYNOMIAL_DEGREE {
        let mut sampled_coefficient = None;
        for _ in 0..maximum_candidate_draws_per_coefficient {
            stream
                .fill_bytes(&mut candidate_bytes)
                .map_err(private_randomness_error)?;
            let last_byte = candidate_bytes.last_mut().ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::MalformedLength,
                    "target flooding sampler has no candidate bytes",
                )
            })?;
            *last_byte &= high_byte_mask;
            let candidate = BigUint::from_bytes_le(&candidate_bytes);
            if candidate < sample_range {
                sampled_coefficient = Some(candidate);
                break;
            }
        }
        coefficients.push_centered_sample(
            sampled_coefficient.ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "target flooding sampler exhausted the suite candidate-draw bound",
                )
            })?,
            coefficient_bound,
        )?;
    }
    coefficients.finish()
}

fn private_randomness_error(error: crate::foundation::FoundationSchemaError) -> CanonicalError {
    invalid_release(
        CanonicalErrorCode::InvalidProtocolObject,
        format!("target release private randomness refused: {error:?}"),
    )
}

/// The evaluator decrypts with the positive-message BGV convention
/// `c0 + c1 * s = m + p * e`. For every selected `q = 1 mod p`, the positive
/// BFV message scale is `(q - 1) / p = -p^-1 mod q`; using the opposite sign
/// would make the final full-modulus rounding recover `-m`.
fn positive_bfv_message_conversion_scale(modulus: u64) -> CanonicalResult<u64> {
    let inverse_plaintext = inverse_mod(PLAINTEXT_MODULUS % modulus, modulus)?;
    Ok(sub_mod_fast(0, inverse_plaintext, modulus))
}

fn factor_four_partial_limb(
    bgv_component_one: &[u64],
    threshold_share_transform: &[u64],
    flooding_error: &[BigInt],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let converted_scale = positive_bfv_message_conversion_scale(modulus)?;
    let factor_four_converted_scale = mul_mod_fast(
        KLLPS_DENOMINATOR_CLEARING_FACTOR % modulus,
        converted_scale,
        modulus,
    );
    let mut product = forward_negacyclic_ntt(bgv_component_one, modulus)?;
    if product.len() != threshold_share_transform.len() {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS target and threshold-share transforms have different lengths",
        ));
    }
    for (product_coefficient, share_coefficient) in
        product.iter_mut().zip(threshold_share_transform)
    {
        *product_coefficient = mul_mod_fast(*product_coefficient, *share_coefficient, modulus);
    }
    inverse_negacyclic_ntt_in_place(&mut product, modulus)?;
    for (product_coefficient, flooding_coefficient) in product.iter_mut().zip(flooding_error) {
        let scaled_product =
            mul_mod_fast(*product_coefficient, factor_four_converted_scale, modulus);
        let scaled_error = mul_mod_fast(
            bigint_residue(flooding_coefficient, modulus)?,
            KLLPS_DENOMINATOR_CLEARING_FACTOR,
            modulus,
        );
        *product_coefficient = add_mod_fast(scaled_product, scaled_error, modulus);
    }

    Ok(product)
}

fn converted_target_component(
    bgv_component_one: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if bgv_component_one.len() != POLYNOMIAL_DEGREE
        || bgv_component_one
            .iter()
            .any(|coefficient| *coefficient >= modulus)
    {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS target component is not a canonical selected-basis polynomial",
        ));
    }
    let converted_scale = positive_bfv_message_conversion_scale(modulus)?;
    Ok(bgv_component_one
        .iter()
        .copied()
        .map(|coefficient| mul_mod_fast(coefficient, converted_scale, modulus))
        .collect())
}

#[cfg(test)]
fn reconstruct_factor_four_target_pair(
    target_pair: &KllpsTargetPair,
    verified_shares: &[&VerifiedKllpsPairedShare],
) -> CanonicalResult<ReconstructedKllpsTargetPair> {
    reconstruct_factor_four_target_pair_from_sources(
        target_pair.binding(),
        &target_pair.target_identifier,
        &target_pair.target_order,
        verified_shares,
    )
}

#[cfg(test)]
pub(crate) fn reconstruct_factor_four_target_scalar_lanes_for_tests(
    target_pair: &KllpsTargetPair,
    verified_shares: &[&VerifiedKllpsPairedShare],
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    reconstruct_factor_four_target_pair(target_pair, verified_shares)?.decode_scalar_lanes()
}

pub(crate) fn reconstruct_factor_four_finalized_target_result(
    target_pair: &KllpsReconstructionTargetPair,
    verified_shares: &[&VerifiedKllpsPairedShare],
) -> CanonicalResult<Vec<u32>> {
    reconstruct_factor_four_target_pair_from_sources(
        &target_pair.binding,
        &target_pair.target_identifier,
        &target_pair.target_order,
        verified_shares,
    )
    .and_then(|reconstructed| {
        reconstructed
            .decode_ordered_option_identifiers(target_pair.top_count, target_pair.option_count)
    })
}

fn reconstruct_factor_four_target_pair_from_sources(
    release_binding: &KllpsReleaseBinding,
    target_identifier: &Ciphertext,
    target_order: &Ciphertext,
    verified_shares: &[&VerifiedKllpsPairedShare],
) -> CanonicalResult<ReconstructedKllpsTargetPair> {
    if target_identifier.level != target_order.level
        || target_identifier.decrypt_scaling != target_order.decrypt_scaling
    {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "paired KLLPS reconstruction targets do not share one basis and scaling",
        ));
    }
    let selected_shares = select_lowest_roster_positions(release_binding, verified_shares)?;
    let selected_positions = selected_shares
        .iter()
        .map(|share| share.roster_position())
        .collect::<Vec<_>>();
    validate_selected_positions(&selected_positions)?;
    let active_primes = &DATA_PRIMES[..=target_identifier.level];
    let lagrange_coefficients_by_limb = active_primes
        .iter()
        .copied()
        .map(|modulus| {
            (0..KLLPS_RECONSTRUCTION_THRESHOLD)
                .map(|selected_index| {
                    authorized_lagrange_coefficient_at_zero(
                        &selected_positions,
                        selected_index,
                        modulus,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let full_modulus_crt = FullModulusCrt::new(active_primes)?;
    let factor_four_inverse = inverse_mod(
        KLLPS_DENOMINATOR_CLEARING_FACTOR % PLAINTEXT_MODULUS,
        PLAINTEXT_MODULUS,
    )?;
    let target_identifier_coefficients = reconstruct_role(
        target_identifier,
        &selected_shares,
        active_primes,
        &lagrange_coefficients_by_limb,
        &full_modulus_crt,
        factor_four_inverse,
        |share| &share.partial_decryption.target_identifier_by_limb,
    )?;
    let target_order_coefficients = reconstruct_role(
        target_order,
        &selected_shares,
        active_primes,
        &lagrange_coefficients_by_limb,
        &full_modulus_crt,
        factor_four_inverse,
        |share| &share.partial_decryption.target_order_by_limb,
    )?;

    Ok(ReconstructedKllpsTargetPair {
        target_identifier_coefficients,
        target_order_coefficients,
    })
}

fn select_lowest_roster_positions<'a>(
    release_binding: &KllpsReleaseBinding,
    verified_shares: &'a [&'a VerifiedKllpsPairedShare],
) -> CanonicalResult<Vec<&'a VerifiedKllpsPairedShare>> {
    let mut by_roster_position = BTreeMap::new();
    for &share in verified_shares {
        let roster_position = share.roster_position();
        validate_roster_position(roster_position)?;
        if share.partial_decryption.binding != *release_binding {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "KLLPS reconstruction received shares from different release contexts",
            ));
        }
        if by_roster_position.insert(roster_position, share).is_some() {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "KLLPS reconstruction received a repeated roster position",
            ));
        }
    }
    if by_roster_position.len() < KLLPS_RECONSTRUCTION_THRESHOLD {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS reconstruction requires at least four distinct paired shares",
        ));
    }

    Ok(by_roster_position
        .into_values()
        .take(KLLPS_RECONSTRUCTION_THRESHOLD)
        .collect())
}

fn reconstruct_role(
    ciphertext: &Ciphertext,
    selected_shares: &[&VerifiedKllpsPairedShare],
    active_primes: &[u64],
    lagrange_coefficients_by_limb: &[Vec<SubringPolynomial>],
    full_modulus_crt: &FullModulusCrt,
    factor_four_inverse: u64,
    role_partials: impl Fn(&VerifiedKllpsPairedShare) -> &[Vec<u64>],
) -> CanonicalResult<Vec<u64>> {
    if active_primes.len() != lagrange_coefficients_by_limb.len() {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS interpolation coefficient count does not match the target basis",
        ));
    }
    let mut accumulator_by_limb = Vec::with_capacity(active_primes.len());
    for (limb_index, modulus) in active_primes.iter().copied().enumerate() {
        let converted_scale = positive_bfv_message_conversion_scale(modulus)?;
        let scaled_converted_component_zero =
            mul_mod_fast(KLLPS_DENOMINATOR_CLEARING_FACTOR, converted_scale, modulus);
        let mut accumulator = ciphertext.components[0][limb_index]
            .iter()
            .map(|coefficient| mul_mod_fast(*coefficient, scaled_converted_component_zero, modulus))
            .collect::<Vec<_>>();
        if lagrange_coefficients_by_limb[limb_index].len() != selected_shares.len() {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "KLLPS interpolation coefficient count does not match the selected shares",
            ));
        }
        for (share, lagrange_coefficient) in selected_shares
            .iter()
            .zip(&lagrange_coefficients_by_limb[limb_index])
        {
            accumulate_full_ring_times_subring(
                &mut accumulator,
                &role_partials(share)[limb_index],
                lagrange_coefficient,
                modulus,
            )?;
        }
        accumulator_by_limb.push(accumulator);
    }

    full_modulus_round_and_decode(
        &accumulator_by_limb,
        full_modulus_crt,
        factor_four_inverse,
        ciphertext.decrypt_scaling,
    )
}

fn full_modulus_round_and_decode(
    accumulator_by_limb: &[Vec<u64>],
    full_modulus_crt: &FullModulusCrt,
    factor_four_inverse: u64,
    target_plaintext_multiplier: u64,
) -> CanonicalResult<Vec<u64>> {
    if accumulator_by_limb.len() != full_modulus_crt.factors.len()
        || accumulator_by_limb
            .iter()
            .any(|limb| limb.len() != POLYNOMIAL_DEGREE)
    {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS accumulator does not match the target basis",
        ));
    }
    if target_plaintext_multiplier == 0 || target_plaintext_multiplier >= PLAINTEXT_MODULUS {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS target plaintext multiplier must be a nonzero canonical residue",
        ));
    }
    let mut decoded = Vec::with_capacity(POLYNOMIAL_DEGREE);
    let mut coefficient_residues = vec![0_u64; full_modulus_crt.factors.len()];
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        for (limb_index, limb) in accumulator_by_limb.iter().enumerate() {
            coefficient_residues[limb_index] = limb[coefficient_index];
        }
        let centered = full_modulus_crt.centered_lift(&coefficient_residues)?;
        let rounded = round_scaled_coefficient(&centered, &full_modulus_crt.modulus);
        let raw_plaintext = bigint_residue(&rounded, PLAINTEXT_MODULUS)?;
        let unscaled = mul_mod_fast(raw_plaintext, factor_four_inverse, PLAINTEXT_MODULUS);
        decoded.push(mul_mod_fast(
            unscaled,
            target_plaintext_multiplier,
            PLAINTEXT_MODULUS,
        ));
    }

    Ok(decoded)
}

fn round_scaled_coefficient(centered_coefficient: &BigInt, modulus: &BigInt) -> BigInt {
    let magnitude = centered_coefficient.abs() * BigInt::from(PLAINTEXT_MODULUS);
    let rounded_magnitude = (magnitude + modulus / BigInt::from(2_u8)) / modulus;
    if centered_coefficient.sign() == Sign::Minus {
        -rounded_magnitude
    } else {
        rounded_magnitude
    }
}

struct FullModulusCrt {
    modulus: BigInt,
    half_modulus: BigInt,
    factors: Vec<BigInt>,
}

impl FullModulusCrt {
    fn new(primes: &[u64]) -> CanonicalResult<Self> {
        if primes.is_empty() {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "KLLPS reconstruction requires a nonempty target basis",
            ));
        }
        let modulus = primes
            .iter()
            .map(|prime| BigInt::from(*prime))
            .product::<BigInt>();
        let mut factors = Vec::with_capacity(primes.len());
        for prime in primes {
            let prime_bigint = BigInt::from(*prime);
            let cofactor = &modulus / &prime_bigint;
            let cofactor_residue = (&cofactor % &prime_bigint).to_u64().ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "KLLPS CRT cofactor residue does not fit its target prime",
                )
            })?;
            let inverse = inverse_mod(cofactor_residue, *prime)?;
            factors.push(cofactor * BigInt::from(inverse));
        }
        let half_modulus = &modulus / BigInt::from(2_u8);

        Ok(Self {
            modulus,
            half_modulus,
            factors,
        })
    }

    fn centered_lift(&self, residues: &[u64]) -> CanonicalResult<BigInt> {
        if residues.len() != self.factors.len() {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "KLLPS CRT residue count does not match the target basis",
            ));
        }
        let mut value = BigInt::zero();
        for (residue, factor) in residues.iter().zip(&self.factors) {
            value += BigInt::from(*residue) * factor;
        }
        value %= &self.modulus;
        if value > self.half_modulus {
            value -= &self.modulus;
        }

        Ok(value)
    }
}

pub(crate) fn ensure_factor_four_parameter_conditions(
    target_level: usize,
    evaluation_error_bound: &BigUint,
    flooding_coefficient_bound: &BigUint,
) -> CanonicalResult<()> {
    ensure_factor_four_parameter_conditions_with_data_primes(
        target_level,
        evaluation_error_bound,
        flooding_coefficient_bound,
        &DATA_PRIMES,
    )
}

pub(crate) fn ensure_factor_four_parameter_conditions_with_data_primes(
    target_level: usize,
    evaluation_error_bound: &BigUint,
    flooding_coefficient_bound: &BigUint,
    data_primes: &[u64],
) -> CanonicalResult<()> {
    if target_level >= data_primes.len() {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "KLLPS target level is outside the selected data basis",
        ));
    }
    if evaluation_error_bound.is_zero() || flooding_coefficient_bound.is_zero() {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS evaluator and flooding coefficient bounds must be positive",
        ));
    }
    let active_primes = &data_primes[..=target_level];
    if inverse_mod(KLLPS_DENOMINATOR_CLEARING_FACTOR, PLAINTEXT_MODULUS).is_err()
        || active_primes
            .iter()
            .any(|prime| inverse_mod(KLLPS_DENOMINATOR_CLEARING_FACTOR, *prime).is_err())
    {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS factor-four constants are not invertible in the target rings",
        ));
    }
    if active_primes.iter().any(|prime| {
        prime % PLAINTEXT_MODULUS != 1 || (prime - 1) % (2 * POLYNOMIAL_DEGREE as u64) != 0
    }) {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS target basis violates an exact conversion or ring congruence",
        ));
    }
    let target_modulus = active_primes
        .iter()
        .map(|prime| BigUint::from(*prime))
        .product::<BigUint>();
    if flooding_coefficient_bound >= &target_modulus {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS flooding coefficient bound must be smaller than the target modulus",
        ));
    }

    let scaled_c2_left =
        factor_four_scaled_c2_left(evaluation_error_bound, flooding_coefficient_bound);
    if scaled_c2_left >= (&target_modulus << 1_usize) {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS factor-four parameters do not satisfy the exact C2 bound",
        ));
    }

    let required_flooding_bound = factor_four_required_flooding_bound(evaluation_error_bound)?;
    if flooding_coefficient_bound < &required_flooding_bound {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS factor-four parameters do not satisfy the exact C4 bound",
        ));
    }

    Ok(())
}

/// Returns four times the plaintext modulus times the operative C2 left side.
/// `evaluation_error_bound` bounds the unscaled error in the converted
/// ciphertext equation. Final decryption contains `Cdec * error`, so the
/// factor-four scalar has coefficient norm four. The exact inequality is
/// `||Cdec||_1 * B_eval + p/4 * (||Cdec||_1 + 1)
/// + t * B_sm * B2 < q/(2p)`.
fn factor_four_scaled_c2_left(
    evaluation_error_bound: &BigUint,
    flooding_coefficient_bound: &BigUint,
) -> BigUint {
    let plaintext_modulus = BigUint::from(PLAINTEXT_MODULUS);
    let clearing_coefficient_norm = BigUint::from(KLLPS_DENOMINATOR_CLEARING_FACTOR);
    let scaled_evaluation_term =
        evaluation_error_bound * BigUint::from(4_u8) * &clearing_coefficient_norm;
    let scaled_plaintext_rounding_term =
        &plaintext_modulus * (&clearing_coefficient_norm + BigUint::from(1_u8));
    let scaled_flooding_term = flooding_coefficient_bound
        * BigUint::from(
            4_u64 * KLLPS_RECONSTRUCTION_THRESHOLD as u64 * MAXIMUM_AUTHORIZED_COEFFICIENT_NORM,
        );
    plaintext_modulus
        * (scaled_evaluation_term + scaled_plaintext_rounding_term + scaled_flooding_term)
}

/// Derives the one flooding bound admitted by the selected evaluator and
/// target basis. Generation and proof planning call this same recurrence, so
/// transported accounting or a caller-selected support cannot alter C2 or C4.
pub(crate) fn selected_factor_four_flooding_bound() -> CanonicalResult<BigUint> {
    let target_bounds = direct_ballot_target_noise_bounds(
        u64::from(FOUNDATION_PROFILE.participant_count),
        usize::from(FOUNDATION_PROFILE.participant_count),
        usize::from(FOUNDATION_PROFILE.option_count),
        MINIMUM_SCORE,
        MAXIMUM_SCORE,
    )
    .map_err(|error| {
        invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            format!("selected evaluator noise recurrence refused: {error:?}"),
        )
    })?;
    let evaluation_error_bound = target_bounds
        .iter()
        .map(|bound| bound.maximum_error_coefficient_bound())
        .max()
        .cloned()
        .ok_or_else(|| {
            invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "selected evaluator has no target error bound",
            )
        })?;
    let flooding_coefficient_bound = factor_four_required_flooding_bound(&evaluation_error_bound)?;
    let release_trace =
        direct_ballot_target_release_noise_trace(DirectBallotTargetReleaseNoiseInput {
            participant_count: u64::from(FOUNDATION_PROFILE.participant_count),
            ballot_count: usize::from(FOUNDATION_PROFILE.participant_count),
            option_count: usize::from(FOUNDATION_PROFILE.option_count),
            minimum_score: MINIMUM_SCORE,
            maximum_score: MAXIMUM_SCORE,
            denominator_clearing_factor: KLLPS_DENOMINATOR_CLEARING_FACTOR,
            reconstruction_threshold: KLLPS_RECONSTRUCTION_THRESHOLD,
            maximum_authorized_coefficient_norm: MAXIMUM_AUTHORIZED_COEFFICIENT_NORM,
            flooding_coefficient_bound: &flooding_coefficient_bound,
        })?;
    let scaled_c2_left =
        factor_four_scaled_c2_left(&evaluation_error_bound, &flooding_coefficient_bound);
    if release_trace.last().is_none_or(|bound| {
        bound.stage != TargetReleaseNoiseStage::Decode
            || !bound.scaled_no_wrap_margin.is_positive()
            || BigUint::from(PLAINTEXT_MODULUS) * &bound.four_times_reconstruction_error_bound
                != scaled_c2_left
    }) {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "selected evaluator-to-release recurrence has no positive decode margin",
        ));
    }
    ensure_factor_four_parameter_conditions(
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        &evaluation_error_bound,
        &flooding_coefficient_bound,
    )?;
    Ok(flooding_coefficient_bound)
}

pub(crate) fn factor_four_required_flooding_bound(
    evaluation_error_bound: &BigUint,
) -> CanonicalResult<BigUint> {
    let simulation_shift =
        usize::try_from(KLLPS_THRESHOLD_SIMULATION_BIT_LENGTH).map_err(|_| {
            invalid_release(
                CanonicalErrorCode::MalformedLength,
                "KLLPS threshold simulation bit length does not fit this runtime",
            )
        })?;
    Ok((evaluation_error_bound << simulation_shift)
        * BigUint::from(POLYNOMIAL_DEGREE)
        * BigUint::from(MAXIMUM_UNAUTHORIZED_COEFFICIENT_NORM))
}

#[cfg(test)]
pub(crate) fn authorized_scaled_lagrange_coefficient_at_zero(
    selected_positions: &[usize],
    selected_index: usize,
    modulus: u64,
) -> CanonicalResult<SubringPolynomial> {
    let coefficient =
        authorized_lagrange_coefficient_at_zero(selected_positions, selected_index, modulus)?;
    Ok(coefficient.map(|value| mul_mod_fast(value, KLLPS_DENOMINATOR_CLEARING_FACTOR, modulus)))
}

#[cfg(test)]
pub(crate) fn authorized_lagrange_coefficient_at_zero_for_tests(
    selected_positions: &[usize],
    selected_index: usize,
    modulus: u64,
) -> CanonicalResult<[u64; KLLPS_SUBRING_DEGREE]> {
    authorized_lagrange_coefficient_at_zero(selected_positions, selected_index, modulus)
}

fn authorized_lagrange_coefficient_at_zero(
    selected_positions: &[usize],
    selected_index: usize,
    modulus: u64,
) -> CanonicalResult<SubringPolynomial> {
    validate_selected_positions(selected_positions)?;
    if selected_index >= selected_positions.len() {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS selected-share index is outside the reconstruction subset",
        ));
    }
    let selected_point = subring_monomial(selected_positions[selected_index], modulus);
    let mut numerator = subring_one();
    let mut denominator = subring_one();
    for (other_index, other_position) in selected_positions.iter().copied().enumerate() {
        if other_index == selected_index {
            continue;
        }
        let other_point = subring_monomial(other_position, modulus);
        numerator = subring_multiply(&numerator, &subring_negate(&other_point, modulus), modulus);
        denominator = subring_multiply(
            &denominator,
            &subring_subtract(&selected_point, &other_point, modulus),
            modulus,
        );
    }

    solve_subring_quotient(&denominator, &numerator, modulus)
}

#[cfg(test)]
pub(crate) fn unauthorized_zero_lagrange_coefficient(
    corrupted_positions: &[usize],
    absent_position: usize,
    modulus: u64,
) -> CanonicalResult<SubringPolynomial> {
    if corrupted_positions.len() != KLLPS_RECONSTRUCTION_THRESHOLD - 1 {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS maximal unauthorized subset must contain exactly three participants",
        ));
    }
    validate_distinct_roster_positions(corrupted_positions)?;
    validate_roster_position(absent_position)?;
    if corrupted_positions.contains(&absent_position) {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "KLLPS absent participant occurs in the corrupted subset",
        ));
    }
    let destination = subring_monomial(absent_position, modulus);
    let mut numerator = subring_one();
    let mut denominator = subring_one();
    for corrupted_position in corrupted_positions.iter().copied() {
        let corrupted_point = subring_monomial(corrupted_position, modulus);
        numerator = subring_multiply(
            &numerator,
            &subring_subtract(&destination, &corrupted_point, modulus),
            modulus,
        );
        denominator = subring_multiply(
            &denominator,
            &subring_negate(&corrupted_point, modulus),
            modulus,
        );
    }

    solve_subring_quotient(&denominator, &numerator, modulus)
}

fn solve_subring_quotient(
    denominator: &SubringPolynomial,
    numerator: &SubringPolynomial,
    modulus: u64,
) -> CanonicalResult<SubringPolynomial> {
    let mut augmented = [[0_u64; KLLPS_SUBRING_DEGREE + 1]; KLLPS_SUBRING_DEGREE];
    for column_index in 0..KLLPS_SUBRING_DEGREE {
        let basis = subring_monomial(column_index, modulus);
        let product = subring_multiply(denominator, &basis, modulus);
        for row_index in 0..KLLPS_SUBRING_DEGREE {
            augmented[row_index][column_index] = product[row_index];
        }
    }
    for row_index in 0..KLLPS_SUBRING_DEGREE {
        augmented[row_index][KLLPS_SUBRING_DEGREE] = numerator[row_index];
    }

    for pivot_column in 0..KLLPS_SUBRING_DEGREE {
        let pivot_row = (pivot_column..KLLPS_SUBRING_DEGREE)
            .find(|row_index| augmented[*row_index][pivot_column] != 0)
            .ok_or_else(|| {
                invalid_release(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "KLLPS interpolation denominator is not a unit in the selected ring",
                )
            })?;
        augmented.swap(pivot_column, pivot_row);
        let pivot_inverse = inverse_mod(augmented[pivot_column][pivot_column], modulus)?;
        for column_index in pivot_column..=KLLPS_SUBRING_DEGREE {
            augmented[pivot_column][column_index] = mul_mod_fast(
                augmented[pivot_column][column_index],
                pivot_inverse,
                modulus,
            );
        }
        for row_index in 0..KLLPS_SUBRING_DEGREE {
            if row_index == pivot_column {
                continue;
            }
            let elimination_factor = augmented[row_index][pivot_column];
            if elimination_factor == 0 {
                continue;
            }
            for column_index in pivot_column..=KLLPS_SUBRING_DEGREE {
                let subtracted = mul_mod_fast(
                    elimination_factor,
                    augmented[pivot_column][column_index],
                    modulus,
                );
                augmented[row_index][column_index] =
                    sub_mod_fast(augmented[row_index][column_index], subtracted, modulus);
            }
        }
    }

    Ok(std::array::from_fn(|index| {
        augmented[index][KLLPS_SUBRING_DEGREE]
    }))
}

fn accumulate_full_ring_times_subring(
    accumulator: &mut [u64],
    full_ring_polynomial: &[u64],
    subring_polynomial: &SubringPolynomial,
    modulus: u64,
) -> CanonicalResult<()> {
    if accumulator.len() != POLYNOMIAL_DEGREE || full_ring_polynomial.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS partial-decryption polynomial has the wrong ring degree",
        ));
    }
    for (subring_index, subring_coefficient) in subring_polynomial.iter().copied().enumerate() {
        if subring_coefficient == 0 {
            continue;
        }
        let shift = subring_index * KLLPS_POINT_STRIDE;
        let positive_length = POLYNOMIAL_DEGREE - shift;
        for (source_index, full_ring_coefficient) in full_ring_polynomial[..positive_length]
            .iter()
            .copied()
            .enumerate()
        {
            let term = mul_mod_fast(full_ring_coefficient, subring_coefficient, modulus);
            accumulator[source_index + shift] =
                add_mod_fast(accumulator[source_index + shift], term, modulus);
        }
        for (source_index, full_ring_coefficient) in full_ring_polynomial
            .iter()
            .copied()
            .enumerate()
            .skip(positive_length)
        {
            let term = mul_mod_fast(full_ring_coefficient, subring_coefficient, modulus);
            let destination = source_index - positive_length;
            accumulator[destination] = sub_mod_fast(accumulator[destination], term, modulus);
        }
    }

    Ok(())
}

fn subring_one() -> SubringPolynomial {
    let mut one = [0_u64; KLLPS_SUBRING_DEGREE];
    one[0] = 1;
    one
}

fn subring_monomial(exponent: usize, modulus: u64) -> SubringPolynomial {
    let reduced_exponent = exponent % KLLPS_SPACED_POINT_COUNT;
    let mut polynomial = [0_u64; KLLPS_SUBRING_DEGREE];
    if reduced_exponent < KLLPS_SUBRING_DEGREE {
        polynomial[reduced_exponent] = 1;
    } else {
        polynomial[reduced_exponent - KLLPS_SUBRING_DEGREE] = modulus - 1;
    }
    polynomial
}

fn subring_negate(polynomial: &SubringPolynomial, modulus: u64) -> SubringPolynomial {
    polynomial.map(|coefficient| sub_mod_fast(0, coefficient, modulus))
}

fn subring_subtract(
    left: &SubringPolynomial,
    right: &SubringPolynomial,
    modulus: u64,
) -> SubringPolynomial {
    std::array::from_fn(|index| sub_mod_fast(left[index], right[index], modulus))
}

fn subring_multiply(
    left: &SubringPolynomial,
    right: &SubringPolynomial,
    modulus: u64,
) -> SubringPolynomial {
    let mut product = [0_u64; KLLPS_SUBRING_DEGREE];
    for (left_index, left_coefficient) in left.iter().copied().enumerate() {
        for (right_index, right_coefficient) in right.iter().copied().enumerate() {
            let term = mul_mod_fast(left_coefficient, right_coefficient, modulus);
            let output_index = left_index + right_index;
            if output_index < KLLPS_SUBRING_DEGREE {
                product[output_index] = add_mod_fast(product[output_index], term, modulus);
            } else {
                product[output_index - KLLPS_SUBRING_DEGREE] =
                    sub_mod_fast(product[output_index - KLLPS_SUBRING_DEGREE], term, modulus);
            }
        }
    }
    product
}

fn validate_target_ciphertext(ciphertext: &Ciphertext) -> CanonicalResult<()> {
    if ciphertext.level >= DATA_PRIMES.len() || ciphertext.components.len() != 2 {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS target must be a two-component ciphertext on a selected data-basis prefix",
        ));
    }
    if ciphertext.decrypt_scaling == 0 || ciphertext.decrypt_scaling >= PLAINTEXT_MODULUS {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS target plaintext multiplier is not canonical",
        ));
    }
    for component in &ciphertext.components {
        if component.len() != ciphertext.level + 1 {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "KLLPS target component does not cover its complete target basis",
            ));
        }
        for (limb_index, limb) in component.iter().enumerate() {
            let modulus = DATA_PRIMES[limb_index];
            if limb.len() != POLYNOMIAL_DEGREE {
                return Err(invalid_release(
                    CanonicalErrorCode::MalformedLength,
                    "KLLPS target limb has the wrong ring degree",
                ));
            }
            if limb.iter().any(|coefficient| *coefficient >= modulus) {
                return Err(invalid_release(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "KLLPS target limb contains a noncanonical residue",
                ));
            }
        }
    }

    Ok(())
}

fn validate_threshold_share<ThresholdShareLimb>(
    threshold_share_by_limb: &[ThresholdShareLimb],
    target_level: usize,
) -> CanonicalResult<()>
where
    ThresholdShareLimb: AsRef<[u64]>,
{
    if threshold_share_by_limb.len() != target_level + 1 {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS threshold share does not cover the complete target basis",
        ));
    }
    for (limb_index, limb) in threshold_share_by_limb.iter().enumerate() {
        let limb = limb.as_ref();
        let modulus = DATA_PRIMES[limb_index];
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "KLLPS threshold-share limb has the wrong ring degree",
            ));
        }
        if limb.iter().any(|coefficient| *coefficient >= modulus) {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "KLLPS threshold-share limb contains a noncanonical residue",
            ));
        }
    }

    Ok(())
}

fn validate_partial_limb_set(partials: &[Vec<u64>], target_level: usize) -> CanonicalResult<()> {
    if partials.len() != target_level + 1 {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS paired share does not cover the complete target basis",
        ));
    }
    for (limb_index, limb) in partials.iter().enumerate() {
        let modulus = DATA_PRIMES[limb_index];
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(invalid_release(
                CanonicalErrorCode::MalformedLength,
                "KLLPS paired-share limb has the wrong ring degree",
            ));
        }
        if limb.iter().any(|coefficient| *coefficient >= modulus) {
            return Err(invalid_release(
                CanonicalErrorCode::InvalidProtocolObject,
                "KLLPS paired-share limb contains a noncanonical residue",
            ));
        }
    }

    Ok(())
}

fn validate_flooding_error(
    flooding_error: &[BigInt],
    flooding_coefficient_bound: &BigUint,
) -> CanonicalResult<()> {
    if flooding_error.len() != POLYNOMIAL_DEGREE {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS flooding error has the wrong ring degree",
        ));
    }
    if flooding_error
        .iter()
        .any(|coefficient| coefficient.magnitude() > flooding_coefficient_bound)
    {
        return Err(invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS flooding error exceeds the suite coefficient bound",
        ));
    }

    Ok(())
}

fn validate_selected_positions(selected_positions: &[usize]) -> CanonicalResult<()> {
    if selected_positions.len() != KLLPS_RECONSTRUCTION_THRESHOLD {
        return Err(invalid_release(
            CanonicalErrorCode::MalformedLength,
            "KLLPS reconstruction subset must contain exactly four participants",
        ));
    }
    validate_distinct_roster_positions(selected_positions)
}

fn validate_distinct_roster_positions(roster_positions: &[usize]) -> CanonicalResult<()> {
    let mut previous = None;
    for roster_position in roster_positions.iter().copied() {
        validate_roster_position(roster_position)?;
        if previous.is_some_and(|previous_position| previous_position >= roster_position) {
            return Err(invalid_release(
                CanonicalErrorCode::ComponentMismatch,
                "KLLPS roster positions must be distinct and strictly increasing",
            ));
        }
        previous = Some(roster_position);
    }
    Ok(())
}

fn validate_roster_position(roster_position: usize) -> CanonicalResult<()> {
    if roster_position >= KLLPS_PARTICIPANT_COUNT {
        return Err(invalid_release(
            CanonicalErrorCode::ComponentMismatch,
            "KLLPS roster position is outside the selected ten-participant suite",
        ));
    }
    Ok(())
}

fn bigint_residue(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_bigint = BigInt::from(modulus);
    let residue = ((value % &modulus_bigint) + &modulus_bigint) % &modulus_bigint;
    residue.to_u64().ok_or_else(|| {
        invalid_release(
            CanonicalErrorCode::InvalidProtocolObject,
            "KLLPS arbitrary-width coefficient residue does not fit its target prime",
        )
    })
}

fn invalid_release(code: CanonicalErrorCode, message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(code, message)
}

fn partial_stream_error(error: TargetPartialDecryptionStreamError) -> CanonicalError {
    let code = match error {
        TargetPartialDecryptionStreamError::CountOverflow => CanonicalErrorCode::MalformedLength,
        TargetPartialDecryptionStreamError::InvalidRole
        | TargetPartialDecryptionStreamError::InvalidTargetPrime
        | TargetPartialDecryptionStreamError::NoncanonicalResidue => {
            CanonicalErrorCode::InvalidProtocolObject
        }
        TargetPartialDecryptionStreamError::InvalidLimbCount
        | TargetPartialDecryptionStreamError::InvalidCoefficientCount
        | TargetPartialDecryptionStreamError::InvalidByteLength => {
            CanonicalErrorCode::MalformedLength
        }
    };
    invalid_release(code, format!("invalid KLLPS partial stream: {error:?}"))
}

#[cfg(test)]
mod tests;
