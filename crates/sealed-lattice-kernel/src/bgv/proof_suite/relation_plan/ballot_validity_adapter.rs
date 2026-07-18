//! Exact family adapter for the direct-ballot relation.
//!
//! The adapter keeps one typed ballot/encryption witness and derives one
//! plan-addressed polynomial at a time. Public-key and ciphertext polynomials
//! are retained as authenticated, root-bound residue vectors; they are never
//! accepted as prover columns.

use std::{mem::size_of, rc::Rc, sync::Arc};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    bgv::{
        coefficient_codec::canonical_modulus_byte_length,
        direct_ballots::direct_ballot_slots,
        encoding::encode_logical_slots_to_plaintext_coefficients,
        evaluator::engine::{negacyclic_mul, signed_residue},
        modular_arithmetic::add_mod,
        setup::{VerifiedAcceptedSetupAuthorityHandle, with_verified_accepted_setup_authority},
    },
    encoding::{CanonicalError, CanonicalErrorCode},
    foundation::{
        ActionPrivateRandomness, AuthenticatedCheckpointContinuationSource, CanonicalItem,
        CanonicalStreamDomain, CanonicalStreamVerifier, CanonicalStreamWriter, CanonicalTuple,
        FOUNDATION_PROFILE, FoundationSchemaError, Hash512, OrdinaryProofCoinInput,
        PrivateRandomCursor, PrivateRandomnessAttemptIdentifier, PrivateRandomnessDomain,
        PrivateRandomnessKmacInputClassAccounting, ProofApplicationSlot, RefusalReason,
        SelectedSuiteCapability, StreamDescriptor, VerificationResult, hash_foundation_tuple_512,
        private_randomness_stream_block_count_for_bit_length,
        private_randomness_stream_block_count_for_modulo_outputs,
        resolve_prepared_ordinary_proof_attempt_source,
    },
    hashing::hash_framed_parts_512,
};

use super::*;
use crate::bgv::proof_suite::{
    CommonProofGenerationAuthorization, CommonProofGenerationPreparationError,
    CommonProofGenerationSources, CommonProofPrivateCoinCoordinateCapacity, CommonProofProverError,
    CommonProofRelationPlanCapability, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofSourcePolynomial, CommonProofSourcePolynomialProvider,
    CommonProofSourcePolynomialProviderPoll, CommonProofSourcePolynomialReplayIdentity,
    CommonProofSourcePolynomialRequest, OpenedFriLayerPair, PROOF_BASE_FIELD_MODULUS,
    PreparedCommonProofGeneration, PrivateRandomnessCommonProofCoinError,
    PrivateRandomnessCommonProofCoinSource, ProofBaseFieldElement, ProofChallengeExtensionElement,
    ProofEvaluationDomain, ProofFieldError, ProofLeafVisibility, ProofPolynomialError,
    ProofTreeRole, ProvidedCommonProofSourcePolynomial, RelationProofTreeInput,
    SelectedApplicationStatementContext, VerifiedRelationColumnEvaluator,
    canonical_selected_ballot_validity_statement, decode_selected_ballot_validity_statement,
    selected_ballot_validity_relation_compilation, verified_application_statement_hash,
};

const OPTION_COUNT: usize = 20;
const MINIMUM_SCORE: u64 = 1;
const MAXIMUM_SCORE: u64 = 10;
const RADIX: i128 = 3;
const VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL: u64 = 7;
const BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL: u64 = 8;
const BALLOT_SOURCE_RESTART_BINDING_DOMAIN: &str =
    "sealed-lattice/proof/ballot-source-restart-binding/v1";
const BALLOT_SOURCE_POLYNOMIAL_REPLAY_DOMAIN: &str =
    "sealed-lattice/proof/ballot-source-polynomial-replay/v1";
const BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x1303;
const BALLOT_ENCRYPTION_COIN_CONTEXT_HASH_DOMAIN: &str =
    "sealed-lattice/ballot/encryption-coin-context/v1";
const BALLOT_EPHEMERAL_SECRET_RANDOMNESS_PURPOSE: u16 = 8;
const BALLOT_ERROR_ZERO_RANDOMNESS_PURPOSE: u16 = 9;
const BALLOT_ERROR_ONE_RANDOMNESS_PURPOSE: u16 = 10;

/// Source-owned count for one ballot encryption attempt. The centered
/// ternary randomizer uses rejection sampling, while each eta-two centered
/// binomial error stream consumes four packed bits per coefficient.
pub(crate) fn ballot_encryption_private_randomness_kmac_input_accounting(
    ring_degree: u64,
    maximum_candidate_draws_per_output: u32,
) -> Option<PrivateRandomnessKmacInputClassAccounting> {
    let randomizer_stream_block_count = private_randomness_stream_block_count_for_modulo_outputs(
        ring_degree,
        3,
        maximum_candidate_draws_per_output,
    )?;
    let centered_binomial_stream_block_count =
        private_randomness_stream_block_count_for_bit_length(ring_degree.checked_mul(4)?)?;
    PrivateRandomnessKmacInputClassAccounting::checked_new(
        0,
        0,
        randomizer_stream_block_count
            .checked_add(centered_binomial_stream_block_count.checked_mul(2)?)?,
        0,
    )
}

/// Production-derived buffer geometry for the selected ballot carrier and
/// its streaming common-proof source adapter. Counts cover owned coefficient,
/// transform, cache, stream, and boundary-copy buffers; allocator metadata is
/// intentionally left to the runtime heap measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedBallotValidityCarrierBufferAccounting {
    canonical_ciphertext_byte_length: u64,
    canonical_ciphertext_chunk_count: u32,
    canonical_ciphertext_descriptor_encoded_byte_length: u64,
    canonical_ciphertext_descriptor_digest_catalog_byte_length: u64,
    ciphertext_readback_polynomial_catalog_byte_length: u64,
    decoded_ciphertext_residue_byte_length: u64,
    provider_bound_public_residue_byte_length: u64,
    provider_witness_coefficient_byte_length: u64,
    provider_precomputed_transform_byte_length: u64,
    provider_value_cache_byte_length: u64,
    provider_transient_scratch_byte_length: u64,
    provider_buffer_live_set_peak_byte_length: u64,
    provider_fixed_owner_byte_length: u64,
    provider_source_plan_catalog_byte_length: u64,
    provider_ordered_source_column_catalog_byte_length: u64,
    provider_loading_persistent_resident_byte_length: u64,
    provider_post_source_finish_persistent_resident_byte_length: u64,
    provider_additional_loading_transient_byte_length: u64,
    transferred_source_polynomial_byte_length: u64,
    maximum_boundary_copied_buffer_byte_length: u64,
}

impl SelectedBallotValidityCarrierBufferAccounting {
    pub(crate) const fn canonical_ciphertext_byte_length(self) -> u64 {
        self.canonical_ciphertext_byte_length
    }

    pub(crate) const fn canonical_ciphertext_chunk_count(self) -> u32 {
        self.canonical_ciphertext_chunk_count
    }

    pub(crate) const fn canonical_ciphertext_descriptor_encoded_byte_length(self) -> u64 {
        self.canonical_ciphertext_descriptor_encoded_byte_length
    }

    pub(crate) const fn canonical_ciphertext_descriptor_digest_catalog_byte_length(self) -> u64 {
        self.canonical_ciphertext_descriptor_digest_catalog_byte_length
    }

    pub(crate) const fn ciphertext_readback_polynomial_catalog_byte_length(self) -> u64 {
        self.ciphertext_readback_polynomial_catalog_byte_length
    }

    pub(crate) const fn decoded_ciphertext_residue_byte_length(self) -> u64 {
        self.decoded_ciphertext_residue_byte_length
    }

    pub(crate) const fn provider_bound_public_residue_byte_length(self) -> u64 {
        self.provider_bound_public_residue_byte_length
    }

    pub(crate) const fn provider_witness_coefficient_byte_length(self) -> u64 {
        self.provider_witness_coefficient_byte_length
    }

    pub(crate) const fn provider_precomputed_transform_byte_length(self) -> u64 {
        self.provider_precomputed_transform_byte_length
    }

    pub(crate) const fn provider_value_cache_byte_length(self) -> u64 {
        self.provider_value_cache_byte_length
    }

    pub(crate) const fn provider_transient_scratch_byte_length(self) -> u64 {
        self.provider_transient_scratch_byte_length
    }

    pub(crate) const fn provider_buffer_live_set_peak_byte_length(self) -> u64 {
        self.provider_buffer_live_set_peak_byte_length
    }

    pub(crate) const fn provider_fixed_owner_byte_length(self) -> u64 {
        self.provider_fixed_owner_byte_length
    }

    pub(crate) const fn provider_source_plan_catalog_byte_length(self) -> u64 {
        self.provider_source_plan_catalog_byte_length
    }

    pub(crate) const fn provider_ordered_source_column_catalog_byte_length(self) -> u64 {
        self.provider_ordered_source_column_catalog_byte_length
    }

    pub(crate) const fn provider_loading_persistent_resident_byte_length(self) -> u64 {
        self.provider_loading_persistent_resident_byte_length
    }

    pub(crate) const fn provider_post_source_finish_persistent_resident_byte_length(self) -> u64 {
        self.provider_post_source_finish_persistent_resident_byte_length
    }

    pub(crate) const fn provider_additional_loading_transient_byte_length(self) -> u64 {
        self.provider_additional_loading_transient_byte_length
    }

    pub(crate) const fn transferred_source_polynomial_byte_length(self) -> u64 {
        self.transferred_source_polynomial_byte_length
    }

    pub(crate) const fn maximum_boundary_copied_buffer_byte_length(self) -> u64 {
        self.maximum_boundary_copied_buffer_byte_length
    }
}

pub(crate) fn selected_ballot_validity_carrier_buffer_accounting()
-> Result<SelectedBallotValidityCarrierBufferAccounting, BallotValidityAdapterError> {
    let compilation = selected_ballot_validity_relation_compilation()?;
    ballot_validity_carrier_buffer_accounting(compilation.source_plan())
}

fn ballot_validity_carrier_buffer_accounting(
    source_plan: &BallotValiditySourcePlan,
) -> Result<SelectedBallotValidityCarrierBufferAccounting, BallotValidityAdapterError> {
    let ring_degree = source_plan.ring_degree();
    let limb_count = u64::try_from(source_plan.data_moduli().len())
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    if limb_count == 0
        || source_plan.active_data_modulus_indices().len() != source_plan.data_moduli().len()
    {
        return Err(BallotValidityAdapterError::InvalidPublicMaterial);
    }
    let canonical_coefficient_width_sum =
        source_plan
            .data_moduli()
            .iter()
            .copied()
            .try_fold(0_u64, |sum, modulus| {
                sum.checked_add(
                    u64::try_from(canonical_modulus_byte_length(modulus))
                        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                )
                .ok_or(BallotValidityAdapterError::IntegerOverflow)
            })?;
    let canonical_ciphertext_byte_length = ring_degree
        .checked_mul(2)
        .and_then(|count| count.checked_mul(canonical_coefficient_width_sum))
        .and_then(|bytes| bytes.checked_add(4))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let stream_chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let canonical_ciphertext_chunk_count =
        u32::try_from(canonical_ciphertext_byte_length.div_ceil(stream_chunk_byte_length))
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let canonical_ciphertext_descriptor = StreamDescriptor::new(
        canonical_ciphertext_byte_length,
        vec![
            Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]);
            usize::try_from(canonical_ciphertext_chunk_count)
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?
        ],
        Hash512::from_bytes([0_u8; Hash512::BYTE_LENGTH]),
    )
    .map_err(|_| BallotValidityAdapterError::InvalidPublicMaterial)?;
    let canonical_ciphertext_descriptor_encoded_byte_length = u64::try_from(
        canonical_ciphertext_descriptor
            .encode()
            .map_err(|_| BallotValidityAdapterError::InvalidPublicMaterial)?
            .len(),
    )
    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let canonical_ciphertext_descriptor_digest_catalog_byte_length =
        u64::from(canonical_ciphertext_chunk_count)
            .checked_mul(
                u64::try_from(size_of::<Hash512>())
                    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
            )
            .and_then(|length| {
                u64::try_from(size_of::<usize>())
                    .ok()
                    .and_then(|word_byte_length| {
                        word_byte_length
                            .checked_mul(2)
                            .and_then(|header| length.checked_add(header))
                    })
            })
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let ciphertext_readback_polynomial_catalog_byte_length = limb_count
        .checked_mul(2)
        .and_then(|count| {
            u64::try_from(size_of::<(u16, u16, u64, Arc<[u64]>)>())
                .ok()
                .and_then(|entry_byte_length| count.checked_mul(entry_byte_length))
        })
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let decoded_ciphertext_residue_byte_length = ring_degree
        .checked_mul(2)
        .and_then(|count| count.checked_mul(limb_count))
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_bound_public_residue_byte_length = decoded_ciphertext_residue_byte_length
        .checked_mul(2)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_witness_coefficient_byte_length = ring_degree
        .checked_mul(4)
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_precomputed_transform_byte_length = ring_degree
        .checked_mul(2)
        .and_then(|count| count.checked_mul(8))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_value_cache_byte_length = ring_degree
        .checked_mul(16)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_transient_scratch_byte_length = provider_precomputed_transform_byte_length;
    let provider_buffer_live_set_peak_byte_length = provider_bound_public_residue_byte_length
        .checked_add(provider_witness_coefficient_byte_length)
        .and_then(|bytes| bytes.checked_add(provider_precomputed_transform_byte_length))
        .and_then(|bytes| bytes.checked_add(provider_value_cache_byte_length))
        .and_then(|bytes| bytes.checked_add(provider_transient_scratch_byte_length))
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let transferred_source_polynomial_byte_length = ring_degree
        .checked_mul(8)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_fixed_owner_byte_length =
        u64::try_from(size_of::<BallotValiditySourcePolynomialAdapter>())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let provider_source_plan_catalog_byte_length = source_plan
        .owned_catalog_byte_length()
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_ordered_source_column_catalog_byte_length =
        checked_slice_byte_length::<(u32, RelationColumnDescriptor)>(
            source_plan.provided_column_count(),
        )?;
    let witness_fixed_owner_and_arc_header_byte_length = u64::try_from(
        size_of::<BallotValidityEncryptionAttemptSecret>()
            .checked_add(
                size_of::<usize>()
                    .checked_mul(2)
                    .ok_or(BallotValidityAdapterError::IntegerOverflow)?,
            )
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?,
    )
    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let public_polynomial_count = limb_count
        .checked_mul(4)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let public_material_catalog_and_arc_header_byte_length =
        checked_slice_byte_length::<[BoundResiduePolynomial; 2]>(source_plan.data_moduli().len())?
            .checked_mul(2)
            .and_then(|length| {
                u64::try_from(size_of::<usize>() * 2)
                    .ok()
                    .and_then(|arc_header_byte_length| {
                        public_polynomial_count
                            .checked_mul(arc_header_byte_length)
                            .and_then(|headers| length.checked_add(headers))
                    })
            })
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    let provider_loading_persistent_resident_byte_length = [
        provider_fixed_owner_byte_length,
        provider_source_plan_catalog_byte_length,
        provider_ordered_source_column_catalog_byte_length,
        witness_fixed_owner_and_arc_header_byte_length,
        provider_witness_coefficient_byte_length,
        public_material_catalog_and_arc_header_byte_length,
        provider_bound_public_residue_byte_length,
        provider_precomputed_transform_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_adapter_add)?;
    let provider_post_source_finish_persistent_resident_byte_length = [
        provider_fixed_owner_byte_length,
        provider_source_plan_catalog_byte_length,
        provider_ordered_source_column_catalog_byte_length,
        public_material_catalog_and_arc_header_byte_length,
        provider_bound_public_residue_byte_length,
    ]
    .into_iter()
    .try_fold(0_u64, checked_adapter_add)?;
    let provider_additional_loading_transient_byte_length = provider_value_cache_byte_length.max(
        provider_value_cache_byte_length
            .checked_add(provider_transient_scratch_byte_length)
            .and_then(|length| length.checked_sub(transferred_source_polynomial_byte_length))
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?,
    );
    Ok(SelectedBallotValidityCarrierBufferAccounting {
        canonical_ciphertext_byte_length,
        canonical_ciphertext_chunk_count,
        canonical_ciphertext_descriptor_encoded_byte_length,
        canonical_ciphertext_descriptor_digest_catalog_byte_length,
        ciphertext_readback_polynomial_catalog_byte_length,
        decoded_ciphertext_residue_byte_length,
        provider_bound_public_residue_byte_length,
        provider_witness_coefficient_byte_length,
        provider_precomputed_transform_byte_length,
        provider_value_cache_byte_length,
        provider_transient_scratch_byte_length,
        provider_buffer_live_set_peak_byte_length,
        provider_fixed_owner_byte_length,
        provider_source_plan_catalog_byte_length,
        provider_ordered_source_column_catalog_byte_length,
        provider_loading_persistent_resident_byte_length,
        provider_post_source_finish_persistent_resident_byte_length,
        provider_additional_loading_transient_byte_length,
        transferred_source_polynomial_byte_length,
        maximum_boundary_copied_buffer_byte_length: stream_chunk_byte_length,
    })
}

fn checked_adapter_add(left: u64, right: u64) -> Result<u64, BallotValidityAdapterError> {
    left.checked_add(right)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)
}

fn checked_slice_byte_length<Element>(
    element_count: usize,
) -> Result<u64, BallotValidityAdapterError> {
    element_count
        .checked_mul(size_of::<Element>())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(BallotValidityAdapterError::IntegerOverflow)
}

/// Derives the common-prover tree inputs from a checked exact-family variant
/// only when every relation tree is proof-created. Statement-bound tree roots
/// must come from a verifier-owned capability, so this path rejects them
/// instead of filling sizing placeholders.
pub(crate) fn proof_created_relation_tree_inputs_from_checked_variant(
    variant: &RelationPlanVariant,
) -> Result<Vec<RelationProofTreeInput>, BallotValidityAdapterError> {
    variant
        .ordered_trees()
        .iter()
        .map(|tree| {
            let RelationTreeDescriptor::ProofCreated {
                proof_tree_role,
                ordered_column_ordinals,
            } = tree
            else {
                return Err(BallotValidityAdapterError::InvalidColumn);
            };
            if ordered_column_ordinals.is_empty() {
                return Err(BallotValidityAdapterError::InvalidColumn);
            }
            let leaf_visibility = ordered_column_ordinals.iter().try_fold(
                ProofLeafVisibility::Public,
                |visibility, column_ordinal| {
                    let column = usize::try_from(*column_ordinal)
                        .ok()
                        .and_then(|column_index| variant.ordered_columns().get(column_index))
                        .ok_or(BallotValidityAdapterError::InvalidColumn)?;
                    Ok::<_, BallotValidityAdapterError>(
                        if matches!(column.origin(), RelationColumnOrigin::Prover) {
                            ProofLeafVisibility::SecretBearing
                        } else {
                            visibility
                        },
                    )
                },
            )?;
            Ok(RelationProofTreeInput::ProofCreated {
                tree_role: match proof_tree_role {
                    1 => ProofTreeRole::BaseOracle,
                    2 => ProofTreeRole::AuxiliaryOracle,
                    _ => return Err(BallotValidityAdapterError::InvalidColumn),
                },
                row_width: u32::try_from(ordered_column_ordinals.len())
                    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                leaf_visibility,
            })
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BallotValidityAdapterError {
    WrongApplication,
    InvalidStatementBinding,
    InvalidWitness,
    InvalidPublicMaterial,
    InvalidColumn,
    IntegerOverflow,
    NoWrapBoundViolated,
    Field(ProofFieldError),
    Polynomial(ProofPolynomialError),
    Relation(RelationPlanError),
    Stream(RefusalReason),
    Canonical(CanonicalError),
    Foundation(FoundationSchemaError),
    PrivateCoins(PrivateRandomnessCommonProofCoinError),
}

#[derive(Debug)]
pub(crate) enum BallotValidityGenerationPreparationError {
    Adapter(BallotValidityAdapterError),
    Runtime(CommonProofRuntimeError),
    Common(CommonProofGenerationPreparationError),
}

impl From<BallotValidityAdapterError> for BallotValidityGenerationPreparationError {
    fn from(error: BallotValidityAdapterError) -> Self {
        Self::Adapter(error)
    }
}

impl From<CommonProofRuntimeError> for BallotValidityGenerationPreparationError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<CommonProofGenerationPreparationError> for BallotValidityGenerationPreparationError {
    fn from(error: CommonProofGenerationPreparationError) -> Self {
        Self::Common(error)
    }
}

impl From<ProofFieldError> for BallotValidityAdapterError {
    fn from(error: ProofFieldError) -> Self {
        Self::Field(error)
    }
}

impl From<ProofPolynomialError> for BallotValidityAdapterError {
    fn from(error: ProofPolynomialError) -> Self {
        Self::Polynomial(error)
    }
}

impl From<RelationPlanError> for BallotValidityAdapterError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CanonicalError> for BallotValidityAdapterError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<FoundationSchemaError> for BallotValidityAdapterError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<PrivateRandomnessCommonProofCoinError> for BallotValidityAdapterError {
    fn from(error: PrivateRandomnessCommonProofCoinError) -> Self {
        Self::PrivateCoins(error)
    }
}

/// Canonical statement coordinates that must agree with the retained accepted
/// setup authority before its collective public-key stream can be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BallotValidityAcceptedSetupBinding {
    pub(crate) protocol_version: u16,
    pub(crate) suite_identifier: [u8; 64],
    pub(crate) ceremony_context_hash: [u8; 64],
    pub(crate) action_context_hash: [u8; 64],
    pub(crate) roster_hash: [u8; 64],
    pub(crate) exact_verified_setup_source_hash: [u8; 64],
}

/// The common witness shared by every RNS limb of one ballot encryption.
///
/// Construction checks the score domain, exact selected batch encoding, and
/// the encryption-noise support. The nonzero attempt identifier is generated
/// by the ballot encryption operation and is retained across a resumed proof;
/// it prevents a restarted provider from being rebound to a different secret
/// witness that happens to have the same public ciphertext.
struct BallotValidityEncryptionAttemptSecret {
    scores: Zeroizing<[u64; OPTION_COUNT]>,
    plaintext_coefficients: Zeroizing<Vec<u64>>,
    randomizer_coefficients: Zeroizing<Vec<i64>>,
    error_zero_coefficients: Zeroizing<Vec<i64>>,
    error_one_coefficients: Zeroizing<Vec<i64>>,
    encryption_attempt_identifier: Zeroizing<[u8; 32]>,
}

#[derive(Clone)]
pub(crate) struct BallotValidityEncryptionAttemptWitness {
    secret: Arc<BallotValidityEncryptionAttemptSecret>,
}

impl BallotValidityEncryptionAttemptWitness {
    pub(crate) fn sample_from_action_randomness(
        source_plan: &BallotValiditySourcePlan,
        selected_suite: &SelectedSuiteCapability,
        action_private_randomness: &ActionPrivateRandomness,
        application_slot: ProofApplicationSlot,
        verified_setup_source_hash: [u8; 64],
        scores: &[u64],
        injected_encryption_attempt_identifier: Zeroizing<[u8; 32]>,
    ) -> Result<(Self, [PrivateRandomCursor; 3]), BallotValidityAdapterError> {
        let derivation_input = action_private_randomness.derivation_input();
        let source_ring_degree = u32::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        if selected_suite.protocol_version() == 0
            || selected_suite.suite_identifier() != application_slot.suite_identifier().into_bytes()
            || selected_suite.suite_identifier() != derivation_input.suite_identifier().into_bytes()
            || application_slot.ceremony_context_hash()
                != derivation_input.ceremony_context_hash()
            || application_slot.action_context_hash() != derivation_input.action_context_hash()
            || application_slot.application_statement_schema_identifier()
                != crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
            || application_slot.roster_position().is_none()
            || application_slot.schedule_position().is_some()
            || application_slot.producer_sequence().is_none()
            || verified_setup_source_hash == [0_u8; 64]
            || selected_suite.polynomial_degree() != source_ring_degree
        {
            return Err(BallotValidityAdapterError::InvalidStatementBinding);
        }
        let coin_context = CanonicalTuple::new(
            BALLOT_ENCRYPTION_COIN_CONTEXT_SCHEMA_IDENTIFIER,
            1,
            vec![
                CanonicalItem::nested_tuple(&application_slot.canonical_tuple()?)
                    .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?,
                CanonicalItem::hash512(verified_setup_source_hash),
            ],
        );
        let canonical_coin_context_bytes = coin_context
            .encode()
            .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?;
        let coin_context_hash = hash_foundation_tuple_512(
            BALLOT_ENCRYPTION_COIN_CONTEXT_HASH_DOMAIN,
            &[CanonicalItem::variable_bytes(canonical_coin_context_bytes)
                .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?],
        )
        .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?;
        let attempt_identifier = action_private_randomness
            .ballot_encryption_attempt_identifier(injected_encryption_attempt_identifier);
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let maximum_candidate_draws =
            selected_suite.maximum_private_sampler_candidate_draws_per_output();
        let mut randomizer_stream = action_private_randomness.begin_stream(
            PrivateRandomnessDomain::ballot_encryption_distribution(
                BALLOT_EPHEMERAL_SECRET_RANDOMNESS_PURPOSE,
            )?,
            coin_context_hash,
            attempt_identifier,
        )?;
        let mut error_zero_stream = action_private_randomness.begin_stream(
            PrivateRandomnessDomain::ballot_encryption_distribution(
                BALLOT_ERROR_ZERO_RANDOMNESS_PURPOSE,
            )?,
            coin_context_hash,
            attempt_identifier,
        )?;
        let mut error_one_stream = action_private_randomness.begin_stream(
            PrivateRandomnessDomain::ballot_encryption_distribution(
                BALLOT_ERROR_ONE_RANDOMNESS_PURPOSE,
            )?,
            coin_context_hash,
            attempt_identifier,
        )?;
        let mut randomizer_coefficients = Zeroizing::new(Vec::with_capacity(ring_degree));
        let mut error_zero_coefficients = Zeroizing::new(Vec::with_capacity(ring_degree));
        let mut error_one_coefficients = Zeroizing::new(Vec::with_capacity(ring_degree));
        for _ in 0..ring_degree {
            randomizer_coefficients.push(i64::from(
                randomizer_stream.sample_centered_ternary(maximum_candidate_draws)?,
            ));
            error_zero_coefficients.push(i64::from(error_zero_stream.sample_centered_binomial(2)?));
            error_one_coefficients.push(i64::from(error_one_stream.sample_centered_binomial(2)?));
        }
        let cursors = [
            randomizer_stream.cursor(),
            error_zero_stream.cursor(),
            error_one_stream.cursor(),
        ];
        let scores: Zeroizing<[u64; OPTION_COUNT]> = Zeroizing::new(
            <[u64; OPTION_COUNT]>::try_from(scores)
                .map_err(|_| BallotValidityAdapterError::InvalidWitness)?,
        );
        let pair_difference_slots = Zeroizing::new(direct_ballot_slots(
            &scores[..],
            source_plan.plaintext_modulus(),
            ring_degree,
        )?);
        let plaintext_coefficients = Zeroizing::new(
            encode_logical_slots_to_plaintext_coefficients(&pair_difference_slots)?,
        );
        let witness = Self::from_zeroizing_encryption_attempt(
            source_plan,
            scores,
            plaintext_coefficients,
            randomizer_coefficients,
            error_zero_coefficients,
            error_one_coefficients,
            Zeroizing::new(*attempt_identifier.as_bytes()),
        )?;
        Ok((witness, cursors))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_encryption_attempt(
        source_plan: &BallotValiditySourcePlan,
        scores: &[u64],
        plaintext_coefficients: Vec<u64>,
        randomizer_coefficients: Vec<i64>,
        error_zero_coefficients: Vec<i64>,
        error_one_coefficients: Vec<i64>,
        encryption_attempt_identifier: [u8; 32],
    ) -> Result<Self, BallotValidityAdapterError> {
        let plaintext_coefficients = Zeroizing::new(plaintext_coefficients);
        let randomizer_coefficients = Zeroizing::new(randomizer_coefficients);
        let error_zero_coefficients = Zeroizing::new(error_zero_coefficients);
        let error_one_coefficients = Zeroizing::new(error_one_coefficients);
        let encryption_attempt_identifier = Zeroizing::new(encryption_attempt_identifier);
        let scores: Zeroizing<[u64; OPTION_COUNT]> = Zeroizing::new(
            <[u64; OPTION_COUNT]>::try_from(scores)
                .map_err(|_| BallotValidityAdapterError::InvalidWitness)?,
        );
        Self::from_zeroizing_encryption_attempt(
            source_plan,
            scores,
            plaintext_coefficients,
            randomizer_coefficients,
            error_zero_coefficients,
            error_one_coefficients,
            encryption_attempt_identifier,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_zeroizing_encryption_attempt(
        source_plan: &BallotValiditySourcePlan,
        scores: Zeroizing<[u64; OPTION_COUNT]>,
        plaintext_coefficients: Zeroizing<Vec<u64>>,
        randomizer_coefficients: Zeroizing<Vec<i64>>,
        error_zero_coefficients: Zeroizing<Vec<i64>>,
        error_one_coefficients: Zeroizing<Vec<i64>>,
        encryption_attempt_identifier: Zeroizing<[u8; 32]>,
    ) -> Result<Self, BallotValidityAdapterError> {
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        if scores
            .iter()
            .any(|score| !(MINIMUM_SCORE..=MAXIMUM_SCORE).contains(score))
            || plaintext_coefficients.len() != ring_degree
            || randomizer_coefficients.len() != ring_degree
            || error_zero_coefficients.len() != ring_degree
            || error_one_coefficients.len() != ring_degree
            || randomizer_coefficients
                .iter()
                .any(|coefficient| !(-1..=1).contains(coefficient))
            || error_zero_coefficients
                .iter()
                .chain(error_one_coefficients.iter())
                .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(BallotValidityAdapterError::InvalidWitness);
        }

        let expected_plaintext_coefficients = Zeroizing::new(
            source_plan
                .plaintext_coefficients_for_scores(&scores[..])
                .ok_or(BallotValidityAdapterError::InvalidWitness)?,
        );
        if plaintext_coefficients.as_slice() != expected_plaintext_coefficients.as_slice() {
            return Err(BallotValidityAdapterError::InvalidWitness);
        }

        Ok(Self {
            secret: Arc::new(BallotValidityEncryptionAttemptSecret {
                scores,
                plaintext_coefficients,
                randomizer_coefficients,
                error_zero_coefficients,
                error_one_coefficients,
                encryption_attempt_identifier,
            }),
        })
    }

    fn scores(&self) -> &[u64; OPTION_COUNT] {
        &self.secret.scores
    }

    fn plaintext_coefficients(&self) -> &[u64] {
        &self.secret.plaintext_coefficients
    }

    fn randomizer_coefficients(&self) -> &[i64] {
        &self.secret.randomizer_coefficients
    }

    fn error_zero_coefficients(&self) -> &[i64] {
        &self.secret.error_zero_coefficients
    }

    fn error_one_coefficients(&self) -> &[i64] {
        &self.secret.error_one_coefficients
    }

    fn encryption_attempt_identifier(&self) -> [u8; 32] {
        *self.secret.encryption_attempt_identifier
    }

    #[cfg(test)]
    fn secret_owner_count(&self) -> usize {
        Arc::strong_count(&self.secret)
    }

    #[cfg(test)]
    fn secret_weak_reference(&self) -> std::sync::Weak<BallotValidityEncryptionAttemptSecret> {
        Arc::downgrade(&self.secret)
    }
}

#[derive(Clone)]
struct BoundResiduePolynomial {
    modulus: u64,
    coefficients: Arc<[u64]>,
}

/// Public material admitted only after the owning setup/ciphertext adapters
/// authenticate the complete canonical streams and their statement hashes.
/// Clones share the coefficient buffers, so the prover and verifier adapters
/// do not duplicate the complete RNS ciphertext in Wasm memory.
#[derive(Clone)]
pub(crate) struct BallotValidityBoundPublicMaterial {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    verified_setup_source_hash: [u8; 64],
    ballot_ciphertext_digest: [u8; 64],
    public_key_by_limb: Box<[[BoundResiduePolynomial; 2]]>,
    ciphertext_by_limb: Box<[[BoundResiduePolynomial; 2]]>,
}

/// Ciphertext polynomials retained only after a complete ballot-ciphertext
/// stream has matched its canonical descriptor and full-object digest.
#[derive(Clone)]
pub(crate) struct BallotValidityAuthenticatedCiphertext {
    full_object_digest: [u8; 64],
    polynomials: Vec<(u16, u16, u64, Arc<[u64]>)>,
}

/// One exact selected-suite ballot ciphertext created from a verified setup
/// authority and the common ballot witness. Canonical output is replayed in
/// bounded chunks directly from the retained residue polynomials.
pub(crate) struct BallotValidityGeneratedCiphertext {
    descriptor: StreamDescriptor,
    authenticated_ciphertext: BallotValidityAuthenticatedCiphertext,
}

/// Browser-owned state for one exact ballot encryption and its common-proof
/// attempt. The ciphertext, canonical statement, common witness, proof retry
/// identity, and private-randomness custody stay joined so a restarted source
/// provider cannot silently switch any of them.
pub(crate) struct BallotValidityPreparedProofAttempt {
    action_private_randomness: Rc<ActionPrivateRandomness>,
    application_slot: ProofApplicationSlot,
    canonical_application_statement_bytes: Vec<u8>,
    application_statement_hash: [u8; 64],
    proof_coin_input: OrdinaryProofCoinInput,
    encryption_randomness_cursors: [PrivateRandomCursor; 3],
    witness: BallotValidityEncryptionAttemptWitness,
    public_material: BallotValidityBoundPublicMaterial,
    generated_ciphertext: BallotValidityGeneratedCiphertext,
}

impl BallotValidityPreparedProofAttempt {
    /// Opens one selected-suite ballot attempt from live browser-owned
    /// randomness and accepted-setup authority. The proof slot, roster
    /// position, statement context, and setup source hash are derived here;
    /// callers provide only the ballot scores, producer sequence, and fresh
    /// local attempt nonces.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_selected(
        compilation: &CompiledBallotValidityRelation,
        selected_suite: &SelectedSuiteCapability,
        action_private_randomness: Rc<ActionPrivateRandomness>,
        authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
        producer_sequence: u64,
        scores: &[u64],
        injected_encryption_attempt_identifier: Zeroizing<[u8; 32]>,
        injected_proof_attempt_nonce: Zeroizing<[u8; 32]>,
    ) -> Result<Self, BallotValidityAdapterError> {
        let derivation_input = action_private_randomness.derivation_input();
        let participant_identity = derivation_input.participant_identity().into_bytes();
        let (expected_setup_binding, roster_position) =
            with_verified_accepted_setup_authority(authority_handle, |authority| {
                if authority.protocol_version() != selected_suite.protocol_version()
                    || authority.suite_identifier() != selected_suite.suite_identifier()
                    || authority.suite_identifier()
                        != derivation_input.suite_identifier().into_bytes()
                    || authority.ceremony_context_hash()
                        != derivation_input.ceremony_context_hash().into_bytes()
                    || authority.action_context_hash()
                        != derivation_input.action_context_hash().into_bytes()
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "ballot randomness, suite, and accepted setup do not share one context",
                    ));
                }
                let roster_position = authority
                    .participant_release_material(participant_identity)
                    .map(|material| material.roster_position())
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::ComponentMismatch,
                            "ballot producer is not a participant in the accepted setup",
                        )
                    })?;
                Ok((
                    BallotValidityAcceptedSetupBinding {
                        protocol_version: authority.protocol_version(),
                        suite_identifier: authority.suite_identifier(),
                        ceremony_context_hash: authority.ceremony_context_hash(),
                        action_context_hash: authority.action_context_hash(),
                        roster_hash: authority.roster_hash(),
                        exact_verified_setup_source_hash: authority
                            .exact_verified_setup_source_hash(),
                    },
                    roster_position,
                ))
            })
            .map_err(BallotValidityAdapterError::Canonical)?;
        let application_slot = ProofApplicationSlot::new(
            derivation_input.suite_identifier(),
            derivation_input.ceremony_context_hash(),
            derivation_input.action_context_hash(),
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            Some(roster_position),
            None,
            Some(producer_sequence),
        )?;
        Self::prepare(
            compilation,
            selected_suite,
            action_private_randomness,
            authority_handle,
            expected_setup_binding,
            application_slot,
            scores,
            injected_encryption_attempt_identifier,
            injected_proof_attempt_nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        compilation: &CompiledBallotValidityRelation,
        selected_suite: &SelectedSuiteCapability,
        action_private_randomness: Rc<ActionPrivateRandomness>,
        authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
        expected_setup_binding: BallotValidityAcceptedSetupBinding,
        application_slot: ProofApplicationSlot,
        scores: &[u64],
        injected_encryption_attempt_identifier: Zeroizing<[u8; 32]>,
        injected_proof_attempt_nonce: Zeroizing<[u8; 32]>,
    ) -> Result<Self, BallotValidityAdapterError> {
        let derivation_input = action_private_randomness.derivation_input();
        let participant_identity = derivation_input.participant_identity().into_bytes();
        let producer_sequence = application_slot
            .producer_sequence()
            .ok_or(BallotValidityAdapterError::InvalidStatementBinding)?;
        if expected_setup_binding.protocol_version != selected_suite.protocol_version()
            || expected_setup_binding.suite_identifier != selected_suite.suite_identifier()
            || application_slot.suite_identifier().into_bytes()
                != expected_setup_binding.suite_identifier
            || application_slot.ceremony_context_hash().into_bytes()
                != expected_setup_binding.ceremony_context_hash
            || application_slot.action_context_hash().into_bytes()
                != expected_setup_binding.action_context_hash
            || derivation_input.suite_identifier().into_bytes()
                != expected_setup_binding.suite_identifier
            || derivation_input.ceremony_context_hash().into_bytes()
                != expected_setup_binding.ceremony_context_hash
            || derivation_input.action_context_hash().into_bytes()
                != expected_setup_binding.action_context_hash
        {
            return Err(BallotValidityAdapterError::InvalidStatementBinding);
        }

        let (witness, encryption_randomness_cursors) =
            BallotValidityEncryptionAttemptWitness::sample_from_action_randomness(
                compilation.source_plan(),
                selected_suite,
                &action_private_randomness,
                application_slot,
                expected_setup_binding.exact_verified_setup_source_hash,
                scores,
                injected_encryption_attempt_identifier,
            )?;
        let public_key_polynomials = verified_public_key_polynomials(
            compilation.source_plan(),
            authority_handle,
            expected_setup_binding,
        )?;
        let generated_ciphertext =
            BallotValidityGeneratedCiphertext::encrypt_with_public_key_polynomials(
                compilation.source_plan(),
                public_key_polynomials.clone(),
                &witness,
            )?;
        let authenticated_ciphertext = generated_ciphertext.authenticated_ciphertext();
        let public_material =
            BallotValidityBoundPublicMaterial::from_authenticated_polynomial_sequences(
                compilation.source_plan(),
                expected_setup_binding.protocol_version,
                expected_setup_binding.suite_identifier,
                expected_setup_binding.exact_verified_setup_source_hash,
                authenticated_ciphertext.full_object_digest,
                public_key_polynomials,
                authenticated_ciphertext.polynomials,
            )?;
        let canonical_application_statement_bytes = canonical_selected_ballot_validity_statement(
            selected_suite.protocol_version(),
            selected_suite.suite_identifier(),
            expected_setup_binding.ceremony_context_hash,
            expected_setup_binding.action_context_hash,
            expected_setup_binding.roster_hash,
            participant_identity,
            producer_sequence,
            expected_setup_binding.exact_verified_setup_source_hash,
            public_material.ballot_ciphertext_digest(),
        )
        .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?;
        let application_statement_hash = verified_application_statement_hash(
            selected_suite.protocol_version(),
            selected_suite.suite_identifier(),
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            &canonical_application_statement_bytes,
        );
        let proof_coin_input = OrdinaryProofCoinInput::new(
            application_slot,
            Hash512::from_bytes(application_statement_hash),
            *injected_proof_attempt_nonce,
        )?;
        action_private_randomness.ordinary_proof_attempt_identifier(&proof_coin_input)?;
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .map_err(BallotValidityAdapterError::from)?;
        proof_created_relation_tree_inputs_from_checked_variant(variant)?;
        Ok(Self {
            action_private_randomness,
            application_slot,
            canonical_application_statement_bytes,
            application_statement_hash,
            proof_coin_input,
            encryption_randomness_cursors,
            witness,
            public_material,
            generated_ciphertext,
        })
    }

    pub(crate) const fn application_slot(&self) -> ProofApplicationSlot {
        self.application_slot
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) const fn application_statement_hash(&self) -> [u8; 64] {
        self.application_statement_hash
    }

    pub(crate) const fn proof_coin_input(&self) -> OrdinaryProofCoinInput {
        self.proof_coin_input
    }

    pub(crate) fn proof_attempt_identifier(
        &self,
    ) -> Result<PrivateRandomnessAttemptIdentifier, BallotValidityAdapterError> {
        self.action_private_randomness
            .ordinary_proof_attempt_identifier(&self.proof_coin_input)
            .map_err(BallotValidityAdapterError::from)
    }

    pub(crate) const fn encryption_randomness_cursors(&self) -> [PrivateRandomCursor; 3] {
        self.encryption_randomness_cursors
    }

    pub(crate) const fn generated_ciphertext(&self) -> &BallotValidityGeneratedCiphertext {
        &self.generated_ciphertext
    }

    pub(crate) fn source_polynomial_provider(
        &self,
        compilation: &CompiledBallotValidityRelation,
    ) -> Result<BallotValiditySourcePolynomialAdapter, BallotValidityAdapterError> {
        BallotValiditySourcePolynomialAdapter::from_canonical_ballot_statement(
            compilation,
            self.application_slot,
            &self.canonical_application_statement_bytes,
            decode_selected_ballot_validity_statement(
                &self.canonical_application_statement_bytes,
                SelectedApplicationStatementContext::new(
                    self.public_material.protocol_version,
                    self.public_material.suite_identifier,
                    None,
                    None,
                ),
            )
            .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?
            .roster_hash(),
            self.action_private_randomness
                .derivation_input()
                .participant_identity()
                .into_bytes(),
            self.witness.clone(),
            self.public_material.clone(),
        )
    }

    pub(crate) fn private_coin_source(
        &self,
        compilation: &CompiledBallotValidityRelation,
        pre_output_generation_binding_hash: [u8; 64],
    ) -> Result<PrivateRandomnessCommonProofCoinSource, BallotValidityAdapterError> {
        if pre_output_generation_binding_hash == [0_u8; 64] {
            return Err(BallotValidityAdapterError::InvalidStatementBinding);
        }
        let variant = compilation.relation_plan().select_variant(None, None)?;
        let coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(variant)
                .map_err(|_| BallotValidityAdapterError::InvalidColumn)?;
        PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&self.action_private_randomness),
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            Hash512::from_bytes(pre_output_generation_binding_hash),
            self.proof_attempt_identifier()?,
            coordinate_capacity,
        )
        .map_err(BallotValidityAdapterError::from)
    }

    pub(crate) fn prepare_fresh_common_generation(
        &self,
        compilation: &CompiledBallotValidityRelation,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
        checkpoint_lineage_identifier: [u8; 32],
    ) -> Result<PreparedCommonProofGeneration, BallotValidityGenerationPreparationError> {
        if checkpoint_lineage_identifier == [0_u8; 32] {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        let checkpoint_schedule_digest = relation_plan.checkpoint_schedule_digest(limits)?;
        self.prepare_common_generation_with_continuation(
            compilation,
            relation_plan,
            limits,
            AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
            ),
        )
    }

    pub(crate) fn prepare_common_generation_with_continuation(
        &self,
        compilation: &CompiledBallotValidityRelation,
        relation_plan: CommonProofRelationPlanCapability,
        limits: CommonProofRuntimeLimits,
        checkpoint_continuation: AuthenticatedCheckpointContinuationSource,
    ) -> Result<PreparedCommonProofGeneration, BallotValidityGenerationPreparationError> {
        let proof_query_count = relation_plan.proof_query_count()?;
        if checkpoint_continuation.checkpoint_schedule_digest()
            != relation_plan.checkpoint_schedule_digest(limits)?
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding.into());
        }
        let attempt_source = resolve_prepared_ordinary_proof_attempt_source(
            &self.action_private_randomness,
            self.proof_coin_input,
            u64::try_from(limits.proof_byte_length())
                .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
            proof_query_count,
            checkpoint_continuation,
        )
        .map_err(BallotValidityAdapterError::from)?;
        let authorization =
            CommonProofGenerationAuthorization::from_ordinary_authenticated_attempt(
                attempt_source,
                &relation_plan,
                self.public_material.protocol_version,
                &self.canonical_application_statement_bytes,
                limits,
            )?;
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .map_err(BallotValidityAdapterError::from)?;
        let relation_trees = proof_created_relation_tree_inputs_from_checked_variant(variant)?;
        let private_coins = self.private_coin_source(compilation, authorization.binding_hash())?;
        let source_polynomials = self.source_polynomial_provider(compilation)?;
        PreparedCommonProofGeneration::from_exact_family_sources(
            authorization,
            relation_plan,
            self.canonical_application_statement_bytes.clone(),
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(BallotValidityGenerationPreparationError::from)
    }
}

impl BallotValidityGeneratedCiphertext {
    pub(crate) fn encrypt(
        source_plan: &BallotValiditySourcePlan,
        authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
        expected_setup_binding: BallotValidityAcceptedSetupBinding,
        witness: &BallotValidityEncryptionAttemptWitness,
    ) -> Result<Self, BallotValidityAdapterError> {
        let public_key_polynomials =
            verified_public_key_polynomials(source_plan, authority_handle, expected_setup_binding)?;
        Self::encrypt_with_public_key_polynomials(source_plan, public_key_polynomials, witness)
    }

    fn encrypt_with_public_key_polynomials(
        source_plan: &BallotValiditySourcePlan,
        public_key_polynomials: Vec<(u16, u16, u64, Arc<[u64]>)>,
        witness: &BallotValidityEncryptionAttemptWitness,
    ) -> Result<Self, BallotValidityAdapterError> {
        let public_key_by_limb = checked_polynomial_sequence(source_plan, public_key_polynomials)?;
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let plaintext_modulus = i64::try_from(source_plan.plaintext_modulus())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let mut ciphertext_by_limb = Vec::with_capacity(source_plan.data_moduli().len());
        for (data_modulus_ordinal, modulus) in source_plan.data_moduli().iter().copied().enumerate()
        {
            let public_key_limb = public_key_by_limb
                .get(data_modulus_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
            let randomizer_residues = Zeroizing::new(
                witness
                    .randomizer_coefficients()
                    .iter()
                    .copied()
                    .map(|coefficient| signed_residue(coefficient, modulus))
                    .collect::<Vec<_>>(),
            );
            let mut component_zero = negacyclic_mul(
                &public_key_limb[0].coefficients,
                &randomizer_residues,
                modulus,
            )?;
            let mut component_one = match negacyclic_mul(
                &public_key_limb[1].coefficients,
                &randomizer_residues,
                modulus,
            ) {
                Ok(component) => component,
                Err(error) => {
                    component_zero.zeroize();
                    return Err(error.into());
                }
            };
            if component_zero.len() != ring_degree || component_one.len() != ring_degree {
                component_zero.zeroize();
                component_one.zeroize();
                return Err(BallotValidityAdapterError::InvalidPublicMaterial);
            }
            let complete_ciphertext_components = (|| {
                for coefficient_ordinal in 0..ring_degree {
                    let scaled_error_zero = witness.error_zero_coefficients()[coefficient_ordinal]
                        .checked_mul(plaintext_modulus)
                        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
                    let scaled_error_one = witness.error_one_coefficients()[coefficient_ordinal]
                        .checked_mul(plaintext_modulus)
                        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
                    component_zero[coefficient_ordinal] = add_mod(
                        add_mod(
                            component_zero[coefficient_ordinal],
                            signed_residue(scaled_error_zero, modulus),
                            modulus,
                        )?,
                        witness.plaintext_coefficients()[coefficient_ordinal],
                        modulus,
                    )?;
                    component_one[coefficient_ordinal] = add_mod(
                        component_one[coefficient_ordinal],
                        signed_residue(scaled_error_one, modulus),
                        modulus,
                    )?;
                }
                Ok::<(), BallotValidityAdapterError>(())
            })();
            if let Err(error) = complete_ciphertext_components {
                component_zero.zeroize();
                component_one.zeroize();
                return Err(error);
            }
            ciphertext_by_limb.push([
                Arc::<[u64]>::from(component_zero),
                Arc::<[u64]>::from(component_one),
            ]);
        }

        let mut polynomials = Vec::with_capacity(ciphertext_by_limb.len() * 2);
        for component_ordinal in 0..2_u16 {
            for (data_modulus_ordinal, (modulus, components)) in source_plan
                .data_moduli()
                .iter()
                .copied()
                .zip(&ciphertext_by_limb)
                .enumerate()
            {
                polynomials.push((
                    component_ordinal,
                    u16::try_from(data_modulus_ordinal)
                        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                    modulus,
                    Arc::clone(&components[usize::from(component_ordinal)]),
                ));
            }
        }
        let mut authenticated_ciphertext = BallotValidityAuthenticatedCiphertext {
            full_object_digest: [0_u8; 64],
            polynomials,
        };
        let total_byte_length = ballot_ciphertext_total_byte_length(
            source_plan,
            &authenticated_ciphertext.polynomials,
        )?;
        let mut writer =
            CanonicalStreamWriter::new(CanonicalStreamDomain::BallotCiphertext, total_byte_length)
                .map_err(BallotValidityAdapterError::Stream)?;
        let mut readback =
            BallotValidityCiphertextReadback::new(source_plan, authenticated_ciphertext.clone())?;
        let mut chunk_index = 0_usize;
        while let Some(chunk) = readback.next_chunk()? {
            writer
                .absorb_chunk(chunk_index, &chunk)
                .map_err(BallotValidityAdapterError::Stream)?;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
        }
        let descriptor = writer
            .finish()
            .map_err(BallotValidityAdapterError::Stream)?;
        authenticated_ciphertext.full_object_digest = descriptor.full_object_digest.into_bytes();
        Ok(Self {
            descriptor,
            authenticated_ciphertext,
        })
    }

    pub(crate) const fn descriptor(&self) -> &StreamDescriptor {
        &self.descriptor
    }

    pub(crate) fn authenticated_ciphertext(&self) -> BallotValidityAuthenticatedCiphertext {
        self.authenticated_ciphertext.clone()
    }

    pub(crate) fn begin_readback(
        &self,
        source_plan: &BallotValiditySourcePlan,
    ) -> Result<BallotValidityCiphertextReadback, BallotValidityAdapterError> {
        BallotValidityCiphertextReadback::new(source_plan, self.authenticated_ciphertext.clone())
    }
}

pub(crate) struct BallotValidityCiphertextReadback {
    header: [u8; 4],
    header_byte_offset: usize,
    polynomials: Box<[(u16, u16, u64, Arc<[u64]>)]>,
    polynomial_ordinal: usize,
    coefficient_ordinal: usize,
    coefficient_byte_offset: usize,
}

impl BallotValidityCiphertextReadback {
    fn new(
        source_plan: &BallotValiditySourcePlan,
        ciphertext: BallotValidityAuthenticatedCiphertext,
    ) -> Result<Self, BallotValidityAdapterError> {
        require_checked_polynomial_sequence(source_plan, &ciphertext.polynomials)?;
        let level = source_plan
            .active_data_modulus_indices()
            .len()
            .checked_sub(1)
            .and_then(|level| u16::try_from(level).ok())
            .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
        let mut header = [0_u8; 4];
        header[..2].copy_from_slice(&level.to_le_bytes());
        header[2..].copy_from_slice(&2_u16.to_le_bytes());
        Ok(Self {
            header,
            header_byte_offset: 0,
            polynomials: ciphertext.polynomials.into_boxed_slice(),
            polynomial_ordinal: 0,
            coefficient_ordinal: 0,
            coefficient_byte_offset: 0,
        })
    }

    pub(crate) fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, BallotValidityAdapterError> {
        if self.header_byte_offset == self.header.len()
            && self.polynomial_ordinal == self.polynomials.len()
        {
            return Ok(None);
        }
        let mut chunk = Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length);
        while chunk.len() < FOUNDATION_PROFILE.stream_chunk_byte_length {
            if self.header_byte_offset < self.header.len() {
                let remaining_capacity = FOUNDATION_PROFILE
                    .stream_chunk_byte_length
                    .checked_sub(chunk.len())
                    .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
                let copied = remaining_capacity.min(self.header.len() - self.header_byte_offset);
                chunk.extend_from_slice(
                    &self.header[self.header_byte_offset..self.header_byte_offset + copied],
                );
                self.header_byte_offset += copied;
                continue;
            }
            let Some((_, _, modulus, coefficients)) = self.polynomials.get(self.polynomial_ordinal)
            else {
                break;
            };
            let coefficient = *coefficients
                .get(self.coefficient_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
            let coefficient_bytes = coefficient.to_le_bytes();
            let coefficient_byte_length = canonical_modulus_byte_length(*modulus);
            let remaining_capacity = FOUNDATION_PROFILE
                .stream_chunk_byte_length
                .checked_sub(chunk.len())
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
            let copied =
                remaining_capacity.min(coefficient_byte_length - self.coefficient_byte_offset);
            chunk.extend_from_slice(
                &coefficient_bytes
                    [self.coefficient_byte_offset..self.coefficient_byte_offset + copied],
            );
            self.coefficient_byte_offset += copied;
            if self.coefficient_byte_offset != coefficient_byte_length {
                continue;
            }
            self.coefficient_byte_offset = 0;
            self.coefficient_ordinal += 1;
            if self.coefficient_ordinal == coefficients.len() {
                self.coefficient_ordinal = 0;
                self.polynomial_ordinal += 1;
            }
        }
        if chunk.is_empty() {
            return Err(BallotValidityAdapterError::InvalidPublicMaterial);
        }
        Ok(Some(chunk))
    }
}

/// Incremental decoder for the exact ballot ciphertext carrier.
///
/// Each incoming chunk is authenticated before its coefficients are parsed.
/// The decoder retains only the resulting residue polynomials and a partial
/// fixed-width coefficient; it never assembles the complete carrier bytes.
pub(crate) struct BallotValidityCiphertextStreamDecoder {
    canonical_stream: CanonicalStreamVerifier,
    full_object_digest: [u8; 64],
    expected_level: u16,
    ring_degree: usize,
    data_moduli: Arc<[u64]>,
    header: [u8; 4],
    header_byte_length: usize,
    component_ordinal: u16,
    data_modulus_ordinal: usize,
    coefficient_ordinal: usize,
    partial_coefficient: [u8; 8],
    partial_coefficient_byte_length: usize,
    current_polynomial: Vec<u64>,
    polynomials: Vec<(u16, u16, u64, Arc<[u64]>)>,
    refusal_reason: Option<RefusalReason>,
}

impl BallotValidityCiphertextStreamDecoder {
    pub(crate) fn new(
        source_plan: &BallotValiditySourcePlan,
        descriptor: StreamDescriptor,
    ) -> Result<Self, RefusalReason> {
        let ring_degree = usize::try_from(source_plan.ring_degree())
            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
        let expected_level = source_plan
            .active_data_modulus_indices()
            .len()
            .checked_sub(1)
            .and_then(|level| u16::try_from(level).ok())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if source_plan
            .active_data_modulus_indices()
            .iter()
            .copied()
            .enumerate()
            .any(|(ordinal, data_modulus_index)| {
                u16::try_from(ordinal).ok() != Some(data_modulus_index)
            })
        {
            return Err(RefusalReason::UnsupportedVersionOrSuite);
        }
        let expected_total_byte_length =
            source_plan
                .data_moduli()
                .iter()
                .try_fold(4_u64, |byte_length, modulus| {
                    let coefficient_byte_length =
                        u64::try_from(canonical_modulus_byte_length(*modulus))
                            .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                    let polynomial_byte_length = u64::try_from(ring_degree)
                        .map_err(|_| RefusalReason::OutsideSupportedProfile)?
                        .checked_mul(coefficient_byte_length)
                        .ok_or(RefusalReason::OutsideSupportedProfile)?;
                    byte_length
                        .checked_add(
                            polynomial_byte_length
                                .checked_mul(2)
                                .ok_or(RefusalReason::OutsideSupportedProfile)?,
                        )
                        .ok_or(RefusalReason::OutsideSupportedProfile)
                })?;
        if descriptor.total_byte_length != expected_total_byte_length {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        let full_object_digest = descriptor.full_object_digest.into_bytes();
        let canonical_stream =
            CanonicalStreamVerifier::new(CanonicalStreamDomain::BallotCiphertext, descriptor)?;
        Ok(Self {
            canonical_stream,
            full_object_digest,
            expected_level,
            ring_degree,
            data_moduli: source_plan.data_moduli().to_vec().into(),
            header: [0_u8; 4],
            header_byte_length: 0,
            component_ordinal: 0,
            data_modulus_ordinal: 0,
            coefficient_ordinal: 0,
            partial_coefficient: [0_u8; 8],
            partial_coefficient_byte_length: 0,
            current_polynomial: Vec::with_capacity(ring_degree),
            polynomials: Vec::with_capacity(source_plan.data_moduli().len() * 2),
            refusal_reason: None,
        })
    }

    pub(crate) fn absorb_chunk(
        &mut self,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> VerificationResult<()> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        if let Err(refusal_reason) = self
            .canonical_stream
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .and_then(|()| self.absorb_authenticated_bytes(chunk_bytes))
        {
            self.refusal_reason = Some(refusal_reason);
            return VerificationResult::refused(refusal_reason);
        }
        VerificationResult::valid(())
    }

    pub(crate) fn finish(self) -> VerificationResult<BallotValidityAuthenticatedCiphertext> {
        if let Some(refusal_reason) = self.refusal_reason {
            return VerificationResult::refused(refusal_reason);
        }
        if self.header_byte_length != self.header.len()
            || self.component_ordinal != 2
            || self.data_modulus_ordinal != 0
            || self.coefficient_ordinal != 0
            || self.partial_coefficient_byte_length != 0
            || !self.current_polynomial.is_empty()
            || self.polynomials.len() != self.data_moduli.len() * 2
        {
            return VerificationResult::refused(RefusalReason::WrongTypeOrLength);
        }
        if let Err(refusal_reason) = self.canonical_stream.finish().into_result() {
            return VerificationResult::refused(refusal_reason);
        }
        VerificationResult::valid(BallotValidityAuthenticatedCiphertext {
            full_object_digest: self.full_object_digest,
            polynomials: self.polynomials,
        })
    }

    fn absorb_authenticated_bytes(&mut self, bytes: &[u8]) -> Result<(), RefusalReason> {
        let mut byte_offset = 0;
        if self.header_byte_length < self.header.len() {
            let consumed = (self.header.len() - self.header_byte_length).min(bytes.len());
            self.header[self.header_byte_length..self.header_byte_length + consumed]
                .copy_from_slice(&bytes[..consumed]);
            self.header_byte_length += consumed;
            byte_offset += consumed;
            if self.header_byte_length == self.header.len() {
                let level = u16::from_le_bytes([self.header[0], self.header[1]]);
                let component_count = u16::from_le_bytes([self.header[2], self.header[3]]);
                if level != self.expected_level || component_count != 2 {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
            }
        }

        while byte_offset < bytes.len() {
            if self.component_ordinal >= 2 {
                return Err(RefusalReason::WrongTypeOrLength);
            }
            let modulus = *self
                .data_moduli
                .get(self.data_modulus_ordinal)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let coefficient_byte_length = canonical_modulus_byte_length(modulus);
            let consumed = (coefficient_byte_length - self.partial_coefficient_byte_length)
                .min(bytes.len() - byte_offset);
            self.partial_coefficient[self.partial_coefficient_byte_length
                ..self.partial_coefficient_byte_length + consumed]
                .copy_from_slice(&bytes[byte_offset..byte_offset + consumed]);
            self.partial_coefficient_byte_length += consumed;
            byte_offset += consumed;
            if self.partial_coefficient_byte_length != coefficient_byte_length {
                continue;
            }

            let coefficient = u64::from_le_bytes(self.partial_coefficient);
            if coefficient >= modulus {
                return Err(RefusalReason::MalformedEncoding);
            }
            self.current_polynomial.push(coefficient);
            self.coefficient_ordinal += 1;
            self.partial_coefficient = [0_u8; 8];
            self.partial_coefficient_byte_length = 0;
            if self.coefficient_ordinal == self.ring_degree {
                let coefficients = core::mem::replace(
                    &mut self.current_polynomial,
                    Vec::with_capacity(self.ring_degree),
                );
                let data_modulus_index = u16::try_from(self.data_modulus_ordinal)
                    .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
                self.polynomials.push((
                    self.component_ordinal,
                    data_modulus_index,
                    modulus,
                    coefficients.into(),
                ));
                self.coefficient_ordinal = 0;
                self.data_modulus_ordinal += 1;
                if self.data_modulus_ordinal == self.data_moduli.len() {
                    self.data_modulus_ordinal = 0;
                    self.component_ordinal += 1;
                }
            }
        }
        Ok(())
    }
}

fn ballot_ciphertext_total_byte_length(
    source_plan: &BallotValiditySourcePlan,
    polynomials: &[(u16, u16, u64, Arc<[u64]>)],
) -> Result<u64, BallotValidityAdapterError> {
    let coefficient_byte_length = polynomials.iter().try_fold(0_u64, |total, entry| {
        let polynomial_byte_length = u64::try_from(entry.3.len())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?
            .checked_mul(
                u64::try_from(canonical_modulus_byte_length(entry.2))
                    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
            )
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
        total
            .checked_add(polynomial_byte_length)
            .ok_or(BallotValidityAdapterError::IntegerOverflow)
    })?;
    let expected_polynomial_count = source_plan
        .data_moduli()
        .len()
        .checked_mul(2)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    if polynomials.len() != expected_polynomial_count {
        return Err(BallotValidityAdapterError::InvalidPublicMaterial);
    }
    coefficient_byte_length
        .checked_add(4)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)
}

fn verified_public_key_polynomials(
    source_plan: &BallotValiditySourcePlan,
    authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
    expected_setup_binding: BallotValidityAcceptedSetupBinding,
) -> Result<Vec<(u16, u16, u64, Arc<[u64]>)>, BallotValidityAdapterError> {
    with_verified_accepted_setup_authority(authority_handle, |authority| {
        let expected_ring_degree = usize::try_from(source_plan.ring_degree()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "ballot relation ring degree does not fit this runtime",
            )
        })?;
        if authority.protocol_version() != expected_setup_binding.protocol_version
            || authority.suite_identifier() != expected_setup_binding.suite_identifier
            || authority.ceremony_context_hash() != expected_setup_binding.ceremony_context_hash
            || authority.action_context_hash() != expected_setup_binding.action_context_hash
            || authority.roster_hash() != expected_setup_binding.roster_hash
            || authority.exact_verified_setup_source_hash()
                != expected_setup_binding.exact_verified_setup_source_hash
            || authority.ring_degree() != expected_ring_degree
            || authority.ordered_data_modulus_indices() != source_plan.active_data_modulus_indices()
            || authority.ordered_data_moduli() != source_plan.data_moduli()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "ballot statement and accepted-setup authority bindings differ",
            ));
        }
        let mut readback = authority.begin_collective_public_key_readback()?;
        let polynomial_count = source_plan
            .active_data_modulus_indices()
            .len()
            .checked_mul(2)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "collective public-key polynomial count overflows",
                )
            })?;
        let mut polynomials = Vec::with_capacity(polynomial_count);
        while let Some(polynomial) = readback.next_polynomial()? {
            polynomials.push((
                polynomial.component_ordinal(),
                polynomial.data_modulus_index(),
                polynomial.modulus(),
                Arc::clone(polynomial.coefficients()),
            ));
        }
        readback.finish()?;
        Ok(polynomials)
    })
    .map_err(BallotValidityAdapterError::Canonical)
}

impl BallotValidityBoundPublicMaterial {
    pub(crate) fn from_verified_accepted_setup(
        source_plan: &BallotValiditySourcePlan,
        authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
        expected_setup_binding: BallotValidityAcceptedSetupBinding,
        authenticated_ciphertext: BallotValidityAuthenticatedCiphertext,
    ) -> Result<Self, BallotValidityAdapterError> {
        let public_key_polynomials =
            verified_public_key_polynomials(source_plan, authority_handle, expected_setup_binding)?;
        Self::from_authenticated_polynomial_sequences(
            source_plan,
            expected_setup_binding.protocol_version,
            expected_setup_binding.suite_identifier,
            expected_setup_binding.exact_verified_setup_source_hash,
            authenticated_ciphertext.full_object_digest,
            public_key_polynomials,
            authenticated_ciphertext.polynomials,
        )
    }

    fn from_authenticated_polynomial_sequences(
        source_plan: &BallotValiditySourcePlan,
        protocol_version: u16,
        suite_identifier: [u8; 64],
        verified_setup_source_hash: [u8; 64],
        ballot_ciphertext_digest: [u8; 64],
        public_key_polynomials: Vec<(u16, u16, u64, Arc<[u64]>)>,
        ciphertext_polynomials: Vec<(u16, u16, u64, Arc<[u64]>)>,
    ) -> Result<Self, BallotValidityAdapterError> {
        if protocol_version == 0
            || suite_identifier == [0_u8; 64]
            || verified_setup_source_hash == [0_u8; 64]
            || ballot_ciphertext_digest == [0_u8; 64]
        {
            return Err(BallotValidityAdapterError::InvalidPublicMaterial);
        }
        let public_key_by_limb =
            checked_polynomial_sequence(source_plan, public_key_polynomials)?.into_boxed_slice();
        let ciphertext_by_limb =
            checked_polynomial_sequence(source_plan, ciphertext_polynomials)?.into_boxed_slice();
        Ok(Self {
            protocol_version,
            suite_identifier,
            verified_setup_source_hash,
            ballot_ciphertext_digest,
            public_key_by_limb,
            ciphertext_by_limb,
        })
    }

    pub(crate) const fn verified_setup_source_hash(&self) -> [u8; 64] {
        self.verified_setup_source_hash
    }

    pub(crate) const fn ballot_ciphertext_digest(&self) -> [u8; 64] {
        self.ballot_ciphertext_digest
    }

    pub(crate) fn authenticated_ciphertext_catalog(
        &self,
    ) -> Result<Vec<(u16, u16, u64, Arc<[u64]>)>, BallotValidityAdapterError> {
        let mut catalog = Vec::with_capacity(self.ciphertext_by_limb.len() * 2);
        for component_ordinal in 0..2_u16 {
            for (data_modulus_index, limb) in self.ciphertext_by_limb.iter().enumerate() {
                let polynomial = &limb[usize::from(component_ordinal)];
                catalog.push((
                    component_ordinal,
                    u16::try_from(data_modulus_index)
                        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
                    polynomial.modulus,
                    Arc::clone(&polynomial.coefficients),
                ));
            }
        }
        Ok(catalog)
    }

    fn polynomial(
        &self,
        source_kind: u16,
        component_ordinal: u16,
        data_modulus_index: u16,
    ) -> Option<&BoundResiduePolynomial> {
        let limbs = match source_kind {
            1 => &self.public_key_by_limb,
            2 => &self.ciphertext_by_limb,
            _ => return None,
        };
        limbs
            .get(usize::from(data_modulus_index))?
            .get(usize::from(component_ordinal))
    }
}

fn checked_polynomial_sequence(
    source_plan: &BallotValiditySourcePlan,
    polynomials: Vec<(u16, u16, u64, Arc<[u64]>)>,
) -> Result<Vec<[BoundResiduePolynomial; 2]>, BallotValidityAdapterError> {
    require_checked_polynomial_sequence(source_plan, &polynomials)?;
    let mut ordered_polynomials = polynomials.into_iter();
    let mut components_by_limb = (0..source_plan.data_moduli().len())
        .map(|_| [None, None])
        .collect::<Vec<[Option<BoundResiduePolynomial>; 2]>>();
    for component_ordinal in 0_u16..2 {
        for limb_ordinal in 0..source_plan.data_moduli().len() {
            let (_, _, modulus, coefficients) = ordered_polynomials
                .next()
                .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
            components_by_limb[limb_ordinal][usize::from(component_ordinal)] =
                Some(BoundResiduePolynomial {
                    modulus,
                    coefficients,
                });
        }
    }
    components_by_limb
        .into_iter()
        .map(|[component_zero, component_one]| {
            Ok([
                component_zero.ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?,
                component_one.ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?,
            ])
        })
        .collect()
}

fn require_checked_polynomial_sequence(
    source_plan: &BallotValiditySourcePlan,
    polynomials: &[(u16, u16, u64, Arc<[u64]>)],
) -> Result<(), BallotValidityAdapterError> {
    let ring_degree = usize::try_from(source_plan.ring_degree())
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    let expected_count = source_plan
        .active_data_modulus_indices()
        .len()
        .checked_mul(2)
        .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
    if polynomials.len() != expected_count {
        return Err(BallotValidityAdapterError::InvalidPublicMaterial);
    }

    let mut ordered_polynomials = polynomials.iter();
    for component_ordinal in 0_u16..2 {
        for (data_modulus_index, modulus) in source_plan
            .active_data_modulus_indices()
            .iter()
            .copied()
            .zip(source_plan.data_moduli().iter().copied())
        {
            let (observed_component, observed_data_modulus_index, observed_modulus, coefficients) =
                ordered_polynomials
                    .next()
                    .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
            if *observed_component != component_ordinal
                || *observed_data_modulus_index != data_modulus_index
                || *observed_modulus != modulus
                || coefficients.len() != ring_degree
                || coefficients
                    .iter()
                    .any(|coefficient| *coefficient >= modulus)
            {
                return Err(BallotValidityAdapterError::InvalidPublicMaterial);
            }
        }
    }
    if ordered_polynomials.next().is_some() {
        return Err(BallotValidityAdapterError::InvalidPublicMaterial);
    }
    Ok(())
}

/// Restartable, plan-derived source provider for the ballot family.
pub(crate) struct BallotValiditySourcePolynomialAdapter {
    source_plan: BallotValiditySourcePlan,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    application_statement_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    restart_binding_hash: [u8; 64],
    witness: Option<BallotValidityEncryptionAttemptWitness>,
    public_material: BallotValidityBoundPublicMaterial,
    trace_domain: ProofEvaluationDomain,
    convolution_domain: ProofEvaluationDomain,
    randomizer_convolution_evaluations: Option<Zeroizing<Vec<ProofBaseFieldElement>>>,
    cached_value_source: Option<(BallotValidityWitnessValueSource, Zeroizing<Vec<i128>>)>,
    ordered_source_columns: Box<[(u32, RelationColumnDescriptor)]>,
    next_source_column_position: usize,
}

impl BallotValiditySourcePolynomialAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_canonical_ballot_statement(
        compilation: &CompiledBallotValidityRelation,
        application_slot: ProofApplicationSlot,
        canonical_application_statement_bytes: &[u8],
        expected_roster_hash: [u8; 64],
        expected_participant_identity: [u8; 64],
        witness: BallotValidityEncryptionAttemptWitness,
        public_material: BallotValidityBoundPublicMaterial,
    ) -> Result<Self, BallotValidityAdapterError> {
        let context = SelectedApplicationStatementContext::new(
            public_material.protocol_version,
            public_material.suite_identifier,
            None,
            None,
        );
        let statement = decode_selected_ballot_validity_statement(
            canonical_application_statement_bytes,
            context,
        )
        .map_err(|_| BallotValidityAdapterError::InvalidStatementBinding)?;
        if application_slot.application_statement_schema_identifier()
            != crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
            || application_slot.suite_identifier().into_bytes() != statement.suite_identifier()
            || application_slot.ceremony_context_hash().into_bytes()
                != statement.ceremony_context_hash()
            || application_slot.action_context_hash().into_bytes() != statement.action_context_hash()
            || application_slot.schedule_position().is_some()
            || application_slot.roster_position().is_none()
            || application_slot.producer_sequence() != Some(statement.producer_sequence())
            || statement.protocol_version() != public_material.protocol_version
            || statement.suite_identifier() != public_material.suite_identifier
            || statement.roster_hash() != expected_roster_hash
            || statement.participant_identity() != expected_participant_identity
            || statement.verified_setup_source_hash()
                != public_material.verified_setup_source_hash
            || statement.ballot_ciphertext_full_object_digest()
                != public_material.ballot_ciphertext_digest
        {
            return Err(BallotValidityAdapterError::InvalidStatementBinding);
        }
        let application_statement_hash = verified_application_statement_hash(
            statement.protocol_version(),
            statement.suite_identifier(),
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            canonical_application_statement_bytes,
        );
        Self::from_bound_inputs(
            compilation,
            statement.protocol_version(),
            statement.suite_identifier(),
            application_statement_hash,
            witness,
            public_material,
        )
    }

    fn from_bound_inputs(
        compilation: &CompiledBallotValidityRelation,
        protocol_version: u16,
        suite_identifier: [u8; 64],
        application_statement_hash: [u8; 64],
        witness: BallotValidityEncryptionAttemptWitness,
        public_material: BallotValidityBoundPublicMaterial,
    ) -> Result<Self, BallotValidityAdapterError> {
        if compilation
            .relation_plan()
            .application_statement_schema_identifier()
            != crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
            || protocol_version == 0
            || suite_identifier == [0_u8; 64]
            || application_statement_hash == [0_u8; 64]
            || public_material.protocol_version != protocol_version
            || public_material.suite_identifier != suite_identifier
        {
            return Err(BallotValidityAdapterError::WrongApplication);
        }
        let variant = compilation.relation_plan().select_variant(None, None)?;
        if variant.trace_domain_size() != compilation.source_plan().ring_degree() {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        validate_material_against_source_plan(compilation.source_plan(), &public_material)?;

        let trace_size = usize::try_from(compilation.source_plan().ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let convolution_size = trace_size
            .checked_mul(2)
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
        let trace_domain = ProofEvaluationDomain::new_subgroup(trace_size)?;
        let convolution_domain = ProofEvaluationDomain::new_subgroup(convolution_size)?;
        let mut randomizer_convolution_evaluations = Zeroizing::new(Vec::with_capacity(trace_size));
        for coefficient in witness.randomizer_coefficients().iter().copied() {
            randomizer_convolution_evaluations
                .push(base_field_from_signed(i128::from(coefficient))?);
        }
        convolution_domain
            .evaluate_base_polynomial_in_place(&mut randomizer_convolution_evaluations)?;
        let relation_plan_variant_hash = variant.canonical_hash()?;
        let relation_plan_hash = compilation.relation_plan().canonical_hash()?;
        let ordered_source_columns = variant
            .ordered_columns()
            .iter()
            .enumerate()
            .map(|(column_index, descriptor)| {
                let column_ordinal = u32::try_from(column_index)
                    .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
                Ok(compilation
                    .source_plan()
                    .has_source(column_ordinal)
                    .then(|| (column_ordinal, descriptor.clone())))
            })
            .collect::<Result<Vec<_>, BallotValidityAdapterError>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .into_boxed_slice();
        if ordered_source_columns.is_empty()
            || ordered_source_columns.len() != compilation.source_plan().provided_column_count()
        {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        let restart_binding_hash = hash_framed_parts_512(
            BALLOT_SOURCE_RESTART_BINDING_DOMAIN,
            &[
                &application_statement_hash,
                &relation_plan_variant_hash,
                &public_material.verified_setup_source_hash,
                &public_material.ballot_ciphertext_digest,
                &witness.encryption_attempt_identifier(),
            ],
        );
        Ok(Self {
            source_plan: compilation.source_plan().clone(),
            protocol_version,
            suite_identifier,
            application_statement_hash,
            relation_plan_hash,
            relation_plan_variant_hash,
            restart_binding_hash,
            witness: Some(witness),
            public_material,
            trace_domain,
            convolution_domain,
            randomizer_convolution_evaluations: Some(randomizer_convolution_evaluations),
            cached_value_source: None,
            ordered_source_columns,
            next_source_column_position: 0,
        })
    }

    fn retained_witness(
        &self,
    ) -> Result<&BallotValidityEncryptionAttemptWitness, BallotValidityAdapterError> {
        self.witness
            .as_ref()
            .ok_or(BallotValidityAdapterError::InvalidWitness)
    }

    fn release_secret_material(&mut self) {
        self.cached_value_source.take();
        self.randomizer_convolution_evaluations.take();
        self.witness.take();
    }

    #[cfg(test)]
    fn secret_material_is_released(&self) -> bool {
        self.cached_value_source.is_none()
            && self.randomizer_convolution_evaluations.is_none()
            && self.witness.is_none()
    }

    pub(crate) const fn restart_binding_hash(&self) -> [u8; 64] {
        self.restart_binding_hash
    }

    pub(crate) fn source_polynomial_replay_identity(
        &self,
        column_ordinal: u32,
    ) -> Result<[u8; 64], BallotValidityAdapterError> {
        let descriptor = self
            .ordered_source_columns
            .iter()
            .find(|(candidate_ordinal, _)| *candidate_ordinal == column_ordinal)
            .map(|(_, descriptor)| descriptor)
            .ok_or(BallotValidityAdapterError::InvalidColumn)?;
        let recipe = self.source_plan.recipe(column_ordinal);
        let verifier_source = self.source_plan.verifier_source(column_ordinal);
        validate_source_descriptor(
            descriptor,
            self.source_plan.ring_degree(),
            verifier_source.is_some(),
        )?;
        let descriptor_bytes = descriptor
            .canonical_tuple()?
            .encode()
            .map_err(|_| BallotValidityAdapterError::InvalidColumn)?;
        let source_derivation_bytes =
            canonical_source_derivation_bytes(recipe, verifier_source)?;
        Ok(hash_framed_parts_512(
            BALLOT_SOURCE_POLYNOMIAL_REPLAY_DOMAIN,
            &[
                &self.restart_binding_hash,
                &column_ordinal.to_le_bytes(),
                &descriptor_bytes,
                &source_derivation_bytes,
            ],
        ))
    }

    fn derive_source_polynomial(
        &mut self,
        column_ordinal: u32,
    ) -> Result<CommonProofSourcePolynomial, BallotValidityAdapterError> {
        let descriptor = self
            .ordered_source_columns
            .iter()
            .find(|(candidate_ordinal, _)| *candidate_ordinal == column_ordinal)
            .map(|(_, descriptor)| descriptor)
            .ok_or(BallotValidityAdapterError::InvalidColumn)?;
        let recipe = self.source_plan.recipe(column_ordinal);
        let verifier_source = self.source_plan.verifier_source(column_ordinal);
        validate_source_descriptor(
            descriptor,
            self.source_plan.ring_degree(),
            verifier_source.is_some(),
        )?;
        let mut coefficients = match (recipe, verifier_source) {
            (Some(recipe), None) => {
                let values = self.values_for_source(recipe.value_source())?;
                let mut coefficients = Vec::with_capacity(values.len());
                for value in values.iter().copied() {
                    match transform_source_value(value, recipe.transform())
                        .and_then(base_field_from_signed)
                    {
                        Ok(coefficient) => coefficients.push(coefficient),
                        Err(error) => {
                            coefficients.zeroize();
                            return Err(error);
                        }
                    }
                }
                coefficients
            }
            (None, Some(verifier_source)) => verifier_source_trace_rows(
                &self.source_plan,
                &self.public_material,
                verifier_source,
            )?,
            _ => return Err(BallotValidityAdapterError::InvalidColumn),
        };
        if let Err(error) = self
            .trace_domain
            .interpolate_base_polynomial_in_place(&mut coefficients)
        {
            coefficients.zeroize();
            return Err(error.into());
        }
        Ok(CommonProofSourcePolynomial::from_base_coefficients(
            coefficients,
        ))
    }

    fn values_for_source(
        &mut self,
        source: BallotValidityWitnessValueSource,
    ) -> Result<&[i128], BallotValidityAdapterError> {
        if self
            .cached_value_source
            .as_ref()
            .is_none_or(|(cached_source, _)| *cached_source != source)
        {
            self.cached_value_source.take();
            let values = self.derive_source_values(source)?;
            self.cached_value_source = Some((source, values));
        }
        self.cached_value_source
            .as_ref()
            .map(|(_, values)| values.as_slice())
            .ok_or(BallotValidityAdapterError::InvalidWitness)
    }

    fn derive_source_values(
        &self,
        source: BallotValidityWitnessValueSource,
    ) -> Result<Zeroizing<Vec<i128>>, BallotValidityAdapterError> {
        let ring_degree = usize::try_from(self.source_plan.ring_degree())
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        let witness = self.retained_witness()?;
        match source {
            BallotValidityWitnessValueSource::ScoreOffset { option_ordinal } => {
                let score = witness
                    .scores()
                    .get(usize::from(option_ordinal))
                    .copied()
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                Ok(Zeroizing::new(vec![
                    i128::from(score - MINIMUM_SCORE);
                    ring_degree
                ]))
            }
            BallotValidityWitnessValueSource::PlaintextCoefficient => Ok(Zeroizing::new(
                witness
                    .plaintext_coefficients()
                    .iter()
                    .copied()
                    .map(i128::from)
                    .collect(),
            )),
            BallotValidityWitnessValueSource::ReversedRandomizerShifted => Ok(Zeroizing::new(
                witness
                    .randomizer_coefficients()
                    .iter()
                    .rev()
                    .map(|coefficient| i128::from(*coefficient) + 1)
                    .collect(),
            )),
            BallotValidityWitnessValueSource::ErrorZeroShifted => Ok(Zeroizing::new(
                witness
                    .error_zero_coefficients()
                    .iter()
                    .map(|coefficient| i128::from(*coefficient) + 2)
                    .collect(),
            )),
            BallotValidityWitnessValueSource::ErrorOneShifted => Ok(Zeroizing::new(
                witness
                    .error_one_coefficients()
                    .iter()
                    .map(|coefficient| i128::from(*coefficient) + 2)
                    .collect(),
            )),
            BallotValidityWitnessValueSource::EncoderReduction => {
                let reductions = self
                    .source_plan
                    .encoder_reductions_for_scores(
                        witness.scores(),
                        witness.plaintext_coefficients(),
                    )
                    .ok_or(BallotValidityAdapterError::InvalidWitness)?;
                Ok(Zeroizing::new(
                    reductions.into_iter().map(i128::from).collect(),
                ))
            }
            BallotValidityWitnessValueSource::EncryptionQuotient {
                data_modulus_index,
                component_ordinal,
            } => self.encryption_quotient(data_modulus_index, component_ordinal),
        }
    }

    fn encryption_quotient(
        &self,
        data_modulus_index: u16,
        component_ordinal: u16,
    ) -> Result<Zeroizing<Vec<i128>>, BallotValidityAdapterError> {
        let public_key = self
            .public_material
            .polynomial(1, component_ordinal, data_modulus_index)
            .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
        let ciphertext = self
            .public_material
            .polynomial(2, component_ordinal, data_modulus_index)
            .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
        if public_key.modulus != ciphertext.modulus {
            return Err(BallotValidityAdapterError::InvalidPublicMaterial);
        }
        let mut quotient = self.exact_negacyclic_product(public_key)?;
        let witness = self.retained_witness()?;
        let error_coefficients = match component_ordinal {
            0 => witness.error_zero_coefficients(),
            1 => witness.error_one_coefficients(),
            _ => return Err(BallotValidityAdapterError::InvalidPublicMaterial),
        };
        let modulus = i128::from(public_key.modulus);
        let plaintext_modulus = i128::from(self.source_plan.plaintext_modulus());
        for (coefficient_ordinal, ciphertext_coefficient) in
            ciphertext.coefficients.iter().copied().enumerate()
        {
            let plaintext = if component_ordinal == 0 {
                i128::from(witness.plaintext_coefficients()[coefficient_ordinal])
            } else {
                0
            };
            let numerator = i128::from(ciphertext_coefficient)
                .checked_sub(quotient[coefficient_ordinal])
                .and_then(|value| value.checked_sub(plaintext))
                .and_then(|value| {
                    value.checked_sub(
                        plaintext_modulus * i128::from(error_coefficients[coefficient_ordinal]),
                    )
                })
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
            if numerator % modulus != 0 {
                return Err(BallotValidityAdapterError::InvalidWitness);
            }
            quotient[coefficient_ordinal] = numerator / modulus;
        }
        Ok(quotient)
    }

    fn exact_negacyclic_product(
        &self,
        public_polynomial: &BoundResiduePolynomial,
    ) -> Result<Zeroizing<Vec<i128>>, BallotValidityAdapterError> {
        let witness = self.retained_witness()?;
        let randomizer_l1_norm = witness
            .randomizer_coefficients()
            .iter()
            .try_fold(0_u128, |sum, coefficient| {
                sum.checked_add(u128::from(coefficient.unsigned_abs()))
            })
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
        let maximum_absolute_product = randomizer_l1_norm
            .checked_mul(u128::from(public_polynomial.modulus - 1))
            .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
        if maximum_absolute_product >= u128::from(PROOF_BASE_FIELD_MODULUS / 2) {
            return Err(BallotValidityAdapterError::NoWrapBoundViolated);
        }

        let mut product_evaluations =
            Zeroizing::new(Vec::with_capacity(public_polynomial.coefficients.len()));
        for coefficient in public_polynomial.coefficients.iter().copied() {
            product_evaluations.push(ProofBaseFieldElement::from_canonical(coefficient)?);
        }
        self.convolution_domain
            .evaluate_base_polynomial_in_place(&mut product_evaluations)?;
        let randomizer_convolution_evaluations =
            self.randomizer_convolution_evaluations
                .as_ref()
                .ok_or(BallotValidityAdapterError::InvalidWitness)?;
        if product_evaluations.len() != randomizer_convolution_evaluations.len() {
            return Err(BallotValidityAdapterError::InvalidPublicMaterial);
        }
        for (product, randomizer) in product_evaluations
            .iter_mut()
            .zip(randomizer_convolution_evaluations.iter())
        {
            *product = product.multiply(*randomizer);
        }
        self.convolution_domain
            .interpolate_base_polynomial_in_place(&mut product_evaluations)?;
        product_evaluations.resize(self.convolution_domain.size(), ProofBaseFieldElement::ZERO);
        let ring_degree = self.trace_domain.size();
        let mut product = Zeroizing::new(Vec::with_capacity(ring_degree));
        for coefficient_ordinal in 0..ring_degree {
            product.push(centered_base_field_value(
                product_evaluations[coefficient_ordinal]
                    .subtract(product_evaluations[coefficient_ordinal + ring_degree]),
            )?);
        }
        Ok(product)
    }
}

impl Drop for BallotValiditySourcePolynomialAdapter {
    fn drop(&mut self) {
        self.release_secret_material();
    }
}

impl CommonProofSourcePolynomialProvider for BallotValiditySourcePolynomialAdapter {
    fn persistent_resident_memory_byte_length(&self) -> Result<u64, CommonProofProverError> {
        ballot_validity_carrier_buffer_accounting(&self.source_plan)
            .map(SelectedBallotValidityCarrierBufferAccounting::provider_loading_persistent_resident_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)
    }

    fn post_source_polynomial_finish_persistent_resident_memory_byte_length(
        &self,
    ) -> Result<u64, CommonProofProverError> {
        ballot_validity_carrier_buffer_accounting(&self.source_plan)
            .map(SelectedBallotValidityCarrierBufferAccounting::provider_post_source_finish_persistent_resident_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)
    }

    fn loading_source_polynomials_transient_byte_length(
        &self,
    ) -> Result<u64, CommonProofProverError> {
        ballot_validity_carrier_buffer_accounting(&self.source_plan)
            .map(SelectedBallotValidityCarrierBufferAccounting::provider_additional_loading_transient_byte_length)
            .map_err(|_| CommonProofProverError::CountOverflow)
    }

    fn poll_source_polynomial(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<CommonProofSourcePolynomialProviderPoll, CommonProofProverError> {
        let result = self.provide_source_polynomial_once(request);
        if result.is_err() {
            self.release_secret_material();
        }
        result.map(CommonProofSourcePolynomialProviderPoll::Ready)
    }

    fn finish(&mut self) -> Result<(), CommonProofProverError> {
        let result = if self.next_source_column_position == self.ordered_source_columns.len() {
            Ok(())
        } else {
            Err(CommonProofProverError::InvalidColumn)
        };
        self.release_secret_material();
        result
    }
}

impl BallotValiditySourcePolynomialAdapter {
    fn provide_source_polynomial_once(
        &mut self,
        request: CommonProofSourcePolynomialRequest<'_>,
    ) -> Result<ProvidedCommonProofSourcePolynomial, CommonProofProverError> {
        let expected_column_ordinal = self
            .ordered_source_columns
            .get(self.next_source_column_position)
            .map(|(column_ordinal, _)| *column_ordinal)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        let expected_descriptor = self
            .ordered_source_columns
            .get(self.next_source_column_position)
            .map(|(_, descriptor)| descriptor)
            .ok_or(CommonProofProverError::InvalidColumn)?;
        if request.protocol_version() != self.protocol_version
            || request.suite_identifier() != self.suite_identifier
            || request.application_statement_schema_identifier()
                != crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
            || request.application_statement_hash() != self.application_statement_hash
            || request.relation_plan_hash() != self.relation_plan_hash
            || request.relation_plan_variant_hash() != self.relation_plan_variant_hash
            || request.schedule_position().is_some()
            || request.top_count().is_some()
            || request.column_ordinal() != expected_column_ordinal
            || request.descriptor() != expected_descriptor
        {
            return Err(CommonProofProverError::InvalidColumn);
        }
        let replay_identity = CommonProofSourcePolynomialReplayIdentity::from_authenticated_source(
            self.source_polynomial_replay_identity(expected_column_ordinal)
                .map_err(|_| CommonProofProverError::InvalidColumn)?,
        )?;
        let polynomial = self
            .derive_source_polynomial(expected_column_ordinal)
            .map_err(|_| CommonProofProverError::InvalidColumn)?;
        self.next_source_column_position += 1;
        Ok(ProvidedCommonProofSourcePolynomial::new(
            polynomial,
            replay_identity,
        ))
    }
}

fn validate_material_against_source_plan(
    source_plan: &BallotValiditySourcePlan,
    public_material: &BallotValidityBoundPublicMaterial,
) -> Result<(), BallotValidityAdapterError> {
    let expected_limb_count = source_plan.active_data_modulus_indices().len();
    if public_material.public_key_by_limb.len() != expected_limb_count
        || public_material.ciphertext_by_limb.len() != expected_limb_count
    {
        return Err(BallotValidityAdapterError::InvalidPublicMaterial);
    }
    for (limb_ordinal, modulus) in source_plan.data_moduli().iter().copied().enumerate() {
        for source in [
            &public_material.public_key_by_limb[limb_ordinal],
            &public_material.ciphertext_by_limb[limb_ordinal],
        ] {
            if source
                .iter()
                .any(|polynomial| polynomial.modulus != modulus)
            {
                return Err(BallotValidityAdapterError::InvalidPublicMaterial);
            }
        }
    }
    Ok(())
}

fn validate_source_descriptor(
    descriptor: &RelationColumnDescriptor,
    ring_degree: u64,
    is_verifier_source: bool,
) -> Result<(), BallotValidityAdapterError> {
    let origin_matches_source = if is_verifier_source {
        matches!(descriptor.origin(), RelationColumnOrigin::VerifierSequence { .. })
    } else {
        matches!(descriptor.origin(), RelationColumnOrigin::Prover)
    };
    if !origin_matches_source
        || descriptor.value_type() != RelationColumnValueType::BaseField
        || descriptor.canonical_residue_modulus().is_some() != is_verifier_source
        || descriptor.source_degree_bound_exclusive() < ring_degree
    {
        return Err(BallotValidityAdapterError::InvalidColumn);
    }
    Ok(())
}

fn transform_source_value(
    value: i128,
    transform: BallotValidityColumnTransform,
) -> Result<i128, BallotValidityAdapterError> {
    match transform {
        BallotValidityColumnTransform::Identity => Ok(value),
        BallotValidityColumnTransform::UnsignedRadixDigit { digit_ordinal } => {
            if value < 0 {
                return Err(BallotValidityAdapterError::InvalidWitness);
            }
            Ok(radix_digit(value, digit_ordinal)?)
        }
        BallotValidityColumnTransform::ShiftedRadixDigit {
            offset,
            digit_ordinal,
        } => {
            let shifted = value
                .checked_add(i128::from(offset))
                .ok_or(BallotValidityAdapterError::IntegerOverflow)?;
            if shifted < 0 {
                return Err(BallotValidityAdapterError::InvalidWitness);
            }
            Ok(radix_digit(shifted, digit_ordinal)?)
        }
        BallotValidityColumnTransform::UpperBoundDifferenceDigit {
            maximum,
            digit_ordinal,
        } => comparator_digit(value, maximum, digit_ordinal, true),
        BallotValidityColumnTransform::UpperBoundBorrow {
            maximum,
            digit_ordinal,
        } => comparator_digit(value, maximum, digit_ordinal, false),
    }
}

fn comparator_digit(
    value: i128,
    maximum: u64,
    requested_digit_ordinal: u16,
    return_difference: bool,
) -> Result<i128, BallotValidityAdapterError> {
    if value < 0 || value > i128::from(maximum) {
        return Err(BallotValidityAdapterError::InvalidWitness);
    }
    let digit_count = radix_digit_count_for_adapter(maximum);
    if usize::from(requested_digit_ordinal) >= digit_count {
        return Err(BallotValidityAdapterError::InvalidColumn);
    }
    let mut incoming_borrow = 0_i128;
    for digit_ordinal in 0..digit_count {
        let maximum_digit = radix_digit(i128::from(maximum), digit_ordinal as u16)?;
        let value_digit = radix_digit(value, digit_ordinal as u16)?;
        let raw_difference = maximum_digit - value_digit - incoming_borrow;
        let outgoing_borrow = i128::from(raw_difference < 0);
        let difference = raw_difference + RADIX * outgoing_borrow;
        if digit_ordinal == usize::from(requested_digit_ordinal) {
            return Ok(if return_difference {
                difference
            } else {
                outgoing_borrow
            });
        }
        incoming_borrow = outgoing_borrow;
    }
    Err(BallotValidityAdapterError::InvalidColumn)
}

fn radix_digit(value: i128, digit_ordinal: u16) -> Result<i128, BallotValidityAdapterError> {
    let divisor = (0..digit_ordinal).try_fold(1_i128, |power, _| {
        power
            .checked_mul(RADIX)
            .ok_or(BallotValidityAdapterError::IntegerOverflow)
    })?;
    Ok((value / divisor) % RADIX)
}

fn radix_digit_count_for_adapter(maximum: u64) -> usize {
    let mut count = 1_usize;
    let mut power = 3_u128;
    while power <= u128::from(maximum) {
        count += 1;
        power *= 3;
    }
    count
}

fn base_field_from_signed(
    value: i128,
) -> Result<ProofBaseFieldElement, BallotValidityAdapterError> {
    let modulus = i128::from(PROOF_BASE_FIELD_MODULUS);
    if value <= -modulus || value >= modulus {
        return Err(BallotValidityAdapterError::NoWrapBoundViolated);
    }
    let canonical = u64::try_from(value.rem_euclid(modulus))
        .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
    Ok(ProofBaseFieldElement::from_canonical(canonical)?)
}

fn centered_base_field_value(
    value: ProofBaseFieldElement,
) -> Result<i128, BallotValidityAdapterError> {
    let canonical = value.canonical();
    if canonical <= PROOF_BASE_FIELD_MODULUS / 2 {
        Ok(i128::from(canonical))
    } else {
        Ok(i128::from(canonical) - i128::from(PROOF_BASE_FIELD_MODULUS))
    }
}

fn canonical_recipe_bytes(recipe: BallotValiditySourceColumnRecipe) -> Vec<u8> {
    let mut bytes = Vec::new();
    match recipe.value_source() {
        BallotValidityWitnessValueSource::ScoreOffset { option_ordinal } => {
            bytes.extend_from_slice(&1_u16.to_le_bytes());
            bytes.extend_from_slice(&option_ordinal.to_le_bytes());
        }
        BallotValidityWitnessValueSource::PlaintextCoefficient => {
            bytes.extend_from_slice(&2_u16.to_le_bytes());
        }
        BallotValidityWitnessValueSource::ReversedRandomizerShifted => {
            bytes.extend_from_slice(&3_u16.to_le_bytes());
        }
        BallotValidityWitnessValueSource::ErrorZeroShifted => {
            bytes.extend_from_slice(&4_u16.to_le_bytes());
        }
        BallotValidityWitnessValueSource::ErrorOneShifted => {
            bytes.extend_from_slice(&5_u16.to_le_bytes());
        }
        BallotValidityWitnessValueSource::EncoderReduction => {
            bytes.extend_from_slice(&6_u16.to_le_bytes());
        }
        BallotValidityWitnessValueSource::EncryptionQuotient {
            data_modulus_index,
            component_ordinal,
        } => {
            bytes.extend_from_slice(&7_u16.to_le_bytes());
            bytes.extend_from_slice(&data_modulus_index.to_le_bytes());
            bytes.extend_from_slice(&component_ordinal.to_le_bytes());
        }
    }
    match recipe.transform() {
        BallotValidityColumnTransform::Identity => bytes.extend_from_slice(&1_u16.to_le_bytes()),
        BallotValidityColumnTransform::UnsignedRadixDigit { digit_ordinal } => {
            bytes.extend_from_slice(&2_u16.to_le_bytes());
            bytes.extend_from_slice(&digit_ordinal.to_le_bytes());
        }
        BallotValidityColumnTransform::ShiftedRadixDigit {
            offset,
            digit_ordinal,
        } => {
            bytes.extend_from_slice(&3_u16.to_le_bytes());
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(&digit_ordinal.to_le_bytes());
        }
        BallotValidityColumnTransform::UpperBoundDifferenceDigit {
            maximum,
            digit_ordinal,
        } => {
            bytes.extend_from_slice(&4_u16.to_le_bytes());
            bytes.extend_from_slice(&maximum.to_le_bytes());
            bytes.extend_from_slice(&digit_ordinal.to_le_bytes());
        }
        BallotValidityColumnTransform::UpperBoundBorrow {
            maximum,
            digit_ordinal,
        } => {
            bytes.extend_from_slice(&5_u16.to_le_bytes());
            bytes.extend_from_slice(&maximum.to_le_bytes());
            bytes.extend_from_slice(&digit_ordinal.to_le_bytes());
        }
    }
    bytes
}

fn canonical_source_derivation_bytes(
    recipe: Option<BallotValiditySourceColumnRecipe>,
    verifier_source: Option<BallotValidityVerifierColumnSource>,
) -> Result<Vec<u8>, BallotValidityAdapterError> {
    match (recipe, verifier_source) {
        (Some(recipe), None) => {
            let mut bytes = vec![1_u8];
            bytes.extend_from_slice(&canonical_recipe_bytes(recipe));
            Ok(bytes)
        }
        (None, Some(verifier_source)) => {
            let mut bytes = vec![2_u8];
            bytes.extend_from_slice(&canonical_verifier_source_bytes(verifier_source));
            Ok(bytes)
        }
        _ => Err(BallotValidityAdapterError::InvalidColumn),
    }
}

fn canonical_verifier_source_bytes(source: BallotValidityVerifierColumnSource) -> Vec<u8> {
    let mut bytes = Vec::new();
    match source {
        BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
            source_kind,
            component_ordinal,
            data_modulus_index,
        } => {
            bytes.extend_from_slice(&1_u16.to_le_bytes());
            bytes.extend_from_slice(&source_kind.to_le_bytes());
            bytes.extend_from_slice(&component_ordinal.to_le_bytes());
            bytes.extend_from_slice(&data_modulus_index.to_le_bytes());
        }
        BallotValidityVerifierColumnSource::PairDifferenceEncoderWeight { option_ordinal } => {
            bytes.extend_from_slice(&2_u16.to_le_bytes());
            bytes.extend_from_slice(&option_ordinal.to_le_bytes());
        }
    }
    bytes
}

fn verifier_source_trace_rows(
    source_plan: &BallotValiditySourcePlan,
    public_material: &BallotValidityBoundPublicMaterial,
    source: BallotValidityVerifierColumnSource,
) -> Result<Vec<ProofBaseFieldElement>, BallotValidityAdapterError> {
    let residues = match source {
        BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
            source_kind,
            component_ordinal,
            data_modulus_index,
        } => public_material
            .polynomial(source_kind, component_ordinal, data_modulus_index)
            .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?
            .coefficients
            .to_vec(),
        BallotValidityVerifierColumnSource::PairDifferenceEncoderWeight { option_ordinal } => {
            source_plan
                .encoder_weight_sequence(option_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidColumn)?
        }
    };
    residues
        .into_iter()
        .map(ProofBaseFieldElement::from_canonical)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

struct CachedEvaluationDomainColumn {
    domain: ProofEvaluationDomain,
    evaluations: Vec<ProofBaseFieldElement>,
}

/// Verifier-sequence adapter rebuilt only from authenticated setup and ballot
/// ciphertext material. It retains at most one coefficient polynomial and one
/// evaluation vector per public column, with all underlying residue bytes
/// shared through `Arc`.
pub(crate) struct BallotValidityVerifiedColumnEvaluator {
    source_plan: BallotValiditySourcePlan,
    public_material: BallotValidityBoundPublicMaterial,
    trace_domain: ProofEvaluationDomain,
    source_by_column: Vec<Option<BallotValidityVerifierColumnSource>>,
    coefficients_by_column: Vec<Option<Vec<ProofBaseFieldElement>>>,
    evaluations_by_column: Vec<Option<CachedEvaluationDomainColumn>>,
}

impl BallotValidityVerifiedColumnEvaluator {
    pub(crate) fn new(
        compilation: &CompiledBallotValidityRelation,
        expected_verified_setup_source_hash: [u8; 64],
        expected_ballot_ciphertext_digest: [u8; 64],
        public_material: BallotValidityBoundPublicMaterial,
    ) -> Result<Self, BallotValidityAdapterError> {
        if expected_verified_setup_source_hash != public_material.verified_setup_source_hash
            || expected_ballot_ciphertext_digest != public_material.ballot_ciphertext_digest
        {
            return Err(BallotValidityAdapterError::InvalidStatementBinding);
        }
        validate_material_against_source_plan(compilation.source_plan(), &public_material)?;
        let variant = compilation.relation_plan().select_variant(None, None)?;
        let mut source_by_column = (0..variant.ordered_columns().len())
            .map(|_| None)
            .collect::<Vec<_>>();
        let mut verifier_source_count = 0;
        for (column_index, descriptor) in variant.ordered_columns().iter().enumerate() {
            let RelationColumnOrigin::VerifierSequence {
                verifier_source_ordinal,
                first_logical_element_index,
                logical_element_stride,
            } = descriptor.origin()
            else {
                continue;
            };
            if *first_logical_element_index != 0
                || *logical_element_stride != 1
                || descriptor.value_type() != RelationColumnValueType::BaseField
                || descriptor.source_degree_bound_exclusive()
                    != compilation.source_plan().ring_degree()
            {
                return Err(BallotValidityAdapterError::InvalidColumn);
            }
            let source = variant
                .verifier_source(*verifier_source_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidColumn)?;
            let column_ordinal = u32::try_from(column_index)
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
            let planned_source = compilation
                .source_plan()
                .verifier_source(column_ordinal)
                .ok_or(BallotValidityAdapterError::InvalidColumn)?;
            match (planned_source, source) {
                (
                    BallotValidityVerifierColumnSource::AuthenticatedPolynomial {
                        source_kind,
                        component_ordinal,
                        data_modulus_index,
                    },
                    RelationVerifierSource::Protocol {
                        protocol_source_kind,
                        source_coordinates,
                        statement_binding_path,
                        ..
                    },
                ) => {
                    let expected_field_ordinal = match source_kind {
                        1 => VERIFIED_SETUP_SOURCE_HASH_FIELD_ORDINAL,
                        2 => BALLOT_CIPHERTEXT_DIGEST_FIELD_ORDINAL,
                        _ => return Err(BallotValidityAdapterError::InvalidColumn),
                    };
                    if *protocol_source_kind != source_kind
                        || source_coordinates
                            != &[u64::from(component_ordinal), u64::from(data_modulus_index)]
                        || statement_binding_path.len() != 1
                        || statement_binding_path[0].step_kind()
                            != SelectorPathStepKind::TupleField
                        || statement_binding_path[0].argument() != expected_field_ordinal
                    {
                        return Err(BallotValidityAdapterError::InvalidColumn);
                    }
                    let polynomial = public_material
                        .polynomial(source_kind, component_ordinal, data_modulus_index)
                        .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?;
                    if descriptor.canonical_residue_modulus()
                        != Some(SuiteModulusReference::data(data_modulus_index))
                        || polynomial.modulus
                            != compilation
                                .source_plan()
                                .data_moduli()
                                .get(usize::from(data_modulus_index))
                                .copied()
                                .ok_or(BallotValidityAdapterError::InvalidPublicMaterial)?
                    {
                        return Err(BallotValidityAdapterError::InvalidPublicMaterial);
                    }
                }
                (
                    BallotValidityVerifierColumnSource::PairDifferenceEncoderWeight {
                        option_ordinal,
                    },
                    RelationVerifierSource::DirectBallotPairDifferenceEncoderWeights {
                        ring_degree,
                        primitive_two_n_root,
                        slot_generator,
                        option_count,
                        option_ordinal: declared_option_ordinal,
                    },
                ) => {
                    if *ring_degree != compilation.source_plan().ring_degree()
                        || *primitive_two_n_root
                            != compilation.source_plan().primitive_two_n_root()
                        || *slot_generator != compilation.source_plan().slot_generator()
                        || usize::from(*option_count) != OPTION_COUNT
                        || *declared_option_ordinal != option_ordinal
                        || descriptor.canonical_residue_modulus()
                            != Some(SuiteModulusReference::plaintext())
                        || compilation
                            .source_plan()
                            .encoder_weight_sequence(option_ordinal)
                            .is_none()
                    {
                        return Err(BallotValidityAdapterError::InvalidColumn);
                    }
                }
                _ => return Err(BallotValidityAdapterError::InvalidColumn),
            }
            if source_by_column[column_index]
                .replace(planned_source)
                .is_some()
            {
                return Err(BallotValidityAdapterError::InvalidColumn);
            }
            verifier_source_count += 1;
        }
        if verifier_source_count != variant.ordered_verifier_sources.len() {
            return Err(BallotValidityAdapterError::InvalidColumn);
        }
        let trace_domain = ProofEvaluationDomain::new_subgroup(
            usize::try_from(compilation.source_plan().ring_degree())
                .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?,
        )?;
        Ok(Self {
            source_plan: compilation.source_plan().clone(),
            public_material,
            trace_domain,
            source_by_column,
            coefficients_by_column: (0..variant.ordered_columns().len()).map(|_| None).collect(),
            evaluations_by_column: (0..variant.ordered_columns().len()).map(|_| None).collect(),
        })
    }

    fn coefficients(
        &mut self,
        column_ordinal: u32,
    ) -> Result<&[ProofBaseFieldElement], BallotValidityAdapterError> {
        let column_index = usize::try_from(column_ordinal)
            .map_err(|_| BallotValidityAdapterError::IntegerOverflow)?;
        if self
            .coefficients_by_column
            .get(column_index)
            .ok_or(BallotValidityAdapterError::InvalidColumn)?
            .is_none()
        {
            let source = self
                .source_by_column
                .get(column_index)
                .and_then(Option::as_ref)
                .copied()
                .ok_or(BallotValidityAdapterError::InvalidColumn)?;
            let rows = verifier_source_trace_rows(
                &self.source_plan,
                &self.public_material,
                source,
            )?;
            let coefficients = self.trace_domain.interpolate_base_polynomial(&rows)?;
            self.coefficients_by_column[column_index] = Some(coefficients);
        }
        self.coefficients_by_column
            .get(column_index)
            .and_then(Option::as_deref)
            .ok_or(BallotValidityAdapterError::InvalidColumn)
    }
}

impl VerifiedRelationColumnEvaluator for BallotValidityVerifiedColumnEvaluator {
    fn evaluate_at_extension_point(
        &mut self,
        column_ordinal: u32,
        point: ProofChallengeExtensionElement,
    ) -> Option<ProofChallengeExtensionElement> {
        let coefficients = self.coefficients(column_ordinal).ok()?;
        Some(coefficients.iter().rev().fold(
            ProofChallengeExtensionElement::ZERO,
            |accumulated, coefficient| {
                accumulated
                    .multiply(point)
                    .add(ProofChallengeExtensionElement::from_base(*coefficient))
            },
        ))
    }

    fn evaluate_at_evaluation_domain_pair(
        &mut self,
        column_ordinal: u32,
        evaluation_domain: ProofEvaluationDomain,
        query_representative: u64,
    ) -> Option<OpenedFriLayerPair> {
        let query_representative = usize::try_from(query_representative).ok()?;
        let half_domain_size = evaluation_domain.size().checked_div(2)?;
        if query_representative >= half_domain_size {
            return None;
        }
        let needs_evaluation = self
            .evaluations_by_column
            .get(column_ordinal as usize)
            .and_then(Option::as_ref)
            .is_none_or(|cached| cached.domain != evaluation_domain);
        if needs_evaluation {
            let coefficients = self.coefficients(column_ordinal).ok()?.to_vec();
            let evaluations = evaluation_domain
                .evaluate_base_polynomial(&coefficients)
                .ok()?;
            *self
                .evaluations_by_column
                .get_mut(column_ordinal as usize)? = Some(CachedEvaluationDomainColumn {
                domain: evaluation_domain,
                evaluations,
            });
        }
        let cached = self
            .evaluations_by_column
            .get(column_ordinal as usize)?
            .as_ref()?;
        Some(OpenedFriLayerPair::new(
            ProofChallengeExtensionElement::from_base(
                *cached.evaluations.get(query_representative)?,
            ),
            ProofChallengeExtensionElement::from_base(
                *cached
                    .evaluations
                    .get(query_representative + half_domain_size)?,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::{
        CommonProofPrivateCoinCoordinate, CommonProofPrivateCoinSource,
        CommonProofSourcePolynomialRequestContext, construct_pre_challenge_relation_columns,
    };

    struct DeterministicPrivateCoins(u64);

    impl CommonProofPrivateCoinSource for DeterministicPrivateCoins {
        type Error = ();

        fn sample_modulo(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            modulus: u64,
            _maximum_candidate_draws_per_output: u32,
        ) -> Result<u64, Self::Error> {
            let value = self.0 % modulus;
            self.0 = self.0.wrapping_add(1);
            Ok(value)
        }

        fn fill_raw_bytes(
            &mut self,
            _coordinate: CommonProofPrivateCoinCoordinate,
            destination: &mut [u8],
        ) -> Result<(), Self::Error> {
            for byte in destination {
                *byte = self.0 as u8;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn selected_ballot_carrier_accounting_matches_production_buffers() {
        let accounting = selected_ballot_validity_carrier_buffer_accounting()
            .expect("selected ballot carrier accounting derives");
        assert_eq!(accounting.canonical_ciphertext_byte_length(), 22_675_460);
        assert_eq!(accounting.canonical_ciphertext_chunk_count(), 22);
        assert!(accounting.canonical_ciphertext_descriptor_encoded_byte_length() > 0);
        assert_eq!(
            accounting.canonical_ciphertext_descriptor_digest_catalog_byte_length(),
            22 * u64::try_from(size_of::<Hash512>()).expect("hash width fits u64")
                + 2 * u64::try_from(size_of::<usize>()).expect("word width fits u64")
        );
        assert_eq!(
            accounting.ciphertext_readback_polynomial_catalog_byte_length(),
            u64::try_from(
                2 * selected_ballot_validity_relation_compilation()
                    .expect("selected compilation derives")
                    .source_plan()
                    .data_moduli()
                    .len(),
            )
            .expect("catalog length fits u64")
                * u64::try_from(size_of::<(u16, u16, u64, Arc<[u64]>)>())
                    .expect("entry width fits u64")
        );
        assert_eq!(
            accounting.decoded_ciphertext_residue_byte_length(),
            27_262_976,
        );
        assert_eq!(
            accounting.provider_bound_public_residue_byte_length(),
            54_525_952,
        );
        assert_eq!(
            accounting.provider_witness_coefficient_byte_length(),
            2_097_152,
        );
        assert_eq!(
            accounting.provider_precomputed_transform_byte_length(),
            1_048_576,
        );
        assert_eq!(accounting.provider_value_cache_byte_length(), 1_048_576);
        assert_eq!(
            accounting.provider_transient_scratch_byte_length(),
            1_048_576,
        );
        assert_eq!(
            accounting.provider_buffer_live_set_peak_byte_length(),
            59_768_832,
        );
        assert_eq!(
            accounting.transferred_source_polynomial_byte_length(),
            524_288,
        );
        assert_eq!(
            accounting.maximum_boundary_copied_buffer_byte_length(),
            1_048_576,
        );
    }

    const TEST_RING_DEGREE: u64 = 64;
    const TEST_PLAINTEXT_MODULUS: u64 = 257;
    const TEST_DATA_MODULUS: u64 = 769;
    const TEST_EVALUATION_DOMAIN_SIZE: u64 = 1_024;

    fn check_context() -> RelationPlanCheckContext {
        let maximum_two_adic_order = 1_u64 << 32;
        RelationPlanCheckContext {
            base_field_modulus: PROOF_BASE_FIELD_MODULUS,
            challenge_extension_degree: crate::bgv::proof_suite::PROOF_CHALLENGE_EXTENSION_DEGREE
                as u16,
            evaluation_blowup_factor: 2,
            evaluation_domain_generator: modular_power(
                crate::bgv::proof_suite::PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                maximum_two_adic_order / TEST_EVALUATION_DOMAIN_SIZE,
                PROOF_BASE_FIELD_MODULUS,
            ),
            evaluation_coset_offset: 7,
            deep_point_count: 1,
            quotient_component_count: 4,
            quotient_component_degree_bound_exclusive: 256,
            fri_fold_count: 6,
            final_polynomial_degree_bound_exclusive: 8,
            unique_query_count: 8,
            non_native_modular_identity_challenge_count: 1,
            maximum_fiat_shamir_candidate_draws_per_output: 128,
            resolved_moduli: vec![
                ResolvedSuiteModulus::new(SuiteModulusReference::data(0), TEST_DATA_MODULUS),
                ResolvedSuiteModulus::new(
                    SuiteModulusReference::plaintext(),
                    TEST_PLAINTEXT_MODULUS,
                ),
            ],
        }
    }

    fn compilation() -> CompiledBallotValidityRelation {
        compile_ballot_validity_relation(
            &BallotValidityRelationPlanInput {
                ring_degree: TEST_RING_DEGREE,
                evaluation_domain_size: TEST_EVALUATION_DOMAIN_SIZE,
                opening_degree_bound_exclusive: 512,
                active_data_modulus_indices: vec![0],
                plaintext_modulus: TEST_PLAINTEXT_MODULUS,
                primitive_two_n_root: 9,
                slot_generator: 3,
                reserved_slot_rule: 1,
            },
            &check_context(),
        )
        .expect("ballot relation compilation")
    }

    fn witness(
        compilation: &CompiledBallotValidityRelation,
    ) -> BallotValidityEncryptionAttemptWitness {
        let scores = (0..OPTION_COUNT)
            .map(|option_ordinal| 1 + (option_ordinal as u64 * 7 + 3) % 10)
            .collect::<Vec<_>>();
        let plaintext_coefficients = (0..TEST_RING_DEGREE as usize)
            .map(|coefficient_ordinal| {
                scores
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(option_ordinal, score)| {
                        modular_product_for_adapter(
                            score,
                            compilation
                                .source_plan()
                                .encoder_weight(option_ordinal as u16, coefficient_ordinal)
                                .expect("weight"),
                            TEST_PLAINTEXT_MODULUS,
                        )
                    })
                    .fold(0_u64, |sum, term| (sum + term) % TEST_PLAINTEXT_MODULUS)
            })
            .collect::<Vec<_>>();
        let randomizer_coefficients = (0..TEST_RING_DEGREE)
            .map(|ordinal| [-1_i64, 0, 1][ordinal as usize % 3])
            .collect::<Vec<_>>();
        let error_zero_coefficients = (0..TEST_RING_DEGREE)
            .map(|ordinal| [-2_i64, -1, 0, 1, 2][ordinal as usize % 5])
            .collect::<Vec<_>>();
        let error_one_coefficients = (0..TEST_RING_DEGREE)
            .map(|ordinal| [2_i64, 0, -2, 1, -1][ordinal as usize % 5])
            .collect::<Vec<_>>();
        BallotValidityEncryptionAttemptWitness::from_encryption_attempt(
            compilation.source_plan(),
            &scores,
            plaintext_coefficients,
            randomizer_coefficients,
            error_zero_coefficients,
            error_one_coefficients,
            [41_u8; 32],
        )
        .expect("valid witness")
    }

    fn dense_negacyclic_product(left: &[u64], right: &[i64]) -> Vec<i128> {
        let ring_degree = left.len();
        let mut product = vec![0_i128; ring_degree];
        for (left_ordinal, left_value) in left.iter().copied().enumerate() {
            for (right_ordinal, right_value) in right.iter().copied().enumerate() {
                let ordinary_ordinal = left_ordinal + right_ordinal;
                let destination = ordinary_ordinal % ring_degree;
                let sign = if ordinary_ordinal < ring_degree {
                    1
                } else {
                    -1
                };
                product[destination] += sign * i128::from(left_value) * i128::from(right_value);
            }
        }
        product
    }

    fn public_material(
        compilation: &CompiledBallotValidityRelation,
        witness: &BallotValidityEncryptionAttemptWitness,
    ) -> BallotValidityBoundPublicMaterial {
        let public_zero = (0..TEST_RING_DEGREE)
            .map(|ordinal| (ordinal * 29 + 17) % TEST_DATA_MODULUS)
            .collect::<Vec<_>>();
        let public_one = (0..TEST_RING_DEGREE)
            .map(|ordinal| (ordinal * ordinal + 31) % TEST_DATA_MODULUS)
            .collect::<Vec<_>>();
        let products = [
            dense_negacyclic_product(&public_zero, witness.randomizer_coefficients()),
            dense_negacyclic_product(&public_one, witness.randomizer_coefficients()),
        ];
        let ciphertext = products
            .iter()
            .enumerate()
            .map(|(component_ordinal, product)| {
                product
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(coefficient_ordinal, product)| {
                        let error = if component_ordinal == 0 {
                            witness.error_zero_coefficients()[coefficient_ordinal]
                        } else {
                            witness.error_one_coefficients()[coefficient_ordinal]
                        };
                        let plaintext = if component_ordinal == 0 {
                            witness.plaintext_coefficients()[coefficient_ordinal]
                        } else {
                            0
                        };
                        let value = product
                            + i128::from(TEST_PLAINTEXT_MODULUS) * i128::from(error)
                            + i128::from(plaintext);
                        u64::try_from(value.rem_euclid(i128::from(TEST_DATA_MODULUS)))
                            .expect("canonical residue")
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        BallotValidityBoundPublicMaterial::from_authenticated_polynomial_sequences(
            compilation.source_plan(),
            1,
            [17_u8; 64],
            [19_u8; 64],
            [23_u8; 64],
            vec![
                (0, 0, TEST_DATA_MODULUS, public_zero.into()),
                (1, 0, TEST_DATA_MODULUS, public_one.into()),
            ],
            vec![
                (0, 0, TEST_DATA_MODULUS, ciphertext[0].clone().into()),
                (1, 0, TEST_DATA_MODULUS, ciphertext[1].clone().into()),
            ],
        )
        .expect("authenticated public material")
    }

    fn ballot_ciphertext_stream_bytes(material: &BallotValidityBoundPublicMaterial) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        for component_ordinal in 0..2 {
            for limb in &material.ciphertext_by_limb {
                let polynomial = &limb[component_ordinal];
                let coefficient_byte_length = canonical_modulus_byte_length(polynomial.modulus);
                for coefficient in polynomial.coefficients.iter().copied() {
                    bytes.extend_from_slice(&coefficient.to_le_bytes()[..coefficient_byte_length]);
                }
            }
        }
        bytes
    }

    fn stream_descriptor(domain: CanonicalStreamDomain, bytes: &[u8]) -> StreamDescriptor {
        let mut writer = crate::foundation::CanonicalStreamWriter::new(
            domain,
            u64::try_from(bytes.len()).expect("stream length"),
        )
        .expect("canonical writer");
        for (chunk_index, chunk) in bytes
            .chunks(crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            writer
                .absorb_chunk(chunk_index, chunk)
                .expect("canonical chunk");
        }
        writer.finish().expect("canonical descriptor")
    }

    #[test]
    fn ciphertext_stream_decoder_authenticates_exact_form_and_refuses_bad_bytes_and_roots() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let material = public_material(&compilation, &witness);
        let canonical_bytes = ballot_ciphertext_stream_bytes(&material);
        let descriptor =
            stream_descriptor(CanonicalStreamDomain::BallotCiphertext, &canonical_bytes);
        let mut decoder = BallotValidityCiphertextStreamDecoder::new(
            compilation.source_plan(),
            descriptor.clone(),
        )
        .expect("exact descriptor");
        decoder
            .absorb_chunk(0, &canonical_bytes)
            .into_result()
            .expect("authenticated bytes");
        let authenticated = decoder
            .finish()
            .into_result()
            .expect("authenticated stream");
        assert_eq!(
            authenticated.full_object_digest,
            descriptor.full_object_digest.into_bytes()
        );
        assert_eq!(authenticated.polynomials.len(), 2);
        assert_eq!(
            authenticated.polynomials[1].3.as_ref(),
            material.ciphertext_by_limb[0][1].coefficients.as_ref()
        );

        let mut noncanonical_bytes = canonical_bytes.clone();
        let coefficient_byte_length = canonical_modulus_byte_length(TEST_DATA_MODULUS);
        noncanonical_bytes[4..4 + coefficient_byte_length]
            .copy_from_slice(&TEST_DATA_MODULUS.to_le_bytes()[..coefficient_byte_length]);
        let noncanonical_descriptor =
            stream_descriptor(CanonicalStreamDomain::BallotCiphertext, &noncanonical_bytes);
        let mut noncanonical_decoder = BallotValidityCiphertextStreamDecoder::new(
            compilation.source_plan(),
            noncanonical_descriptor,
        )
        .expect("length remains exact");
        assert_eq!(
            noncanonical_decoder
                .absorb_chunk(0, &noncanonical_bytes)
                .into_result(),
            Err(RefusalReason::MalformedEncoding)
        );

        let mut wrong_type_bytes = canonical_bytes.clone();
        wrong_type_bytes[2..4].copy_from_slice(&3_u16.to_le_bytes());
        let wrong_type_descriptor =
            stream_descriptor(CanonicalStreamDomain::BallotCiphertext, &wrong_type_bytes);
        let mut wrong_type_decoder = BallotValidityCiphertextStreamDecoder::new(
            compilation.source_plan(),
            wrong_type_descriptor,
        )
        .expect("length remains exact");
        assert_eq!(
            wrong_type_decoder
                .absorb_chunk(0, &wrong_type_bytes)
                .into_result(),
            Err(RefusalReason::WrongTypeOrLength)
        );

        let mut wrong_root_descriptor = descriptor;
        wrong_root_descriptor.full_object_digest =
            crate::foundation::Hash512::from_bytes([7_u8; 64]);
        let mut wrong_root_decoder = BallotValidityCiphertextStreamDecoder::new(
            compilation.source_plan(),
            wrong_root_descriptor,
        )
        .expect("descriptor shape");
        wrong_root_decoder
            .absorb_chunk(0, &canonical_bytes)
            .into_result()
            .expect("chunk digest still matches");
        assert_eq!(
            wrong_root_decoder.finish().into_result().err(),
            Some(RefusalReason::WrongHashOrRoot)
        );

        let wrong_domain_descriptor =
            stream_descriptor(CanonicalStreamDomain::BallotValidityProof, &canonical_bytes);
        let mut wrong_domain_decoder = BallotValidityCiphertextStreamDecoder::new(
            compilation.source_plan(),
            wrong_domain_descriptor,
        )
        .expect("descriptor shape");
        assert_eq!(
            wrong_domain_decoder
                .absorb_chunk(0, &canonical_bytes)
                .into_result(),
            Err(RefusalReason::WrongHashOrRoot)
        );
    }

    #[test]
    fn generated_ciphertext_replays_canonically_and_uses_the_same_witness_relation() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let expected_material = public_material(&compilation, &witness);
        let mut public_key_polynomials = Vec::new();
        for component_ordinal in 0..2_u16 {
            for (data_modulus_ordinal, limb) in
                expected_material.public_key_by_limb.iter().enumerate()
            {
                public_key_polynomials.push((
                    component_ordinal,
                    u16::try_from(data_modulus_ordinal).expect("modulus ordinal"),
                    limb[usize::from(component_ordinal)].modulus,
                    Arc::clone(&limb[usize::from(component_ordinal)].coefficients),
                ));
            }
        }
        let generated = BallotValidityGeneratedCiphertext::encrypt_with_public_key_polynomials(
            compilation.source_plan(),
            public_key_polynomials,
            &witness,
        )
        .expect("ciphertext generation");
        assert_eq!(
            generated.descriptor().total_byte_length,
            u64::try_from(ballot_ciphertext_stream_bytes(&expected_material).len())
                .expect("ciphertext length")
        );

        let mut decoder = BallotValidityCiphertextStreamDecoder::new(
            compilation.source_plan(),
            generated.descriptor().clone(),
        )
        .expect("generated descriptor");
        let mut readback = generated
            .begin_readback(compilation.source_plan())
            .expect("generated readback");
        let mut chunk_index = 0_usize;
        while let Some(chunk) = readback.next_chunk().expect("generated chunk") {
            assert!(chunk.len() <= FOUNDATION_PROFILE.stream_chunk_byte_length);
            decoder
                .absorb_chunk(chunk_index, &chunk)
                .into_result()
                .expect("generated chunk authenticates");
            chunk_index += 1;
        }
        assert!(chunk_index > 0);
        let authenticated = decoder
            .finish()
            .into_result()
            .expect("generated stream authenticates");
        assert_eq!(
            authenticated.full_object_digest,
            generated.descriptor().full_object_digest.into_bytes()
        );
        assert_eq!(authenticated.polynomials.len(), 2);
        for (component_ordinal, polynomial) in authenticated.polynomials.iter().enumerate() {
            assert_eq!(polynomial.0, u16::try_from(component_ordinal).unwrap());
            assert_eq!(
                polynomial.3.as_ref(),
                expected_material.ciphertext_by_limb[0][component_ordinal]
                    .coefficients
                    .as_ref()
            );
        }
    }

    #[test]
    fn provider_derives_all_plan_owned_columns_and_replays_identically() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let material = public_material(&compilation, &witness);
        let mut first = BallotValiditySourcePolynomialAdapter::from_bound_inputs(
            &compilation,
            1,
            [17_u8; 64],
            [13_u8; 64],
            witness.clone(),
            material.clone(),
        )
        .expect("provider");
        let mut restarted = BallotValiditySourcePolynomialAdapter::from_bound_inputs(
            &compilation,
            1,
            [17_u8; 64],
            [13_u8; 64],
            witness,
            material,
        )
        .expect("restarted provider");
        assert_eq!(
            first.restart_binding_hash(),
            restarted.restart_binding_hash()
        );

        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("variant");
        for column_ordinal in 0..u32::try_from(variant.ordered_columns().len()).unwrap() {
            let Some(_) = compilation.source_plan().recipe(column_ordinal) else {
                continue;
            };
            assert_eq!(
                first
                    .source_polynomial_replay_identity(column_ordinal)
                    .expect("first identity"),
                restarted
                    .source_polynomial_replay_identity(column_ordinal)
                    .expect("restarted identity")
            );
            assert_eq!(
                first
                    .derive_source_polynomial(column_ordinal)
                    .expect("first polynomial"),
                restarted
                    .derive_source_polynomial(column_ordinal)
                    .expect("restarted polynomial")
            );
        }
    }

    #[test]
    fn witness_clones_share_one_secret_owner_and_release_on_last_owner() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let weak_secret = witness.secret_weak_reference();
        let plaintext_allocation = witness.plaintext_coefficients().as_ptr();
        let shared_witness = witness.clone();

        assert_eq!(witness.secret_owner_count(), 2);
        assert_eq!(
            plaintext_allocation,
            shared_witness.plaintext_coefficients().as_ptr()
        );
        drop(witness);
        assert_eq!(shared_witness.secret_owner_count(), 1);
        assert!(weak_secret.upgrade().is_some());

        drop(shared_witness);
        assert!(weak_secret.upgrade().is_none());
    }

    #[test]
    fn provider_releases_secret_material_on_finish_rejection_and_drop() {
        let compilation = compilation();
        let active_witness = witness(&compilation);
        let material = public_material(&compilation, &active_witness);
        let remaining_owner = active_witness.clone();
        let weak_secret = active_witness.secret_weak_reference();
        let mut provider = BallotValiditySourcePolynomialAdapter::from_bound_inputs(
            &compilation,
            1,
            [17_u8; 64],
            [13_u8; 64],
            active_witness,
            material,
        )
        .expect("provider");
        let first_source_column = provider.ordered_source_columns[0].0;
        provider
            .derive_source_polynomial(first_source_column)
            .expect("the provider derives a secret-bearing cache entry");
        assert!(provider.cached_value_source.is_some());
        assert_eq!(remaining_owner.secret_owner_count(), 2);

        assert_eq!(
            provider.finish(),
            Err(CommonProofProverError::InvalidColumn)
        );
        assert!(provider.secret_material_is_released());
        assert_eq!(remaining_owner.secret_owner_count(), 1);
        drop(provider);
        assert!(weak_secret.upgrade().is_some());
        drop(remaining_owner);
        assert!(weak_secret.upgrade().is_none());

        let cancelled_witness = witness(&compilation);
        let cancelled_material = public_material(&compilation, &cancelled_witness);
        let cancelled_weak_secret = cancelled_witness.secret_weak_reference();
        let cancelled_provider = BallotValiditySourcePolynomialAdapter::from_bound_inputs(
            &compilation,
            1,
            [17_u8; 64],
            [13_u8; 64],
            cancelled_witness,
            cancelled_material,
        )
        .expect("cancelled provider");
        drop(cancelled_provider);
        assert!(cancelled_weak_secret.upgrade().is_none());
    }

    #[test]
    fn provider_releases_secret_material_after_successful_source_construction() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let material = public_material(&compilation, &witness);
        let remaining_owner = witness.clone();
        let mut provider = BallotValiditySourcePolynomialAdapter::from_bound_inputs(
            &compilation,
            1,
            [17_u8; 64],
            [13_u8; 64],
            witness,
            material,
        )
        .expect("provider");
        let request_context = CommonProofSourcePolynomialRequestContext::new(
            provider.protocol_version,
            provider.suite_identifier,
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            provider.application_statement_hash,
            provider.relation_plan_hash,
            provider.relation_plan_variant_hash,
            None,
            None,
        );
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("variant");
        let mut private_coins = DeterministicPrivateCoins(1);

        let constructed = construct_pre_challenge_relation_columns(
            variant,
            request_context,
            &mut provider,
            &mut private_coins,
            128,
        )
        .expect("all pre-challenge source columns construct");
        assert_ne!(constructed.source_replay_identity_digest(), [0_u8; 64]);
        assert!(provider.secret_material_is_released());
        assert_eq!(remaining_owner.secret_owner_count(), 1);
    }

    #[test]
    fn provider_constructor_rejection_releases_its_last_secret_owner() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let material = public_material(&compilation, &witness);
        let weak_secret = witness.secret_weak_reference();

        assert_eq!(
            BallotValiditySourcePolynomialAdapter::from_bound_inputs(
                &compilation,
                0,
                [17_u8; 64],
                [13_u8; 64],
                witness,
                material,
            )
            .err(),
            Some(BallotValidityAdapterError::WrongApplication)
        );
        assert!(weak_secret.upgrade().is_none());
    }

    #[test]
    fn canonical_statement_constructor_binds_owner_context_setup_and_ciphertext() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let material = public_material(&compilation, &witness);
        let roster_hash = [31_u8; 64];
        let participant_identity = [37_u8; 64];
        let producer_sequence = 29_u64;
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([17_u8; 64]),
            Hash512::from_bytes([41_u8; 64]),
            Hash512::from_bytes([43_u8; 64]),
            crate::foundation::ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            Some(0),
            None,
            Some(producer_sequence),
        )
        .expect("ballot slot");
        let canonical_statement =
            crate::bgv::proof_suite::canonical_selected_ballot_validity_statement(
                1,
                [17_u8; 64],
                [41_u8; 64],
                [43_u8; 64],
                roster_hash,
                participant_identity,
                producer_sequence,
                material.verified_setup_source_hash(),
                material.ballot_ciphertext_digest(),
            )
            .expect("canonical ballot statement");
        BallotValiditySourcePolynomialAdapter::from_canonical_ballot_statement(
            &compilation,
            application_slot,
            &canonical_statement,
            roster_hash,
            participant_identity,
            witness.clone(),
            material.clone(),
        )
        .expect("fully bound source adapter");
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("ballot variant");
        let relation_tree_inputs = proof_created_relation_tree_inputs_from_checked_variant(variant)
            .expect("ballot proof-tree inputs");
        assert_eq!(relation_tree_inputs.len(), 2);
        assert!(matches!(
            relation_tree_inputs[0],
            RelationProofTreeInput::ProofCreated {
                tree_role: ProofTreeRole::BaseOracle,
                row_width,
                leaf_visibility: ProofLeafVisibility::SecretBearing,
            } if row_width > 0
        ));
        assert!(matches!(
            relation_tree_inputs[1],
            RelationProofTreeInput::ProofCreated {
                tree_role: ProofTreeRole::AuxiliaryOracle,
                row_width,
                leaf_visibility: ProofLeafVisibility::SecretBearing,
            } if row_width > 0
        ));

        let changed_ciphertext_statement =
            crate::bgv::proof_suite::canonical_selected_ballot_validity_statement(
                1,
                [17_u8; 64],
                [41_u8; 64],
                [43_u8; 64],
                roster_hash,
                participant_identity,
                producer_sequence,
                material.verified_setup_source_hash(),
                [47_u8; 64],
            )
            .expect("changed canonical statement");
        assert_eq!(
            BallotValiditySourcePolynomialAdapter::from_canonical_ballot_statement(
                &compilation,
                application_slot,
                &changed_ciphertext_statement,
                roster_hash,
                participant_identity,
                witness.clone(),
                material.clone(),
            )
            .err(),
            Some(BallotValidityAdapterError::InvalidStatementBinding)
        );
        assert_eq!(
            BallotValiditySourcePolynomialAdapter::from_canonical_ballot_statement(
                &compilation,
                application_slot,
                &canonical_statement,
                roster_hash,
                [49_u8; 64],
                witness,
                material,
            )
            .err(),
            Some(BallotValidityAdapterError::InvalidStatementBinding)
        );
    }

    #[test]
    fn provider_rejects_malformed_witness_and_wrong_public_root_bindings() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let material = public_material(&compilation, &witness);
        let mut malformed_randomizer = witness.randomizer_coefficients().to_vec();
        malformed_randomizer[17] = 2;
        assert_eq!(
            BallotValidityEncryptionAttemptWitness::from_encryption_attempt(
                compilation.source_plan(),
                witness.scores(),
                witness.plaintext_coefficients().to_vec(),
                malformed_randomizer,
                witness.error_zero_coefficients().to_vec(),
                witness.error_one_coefficients().to_vec(),
                [41_u8; 32],
            )
            .err(),
            Some(BallotValidityAdapterError::InvalidWitness)
        );
        assert_eq!(
            BallotValidityVerifiedColumnEvaluator::new(
                &compilation,
                [29_u8; 64],
                material.ballot_ciphertext_digest(),
                material,
            )
            .err(),
            Some(BallotValidityAdapterError::InvalidStatementBinding)
        );
    }

    #[test]
    fn verifier_adapter_matches_direct_public_polynomial_evaluation_and_refuses_wrong_types() {
        let compilation = compilation();
        let witness = witness(&compilation);
        let material = public_material(&compilation, &witness);
        let mut evaluator = BallotValidityVerifiedColumnEvaluator::new(
            &compilation,
            material.verified_setup_source_hash(),
            material.ballot_ciphertext_digest(),
            material.clone(),
        )
        .expect("evaluator");
        let variant = compilation
            .relation_plan()
            .select_variant(None, None)
            .expect("variant");
        let (column_ordinal, source) = evaluator
            .source_by_column
            .iter()
            .enumerate()
            .find_map(|(column_index, source)| {
                source.map(|source| (u32::try_from(column_index).expect("column ordinal"), source))
            })
            .expect("public source");
        let rows = material
            .polynomial(
                source.source_kind,
                source.component_ordinal,
                source.data_modulus_index,
            )
            .expect("polynomial")
            .coefficients
            .iter()
            .copied()
            .map(ProofBaseFieldElement::from_canonical)
            .collect::<Result<Vec<_>, _>>()
            .expect("field rows");
        let trace_domain =
            ProofEvaluationDomain::new_subgroup(TEST_RING_DEGREE as usize).expect("trace domain");
        let coefficients = trace_domain
            .interpolate_base_polynomial(&rows)
            .expect("interpolation");
        let point = ProofChallengeExtensionElement::from_canonical_coordinates([7, 11, 0, 0, 0])
            .expect("extension point");
        let expected =
            CommonProofSourcePolynomial::from_base_coefficients(coefficients).evaluate_at(point);
        assert_eq!(
            evaluator.evaluate_at_extension_point(column_ordinal, point),
            Some(expected)
        );
        let prover_column = variant
            .ordered_columns()
            .iter()
            .position(|column| matches!(column.origin(), RelationColumnOrigin::Prover))
            .expect("prover column") as u32;
        assert_eq!(
            evaluator.evaluate_at_extension_point(prover_column, point),
            None
        );
    }
}
